use bulk_hash_lib::core::{
    hash_manager::{HashAlgorithm, HashManager},
    ignore_list::IgnoreList,
    io::{
        bulk_hash_error::BulkHashError, directory_node::DirectoryNode, file_manager::FileManager,
        meta_data::MetaData,
    },
    scan_manager::{ScanCancelToken, ScanControl, ScanControlState, ScanManager},
    structs::file_info::FileInfo,
};
use chrono::Utc;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zip::{ZipWriter, write::SimpleFileOptions};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "bulkhash_test_{prefix}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create temp test dir");
        Self { path: dir }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn hash_manager_blake3_and_sha256_match_bytes_hash() {
    let dir = TempDir::new("hash_manager");
    let file_path = dir.path().join("sample.txt");
    let content = b"Hello BulkHashed! Testing 1234567890.";
    fs::write(&file_path, content).expect("write sample file");

    let mut blake3_mgr = HashManager::new(HashAlgorithm::Blake3);
    let b3_file_hash = blake3_mgr
        .get_hash_code(&file_path)
        .expect("blake3 file hash");
    assert_eq!(
        b3_file_hash,
        HashAlgorithm::Blake3.get_hash_from_bytes(content)
    );
    assert_eq!(blake3_mgr.get_files_counted(), 1);

    let mut sha256_mgr = HashManager::new(HashAlgorithm::Sha256);
    let sha_file_hash = sha256_mgr
        .get_hash_code(&file_path)
        .expect("sha256 file hash");
    assert_eq!(
        sha_file_hash,
        HashAlgorithm::Sha256.get_hash_from_bytes(content)
    );
    assert_eq!(sha256_mgr.get_files_counted(), 1);
}

#[test]
fn hash_manager_missing_file_returns_file_not_found() {
    let mut mgr = HashManager::new(HashAlgorithm::Blake3);
    let err = mgr
        .get_hash_code("/nonexistent/path/definitely_missing_file.bin")
        .expect_err("expected FileNotFound");
    assert!(matches!(err, BulkHashError::FileNotFound(_)));
    assert_eq!(err.kind(), "FileNotFound");
}

#[test]
fn scan_manager_scans_directory_and_skips_symlinks_and_resets_state() {
    let dir = TempDir::new("scan_dir");
    let sub = dir.path().join("sub");
    fs::create_dir_all(&sub).expect("create sub dir");

    let f1 = dir.path().join("a.txt");
    let f2 = sub.join("b.txt");
    fs::write(&f1, b"alpha").expect("write a.txt");
    fs::write(&f2, b"beta").expect("write b.txt");

    #[cfg(unix)]
    {
        let link = sub.join("loop_link");
        std::os::unix::fs::symlink(dir.path(), &link).expect("create symlink");
    }

    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    scanner
        .start_hash(dir.path().to_string_lossy().into_owned())
        .expect("scan should succeed");

    assert_eq!(scanner.get_list().len(), 2);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 2);

    // Calling start_hash a second time must reset state cleanly instead of duplicating entries.
    scanner
        .start_hash(dir.path().to_string_lossy().into_owned())
        .expect("second scan should succeed");
    assert_eq!(scanner.get_list().len(), 2);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 2);
}

#[test]
fn scan_manager_single_file_and_missing_path() {
    let dir = TempDir::new("scan_single");
    let file_path = dir.path().join("only.txt");
    fs::write(&file_path, b"single").expect("write single file");

    let mut scanner = ScanManager::new(HashAlgorithm::Sha256);
    scanner
        .start_hash(file_path.to_string_lossy().into_owned())
        .expect("single file scan should succeed");
    assert_eq!(scanner.get_list().len(), 1);

    let tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    assert!(tree.files.contains_key("only.txt"));

    let missing_err = scanner
        .start_hash(
            dir.path()
                .join("does_not_exist")
                .to_string_lossy()
                .into_owned(),
        )
        .expect_err("expected PathNotFound");
    assert!(matches!(missing_err, BulkHashError::PathNotFound(_)));
}

#[test]
fn directory_node_uses_relative_paths_and_handles_colons_in_filenames() {
    let files = vec![
        FileInfo::new(
            String::from("/tmp/root/sub/file:with:colons.txt"),
            Ok(String::from("abc123")),
        ),
        FileInfo::new(
            String::from("/tmp/root/top.txt"),
            Err(BulkHashError::PermissionDenied(String::from(
                "/tmp/root/top.txt",
            ))),
        ),
    ];

    let tree = DirectoryNode::build_tree("/tmp/root", &files);
    assert_eq!(tree.name, "/tmp/root");
    assert!(tree.files.contains_key("top.txt"));
    assert!(matches!(tree.files.get("top.txt"), Some(Err(_))));

    let sub = tree
        .sub_directories
        .get("sub")
        .expect("sub directory must exist directly under root");
    assert_eq!(
        sub.files.get("file:with:colons.txt"),
        Some(&Ok(String::from("abc123")))
    );
}

#[test]
fn save_and_open_roundtrip_without_trailing_slash() {
    let dir = TempDir::new("roundtrip");
    let mut tree = DirectoryNode::new(String::from("/example"));
    tree.insert_path(&["nested", "hello.txt"], Ok(String::from("deadbeef")));

    let meta = MetaData::new(1, Duration::from_millis(42), Utc::now());

    // Pass folder path WITHOUT trailing slash; save_file must join cleanly.
    let saved_path = FileManager::save_file(dir.path(), &tree, &meta).expect("save_file");
    assert!(saved_path.exists());
    assert!(
        !saved_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .contains(':')
    );

    let loaded = FileManager::open_file(&saved_path).expect("open_file");
    assert_eq!(loaded.get_meta().get_version(), 1);
    assert_eq!(loaded.get_meta().get_files_hashed(), 1);
    assert_eq!(loaded.get_tree(), &tree);
    assert!(!loaded.get_hash().is_empty());
}

#[test]
fn open_file_validation_errors() {
    let dir = TempDir::new("open_errors");

    // 1. Missing file
    let err = FileManager::open_file(dir.path().join("missing.hashed")).expect_err("FileNotFound");
    assert!(matches!(err, BulkHashError::FileNotFound(_)));

    // 2. Path is a directory, not a file
    let dir_named_hashed = dir.path().join("folder.hashed");
    fs::create_dir_all(&dir_named_hashed).expect("create dir");
    let err = FileManager::open_file(&dir_named_hashed).expect_err("NotAFile");
    assert!(matches!(err, BulkHashError::NotAFile(_)));

    // 3. Invalid ending
    let wrong_ext = dir.path().join("notes.txt");
    fs::write(&wrong_ext, b"hello").expect("write txt");
    let err = FileManager::open_file(&wrong_ext).expect_err("InvalidEnding");
    assert!(matches!(err, BulkHashError::InvalidEnding(_)));

    // 4. Corrupted zip (missing required entries)
    let missing_entry_zip = dir.path().join("incomplete.hashed");
    {
        let f = File::create(&missing_entry_zip).expect("create zip");
        let mut zip = ZipWriter::new(f);
        zip.start_file("meta.json", SimpleFileOptions::default())
            .expect("start_file");
        zip.write_all(b"{}").expect("write");
        zip.finish().expect("finish");
    }
    let err = FileManager::open_file(&missing_entry_zip).expect_err("FileIsCorrupted");
    assert!(matches!(err, BulkHashError::FileIsCorrupted(_)));

    // 5. Unsupported version
    let bad_version_zip = dir.path().join("v99.hashed");
    {
        let f = File::create(&bad_version_zip).expect("create zip");
        let mut zip = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        let meta_json = format!(
            r#"{{"version":99,"files_hashed":0,"hash_time":{{"secs":0,"nanos":0}},"date_utc":"{}","local_time":"2026-01-01T00:00:00Z","os":"linux"}}"#,
            Utc::now().to_rfc3339()
        );
        zip.start_file("meta.json", opts).expect("meta");
        zip.write_all(meta_json.as_bytes()).expect("write meta");
        zip.start_file("tree.json", opts).expect("tree");
        zip.write_all(b"{}").expect("write tree");
        zip.start_file("hash.sha256", opts).expect("hash");
        zip.write_all(b"0000").expect("write hash");
        zip.finish().expect("finish");
    }
    let err = FileManager::open_file(&bad_version_zip).expect_err("UnsupportedVersion");
    assert!(matches!(err, BulkHashError::UnsupportedVersion(99)));

    // 6. Hash mismatch
    let tampered_zip = dir.path().join("tampered.hashed");
    {
        let f = File::create(&tampered_zip).expect("create zip");
        let mut zip = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        let meta = MetaData::new(0, Duration::ZERO, Utc::now());
        zip.start_file("meta.json", opts).expect("meta");
        serde_json::to_writer(&mut zip, &meta).expect("write meta");
        zip.start_file("tree.json", opts).expect("tree");
        let tree = DirectoryNode::new(String::from("root"));
        serde_json::to_writer(&mut zip, &tree).expect("write tree");
        zip.start_file("hash.sha256", opts).expect("hash");
        zip.write_all(b"0000000000000000000000000000000000000000000000000000000000000000")
            .expect("write bad hash");
        zip.finish().expect("finish");
    }
    let err = FileManager::open_file(&tampered_zip).expect_err("HashMismatch");
    assert!(matches!(err, BulkHashError::HashMismatch { .. }));
}

#[test]
fn save_file_rejects_missing_or_non_dir_target() {
    let dir = TempDir::new("save_errors");
    let tree = DirectoryNode::new(String::from("root"));
    let meta = MetaData::new(0, Duration::ZERO, Utc::now());

    let missing_err =
        FileManager::save_file(dir.path().join("nope"), &tree, &meta).expect_err("PathNotFound");
    assert!(matches!(missing_err, BulkHashError::PathNotFound(_)));

    let file_target = dir.path().join("a_file.txt");
    fs::write(&file_target, b"x").expect("write file");
    let not_dir_err =
        FileManager::save_file(&file_target, &tree, &meta).expect_err("NotADirectory");
    assert!(matches!(not_dir_err, BulkHashError::NotADirectory(_)));
}

#[test]
fn bulk_hash_error_serializes_cleanly_for_gui() {
    let err = BulkHashError::HashMismatch {
        expected: String::from("aaa"),
        actual: String::from("bbb"),
    };
    let json = serde_json::to_value(&err).expect("serialize BulkHashError");
    assert_eq!(json["kind"], "HashMismatch");
    assert_eq!(json["message"], "Hash mismatch: expected 'aaa', got 'bbb'");
}

#[test]
fn single_file_hashing_returns_metadata_and_verifies_hash() {
    let dir = TempDir::new("single_file_feature");
    let file_path = dir.path().join("archive.bin");
    let payload = b"single file hashing payload 1234567890";
    fs::write(&file_path, payload).expect("write test file");

    let mut scanner = ScanManager::new(HashAlgorithm::Sha256);
    let result = scanner
        .hash_single_file(&file_path)
        .expect("single file hash should succeed");

    assert_eq!(result.get_file_name(), "archive.bin");
    assert_eq!(result.get_algorithm(), HashAlgorithm::Sha256);
    assert_eq!(result.get_file_size(), payload.len() as u64);
    assert_eq!(
        result.get_hash(),
        HashAlgorithm::Sha256.get_hash_from_bytes(payload)
    );
    assert_eq!(scanner.get_list().len(), 1);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 1);
    assert_eq!(
        scanner.get_hash_manager().get_algorithm(),
        HashAlgorithm::Sha256
    );

    // Case-insensitive + whitespace-tolerant verification
    let upper = format!("  {}  \n", result.get_hash().to_uppercase());
    assert!(result.verify_hash(&upper).is_ok());

    let mismatch = result
        .verify_hash("deadbeef")
        .expect_err("expected HashMismatch");
    assert!(matches!(mismatch, BulkHashError::HashMismatch { .. }));

    // GUI JSON serialization
    let json = serde_json::to_value(&result).expect("serialize SingleFileHash");
    assert_eq!(json["file_name"], "archive.bin");
    assert_eq!(json["file_size"], payload.len());
    assert_eq!(json["algorithm"], "Sha256");

    // Roundtrip saving single-file scan into a .hashed file
    let tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    let meta = MetaData::new(
        scanner.get_hash_manager().get_files_counted(),
        scanner.get_hash_time(),
        Utc::now(),
    );
    let saved = FileManager::save_file(dir.path(), &tree, &meta).expect("save single-file .hashed");
    let loaded = FileManager::open_file(&saved).expect("open single-file .hashed");
    assert_eq!(
        loaded.get_tree().files.get("archive.bin"),
        Some(&Ok(result.get_hash().to_string()))
    );
}

#[test]
fn single_file_hashing_rejects_directories_and_missing_files() {
    let dir = TempDir::new("single_file_errors");
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);

    let dir_err = scanner
        .hash_single_file(dir.path())
        .expect_err("directory must be rejected with NotAFile");
    assert!(matches!(dir_err, BulkHashError::NotAFile(_)));

    let missing_err = scanner
        .hash_single_file(dir.path().join("missing.txt"))
        .expect_err("missing file must return FileNotFound");
    assert!(matches!(missing_err, BulkHashError::FileNotFound(_)));

    let mut hasher = HashManager::new(HashAlgorithm::Blake3);
    let hasher_dir_err = hasher
        .get_hash_code(dir.path())
        .expect_err("HashManager::get_hash_code must also reject directories");
    assert!(matches!(hasher_dir_err, BulkHashError::NotAFile(_)));
}

#[test]
fn all_hash_algorithms_match_known_test_vectors() {
    // Official reference digests for empty input ""
    assert_eq!(
        HashAlgorithm::Blake3.get_hash_from_bytes(b""),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    assert_eq!(
        HashAlgorithm::Sha256.get_hash_from_bytes(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        HashAlgorithm::Sha512.get_hash_from_bytes(b""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert_eq!(
        HashAlgorithm::Md5.get_hash_from_bytes(b""),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
    assert_eq!(
        HashAlgorithm::XxHash64.get_hash_from_bytes(b""),
        "ef46db3751d8e999"
    );
    assert_eq!(
        HashAlgorithm::XxHash3.get_hash_from_bytes(b""),
        "2d06800538d394c2"
    );
    assert_eq!(
        HashAlgorithm::XxHash128.get_hash_from_bytes(b""),
        "99aa06d3014798d86001c324468d497f"
    );

    // Official reference digests for "abc"
    assert_eq!(
        HashAlgorithm::Blake3.get_hash_from_bytes(b"abc"),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
    assert_eq!(
        HashAlgorithm::Sha256.get_hash_from_bytes(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        HashAlgorithm::Sha512.get_hash_from_bytes(b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert_eq!(
        HashAlgorithm::Md5.get_hash_from_bytes(b"abc"),
        "900150983cd24fb0d6963f7d28e17f72"
    );

    for &algo in HashAlgorithm::all() {
        let digest = algo.get_hash_from_bytes(b"abc");
        assert_eq!(digest.len(), algo.hex_len(), "unexpected hex length for {algo}");
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "digest for {algo} must be lowercase hex"
        );
    }
}

#[test]
fn all_hash_algorithms_stream_empty_and_multichunk_files_identically() {
    let dir = TempDir::new("all_algos_streaming");

    // 0-byte empty file
    let empty_file = dir.path().join("empty.bin");
    fs::write(&empty_file, b"").expect("write empty file");

    // 200 KiB deterministic payload (> 3x 64 KiB read buffer)
    let large_payload: Vec<u8> = (0..(200 * 1024))
        .map(|i| ((i * 31 + 17) % 256) as u8)
        .collect();
    let large_file = dir.path().join("large.bin");
    fs::write(&large_file, &large_payload).expect("write large file");

    let mut mgr = HashManager::new(HashAlgorithm::default());
    for (idx, &algo) in HashAlgorithm::all().iter().enumerate() {
        mgr.set_algorithm(algo);
        assert_eq!(mgr.get_algorithm(), algo);

        let empty_stream = mgr.get_hash_code(&empty_file).expect("hash empty file");
        assert_eq!(empty_stream, algo.get_hash_from_bytes(b""));
        assert_eq!(empty_stream.len(), algo.hex_len());

        let large_stream = mgr.get_hash_code(&large_file).expect("hash large file");
        assert_eq!(large_stream, algo.get_hash_from_bytes(&large_payload));
        assert_eq!(large_stream.len(), algo.hex_len());

        assert_eq!(mgr.get_files_counted(), (idx + 1) * 2);
    }
}

#[test]
fn hash_algorithm_parsing_metadata_and_snapshot_roundtrip() {
    use std::str::FromStr;

    assert_eq!(HashAlgorithm::default(), HashAlgorithm::Blake3);
    assert_eq!(HashAlgorithm::from_str("md5").unwrap(), HashAlgorithm::Md5);
    assert_eq!(
        HashAlgorithm::from_str("SHA-512").unwrap(),
        HashAlgorithm::Sha512
    );
    assert_eq!(
        HashAlgorithm::from_str("sha_256").unwrap(),
        HashAlgorithm::Sha256
    );
    assert_eq!(
        HashAlgorithm::from_str("xxh64").unwrap(),
        HashAlgorithm::XxHash64
    );
    assert_eq!(
        HashAlgorithm::from_str("xxhash3").unwrap(),
        HashAlgorithm::XxHash3
    );
    assert_eq!(
        HashAlgorithm::from_str("XXH3-128").unwrap(),
        HashAlgorithm::XxHash128
    );
    assert_eq!(
        HashAlgorithm::from_str("xxhash").unwrap(),
        HashAlgorithm::XxHash128
    );

    let err = HashAlgorithm::from_str("unknown-algo").expect_err("expected UnsupportedAlgorithm");
    assert!(matches!(err, BulkHashError::UnsupportedAlgorithm(_)));
    assert_eq!(err.kind(), "UnsupportedAlgorithm");

    assert!(HashAlgorithm::Blake3.is_cryptographic());
    assert!(HashAlgorithm::Sha256.is_cryptographic());
    assert!(HashAlgorithm::Sha512.is_cryptographic());
    assert!(!HashAlgorithm::Md5.is_cryptographic());
    assert!(!HashAlgorithm::XxHash64.is_cryptographic());
    assert!(!HashAlgorithm::XxHash3.is_cryptographic());
    assert!(!HashAlgorithm::XxHash128.is_cryptographic());

    // ScanManager algorithm switching + MetaData algorithm persistence in .hashed archive
    let dir = TempDir::new("algo_snapshot");
    let sample = dir.path().join("data.bin");
    fs::write(&sample, b"fast xxhash snapshot test").expect("write sample");

    let mut scanner = ScanManager::new(HashAlgorithm::Md5);
    let md5_res = scanner.hash_single_file(&sample).expect("md5 single hash");
    assert_eq!(md5_res.get_algorithm(), HashAlgorithm::Md5);
    assert_eq!(
        md5_res.get_hash(),
        HashAlgorithm::Md5.get_hash_from_bytes(b"fast xxhash snapshot test")
    );

    scanner.set_algorithm(HashAlgorithm::XxHash128);
    assert_eq!(scanner.get_algorithm(), HashAlgorithm::XxHash128);
    scanner
        .start_hash(dir.path().to_string_lossy().into_owned())
        .expect("scan with XxHash128");

    let tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    let meta = MetaData::new(
        scanner.get_hash_manager().get_files_counted(),
        scanner.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(scanner.get_algorithm());

    let saved = FileManager::save_file(dir.path(), &tree, &meta).expect("save snapshot");
    let loaded = FileManager::open_file(&saved).expect("open snapshot");
    assert_eq!(loaded.get_meta().get_algorithm(), Some(HashAlgorithm::XxHash128));
    assert_eq!(
        loaded.get_tree().files.get("data.bin"),
        Some(&Ok(
            HashAlgorithm::XxHash128.get_hash_from_bytes(b"fast xxhash snapshot test")
        ))
    );
}

#[test]
fn scan_manager_thread_count_configuration_and_normalization() {
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    assert_eq!(scanner.get_thread_count(), None);
    assert!(scanner.effective_thread_count() >= 1);

    let configured = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(4);
    assert_eq!(configured.get_thread_count(), Some(4));
    assert_eq!(configured.effective_thread_count(), 4);

    let auto_from_zero = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(0);
    assert_eq!(auto_from_zero.get_thread_count(), None);
    assert!(auto_from_zero.effective_thread_count() >= 1);

    scanner.set_thread_count(Some(2));
    assert_eq!(scanner.get_thread_count(), Some(2));
    assert_eq!(scanner.effective_thread_count(), 2);

    scanner.set_thread_count(Some(0));
    assert_eq!(scanner.get_thread_count(), None);
    assert!(scanner.effective_thread_count() >= 1);

    scanner.set_thread_count(Some(3));
    scanner.set_thread_count(None);
    assert_eq!(scanner.get_thread_count(), None);
}

#[test]
fn parallel_directory_scan_matches_single_threaded_across_all_algorithms() {
    let dir = TempDir::new("parallel_scan");
    let nested = dir.path().join("nested").join("deep");
    let mixed = dir.path().join("mixed");
    let empty_subdir = dir.path().join("empty_subdir");
    fs::create_dir_all(&nested).expect("create nested dir");
    fs::create_dir_all(&mixed).expect("create mixed dir");
    fs::create_dir_all(&empty_subdir).expect("create empty subdir");

    let mut expected_files: Vec<(PathBuf, Vec<u8>)> = Vec::new();

    // Empty 0-byte file
    let empty_path = dir.path().join("empty.bin");
    fs::write(&empty_path, b"").expect("write empty.bin");
    expected_files.push((empty_path, Vec::new()));

    // Multi-chunk files (> 64 KiB buffer) to verify per-worker buffer isolation
    for idx in 0..4usize {
        let size = (70 + idx * 25) * 1024;
        let payload: Vec<u8> = (0..size)
            .map(|b| ((b * (idx + 7) + idx * 19) % 256) as u8)
            .collect();
        let path = nested.join(format!("chunked_{idx}.bin"));
        fs::write(&path, &payload).expect("write chunked file");
        expected_files.push((path, payload));
    }

    // Many smaller files across directories (including special characters in filenames)
    for idx in 0..30usize {
        let payload = format!("parallel-file-payload-{idx:03}-{}", "x".repeat(idx * 37))
            .into_bytes();
        let path = if idx % 3 == 0 {
            dir.path().join(format!("top_{idx:02}.txt"))
        } else if idx % 3 == 1 {
            mixed.join(format!("item {idx:02}.dat"))
        } else {
            nested.join(format!("leaf_{idx:02}.log"))
        };
        fs::write(&path, &payload).expect("write small file");
        expected_files.push((path, payload));
    }

    #[cfg(unix)]
    {
        let loop_link = nested.join("root_symlink");
        std::os::unix::fs::symlink(dir.path(), &loop_link).expect("create symlink");
    }

    let root_str = dir.path().to_string_lossy().into_owned();
    let expected_count = expected_files.len();

    for &algo in HashAlgorithm::all() {
        let mut single = ScanManager::new(algo).with_thread_count(1);
        single
            .start_hash(root_str.clone())
            .expect("single-threaded scan");

        let mut custom_pool = ScanManager::new(algo).with_thread_count(4);
        custom_pool
            .start_hash(root_str.clone())
            .expect("custom thread pool scan");

        let mut all_cores = ScanManager::new(algo);
        all_cores
            .start_hash(root_str.clone())
            .expect("all-cores parallel scan");

        assert_eq!(single.get_list().len(), expected_count);
        assert_eq!(custom_pool.get_list().len(), expected_count);
        assert_eq!(all_cores.get_list().len(), expected_count);

        assert_eq!(single.get_hash_manager().get_files_counted(), expected_count);
        assert_eq!(
            custom_pool.get_hash_manager().get_files_counted(),
            expected_count
        );
        assert_eq!(
            all_cores.get_hash_manager().get_files_counted(),
            expected_count
        );

        let tree_single = DirectoryNode::build_tree(single.get_path(), single.get_list());
        let tree_custom = DirectoryNode::build_tree(custom_pool.get_path(), custom_pool.get_list());
        let tree_all = DirectoryNode::build_tree(all_cores.get_path(), all_cores.get_list());

        assert_eq!(tree_custom, tree_single, "custom pool mismatch for {algo}");
        assert_eq!(tree_all, tree_single, "all-cores mismatch for {algo}");

        // Verify every computed hash against reference byte hashing
        for (file_path, payload) in &expected_files {
            let expected_hash = algo.get_hash_from_bytes(payload);
            let path_str = file_path.to_string_lossy();
            let found = all_cores
                .get_list()
                .iter()
                .find(|entry| entry.get_path() == path_str)
                .expect("file must be present in parallel scan output");
            assert_eq!(
                found.get_result().as_deref().ok(),
                Some(expected_hash.as_str()),
                "hash mismatch for {path_str} with {algo}"
            );
        }
    }

    // Verify .hashed snapshot roundtrip from a parallel scan
    let output_dir = TempDir::new("parallel_snapshot_out");
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    scanner
        .start_hash(root_str)
        .expect("parallel snapshot scan");
    let tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    let meta = MetaData::new(
        scanner.get_hash_manager().get_files_counted(),
        scanner.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(scanner.get_algorithm());
    let saved = FileManager::save_file(output_dir.path(), &tree, &meta).expect("save snapshot");
    let loaded = FileManager::open_file(&saved).expect("open snapshot");
    assert_eq!(loaded.get_tree(), &tree);
    assert_eq!(loaded.get_meta().get_files_hashed(), expected_count);
}

#[test]
fn hash_files_in_parallel_preserves_order_and_isolates_errors() {
    let dir = TempDir::new("parallel_multi_files");
    let subdir = dir.path().join("a_folder");
    fs::create_dir_all(&subdir).expect("create subdir");

    let empty_file = dir.path().join("00_empty.bin");
    let small_a = dir.path().join("01_small_a.txt");
    let large_file = dir.path().join("02_large.bin");
    let small_b = dir.path().join("03_small_b.txt");
    let missing_file = dir.path().join("99_missing.txt");

    let large_payload: Vec<u8> = (0..(150 * 1024))
        .map(|i| ((i * 13 + 7) % 256) as u8)
        .collect();

    fs::write(&empty_file, b"").expect("write empty");
    fs::write(&small_a, b"alpha-parallel").expect("write small_a");
    fs::write(&large_file, &large_payload).expect("write large");
    fs::write(&small_b, b"beta-parallel").expect("write small_b");

    let inputs = vec![
        empty_file.clone(),
        small_a.clone(),
        missing_file.clone(),
        subdir.clone(),
        large_file.clone(),
        small_b.clone(),
    ];

    // 1. Empty slice edge case
    let mut mgr = HashManager::new(HashAlgorithm::Sha256);
    let empty_paths: Vec<PathBuf> = Vec::new();
    assert!(mgr.hash_files(&empty_paths).is_empty());
    assert_eq!(mgr.get_files_counted(), 0);

    // 2. Single-file slice edge case
    let single_res = mgr.hash_files(&inputs[1..2]);
    assert_eq!(single_res.len(), 1);
    assert_eq!(
        single_res[0].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"alpha-parallel").as_str())
    );
    assert_eq!(mgr.get_files_counted(), 1);

    // 3. Parallel multi-file hashing with mixed valid files and error entries
    mgr.reset_counter();
    let results = mgr.hash_files(&inputs);
    assert_eq!(results.len(), inputs.len());
    assert_eq!(mgr.get_files_counted(), 4);

    // Order must match inputs 1:1
    for (result, expected_path) in results.iter().zip(&inputs) {
        assert_eq!(result.get_path(), expected_path.to_string_lossy());
    }

    assert_eq!(
        results[0].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"").as_str())
    );
    assert_eq!(
        results[1].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"alpha-parallel").as_str())
    );
    assert!(matches!(
        results[2].get_result(),
        Err(BulkHashError::FileNotFound(_))
    ));
    assert!(matches!(
        results[3].get_result(),
        Err(BulkHashError::NotAFile(_))
    ));
    assert_eq!(
        results[4].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(&large_payload).as_str())
    );
    assert_eq!(
        results[5].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"beta-parallel").as_str())
    );

    // 4. ScanManager::hash_files with custom thread count + state reset on subsequent call
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(3);
    scanner
        .hash_files(&inputs)
        .expect("ScanManager::hash_files should succeed");
    assert_eq!(scanner.get_list().len(), inputs.len());
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 4);

    // Subsequent call resets previous state cleanly
    scanner
        .hash_files(&inputs[..2])
        .expect("second ScanManager::hash_files");
    assert_eq!(scanner.get_list().len(), 2);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 2);

    // 5. Empty directory scan works and resets state cleanly
    let empty_dir = TempDir::new("parallel_empty_dir");
    scanner
        .start_hash(empty_dir.path().to_string_lossy().into_owned())
        .expect("empty directory scan should succeed");
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
}

#[test]
fn scan_cancelled_error_and_cancel_token_interop() {
    let err = BulkHashError::ScanCancelled;
    assert!(err.is_cancelled());
    assert!(!BulkHashError::PathNotFound(String::from("/missing")).is_cancelled());
    assert_eq!(err.kind(), "ScanCancelled");
    assert_eq!(err.to_string(), "Scan was cancelled");

    let json = serde_json::to_value(&err).expect("serialize ScanCancelled");
    assert_eq!(json["kind"], "ScanCancelled");
    assert_eq!(json["message"], "Scan was cancelled");

    // ScanCancelToken clone and reset semantics
    let token = ScanCancelToken::new();
    let cloned = token.clone();
    assert!(!token.is_cancelled());
    assert!(!cloned.is_cancelled());

    cloned.cancel();
    assert!(token.is_cancelled());
    assert!(cloned.is_cancelled());

    token.reset();
    assert!(!token.is_cancelled());
    assert!(!cloned.is_cancelled());

    // Direct Arc<AtomicBool> interop with ScanManager
    let raw_flag = Arc::new(AtomicBool::new(false));
    let mut scanner =
        ScanManager::new(HashAlgorithm::Blake3).with_cancel_token(Arc::clone(&raw_flag));
    assert!(!scanner.is_cancelled());

    raw_flag.store(true, Ordering::Release);
    assert!(scanner.is_cancelled());
    assert!(scanner.get_cancel_token().is_cancelled());
    assert!(scanner.get_cancel_flag().load(Ordering::Acquire));

    scanner.reset_cancel();
    assert!(!raw_flag.load(Ordering::Acquire));

    let replacement = ScanCancelToken::new();
    scanner.set_cancel_token(replacement.clone());
    scanner.cancel();
    assert!(replacement.is_cancelled());
    assert!(!raw_flag.load(Ordering::Acquire));
}

#[test]
fn pre_cancelled_scan_manager_aborts_all_entry_points_and_recovers_after_reset() {
    let dir = TempDir::new("pre_cancel_scan");
    let sub = dir.path().join("sub");
    fs::create_dir_all(&sub).expect("create sub dir");

    let f1 = dir.path().join("a.txt");
    let f2 = sub.join("b.txt");
    let f3 = sub.join("c.txt");
    fs::write(&f1, b"alpha-cancel").expect("write a.txt");
    fs::write(&f2, b"beta-cancel").expect("write b.txt");
    fs::write(&f3, b"gamma-cancel").expect("write c.txt");

    let dir_str = dir.path().to_string_lossy().into_owned();
    let files = vec![f1.clone(), f2.clone(), f3.clone()];

    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    let token = scanner.get_cancel_token();

    // Baseline scan succeeds
    scanner
        .start_hash(dir_str.clone())
        .expect("initial scan should succeed");
    assert_eq!(scanner.get_list().len(), 3);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 3);

    // Cancel via shared token before starting new operations
    token.cancel();

    let dir_err = scanner
        .start_hash(dir_str.clone())
        .expect_err("cancelled directory scan must fail");
    assert!(dir_err.is_cancelled());
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
    assert_eq!(scanner.get_hash_time(), Duration::ZERO);

    // Even a missing path aborts immediately with ScanCancelled before touching disk
    let missing_err = scanner
        .start_hash(String::from("/definitely/nonexistent/path/for_cancel_test"))
        .expect_err("cancelled scan on missing path must return ScanCancelled");
    assert!(missing_err.is_cancelled());

    let single_start_err = scanner
        .start_hash(f1.to_string_lossy().into_owned())
        .expect_err("cancelled single-file start_hash must fail");
    assert!(single_start_err.is_cancelled());
    assert!(scanner.get_list().is_empty());

    let batch_err = scanner
        .hash_files(&files)
        .expect_err("cancelled hash_files must fail");
    assert!(batch_err.is_cancelled());
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);

    let single_err = scanner
        .hash_single_file(&f1)
        .expect_err("cancelled hash_single_file must fail");
    assert!(single_err.is_cancelled());
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);

    // Resetting the cancel flag re-arms the scanner cleanly
    scanner.reset_cancel();

    scanner
        .start_hash(dir_str)
        .expect("scan after reset_cancel must succeed");
    assert_eq!(scanner.get_list().len(), 3);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 3);

    scanner
        .hash_files(&files)
        .expect("hash_files after reset_cancel must succeed");
    assert_eq!(scanner.get_list().len(), 3);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), 3);

    let single_res = scanner
        .hash_single_file(&f1)
        .expect("hash_single_file after reset_cancel must succeed");
    assert_eq!(
        single_res.get_hash(),
        HashAlgorithm::Blake3.get_hash_from_bytes(b"alpha-cancel")
    );
}

#[test]
fn hash_manager_cancellable_methods_respect_flag_and_preserve_order() {
    let dir = TempDir::new("hash_manager_cancel");
    let subdir = dir.path().join("folder");
    fs::create_dir_all(&subdir).expect("create subdir");

    let f1 = dir.path().join("01_one.txt");
    let f2 = dir.path().join("02_two.bin");
    let missing = dir.path().join("03_missing.txt");
    let f3 = dir.path().join("04_three.txt");

    let chunked_payload: Vec<u8> = (0..(140 * 1024))
        .map(|i| ((i * 29 + 3) % 256) as u8)
        .collect();
    fs::write(&f1, b"first-item").expect("write f1");
    fs::write(&f2, &chunked_payload).expect("write f2");
    fs::write(&f3, b"third-item").expect("write f3");

    let inputs = vec![f1.clone(), f2.clone(), missing.clone(), subdir.clone(), f3.clone()];

    // Pre-cancelled flag aborts all HashManager cancellable entry points
    let cancelled_flag = AtomicBool::new(true);
    let mut mgr = HashManager::new(HashAlgorithm::Sha256);

    assert!(
        mgr.get_hash_code_cancellable(&f1, &cancelled_flag)
            .expect_err("expected ScanCancelled")
            .is_cancelled()
    );
    assert!(
        mgr.hash_single_file_cancellable(&f1, &cancelled_flag)
            .expect_err("expected ScanCancelled")
            .is_cancelled()
    );
    let empty_paths: Vec<PathBuf> = Vec::new();
    assert!(
        mgr.hash_files_cancellable(&empty_paths, &cancelled_flag)
            .expect_err("expected ScanCancelled for empty slice")
            .is_cancelled()
    );
    assert!(
        mgr.hash_files_cancellable(&inputs[..1], &cancelled_flag)
            .expect_err("expected ScanCancelled for single-file slice")
            .is_cancelled()
    );
    assert!(
        mgr.hash_files_cancellable(&inputs, &cancelled_flag)
            .expect_err("expected ScanCancelled for multi-file slice")
            .is_cancelled()
    );
    assert!(
        mgr.hash_files_with_threads_cancellable(&inputs, Some(1), &cancelled_flag)
            .expect_err("expected ScanCancelled for 1 thread")
            .is_cancelled()
    );
    assert!(
        mgr.hash_files_with_threads_cancellable(&inputs, Some(4), &cancelled_flag)
            .expect_err("expected ScanCancelled for 4 threads")
            .is_cancelled()
    );
    assert_eq!(mgr.get_files_counted(), 0);

    // Uncancelled flag produces exact hashes, preserves 1:1 order, and isolates per-file errors
    let active_flag = AtomicBool::new(false);

    let single_code = mgr
        .get_hash_code_cancellable(&f1, &active_flag)
        .expect("uncancelled get_hash_code_cancellable");
    assert_eq!(
        single_code,
        HashAlgorithm::Sha256.get_hash_from_bytes(b"first-item")
    );
    assert_eq!(mgr.get_files_counted(), 1);

    let single_meta = mgr
        .hash_single_file_cancellable(&f2, &active_flag)
        .expect("uncancelled hash_single_file_cancellable");
    assert_eq!(
        single_meta.get_hash(),
        HashAlgorithm::Sha256.get_hash_from_bytes(&chunked_payload)
    );
    assert_eq!(mgr.get_files_counted(), 2);

    mgr.reset_counter();
    let results = mgr
        .hash_files_with_threads_cancellable(&inputs, Some(3), &active_flag)
        .expect("uncancelled parallel hash_files_with_threads_cancellable");
    assert_eq!(results.len(), inputs.len());
    assert_eq!(mgr.get_files_counted(), 3);

    for (entry, expected_path) in results.iter().zip(&inputs) {
        assert_eq!(entry.get_path(), expected_path.to_string_lossy());
    }
    assert_eq!(
        results[0].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"first-item").as_str())
    );
    assert_eq!(
        results[1].get_result().as_deref().ok(),
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(&chunked_payload)
                .as_str()
        )
    );
    assert!(matches!(
        results[2].get_result(),
        Err(BulkHashError::FileNotFound(_))
    ));
    assert!(matches!(
        results[3].get_result(),
        Err(BulkHashError::NotAFile(_))
    ));
    assert_eq!(
        results[4].get_result().as_deref().ok(),
        Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"third-item").as_str())
    );
}

#[test]
fn live_concurrent_cancellation_stops_multithreaded_and_single_file_scans_promptly() {
    let dir = TempDir::new("live_cancel_scan");
    let mut large_files = Vec::new();

    // Create 4 x 1 GiB sparse files (0 disk blocks on sparse-capable filesystems) so SHA-512
    // takes several seconds if left running, while cancellation aborts within milliseconds.
    let sparse_len = 1024 * 1024 * 1024_u64;
    for idx in 0..4usize {
        let path = dir.path().join(format!("sparse_{idx}.bin"));
        let file = File::create(&path).expect("create sparse file");
        file.set_len(sparse_len).expect("set sparse file length");
        large_files.push(path);
    }

    // 1. Live cancellation of a multithreaded directory scan via start_hash
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(2);
        let token = scanner.get_cancel_token();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let dir_str = dir.path().to_string_lossy().into_owned();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.start_hash(dir_str);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(20));
        let cancelled_at = Instant::now();
        token.cancel();

        let (scanner, result) = handle.join().expect("worker thread must not panic");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(
            result.expect_err("parallel directory scan must be cancelled").is_cancelled()
        );
        assert!(
            shutdown_elapsed < Duration::from_secs(2),
            "parallel directory scan took too long to stop after cancel: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
    }

    // 2. Live mid-file cancellation of start_hash on a single large file
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512);
        let token = scanner.get_cancel_token();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let file_str = large_files[0].to_string_lossy().into_owned();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.start_hash(file_str);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(20));
        let cancelled_at = Instant::now();
        token.cancel();

        let (scanner, result) = handle.join().expect("worker thread must not panic");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(
            result.expect_err("single-file start_hash must be cancelled").is_cancelled()
        );
        assert!(
            shutdown_elapsed < Duration::from_secs(2),
            "single-file start_hash took too long to stop after cancel: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
    }

    // 3. Live mid-file cancellation of hash_single_file
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512);
        let token = scanner.get_cancel_token();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let file_path = large_files[0].clone();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.hash_single_file(&file_path);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(20));
        let cancelled_at = Instant::now();
        token.cancel();

        let (scanner, result) = handle.join().expect("worker thread must not panic");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(
            result.expect_err("hash_single_file must be cancelled").is_cancelled()
        );
        assert!(
            shutdown_elapsed < Duration::from_secs(2),
            "hash_single_file took too long to stop after cancel: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
    }

    // 4. Live cancellation of ScanManager::hash_files (both sequential and parallel)
    for thread_count in [1usize, 2usize] {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(thread_count);
        let token = scanner.get_cancel_token();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let files_clone = large_files.clone();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.hash_files(&files_clone);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(20));
        let cancelled_at = Instant::now();
        token.cancel();

        let (scanner, result) = handle.join().expect("worker thread must not panic");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(
            result
                .expect_err("hash_files must be cancelled")
                .is_cancelled(),
            "expected ScanCancelled for thread_count={thread_count}"
        );
        assert!(
            shutdown_elapsed < Duration::from_secs(2),
            "hash_files (threads={thread_count}) took too long to stop: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
    }
}

#[test]
fn scan_control_state_transitions_serialization_and_interop() {
    let control = ScanControl::new();
    let cloned = control.clone();

    assert_eq!(control.state(), ScanControlState::Running);
    assert_eq!(control.state().to_string(), "Running");
    assert!(!control.is_paused());
    assert!(!control.is_cancelled());
    assert_eq!(control.paused_thread_count(), 0);
    assert!(control.checkpoint().is_ok());

    // Pause is idempotent and shared across clones
    control.pause();
    assert!(control.is_paused());
    assert!(cloned.is_paused());
    assert_eq!(control.state(), ScanControlState::Paused);
    assert_eq!(control.state().to_string(), "Paused");
    control.pause();
    assert!(control.is_paused());

    // Resume is idempotent and restores Running state
    cloned.resume();
    assert!(!control.is_paused());
    assert!(!cloned.is_paused());
    assert_eq!(control.state(), ScanControlState::Running);
    control.resume();
    assert!(!control.is_paused());

    // Atomic toggle_pause flips cleanly between paused and running
    assert!(control.toggle_pause());
    assert!(cloned.is_paused());
    assert!(!cloned.toggle_pause());
    assert!(!control.is_paused());

    // Cancelled state takes precedence over paused state
    control.pause();
    assert_eq!(control.state(), ScanControlState::Paused);
    control.cancel();
    assert!(control.is_cancelled());
    assert!(control.is_paused());
    assert_eq!(control.state(), ScanControlState::Cancelled);
    assert_eq!(control.state().to_string(), "Cancelled");
    assert!(
        control
            .checkpoint()
            .expect_err("cancelled checkpoint must fail even when paused")
            .is_cancelled()
    );

    // GUI JSON serialization for ScanControlState
    assert_eq!(
        serde_json::to_value(ScanControlState::Running).expect("serialize Running"),
        "Running"
    );
    assert_eq!(
        serde_json::to_value(ScanControlState::Paused).expect("serialize Paused"),
        "Paused"
    );
    assert_eq!(
        serde_json::to_value(ScanControlState::Cancelled).expect("serialize Cancelled"),
        "Cancelled"
    );

    // reset_cancel clears only cancel; reset clears both cancel and pause
    control.reset_cancel();
    assert!(!control.is_cancelled());
    assert!(control.is_paused());
    assert_eq!(control.state(), ScanControlState::Paused);

    control.cancel();
    control.reset();
    assert!(!control.is_cancelled());
    assert!(!control.is_paused());
    assert_eq!(control.state(), ScanControlState::Running);
    assert!(control.checkpoint().is_ok());

    // ScanManager builder / setter / accessor interop
    let shared_control = ScanControl::new();
    let mut scanner =
        ScanManager::new(HashAlgorithm::Blake3).with_control(shared_control.clone());
    assert_eq!(scanner.get_control_state(), ScanControlState::Running);

    shared_control.pause();
    assert!(scanner.is_paused());
    assert_eq!(scanner.get_control_state(), ScanControlState::Paused);

    assert!(!scanner.toggle_pause());
    assert!(!shared_control.is_paused());

    scanner.pause();
    assert!(shared_control.is_paused());
    scanner.resume();
    assert!(!shared_control.is_paused());

    let replacement = ScanControl::new();
    scanner.set_control(replacement.clone());
    replacement.pause();
    assert!(scanner.is_paused());
    assert!(!shared_control.is_paused());

    scanner.cancel();
    assert!(replacement.is_cancelled());
    scanner.reset_control();
    assert_eq!(scanner.get_control_state(), ScanControlState::Running);
    assert_eq!(replacement.state(), ScanControlState::Running);
}

#[test]
fn pre_paused_scans_block_until_resumed_and_exclude_pause_from_hash_time() {
    let dir = TempDir::new("pre_pause_scan");
    let sub = dir.path().join("nested");
    fs::create_dir_all(&sub).expect("create nested dir");

    let f1 = dir.path().join("alpha.txt");
    let f2 = sub.join("beta.txt");
    let f3 = sub.join("gamma.txt");
    fs::write(&f1, b"alpha-pause-payload").expect("write alpha");
    fs::write(&f2, b"beta-pause-payload").expect("write beta");
    fs::write(&f3, b"gamma-pause-payload").expect("write gamma");

    let pause_hold = Duration::from_millis(120);
    let min_expected_pause = Duration::from_millis(80);
    let wait_timeout = Duration::from_secs(2);

    // 1. Pre-paused directory start_hash
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha256).with_thread_count(2);
        let control = scanner.get_control();
        control.pause();

        let dir_str = dir.path().to_string_lossy().into_owned();
        let handle = thread::spawn(move || {
            let result = scanner.start_hash(dir_str);
            (scanner, result)
        });

        assert!(
            control.wait_for_paused_threads(1, wait_timeout),
            "directory scan thread should park at initial pause checkpoint"
        );
        thread::sleep(pause_hold);
        assert!(
            !handle.is_finished(),
            "paused directory scan must not complete before resume"
        );

        control.resume();
        let (scanner, result) = handle.join().expect("directory scan thread panicked");
        result.expect("resumed directory scan must succeed");

        assert_eq!(scanner.get_list().len(), 3);
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 3);
        assert!(
            scanner.get_paused_time() >= min_expected_pause,
            "expected paused_time >= {min_expected_pause:?}, got {:?}",
            scanner.get_paused_time()
        );
        assert!(
            scanner.get_hash_time() < scanner.get_paused_time(),
            "active hash_time ({:?}) should exclude paused_time ({:?})",
            scanner.get_hash_time(),
            scanner.get_paused_time()
        );
    }

    // 2. Pre-paused single-file start_hash
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha256);
        let control = scanner.get_control();
        control.pause();

        let file_str = f1.to_string_lossy().into_owned();
        let handle = thread::spawn(move || {
            let result = scanner.start_hash(file_str);
            (scanner, result)
        });

        assert!(
            control.wait_for_paused_threads(1, wait_timeout),
            "single-file start_hash should park when pre-paused"
        );
        thread::sleep(pause_hold);
        assert!(!handle.is_finished());

        control.resume();
        let (scanner, result) = handle.join().expect("single-file start_hash thread panicked");
        result.expect("resumed single-file start_hash must succeed");

        assert_eq!(scanner.get_list().len(), 1);
        assert_eq!(
            scanner.get_list()[0].get_result().as_deref().ok(),
            Some(HashAlgorithm::Sha256.get_hash_from_bytes(b"alpha-pause-payload").as_str())
        );
        assert!(scanner.get_paused_time() >= min_expected_pause);
        assert!(scanner.get_hash_time() < scanner.get_paused_time());
    }

    // 3. Pre-paused ScanManager::hash_files
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(2);
        let control = scanner.get_control();
        control.pause();

        let files = vec![f1.clone(), f2.clone(), f3.clone()];
        let handle = thread::spawn(move || {
            let result = scanner.hash_files(&files);
            (scanner, result)
        });

        assert!(
            control.wait_for_paused_threads(1, wait_timeout),
            "hash_files should park when pre-paused"
        );
        thread::sleep(pause_hold);
        assert!(!handle.is_finished());

        control.resume();
        let (scanner, result) = handle.join().expect("hash_files thread panicked");
        result.expect("resumed hash_files must succeed");

        assert_eq!(scanner.get_list().len(), 3);
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 3);
        assert!(scanner.get_paused_time() >= min_expected_pause);
        assert!(scanner.get_hash_time() < scanner.get_paused_time());
    }

    // 4. Pre-paused ScanManager::hash_single_file
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
        let control = scanner.get_control();
        control.pause();

        let file_path = f2.clone();
        let handle = thread::spawn(move || {
            let result = scanner.hash_single_file(&file_path);
            (scanner, result)
        });

        assert!(
            control.wait_for_paused_threads(1, wait_timeout),
            "hash_single_file should park when pre-paused"
        );
        thread::sleep(pause_hold);
        assert!(!handle.is_finished());

        control.resume();
        let (scanner, result) = handle.join().expect("hash_single_file thread panicked");
        let single_hash = result.expect("resumed hash_single_file must succeed");

        assert_eq!(
            single_hash.get_hash(),
            HashAlgorithm::Blake3.get_hash_from_bytes(b"beta-pause-payload")
        );
        assert!(scanner.get_paused_time() >= min_expected_pause);
        assert!(
            single_hash.get_hash_time() < scanner.get_paused_time(),
            "SingleFileHash hash_time ({:?}) should exclude paused_time ({:?})",
            single_hash.get_hash_time(),
            scanner.get_paused_time()
        );
    }
}

#[test]
fn live_pause_and_resume_preserves_exact_hashes_across_multithreaded_and_single_file_scans() {
    let dir = TempDir::new("live_pause_resume");
    let nested = dir.path().join("sub");
    fs::create_dir_all(&nested).expect("create sub dir");

    // Build 4 deterministic non-zero multi-chunk files (4 MiB = 64 chunks each) so SHA-512 runs
    // long enough to pause mid-file and any offset/buffer corruption during pause/resume is
    // guaranteed to fail hash verification.
    let file_len = 4 * 1024 * 1024_usize;
    let mut paths = Vec::new();
    let mut expected_hashes = Vec::new();

    for idx in 0..4usize {
        let mut payload = vec![0u8; file_len];
        for (offset, byte) in payload.iter_mut().enumerate() {
            *byte = ((offset.wrapping_mul(31 + idx * 7) ^ (offset >> 8) ^ (idx * 53)) & 0xFF) as u8;
        }
        let path = if idx % 2 == 0 {
            dir.path().join(format!("chunked_{idx}.bin"))
        } else {
            nested.join(format!("chunked_{idx}.bin"))
        };
        fs::write(&path, &payload).expect("write deterministic file");
        expected_hashes.push(HashAlgorithm::Sha512.get_hash_from_bytes(&payload));
        paths.push(path);
    }

    let dir_str = dir.path().to_string_lossy().into_owned();

    // Unpaused baseline directory scan for exact tree comparison
    let mut baseline = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(2);
    baseline
        .start_hash(dir_str.clone())
        .expect("baseline scan should succeed");
    let baseline_tree = DirectoryNode::build_tree(baseline.get_path(), baseline.get_list());
    assert_eq!(baseline.get_paused_time(), Duration::ZERO);

    // 1. Live multi-cycle pause & resume on multithreaded directory scan
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(2);
        let control = scanner.get_control();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let dir_clone = dir_str.clone();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.start_hash(dir_clone);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(2));

        // First pause cycle
        control.pause();
        assert!(
            control.wait_for_paused_threads(1, Duration::from_secs(2)),
            "multithreaded directory scan must park at least one worker when paused"
        );
        thread::sleep(Duration::from_millis(80));
        assert!(
            !handle.is_finished(),
            "scan must remain suspended while paused"
        );
        control.resume();

        // Second pause cycle (if still running)
        thread::sleep(Duration::from_millis(2));
        control.pause();
        if control.wait_for_paused_threads(1, Duration::from_millis(150)) {
            thread::sleep(Duration::from_millis(50));
            assert!(!handle.is_finished());
        }
        control.resume();

        let (scanner, result) = handle.join().expect("paused directory scan panicked");
        result.expect("resumed directory scan must succeed");

        assert_eq!(scanner.get_list().len(), 4);
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 4);
        assert!(scanner.get_paused_time() >= Duration::from_millis(50));
        let resumed_tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
        assert_eq!(
            resumed_tree, baseline_tree,
            "resumed multithreaded directory scan must match unpaused baseline exactly"
        );
        assert_eq!(control.paused_thread_count(), 0);
    }

    // 2. Live mid-file pause & resume on hash_single_file
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512);
        let control = scanner.get_control();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let target_file = paths[0].clone();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.hash_single_file(&target_file);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(2));
        control.pause();
        assert!(
            control.wait_for_paused_threads(1, Duration::from_secs(2)),
            "single-file scan must park mid-file when paused"
        );
        thread::sleep(Duration::from_millis(80));
        assert!(!handle.is_finished());
        control.resume();

        let (scanner, result) = handle.join().expect("single-file pause thread panicked");
        let hashed = result.expect("resumed hash_single_file must succeed");
        assert_eq!(hashed.get_hash(), expected_hashes[0]);
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 1);
        assert!(scanner.get_paused_time() >= Duration::from_millis(50));
        assert_eq!(control.paused_thread_count(), 0);
    }

    // 3. Live pause & resume on ScanManager::hash_files (1 thread and 2 threads) preserving order
    for thread_count in [1usize, 2usize] {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(thread_count);
        let control = scanner.get_control();
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let files_clone = paths.clone();

        let handle = thread::spawn(move || {
            worker_barrier.wait();
            let result = scanner.hash_files(&files_clone);
            (scanner, result)
        });

        barrier.wait();
        thread::sleep(Duration::from_millis(2));
        control.pause();
        assert!(
            control.wait_for_paused_threads(1, Duration::from_secs(2)),
            "hash_files (threads={thread_count}) must park when paused"
        );
        thread::sleep(Duration::from_millis(70));
        assert!(!handle.is_finished());
        control.resume();

        let (scanner, result) = handle.join().expect("hash_files pause thread panicked");
        result.expect("resumed hash_files must succeed");

        assert_eq!(scanner.get_list().len(), paths.len());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), paths.len());
        assert!(scanner.get_paused_time() >= Duration::from_millis(40));
        for ((entry, expected_path), expected_hash) in scanner
            .get_list()
            .iter()
            .zip(&paths)
            .zip(&expected_hashes)
        {
            assert_eq!(entry.get_path(), expected_path.to_string_lossy());
            assert_eq!(
                entry.get_result().as_deref().ok(),
                Some(expected_hash.as_str()),
                "hash mismatch for thread_count={thread_count}"
            );
        }
    }
}

#[test]
fn hash_manager_controlled_methods_support_pause_resume_cancel_and_error_isolation() {
    let dir = TempDir::new("hash_manager_controlled");
    let subdir = dir.path().join("folder");
    fs::create_dir_all(&subdir).expect("create subdir");

    let f1 = dir.path().join("01_a.txt");
    let f2 = dir.path().join("02_b.bin");
    let missing = dir.path().join("03_missing.txt");
    let f3 = dir.path().join("04_c.txt");

    let payload_b: Vec<u8> = (0..(180 * 1024))
        .map(|i| ((i * 17 + 11) % 256) as u8)
        .collect();
    fs::write(&f1, b"controlled-a").expect("write f1");
    fs::write(&f2, &payload_b).expect("write f2");
    fs::write(&f3, b"controlled-c").expect("write f3");

    let inputs = vec![f1.clone(), f2.clone(), missing.clone(), subdir.clone(), f3.clone()];
    let control = ScanControl::new();

    // 1. Running control succeeds across all HashManager *_controlled methods
    let mut mgr = HashManager::new(HashAlgorithm::Sha256);
    let code = mgr
        .get_hash_code_controlled(&f1, &control)
        .expect("get_hash_code_controlled");
    assert_eq!(
        code,
        HashAlgorithm::Sha256.get_hash_from_bytes(b"controlled-a")
    );

    let single = mgr
        .hash_single_file_controlled(&f2, &control)
        .expect("hash_single_file_controlled");
    assert_eq!(
        single.get_hash(),
        HashAlgorithm::Sha256.get_hash_from_bytes(&payload_b)
    );

    mgr.reset_counter();
    let results = mgr
        .hash_files_controlled(&inputs, &control)
        .expect("hash_files_controlled");
    assert_eq!(results.len(), inputs.len());
    assert_eq!(mgr.get_files_counted(), 3);
    assert!(matches!(
        results[2].get_result(),
        Err(BulkHashError::FileNotFound(_))
    ));
    assert!(matches!(
        results[3].get_result(),
        Err(BulkHashError::NotAFile(_))
    ));

    // 2. Pre-paused HashManager::hash_files_with_threads_controlled resumes cleanly
    control.pause();
    let worker_control = control.clone();
    let worker_inputs = inputs.clone();
    let handle = thread::spawn(move || {
        let mut worker_mgr = HashManager::new(HashAlgorithm::Blake3);
        let res = worker_mgr.hash_files_with_threads_controlled(
            &worker_inputs,
            Some(2),
            &worker_control,
        );
        (worker_mgr, res)
    });

    assert!(control.wait_for_paused_threads(1, Duration::from_secs(2)));
    thread::sleep(Duration::from_millis(60));
    assert!(!handle.is_finished());
    control.resume();

    let (worker_mgr, res) = handle.join().expect("controlled worker thread panicked");
    let batch = res.expect("resumed controlled batch must succeed");
    assert_eq!(batch.len(), inputs.len());
    assert_eq!(worker_mgr.get_files_counted(), 3);
    assert_eq!(
        batch[0].get_result().as_deref().ok(),
        Some(HashAlgorithm::Blake3.get_hash_from_bytes(b"controlled-a").as_str())
    );
    assert_eq!(
        batch[1].get_result().as_deref().ok(),
        Some(HashAlgorithm::Blake3.get_hash_from_bytes(&payload_b).as_str())
    );
    assert_eq!(
        batch[4].get_result().as_deref().ok(),
        Some(HashAlgorithm::Blake3.get_hash_from_bytes(b"controlled-c").as_str())
    );

    // 3. Cancelled control aborts immediately (even on empty slice)
    control.cancel();
    let empty_paths: Vec<PathBuf> = Vec::new();
    assert!(
        mgr.get_hash_code_controlled(&f1, &control)
            .expect_err("expected ScanCancelled")
            .is_cancelled()
    );
    assert!(
        mgr.hash_single_file_controlled(&f1, &control)
            .expect_err("expected ScanCancelled")
            .is_cancelled()
    );
    assert!(
        mgr.hash_files_controlled(&empty_paths, &control)
            .expect_err("expected ScanCancelled")
            .is_cancelled()
    );
}

#[test]
fn cancelling_a_paused_scan_wakes_workers_immediately_across_all_cancel_paths() {
    let dir = TempDir::new("cancel_while_paused");
    let mut sparse_files = Vec::new();
    let sparse_len = 1024 * 1024 * 1024_u64;

    for idx in 0..4usize {
        let path = dir.path().join(format!("sparse_{idx}.bin"));
        let file = File::create(&path).expect("create sparse file");
        file.set_len(sparse_len).expect("set sparse file length");
        sparse_files.push(path);
    }

    let dir_str = dir.path().to_string_lossy().into_owned();

    // 1. Cancel a paused multithreaded scan via ScanControl::cancel()
    {
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512).with_thread_count(2);
        let control = scanner.get_control();
        let dir_clone = dir_str.clone();

        let handle = thread::spawn(move || {
            let result = scanner.start_hash(dir_clone);
            (scanner, result)
        });

        thread::sleep(Duration::from_millis(15));
        control.pause();
        assert!(
            control.wait_for_paused_threads(2, Duration::from_secs(2)),
            "both worker threads should park while paused"
        );

        let cancelled_at = Instant::now();
        control.cancel();

        let (mut scanner, result) = handle.join().expect("worker thread panicked");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(
            result
                .expect_err("cancelling paused scan must return ScanCancelled")
                .is_cancelled()
        );
        assert!(
            shutdown_elapsed < Duration::from_secs(1),
            "cancelling paused scan via ScanControl took too long: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
        assert_eq!(scanner.get_hash_time(), Duration::ZERO);
        assert_eq!(scanner.get_paused_time(), Duration::ZERO);
        assert_eq!(control.paused_thread_count(), 0);

        // Recovery after reset_control()
        scanner.reset_control();
        assert_eq!(scanner.get_control_state(), ScanControlState::Running);
        let small_dir = TempDir::new("recover_after_paused_cancel");
        let small_file = small_dir.path().join("ok.txt");
        fs::write(&small_file, b"recovered").expect("write ok.txt");
        scanner
            .start_hash(small_dir.path().to_string_lossy().into_owned())
            .expect("scan after reset_control must succeed");
        assert_eq!(scanner.get_list().len(), 1);
    }

    // 2. Cancel a paused scan via externally supplied ScanCancelToken::cancel()
    {
        let cancel_token = ScanCancelToken::new();
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512)
            .with_thread_count(2)
            .with_cancel_token(cancel_token.clone());
        let control = scanner.get_control();
        let files_clone = sparse_files.clone();

        let handle = thread::spawn(move || {
            let result = scanner.hash_files(&files_clone);
            (scanner, result)
        });

        thread::sleep(Duration::from_millis(15));
        control.pause();
        assert!(
            control.wait_for_paused_threads(2, Duration::from_secs(2)),
            "both hash_files workers should park while paused"
        );

        let cancelled_at = Instant::now();
        cancel_token.cancel();

        let (scanner, result) = handle.join().expect("hash_files thread panicked");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(result.expect_err("expected ScanCancelled").is_cancelled());
        assert!(
            shutdown_elapsed < Duration::from_secs(1),
            "cancelling paused scan via ScanCancelToken took too long: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(control.paused_thread_count(), 0);
    }

    // 3. Cancel a paused single-file scan via raw Arc<AtomicBool> (bypassing token methods)
    {
        let raw_flag = Arc::new(AtomicBool::new(false));
        let mut scanner = ScanManager::new(HashAlgorithm::Sha512)
            .with_cancel_token(Arc::clone(&raw_flag));
        let control = scanner.get_control();
        let file_path = sparse_files[0].clone();

        let handle = thread::spawn(move || {
            let result = scanner.hash_single_file(&file_path);
            (scanner, result)
        });

        thread::sleep(Duration::from_millis(15));
        control.pause();
        assert!(
            control.wait_for_paused_threads(1, Duration::from_secs(2)),
            "single-file scan should park while paused"
        );

        let cancelled_at = Instant::now();
        raw_flag.store(true, Ordering::Release);

        let (scanner, result) = handle.join().expect("single-file thread panicked");
        let shutdown_elapsed = cancelled_at.elapsed();

        assert!(result.expect_err("expected ScanCancelled").is_cancelled());
        assert!(
            shutdown_elapsed < Duration::from_secs(1),
            "cancelling paused scan via raw AtomicBool took too long: {shutdown_elapsed:?}"
        );
        assert!(scanner.get_list().is_empty());
        assert_eq!(scanner.get_hash_manager().get_files_counted(), 0);
        assert_eq!(control.paused_thread_count(), 0);
    }
}

#[test]
fn pause_and_resume_during_deep_directory_traversal_discovers_all_files() {
    let dir = TempDir::new("deep_traversal_pause");
    let mut expected_count = 0usize;

    for folder_idx in 0..40usize {
        let sub = dir
            .path()
            .join(format!("group_{:02}", folder_idx / 8))
            .join(format!("leaf_{folder_idx:02}"));
        fs::create_dir_all(&sub).expect("create nested leaf dir");
        for file_idx in 0..5usize {
            let file_path = sub.join(format!("file_{file_idx}.txt"));
            fs::write(&file_path, format!("payload-{folder_idx}-{file_idx}"))
                .expect("write leaf file");
            expected_count += 1;
        }
    }

    let dir_str = dir.path().to_string_lossy().into_owned();

    let mut baseline = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(2);
    baseline
        .start_hash(dir_str.clone())
        .expect("baseline deep scan");
    let baseline_tree = DirectoryNode::build_tree(baseline.get_path(), baseline.get_list());
    assert_eq!(baseline.get_list().len(), expected_count);

    let mut scanner = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(2);
    let control = scanner.get_control();
    control.pause();

    let handle = thread::spawn(move || {
        let result = scanner.start_hash(dir_str);
        (scanner, result)
    });

    assert!(control.wait_for_paused_threads(1, Duration::from_secs(2)));
    thread::sleep(Duration::from_millis(40));
    control.resume();

    // Pause briefly mid-traversal/mid-scan and resume
    thread::sleep(Duration::from_millis(2));
    control.pause();
    thread::sleep(Duration::from_millis(40));
    control.resume();

    let (scanner, result) = handle.join().expect("deep traversal thread panicked");
    result.expect("resumed deep directory scan must succeed");

    assert_eq!(scanner.get_list().len(), expected_count);
    assert_eq!(scanner.get_hash_manager().get_files_counted(), expected_count);
    let resumed_tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    assert_eq!(resumed_tree, baseline_tree);
    assert!(scanner.get_paused_time() >= Duration::from_millis(40));
}

#[test]
fn scan_manager_default_ignore_list_skips_nothing_except_mandatory_system_paths() {
    assert!(IgnoreList::new().is_empty());
    assert!(IgnoreList::default().is_empty());
    assert_eq!(IgnoreList::new().len(), 0);
    assert!(IgnoreList::new().patterns().is_empty());

    let dir = TempDir::new("ignore_default_empty");
    let git_dir = dir.path().join(".git");
    let nm_dir = dir.path().join("node_modules").join("pkg");
    let target_dir = dir.path().join("target").join("debug");
    fs::create_dir_all(&git_dir).expect("create .git");
    fs::create_dir_all(&nm_dir).expect("create node_modules");
    fs::create_dir_all(&target_dir).expect("create target");

    // Even when a .gitignore file exists in the scanned directory, nothing is skipped by default.
    let expected_files = vec![
        git_dir.join("config"),
        dir.path().join(".gitignore"),
        nm_dir.join("index.js"),
        target_dir.join("app.bin"),
        dir.path().join("app.log"),
        dir.path().join(".hidden_file"),
        dir.path().join("normal.txt"),
    ];

    fs::write(&expected_files[0], b"[core]\n\trepositoryformatversion = 0\n").expect("write");
    fs::write(&expected_files[1], b"node_modules/\n*.log\ntarget/\n").expect("write .gitignore");
    fs::write(&expected_files[2], b"module.exports = {};").expect("write");
    fs::write(&expected_files[3], b"\x7fELF").expect("write");
    fs::write(&expected_files[4], b"log entry").expect("write");
    fs::write(&expected_files[5], b"dotfile content").expect("write");
    fs::write(&expected_files[6], b"hello").expect("write");

    let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
    assert!(scanner.get_ignore_list().is_empty());
    assert_eq!(scanner.get_ignored_count(), 0);

    scanner
        .start_hash(dir.path().to_string_lossy().into_owned())
        .expect("default scan should succeed");

    assert_eq!(scanner.get_list().len(), expected_files.len());
    assert_eq!(
        scanner.get_hash_manager().get_files_counted(),
        expected_files.len()
    );
    assert_eq!(scanner.get_ignored_count(), 0);

    for path in &expected_files {
        let path_str = path.to_string_lossy();
        assert!(
            scanner
                .get_list()
                .iter()
                .any(|entry| entry.get_path() == path_str && entry.get_result().is_ok()),
            "default scan must include {path_str}"
        );
    }

    // Mandatory OS paths (such as /dev on Linux) are always skipped even with empty or negated ignore lists.
    #[cfg(target_os = "linux")]
    if Path::new("/dev").exists() {
        let mut dev_scanner = ScanManager::new(HashAlgorithm::Blake3);
        dev_scanner
            .start_hash(String::from("/dev"))
            .expect("/dev scan should skip safely");
        assert!(dev_scanner.get_list().is_empty());
        assert_eq!(dev_scanner.get_ignored_count(), 0);

        let mut negated_scanner = ScanManager::new(HashAlgorithm::Blake3)
            .with_ignore_patterns(["!/dev", "!*"])
            .expect("valid negation patterns");
        negated_scanner
            .start_hash(String::from("/dev"))
            .expect("mandatory system path /dev must not be un-ignored");
        assert!(negated_scanner.get_list().is_empty());
        assert_eq!(negated_scanner.get_ignored_count(), 0);
    }
}

#[test]
fn ignore_list_glob_syntax_anchoring_negation_and_case_sensitivity() {
    let list = IgnoreList::from_patterns([
        "node_modules",
        ".git/",
        "/dist",
        "./cache/",
        "docs/*.md",
        "src/**/*.tmp",
        "a/**/b",
        "foo/**",
        "logs/*",
        "!logs/keep.log",
        "*.log",
        "!important.log",
        "temp_?.bin",
        "part_[0-9].dat",
        "tag_[!0-9].txt",
        r"\#hash.txt",
        r"\!bang.txt",
        r"trail\   ",
        r"star\*lit.txt",
    ])
    .expect("compile comprehensive pattern list");

    // Unanchored basename match (files and directories, plus children via ancestor check)
    assert!(list.is_ignored("node_modules", true));
    assert!(list.is_ignored("node_modules", false));
    assert!(list.is_ignored("apps/web/node_modules", true));
    assert!(list.is_ignored("apps/web/node_modules/pkg/index.js", false));
    assert!(!list.is_ignored("my_node_modules", true));

    // Directory-only pattern
    assert!(list.is_ignored(".git", true));
    assert!(list.is_ignored("sub/.git/HEAD", false));
    assert!(!list.is_ignored(".git", false));

    // Root-anchored patterns (`/dist` and `./cache/`)
    assert!(list.is_ignored("dist", true));
    assert!(list.is_ignored("dist/app.js", false));
    assert!(!list.is_ignored("packages/web/dist", true));
    assert!(!list.is_ignored("packages/web/dist/app.js", false));
    assert!(list.is_ignored("cache", true));
    assert!(list.is_ignored("cache/item.bin", false));
    assert!(!list.is_ignored("cache", false));
    assert!(!list.is_ignored("nested/cache", true));

    // Mid-slash anchored pattern (`docs/*.md`)
    assert!(list.is_ignored("docs/readme.md", false));
    assert!(!list.is_ignored("docs/sub/readme.md", false));
    assert!(!list.is_ignored("other/docs/readme.md", false));

    // Double-star recursive patterns
    assert!(list.is_ignored("src/a.tmp", false));
    assert!(list.is_ignored("src/x/y/z/a.tmp", false));
    assert!(!list.is_ignored("other/src/a.tmp", false));
    assert!(list.is_ignored("a/b", false));
    assert!(list.is_ignored("a/x/b", false));
    assert!(list.is_ignored("a/x/y/b", false));
    assert!(!list.is_ignored("x/a/b", false));

    // Trailing `/**` matches everything *inside* `foo`, not `foo` itself
    assert!(!list.is_ignored("foo", true));
    assert!(list.is_ignored("foo/bar.txt", false));
    assert!(list.is_ignored("foo/sub/deep.txt", false));

    // Negation rules (last match wins)
    assert!(list.is_ignored("app.log", false));
    assert!(list.is_ignored("sub/app.log", false));
    assert!(!list.is_ignored("important.log", false));
    assert!(!list.is_ignored("sub/important.log", false));
    assert!(!list.is_ignored("logs", true));
    assert!(list.is_ignored("logs/drop.txt", false));
    assert!(list.is_ignored("logs/drop.log", false));
    // Note: `logs/keep.log` matches `logs/*` (ignored), `!logs/keep.log` (un-ignored),
    // then `*.log` (ignored again because last rule wins!).
    assert!(list.is_ignored("logs/keep.log", false));

    // Wildcards `?`, character classes, and escaped literals
    assert!(list.is_ignored("temp_1.bin", false));
    assert!(list.is_ignored("sub/temp_a.bin", false));
    assert!(!list.is_ignored("temp_12.bin", false));
    assert!(list.is_ignored("part_5.dat", false));
    assert!(!list.is_ignored("part_x.dat", false));
    assert!(list.is_ignored("tag_a.txt", false));
    assert!(!list.is_ignored("tag_7.txt", false));
    assert!(list.is_ignored("#hash.txt", false));
    assert!(list.is_ignored("!bang.txt", false));
    assert!(list.is_ignored("trail ", false));
    assert!(!list.is_ignored("trail", false));
    assert!(list.is_ignored("star*lit.txt", false));
    assert!(!list.is_ignored("starXYZlit.txt", false));

    // Re-including nested entries inside `logs/**` + allowlist pattern `*` + `!*/` + `!*.rs`
    let allowlist = IgnoreList::from_patterns(["*", "!*/", "!*.rs"]).expect("allowlist");
    assert!(!allowlist.is_ignored("src", true));
    assert!(!allowlist.is_ignored("src/main.rs", false));
    assert!(allowlist.is_ignored("src/readme.txt", false));
    assert!(allowlist.is_ignored("notes.md", false));

    // Excluded parent directory cannot have children re-included (gitignore semantics)
    let pruned_parent =
        IgnoreList::from_patterns(["build/", "!build/keep.bin"]).expect("pruned parent");
    assert!(pruned_parent.is_ignored("build", true));
    assert!(pruned_parent.is_ignored("build/keep.bin", false));

    // Re-enabling the directory itself works
    let reenabled = IgnoreList::from_patterns(["build/", "!build/"]).expect("reenabled dir");
    assert!(!reenabled.is_ignored("build", true));
    assert!(!reenabled.is_ignored("build/keep.bin", false));

    // Case-sensitive by default vs opt-in case-insensitive (including Unicode & ranges)
    let mut ci = IgnoreList::from_patterns(["*.log", "[a-z]_item.txt", "[A-Z]_cap.txt", "äpfel.*"])
        .expect("case sensitivity list");
    assert!(!ci.is_case_insensitive());
    assert!(ci.is_ignored("debug.log", false));
    assert!(!ci.is_ignored("DEBUG.LOG", false));
    assert!(!ci.is_ignored("K_item.txt", false));
    assert!(!ci.is_ignored("k_cap.txt", false));
    assert!(!ci.is_ignored("Äpfel.txt", false));

    ci.set_case_insensitive(true);
    assert!(ci.is_case_insensitive());
    assert!(ci.is_ignored("DEBUG.LOG", false));
    assert!(ci.is_ignored("App.Log", false));
    assert!(ci.is_ignored("K_item.txt", false));
    assert!(ci.is_ignored("k_cap.txt", false));
    assert!(ci.is_ignored("Äpfel.txt", false));

    // `is_ignored_under` and `extend_from` and `clear`
    assert!(list.is_ignored_under("/workspace/proj", "/workspace/proj/dist/out.js", false));
    assert!(!list.is_ignored_under(
        "/workspace/proj",
        "/workspace/proj/packages/dist/out.js",
        false
    ));

    let mut merged = IgnoreList::new();
    merged.extend_from(&allowlist);
    assert_eq!(merged.len(), 3);
    merged.clear();
    assert!(merged.is_empty());
}

#[test]
fn ignore_list_validation_file_loading_and_serde() {
    // Invalid syntax patterns produce BulkHashError::InvalidIgnorePattern
    let invalid_patterns = ["!", "/", "///", "./", "[abc", "[]", "[!]", "[z-a]", r"bad\"];
    for bad in invalid_patterns {
        let err = IgnoreList::from_patterns([bad])
            .expect_err(&format!("expected InvalidIgnorePattern for {bad:?}"));
        assert!(
            matches!(err, BulkHashError::InvalidIgnorePattern { .. }),
            "unexpected error for {bad:?}: {err:?}"
        );
        assert_eq!(err.kind(), "InvalidIgnorePattern");
        let json = serde_json::to_value(&err).expect("serialize error");
        assert_eq!(json["kind"], "InvalidIgnorePattern");
    }

    // Atomic batch updates: existing list stays intact when any pattern fails validation
    let mut atomic = IgnoreList::from_patterns(["*.tmp"]).expect("valid initial");
    assert!(atomic.add_patterns(["*.log", "[unclosed"]).is_err());
    assert_eq!(atomic.patterns(), &[String::from("*.tmp")]);
    assert!(!atomic.is_ignored("debug.log", false));
    assert!(atomic.is_ignored("scratch.tmp", false));

    // Parsing text with BOM, CRLF, comments, blank lines, and FromStr
    let text = "\u{feff}# Comment line\r\n\r\n   \r\nnode_modules/   \r\n*.log\r\n!keep.log\r\n";
    let parsed: IgnoreList = text.parse().expect("parse ignore text");
    assert_eq!(
        parsed.patterns(),
        &[
            String::from("node_modules/"),
            String::from("*.log"),
            String::from("!keep.log"),
        ]
    );
    assert!(parsed.is_ignored("node_modules/a.js", false));
    assert!(parsed.is_ignored("error.log", false));
    assert!(!parsed.is_ignored("keep.log", false));

    // Only comments and whitespace produce an empty IgnoreList
    let comments_only = IgnoreList::parse("# just a comment\n\n   \t  \n").expect("comments only");
    assert!(comments_only.is_empty());

    // Loading from file + error cases
    let dir = TempDir::new("ignore_file_loading");
    let ignore_file = dir.path().join(".bulkhashignore");
    fs::write(&ignore_file, text).expect("write ignore file");
    let from_file = IgnoreList::from_file(&ignore_file).expect("load ignore file");
    assert_eq!(from_file, parsed);

    let missing_err =
        IgnoreList::from_file(dir.path().join("missing.ignore")).expect_err("FileNotFound");
    assert!(matches!(missing_err, BulkHashError::FileNotFound(_)));

    let dir_err = IgnoreList::from_file(dir.path()).expect_err("NotAFile");
    assert!(matches!(dir_err, BulkHashError::NotAFile(_)));

    let bad_utf8 = dir.path().join("binary.ignore");
    fs::write(&bad_utf8, [0xffu8, 0xfe, 0x00, 0x80]).expect("write invalid utf8");
    let utf8_err = IgnoreList::from_file(&bad_utf8).expect_err("invalid UTF-8");
    assert!(matches!(utf8_err, BulkHashError::Io { .. }));

    // Serde JSON roundtrip + invalid deserialization rejection
    let configured = IgnoreList::from_patterns(["node_modules", "*.bak"])
        .expect("valid list")
        .with_case_insensitive(true);
    let json = serde_json::to_value(&configured).expect("serialize IgnoreList");
    assert_eq!(json["case_insensitive"], true);
    assert_eq!(json["patterns"], serde_json::json!(["node_modules", "*.bak"]));

    let restored: IgnoreList = serde_json::from_value(json).expect("deserialize IgnoreList");
    assert_eq!(restored, configured);
    assert!(restored.is_ignored("FILE.BAK", false));
    assert!(restored.is_ignored("NODE_MODULES/a.js", false));

    let bad_json = serde_json::json!({
        "patterns": ["*.log", "[unclosed"],
        "case_insensitive": false
    });
    assert!(serde_json::from_value::<IgnoreList>(bad_json).is_err());
}

#[test]
fn scan_manager_ignore_list_directory_pruning_and_snapshot_roundtrip() {
    let dir = TempDir::new("ignore_scan_e2e");
    let root = dir.path();

    fs::create_dir_all(root.join("src")).expect("create src");
    fs::create_dir_all(root.join("node_modules/pkg/deep")).expect("create node_modules");
    fs::create_dir_all(root.join(".git/objects/ab")).expect("create .git");
    fs::create_dir_all(root.join("dist")).expect("create root dist");
    fs::create_dir_all(root.join("packages/web/dist")).expect("create nested dist");
    fs::create_dir_all(root.join("logs")).expect("create logs");
    fs::create_dir_all(root.join("sub/build")).expect("create sub/build dir");

    let expected_included = vec![
        root.join("src/main.rs"),
        root.join("src/lib.rs"),
        root.join("packages/web/dist/keep.js"),
        root.join("logs/important.log"),
        root.join("build"), // regular FILE named `build` must NOT be ignored by `build/`
        root.join("readme.md"),
    ];

    fs::write(&expected_included[0], b"fn main() {}").expect("write");
    fs::write(&expected_included[1], b"pub fn lib() {}").expect("write");
    fs::write(&expected_included[2], b"console.log('keep');").expect("write");
    fs::write(&expected_included[3], b"critical log").expect("write");
    fs::write(&expected_included[4], b"build script file").expect("write");
    fs::write(&expected_included[5], b"# Readme").expect("write");

    // Ignored files and directories
    fs::write(root.join("src/debug.log"), b"debug").expect("write");
    fs::write(root.join("node_modules/pkg/index.js"), b"nm1").expect("write");
    fs::write(root.join("node_modules/pkg/deep/a.js"), b"nm2").expect("write");
    fs::write(root.join(".git/HEAD"), b"ref: refs/heads/main").expect("write");
    fs::write(root.join(".git/objects/ab/cd"), b"gitobj").expect("write");
    fs::write(root.join("dist/bundle.js"), b"root dist").expect("write");
    fs::write(root.join("logs/error.log"), b"err log").expect("write");
    fs::write(root.join("sub/build/artifact.o"), b"obj").expect("write");

    let patterns = [
        "node_modules",
        ".git/",
        "/dist",
        "build/",
        "*.log",
        "!important.log",
    ];
    let root_str = root.to_string_lossy().into_owned();

    let mut single_threaded = ScanManager::new(HashAlgorithm::Blake3)
        .with_thread_count(1)
        .with_ignore_patterns(patterns)
        .expect("valid patterns");
    single_threaded
        .start_hash(root_str.clone())
        .expect("single-threaded ignored scan");

    let mut parallel = ScanManager::new(HashAlgorithm::Blake3)
        .with_thread_count(4)
        .with_ignore_patterns(patterns)
        .expect("valid patterns");
    parallel
        .start_hash(root_str.clone())
        .expect("parallel ignored scan");

    assert_eq!(single_threaded.get_list().len(), expected_included.len());
    assert_eq!(parallel.get_list().len(), expected_included.len());
    assert_eq!(
        parallel.get_hash_manager().get_files_counted(),
        expected_included.len()
    );
    // 4 pruned directories (node_modules, .git, /dist, sub/build) + 2 ignored files (src/debug.log, logs/error.log)
    assert_eq!(single_threaded.get_ignored_count(), 6);
    assert_eq!(parallel.get_ignored_count(), 6);

    let tree_single = DirectoryNode::build_tree(single_threaded.get_path(), single_threaded.get_list());
    let tree_parallel = DirectoryNode::build_tree(parallel.get_path(), parallel.get_list());
    assert_eq!(tree_parallel, tree_single);

    for path in &expected_included {
        let path_str = path.to_string_lossy();
        assert!(
            parallel
                .get_list()
                .iter()
                .any(|entry| entry.get_path() == path_str && entry.get_result().is_ok()),
            "expected included file missing: {path_str}"
        );
    }

    // Verify ignored directory pruning prevents reading unreadable directories (non-root Unix check)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let locked_dir = root.join("locked_cache");
        fs::create_dir_all(&locked_dir).expect("create locked_cache");
        fs::write(locked_dir.join("secret.bin"), b"secret").expect("write secret");
        fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o000))
            .expect("chmod 000 locked_cache");

        // Only assert pruning skips permission error when the OS actually enforces chmod 000
        let enforces_chmod = fs::read_dir(&locked_dir).is_err();
        if enforces_chmod {
            let mut pruned_scan = ScanManager::new(HashAlgorithm::Blake3)
                .with_ignore_patterns(patterns)
                .expect("patterns");
            pruned_scan
                .add_ignore_pattern("locked_cache/")
                .expect("add locked_cache");
            pruned_scan
                .start_hash(root_str.clone())
                .expect("scan with pruned unreadable dir");

            assert_eq!(pruned_scan.get_list().len(), expected_included.len());
            assert!(pruned_scan.get_list().iter().all(|f| f.get_result().is_ok()));
            assert_eq!(pruned_scan.get_ignored_count(), 7);
        }

        // Restore permissions so TempDir cleanup succeeds cleanly
        let _ = fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&locked_dir);
    }

    // Single-file start_hash honors ignore list, while hash_single_file always hashes explicitly chosen file
    let log_file = root.join("logs/error.log");
    parallel
        .start_hash(log_file.to_string_lossy().into_owned())
        .expect("single-file start_hash with ignore list");
    assert!(parallel.get_list().is_empty());
    assert_eq!(parallel.get_ignored_count(), 1);

    let single_res = parallel
        .hash_single_file(&log_file)
        .expect("hash_single_file must hash explicitly chosen file");
    assert_eq!(single_res.get_file_name(), "error.log");
    assert_eq!(parallel.get_ignored_count(), 0);

    // Batch `hash_files` respects ignore list and resets `ignored_count` after clearing
    let batch_inputs = vec![
        root.join("src/main.rs"),
        root.join("logs/error.log"),
        root.join("node_modules/pkg/index.js"),
        root.join("logs/important.log"),
    ];
    parallel
        .hash_files(&batch_inputs)
        .expect("hash_files with ignore list");
    assert_eq!(parallel.get_list().len(), 2);
    assert_eq!(parallel.get_ignored_count(), 2);

    parallel.clear_ignore_list();
    assert!(parallel.get_ignore_list().is_empty());
    parallel
        .hash_files(&batch_inputs)
        .expect("hash_files after clearing ignore list");
    assert_eq!(parallel.get_list().len(), 4);
    assert_eq!(parallel.get_ignored_count(), 0);

    // Cancelled scan with ignore list leaves ignored_count and file_list clean
    let mut cancelled_scan = ScanManager::new(HashAlgorithm::Blake3)
        .with_ignore_patterns(patterns)
        .expect("patterns");
    cancelled_scan.cancel();
    let cancel_err = cancelled_scan
        .start_hash(root_str.clone())
        .expect_err("expected ScanCancelled");
    assert!(cancel_err.is_cancelled());
    assert!(cancelled_scan.get_list().is_empty());
    assert_eq!(cancelled_scan.get_ignored_count(), 0);

    // Snapshot MetaData roundtrip preserves non-empty IgnoreList and omits empty IgnoreList
    let output_dir = TempDir::new("ignore_snapshot_out");
    let ignore_cfg = IgnoreList::from_patterns(patterns)
        .expect("patterns")
        .with_case_insensitive(true);
    let meta_with_ignore = MetaData::new(
        single_threaded.get_hash_manager().get_files_counted(),
        single_threaded.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(HashAlgorithm::Blake3)
    .with_ignore_list(ignore_cfg.clone());

    let saved =
        FileManager::save_file(output_dir.path(), &tree_single, &meta_with_ignore).expect("save");
    let loaded = FileManager::open_file(&saved).expect("open");
    assert_eq!(loaded.get_meta().get_ignore_list(), Some(&ignore_cfg));

    let meta_empty_ignore =
        MetaData::new(0, Duration::ZERO, Utc::now()).with_ignore_list(IgnoreList::new());
    assert_eq!(meta_empty_ignore.get_ignore_list(), None);
    let meta_json = serde_json::to_value(&meta_empty_ignore).expect("serialize meta");
    assert!(meta_json.get("ignore_list").is_none());
}
