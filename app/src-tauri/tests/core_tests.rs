use bulk_hash_lib::core::{
    hash_manager::{HashAlgorithm, HashManager},
    hidden_filter::{
        HiddenFileFilter, has_os_hidden_attribute, has_os_system_attribute, is_dotfile_name,
        is_known_system_name,
    },
    ignore_list::IgnoreList,
    io::{
        bulk_hash_error::BulkHashError,
        directory_node::{DirectoryNode, FileEntry},
        encryption::{
            ENCRYPTED_TREE_ENTRY, EncryptionCipher, EncryptionOptions, KdfParams,
            KeyDerivationAlgorithm, MAX_KDF_ITERATIONS, MAX_KDF_MEMORY_KIB, MAX_KDF_PARALLELISM,
            MIN_KDF_MEMORY_KIB, PayloadCompression, build_tree_aad, decrypt_tree_payload,
            encrypt_tree_payload, prepare_encryption_metadata,
        },
        file_manager::FileManager,
        meta_data::MetaData,
        migration::{
            CURRENT_FORMAT_VERSION, FORMAT_VERSION_V1, FORMAT_VERSION_V2, FORMAT_VERSION_V3,
            FormatMigration, MIN_SUPPORTED_FORMAT_VERSION, MigrationRegistry, SnapshotPayload,
            VersionCompatibility,
        },
    },
    scan_manager::{ScanCancelToken, ScanControl, ScanControlState, ScanManager},
    structs::{
        file_info::FileInfo,
        file_metadata::{FileMetadata, system_time_to_utc},
    },
};
use chrono::{DateTime, Timelike, Utc};
use std::ffi::OsStr;
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
    assert!(tree.files.get("top.txt").is_some_and(FileEntry::is_err));

    let sub = tree
        .sub_directories
        .get("sub")
        .expect("sub directory must exist directly under root");
    assert_eq!(
        sub.files.get("file:with:colons.txt"),
        Some(&FileEntry::from_result(Ok(String::from("abc123"))))
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
    assert_eq!(loaded.get_meta().get_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(loaded.get_meta().get_migrated_from(), None);
    assert!(!loaded.was_migrated());
    assert_eq!(loaded.get_original_version(), CURRENT_FORMAT_VERSION);
    assert!(loaded.get_migration().is_none());
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
    let loaded_entry = loaded
        .get_tree()
        .files
        .get("archive.bin")
        .expect("archive.bin entry must exist");
    assert_eq!(loaded_entry.hash(), Some(result.get_hash()));
    assert_eq!(loaded_entry.size(), Some(payload.len() as u64));
    assert_eq!(loaded_entry.modified_utc(), result.get_modified_utc());
    assert!(loaded_entry.modified_utc().is_some());
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
        assert_eq!(
            digest.len(),
            algo.hex_len(),
            "unexpected hex length for {algo}"
        );
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
    assert_eq!(
        loaded.get_meta().get_algorithm(),
        Some(HashAlgorithm::XxHash128)
    );
    let data_entry = loaded
        .get_tree()
        .files
        .get("data.bin")
        .expect("data.bin entry must exist");
    assert_eq!(
        data_entry.hash(),
        Some(
            HashAlgorithm::XxHash128
                .get_hash_from_bytes(b"fast xxhash snapshot test")
                .as_str()
        )
    );
    assert_eq!(
        data_entry.size(),
        Some(b"fast xxhash snapshot test".len() as u64)
    );
    assert!(data_entry.modified_utc().is_some());
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
        let payload =
            format!("parallel-file-payload-{idx:03}-{}", "x".repeat(idx * 37)).into_bytes();
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

        assert_eq!(
            single.get_hash_manager().get_files_counted(),
            expected_count
        );
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
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(b"alpha-parallel")
                .as_str()
        )
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
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(b"alpha-parallel")
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
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(&large_payload)
                .as_str()
        )
    );
    assert_eq!(
        results[5].get_result().as_deref().ok(),
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(b"beta-parallel")
                .as_str()
        )
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

    let inputs = vec![
        f1.clone(),
        f2.clone(),
        missing.clone(),
        subdir.clone(),
        f3.clone(),
    ];

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
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(b"first-item")
                .as_str()
        )
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
        Some(
            HashAlgorithm::Sha256
                .get_hash_from_bytes(b"third-item")
                .as_str()
        )
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
            result
                .expect_err("parallel directory scan must be cancelled")
                .is_cancelled()
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
            result
                .expect_err("single-file start_hash must be cancelled")
                .is_cancelled()
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
            result
                .expect_err("hash_single_file must be cancelled")
                .is_cancelled()
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
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3).with_control(shared_control.clone());
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
        let (scanner, result) = handle
            .join()
            .expect("single-file start_hash thread panicked");
        result.expect("resumed single-file start_hash must succeed");

        assert_eq!(scanner.get_list().len(), 1);
        assert_eq!(
            scanner.get_list()[0].get_result().as_deref().ok(),
            Some(
                HashAlgorithm::Sha256
                    .get_hash_from_bytes(b"alpha-pause-payload")
                    .as_str()
            )
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
        for ((entry, expected_path), expected_hash) in
            scanner.get_list().iter().zip(&paths).zip(&expected_hashes)
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

    let inputs = vec![
        f1.clone(),
        f2.clone(),
        missing.clone(),
        subdir.clone(),
        f3.clone(),
    ];
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
        let res =
            worker_mgr.hash_files_with_threads_controlled(&worker_inputs, Some(2), &worker_control);
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
        Some(
            HashAlgorithm::Blake3
                .get_hash_from_bytes(b"controlled-a")
                .as_str()
        )
    );
    assert_eq!(
        batch[1].get_result().as_deref().ok(),
        Some(
            HashAlgorithm::Blake3
                .get_hash_from_bytes(&payload_b)
                .as_str()
        )
    );
    assert_eq!(
        batch[4].get_result().as_deref().ok(),
        Some(
            HashAlgorithm::Blake3
                .get_hash_from_bytes(b"controlled-c")
                .as_str()
        )
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
        let mut scanner =
            ScanManager::new(HashAlgorithm::Sha512).with_cancel_token(Arc::clone(&raw_flag));
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
    assert_eq!(
        scanner.get_hash_manager().get_files_counted(),
        expected_count
    );
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

    fs::write(
        &expected_files[0],
        b"[core]\n\trepositoryformatversion = 0\n",
    )
    .expect("write");
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
    assert_eq!(
        json["patterns"],
        serde_json::json!(["node_modules", "*.bak"])
    );

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

    let tree_single =
        DirectoryNode::build_tree(single_threaded.get_path(), single_threaded.get_list());
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
            assert!(
                pruned_scan
                    .get_list()
                    .iter()
                    .all(|f| f.get_result().is_ok())
            );
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

#[test]
fn hidden_file_filter_presets_builders_matching_and_serde() {
    // Default / include_all includes everything
    let default_filter = HiddenFileFilter::default();
    assert_eq!(default_filter, HiddenFileFilter::new());
    assert_eq!(default_filter, HiddenFileFilter::include_all());
    assert!(default_filter.includes_all());
    assert!(!default_filter.is_active());
    assert!(!default_filter.excludes_all());
    assert!(!default_filter.excludes_dotfiles());
    assert!(!default_filter.excludes_os_hidden());
    assert!(!default_filter.excludes_system_files());

    // Presets
    let all = HiddenFileFilter::exclude_all();
    assert!(all.is_active());
    assert!(all.excludes_all());
    assert!(!all.includes_all());
    assert!(all.excludes_dotfiles());
    assert!(all.excludes_os_hidden());
    assert!(all.excludes_system_files());

    let hidden_only = HiddenFileFilter::exclude_hidden();
    assert!(hidden_only.is_active());
    assert!(!hidden_only.excludes_all());
    assert!(hidden_only.excludes_dotfiles());
    assert!(hidden_only.excludes_os_hidden());
    assert!(!hidden_only.excludes_system_files());

    let dotfiles_only = HiddenFileFilter::exclude_dotfiles();
    assert!(dotfiles_only.is_active());
    assert!(dotfiles_only.excludes_dotfiles());
    assert!(!dotfiles_only.excludes_os_hidden());
    assert!(!dotfiles_only.excludes_system_files());

    let system_only = HiddenFileFilter::exclude_system_files();
    assert!(system_only.is_active());
    assert!(!system_only.excludes_dotfiles());
    assert!(!system_only.excludes_os_hidden());
    assert!(system_only.excludes_system_files());

    // Builders and mutable setters
    let mut custom = HiddenFileFilter::new()
        .with_exclude_dotfiles(true)
        .with_exclude_os_hidden(false)
        .with_exclude_system_files(true);
    assert!(custom.excludes_dotfiles());
    assert!(!custom.excludes_os_hidden());
    assert!(custom.excludes_system_files());

    custom.set_exclude_dotfiles(false);
    custom.set_exclude_os_hidden(true);
    custom.set_exclude_system_files(false);
    assert!(!custom.excludes_dotfiles());
    assert!(custom.excludes_os_hidden());
    assert!(!custom.excludes_system_files());

    // Dotfile name detection (including edge cases `.`, `..`, `..weird`, non-UTF-8 on Unix)
    assert!(is_dotfile_name(OsStr::new(".env")));
    assert!(is_dotfile_name(OsStr::new(".git")));
    assert!(is_dotfile_name(OsStr::new(".DS_Store")));
    assert!(is_dotfile_name(OsStr::new("..hidden")));
    assert!(!is_dotfile_name(OsStr::new(".")));
    assert!(!is_dotfile_name(OsStr::new("..")));
    assert!(!is_dotfile_name(OsStr::new("")));
    assert!(!is_dotfile_name(OsStr::new("normal.txt")));
    assert!(!is_dotfile_name(OsStr::new("archive.tar.gz")));

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        assert!(is_dotfile_name(OsStr::from_bytes(b".\xffhidden")));
        assert!(!is_dotfile_name(OsStr::from_bytes(b"visible\xff")));
        assert!(!is_known_system_name(OsStr::from_bytes(b"thumbs.db\xff")));
    }

    // Known OS system/metadata entry names (case-insensitive ASCII)
    for name in [
        "desktop.ini",
        "DESKTOP.INI",
        "Thumbs.db",
        "thumbs.db",
        "ehthumbs.db",
        "ehthumbs_vista.db",
        "$RECYCLE.BIN",
        "System Volume Information",
        "pagefile.sys",
        "hiberfil.sys",
        "swapfile.sys",
        "NTUSER.DAT",
        ".DS_Store",
        ".AppleDouble",
        ".Spotlight-V100",
        ".Trashes",
        ".fseventsd",
        ".TemporaryItems",
        "lost+found",
        ".Trash",
        ".Trash-1000",
    ] {
        assert!(
            is_known_system_name(OsStr::new(name)),
            "expected system name match for {name:?}"
        );
    }

    for name in [
        "normal.txt",
        ".env",
        ".gitignore",
        ".git",
        "my_thumbs.db",
        ".Trash-",
        ".Trash-abc",
        "recycler",
    ] {
        assert!(
            !is_known_system_name(OsStr::new(name)),
            "did not expect system name match for {name:?}"
        );
    }

    // Path-based helpers: is_hidden_entry, is_hidden_path, is_hidden_under
    assert!(!default_filter.is_hidden_entry("/workspace/.env"));
    assert!(!default_filter.is_hidden_path("/workspace/.git/HEAD"));
    assert!(!default_filter.is_hidden_under("/workspace", "/workspace/.env"));

    assert!(dotfiles_only.is_hidden_entry("/workspace/.env"));
    assert!(!dotfiles_only.is_hidden_entry("/workspace/.git/HEAD"));
    assert!(!dotfiles_only.is_hidden_entry("/workspace/Thumbs.db"));
    assert!(dotfiles_only.is_hidden_path(".git/HEAD"));
    assert!(dotfiles_only.is_hidden_path("./.env"));
    assert!(dotfiles_only.is_hidden_path("../.secret/key"));
    assert!(!dotfiles_only.is_hidden_path("./src/main.rs"));
    assert!(!dotfiles_only.is_hidden_path("../docs/readme.md"));
    assert!(!dotfiles_only.is_hidden_path("sub/Thumbs.db"));

    assert!(system_only.is_hidden_entry("/workspace/Thumbs.db"));
    assert!(system_only.is_hidden_entry("/workspace/.DS_Store"));
    assert!(!system_only.is_hidden_entry("/workspace/.env"));
    assert!(system_only.is_hidden_path("sub/desktop.ini"));
    assert!(system_only.is_hidden_path("$RECYCLE.BIN/deleted.txt"));
    assert!(system_only.is_hidden_path("lost+found/node"));
    assert!(system_only.is_hidden_path(".Trash-1000/item.txt"));
    assert!(!system_only.is_hidden_path(".git/HEAD"));
    assert!(!system_only.is_hidden_path(".env"));

    // Hidden directories *above* scan root must never exclude visible entries inside root
    assert!(!all.is_hidden_under(
        "/home/user/.config/myapp",
        "/home/user/.config/myapp/settings.toml"
    ));
    assert!(!all.is_hidden_under("/home/user/.config/myapp", "/home/user/.config/myapp"));
    assert!(all.is_hidden_under(
        "/home/user/.config/myapp",
        "/home/user/.config/myapp/.cache/blob.bin"
    ));
    assert!(all.is_hidden_under(
        "/home/user/.config/myapp",
        "/home/user/.config/myapp/sub/Thumbs.db"
    ));

    // OS attribute helpers on a normal file return false on Linux/non-attributed files
    let dir = TempDir::new("hidden_attr_check");
    let regular = dir.path().join("regular.txt");
    fs::write(&regular, b"hello").expect("write regular file");
    let regular_meta = fs::symlink_metadata(&regular).expect("metadata");
    assert!(!has_os_hidden_attribute(&regular_meta));
    assert!(!has_os_system_attribute(&regular_meta));

    // Serde JSON roundtrip and partial deserialization with defaults
    let json = serde_json::to_value(all).expect("serialize HiddenFileFilter");
    assert_eq!(json["exclude_dotfiles"], true);
    assert_eq!(json["exclude_os_hidden"], true);
    assert_eq!(json["exclude_system_files"], true);
    let restored: HiddenFileFilter = serde_json::from_value(json).expect("deserialize");
    assert_eq!(restored, all);

    let partial: HiddenFileFilter =
        serde_json::from_value(serde_json::json!({ "exclude_dotfiles": true }))
            .expect("deserialize partial");
    assert_eq!(partial, HiddenFileFilter::exclude_dotfiles());

    let empty_obj: HiddenFileFilter =
        serde_json::from_value(serde_json::json!({})).expect("deserialize empty object");
    assert_eq!(empty_obj, HiddenFileFilter::include_all());
}

#[test]
fn scan_manager_hidden_file_filter_modes_pruning_and_root_inside_hidden_dir() {
    let dir = TempDir::new("hidden_filter_modes");
    let root = dir.path();

    fs::create_dir_all(root.join("src")).expect("create src");
    fs::create_dir_all(root.join("docs")).expect("create docs");
    fs::create_dir_all(root.join(".git/objects/ab")).expect("create .git");
    fs::create_dir_all(root.join("sub/.hidden_sub")).expect("create sub/.hidden_sub");
    fs::create_dir_all(root.join("System Volume Information")).expect("create SVI");
    fs::create_dir_all(root.join("lost+found")).expect("create lost+found");
    fs::create_dir_all(root.join(".Trash-1000")).expect("create .Trash-1000");

    let normal_files = vec![
        root.join("src/main.rs"),
        root.join("docs/readme.md"),
        root.join("normal.txt"),
    ];
    let user_dot_files = vec![
        root.join(".env"),
        root.join(".gitignore"),
        root.join(".git/HEAD"),
        root.join(".git/objects/ab/cd"),
        root.join("sub/.hidden_sub/nested.txt"),
        root.join("sub/.dot_in_sub"),
    ];
    let non_dot_system_files = vec![
        root.join("Thumbs.db"),
        root.join("sub/desktop.ini"),
        root.join("System Volume Information/WPSettings.dat"),
        root.join("lost+found/orphan.bin"),
    ];
    let dot_system_files = vec![root.join(".DS_Store"), root.join(".Trash-1000/deleted.txt")];

    for path in normal_files
        .iter()
        .chain(&user_dot_files)
        .chain(&non_dot_system_files)
        .chain(&dot_system_files)
    {
        fs::write(path, path.to_string_lossy().as_bytes()).expect("write fixture file");
    }

    let total_files = normal_files.len()
        + user_dot_files.len()
        + non_dot_system_files.len()
        + dot_system_files.len();
    let root_str = root.to_string_lossy().into_owned();

    // 1. Default ScanManager includes all hidden & system files
    let mut default_scan = ScanManager::new(HashAlgorithm::Blake3);
    assert!(default_scan.includes_hidden());
    assert_eq!(
        default_scan.get_hidden_filter(),
        HiddenFileFilter::include_all()
    );
    assert_eq!(default_scan.get_hidden_skipped_count(), 0);
    default_scan
        .start_hash(root_str.clone())
        .expect("default scan");
    assert_eq!(default_scan.get_list().len(), total_files);
    assert_eq!(default_scan.get_hidden_skipped_count(), 0);

    // 2. Exclude all hidden & system files (single-threaded and parallel must match identically)
    let mut single_exclude = ScanManager::new(HashAlgorithm::Blake3)
        .with_thread_count(1)
        .with_include_hidden(false);
    assert!(!single_exclude.includes_hidden());
    assert_eq!(
        single_exclude.get_hidden_filter(),
        HiddenFileFilter::exclude_all()
    );
    single_exclude
        .start_hash(root_str.clone())
        .expect("single-threaded exclude-all scan");

    let mut parallel_exclude = ScanManager::new(HashAlgorithm::Blake3)
        .with_thread_count(4)
        .with_hidden_filter(HiddenFileFilter::exclude_all());
    parallel_exclude
        .start_hash(root_str.clone())
        .expect("parallel exclude-all scan");

    assert_eq!(single_exclude.get_list().len(), normal_files.len());
    assert_eq!(parallel_exclude.get_list().len(), normal_files.len());
    assert_eq!(
        parallel_exclude.get_hash_manager().get_files_counted(),
        normal_files.len()
    );
    // Skipped entries:
    // Top-level: .env, .gitignore, .git (pruned dir), Thumbs.db, System Volume Information (pruned dir),
    //            lost+found (pruned dir), .DS_Store, .Trash-1000 (pruned dir) = 8
    // Under sub/: .hidden_sub (pruned dir), .dot_in_sub, desktop.ini = 3
    // Total = 11
    assert_eq!(single_exclude.get_hidden_skipped_count(), 11);
    assert_eq!(parallel_exclude.get_hidden_skipped_count(), 11);

    let tree_single =
        DirectoryNode::build_tree(single_exclude.get_path(), single_exclude.get_list());
    let tree_parallel =
        DirectoryNode::build_tree(parallel_exclude.get_path(), parallel_exclude.get_list());
    assert_eq!(tree_parallel, tree_single);

    for path in &normal_files {
        let path_str = path.to_string_lossy();
        assert!(
            parallel_exclude
                .get_list()
                .iter()
                .any(|entry| entry.get_path() == path_str && entry.get_result().is_ok()),
            "missing expected normal file: {path_str}"
        );
    }

    // 3. Exclude dotfiles only: skips dotfiles & dot-system entries, keeps non-dot system files
    let mut dot_only_scan = ScanManager::new(HashAlgorithm::Blake3)
        .with_hidden_filter(HiddenFileFilter::exclude_dotfiles());
    dot_only_scan
        .start_hash(root_str.clone())
        .expect("dotfiles-only scan");
    assert_eq!(
        dot_only_scan.get_list().len(),
        normal_files.len() + non_dot_system_files.len()
    );
    // Skipped: .env, .gitignore, .git (dir), .DS_Store, .Trash-1000 (dir), sub/.hidden_sub (dir), sub/.dot_in_sub = 7
    assert_eq!(dot_only_scan.get_hidden_skipped_count(), 7);
    for path in normal_files.iter().chain(&non_dot_system_files) {
        let path_str = path.to_string_lossy();
        assert!(
            dot_only_scan
                .get_list()
                .iter()
                .any(|entry| entry.get_path() == path_str && entry.get_result().is_ok()),
            "expected file missing in dotfiles-only scan: {path_str}"
        );
    }

    // 4. Exclude system files only: skips OS metadata files, keeps user dotfiles
    let mut sys_only_scan = ScanManager::new(HashAlgorithm::Blake3)
        .with_hidden_filter(HiddenFileFilter::exclude_system_files());
    sys_only_scan
        .start_hash(root_str.clone())
        .expect("system-files-only scan");
    assert_eq!(
        sys_only_scan.get_list().len(),
        normal_files.len() + user_dot_files.len()
    );
    // Skipped: Thumbs.db, sub/desktop.ini, System Volume Information (dir), lost+found (dir), .DS_Store, .Trash-1000 (dir) = 6
    assert_eq!(sys_only_scan.get_hidden_skipped_count(), 6);
    for path in normal_files.iter().chain(&user_dot_files) {
        let path_str = path.to_string_lossy();
        assert!(
            sys_only_scan
                .get_list()
                .iter()
                .any(|entry| entry.get_path() == path_str && entry.get_result().is_ok()),
            "expected file missing in system-files-only scan: {path_str}"
        );
    }

    // 5. Explicitly scanning a directory inside a hidden parent (or a hidden directory itself)
    //    must still scan non-hidden files underneath it while filtering hidden children.
    let hidden_parent_root = root.join(".config_parent/myapp");
    fs::create_dir_all(hidden_parent_root.join(".cache")).expect("create .cache");
    let visible_in_hidden_parent = hidden_parent_root.join("settings.toml");
    fs::write(&visible_in_hidden_parent, b"theme = 'dark'").expect("write settings");
    fs::write(hidden_parent_root.join(".secret"), b"token").expect("write .secret");
    fs::write(hidden_parent_root.join(".cache/data.bin"), b"cached").expect("write cached");

    let mut nested_root_scan = ScanManager::new(HashAlgorithm::Blake3).with_include_hidden(false);
    nested_root_scan
        .start_hash(hidden_parent_root.to_string_lossy().into_owned())
        .expect("scan root under hidden parent");
    assert_eq!(nested_root_scan.get_list().len(), 1);
    assert_eq!(
        nested_root_scan.get_list()[0].get_path(),
        visible_in_hidden_parent.to_string_lossy()
    );
    assert_eq!(nested_root_scan.get_hidden_skipped_count(), 2);

    let hidden_self_root = root.join(".hidden_root_dir");
    fs::create_dir_all(hidden_self_root.join(".inner")).expect("create .inner");
    let visible_in_hidden_root = hidden_self_root.join("keep.txt");
    fs::write(&visible_in_hidden_root, b"keep").expect("write keep");
    fs::write(hidden_self_root.join(".inner/drop.txt"), b"drop").expect("write drop");

    nested_root_scan
        .start_hash(hidden_self_root.to_string_lossy().into_owned())
        .expect("scan hidden root dir");
    assert_eq!(nested_root_scan.get_list().len(), 1);
    assert_eq!(
        nested_root_scan.get_list()[0].get_path(),
        visible_in_hidden_root.to_string_lossy()
    );
    assert_eq!(nested_root_scan.get_hidden_skipped_count(), 1);

    // 6. Early pruning of hidden directories prevents reading unreadable hidden folders on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let locked_hidden = root.join(".locked_hidden");
        fs::create_dir_all(&locked_hidden).expect("create .locked_hidden");
        fs::write(locked_hidden.join("secret.bin"), b"secret").expect("write secret");
        fs::set_permissions(&locked_hidden, fs::Permissions::from_mode(0o000))
            .expect("chmod 000 .locked_hidden");

        if fs::read_dir(&locked_hidden).is_err() {
            let mut pruned = ScanManager::new(HashAlgorithm::Blake3).with_include_hidden(false);
            pruned
                .start_hash(root_str.clone())
                .expect("pruned unreadable hidden dir scan");
            assert_eq!(pruned.get_list().len(), normal_files.len());
            assert!(pruned.get_list().iter().all(|f| f.get_result().is_ok()));
            // Original 11 + .config_parent + .hidden_root_dir + .locked_hidden = 14
            assert_eq!(pruned.get_hidden_skipped_count(), 14);
        }

        let _ = fs::set_permissions(&locked_hidden, fs::Permissions::from_mode(0o755));
        let _ = fs::remove_dir_all(&locked_hidden);
    }
}

#[test]
fn scan_manager_hidden_filter_combined_with_ignore_list_single_file_batch_and_snapshot() {
    let dir = TempDir::new("hidden_combined_e2e");
    let root = dir.path();

    fs::create_dir_all(root.join("src")).expect("create src");
    fs::create_dir_all(root.join("node_modules/pkg")).expect("create node_modules");
    fs::create_dir_all(root.join(".git")).expect("create .git");
    fs::create_dir_all(root.join(".config")).expect("create .config");

    let keep_file = root.join("src/main.rs");
    let ignored_log = root.join("src/debug.log");
    let ignored_nm = root.join("node_modules/pkg/index.js");
    let hidden_env = root.join(".env");
    let hidden_log = root.join(".hidden.log");
    let hidden_git_head = root.join(".git/HEAD");
    let system_thumbs = root.join("Thumbs.db");
    let visible_under_dot_dir = root.join(".config/visible.txt");

    fs::write(&keep_file, b"fn main() {}").expect("write");
    fs::write(&ignored_log, b"debug").expect("write");
    fs::write(&ignored_nm, b"module.exports = {};").expect("write");
    fs::write(&hidden_env, b"SECRET=1").expect("write");
    fs::write(&hidden_log, b"hidden log").expect("write");
    fs::write(&hidden_git_head, b"ref: refs/heads/main").expect("write");
    fs::write(&system_thumbs, b"thumbs").expect("write");
    fs::write(&visible_under_dot_dir, b"visible file").expect("write");

    let root_str = root.to_string_lossy().into_owned();
    let mut scanner = ScanManager::new(HashAlgorithm::Blake3)
        .with_include_hidden(false)
        .with_ignore_patterns(["node_modules/", "*.log"])
        .expect("valid ignore patterns");

    scanner
        .start_hash(root_str.clone())
        .expect("combined scan should succeed");

    assert_eq!(scanner.get_list().len(), 1);
    assert_eq!(
        scanner.get_list()[0].get_path(),
        keep_file.to_string_lossy()
    );
    // Hidden filter runs first: .env, .hidden.log, .git (dir), .config (dir), Thumbs.db = 5
    assert_eq!(scanner.get_hidden_skipped_count(), 5);
    // Ignore list skips: node_modules (dir), src/debug.log = 2
    assert_eq!(scanner.get_ignored_count(), 2);

    // Single-file start_hash respects HiddenFileFilter on the leaf file only
    scanner
        .start_hash(hidden_env.to_string_lossy().into_owned())
        .expect("single-file hidden start_hash");
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hidden_skipped_count(), 1);
    assert_eq!(scanner.get_ignored_count(), 0);

    scanner
        .start_hash(system_thumbs.to_string_lossy().into_owned())
        .expect("single-file system start_hash");
    assert!(scanner.get_list().is_empty());
    assert_eq!(scanner.get_hidden_skipped_count(), 1);

    // Visible file inside a hidden parent directory is NOT excluded by single-file start_hash
    scanner
        .start_hash(visible_under_dot_dir.to_string_lossy().into_owned())
        .expect("visible leaf inside hidden parent");
    assert_eq!(scanner.get_list().len(), 1);
    assert_eq!(scanner.get_hidden_skipped_count(), 0);

    // Explicit hash_single_file always hashes the chosen file even when hidden
    let single_res = scanner
        .hash_single_file(&hidden_env)
        .expect("hash_single_file must hash explicitly chosen hidden file");
    assert_eq!(single_res.get_file_name(), ".env");
    assert_eq!(scanner.get_hidden_skipped_count(), 0);

    // Batch hash_files applies HiddenFileFilter + IgnoreList and resets counts on re-enable
    let batch_inputs = vec![
        keep_file.clone(),
        hidden_env.clone(),
        hidden_git_head.clone(),
        system_thumbs.clone(),
        ignored_log.clone(),
    ];
    scanner
        .hash_files(&batch_inputs)
        .expect("hash_files with hidden + ignore filters");
    assert_eq!(scanner.get_list().len(), 1);
    assert_eq!(
        scanner.get_list()[0].get_path(),
        keep_file.to_string_lossy()
    );
    assert_eq!(scanner.get_hidden_skipped_count(), 3);
    assert_eq!(scanner.get_ignored_count(), 1);

    scanner.set_include_hidden(true);
    scanner.clear_ignore_list();
    assert!(scanner.includes_hidden());
    scanner
        .hash_files(&batch_inputs)
        .expect("hash_files after re-enabling hidden and clearing ignore list");
    assert_eq!(scanner.get_list().len(), batch_inputs.len());
    assert_eq!(scanner.get_hidden_skipped_count(), 0);
    assert_eq!(scanner.get_ignored_count(), 0);

    // Mutable hidden filter accessor works cleanly
    scanner.get_hidden_filter_mut().set_exclude_dotfiles(true);
    assert!(!scanner.includes_hidden());
    assert_eq!(
        scanner.get_hidden_filter(),
        HiddenFileFilter::exclude_dotfiles()
    );

    // Cancelled scan leaves hidden_skipped_count clean at 0
    let mut cancelled = ScanManager::new(HashAlgorithm::Blake3).with_include_hidden(false);
    cancelled.cancel();
    let cancel_err = cancelled
        .start_hash(root_str)
        .expect_err("expected ScanCancelled");
    assert!(cancel_err.is_cancelled());
    assert!(cancelled.get_list().is_empty());
    assert_eq!(cancelled.get_hidden_skipped_count(), 0);

    // Snapshot MetaData roundtrip preserves active HiddenFileFilter and omits inactive filter
    let output_dir = TempDir::new("hidden_snapshot_out");
    let tree = DirectoryNode::new(String::from("/project"));
    let active_filter = HiddenFileFilter::exclude_all();
    let meta_with_filter = MetaData::new(1, Duration::from_millis(12), Utc::now())
        .with_algorithm(HashAlgorithm::Blake3)
        .with_hidden_filter(active_filter);

    let saved =
        FileManager::save_file(output_dir.path(), &tree, &meta_with_filter).expect("save snapshot");
    let loaded = FileManager::open_file(&saved).expect("open snapshot");
    assert_eq!(loaded.get_meta().get_hidden_filter(), Some(active_filter));

    let meta_inactive = MetaData::new(0, Duration::ZERO, Utc::now())
        .with_hidden_filter(HiddenFileFilter::include_all());
    assert_eq!(meta_inactive.get_hidden_filter(), None);
    let meta_json = serde_json::to_value(&meta_inactive).expect("serialize inactive meta");
    assert!(meta_json.get("hidden_filter").is_none());
}

#[test]
fn file_metadata_and_system_time_conversion_handle_epoch_subseconds_and_pre_1970() {
    let empty = FileMetadata::empty();
    assert!(empty.is_empty());
    assert_eq!(empty, FileMetadata::default());
    assert_eq!(empty.size(), None);
    assert_eq!(empty.modified_utc(), None);
    let empty_json = serde_json::to_value(empty).expect("serialize empty FileMetadata");
    assert_eq!(empty_json, serde_json::json!({}));

    let ts_ns = DateTime::from_timestamp(1_732_745_043, 123_456_789).expect("valid timestamp");
    let zero_sized = FileMetadata::empty().with_size(0).with_modified_utc(ts_ns);
    assert!(!zero_sized.is_empty());
    assert_eq!(zero_sized.size(), Some(0));
    assert_eq!(zero_sized.modified_utc(), Some(ts_ns));
    let zero_json = serde_json::to_value(zero_sized).expect("serialize zero-sized FileMetadata");
    assert_eq!(zero_json["size"], 0);
    assert!(zero_json["modified_utc"].is_string());
    let roundtripped: FileMetadata =
        serde_json::from_value(zero_json).expect("deserialize FileMetadata");
    assert_eq!(roundtripped, zero_sized);
    assert_eq!(
        roundtripped.modified_utc().map(|dt| dt.nanosecond()),
        Some(123_456_789)
    );

    // UNIX_EPOCH exact conversion
    assert_eq!(
        system_time_to_utc(UNIX_EPOCH),
        DateTime::from_timestamp(0, 0)
    );

    // Post-epoch with subsecond nanoseconds
    let post = UNIX_EPOCH + Duration::new(1_700_000_000, 987_654_321);
    assert_eq!(
        system_time_to_utc(post),
        DateTime::from_timestamp(1_700_000_000, 987_654_321)
    );

    // Pre-1970 whole seconds: 1969-12-31T23:59:58Z
    if let Some(pre_whole) = UNIX_EPOCH.checked_sub(Duration::from_secs(2)) {
        assert_eq!(
            system_time_to_utc(pre_whole),
            DateTime::from_timestamp(-2, 0)
        );
    }

    // Pre-1970 sub-second (< 1s before epoch): 1969-12-31T23:59:59.750000000Z
    if let Some(pre_frac) = UNIX_EPOCH.checked_sub(Duration::from_millis(250)) {
        assert_eq!(
            system_time_to_utc(pre_frac),
            DateTime::from_timestamp(-1, 750_000_000)
        );
    }

    // Pre-1970 whole + sub-second (2.25s before epoch): 1969-12-31T23:59:57.750000000Z
    if let Some(pre_mixed) = UNIX_EPOCH.checked_sub(Duration::new(2, 250_000_000)) {
        assert_eq!(
            system_time_to_utc(pre_mixed),
            DateTime::from_timestamp(-3, 750_000_000)
        );
    }
}

#[test]
fn file_entry_serde_supports_extended_format_legacy_v1_and_rejects_invalid_json() {
    let ts = DateTime::from_timestamp(1_764_280_000, 500_000_123).expect("valid timestamp");

    // 1. Extended hash entry with size + modified_utc
    let ok_entry = FileEntry::from_hash(String::from("deadbeef"), Some(1024), Some(ts));
    assert!(ok_entry.is_ok());
    assert!(!ok_entry.is_err());
    assert_eq!(ok_entry.hash(), Some("deadbeef"));
    assert_eq!(ok_entry.error(), None);
    assert_eq!(ok_entry.size(), Some(1024));
    assert_eq!(ok_entry.modified_utc(), Some(ts));
    assert_eq!(ok_entry.metadata(), FileMetadata::new(Some(1024), Some(ts)));

    let ok_json = serde_json::to_value(&ok_entry).expect("serialize ok FileEntry");
    assert_eq!(ok_json["hash"], "deadbeef");
    assert_eq!(ok_json["size"], 1024);
    assert!(ok_json["modified_utc"].is_string());
    assert!(ok_json.get("error").is_none());
    assert!(ok_json.get("Ok").is_none());
    let ok_back: FileEntry = serde_json::from_value(ok_json).expect("deserialize ok FileEntry");
    assert_eq!(ok_back, ok_entry);

    // 2. Zero-byte file preserves explicit size=0 and omits absent modified_utc
    let zero_entry = FileEntry::from_hash(String::from("emptyhash"), Some(0), None);
    let zero_json = serde_json::to_value(&zero_entry).expect("serialize zero FileEntry");
    assert_eq!(
        zero_json,
        serde_json::json!({"hash": "emptyhash", "size": 0})
    );
    let zero_back: FileEntry = serde_json::from_value(zero_json).expect("deserialize zero entry");
    assert_eq!(zero_back, zero_entry);

    // 3. Error entry with preserved metadata
    let err_entry = FileEntry::from_error(
        String::from("Permission denied: /secret"),
        Some(512),
        Some(ts),
    );
    assert!(err_entry.is_err());
    assert_eq!(err_entry.hash(), None);
    assert_eq!(err_entry.error(), Some("Permission denied: /secret"));
    let err_json = serde_json::to_value(&err_entry).expect("serialize err FileEntry");
    assert_eq!(err_json["error"], "Permission denied: /secret");
    assert_eq!(err_json["size"], 512);
    assert!(err_json.get("hash").is_none());
    let err_back: FileEntry = serde_json::from_value(err_json).expect("deserialize err FileEntry");
    assert_eq!(err_back, err_entry);

    // 4. Legacy v1 Result<String, String> JSON format ("Ok" / "Err")
    let legacy_ok: FileEntry =
        serde_json::from_str(r#"{"Ok":"cafebabe"}"#).expect("deserialize legacy Ok");
    assert_eq!(
        legacy_ok,
        FileEntry::from_result(Ok(String::from("cafebabe")))
    );
    assert_eq!(legacy_ok.size(), None);
    assert_eq!(legacy_ok.modified_utc(), None);

    let legacy_err: FileEntry =
        serde_json::from_str(r#"{"Err":"File not found: /gone"}"#).expect("deserialize legacy Err");
    assert_eq!(
        legacy_err,
        FileEntry::from_result(Err(String::from("File not found: /gone")))
    );

    // 5. Explicit nulls and forward-compatible unknown fields
    let with_nulls: FileEntry = serde_json::from_str(
        r#"{"hash":"abc","size":null,"modified_utc":null,"future_ext":{"k":[1,2,3]}}"#,
    )
    .expect("deserialize entry with nulls and unknown fields");
    assert_eq!(with_nulls, FileEntry::from_result(Ok(String::from("abc"))));

    // 6. Invalid JSON payloads must be rejected
    let invalid_cases = [
        r#"{}"#,
        r#"{"size":100}"#,
        r#"{"hash":"abc","error":"boom"}"#,
        r#"{"Ok":"abc","Err":"boom"}"#,
        r#"{"hash":"abc","Ok":"abc"}"#,
        r#"{"error":"e1","Err":"e2"}"#,
        r#"{"hash":"abc","size":-5}"#,
        r#"{"hash":"abc","modified_utc":"not-a-timestamp"}"#,
        r#"{"hash":null}"#,
    ];
    for case in invalid_cases {
        assert!(
            serde_json::from_str::<FileEntry>(case).is_err(),
            "expected invalid FileEntry JSON to fail: {case}"
        );
    }
}

#[test]
fn extended_file_metadata_captured_across_scans_and_persisted_in_hashed_archive() {
    let dir = TempDir::new("extended_meta_scan");
    let sub = dir.path().join("sub");
    let deep = sub.join("deep");
    fs::create_dir_all(&deep).expect("create nested dirs");

    let empty_path = dir.path().join("empty.bin");
    let notes_path = sub.join("notes.txt");
    let blob_path = deep.join("blob.bin");

    let notes_bytes = b"Extended metadata test notes!";
    let blob_bytes: Vec<u8> = (0..(150 * 1024))
        .map(|i| ((i * 29 + 11) % 256) as u8)
        .collect();

    let empty_mtime = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
    let notes_mtime = UNIX_EPOCH + Duration::from_secs(1_710_000_200);
    let blob_mtime = UNIX_EPOCH + Duration::from_secs(1_720_000_300);

    {
        let f = File::create(&empty_path).expect("create empty.bin");
        f.set_modified(empty_mtime).expect("set empty.bin mtime");
    }
    {
        let mut f = File::create(&notes_path).expect("create notes.txt");
        f.write_all(notes_bytes).expect("write notes.txt");
        f.flush().expect("flush notes.txt");
        f.set_modified(notes_mtime).expect("set notes.txt mtime");
    }
    {
        let mut f = File::create(&blob_path).expect("create blob.bin");
        f.write_all(&blob_bytes).expect("write blob.bin");
        f.flush().expect("flush blob.bin");
        f.set_modified(blob_mtime).expect("set blob.bin mtime");
    }

    let expected_empty_utc = system_time_to_utc(
        fs::metadata(&empty_path)
            .expect("empty meta")
            .modified()
            .expect("empty mtime"),
    );
    let expected_notes_utc = system_time_to_utc(
        fs::metadata(&notes_path)
            .expect("notes meta")
            .modified()
            .expect("notes mtime"),
    );
    let expected_blob_utc = system_time_to_utc(
        fs::metadata(&blob_path)
            .expect("blob meta")
            .modified()
            .expect("blob mtime"),
    );
    assert_eq!(
        expected_empty_utc,
        DateTime::from_timestamp(1_700_000_100, 0)
    );
    assert_eq!(
        expected_notes_utc,
        DateTime::from_timestamp(1_710_000_200, 0)
    );
    assert_eq!(
        expected_blob_utc,
        DateTime::from_timestamp(1_720_000_300, 0)
    );

    let expected_total_size = (notes_bytes.len() + blob_bytes.len()) as u64;
    let root_str = dir.path().to_string_lossy().into_owned();

    // 1. Directory scan (single-threaded vs multithreaded)
    let mut single_scan = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(1);
    single_scan
        .start_hash(root_str.clone())
        .expect("single-threaded scan");

    let mut parallel_scan = ScanManager::new(HashAlgorithm::Blake3).with_thread_count(4);
    parallel_scan
        .start_hash(root_str.clone())
        .expect("parallel scan");

    assert_eq!(single_scan.get_total_size(), expected_total_size);
    assert_eq!(parallel_scan.get_total_size(), expected_total_size);
    assert_eq!(
        parallel_scan.get_hash_manager().get_bytes_hashed(),
        expected_total_size
    );

    let single_tree = DirectoryNode::build_tree(single_scan.get_path(), single_scan.get_list());
    let parallel_tree =
        DirectoryNode::build_tree(parallel_scan.get_path(), parallel_scan.get_list());
    assert_eq!(single_tree, parallel_tree);
    assert_eq!(parallel_tree.total_size(), expected_total_size);
    assert_eq!(parallel_tree.hashed_size(), expected_total_size);
    assert_eq!(parallel_tree.file_count(), 3);
    assert_eq!(parallel_tree.hashed_file_count(), 3);
    assert_eq!(parallel_tree.error_count(), 0);

    let empty_entry = parallel_tree
        .files
        .get("empty.bin")
        .expect("empty.bin in tree");
    assert_eq!(
        empty_entry.hash(),
        Some(HashAlgorithm::Blake3.get_hash_from_bytes(b"").as_str())
    );
    assert_eq!(empty_entry.size(), Some(0));
    assert_eq!(empty_entry.modified_utc(), expected_empty_utc);

    let sub_node = parallel_tree
        .sub_directories
        .get("sub")
        .expect("sub dir in tree");
    assert_eq!(sub_node.total_size(), expected_total_size);
    let notes_entry = sub_node.files.get("notes.txt").expect("notes.txt in sub");
    assert_eq!(notes_entry.size(), Some(notes_bytes.len() as u64));
    assert_eq!(notes_entry.modified_utc(), expected_notes_utc);

    let deep_node = sub_node
        .sub_directories
        .get("deep")
        .expect("deep dir in sub");
    assert_eq!(deep_node.total_size(), blob_bytes.len() as u64);
    let blob_entry = deep_node.files.get("blob.bin").expect("blob.bin in deep");
    assert_eq!(blob_entry.size(), Some(blob_bytes.len() as u64));
    assert_eq!(blob_entry.modified_utc(), expected_blob_utc);

    // 2. Snapshot (.hashed) save & open roundtrip preserves per-file metadata and MetaData::total_size
    let out_dir = TempDir::new("extended_meta_out");
    let meta = MetaData::new(
        parallel_scan.get_hash_manager().get_files_counted(),
        parallel_scan.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(parallel_scan.get_algorithm())
    .with_total_size(parallel_scan.get_total_size());

    let saved_path =
        FileManager::save_file(out_dir.path(), &parallel_tree, &meta).expect("save snapshot");
    let loaded = FileManager::open_file(&saved_path).expect("open snapshot");
    assert_eq!(
        loaded.get_meta().get_total_size(),
        Some(expected_total_size)
    );
    assert_eq!(loaded.get_tree(), &parallel_tree);
    assert_eq!(
        loaded
            .get_tree()
            .files
            .get("empty.bin")
            .and_then(FileEntry::size),
        Some(0)
    );
    assert_eq!(
        loaded
            .get_tree()
            .files
            .get("empty.bin")
            .and_then(FileEntry::modified_utc),
        expected_empty_utc
    );

    // 3. Single-file start_hash captures size + modified_utc
    parallel_scan
        .start_hash(notes_path.to_string_lossy().into_owned())
        .expect("single-file start_hash");
    assert_eq!(parallel_scan.get_list().len(), 1);
    assert_eq!(parallel_scan.get_total_size(), notes_bytes.len() as u64);
    assert_eq!(
        parallel_scan.get_list()[0].get_size(),
        Some(notes_bytes.len() as u64)
    );
    assert_eq!(
        parallel_scan.get_list()[0].get_modified_utc(),
        expected_notes_utc
    );

    // 4. ScanManager::hash_single_file captures modified_utc in SingleFileHash and file_list
    let single_res = parallel_scan
        .hash_single_file(&blob_path)
        .expect("hash_single_file");
    assert_eq!(single_res.get_file_size(), blob_bytes.len() as u64);
    assert_eq!(single_res.get_modified_utc(), expected_blob_utc);
    assert_eq!(
        single_res.get_metadata(),
        FileMetadata::new(Some(blob_bytes.len() as u64), expected_blob_utc)
    );
    let single_json = serde_json::to_value(&single_res).expect("serialize SingleFileHash");
    assert!(single_json["modified_utc"].is_string());
    assert_eq!(
        parallel_scan.get_list()[0].get_size(),
        Some(blob_bytes.len() as u64)
    );
    assert_eq!(
        parallel_scan.get_list()[0].get_modified_utc(),
        expected_blob_utc
    );

    // 5. Batch hash_files captures metadata for valid files and None for missing/dir entries
    let missing_path = dir.path().join("missing.dat");
    let batch = vec![
        empty_path.clone(),
        notes_path.clone(),
        missing_path,
        sub.clone(),
    ];
    parallel_scan.hash_files(&batch).expect("batch hash_files");
    assert_eq!(parallel_scan.get_list().len(), 4);
    assert_eq!(parallel_scan.get_total_size(), notes_bytes.len() as u64);
    assert_eq!(parallel_scan.get_list()[0].get_size(), Some(0));
    assert_eq!(
        parallel_scan.get_list()[0].get_modified_utc(),
        expected_empty_utc
    );
    assert_eq!(
        parallel_scan.get_list()[1].get_size(),
        Some(notes_bytes.len() as u64)
    );
    assert_eq!(
        parallel_scan.get_list()[1].get_modified_utc(),
        expected_notes_utc
    );
    assert_eq!(parallel_scan.get_list()[2].get_size(), None);
    assert_eq!(parallel_scan.get_list()[2].get_modified_utc(), None);
    assert_eq!(parallel_scan.get_list()[3].get_size(), None);
    assert_eq!(parallel_scan.get_list()[3].get_modified_utc(), None);

    // 6. Modifying file mtime and size is reflected on rescan (basis for diff & bitrot checks)
    let updated_mtime = UNIX_EPOCH + Duration::from_secs(1_730_000_999);
    {
        let mut f = File::create(&notes_path).expect("overwrite notes.txt");
        f.write_all(b"updated content with different length")
            .expect("write updated notes");
        f.flush().expect("flush updated notes");
        f.set_modified(updated_mtime).expect("set updated mtime");
    }
    parallel_scan
        .start_hash(root_str)
        .expect("rescan after modification");
    let updated_tree =
        DirectoryNode::build_tree(parallel_scan.get_path(), parallel_scan.get_list());
    let updated_notes = updated_tree
        .sub_directories
        .get("sub")
        .and_then(|s| s.files.get("notes.txt"))
        .expect("updated notes.txt");
    assert_eq!(
        updated_notes.size(),
        Some(b"updated content with different length".len() as u64)
    );
    assert_eq!(
        updated_notes.modified_utc(),
        DateTime::from_timestamp(1_730_000_999, 0)
    );
    assert_ne!(updated_notes.hash(), notes_entry.hash());
}

#[test]
fn legacy_v1_hashed_archive_without_extended_metadata_opens_cleanly() {
    let dir = TempDir::new("legacy_v1_archive");
    let legacy_path = dir.path().join("legacy_snapshot.hashed");

    let legacy_tree_json = r#"{
        "name": "/legacy/root",
        "files": {
            "old_ok.txt": { "Ok": "deadbeef" },
            "old_err.txt": { "Err": "Permission denied: /legacy/root/old_err.txt" }
        },
        "sub_directories": {
            "nested": {
                "name": "nested",
                "files": {
                    "child.bin": { "Ok": "cafebabe" }
                },
                "sub_directories": {}
            }
        }
    }"#;
    let tree_hash = HashAlgorithm::Sha256.get_hash_from_bytes(legacy_tree_json.as_bytes());
    let legacy_meta_json = format!(
        r#"{{"version":1,"files_hashed":2,"hash_time":{{"secs":1,"nanos":500}},"date_utc":"{}","local_time":"2026-01-01T00:00:00Z","os":"linux"}}"#,
        Utc::now().to_rfc3339()
    );

    {
        let f = File::create(&legacy_path).expect("create legacy archive");
        let mut zip = ZipWriter::new(f);
        let opts = SimpleFileOptions::default();
        zip.start_file("meta.json", opts).expect("start meta");
        zip.write_all(legacy_meta_json.as_bytes())
            .expect("write meta");
        zip.start_file("tree.json", opts).expect("start tree");
        zip.write_all(legacy_tree_json.as_bytes())
            .expect("write tree");
        zip.start_file("hash.sha256", opts).expect("start hash");
        zip.write_all(tree_hash.as_bytes()).expect("write hash");
        zip.finish().expect("finish zip");
    }

    let loaded = FileManager::open_file(&legacy_path).expect("legacy v1 snapshot must open");
    assert_eq!(loaded.get_meta().get_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(
        loaded.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V1)
    );
    assert!(loaded.was_migrated());
    assert_eq!(loaded.get_original_version(), FORMAT_VERSION_V1);
    let report = loaded
        .get_migration()
        .expect("v1 archive should produce a MigrationReport");
    assert_eq!(report.original_version(), FORMAT_VERSION_V1);
    assert_eq!(report.target_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(report.steps().len(), 2);
    assert_eq!(report.steps()[0].from_version, FORMAT_VERSION_V1);
    assert_eq!(report.steps()[0].to_version, FORMAT_VERSION_V2);
    assert_eq!(report.steps()[1].from_version, FORMAT_VERSION_V2);
    assert_eq!(report.steps()[1].to_version, FORMAT_VERSION_V3);
    assert_eq!(loaded.get_meta().get_total_size(), None);
    assert_eq!(loaded.get_meta().get_files_hashed(), 2);

    let tree = loaded.get_tree();
    assert_eq!(tree.name, "/legacy/root");
    assert_eq!(tree.file_count(), 3);
    assert_eq!(tree.hashed_file_count(), 2);
    assert_eq!(tree.error_count(), 1);
    assert_eq!(tree.total_size(), 0);
    assert_eq!(tree.hashed_size(), 0);

    let old_ok = tree.files.get("old_ok.txt").expect("old_ok.txt");
    assert_eq!(old_ok.hash(), Some("deadbeef"));
    assert_eq!(old_ok.size(), None);
    assert_eq!(old_ok.modified_utc(), None);

    let old_err = tree.files.get("old_err.txt").expect("old_err.txt");
    assert_eq!(
        old_err.error(),
        Some("Permission denied: /legacy/root/old_err.txt")
    );
    assert_eq!(old_err.size(), None);
    assert_eq!(old_err.modified_utc(), None);

    let child = tree
        .sub_directories
        .get("nested")
        .and_then(|n| n.files.get("child.bin"))
        .expect("nested/child.bin");
    assert_eq!(child.hash(), Some("cafebabe"));
    assert_eq!(child.size(), None);
    assert_eq!(child.modified_utc(), None);
}

#[test]
fn directory_node_aggregations_and_unreadable_file_metadata() {
    let ts = DateTime::from_timestamp(1_750_000_000, 0).expect("valid ts");
    let mut tree = DirectoryNode::new(String::from("/synthetic"));
    tree.insert_path(
        &["a.bin"],
        FileEntry::from_hash(String::from("h1"), Some(100), Some(ts)),
    );
    tree.insert_path(
        &["sub", "b.bin"],
        FileEntry::from_hash(String::from("h2"), Some(250), Some(ts)),
    );
    tree.insert_path(
        &["sub", "locked.bin"],
        FileEntry::from_error(String::from("Permission denied"), Some(500), Some(ts)),
    );
    tree.insert_path(
        &["sub", "missing.bin"],
        FileEntry::from_error(String::from("File not found"), None, None),
    );

    assert_eq!(tree.file_count(), 4);
    assert_eq!(tree.hashed_file_count(), 2);
    assert_eq!(tree.error_count(), 2);
    assert_eq!(tree.total_size(), 850);
    assert_eq!(tree.hashed_size(), 350);

    // Saturating addition prevents arithmetic overflow on extreme sizes
    let mut huge = DirectoryNode::new(String::from("/huge"));
    huge.insert_path(
        &["one.bin"],
        FileEntry::from_hash(String::from("h1"), Some(u64::MAX), None),
    );
    huge.insert_path(
        &["two.bin"],
        FileEntry::from_hash(String::from("h2"), Some(42), None),
    );
    assert_eq!(huge.total_size(), u64::MAX);
    assert_eq!(huge.hashed_size(), u64::MAX);

    // On Unix (non-root), scanning a chmod 000 file records its metadata alongside PermissionDenied
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("unreadable_meta");
        let ok_file = dir.path().join("readable.txt");
        let secret_file = dir.path().join("secret.txt");
        fs::write(&ok_file, b"hello").expect("write readable.txt");
        fs::write(&secret_file, b"top secret payload").expect("write secret.txt");

        fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o000))
            .expect("chmod 000 secret.txt");

        let is_unreadable = File::open(&secret_file).is_err();

        let mut scanner = ScanManager::new(HashAlgorithm::Blake3);
        let scan_res = scanner.start_hash(dir.path().to_string_lossy().into_owned());

        // Restore permissions immediately so TempDir cleanup always succeeds
        let _ = fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o644));

        scan_res.expect("scan should isolate per-file permission error");

        if is_unreadable {
            let scanned_tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
            assert_eq!(scanned_tree.file_count(), 2);
            assert_eq!(scanned_tree.hashed_file_count(), 1);
            assert_eq!(scanned_tree.error_count(), 1);
            assert_eq!(scanned_tree.hashed_size(), 5);
            assert_eq!(
                scanned_tree.total_size(),
                5 + b"top secret payload".len() as u64
            );
            assert_eq!(scanner.get_total_size(), 5);

            let secret_entry = scanned_tree
                .files
                .get("secret.txt")
                .expect("secret.txt entry");
            assert!(secret_entry.is_err());
            assert_eq!(
                secret_entry.size(),
                Some(b"top secret payload".len() as u64)
            );
            assert!(secret_entry.modified_utc().is_some());
        }
    }
}

fn write_raw_hashed_archive(path: &Path, entries: &[(&str, &[u8])]) {
    let file = File::create(path).expect("create raw .hashed archive");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    for &(name, data) in entries {
        zip.start_file(name, opts).expect("start zip entry");
        zip.write_all(data).expect("write zip entry");
    }
    zip.finish().expect("finish zip");
}

fn read_zip_entry_string(path: &Path, entry_name: &str) -> String {
    use std::io::Read;

    let file = File::open(path).expect("open zip archive");
    let mut archive = zip::ZipArchive::new(file).expect("parse zip archive");
    let mut entry = archive.by_name(entry_name).expect("find zip entry");
    let mut content = String::new();
    entry
        .read_to_string(&mut content)
        .expect("read zip entry as UTF-8");
    content
}

#[test]
fn inspect_version_and_future_version_probing_work_without_latest_schema() {
    let dir = TempDir::new("version_inspect");

    // 1. Current v2 archive
    let mut tree = DirectoryNode::new(String::from("/v2_root"));
    tree.insert_path(
        &["hello.txt"],
        FileEntry::from_hash(String::from("abc123"), Some(12), None),
    );
    let meta = MetaData::new(1, Duration::from_millis(5), Utc::now())
        .with_algorithm(HashAlgorithm::Blake3)
        .with_total_size(12);
    let current_path = FileManager::save_file(dir.path(), &tree, &meta).expect("save v3 archive");

    let current_info = FileManager::inspect_version(&current_path).expect("inspect current");
    assert_eq!(current_info.version, FORMAT_VERSION_V3);
    assert_eq!(current_info.current_version, CURRENT_FORMAT_VERSION);
    assert!(current_info.is_supported());
    assert!(current_info.is_current());
    assert!(!current_info.needs_migration());
    assert!(!current_info.is_encrypted());
    assert!(current_info.encryption().is_none());
    assert_eq!(current_info.compatibility, VersionCompatibility::Current);
    assert!(current_info.entries.iter().any(|e| e == "meta.json"));
    assert!(current_info.entries.iter().any(|e| e == "tree.json"));
    assert!(current_info.entries.iter().any(|e| e == "hash.sha256"));

    // 2. Legacy v1 archive (requires 2 migration steps: v1 -> v2 -> v3)
    let v1_path = dir.path().join("legacy_v1.hashed");
    let v1_tree = r#"{"name":"/v1","files":{"a.txt":{"Ok":"deadbeef"}},"sub_directories":{}}"#;
    let v1_hash = HashAlgorithm::Sha256.get_hash_from_bytes(v1_tree.as_bytes());
    let v1_meta = format!(
        r#"{{"version":1,"files_hashed":1,"hash_time":{{"secs":0,"nanos":10}},"date_utc":"{}","local_time":"2026-01-01T00:00:00Z","os":"linux"}}"#,
        Utc::now().to_rfc3339()
    );
    write_raw_hashed_archive(
        &v1_path,
        &[
            ("meta.json", v1_meta.as_bytes()),
            ("tree.json", v1_tree.as_bytes()),
            ("hash.sha256", v1_hash.as_bytes()),
        ],
    );

    let v1_info = FileManager::inspect_version(&v1_path).expect("inspect v1");
    assert_eq!(v1_info.version, FORMAT_VERSION_V1);
    assert!(v1_info.is_supported());
    assert!(!v1_info.is_current());
    assert!(v1_info.needs_migration());
    assert!(!v1_info.is_encrypted());
    assert_eq!(
        v1_info.compatibility,
        VersionCompatibility::NeedsMigration {
            from_version: FORMAT_VERSION_V1,
            to_version: CURRENT_FORMAT_VERSION,
            steps_required: 2,
        }
    );

    // 3. Future v99 archive with completely different meta schema & NO tree.json / hash.sha256
    // (simulating e.g. encrypted or segmented future snapshots).
    let future_path = dir.path().join("future_v99.hashed");
    let future_meta = r#"{"version":99,"encrypted":true,"cipher":"aes-256-gcm","segments":42}"#;
    write_raw_hashed_archive(
        &future_path,
        &[
            ("meta.json", future_meta.as_bytes()),
            ("tree.enc", b"opaque-encrypted-bytes"),
        ],
    );

    let future_info = FileManager::inspect_version(&future_path).expect("inspect future v99");
    assert_eq!(future_info.version, 99);
    assert!(!future_info.is_supported());
    assert!(!future_info.is_current());
    assert!(!future_info.needs_migration());
    assert_eq!(
        future_info.compatibility,
        VersionCompatibility::Unsupported {
            found_version: 99,
            min_supported: MIN_SUPPORTED_FORMAT_VERSION,
            max_supported: CURRENT_FORMAT_VERSION,
        }
    );

    // Opening the future archive MUST report UnsupportedVersion(99), NOT FileIsCorrupted or JsonError!
    let future_err =
        FileManager::open_file(&future_path).expect_err("future v99 must fail cleanly");
    assert!(matches!(future_err, BulkHashError::UnsupportedVersion(99)));
    assert!(future_err.to_string().contains("99"));

    // 4. Version 0 archive MUST report UnsupportedVersion(0)
    let v0_path = dir.path().join("v0.hashed");
    write_raw_hashed_archive(&v0_path, &[("meta.json", br#"{"version":0}"#)]);
    let v0_info = FileManager::inspect_version(&v0_path).expect("inspect v0");
    assert!(!v0_info.is_supported());
    let v0_err =
        FileManager::open_file(&v0_path).expect_err("v0 must fail with UnsupportedVersion");
    assert!(matches!(v0_err, BulkHashError::UnsupportedVersion(0)));

    // 5. Corrupted meta.json variations (missing meta.json, missing version, invalid version type)
    let no_meta_path = dir.path().join("no_meta.hashed");
    write_raw_hashed_archive(&no_meta_path, &[("tree.json", b"{}")]);
    assert!(matches!(
        FileManager::inspect_version(&no_meta_path),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    let bad_ver_type = dir.path().join("bad_ver_type.hashed");
    write_raw_hashed_archive(&bad_ver_type, &[("meta.json", br#"{"version":"two"}"#)]);
    assert!(matches!(
        FileManager::inspect_version(&bad_ver_type),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    let neg_ver = dir.path().join("neg_ver.hashed");
    write_raw_hashed_archive(&neg_ver, &[("meta.json", br#"{"version":-1}"#)]);
    assert!(matches!(
        FileManager::open_file(&neg_ver),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    // 6. v1 archive missing tree.json still reports FileIsCorrupted (not UnsupportedVersion)
    let incomplete_v1 = dir.path().join("incomplete_v1.hashed");
    write_raw_hashed_archive(&incomplete_v1, &[("meta.json", v1_meta.as_bytes())]);
    assert!(matches!(
        FileManager::open_file(&incomplete_v1),
        Err(BulkHashError::FileIsCorrupted(_))
    ));
}

#[test]
fn v1_to_v2_in_memory_migration_handles_legacy_transitional_mixed_and_corrupt_archives() {
    let dir = TempDir::new("v1_to_v2_variants");
    let ts = DateTime::from_timestamp(1_760_000_000, 0).expect("valid ts");

    // 1. Minimal v1 archive missing `local_time` + preserving algorithm/ignore_list/hidden_filter
    let minimal_v1 = dir.path().join("minimal_v1.hashed");
    let ignore_list = IgnoreList::from_patterns(["node_modules/", "*.tmp"]).expect("ignore list");
    let hidden_filter = HiddenFileFilter::exclude_dotfiles();
    let v1_meta_json = serde_json::json!({
        "version": 1,
        "files_hashed": 1,
        "hash_time": { "secs": 2, "nanos": 250_000_000 },
        "date_utc": ts.to_rfc3339(),
        "os": "linux",
        "algorithm": "Sha512",
        "ignore_list": ignore_list,
        "hidden_filter": hidden_filter,
    });
    let v1_meta_bytes = serde_json::to_vec(&v1_meta_json).expect("serialize v1 meta");
    let v1_tree_bytes =
        br#"{"name":"/minimal","files":{"doc.txt":{"Ok":"aaaa1111"}},"sub_directories":{}}"#;
    let v1_hash = HashAlgorithm::Sha256.get_hash_from_bytes(v1_tree_bytes);
    write_raw_hashed_archive(
        &minimal_v1,
        &[
            ("meta.json", &v1_meta_bytes),
            ("tree.json", v1_tree_bytes),
            ("hash.sha256", v1_hash.as_bytes()),
        ],
    );

    let loaded_min = FileManager::open_file(&minimal_v1).expect("minimal v1 must migrate");
    assert!(loaded_min.was_migrated());
    assert_eq!(loaded_min.get_original_version(), FORMAT_VERSION_V1);
    assert_eq!(loaded_min.get_meta().get_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(
        loaded_min.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V1)
    );
    assert!(!loaded_min.get_meta().get_local_time().is_empty());
    assert_eq!(
        loaded_min.get_meta().get_algorithm(),
        Some(HashAlgorithm::Sha512)
    );
    assert!(loaded_min.get_meta().get_ignore_list().is_some());
    assert_eq!(
        loaded_min.get_meta().get_hidden_filter(),
        Some(hidden_filter)
    );
    assert_eq!(loaded_min.get_meta().get_total_size(), None);
    let report = loaded_min.get_migration().expect("migration report");
    assert!(
        report.steps()[0]
            .notes
            .iter()
            .any(|note| note.contains("local_time"))
    );

    // 2. Transitional v1 archive (extended FileEntry with sizes, version still 1, no total_size)
    // -> must preserve all extended metadata AND backfill total_size accurately!
    let transitional_v1 = dir.path().join("transitional_v1.hashed");
    let trans_tree = serde_json::json!({
        "name": "/transitional",
        "files": {
            "a.bin": { "hash": "h1", "size": 100, "modified_utc": ts.to_rfc3339() },
            "err.bin": { "error": "Permission denied", "size": 999 }
        },
        "sub_directories": {
            "sub": {
                "name": "sub",
                "files": {
                    "b.bin": { "hash": "h2", "size": 250, "modified_utc": ts.to_rfc3339() }
                },
                "sub_directories": {}
            }
        }
    });
    let trans_tree_bytes = serde_json::to_vec(&trans_tree).expect("serialize trans tree");
    let trans_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&trans_tree_bytes);
    let trans_meta = serde_json::json!({
        "version": 1,
        "files_hashed": 2,
        "hash_time": { "secs": 0, "nanos": 500 },
        "date_utc": ts.to_rfc3339(),
        "local_time": "2026-01-01T00:00:00Z",
        "os": "linux"
    });
    let trans_meta_bytes = serde_json::to_vec(&trans_meta).expect("serialize trans meta");
    write_raw_hashed_archive(
        &transitional_v1,
        &[
            ("meta.json", &trans_meta_bytes),
            ("tree.json", &trans_tree_bytes),
            ("hash.sha256", trans_hash.as_bytes()),
        ],
    );

    let loaded_trans =
        FileManager::open_file(&transitional_v1).expect("transitional v1 must migrate");
    assert!(loaded_trans.was_migrated());
    assert_eq!(
        loaded_trans.get_meta().get_version(),
        CURRENT_FORMAT_VERSION
    );
    // Backfilled total_size counts hashed files (100 + 250 = 350), not errored file (999)
    assert_eq!(loaded_trans.get_meta().get_total_size(), Some(350));
    assert_eq!(
        loaded_trans
            .get_tree()
            .files
            .get("a.bin")
            .and_then(FileEntry::modified_utc),
        Some(ts)
    );
    assert_eq!(
        loaded_trans
            .get_tree()
            .files
            .get("err.bin")
            .and_then(FileEntry::size),
        Some(999)
    );

    // 3. Mixed v1 archive (one entry has size, another legacy Ok entry lacks size)
    // -> must NOT fabricate a partial total_size!
    let mixed_v1 = dir.path().join("mixed_v1.hashed");
    let mixed_tree = br#"{"name":"/mixed","files":{"sized.bin":{"hash":"h1","size":100},"legacy.bin":{"Ok":"h2"}},"sub_directories":{}}"#;
    let mixed_hash = HashAlgorithm::Sha256.get_hash_from_bytes(mixed_tree);
    write_raw_hashed_archive(
        &mixed_v1,
        &[
            ("meta.json", &trans_meta_bytes),
            ("tree.json", mixed_tree),
            ("hash.sha256", mixed_hash.as_bytes()),
        ],
    );

    let loaded_mixed = FileManager::open_file(&mixed_v1).expect("mixed v1 must migrate");
    assert_eq!(loaded_mixed.get_meta().get_total_size(), None);
    assert_eq!(
        loaded_mixed
            .get_tree()
            .files
            .get("sized.bin")
            .and_then(FileEntry::size),
        Some(100)
    );
    assert_eq!(
        loaded_mixed
            .get_tree()
            .files
            .get("legacy.bin")
            .and_then(FileEntry::hash),
        Some("h2")
    );

    // 4. Tampered v1 archive MUST still fail with HashMismatch BEFORE migration
    let tampered_v1 = dir.path().join("tampered_v1.hashed");
    write_raw_hashed_archive(
        &tampered_v1,
        &[
            ("meta.json", &trans_meta_bytes),
            ("tree.json", v1_tree_bytes),
            (
                "hash.sha256",
                b"0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ],
    );
    assert!(matches!(
        FileManager::open_file(&tampered_v1),
        Err(BulkHashError::HashMismatch { .. })
    ));

    // 5. Corrupt v1 tree entries (empty entry, conflicting Ok+Err, non-string Ok) fail with MigrationFailed
    let bad_trees: [&[u8]; 3] = [
        br#"{"name":"/bad","files":{"empty.txt":{}},"sub_directories":{}}"#,
        br#"{"name":"/bad","files":{"both.txt":{"Ok":"aaa","Err":"bbb"}},"sub_directories":{}}"#,
        br#"{"name":"/bad","files":{"num.txt":{"Ok":12345}},"sub_directories":{}}"#,
    ];
    for (idx, bad_tree) in bad_trees.iter().enumerate() {
        let bad_path = dir.path().join(format!("corrupt_v1_{idx}.hashed"));
        let bad_hash = HashAlgorithm::Sha256.get_hash_from_bytes(bad_tree);
        write_raw_hashed_archive(
            &bad_path,
            &[
                ("meta.json", &trans_meta_bytes),
                ("tree.json", bad_tree),
                ("hash.sha256", bad_hash.as_bytes()),
            ],
        );
        let err = FileManager::open_file(&bad_path).expect_err("corrupt v1 tree must fail");
        assert!(
            matches!(
                err,
                BulkHashError::MigrationFailed {
                    from_version: FORMAT_VERSION_V1,
                    to_version: FORMAT_VERSION_V2,
                    ..
                }
            ),
            "expected MigrationFailed for case {idx}, got {err:?}"
        );
    }
}

#[test]
fn migrate_file_and_migrate_file_in_place_upgrade_archives_atomically_with_backups() {
    let dir = TempDir::new("migrate_on_disk");
    let v1_src = dir.path().join("legacy_snapshot.hashed");

    let v1_tree_json = r#"{
        "name": "/project",
        "files": {
            "readme.md": { "Ok": "1111aaaa" },
            "locked.dat": { "Err": "Permission denied: /project/locked.dat" }
        },
        "sub_directories": {
            "src": {
                "name": "src",
                "files": {
                    "main.rs": { "Ok": "2222bbbb" }
                },
                "sub_directories": {}
            }
        }
    }"#;
    let v1_tree_hash = HashAlgorithm::Sha256.get_hash_from_bytes(v1_tree_json.as_bytes());
    let v1_meta_json = format!(
        r#"{{"version":1,"files_hashed":2,"hash_time":{{"secs":3,"nanos":0}},"date_utc":"{}","local_time":"2026-01-01T12:00:00Z","os":"linux","algorithm":"Blake3"}}"#,
        Utc::now().to_rfc3339()
    );
    write_raw_hashed_archive(
        &v1_src,
        &[
            ("meta.json", v1_meta_json.as_bytes()),
            ("tree.json", v1_tree_json.as_bytes()),
            ("hash.sha256", v1_tree_hash.as_bytes()),
        ],
    );
    let original_v1_bytes = fs::read(&v1_src).expect("read original v1 bytes");

    // 1. Out-of-place migration via migrate_file(src, dst)
    let upgraded_dst = dir.path().join("upgraded_current.hashed");
    let report =
        FileManager::migrate_file(&v1_src, &upgraded_dst).expect("migrate_file v1 -> current");
    assert!(report.was_migrated());
    assert_eq!(report.original_version(), FORMAT_VERSION_V1);
    assert_eq!(report.target_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(report.steps().len(), 2);
    assert!(report.backup_path().is_none());

    // Original v1 source must remain completely untouched
    assert_eq!(
        fs::read(&v1_src).expect("re-read v1 src"),
        original_v1_bytes
    );

    // Upgraded destination must contain canonical current meta.json, canonical tree.json,
    // and matching hash.sha256
    let dst_meta_raw = read_zip_entry_string(&upgraded_dst, "meta.json");
    let dst_meta_val: serde_json::Value =
        serde_json::from_str(&dst_meta_raw).expect("parse dst meta.json");
    assert_eq!(dst_meta_val["version"], CURRENT_FORMAT_VERSION);
    assert_eq!(dst_meta_val["migrated_from"], FORMAT_VERSION_V1);

    let dst_tree_raw = read_zip_entry_string(&upgraded_dst, "tree.json");
    assert!(dst_tree_raw.contains(r#""hash":"1111aaaa""#));
    assert!(dst_tree_raw.contains(r#""error":"Permission denied: /project/locked.dat""#));
    assert!(!dst_tree_raw.contains(r#""Ok""#));
    assert!(!dst_tree_raw.contains(r#""Err""#));

    let dst_hash_raw = read_zip_entry_string(&upgraded_dst, "hash.sha256");
    assert_eq!(
        dst_hash_raw.trim(),
        HashAlgorithm::Sha256.get_hash_from_bytes(dst_tree_raw.as_bytes())
    );

    // Re-opening the upgraded file must NOT require migration anymore
    let reopened = FileManager::open_file(&upgraded_dst).expect("open upgraded file");
    assert!(!reopened.was_migrated());
    assert_eq!(reopened.get_original_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(reopened.get_meta().get_version(), CURRENT_FORMAT_VERSION);
    assert_eq!(
        reopened.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V1)
    );
    assert_eq!(
        reopened.get_meta().get_algorithm(),
        Some(HashAlgorithm::Blake3)
    );
    assert_eq!(reopened.get_tree().file_count(), 3);
    assert_eq!(
        reopened
            .get_tree()
            .sub_directories
            .get("src")
            .and_then(|s| s.files.get("main.rs"))
            .and_then(FileEntry::hash),
        Some("2222bbbb")
    );

    // 2. Migrating an already-current file to a new destination reports up-to-date
    let current_copy = dir.path().join("current_copy.hashed");
    let copy_report = FileManager::migrate_file(&upgraded_dst, &current_copy)
        .expect("migrate current -> current");
    assert!(!copy_report.was_migrated());
    assert!(copy_report.steps().is_empty());
    assert!(current_copy.exists());

    // 3. In-place migration WITH backup creates .v1.bak containing exact original bytes
    let in_place_a = dir.path().join("in_place_a.hashed");
    fs::write(&in_place_a, &original_v1_bytes).expect("seed in_place_a");

    let in_place_report =
        FileManager::migrate_file_in_place(&in_place_a, true).expect("migrate in place w/ backup");
    assert!(in_place_report.was_migrated());
    assert_eq!(in_place_report.original_version(), FORMAT_VERSION_V1);
    assert_eq!(in_place_report.target_version(), CURRENT_FORMAT_VERSION);
    let backup_path = in_place_report
        .backup_path()
        .expect("backup path must be returned");
    assert!(backup_path.exists());
    assert!(
        backup_path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".v1.bak"))
    );
    assert_eq!(
        fs::read(backup_path).expect("read backup"),
        original_v1_bytes
    );

    let after_in_place = FileManager::open_file(&in_place_a).expect("open upgraded in_place_a");
    assert!(!after_in_place.was_migrated());
    assert_eq!(
        after_in_place.get_meta().get_version(),
        CURRENT_FORMAT_VERSION
    );
    assert_eq!(
        after_in_place.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V1)
    );

    // Second in-place migration on the now-v2 file is an idempotent no-op (no extra backup)
    let second_report =
        FileManager::migrate_file_in_place(&in_place_a, true).expect("second in-place is no-op");
    assert!(!second_report.was_migrated());
    assert!(second_report.backup_path().is_none());

    // Non-clobbering backup: restore v1 over in_place_a while .v1.bak already exists -> .v1.bak.1
    fs::write(&in_place_a, &original_v1_bytes).expect("re-seed v1 over in_place_a");
    let third_report = FileManager::migrate_file_in_place(&in_place_a, true)
        .expect("migrate in place with existing backup");
    let second_backup = third_report
        .backup_path()
        .expect("second backup must be created");
    assert_ne!(second_backup, backup_path);
    assert!(
        second_backup
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".v1.bak.1"))
    );
    assert_eq!(
        fs::read(second_backup).expect("read second backup"),
        original_v1_bytes
    );

    // 4. In-place migration WITHOUT backup leaves no .bak files
    let no_bak_dir = TempDir::new("migrate_no_backup");
    let in_place_b = no_bak_dir.path().join("snapshot.hashed");
    fs::write(&in_place_b, &original_v1_bytes).expect("seed in_place_b");
    let no_bak_report =
        FileManager::migrate_file_in_place(&in_place_b, false).expect("migrate without backup");
    assert!(no_bak_report.was_migrated());
    assert!(no_bak_report.backup_path().is_none());
    let entries_in_dir: Vec<_> = fs::read_dir(no_bak_dir.path())
        .expect("read no_bak_dir")
        .collect();
    assert_eq!(
        entries_in_dir.len(),
        1,
        "no temporary or backup files should remain"
    );

    // 5. Validation errors for migrate_file (invalid extension, missing parent, dir destination, tampered source)
    assert!(matches!(
        FileManager::migrate_file(&v1_src, dir.path().join("wrong.zip")),
        Err(BulkHashError::InvalidEnding(_))
    ));
    assert!(matches!(
        FileManager::migrate_file(&v1_src, dir.path().join("missing_dir").join("out.hashed")),
        Err(BulkHashError::PathNotFound(_))
    ));
    let dir_as_dest = dir.path().join("dir_dest.hashed");
    fs::create_dir_all(&dir_as_dest).expect("create dir_as_dest");
    assert!(matches!(
        FileManager::migrate_file(&v1_src, &dir_as_dest),
        Err(BulkHashError::NotAFile(_))
    ));

    let tampered_src = dir.path().join("tampered_src.hashed");
    write_raw_hashed_archive(
        &tampered_src,
        &[
            ("meta.json", v1_meta_json.as_bytes()),
            ("tree.json", v1_tree_json.as_bytes()),
            ("hash.sha256", b"deadbeef"),
        ],
    );
    let untouched_dst = dir.path().join("must_not_exist.hashed");
    assert!(matches!(
        FileManager::migrate_file(&tampered_src, &untouched_dst),
        Err(BulkHashError::HashMismatch { .. })
    ));
    assert!(
        !untouched_dst.exists(),
        "failed migration must never create destination file"
    );
}

#[test]
fn extensible_migration_registry_supports_multihop_future_chains_and_validates_invariants() {
    struct V2ToV3Migration;
    impl FormatMigration for V2ToV3Migration {
        fn source_version(&self) -> usize {
            2
        }

        fn target_version(&self) -> usize {
            3
        }

        fn description(&self) -> &'static str {
            "Add v3 encryption envelope metadata"
        }

        fn migrate(&self, payload: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError> {
            let meta =
                payload
                    .meta
                    .as_object_mut()
                    .ok_or_else(|| BulkHashError::MigrationFailed {
                        from_version: 2,
                        to_version: 3,
                        reason: String::from("meta is not an object"),
                    })?;
            meta.insert(String::from("encrypted"), serde_json::Value::Bool(false));
            Ok(vec![String::from("Defaulted encrypted=false")])
        }
    }

    struct V3ToV4Migration;
    impl FormatMigration for V3ToV4Migration {
        fn source_version(&self) -> usize {
            3
        }

        fn target_version(&self) -> usize {
            4
        }

        fn description(&self) -> &'static str {
            "Attach v4 segmented-tree manifest entry"
        }

        fn migrate(&self, payload: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError> {
            let meta =
                payload
                    .meta
                    .as_object_mut()
                    .ok_or_else(|| BulkHashError::MigrationFailed {
                        from_version: 3,
                        to_version: 4,
                        reason: String::from("meta is not an object"),
                    })?;
            meta.insert(String::from("segmented"), serde_json::Value::Bool(true));
            payload.extra_entries.insert(
                String::from("segments/index.json"),
                b"{\"chunks\":1}".to_vec(),
            );
            Ok(vec![String::from("Generated segments/index.json")])
        }
    }

    struct InvalidBackwardMigration;
    impl FormatMigration for InvalidBackwardMigration {
        fn source_version(&self) -> usize {
            5
        }
        fn target_version(&self) -> usize {
            5
        }
        fn description(&self) -> &'static str {
            "invalid"
        }
        fn migrate(&self, _: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError> {
            Ok(Vec::new())
        }
    }

    // 1. Built-in registry chain must always validate cleanly
    let builtin = MigrationRegistry::with_builtin_migrations();
    builtin
        .validate_chain()
        .expect("built-in migration chain must be complete");
    assert_eq!(
        builtin.min_supported_version(),
        MIN_SUPPORTED_FORMAT_VERSION
    );
    assert_eq!(builtin.target_version(), CURRENT_FORMAT_VERSION);

    // 2. Custom multi-hop chain: v1 -> v2 -> v3 -> v4
    let mut registry = MigrationRegistry::new(1, 4);
    registry
        .register(Box::new(
            bulk_hash_lib::core::io::migration::V1ToV2Migration,
        ))
        .expect("register v1->v2");
    registry
        .register(Box::new(V2ToV3Migration))
        .expect("register v2->v3");
    registry
        .register(Box::new(V3ToV4Migration))
        .expect("register v3->v4");
    registry
        .validate_chain()
        .expect("v1..=v4 chain must validate");

    assert_eq!(
        registry.check_compatibility(1),
        VersionCompatibility::NeedsMigration {
            from_version: 1,
            to_version: 4,
            steps_required: 3,
        }
    );
    assert_eq!(
        registry.check_compatibility(4),
        VersionCompatibility::Current
    );

    let mut payload = SnapshotPayload::new(
        1,
        serde_json::json!({
            "version": 1,
            "files_hashed": 1,
            "hash_time": { "secs": 0, "nanos": 1 },
            "date_utc": Utc::now().to_rfc3339(),
            "local_time": "2026-01-01T00:00:00Z",
            "os": "linux"
        }),
        serde_json::json!({
            "name": "/chain",
            "files": { "item.txt": { "Ok": "abcdef" } },
            "sub_directories": {}
        }),
    );

    let report = registry
        .migrate(&mut payload)
        .expect("v1 -> v4 multi-hop migration");
    assert!(report.was_migrated());
    assert_eq!(report.original_version(), 1);
    assert_eq!(report.target_version(), 4);
    assert_eq!(report.steps().len(), 3);
    assert_eq!(report.steps()[0].from_version, 1);
    assert_eq!(report.steps()[0].to_version, 2);
    assert_eq!(report.steps()[1].from_version, 2);
    assert_eq!(report.steps()[1].to_version, 3);
    assert_eq!(report.steps()[2].from_version, 3);
    assert_eq!(report.steps()[2].to_version, 4);

    assert_eq!(payload.version, 4);
    assert_eq!(payload.meta["version"], 4);
    // Original provenance must remain 1 across all hops!
    assert_eq!(payload.meta["migrated_from"], 1);
    assert_eq!(payload.meta["encrypted"], false);
    assert_eq!(payload.meta["segmented"], true);
    assert_eq!(payload.tree["files"]["item.txt"]["hash"], "abcdef");
    assert!(payload.tree["files"]["item.txt"].get("Ok").is_none());
    assert_eq!(
        payload.extra_entries.get("segments/index.json"),
        Some(&b"{\"chunks\":1}".to_vec())
    );

    // Migrating a v2 payload that already recorded migrated_from=1 keeps migrated_from=1
    let mut previously_migrated_v2 = SnapshotPayload::new(
        2,
        serde_json::json!({ "version": 2, "migrated_from": 1 }),
        serde_json::json!({ "name": "/", "files": {}, "sub_directories": {} }),
    );
    let hop_report = registry
        .migrate(&mut previously_migrated_v2)
        .expect("v2 -> v4");
    assert_eq!(hop_report.steps().len(), 2);
    assert_eq!(previously_migrated_v2.meta["migrated_from"], 1);
    assert_eq!(previously_migrated_v2.meta["version"], 4);

    // 3. Registry guard rails: duplicate, non-advancing, gap in chain, mismatched version stamp
    assert!(matches!(
        registry.register(Box::new(V2ToV3Migration)),
        Err(BulkHashError::MigrationFailed { .. })
    ));

    assert!(matches!(
        registry.register(Box::new(InvalidBackwardMigration)),
        Err(BulkHashError::MigrationFailed { .. })
    ));

    // Gap in chain (v1 -> v2 present, v2 -> v3 missing, target = 3)
    let mut broken = MigrationRegistry::new(1, 3);
    broken
        .register(Box::new(
            bulk_hash_lib::core::io::migration::V1ToV2Migration,
        ))
        .expect("register v1->v2");
    assert!(matches!(
        broken.validate_chain(),
        Err(BulkHashError::MigrationFailed {
            from_version: 2,
            to_version: 3,
            ..
        })
    ));

    // Mismatched payload.version vs meta["version"]
    let mut mismatch_payload = SnapshotPayload::new(
        1,
        serde_json::json!({ "version": 2 }),
        serde_json::json!({ "name": "/", "files": {}, "sub_directories": {} }),
    );
    assert!(matches!(
        builtin.migrate(&mut mismatch_payload),
        Err(BulkHashError::MigrationFailed { .. })
    ));

    // BulkHashError::MigrationFailed serializes cleanly for GUI/IPC
    let mig_err = BulkHashError::MigrationFailed {
        from_version: 1,
        to_version: 2,
        reason: String::from("corrupt file entry"),
    };
    let err_json = serde_json::to_value(&mig_err).expect("serialize MigrationFailed");
    assert_eq!(err_json["kind"], "MigrationFailed");
    assert_eq!(
        err_json["message"],
        "Failed to migrate snapshot from v1 to v2: corrupt file entry"
    );
}

#[test]
fn deep_v1_tree_migration_and_save_file_version_guard() {
    let dir = TempDir::new("deep_v1_and_save_guard");

    // 1. Deeply nested v1 tree (40 levels deep) verifies iterative migration
    let mut deep_val = serde_json::json!({
        "name": "leaf",
        "files": { "deep.txt": { "Ok": "cafe0001" } },
        "sub_directories": {}
    });
    for depth in (0..40).rev() {
        let dir_name = format!("level_{depth}");
        let mut subdirs = serde_json::Map::new();
        let child_key = deep_val["name"].as_str().unwrap_or("child").to_string();
        subdirs.insert(child_key, deep_val);
        deep_val = serde_json::json!({
            "name": dir_name,
            "files": {},
            "sub_directories": subdirs
        });
    }

    let deep_tree_bytes = serde_json::to_vec(&deep_val).expect("serialize deep tree");
    let deep_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&deep_tree_bytes);
    let v1_meta = format!(
        r#"{{"version":1,"files_hashed":1,"hash_time":{{"secs":0,"nanos":1}},"date_utc":"{}","local_time":"2026-01-01T00:00:00Z","os":"linux"}}"#,
        Utc::now().to_rfc3339()
    );
    let deep_path = dir.path().join("deep_v1.hashed");
    write_raw_hashed_archive(
        &deep_path,
        &[
            ("meta.json", v1_meta.as_bytes()),
            ("tree.json", &deep_tree_bytes),
            ("hash.sha256", deep_hash.as_bytes()),
        ],
    );

    let loaded_deep = FileManager::open_file(&deep_path).expect("deep v1 tree must migrate");
    assert!(loaded_deep.was_migrated());
    assert_eq!(loaded_deep.get_tree().hashed_file_count(), 1);
    let mut cursor = loaded_deep.get_tree();
    for depth in 1..40 {
        cursor = cursor
            .sub_directories
            .get(&format!("level_{depth}"))
            .expect("nested dir must exist");
    }
    let leaf = cursor
        .sub_directories
        .get("leaf")
        .expect("leaf dir must exist");
    assert_eq!(
        leaf.files.get("deep.txt").and_then(FileEntry::hash),
        Some("cafe0001")
    );

    // 2. FileManager::save_file rejects MetaData with non-current version
    let stale_meta: MetaData = serde_json::from_str(&v1_meta).expect("deserialize v1 MetaData");
    assert_eq!(stale_meta.get_version(), FORMAT_VERSION_V1);
    let empty_tree = DirectoryNode::new(String::from("/stale"));
    let save_err = FileManager::save_file(dir.path(), &empty_tree, &stale_meta)
        .expect_err("save_file must reject non-current format version");
    assert!(matches!(
        save_err,
        BulkHashError::UnsupportedVersion(FORMAT_VERSION_V1)
    ));
}

fn read_zip_entry_bytes(path: &Path, entry_name: &str) -> Vec<u8> {
    use std::io::Read;

    let file = File::open(path).expect("open zip archive");
    let mut archive = zip::ZipArchive::new(file).expect("parse zip archive");
    let mut entry = archive.by_name(entry_name).expect("find zip entry");
    let mut content = Vec::new();
    entry.read_to_end(&mut content).expect("read zip entry");
    content
}

fn fast_test_kdf_params() -> KdfParams {
    KdfParams::new(MIN_KDF_MEMORY_KIB, 1, 1).expect("minimal valid Argon2id params for fast tests")
}

fn fast_encryption_options(password: &str) -> EncryptionOptions {
    EncryptionOptions::new(password)
        .expect("valid test password")
        .with_kdf_params(fast_test_kdf_params())
        .expect("valid fast test kdf params")
}

#[test]
fn encrypted_snapshot_roundtrip_semantic_security_and_zero_plaintext_leakage() {
    let dir = TempDir::new("encrypted_roundtrip");
    let ts = DateTime::from_timestamp(1_765_000_123, 0).expect("valid ts");

    let mut tree = DirectoryNode::new(String::from("/vault/top-secret-client-data"));
    tree.insert_path(
        &["finances", "tax_return_2026.pdf"],
        FileEntry::from_hash(
            String::from("deadbeefcafe111122223333444455556666777788889999aaaabbbbccccdddd"),
            Some(4096),
            Some(ts),
        ),
    );
    tree.insert_path(
        &["ssh", "id_ed25519_private"],
        FileEntry::from_error(
            String::from("Permission denied: /vault/top-secret-client-data/ssh/id_ed25519_private"),
            Some(512),
            Some(ts),
        ),
    );

    let ignore_list = IgnoreList::from_patterns(["*.tmp", "cache/"]).expect("ignore list");
    let hidden_filter = HiddenFileFilter::exclude_all();
    let meta = MetaData::new(1, Duration::from_millis(87), ts)
        .with_algorithm(HashAlgorithm::Blake3)
        .with_ignore_list(ignore_list.clone())
        .with_hidden_filter(hidden_filter)
        .with_total_size(4096);

    let password = "Sup3r S3cret P@ssphrase! 🔒";
    let enc_opts = fast_encryption_options(password);

    // Debug output must NEVER leak the secret password
    let debug_repr = format!("{enc_opts:?}");
    assert!(debug_repr.contains("[REDACTED]"));
    assert!(!debug_repr.contains(password));
    assert!(!debug_repr.contains("Sup3r"));

    let plain_dir = TempDir::new("encrypted_roundtrip_plain");
    let enc_dir_a = TempDir::new("encrypted_roundtrip_a");
    let enc_dir_b = TempDir::new("encrypted_roundtrip_b");

    let plain_path = FileManager::save_file(plain_dir.path(), &tree, &meta).expect("save plain");
    let enc_path_a = FileManager::save_file_encrypted(enc_dir_a.path(), &tree, &meta, &enc_opts)
        .expect("save encrypted A");
    let enc_path_b =
        FileManager::save_file_with_encryption(enc_dir_b.path(), &tree, &meta, Some(&enc_opts))
            .expect("save encrypted B");

    // Lightweight inspection works without a password
    assert!(!FileManager::is_encrypted(&plain_path).expect("plain is_encrypted"));
    assert!(FileManager::is_encrypted(&enc_path_a).expect("enc A is_encrypted"));

    let enc_info_a = FileManager::inspect_version(&enc_path_a).expect("inspect enc A");
    let enc_info_b = FileManager::inspect_version(&enc_path_b).expect("inspect enc B");
    assert_eq!(enc_info_a.version, FORMAT_VERSION_V3);
    assert!(enc_info_a.is_current());
    assert!(enc_info_a.is_encrypted());
    assert!(enc_info_a.entries.iter().any(|e| e == "meta.json"));
    assert!(enc_info_a.entries.iter().any(|e| e == ENCRYPTED_TREE_ENTRY));
    assert!(enc_info_a.entries.iter().any(|e| e == "hash.sha256"));
    assert!(!enc_info_a.entries.iter().any(|e| e == "tree.json"));

    let enc_meta_a = enc_info_a.encryption().expect("encryption metadata A");
    let enc_meta_b = enc_info_b.encryption().expect("encryption metadata B");
    assert_eq!(enc_meta_a.cipher, EncryptionCipher::Aes256Gcm);
    assert_eq!(enc_meta_a.kdf, KeyDerivationAlgorithm::Argon2id);
    assert_eq!(enc_meta_a.kdf_params, fast_test_kdf_params());
    assert_eq!(enc_meta_a.payload_compression, PayloadCompression::Deflate);

    // Semantic security: encrypting the identical tree + meta + password twice must produce
    // completely fresh salt, nonce, ciphertext, and ciphertext digest.
    assert_ne!(enc_meta_a.salt, enc_meta_b.salt);
    assert_ne!(enc_meta_a.nonce, enc_meta_b.nonce);
    let ct_a = read_zip_entry_bytes(&enc_path_a, ENCRYPTED_TREE_ENTRY);
    let ct_b = read_zip_entry_bytes(&enc_path_b, ENCRYPTED_TREE_ENTRY);
    assert_ne!(ct_a, ct_b);
    let disk_hash_a = read_zip_entry_string(&enc_path_a, "hash.sha256");
    let disk_hash_b = read_zip_entry_string(&enc_path_b, "hash.sha256");
    assert_ne!(disk_hash_a, disk_hash_b);
    assert_eq!(
        disk_hash_a.trim(),
        HashAlgorithm::Sha256.get_hash_from_bytes(&ct_a)
    );

    // Zero plaintext leakage anywhere in raw .hashed archive bytes, meta.json, or tree.enc
    let raw_archive_a = fs::read(&enc_path_a).expect("read raw encrypted archive");
    let meta_raw_a = read_zip_entry_string(&enc_path_a, "meta.json");
    let sensitive_needles = [
        "top-secret-client-data",
        "tax_return_2026.pdf",
        "id_ed25519_private",
        "finances",
        "deadbeefcafe11112222",
        "Permission denied",
    ];
    for needle in sensitive_needles {
        assert!(
            !raw_archive_a
                .windows(needle.len())
                .any(|w| w == needle.as_bytes()),
            "sensitive string '{needle}' leaked in raw encrypted archive!"
        );
        assert!(
            !meta_raw_a.contains(needle),
            "sensitive string '{needle}' leaked in meta.json!"
        );
    }

    // Verify tree.enc is stored uncompressed (Stored) inside the ZIP container
    {
        let f = File::open(&enc_path_a).expect("open enc A zip");
        let mut zip = zip::ZipArchive::new(f).expect("parse zip");
        let entry = zip.by_name(ENCRYPTED_TREE_ENTRY).expect("find tree.enc");
        assert_eq!(entry.compression(), zip::CompressionMethod::Stored);
    }

    // Opening without password MUST fail with PasswordRequired
    let no_pw_err =
        FileManager::open_file(&enc_path_a).expect_err("open_file must reject encrypted");
    assert!(matches!(no_pw_err, BulkHashError::PasswordRequired(_)));
    assert!(no_pw_err.is_password_required());

    // Unlocking with the correct password restores the exact tree, metadata, and logical tree hash
    let loaded_plain = FileManager::open_file(&plain_path).expect("open plain");
    let loaded_enc =
        FileManager::open_file_with_password(&enc_path_a, password).expect("open encrypted A");
    assert!(!loaded_plain.is_encrypted());
    assert!(loaded_enc.is_encrypted());
    assert!(loaded_enc.get_encryption().is_some());
    assert_eq!(loaded_enc.get_tree(), &tree);
    assert_eq!(loaded_enc.get_hash(), loaded_plain.get_hash());
    // On-disk hash.sha256 MUST NOT equal plaintext tree hash (no plaintext hash oracle!)
    assert_ne!(disk_hash_a.trim(), loaded_plain.get_hash());
    assert_eq!(
        loaded_enc.get_meta().get_algorithm(),
        Some(HashAlgorithm::Blake3)
    );
    assert_eq!(loaded_enc.get_meta().get_ignore_list(), Some(&ignore_list));
    assert_eq!(
        loaded_enc.get_meta().get_hidden_filter(),
        Some(hidden_filter)
    );
    assert_eq!(loaded_enc.get_meta().get_total_size(), Some(4096));

    // Re-saving loaded encrypted metadata via unencrypted save_file strips stale encryption header
    let stripped_dir = TempDir::new("stripped_plain_out");
    let stripped_path = FileManager::save_file(
        stripped_dir.path(),
        loaded_enc.get_tree(),
        loaded_enc.get_meta(),
    )
    .expect("save plain from loaded encrypted meta");
    assert!(!FileManager::is_encrypted(&stripped_path).expect("stripped must be unencrypted"));
    let reopened_plain = FileManager::open_file(&stripped_path).expect("open stripped plain");
    assert_eq!(reopened_plain.get_tree(), &tree);
    assert!(!reopened_plain.is_encrypted());

    // Re-saving loaded encrypted metadata via save_file_encrypted MUST rotate salt & nonce
    let rotated_path = FileManager::save_file_encrypted(
        dir.path(),
        loaded_enc.get_tree(),
        loaded_enc.get_meta(),
        &enc_opts,
    )
    .expect("resave encrypted");
    let rotated_info = FileManager::inspect_version(&rotated_path).expect("inspect rotated");
    let rotated_enc = rotated_info.encryption().expect("rotated enc meta");
    assert_ne!(rotated_enc.salt, enc_meta_a.salt);
    assert_ne!(rotated_enc.nonce, enc_meta_a.nonce);

    // Opening an unencrypted snapshot via open_file_with_password works cleanly
    let plain_via_pw =
        FileManager::open_file_with_password(&plain_path, "unused").expect("open plain via pw");
    assert!(!plain_via_pw.is_encrypted());
    assert_eq!(plain_via_pw.get_tree(), &tree);
}

#[test]
fn encrypted_snapshot_standard_kdf_presets_payload_compression_and_password_whitespace() {
    let ts = DateTime::from_timestamp(1_765_100_000, 0).expect("valid ts");
    let mut tree = DirectoryNode::new(String::from("/large-repetitive-tree"));
    for idx in 0..200usize {
        tree.insert_path(
            &[
                "modules",
                &format!("service_{:02}", idx % 10),
                &format!("file_{idx:03}.rs"),
            ],
            FileEntry::from_hash(format!("{idx:064x}"), Some(1024 + idx as u64), Some(ts)),
        );
    }
    let meta = MetaData::new(200, Duration::from_secs(1), ts).with_algorithm(HashAlgorithm::Sha256);

    // 1. Real default KdfParams::standard() + whitespace-sensitive password
    let std_dir = TempDir::new("enc_standard_kdf");
    let spaced_pw = "  correct horse battery staple  ";
    let std_opts = EncryptionOptions::new(spaced_pw).expect("standard opts");
    assert_eq!(std_opts.kdf_params(), KdfParams::standard());
    assert_eq!(std_opts.payload_compression(), PayloadCompression::Deflate);

    let std_path = FileManager::save_file_encrypted(std_dir.path(), &tree, &meta, &std_opts)
        .expect("save std");
    // Trimmed password MUST fail (whitespace is significant!)
    let trimmed_err = FileManager::open_file_with_password(&std_path, spaced_pw.trim())
        .expect_err("trimmed password must fail");
    assert!(matches!(trimmed_err, BulkHashError::DecryptionFailed(_)));

    let std_loaded =
        FileManager::open_file_with_password(&std_path, spaced_pw).expect("unlock std");
    assert_eq!(std_loaded.get_tree(), &tree);
    assert_eq!(
        std_loaded.get_encryption().expect("enc").kdf_params,
        KdfParams::standard()
    );

    // 2. Compare PayloadCompression::Deflate vs PayloadCompression::None using interactive preset
    let deflate_dir = TempDir::new("enc_deflate");
    let raw_dir = TempDir::new("enc_uncompressed");

    let deflate_opts = EncryptionOptions::new("pw-compress")
        .expect("opts")
        .with_kdf_params(KdfParams::interactive())
        .expect("interactive")
        .with_payload_compression(PayloadCompression::Deflate);
    let raw_opts = EncryptionOptions::new("pw-compress")
        .expect("opts")
        .with_kdf_params(KdfParams::interactive())
        .expect("interactive")
        .with_payload_compression(PayloadCompression::None);

    let deflate_path =
        FileManager::save_file_encrypted(deflate_dir.path(), &tree, &meta, &deflate_opts)
            .expect("save deflate");
    let raw_path = FileManager::save_file_encrypted(raw_dir.path(), &tree, &meta, &raw_opts)
        .expect("save raw");

    let deflate_ct = read_zip_entry_bytes(&deflate_path, ENCRYPTED_TREE_ENTRY);
    let raw_ct = read_zip_entry_bytes(&raw_path, ENCRYPTED_TREE_ENTRY);
    assert!(
        deflate_ct.len() * 2 < raw_ct.len(),
        "inner Deflate should significantly shrink encrypted repetitive tree ({} vs {})",
        deflate_ct.len(),
        raw_ct.len()
    );

    let loaded_deflate =
        FileManager::open_file_with_password(&deflate_path, "pw-compress").expect("open deflate");
    let loaded_raw =
        FileManager::open_file_with_password(&raw_path, "pw-compress").expect("open raw");
    assert_eq!(loaded_deflate.get_tree(), &tree);
    assert_eq!(loaded_raw.get_tree(), &tree);
    assert_eq!(loaded_deflate.get_hash(), loaded_raw.get_hash());
}

#[test]
fn encrypted_snapshot_rejects_wrong_password_tampering_aad_modification_and_confusion() {
    let dir = TempDir::new("enc_tamper");
    let ts = DateTime::from_timestamp(1_765_200_000, 0).expect("valid ts");

    let mut tree_a = DirectoryNode::new(String::from("/alpha"));
    tree_a.insert_path(
        &["secret.txt"],
        FileEntry::from_hash(String::from("aaaa1111"), Some(42), Some(ts)),
    );
    let mut tree_b = DirectoryNode::new(String::from("/beta"));
    tree_b.insert_path(
        &["other.txt"],
        FileEntry::from_hash(String::from("bbbb2222"), Some(99), Some(ts)),
    );

    let meta = MetaData::new(1, Duration::from_millis(12), ts);
    let opts = fast_encryption_options("master-key-123");

    let dir_a = TempDir::new("enc_tamper_a");
    let dir_b = TempDir::new("enc_tamper_b");
    let path_a =
        FileManager::save_file_encrypted(dir_a.path(), &tree_a, &meta, &opts).expect("save A");
    let path_b =
        FileManager::save_file_encrypted(dir_b.path(), &tree_b, &meta, &opts).expect("save B");

    // 1. Empty password rejected on construction & open
    assert!(matches!(
        EncryptionOptions::new(""),
        Err(BulkHashError::EmptyPassword)
    ));
    assert!(matches!(
        FileManager::open_file_with_password(&path_a, ""),
        Err(BulkHashError::EmptyPassword)
    ));

    // 2. Wrong password rejected with DecryptionFailed
    let wrong_pw = FileManager::open_file_with_password(&path_a, "wrong-password")
        .expect_err("wrong password must fail");
    assert!(matches!(wrong_pw, BulkHashError::DecryptionFailed(_)));

    let orig_meta = read_zip_entry_bytes(&path_a, "meta.json");
    let orig_ct = read_zip_entry_bytes(&path_a, ENCRYPTED_TREE_ENTRY);
    let orig_hash = read_zip_entry_bytes(&path_a, "hash.sha256");

    // 3. Bit-flip in ciphertext WITHOUT updating hash.sha256 -> fast HashMismatch before KDF
    let mut flipped_ct = orig_ct.clone();
    flipped_ct[0] ^= 0x01;
    let corrupt_ct_path = dir.path().join("bitflip_no_rehash.hashed");
    write_raw_hashed_archive(
        &corrupt_ct_path,
        &[
            ("meta.json", &orig_meta),
            (ENCRYPTED_TREE_ENTRY, &flipped_ct),
            ("hash.sha256", &orig_hash),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&corrupt_ct_path, "master-key-123"),
        Err(BulkHashError::HashMismatch { .. })
    ));

    // 4. Bit-flip in ciphertext WITH attacker recomputing hash.sha256 -> AES-GCM tag fails!
    let forged_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&flipped_ct);
    let forged_ct_path = dir.path().join("bitflip_rehashed.hashed");
    write_raw_hashed_archive(
        &forged_ct_path,
        &[
            ("meta.json", &orig_meta),
            (ENCRYPTED_TREE_ENTRY, &flipped_ct),
            ("hash.sha256", forged_hash.as_bytes()),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&forged_ct_path, "master-key-123"),
        Err(BulkHashError::DecryptionFailed(_))
    ));

    // 5. Tampering with meta.json (AAD binding!) -> AES-GCM authentication fails!
    let mut tampered_meta_val: serde_json::Value =
        serde_json::from_slice(&orig_meta).expect("parse meta");
    tampered_meta_val["files_hashed"] = serde_json::Value::from(999);
    let tampered_meta_bytes = serde_json::to_vec(&tampered_meta_val).expect("serialize meta");
    let tampered_meta_path = dir.path().join("tampered_meta_aad.hashed");
    write_raw_hashed_archive(
        &tampered_meta_path,
        &[
            ("meta.json", &tampered_meta_bytes),
            (ENCRYPTED_TREE_ENTRY, &orig_ct),
            ("hash.sha256", &orig_hash),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&tampered_meta_path, "master-key-123"),
        Err(BulkHashError::DecryptionFailed(_))
    ));

    // 6. Cross-snapshot ciphertext transplant (same password, different archive) -> DecryptionFailed!
    let ct_b = read_zip_entry_bytes(&path_b, ENCRYPTED_TREE_ENTRY);
    let hash_b = read_zip_entry_bytes(&path_b, "hash.sha256");
    let transplanted_path = dir.path().join("transplanted.hashed");
    write_raw_hashed_archive(
        &transplanted_path,
        &[
            ("meta.json", &orig_meta),
            (ENCRYPTED_TREE_ENTRY, &ct_b),
            ("hash.sha256", &hash_b),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&transplanted_path, "master-key-123"),
        Err(BulkHashError::DecryptionFailed(_))
    ));

    // 7. Truncated ciphertext (< 16-byte GCM tag) with matching hash -> FileIsCorrupted
    let short_ct = b"too-short";
    let short_hash = HashAlgorithm::Sha256.get_hash_from_bytes(short_ct);
    let short_path = dir.path().join("truncated_ct.hashed");
    write_raw_hashed_archive(
        &short_path,
        &[
            ("meta.json", &orig_meta),
            (ENCRYPTED_TREE_ENTRY, short_ct),
            ("hash.sha256", short_hash.as_bytes()),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&short_path, "master-key-123"),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    // 8. Confusion attack: encrypted archive also containing plaintext tree.json -> FileIsCorrupted
    let dual_entry_path = dir.path().join("dual_entries.hashed");
    write_raw_hashed_archive(
        &dual_entry_path,
        &[
            ("meta.json", &orig_meta),
            (ENCRYPTED_TREE_ENTRY, &orig_ct),
            (
                "tree.json",
                br#"{"name":"/fake","files":{},"sub_directories":{}}"#,
            ),
            ("hash.sha256", &orig_hash),
        ],
    );
    assert!(matches!(
        FileManager::open_file_with_password(&dual_entry_path, "master-key-123"),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    // 9. Reverse confusion: unencrypted meta.json with stray tree.enc -> FileIsCorrupted
    let plain_meta = serde_json::to_vec(&meta).expect("plain meta");
    let plain_tree = serde_json::to_vec(&tree_a).expect("plain tree");
    let plain_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&plain_tree);
    let stray_enc_path = dir.path().join("stray_tree_enc.hashed");
    write_raw_hashed_archive(
        &stray_enc_path,
        &[
            ("meta.json", &plain_meta),
            ("tree.json", &plain_tree),
            (ENCRYPTED_TREE_ENTRY, &orig_ct),
            ("hash.sha256", plain_hash.as_bytes()),
        ],
    );
    assert!(matches!(
        FileManager::open_file(&stray_enc_path),
        Err(BulkHashError::FileIsCorrupted(_))
    ));

    // 10. Pre-v3 (v2) archive claiming encryption -> FileIsCorrupted on inspect & open
    let mut v2_bogus_meta: serde_json::Value =
        serde_json::from_slice(&orig_meta).expect("parse orig meta");
    v2_bogus_meta["version"] = serde_json::Value::from(FORMAT_VERSION_V2);
    let v2_bogus_bytes = serde_json::to_vec(&v2_bogus_meta).expect("serialize v2 bogus");
    let v2_enc_path = dir.path().join("v2_claiming_encryption.hashed");
    write_raw_hashed_archive(
        &v2_enc_path,
        &[
            ("meta.json", &v2_bogus_bytes),
            (ENCRYPTED_TREE_ENTRY, &orig_ct),
            ("hash.sha256", &orig_hash),
        ],
    );
    assert!(matches!(
        FileManager::inspect_version(&v2_enc_path),
        Err(BulkHashError::FileIsCorrupted(_))
    ));
    assert!(matches!(
        FileManager::open_file_with_password(&v2_enc_path, "master-key-123"),
        Err(BulkHashError::FileIsCorrupted(_))
    ));
}

#[test]
fn encryption_parameter_validation_dos_bounds_and_decompression_bomb_protection() {
    let dir = TempDir::new("enc_dos_bounds");

    // 1. KdfParams boundary checks
    assert!(matches!(
        KdfParams::new(0, 1, 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(MIN_KDF_MEMORY_KIB - 1, 1, 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(MAX_KDF_MEMORY_KIB + 1, 1, 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(64, 0, 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(64, MAX_KDF_ITERATIONS + 1, 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(64, 1, 0),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(matches!(
        KdfParams::new(1024, 1, MAX_KDF_PARALLELISM + 1),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    // Argon2 invariant: memory_kib >= 8 * parallelism (64 < 8 * 16 = 128)
    assert!(matches!(
        KdfParams::new(64, 1, 16),
        Err(BulkHashError::InvalidEncryptionParameters(_))
    ));
    assert!(KdfParams::new(128, 1, 16).is_ok());

    // 2. Malicious archives with OOM / CPU-hang / bad base64 / wrong lengths / unknown cipher
    let malicious_encryption_headers = [
        // 4 TB Argon2 memory OOM DoS
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": u32::MAX, "iterations": 1, "parallelism": 1 },
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
        // 1 million iterations CPU freeze DoS
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": 64, "iterations": 1_000_000, "parallelism": 1 },
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
        // Invalid Base64 salt
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": 64, "iterations": 1, "parallelism": 1 },
            "salt": "not!!valid!!base64",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
        // Salt too short (8 bytes instead of >= 16)
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": 64, "iterations": 1, "parallelism": 1 },
            "salt": "AAAAAAAAAAA=",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
        // Nonce wrong length (16 bytes instead of 12)
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": 64, "iterations": 1, "parallelism": 1 },
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAAAAAAAA=="
        }),
        // Unsupported cipher
        serde_json::json!({
            "cipher": "chacha20-poly1305",
            "kdf": "argon2id",
            "kdf_params": { "memory_kib": 64, "iterations": 1, "parallelism": 1 },
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
        // Unsupported KDF
        serde_json::json!({
            "cipher": "aes-256-gcm",
            "kdf": "pbkdf2",
            "kdf_params": { "memory_kib": 64, "iterations": 1, "parallelism": 1 },
            "salt": "AAAAAAAAAAAAAAAAAAAAAA==",
            "nonce": "AAAAAAAAAAAAAAAA"
        }),
    ];

    let dummy_ct = vec![0xAAu8; 32];
    let dummy_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&dummy_ct);
    for (idx, enc_header) in malicious_encryption_headers.iter().enumerate() {
        let meta_json = serde_json::json!({
            "version": FORMAT_VERSION_V3,
            "files_hashed": 0,
            "hash_time": { "secs": 0, "nanos": 0 },
            "date_utc": Utc::now().to_rfc3339(),
            "local_time": "2026-01-01T00:00:00Z",
            "os": "linux",
            "encryption": enc_header
        });
        let meta_bytes = serde_json::to_vec(&meta_json).expect("serialize malicious meta");
        let path = dir.path().join(format!("malicious_{idx}.hashed"));
        write_raw_hashed_archive(
            &path,
            &[
                ("meta.json", &meta_bytes),
                (ENCRYPTED_TREE_ENTRY, &dummy_ct),
                ("hash.sha256", dummy_hash.as_bytes()),
            ],
        );

        let inspect_err = FileManager::inspect_version(&path)
            .expect_err("malicious encryption header must fail inspect");
        assert!(
            matches!(inspect_err, BulkHashError::InvalidEncryptionParameters(_)),
            "case {idx} inspect expected InvalidEncryptionParameters, got {inspect_err:?}"
        );

        let open_err = FileManager::open_file_with_password(&path, "any-pw")
            .expect_err("malicious encryption header must fail open before KDF");
        assert!(
            matches!(open_err, BulkHashError::InvalidEncryptionParameters(_)),
            "case {idx} open expected InvalidEncryptionParameters, got {open_err:?}"
        );
    }

    // 3. Decompression-bomb guard: 16 KiB highly-compressible payload rejected when max_bytes = 256
    let bomb_plaintext = vec![b'A'; 16 * 1024];
    let opts =
        fast_encryption_options("bomb-pw").with_payload_compression(PayloadCompression::Deflate);
    let enc_meta = prepare_encryption_metadata(&opts).expect("enc meta");
    let aad = build_tree_aad(FORMAT_VERSION_V3, b"{}");
    let ct = encrypt_tree_payload(&bomb_plaintext, &opts, &enc_meta, &aad).expect("encrypt bomb");
    assert!(ct.len() < 128, "compressed ciphertext should be tiny");

    let bomb_err = decrypt_tree_payload(&ct, "bomb-pw", &enc_meta, &aad, 256, "bomb.hashed")
        .expect_err("decompression exceeding limit must fail");
    assert!(matches!(bomb_err, BulkHashError::FileIsCorrupted(_)));

    // Exact bound succeeds
    let ok_plain = decrypt_tree_payload(
        &ct,
        "bomb-pw",
        &enc_meta,
        &aad,
        bomb_plaintext.len() as u64,
        "bomb.hashed",
    )
    .expect("exact bound must succeed");
    assert_eq!(ok_plain.as_slice(), bomb_plaintext.as_slice());
}

#[test]
fn encrypt_decrypt_reencrypt_and_password_aware_migration_workflows() {
    let dir = TempDir::new("enc_workflows");
    let ts = DateTime::from_timestamp(1_765_300_000, 0).expect("valid ts");

    let mut tree = DirectoryNode::new(String::from("/project"));
    tree.insert_path(
        &["src", "secret.rs"],
        FileEntry::from_hash(String::from("1234abcd"), Some(2048), Some(ts)),
    );
    let meta = MetaData::new(1, Duration::from_millis(55), ts)
        .with_algorithm(HashAlgorithm::Blake3)
        .with_total_size(2048);

    // 1. Out-of-place encrypt_file on an unencrypted v3 archive
    let plain_path = FileManager::save_file(dir.path(), &tree, &meta).expect("save plain");
    let expected_tree_hash = FileManager::open_file(&plain_path)
        .expect("open plain")
        .get_hash()
        .to_string();

    let enc_out = dir.path().join("encrypted_copy.hashed");
    let opts_v1 = fast_encryption_options("first-password");
    let enc_report =
        FileManager::encrypt_file(&plain_path, &enc_out, &opts_v1).expect("encrypt_file");
    assert!(!enc_report.was_migrated());
    assert!(!FileManager::is_encrypted(&plain_path).expect("source stays plain"));
    assert!(FileManager::is_encrypted(&enc_out).expect("dest is encrypted"));

    let unlocked =
        FileManager::open_file_with_password(&enc_out, "first-password").expect("unlock");
    assert_eq!(unlocked.get_tree(), &tree);
    assert_eq!(unlocked.get_hash(), expected_tree_hash);

    // Calling encrypt_file on an already-encrypted snapshot fails with PasswordRequired
    assert!(matches!(
        FileManager::encrypt_file(&enc_out, dir.path().join("dup.hashed"), &opts_v1),
        Err(BulkHashError::PasswordRequired(_))
    ));

    // 2. In-place encrypt_file on a legacy v1 snapshot -> transparently upgrades v1 -> v3 & encrypts!
    let legacy_v1_dir = TempDir::new("enc_v1_inplace");
    let legacy_v1_path = legacy_v1_dir.path().join("legacy.hashed");
    let v1_tree =
        r#"{"name":"/legacy","files":{"doc.txt":{"Ok":"face0001"}},"sub_directories":{}}"#;
    let v1_hash = HashAlgorithm::Sha256.get_hash_from_bytes(v1_tree.as_bytes());
    let v1_meta = format!(
        r#"{{"version":1,"files_hashed":1,"hash_time":{{"secs":0,"nanos":5}},"date_utc":"{}","local_time":"2026-01-01T00:00:00Z","os":"linux"}}"#,
        ts.to_rfc3339()
    );
    write_raw_hashed_archive(
        &legacy_v1_path,
        &[
            ("meta.json", v1_meta.as_bytes()),
            ("tree.json", v1_tree.as_bytes()),
            ("hash.sha256", v1_hash.as_bytes()),
        ],
    );

    let v1_enc_report = FileManager::encrypt_file(&legacy_v1_path, &legacy_v1_path, &opts_v1)
        .expect("in-place encrypt v1");
    assert!(v1_enc_report.was_migrated());
    assert_eq!(v1_enc_report.original_version(), FORMAT_VERSION_V1);
    assert_eq!(v1_enc_report.target_version(), FORMAT_VERSION_V3);
    assert!(FileManager::is_encrypted(&legacy_v1_path).expect("v1 now encrypted"));
    let loaded_v1_enc = FileManager::open_file_with_password(&legacy_v1_path, "first-password")
        .expect("open v1 enc");
    assert_eq!(loaded_v1_enc.get_meta().get_version(), FORMAT_VERSION_V3);
    assert_eq!(
        loaded_v1_enc.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V1)
    );
    assert_eq!(
        loaded_v1_enc
            .get_tree()
            .files
            .get("doc.txt")
            .and_then(FileEntry::hash),
        Some("face0001")
    );
    // Ensure zero leftover temp staging files in directory
    assert_eq!(
        fs::read_dir(legacy_v1_dir.path())
            .expect("read dir")
            .count(),
        1
    );

    // 3. Re-encrypt (password rotation + compression change) in-place & out-of-place
    let old_enc_meta = FileManager::inspect_version(&enc_out)
        .expect("inspect before reencrypt")
        .encryption()
        .expect("old enc meta")
        .clone();
    let opts_v2 = fast_encryption_options("second-rotated-password")
        .with_payload_compression(PayloadCompression::None);

    // Wrong current password leaves file untouched
    let orig_enc_bytes = fs::read(&enc_out).expect("read enc_out bytes");
    assert!(matches!(
        FileManager::reencrypt_file(&enc_out, &enc_out, "wrong-old-pw", &opts_v2),
        Err(BulkHashError::DecryptionFailed(_))
    ));
    assert_eq!(
        fs::read(&enc_out).expect("verify untouched"),
        orig_enc_bytes
    );

    // Valid in-place rotation
    FileManager::reencrypt_file(&enc_out, &enc_out, "first-password", &opts_v2)
        .expect("in-place reencrypt");
    let new_enc_meta = FileManager::inspect_version(&enc_out)
        .expect("inspect after reencrypt")
        .encryption()
        .expect("new enc meta")
        .clone();
    assert_ne!(new_enc_meta.salt, old_enc_meta.salt);
    assert_ne!(new_enc_meta.nonce, old_enc_meta.nonce);
    assert_eq!(new_enc_meta.payload_compression, PayloadCompression::None);

    // Old password no longer works; new password succeeds
    assert!(matches!(
        FileManager::open_file_with_password(&enc_out, "first-password"),
        Err(BulkHashError::DecryptionFailed(_))
    ));
    let reopened_rotated =
        FileManager::open_file_with_password(&enc_out, "second-rotated-password")
            .expect("open with new password");
    assert_eq!(reopened_rotated.get_tree(), &tree);
    assert_eq!(reopened_rotated.get_hash(), expected_tree_hash);

    // 4. Password-aware migration on encrypted v3 preserves encryption (fresh salt/nonce)
    assert!(matches!(
        FileManager::migrate_file(&enc_out, dir.path().join("mig_no_pw.hashed")),
        Err(BulkHashError::PasswordRequired(_))
    ));
    let mig_enc_copy = dir.path().join("mig_enc_copy.hashed");
    let mig_enc_report = FileManager::migrate_file_with_password(
        &enc_out,
        &mig_enc_copy,
        Some("second-rotated-password"),
    )
    .expect("migrate encrypted copy");
    assert!(!mig_enc_report.was_migrated());
    assert!(FileManager::is_encrypted(&mig_enc_copy).expect("copy stays encrypted"));
    let copy_enc_meta = FileManager::inspect_version(&mig_enc_copy)
        .expect("inspect copy")
        .encryption()
        .expect("copy enc")
        .clone();
    assert_ne!(copy_enc_meta.salt, new_enc_meta.salt);
    assert_ne!(copy_enc_meta.nonce, new_enc_meta.nonce);
    assert_eq!(copy_enc_meta.kdf_params, new_enc_meta.kdf_params);
    assert_eq!(
        copy_enc_meta.payload_compression,
        new_enc_meta.payload_compression
    );

    let inplace_enc_mig = FileManager::migrate_file_in_place_with_password(
        &enc_out,
        true,
        Some("second-rotated-password"),
    )
    .expect("in-place migrate current encrypted is no-op");
    assert!(!inplace_enc_mig.was_migrated());
    assert!(inplace_enc_mig.backup_path().is_none());

    // 5. Decrypt back to unencrypted (out-of-place & in-place)
    let dec_out = dir.path().join("decrypted.hashed");
    FileManager::decrypt_file(&enc_out, &dec_out, "second-rotated-password")
        .expect("decrypt out-of-place");
    assert!(!FileManager::is_encrypted(&dec_out).expect("decrypted is plain"));
    let dec_meta_raw = read_zip_entry_string(&dec_out, "meta.json");
    assert!(!dec_meta_raw.contains("encryption"));
    let dec_loaded = FileManager::open_file(&dec_out).expect("open decrypted without pw");
    assert_eq!(dec_loaded.get_tree(), &tree);
    assert_eq!(dec_loaded.get_hash(), expected_tree_hash);

    // In-place decrypt
    FileManager::decrypt_file(&enc_out, &enc_out, "second-rotated-password")
        .expect("decrypt in-place");
    assert!(!FileManager::is_encrypted(&enc_out).expect("enc_out now plain"));
    assert_eq!(
        FileManager::open_file(&enc_out)
            .expect("open now-plain")
            .get_tree(),
        &tree
    );

    // Calling decrypt_file or reencrypt_file on an unencrypted archive returns SnapshotNotEncrypted
    assert!(matches!(
        FileManager::decrypt_file(&plain_path, dir.path().join("x.hashed"), ""),
        Err(BulkHashError::SnapshotNotEncrypted(_))
    ));
    assert!(matches!(
        FileManager::reencrypt_file(&plain_path, dir.path().join("x.hashed"), "any", &opts_v1),
        Err(BulkHashError::SnapshotNotEncrypted(_))
    ));
}

#[test]
fn v2_to_v3_migration_and_encryption_error_gui_serialization() {
    let dir = TempDir::new("v2_to_v3_and_errors");
    let ts = DateTime::from_timestamp(1_765_400_000, 0).expect("valid ts");

    // 1. Construct a canonical v2 archive and verify 1-step v2 -> v3 migration
    let v2_path = dir.path().join("snapshot_v2.hashed");
    let v2_tree = serde_json::json!({
        "name": "/v2_workspace",
        "files": {
            "app.bin": { "hash": "9999ffff", "size": 512, "modified_utc": ts.to_rfc3339() }
        },
        "sub_directories": {}
    });
    let v2_tree_bytes = serde_json::to_vec(&v2_tree).expect("serialize v2 tree");
    let v2_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&v2_tree_bytes);
    let v2_meta = serde_json::json!({
        "version": FORMAT_VERSION_V2,
        "files_hashed": 1,
        "hash_time": { "secs": 0, "nanos": 1000 },
        "date_utc": ts.to_rfc3339(),
        "local_time": "2026-01-01T00:00:00Z",
        "os": "linux",
        "algorithm": "Blake3",
        "total_size": 512
    });
    let v2_meta_bytes = serde_json::to_vec(&v2_meta).expect("serialize v2 meta");
    write_raw_hashed_archive(
        &v2_path,
        &[
            ("meta.json", &v2_meta_bytes),
            ("tree.json", &v2_tree_bytes),
            ("hash.sha256", v2_hash.as_bytes()),
        ],
    );

    let v2_info = FileManager::inspect_version(&v2_path).expect("inspect v2");
    assert_eq!(v2_info.version, FORMAT_VERSION_V2);
    assert!(!v2_info.is_encrypted());
    assert_eq!(
        v2_info.compatibility,
        VersionCompatibility::NeedsMigration {
            from_version: FORMAT_VERSION_V2,
            to_version: FORMAT_VERSION_V3,
            steps_required: 1,
        }
    );

    let loaded_v2 = FileManager::open_file(&v2_path).expect("open & migrate v2 -> v3");
    assert!(loaded_v2.was_migrated());
    assert_eq!(loaded_v2.get_original_version(), FORMAT_VERSION_V2);
    assert_eq!(loaded_v2.get_meta().get_version(), FORMAT_VERSION_V3);
    assert_eq!(
        loaded_v2.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V2)
    );
    assert_eq!(loaded_v2.get_meta().get_total_size(), Some(512));
    assert!(!loaded_v2.is_encrypted());

    let mig_report =
        FileManager::migrate_file_in_place(&v2_path, true).expect("in-place migrate v2 -> v3");
    assert!(mig_report.was_migrated());
    assert_eq!(mig_report.original_version(), FORMAT_VERSION_V2);
    assert_eq!(mig_report.target_version(), FORMAT_VERSION_V3);
    assert_eq!(mig_report.steps().len(), 1);
    assert!(
        mig_report
            .backup_path()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".v2.bak"))
    );

    let reopened_v3 = FileManager::open_file(&v2_path).expect("reopen upgraded v3");
    assert!(!reopened_v3.was_migrated());
    assert_eq!(reopened_v3.get_meta().get_version(), FORMAT_VERSION_V3);
    assert_eq!(
        reopened_v3.get_meta().get_migrated_from(),
        Some(FORMAT_VERSION_V2)
    );

    // 2. Verify clean GUI/IPC JSON serialization of all new encryption BulkHashError variants
    let error_cases = [
        (
            BulkHashError::PasswordRequired(String::from("/tmp/secret.hashed")),
            "PasswordRequired",
        ),
        (BulkHashError::EmptyPassword, "EmptyPassword"),
        (
            BulkHashError::DecryptionFailed(String::from("/tmp/secret.hashed")),
            "DecryptionFailed",
        ),
        (
            BulkHashError::EncryptionFailed(String::from("rng unavailable")),
            "EncryptionFailed",
        ),
        (
            BulkHashError::InvalidEncryptionParameters(String::from("bad salt")),
            "InvalidEncryptionParameters",
        ),
        (
            BulkHashError::SnapshotNotEncrypted(String::from("/tmp/plain.hashed")),
            "SnapshotNotEncrypted",
        ),
    ];

    for (err, expected_kind) in error_cases {
        let json = serde_json::to_value(&err).expect("serialize BulkHashError");
        assert_eq!(json["kind"], expected_kind);
        assert!(
            json["message"].as_str().is_some_and(|msg| !msg.is_empty()),
            "error message for {expected_kind} must be non-empty"
        );
    }
}
