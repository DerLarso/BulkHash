use bulk_hash_lib::core::{
    hash_manager::{HashAlgorithm, HashManager},
    io::{
        bulk_hash_error::BulkHashError, directory_node::DirectoryNode, file_manager::FileManager,
        meta_data::MetaData,
    },
    scan_manager::ScanManager,
    structs::file_info::FileInfo,
};
use chrono::Utc;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
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
