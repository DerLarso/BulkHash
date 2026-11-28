use bulk_hash_lib::core::{
    diff::{
        ComparisonOptions, ComparisonWarning, DiffDirectoryNode, DiffDuplicateScope, DiffFileEntry,
        DiffStatistics, DuplicateFinder, DuplicateOccurrence, DuplicateOptions, DuplicateReport,
        DuplicateSortOrder, DuplicateSource, EntryPresence, FileComparisonOutcome, FileStatus, FileStatusCounts,
        FileStatusDetail, FileStatusFilter, FileStatusPolicy, FolderDuplicateSummary, FolderStatus,
        FolderStatusCounts, FolderStatusFilter, LiveComparer, LiveComparisonOptions,
        LiveComparisonResult, MAX_WARNING_SAMPLES, NameMatchingMode, PrecheckReport,
        StorageStatistics, TreeComparer, TreeDiff, WarningCode, WarningDetails, WarningSeverity,
        classify_file_entry, classify_file_entry_detailed, classify_pair,
        compare_archive_with_folder, compare_archive_with_folder_with_options,
        compare_snapshot_with_folder, compare_snapshot_with_folder_with_options,
        compare_snapshots, compare_snapshots_with_options, compare_trees,
        compare_trees_with_options, extract_path_basename, find_duplicates_in_archive,
        find_duplicates_in_archive_with_password, find_duplicates_in_diff,
        find_duplicates_in_diff_with_options, find_duplicates_in_snapshot, find_duplicates_in_tree,
        find_duplicates_in_tree_with_options, format_bytes, format_signed_bytes,
        infer_os_from_path, precheck_archive_files, precheck_archive_with_folder,
        precheck_metadata, precheck_snapshot_with_folder, precheck_snapshots, precheck_trees,
        precheck_trees_with_metadata,
    },
    hash_manager::HashAlgorithm,
    hidden_filter::HiddenFileFilter,
    ignore_list::IgnoreList,
    io::{
        bulk_hash_error::BulkHashError,
        directory_node::{DirectoryNode, FileEntry},
        encryption::{EncryptionOptions, KdfParams},
        file_manager::FileManager,
        meta_data::MetaData,
    },
    scan_manager::{ScanControl, ScanManager},
    structs::bulk_hash_file_struct::BulkHashFileStruct,
};
use chrono::{DateTime, TimeZone, Utc};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            "bulkhash_diff_test_{prefix}_{}_{nanos}",
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

fn utc(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
        .single()
        .expect("valid UTC timestamp")
}

fn hash64(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn hash32(ch: char) -> String {
    std::iter::repeat_n(ch, 32).collect()
}

fn file_entry(hash: String, size: u64, modified: DateTime<Utc>) -> FileEntry {
    FileEntry::from_hash(hash, Some(size), Some(modified))
}

fn sample_meta(os: &str, algo: HashAlgorithm, date: DateTime<Utc>) -> MetaData {
    MetaData::new(2, Duration::from_millis(25), date)
        .with_os(os)
        .with_algorithm(algo)
}

#[test]
fn identical_trees_produce_clean_diff_with_no_warnings() {
    let t = utc(2026, 5, 10, 12, 0, 0);
    let mut left = DirectoryNode::new(String::from("/home/lars/project"));
    left.insert_path(&["README.md"], file_entry(hash64('a'), 120, t));
    left.insert_path(&["src", "main.rs"], file_entry(hash64('b'), 512, t));
    left.insert_path(
        &["src", "core", "mod.rs"],
        file_entry(hash64('c'), 64, t),
    );

    let right = left.clone();

    let diff = compare_trees(&left, &right);
    assert!(diff.is_identical());
    assert!(!diff.is_truncated());
    assert!(!diff.has_warnings());
    assert!(!diff.has_critical_warnings());
    assert_eq!(diff.left_info().total_files, 3);
    assert_eq!(diff.right_info().total_files, 3);
    assert_eq!(diff.left_info().total_directories, 2);
    assert_eq!(diff.right_info().total_directories, 2);
    assert_eq!(diff.left_info().error_files, 0);
    assert_eq!(diff.right_info().error_files, 0);

    // Deterministic sorted depth-first order.
    let paths: Vec<&str> = diff.iter_files().map(DiffFileEntry::relative_path).collect();
    assert_eq!(paths, vec!["README.md", "src/main.rs", "src/core/mod.rs"]);
    assert_eq!(diff.iter_changed_files().count(), 0);

    let dir_paths: Vec<&str> = diff
        .iter_directories()
        .map(DiffDirectoryNode::relative_path)
        .collect();
    assert_eq!(dir_paths, vec!["", "src", "src/core"]);

    // Lookup helpers accept both `/` and `\` separators.
    let main_rs = diff.find_file("src\\main.rs").expect("find main.rs");
    assert_eq!(main_rs.presence(), EntryPresence::Both);
    assert_eq!(main_rs.outcome(), FileComparisonOutcome::Identical);
    assert_eq!(main_rs.hashes_equal(), Some(true));
    assert_eq!(main_rs.size_delta(), Some(0));
    assert_eq!(main_rs.modified_changed(), Some(false));
    assert!(!main_rs.has_error());

    assert_eq!(
        diff.find_directory("").expect("root").relative_path(),
        ""
    );
    assert_eq!(
        diff.find_directory(".").expect("root dot").relative_path(),
        ""
    );
    assert_eq!(
        diff.find_directory("/").expect("root slash").relative_path(),
        ""
    );
    assert_eq!(
        diff.find_directory("src/core").expect("src/core").depth(),
        2
    );
}

#[test]
fn detects_all_file_and_directory_outcomes_recursively() {
    let t1 = utc(2026, 5, 10, 12, 0, 0);
    let t2 = utc(2026, 5, 11, 15, 30, 0);

    let mut left = DirectoryNode::new(String::from("/data/app"));
    left.insert_path(&["same.txt"], file_entry(hash64('a'), 100, t1));
    left.insert_path(&["meta_only.txt"], file_entry(hash64('b'), 200, t1));
    left.insert_path(&["changed.txt"], file_entry(hash64('c'), 300, t1));
    left.insert_path(&["removed.txt"], file_entry(hash64('d'), 400, t1));
    left.insert_path(
        &["errored.txt"],
        FileEntry::from_error(String::from("Permission denied"), None, None),
    );
    left.insert_path(&["old_dir", "nested", "gone.bin"], file_entry(hash64('e'), 50, t1));
    left.sub_directories
        .insert(String::from("empty_left"), DirectoryNode::new(String::from("empty_left")));

    let mut right = DirectoryNode::new(String::from("/data/app"));
    // Uppercase hex hash should still be treated as equal to lowercase.
    right.insert_path(&["same.txt"], file_entry(hash64('A'), 100, t1));
    right.insert_path(&["meta_only.txt"], file_entry(hash64('b'), 200, t2));
    right.insert_path(&["changed.txt"], file_entry(hash64('f'), 350, t2));
    right.insert_path(&["added.txt"], file_entry(hash64('1'), 125, t2));
    right.insert_path(&["errored.txt"], file_entry(hash64('2'), 80, t2));
    right.insert_path(&["new_dir", "child.bin"], file_entry(hash64('3'), 75, t2));
    right.sub_directories
        .insert(String::from("empty_right"), DirectoryNode::new(String::from("empty_right")));

    let diff = compare_trees(&left, &right);
    assert!(!diff.is_identical());

    let same = diff.find_file("same.txt").expect("same.txt");
    assert_eq!(same.outcome(), FileComparisonOutcome::Identical);
    assert_eq!(same.hashes_equal(), Some(true));

    let meta_only = diff.find_file("meta_only.txt").expect("meta_only.txt");
    assert_eq!(meta_only.outcome(), FileComparisonOutcome::MetadataChanged);
    assert_eq!(meta_only.hashes_equal(), Some(true));
    assert_eq!(meta_only.modified_changed(), Some(true));
    assert_eq!(meta_only.size_delta(), Some(0));

    let changed = diff.find_file("changed.txt").expect("changed.txt");
    assert_eq!(changed.outcome(), FileComparisonOutcome::ContentChanged);
    assert_eq!(changed.hashes_equal(), Some(false));
    assert_eq!(changed.size_delta(), Some(50));

    let removed = diff.find_file("removed.txt").expect("removed.txt");
    assert_eq!(removed.presence(), EntryPresence::OnlyLeft);
    assert_eq!(removed.outcome(), FileComparisonOutcome::OnlyLeft);
    assert_eq!(removed.size_delta(), Some(-400));
    assert_eq!(removed.left_name(), Some("removed.txt"));
    assert_eq!(removed.right_name(), None);

    let added = diff.find_file("added.txt").expect("added.txt");
    assert_eq!(added.presence(), EntryPresence::OnlyRight);
    assert_eq!(added.outcome(), FileComparisonOutcome::OnlyRight);
    assert_eq!(added.size_delta(), Some(125));
    assert_eq!(added.left_name(), None);
    assert_eq!(added.right_name(), Some("added.txt"));

    let errored = diff.find_file("errored.txt").expect("errored.txt");
    assert_eq!(errored.presence(), EntryPresence::Both);
    assert_eq!(errored.outcome(), FileComparisonOutcome::Error);
    assert!(errored.has_error());
    assert_eq!(errored.left_error(), Some("Permission denied"));
    assert_eq!(errored.right_error(), None);
    assert_eq!(errored.hashes_equal(), None);

    // Subtrees present only on one side must be fully traversed.
    let old_dir = diff.find_directory("old_dir").expect("old_dir");
    assert_eq!(old_dir.presence(), EntryPresence::OnlyLeft);
    assert_eq!(old_dir.depth(), 1);
    let gone = diff
        .find_file("old_dir/nested/gone.bin")
        .expect("old_dir/nested/gone.bin");
    assert_eq!(gone.presence(), EntryPresence::OnlyLeft);
    assert_eq!(gone.outcome(), FileComparisonOutcome::OnlyLeft);

    let new_dir = diff.find_directory("new_dir").expect("new_dir");
    assert_eq!(new_dir.presence(), EntryPresence::OnlyRight);
    let child = diff.find_file("new_dir/child.bin").expect("new_dir/child.bin");
    assert_eq!(child.presence(), EntryPresence::OnlyRight);
    assert_eq!(child.outcome(), FileComparisonOutcome::OnlyRight);

    // Empty subdirectories are preserved with accurate presence.
    assert_eq!(
        diff.find_directory("empty_left").expect("empty_left").presence(),
        EntryPresence::OnlyLeft
    );
    assert_eq!(
        diff.find_directory("empty_right")
            .expect("empty_right")
            .presence(),
        EntryPresence::OnlyRight
    );

    // Scan error warning should fire, while missing metadata must NOT falsely trigger
    // just because the errored file had no size/mtime.
    assert!(diff.has_warning(WarningCode::ScanErrorsPresent));
    assert!(!diff.has_warning(WarningCode::MissingExtendedMetadata));

    // Disabling metadata comparison treats `meta_only.txt` as `Identical`.
    let no_meta_opts = ComparisonOptions::new().with_compare_metadata(false);
    let diff_no_meta = compare_trees_with_options(&left, &right, &no_meta_opts);
    assert_eq!(
        diff_no_meta
            .find_file("meta_only.txt")
            .expect("meta_only.txt")
            .outcome(),
        FileComparisonOutcome::Identical
    );
}

#[test]
fn warns_on_windows_vs_linux_from_metadata_and_inferred_paths() {
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 1, 11, 0, 0);

    let mut win_tree = DirectoryNode::new(String::from(r"C:\Users\Lars\Projects\MyApp"));
    win_tree.insert_path(&["src", "lib.rs"], file_entry(hash64('a'), 100, t1));

    let mut linux_tree = DirectoryNode::new(String::from("/home/lars/projects/MyApp"));
    linux_tree.insert_path(&["src", "lib.rs"], file_entry(hash64('a'), 100, t1));

    // 1. Explicit metadata OS mismatch (Windows vs Linux).
    let win_meta = sample_meta("windows", HashAlgorithm::Blake3, t1);
    let linux_meta = sample_meta("linux", HashAlgorithm::Blake3, t2);
    let comparer = TreeComparer::new();
    let diff = comparer.compare_trees_with_metadata(
        &win_tree,
        Some(&win_meta),
        &linux_tree,
        Some(&linux_meta),
    );

    assert!(diff.is_identical());
    assert!(diff.has_warning(WarningCode::DifferentOperatingSystem));
    assert!(!diff.has_warning(WarningCode::DifferentRootName));
    let os_warn = diff
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::DifferentOperatingSystem)
        .expect("OS warning");
    assert_eq!(os_warn.severity, WarningSeverity::Warning);
    assert_eq!(
        os_warn.details,
        WarningDetails::DifferentOperatingSystem {
            left_os: String::from("windows"),
            right_os: String::from("linux"),
            inferred_from_paths: false,
        }
    );

    // 2. Without metadata, OS mismatch is still inferred from root path styles.
    let diff_inferred = compare_trees(&win_tree, &linux_tree);
    let inferred_warn = diff_inferred
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::DifferentOperatingSystem)
        .expect("inferred OS warning");
    assert_eq!(
        inferred_warn.details,
        WarningDetails::DifferentOperatingSystem {
            left_os: String::from("windows"),
            right_os: String::from("unix"),
            inferred_from_paths: true,
        }
    );

    // 3. Mixed: Linux metadata on left + POSIX path without metadata on right -> NO false positive.
    let mut linux_tree_2 = DirectoryNode::new(String::from("/opt/deployments/MyApp"));
    linux_tree_2.insert_path(&["src", "lib.rs"], file_entry(hash64('a'), 100, t1));
    let diff_linux_unix = comparer.compare_trees_with_metadata(
        &linux_tree,
        Some(&linux_meta),
        &linux_tree_2,
        None,
    );
    assert!(!diff_linux_unix.has_warning(WarningCode::DifferentOperatingSystem));

    // 4. Mixed: Windows metadata on left + POSIX path without metadata on right -> WARNS.
    let diff_win_unix = comparer.compare_trees_with_metadata(
        &win_tree,
        Some(&win_meta),
        &linux_tree,
        None,
    );
    assert!(diff_win_unix.has_warning(WarningCode::DifferentOperatingSystem));

    // 5. Linux vs macOS metadata -> WARNS.
    let macos_meta = sample_meta("macos", HashAlgorithm::Blake3, t2);
    let diff_linux_mac = comparer.compare_trees_with_metadata(
        &linux_tree,
        Some(&linux_meta),
        &linux_tree_2,
        Some(&macos_meta),
    );
    assert!(diff_linux_mac.has_warning(WarningCode::DifferentOperatingSystem));

    // 6. Bare relative root names without metadata -> NO false positive OS warning.
    let mut bare_a = DirectoryNode::new(String::from("snapshot_root"));
    bare_a.insert_path(&["a.txt"], file_entry(hash64('a'), 10, t1));
    let mut bare_b = DirectoryNode::new(String::from("snapshot_root"));
    bare_b.insert_path(&["a.txt"], file_entry(hash64('a'), 10, t1));
    assert!(!compare_trees(&bare_a, &bare_b).has_warning(WarningCode::DifferentOperatingSystem));
}

#[test]
fn warns_on_incompatible_hash_algorithms_and_mismatched_hash_lengths() {
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 1, 11, 0, 0);

    let mut left = DirectoryNode::new(String::from("/data/app"));
    left.insert_path(&["file.bin"], file_entry(hash64('a'), 10, t1));

    let mut right = DirectoryNode::new(String::from("/data/app"));
    right.insert_path(&["file.bin"], file_entry(hash32('b'), 10, t1));

    let comparer = TreeComparer::new();

    // 1. Metadata declares BLAKE3 vs MD5 -> Critical DifferentHashAlgorithm, no duplicate length warning.
    let left_meta = sample_meta("linux", HashAlgorithm::Blake3, t1);
    let right_meta = sample_meta("linux", HashAlgorithm::Md5, t2);
    let diff = comparer.compare_trees_with_metadata(&left, Some(&left_meta), &right, Some(&right_meta));

    assert!(diff.has_critical_warnings());
    assert!(diff.has_warning(WarningCode::DifferentHashAlgorithm));
    assert!(!diff.has_warning(WarningCode::InconsistentHashLengths));
    assert_eq!(diff.warnings()[0].severity, WarningSeverity::Critical);
    assert_eq!(diff.warnings()[0].code, WarningCode::DifferentHashAlgorithm);

    // 2. Without metadata, disjoint observed hash lengths (64 vs 32) trigger Critical InconsistentHashLengths.
    let raw_diff = compare_trees(&left, &right);
    assert!(raw_diff.has_critical_warnings());
    assert!(raw_diff.has_warning(WarningCode::InconsistentHashLengths));
    assert!(!raw_diff.has_warning(WarningCode::UnknownHashAlgorithm));

    // 3. Metadata present without algorithm -> Warning UnknownHashAlgorithm + Critical InconsistentHashLengths.
    let left_no_algo = MetaData::new(1, Duration::from_millis(5), t1).with_os("linux");
    let right_no_algo = MetaData::new(1, Duration::from_millis(5), t2).with_os("linux");
    let unknown_diff = comparer.compare_trees_with_metadata(
        &left,
        Some(&left_no_algo),
        &right,
        Some(&right_no_algo),
    );
    assert!(unknown_diff.has_warning(WarningCode::UnknownHashAlgorithm));
    assert!(unknown_diff.has_warning(WarningCode::InconsistentHashLengths));
    // Verify sorting: Critical first, then Warning.
    assert_eq!(unknown_diff.warnings()[0].severity, WarningSeverity::Critical);
    assert_eq!(unknown_diff.warnings()[1].severity, WarningSeverity::Warning);
}

#[test]
fn warns_on_different_filters_reversed_timestamps_and_identical_snapshot() {
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 2, 10, 0, 0);

    let mut tree = DirectoryNode::new(String::from("/data/app"));
    tree.insert_path(&["a.txt"], file_entry(hash64('a'), 10, t1));

    let ignore_a = IgnoreList::from_patterns(["node_modules/", "*.log"]).expect("valid ignore list");
    let ignore_b = IgnoreList::from_patterns(["node_modules/"]).expect("valid ignore list");

    // Left is NEWER than right, different ignore lists, different hidden filters.
    let left_meta = sample_meta("linux", HashAlgorithm::Blake3, t2)
        .with_ignore_list(ignore_a)
        .with_hidden_filter(HiddenFileFilter::exclude_all());
    let right_meta = sample_meta("linux", HashAlgorithm::Blake3, t1)
        .with_ignore_list(ignore_b)
        .with_hidden_filter(HiddenFileFilter::include_all());

    let diff = TreeComparer::new().compare_trees_with_metadata(
        &tree,
        Some(&left_meta),
        &tree,
        Some(&right_meta),
    );
    assert!(diff.has_warning(WarningCode::DifferentIgnoreLists));
    assert!(diff.has_warning(WarningCode::DifferentHiddenFileFilter));
    assert!(diff.has_warning(WarningCode::ReversedChronologicalOrder));

    // Identical filters (`None` vs `include_all()`, `None` vs empty ignore list) do NOT warn.
    let clean_left = sample_meta("linux", HashAlgorithm::Blake3, t1)
        .with_ignore_list(IgnoreList::new())
        .with_hidden_filter(HiddenFileFilter::include_all());
    let clean_right = sample_meta("linux", HashAlgorithm::Blake3, t2);
    let clean_diff = TreeComparer::new().compare_trees_with_metadata(
        &tree,
        Some(&clean_left),
        &tree,
        Some(&clean_right),
    );
    assert!(!clean_diff.has_warnings());

    // Comparing the exact same BulkHashFileStruct warns with IdenticalSnapshot (Info).
    let snap = BulkHashFileStruct::new(clean_left, tree.clone(), hash64('z'));
    let same_snap_diff = compare_snapshots(&snap, &snap);
    assert!(same_snap_diff.is_identical());
    assert!(same_snap_diff.has_warning(WarningCode::IdenticalSnapshot));
    assert_eq!(same_snap_diff.warnings().len(), 1);
    assert_eq!(same_snap_diff.warnings()[0].severity, WarningSeverity::Info);

    // Same tree hash at DIFFERENT timestamps must NOT emit IdenticalSnapshot.
    let snap_later = BulkHashFileStruct::new(clean_right, tree, hash64('z'));
    let diff_later = compare_snapshots(&snap, &snap_later);
    assert!(!diff_later.has_warning(WarningCode::IdenticalSnapshot));
    assert!(!diff_later.has_warnings());
}

#[test]
fn warns_on_different_root_names_no_common_entries_empty_trees_and_os_noise() {
    let t = utc(2026, 6, 1, 10, 0, 0);

    // Completely disjoint trees with different root basenames + OS metadata files.
    let mut left = DirectoryNode::new(String::from("/home/lars/Photos"));
    left.insert_path(&["vacation.jpg"], file_entry(hash64('a'), 500, t));
    left.insert_path(&[".DS_Store"], file_entry(hash64('b'), 12, t));

    let mut right = DirectoryNode::new(String::from("/home/lars/Documents"));
    right.insert_path(&["report.pdf"], file_entry(hash64('c'), 900, t));
    right.insert_path(&["Thumbs.db"], file_entry(hash64('d'), 24, t));

    let diff = compare_trees(&left, &right);
    assert!(diff.has_warning(WarningCode::DifferentRootName));
    assert!(diff.has_warning(WarningCode::NoCommonEntries));
    assert!(diff.has_warning(WarningCode::OsMetadataFilesInDiff));
    assert!(!diff.has_warning(WarningCode::EmptyTree));

    let noise_warn = diff
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::OsMetadataFilesInDiff)
        .expect("OS noise warning");
    match &noise_warn.details {
        WarningDetails::OsMetadataFilesInDiff {
            count,
            sample_paths,
        } => {
            assert_eq!(*count, 2);
            assert!(sample_paths.contains(&String::from(".DS_Store")));
            assert!(sample_paths.contains(&String::from("Thumbs.db")));
        }
        other => panic!("unexpected details: {other:?}"),
    }

    // Empty tree vs non-empty tree emits EmptyTree (Info) and NOT NoCommonEntries.
    let empty = DirectoryNode::new(String::from("/home/lars/Photos"));
    let diff_empty = compare_trees(&empty, &left);
    assert!(diff_empty.has_warning(WarningCode::EmptyTree));
    assert!(!diff_empty.has_warning(WarningCode::NoCommonEntries));

    // Both empty.
    let diff_both_empty = compare_trees(&empty, &empty);
    assert!(diff_both_empty.is_identical());
    assert!(diff_both_empty.has_warning(WarningCode::EmptyTree));
    assert!(!diff_both_empty.has_warning(WarningCode::NoCommonEntries));
}

#[test]
fn case_sensitive_vs_case_insensitive_matching_and_collision_safety() {
    let t = utc(2026, 6, 1, 10, 0, 0);

    // 1. Exact mode detects case-only path differences for both files and directories.
    let mut left = DirectoryNode::new(String::from("/proj"));
    left.insert_path(&["README.md"], file_entry(hash64('a'), 100, t));
    left.insert_path(&["Assets", "Icon.png"], file_entry(hash64('b'), 200, t));
    left.insert_path(&["Äpfel.txt"], file_entry(hash64('c'), 50, t));

    let mut right = DirectoryNode::new(String::from("/proj"));
    right.insert_path(&["readme.md"], file_entry(hash64('a'), 100, t));
    right.insert_path(&["assets", "icon.png"], file_entry(hash64('b'), 200, t));
    right.insert_path(&["äpfel.txt"], file_entry(hash64('c'), 50, t));

    let exact_diff = compare_trees(&left, &right);
    assert!(!exact_diff.is_identical());
    assert!(exact_diff.has_warning(WarningCode::CaseOnlyPathDifference));
    assert!(!exact_diff.has_warning(WarningCode::CaseOnlyNameMatched));
    assert_eq!(
        exact_diff.find_file("README.md").expect("README.md").presence(),
        EntryPresence::OnlyLeft
    );
    assert_eq!(
        exact_diff.find_file("readme.md").expect("readme.md").presence(),
        EntryPresence::OnlyRight
    );

    // 2. CaseInsensitive mode aligns files, directories, and Unicode umlauts cleanly.
    let ci_opts = ComparisonOptions::new().with_case_insensitive(true);
    let ci_diff = compare_trees_with_options(&left, &right, &ci_opts);
    assert!(ci_diff.is_identical());
    assert!(!ci_diff.has_warning(WarningCode::CaseOnlyPathDifference));
    assert!(ci_diff.has_warning(WarningCode::CaseOnlyNameMatched));

    let readme = ci_diff.find_file("readme.md").expect("matched readme.md");
    assert_eq!(readme.presence(), EntryPresence::Both);
    assert_eq!(readme.outcome(), FileComparisonOutcome::Identical);
    assert!(readme.name_case_differs());
    assert_eq!(readme.left_name(), Some("README.md"));
    assert_eq!(readme.right_name(), Some("readme.md"));

    let assets_dir = ci_diff.find_directory("assets").expect("matched assets");
    assert_eq!(assets_dir.presence(), EntryPresence::Both);
    assert!(assets_dir.name_case_differs());
    assert_eq!(assets_dir.left_name(), Some("Assets"));
    assert_eq!(assets_dir.right_name(), Some("assets"));

    let icon = ci_diff.find_file("assets/icon.png").expect("matched icon");
    assert!(icon.name_case_differs());
    assert_eq!(icon.left_name(), Some("Icon.png"));
    assert_eq!(icon.right_name(), Some("icon.png"));

    // Verify sample pair uses the real left relative path ("Assets/Icon.png", "assets/icon.png").
    let matched_warn = ci_diff
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::CaseOnlyNameMatched)
        .expect("CaseOnlyNameMatched warning");
    match &matched_warn.details {
        WarningDetails::CaseOnlyNameMatched {
            count,
            sample_pairs,
        } => {
            assert_eq!(*count, 4); // README.md, Äpfel.txt, Assets, Assets/Icon.png
            assert!(sample_pairs.contains(&(
                String::from("Assets/Icon.png"),
                String::from("assets/icon.png")
            )));
        }
        other => panic!("unexpected details: {other:?}"),
    }

    // 3. Same-directory case collision: exact match prioritized, colliding entry NEVER dropped!
    let mut linux_colliding = DirectoryNode::new(String::from("/proj"));
    linux_colliding.insert_path(&["README.md"], file_entry(hash64('1'), 10, t));
    linux_colliding.insert_path(&["readme.md"], file_entry(hash64('2'), 20, t));
    linux_colliding.insert_path(&["Solo"], file_entry(hash64('3'), 30, t));
    linux_colliding.insert_path(&["solo"], file_entry(hash64('4'), 40, t));

    let mut win_target = DirectoryNode::new(String::from("/proj"));
    win_target.insert_path(&["readme.md"], file_entry(hash64('2'), 20, t));

    let coll_diff = compare_trees_with_options(&linux_colliding, &win_target, &ci_opts);
    assert!(coll_diff.has_warning(WarningCode::CaseCollision));
    assert_eq!(coll_diff.root().file_count(), 4);

    let exact_readme = coll_diff.find_file("readme.md").expect("exact readme.md");
    assert_eq!(exact_readme.presence(), EntryPresence::Both);
    assert_eq!(exact_readme.outcome(), FileComparisonOutcome::Identical);
    assert!(!exact_readme.name_case_differs());

    let leftover_readme = coll_diff.find_file("README.md").expect("leftover README.md");
    assert_eq!(leftover_readme.presence(), EntryPresence::OnlyLeft);
    assert_eq!(leftover_readme.left_hash(), Some(hash64('1').as_str()));

    assert_eq!(
        coll_diff.find_file("Solo").expect("Solo").presence(),
        EntryPresence::OnlyLeft
    );
    assert_eq!(
        coll_diff.find_file("solo").expect("solo").presence(),
        EntryPresence::OnlyLeft
    );
}

#[test]
fn detects_file_vs_directory_type_conflicts_without_losing_entries() {
    let t = utc(2026, 6, 1, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/proj"));
    left.insert_path(&["keep.txt"], file_entry(hash64('k'), 10, t));
    left.insert_path(&["config"], file_entry(hash64('a'), 50, t));

    let mut right = DirectoryNode::new(String::from("/proj"));
    right.insert_path(&["keep.txt"], file_entry(hash64('k'), 10, t));
    right.insert_path(&["config", "settings.toml"], file_entry(hash64('b'), 80, t));

    let diff = compare_trees(&left, &right);
    assert!(diff.has_warning(WarningCode::FileDirectoryTypeConflict));

    let file_entry_diff = diff.find_file("config").expect("file config");
    assert_eq!(file_entry_diff.presence(), EntryPresence::OnlyLeft);
    assert!(file_entry_diff.has_type_conflict());

    let dir_entry_diff = diff.find_directory("config").expect("dir config");
    assert_eq!(dir_entry_diff.presence(), EntryPresence::OnlyRight);
    assert!(dir_entry_diff.has_type_conflict());

    let nested = diff
        .find_file("config/settings.toml")
        .expect("nested settings.toml");
    assert_eq!(nested.presence(), EntryPresence::OnlyRight);

    let conflict_warn = diff
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::FileDirectoryTypeConflict)
        .expect("type conflict warning");
    assert_eq!(
        conflict_warn.details,
        WarningDetails::FileDirectoryTypeConflict {
            count: 1,
            sample_paths: vec![String::from("config")],
        }
    );
}

#[test]
fn missing_extended_metadata_migrated_snapshot_and_sample_capping() {
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 2, 10, 0, 0);

    // Legacy v1-like tree without size/modified_utc vs current tree with size/modified_utc.
    let mut left = DirectoryNode::new(String::from("/proj"));
    left.insert_path(&["file.txt"], FileEntry::from_hash(hash64('a'), None, None));

    let mut right = DirectoryNode::new(String::from("/proj"));
    right.insert_path(&["file.txt"], file_entry(hash64('a'), 42, t2));

    let left_meta = sample_meta("linux", HashAlgorithm::Blake3, t1).with_migrated_from(1);
    let right_meta = sample_meta("linux", HashAlgorithm::Blake3, t2);

    let diff = TreeComparer::new().compare_trees_with_metadata(
        &left,
        Some(&left_meta),
        &right,
        Some(&right_meta),
    );
    // Missing metadata on left must NOT falsely mark identical hashes as MetadataChanged.
    assert_eq!(
        diff.find_file("file.txt").expect("file.txt").outcome(),
        FileComparisonOutcome::Identical
    );
    assert!(diff.has_warning(WarningCode::MissingExtendedMetadata));
    assert!(diff.has_warning(WarningCode::MigratedSnapshot));

    // Verify sample capping at MAX_WARNING_SAMPLES while keeping exact counts.
    let mut left_many = DirectoryNode::new(String::from("/proj"));
    let mut right_many = DirectoryNode::new(String::from("/proj"));
    for i in 0..(MAX_WARNING_SAMPLES + 7) {
        left_many.insert_path(&[&format!("FILE_{i:02}.TXT")], file_entry(hash64('a'), 10, t1));
        right_many.insert_path(&[&format!("file_{i:02}.txt")], file_entry(hash64('a'), 10, t1));
    }
    let capped_diff = compare_trees(&left_many, &right_many);
    let case_warn = capped_diff
        .warnings()
        .iter()
        .find(|w| w.code == WarningCode::CaseOnlyPathDifference)
        .expect("case diff warning");
    match &case_warn.details {
        WarningDetails::CaseOnlyPathDifference {
            count,
            sample_pairs,
        } => {
            assert_eq!(*count, MAX_WARNING_SAMPLES + 7);
            assert_eq!(sample_pairs.len(), MAX_WARNING_SAMPLES);
        }
        other => panic!("unexpected details: {other:?}"),
    }

    // Disabling warnings suppresses all warnings.
    let quiet_opts = ComparisonOptions::new().with_collect_warnings(false);
    let quiet_diff = compare_trees_with_options(&left_many, &right_many, &quiet_opts);
    assert!(!quiet_diff.has_warnings());
}

#[test]
fn max_depth_truncates_cleanly_while_preserving_full_side_info() {
    let t = utc(2026, 6, 1, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/proj"));
    left.insert_path(&["root.txt"], file_entry(hash64('a'), 10, t));
    left.insert_path(&["lvl1", "a.txt"], file_entry(hash64('b'), 20, t));
    left.insert_path(&["lvl1", "lvl2", "deep.txt"], file_entry(hash64('c'), 30, t));

    let mut right = left.clone();
    right.insert_path(&["lvl1", "lvl2", "deep.txt"], file_entry(hash64('d'), 35, t));

    // Depth 0: compares root files only, marks truncated, does not falsely emit NoCommonEntries.
    let opts0 = ComparisonOptions::new().with_max_depth(Some(0));
    let diff0 = compare_trees_with_options(&left, &right, &opts0);
    assert!(diff0.is_truncated());
    assert!(!diff0.is_identical());
    assert!(!diff0.root().has_any_difference());
    assert_eq!(diff0.root().directory_count(), 0);
    assert_eq!(diff0.left_info().total_files, 3);
    assert_eq!(diff0.left_info().total_directories, 2);
    assert_eq!(diff0.right_info().total_files, 3);
    assert!(!diff0.has_warning(WarningCode::NoCommonEntries));

    // Depth 0 when there are NO subdirectories at all -> NOT truncated.
    let mut flat = DirectoryNode::new(String::from("/flat"));
    flat.insert_path(&["only.txt"], file_entry(hash64('a'), 10, t));
    let flat_diff = compare_trees_with_options(&flat, &flat, &opts0);
    assert!(!flat_diff.is_truncated());
    assert!(flat_diff.is_identical());

    // Depth 1: compares root and lvl1 files, stops before lvl2.
    let opts1 = ComparisonOptions::new().with_max_depth(Some(1));
    let diff1 = compare_trees_with_options(&left, &right, &opts1);
    assert!(diff1.is_truncated());
    assert!(diff1.find_file("lvl1/a.txt").is_some());
    assert!(diff1.find_directory("lvl1/lvl2").is_none());
    assert_eq!(diff1.left_info().total_files, 3);
    assert_eq!(diff1.left_info().total_directories, 2);
}

#[test]
fn handles_very_deep_trees_without_stack_overflow() {
    const DEPTH: usize = 2_000;
    let t = utc(2026, 6, 1, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/deep"));
    let mut right = DirectoryNode::new(String::from("/deep"));

    let mut cur_l = &mut left;
    let mut cur_r = &mut right;
    for level in 0..DEPTH {
        let dir_name = format!("d{level}");
        cur_l = cur_l
            .sub_directories
            .entry(dir_name.clone())
            .or_insert_with(|| DirectoryNode::new(dir_name.clone()));
        cur_r = cur_r
            .sub_directories
            .entry(dir_name.clone())
            .or_insert_with(|| DirectoryNode::new(dir_name));
    }
    cur_l
        .files
        .insert(String::from("leaf.txt"), file_entry(hash64('a'), 10, t));
    cur_r
        .files
        .insert(String::from("leaf.txt"), file_entry(hash64('b'), 20, t));

    let diff = compare_trees(&left, &right);
    assert!(!diff.is_identical());
    assert_eq!(diff.left_info().total_directories, DEPTH);
    assert_eq!(diff.right_info().total_directories, DEPTH);
    assert_eq!(diff.iter_directories().count(), DEPTH + 1);

    let files: Vec<_> = diff.iter_files().collect();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].outcome(), FileComparisonOutcome::ContentChanged);
    assert_eq!(files[0].size_delta(), Some(10));

    // Explicitly drop `diff` (iterative Drop) and avoid recursive Drop on the two input trees.
    drop(diff);
    let mut drain = vec![left, right];
    while let Some(mut node) = drain.pop() {
        drain.extend(std::mem::take(&mut node.sub_directories).into_values());
    }
}

#[test]
fn end_to_end_scan_save_encrypted_and_compare_archive_files_and_serde_roundtrip() {
    let data_dir = TempDir::new("e2e_data");
    let archive_dir = TempDir::new("e2e_archives");
    let sub = data_dir.path().join("sub");
    fs::create_dir_all(&sub).expect("create sub dir");

    fs::write(data_dir.path().join("unchanged.txt"), b"same content").expect("write unchanged");
    fs::write(data_dir.path().join("modified.txt"), b"version 1").expect("write modified");
    fs::write(sub.join("deleted.txt"), b"goodbye").expect("write deleted");

    // Snapshot 1 (unencrypted)
    let mut scan1 = ScanManager::new(HashAlgorithm::Blake3);
    scan1
        .start_hash(data_dir.path().to_string_lossy().into_owned())
        .expect("scan 1");
    let tree1 = DirectoryNode::build_tree(scan1.get_path(), scan1.get_list());
    let meta1 = MetaData::new(
        scan1.get_hash_manager().get_files_counted(),
        scan1.get_hash_time(),
        utc(2026, 6, 1, 10, 0, 0),
    )
    .with_algorithm(scan1.get_algorithm())
    .with_total_size(scan1.get_total_size());
    let snap1_path = FileManager::save_file(archive_dir.path(), &tree1, &meta1).expect("save 1");

    // Mutate directory on disk
    fs::write(data_dir.path().join("modified.txt"), b"version 2 with more bytes")
        .expect("update modified");
    fs::remove_file(sub.join("deleted.txt")).expect("remove deleted");
    fs::write(sub.join("added.txt"), b"brand new").expect("write added");

    // Snapshot 2 (encrypted with fast KDF params for unit tests)
    let mut scan2 = ScanManager::new(HashAlgorithm::Blake3);
    scan2
        .start_hash(data_dir.path().to_string_lossy().into_owned())
        .expect("scan 2");
    let tree2 = DirectoryNode::build_tree(scan2.get_path(), scan2.get_list());
    let meta2 = MetaData::new(
        scan2.get_hash_manager().get_files_counted(),
        scan2.get_hash_time(),
        utc(2026, 6, 1, 10, 5, 0),
    )
    .with_algorithm(scan2.get_algorithm())
    .with_total_size(scan2.get_total_size());
    let fast_kdf = KdfParams::new(8 * 1024, 1, 1).expect("fast test kdf");
    let enc_opts = EncryptionOptions::new("secret-pass")
        .expect("enc opts")
        .with_kdf_params(fast_kdf)
        .expect("with kdf");
    let snap2_path =
        FileManager::save_file_encrypted(archive_dir.path(), &tree2, &meta2, &enc_opts)
            .expect("save 2");

    let comparer = TreeComparer::new();

    // Without password, comparing against an encrypted archive returns PasswordRequired.
    let err = comparer
        .compare_archive_files(&snap1_path, &snap2_path)
        .expect_err("expected PasswordRequired");
    assert!(matches!(err, BulkHashError::PasswordRequired(_)));

    // With password, comparison succeeds cleanly with zero warnings.
    let diff = comparer
        .compare_archive_files_with_passwords(&snap1_path, None, &snap2_path, Some("secret-pass"))
        .expect("compare archives");
    assert!(!diff.is_identical());
    assert!(!diff.has_warnings());
    assert_eq!(diff.left_info().algorithm, Some(HashAlgorithm::Blake3));
    assert_eq!(diff.right_info().algorithm, Some(HashAlgorithm::Blake3));

    assert_eq!(
        diff.find_file("unchanged.txt").expect("unchanged").outcome(),
        FileComparisonOutcome::Identical
    );
    assert_eq!(
        diff.find_file("modified.txt").expect("modified").outcome(),
        FileComparisonOutcome::ContentChanged
    );
    assert_eq!(
        diff.find_file("sub/deleted.txt").expect("deleted").outcome(),
        FileComparisonOutcome::OnlyLeft
    );
    assert_eq!(
        diff.find_file("sub/added.txt").expect("added").outcome(),
        FileComparisonOutcome::OnlyRight
    );

    // JSON serde roundtrip must be completely lossless for Tauri IPC / frontend consumption.
    let json = serde_json::to_string(&diff).expect("serialize TreeDiff");
    let decoded: TreeDiff = serde_json::from_str(&json).expect("deserialize TreeDiff");
    assert_eq!(decoded, diff);

    // Convenience compare_snapshots_with_options matches comparer output.
    let loaded1 = FileManager::open_file(&snap1_path).expect("open 1");
    let loaded2 = FileManager::open_file_with_password(&snap2_path, "secret-pass").expect("open 2");
    let via_fn = compare_snapshots_with_options(&loaded1, &loaded2, &ComparisonOptions::new());
    assert_eq!(via_fn, diff);
}

#[test]
fn path_helpers_and_display_impls_behave_cross_platform() {
    assert_eq!(extract_path_basename("/home/lars/Downloads/"), "Downloads");
    assert_eq!(
        extract_path_basename(r"C:\Users\Lars\Downloads\"),
        "Downloads"
    );
    assert_eq!(
        extract_path_basename(r"\\server\share\Backups"),
        "Backups"
    );
    assert_eq!(extract_path_basename("c:\\"), "C:");
    assert_eq!(extract_path_basename("/"), "/");
    assert_eq!(extract_path_basename(""), "");

    assert_eq!(infer_os_from_path(r"C:\Users\Lars"), Some("windows"));
    assert_eq!(infer_os_from_path("D:/Games"), Some("windows"));
    assert_eq!(infer_os_from_path(r"\\nas\media"), Some("windows"));
    assert_eq!(infer_os_from_path(r"relative\win\path"), Some("windows"));
    assert_eq!(infer_os_from_path("/home/lars/Games"), Some("unix"));
    assert_eq!(infer_os_from_path("relative/bare"), None);
    assert_eq!(infer_os_from_path(""), None);

    assert_eq!(NameMatchingMode::Exact.to_string(), "exact");
    assert_eq!(
        NameMatchingMode::CaseInsensitive.to_string(),
        "case_insensitive"
    );
    assert_eq!(EntryPresence::OnlyLeft.to_string(), "only_left");
    assert_eq!(FileComparisonOutcome::ContentChanged.to_string(), "content_changed");
    assert_eq!(WarningSeverity::Critical.to_string(), "critical");
    assert_eq!(
        WarningCode::DifferentOperatingSystem.to_string(),
        "different_operating_system"
    );

    let warn = ComparisonWarning::new(
        WarningSeverity::Warning,
        WarningCode::DifferentOperatingSystem,
        String::from("Windows vs Linux"),
        WarningDetails::DifferentOperatingSystem {
            left_os: String::from("windows"),
            right_os: String::from("linux"),
            inferred_from_paths: false,
        },
    );
    assert!(warn.is_warning_or_higher());
    assert!(!warn.is_critical());
    assert_eq!(
        warn.to_string(),
        "[WARNING] (different_operating_system) Windows vs Linux"
    );
}

#[test]
fn precheck_aggregates_all_preflight_warnings_into_one_single_report() {
    let t_older = utc(2026, 6, 1, 10, 0, 0);
    let t_newer = utc(2026, 6, 2, 10, 0, 0);

    // Combine multiple pre-flight problems at once:
    // - Critical: DifferentHashAlgorithm (Blake3 vs Sha256)
    // - Warning: DifferentOperatingSystem (windows vs linux), DifferentIgnoreLists,
    //            DifferentHiddenFileFilter, ReversedChronologicalOrder
    // - Info: DifferentRootName (Dokumente vs downloads), MigratedSnapshot
    let mut left_tree = DirectoryNode::new(String::from(r"C:\Users\Lars\Dokumente"));
    left_tree.insert_path(&["a.txt"], file_entry(hash64('a'), 100, t_newer));
    let mut right_tree = DirectoryNode::new(String::from("/home/lars/downloads"));
    right_tree.insert_path(&["b.txt"], file_entry(hash64('b'), 200, t_older));

    let left_meta = sample_meta("windows", HashAlgorithm::Blake3, t_newer)
        .with_ignore_list(IgnoreList::from_patterns(["*.tmp"]).expect("ignore list"))
        .with_hidden_filter(HiddenFileFilter::exclude_all())
        .with_migrated_from(1);
    let right_meta = sample_meta("linux", HashAlgorithm::Sha256, t_older);

    let left_snap = BulkHashFileStruct::new(left_meta.clone(), left_tree.clone(), hash64('1'));
    let right_snap = BulkHashFileStruct::new(right_meta.clone(), right_tree.clone(), hash64('2'));

    let report = precheck_snapshots(&left_snap, &right_snap);
    assert!(!report.is_clean());
    assert!(report.has_warnings());
    assert!(report.requires_confirmation());
    assert!(report.has_critical_warnings());
    assert!(!report.can_compare_reliably());
    assert_eq!(report.highest_severity(), Some(WarningSeverity::Critical));
    assert_eq!(report.critical_count, 1);
    assert_eq!(report.warning_count, 4);
    assert_eq!(report.info_count, 2);
    assert_eq!(report.warnings().len(), 7);

    // Highest severity first: Critical -> Warning -> Info.
    assert_eq!(report.warnings()[0].code, WarningCode::DifferentHashAlgorithm);
    assert!(report.has_warning(WarningCode::DifferentOperatingSystem));
    assert!(report.has_warning(WarningCode::DifferentIgnoreLists));
    assert!(report.has_warning(WarningCode::DifferentHiddenFileFilter));
    assert!(report.has_warning(WarningCode::ReversedChronologicalOrder));
    assert!(report.has_warning(WarningCode::DifferentRootName));
    assert!(report.has_warning(WarningCode::MigratedSnapshot));
    assert!(report.warnings().iter().all(|w| w.code.is_precheck()));

    // Side summaries carry all context needed for a single UI popup header.
    assert_eq!(
        report.left().root_name.as_deref(),
        Some(r"C:\Users\Lars\Dokumente")
    );
    assert_eq!(report.left().os.as_deref(), Some("windows"));
    assert_eq!(report.left().algorithm, Some(HashAlgorithm::Blake3));
    assert_eq!(report.left().migrated_from, Some(1));
    assert_eq!(report.right().os.as_deref(), Some("linux"));
    assert_eq!(report.right().algorithm, Some(HashAlgorithm::Sha256));

    // Verify JSON roundtrip of PrecheckReport for Tauri IPC.
    let json = serde_json::to_string(&report).expect("serialize PrecheckReport");
    let decoded: PrecheckReport =
        serde_json::from_str(&json).expect("deserialize PrecheckReport");
    assert_eq!(decoded, report);

    // Every pre-flight warning emitted by precheck_snapshots must also appear in full compare_snapshots.
    let full_diff = compare_snapshots(&left_snap, &right_snap);
    for pre_warn in report.warnings() {
        assert!(
            full_diff.has_warning(pre_warn.code),
            "full diff missing precheck warning {:?}",
            pre_warn.code
        );
    }

    // Traversal-only warnings are NOT classified as precheck.
    assert!(!WarningCode::NoCommonEntries.is_precheck());
    assert!(!WarningCode::CaseCollision.is_precheck());
    assert!(!WarningCode::ScanErrorsPresent.is_precheck());
    assert!(WarningCode::DifferentOperatingSystem.is_precheck());
    assert!(WarningCode::DifferentRootName.is_precheck());
}

#[test]
fn precheck_clean_pair_and_info_only_root_difference() {
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 1, 11, 0, 0);

    // Completely compatible pair -> clean report (no popup needed).
    let mut left_tree = DirectoryNode::new(String::from("/home/lars/projekt"));
    left_tree.insert_path(&["main.rs"], file_entry(hash64('a'), 100, t1));
    let right_tree = left_tree.clone();
    let left_meta = sample_meta("linux", HashAlgorithm::Blake3, t1);
    let right_meta = sample_meta("linux", HashAlgorithm::Blake3, t2);

    let clean = precheck_trees_with_metadata(&left_tree, Some(&left_meta), &right_tree, Some(&right_meta));
    assert!(clean.is_clean());
    assert!(!clean.has_warnings());
    assert!(!clean.requires_confirmation());
    assert!(clean.can_compare_reliably());
    assert_eq!(clean.highest_severity(), None);

    // Different root folder names only (dokumente vs downloads) -> single Info warning.
    let mut docs = DirectoryNode::new(String::from("/home/lars/dokumente"));
    docs.insert_path(&["a.txt"], file_entry(hash64('a'), 10, t1));
    let mut downloads = DirectoryNode::new(String::from("/home/lars/downloads"));
    downloads.insert_path(&["b.txt"], file_entry(hash64('b'), 10, t2));

    let root_only = precheck_trees(&docs, &downloads);
    assert!(root_only.has_warnings());
    assert!(!root_only.requires_confirmation());
    assert!(root_only.can_compare_reliably());
    assert_eq!(root_only.highest_severity(), Some(WarningSeverity::Info));
    assert_eq!(root_only.info_count, 1);
    assert!(root_only.has_warning(WarningCode::DifferentRootName));

    // Same snapshot passed to precheck_snapshots emits IdenticalSnapshot.
    let snap = BulkHashFileStruct::new(left_meta.clone(), left_tree, hash64('z'));
    let same = precheck_snapshots(&snap, &snap);
    assert!(same.has_warning(WarningCode::IdenticalSnapshot));
    assert_eq!(same.warnings().len(), 1);

    // precheck_metadata works without DirectoryNodes (e.g. before loading/scanning trees).
    let win_meta = sample_meta("windows", HashAlgorithm::Blake3, t1);
    let meta_only = precheck_metadata(
        Some(&win_meta),
        Some(r"C:\Users\Lars\Dokumente"),
        Some(&right_meta),
        Some("/home/lars/downloads"),
    );
    assert!(meta_only.requires_confirmation());
    assert!(meta_only.has_warning(WarningCode::DifferentOperatingSystem));
    assert!(meta_only.has_warning(WarningCode::DifferentRootName));
    assert_eq!(
        meta_only
            .warnings_at_least(WarningSeverity::Warning)
            .count(),
        1
    );
}

#[test]
fn precheck_archive_files_works_passwordlessly_on_encrypted_and_unencrypted_archives() {
    let dir = TempDir::new("precheck_archives");
    let t1 = utc(2026, 6, 1, 10, 0, 0);
    let t2 = utc(2026, 6, 1, 12, 0, 0);

    let mut tree_a = DirectoryNode::new(String::from(r"C:\Projects\App"));
    tree_a.insert_path(&["a.txt"], file_entry(hash64('a'), 50, t1));
    let meta_a = sample_meta("windows", HashAlgorithm::Blake3, t2);
    let fast_kdf = KdfParams::new(8 * 1024, 1, 1).expect("fast test kdf");
    let enc_opts = EncryptionOptions::new("top-secret")
        .expect("enc opts")
        .with_kdf_params(fast_kdf)
        .expect("kdf");
    let encrypted_win_path =
        FileManager::save_file_encrypted(dir.path(), &tree_a, &meta_a, &enc_opts)
            .expect("save encrypted win archive");

    let mut tree_b = DirectoryNode::new(String::from("/home/lars/App"));
    tree_b.insert_path(&["a.txt"], file_entry(hash64('b'), 50, t1));
    let meta_b = sample_meta("linux", HashAlgorithm::Sha256, t1);
    let plain_linux_path =
        FileManager::save_file(dir.path(), &tree_b, &meta_b).expect("save plain linux archive");

    // Precheck runs WITHOUT passwords and catches all incompatibilities in ONE report!
    let report = precheck_archive_files(&encrypted_win_path, &plain_linux_path)
        .expect("passwordless archive precheck");
    assert!(report.has_critical_warnings());
    assert!(report.requires_confirmation());
    assert!(report.left().encrypted);
    assert!(!report.right().encrypted);
    assert!(report.has_warning(WarningCode::DifferentHashAlgorithm));
    assert!(report.has_warning(WarningCode::DifferentOperatingSystem));
    assert!(report.has_warning(WarningCode::ReversedChronologicalOrder));

    // Selecting the exact same encrypted archive twice detects IdenticalSnapshot without a password!
    let same_enc = TreeComparer::precheck_archive_files(&encrypted_win_path, &encrypted_win_path)
        .expect("same archive precheck");
    assert!(same_enc.has_warning(WarningCode::IdenticalSnapshot));
    assert!(!same_enc.requires_confirmation());
}

fn build_five_status_sample_diff() -> TreeDiff {
    let t1 = utc(2026, 7, 1, 10, 0, 0);
    let t2 = utc(2026, 7, 2, 12, 0, 0);

    let mut left = DirectoryNode::new(String::from("/data/app"));
    left.insert_path(&["unchanged.txt"], file_entry(hash64('a'), 100, t1));
    left.insert_path(&["content_mod.txt"], file_entry(hash64('b'), 100, t1));
    left.insert_path(&["meta_mod.txt"], file_entry(hash64('c'), 200, t1));
    left.insert_path(&["removed.txt"], file_entry(hash64('d'), 300, t1));
    left.insert_path(
        &["err_both.txt"],
        FileEntry::from_error(String::from("left read failed"), None, None),
    );
    left.insert_path(
        &["err_left_only.txt"],
        FileEntry::from_error(String::from("locked in baseline"), None, None),
    );
    left.insert_path(&["sub", "ok_removed.txt"], file_entry(hash64('e'), 40, t1));

    let mut right = DirectoryNode::new(String::from("/data/app"));
    right.insert_path(&["unchanged.txt"], file_entry(hash64('A'), 100, t1));
    right.insert_path(&["content_mod.txt"], file_entry(hash64('f'), 120, t2));
    right.insert_path(&["meta_mod.txt"], file_entry(hash64('c'), 200, t2));
    right.insert_path(&["added.txt"], file_entry(hash64('1'), 50, t2));
    right.insert_path(
        &["err_both.txt"],
        FileEntry::from_error(String::from("right read failed"), None, None),
    );
    right.insert_path(
        &["err_right_only.txt"],
        FileEntry::from_error(String::from("locked in target"), None, None),
    );
    right.insert_path(&["sub", "ok_added.txt"], file_entry(hash64('2'), 60, t2));

    compare_trees(&left, &right)
}

#[test]
fn file_status_categorizes_all_five_states_and_details_accurately() {
    let diff = build_five_status_sample_diff();

    // Verify all 5 core categories on individual entries + rich status details.
    let unchanged = diff.find_file("unchanged.txt").expect("unchanged");
    assert_eq!(unchanged.status(), FileStatus::Unchanged);
    assert_eq!(
        unchanged.status_detail(),
        FileStatusDetail::Unchanged {
            name_case_differs: false,
            metadata_differs: false,
        }
    );

    let content_mod = diff.find_file("content_mod.txt").expect("content_mod");
    assert_eq!(content_mod.status(), FileStatus::Modified);
    assert!(content_mod.status_detail().is_content_modification());
    assert!(!content_mod.status_detail().is_metadata_only_modification());
    assert_eq!(
        content_mod.status_detail(),
        FileStatusDetail::Modified {
            content_changed: true,
            size_changed: Some(true),
            modified_changed: Some(true),
        }
    );

    let meta_mod = diff.find_file("meta_mod.txt").expect("meta_mod");
    assert_eq!(meta_mod.status(), FileStatus::Modified);
    assert!(meta_mod.status_detail().is_metadata_only_modification());
    assert!(!meta_mod.status_detail().is_content_modification());
    assert_eq!(
        meta_mod.status_detail(),
        FileStatusDetail::Modified {
            content_changed: false,
            size_changed: Some(false),
            modified_changed: Some(true),
        }
    );

    let added = diff.find_file("added.txt").expect("added");
    assert_eq!(added.status(), FileStatus::Added);
    assert_eq!(
        added.status_detail(),
        FileStatusDetail::Added {
            type_conflict: false,
            has_error: false,
        }
    );

    let removed = diff.find_file("removed.txt").expect("removed");
    assert_eq!(removed.status(), FileStatus::Removed);
    assert_eq!(
        removed.status_detail(),
        FileStatusDetail::Removed {
            type_conflict: false,
            has_error: false,
        }
    );
}

#[test]
fn file_status_error_cases_counts_and_grouping_cover_root_and_subdirectories() {
    let diff = build_five_status_sample_diff();

    // Both-side and single-side scan errors all surface under FileStatus::Error by default.
    let err_both = diff.find_file("err_both.txt").expect("err_both");
    assert_eq!(err_both.status(), FileStatus::Error);
    assert_eq!(
        err_both.status_detail(),
        FileStatusDetail::Error {
            presence: EntryPresence::Both,
            left_error: Some(String::from("left read failed")),
            right_error: Some(String::from("right read failed")),
        }
    );

    let err_left = diff.find_file("err_left_only.txt").expect("err_left");
    assert_eq!(err_left.status(), FileStatus::Error);
    assert_eq!(
        err_left.status_detail(),
        FileStatusDetail::Error {
            presence: EntryPresence::OnlyLeft,
            left_error: Some(String::from("locked in baseline")),
            right_error: None,
        }
    );

    let err_right = diff.find_file("err_right_only.txt").expect("err_right");
    assert_eq!(err_right.status(), FileStatus::Error);
    assert_eq!(
        err_right.status_detail(),
        FileStatusDetail::Error {
            presence: EntryPresence::OnlyRight,
            left_error: None,
            right_error: Some(String::from("locked in target")),
        }
    );

    // Every entry satisfies `entry.status_detail().status() == entry.status()`.
    for entry in diff.iter_files() {
        assert_eq!(entry.status_detail().status(), entry.status());
    }

    // Verify status_counts and files_by_status across the whole tree and subdirectories.
    let counts = diff.status_counts();
    assert_eq!(
        counts,
        FileStatusCounts {
            unchanged: 1,
            modified: 2,
            added: 2,
            removed: 2,
            error: 3,
        }
    );
    assert_eq!(counts.total(), 10);
    assert_eq!(counts.changed_total(), 9);
    assert_eq!(counts.count_for(FileStatus::Error), 3);

    let grouped = diff.files_by_status();
    assert_eq!(grouped[&FileStatus::Unchanged].len(), 1);
    assert_eq!(grouped[&FileStatus::Modified].len(), 2);
    assert_eq!(grouped[&FileStatus::Added].len(), 2);
    assert_eq!(grouped[&FileStatus::Removed].len(), 2);
    assert_eq!(grouped[&FileStatus::Error].len(), 3);

    let sub_counts = diff
        .find_directory("sub")
        .expect("sub dir")
        .status_counts();
    assert_eq!(sub_counts.added, 1);
    assert_eq!(sub_counts.removed, 1);
    assert_eq!(sub_counts.total(), 2);
}

#[test]
fn file_status_policy_and_in_place_reclassification_work_consistently() {
    let t1 = utc(2026, 7, 1, 10, 0, 0);
    let t2 = utc(2026, 7, 2, 12, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app"));
    left.insert_path(&["meta_only.txt"], file_entry(hash64('a'), 100, t1));
    left.insert_path(
        &["left_err.txt"],
        FileEntry::from_error(String::from("boom"), None, None),
    );
    left.insert_path(
        &["both_err.txt"],
        FileEntry::from_error(String::from("boom"), None, None),
    );

    let mut right = DirectoryNode::new(String::from("/app"));
    right.insert_path(&["meta_only.txt"], file_entry(hash64('a'), 100, t2));
    right.insert_path(
        &["right_err.txt"],
        FileEntry::from_error(String::from("denied"), None, None),
    );
    right.insert_path(&["both_err.txt"], file_entry(hash64('b'), 10, t2));

    // Content-only policy keeps `outcome = MetadataChanged` while classifying `status = Unchanged`.
    let content_policy = FileStatusPolicy::content_only();
    let opts = ComparisonOptions::new().with_status_policy(content_policy);
    let mut diff = compare_trees_with_options(&left, &right, &opts);

    let meta_only = diff.find_file("meta_only.txt").expect("meta_only");
    assert_eq!(meta_only.outcome(), FileComparisonOutcome::MetadataChanged);
    assert_eq!(meta_only.status(), FileStatus::Unchanged);
    assert_eq!(
        meta_only.status_detail(),
        FileStatusDetail::Unchanged {
            name_case_differs: false,
            metadata_differs: true,
        }
    );

    // Non-mutating policy preview helpers.
    assert_eq!(
        meta_only.status_with_policy(FileStatusPolicy::strict()),
        FileStatus::Modified
    );
    assert!(
        meta_only
            .status_detail_with_policy(FileStatusPolicy::strict())
            .is_metadata_only_modification()
    );
    assert_eq!(
        classify_file_entry(meta_only, FileStatusPolicy::strict()),
        FileStatus::Modified
    );
    assert_eq!(
        classify_file_entry_detailed(meta_only, FileStatusPolicy::content_only()).status,
        FileStatus::Unchanged
    );

    // Reclassify in-place with single-side errors kept as Added/Removed (both-side errors stay Error!).
    let relaxed = FileStatusPolicy::strict().with_classify_single_side_errors_as_error(false);
    diff.reclassify_statuses(relaxed);
    assert_eq!(diff.options().status_policy, relaxed);
    assert_eq!(
        diff.find_file("meta_only.txt").expect("meta_only").status(),
        FileStatus::Modified
    );
    let left_err = diff.find_file("left_err.txt").expect("left_err");
    assert_eq!(left_err.status(), FileStatus::Removed);
    assert_eq!(
        left_err.status_detail(),
        FileStatusDetail::Removed {
            type_conflict: false,
            has_error: true,
        }
    );
    let right_err = diff.find_file("right_err.txt").expect("right_err");
    assert_eq!(right_err.status(), FileStatus::Added);
    assert_eq!(
        right_err.status_detail(),
        FileStatusDetail::Added {
            type_conflict: false,
            has_error: true,
        }
    );
    assert_eq!(
        diff.find_file("both_err.txt").expect("both_err").status(),
        FileStatus::Error
    );

    // Direct `classify_pair` works cleanly without a DiffFileEntry wrapper.
    let a = file_entry(hash64('x'), 10, t1);
    let b = file_entry(hash64('x'), 10, t2);
    assert_eq!(
        classify_pair(Some(&a), Some(&b), false, FileStatusPolicy::strict()),
        FileStatus::Unchanged
    );
    assert_eq!(
        classify_pair(Some(&a), Some(&b), true, FileStatusPolicy::strict()),
        FileStatus::Modified
    );
    assert_eq!(
        classify_pair(None, None, true, FileStatusPolicy::strict()),
        FileStatus::Error
    );
}

#[test]
fn file_status_filter_parsing_formatting_and_serde_roundtrip() {
    let t = utc(2026, 7, 1, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app"));
    left.insert_path(&["same.txt"], file_entry(hash64('a'), 10, t));
    left.insert_path(&["changed.txt"], file_entry(hash64('b'), 10, t));
    left.insert_path(&["deleted.txt"], file_entry(hash64('c'), 10, t));

    let mut right = DirectoryNode::new(String::from("/app"));
    right.insert_path(&["same.txt"], file_entry(hash64('a'), 10, t));
    right.insert_path(&["changed.txt"], file_entry(hash64('d'), 20, t));
    right.insert_path(&["new.txt"], file_entry(hash64('e'), 30, t));
    right.insert_path(
        &["broken.txt"],
        FileEntry::from_error(String::from("io error"), None, None),
    );

    let diff = compare_trees(&left, &right);

    // Quick-toggle filter: hide unchanged files.
    let changes_only = FileStatusFilter::changes_only();
    assert!(!changes_only.matches(FileStatus::Unchanged));
    assert!(changes_only.matches(FileStatus::Modified));
    assert!(changes_only.matches(FileStatus::Added));
    assert!(changes_only.matches(FileStatus::Removed));
    assert!(changes_only.matches(FileStatus::Error));
    assert_eq!(changes_only.len(), 4);

    let changed_paths: Vec<&str> = diff
        .iter_files_matching_filter(changes_only)
        .map(DiffFileEntry::relative_path)
        .collect();
    assert_eq!(
        changed_paths,
        vec!["broken.txt", "changed.txt", "deleted.txt", "new.txt"]
    );

    // Single-status iterator & custom filter builders.
    let only_added: Vec<&str> = diff
        .iter_files_with_status(FileStatus::Added)
        .map(DiffFileEntry::relative_path)
        .collect();
    assert_eq!(only_added, vec!["new.txt"]);

    let custom = FileStatusFilter::only(FileStatus::Added)
        .include(FileStatus::Removed)
        .with_status(FileStatus::Error, true)
        .exclude(FileStatus::Removed);
    assert_eq!(custom.statuses(), vec![FileStatus::Added, FileStatus::Error]);

    // Filter JSON serialization is a clean array of status strings.
    let filter_json = serde_json::to_string(&custom).expect("serialize filter");
    assert_eq!(filter_json, r#"["added","error"]"#);
    let filter_decoded: FileStatusFilter =
        serde_json::from_str(&filter_json).expect("deserialize filter");
    assert_eq!(filter_decoded, custom);

    // Enum parsing, symbols, display names, and predicates.
    for status in FileStatus::ALL {
        let parsed: FileStatus = status.as_str().parse().expect("parse canonical");
        assert_eq!(parsed, status);
        let parsed_sym: FileStatus = status.symbol().parse().expect("parse symbol");
        assert_eq!(parsed_sym, status);
        assert_eq!(status.to_string(), status.as_str());
        assert!(!status.display_name().is_empty());
    }
    assert_eq!("new".parse::<FileStatus>(), Ok(FileStatus::Added));
    assert_eq!("deleted".parse::<FileStatus>(), Ok(FileStatus::Removed));
    assert_eq!("equal".parse::<FileStatus>(), Ok(FileStatus::Unchanged));
    assert_eq!("changed".parse::<FileStatus>(), Ok(FileStatus::Modified));
    assert_eq!("failed".parse::<FileStatus>(), Ok(FileStatus::Error));

    let bad = "nonsense".parse::<FileStatus>().expect_err("invalid status");
    assert_eq!(bad.input(), "nonsense");
    assert!(bad.to_string().contains("nonsense"));
}

fn build_folder_propagation_sample_diff() -> TreeDiff {
    let t1 = utc(2026, 8, 1, 10, 0, 0);
    let t2 = utc(2026, 8, 2, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/repo"));
    left.insert_path(&["clean", "nested", "same.txt"], file_entry(hash64('a'), 10, t1));
    left.insert_path(&["deep", "a", "b", "file.txt"], file_entry(hash64('b'), 20, t1));
    left.insert_path(&["old_module", "sub", "gone.rs"], file_entry(hash64('c'), 30, t1));
    left.insert_path(&["only_added_files", "base.txt"], file_entry(hash64('d'), 40, t1));
    left.insert_path(&["only_removed_files", "stay.txt"], file_entry(hash64('e'), 50, t1));
    left.insert_path(&["only_removed_files", "drop.txt"], file_entry(hash64('f'), 60, t1));

    let mut right = DirectoryNode::new(String::from("/repo"));
    right.insert_path(&["clean", "nested", "same.txt"], file_entry(hash64('a'), 10, t1));
    right.insert_path(&["deep", "a", "b", "file.txt"], file_entry(hash64('9'), 25, t2));
    right.insert_path(&["new_module", "sub", "fresh.rs"], file_entry(hash64('1'), 35, t2));
    right.insert_path(&["only_added_files", "base.txt"], file_entry(hash64('d'), 40, t1));
    right.insert_path(&["only_added_files", "extra.txt"], file_entry(hash64('2'), 45, t2));
    right.insert_path(&["only_removed_files", "stay.txt"], file_entry(hash64('e'), 50, t1));
    right
        .sub_directories
        .entry(String::from("empty_parent"))
        .or_insert_with(|| DirectoryNode::new(String::from("empty_parent")))
        .sub_directories
        .insert(
            String::from("empty_new"),
            DirectoryNode::new(String::from("empty_new")),
        );
    left.sub_directories.insert(
        String::from("empty_parent"),
        DirectoryNode::new(String::from("empty_parent")),
    );

    compare_trees(&left, &right)
}

#[test]
fn folder_status_propagates_bottom_up_for_modified_added_removed_and_unchanged_branches() {
    let diff = build_folder_propagation_sample_diff();

    // Unchanged subtree remains strictly Unchanged at every level.
    assert_eq!(
        diff.find_directory("clean").expect("clean").status(),
        FolderStatus::Unchanged
    );
    assert_eq!(
        diff.find_directory("clean/nested").expect("nested").status(),
        FolderStatus::Unchanged
    );
    assert_eq!(
        diff.find_directory("clean")
            .expect("clean")
            .status_summary()
            .dominant_change_status(),
        None
    );

    // Deep modification propagates upward through every ancestor up to root.
    assert_eq!(
        diff.find_directory("deep/a/b").expect("deep/a/b").status(),
        FolderStatus::Modified
    );
    assert_eq!(
        diff.find_directory("deep/a").expect("deep/a").status(),
        FolderStatus::Modified
    );
    assert_eq!(
        diff.find_directory("deep").expect("deep").status(),
        FolderStatus::Modified
    );
    assert_eq!(diff.root_status(), FolderStatus::Modified);

    // Added & removed subtrees carry Added / Removed at every level.
    assert_eq!(
        diff.find_directory("new_module").expect("new_module").status(),
        FolderStatus::Added
    );
    assert_eq!(
        diff.find_directory("new_module/sub").expect("new_module/sub").status(),
        FolderStatus::Added
    );
    assert_eq!(
        diff.find_directory("old_module").expect("old_module").status(),
        FolderStatus::Removed
    );
    assert_eq!(
        diff.find_directory("old_module/sub").expect("old_module/sub").status(),
        FolderStatus::Removed
    );

    // Empty added directory propagates Modified to its existing `Both` parent.
    assert_eq!(
        diff.find_directory("empty_parent/empty_new")
            .expect("empty_new")
            .status(),
        FolderStatus::Added
    );
    assert_eq!(
        diff.find_directory("empty_parent")
            .expect("empty_parent")
            .status(),
        FolderStatus::Modified
    );

    // Dominant change status distinguishes purely added vs purely removed vs mixed folders.
    let only_added_dir = diff.find_directory("only_added_files").expect("only_added");
    assert_eq!(only_added_dir.status(), FolderStatus::Modified);
    assert_eq!(
        only_added_dir.status_summary().dominant_change_status(),
        Some(FileStatus::Added)
    );
    assert!(!only_added_dir.status_summary().has_mixed_file_changes());

    let only_removed_dir = diff
        .find_directory("only_removed_files")
        .expect("only_removed");
    assert_eq!(only_removed_dir.status(), FolderStatus::Modified);
    assert_eq!(
        only_removed_dir.status_summary().dominant_change_status(),
        Some(FileStatus::Removed)
    );

    // Root contains mixed changes (Modified + Added + Removed).
    assert!(diff.root().status_summary().has_mixed_file_changes());
    assert_eq!(
        diff.root().status_summary().dominant_change_status(),
        Some(FileStatus::Modified)
    );
    assert_eq!(
        diff.directory_status_counts(),
        FolderStatusCounts {
            unchanged: 2, // clean, clean/nested
            modified: 6,  // deep, deep/a, deep/a/b, only_added_files, only_removed_files, empty_parent
            added: 3,     // new_module, new_module/sub, empty_parent/empty_new
            removed: 2,   // old_module, old_module/sub
            error: 0,
        }
    );
    assert_eq!(diff.directory_status_counts().total(), 13);
    assert_eq!(diff.directory_status_counts().changed_total(), 11);
}

#[test]
fn folder_status_error_propagation_reclassification_and_deep_trees() {
    const DEPTH: usize = 2_000;
    let t1 = utc(2026, 8, 1, 10, 0, 0);
    let t2 = utc(2026, 8, 2, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app"));
    left.insert_path(&["meta_dir", "sub", "note.txt"], file_entry(hash64('a'), 100, t1));
    left.insert_path(&["ok_dir", "same.txt"], file_entry(hash64('b'), 100, t1));

    let mut right = DirectoryNode::new(String::from("/app"));
    right.insert_path(&["meta_dir", "sub", "note.txt"], file_entry(hash64('a'), 100, t2));
    right.insert_path(&["ok_dir", "same.txt"], file_entry(hash64('b'), 100, t1));
    right.insert_path(
        &["new_dir", "inner", "locked.bin"],
        FileEntry::from_error(String::from("Permission denied"), None, None),
    );

    // Under default strict policy:
    // - `new_dir/inner/locked.bin` is `Error` -> propagates monotonically up `new_dir/inner`,
    //   `new_dir`, and `root` so the UI always has an unbroken error trail!
    // - `meta_dir/sub/note.txt` is `Modified` (mtime changed) -> `meta_dir/sub` and `meta_dir` are `Modified`.
    let mut diff = compare_trees(&left, &right);
    assert_eq!(diff.root_status(), FolderStatus::Error);
    assert_eq!(
        diff.find_directory("new_dir").expect("new_dir").status(),
        FolderStatus::Error
    );
    assert_eq!(
        diff.find_directory("new_dir").expect("new_dir").presence(),
        EntryPresence::OnlyRight
    );
    assert_eq!(
        diff.find_directory("new_dir/inner").expect("inner").status(),
        FolderStatus::Error
    );
    assert_eq!(
        diff.find_directory("meta_dir").expect("meta_dir").status(),
        FolderStatus::Modified
    );
    assert_eq!(
        diff.find_directory("ok_dir").expect("ok_dir").status(),
        FolderStatus::Unchanged
    );

    // Reclassifying with content-only + single-side errors as Added updates ALL ancestor folders!
    let relaxed = FileStatusPolicy::content_only().with_classify_single_side_errors_as_error(false);
    diff.reclassify_statuses(relaxed);
    assert_eq!(
        diff.find_directory("meta_dir/sub").expect("sub").status(),
        FolderStatus::Unchanged
    );
    assert_eq!(
        diff.find_directory("meta_dir").expect("meta_dir").status(),
        FolderStatus::Unchanged
    );
    assert_eq!(
        diff.find_directory("new_dir/inner").expect("inner").status(),
        FolderStatus::Added
    );
    assert_eq!(
        diff.find_directory("new_dir").expect("new_dir").status(),
        FolderStatus::Added
    );
    assert_eq!(diff.root_status(), FolderStatus::Modified);

    // Repropagating manually on a 2,000-level deep tree stays completely stack-safe.
    let mut deep_l = DirectoryNode::new(String::from("/deep"));
    let mut deep_r = DirectoryNode::new(String::from("/deep"));
    let (mut cur_l, mut cur_r) = (&mut deep_l, &mut deep_r);
    for level in 0..DEPTH {
        let name = format!("d{level}");
        cur_l = cur_l
            .sub_directories
            .entry(name.clone())
            .or_insert_with(|| DirectoryNode::new(name.clone()));
        cur_r = cur_r
            .sub_directories
            .entry(name.clone())
            .or_insert_with(|| DirectoryNode::new(name));
    }
    cur_l
        .files
        .insert(String::from("leaf.txt"), file_entry(hash64('a'), 10, t1));
    cur_r
        .files
        .insert(String::from("leaf.txt"), file_entry(hash64('b'), 10, t2));

    let mut deep_diff = compare_trees(&deep_l, &deep_r);
    assert_eq!(deep_diff.root_status(), FolderStatus::Modified);
    assert_eq!(deep_diff.directory_status_counts().modified, DEPTH);
    deep_diff.repropagate_folder_statuses();
    assert_eq!(deep_diff.root_status(), FolderStatus::Modified);
    assert_eq!(deep_diff.directory_status_counts().modified, DEPTH);

    drop(deep_diff);
    let mut drain = vec![deep_l, deep_r];
    while let Some(mut node) = drain.pop() {
        drain.extend(std::mem::take(&mut node.sub_directories).into_values());
    }
}

#[test]
fn folder_status_filter_queries_parsing_and_serde_roundtrip() {
    let t1 = utc(2026, 8, 1, 10, 0, 0);
    let t2 = utc(2026, 8, 2, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app"));
    left.insert_path(&["same_dir", "a.txt"], file_entry(hash64('a'), 10, t1));
    left.insert_path(&["mod_dir", "b.txt"], file_entry(hash64('b'), 10, t1));
    left.insert_path(&["del_dir", "c.txt"], file_entry(hash64('c'), 10, t1));

    let mut right = DirectoryNode::new(String::from("/app"));
    right.insert_path(&["same_dir", "a.txt"], file_entry(hash64('a'), 10, t1));
    right.insert_path(&["mod_dir", "b.txt"], file_entry(hash64('x'), 20, t2));
    right.insert_path(&["add_dir", "d.txt"], file_entry(hash64('d'), 30, t2));

    let diff = compare_trees(&left, &right);

    let changed_dirs: Vec<&str> = diff
        .iter_directories_matching_filter(FolderStatusFilter::changes_only())
        .map(DiffDirectoryNode::relative_path)
        .collect();
    assert_eq!(changed_dirs, vec!["", "add_dir", "del_dir", "mod_dir"]);

    let unchanged_dirs: Vec<&str> = diff
        .iter_directories_with_status(FolderStatus::Unchanged)
        .map(DiffDirectoryNode::relative_path)
        .collect();
    assert_eq!(unchanged_dirs, vec!["same_dir"]);

    let grouped = diff.directories_by_status();
    assert_eq!(grouped[&FolderStatus::Unchanged].len(), 1);
    assert_eq!(grouped[&FolderStatus::Modified].len(), 2); // root + mod_dir
    assert_eq!(grouped[&FolderStatus::Added].len(), 1);
    assert_eq!(grouped[&FolderStatus::Removed].len(), 1);

    // Filter builders & JSON roundtrip.
    let filter = FolderStatusFilter::only(FolderStatus::Modified)
        .include(FolderStatus::Error)
        .with_status(FolderStatus::Added, true)
        .exclude(FolderStatus::Modified);
    assert_eq!(filter.statuses(), vec![FolderStatus::Added, FolderStatus::Error]);
    let json = serde_json::to_string(&filter).expect("serialize filter");
    assert_eq!(json, r#"["added","error"]"#);
    let decoded: FolderStatusFilter = serde_json::from_str(&json).expect("deserialize filter");
    assert_eq!(decoded, filter);

    // Enum parsing & formatting.
    for status in FolderStatus::ALL {
        assert_eq!(status.as_str().parse::<FolderStatus>(), Ok(status));
        assert_eq!(status.symbol().parse::<FolderStatus>(), Ok(status));
        assert_eq!(status.to_string(), status.as_str());
        assert!(!status.display_name().is_empty());
    }
    let bad = "bogus".parse::<FolderStatus>().expect_err("invalid");
    assert_eq!(bad.input(), "bogus");
    assert!(bad.to_string().contains("bogus"));

    // TreeDiff JSON roundtrip preserves folder status and status_summary faithfully.
    let diff_json = serde_json::to_string(&diff).expect("serialize diff");
    let diff_decoded: TreeDiff = serde_json::from_str(&diff_json).expect("deserialize diff");
    assert_eq!(diff_decoded, diff);
}

#[test]
fn diff_statistics_calculates_exact_change_counts_and_storage_deltas() {
    let t1 = utc(2026, 9, 1, 10, 0, 0);
    let t2 = utc(2026, 9, 2, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app"));
    left.insert_path(&["unchanged.bin"], file_entry(hash64('a'), 1_000, t1));
    left.insert_path(&["grew.bin"], file_entry(hash64('b'), 500, t1));
    left.insert_path(&["shrank.bin"], file_entry(hash64('c'), 800, t1));
    left.insert_path(&["meta_only.bin"], file_entry(hash64('d'), 300, t1));
    left.insert_path(&["deleted.bin"], file_entry(hash64('e'), 400, t1));

    let mut right = DirectoryNode::new(String::from("/app"));
    right.insert_path(&["unchanged.bin"], file_entry(hash64('a'), 1_000, t1));
    right.insert_path(&["grew.bin"], file_entry(hash64('x'), 900, t2)); // +400
    right.insert_path(&["shrank.bin"], file_entry(hash64('y'), 200, t2)); // -600
    right.insert_path(&["meta_only.bin"], file_entry(hash64('d'), 300, t2)); // 0
    right.insert_path(&["added.bin"], file_entry(hash64('z'), 1_200, t2)); // +1200

    let mut diff = compare_trees(&left, &right);
    let stats = diff.statistics();

    assert_eq!(stats.total_files(), 6);
    assert_eq!(stats.total_file_changes(), 5);
    assert_eq!(stats.files.unchanged, 1);
    assert_eq!(stats.files.modified, 3);
    assert_eq!(stats.files.added, 1);
    assert_eq!(stats.files.removed, 1);
    assert_eq!(stats.files.error, 0);
    assert_eq!(stats.content_modified_files, 2);
    assert_eq!(stats.metadata_only_modified_files, 1);
    assert!(stats.has_changes());
    assert!(!stats.has_errors());
    assert!(!stats.truncated);

    let s = stats.storage();
    assert_eq!(s.left_total_bytes, 3_000);
    assert_eq!(s.right_total_bytes, 3_600);
    assert_eq!(s.net_delta_bytes, 600);
    assert_eq!(stats.net_size_delta(), 600);
    assert_eq!(s.added_bytes, 1_200);
    assert_eq!(s.removed_bytes, 400);
    assert_eq!(s.modified_before_bytes, 1_600);
    assert_eq!(s.modified_after_bytes, 1_400);
    assert_eq!(s.modified_net_delta_bytes, -200);
    assert_eq!(s.modified_growth_bytes, 400);
    assert_eq!(s.modified_shrink_bytes, 600);
    assert_eq!(s.unchanged_bytes, 1_000);
    assert_eq!(s.total_bytes_gained(), 1_600); // 1200 added + 400 growth
    assert_eq!(s.total_bytes_freed(), 1_000); // 400 removed + 600 shrink
    assert!(s.is_size_complete());
    assert!(!s.has_unknown_sizes());
    assert!((s.net_delta_percent().expect("pct") - 20.0).abs() < 1e-9);
    assert!((stats.file_change_ratio() - (5.0 / 6.0)).abs() < 1e-9);
    assert!((stats.file_unchanged_ratio() - (1.0 / 6.0)).abs() < 1e-9);

    // Reclassifying as content-only moves `meta_only.bin` from Modified to Unchanged!
    diff.reclassify_statuses(FileStatusPolicy::content_only());
    let content_stats = diff.statistics();
    assert_eq!(content_stats.total_file_changes(), 4);
    assert_eq!(content_stats.files.unchanged, 2);
    assert_eq!(content_stats.files.modified, 2);
    assert_eq!(content_stats.content_modified_files, 2);
    assert_eq!(content_stats.metadata_only_modified_files, 0);
    assert_eq!(content_stats.storage.unchanged_bytes, 1_300);
    assert_eq!(content_stats.storage.modified_before_bytes, 1_300);
    assert_eq!(content_stats.storage.modified_after_bytes, 1_100);
    assert_eq!(content_stats.storage.net_delta_bytes, 600);

    // Lossless JSON serde roundtrip.
    let json = serde_json::to_string(&stats).expect("serialize DiffStatistics");
    let decoded: DiffStatistics = serde_json::from_str(&json).expect("deserialize DiffStatistics");
    assert_eq!(decoded, stats);
}

#[test]
fn diff_statistics_handles_negative_deltas_unknown_sizes_truncation_and_empty_trees() {
    let t = utc(2026, 9, 1, 10, 0, 0);

    // Negative net delta + unknown sizes (legacy v1 / errored entries).
    let mut left = DirectoryNode::new(String::from("/data"));
    left.insert_path(&["big.bin"], file_entry(hash64('a'), 10_000, t));
    left.insert_path(&["legacy.bin"], FileEntry::from_hash(hash64('b'), None, None));
    left.insert_path(
        &["broken.bin"],
        FileEntry::from_error(String::from("io error"), None, None),
    );

    let mut right = DirectoryNode::new(String::from("/data"));
    right.insert_path(&["big.bin"], file_entry(hash64('x'), 2_500, t));
    right.insert_path(&["legacy.bin"], FileEntry::from_hash(hash64('b'), None, None));

    let diff = compare_trees(&left, &right);
    let stats = diff.statistics();
    assert_eq!(stats.storage.left_total_bytes, 10_000);
    assert_eq!(stats.storage.right_total_bytes, 2_500);
    assert_eq!(stats.storage.net_delta_bytes, -7_500);
    assert_eq!(stats.storage.abs_net_delta_bytes(), 7_500);
    assert!((stats.storage.net_delta_percent().expect("pct") + 75.0).abs() < 1e-9);
    assert_eq!(stats.storage.left_unknown_size_files, 2); // legacy.bin + broken.bin
    assert_eq!(stats.storage.right_unknown_size_files, 1); // legacy.bin
    assert!(stats.storage.has_unknown_sizes());
    assert!(!stats.storage.is_size_complete());
    assert!(stats.has_errors());

    // Empty trees have 0% change and 100% unchanged ratio, 0.0% storage delta.
    let empty = DirectoryNode::new(String::from("/empty"));
    let empty_stats = compare_trees(&empty, &empty).statistics();
    assert!(!empty_stats.has_changes());
    assert_eq!(empty_stats.storage.net_delta_bytes, 0);
    assert_eq!(empty_stats.storage.net_delta_percent(), Some(0.0));
    assert!((empty_stats.file_change_ratio() - 0.0).abs() < 1e-9);
    assert!((empty_stats.file_unchanged_ratio() - 1.0).abs() < 1e-9);

    // Growing from 0 bytes to >0 bytes reports `None` for percentage (no infinity/NaN).
    let mut non_empty = DirectoryNode::new(String::from("/empty"));
    non_empty.insert_path(&["sub", "new.bin"], file_entry(hash64('1'), 500, t));
    let grow_stats = compare_trees(&empty, &non_empty).statistics();
    assert_eq!(grow_stats.storage.net_delta_bytes, 500);
    assert_eq!(grow_stats.storage.net_delta_percent(), None);

    // Truncated diff reflects `truncated = true` in statistics.
    let trunc_diff =
        compare_trees_with_options(&empty, &non_empty, &ComparisonOptions::new().with_max_depth(Some(0)));
    assert!(trunc_diff.statistics().truncated);

    // Empty added directory still reports `has_changes() == true` even with 0 changed files.
    let mut with_empty_dir = DirectoryNode::new(String::from("/empty"));
    with_empty_dir
        .sub_directories
        .insert(String::from("blank"), DirectoryNode::new(String::from("blank")));
    let dir_only_stats = compare_trees(&empty, &with_empty_dir).statistics();
    assert_eq!(dir_only_stats.total_file_changes(), 0);
    assert_eq!(dir_only_stats.total_affected_directories(), 1);
    assert!(dir_only_stats.has_changes());
}

#[test]
fn per_folder_storage_stats_drilldown_top_changes_deep_trees_and_formatting() {
    const DEPTH: usize = 2_000;
    let t = utc(2026, 9, 1, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/project"));
    left.insert_path(&["root.txt"], file_entry(hash64('r'), 100, t));
    left.insert_path(&["assets", "img", "hero.png"], file_entry(hash64('a'), 5_000, t));
    left.insert_path(&["docs", "guide.md"], file_entry(hash64('b'), 1_000, t));

    let mut right = DirectoryNode::new(String::from("/project"));
    right.insert_path(&["root.txt"], file_entry(hash64('r'), 100, t));
    right.insert_path(&["assets", "img", "hero.png"], file_entry(hash64('a'), 5_000, t));
    right.insert_path(&["assets", "img", "banner.png"], file_entry(hash64('c'), 8_000, t)); // +8000
    right.insert_path(&["docs", "guide.md"], file_entry(hash64('d'), 200, t)); // -800
    right.insert_path(&["videos", "intro.mp4"], file_entry(hash64('e'), 20_000, t)); // +20000

    let diff = compare_trees(&left, &right);

    // Full per-folder breakdown (pre-order): "", "assets", "assets/img", "docs", "videos".
    let all_folders = diff.folder_storage_stats();
    let folder_paths: Vec<&str> = all_folders.iter().map(|f| f.relative_path.as_str()).collect();
    assert_eq!(
        folder_paths,
        vec!["", "assets", "assets/img", "docs", "videos"]
    );

    // Direct vs recursive storage on `assets`: 0 direct bytes, +8000 recursive bytes from `assets/img`.
    let assets = &all_folders[1];
    assert_eq!(assets.direct_net_delta_bytes(), 0);
    assert_eq!(assets.recursive_net_delta_bytes(), 8_000);
    assert_eq!(assets.recursive_storage.left_total_bytes, 5_000);
    assert_eq!(assets.recursive_storage.right_total_bytes, 13_000);

    // Drill-down immediate children of root sorted by abs recursive delta desc: videos (+20000), assets (+8000), docs (-800).
    let top_level = diff
        .child_folder_storage_stats("")
        .expect("root children");
    let top_level_names: Vec<&str> = top_level.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(top_level_names, vec!["videos", "assets", "docs"]);
    assert_eq!(diff.child_folder_storage_stats("nonexistent"), None);

    // Top 2 directories with non-zero DIRECT storage delta: videos (+20000), assets/img (+8000).
    let top_direct = diff.top_folder_storage_changes(2);
    let top_direct_paths: Vec<&str> = top_direct.iter().map(|f| f.relative_path.as_str()).collect();
    assert_eq!(top_direct_paths, vec!["videos", "assets/img"]);
    assert!(diff.top_folder_storage_changes(0).is_empty());

    // Subtree `storage_statistics()` matches recursive folder stats.
    assert_eq!(
        diff.find_directory("assets")
            .expect("assets")
            .storage_statistics(),
        assets.recursive_storage
    );
    assert_eq!(
        diff.storage_statistics(),
        StorageStatistics {
            left_total_bytes: 6_100,
            right_total_bytes: 33_300,
            net_delta_bytes: 27_200,
            added_bytes: 28_000,
            removed_bytes: 0,
            modified_before_bytes: 1_000,
            modified_after_bytes: 200,
            modified_net_delta_bytes: -800,
            modified_growth_bytes: 0,
            modified_shrink_bytes: 800,
            unchanged_bytes: 5_100,
            left_unknown_size_files: 0,
            right_unknown_size_files: 0,
        }
    );

    // Byte formatting helpers.
    assert_eq!(format_bytes(0), "0 B");
    assert_eq!(format_bytes(512), "512 B");
    assert_eq!(format_bytes(1_024), "1.00 KiB");
    assert_eq!(format_bytes(1_572_864), "1.50 MiB");
    assert_eq!(format_signed_bytes(0), "0 B");
    assert_eq!(format_signed_bytes(1_536), "+1.50 KiB");
    assert_eq!(format_signed_bytes(-2_048), "-2.00 KiB");

    // Stack-safe `folder_storage_stats()` on a 2,000-level deep tree.
    let mut deep_l = DirectoryNode::new(String::from("/deep"));
    let mut deep_r = DirectoryNode::new(String::from("/deep"));
    let (mut cur_l, mut cur_r) = (&mut deep_l, &mut deep_r);
    for level in 0..DEPTH {
        let name = format!("d{level}");
        cur_l = cur_l
            .sub_directories
            .entry(name.clone())
            .or_insert_with(|| DirectoryNode::new(name.clone()));
        cur_r = cur_r
            .sub_directories
            .entry(name.clone())
            .or_insert_with(|| DirectoryNode::new(name));
    }
    cur_l
        .files
        .insert(String::from("leaf.bin"), file_entry(hash64('a'), 100, t));
    cur_r
        .files
        .insert(String::from("leaf.bin"), file_entry(hash64('b'), 350, t));

    let deep_diff = compare_trees(&deep_l, &deep_r);
    let deep_folders = deep_diff.folder_storage_stats();
    assert_eq!(deep_folders.len(), DEPTH + 1);
    assert_eq!(deep_folders[0].recursive_net_delta_bytes(), 250);
    assert_eq!(deep_folders[0].direct_net_delta_bytes(), 0);
    assert_eq!(deep_folders[DEPTH].direct_net_delta_bytes(), 250);

    drop(deep_diff);
    let mut drain = vec![deep_l, deep_r];
    while let Some(mut node) = drain.pop() {
        drain.extend(std::mem::take(&mut node.sub_directories).into_values());
    }
}

fn scan_and_save_snapshot(
    data_dir: &Path,
    archive_dir: &Path,
    algorithm: HashAlgorithm,
    ignore_list: IgnoreList,
    hidden_filter: HiddenFileFilter,
    encryption: Option<&EncryptionOptions>,
) -> PathBuf {
    let mut scan = ScanManager::new(algorithm)
        .with_ignore_list(ignore_list.clone())
        .with_hidden_filter(hidden_filter);
    scan.start_hash(data_dir.to_string_lossy().into_owned())
        .expect("baseline scan");

    let tree = DirectoryNode::build_tree(scan.get_path(), scan.get_list());
    let mut meta = MetaData::new(
        scan.get_hash_manager().get_files_counted(),
        scan.get_hash_time(),
        utc(2026, 9, 1, 10, 0, 0),
    )
    .with_algorithm(algorithm)
    .with_total_size(scan.get_total_size())
    .with_hidden_filter(hidden_filter);
    if !ignore_list.is_empty() {
        meta = meta.with_ignore_list(ignore_list);
    }

    FileManager::save_file_with_encryption(archive_dir, &tree, &meta, encryption)
        .expect("save baseline snapshot")
}

#[test]
fn live_compare_detects_clean_match_and_disk_changes_with_stats_and_propagation() {
    let data_dir = TempDir::new("live_basic_data");
    let archive_dir = TempDir::new("live_basic_arch");
    let sub = data_dir.path().join("src");
    fs::create_dir_all(&sub).expect("create src");

    fs::write(data_dir.path().join("readme.md"), b"hello world").expect("write readme");
    fs::write(sub.join("main.rs"), b"fn main() {}").expect("write main");
    fs::write(sub.join("old.rs"), b"deprecated").expect("write old");

    let archive_path = scan_and_save_snapshot(
        data_dir.path(),
        archive_dir.path(),
        HashAlgorithm::Blake3,
        IgnoreList::new(),
        HiddenFileFilter::include_all(),
        None,
    );

    // 1. Unmodified folder matches snapshot cleanly with zero warnings and zero changes.
    let clean = compare_archive_with_folder(&archive_path, data_dir.path()).expect("live clean");
    assert!(clean.is_clean_match());
    assert!(!clean.has_changes());
    assert!(!clean.has_warnings());
    assert!(!clean.has_errors());
    assert!(clean.inherited_algorithm);
    assert_eq!(clean.effective_algorithm(), HashAlgorithm::Blake3);
    assert_eq!(clean.statistics().total_file_changes(), 0);
    assert_eq!(clean.statistics().net_size_delta(), 0);
    assert_eq!(clean.diff().root_status(), FolderStatus::Unchanged);

    // 2. Modify, delete, and add files on disk, then live-compare again.
    fs::write(sub.join("main.rs"), b"fn main() { println!(\"v2\"); }").expect("modify main");
    fs::remove_file(sub.join("old.rs")).expect("remove old");
    let new_dir = data_dir.path().join("assets");
    fs::create_dir_all(&new_dir).expect("create assets");
    fs::write(new_dir.join("logo.bin"), vec![42u8; 256]).expect("write logo");

    let live = compare_archive_with_folder(&archive_path, data_dir.path()).expect("live changed");
    assert!(!live.is_clean_match());
    assert!(live.has_changes());
    assert!(!live.has_warnings());

    assert_eq!(
        live.diff().find_file("readme.md").expect("readme").status(),
        FileStatus::Unchanged
    );
    assert_eq!(
        live.diff().find_file("src/main.rs").expect("main").status(),
        FileStatus::Modified
    );
    assert_eq!(
        live.diff().find_file("src/old.rs").expect("old").status(),
        FileStatus::Removed
    );
    assert_eq!(
        live.diff()
            .find_file("assets/logo.bin")
            .expect("logo")
            .status(),
        FileStatus::Added
    );
    assert_eq!(
        live.diff().find_directory("src").expect("src").status(),
        FolderStatus::Modified
    );
    assert_eq!(
        live.diff()
            .find_directory("assets")
            .expect("assets")
            .status(),
        FolderStatus::Added
    );
    assert_eq!(live.diff().root_status(), FolderStatus::Modified);

    // Net delta: +17 bytes in main.rs (12 -> 29), -10 bytes in old.rs, +256 bytes in logo.bin = +263 bytes.
    assert_eq!(live.statistics().total_file_changes(), 3);
    assert_eq!(live.statistics().net_size_delta(), 263);

    // JSON serde roundtrip of LiveComparisonResult for Tauri IPC.
    let json = serde_json::to_string(&live).expect("serialize LiveComparisonResult");
    let decoded: LiveComparisonResult =
        serde_json::from_str(&json).expect("deserialize LiveComparisonResult");
    assert_eq!(decoded.diff, live.diff);
    assert_eq!(decoded.statistics, live.statistics);
    assert_eq!(decoded.effective_algorithm, live.effective_algorithm);
}

#[test]
fn live_compare_inherits_algorithm_ignore_list_and_hidden_filter_and_supports_overrides() {
    let data_dir = TempDir::new("live_inherit_data");
    let archive_dir = TempDir::new("live_inherit_arch");

    fs::write(data_dir.path().join("app.rs"), b"pub fn run() {}").expect("write app");
    fs::write(data_dir.path().join("debug.log"), b"ignored log").expect("write log");
    fs::write(data_dir.path().join(".env"), b"SECRET=1").expect("write dotfile");

    let ignore_list = IgnoreList::from_patterns(["*.log"]).expect("valid ignore");
    let hidden_filter = HiddenFileFilter::exclude_dotfiles();

    // Baseline saved with SHA-256 + ignore list + hidden filter!
    let archive_path = scan_and_save_snapshot(
        data_dir.path(),
        archive_dir.path(),
        HashAlgorithm::Sha256,
        ignore_list,
        hidden_filter,
        None,
    );

    // Default live comparison inherits SHA-256, `*.log` ignore list, and dotfile filter -> clean match!
    let inherited =
        compare_archive_with_folder(&archive_path, data_dir.path()).expect("live inherited");
    assert!(inherited.is_clean_match());
    assert!(!inherited.has_warnings());
    assert_eq!(inherited.effective_algorithm(), HashAlgorithm::Sha256);
    assert!(inherited.inherited_algorithm);
    assert!(inherited.inherited_ignore_list);
    assert!(inherited.inherited_hidden_filter);
    assert_eq!(inherited.live_ignored_count, 1);
    assert_eq!(inherited.live_hidden_skipped_count, 1);

    // Overriding algorithm, ignore list, and hidden filter surfaces all 3 mismatch warnings!
    let override_opts = LiveComparisonOptions::new()
        .with_algorithm(HashAlgorithm::XxHash3)
        .with_inherit_ignore_list(false)
        .with_hidden_filter(HiddenFileFilter::include_all())
        .with_thread_count(2);

    let precheck = precheck_archive_with_folder(&archive_path, data_dir.path(), &override_opts)
        .expect("precheck overrides");
    assert!(precheck.has_critical_warnings());
    assert!(precheck.has_warning(WarningCode::DifferentHashAlgorithm));
    assert!(precheck.has_warning(WarningCode::DifferentIgnoreLists));
    assert!(precheck.has_warning(WarningCode::DifferentHiddenFileFilter));

    let overridden =
        compare_archive_with_folder_with_options(&archive_path, None, data_dir.path(), &override_opts)
            .expect("live overridden");
    assert!(overridden.has_critical_warnings());
    assert!(!overridden.inherited_algorithm);
    assert!(!overridden.inherited_ignore_list);
    assert!(!overridden.inherited_hidden_filter);
    assert_eq!(overridden.effective_algorithm(), HashAlgorithm::XxHash3);
    assert!(overridden.diff().has_warning(WarningCode::DifferentHashAlgorithm));
    assert!(overridden.diff().has_warning(WarningCode::DifferentIgnoreLists));
    assert!(overridden.diff().has_warning(WarningCode::DifferentHiddenFileFilter));
    // `.env` and `debug.log` now show up as Added because filters were disabled.
    assert_eq!(
        overridden.diff().find_file("debug.log").expect("log").status(),
        FileStatus::Added
    );
    assert_eq!(
        overridden.diff().find_file(".env").expect("env").status(),
        FileStatus::Added
    );
}

#[test]
fn live_compare_supports_encrypted_archives_passwordless_precheck_cross_os_and_cancellation() {
    let data_dir = TempDir::new("live_enc_data");
    let archive_dir = TempDir::new("live_enc_arch");
    fs::write(data_dir.path().join("readme.md"), b"cross platform").expect("write readme");

    // 1. Encrypted archive live comparison + passwordless precheck.
    let fast_kdf = KdfParams::new(8 * 1024, 1, 1).expect("fast test kdf");
    let enc_opts = EncryptionOptions::new("live-secret")
        .expect("enc opts")
        .with_kdf_params(fast_kdf)
        .expect("kdf");
    let enc_archive = scan_and_save_snapshot(
        data_dir.path(),
        archive_dir.path(),
        HashAlgorithm::XxHash3,
        IgnoreList::new(),
        HiddenFileFilter::include_all(),
        Some(&enc_opts),
    );

    // Precheck works WITHOUT a password!
    let pre = precheck_archive_with_folder(&enc_archive, data_dir.path(), &LiveComparisonOptions::new())
        .expect("passwordless live precheck");
    assert!(pre.left().encrypted);
    assert!(!pre.right().encrypted);
    assert!(pre.is_clean());

    // Full live comparison without password returns PasswordRequired.
    let missing_pwd = compare_archive_with_folder(&enc_archive, data_dir.path())
        .expect_err("expected PasswordRequired");
    assert!(matches!(missing_pwd, BulkHashError::PasswordRequired(_)));

    // With password, full live comparison succeeds cleanly with inherited XxHash3.
    let comparer = LiveComparer::new();
    let unlocked = comparer
        .compare_archive(&enc_archive, Some("live-secret"), data_dir.path())
        .expect("unlocked live compare");
    assert!(unlocked.is_clean_match());
    assert_eq!(unlocked.effective_algorithm(), HashAlgorithm::XxHash3);

    // 2. Cross-OS baseline snapshot (e.g. Windows) compared against live folder with case-insensitive matching.
    let mut win_tree = DirectoryNode::new(String::from(r"C:\Users\Lars\OtherFolder"));
    win_tree.insert_path(
        &["README.md"],
        file_entry(
            HashAlgorithm::Blake3.get_hash_from_bytes(b"cross platform"),
            14,
            utc(2026, 9, 1, 10, 0, 0),
        ),
    );
    let win_meta = MetaData::new(1, Duration::from_millis(5), utc(2026, 9, 1, 10, 0, 0))
        .with_os("windows")
        .with_algorithm(HashAlgorithm::Blake3);
    let win_snap = BulkHashFileStruct::new(win_meta, win_tree, hash64('w'));

    let ci_opts = LiveComparisonOptions::new()
        .with_case_insensitive(true)
        .with_status_policy(FileStatusPolicy::content_only());

    let win_pre = precheck_snapshot_with_folder(&win_snap, data_dir.path(), &ci_opts)
        .expect("cross-os live precheck");
    if std::env::consts::OS != "windows" {
        assert!(win_pre.has_warning(WarningCode::DifferentOperatingSystem));
    }
    assert!(win_pre.has_warning(WarningCode::DifferentRootName));

    let mut win_live =
        compare_snapshot_with_folder_with_options(&win_snap, data_dir.path(), &ci_opts)
            .expect("cross-os live compare");
    assert_eq!(
        win_live
            .diff()
            .find_file("readme.md")
            .expect("case-matched readme")
            .status(),
        FileStatus::Unchanged
    );
    assert_eq!(win_live.statistics().total_file_changes(), 0);

    // Reclassifying to strict mode picks up the live mtime difference and syncs statistics!
    win_live.reclassify_statuses(FileStatusPolicy::strict());
    assert_eq!(
        win_live
            .diff()
            .find_file("readme.md")
            .expect("readme")
            .status(),
        FileStatus::Modified
    );
    assert_eq!(win_live.statistics().total_file_changes(), 1);

    // 3. Pre-cancelled ScanControl aborts immediately with ScanCancelled, missing path returns PathNotFound.
    let control = ScanControl::new();
    control.cancel();
    let cancel_opts = LiveComparisonOptions::new().with_control(control);
    let cancelled = compare_snapshot_with_folder_with_options(&win_snap, data_dir.path(), &cancel_opts)
        .expect_err("expected ScanCancelled");
    assert!(matches!(cancelled, BulkHashError::ScanCancelled));

    let missing_dir = data_dir.path().join("does_not_exist");
    let not_found = compare_snapshot_with_folder(&win_snap, &missing_dir)
        .expect_err("expected PathNotFound");
    assert!(matches!(not_found, BulkHashError::PathNotFound(_)));
}

#[test]
fn duplicate_finder_detects_groups_in_single_tree_and_builds_viewer_overlays() {
    let t = utc(2026, 10, 1, 10, 0, 0);

    let mut tree = DirectoryNode::new(String::from("/media/library"));
    // Group A (largest wasted space: 3 copies * 1000 B -> 2000 B wasted, mixed hex case!)
    tree.insert_path(&["photos", "a.jpg"], file_entry(hash64('a'), 1_000, t));
    tree.insert_path(&["photos", "backup", "a_copy.jpg"], file_entry(hash64('A'), 1_000, t));
    tree.insert_path(&["exports", "a_export.jpg"], file_entry(hash64('a'), 1_000, t));
    // Group B (2 copies * 400 B -> 400 B wasted)
    tree.insert_path(&["docs", "manual.pdf"], file_entry(hash64('b'), 400, t));
    tree.insert_path(&["manual_copy.pdf"], file_entry(hash64('b'), 400, t));
    // Unique file (not duplicate)
    tree.insert_path(&["unique.txt"], file_entry(hash64('u'), 500, t));
    // Two errored files with same error text must NEVER be grouped as duplicates!
    tree.insert_path(
        &["err1.bin"],
        FileEntry::from_error(String::from("Permission denied"), None, None),
    );
    tree.insert_path(
        &["err2.bin"],
        FileEntry::from_error(String::from("Permission denied"), None, None),
    );

    let report = find_duplicates_in_tree(&tree);
    assert!(report.has_duplicates());
    assert!(!report.is_truncated());
    assert_eq!(
        report.source(),
        &DuplicateSource::Tree {
            root_name: String::from("/media/library")
        }
    );
    assert_eq!(report.summary().total_files_scanned, 8);
    assert_eq!(report.summary().hashed_files_considered, 6);
    assert_eq!(report.summary().errored_files_skipped, 2);
    assert_eq!(report.summary().duplicate_group_count, 2);
    assert_eq!(report.summary().duplicate_file_count, 5);
    assert_eq!(report.summary().redundant_file_count, 3);
    assert_eq!(report.summary().total_duplicate_bytes, 3_800);
    assert_eq!(report.summary().total_wasted_bytes, 2_400);
    assert!(report.summary().is_size_complete());

    // Default sorting: largest wasted bytes first (Group A = 2000 B, Group B = 400 B).
    assert_eq!(report.groups().len(), 2);
    assert_eq!(report.groups()[0].group_id, 0);
    assert_eq!(report.groups()[0].hash, hash64('a'));
    assert_eq!(report.groups()[0].copy_count, 3);
    assert_eq!(report.groups()[0].redundant_copies(), 2);
    assert_eq!(report.groups()[0].wasted_bytes, Some(2_000));
    let group_a_paths: Vec<&str> = report.groups()[0]
        .files
        .iter()
        .map(DuplicateOccurrence::relative_path)
        .collect();
    assert_eq!(
        group_a_paths,
        vec!["exports/a_export.jpg", "photos/a.jpg", "photos/backup/a_copy.jpg"]
    );

    // Tree-viewer overlay lookup & symmetric DirectoryNode::find_file / find_directory navigation.
    let path_idx = report.path_to_group_index();
    assert_eq!(path_idx.get("photos/a.jpg"), Some(&0));
    assert_eq!(path_idx.get("docs/manual.pdf"), Some(&1));
    assert_eq!(path_idx.get("unique.txt"), None);
    assert!(report.is_duplicate_path("photos\\backup\\a_copy.jpg"));
    assert!(!report.is_duplicate_path("unique.txt"));

    for occ in &report.groups()[0].files {
        assert!(tree.find_file(occ.relative_path()).is_some());
        assert!(tree.find_directory(occ.parent_path()).is_some());
    }
    assert_eq!(tree.find_directory("").expect("root").name, "/media/library");

    // Folder duplicate summary propagates bottom-up to ancestor folders (ready for tree viewer badges).
    let folder_overlays = report.folder_duplicate_summaries();
    assert_eq!(
        folder_overlays.get("photos"),
        Some(&FolderDuplicateSummary {
            direct_duplicate_files: 1,
            recursive_duplicate_files: 2,
            distinct_groups: 1,
            recursive_duplicate_bytes: 2_000,
        })
    );
    assert_eq!(
        folder_overlays.get(""),
        Some(&FolderDuplicateSummary {
            direct_duplicate_files: 1,
            recursive_duplicate_files: 5,
            distinct_groups: 2,
            recursive_duplicate_bytes: 3_800,
        })
    );
}

#[test]
fn duplicate_finder_options_filtering_sorting_truncation_and_size_mismatch() {
    let t = utc(2026, 10, 1, 10, 0, 0);

    let mut tree = DirectoryNode::new(String::from("/opts"));
    // Empty file duplicates (2 copies, 0 bytes)
    tree.insert_path(&["empty1.txt"], file_entry(hash64('0'), 0, t));
    tree.insert_path(&["empty2.txt"], file_entry(hash64('0'), 0, t));
    // Small 3-copy group (3 * 50 B -> 100 B wasted)
    tree.insert_path(&["s1.bin"], file_entry(hash64('1'), 50, t));
    tree.insert_path(&["s2.bin"], file_entry(hash64('1'), 50, t));
    tree.insert_path(&["s3.bin"], file_entry(hash64('1'), 50, t));
    // Large 2-copy group (2 * 500 B -> 500 B wasted)
    tree.insert_path(&["big1.bin"], file_entry(hash64('2'), 500, t));
    tree.insert_path(&["big2.bin"], file_entry(hash64('2'), 500, t));
    // Size-mismatch group (same hash, conflicting sizes 200 vs 250)
    tree.insert_path(&["weird1.bin"], file_entry(hash64('3'), 200, t));
    tree.insert_path(&["weird2.bin"], file_entry(hash64('3'), 250, t));

    // Ignore empty files + require min_file_size >= 100 + sort by FileSizeDesc + cap max_groups = 1.
    let opts = DuplicateOptions::new()
        .with_ignore_empty_files(true)
        .with_min_file_size(Some(100))
        .with_sort_order(DuplicateSortOrder::FileSizeDesc)
        .with_max_groups(Some(1));
    let report = find_duplicates_in_tree_with_options(&tree, &opts);

    assert!(report.is_truncated());
    assert_eq!(report.summary().empty_files_skipped, 2);
    assert_eq!(report.summary().below_min_size_skipped, 3);
    assert_eq!(report.summary().duplicate_group_count, 2); // big + weird (summary keeps full totals!)
    assert_eq!(report.summary().groups_with_size_mismatch, 1);
    assert_eq!(report.groups().len(), 1); // capped to 1
    assert_eq!(report.groups()[0].hash, hash64('2'));
    assert_eq!(report.groups()[0].file_size, Some(500));

    // Sort by CopyCountDesc with min_copies = 3 finds ONLY the 3-copy group.
    let copy_opts = DuplicateOptions::new()
        .with_min_copies(3)
        .with_sort_order(DuplicateSortOrder::CopyCountDesc);
    let copy_report = find_duplicates_in_tree_with_options(&tree, &copy_opts);
    assert_eq!(copy_report.groups().len(), 1);
    assert_eq!(copy_report.groups()[0].hash, hash64('1'));
    assert_eq!(copy_report.groups()[0].copy_count, 3);

    // Check size_mismatch flag explicitly.
    let full = find_duplicates_in_tree(&tree);
    let weird = full
        .groups()
        .iter()
        .find(|g| g.hash == hash64('3'))
        .expect("weird group");
    assert!(weird.size_mismatch);
    assert_eq!(weird.wasted_bytes, Some(200)); // 450 - 250
}

#[test]
fn duplicate_finder_works_on_tree_diff_left_right_and_unified_scopes() {
    let t1 = utc(2026, 10, 1, 10, 0, 0);
    let t2 = utc(2026, 10, 2, 10, 0, 0);

    let mut left = DirectoryNode::new(String::from("/app/v1"));
    left.insert_path(&["keep.bin"], file_entry(hash64('a'), 1_000, t1));
    left.insert_path(&["old_dup.bin"], file_entry(hash64('b'), 600, t1));
    left.insert_path(&["old_dup_copy.bin"], file_entry(hash64('b'), 600, t1));
    left.insert_path(&["moved_from.bin"], file_entry(hash64('m'), 800, t1));

    let mut right = DirectoryNode::new(String::from("/app/v2"));
    right.insert_path(&["keep.bin"], file_entry(hash64('a'), 1_000, t1));
    // Newly added duplicate of `keep.bin` in v2!
    right.insert_path(&["sub", "keep_copy.bin"], file_entry(hash64('a'), 1_000, t2));
    // Old duplicate was cleaned up in v2 (only one copy left).
    right.insert_path(&["old_dup.bin"], file_entry(hash64('b'), 600, t1));
    // Same hash as removed `moved_from.bin` appears at new path `moved_to.bin`.
    right.insert_path(&["moved_to.bin"], file_entry(hash64('m'), 800, t2));

    let diff = compare_trees(&left, &right);

    // 1. Left scope: finds `old_dup.bin` + `old_dup_copy.bin` (baseline duplicates).
    let left_dups = diff.find_duplicates(DiffDuplicateScope::Left);
    assert_eq!(left_dups.groups().len(), 1);
    assert_eq!(left_dups.groups()[0].hash, hash64('b'));
    assert!(left_dups.groups()[0].has_any_status(FileStatus::Unchanged));
    assert!(left_dups.groups()[0].has_any_status(FileStatus::Removed));
    assert_eq!(
        left_dups.source(),
        &DuplicateSource::Diff {
            scope: DiffDuplicateScope::Left,
            left_root_name: String::from("/app/v1"),
            right_root_name: String::from("/app/v2"),
        }
    );

    // 2. Right scope: finds `keep.bin` (Unchanged) + `sub/keep_copy.bin` (Added).
    let right_dups = find_duplicates_in_diff(&diff, DiffDuplicateScope::Right);
    assert_eq!(right_dups.groups().len(), 1);
    assert_eq!(right_dups.groups()[0].hash, hash64('a'));
    assert!(right_dups.groups()[0].has_any_status(FileStatus::Added));
    assert!(right_dups.groups()[0].has_any_status(FileStatus::Unchanged));
    assert_eq!(
        right_dups
            .groups_matching_status_filter(FileStatusFilter::only(FileStatus::Added))
            .count(),
        1
    );

    // 3. Unified scope: finds all 3 duplicate hash groups across distinct diff rows (`a`, `b`, `m`)
    //    without ever duplicating an unchanged file against itself!
    let unified_dups =
        find_duplicates_in_diff_with_options(&diff, DiffDuplicateScope::Unified, &DuplicateOptions::new());
    assert_eq!(unified_dups.groups().len(), 3);
    assert_eq!(unified_dups.summary().duplicate_file_count, 6);
    assert!(unified_dups.group_for_path("moved_from.bin").is_some());
    assert_eq!(
        unified_dups
            .group_for_path("moved_from.bin")
            .expect("m group")
            .group_id,
        unified_dups
            .group_for_path("moved_to.bin")
            .expect("m group")
            .group_id
    );

    // Lossless JSON serde roundtrip of DuplicateReport.
    let json = serde_json::to_string(&unified_dups).expect("serialize DuplicateReport");
    let decoded: DuplicateReport =
        serde_json::from_str(&json).expect("deserialize DuplicateReport");
    assert_eq!(decoded, unified_dups);
}

#[test]
fn duplicate_finder_supports_snapshots_encrypted_archives_and_deep_trees() {
    const DEPTH: usize = 2_000;
    let data_dir = TempDir::new("dup_arch_data");
    let archive_dir = TempDir::new("dup_arch_out");

    fs::write(data_dir.path().join("orig.bin"), b"identical payload 123456").expect("write orig");
    fs::write(data_dir.path().join("copy.bin"), b"identical payload 123456").expect("write copy");
    fs::write(data_dir.path().join("other.bin"), b"something else").expect("write other");

    let plain_archive = scan_and_save_snapshot(
        data_dir.path(),
        archive_dir.path(),
        HashAlgorithm::Blake3,
        IgnoreList::new(),
        HiddenFileFilter::include_all(),
        None,
    );

    let plain_report = find_duplicates_in_archive(&plain_archive).expect("plain archive dups");
    assert_eq!(plain_report.summary().duplicate_group_count, 1);
    assert_eq!(plain_report.summary().total_wasted_bytes, 24);
    assert!(matches!(
        plain_report.source(),
        DuplicateSource::Snapshot {
            algorithm: Some(HashAlgorithm::Blake3),
            ..
        }
    ));

    // Snapshot helper matches archive helper.
    let loaded = FileManager::open_file(&plain_archive).expect("open plain");
    assert_eq!(find_duplicates_in_snapshot(&loaded), plain_report);

    // Encrypted archive duplicate search.
    let fast_kdf = KdfParams::new(8 * 1024, 1, 1).expect("fast kdf");
    let enc_opts = EncryptionOptions::new("dup-secret")
        .expect("enc opts")
        .with_kdf_params(fast_kdf)
        .expect("kdf");
    let enc_dir = TempDir::new("dup_enc_out");
    let enc_archive = scan_and_save_snapshot(
        data_dir.path(),
        enc_dir.path(),
        HashAlgorithm::Sha256,
        IgnoreList::new(),
        HiddenFileFilter::include_all(),
        Some(&enc_opts),
    );
    assert!(matches!(
        DuplicateFinder::new().find_in_archive(&enc_archive),
        Err(BulkHashError::PasswordRequired(_))
    ));
    let enc_report = find_duplicates_in_archive_with_password(
        &enc_archive,
        Some("dup-secret"),
        &DuplicateOptions::new(),
    )
    .expect("encrypted archive dups");
    assert_eq!(enc_report.summary().duplicate_group_count, 1);
    assert_eq!(enc_report.summary().total_wasted_bytes, 24);

    // Stack-safe iterative duplicate scan on a 2,000-level deep tree.
    let t = utc(2026, 10, 1, 10, 0, 0);
    let mut deep = DirectoryNode::new(String::from("/deep"));
    deep.files
        .insert(String::from("root_copy.bin"), file_entry(hash64('d'), 128, t));
    let mut cur = &mut deep;
    for level in 0..DEPTH {
        let name = format!("d{level}");
        cur = cur
            .sub_directories
            .entry(name.clone())
            .or_insert_with(|| DirectoryNode::new(name));
    }
    cur.files
        .insert(String::from("leaf_copy.bin"), file_entry(hash64('d'), 128, t));

    let deep_report = find_duplicates_in_tree(&deep);
    assert_eq!(deep_report.summary().duplicate_group_count, 1);
    assert_eq!(deep_report.summary().total_wasted_bytes, 128);

    let mut drain = vec![deep];
    while let Some(mut node) = drain.pop() {
        drain.extend(std::mem::take(&mut node.sub_directories).into_values());
    }
}
