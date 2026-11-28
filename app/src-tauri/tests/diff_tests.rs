use bulk_hash_lib::core::{
    diff::{
        ComparisonOptions, ComparisonWarning, DiffDirectoryNode, DiffFileEntry, EntryPresence,
        FileComparisonOutcome, FileStatus, FileStatusCounts, FileStatusDetail, FileStatusFilter,
        FileStatusPolicy, MAX_WARNING_SAMPLES, NameMatchingMode, PrecheckReport, TreeComparer,
        TreeDiff, WarningCode, WarningDetails, WarningSeverity, classify_file_entry,
        classify_file_entry_detailed, classify_pair, compare_snapshots,
        compare_snapshots_with_options, compare_trees, compare_trees_with_options,
        extract_path_basename, infer_os_from_path, precheck_archive_files, precheck_metadata,
        precheck_snapshots, precheck_trees, precheck_trees_with_metadata,
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
    scan_manager::ScanManager,
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
