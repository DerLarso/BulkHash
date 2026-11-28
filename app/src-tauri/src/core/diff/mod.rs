pub mod file_status;
pub mod folder_status;
pub mod live_compare;
pub mod statistics;
pub mod tree_diff;
pub mod warnings;

pub use file_status::{
    FileStatus, FileStatusCounts, FileStatusDetail, FileStatusFilter, FileStatusInfo,
    FileStatusPolicy, ParseFileStatusError, classify_file_entry, classify_file_entry_detailed,
    classify_pair,
};
pub use folder_status::{
    FolderStatus, FolderStatusCounts, FolderStatusFilter, FolderStatusSummary,
    ParseFolderStatusError, derive_folder_status, propagate_folder_statuses,
};
pub use live_compare::{
    LiveComparer, LiveComparisonOptions, LiveComparisonResult, compare_archive_with_folder,
    compare_archive_with_folder_with_options, compare_snapshot_with_folder,
    compare_snapshot_with_folder_with_options, precheck_archive_with_folder,
    precheck_snapshot_with_folder,
};
pub use statistics::{
    DiffStatistics, FolderStorageStats, StorageStatistics, compute_diff_statistics,
    compute_folder_storage_stats, compute_storage_statistics, compute_subtree_statistics,
    format_bytes, format_signed_bytes,
};
pub use tree_diff::{
    ComparisonOptions, DiffDirIter, DiffDirectoryNode, DiffFileEntry, DiffFileIter, EntryPresence,
    FileComparisonOutcome, NameMatchingMode, TreeComparer, TreeDiff, TreeSideInfo,
    compare_snapshots, compare_snapshots_with_options, compare_trees, compare_trees_with_options,
    precheck_archive_files, precheck_metadata, precheck_snapshots, precheck_trees,
    precheck_trees_with_metadata,
};
pub use warnings::{
    ComparisonWarning, MAX_WARNING_SAMPLES, PrecheckReport, PrecheckSideInfo, WarningCode,
    WarningDetails, WarningSeverity, extract_path_basename, infer_os_from_path,
};
