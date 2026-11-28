use crate::core::diff::file_status::{FileStatus, FileStatusCounts};
use crate::core::diff::folder_status::{FolderStatus, FolderStatusCounts};
use crate::core::diff::tree_diff::{DiffDirectoryNode, DiffFileEntry, TreeDiff};
use crate::core::io::directory_node::FileEntry;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

/// Byte-level storage totals and disk-space deltas computed across a compared tree or subtree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StorageStatistics {
    /// Sum of all known file sizes in the baseline (left) tree, in bytes.
    pub left_total_bytes: u64,
    /// Sum of all known file sizes in the target (right) tree, in bytes.
    pub right_total_bytes: u64,
    /// Signed net storage difference (`right_total_bytes - left_total_bytes`), in bytes.
    /// Positive values indicate storage growth; negative values indicate storage reduction.
    pub net_delta_bytes: i128,
    /// Total bytes introduced by [`FileStatus::Added`] files (with known target size).
    pub added_bytes: u64,
    /// Total bytes freed by [`FileStatus::Removed`] files (with known baseline size).
    pub removed_bytes: u64,
    /// Sum of baseline (left) sizes for [`FileStatus::Modified`] files.
    pub modified_before_bytes: u64,
    /// Sum of target (right) sizes for [`FileStatus::Modified`] files.
    pub modified_after_bytes: u64,
    /// Signed net storage delta across [`FileStatus::Modified`] files
    /// (`modified_after_bytes - modified_before_bytes`), in bytes.
    pub modified_net_delta_bytes: i128,
    /// Cumulative bytes gained by [`FileStatus::Modified`] files that grew (`right > left`).
    pub modified_growth_bytes: u64,
    /// Cumulative bytes saved by [`FileStatus::Modified`] files that shrank (`left > right`).
    pub modified_shrink_bytes: u64,
    /// Total bytes occupied by [`FileStatus::Unchanged`] files.
    pub unchanged_bytes: u64,
    /// Number of files present on the left whose `size` metadata was unavailable (`None`).
    pub left_unknown_size_files: usize,
    /// Number of files present on the right whose `size` metadata was unavailable (`None`).
    pub right_unknown_size_files: usize,
}

impl StorageStatistics {
    /// Accumulates a single [`DiffFileEntry`]'s byte contributions into `self`.
    pub fn record_file(&mut self, entry: &DiffFileEntry) {
        if let Some(left) = entry.left() {
            if let Some(size) = left.size() {
                self.left_total_bytes = self.left_total_bytes.saturating_add(size);
            } else {
                self.left_unknown_size_files = self.left_unknown_size_files.saturating_add(1);
            }
        }

        if let Some(right) = entry.right() {
            if let Some(size) = right.size() {
                self.right_total_bytes = self.right_total_bytes.saturating_add(size);
            } else {
                self.right_unknown_size_files = self.right_unknown_size_files.saturating_add(1);
            }
        }

        match entry.status() {
            FileStatus::Added => {
                if let Some(size) = entry.right().and_then(FileEntry::size) {
                    self.added_bytes = self.added_bytes.saturating_add(size);
                }
            }
            FileStatus::Removed => {
                if let Some(size) = entry.left().and_then(FileEntry::size) {
                    self.removed_bytes = self.removed_bytes.saturating_add(size);
                }
            }
            FileStatus::Unchanged => {
                if let Some(size) = entry
                    .right()
                    .and_then(FileEntry::size)
                    .or_else(|| entry.left().and_then(FileEntry::size))
                {
                    self.unchanged_bytes = self.unchanged_bytes.saturating_add(size);
                }
            }
            FileStatus::Modified => {
                let left_size = entry.left().and_then(FileEntry::size);
                let right_size = entry.right().and_then(FileEntry::size);
                if let Some(ls) = left_size {
                    self.modified_before_bytes = self.modified_before_bytes.saturating_add(ls);
                }
                if let Some(rs) = right_size {
                    self.modified_after_bytes = self.modified_after_bytes.saturating_add(rs);
                }
                if let (Some(ls), Some(rs)) = (left_size, right_size) {
                    if rs > ls {
                        self.modified_growth_bytes =
                            self.modified_growth_bytes.saturating_add(rs - ls);
                    } else if ls > rs {
                        self.modified_shrink_bytes =
                            self.modified_shrink_bytes.saturating_add(ls - rs);
                    }
                }
            }
            FileStatus::Error => {}
        }

        self.recompute_deltas();
    }

    /// Merges another [`StorageStatistics`] accumulator into `self` in $O(1)$ time.
    pub const fn merge(&mut self, other: &Self) {
        self.left_total_bytes = self.left_total_bytes.saturating_add(other.left_total_bytes);
        self.right_total_bytes = self
            .right_total_bytes
            .saturating_add(other.right_total_bytes);
        self.added_bytes = self.added_bytes.saturating_add(other.added_bytes);
        self.removed_bytes = self.removed_bytes.saturating_add(other.removed_bytes);
        self.modified_before_bytes = self
            .modified_before_bytes
            .saturating_add(other.modified_before_bytes);
        self.modified_after_bytes = self
            .modified_after_bytes
            .saturating_add(other.modified_after_bytes);
        self.modified_growth_bytes = self
            .modified_growth_bytes
            .saturating_add(other.modified_growth_bytes);
        self.modified_shrink_bytes = self
            .modified_shrink_bytes
            .saturating_add(other.modified_shrink_bytes);
        self.unchanged_bytes = self.unchanged_bytes.saturating_add(other.unchanged_bytes);
        self.left_unknown_size_files = self
            .left_unknown_size_files
            .saturating_add(other.left_unknown_size_files);
        self.right_unknown_size_files = self
            .right_unknown_size_files
            .saturating_add(other.right_unknown_size_files);
        self.recompute_deltas();
    }

    const fn recompute_deltas(&mut self) {
        self.net_delta_bytes =
            (self.right_total_bytes as i128) - (self.left_total_bytes as i128);
        self.modified_net_delta_bytes =
            (self.modified_after_bytes as i128) - (self.modified_before_bytes as i128);
    }

    /// Returns `true` if every file on both sides had known byte-size metadata.
    #[must_use]
    pub const fn is_size_complete(&self) -> bool {
        self.left_unknown_size_files == 0 && self.right_unknown_size_files == 0
    }

    /// Returns `true` if at least one file on either side was missing size metadata.
    #[must_use]
    pub const fn has_unknown_sizes(&self) -> bool {
        !self.is_size_complete()
    }

    /// Returns the unsigned magnitude of [`Self::net_delta_bytes`].
    #[must_use]
    pub const fn abs_net_delta_bytes(&self) -> u128 {
        self.net_delta_bytes.unsigned_abs()
    }

    /// Returns total gross bytes gained across new files and enlarged modified files.
    #[must_use]
    pub const fn total_bytes_gained(&self) -> u64 {
        self.added_bytes.saturating_add(self.modified_growth_bytes)
    }

    /// Returns total gross bytes freed across removed files and shrunken modified files.
    #[must_use]
    pub const fn total_bytes_freed(&self) -> u64 {
        self.removed_bytes.saturating_add(self.modified_shrink_bytes)
    }

    /// Returns the net percentage change relative to [`Self::left_total_bytes`].
    ///
    /// Returns `Some(0.0)` if both sides are `0` bytes, or `None` if `left_total_bytes == 0`
    /// while `right_total_bytes > 0` (percentage growth from zero is undefined).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn net_delta_percent(&self) -> Option<f64> {
        if self.left_total_bytes == 0 {
            return (self.right_total_bytes == 0).then_some(0.0);
        }
        Some((self.net_delta_bytes as f64 / self.left_total_bytes as f64) * 100.0)
    }
}

/// Comprehensive change counts and storage-space deltas for a [`TreeDiff`] or any
/// [`DiffDirectoryNode`] subtree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiffStatistics {
    /// File counts grouped by [`FileStatus`] (`unchanged`, `modified`, `added`, `removed`, `error`).
    pub files: FileStatusCounts,
    /// Descendant subdirectory counts (excluding the root node of the analyzed subtree) grouped by
    /// [`FolderStatus`].
    pub directories: FolderStatusCounts,
    /// Total number of changed files (`modified + added + removed + error`).
    pub total_file_changes: usize,
    /// Total number of descendant subdirectories with a non-unchanged [`FolderStatus`].
    pub total_affected_directories: usize,
    /// Number of [`FileStatus::Modified`] files whose hash (content) differed.
    pub content_modified_files: usize,
    /// Number of [`FileStatus::Modified`] files whose hash matched and only metadata
    /// (`size` or `modified_utc`) differed.
    pub metadata_only_modified_files: usize,
    /// Number of compared file entries involved in a file-vs-directory type conflict.
    pub type_conflict_files: usize,
    /// Number of files matched case-insensitively across differing letter case.
    pub case_mismatch_files: usize,
    /// Byte-level storage totals and disk-space deltas across the analyzed tree.
    pub storage: StorageStatistics,
    /// Whether the analyzed [`TreeDiff`] was truncated by `max_depth` (statistics reflect the
    /// traversed scope when `true`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl DiffStatistics {
    /// Returns the total number of compared file positions across all statuses.
    #[must_use]
    pub const fn total_files(&self) -> usize {
        self.files.total()
    }

    /// Returns the total number of descendant subdirectories across all statuses.
    #[must_use]
    pub const fn total_directories(&self) -> usize {
        self.directories.total()
    }

    /// Returns the total number of changed files (`modified + added + removed + error`).
    #[must_use]
    pub const fn total_file_changes(&self) -> usize {
        self.total_file_changes
    }

    /// Returns the total number of descendant subdirectories with a non-unchanged status.
    #[must_use]
    pub const fn total_affected_directories(&self) -> usize {
        self.total_affected_directories
    }

    /// Returns `true` if any file or descendant directory changed (including empty added/removed
    /// directories or scan errors).
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.total_file_changes > 0 || self.total_affected_directories > 0
    }

    /// Returns `true` if any file or descendant directory recorded a scan/hashing error.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        self.files.error > 0 || self.directories.error > 0
    }

    /// Returns the signed net disk-space difference in bytes (`right - left`).
    #[must_use]
    pub const fn net_size_delta(&self) -> i128 {
        self.storage.net_delta_bytes
    }

    /// Returns the underlying [`StorageStatistics`].
    #[must_use]
    pub const fn storage(&self) -> &StorageStatistics {
        &self.storage
    }

    /// Returns the fraction of compared files that changed (`0.0..=1.0`, or `0.0` if empty).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn file_change_ratio(&self) -> f64 {
        let total = self.files.total();
        if total == 0 {
            return 0.0;
        }
        self.total_file_changes as f64 / total as f64
    }

    /// Returns the fraction of compared files that stayed unchanged (`0.0..=1.0`, or `1.0` if
    /// empty).
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn file_unchanged_ratio(&self) -> f64 {
        let total = self.files.total();
        if total == 0 {
            return 1.0;
        }
        self.files.unchanged as f64 / total as f64
    }
}

/// Per-directory change counts and storage-space deltas for folder-level visualizations
/// (such as bar charts or treemaps showing where disk space grew or shrank).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderStorageStats {
    /// Canonical directory name.
    pub name: String,
    /// Canonical `/`-separated relative path (`""` for the root directory).
    pub relative_path: String,
    /// Depth from the root (`0` for root).
    pub depth: usize,
    /// Propagated [`FolderStatus`] of this directory.
    pub status: FolderStatus,
    /// Counts of files located directly inside this directory (excluding subdirectories).
    pub direct_files: FileStatusCounts,
    /// Counts of all files across this directory and all nested subdirectories.
    pub recursive_files: FileStatusCounts,
    /// Storage metrics for files located directly inside this directory only.
    pub direct_storage: StorageStatistics,
    /// Storage metrics aggregated across this directory and all nested subdirectories.
    pub recursive_storage: StorageStatistics,
}

impl FolderStorageStats {
    /// Returns the signed net byte delta for files directly in this directory.
    #[must_use]
    pub const fn direct_net_delta_bytes(&self) -> i128 {
        self.direct_storage.net_delta_bytes
    }

    /// Returns the signed net byte delta across this directory and all nested subdirectories.
    #[must_use]
    pub const fn recursive_net_delta_bytes(&self) -> i128 {
        self.recursive_storage.net_delta_bytes
    }
}

/// Computes comprehensive [`DiffStatistics`] for a [`TreeDiff`] in a single stack-safe pass.
#[must_use]
pub fn compute_diff_statistics(diff: &TreeDiff) -> DiffStatistics {
    let mut stats = compute_subtree_statistics(diff.root());
    stats.truncated = diff.is_truncated();
    stats
}

/// Computes comprehensive [`DiffStatistics`] for any [`DiffDirectoryNode`] subtree in a single
/// stack-safe pass.
#[must_use]
pub fn compute_subtree_statistics(root: &DiffDirectoryNode) -> DiffStatistics {
    let files = root.status_counts();
    let directories = root.directory_status_counts();
    let mut storage = StorageStatistics::default();
    let mut content_modified_files = 0usize;
    let mut metadata_only_modified_files = 0usize;
    let mut type_conflict_files = 0usize;
    let mut case_mismatch_files = 0usize;

    for entry in root.iter_files() {
        storage.record_file(entry);

        if entry.status().is_modified() {
            if entry.hashes_equal() == Some(true) {
                metadata_only_modified_files = metadata_only_modified_files.saturating_add(1);
            } else {
                content_modified_files = content_modified_files.saturating_add(1);
            }
        }
        if entry.has_type_conflict() {
            type_conflict_files = type_conflict_files.saturating_add(1);
        }
        if entry.name_case_differs() {
            case_mismatch_files = case_mismatch_files.saturating_add(1);
        }
    }

    DiffStatistics {
        files,
        directories,
        total_file_changes: files.changed_total(),
        total_affected_directories: directories.changed_total(),
        content_modified_files,
        metadata_only_modified_files,
        type_conflict_files,
        case_mismatch_files,
        storage,
        truncated: false,
    }
}

/// Computes [`StorageStatistics`] across a [`DiffDirectoryNode`] subtree in a single stack-safe
/// pass.
#[must_use]
pub fn compute_storage_statistics(root: &DiffDirectoryNode) -> StorageStatistics {
    let mut storage = StorageStatistics::default();
    for entry in root.iter_files() {
        storage.record_file(entry);
    }
    storage
}

/// Computes direct and recursive [`FolderStorageStats`] for `root` and every descendant
/// subdirectory in deterministic sorted pre-order using a stack-safe two-phase algorithm.
#[must_use]
pub fn compute_folder_storage_stats(root: &DiffDirectoryNode) -> Vec<FolderStorageStats> {
    let mut nodes: Vec<(&DiffDirectoryNode, Option<usize>)> = Vec::new();
    let mut stack: Vec<(&DiffDirectoryNode, Option<usize>)> = vec![(root, None)];

    while let Some((dir, parent_idx)) = stack.pop() {
        let current_idx = nodes.len();
        nodes.push((dir, parent_idx));
        for child in dir.sub_directories().values().rev() {
            stack.push((child, Some(current_idx)));
        }
    }

    let mut stats: Vec<FolderStorageStats> = Vec::with_capacity(nodes.len());
    for &(dir, _) in &nodes {
        let mut direct_files = FileStatusCounts::default();
        let mut direct_storage = StorageStatistics::default();
        for entry in dir.files().values() {
            direct_files.increment(entry.status());
            direct_storage.record_file(entry);
        }

        stats.push(FolderStorageStats {
            name: dir.name().to_string(),
            relative_path: dir.relative_path().to_string(),
            depth: dir.depth(),
            status: dir.status(),
            direct_files,
            recursive_files: direct_files,
            direct_storage,
            recursive_storage: direct_storage,
        });
    }

    // Reverse pass: every child index is strictly greater than its parent index, so folding
    // right-to-left accumulates exact recursive totals bottom-up without recursion.
    for idx in (0..nodes.len()).rev() {
        if let Some(parent_idx) = nodes[idx].1 {
            let child_files = stats[idx].recursive_files;
            let child_storage = stats[idx].recursive_storage;
            stats[parent_idx].recursive_files.merge(&child_files);
            stats[parent_idx].recursive_storage.merge(&child_storage);
        }
    }

    stats
}

/// Computes up to `limit` directories with non-zero direct storage delta, ordered by largest
/// absolute direct byte delta descending, then by relative path ascending, without allocating
/// folder name/path strings for unchanged or out-of-range directories.
#[must_use]
pub(crate) fn compute_top_folder_storage_changes(
    root: &DiffDirectoryNode,
    limit: usize,
) -> Vec<FolderStorageStats> {
    if limit == 0 {
        return Vec::new();
    }

    let mut nodes: Vec<(&DiffDirectoryNode, Option<usize>)> = Vec::new();
    let mut stack: Vec<(&DiffDirectoryNode, Option<usize>)> = vec![(root, None)];

    while let Some((dir, parent_idx)) = stack.pop() {
        let current_idx = nodes.len();
        nodes.push((dir, parent_idx));
        for child in dir.sub_directories().values().rev() {
            stack.push((child, Some(current_idx)));
        }
    }

    let mut direct_files_vec: Vec<FileStatusCounts> = Vec::with_capacity(nodes.len());
    let mut direct_storage_vec: Vec<StorageStatistics> = Vec::with_capacity(nodes.len());
    let mut recursive_storage_vec: Vec<StorageStatistics> = Vec::with_capacity(nodes.len());

    for &(dir, _) in &nodes {
        let mut direct_files = FileStatusCounts::default();
        let mut direct_storage = StorageStatistics::default();
        for entry in dir.files().values() {
            direct_files.increment(entry.status());
            direct_storage.record_file(entry);
        }
        direct_files_vec.push(direct_files);
        direct_storage_vec.push(direct_storage);
        recursive_storage_vec.push(direct_storage);
    }

    for idx in (0..nodes.len()).rev() {
        if let Some(parent_idx) = nodes[idx].1 {
            let child_storage = recursive_storage_vec[idx];
            recursive_storage_vec[parent_idx].merge(&child_storage);
        }
    }

    let mut changed_indices: Vec<usize> = (0..nodes.len())
        .filter(|&idx| direct_storage_vec[idx].net_delta_bytes != 0)
        .collect();
    changed_indices.sort_by(|&a, &b| {
        direct_storage_vec[b]
            .abs_net_delta_bytes()
            .cmp(&direct_storage_vec[a].abs_net_delta_bytes())
            .then_with(|| nodes[a].0.relative_path().cmp(nodes[b].0.relative_path()))
    });
    changed_indices.truncate(limit);

    changed_indices
        .into_iter()
        .map(|idx| {
            let dir = nodes[idx].0;
            FolderStorageStats {
                name: dir.name().to_string(),
                relative_path: dir.relative_path().to_string(),
                depth: dir.depth(),
                status: dir.status(),
                direct_files: direct_files_vec[idx],
                recursive_files: dir.status_counts(),
                direct_storage: direct_storage_vec[idx],
                recursive_storage: recursive_storage_vec[idx],
            }
        })
        .collect()
}

/// Formats an unsigned byte count in binary IEC units (`B`, `KiB`, `MiB`, `GiB`, `TiB`, `PiB`,
/// `EiB`).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    format_bytes_u128(u128::from(bytes))
}

/// Formats a signed byte delta in binary IEC units with an explicit leading `+` or `-` sign
/// (`"0 B"` when `delta == 0`).
#[must_use]
pub fn format_signed_bytes(delta: i128) -> String {
    if delta == 0 {
        return String::from("0 B");
    }
    let sign = if delta > 0 { '+' } else { '-' };
    let magnitude = format_bytes_u128(delta.unsigned_abs());
    format!("{sign}{magnitude}")
}

#[allow(clippy::cast_precision_loss)]
fn format_bytes_u128(bytes: u128) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }

    let mut value = bytes as f64;
    let mut unit_idx = 0usize;
    while value >= 1024.0 && unit_idx + 1 < UNITS.len() {
        value /= 1024.0;
        unit_idx += 1;
    }
    format!("{value:.2} {}", UNITS[unit_idx])
}
