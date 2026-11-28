use crate::core::diff::file_status::{FileStatus, FileStatusFilter};
use crate::core::diff::statistics::format_bytes;
use crate::core::diff::tree_diff::{EntryPresence, TreeDiff};
use crate::core::hash_manager::HashAlgorithm;
use crate::core::io::{
    bulk_hash_error::BulkHashError,
    directory_node::{DirectoryNode, FileEntry},
    file_manager::FileManager,
};
use crate::core::structs::bulk_hash_file_struct::BulkHashFileStruct;
use chrono::{DateTime, Utc};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet, hash_map};
use std::fmt;
use std::path::Path;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_min_copies() -> usize {
    2
}

/// Controls which side(s) of a [`TreeDiff`] are scanned for duplicate files.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DiffDuplicateScope {
    /// Scan files present in the baseline (left / "before") tree of the diff.
    Left,
    /// Scan files present in the target (right / "after") tree of the diff (default).
    #[default]
    Right,
    /// Scan all rows in the unified diff tree, using each file's active hash (`right` hash if
    /// present, otherwise `left` hash). Useful for spotting identical content across both
    /// retained/added files and removed files without ever pairing a file with itself.
    Unified,
}

impl DiffDuplicateScope {
    /// Returns the canonical `snake_case` identifier (`"left"`, `"right"`, or `"unified"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
            Self::Unified => "unified",
        }
    }
}

impl fmt::Display for DiffDuplicateScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Controls how [`DuplicateReport::groups`] are ordered.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DuplicateSortOrder {
    /// Largest reclaimable wasted space first (tie-broken by copy count desc, then hash asc).
    #[default]
    WastedBytesDesc,
    /// Most duplicate copies first (tie-broken by wasted bytes desc, then hash asc).
    CopyCountDesc,
    /// Largest single file size first (tie-broken by copy count desc, then hash asc).
    FileSizeDesc,
    /// Lexicographical ascending order by normalized hash.
    HashAsc,
}

impl DuplicateSortOrder {
    /// Returns the canonical `snake_case` identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WastedBytesDesc => "wasted_bytes_desc",
            Self::CopyCountDesc => "copy_count_desc",
            Self::FileSizeDesc => "file_size_desc",
            Self::HashAsc => "hash_asc",
        }
    }
}

impl fmt::Display for DuplicateSortOrder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration controlling how duplicate files are detected, filtered, and sorted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateOptions {
    /// Skip empty files (`size == Some(0)`). Default: `false` (all identical hashes reported).
    #[serde(default)]
    pub ignore_empty_files: bool,
    /// Optional minimum file size in bytes (files with known size `< min` or unknown size when
    /// `min > 0` are excluded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_file_size: Option<u64>,
    /// Minimum number of files sharing the same hash required to form a duplicate group
    /// (clamped to at least `2`).
    #[serde(default = "default_min_copies")]
    pub min_copies: usize,
    /// Ordering applied to [`DuplicateReport::groups`].
    #[serde(default)]
    pub sort_order: DuplicateSortOrder,
    /// Optional cap on the number of [`DuplicateGroup`] entries returned in
    /// [`DuplicateReport::groups`] (`summary` always reflects exact totals across all groups).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_groups: Option<usize>,
}

impl Default for DuplicateOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl DuplicateOptions {
    /// Creates default duplicate detection options (include all sizes, `min_copies = 2`, sorted
    /// by largest wasted bytes first, unlimited groups).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ignore_empty_files: false,
            min_file_size: None,
            min_copies: 2,
            sort_order: DuplicateSortOrder::WastedBytesDesc,
            max_groups: None,
        }
    }

    /// Configures whether zero-byte files (`size == Some(0)`) are skipped.
    #[must_use]
    pub const fn with_ignore_empty_files(mut self, ignore: bool) -> Self {
        self.ignore_empty_files = ignore;
        self
    }

    /// Sets an optional minimum file size in bytes.
    #[must_use]
    pub const fn with_min_file_size(mut self, min_bytes: Option<u64>) -> Self {
        self.min_file_size = min_bytes;
        self
    }

    /// Sets the minimum copy count required to form a duplicate group (values `< 2` clamp to `2`).
    #[must_use]
    pub const fn with_min_copies(mut self, min_copies: usize) -> Self {
        self.min_copies = if min_copies < 2 { 2 } else { min_copies };
        self
    }

    /// Configures how duplicate groups are sorted in [`DuplicateReport::groups`].
    #[must_use]
    pub const fn with_sort_order(mut self, sort_order: DuplicateSortOrder) -> Self {
        self.sort_order = sort_order;
        self
    }

    /// Caps the number of groups returned in [`DuplicateReport::groups`].
    #[must_use]
    pub const fn with_max_groups(mut self, max_groups: Option<usize>) -> Self {
        self.max_groups = max_groups;
        self
    }

    #[must_use]
    const fn effective_min_copies(&self) -> usize {
        if self.min_copies < 2 {
            2
        } else {
            self.min_copies
        }
    }
}

/// Identifies which tree, snapshot, or diff view a [`DuplicateReport`] was generated from,
/// enabling reusable GUI tree viewers (single snapshot, left/right side-by-side, or diff viewer)
/// to bind duplicate overlays accurately to the matching tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DuplicateSource {
    /// Scanned directly from a [`DirectoryNode`] tree.
    Tree { root_name: String },
    /// Scanned from a loaded [`BulkHashFileStruct`] snapshot (or `.hashed` archive).
    Snapshot {
        root_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        os: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        algorithm: Option<HashAlgorithm>,
    },
    /// Scanned from a [`TreeDiff`] using the selected [`DiffDuplicateScope`].
    Diff {
        scope: DiffDuplicateScope,
        left_root_name: String,
        right_root_name: String,
    },
}

/// A single file occurrence belonging to a [`DuplicateGroup`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateOccurrence {
    /// File name without directory components.
    pub name: String,
    /// Canonical `/`-separated path relative to the tree root (matches
    /// [`DirectoryNode::find_file`] and [`crate::core::diff::DiffDirectoryNode::find_file`]).
    pub relative_path: String,
    /// Canonical `/`-separated relative path of the parent directory (`""` for files directly in
    /// the root directory).
    pub parent_path: String,
    /// File size in bytes, if recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Last modification timestamp in UTC, if recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<DateTime<Utc>>,
    /// Side presence when scanned from a [`TreeDiff`] (`None` for single-tree/snapshot scans).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence: Option<EntryPresence>,
    /// Semantic [`FileStatus`] when scanned from a [`TreeDiff`] (`None` for single-tree scans).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<FileStatus>,
}

impl DuplicateOccurrence {
    /// Returns the filename.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the canonical `/`-separated relative path from root.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the canonical `/`-separated relative path of the containing directory.
    #[must_use]
    pub fn parent_path(&self) -> &str {
        &self.parent_path
    }
}

/// Group of two or more files sharing an identical hash digest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateGroup {
    /// Stable 0-based index of this group inside [`DuplicateReport::groups`].
    pub group_id: usize,
    /// Normalized lowercase hex hash digest shared by every file in [`Self::files`].
    pub hash: String,
    /// Number of duplicate occurrences in this group (`== files.len()`).
    pub copy_count: usize,
    /// Known single-file size in bytes (when at least one member recorded `size`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    /// Total known bytes across all occurrences in this group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Reclaimable wasted bytes if keeping one copy (`file_size * (copy_count - 1)` when sizes
    /// are known and consistent, or `total_bytes - max_member_size` when sizes disagree).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wasted_bytes: Option<u64>,
    /// `true` if two members sharing this hash recorded different byte sizes (possible hash
    /// collision or inconsistent metadata).
    #[serde(default, skip_serializing_if = "is_false")]
    pub size_mismatch: bool,
    /// All file occurrences sharing [`Self::hash`], sorted deterministically by `relative_path`.
    pub files: Vec<DuplicateOccurrence>,
}

impl DuplicateGroup {
    /// Returns the number of redundant copies that could be removed while keeping one copy.
    #[must_use]
    pub const fn redundant_copies(&self) -> usize {
        self.copy_count.saturating_sub(1)
    }

    /// Returns `true` if any occurrence in this group carries `status` (for diff-sourced reports).
    #[must_use]
    pub fn has_any_status(&self, status: FileStatus) -> bool {
        self.files.iter().any(|file| file.status == Some(status))
    }

    /// Returns `true` if any occurrence in this group passes `filter` (for diff-sourced reports).
    #[must_use]
    pub fn matches_status_filter(&self, filter: FileStatusFilter) -> bool {
        self.files
            .iter()
            .any(|file| file.status.is_some_and(|status| filter.matches(status)))
    }
}

/// Summary totals across all duplicate groups discovered during a duplicate scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateSummary {
    /// Total file entries inspected across the source.
    pub total_files_scanned: usize,
    /// Files with valid hashes that passed configured size filters.
    pub hashed_files_considered: usize,
    /// Files skipped because they recorded a scan/hashing error instead of a hash.
    pub errored_files_skipped: usize,
    /// Files skipped because `size == Some(0)` while `ignore_empty_files` was enabled.
    pub empty_files_skipped: usize,
    /// Files skipped because they did not satisfy `min_file_size`.
    pub below_min_size_skipped: usize,
    /// Total number of duplicate groups found (before any `max_groups` cap).
    pub duplicate_group_count: usize,
    /// Total file occurrences participating across all duplicate groups.
    pub duplicate_file_count: usize,
    /// Total redundant extra copies (`duplicate_file_count - duplicate_group_count`).
    pub redundant_file_count: usize,
    /// Total known bytes occupied by all duplicate files across all groups.
    pub total_duplicate_bytes: u64,
    /// Total known reclaimable wasted bytes across all groups.
    pub total_wasted_bytes: u64,
    /// Number of duplicate groups whose members lacked size metadata.
    pub groups_with_unknown_size: usize,
    /// Number of duplicate groups whose members had disagreeing byte sizes.
    pub groups_with_size_mismatch: usize,
}

impl DuplicateSummary {
    /// Returns `true` if at least one duplicate group was found.
    #[must_use]
    pub const fn has_duplicates(&self) -> bool {
        self.duplicate_group_count > 0
    }

    /// Returns `true` if every duplicate group had known size metadata.
    #[must_use]
    pub const fn is_size_complete(&self) -> bool {
        self.groups_with_unknown_size == 0
    }

    /// Formats [`Self::total_wasted_bytes`] in human-readable IEC binary units.
    #[must_use]
    pub fn wasted_bytes_formatted(&self) -> String {
        format_bytes(self.total_wasted_bytes)
    }
}

/// Per-folder duplicate overlay metrics allowing any GUI tree viewer (single snapshot, left/right
/// comparison viewer, or diff tree viewer) to badge folders that contain duplicate files.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderDuplicateSummary {
    /// Duplicate file occurrences located directly inside this directory.
    pub direct_duplicate_files: usize,
    /// Duplicate file occurrences located in this directory or any nested subdirectory.
    pub recursive_duplicate_files: usize,
    /// Number of distinct duplicate groups represented in this directory or its subdirectories.
    pub distinct_groups: usize,
    /// Total known bytes of duplicate file occurrences across this directory and its
    /// subdirectories.
    pub recursive_duplicate_bytes: u64,
}

/// Complete duplicate detection report for a tree, snapshot, archive, or [`TreeDiff`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DuplicateReport {
    /// Provenance identifying the exact tree, snapshot, or diff scope analyzed.
    pub source: DuplicateSource,
    /// Options used to produce this report.
    pub options: DuplicateOptions,
    /// Aggregated duplicate counts and reclaimable storage totals (always across all groups, even
    /// when [`Self::truncated`] is `true`).
    pub summary: DuplicateSummary,
    /// Detected duplicate groups ordered according to [`DuplicateOptions::sort_order`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<DuplicateGroup>,
    /// `true` if [`Self::groups`] was truncated by [`DuplicateOptions::max_groups`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl DuplicateReport {
    /// Returns `true` if at least one duplicate group was found.
    #[must_use]
    pub const fn has_duplicates(&self) -> bool {
        self.summary.has_duplicates()
    }

    /// Returns the provenance [`DuplicateSource`].
    #[must_use]
    pub const fn source(&self) -> &DuplicateSource {
        &self.source
    }

    /// Returns the [`DuplicateSummary`] totals.
    #[must_use]
    pub const fn summary(&self) -> &DuplicateSummary {
        &self.summary
    }

    /// Returns all returned [`DuplicateGroup`] entries.
    #[must_use]
    pub fn groups(&self) -> &[DuplicateGroup] {
        &self.groups
    }

    /// Returns `true` if [`Self::groups`] was capped by [`DuplicateOptions::max_groups`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Builds a fast lookup index mapping every duplicate file's canonical `relative_path` to its
    /// `group_id` in [`Self::groups`] for $O(\log n)$ tree-viewer row highlighting.
    #[must_use]
    pub fn path_to_group_index(&self) -> BTreeMap<&str, usize> {
        let mut index = BTreeMap::new();
        for group in &self.groups {
            for file in &group.files {
                index.insert(file.relative_path.as_str(), group.group_id);
            }
        }
        index
    }

    /// Finds the [`DuplicateGroup`] containing `relative_path` (accepting `/` or `\` separators).
    #[must_use]
    pub fn group_for_path(&self, relative_path: &str) -> Option<&DuplicateGroup> {
        let normalized = normalize_rel_path(relative_path);
        self.groups.iter().find(|group| {
            group
                .files
                .iter()
                .any(|file| file.relative_path == normalized)
        })
    }

    /// Returns `true` if `relative_path` belongs to any group in [`Self::groups`].
    #[must_use]
    pub fn is_duplicate_path(&self, relative_path: &str) -> bool {
        self.group_for_path(relative_path).is_some()
    }

    /// Iterates over duplicate groups that contain at least one occurrence matching `filter`
    /// (for diff-sourced reports, e.g. finding duplicate groups containing newly `Added` files).
    pub fn groups_matching_status_filter(
        &self,
        filter: FileStatusFilter,
    ) -> impl Iterator<Item = &DuplicateGroup> {
        self.groups
            .iter()
            .filter(move |group| group.matches_status_filter(filter))
    }

    /// Computes per-folder [`FolderDuplicateSummary`] overlays propagated bottom-up to every
    /// ancestor folder `relative_path` (including `""` for root) so any tree viewer can badge
    /// folders containing duplicates without re-scanning the tree.
    #[must_use]
    pub fn folder_duplicate_summaries(&self) -> BTreeMap<String, FolderDuplicateSummary> {
        let mut per_folder: HashMap<&str, (FolderDuplicateSummary, HashSet<usize>)> =
            HashMap::new();

        for group in &self.groups {
            for file in &group.files {
                let parent = file.parent_path.as_str();
                let (direct_summary, _) = per_folder.entry(parent).or_default();
                direct_summary.direct_duplicate_files =
                    direct_summary.direct_duplicate_files.saturating_add(1);

                let file_bytes = file.size.unwrap_or(0);
                for_each_ancestor_folder(parent, |ancestor| {
                    let (summary, group_ids) = per_folder.entry(ancestor).or_default();
                    summary.recursive_duplicate_files =
                        summary.recursive_duplicate_files.saturating_add(1);
                    summary.recursive_duplicate_bytes =
                        summary.recursive_duplicate_bytes.saturating_add(file_bytes);
                    group_ids.insert(group.group_id);
                });
            }
        }

        per_folder
            .into_iter()
            .map(|(folder, (mut summary, group_ids))| {
                summary.distinct_groups = group_ids.len();
                (folder.to_owned(), summary)
            })
            .collect()
    }
}

/// Configurable duplicate finder operating across single [`DirectoryNode`] trees, loaded
/// [`BulkHashFileStruct`] snapshots, `.hashed` archive files, and [`TreeDiff`] comparisons.
#[derive(Debug, Clone, Default)]
pub struct DuplicateFinder {
    options: DuplicateOptions,
}

impl DuplicateFinder {
    /// Creates a [`DuplicateFinder`] with default [`DuplicateOptions`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: DuplicateOptions::new(),
        }
    }

    /// Creates a [`DuplicateFinder`] with explicit [`DuplicateOptions`].
    #[must_use]
    pub const fn with_options(options: DuplicateOptions) -> Self {
        Self { options }
    }

    /// Returns the active [`DuplicateOptions`].
    #[must_use]
    pub const fn options(&self) -> &DuplicateOptions {
        &self.options
    }

    /// Finds all duplicate files inside a single [`DirectoryNode`] tree iteratively (stack-safe).
    #[must_use]
    pub fn find_in_tree(&self, tree: &DirectoryNode) -> DuplicateReport {
        find_duplicates_in_tree_with_options(tree, &self.options)
    }

    /// Finds all duplicate files inside a loaded [`BulkHashFileStruct`] snapshot.
    #[must_use]
    pub fn find_in_snapshot(&self, snapshot: &BulkHashFileStruct) -> DuplicateReport {
        find_duplicates_in_snapshot_with_options(snapshot, &self.options)
    }

    /// Opens an unencrypted `.hashed` archive and finds all duplicate files inside it.
    ///
    /// # Errors
    ///
    /// Propagates archive open/integrity/migration errors from [`FileManager::open_file`].
    pub fn find_in_archive(
        &self,
        archive_path: impl AsRef<Path>,
    ) -> Result<DuplicateReport, BulkHashError> {
        self.find_in_archive_with_password(archive_path, None)
    }

    /// Opens a `.hashed` archive (decrypting with `password` when encrypted) and finds all
    /// duplicate files inside it.
    ///
    /// # Errors
    ///
    /// Propagates archive open/decryption/integrity/migration errors from [`FileManager`].
    pub fn find_in_archive_with_password(
        &self,
        archive_path: impl AsRef<Path>,
        password: Option<&str>,
    ) -> Result<DuplicateReport, BulkHashError> {
        let snapshot = match password {
            Some(pwd) => FileManager::open_file_with_password(archive_path, pwd)?,
            None => FileManager::open_file(archive_path)?,
        };
        Ok(self.find_in_snapshot(&snapshot))
    }

    /// Finds duplicate files inside a [`TreeDiff`] for the chosen [`DiffDuplicateScope`] (`Left`,
    /// `Right`, or `Unified`), annotating every occurrence with its diff `presence` and `status`.
    #[must_use]
    pub fn find_in_diff(&self, diff: &TreeDiff, scope: DiffDuplicateScope) -> DuplicateReport {
        find_duplicates_in_diff_with_options(diff, scope, &self.options)
    }
}

/// Finds duplicate files inside a [`DirectoryNode`] tree using default [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_tree(tree: &DirectoryNode) -> DuplicateReport {
    find_duplicates_in_tree_with_options(tree, &DuplicateOptions::new())
}

/// Finds duplicate files inside a [`DirectoryNode`] tree using custom [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_tree_with_options(
    tree: &DirectoryNode,
    options: &DuplicateOptions,
) -> DuplicateReport {
    let source = DuplicateSource::Tree {
        root_name: tree.name.clone(),
    };
    scan_directory_node_duplicates(tree, source, options)
}

/// Finds duplicate files inside a loaded [`BulkHashFileStruct`] snapshot using default
/// [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_snapshot(snapshot: &BulkHashFileStruct) -> DuplicateReport {
    find_duplicates_in_snapshot_with_options(snapshot, &DuplicateOptions::new())
}

/// Finds duplicate files inside a loaded [`BulkHashFileStruct`] snapshot using custom
/// [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_snapshot_with_options(
    snapshot: &BulkHashFileStruct,
    options: &DuplicateOptions,
) -> DuplicateReport {
    let meta = snapshot.get_meta();
    let source = DuplicateSource::Snapshot {
        root_name: snapshot.get_tree().name.clone(),
        os: Some(meta.get_current_os().to_string()),
        algorithm: meta.get_algorithm(),
    };
    scan_directory_node_duplicates(snapshot.get_tree(), source, options)
}

/// Opens an unencrypted `.hashed` archive and finds duplicate files using default
/// [`DuplicateOptions`].
///
/// # Errors
///
/// Propagates errors from [`FileManager::open_file`].
pub fn find_duplicates_in_archive(
    archive_path: impl AsRef<Path>,
) -> Result<DuplicateReport, BulkHashError> {
    DuplicateFinder::new().find_in_archive(archive_path)
}

/// Opens a `.hashed` archive (decrypting with `password` when encrypted) and finds duplicate
/// files using custom [`DuplicateOptions`].
///
/// # Errors
///
/// Propagates errors from [`FileManager::open_file`] / [`FileManager::open_file_with_password`].
pub fn find_duplicates_in_archive_with_password(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    options: &DuplicateOptions,
) -> Result<DuplicateReport, BulkHashError> {
    DuplicateFinder::with_options(options.clone())
        .find_in_archive_with_password(archive_path, password)
}

/// Finds duplicate files inside a [`TreeDiff`] for `scope` using default [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_diff(diff: &TreeDiff, scope: DiffDuplicateScope) -> DuplicateReport {
    find_duplicates_in_diff_with_options(diff, scope, &DuplicateOptions::new())
}

/// Finds duplicate files inside a [`TreeDiff`] for `scope` using custom [`DuplicateOptions`].
#[must_use]
pub fn find_duplicates_in_diff_with_options(
    diff: &TreeDiff,
    scope: DiffDuplicateScope,
    options: &DuplicateOptions,
) -> DuplicateReport {
    let mut acc = DuplicateAccumulator::new(options);

    for diff_entry in diff.iter_files() {
        let selected: Option<(&str, &FileEntry)> = match scope {
            DiffDuplicateScope::Left => diff_entry
                .left()
                .map(|entry| (diff_entry.left_name().unwrap_or(diff_entry.name()), entry)),
            DiffDuplicateScope::Right => diff_entry
                .right()
                .map(|entry| (diff_entry.right_name().unwrap_or(diff_entry.name()), entry)),
            DiffDuplicateScope::Unified => diff_entry
                .right()
                .map(|entry| (diff_entry.name(), entry))
                .or_else(|| diff_entry.left().map(|entry| (diff_entry.name(), entry))),
        };

        let Some((name, entry)) = selected else {
            continue;
        };

        acc.record(entry, || (name, diff_entry, entry));
    }

    let source = DuplicateSource::Diff {
        scope,
        left_root_name: diff.left_info().root_name.clone(),
        right_root_name: diff.right_info().root_name.clone(),
    };
    acc.finish(source, |(name, diff_entry, entry)| {
        let rel_path = diff_entry.relative_path();
        DuplicateOccurrence {
            name: name.to_owned(),
            relative_path: rel_path.to_owned(),
            parent_path: parent_rel_path(rel_path),
            size: entry.size(),
            modified_utc: entry.modified_utc(),
            presence: Some(diff_entry.presence()),
            status: Some(diff_entry.status()),
        }
    })
}

fn scan_directory_node_duplicates(
    root: &DirectoryNode,
    source: DuplicateSource,
    options: &DuplicateOptions,
) -> DuplicateReport {
    let mut acc = DuplicateAccumulator::new(options);
    let mut dir_paths: Vec<String> = vec![String::new()];
    let mut stack: Vec<(&DirectoryNode, usize)> = vec![(root, 0)];

    while let Some((dir, dir_idx)) = stack.pop() {
        for (file_name, entry) in &dir.files {
            acc.record(entry, || (dir_idx, file_name.as_str(), entry));
        }

        for (child_name, child_dir) in dir.sub_directories.iter().rev() {
            let child_rel = join_rel_path(&dir_paths[dir_idx], child_name);
            let child_idx = dir_paths.len();
            dir_paths.push(child_rel);
            stack.push((child_dir, child_idx));
        }
    }

    acc.finish(source, |(dir_idx, file_name, entry)| {
        let dir_rel = &dir_paths[dir_idx];
        DuplicateOccurrence {
            name: file_name.to_owned(),
            relative_path: join_rel_path(dir_rel, file_name),
            parent_path: dir_rel.clone(),
            size: entry.size(),
            modified_utc: entry.modified_utc(),
            presence: None,
            status: None,
        }
    })
}

enum DuplicateBucket<T> {
    Single(T),
    Multiple(Vec<T>),
}

impl<T> DuplicateBucket<T> {
    fn push(&mut self, item: T) {
        match self {
            Self::Single(_) => {
                let prev = std::mem::replace(self, Self::Multiple(Vec::with_capacity(2)));
                if let Self::Single(first) = prev
                    && let Self::Multiple(vec) = self
                {
                    vec.push(first);
                    vec.push(item);
                }
            }
            Self::Multiple(vec) => vec.push(item),
        }
    }
}

fn normalize_hash_key(raw_hash: &str) -> Cow<'_, str> {
    if raw_hash.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(raw_hash.to_ascii_lowercase())
    } else {
        Cow::Borrowed(raw_hash)
    }
}

struct DuplicateAccumulator<'a, T> {
    options: &'a DuplicateOptions,
    summary: DuplicateSummary,
    buckets: HashMap<Cow<'a, str>, DuplicateBucket<T>>,
}

impl<'a, T> DuplicateAccumulator<'a, T> {
    fn new(options: &'a DuplicateOptions) -> Self {
        Self {
            options,
            summary: DuplicateSummary::default(),
            buckets: HashMap::new(),
        }
    }

    fn record(&mut self, entry: &'a FileEntry, make_candidate: impl FnOnce() -> T) {
        self.summary.total_files_scanned = self.summary.total_files_scanned.saturating_add(1);

        let Some(raw_hash) = entry.hash() else {
            self.summary.errored_files_skipped =
                self.summary.errored_files_skipped.saturating_add(1);
            return;
        };

        if self.options.ignore_empty_files && entry.size() == Some(0) {
            self.summary.empty_files_skipped = self.summary.empty_files_skipped.saturating_add(1);
            return;
        }

        if let Some(min_size) = self.options.min_file_size
            && min_size > 0
            && entry.size().is_none_or(|size| size < min_size)
        {
            self.summary.below_min_size_skipped =
                self.summary.below_min_size_skipped.saturating_add(1);
            return;
        }

        self.summary.hashed_files_considered =
            self.summary.hashed_files_considered.saturating_add(1);

        let normalized_hash = normalize_hash_key(raw_hash);
        let candidate = make_candidate();
        match self.buckets.entry(normalized_hash) {
            hash_map::Entry::Vacant(slot) => {
                slot.insert(DuplicateBucket::Single(candidate));
            }
            hash_map::Entry::Occupied(mut slot) => {
                slot.get_mut().push(candidate);
            }
        }
    }

    fn finish(
        mut self,
        source: DuplicateSource,
        mut materialize: impl FnMut(T) -> DuplicateOccurrence,
    ) -> DuplicateReport {
        let min_copies = self.options.effective_min_copies();
        let mut groups: Vec<DuplicateGroup> = Vec::new();

        for (hash, bucket) in self.buckets {
            let DuplicateBucket::Multiple(candidates) = bucket else {
                continue;
            };
            if candidates.len() < min_copies {
                continue;
            }

            let mut files: Vec<DuplicateOccurrence> =
                candidates.into_iter().map(&mut materialize).collect();
            files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

            let copy_count = files.len();
            let (file_size, total_bytes, wasted_bytes, size_mismatch) =
                compute_group_size_metrics(&files);

            self.summary.duplicate_group_count =
                self.summary.duplicate_group_count.saturating_add(1);
            self.summary.duplicate_file_count =
                self.summary.duplicate_file_count.saturating_add(copy_count);
            self.summary.redundant_file_count = self
                .summary
                .redundant_file_count
                .saturating_add(copy_count.saturating_sub(1));

            if let Some(total) = total_bytes {
                self.summary.total_duplicate_bytes =
                    self.summary.total_duplicate_bytes.saturating_add(total);
            }
            if let Some(wasted) = wasted_bytes {
                self.summary.total_wasted_bytes =
                    self.summary.total_wasted_bytes.saturating_add(wasted);
            } else {
                self.summary.groups_with_unknown_size =
                    self.summary.groups_with_unknown_size.saturating_add(1);
            }
            if size_mismatch {
                self.summary.groups_with_size_mismatch =
                    self.summary.groups_with_size_mismatch.saturating_add(1);
            }

            groups.push(DuplicateGroup {
                group_id: 0,
                hash: hash.into_owned(),
                copy_count,
                file_size,
                total_bytes,
                wasted_bytes,
                size_mismatch,
                files,
            });
        }

        sort_duplicate_groups(&mut groups, self.options.sort_order);

        let truncated = if let Some(max_groups) = self.options.max_groups
            && groups.len() > max_groups
        {
            groups.truncate(max_groups);
            true
        } else {
            false
        };

        for (idx, group) in groups.iter_mut().enumerate() {
            group.group_id = idx;
        }

        DuplicateReport {
            source,
            options: self.options.clone(),
            summary: self.summary,
            groups,
            truncated,
        }
    }
}

fn compute_group_size_metrics(
    files: &[DuplicateOccurrence],
) -> (Option<u64>, Option<u64>, Option<u64>, bool) {
    let mut first_known: Option<u64> = None;
    let mut max_known = 0u64;
    let mut sum_known = 0u64;
    let mut known_count = 0usize;
    let mut size_mismatch = false;

    for file in files {
        if let Some(size) = file.size {
            known_count = known_count.saturating_add(1);
            sum_known = sum_known.saturating_add(size);
            if size > max_known {
                max_known = size;
            }
            match first_known {
                None => first_known = Some(size),
                Some(prev) if prev != size => size_mismatch = true,
                Some(_) => {}
            }
        }
    }

    let Some(rep_size) = first_known else {
        return (None, None, None, false);
    };

    if known_count == files.len() {
        let wasted = if size_mismatch {
            sum_known.saturating_sub(max_known)
        } else {
            let redundant = u64::try_from(files.len().saturating_sub(1)).unwrap_or(u64::MAX);
            rep_size.saturating_mul(redundant)
        };
        (Some(rep_size), Some(sum_known), Some(wasted), size_mismatch)
    } else {
        // Partial size metadata (e.g. mixed legacy/current entries in a unified diff).
        let wasted = sum_known.saturating_sub(max_known);
        (Some(rep_size), Some(sum_known), Some(wasted), size_mismatch)
    }
}

fn sort_duplicate_groups(groups: &mut [DuplicateGroup], order: DuplicateSortOrder) {
    groups.sort_by(|a, b| match order {
        DuplicateSortOrder::WastedBytesDesc => b
            .wasted_bytes
            .unwrap_or(0)
            .cmp(&a.wasted_bytes.unwrap_or(0))
            .then_with(|| b.copy_count.cmp(&a.copy_count))
            .then_with(|| a.hash.cmp(&b.hash)),
        DuplicateSortOrder::CopyCountDesc => b
            .copy_count
            .cmp(&a.copy_count)
            .then_with(|| {
                b.wasted_bytes
                    .unwrap_or(0)
                    .cmp(&a.wasted_bytes.unwrap_or(0))
            })
            .then_with(|| a.hash.cmp(&b.hash)),
        DuplicateSortOrder::FileSizeDesc => b
            .file_size
            .unwrap_or(0)
            .cmp(&a.file_size.unwrap_or(0))
            .then_with(|| b.copy_count.cmp(&a.copy_count))
            .then_with(|| a.hash.cmp(&b.hash)),
        DuplicateSortOrder::HashAsc => a.hash.cmp(&b.hash),
    });
}

fn join_rel_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        let mut combined = String::with_capacity(parent.len() + 1 + child.len());
        combined.push_str(parent);
        combined.push('/');
        combined.push_str(child);
        combined
    }
}

fn parent_rel_path(relative_path: &str) -> String {
    match relative_path.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    }
}

fn normalize_rel_path(path: &str) -> String {
    path.split(['/', '\\'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn for_each_ancestor_folder<'a>(folder_rel_path: &'a str, mut visit: impl FnMut(&'a str)) {
    if folder_rel_path.is_empty() {
        visit("");
        return;
    }

    let mut current = folder_rel_path;
    loop {
        visit(current);
        let Some((parent, _)) = current.rsplit_once('/') else {
            visit("");
            break;
        };
        current = parent;
    }
}
