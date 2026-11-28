use crate::core::diff::duplicates::{
    DiffDuplicateScope, DuplicateOptions, DuplicateReport, find_duplicates_in_diff,
    find_duplicates_in_diff_with_options,
};
use crate::core::diff::file_status::{
    FileStatus, FileStatusCounts, FileStatusDetail, FileStatusFilter, FileStatusPolicy,
    classify_entry_with_options, classify_file_entry, classify_file_entry_detailed, classify_pair,
};
use crate::core::diff::folder_status::{
    FolderStatus, FolderStatusCounts, FolderStatusFilter, FolderStatusSummary,
    derive_folder_status, propagate_folder_statuses,
};
use crate::core::diff::statistics::{
    DiffStatistics, FolderStorageStats, StorageStatistics, compute_diff_statistics,
    compute_folder_storage_stats, compute_storage_statistics, compute_subtree_statistics,
};
use crate::core::diff::warnings::{
    ComparisonDiagnostics, ComparisonWarning, PrecheckContext, PrecheckReport, WarningCode,
    WarningContext, WarningSeverity, collect_warnings, evaluate_precheck,
};
use crate::core::hash_manager::HashAlgorithm;
use crate::core::hidden_filter::is_known_system_name;
use crate::core::io::{
    bulk_hash_error::BulkHashError,
    directory_node::{DirectoryNode, FileEntry},
    file_manager::FileManager,
    meta_data::MetaData,
    migration::MigrationReport,
};
use crate::core::structs::bulk_hash_file_struct::BulkHashFileStruct;
use chrono::{DateTime, Utc};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, btree_map};
use std::ffi::OsStr;
use std::fmt;
use std::mem;
use std::path::Path;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_true() -> bool {
    true
}

/// Controls how file and directory names are matched between the left (baseline)
/// and right (target) trees.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum NameMatchingMode {
    /// Exact case-sensitive matching (`"README.md"` != `"readme.md"`).
    #[default]
    Exact,
    /// Case-insensitive Unicode lowercase matching (`"README.md"` matches `"readme.md"`).
    /// Useful when comparing trees across case-insensitive (Windows/macOS) and
    /// case-sensitive (Linux) filesystems. Same-directory collisions are resolved
    /// deterministically without dropping any entries.
    CaseInsensitive,
}

impl NameMatchingMode {
    /// Returns the canonical `snake_case` identifier (`"exact"` or `"case_insensitive"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::CaseInsensitive => "case_insensitive",
        }
    }
}

impl fmt::Display for NameMatchingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration controlling how two [`DirectoryNode`] trees (or `.hashed` snapshots) are compared.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComparisonOptions {
    /// How file and directory names are matched at each tree level.
    #[serde(default)]
    pub name_matching: NameMatchingMode,
    /// Whether compatibility, integrity, and sanity warnings should be collected.
    #[serde(default = "default_true")]
    pub collect_warnings: bool,
    /// Whether per-file metadata (`size`, `modified_utc`) is compared in addition to file hashes.
    #[serde(default = "default_true")]
    pub compare_metadata: bool,
    /// Optional maximum directory depth to descend (`None` = unlimited).
    /// Depth `0` compares files in the root directory only without descending into subdirectories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<usize>,
    /// Policy controlling edge-case rules when assigning semantic [`FileStatus`] values.
    #[serde(default)]
    pub status_policy: FileStatusPolicy,
}

impl Default for ComparisonOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl ComparisonOptions {
    /// Creates default comparison options (exact matching, warnings enabled, metadata comparison
    /// enabled, unlimited depth, default strict status policy).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name_matching: NameMatchingMode::Exact,
            collect_warnings: true,
            compare_metadata: true,
            max_depth: None,
            status_policy: FileStatusPolicy::new(),
        }
    }

    /// Configures how entry names are matched across the two trees.
    #[must_use]
    pub const fn with_name_matching(mut self, mode: NameMatchingMode) -> Self {
        self.name_matching = mode;
        self
    }

    /// Convenience builder toggling between [`NameMatchingMode::CaseInsensitive`] and
    /// [`NameMatchingMode::Exact`].
    #[must_use]
    pub const fn with_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.name_matching = if case_insensitive {
            NameMatchingMode::CaseInsensitive
        } else {
            NameMatchingMode::Exact
        };
        self
    }

    /// Configures whether [`TreeDiff::warnings`] are collected.
    #[must_use]
    pub const fn with_collect_warnings(mut self, collect_warnings: bool) -> Self {
        self.collect_warnings = collect_warnings;
        self
    }

    /// Configures whether file size and modification timestamp differences are distinguished
    /// when hashes are equal.
    #[must_use]
    pub const fn with_compare_metadata(mut self, compare_metadata: bool) -> Self {
        self.compare_metadata = compare_metadata;
        self
    }

    /// Limits traversal depth (`Some(0)` = root files only, `None` = unlimited).
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: Option<usize>) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Configures the [`FileStatusPolicy`] used to categorize compared files into [`FileStatus`].
    #[must_use]
    pub const fn with_status_policy(mut self, status_policy: FileStatusPolicy) -> Self {
        self.status_policy = status_policy;
        self
    }
}

/// Indicates which side(s) of a tree comparison contain an entry at a given position.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPresence {
    /// Entry exists only in the left (baseline / "before") tree.
    OnlyLeft,
    /// Entry exists only in the right (target / "after") tree.
    OnlyRight,
    /// Entry exists in both trees.
    Both,
}

impl EntryPresence {
    /// Returns the canonical `snake_case` identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnlyLeft => "only_left",
            Self::OnlyRight => "only_right",
            Self::Both => "both",
        }
    }

    /// Returns `true` if the entry exists only in the left (baseline) tree.
    #[must_use]
    pub const fn is_only_left(self) -> bool {
        matches!(self, Self::OnlyLeft)
    }

    /// Returns `true` if the entry exists only in the right (target) tree.
    #[must_use]
    pub const fn is_only_right(self) -> bool {
        matches!(self, Self::OnlyRight)
    }

    /// Returns `true` if the entry exists in both trees.
    #[must_use]
    pub const fn is_both(self) -> bool {
        matches!(self, Self::Both)
    }
}

impl fmt::Display for EntryPresence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structural comparison outcome for a single file position in a [`DiffDirectoryNode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileComparisonOutcome {
    /// File exists only in the left (baseline) tree.
    OnlyLeft,
    /// File exists only in the right (target) tree.
    OnlyRight,
    /// File exists in both trees with matching hashes (and matching or ignored metadata).
    Identical,
    /// File exists in both trees with matching hashes, but extended metadata (`size` or
    /// `modified_utc`) differs while [`ComparisonOptions::compare_metadata`] is enabled.
    MetadataChanged,
    /// File exists in both trees with different hashes.
    ContentChanged,
    /// File exists in both trees, but at least one side recorded a scan/hashing error.
    Error,
}

impl FileComparisonOutcome {
    /// Returns the canonical `snake_case` identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OnlyLeft => "only_left",
            Self::OnlyRight => "only_right",
            Self::Identical => "identical",
            Self::MetadataChanged => "metadata_changed",
            Self::ContentChanged => "content_changed",
            Self::Error => "error",
        }
    }

    /// Returns `true` if the file is identical across both trees.
    #[must_use]
    pub const fn is_identical(self) -> bool {
        matches!(self, Self::Identical)
    }

    /// Returns `true` if this file differs or errored between the two trees.
    #[must_use]
    pub const fn is_difference(self) -> bool {
        !self.is_identical()
    }
}

impl fmt::Display for FileComparisonOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compared file entry within a [`DiffDirectoryNode`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiffFileEntry {
    /// Canonical entry name (right tree name when present on the right, otherwise left name).
    pub name: String,
    /// Original filename in the left tree when it differs from `name` (case-insensitive match).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_name: Option<String>,
    /// Canonical `/`-separated path relative to the comparison root.
    pub relative_path: String,
    /// Side presence (`only_left`, `only_right`, or `both`).
    pub presence: EntryPresence,
    /// Structural comparison outcome for this file position.
    pub outcome: FileComparisonOutcome,
    /// Semantic file status (`unchanged`, `modified`, `added`, `removed`, or `error`).
    pub status: FileStatus,
    /// File entry from the left (baseline) tree, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<FileEntry>,
    /// File entry from the right (target) tree, if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right: Option<FileEntry>,
    /// Whether the left and right filenames differed in letter case.
    #[serde(default, skip_serializing_if = "is_false")]
    pub name_case_differs: bool,
    /// Whether a directory with the same name exists on the opposite side.
    #[serde(default, skip_serializing_if = "is_false")]
    pub type_conflict: bool,
}

impl DiffFileEntry {
    /// Returns the canonical entry name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact filename in the left tree, if present in the left tree.
    #[must_use]
    pub fn left_name(&self) -> Option<&str> {
        match self.presence {
            EntryPresence::OnlyRight => None,
            EntryPresence::OnlyLeft => Some(self.name.as_str()),
            EntryPresence::Both => Some(self.left_name.as_deref().unwrap_or(self.name.as_str())),
        }
    }

    /// Returns the exact filename in the right tree, if present in the right tree.
    #[must_use]
    pub fn right_name(&self) -> Option<&str> {
        match self.presence {
            EntryPresence::OnlyLeft => None,
            EntryPresence::OnlyRight | EntryPresence::Both => Some(self.name.as_str()),
        }
    }

    /// Returns the canonical `/`-separated relative path from the tree root.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns which side(s) contain this file.
    #[must_use]
    pub const fn presence(&self) -> EntryPresence {
        self.presence
    }

    /// Returns the structural comparison outcome for this file.
    #[must_use]
    pub const fn outcome(&self) -> FileComparisonOutcome {
        self.outcome
    }

    /// Returns the semantic [`FileStatus`] assigned to this file (`Unchanged`, `Modified`,
    /// `Added`, `Removed`, or `Error`).
    #[must_use]
    pub const fn status(&self) -> FileStatus {
        self.status
    }

    /// Returns structured [`FileStatusDetail`] explaining [`Self::status`].
    #[must_use]
    pub fn status_detail(&self) -> FileStatusDetail {
        let policy = FileStatusPolicy {
            treat_metadata_only_as_modified: matches!(self.status, FileStatus::Modified),
            classify_single_side_errors_as_error: matches!(self.status, FileStatus::Error),
        };
        classify_entry_with_options(self, true, policy).detail
    }

    /// Evaluates what [`FileStatus`] this entry would receive under an arbitrary
    /// [`FileStatusPolicy`] without mutating the entry.
    #[must_use]
    pub fn status_with_policy(&self, policy: FileStatusPolicy) -> FileStatus {
        classify_file_entry(self, policy)
    }

    /// Evaluates structured [`FileStatusDetail`] for this entry under an arbitrary
    /// [`FileStatusPolicy`] without mutating the entry.
    #[must_use]
    pub fn status_detail_with_policy(&self, policy: FileStatusPolicy) -> FileStatusDetail {
        classify_file_entry_detailed(self, policy).detail
    }

    /// Returns the left [`FileEntry`], if present.
    #[must_use]
    pub const fn left(&self) -> Option<&FileEntry> {
        self.left.as_ref()
    }

    /// Returns the right [`FileEntry`], if present.
    #[must_use]
    pub const fn right(&self) -> Option<&FileEntry> {
        self.right.as_ref()
    }

    /// Returns the left hash string, if present and hashed without error.
    #[must_use]
    pub fn left_hash(&self) -> Option<&str> {
        self.left.as_ref().and_then(FileEntry::hash)
    }

    /// Returns the right hash string, if present and hashed without error.
    #[must_use]
    pub fn right_hash(&self) -> Option<&str> {
        self.right.as_ref().and_then(FileEntry::hash)
    }

    /// Returns the left error message, if present and errored during scanning.
    #[must_use]
    pub fn left_error(&self) -> Option<&str> {
        self.left.as_ref().and_then(FileEntry::error)
    }

    /// Returns the right error message, if present and errored during scanning.
    #[must_use]
    pub fn right_error(&self) -> Option<&str> {
        self.right.as_ref().and_then(FileEntry::error)
    }

    /// Returns `Some(true)` if both sides have matching hashes (case-insensitive hex comparison),
    /// `Some(false)` if both sides have different hashes, or `None` if either side is missing or
    /// errored.
    #[must_use]
    pub fn hashes_equal(&self) -> Option<bool> {
        match (self.left_hash(), self.right_hash()) {
            (Some(lh), Some(rh)) => Some(lh.eq_ignore_ascii_case(rh)),
            _ => None,
        }
    }

    /// Returns `true` if either side recorded a scan/hashing error.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.left.as_ref().is_some_and(FileEntry::is_err)
            || self.right.as_ref().is_some_and(FileEntry::is_err)
    }

    /// Returns `true` if this file is identical across both trees.
    #[must_use]
    pub const fn is_identical(&self) -> bool {
        self.outcome.is_identical()
    }

    /// Returns `true` if this file differs or errored between the two trees.
    #[must_use]
    pub const fn is_changed(&self) -> bool {
        self.outcome.is_difference()
    }

    /// Returns the signed byte-size delta (`right - left`) when size metadata is available for
    /// all present sides.
    #[must_use]
    pub fn size_delta(&self) -> Option<i128> {
        match (&self.left, &self.right) {
            (Some(l), Some(r)) => Some(i128::from(r.size?) - i128::from(l.size?)),
            (Some(l), None) => Some(-i128::from(l.size?)),
            (None, Some(r)) => Some(i128::from(r.size?)),
            (None, None) => None,
        }
    }

    /// Returns `Some(true)` if both sides carry `modified_utc` timestamps and they differ,
    /// `Some(false)` if both carry equal timestamps, or `None` if timestamps are unavailable.
    #[must_use]
    pub fn modified_changed(&self) -> Option<bool> {
        match (
            self.left.as_ref().and_then(FileEntry::modified_utc),
            self.right.as_ref().and_then(FileEntry::modified_utc),
        ) {
            (Some(lm), Some(rm)) => Some(lm != rm),
            _ => None,
        }
    }

    /// Returns `true` if matched case-insensitively across differing letter case.
    #[must_use]
    pub const fn name_case_differs(&self) -> bool {
        self.name_case_differs
    }

    /// Returns `true` if the opposite tree contains a directory with the same name.
    #[must_use]
    pub const fn has_type_conflict(&self) -> bool {
        self.type_conflict
    }
}

/// A directory node in the aligned comparison tree produced by comparing two [`DirectoryNode`]s.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiffDirectoryNode {
    /// Canonical directory name (right tree name when present on the right, otherwise left name).
    pub name: String,
    /// Original directory name in the left tree when it differs from `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_name: Option<String>,
    /// Canonical `/`-separated relative path from the comparison root (`""` for the root node).
    pub relative_path: String,
    /// Depth from the root node (`0` for the root directory).
    pub depth: usize,
    /// Side presence (`only_left`, `only_right`, or `both`).
    pub presence: EntryPresence,
    /// Propagated semantic folder status (`unchanged`, `modified`, `added`, `removed`, or `error`).
    pub status: FolderStatus,
    /// Precomputed bottom-up status summary of all files and descendant subdirectories beneath
    /// this directory.
    pub status_summary: FolderStatusSummary,
    /// Whether the left and right directory names differed in letter case.
    #[serde(default, skip_serializing_if = "is_false")]
    pub name_case_differs: bool,
    /// Whether a file with the same name exists on the opposite side.
    #[serde(default, skip_serializing_if = "is_false")]
    pub type_conflict: bool,
    /// Compared files directly inside this directory (sorted by canonical name).
    pub files: BTreeMap<String, DiffFileEntry>,
    /// Compared child directories directly inside this directory (sorted by canonical name).
    pub sub_directories: BTreeMap<String, Self>,
}

impl Drop for DiffDirectoryNode {
    fn drop(&mut self) {
        if self.sub_directories.is_empty() {
            return;
        }
        let mut stack: Vec<Self> = mem::take(&mut self.sub_directories).into_values().collect();
        while let Some(mut node) = stack.pop() {
            stack.extend(mem::take(&mut node.sub_directories).into_values());
        }
    }
}

impl DiffDirectoryNode {
    /// Returns the canonical directory name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the exact directory name in the left tree, if present in the left tree.
    #[must_use]
    pub fn left_name(&self) -> Option<&str> {
        match self.presence {
            EntryPresence::OnlyRight => None,
            EntryPresence::OnlyLeft => Some(self.name.as_str()),
            EntryPresence::Both => Some(self.left_name.as_deref().unwrap_or(self.name.as_str())),
        }
    }

    /// Returns the exact directory name in the right tree, if present in the right tree.
    #[must_use]
    pub fn right_name(&self) -> Option<&str> {
        match self.presence {
            EntryPresence::OnlyLeft => None,
            EntryPresence::OnlyRight | EntryPresence::Both => Some(self.name.as_str()),
        }
    }

    /// Returns the canonical `/`-separated relative path (`""` for the root).
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns this directory's depth from the root (`0` for root).
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.depth
    }

    /// Returns which side(s) contain this directory.
    #[must_use]
    pub const fn presence(&self) -> EntryPresence {
        self.presence
    }

    /// Returns the propagated semantic [`FolderStatus`] of this directory (`Unchanged`,
    /// `Modified`, `Added`, `Removed`, or `Error`).
    #[must_use]
    pub const fn status(&self) -> FolderStatus {
        self.status
    }

    /// Returns the precomputed bottom-up [`FolderStatusSummary`] covering this directory and all
    /// of its descendants.
    #[must_use]
    pub const fn status_summary(&self) -> &FolderStatusSummary {
        &self.status_summary
    }

    /// Returns `true` if matched case-insensitively across differing letter case.
    #[must_use]
    pub const fn name_case_differs(&self) -> bool {
        self.name_case_differs
    }

    /// Returns `true` if the opposite tree contains a file with the same name.
    #[must_use]
    pub const fn has_type_conflict(&self) -> bool {
        self.type_conflict
    }

    /// Returns the map of compared files directly in this directory.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<String, DiffFileEntry> {
        &self.files
    }

    /// Returns the map of compared subdirectories directly in this directory.
    #[must_use]
    pub const fn sub_directories(&self) -> &BTreeMap<String, Self> {
        &self.sub_directories
    }

    /// Returns `true` if this directory has neither files nor subdirectories.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty() && self.sub_directories.is_empty()
    }

    /// Looks up a compared file by relative path (accepting both `/` and `\` separators).
    #[must_use]
    pub fn find_file(&self, relative_path: &str) -> Option<&DiffFileEntry> {
        let parts: Vec<&str> = split_relative_path(relative_path).collect();
        let (&file_name, dirs) = parts.split_last()?;
        let mut current = self;
        for &dir in dirs {
            current = current.sub_directories.get(dir)?;
        }
        current.files.get(file_name)
    }

    /// Looks up a compared directory by relative path (accepting both `/` and `\` separators).
    /// Returns `Some(self)` for `""`, `"."`, or `"/"`.
    #[must_use]
    pub fn find_directory(&self, relative_path: &str) -> Option<&Self> {
        let mut current = self;
        for dir in split_relative_path(relative_path) {
            current = current.sub_directories.get(dir)?;
        }
        Some(current)
    }

    /// Returns a stack-safe depth-first pre-order iterator over all compared files in this
    /// subtree (in deterministic sorted order).
    #[must_use]
    pub fn iter_files(&self) -> DiffFileIter<'_> {
        DiffFileIter {
            dir_stack: vec![self],
            current_files: None,
        }
    }

    /// Returns a stack-safe depth-first pre-order iterator over all compared directories in this
    /// subtree, starting with `self` (in deterministic sorted order).
    #[must_use]
    pub fn iter_directories(&self) -> DiffDirIter<'_> {
        DiffDirIter {
            dir_stack: vec![self],
        }
    }

    /// Returns `true` if this directory or any descendant differs between left and right
    /// (including single-side empty directories, changed/unpaired files, or errored files).
    #[must_use]
    pub fn has_any_difference(&self) -> bool {
        for dir in self.iter_directories() {
            if !dir.presence.is_both() {
                return true;
            }
            if dir.files.values().any(DiffFileEntry::is_changed) {
                return true;
            }
        }
        false
    }

    /// Returns the total number of compared file positions in this subtree.
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.iter_directories()
            .fold(0usize, |acc, dir| acc.saturating_add(dir.files.len()))
    }

    /// Returns the total number of compared subdirectories in this subtree (excluding `self`).
    #[must_use]
    pub fn directory_count(&self) -> usize {
        self.iter_directories().count().saturating_sub(1)
    }

    /// Iterates over all files in this subtree matching a specific [`FileStatus`].
    pub fn iter_files_with_status(
        &self,
        status: FileStatus,
    ) -> impl Iterator<Item = &DiffFileEntry> {
        self.iter_files()
            .filter(move |entry| entry.status() == status)
    }

    /// Iterates over all files in this subtree matching a [`FileStatusFilter`].
    pub fn iter_files_matching_filter(
        &self,
        filter: FileStatusFilter,
    ) -> impl Iterator<Item = &DiffFileEntry> {
        self.iter_files()
            .filter(move |entry| filter.matches(entry.status()))
    }

    /// Groups all files in this subtree by their [`FileStatus`] in deterministic tree order.
    #[must_use]
    pub fn files_by_status(&self) -> BTreeMap<FileStatus, Vec<&DiffFileEntry>> {
        let mut grouped: BTreeMap<FileStatus, Vec<&DiffFileEntry>> = BTreeMap::new();
        for entry in self.iter_files() {
            grouped.entry(entry.status()).or_default().push(entry);
        }
        grouped
    }

    /// Counts all files in this subtree grouped by [`FileStatus`] in $O(1)$ time from the
    /// propagated [`FolderStatusSummary`].
    #[must_use]
    pub const fn status_counts(&self) -> FileStatusCounts {
        self.status_summary.files
    }

    /// Counts all descendant subdirectories beneath this directory (excluding `self`) grouped by
    /// [`FolderStatus`] in $O(1)$ time from the propagated [`FolderStatusSummary`].
    #[must_use]
    pub const fn directory_status_counts(&self) -> FolderStatusCounts {
        self.status_summary.directories
    }

    /// Iterates over all directories in this subtree (including `self`) matching a specific
    /// [`FolderStatus`].
    pub fn iter_directories_with_status(
        &self,
        status: FolderStatus,
    ) -> impl Iterator<Item = &Self> {
        self.iter_directories()
            .filter(move |dir| dir.status() == status)
    }

    /// Iterates over all directories in this subtree (including `self`) matching a
    /// [`FolderStatusFilter`].
    pub fn iter_directories_matching_filter(
        &self,
        filter: FolderStatusFilter,
    ) -> impl Iterator<Item = &Self> {
        self.iter_directories()
            .filter(move |dir| filter.matches(dir.status()))
    }

    /// Groups all directories in this subtree (including `self`) by their [`FolderStatus`] in
    /// deterministic tree order.
    #[must_use]
    pub fn directories_by_status(&self) -> BTreeMap<FolderStatus, Vec<&Self>> {
        let mut grouped: BTreeMap<FolderStatus, Vec<&Self>> = BTreeMap::new();
        for dir in self.iter_directories() {
            grouped.entry(dir.status()).or_default().push(dir);
        }
        grouped
    }

    /// Computes comprehensive [`DiffStatistics`] (change counts and storage-space deltas) across
    /// this directory and all nested descendants.
    #[must_use]
    pub fn statistics(&self) -> DiffStatistics {
        compute_subtree_statistics(self)
    }

    /// Computes [`StorageStatistics`] across this directory and all nested descendants.
    #[must_use]
    pub fn storage_statistics(&self) -> StorageStatistics {
        compute_storage_statistics(self)
    }

    /// Computes direct and recursive [`FolderStorageStats`] for this directory and every
    /// descendant subdirectory in deterministic sorted pre-order.
    #[must_use]
    pub fn folder_storage_stats(&self) -> Vec<FolderStorageStats> {
        compute_folder_storage_stats(self)
    }
}

/// Stack-safe depth-first pre-order iterator over `&DiffDirectoryNode` entries.
pub struct DiffDirIter<'a> {
    dir_stack: Vec<&'a DiffDirectoryNode>,
}

impl<'a> Iterator for DiffDirIter<'a> {
    type Item = &'a DiffDirectoryNode;

    fn next(&mut self) -> Option<Self::Item> {
        let dir = self.dir_stack.pop()?;
        for child in dir.sub_directories.values().rev() {
            self.dir_stack.push(child);
        }
        Some(dir)
    }
}

/// Stack-safe depth-first pre-order iterator over `&DiffFileEntry` items in a diff tree.
pub struct DiffFileIter<'a> {
    dir_stack: Vec<&'a DiffDirectoryNode>,
    current_files: Option<btree_map::Values<'a, String, DiffFileEntry>>,
}

impl<'a> Iterator for DiffFileIter<'a> {
    type Item = &'a DiffFileEntry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(files_iter) = self.current_files.as_mut()
                && let Some(file) = files_iter.next()
            {
                return Some(file);
            }

            let next_dir = self.dir_stack.pop()?;
            for child in next_dir.sub_directories.values().rev() {
                self.dir_stack.push(child);
            }
            self.current_files = Some(next_dir.files.values());
        }
    }
}

/// Summary metadata about one side (left/baseline or right/target) of a [`TreeDiff`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeSideInfo {
    /// Original root directory name (`DirectoryNode::name`).
    pub root_name: String,
    /// Operating system recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Hash algorithm recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<HashAlgorithm>,
    /// Snapshot creation timestamp in UTC recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_utc: Option<DateTime<Utc>>,
    /// Snapshot format version recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<usize>,
    /// Original format version if the snapshot was migrated on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<usize>,
    /// Total number of file entries present in this side's full input tree.
    pub total_files: usize,
    /// Total number of subdirectories present in this side's full input tree (excluding root).
    pub total_directories: usize,
    /// Number of file entries in this side's full input tree that recorded a scan/hash error.
    pub error_files: usize,
}

/// Complete result of comparing two [`DirectoryNode`] trees (or two `.hashed` snapshots).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TreeDiff {
    /// Root node of the aligned comparison tree.
    pub root: DiffDirectoryNode,
    /// Options used to produce this tree comparison.
    pub options: ComparisonOptions,
    /// Summary provenance and counts for the left (baseline) tree.
    pub left_info: TreeSideInfo,
    /// Summary provenance and counts for the right (target) tree.
    pub right_info: TreeSideInfo,
    /// Compatibility, integrity, and sanity warnings detected during comparison, sorted by
    /// severity descending (`Critical` -> `Warning` -> `Info`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ComparisonWarning>,
    /// Whether traversal stopped early because [`ComparisonOptions::max_depth`] was reached.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl TreeDiff {
    /// Returns the root [`DiffDirectoryNode`].
    #[must_use]
    pub const fn root(&self) -> &DiffDirectoryNode {
        &self.root
    }

    /// Returns the [`ComparisonOptions`] used to build this diff.
    #[must_use]
    pub const fn options(&self) -> &ComparisonOptions {
        &self.options
    }

    /// Returns summary metadata for the left (baseline) tree.
    #[must_use]
    pub const fn left_info(&self) -> &TreeSideInfo {
        &self.left_info
    }

    /// Returns summary metadata for the right (target) tree.
    #[must_use]
    pub const fn right_info(&self) -> &TreeSideInfo {
        &self.right_info
    }

    /// Returns all warnings emitted during this comparison.
    #[must_use]
    pub fn warnings(&self) -> &[ComparisonWarning] {
        &self.warnings
    }

    /// Returns `true` if traversal was truncated by [`ComparisonOptions::max_depth`].
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns `true` if the compared trees are completely identical and traversal was not
    /// truncated by `max_depth`.
    #[must_use]
    pub fn is_identical(&self) -> bool {
        !self.truncated && !self.root.has_any_difference()
    }

    /// Returns `true` if at least one warning was emitted.
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns `true` if any [`WarningSeverity::Critical`] warning was emitted.
    #[must_use]
    pub fn has_critical_warnings(&self) -> bool {
        self.warnings.iter().any(ComparisonWarning::is_critical)
    }

    /// Returns `true` if a warning with the given [`WarningCode`] was emitted.
    #[must_use]
    pub fn has_warning(&self, code: WarningCode) -> bool {
        self.warnings.iter().any(|warning| warning.code == code)
    }

    /// Iterates over warnings with severity greater than or equal to `min_severity`.
    pub fn warnings_at_least(
        &self,
        min_severity: WarningSeverity,
    ) -> impl Iterator<Item = &ComparisonWarning> {
        self.warnings
            .iter()
            .filter(move |warning| warning.severity >= min_severity)
    }

    /// Looks up a compared file by relative path (accepting both `/` and `\` separators).
    #[must_use]
    pub fn find_file(&self, relative_path: &str) -> Option<&DiffFileEntry> {
        self.root.find_file(relative_path)
    }

    /// Looks up a compared directory by relative path (accepting both `/` and `\` separators).
    #[must_use]
    pub fn find_directory(&self, relative_path: &str) -> Option<&DiffDirectoryNode> {
        self.root.find_directory(relative_path)
    }

    /// Iterates over all compared files in deterministic sorted depth-first order.
    #[must_use]
    pub fn iter_files(&self) -> DiffFileIter<'_> {
        self.root.iter_files()
    }

    /// Iterates over all compared directories in deterministic sorted depth-first order,
    /// starting with the root directory.
    #[must_use]
    pub fn iter_directories(&self) -> DiffDirIter<'_> {
        self.root.iter_directories()
    }

    /// Iterates over all compared files whose outcome is not [`FileComparisonOutcome::Identical`].
    pub fn iter_changed_files(&self) -> impl Iterator<Item = &DiffFileEntry> {
        self.iter_files().filter(|entry| entry.is_changed())
    }

    /// Iterates over all files in this diff matching a specific [`FileStatus`].
    pub fn iter_files_with_status(
        &self,
        status: FileStatus,
    ) -> impl Iterator<Item = &DiffFileEntry> {
        self.root.iter_files_with_status(status)
    }

    /// Iterates over all files in this diff matching a [`FileStatusFilter`] (for example
    /// [`FileStatusFilter::changes_only`] to hide unchanged files).
    pub fn iter_files_matching_filter(
        &self,
        filter: FileStatusFilter,
    ) -> impl Iterator<Item = &DiffFileEntry> {
        self.root.iter_files_matching_filter(filter)
    }

    /// Groups all files in this diff by their [`FileStatus`] in deterministic tree order.
    #[must_use]
    pub fn files_by_status(&self) -> BTreeMap<FileStatus, Vec<&DiffFileEntry>> {
        self.root.files_by_status()
    }

    /// Counts all files in this diff grouped by [`FileStatus`] in $O(1)$ time.
    #[must_use]
    pub const fn status_counts(&self) -> FileStatusCounts {
        self.root.status_counts()
    }

    /// Returns the propagated [`FolderStatus`] of the root directory.
    #[must_use]
    pub const fn root_status(&self) -> FolderStatus {
        self.root.status()
    }

    /// Counts all subdirectories in this diff (excluding root) grouped by [`FolderStatus`] in
    /// $O(1)$ time.
    #[must_use]
    pub const fn directory_status_counts(&self) -> FolderStatusCounts {
        self.root.directory_status_counts()
    }

    /// Iterates over all directories in this diff (including root) matching a specific
    /// [`FolderStatus`].
    pub fn iter_directories_with_status(
        &self,
        status: FolderStatus,
    ) -> impl Iterator<Item = &DiffDirectoryNode> {
        self.root.iter_directories_with_status(status)
    }

    /// Iterates over all directories in this diff (including root) matching a
    /// [`FolderStatusFilter`].
    pub fn iter_directories_matching_filter(
        &self,
        filter: FolderStatusFilter,
    ) -> impl Iterator<Item = &DiffDirectoryNode> {
        self.root.iter_directories_matching_filter(filter)
    }

    /// Groups all directories in this diff (including root) by their [`FolderStatus`] in
    /// deterministic tree order.
    #[must_use]
    pub fn directories_by_status(&self) -> BTreeMap<FolderStatus, Vec<&DiffDirectoryNode>> {
        self.root.directories_by_status()
    }

    /// Recomputes [`DiffDirectoryNode::status`] and [`DiffDirectoryNode::status_summary`]
    /// bottom-up across the entire diff tree iteratively (stack-safe).
    pub fn repropagate_folder_statuses(&mut self) {
        propagate_folder_statuses(&mut self.root);
    }

    /// Computes comprehensive [`DiffStatistics`] (total change counts, modification breakdown,
    /// and byte-level storage deltas) across this diff.
    #[must_use]
    pub fn statistics(&self) -> DiffStatistics {
        compute_diff_statistics(self)
    }

    /// Computes byte-level [`StorageStatistics`] across this diff.
    #[must_use]
    pub fn storage_statistics(&self) -> StorageStatistics {
        self.root.storage_statistics()
    }

    /// Computes direct and recursive [`FolderStorageStats`] for the root and every subdirectory
    /// in deterministic sorted pre-order (useful for per-folder bar charts and treemaps).
    #[must_use]
    pub fn folder_storage_stats(&self) -> Vec<FolderStorageStats> {
        self.root.folder_storage_stats()
    }

    /// Returns [`FolderStorageStats`] for the immediate child subdirectories of
    /// `parent_relative_path` (`""`, `"."`, or `"/"` for top-level folders), sorted by largest
    /// absolute recursive storage delta descending, then by path ascending.
    #[must_use]
    pub fn child_folder_storage_stats(
        &self,
        parent_relative_path: &str,
    ) -> Option<Vec<FolderStorageStats>> {
        let parent = self.find_directory(parent_relative_path)?;
        let target_depth = parent.depth().saturating_add(1);
        let mut children: Vec<FolderStorageStats> = parent
            .folder_storage_stats()
            .into_iter()
            .filter(|entry| entry.depth == target_depth)
            .collect();
        children.sort_by(|a, b| {
            b.recursive_storage
                .abs_net_delta_bytes()
                .cmp(&a.recursive_storage.abs_net_delta_bytes())
                .then_with(|| a.relative_path.cmp(&b.relative_path))
        });
        Some(children)
    }

    /// Returns up to `limit` directories with non-zero direct storage delta, ordered by largest
    /// absolute direct byte delta descending, then by relative path ascending.
    #[must_use]
    pub fn top_folder_storage_changes(&self, limit: usize) -> Vec<FolderStorageStats> {
        if limit == 0 {
            return Vec::new();
        }
        let mut changed: Vec<FolderStorageStats> = self
            .folder_storage_stats()
            .into_iter()
            .filter(|entry| entry.direct_storage.net_delta_bytes != 0)
            .collect();
        changed.sort_by(|a, b| {
            b.direct_storage
                .abs_net_delta_bytes()
                .cmp(&a.direct_storage.abs_net_delta_bytes())
                .then_with(|| a.relative_path.cmp(&b.relative_path))
        });
        changed.truncate(limit);
        changed
    }

    /// Finds duplicate files within this diff for the requested [`DiffDuplicateScope`] (`Left`,
    /// `Right`, or `Unified`) using default [`DuplicateOptions`].
    #[must_use]
    pub fn find_duplicates(&self, scope: DiffDuplicateScope) -> DuplicateReport {
        find_duplicates_in_diff(self, scope)
    }

    /// Finds duplicate files within this diff for the requested [`DiffDuplicateScope`] (`Left`,
    /// `Right`, or `Unified`) using custom [`DuplicateOptions`].
    #[must_use]
    pub fn find_duplicates_with_options(
        &self,
        scope: DiffDuplicateScope,
        options: &DuplicateOptions,
    ) -> DuplicateReport {
        find_duplicates_in_diff_with_options(self, scope, options)
    }

    /// Iteratively (stack-safe) recomputes [`DiffFileEntry::status`] across the entire diff tree
    /// using `policy`, re-propagates every directory's [`FolderStatus`] and
    /// [`FolderStatusSummary`] bottom-up, and updates [`ComparisonOptions::status_policy`].
    pub fn reclassify_statuses(&mut self, policy: FileStatusPolicy) {
        self.options.status_policy = policy;
        let compare_metadata = self.options.compare_metadata;
        let mut stack = vec![&mut self.root];
        while let Some(dir) = stack.pop() {
            for entry in dir.files.values_mut() {
                entry.status = classify_pair(
                    entry.left.as_ref(),
                    entry.right.as_ref(),
                    compare_metadata,
                    policy,
                );
            }
            stack.extend(dir.sub_directories.values_mut());
        }
        propagate_folder_statuses(&mut self.root);
    }
}

/// Configurable engine for comparing [`DirectoryNode`] trees and `.hashed` snapshots.
#[derive(Debug, Clone, Default)]
pub struct TreeComparer {
    options: ComparisonOptions,
}

impl TreeComparer {
    /// Creates a [`TreeComparer`] with default [`ComparisonOptions`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: ComparisonOptions::new(),
        }
    }

    /// Creates a [`TreeComparer`] using explicit [`ComparisonOptions`].
    #[must_use]
    pub const fn with_options(options: ComparisonOptions) -> Self {
        Self { options }
    }

    /// Returns the active [`ComparisonOptions`].
    #[must_use]
    pub const fn options(&self) -> &ComparisonOptions {
        &self.options
    }

    /// Runs a fast, $O(1)$ pre-comparison compatibility check on two [`DirectoryNode`] roots
    /// without traversing their subtrees, returning a single consolidated [`PrecheckReport`].
    #[must_use]
    pub fn precheck_trees(left: &DirectoryNode, right: &DirectoryNode) -> PrecheckReport {
        precheck_trees(left, right)
    }

    /// Runs a fast, $O(1)$ pre-comparison compatibility check from optional [`MetaData`] and
    /// optional root directory names, returning a single consolidated [`PrecheckReport`].
    #[must_use]
    pub fn precheck_metadata(
        left_meta: Option<&MetaData>,
        left_root_name: Option<&str>,
        right_meta: Option<&MetaData>,
        right_root_name: Option<&str>,
    ) -> PrecheckReport {
        precheck_metadata(left_meta, left_root_name, right_meta, right_root_name)
    }

    /// Runs a fast, $O(1)$ pre-comparison compatibility check on two [`DirectoryNode`] roots and
    /// their optional [`MetaData`], returning a single consolidated [`PrecheckReport`].
    #[must_use]
    pub fn precheck_trees_with_metadata(
        left_tree: &DirectoryNode,
        left_meta: Option<&MetaData>,
        right_tree: &DirectoryNode,
        right_meta: Option<&MetaData>,
    ) -> PrecheckReport {
        precheck_trees_with_metadata(left_tree, left_meta, right_tree, right_meta)
    }

    /// Runs a fast, $O(1)$ pre-comparison compatibility check on two loaded
    /// [`BulkHashFileStruct`] snapshots without traversing their file trees, returning a single
    /// consolidated [`PrecheckReport`].
    #[must_use]
    pub fn precheck_snapshots(
        left: &BulkHashFileStruct,
        right: &BulkHashFileStruct,
    ) -> PrecheckReport {
        precheck_snapshots(left, right)
    }

    /// Runs a fast, passwordless pre-comparison compatibility check directly on two `.hashed`
    /// archive files by reading only `meta.json` and `hash.sha256` (never decompressing
    /// `tree.json` or decrypting `tree.enc`).
    ///
    /// Returns a single consolidated [`PrecheckReport`] aggregating all detected pre-flight
    /// warnings so the UI can present one confirmation popup before starting a full diff.
    ///
    /// # Errors
    ///
    /// Returns any [`BulkHashError`] encountered while probing either archive's `meta.json` or
    /// `hash.sha256` (such as [`BulkHashError::FileNotFound`], [`BulkHashError::InvalidEnding`],
    /// [`BulkHashError::UnsupportedVersion`], or [`BulkHashError::FileIsCorrupted`]).
    pub fn precheck_archive_files(
        left_path: impl AsRef<Path>,
        right_path: impl AsRef<Path>,
    ) -> Result<PrecheckReport, BulkHashError> {
        precheck_archive_files(left_path, right_path)
    }

    /// Compares two [`DirectoryNode`] trees directly without snapshot metadata.
    #[must_use]
    pub fn compare_trees(&self, left: &DirectoryNode, right: &DirectoryNode) -> TreeDiff {
        self.compare_internal(left, None, None, None, right, None, None, None)
    }

    /// Compares two [`DirectoryNode`] trees alongside optional [`MetaData`] from each side.
    #[must_use]
    pub fn compare_trees_with_metadata(
        &self,
        left_tree: &DirectoryNode,
        left_meta: Option<&MetaData>,
        right_tree: &DirectoryNode,
        right_meta: Option<&MetaData>,
    ) -> TreeDiff {
        self.compare_internal(
            left_tree,
            left_meta,
            None,
            left_meta.and_then(MetaData::get_migrated_from),
            right_tree,
            right_meta,
            None,
            right_meta.and_then(MetaData::get_migrated_from),
        )
    }

    /// Compares two loaded [`BulkHashFileStruct`] snapshots, using both their trees and full
    /// metadata (OS, hash algorithm, filters, timestamps, migration status, archive hashes).
    #[must_use]
    pub fn compare_snapshots(
        &self,
        left: &BulkHashFileStruct,
        right: &BulkHashFileStruct,
    ) -> TreeDiff {
        let left_migrated = left
            .get_meta()
            .get_migrated_from()
            .or_else(|| left.get_migration().map(MigrationReport::original_version));
        let right_migrated = right
            .get_meta()
            .get_migrated_from()
            .or_else(|| right.get_migration().map(MigrationReport::original_version));

        self.compare_internal(
            left.get_tree(),
            Some(left.get_meta()),
            Some(left.get_hash()),
            left_migrated,
            right.get_tree(),
            Some(right.get_meta()),
            Some(right.get_hash()),
            right_migrated,
        )
    }

    /// Loads two unencrypted `.hashed` snapshot archives from disk via [`FileManager::open_file`]
    /// and compares them.
    ///
    /// # Errors
    ///
    /// Returns any [`BulkHashError`] encountered while opening, verifying, or migrating either
    /// `.hashed` archive (including [`BulkHashError::PasswordRequired`] if an archive is
    /// encrypted).
    pub fn compare_archive_files(
        &self,
        left_path: impl AsRef<Path>,
        right_path: impl AsRef<Path>,
    ) -> Result<TreeDiff, BulkHashError> {
        self.compare_archive_files_with_passwords(left_path, None, right_path, None)
    }

    /// Loads two `.hashed` snapshot archives from disk (unlocking encrypted archives when a
    /// password is provided) and compares them.
    ///
    /// # Errors
    ///
    /// Returns any [`BulkHashError`] encountered while opening, decrypting, verifying, or
    /// migrating either `.hashed` archive.
    pub fn compare_archive_files_with_passwords(
        &self,
        left_path: impl AsRef<Path>,
        left_password: Option<&str>,
        right_path: impl AsRef<Path>,
        right_password: Option<&str>,
    ) -> Result<TreeDiff, BulkHashError> {
        let left = match left_password {
            Some(pwd) => FileManager::open_file_with_password(left_path, pwd)?,
            None => FileManager::open_file(left_path)?,
        };
        let right = match right_password {
            Some(pwd) => FileManager::open_file_with_password(right_path, pwd)?,
            None => FileManager::open_file(right_path)?,
        };
        Ok(self.compare_snapshots(&left, &right))
    }

    #[allow(clippy::too_many_arguments)]
    fn compare_internal(
        &self,
        left_tree: &DirectoryNode,
        left_meta: Option<&MetaData>,
        left_snapshot_hash: Option<&str>,
        left_migrated_from: Option<usize>,
        right_tree: &DirectoryNode,
        right_meta: Option<&MetaData>,
        right_snapshot_hash: Option<&str>,
        right_migrated_from: Option<usize>,
    ) -> TreeDiff {
        let mut diag = ComparisonDiagnostics::default();
        let mut truncated = false;

        let root = compare_nodes_iterative(
            left_tree,
            right_tree,
            &self.options,
            &mut diag,
            &mut truncated,
        );

        let left_info = build_side_info(
            &left_tree.name,
            left_meta,
            left_migrated_from,
            diag.left_files,
            diag.left_directories,
            diag.left_errors,
        );
        let right_info = build_side_info(
            &right_tree.name,
            right_meta,
            right_migrated_from,
            diag.right_files,
            diag.right_directories,
            diag.right_errors,
        );

        let warnings = if self.options.collect_warnings {
            let ctx = WarningContext {
                left_root_name: &left_tree.name,
                right_root_name: &right_tree.name,
                left_meta,
                right_meta,
                left_snapshot_hash,
                right_snapshot_hash,
                left_migrated_from,
                right_migrated_from,
                truncated,
            };
            collect_warnings(&ctx, &diag)
        } else {
            Vec::new()
        };

        TreeDiff {
            root,
            options: self.options.clone(),
            left_info,
            right_info,
            warnings,
            truncated,
        }
    }
}

/// Convenience function comparing two [`DirectoryNode`] trees with default [`ComparisonOptions`].
#[must_use]
pub fn compare_trees(left: &DirectoryNode, right: &DirectoryNode) -> TreeDiff {
    TreeComparer::new().compare_trees(left, right)
}

/// Fast, $O(1)$ pre-comparison compatibility check on two [`DirectoryNode`] roots without
/// traversing their subtrees.
///
/// Aggregates all detected pre-flight warnings (e.g. inferred Windows vs. Linux OS mismatch,
/// differing root directory names, empty trees) into one consolidated [`PrecheckReport`].
#[must_use]
pub fn precheck_trees(left: &DirectoryNode, right: &DirectoryNode) -> PrecheckReport {
    precheck_trees_with_metadata(left, None, right, None)
}

/// Fast, $O(1)$ pre-comparison compatibility check from optional [`MetaData`] and optional root
/// directory names.
///
/// Aggregates all detected pre-flight warnings into one consolidated [`PrecheckReport`] so the UI
/// can display a single confirmation dialog before starting the comparison.
#[must_use]
pub fn precheck_metadata(
    left_meta: Option<&MetaData>,
    left_root_name: Option<&str>,
    right_meta: Option<&MetaData>,
    right_root_name: Option<&str>,
) -> PrecheckReport {
    let ctx = PrecheckContext {
        left_root_name,
        right_root_name,
        left_meta,
        right_meta,
        left_snapshot_hash: None,
        right_snapshot_hash: None,
        left_migrated_from: left_meta.and_then(MetaData::get_migrated_from),
        right_migrated_from: right_meta.and_then(MetaData::get_migrated_from),
        left_is_empty: left_meta.map(|m| m.get_files_hashed() == 0),
        right_is_empty: right_meta.map(|m| m.get_files_hashed() == 0),
        left_encrypted: left_meta.is_some_and(MetaData::is_encrypted),
        right_encrypted: right_meta.is_some_and(MetaData::is_encrypted),
    };
    evaluate_precheck(&ctx)
}

/// Fast, $O(1)$ pre-comparison compatibility check on two [`DirectoryNode`] roots alongside
/// optional [`MetaData`], returning one consolidated [`PrecheckReport`].
#[must_use]
pub fn precheck_trees_with_metadata(
    left_tree: &DirectoryNode,
    left_meta: Option<&MetaData>,
    right_tree: &DirectoryNode,
    right_meta: Option<&MetaData>,
) -> PrecheckReport {
    let ctx = PrecheckContext {
        left_root_name: Some(left_tree.name.as_str()),
        right_root_name: Some(right_tree.name.as_str()),
        left_meta,
        right_meta,
        left_snapshot_hash: None,
        right_snapshot_hash: None,
        left_migrated_from: left_meta.and_then(MetaData::get_migrated_from),
        right_migrated_from: right_meta.and_then(MetaData::get_migrated_from),
        left_is_empty: Some(left_tree.files.is_empty() && left_tree.sub_directories.is_empty()),
        right_is_empty: Some(right_tree.files.is_empty() && right_tree.sub_directories.is_empty()),
        left_encrypted: left_meta.is_some_and(MetaData::is_encrypted),
        right_encrypted: right_meta.is_some_and(MetaData::is_encrypted),
    };
    evaluate_precheck(&ctx)
}

/// Fast, $O(1)$ pre-comparison compatibility check on two loaded [`BulkHashFileStruct`] snapshots
/// without traversing their file trees, returning one consolidated [`PrecheckReport`].
#[must_use]
pub fn precheck_snapshots(left: &BulkHashFileStruct, right: &BulkHashFileStruct) -> PrecheckReport {
    let left_migrated = left
        .get_meta()
        .get_migrated_from()
        .or_else(|| left.get_migration().map(MigrationReport::original_version));
    let right_migrated = right
        .get_meta()
        .get_migrated_from()
        .or_else(|| right.get_migration().map(MigrationReport::original_version));

    let ctx = PrecheckContext {
        left_root_name: Some(left.get_tree().name.as_str()),
        right_root_name: Some(right.get_tree().name.as_str()),
        left_meta: Some(left.get_meta()),
        right_meta: Some(right.get_meta()),
        left_snapshot_hash: Some(left.get_hash()),
        right_snapshot_hash: Some(right.get_hash()),
        left_migrated_from: left_migrated,
        right_migrated_from: right_migrated,
        left_is_empty: Some(
            left.get_tree().files.is_empty() && left.get_tree().sub_directories.is_empty(),
        ),
        right_is_empty: Some(
            right.get_tree().files.is_empty() && right.get_tree().sub_directories.is_empty(),
        ),
        left_encrypted: left.is_encrypted(),
        right_encrypted: right.is_encrypted(),
    };
    evaluate_precheck(&ctx)
}

/// Fast, passwordless pre-comparison compatibility check directly on two `.hashed` archive files.
///
/// Inspects only `meta.json` and `hash.sha256` via [`FileManager::inspect_metadata`] without
/// decompressing `tree.json` or decrypting `tree.enc`, so even large or password-protected
/// snapshots can be pre-checked instantaneously before prompting for passwords or running the diff.
///
/// Note: Because `tree.json`/`tree.enc` is not opened, root directory names (`DifferentRootName`)
/// are not inspected here; use [`precheck_snapshots`] once snapshots are loaded if you also want
/// root-name comparison before diffing.
///
/// # Errors
///
/// Returns any [`BulkHashError`] encountered while probing either `.hashed` archive's metadata.
pub fn precheck_archive_files(
    left_path: impl AsRef<Path>,
    right_path: impl AsRef<Path>,
) -> Result<PrecheckReport, BulkHashError> {
    let left_probe = FileManager::inspect_metadata(left_path)?;
    let right_probe = FileManager::inspect_metadata(right_path)?;

    let left_migrated = left_probe
        .needs_migration
        .then_some(left_probe.version)
        .or_else(|| left_probe.meta.get_migrated_from());
    let right_migrated = right_probe
        .needs_migration
        .then_some(right_probe.version)
        .or_else(|| right_probe.meta.get_migrated_from());

    let ctx = PrecheckContext {
        left_root_name: None,
        right_root_name: None,
        left_meta: Some(&left_probe.meta),
        right_meta: Some(&right_probe.meta),
        left_snapshot_hash: Some(&left_probe.archive_hash),
        right_snapshot_hash: Some(&right_probe.archive_hash),
        left_migrated_from: left_migrated,
        right_migrated_from: right_migrated,
        left_is_empty: Some(left_probe.meta.get_files_hashed() == 0),
        right_is_empty: Some(right_probe.meta.get_files_hashed() == 0),
        left_encrypted: left_probe.encrypted,
        right_encrypted: right_probe.encrypted,
    };
    Ok(evaluate_precheck(&ctx))
}

/// Convenience function comparing two [`DirectoryNode`] trees with custom [`ComparisonOptions`].
#[must_use]
pub fn compare_trees_with_options(
    left: &DirectoryNode,
    right: &DirectoryNode,
    options: &ComparisonOptions,
) -> TreeDiff {
    TreeComparer::with_options(options.clone()).compare_trees(left, right)
}

/// Convenience function comparing two [`BulkHashFileStruct`] snapshots with default
/// [`ComparisonOptions`].
#[must_use]
pub fn compare_snapshots(left: &BulkHashFileStruct, right: &BulkHashFileStruct) -> TreeDiff {
    TreeComparer::new().compare_snapshots(left, right)
}

/// Convenience function comparing two [`BulkHashFileStruct`] snapshots with custom
/// [`ComparisonOptions`].
#[must_use]
pub fn compare_snapshots_with_options(
    left: &BulkHashFileStruct,
    right: &BulkHashFileStruct,
    options: &ComparisonOptions,
) -> TreeDiff {
    TreeComparer::with_options(options.clone()).compare_snapshots(left, right)
}

fn build_side_info(
    root_name: &str,
    meta: Option<&MetaData>,
    migrated_from: Option<usize>,
    total_files: usize,
    total_directories: usize,
    error_files: usize,
) -> TreeSideInfo {
    TreeSideInfo {
        root_name: root_name.to_string(),
        os: meta.map(|m| m.get_current_os().to_string()),
        algorithm: meta.and_then(MetaData::get_algorithm),
        date_utc: meta.map(MetaData::get_date_utc),
        format_version: meta.map(MetaData::get_version),
        migrated_from,
        total_files,
        total_directories,
        error_files,
    }
}

// ---------------------------------------------------------------------------
// Iterative stack-safe tree comparison engine
// ---------------------------------------------------------------------------

struct PendingSubdir<'a> {
    name: String,
    left_name: Option<String>,
    relative_path: String,
    left_relative_path: String,
    depth: usize,
    presence: EntryPresence,
    name_case_differs: bool,
    type_conflict: bool,
    left: Option<&'a DirectoryNode>,
    right: Option<&'a DirectoryNode>,
}

struct DirBuildFrame<'a> {
    name: String,
    left_name: Option<String>,
    relative_path: String,
    depth: usize,
    presence: EntryPresence,
    status_summary: FolderStatusSummary,
    name_case_differs: bool,
    type_conflict: bool,
    files: BTreeMap<String, DiffFileEntry>,
    sub_directories: BTreeMap<String, DiffDirectoryNode>,
    pending_children: Vec<PendingSubdir<'a>>,
}

impl DirBuildFrame<'_> {
    fn into_node(self) -> DiffDirectoryNode {
        let status = derive_folder_status(self.presence, &self.status_summary);
        DiffDirectoryNode {
            name: self.name,
            left_name: self.left_name,
            relative_path: self.relative_path,
            depth: self.depth,
            presence: self.presence,
            status,
            status_summary: self.status_summary,
            name_case_differs: self.name_case_differs,
            type_conflict: self.type_conflict,
            files: self.files,
            sub_directories: self.sub_directories,
        }
    }
}

struct MatchedPair<'a, V> {
    name: String,
    left_name: Option<String>,
    presence: EntryPresence,
    name_case_differs: bool,
    left: Option<&'a V>,
    right: Option<&'a V>,
}

fn compare_nodes_iterative(
    left_root: &DirectoryNode,
    right_root: &DirectoryNode,
    options: &ComparisonOptions,
    diag: &mut ComparisonDiagnostics,
    truncated: &mut bool,
) -> DiffDirectoryNode {
    let root_left_name = (left_root.name != right_root.name).then(|| left_root.name.clone());
    let root_pending = PendingSubdir {
        name: right_root.name.clone(),
        left_name: root_left_name,
        relative_path: String::new(),
        left_relative_path: String::new(),
        depth: 0,
        presence: EntryPresence::Both,
        name_case_differs: false,
        type_conflict: false,
        left: Some(left_root),
        right: Some(right_root),
    };

    let mut stack: Vec<DirBuildFrame<'_>> =
        vec![build_frame(root_pending, options, diag, truncated)];

    loop {
        let next_child = stack
            .last_mut()
            .and_then(|frame| frame.pending_children.pop());

        if let Some(child) = next_child {
            let child_frame = build_frame(child, options, diag, truncated);
            stack.push(child_frame);
            continue;
        }

        let Some(completed) = stack.pop() else {
            unreachable!("comparison stack cannot become empty before returning root");
        };
        let node = completed.into_node();

        if let Some(parent) = stack.last_mut() {
            parent
                .status_summary
                .merge_child_directory(node.status, &node.status_summary);
            parent.sub_directories.insert(node.name.clone(), node);
        } else {
            return node;
        }
    }
}

fn build_frame<'a>(
    spec: PendingSubdir<'a>,
    options: &ComparisonOptions,
    diag: &mut ComparisonDiagnostics,
    truncated: &mut bool,
) -> DirBuildFrame<'a> {
    static EMPTY_FILES: BTreeMap<String, FileEntry> = BTreeMap::new();
    static EMPTY_DIRS: BTreeMap<String, DirectoryNode> = BTreeMap::new();

    let left_files = spec.left.map_or(&EMPTY_FILES, |node| &node.files);
    let right_files = spec.right.map_or(&EMPTY_FILES, |node| &node.files);
    let left_dirs = spec.left.map_or(&EMPTY_DIRS, |node| &node.sub_directories);
    let right_dirs = spec.right.map_or(&EMPTY_DIRS, |node| &node.sub_directories);

    let conflict_ctx = TypeConflictLookup::new(
        options.name_matching,
        left_files,
        right_files,
        left_dirs,
        right_dirs,
    );
    let mut recorded_conflicts: HashSet<String> = HashSet::new();

    let files = compare_files_in_dir(
        left_files,
        right_files,
        &spec.relative_path,
        &spec.left_relative_path,
        options,
        &conflict_ctx,
        &mut recorded_conflicts,
        diag,
    );

    let depth_limit_reached = options
        .max_depth
        .is_some_and(|max_depth| spec.depth >= max_depth);

    let pending_children = if depth_limit_reached {
        if !left_dirs.is_empty() || !right_dirs.is_empty() {
            *truncated = true;
            for child in left_dirs.values() {
                accumulate_unvisited_subtree(child, Side::Left, diag);
            }
            for child in right_dirs.values() {
                accumulate_unvisited_subtree(child, Side::Right, diag);
            }
        }
        Vec::new()
    } else {
        let mut children = compare_subdirs_in_dir(
            left_dirs,
            right_dirs,
            &spec.relative_path,
            &spec.left_relative_path,
            spec.depth.saturating_add(1),
            options,
            &conflict_ctx,
            &mut recorded_conflicts,
            diag,
        );
        // Reverse so `Vec::pop()` processes children in ascending deterministic order.
        children.reverse();
        children
    };

    let status_summary = FolderStatusSummary::from_files(files.values());

    DirBuildFrame {
        name: spec.name,
        left_name: spec.left_name,
        relative_path: spec.relative_path,
        depth: spec.depth,
        presence: spec.presence,
        status_summary,
        name_case_differs: spec.name_case_differs,
        type_conflict: spec.type_conflict,
        files,
        sub_directories: BTreeMap::new(),
        pending_children,
    }
}

#[derive(Clone, Copy)]
enum Side {
    Left,
    Right,
}

fn accumulate_unvisited_subtree(
    root: &DirectoryNode,
    side: Side,
    diag: &mut ComparisonDiagnostics,
) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        match side {
            Side::Left => diag.left_directories = diag.left_directories.saturating_add(1),
            Side::Right => diag.right_directories = diag.right_directories.saturating_add(1),
        }
        for entry in node.files.values() {
            record_file_diagnostics(entry, side, diag);
        }
        stack.extend(node.sub_directories.values());
    }
}

fn record_file_diagnostics(entry: &FileEntry, side: Side, diag: &mut ComparisonDiagnostics) {
    match side {
        Side::Left => {
            diag.left_files = diag.left_files.saturating_add(1);
            match entry.hash() {
                Some(hash) => {
                    diag.left_hashed_files = diag.left_hashed_files.saturating_add(1);
                    diag.left_hash_lengths.insert(hash.len());
                    if entry.size.is_none() {
                        diag.left_missing_size = diag.left_missing_size.saturating_add(1);
                    }
                    if entry.modified_utc.is_none() {
                        diag.left_missing_modified = diag.left_missing_modified.saturating_add(1);
                    }
                }
                None => {
                    diag.left_errors = diag.left_errors.saturating_add(1);
                }
            }
        }
        Side::Right => {
            diag.right_files = diag.right_files.saturating_add(1);
            match entry.hash() {
                Some(hash) => {
                    diag.right_hashed_files = diag.right_hashed_files.saturating_add(1);
                    diag.right_hash_lengths.insert(hash.len());
                    if entry.size.is_none() {
                        diag.right_missing_size = diag.right_missing_size.saturating_add(1);
                    }
                    if entry.modified_utc.is_none() {
                        diag.right_missing_modified = diag.right_missing_modified.saturating_add(1);
                    }
                }
                None => {
                    diag.right_errors = diag.right_errors.saturating_add(1);
                }
            }
        }
    }
}

struct TypeConflictLookup<'a> {
    mode: NameMatchingMode,
    left_files_exact: &'a BTreeMap<String, FileEntry>,
    right_files_exact: &'a BTreeMap<String, FileEntry>,
    left_dirs_exact: &'a BTreeMap<String, DirectoryNode>,
    right_dirs_exact: &'a BTreeMap<String, DirectoryNode>,
    left_files_folded: HashSet<String>,
    right_files_folded: HashSet<String>,
    left_dirs_folded: HashSet<String>,
    right_dirs_folded: HashSet<String>,
}

impl<'a> TypeConflictLookup<'a> {
    fn new(
        mode: NameMatchingMode,
        left_files: &'a BTreeMap<String, FileEntry>,
        right_files: &'a BTreeMap<String, FileEntry>,
        left_dirs: &'a BTreeMap<String, DirectoryNode>,
        right_dirs: &'a BTreeMap<String, DirectoryNode>,
    ) -> Self {
        let (left_files_folded, right_files_folded, left_dirs_folded, right_dirs_folded) =
            if matches!(mode, NameMatchingMode::CaseInsensitive) {
                (
                    left_files.keys().map(|k| k.to_lowercase()).collect(),
                    right_files.keys().map(|k| k.to_lowercase()).collect(),
                    left_dirs.keys().map(|k| k.to_lowercase()).collect(),
                    right_dirs.keys().map(|k| k.to_lowercase()).collect(),
                )
            } else {
                (
                    HashSet::new(),
                    HashSet::new(),
                    HashSet::new(),
                    HashSet::new(),
                )
            };

        Self {
            mode,
            left_files_exact: left_files,
            right_files_exact: right_files,
            left_dirs_exact: left_dirs,
            right_dirs_exact: right_dirs,
            left_files_folded,
            right_files_folded,
            left_dirs_folded,
            right_dirs_folded,
        }
    }

    fn file_conflicts_with_opposite_dir(&self, presence: EntryPresence, name: &str) -> bool {
        match (self.mode, presence) {
            (NameMatchingMode::Exact, EntryPresence::OnlyLeft) => {
                self.right_dirs_exact.contains_key(name)
            }
            (NameMatchingMode::Exact, EntryPresence::OnlyRight) => {
                self.left_dirs_exact.contains_key(name)
            }
            (NameMatchingMode::CaseInsensitive, EntryPresence::OnlyLeft) => {
                self.right_dirs_folded.contains(&name.to_lowercase())
            }
            (NameMatchingMode::CaseInsensitive, EntryPresence::OnlyRight) => {
                self.left_dirs_folded.contains(&name.to_lowercase())
            }
            (_, EntryPresence::Both) => false,
        }
    }

    fn dir_conflicts_with_opposite_file(&self, presence: EntryPresence, name: &str) -> bool {
        match (self.mode, presence) {
            (NameMatchingMode::Exact, EntryPresence::OnlyLeft) => {
                self.right_files_exact.contains_key(name)
            }
            (NameMatchingMode::Exact, EntryPresence::OnlyRight) => {
                self.left_files_exact.contains_key(name)
            }
            (NameMatchingMode::CaseInsensitive, EntryPresence::OnlyLeft) => {
                self.right_files_folded.contains(&name.to_lowercase())
            }
            (NameMatchingMode::CaseInsensitive, EntryPresence::OnlyRight) => {
                self.left_files_folded.contains(&name.to_lowercase())
            }
            (_, EntryPresence::Both) => false,
        }
    }

    fn conflict_key(&self, name: &str) -> String {
        match self.mode {
            NameMatchingMode::Exact => name.to_string(),
            NameMatchingMode::CaseInsensitive => name.to_lowercase(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_files_in_dir(
    left_files: &BTreeMap<String, FileEntry>,
    right_files: &BTreeMap<String, FileEntry>,
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    options: &ComparisonOptions,
    conflict_ctx: &TypeConflictLookup<'_>,
    recorded_conflicts: &mut HashSet<String>,
    diag: &mut ComparisonDiagnostics,
) -> BTreeMap<String, DiffFileEntry> {
    let pairs = match_entries(
        left_files,
        right_files,
        dir_rel_path,
        left_dir_rel_path,
        options.name_matching,
        options.collect_warnings,
        diag,
    );

    let mut result = BTreeMap::new();
    for pair in pairs {
        if let Some(left_entry) = pair.left {
            record_file_diagnostics(left_entry, Side::Left, diag);
        }
        if let Some(right_entry) = pair.right {
            record_file_diagnostics(right_entry, Side::Right, diag);
        }
        if pair.presence.is_both() {
            diag.common_files = diag.common_files.saturating_add(1);
        }

        let relative_path = join_rel_path(dir_rel_path, &pair.name);

        if options.collect_warnings
            && !pair.presence.is_both()
            && is_known_system_name(OsStr::new(&pair.name))
        {
            diag.record_os_metadata_diff(relative_path.clone());
        }

        let type_conflict =
            conflict_ctx.file_conflicts_with_opposite_dir(pair.presence, &pair.name);
        if type_conflict
            && options.collect_warnings
            && recorded_conflicts.insert(conflict_ctx.conflict_key(&pair.name))
        {
            diag.record_type_conflict(relative_path.clone());
        }

        let outcome = evaluate_file_outcome(pair.left, pair.right, options.compare_metadata);
        let status = classify_pair(
            pair.left,
            pair.right,
            options.compare_metadata,
            options.status_policy,
        );
        let key = pair.name.clone();
        result.insert(
            key,
            DiffFileEntry {
                name: pair.name,
                left_name: pair.left_name,
                relative_path,
                presence: pair.presence,
                outcome,
                status,
                left: pair.left.cloned(),
                right: pair.right.cloned(),
                name_case_differs: pair.name_case_differs,
                type_conflict,
            },
        );
    }

    result
}

#[allow(clippy::too_many_arguments)]
fn compare_subdirs_in_dir<'a>(
    left_dirs: &'a BTreeMap<String, DirectoryNode>,
    right_dirs: &'a BTreeMap<String, DirectoryNode>,
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    child_depth: usize,
    options: &ComparisonOptions,
    conflict_ctx: &TypeConflictLookup<'_>,
    recorded_conflicts: &mut HashSet<String>,
    diag: &mut ComparisonDiagnostics,
) -> Vec<PendingSubdir<'a>> {
    let pairs = match_entries(
        left_dirs,
        right_dirs,
        dir_rel_path,
        left_dir_rel_path,
        options.name_matching,
        options.collect_warnings,
        diag,
    );

    let mut children = Vec::with_capacity(pairs.len());
    for pair in pairs {
        if pair.left.is_some() {
            diag.left_directories = diag.left_directories.saturating_add(1);
        }
        if pair.right.is_some() {
            diag.right_directories = diag.right_directories.saturating_add(1);
        }
        if pair.presence.is_both() {
            diag.common_directories = diag.common_directories.saturating_add(1);
        }

        let relative_path = join_rel_path(dir_rel_path, &pair.name);
        let left_seg = pair.left_name.as_deref().unwrap_or(&pair.name);
        let left_relative_path = join_rel_path(left_dir_rel_path, left_seg);

        if options.collect_warnings
            && !pair.presence.is_both()
            && is_known_system_name(OsStr::new(&pair.name))
        {
            diag.record_os_metadata_diff(relative_path.clone());
        }

        let type_conflict =
            conflict_ctx.dir_conflicts_with_opposite_file(pair.presence, &pair.name);
        if type_conflict
            && options.collect_warnings
            && recorded_conflicts.insert(conflict_ctx.conflict_key(&pair.name))
        {
            diag.record_type_conflict(relative_path.clone());
        }

        children.push(PendingSubdir {
            name: pair.name,
            left_name: pair.left_name,
            relative_path,
            left_relative_path,
            depth: child_depth,
            presence: pair.presence,
            name_case_differs: pair.name_case_differs,
            type_conflict,
            left: pair.left,
            right: pair.right,
        });
    }

    children
}

fn evaluate_file_outcome(
    left: Option<&FileEntry>,
    right: Option<&FileEntry>,
    compare_metadata: bool,
) -> FileComparisonOutcome {
    match (left, right) {
        (Some(_), None) => FileComparisonOutcome::OnlyLeft,
        (None, Some(_)) => FileComparisonOutcome::OnlyRight,
        (Some(l), Some(r)) => match (l.hash(), r.hash()) {
            (Some(lh), Some(rh)) => {
                if !lh.eq_ignore_ascii_case(rh) {
                    return FileComparisonOutcome::ContentChanged;
                }
                if compare_metadata && file_metadata_differs(l, r) {
                    FileComparisonOutcome::MetadataChanged
                } else {
                    FileComparisonOutcome::Identical
                }
            }
            _ => FileComparisonOutcome::Error,
        },
        (None, None) => unreachable!("matched entry must exist on at least one side"),
    }
}

fn file_metadata_differs(left: &FileEntry, right: &FileEntry) -> bool {
    let size_differs = matches!((left.size, right.size), (Some(ls), Some(rs)) if ls != rs);
    let modified_differs =
        matches!((left.modified_utc, right.modified_utc), (Some(lm), Some(rm)) if lm != rm);
    size_differs || modified_differs
}

fn match_entries<'a, V>(
    left_map: &'a BTreeMap<String, V>,
    right_map: &'a BTreeMap<String, V>,
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    mode: NameMatchingMode,
    collect_warnings: bool,
    diag: &mut ComparisonDiagnostics,
) -> Vec<MatchedPair<'a, V>> {
    match mode {
        NameMatchingMode::Exact => match_entries_exact(
            left_map,
            right_map,
            dir_rel_path,
            left_dir_rel_path,
            collect_warnings,
            diag,
        ),
        NameMatchingMode::CaseInsensitive => match_entries_case_insensitive(
            left_map,
            right_map,
            dir_rel_path,
            left_dir_rel_path,
            collect_warnings,
            diag,
        ),
    }
}

fn match_entries_exact<'a, V>(
    left_map: &'a BTreeMap<String, V>,
    right_map: &'a BTreeMap<String, V>,
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    collect_warnings: bool,
    diag: &mut ComparisonDiagnostics,
) -> Vec<MatchedPair<'a, V>> {
    let mut pairs = Vec::with_capacity(left_map.len().max(right_map.len()));
    let mut only_left_names: Vec<&str> = Vec::new();
    let mut only_right_names: Vec<&str> = Vec::new();

    let mut left_iter = left_map.iter().peekable();
    let mut right_iter = right_map.iter().peekable();

    loop {
        match (left_iter.peek(), right_iter.peek()) {
            (Some(&(lk, lv)), Some(&(rk, rv))) => match lk.cmp(rk) {
                Ordering::Less => {
                    if collect_warnings {
                        only_left_names.push(lk.as_str());
                    }
                    pairs.push(MatchedPair {
                        name: lk.clone(),
                        left_name: None,
                        presence: EntryPresence::OnlyLeft,
                        name_case_differs: false,
                        left: Some(lv),
                        right: None,
                    });
                    let _ = left_iter.next();
                }
                Ordering::Greater => {
                    if collect_warnings {
                        only_right_names.push(rk.as_str());
                    }
                    pairs.push(MatchedPair {
                        name: rk.clone(),
                        left_name: None,
                        presence: EntryPresence::OnlyRight,
                        name_case_differs: false,
                        left: None,
                        right: Some(rv),
                    });
                    let _ = right_iter.next();
                }
                Ordering::Equal => {
                    pairs.push(MatchedPair {
                        name: rk.clone(),
                        left_name: None,
                        presence: EntryPresence::Both,
                        name_case_differs: false,
                        left: Some(lv),
                        right: Some(rv),
                    });
                    let _ = left_iter.next();
                    let _ = right_iter.next();
                }
            },
            (Some(&(lk, lv)), None) => {
                if collect_warnings {
                    only_left_names.push(lk.as_str());
                }
                pairs.push(MatchedPair {
                    name: lk.clone(),
                    left_name: None,
                    presence: EntryPresence::OnlyLeft,
                    name_case_differs: false,
                    left: Some(lv),
                    right: None,
                });
                let _ = left_iter.next();
            }
            (None, Some(&(rk, rv))) => {
                if collect_warnings {
                    only_right_names.push(rk.as_str());
                }
                pairs.push(MatchedPair {
                    name: rk.clone(),
                    left_name: None,
                    presence: EntryPresence::OnlyRight,
                    name_case_differs: false,
                    left: None,
                    right: Some(rv),
                });
                let _ = right_iter.next();
            }
            (None, None) => break,
        }
    }

    if collect_warnings && !only_left_names.is_empty() && !only_right_names.is_empty() {
        record_case_only_differences(
            &only_left_names,
            &only_right_names,
            left_dir_rel_path,
            dir_rel_path,
            diag,
        );
    }

    pairs
}

fn record_case_only_differences(
    only_left_names: &[&str],
    only_right_names: &[&str],
    left_dir_rel_path: &str,
    dir_rel_path: &str,
    diag: &mut ComparisonDiagnostics,
) {
    let mut left_folded: HashMap<String, Vec<&str>> = HashMap::with_capacity(only_left_names.len());
    for &lname in only_left_names {
        left_folded
            .entry(lname.to_lowercase())
            .or_default()
            .push(lname);
    }

    for &rname in only_right_names {
        if let Some(matches) = left_folded.get(&rname.to_lowercase()) {
            for &lname in matches {
                diag.record_case_only_diff(
                    join_rel_path(left_dir_rel_path, lname),
                    join_rel_path(dir_rel_path, rname),
                );
            }
        }
    }
}

fn match_entries_case_insensitive<'a, V>(
    left_map: &'a BTreeMap<String, V>,
    right_map: &'a BTreeMap<String, V>,
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    collect_warnings: bool,
    diag: &mut ComparisonDiagnostics,
) -> Vec<MatchedPair<'a, V>> {
    let mut left_groups: BTreeMap<String, Vec<(&'a str, &'a V)>> = BTreeMap::new();
    for (k, v) in left_map {
        left_groups
            .entry(k.to_lowercase())
            .or_default()
            .push((k.as_str(), v));
    }

    let mut right_groups: BTreeMap<String, Vec<(&'a str, &'a V)>> = BTreeMap::new();
    for (k, v) in right_map {
        right_groups
            .entry(k.to_lowercase())
            .or_default()
            .push((k.as_str(), v));
    }

    let mut pairs = Vec::with_capacity(left_map.len().max(right_map.len()));
    let mut left_iter = left_groups.iter().peekable();
    let mut right_iter = right_groups.iter().peekable();

    loop {
        match (left_iter.peek(), right_iter.peek()) {
            (Some(&(lf, lg)), Some(&(rf, rg))) => match lf.cmp(rf) {
                Ordering::Less => {
                    emit_single_side_group(
                        lg,
                        Side::Left,
                        left_dir_rel_path,
                        collect_warnings,
                        diag,
                        &mut pairs,
                    );
                    let _ = left_iter.next();
                }
                Ordering::Greater => {
                    emit_single_side_group(
                        rg,
                        Side::Right,
                        dir_rel_path,
                        collect_warnings,
                        diag,
                        &mut pairs,
                    );
                    let _ = right_iter.next();
                }
                Ordering::Equal => {
                    pair_folded_groups(
                        lg,
                        rg,
                        dir_rel_path,
                        left_dir_rel_path,
                        collect_warnings,
                        diag,
                        &mut pairs,
                    );
                    let _ = left_iter.next();
                    let _ = right_iter.next();
                }
            },
            (Some(&(_, lg)), None) => {
                emit_single_side_group(
                    lg,
                    Side::Left,
                    left_dir_rel_path,
                    collect_warnings,
                    diag,
                    &mut pairs,
                );
                let _ = left_iter.next();
            }
            (None, Some(&(_, rg))) => {
                emit_single_side_group(
                    rg,
                    Side::Right,
                    dir_rel_path,
                    collect_warnings,
                    diag,
                    &mut pairs,
                );
                let _ = right_iter.next();
            }
            (None, None) => break,
        }
    }

    pairs.sort_by(|a, b| a.name.cmp(&b.name));
    pairs
}

fn emit_single_side_group<'a, V>(
    group: &[(&'a str, &'a V)],
    side: Side,
    dir_rel_path: &str,
    collect_warnings: bool,
    diag: &mut ComparisonDiagnostics,
    out: &mut Vec<MatchedPair<'a, V>>,
) {
    if collect_warnings && group.len() > 1 {
        let collision_desc = format_collision_sample(dir_rel_path, group);
        diag.record_case_collision(collision_desc);
    }

    for &(name, val) in group {
        match side {
            Side::Left => out.push(MatchedPair {
                name: name.to_string(),
                left_name: None,
                presence: EntryPresence::OnlyLeft,
                name_case_differs: false,
                left: Some(val),
                right: None,
            }),
            Side::Right => out.push(MatchedPair {
                name: name.to_string(),
                left_name: None,
                presence: EntryPresence::OnlyRight,
                name_case_differs: false,
                left: None,
                right: Some(val),
            }),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn pair_folded_groups<'a, V>(
    left_group: &[(&'a str, &'a V)],
    right_group: &[(&'a str, &'a V)],
    dir_rel_path: &str,
    left_dir_rel_path: &str,
    collect_warnings: bool,
    diag: &mut ComparisonDiagnostics,
    out: &mut Vec<MatchedPair<'a, V>>,
) {
    if collect_warnings {
        if left_group.len() > 1 {
            diag.record_case_collision(format_collision_sample(left_dir_rel_path, left_group));
        }
        if right_group.len() > 1 {
            diag.record_case_collision(format_collision_sample(dir_rel_path, right_group));
        }
    }

    let mut left_used = vec![false; left_group.len()];
    let mut right_used = vec![false; right_group.len()];

    // Pass 1: pair exact-case matches first so they are never shadowed by case-folded entries.
    for (li, &(lk, lv)) in left_group.iter().enumerate() {
        for (ri, &(rk, rv)) in right_group.iter().enumerate() {
            if !right_used[ri] && lk == rk {
                left_used[li] = true;
                right_used[ri] = true;
                out.push(MatchedPair {
                    name: rk.to_string(),
                    left_name: None,
                    presence: EntryPresence::Both,
                    name_case_differs: false,
                    left: Some(lv),
                    right: Some(rv),
                });
                break;
            }
        }
    }

    // Pass 2: deterministically pair remaining unmatched entries across differing letter case.
    let mut rem_left = left_group
        .iter()
        .enumerate()
        .filter(|&(idx, _)| !left_used[idx])
        .map(|(_, &item)| item);
    let mut rem_right = right_group
        .iter()
        .enumerate()
        .filter(|&(idx, _)| !right_used[idx])
        .map(|(_, &item)| item);

    loop {
        match (rem_left.next(), rem_right.next()) {
            (Some((lk, lv)), Some((rk, rv))) => {
                if collect_warnings {
                    diag.record_case_only_matched(
                        join_rel_path(left_dir_rel_path, lk),
                        join_rel_path(dir_rel_path, rk),
                    );
                }
                out.push(MatchedPair {
                    name: rk.to_string(),
                    left_name: Some(lk.to_string()),
                    presence: EntryPresence::Both,
                    name_case_differs: true,
                    left: Some(lv),
                    right: Some(rv),
                });
            }
            (Some((lk, lv)), None) => {
                out.push(MatchedPair {
                    name: lk.to_string(),
                    left_name: None,
                    presence: EntryPresence::OnlyLeft,
                    name_case_differs: false,
                    left: Some(lv),
                    right: None,
                });
            }
            (None, Some((rk, rv))) => {
                out.push(MatchedPair {
                    name: rk.to_string(),
                    left_name: None,
                    presence: EntryPresence::OnlyRight,
                    name_case_differs: false,
                    left: None,
                    right: Some(rv),
                });
            }
            (None, None) => break,
        }
    }
}

fn format_collision_sample<V>(dir_rel_path: &str, group: &[(&str, &V)]) -> String {
    let names: Vec<&str> = group.iter().map(|&(name, _)| name).collect();
    let joined = names.join(", ");
    if dir_rel_path.is_empty() {
        format!("{{{joined}}}")
    } else {
        format!("{dir_rel_path}/{{{joined}}}")
    }
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

fn split_relative_path(path: &str) -> impl Iterator<Item = &str> {
    path.split(['/', '\\'])
        .filter(|segment| !segment.is_empty() && *segment != ".")
}
