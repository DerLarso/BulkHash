use crate::core::diff::file_status::{FileStatus, FileStatusCounts};
use crate::core::diff::tree_diff::{DiffDirectoryNode, DiffFileEntry, EntryPresence};
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::collections::BTreeMap;
use std::fmt;
use std::mem;
use std::str::FromStr;

/// Error returned when parsing a [`FolderStatus`] from a string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFolderStatusError {
    input: String,
}

impl ParseFolderStatusError {
    /// Returns the unrecognized input string.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for ParseFolderStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown folder status '{}' (expected: unchanged, modified, added, removed, error)",
            self.input
        )
    }
}

impl std::error::Error for ParseFolderStatusError {}

/// High-level semantic status of a directory node in a [`crate::core::diff::TreeDiff`],
/// combining the directory's own [`EntryPresence`] with bottom-up propagation from all
/// descendant files and subdirectories.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FolderStatus {
    /// Directory exists on both sides and every descendant file and subdirectory is unchanged.
    Unchanged,
    /// Directory exists on both sides and contains at least one modified, added, or removed
    /// descendant file or subdirectory (with no descendant errors).
    Modified,
    /// Directory exists only in the target (right / "after") tree and contains no errors.
    Added,
    /// Directory exists only in the baseline (left / "before") tree and contains no errors.
    Removed,
    /// Directory contains at least one descendant file or subdirectory with a scan/hashing error.
    ///
    /// Propagates monotonically up every ancestor (including newly added or removed folders that
    /// contain an errored file) so the UI always preserves an unbroken error path from root to
    /// leaf.
    Error,
}

impl FolderStatus {
    /// All five folder statuses in canonical display order.
    pub const ALL: [Self; 5] = [
        Self::Unchanged,
        Self::Modified,
        Self::Added,
        Self::Removed,
        Self::Error,
    ];

    /// Returns the canonical `snake_case` identifier (`"unchanged"`, `"modified"`, `"added"`,
    /// `"removed"`, or `"error"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Modified => "modified",
            Self::Added => "added",
            Self::Removed => "removed",
            Self::Error => "error",
        }
    }

    /// Returns a compact single-character diff badge symbol (`"="`, `"~"`, `"+"`, `"-"`, `"!"`).
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Unchanged => "=",
            Self::Modified => "~",
            Self::Added => "+",
            Self::Removed => "-",
            Self::Error => "!",
        }
    }

    /// Returns a human-readable English display label.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Unchanged => "Unchanged",
            Self::Modified => "Modified",
            Self::Added => "Added",
            Self::Removed => "Removed",
            Self::Error => "Error",
        }
    }

    /// Returns `true` if the folder status is [`Self::Unchanged`].
    #[must_use]
    pub const fn is_unchanged(self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// Returns `true` if the folder status is [`Self::Modified`].
    #[must_use]
    pub const fn is_modified(self) -> bool {
        matches!(self, Self::Modified)
    }

    /// Returns `true` if the folder status is [`Self::Added`].
    #[must_use]
    pub const fn is_added(self) -> bool {
        matches!(self, Self::Added)
    }

    /// Returns `true` if the folder status is [`Self::Removed`].
    #[must_use]
    pub const fn is_removed(self) -> bool {
        matches!(self, Self::Removed)
    }

    /// Returns `true` if the folder status is [`Self::Error`].
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }

    /// Returns `true` for any non-unchanged folder status (`Modified`, `Added`, `Removed`, or
    /// `Error`).
    #[must_use]
    pub const fn is_changed(self) -> bool {
        !self.is_unchanged()
    }

    const fn bit(self) -> u8 {
        match self {
            Self::Unchanged => 1 << 0,
            Self::Modified => 1 << 1,
            Self::Added => 1 << 2,
            Self::Removed => 1 << 3,
            Self::Error => 1 << 4,
        }
    }
}

impl fmt::Display for FolderStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FolderStatus {
    type Err = ParseFolderStatusError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "unchanged" | "equal" | "identical" | "same" | "=" => Ok(Self::Unchanged),
            "modified" | "changed" | "updated" | "~" => Ok(Self::Modified),
            "added" | "new" | "created" | "+" => Ok(Self::Added),
            "removed" | "deleted" | "missing" | "-" => Ok(Self::Removed),
            "error" | "errored" | "failed" | "!" => Ok(Self::Error),
            _ => Err(ParseFolderStatusError {
                input: value.trim().to_string(),
            }),
        }
    }
}

/// Counts of descendant subdirectories grouped by [`FolderStatus`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderStatusCounts {
    pub unchanged: usize,
    pub modified: usize,
    pub added: usize,
    pub removed: usize,
    pub error: usize,
}

impl FolderStatusCounts {
    /// Increments the counter corresponding to `status`.
    pub const fn increment(&mut self, status: FolderStatus) {
        match status {
            FolderStatus::Unchanged => self.unchanged = self.unchanged.saturating_add(1),
            FolderStatus::Modified => self.modified = self.modified.saturating_add(1),
            FolderStatus::Added => self.added = self.added.saturating_add(1),
            FolderStatus::Removed => self.removed = self.removed.saturating_add(1),
            FolderStatus::Error => self.error = self.error.saturating_add(1),
        }
    }

    /// Adds all counts from `other` into `self` using saturating arithmetic.
    pub const fn merge(&mut self, other: &Self) {
        self.unchanged = self.unchanged.saturating_add(other.unchanged);
        self.modified = self.modified.saturating_add(other.modified);
        self.added = self.added.saturating_add(other.added);
        self.removed = self.removed.saturating_add(other.removed);
        self.error = self.error.saturating_add(other.error);
    }

    /// Returns the count for a specific [`FolderStatus`].
    #[must_use]
    pub const fn count_for(&self, status: FolderStatus) -> usize {
        match status {
            FolderStatus::Unchanged => self.unchanged,
            FolderStatus::Modified => self.modified,
            FolderStatus::Added => self.added,
            FolderStatus::Removed => self.removed,
            FolderStatus::Error => self.error,
        }
    }

    /// Returns the total number of counted subdirectories across all statuses.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.unchanged
            .saturating_add(self.modified)
            .saturating_add(self.added)
            .saturating_add(self.removed)
            .saturating_add(self.error)
    }

    /// Returns the total number of non-unchanged subdirectories (`modified + added + removed +
    /// error`).
    #[must_use]
    pub const fn changed_total(&self) -> usize {
        self.modified
            .saturating_add(self.added)
            .saturating_add(self.removed)
            .saturating_add(self.error)
    }
}

/// Aggregated bottom-up status summary propagated across a [`DiffDirectoryNode`] and all of its
/// descendants.
///
/// Precomputed in $O(1)$ per node during tree comparison so UI components (such as colored folder
/// icons, per-folder change badges `+N ~M -K`, and virtualized trees) can read subtree status
/// information without traversing descendants.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderStatusSummary {
    /// File counts across this directory and all nested subdirectories, grouped by [`FileStatus`].
    pub files: FileStatusCounts,
    /// Descendant subdirectory counts (excluding this directory itself), grouped by
    /// [`FolderStatus`].
    pub directories: FolderStatusCounts,
}

impl FolderStatusSummary {
    /// Initializes a summary from the direct file entries inside a single directory.
    #[must_use]
    pub fn from_files<'a>(files: impl IntoIterator<Item = &'a DiffFileEntry>) -> Self {
        let mut summary = Self::default();
        for entry in files {
            summary.files.increment(entry.status());
        }
        summary
    }

    /// Merges a finalized child directory's own `child_status` and `child_summary` into `self`
    /// in $O(1)$ time without double-counting.
    pub const fn merge_child_directory(
        &mut self,
        child_status: FolderStatus,
        child_summary: &Self,
    ) {
        self.files.merge(&child_summary.files);
        self.directories.increment(child_status);
        self.directories.merge(&child_summary.directories);
    }

    /// Returns `true` if any descendant file or subdirectory recorded an error.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        self.files.error > 0 || self.directories.error > 0
    }

    /// Returns `true` if any descendant file or subdirectory differs from unchanged (including
    /// empty added/removed subdirectories or errors).
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.files.changed_total() > 0 || self.directories.changed_total() > 0
    }

    /// Returns `true` if at least one file in this subtree has `status`.
    #[must_use]
    pub const fn has_file_status(&self, status: FileStatus) -> bool {
        self.files.count_for(status) > 0
    }

    /// Returns `true` if two or more distinct non-unchanged [`FileStatus`] categories exist in
    /// this subtree (for example both `Added` and `Removed` files).
    #[must_use]
    pub const fn has_mixed_file_changes(&self) -> bool {
        let active = (self.files.modified > 0) as u8
            + (self.files.added > 0) as u8
            + (self.files.removed > 0) as u8
            + (self.files.error > 0) as u8;
        active >= 2
    }

    /// Returns the dominant non-unchanged [`FileStatus`] present in this subtree, useful for
    /// fine-grained UI folder badges or tinting:
    /// - `Some(FileStatus::Error)` if any errors exist
    /// - `Some(FileStatus::Added)` if all changes in this subtree are exclusively additions
    /// - `Some(FileStatus::Removed)` if all changes in this subtree are exclusively removals
    /// - `Some(FileStatus::Modified)` if there are modified files or a mix of change kinds
    /// - `None` if there are no changes anywhere in this subtree
    #[must_use]
    pub const fn dominant_change_status(&self) -> Option<FileStatus> {
        if self.has_errors() {
            return Some(FileStatus::Error);
        }
        if !self.has_changes() {
            return None;
        }
        let has_added = self.files.added > 0 || self.directories.added > 0;
        let has_removed = self.files.removed > 0 || self.directories.removed > 0;
        let has_modified = self.files.modified > 0 || self.directories.modified > 0;

        if has_added && !has_removed && !has_modified {
            Some(FileStatus::Added)
        } else if has_removed && !has_added && !has_modified {
            Some(FileStatus::Removed)
        } else {
            Some(FileStatus::Modified)
        }
    }
}

/// Compact, copyable set filter selecting which [`FolderStatus`] categories to include.
///
/// Serializes cleanly to/from a JSON array of [`FolderStatus`] values (e.g.
/// `["modified", "added", "removed", "error"]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FolderStatusFilter {
    bits: u8,
}

impl Default for FolderStatusFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl FolderStatusFilter {
    const ALL_BITS: u8 = FolderStatus::Unchanged.bit()
        | FolderStatus::Modified.bit()
        | FolderStatus::Added.bit()
        | FolderStatus::Removed.bit()
        | FolderStatus::Error.bit();

    /// Creates an empty filter matching no folder statuses.
    #[must_use]
    pub const fn none() -> Self {
        Self { bits: 0 }
    }

    /// Creates a filter matching all five [`FolderStatus`] values.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bits: Self::ALL_BITS,
        }
    }

    /// Creates a filter matching every folder status except [`FolderStatus::Unchanged`].
    #[must_use]
    pub const fn changes_only() -> Self {
        Self {
            bits: Self::ALL_BITS & !FolderStatus::Unchanged.bit(),
        }
    }

    /// Creates a filter matching only a single [`FolderStatus`].
    #[must_use]
    pub const fn only(status: FolderStatus) -> Self {
        Self { bits: status.bit() }
    }

    /// Creates a filter from any iterator of [`FolderStatus`] values.
    #[must_use]
    pub fn from_statuses(statuses: impl IntoIterator<Item = FolderStatus>) -> Self {
        let mut filter = Self::none();
        for status in statuses {
            filter.bits |= status.bit();
        }
        filter
    }

    /// Returns a copy of this filter with `status` included.
    #[must_use]
    pub const fn include(mut self, status: FolderStatus) -> Self {
        self.bits |= status.bit();
        self
    }

    /// Returns a copy of this filter with `status` excluded.
    #[must_use]
    pub const fn exclude(mut self, status: FolderStatus) -> Self {
        self.bits &= !status.bit();
        self
    }

    /// Returns a copy of this filter with `status` toggled to `enabled`.
    #[must_use]
    pub const fn with_status(self, status: FolderStatus, enabled: bool) -> Self {
        if enabled {
            self.include(status)
        } else {
            self.exclude(status)
        }
    }

    /// Returns `true` if `status` passes this filter.
    #[must_use]
    pub const fn matches(self, status: FolderStatus) -> bool {
        (self.bits & status.bit()) != 0
    }

    /// Returns `true` if no statuses are selected.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// Returns `true` if all five statuses are selected.
    #[must_use]
    pub const fn is_all(self) -> bool {
        self.bits == Self::ALL_BITS
    }

    /// Returns the number of selected statuses (`0..=5`).
    #[must_use]
    pub const fn len(self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Returns the selected statuses in canonical [`FolderStatus::ALL`] order.
    #[must_use]
    pub fn statuses(self) -> Vec<FolderStatus> {
        FolderStatus::ALL
            .into_iter()
            .filter(|&status| self.matches(status))
            .collect()
    }
}

impl Serialize for FolderStatusFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for status in FolderStatus::ALL {
            if self.matches(status) {
                seq.serialize_element(&status)?;
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for FolderStatusFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let statuses = Vec::<FolderStatus>::deserialize(deserializer)?;
        Ok(Self::from_statuses(statuses))
    }
}

/// Derives the propagated [`FolderStatus`] of a directory from its [`EntryPresence`] and
/// aggregated [`FolderStatusSummary`].
#[must_use]
pub const fn derive_folder_status(
    presence: EntryPresence,
    summary: &FolderStatusSummary,
) -> FolderStatus {
    if summary.has_errors() {
        return FolderStatus::Error;
    }

    match presence {
        EntryPresence::OnlyRight => FolderStatus::Added,
        EntryPresence::OnlyLeft => FolderStatus::Removed,
        EntryPresence::Both => {
            if summary.has_changes() {
                FolderStatus::Modified
            } else {
                FolderStatus::Unchanged
            }
        }
    }
}

/// Recomputes [`DiffDirectoryNode::status`] and [`DiffDirectoryNode::status_summary`] bottom-up
/// across `root` and all descendants using an iterative, stack-safe post-order traversal.
///
/// Safe for arbitrarily deep directory trees without recursion or cloning entries.
pub fn propagate_folder_statuses(root: &mut DiffDirectoryNode) {
    struct PostOrderFrame {
        node: DiffDirectoryNode,
        pending_children: Vec<DiffDirectoryNode>,
    }

    let placeholder = DiffDirectoryNode {
        name: String::new(),
        left_name: None,
        relative_path: String::new(),
        depth: 0,
        presence: EntryPresence::Both,
        status: FolderStatus::Unchanged,
        status_summary: FolderStatusSummary::default(),
        name_case_differs: false,
        type_conflict: false,
        files: BTreeMap::new(),
        sub_directories: BTreeMap::new(),
    };

    let mut root_owned = mem::replace(root, placeholder);
    let root_children: Vec<DiffDirectoryNode> = mem::take(&mut root_owned.sub_directories)
        .into_values()
        .collect();
    let mut stack = vec![PostOrderFrame {
        node: root_owned,
        pending_children: root_children,
    }];

    while let Some(top) = stack.last_mut() {
        if let Some(mut child) = top.pending_children.pop() {
            let grand_children: Vec<DiffDirectoryNode> = mem::take(&mut child.sub_directories)
                .into_values()
                .collect();
            stack.push(PostOrderFrame {
                node: child,
                pending_children: grand_children,
            });
            continue;
        }

        let Some(mut completed) = stack.pop() else {
            unreachable!("post-order propagation stack cannot empty before finishing root");
        };

        let mut summary = FolderStatusSummary::from_files(completed.node.files.values());
        for child in completed.node.sub_directories.values() {
            summary.merge_child_directory(child.status, &child.status_summary);
        }
        completed.node.status = derive_folder_status(completed.node.presence, &summary);
        completed.node.status_summary = summary;

        if let Some(parent) = stack.last_mut() {
            parent
                .node
                .sub_directories
                .insert(completed.node.name.clone(), completed.node);
        } else {
            *root = completed.node;
            return;
        }
    }
}
