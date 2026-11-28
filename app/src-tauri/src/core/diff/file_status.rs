use crate::core::diff::tree_diff::{DiffFileEntry, EntryPresence};
use crate::core::io::directory_node::FileEntry;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq};
use std::fmt;
use std::str::FromStr;

/// Error returned when parsing a [`FileStatus`] from a string fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseFileStatusError {
    input: String,
}

impl ParseFileStatusError {
    /// Returns the unrecognized input string.
    #[must_use]
    pub fn input(&self) -> &str {
        &self.input
    }
}

impl fmt::Display for ParseFileStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown file status '{}' (expected: unchanged, modified, added, removed, error)",
            self.input
        )
    }
}

impl std::error::Error for ParseFileStatusError {}

/// High-level semantic status of a file entry in a [`crate::core::diff::TreeDiff`].
///
/// Categorizes every compared file position into one of five core states:
/// - [`Self::Unchanged`] (Unverändert)
/// - [`Self::Modified`] (Geändert)
/// - [`Self::Added`] (Neu)
/// - [`Self::Removed`] (Gelöscht)
/// - [`Self::Error`] (Fehler)
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    /// File exists on both sides with matching content (and matching or ignored metadata).
    Unchanged,
    /// File exists on both sides and its content (hash) or tracked metadata changed.
    Modified,
    /// File exists only in the target (right / "after") tree.
    Added,
    /// File exists only in the baseline (left / "before") tree.
    Removed,
    /// File could not be reliably hashed or compared due to a scan/hashing error.
    Error,
}

impl FileStatus {
    /// All five core file statuses in canonical display order.
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

    /// Returns `true` if the status is [`Self::Unchanged`].
    #[must_use]
    pub const fn is_unchanged(self) -> bool {
        matches!(self, Self::Unchanged)
    }

    /// Returns `true` if the status is [`Self::Modified`].
    #[must_use]
    pub const fn is_modified(self) -> bool {
        matches!(self, Self::Modified)
    }

    /// Returns `true` if the status is [`Self::Added`].
    #[must_use]
    pub const fn is_added(self) -> bool {
        matches!(self, Self::Added)
    }

    /// Returns `true` if the status is [`Self::Removed`].
    #[must_use]
    pub const fn is_removed(self) -> bool {
        matches!(self, Self::Removed)
    }

    /// Returns `true` if the status is [`Self::Error`].
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }

    /// Returns `true` for any non-unchanged status (`Modified`, `Added`, `Removed`, or `Error`).
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

impl fmt::Display for FileStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FileStatus {
    type Err = ParseFileStatusError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "unchanged" | "equal" | "identical" | "same" | "=" => Ok(Self::Unchanged),
            "modified" | "changed" | "updated" | "~" => Ok(Self::Modified),
            "added" | "new" | "created" | "+" => Ok(Self::Added),
            "removed" | "deleted" | "missing" | "-" => Ok(Self::Removed),
            "error" | "errored" | "failed" | "!" => Ok(Self::Error),
            _ => Err(ParseFileStatusError {
                input: value.trim().to_string(),
            }),
        }
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_true() -> bool {
    true
}

/// Detailed explanation accompanying a [`FileStatus`] classification, useful for file detail
/// inspectors, diagnostics, and downstream analyzers (such as bitrot or move/rename detection).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileStatusDetail {
    Unchanged {
        /// Whether left and right names differed in letter case (in case-insensitive mode).
        #[serde(default, skip_serializing_if = "is_false")]
        name_case_differs: bool,
        /// Whether extended metadata (`size` or `modified_utc`) differed even though content
        /// matched (only `true` when metadata-only changes are treated as `Unchanged`).
        #[serde(default, skip_serializing_if = "is_false")]
        metadata_differs: bool,
    },
    Modified {
        /// `true` if the file hashes differed; `false` for metadata-only modifications.
        content_changed: bool,
        /// `Some(true)` if both sides carry `size` and they differ; `Some(false)` if equal;
        /// `None` if size is unavailable on either side.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_changed: Option<bool>,
        /// `Some(true)` if both sides carry `modified_utc` and they differ; `Some(false)` if
        /// equal; `None` if timestamp is unavailable on either side.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        modified_changed: Option<bool>,
    },
    Added {
        /// Whether a directory with the same name existed in the baseline (left) tree.
        #[serde(default, skip_serializing_if = "is_false")]
        type_conflict: bool,
        /// Whether the added entry itself recorded a scan/hashing error (only possible when
        /// [`FileStatusPolicy::classify_single_side_errors_as_error`] is `false`).
        #[serde(default, skip_serializing_if = "is_false")]
        has_error: bool,
    },
    Removed {
        /// Whether a directory with the same name exists in the target (right) tree.
        #[serde(default, skip_serializing_if = "is_false")]
        type_conflict: bool,
        /// Whether the removed entry itself recorded a scan/hashing error (only possible when
        /// [`FileStatusPolicy::classify_single_side_errors_as_error`] is `false`).
        #[serde(default, skip_serializing_if = "is_false")]
        has_error: bool,
    },
    Error {
        /// Which side(s) contained this file position (`only_left`, `only_right`, or `both`).
        presence: EntryPresence,
        /// Scan/hashing error recorded on the left (baseline) side, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        left_error: Option<String>,
        /// Scan/hashing error recorded on the right (target) side, if any.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        right_error: Option<String>,
    },
}

impl FileStatusDetail {
    /// Returns the corresponding [`FileStatus`] variant for this detail payload.
    #[must_use]
    pub const fn status(&self) -> FileStatus {
        match self {
            Self::Unchanged { .. } => FileStatus::Unchanged,
            Self::Modified { .. } => FileStatus::Modified,
            Self::Added { .. } => FileStatus::Added,
            Self::Removed { .. } => FileStatus::Removed,
            Self::Error { .. } => FileStatus::Error,
        }
    }

    /// Returns `true` if this detail describes a modification where hashes matched and only
    /// file metadata (`size` or `modified_utc`) differed.
    #[must_use]
    pub const fn is_metadata_only_modification(&self) -> bool {
        matches!(
            self,
            Self::Modified {
                content_changed: false,
                ..
            }
        )
    }

    /// Returns `true` if this detail describes a content (hash) modification.
    #[must_use]
    pub const fn is_content_modification(&self) -> bool {
        matches!(
            self,
            Self::Modified {
                content_changed: true,
                ..
            }
        )
    }
}

/// Combined [`FileStatus`] and [`FileStatusDetail`] produced by [`classify_file_entry_detailed`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileStatusInfo {
    pub status: FileStatus,
    pub detail: FileStatusDetail,
}

/// Policy controlling edge-case rules when classifying compared files into [`FileStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct FileStatusPolicy {
    /// When `true` (default), a file whose hash is identical across both sides but whose tracked
    /// metadata (`size` or `modified_utc`) differs is classified as [`FileStatus::Modified`].
    /// When `false`, metadata-only differences with matching hashes are classified as
    /// [`FileStatus::Unchanged`].
    #[serde(default = "default_true")]
    pub treat_metadata_only_as_modified: bool,
    /// When `true` (default), a file present on only one side that recorded a scan/hashing error
    /// is classified as [`FileStatus::Error`] so no scan error can hide under [`FileStatus::Added`]
    /// or [`FileStatus::Removed`]. When `false`, single-side errored files keep `Added`/`Removed`
    /// while both-side entries with an error remain [`FileStatus::Error`].
    #[serde(default = "default_true")]
    pub classify_single_side_errors_as_error: bool,
}

impl Default for FileStatusPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl FileStatusPolicy {
    /// Creates the default strict policy (`treat_metadata_only_as_modified = true`,
    /// `classify_single_side_errors_as_error = true`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            treat_metadata_only_as_modified: true,
            classify_single_side_errors_as_error: true,
        }
    }

    /// Alias for [`Self::new`] (strict metadata and error classification).
    #[must_use]
    pub const fn strict() -> Self {
        Self::new()
    }

    /// Creates a content-focused policy that classifies matching-hash files as
    /// [`FileStatus::Unchanged`] even if timestamps/metadata changed, while still surfacing all
    /// scan errors as [`FileStatus::Error`].
    #[must_use]
    pub const fn content_only() -> Self {
        Self {
            treat_metadata_only_as_modified: false,
            classify_single_side_errors_as_error: true,
        }
    }

    /// Configures whether metadata-only changes (identical hash, differing size/timestamp) count
    /// as [`FileStatus::Modified`].
    #[must_use]
    pub const fn with_treat_metadata_only_as_modified(mut self, enabled: bool) -> Self {
        self.treat_metadata_only_as_modified = enabled;
        self
    }

    /// Configures whether single-side entries with scan/hashing errors are classified as
    /// [`FileStatus::Error`].
    #[must_use]
    pub const fn with_classify_single_side_errors_as_error(mut self, enabled: bool) -> Self {
        self.classify_single_side_errors_as_error = enabled;
        self
    }
}

/// Compact, copyable set filter selecting which [`FileStatus`] categories to include (e.g. for
/// "hide unchanged" toggles or status filter pills in the UI).
///
/// Serializes cleanly to/from a JSON array of [`FileStatus`] values (e.g.
/// `["modified", "added", "removed", "error"]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileStatusFilter {
    bits: u8,
}

impl Default for FileStatusFilter {
    fn default() -> Self {
        Self::all()
    }
}

impl FileStatusFilter {
    const ALL_BITS: u8 = FileStatus::Unchanged.bit()
        | FileStatus::Modified.bit()
        | FileStatus::Added.bit()
        | FileStatus::Removed.bit()
        | FileStatus::Error.bit();

    /// Creates an empty filter matching no statuses.
    #[must_use]
    pub const fn none() -> Self {
        Self { bits: 0 }
    }

    /// Creates a filter matching all five [`FileStatus`] values.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            bits: Self::ALL_BITS,
        }
    }

    /// Creates a filter matching every status except [`FileStatus::Unchanged`] (useful for
    /// "hide unchanged files" quick-toggle filters).
    #[must_use]
    pub const fn changes_only() -> Self {
        Self {
            bits: Self::ALL_BITS & !FileStatus::Unchanged.bit(),
        }
    }

    /// Creates a filter matching only a single [`FileStatus`].
    #[must_use]
    pub const fn only(status: FileStatus) -> Self {
        Self { bits: status.bit() }
    }

    /// Creates a filter from any iterator of [`FileStatus`] values.
    #[must_use]
    pub fn from_statuses(statuses: impl IntoIterator<Item = FileStatus>) -> Self {
        let mut filter = Self::none();
        for status in statuses {
            filter.bits |= status.bit();
        }
        filter
    }

    /// Returns a copy of this filter with `status` included.
    #[must_use]
    pub const fn include(mut self, status: FileStatus) -> Self {
        self.bits |= status.bit();
        self
    }

    /// Returns a copy of this filter with `status` excluded.
    #[must_use]
    pub const fn exclude(mut self, status: FileStatus) -> Self {
        self.bits &= !status.bit();
        self
    }

    /// Returns a copy of this filter with `status` toggled to `enabled`.
    #[must_use]
    pub const fn with_status(self, status: FileStatus, enabled: bool) -> Self {
        if enabled {
            self.include(status)
        } else {
            self.exclude(status)
        }
    }

    /// Returns `true` if `status` passes this filter.
    #[must_use]
    pub const fn matches(self, status: FileStatus) -> bool {
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

    /// Returns the selected statuses in canonical [`FileStatus::ALL`] order.
    #[must_use]
    pub fn statuses(self) -> Vec<FileStatus> {
        FileStatus::ALL
            .into_iter()
            .filter(|&status| self.matches(status))
            .collect()
    }
}

impl Serialize for FileStatusFilter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for status in FileStatus::ALL {
            if self.matches(status) {
                seq.serialize_element(&status)?;
            }
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for FileStatusFilter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let statuses = Vec::<FileStatus>::deserialize(deserializer)?;
        Ok(Self::from_statuses(statuses))
    }
}

/// Counts of classified file entries grouped by [`FileStatus`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileStatusCounts {
    pub unchanged: usize,
    pub modified: usize,
    pub added: usize,
    pub removed: usize,
    pub error: usize,
}

impl FileStatusCounts {
    /// Increments the counter corresponding to `status`.
    pub const fn increment(&mut self, status: FileStatus) {
        match status {
            FileStatus::Unchanged => self.unchanged = self.unchanged.saturating_add(1),
            FileStatus::Modified => self.modified = self.modified.saturating_add(1),
            FileStatus::Added => self.added = self.added.saturating_add(1),
            FileStatus::Removed => self.removed = self.removed.saturating_add(1),
            FileStatus::Error => self.error = self.error.saturating_add(1),
        }
    }

    /// Returns the count for a specific [`FileStatus`].
    #[must_use]
    pub const fn count_for(&self, status: FileStatus) -> usize {
        match status {
            FileStatus::Unchanged => self.unchanged,
            FileStatus::Modified => self.modified,
            FileStatus::Added => self.added,
            FileStatus::Removed => self.removed,
            FileStatus::Error => self.error,
        }
    }

    /// Returns the total number of counted files across all statuses.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.unchanged
            .saturating_add(self.modified)
            .saturating_add(self.added)
            .saturating_add(self.removed)
            .saturating_add(self.error)
    }

    /// Returns the total number of non-unchanged files (`modified + added + removed + error`).
    #[must_use]
    pub const fn changed_total(&self) -> usize {
        self.modified
            .saturating_add(self.added)
            .saturating_add(self.removed)
            .saturating_add(self.error)
    }
}

/// Classifies a raw `(left, right)` [`FileEntry`] pair into a [`FileStatus`] according to `policy`
/// and whether metadata comparison is enabled (`compare_metadata`).
#[must_use]
pub fn classify_pair(
    left: Option<&FileEntry>,
    right: Option<&FileEntry>,
    compare_metadata: bool,
    policy: FileStatusPolicy,
) -> FileStatus {
    match (left, right) {
        (Some(l), None) => {
            if policy.classify_single_side_errors_as_error && l.is_err() {
                FileStatus::Error
            } else {
                FileStatus::Removed
            }
        }
        (None, Some(r)) => {
            if policy.classify_single_side_errors_as_error && r.is_err() {
                FileStatus::Error
            } else {
                FileStatus::Added
            }
        }
        (Some(l), Some(r)) => match (l.hash(), r.hash()) {
            (Some(lh), Some(rh)) => {
                if !lh.eq_ignore_ascii_case(rh) {
                    return FileStatus::Modified;
                }
                let meta_changed = compare_metadata
                    && policy.treat_metadata_only_as_modified
                    && pair_metadata_differs(l, r);
                if meta_changed {
                    FileStatus::Modified
                } else {
                    FileStatus::Unchanged
                }
            }
            _ => FileStatus::Error,
        },
        (None, None) => FileStatus::Error,
    }
}

/// Classifies a [`DiffFileEntry`] into a [`FileStatus`] according to `policy`.
///
/// Respects metadata differences already detected on `entry` when
/// `policy.treat_metadata_only_as_modified` is `true`, and classifies single-side errored files
/// according to `policy.classify_single_side_errors_as_error`.
#[must_use]
pub fn classify_file_entry(entry: &DiffFileEntry, policy: FileStatusPolicy) -> FileStatus {
    classify_file_entry_internal(entry, true, policy).status
}

/// Classifies a [`DiffFileEntry`] into both its [`FileStatus`] and rich [`FileStatusDetail`].
#[must_use]
pub fn classify_file_entry_detailed(
    entry: &DiffFileEntry,
    policy: FileStatusPolicy,
) -> FileStatusInfo {
    classify_file_entry_internal(entry, true, policy)
}

pub(crate) fn classify_entry_with_options(
    entry: &DiffFileEntry,
    compare_metadata: bool,
    policy: FileStatusPolicy,
) -> FileStatusInfo {
    classify_file_entry_internal(entry, compare_metadata, policy)
}

fn classify_file_entry_internal(
    entry: &DiffFileEntry,
    compare_metadata: bool,
    policy: FileStatusPolicy,
) -> FileStatusInfo {
    let detail = match (entry.left(), entry.right()) {
        (Some(l), None) => {
            if policy.classify_single_side_errors_as_error && l.is_err() {
                FileStatusDetail::Error {
                    presence: EntryPresence::OnlyLeft,
                    left_error: l.error().map(ToString::to_string),
                    right_error: None,
                }
            } else {
                FileStatusDetail::Removed {
                    type_conflict: entry.has_type_conflict(),
                    has_error: l.is_err(),
                }
            }
        }
        (None, Some(r)) => {
            if policy.classify_single_side_errors_as_error && r.is_err() {
                FileStatusDetail::Error {
                    presence: EntryPresence::OnlyRight,
                    left_error: None,
                    right_error: r.error().map(ToString::to_string),
                }
            } else {
                FileStatusDetail::Added {
                    type_conflict: entry.has_type_conflict(),
                    has_error: r.is_err(),
                }
            }
        }
        (Some(l), Some(r)) => match (l.hash(), r.hash()) {
            (Some(lh), Some(rh)) => {
                let size_changed = match (l.size, r.size) {
                    (Some(ls), Some(rs)) => Some(ls != rs),
                    _ => None,
                };
                let modified_changed = match (l.modified_utc, r.modified_utc) {
                    (Some(lm), Some(rm)) => Some(lm != rm),
                    _ => None,
                };
                let metadata_differs = size_changed == Some(true) || modified_changed == Some(true);

                if !lh.eq_ignore_ascii_case(rh) {
                    FileStatusDetail::Modified {
                        content_changed: true,
                        size_changed,
                        modified_changed,
                    }
                } else if compare_metadata
                    && policy.treat_metadata_only_as_modified
                    && metadata_differs
                {
                    FileStatusDetail::Modified {
                        content_changed: false,
                        size_changed,
                        modified_changed,
                    }
                } else {
                    FileStatusDetail::Unchanged {
                        name_case_differs: entry.name_case_differs(),
                        metadata_differs,
                    }
                }
            }
            _ => FileStatusDetail::Error {
                presence: EntryPresence::Both,
                left_error: l.error().map(ToString::to_string),
                right_error: r.error().map(ToString::to_string),
            },
        },
        (None, None) => FileStatusDetail::Error {
            presence: entry.presence(),
            left_error: None,
            right_error: None,
        },
    };

    FileStatusInfo {
        status: detail.status(),
        detail,
    }
}

fn pair_metadata_differs(left: &FileEntry, right: &FileEntry) -> bool {
    let size_differs = matches!((left.size, right.size), (Some(ls), Some(rs)) if ls != rs);
    let modified_differs =
        matches!((left.modified_utc, right.modified_utc), (Some(lm), Some(rm)) if lm != rm);
    size_differs || modified_differs
}
