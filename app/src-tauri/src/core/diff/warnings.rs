use crate::core::hash_manager::HashAlgorithm;
use crate::core::hidden_filter::HiddenFileFilter;
use crate::core::ignore_list::IgnoreList;
use crate::core::io::meta_data::MetaData;
use chrono::{DateTime, Utc};
use std::collections::BTreeSet;
use std::fmt;

/// Maximum number of example paths or path pairs stored per [`ComparisonWarning`] so large
/// diffs keep warning payloads compact and serialization-friendly.
pub const MAX_WARNING_SAMPLES: usize = 10;

/// Severity level of a [`ComparisonWarning`] emitted during tree or snapshot comparison.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WarningSeverity {
    /// Informational notice that does not invalidate hash comparisons.
    Info,
    /// Significant comparability caveat that may cause unexpected or noisy differences
    /// (for example, comparing a Windows tree against a Linux tree or using mismatched filters).
    Warning,
    /// Severe incompatibility that makes hash comparisons unreliable or meaningless
    /// (for example, comparing SHA-256 hashes against BLAKE3 hashes).
    Critical,
}

impl WarningSeverity {
    /// Returns the canonical lowercase identifier (`"info"`, `"warning"`, or `"critical"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for WarningSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable machine-readable identifier for each category of [`ComparisonWarning`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    DifferentHashAlgorithm,
    InconsistentHashLengths,
    DifferentOperatingSystem,
    UnknownHashAlgorithm,
    DifferentIgnoreLists,
    DifferentHiddenFileFilter,
    ReversedChronologicalOrder,
    CaseCollision,
    CaseOnlyPathDifference,
    FileDirectoryTypeConflict,
    ScanErrorsPresent,
    NoCommonEntries,
    CaseOnlyNameMatched,
    OsMetadataFilesInDiff,
    DifferentRootName,
    MissingExtendedMetadata,
    MigratedSnapshot,
    IdenticalSnapshot,
    EmptyTree,
}

impl WarningCode {
    /// Returns the canonical `snake_case` identifier for this warning code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DifferentHashAlgorithm => "different_hash_algorithm",
            Self::InconsistentHashLengths => "inconsistent_hash_lengths",
            Self::DifferentOperatingSystem => "different_operating_system",
            Self::UnknownHashAlgorithm => "unknown_hash_algorithm",
            Self::DifferentIgnoreLists => "different_ignore_lists",
            Self::DifferentHiddenFileFilter => "different_hidden_file_filter",
            Self::ReversedChronologicalOrder => "reversed_chronological_order",
            Self::CaseCollision => "case_collision",
            Self::CaseOnlyPathDifference => "case_only_path_difference",
            Self::FileDirectoryTypeConflict => "file_directory_type_conflict",
            Self::ScanErrorsPresent => "scan_errors_present",
            Self::NoCommonEntries => "no_common_entries",
            Self::CaseOnlyNameMatched => "case_only_name_matched",
            Self::OsMetadataFilesInDiff => "os_metadata_files_in_diff",
            Self::DifferentRootName => "different_root_name",
            Self::MissingExtendedMetadata => "missing_extended_metadata",
            Self::MigratedSnapshot => "migrated_snapshot",
            Self::IdenticalSnapshot => "identical_snapshot",
            Self::EmptyTree => "empty_tree",
        }
    }

    /// Returns `true` if this warning category can be detected during a fast pre-comparison
    /// check (before traversing the full directory trees).
    #[must_use]
    pub const fn is_precheck(self) -> bool {
        matches!(
            self,
            Self::DifferentHashAlgorithm
                | Self::DifferentOperatingSystem
                | Self::UnknownHashAlgorithm
                | Self::DifferentIgnoreLists
                | Self::DifferentHiddenFileFilter
                | Self::ReversedChronologicalOrder
                | Self::DifferentRootName
                | Self::MigratedSnapshot
                | Self::IdenticalSnapshot
                | Self::EmptyTree
        )
    }
}

impl fmt::Display for WarningCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured machine-readable payload associated with a [`ComparisonWarning`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WarningDetails {
    DifferentOperatingSystem {
        left_os: String,
        right_os: String,
        inferred_from_paths: bool,
    },
    DifferentHashAlgorithm {
        left_algorithm: HashAlgorithm,
        right_algorithm: HashAlgorithm,
    },
    UnknownHashAlgorithm {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        left_algorithm: Option<HashAlgorithm>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        right_algorithm: Option<HashAlgorithm>,
    },
    InconsistentHashLengths {
        left_lengths: Vec<usize>,
        right_lengths: Vec<usize>,
    },
    DifferentIgnoreLists {
        left_pattern_count: usize,
        right_pattern_count: usize,
        left_case_insensitive: bool,
        right_case_insensitive: bool,
    },
    DifferentHiddenFileFilter {
        left_filter: HiddenFileFilter,
        right_filter: HiddenFileFilter,
    },
    ReversedChronologicalOrder {
        left_date_utc: DateTime<Utc>,
        right_date_utc: DateTime<Utc>,
    },
    IdenticalSnapshot {
        hash: String,
        date_utc: DateTime<Utc>,
    },
    DifferentRootName {
        left_root: String,
        right_root: String,
        left_basename: String,
        right_basename: String,
    },
    NoCommonEntries {
        left_file_count: usize,
        right_file_count: usize,
        left_directory_count: usize,
        right_directory_count: usize,
    },
    CaseOnlyPathDifference {
        count: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sample_pairs: Vec<(String, String)>,
    },
    CaseOnlyNameMatched {
        count: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sample_pairs: Vec<(String, String)>,
    },
    CaseCollision {
        count: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sample_paths: Vec<String>,
    },
    FileDirectoryTypeConflict {
        count: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sample_paths: Vec<String>,
    },
    ScanErrorsPresent {
        left_error_count: usize,
        right_error_count: usize,
    },
    MissingExtendedMetadata {
        left_missing_size: usize,
        right_missing_size: usize,
        left_missing_modified: usize,
        right_missing_modified: usize,
    },
    MigratedSnapshot {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        left_migrated_from: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        right_migrated_from: Option<usize>,
    },
    OsMetadataFilesInDiff {
        count: usize,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sample_paths: Vec<String>,
    },
    EmptyTree {
        left_empty: bool,
        right_empty: bool,
    },
}

/// A compatibility, integrity, or sanity warning emitted during a tree or snapshot comparison.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComparisonWarning {
    pub severity: WarningSeverity,
    pub code: WarningCode,
    pub message: String,
    pub details: WarningDetails,
}

impl ComparisonWarning {
    /// Creates a new [`ComparisonWarning`].
    #[must_use]
    pub const fn new(
        severity: WarningSeverity,
        code: WarningCode,
        message: String,
        details: WarningDetails,
    ) -> Self {
        Self {
            severity,
            code,
            message,
            details,
        }
    }

    /// Returns `true` if this warning has [`WarningSeverity::Critical`].
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        matches!(self.severity, WarningSeverity::Critical)
    }

    /// Returns `true` if this warning has [`WarningSeverity::Warning`] or higher.
    #[must_use]
    pub const fn is_warning_or_higher(&self) -> bool {
        matches!(
            self.severity,
            WarningSeverity::Warning | WarningSeverity::Critical
        )
    }
}

impl fmt::Display for ComparisonWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] ({}) {}",
            self.severity.as_str().to_ascii_uppercase(),
            self.code,
            self.message
        )
    }
}

/// Internal accumulator populated during a single traversal pass of the tree comparison engine
/// and turned into sorted [`ComparisonWarning`] values once traversal finishes.
#[derive(Debug, Default)]
pub(crate) struct ComparisonDiagnostics {
    pub(crate) left_files: usize,
    pub(crate) right_files: usize,
    pub(crate) left_hashed_files: usize,
    pub(crate) right_hashed_files: usize,
    pub(crate) left_directories: usize,
    pub(crate) right_directories: usize,
    pub(crate) left_errors: usize,
    pub(crate) right_errors: usize,
    pub(crate) left_missing_size: usize,
    pub(crate) right_missing_size: usize,
    pub(crate) left_missing_modified: usize,
    pub(crate) right_missing_modified: usize,
    pub(crate) left_hash_lengths: BTreeSet<usize>,
    pub(crate) right_hash_lengths: BTreeSet<usize>,
    pub(crate) common_files: usize,
    pub(crate) common_directories: usize,
    pub(crate) case_only_diff_count: usize,
    pub(crate) case_only_diff_samples: Vec<(String, String)>,
    pub(crate) case_only_matched_count: usize,
    pub(crate) case_only_matched_samples: Vec<(String, String)>,
    pub(crate) case_collision_count: usize,
    pub(crate) case_collision_samples: Vec<String>,
    pub(crate) type_conflict_count: usize,
    pub(crate) type_conflict_samples: Vec<String>,
    pub(crate) os_metadata_diff_count: usize,
    pub(crate) os_metadata_diff_samples: Vec<String>,
}

impl ComparisonDiagnostics {
    pub(crate) fn record_case_only_diff(&mut self, left_path: String, right_path: String) {
        self.case_only_diff_count = self.case_only_diff_count.saturating_add(1);
        if self.case_only_diff_samples.len() < MAX_WARNING_SAMPLES {
            self.case_only_diff_samples.push((left_path, right_path));
        }
    }

    pub(crate) fn record_case_only_matched(&mut self, left_path: String, right_path: String) {
        self.case_only_matched_count = self.case_only_matched_count.saturating_add(1);
        if self.case_only_matched_samples.len() < MAX_WARNING_SAMPLES {
            self.case_only_matched_samples.push((left_path, right_path));
        }
    }

    pub(crate) fn record_case_collision(&mut self, path: String) {
        self.case_collision_count = self.case_collision_count.saturating_add(1);
        if self.case_collision_samples.len() < MAX_WARNING_SAMPLES {
            self.case_collision_samples.push(path);
        }
    }

    pub(crate) fn record_type_conflict(&mut self, path: String) {
        self.type_conflict_count = self.type_conflict_count.saturating_add(1);
        if self.type_conflict_samples.len() < MAX_WARNING_SAMPLES {
            self.type_conflict_samples.push(path);
        }
    }

    pub(crate) fn record_os_metadata_diff(&mut self, path: String) {
        self.os_metadata_diff_count = self.os_metadata_diff_count.saturating_add(1);
        if self.os_metadata_diff_samples.len() < MAX_WARNING_SAMPLES {
            self.os_metadata_diff_samples.push(path);
        }
    }
}

/// Lightweight summary of one side (left/baseline or right/target) inspected during a
/// pre-comparison compatibility check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrecheckSideInfo {
    /// Original root directory name, if available (present when pre-checking trees or loaded
    /// snapshots; `None` when probing only `meta.json` without opening `tree.json`/`tree.enc`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_name: Option<String>,
    /// Operating system recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// Hash algorithm recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<HashAlgorithm>,
    /// Snapshot creation timestamp in UTC, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_utc: Option<DateTime<Utc>>,
    /// Number of hashed files recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_hashed: Option<usize>,
    /// Snapshot format version recorded in [`MetaData`], if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format_version: Option<usize>,
    /// Original format version if the snapshot was migrated or requires migration on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrated_from: Option<usize>,
    /// Whether the snapshot archive is password-encrypted.
    #[serde(default)]
    pub encrypted: bool,
}

/// Consolidated pre-comparison compatibility report designed to drive a **single** confirmation
/// popup in the UI before executing a full tree diff.
///
/// All detected pre-flight warnings are collected together in [`Self::warnings`], sorted from
/// highest to lowest [`WarningSeverity`] (`Critical` -> `Warning` -> `Info`), so the user never
/// has to dismiss multiple sequential popups.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrecheckReport {
    /// All pre-flight warnings detected for this comparison, sorted by severity descending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ComparisonWarning>,
    /// Highest severity among [`Self::warnings`], or `None` when no warnings were detected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highest_severity: Option<WarningSeverity>,
    /// Number of [`WarningSeverity::Critical`] warnings in [`Self::warnings`].
    pub critical_count: usize,
    /// Number of [`WarningSeverity::Warning`] warnings in [`Self::warnings`].
    pub warning_count: usize,
    /// Number of [`WarningSeverity::Info`] warnings in [`Self::warnings`].
    pub info_count: usize,
    /// Summary metadata for the left (baseline) side.
    pub left: PrecheckSideInfo,
    /// Summary metadata for the right (target) side.
    pub right: PrecheckSideInfo,
}

impl PrecheckReport {
    /// Returns `true` if no pre-comparison warnings were detected (no popup needed).
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Returns `true` if at least one pre-comparison warning was detected (UI can present one
    /// consolidated popup listing [`Self::warnings`]).
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Returns `true` if at least one [`WarningSeverity::Warning`] or [`WarningSeverity::Critical`]
    /// issue was detected (recommended threshold for explicit user confirmation).
    #[must_use]
    pub const fn requires_confirmation(&self) -> bool {
        self.critical_count > 0 || self.warning_count > 0
    }

    /// Returns `true` if any [`WarningSeverity::Critical`] warning was detected.
    #[must_use]
    pub const fn has_critical_warnings(&self) -> bool {
        self.critical_count > 0
    }

    /// Returns `true` if no critical incompatibility blocks reliable hash comparison.
    #[must_use]
    pub const fn can_compare_reliably(&self) -> bool {
        self.critical_count == 0
    }

    /// Returns `true` if a warning with the given [`WarningCode`] was detected.
    #[must_use]
    pub fn has_warning(&self, code: WarningCode) -> bool {
        self.warnings.iter().any(|warning| warning.code == code)
    }

    /// Returns the highest severity present in this report, if any.
    #[must_use]
    pub const fn highest_severity(&self) -> Option<WarningSeverity> {
        self.highest_severity
    }

    /// Returns all consolidated pre-comparison warnings (sorted by severity descending).
    #[must_use]
    pub fn warnings(&self) -> &[ComparisonWarning] {
        &self.warnings
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

    /// Returns summary metadata for the left (baseline) side.
    #[must_use]
    pub const fn left(&self) -> &PrecheckSideInfo {
        &self.left
    }

    /// Returns summary metadata for the right (target) side.
    #[must_use]
    pub const fn right(&self) -> &PrecheckSideInfo {
        &self.right
    }
}

/// Input context for the fast, $O(1)$ pre-comparison compatibility check.
pub(crate) struct PrecheckContext<'a> {
    pub(crate) left_root_name: Option<&'a str>,
    pub(crate) right_root_name: Option<&'a str>,
    pub(crate) left_meta: Option<&'a MetaData>,
    pub(crate) right_meta: Option<&'a MetaData>,
    pub(crate) left_snapshot_hash: Option<&'a str>,
    pub(crate) right_snapshot_hash: Option<&'a str>,
    pub(crate) left_migrated_from: Option<usize>,
    pub(crate) right_migrated_from: Option<usize>,
    pub(crate) left_is_empty: Option<bool>,
    pub(crate) right_is_empty: Option<bool>,
    pub(crate) left_encrypted: bool,
    pub(crate) right_encrypted: bool,
}

/// Evaluates all fast pre-comparison checks in one pass and returns a single consolidated
/// [`PrecheckReport`] ready for a one-popup confirmation flow.
pub(crate) fn evaluate_precheck(ctx: &PrecheckContext<'_>) -> PrecheckReport {
    let mut warnings = Vec::new();
    let left_root = ctx.left_root_name.unwrap_or("");
    let right_root = ctx.right_root_name.unwrap_or("");

    check_operating_systems_raw(
        ctx.left_meta,
        left_root,
        ctx.right_meta,
        right_root,
        &mut warnings,
    );

    let any_hashed_files = if ctx.left_is_empty == Some(true) && ctx.right_is_empty == Some(true) {
        false
    } else if ctx.left_meta.is_some_and(|m| m.get_files_hashed() > 0)
        || ctx.right_meta.is_some_and(|m| m.get_files_hashed() > 0)
    {
        true
    } else {
        ctx.left_is_empty == Some(false) || ctx.right_is_empty == Some(false)
    };
    let _ = check_metadata_hash_algorithms(
        ctx.left_meta,
        ctx.right_meta,
        any_hashed_files,
        &mut warnings,
    );

    check_scan_filters_raw(ctx.left_meta, ctx.right_meta, &mut warnings);
    check_timestamps_and_identity_raw(
        ctx.left_meta,
        ctx.right_meta,
        ctx.left_snapshot_hash,
        ctx.right_snapshot_hash,
        &mut warnings,
    );

    if ctx.left_is_empty.is_some() || ctx.right_is_empty.is_some() {
        check_empty_trees_raw(
            ctx.left_is_empty.unwrap_or(false),
            ctx.right_is_empty.unwrap_or(false),
            &mut warnings,
        );
    }

    check_root_names_raw(left_root, right_root, &mut warnings);
    check_migrated_snapshots_raw(
        ctx.left_meta,
        ctx.right_meta,
        ctx.left_migrated_from,
        ctx.right_migrated_from,
        &mut warnings,
    );

    warnings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.code.cmp(&b.code)));

    let mut critical_count = 0usize;
    let mut warning_count = 0usize;
    let mut info_count = 0usize;
    for warning in &warnings {
        match warning.severity {
            WarningSeverity::Critical => critical_count = critical_count.saturating_add(1),
            WarningSeverity::Warning => warning_count = warning_count.saturating_add(1),
            WarningSeverity::Info => info_count = info_count.saturating_add(1),
        }
    }
    let highest_severity = warnings.first().map(|w| w.severity);

    let left = build_precheck_side_info(
        ctx.left_root_name,
        ctx.left_meta,
        ctx.left_migrated_from,
        ctx.left_encrypted,
    );
    let right = build_precheck_side_info(
        ctx.right_root_name,
        ctx.right_meta,
        ctx.right_migrated_from,
        ctx.right_encrypted,
    );

    PrecheckReport {
        warnings,
        highest_severity,
        critical_count,
        warning_count,
        info_count,
        left,
        right,
    }
}

fn build_precheck_side_info(
    root_name: Option<&str>,
    meta: Option<&MetaData>,
    migrated_from: Option<usize>,
    encrypted: bool,
) -> PrecheckSideInfo {
    PrecheckSideInfo {
        root_name: root_name.map(ToString::to_string),
        os: meta.map(|m| m.get_current_os().to_string()),
        algorithm: meta.and_then(MetaData::get_algorithm),
        date_utc: meta.map(MetaData::get_date_utc),
        files_hashed: meta.map(MetaData::get_files_hashed),
        format_version: meta.map(MetaData::get_version),
        migrated_from: migrated_from.or_else(|| meta.and_then(MetaData::get_migrated_from)),
        encrypted: encrypted || meta.is_some_and(MetaData::is_encrypted),
    }
}

/// Optional provenance context from [`MetaData`] and snapshot archive hashes passed into the
/// warning evaluator.
pub(crate) struct WarningContext<'a> {
    pub(crate) left_root_name: &'a str,
    pub(crate) right_root_name: &'a str,
    pub(crate) left_meta: Option<&'a MetaData>,
    pub(crate) right_meta: Option<&'a MetaData>,
    pub(crate) left_snapshot_hash: Option<&'a str>,
    pub(crate) right_snapshot_hash: Option<&'a str>,
    pub(crate) left_migrated_from: Option<usize>,
    pub(crate) right_migrated_from: Option<usize>,
    pub(crate) truncated: bool,
}

/// Evaluates metadata and traversal diagnostics to produce a deterministically sorted list of
/// [`ComparisonWarning`] entries (highest severity first).
pub(crate) fn collect_warnings(
    ctx: &WarningContext<'_>,
    diag: &ComparisonDiagnostics,
) -> Vec<ComparisonWarning> {
    let mut warnings = Vec::new();

    check_operating_systems_raw(
        ctx.left_meta,
        ctx.left_root_name,
        ctx.right_meta,
        ctx.right_root_name,
        &mut warnings,
    );
    check_hash_algorithms_and_lengths(ctx, diag, &mut warnings);
    check_scan_filters_raw(ctx.left_meta, ctx.right_meta, &mut warnings);
    check_timestamps_and_identity_raw(
        ctx.left_meta,
        ctx.right_meta,
        ctx.left_snapshot_hash,
        ctx.right_snapshot_hash,
        &mut warnings,
    );
    check_root_names_and_overlap(ctx, diag, &mut warnings);
    check_case_and_type_issues(diag, &mut warnings);
    check_errors_metadata_and_noise(ctx, diag, &mut warnings);

    warnings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.code.cmp(&b.code)));
    warnings
}

fn check_operating_systems_raw(
    left_meta: Option<&MetaData>,
    left_root_name: &str,
    right_meta: Option<&MetaData>,
    right_root_name: &str,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let left_explicit = left_meta
        .map(|meta| meta.get_current_os().trim().to_ascii_lowercase())
        .filter(|os| !os.is_empty());
    let right_explicit = right_meta
        .map(|meta| meta.get_current_os().trim().to_ascii_lowercase())
        .filter(|os| !os.is_empty());

    let mismatch: Option<(String, String, bool)> = match (left_explicit, right_explicit) {
        (Some(left_os), Some(right_os)) => (left_os != right_os).then_some((left_os, right_os, false)),
        (Some(left_os), None) => infer_os_from_path(right_root_name)
            .filter(|&inferred| are_os_incompatible(&left_os, inferred))
            .map(|inferred| (left_os, inferred.to_string(), true)),
        (None, Some(right_os)) => infer_os_from_path(left_root_name)
            .filter(|&inferred| are_os_incompatible(inferred, &right_os))
            .map(|inferred| (inferred.to_string(), right_os, true)),
        (None, None) => match (
            infer_os_from_path(left_root_name),
            infer_os_from_path(right_root_name),
        ) {
            (Some(left_inf), Some(right_inf)) if left_inf != right_inf => {
                Some((left_inf.to_string(), right_inf.to_string(), true))
            }
            _ => None,
        },
    };

    if let Some((left_os, right_os, inferred_from_paths)) = mismatch {
        let source_hint = if inferred_from_paths {
            " (inferred from root paths)"
        } else {
            ""
        };
        let involves_windows = left_os == "windows" || right_os == "windows";
        let impact = if involves_windows {
            "Filesystem case sensitivity, line endings (CRLF vs LF), and OS-specific metadata files (e.g. Thumbs.db, desktop.ini) may cause unexpected differences."
        } else {
            "Filesystem case sensitivity, timestamp precision, and OS-specific metadata files (e.g. .DS_Store) may cause unexpected differences."
        };
        let message = format!(
            "Comparing trees from different operating systems{source_hint}: left='{left_os}', right='{right_os}'. {impact}"
        );
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::DifferentOperatingSystem,
            message,
            WarningDetails::DifferentOperatingSystem {
                left_os,
                right_os,
                inferred_from_paths,
            },
        ));
    }
}

fn check_metadata_hash_algorithms(
    left_meta: Option<&MetaData>,
    right_meta: Option<&MetaData>,
    any_hashed_files: bool,
    warnings: &mut Vec<ComparisonWarning>,
) -> bool {
    let left_algo = left_meta.and_then(MetaData::get_algorithm);
    let right_algo = right_meta.and_then(MetaData::get_algorithm);
    let has_any_meta = left_meta.is_some() || right_meta.is_some();

    match (left_algo, right_algo) {
        (Some(left_algorithm), Some(right_algorithm)) if left_algorithm != right_algorithm => {
            warnings.push(ComparisonWarning::new(
                WarningSeverity::Critical,
                WarningCode::DifferentHashAlgorithm,
                format!(
                    "Snapshots were created with different hash algorithms: left='{left_algorithm}', right='{right_algorithm}'. File hashes cannot be compared reliably."
                ),
                WarningDetails::DifferentHashAlgorithm {
                    left_algorithm,
                    right_algorithm,
                },
            ));
            true
        }
        (Some(_), Some(_)) => false,
        (left_algorithm, right_algorithm) if has_any_meta && any_hashed_files => {
            let side_desc = match (left_algorithm, right_algorithm) {
                (Some(la), None) => format!("left='{la}', right=unknown"),
                (None, Some(ra)) => format!("left=unknown, right='{ra}'"),
                _ => String::from("left=unknown, right=unknown"),
            };
            warnings.push(ComparisonWarning::new(
                WarningSeverity::Warning,
                WarningCode::UnknownHashAlgorithm,
                format!(
                    "Hash algorithm metadata is missing for at least one side ({side_desc}); hash compatibility cannot be guaranteed."
                ),
                WarningDetails::UnknownHashAlgorithm {
                    left_algorithm,
                    right_algorithm,
                },
            ));
            false
        }
        _ => false,
    }
}

fn check_hash_algorithms_and_lengths(
    ctx: &WarningContext<'_>,
    diag: &ComparisonDiagnostics,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let any_hashed_files =
        !diag.left_hash_lengths.is_empty() || !diag.right_hash_lengths.is_empty();
    let algorithm_mismatch_reported = check_metadata_hash_algorithms(
        ctx.left_meta,
        ctx.right_meta,
        any_hashed_files,
        warnings,
    );

    if !algorithm_mismatch_reported
        && !diag.left_hash_lengths.is_empty()
        && !diag.right_hash_lengths.is_empty()
        && diag.left_hash_lengths.is_disjoint(&diag.right_hash_lengths)
    {
        let left_lengths: Vec<usize> = diag.left_hash_lengths.iter().copied().collect();
        let right_lengths: Vec<usize> = diag.right_hash_lengths.iter().copied().collect();
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Critical,
            WarningCode::InconsistentHashLengths,
            format!(
                "Observed hash lengths do not overlap between trees (left={left_lengths:?}, right={right_lengths:?}); the trees were likely hashed with different algorithms."
            ),
            WarningDetails::InconsistentHashLengths {
                left_lengths,
                right_lengths,
            },
        ));
    }
}

fn check_scan_filters_raw(
    left_meta: Option<&MetaData>,
    right_meta: Option<&MetaData>,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let (Some(left_meta), Some(right_meta)) = (left_meta, right_meta) else {
        return;
    };

    let left_ignore = left_meta.get_ignore_list();
    let right_ignore = right_meta.get_ignore_list();
    let left_patterns: &[String] = left_ignore.map_or(&[], IgnoreList::patterns);
    let right_patterns: &[String] = right_ignore.map_or(&[], IgnoreList::patterns);
    let left_ci = left_ignore.is_some_and(IgnoreList::is_case_insensitive);
    let right_ci = right_ignore.is_some_and(IgnoreList::is_case_insensitive);
    let both_empty = left_patterns.is_empty() && right_patterns.is_empty();

    if !both_empty && (left_patterns != right_patterns || left_ci != right_ci) {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::DifferentIgnoreLists,
            format!(
                "Snapshots were scanned with different ignore lists (left={} pattern(s), right={} pattern(s)); files excluded in only one scan may appear as added or removed.",
                left_patterns.len(),
                right_patterns.len()
            ),
            WarningDetails::DifferentIgnoreLists {
                left_pattern_count: left_patterns.len(),
                right_pattern_count: right_patterns.len(),
                left_case_insensitive: left_ci,
                right_case_insensitive: right_ci,
            },
        ));
    }

    let left_filter = left_meta
        .get_hidden_filter()
        .unwrap_or_else(HiddenFileFilter::include_all);
    let right_filter = right_meta
        .get_hidden_filter()
        .unwrap_or_else(HiddenFileFilter::include_all);
    if left_filter != right_filter {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::DifferentHiddenFileFilter,
            String::from(
                "Snapshots were scanned with different hidden/system file filters; hidden or system files may falsely appear as added or removed.",
            ),
            WarningDetails::DifferentHiddenFileFilter {
                left_filter,
                right_filter,
            },
        ));
    }
}

fn check_timestamps_and_identity_raw(
    left_meta: Option<&MetaData>,
    right_meta: Option<&MetaData>,
    left_snapshot_hash: Option<&str>,
    right_snapshot_hash: Option<&str>,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let (Some(left_meta), Some(right_meta)) = (left_meta, right_meta) else {
        return;
    };

    let left_date = left_meta.get_date_utc();
    let right_date = right_meta.get_date_utc();

    if left_date > right_date {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::ReversedChronologicalOrder,
            format!(
                "The baseline (left) snapshot is newer than the target (right) snapshot (left={}, right={}); added and removed files may appear inverted.",
                left_date.to_rfc3339(),
                right_date.to_rfc3339()
            ),
            WarningDetails::ReversedChronologicalOrder {
                left_date_utc: left_date,
                right_date_utc: right_date,
            },
        ));
    }

    if let (Some(left_hash), Some(right_hash)) = (left_snapshot_hash, right_snapshot_hash)
        && !left_hash.is_empty()
        && left_hash.eq_ignore_ascii_case(right_hash)
        && left_date == right_date
        && left_meta
            .get_current_os()
            .eq_ignore_ascii_case(right_meta.get_current_os())
    {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::IdenticalSnapshot,
            String::from(
                "Both sides appear to be the exact same snapshot (identical tree hash, timestamp, and OS).",
            ),
            WarningDetails::IdenticalSnapshot {
                hash: left_hash.to_string(),
                date_utc: left_date,
            },
        ));
    }
}

fn check_empty_trees_raw(
    left_empty: bool,
    right_empty: bool,
    warnings: &mut Vec<ComparisonWarning>,
) {
    if !left_empty && !right_empty {
        return;
    }

    let message = match (left_empty, right_empty) {
        (true, true) => String::from("Both compared directory trees are empty."),
        (true, false) => String::from("The baseline (left) directory tree is empty."),
        (false, true) => String::from("The target (right) directory tree is empty."),
        (false, false) => unreachable!(),
    };
    warnings.push(ComparisonWarning::new(
        WarningSeverity::Info,
        WarningCode::EmptyTree,
        message,
        WarningDetails::EmptyTree {
            left_empty,
            right_empty,
        },
    ));
}

fn check_root_names_raw(
    left_root_name: &str,
    right_root_name: &str,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let left_basename = extract_path_basename(left_root_name);
    let right_basename = extract_path_basename(right_root_name);
    if !left_basename.is_empty()
        && !right_basename.is_empty()
        && left_basename.to_lowercase() != right_basename.to_lowercase()
    {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::DifferentRootName,
            format!(
                "Root directory names differ: left='{left_basename}', right='{right_basename}'. Entries are still compared relative to each root."
            ),
            WarningDetails::DifferentRootName {
                left_root: left_root_name.to_string(),
                right_root: right_root_name.to_string(),
                left_basename,
                right_basename,
            },
        ));
    }
}

fn check_root_names_and_overlap(
    ctx: &WarningContext<'_>,
    diag: &ComparisonDiagnostics,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let left_empty = diag.left_files == 0 && diag.left_directories == 0;
    let right_empty = diag.right_files == 0 && diag.right_directories == 0;

    if left_empty || right_empty {
        check_empty_trees_raw(left_empty, right_empty, warnings);
    } else if !ctx.truncated && diag.common_files == 0 && diag.common_directories == 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::NoCommonEntries,
            format!(
                "The two non-empty trees share no common file or directory paths (left={} file(s), right={} file(s)); they may be unrelated folders or scanned at different root depths.",
                diag.left_files, diag.right_files
            ),
            WarningDetails::NoCommonEntries {
                left_file_count: diag.left_files,
                right_file_count: diag.right_files,
                left_directory_count: diag.left_directories,
                right_directory_count: diag.right_directories,
            },
        ));
    }

    check_root_names_raw(ctx.left_root_name, ctx.right_root_name, warnings);
}

fn check_case_and_type_issues(
    diag: &ComparisonDiagnostics,
    warnings: &mut Vec<ComparisonWarning>,
) {
    if diag.case_collision_count > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::CaseCollision,
            format!(
                "Detected {} case-insensitive name collision(s) within the same directory (e.g. files/folders differing only by letter case). Exact matches were prioritized and all colliding entries were preserved.",
                diag.case_collision_count
            ),
            WarningDetails::CaseCollision {
                count: diag.case_collision_count,
                sample_paths: diag.case_collision_samples.clone(),
            },
        ));
    }

    if diag.case_only_diff_count > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::CaseOnlyPathDifference,
            format!(
                "Found {} path pair(s) that differ only in letter case. Consider enabling case-insensitive name matching when comparing across Windows/macOS and Linux.",
                diag.case_only_diff_count
            ),
            WarningDetails::CaseOnlyPathDifference {
                count: diag.case_only_diff_count,
                sample_pairs: diag.case_only_diff_samples.clone(),
            },
        ));
    }

    if diag.case_only_matched_count > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::CaseOnlyNameMatched,
            format!(
                "Matched {} entry pair(s) case-insensitively despite differing letter case.",
                diag.case_only_matched_count
            ),
            WarningDetails::CaseOnlyNameMatched {
                count: diag.case_only_matched_count,
                sample_pairs: diag.case_only_matched_samples.clone(),
            },
        ));
    }

    if diag.type_conflict_count > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::FileDirectoryTypeConflict,
            format!(
                "Detected {} path(s) where an entry is a file in one tree and a directory in the other.",
                diag.type_conflict_count
            ),
            WarningDetails::FileDirectoryTypeConflict {
                count: diag.type_conflict_count,
                sample_paths: diag.type_conflict_samples.clone(),
            },
        ));
    }
}

fn check_errors_metadata_and_noise(
    ctx: &WarningContext<'_>,
    diag: &ComparisonDiagnostics,
    warnings: &mut Vec<ComparisonWarning>,
) {
    if diag.left_errors > 0 || diag.right_errors > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Warning,
            WarningCode::ScanErrorsPresent,
            format!(
                "Scan/hashing errors are present in the compared trees (left={} error(s), right={} error(s)); affected files cannot be reliably content-compared.",
                diag.left_errors, diag.right_errors
            ),
            WarningDetails::ScanErrorsPresent {
                left_error_count: diag.left_errors,
                right_error_count: diag.right_errors,
            },
        ));
    }

    if diag.os_metadata_diff_count > 0 {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::OsMetadataFilesInDiff,
            format!(
                "Found {} OS-specific system/metadata entry(ies) (e.g. Thumbs.db, desktop.ini, .DS_Store) among unpaired differences.",
                diag.os_metadata_diff_count
            ),
            WarningDetails::OsMetadataFilesInDiff {
                count: diag.os_metadata_diff_count,
                sample_paths: diag.os_metadata_diff_samples.clone(),
            },
        ));
    }

    let missing_any_meta = diag.left_missing_size > 0
        || diag.right_missing_size > 0
        || diag.left_missing_modified > 0
        || diag.right_missing_modified > 0;
    let has_any_meta_present = (diag.left_missing_size < diag.left_hashed_files)
        || (diag.right_missing_size < diag.right_hashed_files)
        || (diag.left_missing_modified < diag.left_hashed_files)
        || (diag.right_missing_modified < diag.right_hashed_files)
        || ctx.left_meta.is_some()
        || ctx.right_meta.is_some();

    if missing_any_meta && has_any_meta_present {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::MissingExtendedMetadata,
            format!(
                "Extended per-file metadata (size/modified timestamp) is missing for some files (missing size: left={}, right={}; missing modified: left={}, right={}); metadata and size-delta comparisons may be incomplete.",
                diag.left_missing_size,
                diag.right_missing_size,
                diag.left_missing_modified,
                diag.right_missing_modified
            ),
            WarningDetails::MissingExtendedMetadata {
                left_missing_size: diag.left_missing_size,
                right_missing_size: diag.right_missing_size,
                left_missing_modified: diag.left_missing_modified,
                right_missing_modified: diag.right_missing_modified,
            },
        ));
    }

    check_migrated_snapshots_raw(
        ctx.left_meta,
        ctx.right_meta,
        ctx.left_migrated_from,
        ctx.right_migrated_from,
        warnings,
    );
}

fn check_migrated_snapshots_raw(
    left_meta: Option<&MetaData>,
    right_meta: Option<&MetaData>,
    left_migrated_from: Option<usize>,
    right_migrated_from: Option<usize>,
    warnings: &mut Vec<ComparisonWarning>,
) {
    let left_migrated = left_migrated_from.or_else(|| left_meta.and_then(MetaData::get_migrated_from));
    let right_migrated = right_migrated_from.or_else(|| right_meta.and_then(MetaData::get_migrated_from));
    if left_migrated.is_some() || right_migrated.is_some() {
        warnings.push(ComparisonWarning::new(
            WarningSeverity::Info,
            WarningCode::MigratedSnapshot,
            String::from(
                "At least one snapshot was migrated from an older .hashed format version; optional fields such as algorithm or per-file metadata may be absent.",
            ),
            WarningDetails::MigratedSnapshot {
                left_migrated_from: left_migrated,
                right_migrated_from: right_migrated,
            },
        ));
    }
}

/// Platform-independent extraction of the final path component (basename) from a root path string,
/// handling both POSIX (`/`) and Windows (`\`, drive prefixes, UNC paths) formats regardless of
/// the host OS running `BulkHash`.
#[must_use]
pub fn extract_path_basename(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let stripped = trimmed.trim_end_matches(['/', '\\']);
    if stripped.is_empty() {
        return if trimmed.starts_with("\\\\") {
            String::from("\\\\")
        } else {
            String::from("/")
        };
    }

    if is_windows_drive_only(stripped) {
        return stripped.to_ascii_uppercase();
    }

    stripped
        .rsplit(['/', '\\'])
        .find(|part| !part.is_empty())
        .map_or_else(String::new, ToString::to_string)
}

/// Infers a coarse operating system family (`"windows"` or `"unix"`) from a root directory path
/// string when explicit [`MetaData`] OS information is unavailable.
///
/// Returns `None` for relative or bare folder names that carry no OS-specific path markers.
#[must_use]
pub fn infer_os_from_path(path: &str) -> Option<&'static str> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return None;
    }

    if has_windows_drive_prefix(trimmed) || trimmed.starts_with("\\\\") {
        return Some("windows");
    }

    if trimmed.starts_with('/') {
        return Some("unix");
    }

    if trimmed.contains('\\') {
        return Some("windows");
    }

    None
}

fn is_windows_drive_only(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn has_windows_drive_prefix(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || matches!(bytes[2], b'\\' | b'/'))
}

fn is_unix_like_os(os: &str) -> bool {
    matches!(
        os,
        "linux"
            | "macos"
            | "freebsd"
            | "openbsd"
            | "netbsd"
            | "dragonfly"
            | "solaris"
            | "illumos"
            | "android"
            | "ios"
            | "unix"
    )
}

fn are_os_incompatible(left: &str, right: &str) -> bool {
    if left == right {
        return false;
    }
    if (left == "unix" && is_unix_like_os(right)) || (right == "unix" && is_unix_like_os(left)) {
        return false;
    }
    true
}
