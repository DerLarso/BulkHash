use crate::core::diff::live_compare::{
    LiveComparisonOptions, LiveComparisonResult, compare_archive_with_folder_with_options,
    compare_snapshot_with_folder_with_options,
};
use crate::core::diff::statistics::format_bytes;
use crate::core::diff::tree_diff::{ComparisonOptions, DiffFileEntry, TreeComparer, TreeDiff};
use crate::core::diff::warnings::WarningCode;
use crate::core::io::{bulk_hash_error::BulkHashError, directory_node::FileEntry};
use crate::core::structs::bulk_hash_file_struct::BulkHashFileStruct;
use chrono::{DateTime, TimeDelta, Utc};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;
use std::time::Duration;

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

const fn default_true() -> bool {
    true
}

/// Overall integrity assessment returned in an [`IntegrityReport`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityStatus {
    /// All verifiable common files matched their baseline hashes or had expected newer-timestamp
    /// edits, with no bitrot suspects, read errors, or hash/size anomalies.
    Healthy,
    /// One or more suspected bitrot files, target read errors, or hash/size inconsistencies were
    /// detected.
    IssuesDetected,
    /// Integrity results cannot be trusted (for example, baseline and target were hashed using
    /// incompatible hash algorithms).
    Unreliable,
}

impl IntegrityStatus {
    /// Returns the canonical `snake_case` identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::IssuesDetected => "issues_detected",
            Self::Unreliable => "unreliable",
        }
    }
}

impl fmt::Display for IntegrityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Confidence level assigned to an [`IntegrityFinding`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum BitrotConfidence {
    /// Suspicious content change with unchanged or regressed timestamp where size also changed or
    /// was unavailable (could also be produced by a timestamp-preserving tool).
    Medium,
    /// Strong corruption or I/O failure indicator (hash changed with identical timestamp and size,
    /// previously readable file failed to read/hash, or identical hash with conflicting sizes).
    High,
}

impl BitrotConfidence {
    /// Returns the canonical `snake_case` identifier (`"medium"` or `"high"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

impl fmt::Display for BitrotConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Specific category of integrity issue detected for a file.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityFindingKind {
    /// Hash changed while both `modified_utc` (within tolerance) and byte `size` stayed
    /// identical — classic silent data corruption / bitrot indicator.
    SilentCorruption,
    /// Hash changed while `modified_utc` stayed identical (within tolerance), while `size`
    /// changed or was unavailable on at least one side.
    UnchangedTimestampContentMismatch,
    /// Hash changed while `modified_utc` moved backwards relative to the baseline snapshot.
    TimestampRegressedContentMismatch,
    /// File was successfully hashed in the baseline snapshot but failed with a read/hashing error
    /// on the target side.
    ReadError,
    /// Both sides produced identical hashes while recording conflicting byte sizes (possible hash
    /// collision or corrupted metadata).
    SizeHashInconsistency,
}

impl IntegrityFindingKind {
    /// Returns the canonical `snake_case` identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SilentCorruption => "silent_corruption",
            Self::UnchangedTimestampContentMismatch => "unchanged_timestamp_content_mismatch",
            Self::TimestampRegressedContentMismatch => "timestamp_regressed_content_mismatch",
            Self::ReadError => "read_error",
            Self::SizeHashInconsistency => "size_hash_inconsistency",
        }
    }

    /// Returns `true` if this finding directly indicates suspected bitrot / silent content
    /// corruption.
    #[must_use]
    pub const fn is_bitrot_suspect(self) -> bool {
        matches!(
            self,
            Self::SilentCorruption
                | Self::UnchangedTimestampContentMismatch
                | Self::TimestampRegressedContentMismatch
        )
    }

    /// Returns the default [`BitrotConfidence`] associated with this finding kind.
    #[must_use]
    pub const fn confidence(self) -> BitrotConfidence {
        match self {
            Self::SilentCorruption | Self::ReadError | Self::SizeHashInconsistency => {
                BitrotConfidence::High
            }
            Self::UnchangedTimestampContentMismatch | Self::TimestampRegressedContentMismatch => {
                BitrotConfidence::Medium
            }
        }
    }
}

impl fmt::Display for IntegrityFindingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Configuration controlling bitrot and file integrity verification heuristics.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegrityCheckOptions {
    /// Maximum allowed absolute difference between baseline and target `modified_utc` for two
    /// timestamps to still be treated as unchanged (default: `Duration::ZERO`, i.e. exact match).
    ///
    /// Raising this (e.g. to `2s`) helps when verifying files copied across filesystems with
    /// coarser timestamp granularity such as FAT32 or network shares.
    #[serde(default)]
    pub timestamp_tolerance: Duration,
    /// When `true`, compares only whole seconds of `modified_utc` (ignoring subsecond nanoseconds),
    /// useful when comparing across filesystems with different subsecond precision.
    #[serde(default)]
    pub ignore_subsec_timestamps: bool,
    /// When `true` (default), flags modified files whose `modified_utc` moved backwards relative
    /// to baseline as [`IntegrityFindingKind::TimestampRegressedContentMismatch`].
    #[serde(default = "default_true")]
    pub flag_timestamp_regression: bool,
    /// When `true` (default), flags previously readable baseline files that failed with a
    /// read/hash error on the target side as [`IntegrityFindingKind::ReadError`].
    #[serde(default = "default_true")]
    pub include_read_errors: bool,
    /// Optional cap on the number of [`IntegrityFinding`] entries returned in
    /// [`IntegrityReport::findings`] (`summary` always reflects exact totals).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_findings: Option<usize>,
}

impl Default for IntegrityCheckOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegrityCheckOptions {
    /// Creates default strict integrity check options (exact timestamps, regression detection
    /// enabled, target read errors included, unlimited findings).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timestamp_tolerance: Duration::ZERO,
            ignore_subsec_timestamps: false,
            flag_timestamp_regression: true,
            include_read_errors: true,
            max_findings: None,
        }
    }

    /// Sets the allowed timestamp rounding tolerance for treating two timestamps as unchanged.
    #[must_use]
    pub const fn with_timestamp_tolerance(mut self, tolerance: Duration) -> Self {
        self.timestamp_tolerance = tolerance;
        self
    }

    /// Configures whether subsecond nanoseconds are ignored when comparing `modified_utc`.
    #[must_use]
    pub const fn with_ignore_subsec_timestamps(mut self, ignore: bool) -> Self {
        self.ignore_subsec_timestamps = ignore;
        self
    }

    /// Configures whether backward-moving `modified_utc` on modified files is flagged.
    #[must_use]
    pub const fn with_flag_timestamp_regression(mut self, enabled: bool) -> Self {
        self.flag_timestamp_regression = enabled;
        self
    }

    /// Configures whether target-side read/hashing errors on previously readable files are
    /// reported as [`IntegrityFindingKind::ReadError`].
    #[must_use]
    pub const fn with_include_read_errors(mut self, include: bool) -> Self {
        self.include_read_errors = include;
        self
    }

    /// Caps the number of findings returned in [`IntegrityReport::findings`].
    #[must_use]
    pub const fn with_max_findings(mut self, max_findings: Option<usize>) -> Self {
        self.max_findings = max_findings;
        self
    }
}

/// Detailed integrity finding for a single file in an [`IntegrityReport`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegrityFinding {
    /// File name without directory components.
    pub name: String,
    /// Canonical `/`-separated relative path (matches [`crate::core::diff::DiffDirectoryNode::find_file`]
    /// and [`crate::core::io::directory_node::DirectoryNode::find_file`]).
    pub relative_path: String,
    /// Canonical `/`-separated parent directory relative path (`""` for files directly in root).
    pub parent_path: String,
    /// Specific kind of integrity issue detected.
    pub kind: IntegrityFindingKind,
    /// Confidence level (`High` or `Medium`).
    pub confidence: BitrotConfidence,
    /// Human-readable explanation of why this file was flagged.
    pub reason: String,
    /// Baseline (left) hash digest, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_hash: Option<String>,
    /// Target (right) hash digest, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_hash: Option<String>,
    /// Baseline (left) file size in bytes, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_size: Option<u64>,
    /// Target (right) file size in bytes, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_size: Option<u64>,
    /// Baseline (left) last modification timestamp in UTC, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_modified_utc: Option<DateTime<Utc>>,
    /// Target (right) last modification timestamp in UTC, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub right_modified_utc: Option<DateTime<Utc>>,
    /// Target-side error message when `kind == IntegrityFindingKind::ReadError`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

impl IntegrityFinding {
    /// Returns the canonical `/`-separated relative path of the flagged file.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the canonical `/`-separated parent directory path.
    #[must_use]
    pub fn parent_path(&self) -> &str {
        &self.parent_path
    }

    /// Returns `true` if this finding is a suspected bitrot / silent corruption case.
    #[must_use]
    pub const fn is_bitrot_suspect(&self) -> bool {
        self.kind.is_bitrot_suspect()
    }
}

/// Summary counters produced by a bitrot / integrity verification pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegritySummary {
    /// Total files present on both sides (baseline and target) that were evaluated.
    pub total_common_files: usize,
    /// Common files verified intact (matching hashes and consistent size metadata).
    pub verified_intact_files: usize,
    /// Common files whose hash changed alongside a legitimately newer `modified_utc`.
    pub expected_modified_files: usize,
    /// Files flagged as [`IntegrityFindingKind::SilentCorruption`] (hash changed, unchanged
    /// `modified_utc` and unchanged `size`).
    pub silent_corruption_files: usize,
    /// Files flagged as [`IntegrityFindingKind::UnchangedTimestampContentMismatch`].
    pub unchanged_timestamp_mismatch_files: usize,
    /// Files flagged as [`IntegrityFindingKind::TimestampRegressedContentMismatch`].
    pub timestamp_regressed_files: usize,
    /// Previously readable baseline files that failed with a read/hashing error on target.
    pub read_error_files: usize,
    /// Common files with matching hashes but disagreeing recorded sizes.
    pub size_hash_inconsistency_files: usize,
    /// Total count of all detected integrity findings (before any `max_findings` cap).
    pub total_findings: usize,
    /// Modified files whose bitrot status could not be checked because `modified_utc` was missing
    /// on at least one side (e.g. legacy v1 snapshot).
    pub unverifiable_missing_timestamp_files: usize,
    /// Common files skipped because the baseline itself recorded a scan error (no reference hash).
    pub unverifiable_baseline_error_files: usize,
    /// Total known bytes across all flagged findings.
    pub affected_bytes: u64,
    /// Files present only in the baseline (removed) — tracked separately from corruption.
    pub removed_files: usize,
    /// Files present only in the target (added) — tracked separately from corruption.
    pub added_files: usize,
}

impl IntegritySummary {
    /// Returns the total number of suspected bitrot files (`silent_corruption +
    /// unchanged_timestamp_mismatch + timestamp_regressed`).
    #[must_use]
    pub const fn suspected_bitrot_files(&self) -> usize {
        self.silent_corruption_files
            .saturating_add(self.unchanged_timestamp_mismatch_files)
            .saturating_add(self.timestamp_regressed_files)
    }

    /// Returns the total number of high-confidence integrity findings (`silent_corruption +
    /// read_error + size_hash_inconsistency`).
    #[must_use]
    pub const fn high_confidence_findings(&self) -> usize {
        self.silent_corruption_files
            .saturating_add(self.read_error_files)
            .saturating_add(self.size_hash_inconsistency_files)
    }

    /// Formats [`Self::affected_bytes`] in human-readable IEC binary units.
    #[must_use]
    pub fn affected_bytes_formatted(&self) -> String {
        format_bytes(self.affected_bytes)
    }
}

/// Per-folder integrity overlay metrics propagated bottom-up to every ancestor directory for GUI
/// tree-viewer highlighting.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FolderIntegritySummary {
    /// Integrity findings located directly inside this directory.
    pub direct_findings: usize,
    /// Integrity findings across this directory and all nested subdirectories.
    pub recursive_findings: usize,
    /// Suspected bitrot findings across this directory and all nested subdirectories.
    pub recursive_bitrot_suspects: usize,
    /// Target read-error findings across this directory and all nested subdirectories.
    pub recursive_read_errors: usize,
    /// Total known bytes of flagged files across this directory and all nested subdirectories.
    pub recursive_affected_bytes: u64,
}

/// Complete bitrot & integrity verification report for a [`TreeDiff`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntegrityReport {
    /// Overall integrity verdict (`Healthy`, `IssuesDetected`, or `Unreliable`).
    pub status: IntegrityStatus,
    /// `false` if incompatible hash algorithms or disjoint hash lengths make findings unreliable.
    pub algorithm_compatible: bool,
    /// Options used during verification.
    pub options: IntegrityCheckOptions,
    /// Aggregated verification counts and affected byte totals (always across all findings).
    pub summary: IntegritySummary,
    /// Detected integrity findings sorted by confidence descending (`High` -> `Medium`), then
    /// finding kind, then canonical relative path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<IntegrityFinding>,
    /// Contextual caveats affecting reliability (e.g. algorithm mismatch, unknown algorithm,
    /// cross-OS timestamp precision differences, or missing timestamps).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reliability_notes: Vec<String>,
    /// `true` if [`Self::findings`] was capped by [`IntegrityCheckOptions::max_findings`] or if
    /// the underlying [`TreeDiff`] was truncated by `max_depth`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
}

impl IntegrityReport {
    /// Returns the overall [`IntegrityStatus`].
    #[must_use]
    pub const fn status(&self) -> IntegrityStatus {
        self.status
    }

    /// Returns `true` if the verification verdict is [`IntegrityStatus::Healthy`].
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        matches!(self.status, IntegrityStatus::Healthy)
    }

    /// Returns `true` if baseline and target hash algorithms are compatible.
    #[must_use]
    pub const fn is_algorithm_compatible(&self) -> bool {
        self.algorithm_compatible
    }

    /// Returns `true` if at least one integrity finding was detected.
    #[must_use]
    pub const fn has_findings(&self) -> bool {
        self.summary.total_findings > 0
    }

    /// Returns `true` if at least one suspected bitrot file was detected.
    #[must_use]
    pub const fn has_bitrot_suspects(&self) -> bool {
        self.summary.suspected_bitrot_files() > 0
    }

    /// Returns the aggregated [`IntegritySummary`].
    #[must_use]
    pub const fn summary(&self) -> &IntegritySummary {
        &self.summary
    }

    /// Returns all returned [`IntegrityFinding`] entries.
    #[must_use]
    pub fn findings(&self) -> &[IntegrityFinding] {
        &self.findings
    }

    /// Returns reliability caveats collected for this check.
    #[must_use]
    pub fn reliability_notes(&self) -> &[String] {
        &self.reliability_notes
    }

    /// Returns `true` if results were truncated by `max_findings` or diff `max_depth`.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Iterates over findings of a specific [`IntegrityFindingKind`].
    pub fn findings_of_kind(
        &self,
        kind: IntegrityFindingKind,
    ) -> impl Iterator<Item = &IntegrityFinding> {
        self.findings
            .iter()
            .filter(move |finding| finding.kind == kind)
    }

    /// Builds a fast lookup index mapping each flagged file's `relative_path` to its index inside
    /// [`Self::findings`] for tree-viewer row highlighting.
    #[must_use]
    pub fn path_to_finding_index(&self) -> BTreeMap<&str, usize> {
        self.findings
            .iter()
            .enumerate()
            .map(|(idx, finding)| (finding.relative_path.as_str(), idx))
            .collect()
    }

    /// Looks up the [`IntegrityFinding`] for `relative_path` (accepting `/` or `\` separators).
    #[must_use]
    pub fn finding_for_path(&self, relative_path: &str) -> Option<&IntegrityFinding> {
        let normalized = normalize_rel_path(relative_path);
        self.findings
            .iter()
            .find(|finding| finding.relative_path == normalized)
    }

    /// Computes bottom-up [`FolderIntegritySummary`] overlays for every ancestor folder containing
    /// findings (including `""` for root) so GUI tree viewers can highlight corrupted folders.
    #[must_use]
    pub fn folder_integrity_summaries(&self) -> BTreeMap<String, FolderIntegritySummary> {
        let mut map: HashMap<&str, FolderIntegritySummary> = HashMap::new();

        for finding in &self.findings {
            let parent = finding.parent_path.as_str();
            let direct = map.entry(parent).or_default();
            direct.direct_findings = direct.direct_findings.saturating_add(1);

            let bytes = finding.right_size.or(finding.left_size).unwrap_or(0);
            let is_bitrot = finding.is_bitrot_suspect();
            let is_read_err = matches!(finding.kind, IntegrityFindingKind::ReadError);

            for_each_ancestor_folder(parent, |ancestor| {
                let entry = map.entry(ancestor).or_default();
                entry.recursive_findings = entry.recursive_findings.saturating_add(1);
                if is_bitrot {
                    entry.recursive_bitrot_suspects =
                        entry.recursive_bitrot_suspects.saturating_add(1);
                }
                if is_read_err {
                    entry.recursive_read_errors = entry.recursive_read_errors.saturating_add(1);
                }
                entry.recursive_affected_bytes =
                    entry.recursive_affected_bytes.saturating_add(bytes);
            });
        }

        map.into_iter()
            .map(|(folder, summary)| (folder.to_owned(), summary))
            .collect()
    }
}

/// Combined result of running a live folder comparison together with a bitrot / integrity check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LiveIntegrityReport {
    /// Underlying live comparison (full [`TreeDiff`], [`crate::core::diff::DiffStatistics`], and
    /// live scan metadata).
    pub live_comparison: LiveComparisonResult,
    /// Bitrot and integrity verification report derived from [`Self::live_comparison`].
    pub integrity: IntegrityReport,
}

impl LiveIntegrityReport {
    /// Returns the underlying [`LiveComparisonResult`].
    #[must_use]
    pub const fn live_comparison(&self) -> &LiveComparisonResult {
        &self.live_comparison
    }

    /// Returns the [`IntegrityReport`].
    #[must_use]
    pub const fn integrity(&self) -> &IntegrityReport {
        &self.integrity
    }

    /// Returns `true` if the live integrity verdict is [`IntegrityStatus::Healthy`].
    #[must_use]
    pub const fn is_healthy(&self) -> bool {
        self.integrity.is_healthy()
    }

    /// Returns `true` if any suspected bitrot file was detected.
    #[must_use]
    pub const fn has_bitrot_suspects(&self) -> bool {
        self.integrity.has_bitrot_suspects()
    }
}

/// Configurable engine for bitrot and file integrity checks across [`TreeDiff`]s, `.hashed`
/// archive pairs, and live folders on disk.
#[derive(Debug, Clone, Default)]
pub struct IntegrityChecker {
    options: IntegrityCheckOptions,
}

impl IntegrityChecker {
    /// Creates an [`IntegrityChecker`] with default [`IntegrityCheckOptions`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: IntegrityCheckOptions::new(),
        }
    }

    /// Creates an [`IntegrityChecker`] with custom [`IntegrityCheckOptions`].
    #[must_use]
    pub const fn with_options(options: IntegrityCheckOptions) -> Self {
        Self { options }
    }

    /// Returns the active [`IntegrityCheckOptions`].
    #[must_use]
    pub const fn options(&self) -> &IntegrityCheckOptions {
        &self.options
    }

    /// Analyzes a [`TreeDiff`] for suspected bitrot, target read errors, and hash/size anomalies.
    #[must_use]
    pub fn check_diff(&self, diff: &TreeDiff) -> IntegrityReport {
        check_diff_integrity_with_options(diff, &self.options)
    }

    /// Opens two `.hashed` archives (decrypting with passwords when encrypted), compares them,
    /// and runs a bitrot / integrity check.
    ///
    /// # Errors
    ///
    /// Propagates archive open/decryption/migration errors from [`TreeComparer`].
    pub fn check_archives(
        &self,
        left_path: impl AsRef<Path>,
        left_password: Option<&str>,
        right_path: impl AsRef<Path>,
        right_password: Option<&str>,
    ) -> Result<IntegrityReport, BulkHashError> {
        check_archives_integrity(
            left_path,
            left_password,
            right_path,
            right_password,
            &self.options,
        )
    }

    /// Scans a live folder on disk against a loaded baseline snapshot and runs a bitrot /
    /// integrity check.
    ///
    /// # Errors
    ///
    /// Propagates live scan errors (such as [`BulkHashError::PathNotFound`] or
    /// [`BulkHashError::ScanCancelled`]).
    pub fn check_snapshot_live(
        &self,
        snapshot: &BulkHashFileStruct,
        folder_path: impl AsRef<Path>,
        live_options: &LiveComparisonOptions,
    ) -> Result<LiveIntegrityReport, BulkHashError> {
        check_snapshot_integrity_live(snapshot, folder_path, live_options, &self.options)
    }

    /// Opens a `.hashed` archive (decrypting with `password` when encrypted), scans a live folder
    /// on disk, and runs a bitrot / integrity check.
    ///
    /// # Errors
    ///
    /// Propagates archive open/decryption errors or live scan errors.
    pub fn check_archive_live(
        &self,
        archive_path: impl AsRef<Path>,
        password: Option<&str>,
        folder_path: impl AsRef<Path>,
        live_options: &LiveComparisonOptions,
    ) -> Result<LiveIntegrityReport, BulkHashError> {
        check_archive_integrity_live(
            archive_path,
            password,
            folder_path,
            live_options,
            &self.options,
        )
    }
}

/// Runs a bitrot and integrity check on a [`TreeDiff`] using default [`IntegrityCheckOptions`].
#[must_use]
pub fn check_diff_integrity(diff: &TreeDiff) -> IntegrityReport {
    check_diff_integrity_with_options(diff, &IntegrityCheckOptions::new())
}

/// Runs a bitrot and integrity check on a [`TreeDiff`] using custom [`IntegrityCheckOptions`].
#[must_use]
pub fn check_diff_integrity_with_options(
    diff: &TreeDiff,
    options: &IntegrityCheckOptions,
) -> IntegrityReport {
    let algorithm_compatible = !diff.has_warning(WarningCode::DifferentHashAlgorithm)
        && !diff.has_warning(WarningCode::InconsistentHashLengths);

    let mut reliability_notes = collect_reliability_notes(diff, algorithm_compatible);
    let mut summary = IntegritySummary::default();
    let mut findings: Vec<IntegrityFinding> = Vec::new();
    let tolerance = TimeDelta::from_std(options.timestamp_tolerance).unwrap_or(TimeDelta::MAX);

    for entry in diff.iter_files() {
        inspect_diff_file(entry, options, tolerance, &mut summary, &mut findings);
    }

    if summary.unverifiable_missing_timestamp_files > 0 {
        reliability_notes.push(format!(
            "{} modified file(s) lacked modification timestamps on at least one side and could not be evaluated for bitrot.",
            summary.unverifiable_missing_timestamp_files
        ));
    }
    if summary.unverifiable_baseline_error_files > 0 {
        reliability_notes.push(format!(
            "{} common file(s) had baseline scan errors and had no reference hash to verify against.",
            summary.unverifiable_baseline_error_files
        ));
    }

    findings.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });

    let capped = if let Some(max_findings) = options.max_findings
        && findings.len() > max_findings
    {
        findings.truncate(max_findings);
        true
    } else {
        false
    };

    let status = if !algorithm_compatible {
        IntegrityStatus::Unreliable
    } else if summary.total_findings > 0 {
        IntegrityStatus::IssuesDetected
    } else {
        IntegrityStatus::Healthy
    };

    IntegrityReport {
        status,
        algorithm_compatible,
        options: options.clone(),
        summary,
        findings,
        reliability_notes,
        truncated: capped || diff.is_truncated(),
    }
}

/// Opens two `.hashed` archives (with optional passwords), compares them, and evaluates bitrot /
/// file integrity.
///
/// # Errors
///
/// Propagates archive open/decryption/integrity/migration errors.
pub fn check_archives_integrity(
    left_path: impl AsRef<Path>,
    left_password: Option<&str>,
    right_path: impl AsRef<Path>,
    right_password: Option<&str>,
    options: &IntegrityCheckOptions,
) -> Result<IntegrityReport, BulkHashError> {
    let comparer = TreeComparer::with_options(ComparisonOptions::new());
    let diff = comparer.compare_archive_files_with_passwords(
        left_path,
        left_password,
        right_path,
        right_password,
    )?;
    Ok(check_diff_integrity_with_options(&diff, options))
}

/// Scans a live folder on disk against a loaded baseline snapshot and evaluates bitrot / file
/// integrity.
///
/// # Errors
///
/// Propagates live scan errors from [`compare_snapshot_with_folder_with_options`].
pub fn check_snapshot_integrity_live(
    snapshot: &BulkHashFileStruct,
    folder_path: impl AsRef<Path>,
    live_options: &LiveComparisonOptions,
    integrity_options: &IntegrityCheckOptions,
) -> Result<LiveIntegrityReport, BulkHashError> {
    let live_comparison =
        compare_snapshot_with_folder_with_options(snapshot, folder_path, live_options)?;
    let integrity = check_diff_integrity_with_options(live_comparison.diff(), integrity_options);
    Ok(LiveIntegrityReport {
        live_comparison,
        integrity,
    })
}

/// Opens a `.hashed` archive (decrypting with `password` when encrypted), scans a live folder on
/// disk, and evaluates bitrot / file integrity.
///
/// # Errors
///
/// Propagates archive open/decryption errors or live scan errors.
pub fn check_archive_integrity_live(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    folder_path: impl AsRef<Path>,
    live_options: &LiveComparisonOptions,
    integrity_options: &IntegrityCheckOptions,
) -> Result<LiveIntegrityReport, BulkHashError> {
    let live_comparison = compare_archive_with_folder_with_options(
        archive_path,
        password,
        folder_path,
        live_options,
    )?;
    let integrity = check_diff_integrity_with_options(live_comparison.diff(), integrity_options);
    Ok(LiveIntegrityReport {
        live_comparison,
        integrity,
    })
}

fn collect_reliability_notes(diff: &TreeDiff, algorithm_compatible: bool) -> Vec<String> {
    let mut notes = Vec::new();
    if !algorithm_compatible {
        notes.push(String::from(
            "Baseline and target used incompatible hash algorithms or disjoint hash lengths; bitrot findings are not reliable.",
        ));
    }
    if diff.has_warning(WarningCode::UnknownHashAlgorithm) {
        notes.push(String::from(
            "Hash algorithm metadata is missing for at least one side; ensure both sides were hashed with the same algorithm.",
        ));
    }
    if diff.has_warning(WarningCode::DifferentOperatingSystem) {
        notes.push(String::from(
            "Snapshots originate from different operating systems; timestamp precision and line-ending differences may affect bitrot heuristics.",
        ));
    }
    if diff.has_warning(WarningCode::ReversedChronologicalOrder) {
        notes.push(String::from(
            "Baseline snapshot timestamp is newer than target snapshot; timestamp-based bitrot checks may be inverted.",
        ));
    }
    if diff.is_truncated() {
        notes.push(String::from(
            "Diff traversal was truncated by max_depth; deeper subdirectories were not verified.",
        ));
    }
    notes
}

fn inspect_diff_file(
    entry: &DiffFileEntry,
    options: &IntegrityCheckOptions,
    tolerance: TimeDelta,
    summary: &mut IntegritySummary,
    findings: &mut Vec<IntegrityFinding>,
) {
    let (Some(left), Some(right)) = (entry.left(), entry.right()) else {
        if entry.left().is_some() {
            summary.removed_files = summary.removed_files.saturating_add(1);
        } else if entry.right().is_some() {
            summary.added_files = summary.added_files.saturating_add(1);
        }
        return;
    };

    summary.total_common_files = summary.total_common_files.saturating_add(1);

    match (left.hash(), right.hash()) {
        (None, _) => {
            summary.unverifiable_baseline_error_files =
                summary.unverifiable_baseline_error_files.saturating_add(1);
        }
        (Some(lh), None) => {
            if options.include_read_errors {
                let err_msg = right
                    .error()
                    .map_or_else(|| String::from("Unknown read/hash error"), ToString::to_string);
                record_finding(
                    entry,
                    IntegrityFindingKind::ReadError,
                    format!("Previously readable file failed to read or hash on target: {err_msg}"),
                    Some(lh),
                    None,
                    Some(err_msg),
                    summary,
                    findings,
                );
            }
        }
        (Some(lh), Some(rh)) if lh.eq_ignore_ascii_case(rh) => {
            if let (Some(ls), Some(rs)) = (left.size(), right.size())
                && ls != rs
            {
                record_finding(
                    entry,
                    IntegrityFindingKind::SizeHashInconsistency,
                    format!(
                        "File hashes match ('{lh}') but recorded sizes disagree (baseline={ls} B, target={rs} B)."
                    ),
                    Some(lh),
                    Some(rh),
                    None,
                    summary,
                    findings,
                );
            } else {
                summary.verified_intact_files = summary.verified_intact_files.saturating_add(1);
            }
        }
        (Some(lh), Some(rh)) => {
            evaluate_changed_hash_entry(
                entry,
                lh,
                rh,
                left.size(),
                right.size(),
                left.modified_utc(),
                right.modified_utc(),
                options,
                tolerance,
                summary,
                findings,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_changed_hash_entry(
    entry: &DiffFileEntry,
    left_hash: &str,
    right_hash: &str,
    left_size: Option<u64>,
    right_size: Option<u64>,
    left_mtime: Option<DateTime<Utc>>,
    right_mtime: Option<DateTime<Utc>>,
    options: &IntegrityCheckOptions,
    tolerance: TimeDelta,
    summary: &mut IntegritySummary,
    findings: &mut Vec<IntegrityFinding>,
) {
    let (Some(lm), Some(rm)) = (left_mtime, right_mtime) else {
        summary.unverifiable_missing_timestamp_files =
            summary.unverifiable_missing_timestamp_files.saturating_add(1);
        return;
    };

    let delta = compute_timestamp_delta(lm, rm, options.ignore_subsec_timestamps);

    if delta.abs() <= tolerance {
        let same_known_size = matches!((left_size, right_size), (Some(ls), Some(rs)) if ls == rs);
        if same_known_size {
            let size = left_size.unwrap_or(0);
            record_finding(
                entry,
                IntegrityFindingKind::SilentCorruption,
                format!(
                    "Suspected bitrot: file hash changed while modification timestamp ({}) and size ({size} B) remained unchanged.",
                    rm.to_rfc3339()
                ),
                Some(left_hash),
                Some(right_hash),
                None,
                summary,
                findings,
            );
        } else {
            record_finding(
                entry,
                IntegrityFindingKind::UnchangedTimestampContentMismatch,
                format!(
                    "File hash changed while modification timestamp ({}) remained unchanged (size baseline={left_size:?}, target={right_size:?}).",
                    rm.to_rfc3339()
                ),
                Some(left_hash),
                Some(right_hash),
                None,
                summary,
                findings,
            );
        }
    } else if delta < -tolerance {
        if options.flag_timestamp_regression {
            record_finding(
                entry,
                IntegrityFindingKind::TimestampRegressedContentMismatch,
                format!(
                    "File hash changed while modification timestamp moved backwards (baseline={}, target={}).",
                    lm.to_rfc3339(),
                    rm.to_rfc3339()
                ),
                Some(left_hash),
                Some(right_hash),
                None,
                summary,
                findings,
            );
        } else {
            summary.expected_modified_files = summary.expected_modified_files.saturating_add(1);
        }
    } else {
        summary.expected_modified_files = summary.expected_modified_files.saturating_add(1);
    }
}

#[allow(clippy::too_many_arguments)]
fn record_finding(
    entry: &DiffFileEntry,
    kind: IntegrityFindingKind,
    reason: String,
    left_hash: Option<&str>,
    right_hash: Option<&str>,
    error_message: Option<String>,
    summary: &mut IntegritySummary,
    findings: &mut Vec<IntegrityFinding>,
) {
    match kind {
        IntegrityFindingKind::SilentCorruption => {
            summary.silent_corruption_files = summary.silent_corruption_files.saturating_add(1);
        }
        IntegrityFindingKind::UnchangedTimestampContentMismatch => {
            summary.unchanged_timestamp_mismatch_files = summary
                .unchanged_timestamp_mismatch_files
                .saturating_add(1);
        }
        IntegrityFindingKind::TimestampRegressedContentMismatch => {
            summary.timestamp_regressed_files =
                summary.timestamp_regressed_files.saturating_add(1);
        }
        IntegrityFindingKind::ReadError => {
            summary.read_error_files = summary.read_error_files.saturating_add(1);
        }
        IntegrityFindingKind::SizeHashInconsistency => {
            summary.size_hash_inconsistency_files =
                summary.size_hash_inconsistency_files.saturating_add(1);
        }
    }
    summary.total_findings = summary.total_findings.saturating_add(1);

    let left_size = entry.left().and_then(FileEntry::size);
    let right_size = entry.right().and_then(FileEntry::size);
    if let Some(bytes) = right_size.or(left_size) {
        summary.affected_bytes = summary.affected_bytes.saturating_add(bytes);
    }

    let rel_path = entry.relative_path().to_string();
    let parent_path = match rel_path.rsplit_once('/') {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    };

    findings.push(IntegrityFinding {
        name: entry.name().to_string(),
        relative_path: rel_path,
        parent_path,
        kind,
        confidence: kind.confidence(),
        reason,
        left_hash: left_hash.map(ToString::to_string),
        right_hash: right_hash.map(ToString::to_string),
        left_size,
        right_size,
        left_modified_utc: entry.left().and_then(FileEntry::modified_utc),
        right_modified_utc: entry.right().and_then(FileEntry::modified_utc),
        error_message,
    });
}

fn compute_timestamp_delta(
    left: DateTime<Utc>,
    right: DateTime<Utc>,
    ignore_subsec: bool,
) -> TimeDelta {
    if ignore_subsec {
        TimeDelta::seconds(right.timestamp().saturating_sub(left.timestamp()))
    } else {
        right.signed_duration_since(left)
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
