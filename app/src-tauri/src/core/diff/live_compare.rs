use crate::core::diff::file_status::FileStatusPolicy;
use crate::core::diff::statistics::DiffStatistics;
use crate::core::diff::tree_diff::{ComparisonOptions, TreeComparer, TreeDiff};
use crate::core::diff::warnings::{PrecheckContext, PrecheckReport, evaluate_precheck};
use crate::core::hash_manager::HashAlgorithm;
use crate::core::hidden_filter::HiddenFileFilter;
use crate::core::ignore_list::IgnoreList;
use crate::core::io::{
    bulk_hash_error::BulkHashError,
    directory_node::DirectoryNode,
    file_manager::FileManager,
    meta_data::MetaData,
    migration::MigrationReport,
};
use crate::core::scan_control::{ScanCancelToken, ScanControl};
use crate::core::scan_manager::ScanManager;
use crate::core::structs::bulk_hash_file_struct::BulkHashFileStruct;
use chrono::Utc;
use std::path::Path;
use std::time::Duration;

/// Configuration for comparing a baseline `.hashed` snapshot against a live directory (or file)
/// on disk.
///
/// By default (`LiveComparisonOptions::new()` / `Default`):
/// - Inherits the baseline snapshot's [`HashAlgorithm`] (falling back to [`HashAlgorithm::Blake3`]
///   when the snapshot does not record one).
/// - Inherits the baseline snapshot's [`IgnoreList`] and [`HiddenFileFilter`] so previously
///   excluded files do not show up as false additions.
/// - Scans in parallel across all available CPU cores via Rayon with default
///   [`ComparisonOptions`].
#[derive(Debug, Clone)]
pub struct LiveComparisonOptions {
    /// Explicit hash algorithm override; when `None`, inherits the baseline snapshot's algorithm
    /// (or falls back to [`Self::fallback_algorithm`]).
    pub algorithm_override: Option<HashAlgorithm>,
    /// Fallback hash algorithm used when neither [`Self::algorithm_override`] nor the baseline
    /// snapshot's metadata specifies an algorithm (default: [`HashAlgorithm::Blake3`]).
    pub fallback_algorithm: HashAlgorithm,
    /// Whether to inherit the baseline snapshot's [`IgnoreList`] when [`Self::ignore_list_override`]
    /// is `None` (default: `true`).
    pub inherit_ignore_list: bool,
    /// Explicit [`IgnoreList`] override for the live scan (takes precedence over inheritance).
    pub ignore_list_override: Option<IgnoreList>,
    /// Whether to inherit the baseline snapshot's [`HiddenFileFilter`] when
    /// [`Self::hidden_filter_override`] is `None` (default: `true`).
    pub inherit_hidden_filter: bool,
    /// Explicit [`HiddenFileFilter`] override for the live scan (takes precedence over
    /// inheritance).
    pub hidden_filter_override: Option<HiddenFileFilter>,
    /// Optional worker thread count limit for parallel Rayon hashing (`None` = all logical cores).
    pub thread_count: Option<usize>,
    /// Optional [`ScanControl`] enabling live pause, resume, and cancellation of the disk scan.
    pub control: Option<ScanControl>,
    /// Tree comparison options (name matching mode, warnings, metadata comparison, max depth,
    /// status policy).
    pub comparison: ComparisonOptions,
}

impl Default for LiveComparisonOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveComparisonOptions {
    /// Creates default live comparison options inheriting algorithm, ignore list, and hidden
    /// filter from the baseline snapshot.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            algorithm_override: None,
            fallback_algorithm: HashAlgorithm::Blake3,
            inherit_ignore_list: true,
            ignore_list_override: None,
            inherit_hidden_filter: true,
            hidden_filter_override: None,
            thread_count: None,
            control: None,
            comparison: ComparisonOptions::new(),
        }
    }

    /// Forces the live scan to hash files with `algorithm` instead of inheriting from the
    /// baseline snapshot.
    #[must_use]
    pub const fn with_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm_override = Some(algorithm);
        self
    }

    /// Sets the fallback algorithm used when the baseline snapshot does not record one.
    #[must_use]
    pub const fn with_fallback_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.fallback_algorithm = algorithm;
        self
    }

    /// Configures whether the baseline snapshot's [`IgnoreList`] is inherited by default.
    #[must_use]
    pub const fn with_inherit_ignore_list(mut self, inherit: bool) -> Self {
        self.inherit_ignore_list = inherit;
        self
    }

    /// Overrides the [`IgnoreList`] used during the live scan.
    #[must_use]
    pub fn with_ignore_list(mut self, ignore_list: IgnoreList) -> Self {
        self.ignore_list_override = Some(ignore_list);
        self
    }

    /// Configures whether the baseline snapshot's [`HiddenFileFilter`] is inherited by default.
    #[must_use]
    pub const fn with_inherit_hidden_filter(mut self, inherit: bool) -> Self {
        self.inherit_hidden_filter = inherit;
        self
    }

    /// Overrides the [`HiddenFileFilter`] used during the live scan.
    #[must_use]
    pub const fn with_hidden_filter(mut self, hidden_filter: HiddenFileFilter) -> Self {
        self.hidden_filter_override = Some(hidden_filter);
        self
    }

    /// Limits parallel hashing during the live scan to `thread_count` worker threads (`0` resets
    /// to default automatic Rayon parallelism).
    #[must_use]
    pub const fn with_thread_count(mut self, thread_count: usize) -> Self {
        self.thread_count = if thread_count > 0 {
            Some(thread_count)
        } else {
            None
        };
        self
    }

    /// Attaches a [`ScanControl`] handle for pausing, resuming, or cancelling the live scan.
    #[must_use]
    pub fn with_control(mut self, control: impl Into<ScanControl>) -> Self {
        self.control = Some(control.into());
        self
    }

    /// Attaches a [`ScanCancelToken`] handle for cancelling the live scan.
    #[must_use]
    pub fn with_cancel_token(mut self, cancel_token: impl Into<ScanCancelToken>) -> Self {
        let mut control = self.control.unwrap_or_default();
        control.set_cancel_token(cancel_token);
        self.control = Some(control);
        self
    }

    /// Replaces the nested [`ComparisonOptions`] used when diffing the baseline and live trees.
    #[must_use]
    pub fn with_comparison_options(mut self, comparison: ComparisonOptions) -> Self {
        self.comparison = comparison;
        self
    }

    /// Convenience builder toggling case-insensitive name matching on [`Self::comparison`].
    #[must_use]
    pub const fn with_case_insensitive(mut self, case_insensitive: bool) -> Self {
        self.comparison = self.comparison.with_case_insensitive(case_insensitive);
        self
    }

    /// Convenience builder setting [`ComparisonOptions::compare_metadata`].
    #[must_use]
    pub const fn with_compare_metadata(mut self, compare_metadata: bool) -> Self {
        self.comparison = self.comparison.with_compare_metadata(compare_metadata);
        self
    }

    /// Convenience builder setting [`ComparisonOptions::collect_warnings`].
    #[must_use]
    pub const fn with_collect_warnings(mut self, collect_warnings: bool) -> Self {
        self.comparison = self.comparison.with_collect_warnings(collect_warnings);
        self
    }

    /// Convenience builder setting [`ComparisonOptions::max_depth`].
    #[must_use]
    pub const fn with_max_depth(mut self, max_depth: Option<usize>) -> Self {
        self.comparison = self.comparison.with_max_depth(max_depth);
        self
    }

    /// Convenience builder setting [`ComparisonOptions::status_policy`].
    #[must_use]
    pub const fn with_status_policy(mut self, status_policy: FileStatusPolicy) -> Self {
        self.comparison = self.comparison.with_status_policy(status_policy);
        self
    }
}

/// Complete result of comparing a baseline `.hashed` snapshot against a live directory (or file)
/// on disk.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LiveComparisonResult {
    /// Aligned tree diff with baseline on the left and the live scan on the right.
    pub diff: TreeDiff,
    /// Precomputed change counts and byte-level storage deltas for [`Self::diff`].
    pub statistics: DiffStatistics,
    /// Path on disk that was scanned live.
    pub target_path: String,
    /// Metadata recorded for the live scan (OS, effective algorithm, active scan duration,
    /// timestamp, hashed file count, total bytes, active filters).
    pub live_meta: MetaData,
    /// Effective hash algorithm used during the live scan.
    pub effective_algorithm: HashAlgorithm,
    /// Whether the hash algorithm was inherited from the baseline snapshot's metadata.
    pub inherited_algorithm: bool,
    /// Whether the ignore list was inherited from the baseline snapshot's metadata.
    pub inherited_ignore_list: bool,
    /// Whether the hidden/system file filter was inherited from the baseline snapshot's metadata.
    pub inherited_hidden_filter: bool,
    /// Number of entries skipped by the ignore list during the live scan.
    pub live_ignored_count: usize,
    /// Number of entries skipped by the hidden/system file filter during the live scan.
    pub live_hidden_skipped_count: usize,
    /// Time spent paused during the live scan (excluded from `live_meta.get_hash_time()`).
    pub live_paused_time: Duration,
}

impl LiveComparisonResult {
    /// Returns the underlying [`TreeDiff`].
    #[must_use]
    pub const fn diff(&self) -> &TreeDiff {
        &self.diff
    }

    /// Returns a mutable reference to the underlying [`TreeDiff`].
    pub const fn diff_mut(&mut self) -> &mut TreeDiff {
        &mut self.diff
    }

    /// Returns the [`DiffStatistics`] corresponding to [`Self::diff`].
    #[must_use]
    pub const fn statistics(&self) -> &DiffStatistics {
        &self.statistics
    }

    /// Returns the live path on disk that was scanned.
    #[must_use]
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    /// Returns the [`MetaData`] generated for the live scan.
    #[must_use]
    pub const fn live_meta(&self) -> &MetaData {
        &self.live_meta
    }

    /// Returns the effective [`HashAlgorithm`] used to hash live files.
    #[must_use]
    pub const fn effective_algorithm(&self) -> HashAlgorithm {
        self.effective_algorithm
    }

    /// Returns `true` if the live directory matches the baseline snapshot with zero differences
    /// and no depth truncation.
    #[must_use]
    pub fn is_clean_match(&self) -> bool {
        self.diff.is_identical()
    }

    /// Returns `true` if any file or directory changed or errored.
    #[must_use]
    pub const fn has_changes(&self) -> bool {
        self.statistics.has_changes()
    }

    /// Returns `true` if any file or directory recorded a scan/hashing error.
    #[must_use]
    pub const fn has_errors(&self) -> bool {
        self.statistics.has_errors()
    }

    /// Returns `true` if any comparison warning was emitted.
    #[must_use]
    pub const fn has_warnings(&self) -> bool {
        self.diff.has_warnings()
    }

    /// Returns `true` if any [`crate::core::diff::WarningSeverity::Critical`] warning was emitted.
    #[must_use]
    pub fn has_critical_warnings(&self) -> bool {
        self.diff.has_critical_warnings()
    }

    /// Reclassifies all file statuses under `policy`, re-propagates folder statuses bottom-up,
    /// and refreshes [`Self::statistics`] so diff and statistics remain completely in sync.
    pub fn reclassify_statuses(&mut self, policy: FileStatusPolicy) {
        self.diff.reclassify_statuses(policy);
        self.statistics = self.diff.statistics();
    }
}

/// Configurable engine for comparing `.hashed` snapshots directly against live directories on disk.
#[derive(Debug, Clone, Default)]
pub struct LiveComparer {
    options: LiveComparisonOptions,
}

impl LiveComparer {
    /// Creates a [`LiveComparer`] with default [`LiveComparisonOptions`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            options: LiveComparisonOptions::new(),
        }
    }

    /// Creates a [`LiveComparer`] with custom [`LiveComparisonOptions`].
    #[must_use]
    pub const fn with_options(options: LiveComparisonOptions) -> Self {
        Self { options }
    }

    /// Returns the active [`LiveComparisonOptions`].
    #[must_use]
    pub const fn options(&self) -> &LiveComparisonOptions {
        &self.options
    }

    /// Runs a fast, consolidated pre-comparison compatibility check between a loaded snapshot and
    /// a live target path on disk without hashing any files.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::PathNotFound`] or an I/O error if `target_path` does not exist or
    /// cannot be accessed.
    pub fn precheck_snapshot(
        &self,
        snapshot: &BulkHashFileStruct,
        target_path: impl AsRef<Path>,
    ) -> Result<PrecheckReport, BulkHashError> {
        precheck_snapshot_with_folder(snapshot, target_path, &self.options)
    }

    /// Runs a fast, passwordless pre-comparison compatibility check between a `.hashed` archive
    /// file (reading only `meta.json` and `hash.sha256`) and a live target path on disk without
    /// decrypting `tree.enc` or hashing any live files.
    ///
    /// # Errors
    ///
    /// Returns archive inspection errors from [`FileManager::inspect_metadata`] or
    /// [`BulkHashError::PathNotFound`] / I/O errors if `target_path` does not exist.
    pub fn precheck_archive(
        &self,
        archive_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
    ) -> Result<PrecheckReport, BulkHashError> {
        precheck_archive_with_folder(archive_path, target_path, &self.options)
    }

    /// Scans `target_path` live on disk and compares it against the baseline `snapshot`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanCancelled`] if cancelled via [`ScanControl`],
    /// [`BulkHashError::PathNotFound`] / [`BulkHashError::PermissionDenied`] if `target_path`
    /// cannot be accessed, or Rayon/I/O errors.
    pub fn compare_snapshot(
        &self,
        snapshot: &BulkHashFileStruct,
        target_path: impl AsRef<Path>,
    ) -> Result<LiveComparisonResult, BulkHashError> {
        compare_snapshot_with_folder_with_options(snapshot, target_path, &self.options)
    }

    /// Opens a `.hashed` archive from `archive_path` (decrypting with `password` when encrypted),
    /// scans `target_path` live on disk, and compares the two trees.
    ///
    /// # Errors
    ///
    /// Returns archive open/decryption/migration errors (such as
    /// [`BulkHashError::PasswordRequired`] or [`BulkHashError::HashMismatch`]) or live scan
    /// errors (such as [`BulkHashError::PathNotFound`] or [`BulkHashError::ScanCancelled`]).
    pub fn compare_archive(
        &self,
        archive_path: impl AsRef<Path>,
        password: Option<&str>,
        target_path: impl AsRef<Path>,
    ) -> Result<LiveComparisonResult, BulkHashError> {
        compare_archive_with_folder_with_options(archive_path, password, target_path, &self.options)
    }
}

/// Convenience function comparing a loaded [`BulkHashFileStruct`] snapshot against a live folder
/// (or file) on disk using default [`LiveComparisonOptions`].
///
/// # Errors
///
/// Returns [`BulkHashError`] if `folder_path` cannot be accessed or the live scan fails.
pub fn compare_snapshot_with_folder(
    snapshot: &BulkHashFileStruct,
    folder_path: impl AsRef<Path>,
) -> Result<LiveComparisonResult, BulkHashError> {
    compare_snapshot_with_folder_with_options(
        snapshot,
        folder_path,
        &LiveComparisonOptions::new(),
    )
}

/// Compares a loaded [`BulkHashFileStruct`] snapshot against a live folder (or file) on disk
/// using custom [`LiveComparisonOptions`].
///
/// # Errors
///
/// Returns [`BulkHashError::ScanCancelled`] if cancelled via [`LiveComparisonOptions::control`],
/// [`BulkHashError::PathNotFound`] / [`BulkHashError::PermissionDenied`] if `folder_path` cannot
/// be accessed, or Rayon/I/O errors.
pub fn compare_snapshot_with_folder_with_options(
    snapshot: &BulkHashFileStruct,
    folder_path: impl AsRef<Path>,
    options: &LiveComparisonOptions,
) -> Result<LiveComparisonResult, BulkHashError> {
    if let Some(control) = &options.control {
        control.checkpoint()?;
    }

    let target_ref = folder_path.as_ref();
    let target_display = validate_live_target_exists(target_ref)?;
    let baseline_meta = snapshot.get_meta();
    let resolved = resolve_live_scan_config(baseline_meta, options);

    let mut scanner = ScanManager::new(resolved.algorithm)
        .with_ignore_list(resolved.ignore_list.clone())
        .with_hidden_filter(resolved.hidden_filter);
    if let Some(threads) = options.thread_count {
        scanner.set_thread_count(Some(threads));
    }
    if let Some(control) = &options.control {
        scanner.set_control(control.clone());
    }

    scanner.start_hash(target_display.clone())?;

    let live_tree = DirectoryNode::build_tree(scanner.get_path(), scanner.get_list());
    let mut live_meta = MetaData::new(
        scanner.get_hash_manager().get_files_counted(),
        scanner.get_hash_time(),
        Utc::now(),
    )
    .with_algorithm(resolved.algorithm)
    .with_total_size(scanner.get_total_size())
    .with_hidden_filter(resolved.hidden_filter);
    if !resolved.ignore_list.is_empty() {
        live_meta = live_meta.with_ignore_list(resolved.ignore_list);
    }

    let comparer = TreeComparer::with_options(options.comparison.clone());
    let diff = comparer.compare_trees_with_metadata(
        snapshot.get_tree(),
        Some(baseline_meta),
        &live_tree,
        Some(&live_meta),
    );
    let statistics = diff.statistics();

    Ok(LiveComparisonResult {
        diff,
        statistics,
        target_path: target_display,
        live_meta,
        effective_algorithm: resolved.algorithm,
        inherited_algorithm: resolved.inherited_algorithm,
        inherited_ignore_list: resolved.inherited_ignore_list,
        inherited_hidden_filter: resolved.inherited_hidden_filter,
        live_ignored_count: scanner.get_ignored_count(),
        live_hidden_skipped_count: scanner.get_hidden_skipped_count(),
        live_paused_time: scanner.get_paused_time(),
    })
}

/// Convenience function opening an unencrypted `.hashed` archive and comparing it directly
/// against a live folder (or file) on disk using default [`LiveComparisonOptions`].
///
/// # Errors
///
/// Returns archive errors from [`FileManager::open_file`] (including
/// [`BulkHashError::PasswordRequired`] if encrypted) or live scan errors.
pub fn compare_archive_with_folder(
    archive_path: impl AsRef<Path>,
    folder_path: impl AsRef<Path>,
) -> Result<LiveComparisonResult, BulkHashError> {
    compare_archive_with_folder_with_options(
        archive_path,
        None,
        folder_path,
        &LiveComparisonOptions::new(),
    )
}

/// Opens a `.hashed` archive (decrypting with `password` when encrypted) and compares it directly
/// against a live folder (or file) on disk using custom [`LiveComparisonOptions`].
///
/// # Errors
///
/// Returns archive open/decryption/integrity/migration errors or live scan errors.
pub fn compare_archive_with_folder_with_options(
    archive_path: impl AsRef<Path>,
    password: Option<&str>,
    folder_path: impl AsRef<Path>,
    options: &LiveComparisonOptions,
) -> Result<LiveComparisonResult, BulkHashError> {
    if let Some(control) = &options.control {
        control.checkpoint()?;
    }

    let snapshot = match password {
        Some(pwd) => FileManager::open_file_with_password(archive_path, pwd)?,
        None => FileManager::open_file(archive_path)?,
    };

    compare_snapshot_with_folder_with_options(&snapshot, folder_path, options)
}

/// Runs a fast, $O(1)$ pre-comparison compatibility check between a loaded
/// [`BulkHashFileStruct`] snapshot and a live folder path on disk without scanning any files.
///
/// Returns one consolidated [`PrecheckReport`] (suitable for a single confirmation popup before
/// starting a potentially large live disk scan).
///
/// # Errors
///
/// Returns [`BulkHashError::PathNotFound`] or an I/O error if `folder_path` does not exist or
/// cannot be accessed.
pub fn precheck_snapshot_with_folder(
    snapshot: &BulkHashFileStruct,
    folder_path: impl AsRef<Path>,
    options: &LiveComparisonOptions,
) -> Result<PrecheckReport, BulkHashError> {
    let target_display = validate_live_target_exists(folder_path.as_ref())?;
    let baseline_meta = snapshot.get_meta();
    let synthetic_live_meta = build_synthetic_live_meta(baseline_meta, options);

    let left_migrated = baseline_meta
        .get_migrated_from()
        .or_else(|| snapshot.get_migration().map(MigrationReport::original_version));
    let left_empty =
        snapshot.get_tree().files.is_empty() && snapshot.get_tree().sub_directories.is_empty();

    let ctx = PrecheckContext {
        left_root_name: Some(snapshot.get_tree().name.as_str()),
        right_root_name: Some(target_display.as_str()),
        left_meta: Some(baseline_meta),
        right_meta: Some(&synthetic_live_meta),
        left_snapshot_hash: None,
        right_snapshot_hash: None,
        left_migrated_from: left_migrated,
        right_migrated_from: None,
        left_is_empty: Some(left_empty),
        right_is_empty: None,
        left_encrypted: snapshot.is_encrypted(),
        right_encrypted: false,
    };
    Ok(evaluate_precheck(&ctx))
}

/// Runs a fast, passwordless pre-comparison compatibility check between a `.hashed` archive on
/// disk (reading only `meta.json` and `hash.sha256`) and a live folder path on disk without
/// decrypting `tree.enc` or hashing any live files.
///
/// Returns one consolidated [`PrecheckReport`] so the UI can warn about OS mismatches, algorithm
/// overrides, mismatched scan filters, or legacy snapshot migration before prompting for a
/// password or starting the live scan.
///
/// # Errors
///
/// Returns archive metadata inspection errors from [`FileManager::inspect_metadata`] or
/// [`BulkHashError::PathNotFound`] / I/O errors if `folder_path` does not exist.
pub fn precheck_archive_with_folder(
    archive_path: impl AsRef<Path>,
    folder_path: impl AsRef<Path>,
    options: &LiveComparisonOptions,
) -> Result<PrecheckReport, BulkHashError> {
    let probe = FileManager::inspect_metadata(archive_path)?;
    let target_display = validate_live_target_exists(folder_path.as_ref())?;
    let synthetic_live_meta = build_synthetic_live_meta(&probe.meta, options);

    let left_migrated = probe
        .needs_migration
        .then_some(probe.version)
        .or_else(|| probe.meta.get_migrated_from());

    let ctx = PrecheckContext {
        left_root_name: None,
        right_root_name: Some(target_display.as_str()),
        left_meta: Some(&probe.meta),
        right_meta: Some(&synthetic_live_meta),
        left_snapshot_hash: None,
        right_snapshot_hash: None,
        left_migrated_from: left_migrated,
        right_migrated_from: None,
        left_is_empty: Some(probe.meta.get_files_hashed() == 0),
        right_is_empty: None,
        left_encrypted: probe.encrypted,
        right_encrypted: false,
    };
    Ok(evaluate_precheck(&ctx))
}

struct ResolvedLiveScanConfig {
    algorithm: HashAlgorithm,
    inherited_algorithm: bool,
    ignore_list: IgnoreList,
    inherited_ignore_list: bool,
    hidden_filter: HiddenFileFilter,
    inherited_hidden_filter: bool,
}

fn resolve_live_scan_config(
    baseline_meta: &MetaData,
    options: &LiveComparisonOptions,
) -> ResolvedLiveScanConfig {
    let (algorithm, inherited_algorithm) = match options.algorithm_override {
        Some(algo) => (algo, false),
        None => match baseline_meta.get_algorithm() {
            Some(algo) => (algo, true),
            None => (options.fallback_algorithm, false),
        },
    };

    let (ignore_list, inherited_ignore_list) = match &options.ignore_list_override {
        Some(list) => (list.clone(), false),
        None if options.inherit_ignore_list => match baseline_meta.get_ignore_list() {
            Some(list) => (list.clone(), true),
            None => (IgnoreList::new(), true),
        },
        None => (IgnoreList::new(), false),
    };

    let (hidden_filter, inherited_hidden_filter) = match options.hidden_filter_override {
        Some(filter) => (filter, false),
        None if options.inherit_hidden_filter => (
            baseline_meta
                .get_hidden_filter()
                .unwrap_or_else(HiddenFileFilter::include_all),
            true,
        ),
        None => (HiddenFileFilter::include_all(), false),
    };

    ResolvedLiveScanConfig {
        algorithm,
        inherited_algorithm,
        ignore_list,
        inherited_ignore_list,
        hidden_filter,
        inherited_hidden_filter,
    }
}

fn build_synthetic_live_meta(
    baseline_meta: &MetaData,
    options: &LiveComparisonOptions,
) -> MetaData {
    let resolved = resolve_live_scan_config(baseline_meta, options);
    let mut meta = MetaData::new(0, Duration::ZERO, Utc::now())
        .with_algorithm(resolved.algorithm)
        .with_hidden_filter(resolved.hidden_filter);
    if !resolved.ignore_list.is_empty() {
        meta = meta.with_ignore_list(resolved.ignore_list);
    }
    meta
}

fn validate_live_target_exists(target_ref: &Path) -> Result<String, BulkHashError> {
    let target_display = target_ref.to_string_lossy().into_owned();
    let exists = target_ref
        .try_exists()
        .map_err(|err| BulkHashError::from_io(err, target_display.clone()))?;
    if !exists {
        return Err(BulkHashError::PathNotFound(target_display));
    }
    Ok(target_display)
}
