use crate::app::info::{
    AppDirectories, AppIdentity, AppInfo, AppStatus, FormatCapabilities, PlatformInfo,
};
use crate::core::{
    hash_manager::HashAlgorithm,
    io::bulk_hash_error::BulkHashError,
    scan_control::{ScanControl, ScanControlState},
    structs::bulk_hash_file_struct::BulkHashFileStruct,
};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, Weak};
use std::time::{Duration, Instant};

/// Category of an active scan or verification operation tracked by [`AppState`].
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobKind {
    #[default]
    Directory,
    SingleFile,
    LiveCompare,
    IntegrityCheck,
}

impl ScanJobKind {
    /// Returns the canonical `snake_case` identifier for this job kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::SingleFile => "single_file",
            Self::LiveCompare => "live_compare",
            Self::IntegrityCheck => "integrity_check",
        }
    }
}

impl fmt::Display for ScanJobKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Serializable summary of an active scan job managed by [`AppState`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActiveScanSummary {
    pub job_id: u64,
    pub kind: ScanJobKind,
    pub target_path: String,
    pub algorithm: HashAlgorithm,
    pub state: ScanControlState,
    pub started_at_utc: DateTime<Utc>,
}

/// Serializable summary of a `.hashed` snapshot currently loaded in [`AppState`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoadedSnapshotSummary {
    pub snapshot_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    pub opened_at_utc: DateTime<Utc>,
    pub files_hashed: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<HashAlgorithm>,
    pub encrypted: bool,
    pub version: usize,
    pub was_migrated: bool,
    /// Hex SHA-256 digest of the snapshot's plaintext `tree.json` payload.
    pub tree_hash: String,
}

#[derive(Debug)]
struct ActiveScanRecord {
    job_id: u64,
    kind: ScanJobKind,
    target_path: String,
    algorithm: HashAlgorithm,
    control: ScanControl,
    started_at_utc: DateTime<Utc>,
}

impl ActiveScanRecord {
    fn summary(&self) -> ActiveScanSummary {
        ActiveScanSummary {
            job_id: self.job_id,
            kind: self.kind,
            target_path: self.target_path.clone(),
            algorithm: self.algorithm,
            state: self.control.state(),
            started_at_utc: self.started_at_utc,
        }
    }
}

#[derive(Debug)]
struct ScanRegistry {
    next_job_id: u64,
    jobs: BTreeMap<u64, ActiveScanRecord>,
}

impl ScanRegistry {
    const fn new() -> Self {
        Self {
            next_job_id: 1,
            jobs: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct LoadedSnapshotRecord {
    snapshot_id: u64,
    source_path: Option<PathBuf>,
    opened_at_utc: DateTime<Utc>,
    snapshot: Arc<BulkHashFileStruct>,
}

impl LoadedSnapshotRecord {
    fn summary(&self) -> LoadedSnapshotSummary {
        let meta = self.snapshot.get_meta();
        LoadedSnapshotSummary {
            snapshot_id: self.snapshot_id,
            source_path: self
                .source_path
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned()),
            opened_at_utc: self.opened_at_utc,
            files_hashed: meta.get_files_hashed(),
            total_size: meta.get_total_size(),
            algorithm: meta.get_algorithm(),
            encrypted: self.snapshot.is_encrypted(),
            version: meta.get_version(),
            was_migrated: self.snapshot.was_migrated(),
            tree_hash: self.snapshot.get_hash().to_owned(),
        }
    }
}

#[derive(Debug)]
struct SnapshotStore {
    next_snapshot_id: u64,
    entries: BTreeMap<u64, LoadedSnapshotRecord>,
}

impl SnapshotStore {
    const fn new() -> Self {
        Self {
            next_snapshot_id: 1,
            entries: BTreeMap::new(),
        }
    }
}

#[derive(Debug)]
struct AppRuntimeMetadata {
    initialized: bool,
    identity: AppIdentity,
    directories: AppDirectories,
}

impl AppRuntimeMetadata {
    fn new() -> Self {
        Self {
            initialized: false,
            identity: AppIdentity::from_cargo_metadata(),
            directories: AppDirectories::default(),
        }
    }
}

/// RAII handle for an active scan registered in [`AppState`].
///
/// Automatically removes the scan job from [`AppState`] when dropped (including on early returns
/// or thread panics), preventing leaked active-scan entries.
#[derive(Debug)]
pub struct ActiveScanGuard {
    job_id: u64,
    control: ScanControl,
    registry: Weak<Mutex<ScanRegistry>>,
    finished: bool,
}

impl ActiveScanGuard {
    /// Returns the unique job identifier assigned by [`AppState`].
    #[must_use]
    pub const fn job_id(&self) -> u64 {
        self.job_id
    }

    /// Returns a cloned [`ScanControl`] handle linked to this scan job.
    #[must_use]
    pub fn control(&self) -> ScanControl {
        self.control.clone()
    }

    /// Returns a reference to this scan job's [`ScanControl`].
    #[must_use]
    pub const fn control_ref(&self) -> &ScanControl {
        &self.control
    }

    /// Returns `true` if cancellation has been requested for this job.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.control.is_cancelled()
    }

    /// Explicitly marks the scan job finished and removes it from [`AppState`].
    pub fn finish(mut self) {
        self.unregister();
    }

    fn unregister(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Some(registry) = self.registry.upgrade() {
            let mut guard = registry.lock().unwrap_or_else(PoisonError::into_inner);
            guard.jobs.remove(&self.job_id);
        }
    }
}

impl Drop for ActiveScanGuard {
    fn drop(&mut self) {
        self.unregister();
    }
}

/// Central thread-safe managed state for the `BulkHash` Tauri desktop application.
///
/// Registered with Tauri via `Builder::manage` during startup and accessed by IPC commands and
/// window/application lifecycle hooks via `tauri::State<'_, AppState>`.
#[derive(Debug)]
pub struct AppState {
    started_at: Instant,
    shutting_down: AtomicBool,
    metadata: RwLock<AppRuntimeMetadata>,
    scans: Arc<Mutex<ScanRegistry>>,
    snapshots: Mutex<SnapshotStore>,
    pending_startup_paths: Mutex<Vec<PathBuf>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Creates a fresh uninitialized [`AppState`] instance ready to be managed by Tauri.
    #[must_use]
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            shutting_down: AtomicBool::new(false),
            metadata: RwLock::new(AppRuntimeMetadata::new()),
            scans: Arc::new(Mutex::new(ScanRegistry::new())),
            snapshots: Mutex::new(SnapshotStore::new()),
            pending_startup_paths: Mutex::new(Vec::new()),
        }
    }

    fn read_metadata(&self) -> RwLockReadGuard<'_, AppRuntimeMetadata> {
        self.metadata.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write_metadata(&self) -> RwLockWriteGuard<'_, AppRuntimeMetadata> {
        self.metadata
            .write()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_scans(&self) -> MutexGuard<'_, ScanRegistry> {
        self.scans.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_snapshots(&self) -> MutexGuard<'_, SnapshotStore> {
        self.snapshots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn lock_startup_paths(&self) -> MutexGuard<'_, Vec<PathBuf>> {
        self.pending_startup_paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Populates resolved Tauri package metadata and OS directories during `.setup()`.
    pub fn mark_initialized(&self, identity: AppIdentity, directories: AppDirectories) {
        let mut meta = self.write_metadata();
        meta.identity = identity;
        meta.directories = directories;
        meta.initialized = true;
    }

    /// Returns `true` once Tauri's `.setup()` hook has completed initialization.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.read_metadata().initialized
    }

    /// Returns the resolved [`AppIdentity`].
    #[must_use]
    pub fn identity(&self) -> AppIdentity {
        self.read_metadata().identity.clone()
    }

    /// Returns the resolved [`AppDirectories`].
    #[must_use]
    pub fn directories(&self) -> AppDirectories {
        self.read_metadata().directories.clone()
    }

    /// Returns how long this [`AppState`] instance has been alive.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        self.started_at.elapsed()
    }

    /// Builds a complete [`AppInfo`] payload describing identity, platform, format capabilities,
    /// and resolved directories.
    #[must_use]
    pub fn app_info(&self) -> AppInfo {
        let meta = self.read_metadata();
        AppInfo {
            identity: meta.identity.clone(),
            platform: PlatformInfo::detect(),
            capabilities: FormatCapabilities::current(),
            directories: meta.directories.clone(),
            initialized: meta.initialized,
        }
    }

    /// Builds a point-in-time [`AppStatus`] snapshot of active jobs, loaded snapshots, and
    /// lifecycle flags.
    #[must_use]
    pub fn app_status(&self) -> AppStatus {
        let initialized = self.is_initialized();
        let shutting_down = self.is_shutting_down();
        let uptime_ms = u64::try_from(self.uptime().as_millis()).unwrap_or(u64::MAX);
        let active_scans = self.list_active_scans();
        let active_scan_count = active_scans.len();
        let paused_scan_count = active_scans
            .iter()
            .filter(|scan| scan.state == ScanControlState::Paused)
            .count();
        let loaded_snapshots = self.list_snapshots();
        let loaded_snapshot_count = loaded_snapshots.len();
        let pending_startup_paths_count = self.pending_startup_paths_count();

        AppStatus {
            initialized,
            shutting_down,
            uptime_ms,
            active_scan_count,
            paused_scan_count,
            active_scans,
            loaded_snapshot_count,
            loaded_snapshots,
            pending_startup_paths_count,
        }
    }

    /// Returns `true` if graceful application shutdown has been initiated.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::Acquire)
    }

    /// Marks the application as shutting down and cancels all active scan jobs immediately.
    ///
    /// This operation is idempotent and safe to invoke from both window-close and run-loop exit
    /// hooks. Returns the number of active scans that were signalled to cancel.
    pub fn begin_shutdown(&self) -> usize {
        self.shutting_down.store(true, Ordering::Release);
        self.cancel_all_scans()
    }

    /// Registers a new active scan job with a fresh [`ScanControl`] and returns an RAII
    /// [`ActiveScanGuard`] that removes the job upon drop.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::AppShuttingDown`] if application shutdown has already started.
    pub fn register_scan(
        &self,
        kind: ScanJobKind,
        target_path: impl Into<String>,
        algorithm: HashAlgorithm,
    ) -> Result<ActiveScanGuard, BulkHashError> {
        self.register_scan_with_control(kind, target_path, algorithm, ScanControl::new())
    }

    /// Registers a new active scan job using a caller-provided [`ScanControl`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::AppShuttingDown`] if application shutdown has already started.
    pub fn register_scan_with_control(
        &self,
        kind: ScanJobKind,
        target_path: impl Into<String>,
        algorithm: HashAlgorithm,
        control: ScanControl,
    ) -> Result<ActiveScanGuard, BulkHashError> {
        if self.is_shutting_down() {
            return Err(BulkHashError::AppShuttingDown);
        }

        let mut registry = self.lock_scans();
        // Re-check under the registry lock so a concurrent `begin_shutdown()` can never miss
        // a newly registered scan.
        if self.is_shutting_down() {
            return Err(BulkHashError::AppShuttingDown);
        }

        let job_id = registry.next_job_id;
        registry.next_job_id = registry.next_job_id.saturating_add(1);

        registry.jobs.insert(
            job_id,
            ActiveScanRecord {
                job_id,
                kind,
                target_path: target_path.into(),
                algorithm,
                control: control.clone(),
                started_at_utc: Utc::now(),
            },
        );
        drop(registry);

        Ok(ActiveScanGuard {
            job_id,
            control,
            registry: Arc::downgrade(&self.scans),
            finished: false,
        })
    }

    /// Looks up the [`ScanControl`] for an active scan job by `job_id`.
    #[must_use]
    pub fn get_scan_control(&self, job_id: u64) -> Option<ScanControl> {
        let registry = self.lock_scans();
        registry.jobs.get(&job_id).map(|job| job.control.clone())
    }

    /// Pauses an active scan job and returns its resulting [`ScanControlState`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanJobNotFound`] if no active job exists with `job_id`.
    pub fn pause_scan(&self, job_id: u64) -> Result<ScanControlState, BulkHashError> {
        let control = self
            .get_scan_control(job_id)
            .ok_or(BulkHashError::ScanJobNotFound(job_id))?;
        control.pause();
        Ok(control.state())
    }

    /// Resumes a paused scan job and returns its resulting [`ScanControlState`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanJobNotFound`] if no active job exists with `job_id`.
    pub fn resume_scan(&self, job_id: u64) -> Result<ScanControlState, BulkHashError> {
        let control = self
            .get_scan_control(job_id)
            .ok_or(BulkHashError::ScanJobNotFound(job_id))?;
        control.resume();
        Ok(control.state())
    }

    /// Toggles pause/resume on an active scan job and returns its resulting [`ScanControlState`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanJobNotFound`] if no active job exists with `job_id`.
    pub fn toggle_pause_scan(&self, job_id: u64) -> Result<ScanControlState, BulkHashError> {
        let control = self
            .get_scan_control(job_id)
            .ok_or(BulkHashError::ScanJobNotFound(job_id))?;
        let _ = control.toggle_pause();
        Ok(control.state())
    }

    /// Requests cancellation of an active scan job and returns its resulting [`ScanControlState`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::ScanJobNotFound`] if no active job exists with `job_id`.
    pub fn cancel_scan(&self, job_id: u64) -> Result<ScanControlState, BulkHashError> {
        let control = self
            .get_scan_control(job_id)
            .ok_or(BulkHashError::ScanJobNotFound(job_id))?;
        control.cancel();
        Ok(control.state())
    }

    /// Requests cancellation on every currently active scan job and returns the number of jobs
    /// signalled.
    pub fn cancel_all_scans(&self) -> usize {
        let controls: Vec<ScanControl> = {
            let registry = self.lock_scans();
            registry
                .jobs
                .values()
                .map(|job| job.control.clone())
                .collect()
        };

        for control in &controls {
            control.cancel();
        }
        controls.len()
    }

    /// Returns the number of currently active scan jobs.
    #[must_use]
    pub fn active_scan_count(&self) -> usize {
        self.lock_scans().jobs.len()
    }

    /// Returns deterministic summaries of all currently active scan jobs, ordered by `job_id`.
    #[must_use]
    pub fn list_active_scans(&self) -> Vec<ActiveScanSummary> {
        let registry = self.lock_scans();
        registry
            .jobs
            .values()
            .map(ActiveScanRecord::summary)
            .collect()
    }

    /// Stores a loaded `.hashed` snapshot in session memory and returns its assigned handle ID.
    #[must_use]
    pub fn insert_snapshot(
        &self,
        source_path: Option<PathBuf>,
        snapshot: BulkHashFileStruct,
    ) -> u64 {
        let mut store = self.lock_snapshots();
        let snapshot_id = store.next_snapshot_id;
        store.next_snapshot_id = store.next_snapshot_id.saturating_add(1);

        store.entries.insert(
            snapshot_id,
            LoadedSnapshotRecord {
                snapshot_id,
                source_path,
                opened_at_utc: Utc::now(),
                snapshot: Arc::new(snapshot),
            },
        );
        snapshot_id
    }

    /// Retrieves a shared reference to a loaded snapshot by `snapshot_id`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::SnapshotNotFound`] if no loaded snapshot matches `snapshot_id`.
    pub fn get_snapshot(&self, snapshot_id: u64) -> Result<Arc<BulkHashFileStruct>, BulkHashError> {
        let store = self.lock_snapshots();
        store
            .entries
            .get(&snapshot_id)
            .map(|entry| Arc::clone(&entry.snapshot))
            .ok_or(BulkHashError::SnapshotNotFound(snapshot_id))
    }

    /// Retrieves metadata summary information for a loaded snapshot by `snapshot_id`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::SnapshotNotFound`] if no loaded snapshot matches `snapshot_id`.
    pub fn get_snapshot_summary(
        &self,
        snapshot_id: u64,
    ) -> Result<LoadedSnapshotSummary, BulkHashError> {
        let store = self.lock_snapshots();
        store
            .entries
            .get(&snapshot_id)
            .map(LoadedSnapshotRecord::summary)
            .ok_or(BulkHashError::SnapshotNotFound(snapshot_id))
    }

    /// Removes a loaded snapshot from session memory by `snapshot_id`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::SnapshotNotFound`] if no loaded snapshot matches `snapshot_id`.
    pub fn remove_snapshot(&self, snapshot_id: u64) -> Result<(), BulkHashError> {
        let mut store = self.lock_snapshots();
        if store.entries.remove(&snapshot_id).is_some() {
            Ok(())
        } else {
            Err(BulkHashError::SnapshotNotFound(snapshot_id))
        }
    }

    /// Clears all loaded snapshots from session memory and returns how many were removed.
    pub fn clear_snapshots(&self) -> usize {
        let mut store = self.lock_snapshots();
        let count = store.entries.len();
        store.entries.clear();
        count
    }

    /// Returns the number of snapshots currently held in session memory.
    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.lock_snapshots().entries.len()
    }

    /// Returns summaries of all loaded snapshots ordered by `snapshot_id`.
    #[must_use]
    pub fn list_snapshots(&self) -> Vec<LoadedSnapshotSummary> {
        let store = self.lock_snapshots();
        store
            .entries
            .values()
            .map(LoadedSnapshotRecord::summary)
            .collect()
    }

    /// Queues a startup path (for example, a `.hashed` file or folder passed at launch) for the
    /// frontend to consume once ready.
    pub fn push_startup_path(&self, path: PathBuf) {
        let mut queue = self.lock_startup_paths();
        queue.push(path);
    }

    /// Queues multiple startup paths in order.
    pub fn push_startup_paths<I>(&self, paths: I)
    where
        I: IntoIterator<Item = PathBuf>,
    {
        let mut queue = self.lock_startup_paths();
        queue.extend(paths);
    }

    /// Drains and returns all queued startup paths in FIFO order.
    #[must_use]
    pub fn take_startup_paths(&self) -> Vec<PathBuf> {
        let mut queue = self.lock_startup_paths();
        std::mem::take(&mut *queue)
    }

    /// Clones currently queued startup paths without removing them.
    #[must_use]
    pub fn peek_startup_paths(&self) -> Vec<PathBuf> {
        self.lock_startup_paths().clone()
    }

    /// Returns the number of startup paths awaiting consumption by the frontend.
    #[must_use]
    pub fn pending_startup_paths_count(&self) -> usize {
        self.lock_startup_paths().len()
    }
}
