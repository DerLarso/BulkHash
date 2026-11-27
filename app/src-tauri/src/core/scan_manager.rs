use crate::core::hash_manager::{HashAlgorithm, HashManager};
use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::structs::{file_info::FileInfo, single_file_hash::SingleFileHash};
use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
pub struct ScanCancelToken {
    cancelled: Arc<AtomicBool>,
}

impl ScanCancelToken {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    #[must_use]
    pub fn from_atomic(flag: Arc<AtomicBool>) -> Self {
        Self { cancelled: flag }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn reset(&self) {
        self.cancelled.store(false, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn as_atomic(&self) -> &AtomicBool {
        &self.cancelled
    }

    #[must_use]
    pub fn clone_atomic(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }
}

impl From<Arc<AtomicBool>> for ScanCancelToken {
    fn from(flag: Arc<AtomicBool>) -> Self {
        Self::from_atomic(flag)
    }
}

impl AsRef<AtomicBool> for ScanCancelToken {
    fn as_ref(&self) -> &AtomicBool {
        self.as_atomic()
    }
}

struct DiscoveredFile {
    path: PathBuf,
    size: u64,
}

impl AsRef<Path> for DiscoveredFile {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

struct DiscoveredEntries {
    files: Vec<DiscoveredFile>,
    errors: Vec<FileInfo>,
}

pub struct ScanManager {
    file_list: Vec<FileInfo>,
    hasher: HashManager,
    start_path: String,
    hash_time: Duration,
    thread_count: Option<usize>,
    cancel_token: ScanCancelToken,
}

impl ScanManager {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            file_list: Vec::new(),
            hasher: HashManager::new(algorithm),
            start_path: String::new(),
            hash_time: Duration::ZERO,
            thread_count: None,
            cancel_token: ScanCancelToken::new(),
        }
    }

    pub fn with_thread_count(mut self, thread_count: usize) -> Self {
        self.thread_count = (thread_count > 0).then_some(thread_count);
        self
    }

    pub fn with_cancel_token(mut self, cancel_token: impl Into<ScanCancelToken>) -> Self {
        self.cancel_token = cancel_token.into();
        self
    }

    pub fn set_thread_count(&mut self, thread_count: Option<usize>) {
        self.thread_count = thread_count.filter(|&count| count > 0);
    }

    pub fn set_cancel_token(&mut self, cancel_token: impl Into<ScanCancelToken>) {
        self.cancel_token = cancel_token.into();
    }

    pub fn get_cancel_token(&self) -> ScanCancelToken {
        self.cancel_token.clone()
    }

    pub fn get_cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel_token.clone_atomic()
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    pub fn reset_cancel(&self) {
        self.cancel_token.reset();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel_token.is_cancelled()
    }

    pub fn get_thread_count(&self) -> Option<usize> {
        self.thread_count
    }

    pub fn effective_thread_count(&self) -> usize {
        self.thread_count.unwrap_or_else(rayon::current_num_threads)
    }

    pub fn start_hash(&mut self, path: String) -> Result<(), BulkHashError> {
        self.reset_state(&path);

        if self.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        let start_time = Instant::now();
        let root_path = Path::new(&path);

        let exists = root_path
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, path.clone()))?;

        if !exists {
            return Err(BulkHashError::PathNotFound(path));
        }

        if self.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        let root_metadata =
            fs::metadata(root_path).map_err(|err| BulkHashError::from_io(err, path.clone()))?;

        if root_metadata.is_file() {
            match self.compute_hash(root_path) {
                Err(BulkHashError::ScanCancelled) => return Err(BulkHashError::ScanCancelled),
                result => self.file_list.push(FileInfo::new(path, result)),
            }
        } else if root_metadata.is_dir() {
            // Verify the root directory itself is readable so top-level access errors surface directly.
            let initial_entries =
                fs::read_dir(root_path).map_err(|err| BulkHashError::from_io(err, path.clone()))?;
            let mut discovered = Self::collect_directory_iterative(
                initial_entries,
                root_path,
                self.cancel_token.as_atomic(),
            )?;

            if self.is_cancelled() {
                return Err(BulkHashError::ScanCancelled);
            }

            // Schedule larger files first (LPT) so worker threads finish closer together.
            discovered
                .files
                .sort_unstable_by_key(|file| Reverse(file.size));

            let hashed_files = self.hasher.hash_files_with_threads_cancellable(
                &discovered.files,
                self.thread_count,
                self.cancel_token.as_atomic(),
            )?;

            self.file_list
                .reserve(discovered.errors.len().saturating_add(hashed_files.len()));
            self.file_list.extend(discovered.errors);
            self.file_list.extend(hashed_files);
        } else {
            return Err(BulkHashError::NotAFile(path));
        }

        self.hash_time = start_time.elapsed();
        Ok(())
    }

    pub fn hash_files<P>(&mut self, paths: &[P]) -> Result<(), BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.reset_state("");

        if self.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        let start_time = Instant::now();
        self.file_list = self.hasher.hash_files_with_threads_cancellable(
            paths,
            self.thread_count,
            self.cancel_token.as_atomic(),
        )?;
        self.hash_time = start_time.elapsed();

        Ok(())
    }

    pub fn hash_single_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<SingleFileHash, BulkHashError> {
        let file_path = path.as_ref();
        let path_display = file_path.to_string_lossy().into_owned();
        self.reset_state(&path_display);

        if self.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        let result = self
            .hasher
            .hash_single_file_cancellable(file_path, self.cancel_token.as_atomic())?;

        self.hash_time = result.get_hash_time();
        self.file_list.push(FileInfo::new(
            result.get_path().to_string(),
            Ok(result.get_hash().to_string()),
        ));

        Ok(result)
    }

    fn reset_state(&mut self, start_path: &str) {
        self.file_list.clear();
        self.hasher.reset_counter();
        self.hash_time = Duration::ZERO;
        self.start_path.clear();
        self.start_path.push_str(start_path);
    }

    fn collect_directory_iterative(
        initial_entries: fs::ReadDir,
        root_path: &Path,
        cancel_flag: &AtomicBool,
    ) -> Result<DiscoveredEntries, BulkHashError> {
        let mut discovered = DiscoveredEntries {
            files: Vec::new(),
            errors: Vec::new(),
        };
        let mut dir_stack: Vec<PathBuf> = Vec::new();
        Self::process_read_dir(
            initial_entries,
            root_path,
            &mut dir_stack,
            &mut discovered,
            cancel_flag,
        )?;

        while let Some(current_dir) = dir_stack.pop() {
            if cancel_flag.load(Ordering::Acquire) {
                return Err(BulkHashError::ScanCancelled);
            }

            if Self::is_excluded_system_path(&current_dir) {
                continue;
            }

            match fs::read_dir(&current_dir) {
                Ok(entries) => {
                    Self::process_read_dir(
                        entries,
                        &current_dir,
                        &mut dir_stack,
                        &mut discovered,
                        cancel_flag,
                    )?;
                }
                Err(err) => {
                    let dir_str = current_dir.to_string_lossy().into_owned();
                    discovered.errors.push(FileInfo::new(
                        dir_str.clone(),
                        Err(BulkHashError::from_io(err, dir_str)),
                    ));
                }
            }
        }

        Ok(discovered)
    }

    fn process_read_dir(
        entries: fs::ReadDir,
        parent_dir: &Path,
        dir_stack: &mut Vec<PathBuf>,
        discovered: &mut DiscoveredEntries,
        cancel_flag: &AtomicBool,
    ) -> Result<(), BulkHashError> {
        for entry_result in entries {
            if cancel_flag.load(Ordering::Acquire) {
                return Err(BulkHashError::ScanCancelled);
            }

            let entry = match entry_result {
                Ok(entry) => entry,
                Err(err) => {
                    let parent_str = parent_dir.to_string_lossy().into_owned();
                    discovered.errors.push(FileInfo::new(
                        parent_str.clone(),
                        Err(BulkHashError::from_io(err, parent_str)),
                    ));
                    continue;
                }
            };

            let entry_path = entry.path();
            if Self::is_excluded_system_path(&entry_path) {
                continue;
            }

            let metadata = match entry_path.symlink_metadata() {
                Ok(meta) => meta,
                Err(err) => {
                    let entry_str = entry_path.to_string_lossy().into_owned();
                    discovered.errors.push(FileInfo::new(
                        entry_str.clone(),
                        Err(BulkHashError::from_io(err, entry_str)),
                    ));
                    continue;
                }
            };

            if metadata.is_symlink() {
                continue;
            }

            if metadata.is_file() {
                discovered.files.push(DiscoveredFile {
                    path: entry_path,
                    size: metadata.len(),
                });
            } else if metadata.is_dir() {
                dir_stack.push(entry_path);
            }
        }

        Ok(())
    }

    fn is_excluded_system_path(path: &Path) -> bool {
        if cfg!(target_os = "linux")
            && (path.starts_with("/proc")
                || path.starts_with("/sys")
                || path.starts_with("/dev")
                || path.starts_with("/run"))
        {
            return true;
        }

        if cfg!(target_os = "windows")
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
            && (name.eq_ignore_ascii_case("pagefile.sys")
                || name.eq_ignore_ascii_case("hiberfil.sys")
                || name.eq_ignore_ascii_case("swapfile.sys"))
        {
            return true;
        }

        false
    }

    pub fn get_list(&self) -> &[FileInfo] {
        &self.file_list
    }

    fn compute_hash(&mut self, path: &Path) -> Result<String, BulkHashError> {
        self.hasher
            .get_hash_code_cancellable(path, self.cancel_token.as_atomic())
    }

    pub fn get_hash_manager(&self) -> &HashManager {
        &self.hasher
    }

    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.hasher.get_algorithm()
    }

    pub fn set_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.hasher.set_algorithm(algorithm);
    }

    pub fn get_path(&self) -> &str {
        &self.start_path
    }

    pub fn get_hash_time(&self) -> Duration {
        self.hash_time
    }
}
