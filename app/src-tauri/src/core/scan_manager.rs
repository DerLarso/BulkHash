use crate::core::hash_manager::{HashAlgorithm, HashManager};
use crate::core::io::bulk_hash_error::BulkHashError;
pub use crate::core::scan_control::{ScanCancelToken, ScanControl, ScanControlState};
use crate::core::structs::{file_info::FileInfo, single_file_hash::SingleFileHash};
use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

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
    paused_time: Duration,
    thread_count: Option<usize>,
    control: ScanControl,
}

impl ScanManager {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            file_list: Vec::new(),
            hasher: HashManager::new(algorithm),
            start_path: String::new(),
            hash_time: Duration::ZERO,
            paused_time: Duration::ZERO,
            thread_count: None,
            control: ScanControl::new(),
        }
    }

    pub fn with_thread_count(mut self, thread_count: usize) -> Self {
        self.thread_count = (thread_count > 0).then_some(thread_count);
        self
    }

    pub fn with_control(mut self, control: impl Into<ScanControl>) -> Self {
        self.control = control.into();
        self
    }

    pub fn with_cancel_token(mut self, cancel_token: impl Into<ScanCancelToken>) -> Self {
        self.control.set_cancel_token(cancel_token);
        self
    }

    pub fn set_thread_count(&mut self, thread_count: Option<usize>) {
        self.thread_count = thread_count.filter(|&count| count > 0);
    }

    pub fn set_control(&mut self, control: impl Into<ScanControl>) {
        self.control = control.into();
    }

    pub fn set_cancel_token(&mut self, cancel_token: impl Into<ScanCancelToken>) {
        self.control.set_cancel_token(cancel_token);
    }

    pub fn get_control(&self) -> ScanControl {
        self.control.clone()
    }

    pub fn get_cancel_token(&self) -> ScanCancelToken {
        self.control.cancel_token()
    }

    pub fn get_cancel_flag(&self) -> Arc<AtomicBool> {
        self.control.cancel_flag()
    }

    pub fn pause(&self) {
        self.control.pause();
    }

    pub fn resume(&self) {
        self.control.resume();
    }

    pub fn toggle_pause(&self) -> bool {
        self.control.toggle_pause()
    }

    pub fn is_paused(&self) -> bool {
        self.control.is_paused()
    }

    pub fn cancel(&self) {
        self.control.cancel();
    }

    pub fn reset_cancel(&self) {
        self.control.reset_cancel();
    }

    pub fn reset_control(&self) {
        self.control.reset();
    }

    pub fn is_cancelled(&self) -> bool {
        self.control.is_cancelled()
    }

    pub fn get_control_state(&self) -> ScanControlState {
        self.control.state()
    }

    pub fn get_thread_count(&self) -> Option<usize> {
        self.thread_count
    }

    pub fn effective_thread_count(&self) -> usize {
        self.thread_count.unwrap_or_else(rayon::current_num_threads)
    }

    pub fn start_hash(&mut self, path: String) -> Result<(), BulkHashError> {
        self.reset_state(&path);

        let timer = self.control.start_timer();
        self.control.checkpoint()?;

        let root_path = Path::new(&path);

        let exists = root_path
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, path.clone()))?;

        if !exists {
            return Err(BulkHashError::PathNotFound(path));
        }

        self.control.checkpoint()?;

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
            let mut discovered =
                Self::collect_directory_iterative(initial_entries, root_path, &self.control)?;

            self.control.checkpoint()?;

            // Schedule larger files first (LPT) so worker threads finish closer together.
            discovered
                .files
                .sort_unstable_by_key(|file| Reverse(file.size));

            let hashed_files = self.hasher.hash_files_with_threads_controlled(
                &discovered.files,
                self.thread_count,
                &self.control,
            )?;

            self.file_list
                .reserve(discovered.errors.len().saturating_add(hashed_files.len()));
            self.file_list.extend(discovered.errors);
            self.file_list.extend(hashed_files);
        } else {
            return Err(BulkHashError::NotAFile(path));
        }

        let (active_time, paused_time) = timer.finish(&self.control);
        self.hash_time = active_time;
        self.paused_time = paused_time;
        Ok(())
    }

    pub fn hash_files<P>(&mut self, paths: &[P]) -> Result<(), BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.reset_state("");

        let timer = self.control.start_timer();
        self.control.checkpoint()?;

        self.file_list = self.hasher.hash_files_with_threads_controlled(
            paths,
            self.thread_count,
            &self.control,
        )?;

        let (active_time, paused_time) = timer.finish(&self.control);
        self.hash_time = active_time;
        self.paused_time = paused_time;

        Ok(())
    }

    pub fn hash_single_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<SingleFileHash, BulkHashError> {
        let file_path = path.as_ref();
        let path_display = file_path.to_string_lossy().into_owned();
        self.reset_state(&path_display);

        let timer = self.control.start_timer();

        let result = self
            .hasher
            .hash_single_file_controlled(file_path, &self.control)?;

        let (_active_time, paused_time) = timer.finish(&self.control);
        self.hash_time = result.get_hash_time();
        self.paused_time = paused_time;
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
        self.paused_time = Duration::ZERO;
        self.start_path.clear();
        self.start_path.push_str(start_path);
    }

    fn collect_directory_iterative(
        initial_entries: fs::ReadDir,
        root_path: &Path,
        control: &ScanControl,
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
            control,
        )?;

        while let Some(current_dir) = dir_stack.pop() {
            control.checkpoint()?;

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
                        control,
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
        control: &ScanControl,
    ) -> Result<(), BulkHashError> {
        for entry_result in entries {
            control.checkpoint()?;

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
        self.hasher.get_hash_code_controlled(path, &self.control)
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

    pub fn get_paused_time(&self) -> Duration {
        self.paused_time
    }
}
