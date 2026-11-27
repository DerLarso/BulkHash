use crate::core::hash_manager::{HashAlgorithm, HashManager};
use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::structs::file_info::FileInfo;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct ScanManager {
    file_list: Vec<FileInfo>,
    hasher: HashManager,
    start_path: String,
    hash_time: Duration,
}

impl ScanManager {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            file_list: Vec::new(),
            hasher: HashManager::new(algorithm),
            start_path: String::new(),
            hash_time: Duration::ZERO,
        }
    }

    pub fn start_hash(&mut self, path: String) -> Result<(), BulkHashError> {
        self.file_list.clear();
        self.hasher.reset_counter();
        self.hash_time = Duration::ZERO;
        self.start_path.clone_from(&path);

        let start_time = Instant::now();
        let root_path = Path::new(&path);

        let exists = root_path
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, path.clone()))?;

        if !exists {
            return Err(BulkHashError::PathNotFound(path));
        }

        let root_metadata =
            fs::metadata(root_path).map_err(|err| BulkHashError::from_io(err, path.clone()))?;

        if root_metadata.is_file() {
            let result = self.compute_hash(root_path);
            self.file_list.push(FileInfo::new(path, result));
        } else if root_metadata.is_dir() {
            // Verify the root directory itself is readable so top-level access errors surface directly.
            let initial_entries =
                fs::read_dir(root_path).map_err(|err| BulkHashError::from_io(err, path.clone()))?;
            self.scan_directory_iterative(initial_entries, root_path);
        }

        self.hash_time = start_time.elapsed();
        Ok(())
    }

    fn scan_directory_iterative(&mut self, initial_entries: fs::ReadDir, root_path: &Path) {
        let mut dir_stack: Vec<PathBuf> = Vec::new();
        self.process_read_dir(initial_entries, root_path, &mut dir_stack);

        while let Some(current_dir) = dir_stack.pop() {
            if Self::is_excluded_system_path(&current_dir) {
                continue;
            }

            match fs::read_dir(&current_dir) {
                Ok(entries) => self.process_read_dir(entries, &current_dir, &mut dir_stack),
                Err(err) => {
                    let dir_str = current_dir.to_string_lossy().into_owned();
                    self.file_list.push(FileInfo::new(
                        dir_str.clone(),
                        Err(BulkHashError::from_io(err, dir_str)),
                    ));
                }
            }
        }
    }

    fn process_read_dir(
        &mut self,
        entries: fs::ReadDir,
        parent_dir: &Path,
        dir_stack: &mut Vec<PathBuf>,
    ) {
        for entry_result in entries {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(err) => {
                    let parent_str = parent_dir.to_string_lossy().into_owned();
                    self.file_list.push(FileInfo::new(
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
                    self.file_list.push(FileInfo::new(
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
                let result = self.compute_hash(&entry_path);
                let entry_str = entry_path.to_string_lossy().into_owned();
                self.file_list.push(FileInfo::new(entry_str, result));
            } else if metadata.is_dir() {
                dir_stack.push(entry_path);
            }
        }
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
        self.hasher.get_hash_code(path)
    }

    pub fn get_hash_manager(&self) -> &HashManager {
        &self.hasher
    }

    pub fn get_path(&self) -> &str {
        &self.start_path
    }

    pub fn get_hash_time(&self) -> Duration {
        self.hash_time
    }
}
