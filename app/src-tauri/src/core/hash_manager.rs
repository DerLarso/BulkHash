use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::scan_control::ScanControl;
use crate::core::structs::{
    file_info::FileInfo,
    file_metadata::{FileMetadata, system_time_to_utc},
    single_file_hash::SingleFileHash,
};
use md5::Md5;
use rayon::{ThreadPoolBuilder, prelude::*};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::fs::{self, File};
use std::hash::Hasher;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};
use xxhash_rust::xxh3::{Xxh3, xxh3_64, xxh3_128};
use xxhash_rust::xxh64::{Xxh64, xxh64};

const HASH_BUFFER_SIZE: usize = 64 * 1024;
const XXHASH64_SEED: u64 = 0;

pub(crate) struct DiscoveredFile {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
    pub(crate) modified: Option<SystemTime>,
}

#[derive(Clone, Copy)]
enum ExecutionControl<'a> {
    None,
    CancelOnly(&'a AtomicBool),
    Full(&'a ScanControl),
}

impl ExecutionControl<'_> {
    #[inline]
    fn is_cancelled(self) -> bool {
        match self {
            Self::None => false,
            Self::CancelOnly(flag) => flag.load(Ordering::Acquire),
            Self::Full(control) => control.is_cancelled(),
        }
    }

    #[inline]
    fn checkpoint(self) -> Result<(), BulkHashError> {
        match self {
            Self::None => Ok(()),
            Self::CancelOnly(flag) => {
                if flag.load(Ordering::Acquire) {
                    Err(BulkHashError::ScanCancelled)
                } else {
                    Ok(())
                }
            }
            Self::Full(control) => control.checkpoint(),
        }
    }
}

pub struct HashManager {
    files_counted: usize,
    bytes_hashed: u64,
    algorithm: HashAlgorithm,
    buffer: Vec<u8>,
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    #[default]
    Blake3,
    Md5,
    XxHash64,
    XxHash3,
    XxHash128,
}

impl HashManager {
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            files_counted: 0,
            bytes_hashed: 0,
            algorithm,
            buffer: vec![0u8; HASH_BUFFER_SIZE],
        }
    }

    pub fn get_hash_code(&mut self, path: impl AsRef<Path>) -> Result<String, BulkHashError> {
        self.get_hash_code_internal(path.as_ref(), ExecutionControl::None)
    }

    pub fn get_hash_code_cancellable(
        &mut self,
        path: impl AsRef<Path>,
        cancel_flag: &AtomicBool,
    ) -> Result<String, BulkHashError> {
        self.get_hash_code_internal(path.as_ref(), ExecutionControl::CancelOnly(cancel_flag))
    }

    pub fn get_hash_code_controlled(
        &mut self,
        path: impl AsRef<Path>,
        control: &ScanControl,
    ) -> Result<String, BulkHashError> {
        self.get_hash_code_internal(path.as_ref(), ExecutionControl::Full(control))
    }

    pub fn hash_file_info_controlled(
        &mut self,
        path: impl AsRef<Path>,
        control: &ScanControl,
    ) -> Result<FileInfo, BulkHashError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();
        let exec_control = ExecutionControl::Full(control);

        let info = hash_file_info_with_buffer(
            self.algorithm,
            &mut self.buffer,
            path_ref,
            path_display,
            exec_control,
        )?;
        if exec_control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        if info.get_result().is_ok() {
            self.files_counted = self.files_counted.saturating_add(1);
            if let Some(size) = info.get_size() {
                self.bytes_hashed = self.bytes_hashed.saturating_add(size);
            }
        }
        Ok(info)
    }

    fn get_hash_code_internal(
        &mut self,
        path_ref: &Path,
        control: ExecutionControl<'_>,
    ) -> Result<String, BulkHashError> {
        control.checkpoint()?;

        let path_display = path_ref.to_string_lossy().into_owned();
        let (hash, file_meta) = hash_file_with_buffer(
            self.algorithm,
            &mut self.buffer,
            path_ref,
            &path_display,
            control,
        )?;
        if control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }
        self.files_counted = self.files_counted.saturating_add(1);
        if let Some(size) = file_meta.size() {
            self.bytes_hashed = self.bytes_hashed.saturating_add(size);
        }
        Ok(hash)
    }

    pub fn hash_single_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<SingleFileHash, BulkHashError> {
        self.hash_single_file_internal(path.as_ref(), ExecutionControl::None)
    }

    pub fn hash_single_file_cancellable(
        &mut self,
        path: impl AsRef<Path>,
        cancel_flag: &AtomicBool,
    ) -> Result<SingleFileHash, BulkHashError> {
        self.hash_single_file_internal(path.as_ref(), ExecutionControl::CancelOnly(cancel_flag))
    }

    pub fn hash_single_file_controlled(
        &mut self,
        path: impl AsRef<Path>,
        control: &ScanControl,
    ) -> Result<SingleFileHash, BulkHashError> {
        self.hash_single_file_internal(path.as_ref(), ExecutionControl::Full(control))
    }

    fn hash_single_file_internal(
        &mut self,
        path_ref: &Path,
        control: ExecutionControl<'_>,
    ) -> Result<SingleFileHash, BulkHashError> {
        let timer = match control {
            ExecutionControl::Full(ctrl) => Some(ctrl.start_timer()),
            ExecutionControl::None | ExecutionControl::CancelOnly(_) => None,
        };
        let start_time = Instant::now();
        control.checkpoint()?;

        let path_display = path_ref.to_string_lossy().into_owned();
        let metadata = fs::metadata(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !metadata.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        let (hash, file_meta) = hash_regular_file_with_buffer(
            self.algorithm,
            &mut self.buffer,
            path_ref,
            &path_display,
            &metadata,
            control,
        )?;
        if control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }
        let file_size = file_meta.size().unwrap_or(metadata.len());
        self.files_counted = self.files_counted.saturating_add(1);
        self.bytes_hashed = self.bytes_hashed.saturating_add(file_size);
        let hash_time = match (control, timer) {
            (ExecutionControl::Full(ctrl), Some(t)) => t.finish(ctrl).0,
            _ => start_time.elapsed(),
        };

        let file_name = path_ref
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path_display.clone());

        let mut single = SingleFileHash::new(
            path_display,
            file_name,
            hash,
            self.algorithm,
            file_size,
            hash_time,
        );
        if let Some(modified_utc) = file_meta.modified_utc() {
            single = single.with_modified_utc(modified_utc);
        }

        Ok(single)
    }

    pub fn hash_files<P>(&mut self, paths: &[P]) -> Vec<FileInfo>
    where
        P: AsRef<Path> + Sync,
    {
        if paths.is_empty() {
            return Vec::new();
        }

        if paths.len() == 1 {
            return self
                .hash_files_sequential(paths, ExecutionControl::None)
                .unwrap_or_default();
        }

        let results = hash_paths_parallel(self.algorithm, paths);
        self.record_hashed_results(&results);
        results
    }

    pub fn hash_files_cancellable<P>(
        &mut self,
        paths: &[P],
        cancel_flag: &AtomicBool,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(
            paths,
            None,
            ExecutionControl::CancelOnly(cancel_flag),
        )
    }

    pub fn hash_files_controlled<P>(
        &mut self,
        paths: &[P],
        control: &ScanControl,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(paths, None, ExecutionControl::Full(control))
    }

    pub fn hash_files_with_threads<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(paths, thread_count, ExecutionControl::None)
    }

    pub fn hash_files_with_threads_cancellable<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
        cancel_flag: &AtomicBool,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(
            paths,
            thread_count,
            ExecutionControl::CancelOnly(cancel_flag),
        )
    }

    pub fn hash_files_with_threads_controlled<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
        control: &ScanControl,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(paths, thread_count, ExecutionControl::Full(control))
    }

    pub(crate) fn hash_discovered_files_controlled(
        &mut self,
        files: &[DiscoveredFile],
        thread_count: Option<usize>,
        control: &ScanControl,
    ) -> Result<Vec<FileInfo>, BulkHashError> {
        let exec_control = ExecutionControl::Full(control);
        exec_control.checkpoint()?;

        if files.is_empty() {
            return Ok(Vec::new());
        }

        let normalized_threads = thread_count.filter(|&count| count > 0);
        if files.len() == 1 || normalized_threads == Some(1) {
            return self.hash_discovered_sequential(files, exec_control);
        }

        let algorithm = self.algorithm;
        let run_parallel = || hash_discovered_parallel_controlled(algorithm, files, exec_control);

        let results = match normalized_threads {
            Some(num_threads) => {
                let pool_threads = num_threads.min(files.len());
                let pool = ThreadPoolBuilder::new().num_threads(pool_threads).build()?;
                pool.install(run_parallel)?
            }
            None => run_parallel()?,
        };

        if exec_control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn hash_discovered_sequential(
        &mut self,
        files: &[DiscoveredFile],
        control: ExecutionControl<'_>,
    ) -> Result<Vec<FileInfo>, BulkHashError> {
        let mut results = Vec::with_capacity(files.len());

        for file in files {
            control.checkpoint()?;
            let info =
                hash_discovered_file_with_buffer(self.algorithm, &mut self.buffer, file, control)?;
            results.push(info);
        }

        if control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn hash_files_with_threads_internal<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
        control: ExecutionControl<'_>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        control.checkpoint()?;

        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let normalized_threads = thread_count.filter(|&count| count > 0);
        if paths.len() == 1 || normalized_threads == Some(1) {
            return self.hash_files_sequential(paths, control);
        }

        let algorithm = self.algorithm;
        let run_parallel = || match control {
            ExecutionControl::None => Ok(hash_paths_parallel(algorithm, paths)),
            ExecutionControl::CancelOnly(_) | ExecutionControl::Full(_) => {
                hash_paths_parallel_controlled(algorithm, paths, control)
            }
        };

        let results = match normalized_threads {
            Some(num_threads) => {
                let pool_threads = num_threads.min(paths.len());
                let pool = ThreadPoolBuilder::new().num_threads(pool_threads).build()?;
                pool.install(run_parallel)?
            }
            None => run_parallel()?,
        };

        if control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn hash_files_sequential<P>(
        &mut self,
        paths: &[P],
        control: ExecutionControl<'_>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path>,
    {
        let mut results = Vec::with_capacity(paths.len());

        for path in paths {
            control.checkpoint()?;

            let path_ref = path.as_ref();
            let path_display = path_ref.to_string_lossy().into_owned();
            let info = hash_file_info_with_buffer(
                self.algorithm,
                &mut self.buffer,
                path_ref,
                path_display,
                control,
            )?;
            results.push(info);
        }

        if control.is_cancelled() {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn record_hashed_results(&mut self, results: &[FileInfo]) {
        let mut succeeded = 0usize;
        let mut bytes = 0u64;
        for info in results {
            if info.get_result().is_ok() {
                succeeded = succeeded.saturating_add(1);
                if let Some(size) = info.get_size() {
                    bytes = bytes.saturating_add(size);
                }
            }
        }
        self.files_counted = self.files_counted.saturating_add(succeeded);
        self.bytes_hashed = self.bytes_hashed.saturating_add(bytes);
    }

    #[must_use]
    pub const fn get_files_counted(&self) -> usize {
        self.files_counted
    }

    #[must_use]
    pub const fn get_bytes_hashed(&self) -> u64 {
        self.bytes_hashed
    }

    #[must_use]
    pub const fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn set_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.algorithm = algorithm;
    }

    pub fn reset_counter(&mut self) {
        self.files_counted = 0;
        self.bytes_hashed = 0;
    }
}

fn hash_paths_parallel<P>(algorithm: HashAlgorithm, paths: &[P]) -> Vec<FileInfo>
where
    P: AsRef<Path> + Sync,
{
    paths
        .par_iter()
        .map_init(
            || vec![0u8; HASH_BUFFER_SIZE],
            |buffer, path| {
                let path_ref = path.as_ref();
                let path_display = path_ref.to_string_lossy().into_owned();
                hash_file_info_with_buffer(
                    algorithm,
                    buffer,
                    path_ref,
                    path_display.clone(),
                    ExecutionControl::None,
                )
                .unwrap_or_else(|err| FileInfo::new(path_display, Err(err)))
            },
        )
        .collect()
}

fn hash_paths_parallel_controlled<P>(
    algorithm: HashAlgorithm,
    paths: &[P],
    control: ExecutionControl<'_>,
) -> Result<Vec<FileInfo>, BulkHashError>
where
    P: AsRef<Path> + Sync,
{
    paths
        .par_iter()
        .map_init(
            || vec![0u8; HASH_BUFFER_SIZE],
            |buffer, path| {
                control.checkpoint()?;

                let path_ref = path.as_ref();
                let path_display = path_ref.to_string_lossy().into_owned();
                hash_file_info_with_buffer(algorithm, buffer, path_ref, path_display, control)
            },
        )
        .collect()
}

fn hash_discovered_parallel_controlled(
    algorithm: HashAlgorithm,
    files: &[DiscoveredFile],
    control: ExecutionControl<'_>,
) -> Result<Vec<FileInfo>, BulkHashError> {
    files
        .par_iter()
        .map_init(
            || vec![0u8; HASH_BUFFER_SIZE],
            |buffer, file| {
                control.checkpoint()?;
                hash_discovered_file_with_buffer(algorithm, buffer, file, control)
            },
        )
        .collect()
}

fn hash_discovered_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    discovered: &DiscoveredFile,
    control: ExecutionControl<'_>,
) -> Result<FileInfo, BulkHashError> {
    control.checkpoint()?;

    let path_ref = discovered.path.as_path();
    let path_display = path_ref.to_string_lossy().into_owned();

    let mut file = match File::open(path_ref) {
        Ok(file) => file,
        Err(err) => {
            if err.kind() == io::ErrorKind::PermissionDenied
                && fs::metadata(path_ref).is_ok_and(|meta| !meta.is_file())
            {
                return Ok(FileInfo::new(
                    path_display.clone(),
                    Err(BulkHashError::NotAFile(path_display)),
                ));
            }
            let fallback_meta = if err.kind() == io::ErrorKind::NotFound {
                FileMetadata::empty()
            } else {
                FileMetadata::new(
                    Some(discovered.size),
                    discovered.modified.and_then(system_time_to_utc),
                )
            };
            return Ok(FileInfo::with_metadata(
                path_display.clone(),
                Err(BulkHashError::from_io(err, path_display)),
                fallback_meta,
            ));
        }
    };

    let file_metadata = match file.metadata() {
        Ok(open_meta) => {
            if !open_meta.is_file() {
                return Ok(FileInfo::new(
                    path_display.clone(),
                    Err(BulkHashError::NotAFile(path_display)),
                ));
            }
            FileMetadata::from_fs_metadata(&open_meta)
        }
        Err(_) => FileMetadata::new(
            Some(discovered.size),
            discovered.modified.and_then(system_time_to_utc),
        ),
    };

    match hash_open_file_with_buffer(algorithm, buffer, &mut file, &path_display, control) {
        Ok(hash) => Ok(FileInfo::with_metadata(path_display, Ok(hash), file_metadata)),
        Err(BulkHashError::ScanCancelled) => Err(BulkHashError::ScanCancelled),
        Err(err) => Ok(FileInfo::with_metadata(path_display, Err(err), file_metadata)),
    }
}

fn hash_file_info_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    path_ref: &Path,
    path_display: String,
    control: ExecutionControl<'_>,
) -> Result<FileInfo, BulkHashError> {
    control.checkpoint()?;

    let initial_metadata = match fs::metadata(path_ref) {
        Ok(meta) => meta,
        Err(err) => {
            return Ok(FileInfo::new(
                path_display.clone(),
                Err(BulkHashError::from_io(err, path_display)),
            ));
        }
    };

    if !initial_metadata.is_file() {
        return Ok(FileInfo::new(
            path_display.clone(),
            Err(BulkHashError::NotAFile(path_display)),
        ));
    }

    match hash_regular_file_with_buffer(
        algorithm,
        buffer,
        path_ref,
        &path_display,
        &initial_metadata,
        control,
    ) {
        Ok((hash, file_meta)) => Ok(FileInfo::with_metadata(path_display, Ok(hash), file_meta)),
        Err(BulkHashError::ScanCancelled) => Err(BulkHashError::ScanCancelled),
        Err(err) => Ok(FileInfo::with_metadata(
            path_display,
            Err(err),
            FileMetadata::from_fs_metadata(&initial_metadata),
        )),
    }
}

fn hash_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    path_ref: &Path,
    path_display: &str,
    control: ExecutionControl<'_>,
) -> Result<(String, FileMetadata), BulkHashError> {
    control.checkpoint()?;

    let metadata = fs::metadata(path_ref)
        .map_err(|err| BulkHashError::from_io(err, path_display.to_owned()))?;

    if !metadata.is_file() {
        return Err(BulkHashError::NotAFile(path_display.to_owned()));
    }

    hash_regular_file_with_buffer(algorithm, buffer, path_ref, path_display, &metadata, control)
}

fn hash_regular_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    path_ref: &Path,
    path_display: &str,
    fallback_metadata: &fs::Metadata,
    control: ExecutionControl<'_>,
) -> Result<(String, FileMetadata), BulkHashError> {
    let mut file = File::open(path_ref).map_err(|err| BulkHashError::from_io(err, path_display))?;
    let file_metadata = match file.metadata() {
        Ok(open_meta) => {
            if !open_meta.is_file() {
                return Err(BulkHashError::NotAFile(path_display.to_owned()));
            }
            FileMetadata::from_fs_metadata(&open_meta)
        }
        Err(_) => FileMetadata::from_fs_metadata(fallback_metadata),
    };

    let hex_string = hash_open_file_with_buffer(algorithm, buffer, &mut file, path_display, control)?;
    Ok((hex_string, file_metadata))
}

fn hash_open_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    file: &mut File,
    path_display: &str,
    control: ExecutionControl<'_>,
) -> Result<String, BulkHashError> {
    let hex_string = match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            hasher.finalize().to_hex().to_string()
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::XxHash64 => {
            let mut hasher = Xxh64::new(XXHASH64_SEED);
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.write(chunk);
            })?;
            format!("{:016x}", hasher.finish())
        }
        HashAlgorithm::XxHash3 => {
            let mut hasher = Xxh3::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            format!("{:016x}", hasher.digest())
        }
        HashAlgorithm::XxHash128 => {
            let mut hasher = Xxh3::new();
            stream_file_into(buffer, file, path_display, control, |chunk| {
                hasher.update(chunk);
            })?;
            format!("{:032x}", hasher.digest128())
        }
    };

    Ok(hex_string)
}

fn stream_file_into(
    buffer: &mut [u8],
    file: &mut File,
    path_display: &str,
    control: ExecutionControl<'_>,
    mut update: impl FnMut(&[u8]),
) -> Result<(), BulkHashError> {
    loop {
        control.checkpoint()?;

        match file.read(buffer) {
            Ok(0) => return Ok(()),
            Ok(read_bytes) => {
                if let Some(chunk) = buffer.get(..read_bytes) {
                    update(chunk);
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
            Err(err) => return Err(BulkHashError::from_io(err, path_display)),
        }
    }
}

impl HashAlgorithm {
    pub const ALL: &'static [Self] = &[
        Self::Blake3,
        Self::Sha256,
        Self::Sha512,
        Self::Md5,
        Self::XxHash64,
        Self::XxHash3,
        Self::XxHash128,
    ];

    pub const fn all() -> &'static [Self] {
        Self::ALL
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Blake3 => "BLAKE3",
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Md5 => "MD5",
            Self::XxHash64 => "XXH64",
            Self::XxHash3 => "XXH3-64",
            Self::XxHash128 => "XXH3-128",
        }
    }

    pub const fn is_cryptographic(self) -> bool {
        matches!(self, Self::Blake3 | Self::Sha256 | Self::Sha512)
    }

    pub const fn hex_len(self) -> usize {
        match self {
            Self::XxHash64 | Self::XxHash3 => 16,
            Self::Md5 | Self::XxHash128 => 32,
            Self::Sha256 | Self::Blake3 => 64,
            Self::Sha512 => 128,
        }
    }

    pub fn get_hash_from_bytes(self, bytes: &[u8]) -> String {
        match self {
            Self::Blake3 => blake3::hash(bytes).to_hex().to_string(),
            Self::Sha256 => hex::encode(Sha256::digest(bytes)),
            Self::Sha512 => hex::encode(Sha512::digest(bytes)),
            Self::Md5 => hex::encode(Md5::digest(bytes)),
            Self::XxHash64 => format!("{:016x}", xxh64(bytes, XXHASH64_SEED)),
            Self::XxHash3 => format!("{:016x}", xxh3_64(bytes)),
            Self::XxHash128 => format!("{:032x}", xxh3_128(bytes)),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

impl FromStr for HashAlgorithm {
    type Err = BulkHashError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized: String = s
            .trim()
            .chars()
            .filter(|c| !matches!(c, '-' | '_' | ' '))
            .flat_map(char::to_lowercase)
            .collect();

        match normalized.as_str() {
            "blake3" | "b3" => Ok(Self::Blake3),
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            "md5" => Ok(Self::Md5),
            "xxh64" | "xxhash64" => Ok(Self::XxHash64),
            "xxh3" | "xxh364" | "xxhash3" | "xxhash364" => Ok(Self::XxHash3),
            "xxh128" | "xxh3128" | "xxhash128" | "xxhash3128" | "xxhash" => Ok(Self::XxHash128),
            _ => Err(BulkHashError::UnsupportedAlgorithm(s.trim().to_string())),
        }
    }
}
