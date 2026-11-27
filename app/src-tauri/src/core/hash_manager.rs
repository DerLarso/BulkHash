use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::structs::{file_info::FileInfo, single_file_hash::SingleFileHash};
use md5::Md5;
use rayon::{ThreadPoolBuilder, prelude::*};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::fs::{self, File};
use std::hash::Hasher;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use xxhash_rust::xxh3::{Xxh3, xxh3_64, xxh3_128};
use xxhash_rust::xxh64::{Xxh64, xxh64};

const HASH_BUFFER_SIZE: usize = 64 * 1024;
const XXHASH64_SEED: u64 = 0;

pub struct HashManager {
    files_counted: usize,
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
            algorithm,
            buffer: vec![0u8; HASH_BUFFER_SIZE],
        }
    }

    pub fn get_hash_code(&mut self, path: impl AsRef<Path>) -> Result<String, BulkHashError> {
        self.get_hash_code_internal(path.as_ref(), None)
    }

    pub fn get_hash_code_cancellable(
        &mut self,
        path: impl AsRef<Path>,
        cancel_flag: &AtomicBool,
    ) -> Result<String, BulkHashError> {
        self.get_hash_code_internal(path.as_ref(), Some(cancel_flag))
    }

    fn get_hash_code_internal(
        &mut self,
        path_ref: &Path,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<String, BulkHashError> {
        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

        let path_display = path_ref.to_string_lossy().into_owned();
        let hash = hash_file_with_buffer(
            self.algorithm,
            &mut self.buffer,
            path_ref,
            &path_display,
            cancel_flag,
        )?;
        self.files_counted = self.files_counted.saturating_add(1);
        Ok(hash)
    }

    pub fn hash_single_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<SingleFileHash, BulkHashError> {
        self.hash_single_file_internal(path.as_ref(), None)
    }

    pub fn hash_single_file_cancellable(
        &mut self,
        path: impl AsRef<Path>,
        cancel_flag: &AtomicBool,
    ) -> Result<SingleFileHash, BulkHashError> {
        self.hash_single_file_internal(path.as_ref(), Some(cancel_flag))
    }

    fn hash_single_file_internal(
        &mut self,
        path_ref: &Path,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<SingleFileHash, BulkHashError> {
        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

        let path_display = path_ref.to_string_lossy().into_owned();
        let start_time = Instant::now();

        let metadata = fs::metadata(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !metadata.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        let file_size = metadata.len();
        let hash = hash_regular_file_with_buffer(
            self.algorithm,
            &mut self.buffer,
            path_ref,
            &path_display,
            cancel_flag,
        )?;
        self.files_counted = self.files_counted.saturating_add(1);
        let hash_time = start_time.elapsed();

        let file_name = path_ref
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path_display.clone());

        Ok(SingleFileHash::new(
            path_display,
            file_name,
            hash,
            self.algorithm,
            file_size,
            hash_time,
        ))
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
                .hash_files_sequential(paths, None)
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
        self.hash_files_with_threads_internal(paths, None, Some(cancel_flag))
    }

    pub fn hash_files_with_threads<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        self.hash_files_with_threads_internal(paths, thread_count, None)
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
        self.hash_files_with_threads_internal(paths, thread_count, Some(cancel_flag))
    }

    fn hash_files_with_threads_internal<P>(
        &mut self,
        paths: &[P],
        thread_count: Option<usize>,
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path> + Sync,
    {
        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

        if paths.is_empty() {
            return Ok(Vec::new());
        }

        let normalized_threads = thread_count.filter(|&count| count > 0);
        if paths.len() == 1 || normalized_threads == Some(1) {
            return self.hash_files_sequential(paths, cancel_flag);
        }

        let algorithm = self.algorithm;
        let run_parallel = || match cancel_flag {
            Some(flag) => hash_paths_parallel_cancellable(algorithm, paths, flag),
            None => Ok(hash_paths_parallel(algorithm, paths)),
        };

        let results = match normalized_threads {
            Some(num_threads) => {
                let pool_threads = num_threads.min(paths.len());
                let pool = ThreadPoolBuilder::new().num_threads(pool_threads).build()?;
                pool.install(run_parallel)?
            }
            None => run_parallel()?,
        };

        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn hash_files_sequential<P>(
        &mut self,
        paths: &[P],
        cancel_flag: Option<&AtomicBool>,
    ) -> Result<Vec<FileInfo>, BulkHashError>
    where
        P: AsRef<Path>,
    {
        let mut results = Vec::with_capacity(paths.len());

        for path in paths {
            if is_cancelled(cancel_flag) {
                return Err(BulkHashError::ScanCancelled);
            }

            let path_ref = path.as_ref();
            let path_display = path_ref.to_string_lossy().into_owned();
            let result = hash_file_with_buffer(
                self.algorithm,
                &mut self.buffer,
                path_ref,
                &path_display,
                cancel_flag,
            );
            if matches!(result, Err(BulkHashError::ScanCancelled)) {
                return Err(BulkHashError::ScanCancelled);
            }
            results.push(FileInfo::new(path_display, result));
        }

        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

        self.record_hashed_results(&results);
        Ok(results)
    }

    fn record_hashed_results(&mut self, results: &[FileInfo]) {
        let succeeded = results
            .iter()
            .filter(|info| info.get_result().is_ok())
            .count();
        self.files_counted = self.files_counted.saturating_add(succeeded);
    }

    pub fn get_files_counted(&self) -> usize {
        self.files_counted
    }

    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn set_algorithm(&mut self, algorithm: HashAlgorithm) {
        self.algorithm = algorithm;
    }

    pub fn reset_counter(&mut self) {
        self.files_counted = 0;
    }
}

#[inline]
fn is_cancelled(cancel_flag: Option<&AtomicBool>) -> bool {
    cancel_flag.is_some_and(|flag| flag.load(Ordering::Acquire))
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
                let result =
                    hash_file_with_buffer(algorithm, buffer, path_ref, &path_display, None);
                FileInfo::new(path_display, result)
            },
        )
        .collect()
}

fn hash_paths_parallel_cancellable<P>(
    algorithm: HashAlgorithm,
    paths: &[P],
    cancel_flag: &AtomicBool,
) -> Result<Vec<FileInfo>, BulkHashError>
where
    P: AsRef<Path> + Sync,
{
    paths
        .par_iter()
        .map_init(
            || vec![0u8; HASH_BUFFER_SIZE],
            |buffer, path| {
                if cancel_flag.load(Ordering::Acquire) {
                    return Err(BulkHashError::ScanCancelled);
                }

                let path_ref = path.as_ref();
                let path_display = path_ref.to_string_lossy().into_owned();
                let result = hash_file_with_buffer(
                    algorithm,
                    buffer,
                    path_ref,
                    &path_display,
                    Some(cancel_flag),
                );
                if matches!(result, Err(BulkHashError::ScanCancelled)) {
                    return Err(BulkHashError::ScanCancelled);
                }

                Ok(FileInfo::new(path_display, result))
            },
        )
        .collect()
}

fn hash_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    path_ref: &Path,
    path_display: &str,
    cancel_flag: Option<&AtomicBool>,
) -> Result<String, BulkHashError> {
    if is_cancelled(cancel_flag) {
        return Err(BulkHashError::ScanCancelled);
    }

    let metadata = fs::metadata(path_ref)
        .map_err(|err| BulkHashError::from_io(err, path_display.to_owned()))?;

    if !metadata.is_file() {
        return Err(BulkHashError::NotAFile(path_display.to_owned()));
    }

    hash_regular_file_with_buffer(algorithm, buffer, path_ref, path_display, cancel_flag)
}

fn hash_regular_file_with_buffer(
    algorithm: HashAlgorithm,
    buffer: &mut [u8],
    path_ref: &Path,
    path_display: &str,
    cancel_flag: Option<&AtomicBool>,
) -> Result<String, BulkHashError> {
    if is_cancelled(cancel_flag) {
        return Err(BulkHashError::ScanCancelled);
    }

    let mut file = File::open(path_ref).map_err(|err| BulkHashError::from_io(err, path_display))?;

    let hex_string = match algorithm {
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.update(chunk);
            })?;
            hasher.finalize().to_hex().to_string()
        }
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Sha512 => {
            let mut hasher = Sha512::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::Md5 => {
            let mut hasher = Md5::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.update(chunk);
            })?;
            hex::encode(hasher.finalize())
        }
        HashAlgorithm::XxHash64 => {
            let mut hasher = Xxh64::new(XXHASH64_SEED);
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.write(chunk);
            })?;
            format!("{:016x}", hasher.finish())
        }
        HashAlgorithm::XxHash3 => {
            let mut hasher = Xxh3::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
                hasher.update(chunk);
            })?;
            format!("{:016x}", hasher.digest())
        }
        HashAlgorithm::XxHash128 => {
            let mut hasher = Xxh3::new();
            stream_file_into(buffer, &mut file, path_display, cancel_flag, |chunk| {
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
    cancel_flag: Option<&AtomicBool>,
    mut update: impl FnMut(&[u8]),
) -> Result<(), BulkHashError> {
    loop {
        if is_cancelled(cancel_flag) {
            return Err(BulkHashError::ScanCancelled);
        }

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
