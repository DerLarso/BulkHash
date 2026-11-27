use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::structs::single_file_hash::SingleFileHash;
use md5::Md5;
use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::fs::{self, File};
use std::hash::Hasher;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;
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
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();

        let metadata = fs::metadata(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !metadata.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        self.hash_regular_file(path_ref, &path_display)
    }

    pub fn hash_single_file(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<SingleFileHash, BulkHashError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();
        let start_time = Instant::now();

        let metadata = fs::metadata(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !metadata.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        let file_size = metadata.len();
        let hash = self.hash_regular_file(path_ref, &path_display)?;
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

    fn hash_regular_file(
        &mut self,
        path_ref: &Path,
        path_display: &str,
    ) -> Result<String, BulkHashError> {
        let mut file =
            File::open(path_ref).map_err(|err| BulkHashError::from_io(err, path_display))?;

        let hex_string = match self.algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                self.stream_file_into(&mut file, path_display, |chunk| {
                    hasher.update(chunk);
                })?;
                hasher.finalize().to_hex().to_string()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                self.stream_file_into(&mut file, path_display, |chunk| hasher.update(chunk))?;
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                self.stream_file_into(&mut file, path_display, |chunk| hasher.update(chunk))?;
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Md5 => {
                let mut hasher = Md5::new();
                self.stream_file_into(&mut file, path_display, |chunk| hasher.update(chunk))?;
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::XxHash64 => {
                let mut hasher = Xxh64::new(XXHASH64_SEED);
                self.stream_file_into(&mut file, path_display, |chunk| hasher.write(chunk))?;
                format!("{:016x}", hasher.finish())
            }
            HashAlgorithm::XxHash3 => {
                let mut hasher = Xxh3::new();
                self.stream_file_into(&mut file, path_display, |chunk| hasher.update(chunk))?;
                format!("{:016x}", hasher.digest())
            }
            HashAlgorithm::XxHash128 => {
                let mut hasher = Xxh3::new();
                self.stream_file_into(&mut file, path_display, |chunk| hasher.update(chunk))?;
                format!("{:032x}", hasher.digest128())
            }
        };

        self.files_counted = self.files_counted.saturating_add(1);

        Ok(hex_string)
    }

    fn stream_file_into(
        &mut self,
        file: &mut File,
        path_display: &str,
        mut update: impl FnMut(&[u8]),
    ) -> Result<(), BulkHashError> {
        loop {
            match file.read(&mut self.buffer) {
                Ok(0) => return Ok(()),
                Ok(read_bytes) => {
                    if let Some(chunk) = self.buffer.get(..read_bytes) {
                        update(chunk);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                Err(err) => return Err(BulkHashError::from_io(err, path_display)),
            }
        }
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
