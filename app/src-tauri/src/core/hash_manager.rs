use crate::core::io::bulk_hash_error::BulkHashError;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const HASH_BUFFER_SIZE: usize = 64 * 1024;

pub struct HashManager {
    files_counted: usize,
    algorithm: HashAlgorithm,
    buffer: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
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

        let mut file = File::open(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        let hex_string = match self.algorithm {
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();

                loop {
                    match file.read(&mut self.buffer) {
                        Ok(0) => break,
                        Ok(read_bytes) => {
                            if let Some(chunk) = self.buffer.get(..read_bytes) {
                                hasher.update(chunk);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => return Err(BulkHashError::from_io(err, path_display)),
                    }
                }

                hasher.finalize().to_hex().to_string()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();

                loop {
                    match file.read(&mut self.buffer) {
                        Ok(0) => break,
                        Ok(read_bytes) => {
                            if let Some(chunk) = self.buffer.get(..read_bytes) {
                                hasher.update(chunk);
                            }
                        }
                        Err(err) if err.kind() == io::ErrorKind::Interrupted => {}
                        Err(err) => return Err(BulkHashError::from_io(err, path_display)),
                    }
                }

                hex::encode(hasher.finalize())
            }
        };

        self.files_counted = self.files_counted.saturating_add(1);

        Ok(hex_string)
    }

    pub fn get_files_counted(&self) -> usize {
        self.files_counted
    }

    pub fn reset_counter(&mut self) {
        self.files_counted = 0;
    }
}

impl HashAlgorithm {
    pub fn get_hash_from_bytes(self, bytes: &[u8]) -> String {
        match self {
            Self::Blake3 => blake3::hash(bytes).to_hex().to_string(),
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                hex::encode(hasher.finalize())
            }
        }
    }
}
