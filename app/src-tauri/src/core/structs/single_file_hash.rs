use crate::core::hash_manager::HashAlgorithm;
use crate::core::io::bulk_hash_error::BulkHashError;
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleFileHash {
    path: String,
    file_name: String,
    hash: String,
    algorithm: HashAlgorithm,
    file_size: u64,
    hash_time: Duration,
}

impl SingleFileHash {
    pub fn new(
        path: String,
        file_name: String,
        hash: String,
        algorithm: HashAlgorithm,
        file_size: u64,
        hash_time: Duration,
    ) -> Self {
        Self {
            path,
            file_name,
            hash,
            algorithm,
            file_size,
            hash_time,
        }
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }

    pub fn get_file_name(&self) -> &str {
        &self.file_name
    }

    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    pub fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    pub fn get_file_size(&self) -> u64 {
        self.file_size
    }

    pub fn get_hash_time(&self) -> Duration {
        self.hash_time
    }

    pub fn verify_hash(&self, expected_hash: &str) -> Result<(), BulkHashError> {
        let trimmed = expected_hash.trim();
        if self.hash.eq_ignore_ascii_case(trimmed) {
            Ok(())
        } else {
            Err(BulkHashError::HashMismatch {
                expected: trimmed.to_string(),
                actual: self.hash.clone(),
            })
        }
    }
}
