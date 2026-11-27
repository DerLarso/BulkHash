use crate::core::hash_manager::HashAlgorithm;
use crate::core::io::bulk_hash_error::BulkHashError;
use crate::core::structs::file_metadata::FileMetadata;
use chrono::{DateTime, Utc};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SingleFileHash {
    path: String,
    file_name: String,
    hash: String,
    algorithm: HashAlgorithm,
    file_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified_utc: Option<DateTime<Utc>>,
    hash_time: Duration,
}

impl SingleFileHash {
    #[must_use]
    pub const fn new(
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
            modified_utc: None,
            hash_time,
        }
    }

    #[must_use]
    pub const fn with_modified_utc(mut self, modified_utc: DateTime<Utc>) -> Self {
        self.modified_utc = Some(modified_utc);
        self
    }

    #[must_use]
    pub fn get_path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn get_file_name(&self) -> &str {
        &self.file_name
    }

    #[must_use]
    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    #[must_use]
    pub const fn get_algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    #[must_use]
    pub const fn get_file_size(&self) -> u64 {
        self.file_size
    }

    #[must_use]
    pub const fn get_modified_utc(&self) -> Option<DateTime<Utc>> {
        self.modified_utc
    }

    #[must_use]
    pub const fn get_metadata(&self) -> FileMetadata {
        FileMetadata::new(Some(self.file_size), self.modified_utc)
    }

    #[must_use]
    pub const fn get_hash_time(&self) -> Duration {
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
