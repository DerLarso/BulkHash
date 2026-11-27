use crate::core::io::bulk_hash_error::BulkHashError;
pub use crate::core::structs::file_metadata::FileMetadata;
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub struct FileInfo {
    path: String,
    result: Result<String, BulkHashError>,
    metadata: FileMetadata,
}

impl FileInfo {
    #[must_use]
    pub const fn new(path: String, result: Result<String, BulkHashError>) -> Self {
        Self {
            path,
            result,
            metadata: FileMetadata::empty(),
        }
    }

    #[must_use]
    pub const fn with_metadata(
        path: String,
        result: Result<String, BulkHashError>,
        metadata: FileMetadata,
    ) -> Self {
        Self {
            path,
            result,
            metadata,
        }
    }

    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.metadata = self.metadata.with_size(size);
        self
    }

    #[must_use]
    pub const fn with_modified_utc(mut self, modified_utc: DateTime<Utc>) -> Self {
        self.metadata = self.metadata.with_modified_utc(modified_utc);
        self
    }

    #[must_use]
    pub fn get_path(&self) -> &str {
        &self.path
    }

    pub const fn get_result(&self) -> &Result<String, BulkHashError> {
        &self.result
    }

    #[must_use]
    pub const fn get_metadata(&self) -> FileMetadata {
        self.metadata
    }

    #[must_use]
    pub const fn get_size(&self) -> Option<u64> {
        self.metadata.size()
    }

    #[must_use]
    pub const fn get_modified_utc(&self) -> Option<DateTime<Utc>> {
        self.metadata.modified_utc()
    }
}
