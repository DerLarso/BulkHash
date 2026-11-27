use crate::core::io::bulk_hash_error::BulkHashError;

#[derive(Debug)]
pub struct FileInfo {
    path: String,
    result: Result<String, BulkHashError>,
}

impl FileInfo {
    pub fn new(path: String, result: Result<String, BulkHashError>) -> Self {
        Self { path, result }
    }

    pub fn get_path(&self) -> &str {
        &self.path
    }

    pub fn get_result(&self) -> &Result<String, BulkHashError> {
        &self.result
    }
}
