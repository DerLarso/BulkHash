use std::fmt;
use std::io;

#[derive(Debug)]
pub enum BulkHashError {
    PathNotFound(String),
    FileNotFound(String),
    InvalidEnding(String),
    HashMismatch { expected: String, actual: String },
    UnsupportedVersion(usize),
    FileIsCorrupted(String),
    Io(io::Error),
    JsonError(serde_json::Error),
    ZipError(zip::result::ZipError),
}

impl fmt::Display for BulkHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BulkHashError::PathNotFound(path) => write!(f, "Path not found: {}", path),
            BulkHashError::FileNotFound(file) => write!(f, "File not found: {}", file),
            BulkHashError::InvalidEnding(ending) => {
                write!(f, "Invalid file extension: {}", ending)
            }
            BulkHashError::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "Hash mismatch: expected '{}', got '{}'",
                    expected, actual
                )
            }
            BulkHashError::UnsupportedVersion(version) => {
                write!(f, "Unsupported version: {}", version)
            }
            BulkHashError::FileIsCorrupted(file) => write!(f, "File is corrupted: {}", file),
            BulkHashError::Io(e) => write!(f, "I/O error: {}", e),
            BulkHashError::JsonError(e) => write!(f, "JSON parsing error: {}", e),
            BulkHashError::ZipError(e) => write!(f, "ZIP archive error: {}", e),
        }
    }
}

impl std::error::Error for BulkHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BulkHashError::Io(e) => Some(e),
            BulkHashError::ZipError(e) => Some(e),
            BulkHashError::JsonError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for BulkHashError {
    fn from(err: io::Error) -> Self {
        BulkHashError::Io(err)
    }
}

impl From<serde_json::Error> for BulkHashError {
    fn from(err: serde_json::Error) -> Self {
        BulkHashError::JsonError(err)
    }
}

impl From<zip::result::ZipError> for BulkHashError {
    fn from(err: zip::result::ZipError) -> Self {
        BulkHashError::ZipError(err)
    }
}
