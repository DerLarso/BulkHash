use crate::core::io::migration::{CURRENT_FORMAT_VERSION, MIN_SUPPORTED_FORMAT_VERSION};
use serde::ser::SerializeStruct;
use std::fmt;
use std::io;

#[derive(Debug)]
pub enum BulkHashError {
    PathNotFound(String),
    FileNotFound(String),
    NotADirectory(String),
    NotAFile(String),
    PermissionDenied(String),
    InvalidEnding(String),
    HashMismatch {
        expected: String,
        actual: String,
    },
    UnsupportedAlgorithm(String),
    UnsupportedVersion(usize),
    MigrationFailed {
        from_version: usize,
        to_version: usize,
        reason: String,
    },
    InvalidIgnorePattern {
        pattern: String,
        reason: String,
    },
    PasswordRequired(String),
    EmptyPassword,
    DecryptionFailed(String),
    EncryptionFailed(String),
    InvalidEncryptionParameters(String),
    InvalidCompressionLevel(String),
    SnapshotNotEncrypted(String),
    FileIsCorrupted(String),
    ScanCancelled,
    Io {
        path: Option<String>,
        source: io::Error,
    },
    JsonError(serde_json::Error),
    ZipError(zip::result::ZipError),
    ThreadPoolError(rayon::ThreadPoolBuildError),
    TauriError(tauri::Error),
}

impl BulkHashError {
    pub fn from_io(source: io::Error, path: impl Into<String>) -> Self {
        let path = path.into();
        match source.kind() {
            io::ErrorKind::NotFound => Self::FileNotFound(path),
            io::ErrorKind::PermissionDenied => Self::PermissionDenied(path),
            _ => Self::Io {
                path: Some(path),
                source,
            },
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::PathNotFound(_) => "PathNotFound",
            Self::FileNotFound(_) => "FileNotFound",
            Self::NotADirectory(_) => "NotADirectory",
            Self::NotAFile(_) => "NotAFile",
            Self::PermissionDenied(_) => "PermissionDenied",
            Self::InvalidEnding(_) => "InvalidEnding",
            Self::HashMismatch { .. } => "HashMismatch",
            Self::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
            Self::UnsupportedVersion(_) => "UnsupportedVersion",
            Self::MigrationFailed { .. } => "MigrationFailed",
            Self::InvalidIgnorePattern { .. } => "InvalidIgnorePattern",
            Self::PasswordRequired(_) => "PasswordRequired",
            Self::EmptyPassword => "EmptyPassword",
            Self::DecryptionFailed(_) => "DecryptionFailed",
            Self::EncryptionFailed(_) => "EncryptionFailed",
            Self::InvalidEncryptionParameters(_) => "InvalidEncryptionParameters",
            Self::InvalidCompressionLevel(_) => "InvalidCompressionLevel",
            Self::SnapshotNotEncrypted(_) => "SnapshotNotEncrypted",
            Self::FileIsCorrupted(_) => "FileIsCorrupted",
            Self::ScanCancelled => "ScanCancelled",
            Self::Io { .. } => "Io",
            Self::JsonError(_) => "JsonError",
            Self::ZipError(_) => "ZipError",
            Self::ThreadPoolError(_) => "ThreadPoolError",
            Self::TauriError(_) => "TauriError",
        }
    }

    pub const fn is_cancelled(&self) -> bool {
        matches!(self, Self::ScanCancelled)
    }

    pub const fn is_password_required(&self) -> bool {
        matches!(self, Self::PasswordRequired(_))
    }
}

impl fmt::Display for BulkHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathNotFound(path) => write!(f, "Path not found: {path}"),
            Self::FileNotFound(file) => write!(f, "File not found: {file}"),
            Self::NotADirectory(path) => write!(f, "Path is not a directory: {path}"),
            Self::NotAFile(path) => write!(f, "Path is not a file: {path}"),
            Self::PermissionDenied(path) => write!(f, "Permission denied: {path}"),
            Self::InvalidEnding(ending) => write!(f, "Invalid file extension: {ending}"),
            Self::HashMismatch { expected, actual } => {
                write!(f, "Hash mismatch: expected '{expected}', got '{actual}'")
            }
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "Unsupported hash algorithm: {algorithm}")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    f,
                    "Unsupported snapshot format version: {version} (supported: v{MIN_SUPPORTED_FORMAT_VERSION}..=v{CURRENT_FORMAT_VERSION})"
                )
            }
            Self::MigrationFailed {
                from_version,
                to_version,
                reason,
            } => {
                write!(
                    f,
                    "Failed to migrate snapshot from v{from_version} to v{to_version}: {reason}"
                )
            }
            Self::InvalidIgnorePattern { pattern, reason } => {
                write!(f, "Invalid ignore pattern '{pattern}': {reason}")
            }
            Self::PasswordRequired(path) => {
                write!(f, "Snapshot is encrypted and requires a password: {path}")
            }
            Self::EmptyPassword => write!(f, "Password must not be empty"),
            Self::DecryptionFailed(path) => {
                write!(
                    f,
                    "Failed to decrypt snapshot '{path}': wrong password or tampered data"
                )
            }
            Self::EncryptionFailed(reason) => write!(f, "Failed to encrypt snapshot: {reason}"),
            Self::InvalidEncryptionParameters(reason) => {
                write!(f, "Invalid encryption parameters: {reason}")
            }
            Self::InvalidCompressionLevel(reason) => {
                write!(f, "Invalid compression level: {reason}")
            }
            Self::SnapshotNotEncrypted(path) => write!(f, "Snapshot is not encrypted: {path}"),
            Self::FileIsCorrupted(file) => write!(f, "File is corrupted: {file}"),
            Self::ScanCancelled => write!(f, "Scan was cancelled"),
            Self::Io {
                path: Some(path),
                source,
            } => write!(f, "I/O error at '{path}': {source}"),
            Self::Io { path: None, source } => write!(f, "I/O error: {source}"),
            Self::JsonError(e) => write!(f, "JSON parsing error: {e}"),
            Self::ZipError(e) => write!(f, "ZIP archive error: {e}"),
            Self::ThreadPoolError(e) => write!(f, "Thread pool error: {e}"),
            Self::TauriError(e) => write!(f, "Application error: {e}"),
        }
    }
}

impl std::error::Error for BulkHashError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ZipError(e) => Some(e),
            Self::JsonError(e) => Some(e),
            Self::ThreadPoolError(e) => Some(e),
            Self::TauriError(e) => Some(e),
            _ => None,
        }
    }
}

impl serde::Serialize for BulkHashError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("BulkHashError", 2)?;
        state.serialize_field("kind", self.kind())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

impl From<io::Error> for BulkHashError {
    fn from(source: io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

impl From<serde_json::Error> for BulkHashError {
    fn from(err: serde_json::Error) -> Self {
        Self::JsonError(err)
    }
}

impl From<zip::result::ZipError> for BulkHashError {
    fn from(err: zip::result::ZipError) -> Self {
        Self::ZipError(err)
    }
}

impl From<rayon::ThreadPoolBuildError> for BulkHashError {
    fn from(err: rayon::ThreadPoolBuildError) -> Self {
        Self::ThreadPoolError(err)
    }
}

impl From<tauri::Error> for BulkHashError {
    fn from(err: tauri::Error) -> Self {
        Self::TauriError(err)
    }
}
