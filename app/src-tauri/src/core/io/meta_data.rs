use crate::core::hash_manager::HashAlgorithm;
use crate::core::hidden_filter::HiddenFileFilter;
use crate::core::ignore_list::IgnoreList;
use crate::core::io::compression::{CompressionLevel, CompressionMetadata};
use crate::core::io::encryption::EncryptionMetadata;
use crate::core::io::migration::CURRENT_FORMAT_VERSION;
use chrono::{DateTime, Local, SecondsFormat, Utc};
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetaData {
    version: usize,
    files_hashed: usize,
    hash_time: Duration,
    date_utc: DateTime<Utc>,
    local_time: String,
    os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    algorithm: Option<HashAlgorithm>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ignore_list: Option<IgnoreList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hidden_filter: Option<HiddenFileFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migrated_from: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    encryption: Option<EncryptionMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compression: Option<CompressionMetadata>,
}

impl MetaData {
    pub fn new(files_hashed: usize, hash_time: Duration, date_utc: DateTime<Utc>) -> Self {
        Self {
            version: CURRENT_FORMAT_VERSION,
            files_hashed,
            hash_time,
            date_utc,
            local_time: date_utc
                .with_timezone(&Local)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            os: std::env::consts::OS.to_string(),
            algorithm: None,
            ignore_list: None,
            hidden_filter: None,
            total_size: None,
            migrated_from: None,
            encryption: None,
            compression: None,
        }
    }

    pub fn with_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    pub fn with_ignore_list(mut self, ignore_list: IgnoreList) -> Self {
        self.ignore_list = (!ignore_list.is_empty()).then_some(ignore_list);
        self
    }

    #[must_use]
    pub fn with_hidden_filter(mut self, hidden_filter: HiddenFileFilter) -> Self {
        self.hidden_filter = hidden_filter.is_active().then_some(hidden_filter);
        self
    }

    #[must_use]
    pub const fn with_total_size(mut self, total_size: u64) -> Self {
        self.total_size = Some(total_size);
        self
    }

    #[must_use]
    pub const fn with_migrated_from(mut self, original_version: usize) -> Self {
        self.migrated_from = Some(original_version);
        self
    }

    pub(crate) fn with_encryption_metadata(
        mut self,
        encryption: Option<EncryptionMetadata>,
    ) -> Self {
        self.encryption = encryption;
        self
    }

    pub(crate) const fn with_compression_metadata(
        mut self,
        compression: Option<CompressionMetadata>,
    ) -> Self {
        self.compression = compression;
        self
    }

    pub fn get_algorithm(&self) -> Option<HashAlgorithm> {
        self.algorithm
    }

    pub fn get_ignore_list(&self) -> Option<&IgnoreList> {
        self.ignore_list.as_ref()
    }

    #[must_use]
    pub const fn get_hidden_filter(&self) -> Option<HiddenFileFilter> {
        self.hidden_filter
    }

    #[must_use]
    pub const fn get_total_size(&self) -> Option<u64> {
        self.total_size
    }

    #[must_use]
    pub const fn get_migrated_from(&self) -> Option<usize> {
        self.migrated_from
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encryption.is_some()
    }

    #[must_use]
    pub const fn get_encryption(&self) -> Option<&EncryptionMetadata> {
        self.encryption.as_ref()
    }

    #[must_use]
    pub const fn get_compression(&self) -> Option<CompressionMetadata> {
        self.compression
    }

    #[must_use]
    pub const fn get_compression_level(&self) -> Option<CompressionLevel> {
        match self.compression {
            Some(meta) => Some(meta.level),
            None => None,
        }
    }

    pub fn get_local_time(&self) -> &str {
        &self.local_time
    }

    pub fn get_filename_timestamp(&self) -> String {
        self.date_utc
            .with_timezone(&Local)
            .format("%Y-%m-%d_%H-%M-%S")
            .to_string()
    }

    pub fn get_current_os(&self) -> &str {
        &self.os
    }

    pub fn get_version(&self) -> usize {
        self.version
    }

    pub fn get_files_hashed(&self) -> usize {
        self.files_hashed
    }

    pub fn get_hash_time(&self) -> Duration {
        self.hash_time
    }

    pub fn get_date_utc(&self) -> DateTime<Utc> {
        self.date_utc
    }
}
