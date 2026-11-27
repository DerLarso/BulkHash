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
}

impl MetaData {
    pub fn new(files_hashed: usize, hash_time: Duration, date_utc: DateTime<Utc>) -> Self {
        Self {
            version: 1,
            files_hashed,
            hash_time,
            date_utc,
            local_time: date_utc
                .with_timezone(&Local)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            os: std::env::consts::OS.to_string(),
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
