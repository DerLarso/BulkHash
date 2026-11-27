use chrono::{DateTime, Utc};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

const NANOS_PER_SEC: u32 = 1_000_000_000;

/// Extended filesystem metadata captured for an individual file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    /// File size in bytes, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Last modification timestamp in UTC, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<DateTime<Utc>>,
}

impl FileMetadata {
    #[must_use]
    pub const fn new(size: Option<u64>, modified_utc: Option<DateTime<Utc>>) -> Self {
        Self { size, modified_utc }
    }

    #[must_use]
    pub const fn empty() -> Self {
        Self {
            size: None,
            modified_utc: None,
        }
    }

    #[must_use]
    pub fn from_fs_metadata(metadata: &fs::Metadata) -> Self {
        let size = Some(metadata.len());
        let modified_utc = metadata.modified().ok().and_then(system_time_to_utc);
        Self { size, modified_utc }
    }

    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    #[must_use]
    pub const fn with_modified_utc(mut self, modified_utc: DateTime<Utc>) -> Self {
        self.modified_utc = Some(modified_utc);
        self
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size.is_none() && self.modified_utc.is_none()
    }

    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    #[must_use]
    pub const fn modified_utc(&self) -> Option<DateTime<Utc>> {
        self.modified_utc
    }
}

/// Converts a [`SystemTime`] into a UTC [`DateTime`] without panicking on
/// out-of-range or pre-1970 timestamps.
#[must_use]
pub fn system_time_to_utc(time: SystemTime) -> Option<DateTime<Utc>> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            let secs = i64::try_from(duration.as_secs()).ok()?;
            DateTime::from_timestamp(secs, duration.subsec_nanos())
        }
        Err(err) => {
            let before_epoch = err.duration();
            let subsec = before_epoch.subsec_nanos();
            let whole_secs = i64::try_from(before_epoch.as_secs()).ok()?;
            if subsec == 0 {
                let secs = whole_secs.checked_neg()?;
                DateTime::from_timestamp(secs, 0)
            } else {
                let secs = whole_secs.checked_neg()?.checked_sub(1)?;
                let nanos = NANOS_PER_SEC.checked_sub(subsec)?;
                DateTime::from_timestamp(secs, nanos)
            }
        }
    }
}
