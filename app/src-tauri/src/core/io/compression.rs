use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use zip::{CompressionMethod, write::SimpleFileOptions};

use crate::core::io::bulk_hash_error::BulkHashError;

/// Minimum supported `.hashed` ZIP compression level (`0` = uncompressed / `Stored`).
pub const MIN_COMPRESSION_LEVEL: u8 = 0;

/// Fast `.hashed` ZIP DEFLATE compression level (`1`).
pub const FAST_COMPRESSION_LEVEL: u8 = 1;

/// Default balanced `.hashed` ZIP DEFLATE compression level (`6`).
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 6;

/// Maximum supported `.hashed` ZIP DEFLATE compression level (`9` = smallest archive).
pub const MAX_COMPRESSION_LEVEL: u8 = 9;

/// ZIP container compression method used when writing `.hashed` archive entries.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveCompressionMethod {
    /// Store archive entries verbatim without compression (ZIP method 0 / `Stored`).
    Stored,
    /// Compress archive entries using standard ZIP DEFLATE (ZIP method 8 / `Deflated`).
    #[default]
    Deflate,
}

impl ArchiveCompressionMethod {
    /// Returns the corresponding `zip::CompressionMethod` for writing ZIP entries.
    #[must_use]
    pub const fn to_zip_method(self) -> CompressionMethod {
        match self {
            Self::Stored => CompressionMethod::Stored,
            Self::Deflate => CompressionMethod::Deflated,
        }
    }

    /// Maps a `zip::CompressionMethod` read from a ZIP central directory into a known
    /// `.hashed` archive compression method, returning `None` for non-standard methods.
    #[must_use]
    pub const fn from_zip_method(method: CompressionMethod) -> Option<Self> {
        match method {
            CompressionMethod::Stored => Some(Self::Stored),
            CompressionMethod::Deflated => Some(Self::Deflate),
            _ => None,
        }
    }

    /// Returns the canonical lowercase string identifier (`"stored"` or `"deflate"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Deflate => "deflate",
        }
    }
}

impl fmt::Display for ArchiveCompressionMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// High-level preset profiles trading off snapshot save speed against `.hashed` file size.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CompressionPreset {
    /// No compression (`Stored`, level `0`) — fastest save/load, largest `.hashed` file.
    None,
    /// Fast DEFLATE compression (level `1`) — minimal CPU overhead with solid size reduction.
    Fast,
    /// Balanced DEFLATE compression (level `6`, default) — optimal default speed/size trade-off.
    #[default]
    Balanced,
    /// Maximum DEFLATE compression (level `9`) — smallest `.hashed` file size, higher CPU cost.
    Best,
}

impl CompressionPreset {
    /// All supported compression presets ordered from fastest/largest to slowest/smallest.
    pub const ALL: [Self; 4] = [Self::None, Self::Fast, Self::Balanced, Self::Best];

    /// Converts this preset into its corresponding validated [`CompressionLevel`].
    #[must_use]
    pub const fn level(self) -> CompressionLevel {
        match self {
            Self::None => CompressionLevel::NONE,
            Self::Fast => CompressionLevel::FAST,
            Self::Balanced => CompressionLevel::BALANCED,
            Self::Best => CompressionLevel::BEST,
        }
    }

    /// Returns the canonical lowercase preset name (`"none"`, `"fast"`, `"balanced"`, `"best"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Best => "best",
        }
    }
}

impl fmt::Display for CompressionPreset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CompressionPreset {
    type Err = BulkHashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "none" | "store" | "stored" | "uncompressed" | "off" => Ok(Self::None),
            "fast" | "fastest" | "quick" => Ok(Self::Fast),
            "balanced" | "default" | "normal" | "standard" => Ok(Self::Balanced),
            "best" | "max" | "maximum" | "smallest" => Ok(Self::Best),
            _ => Err(BulkHashError::InvalidCompressionLevel(format!(
                "unknown compression preset '{value}' (expected: none, fast, balanced, best)"
            ))),
        }
    }
}

/// Validated `.hashed` ZIP compression level in the standard DEFLATE range `0..=9`.
///
/// - Level `0` ([`Self::NONE`]) stores entries uncompressed (`CompressionMethod::Stored`) for
///   maximum speed.
/// - Levels `1..=9` compress entries with standard ZIP DEFLATE (`CompressionMethod::Deflated`),
///   from [`Self::FAST`] (`1`) through [`Self::BALANCED`] (`6`, default) up to [`Self::BEST`]
///   (`9`, smallest `.hashed` file).
///
/// All values are universally compatible with standard ZIP utilities and all `.hashed` format
/// versions. When serialized to JSON, `CompressionLevel` encodes as its numeric level (`0..=9`),
/// while deserialization accepts both numeric levels (`0..=9`) and preset/numeric strings
/// (`"none"`, `"fast"`, `"balanced"`, `"best"`, `"0"`..=`"9"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressionLevel {
    level: u8,
}

impl Default for CompressionLevel {
    fn default() -> Self {
        Self::BALANCED
    }
}

impl CompressionLevel {
    /// Uncompressed ZIP (`Stored`, level `0`) — fastest save/load, largest `.hashed` file.
    pub const NONE: Self = Self {
        level: MIN_COMPRESSION_LEVEL,
    };

    /// Fast ZIP DEFLATE (level `1`) — very low CPU overhead, good size reduction on JSON trees.
    pub const FAST: Self = Self {
        level: FAST_COMPRESSION_LEVEL,
    };

    /// Balanced ZIP DEFLATE (level `6`, default) — standard speed/size trade-off.
    pub const BALANCED: Self = Self {
        level: DEFAULT_COMPRESSION_LEVEL,
    };

    /// Maximum ZIP DEFLATE (level `9`) — smallest `.hashed` file size, higher CPU usage.
    pub const BEST: Self = Self {
        level: MAX_COMPRESSION_LEVEL,
    };

    /// Returns [`Self::NONE`] (level `0`, uncompressed `Stored`).
    #[must_use]
    pub const fn none() -> Self {
        Self::NONE
    }

    /// Returns [`Self::FAST`] (level `1`, fast DEFLATE).
    #[must_use]
    pub const fn fast() -> Self {
        Self::FAST
    }

    /// Returns [`Self::BALANCED`] (level `6`, default DEFLATE).
    #[must_use]
    pub const fn balanced() -> Self {
        Self::BALANCED
    }

    /// Returns [`Self::BEST`] (level `9`, maximum DEFLATE).
    #[must_use]
    pub const fn best() -> Self {
        Self::BEST
    }

    /// Creates a validated compression level in `0..=9`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidCompressionLevel`] if `level > MAX_COMPRESSION_LEVEL` (`9`).
    pub fn new(level: u8) -> Result<Self, BulkHashError> {
        if level > MAX_COMPRESSION_LEVEL {
            return Err(BulkHashError::InvalidCompressionLevel(format!(
                "compression level {level} is out of range (supported: {MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL})"
            )));
        }
        Ok(Self { level })
    }

    /// Converts a [`CompressionPreset`] into its corresponding [`CompressionLevel`].
    #[must_use]
    pub const fn from_preset(preset: CompressionPreset) -> Self {
        preset.level()
    }

    /// Returns all standard named presets ordered from fastest/largest to slowest/smallest.
    #[must_use]
    pub const fn presets() -> &'static [CompressionPreset] {
        &CompressionPreset::ALL
    }

    /// Returns the numeric compression level (`0` = Stored, `1..=9` = DEFLATE level).
    #[must_use]
    pub const fn level(self) -> u8 {
        self.level
    }

    /// Returns the matching named [`CompressionPreset`], or `None` for intermediate custom levels
    /// (`2..=5`, `7..=8`).
    #[must_use]
    pub const fn preset(self) -> Option<CompressionPreset> {
        match self.level {
            MIN_COMPRESSION_LEVEL => Some(CompressionPreset::None),
            FAST_COMPRESSION_LEVEL => Some(CompressionPreset::Fast),
            DEFAULT_COMPRESSION_LEVEL => Some(CompressionPreset::Balanced),
            MAX_COMPRESSION_LEVEL => Some(CompressionPreset::Best),
            _ => None,
        }
    }

    /// Returns the ZIP container compression method used by this level.
    #[must_use]
    pub const fn method(self) -> ArchiveCompressionMethod {
        if self.level == MIN_COMPRESSION_LEVEL {
            ArchiveCompressionMethod::Stored
        } else {
            ArchiveCompressionMethod::Deflate
        }
    }

    /// Returns `true` if this level applies DEFLATE compression (`1..=9`).
    #[must_use]
    pub const fn is_compressed(self) -> bool {
        self.level > MIN_COMPRESSION_LEVEL
    }

    /// Returns `true` if this level stores entries uncompressed (`0` / `Stored`).
    #[must_use]
    pub const fn is_uncompressed(self) -> bool {
        self.level == MIN_COMPRESSION_LEVEL
    }

    /// Constructs the [`CompressionMetadata`] descriptor recorded in `meta.json`.
    #[must_use]
    pub const fn to_metadata(self) -> CompressionMetadata {
        CompressionMetadata::from_level(self)
    }

    /// Builds `zip::write::SimpleFileOptions` configured for this compression level.
    ///
    /// For [`Self::NONE`] (`0`), configures `CompressionMethod::Stored` without a numeric level
    /// (as required by the `zip` crate). For levels `1..=9`, configures
    /// `CompressionMethod::Deflated` with the exact DEFLATE level.
    #[must_use]
    pub fn to_zip_file_options(self) -> SimpleFileOptions {
        if self.is_uncompressed() {
            SimpleFileOptions::default().compression_method(CompressionMethod::Stored)
        } else {
            SimpleFileOptions::default()
                .compression_method(CompressionMethod::Deflated)
                .compression_level(Some(i64::from(self.level)))
        }
    }

    /// Converts this level into a `flate2::Compression` for raw DEFLATE streams (e.g. inner
    /// plaintext compression prior to AES-256-GCM encryption).
    #[must_use]
    pub const fn to_flate2_compression(self) -> flate2::Compression {
        flate2::Compression::new(self.level as u32)
    }
}

impl From<CompressionPreset> for CompressionLevel {
    fn from(preset: CompressionPreset) -> Self {
        preset.level()
    }
}

impl From<CompressionLevel> for u8 {
    fn from(value: CompressionLevel) -> Self {
        value.level
    }
}

impl TryFrom<u8> for CompressionLevel {
    type Error = BulkHashError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.preset() {
            Some(preset) => f.write_str(preset.as_str()),
            None => write!(f, "{}", self.level),
        }
    }
}

impl FromStr for CompressionLevel {
    type Err = BulkHashError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(BulkHashError::InvalidCompressionLevel(String::from(
                "compression level must not be empty (expected: none, fast, balanced, best, or 0..=9)",
            )));
        }

        if let Ok(preset) = CompressionPreset::from_str(trimmed) {
            return Ok(preset.level());
        }

        if let Ok(parsed) = trimmed.parse::<u8>() {
            return Self::new(parsed);
        }

        Err(BulkHashError::InvalidCompressionLevel(format!(
            "unrecognized compression level '{value}' (expected: none, fast, balanced, best, or {MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL})"
        )))
    }
}

impl Serialize for CompressionLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.level)
    }
}

impl<'de> Deserialize<'de> for CompressionLevel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CompressionLevelVisitor;

        impl de::Visitor<'_> for CompressionLevelVisitor {
            type Value = CompressionLevel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    formatter,
                    "a compression level integer ({MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL}) or preset string (none, fast, balanced, best)"
                )
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let level_u8 = u8::try_from(value).map_err(|_| {
                    E::custom(format!(
                        "compression level {value} is out of range ({MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL})"
                    ))
                })?;
                CompressionLevel::new(level_u8).map_err(E::custom)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let level_u8 = u8::try_from(value).map_err(|_| {
                    E::custom(format!(
                        "compression level {value} is out of range ({MIN_COMPRESSION_LEVEL}..={MAX_COMPRESSION_LEVEL})"
                    ))
                })?;
                CompressionLevel::new(level_u8).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                CompressionLevel::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(CompressionLevelVisitor)
    }
}

/// Compression descriptor stored inside `meta.json` recording how a `.hashed` snapshot was
/// compressed when written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub struct CompressionMetadata {
    pub method: ArchiveCompressionMethod,
    pub level: CompressionLevel,
}

impl Default for CompressionMetadata {
    fn default() -> Self {
        Self::from_level(CompressionLevel::default())
    }
}

impl CompressionMetadata {
    /// Derives canonical [`CompressionMetadata`] directly from a [`CompressionLevel`].
    #[must_use]
    pub const fn from_level(level: CompressionLevel) -> Self {
        Self {
            method: level.method(),
            level,
        }
    }

    /// Creates validated [`CompressionMetadata`], ensuring `method` and `level` are consistent
    /// (`Stored` requires level `0`; `Deflate` requires levels `1..=9`).
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidCompressionLevel`] if `method` and `level` disagree.
    pub fn new(
        method: ArchiveCompressionMethod,
        level: CompressionLevel,
    ) -> Result<Self, BulkHashError> {
        let meta = Self { method, level };
        meta.validate()?;
        Ok(meta)
    }

    /// Validates that `method` and `level` are mutually consistent.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::InvalidCompressionLevel`] if `Stored` has a non-zero level or
    /// `Deflate` has level `0`.
    pub fn validate(&self) -> Result<(), BulkHashError> {
        match (self.method, self.level.level()) {
            (ArchiveCompressionMethod::Stored, MIN_COMPRESSION_LEVEL)
            | (ArchiveCompressionMethod::Deflate, 1..=MAX_COMPRESSION_LEVEL) => Ok(()),
            (ArchiveCompressionMethod::Stored, lvl) => {
                Err(BulkHashError::InvalidCompressionLevel(format!(
                    "compression method 'stored' requires level {MIN_COMPRESSION_LEVEL}, got {lvl}"
                )))
            }
            (ArchiveCompressionMethod::Deflate, lvl) => {
                Err(BulkHashError::InvalidCompressionLevel(format!(
                    "compression method 'deflate' requires level 1..={MAX_COMPRESSION_LEVEL}, got {lvl}"
                )))
            }
        }
    }

    /// Returns the matching named preset, if any.
    #[must_use]
    pub const fn preset(&self) -> Option<CompressionPreset> {
        self.level.preset()
    }
}

impl<'de> Deserialize<'de> for CompressionMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawCompressionMetadata {
            method: ArchiveCompressionMethod,
            level: CompressionLevel,
        }

        let raw = RawCompressionMetadata::deserialize(deserializer)?;
        Self::new(raw.method, raw.level).map_err(de::Error::custom)
    }
}

/// Parses and validates a [`CompressionMetadata`] header from a parsed `meta.json` JSON value.
///
/// # Errors
///
/// Returns [`BulkHashError::InvalidCompressionLevel`] if the JSON structure is malformed,
/// specifies an unsupported method/level, or has a method/level mismatch.
pub fn parse_compression_metadata(
    value: &serde_json::Value,
) -> Result<CompressionMetadata, BulkHashError> {
    let metadata: CompressionMetadata = serde_json::from_value(value.clone()).map_err(|err| {
        BulkHashError::InvalidCompressionLevel(format!("malformed 'compression' metadata: {err}"))
    })?;
    metadata.validate()?;
    Ok(metadata)
}

/// Lightweight compression summary returned by inspecting a `.hashed` ZIP container without
/// decompressing or decrypting the snapshot tree.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveCompressionStats {
    /// Compression metadata declared inside `meta.json`, if present (older v1/v2 or legacy v3
    /// snapshots may omit this field).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<CompressionMetadata>,
    /// Actual ZIP compression method of the primary tree entry (`tree.json` or `tree.enc`),
    /// inspected directly from the ZIP central directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_zip_method: Option<ArchiveCompressionMethod>,
    /// Total `.hashed` archive size on disk in bytes (including ZIP headers/central directory).
    pub archive_file_size: u64,
    /// Sum of compressed payload bytes across all ZIP entries.
    pub total_compressed_bytes: u64,
    /// Sum of uncompressed payload bytes across all ZIP entries.
    pub total_uncompressed_bytes: u64,
    /// Compressed bytes of the primary tree entry (`tree.json` or `tree.enc`), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_compressed_bytes: Option<u64>,
    /// Uncompressed bytes of the primary tree entry (`tree.json` or `tree.enc`), if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tree_uncompressed_bytes: Option<u64>,
    /// Whether this archive is password-encrypted (in which case `tree.enc` is stored uncompressed
    /// in ZIP because DEFLATE runs on plaintext prior to AES-256-GCM encryption).
    pub encrypted: bool,
}

impl ArchiveCompressionStats {
    /// Returns the ratio `total_compressed_bytes / total_uncompressed_bytes` across ZIP entries
    /// (e.g. `0.25` means compressed entries take 25% of their uncompressed size). Returns `1.0`
    /// when `total_uncompressed_bytes == 0`.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn compression_ratio(&self) -> f64 {
        if self.total_uncompressed_bytes == 0 {
            1.0
        } else {
            self.total_compressed_bytes as f64 / self.total_uncompressed_bytes as f64
        }
    }

    /// Returns the percentage of entry payload bytes saved by ZIP compression
    /// (`(1.0 - compression_ratio()) * 100.0`).
    #[must_use]
    pub fn space_savings_percent(&self) -> f64 {
        (1.0 - self.compression_ratio()) * 100.0
    }
}
