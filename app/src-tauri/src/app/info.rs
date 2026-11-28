use crate::app::state::{ActiveScanSummary, LoadedSnapshotSummary};
use crate::core::{
    hash_manager::HashAlgorithm,
    io::{
        compression::{CompressionPreset, DEFAULT_COMPRESSION_LEVEL},
        migration::{CURRENT_FORMAT_VERSION, MIN_SUPPORTED_FORMAT_VERSION},
    },
};
use std::fs;
use std::path::PathBuf;

/// Window label of the primary desktop window configured in `tauri.conf.json`.
pub const MAIN_WINDOW_LABEL: &str = "main";

/// File extension (without leading dot) used by `BulkHash` snapshot archives.
pub const SNAPSHOT_FILE_EXTENSION: &str = "hashed";

/// Default bundle identifier fallback when running outside a full Tauri config context.
pub const DEFAULT_APP_IDENTIFIER: &str = "de.derlarso.BulkHash";

/// Linux `WebKitGTK` environment variable used to avoid DMABUF rendering crashes under Wayland.
pub const WEBKIT_DMABUF_ENV_VAR: &str = "WEBKIT_DISABLE_DMABUF_RENDERER";

/// Static application identity metadata derived from `Cargo.toml` and `tauri.conf.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppIdentity {
    pub name: String,
    pub version: String,
    pub identifier: String,
    pub description: String,
}

impl AppIdentity {
    /// Builds default identity metadata from Cargo package metadata.
    #[must_use]
    pub fn from_cargo_metadata() -> Self {
        Self {
            name: String::from(env!("CARGO_PKG_NAME")),
            version: String::from(env!("CARGO_PKG_VERSION")),
            identifier: String::from(DEFAULT_APP_IDENTIFIER),
            description: String::from(env!("CARGO_PKG_DESCRIPTION")),
        }
    }

    /// Builds identity metadata from Tauri's resolved [`tauri::PackageInfo`] and [`tauri::Config`].
    #[must_use]
    pub fn from_tauri(package_info: &tauri::PackageInfo, config: &tauri::Config) -> Self {
        let name = config
            .product_name
            .clone()
            .filter(|product| !product.trim().is_empty())
            .unwrap_or_else(|| package_info.name.clone());

        Self {
            name,
            version: package_info.version.to_string(),
            identifier: config.identifier.clone(),
            description: package_info.description.to_string(),
        }
    }
}

impl Default for AppIdentity {
    fn default() -> Self {
        Self::from_cargo_metadata()
    }
}

/// Host operating system, CPU parallelism, and graphics-runtime metadata.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub family: String,
    pub available_parallelism: usize,
    pub default_rayon_threads: usize,
    pub wayland_detected: bool,
    pub webkit_dmabuf_disabled: bool,
}

impl PlatformInfo {
    /// Probes the current host platform and threading environment.
    #[must_use]
    pub fn detect() -> Self {
        let available_parallelism =
            std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let default_rayon_threads = rayon::current_num_threads();
        let wayland_detected = cfg!(target_os = "linux")
            && std::env::var_os("WAYLAND_DISPLAY").is_some_and(|val| !val.is_empty());
        let webkit_dmabuf_disabled = std::env::var_os(WEBKIT_DMABUF_ENV_VAR)
            .is_some_and(|val| val == "1" || val.eq_ignore_ascii_case("true"));

        Self {
            os: String::from(std::env::consts::OS),
            arch: String::from(std::env::consts::ARCH),
            family: String::from(std::env::consts::FAMILY),
            available_parallelism,
            default_rayon_threads,
            wayland_detected,
            webkit_dmabuf_disabled,
        }
    }
}

/// Frontend-ready descriptor for a single supported [`HashAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AlgorithmDescriptor {
    pub id: HashAlgorithm,
    pub name: String,
    pub hex_len: usize,
    pub digest_bytes: usize,
    pub cryptographic: bool,
    pub is_default: bool,
}

impl AlgorithmDescriptor {
    /// Builds a descriptor from a [`HashAlgorithm`] variant.
    #[must_use]
    pub fn from_algorithm(algorithm: HashAlgorithm) -> Self {
        let hex_len = algorithm.hex_len();
        Self {
            id: algorithm,
            name: String::from(algorithm.display_name()),
            hex_len,
            digest_bytes: hex_len / 2,
            cryptographic: algorithm.is_cryptographic(),
            is_default: algorithm == HashAlgorithm::default(),
        }
    }
}

/// Frontend-ready descriptor for a named `.hashed` ZIP [`CompressionPreset`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompressionPresetDescriptor {
    pub preset: CompressionPreset,
    pub name: String,
    pub level: u8,
    pub is_default: bool,
}

impl CompressionPresetDescriptor {
    /// Builds a descriptor from a [`CompressionPreset`] variant.
    #[must_use]
    pub fn from_preset(preset: CompressionPreset) -> Self {
        Self {
            preset,
            name: String::from(preset.as_str()),
            level: preset.level().level(),
            is_default: preset == CompressionPreset::default(),
        }
    }
}

/// Snapshot format and hashing capabilities exposed by the Rust backend.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FormatCapabilities {
    pub file_extension: String,
    pub current_version: usize,
    pub min_supported_version: usize,
    pub supports_encryption: bool,
    pub default_algorithm: HashAlgorithm,
    pub supported_algorithms: Vec<AlgorithmDescriptor>,
    pub default_compression_level: u8,
    pub compression_presets: Vec<CompressionPresetDescriptor>,
}

impl FormatCapabilities {
    /// Collects the backend's compiled snapshot format and algorithm capabilities.
    #[must_use]
    pub fn current() -> Self {
        let supported_algorithms = HashAlgorithm::all()
            .iter()
            .copied()
            .map(AlgorithmDescriptor::from_algorithm)
            .collect();
        let compression_presets = CompressionPreset::ALL
            .iter()
            .copied()
            .map(CompressionPresetDescriptor::from_preset)
            .collect();

        Self {
            file_extension: String::from(SNAPSHOT_FILE_EXTENSION),
            current_version: CURRENT_FORMAT_VERSION,
            min_supported_version: MIN_SUPPORTED_FORMAT_VERSION,
            supports_encryption: true,
            default_algorithm: HashAlgorithm::default(),
            supported_algorithms,
            default_compression_level: DEFAULT_COMPRESSION_LEVEL,
            compression_presets,
        }
    }
}

impl Default for FormatCapabilities {
    fn default() -> Self {
        Self::current()
    }
}

/// OS-standard application directories resolved via Tauri's [`tauri::path::PathResolver`].
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppDirectories {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_data_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<String>,
}

impl AppDirectories {
    /// Resolves all standard `BulkHash` directories from Tauri's path resolver without failing
    /// if any individual OS directory is unavailable.
    #[must_use]
    pub fn resolve_from_path_resolver<R: tauri::Runtime>(
        resolver: &tauri::path::PathResolver<R>,
    ) -> Self {
        Self {
            config_dir: resolver
                .app_config_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            data_dir: resolver
                .app_data_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            local_data_dir: resolver
                .app_local_data_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            cache_dir: resolver
                .app_cache_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
            log_dir: resolver
                .app_log_dir()
                .ok()
                .map(|path| path.to_string_lossy().into_owned()),
        }
    }

    /// Ensures writable base directories (`config_dir`, `data_dir`) exist on disk.
    ///
    /// Returns a list of non-fatal `(directory_name, error_message)` pairs if creation failed.
    #[must_use]
    pub fn ensure_base_directories(&self) -> Vec<(String, String)> {
        let mut errors = Vec::new();
        for (label, maybe_dir) in [
            ("config_dir", self.config_dir.as_deref()),
            ("data_dir", self.data_dir.as_deref()),
        ] {
            if let Some(dir) = maybe_dir
                && let Err(err) = fs::create_dir_all(dir)
            {
                errors.push((String::from(label), err.to_string()));
            }
        }
        errors
    }

    #[must_use]
    pub fn config_path(&self) -> Option<PathBuf> {
        self.config_dir.as_deref().map(PathBuf::from)
    }

    #[must_use]
    pub fn data_path(&self) -> Option<PathBuf> {
        self.data_dir.as_deref().map(PathBuf::from)
    }

    #[must_use]
    pub fn local_data_path(&self) -> Option<PathBuf> {
        self.local_data_dir.as_deref().map(PathBuf::from)
    }

    #[must_use]
    pub fn cache_path(&self) -> Option<PathBuf> {
        self.cache_dir.as_deref().map(PathBuf::from)
    }

    #[must_use]
    pub fn log_path(&self) -> Option<PathBuf> {
        self.log_dir.as_deref().map(PathBuf::from)
    }
}

/// Complete bootstrap information payload returned to the desktop frontend via `get_app_info`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppInfo {
    pub identity: AppIdentity,
    pub platform: PlatformInfo,
    pub capabilities: FormatCapabilities,
    pub directories: AppDirectories,
    pub initialized: bool,
}

/// Live runtime status snapshot returned to the desktop frontend via `get_app_status`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppStatus {
    pub initialized: bool,
    pub shutting_down: bool,
    pub uptime_ms: u64,
    pub active_scan_count: usize,
    pub paused_scan_count: usize,
    pub active_scans: Vec<ActiveScanSummary>,
    pub loaded_snapshot_count: usize,
    pub loaded_snapshots: Vec<LoadedSnapshotSummary>,
    pub pending_startup_paths_count: usize,
}
