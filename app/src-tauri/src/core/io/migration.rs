use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, SecondsFormat, Utc};
use serde_json::{Map, Value};

use crate::core::io::{
    bulk_hash_error::BulkHashError,
    encryption::{ENCRYPTED_TREE_ENTRY, EncryptionMetadata},
};

/// Lowest `.hashed` format version that this version of `BulkHash` can read and migrate.
pub const MIN_SUPPORTED_FORMAT_VERSION: usize = 1;

/// Initial `.hashed` format version (ZIP containing `meta.json`, `hash.sha256`, and `tree.json`
/// with legacy `Result<String, String>` `"Ok"`/`"Err"` file entries).
pub const FORMAT_VERSION_V1: usize = 1;

/// Extended-metadata `.hashed` format version (canonical `FileEntry` `"hash"`/`"error"` entries
/// with optional per-file `size` and `modified_utc`, plus optional `total_size` and
/// `migrated_from` provenance in `meta.json`).
pub const FORMAT_VERSION_V2: usize = 2;

/// Encryption-capable `.hashed` format version supporting optional AES-256-GCM + Argon2id
/// snapshot protection (`meta.json` with optional `encryption` header, `tree.enc` when encrypted
/// or `tree.json` when unencrypted, plus `hash.sha256`).
pub const FORMAT_VERSION_V3: usize = 3;

/// Latest `.hashed` format version produced when saving or migrating snapshots.
pub const CURRENT_FORMAT_VERSION: usize = FORMAT_VERSION_V3;

const UNENCRYPTED_REQUIRED_ENTRIES: &[&str] = &["meta.json", "hash.sha256", "tree.json"];
const V3_ENCRYPTED_REQUIRED_ENTRIES: &[&str] = &["meta.json", "hash.sha256", ENCRYPTED_TREE_ENTRY];

/// Returns whether a `.hashed` format version supports snapshot encryption.
#[must_use]
pub const fn supports_encryption(version: usize) -> bool {
    version >= FORMAT_VERSION_V3
}

/// Returns the required ZIP archive entries for an unencrypted `.hashed` format version,
/// or `None` if the version is unknown to this build.
#[must_use]
pub const fn required_entries_for_version(version: usize) -> Option<&'static [&'static str]> {
    required_entries_for_archive(version, false)
}

/// Returns the required ZIP archive entries for a known `.hashed` format version and
/// encryption state, or `None` if the combination is not supported by this build.
#[must_use]
pub const fn required_entries_for_archive(
    version: usize,
    encrypted: bool,
) -> Option<&'static [&'static str]> {
    match (version, encrypted) {
        (FORMAT_VERSION_V1 | FORMAT_VERSION_V2 | FORMAT_VERSION_V3, false) => {
            Some(UNENCRYPTED_REQUIRED_ENTRIES)
        }
        (FORMAT_VERSION_V3, true) => Some(V3_ENCRYPTED_REQUIRED_ENTRIES),
        _ => None,
    }
}

/// Extracts and validates the numeric `"version"` field from a parsed `meta.json` JSON value
/// before deserializing version-specific metadata structs.
///
/// # Errors
///
/// Returns [`BulkHashError::FileIsCorrupted`] if `meta` is not a JSON object, is missing the
/// `"version"` field, or has a `"version"` value that is not a valid unsigned integer.
pub fn extract_format_version(meta: &Value, source_label: &str) -> Result<usize, BulkHashError> {
    let Some(obj) = meta.as_object() else {
        return Err(BulkHashError::FileIsCorrupted(format!(
            "{source_label}: 'meta.json' must be a JSON object"
        )));
    };

    let Some(version_val) = obj.get("version") else {
        return Err(BulkHashError::FileIsCorrupted(format!(
            "{source_label}: 'meta.json' is missing required 'version' field"
        )));
    };

    let Some(version_u64) = version_val.as_u64() else {
        return Err(BulkHashError::FileIsCorrupted(format!(
            "{source_label}: 'meta.json' has an invalid 'version' field"
        )));
    };

    usize::try_from(version_u64).map_err(|_| {
        BulkHashError::FileIsCorrupted(format!(
            "{source_label}: 'meta.json' version number exceeds platform limits"
        ))
    })
}

/// Compatibility classification of a `.hashed` archive relative to this application version.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status")]
pub enum VersionCompatibility {
    /// Archive already uses the latest format version; no migration is needed.
    Current,
    /// Archive uses an older supported format version and can be upgraded to the current version.
    NeedsMigration {
        from_version: usize,
        to_version: usize,
        steps_required: usize,
    },
    /// Archive uses a version outside the supported range (e.g. `0` or a newer future format).
    Unsupported {
        found_version: usize,
        min_supported: usize,
        max_supported: usize,
    },
}

impl VersionCompatibility {
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported { .. })
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }

    #[must_use]
    pub const fn needs_migration(&self) -> bool {
        matches!(self, Self::NeedsMigration { .. })
    }
}

/// Lightweight version, encryption, and structure probe returned by inspecting a `.hashed`
/// archive without reading or decrypting `tree.json` / `tree.enc`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArchiveVersionInfo {
    pub version: usize,
    pub current_version: usize,
    pub compatibility: VersionCompatibility,
    pub encrypted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<EncryptionMetadata>,
    pub entries: Vec<String>,
}

impl ArchiveVersionInfo {
    #[must_use]
    pub const fn is_supported(&self) -> bool {
        self.compatibility.is_supported()
    }

    #[must_use]
    pub const fn is_current(&self) -> bool {
        self.compatibility.is_current()
    }

    #[must_use]
    pub const fn needs_migration(&self) -> bool {
        self.compatibility.needs_migration()
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    #[must_use]
    pub const fn encryption(&self) -> Option<&EncryptionMetadata> {
        self.encryption.as_ref()
    }
}

/// Record of a single migration hop executed as part of upgrading a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationStepRecord {
    pub from_version: usize,
    pub to_version: usize,
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Summary of the format version migration performed on a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationReport {
    pub original_version: usize,
    pub target_version: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<MigrationStepRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
}

impl MigrationReport {
    /// Creates a report indicating the snapshot was already at `version` and needed no migration.
    #[must_use]
    pub const fn up_to_date(version: usize) -> Self {
        Self {
            original_version: version,
            target_version: version,
            steps: Vec::new(),
            backup_path: None,
        }
    }

    #[must_use]
    pub fn with_backup_path(mut self, backup_path: PathBuf) -> Self {
        self.backup_path = Some(backup_path);
        self
    }

    #[must_use]
    pub const fn was_migrated(&self) -> bool {
        self.original_version != self.target_version
    }

    #[must_use]
    pub const fn original_version(&self) -> usize {
        self.original_version
    }

    #[must_use]
    pub const fn target_version(&self) -> usize {
        self.target_version
    }

    #[must_use]
    pub fn steps(&self) -> &[MigrationStepRecord] {
        &self.steps
    }

    #[must_use]
    pub fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }
}

/// Version-agnostic intermediate representation of a `.hashed` snapshot used by sequential
/// [`FormatMigration`] steps before deserializing into the latest strongly-typed structs.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotPayload {
    pub version: usize,
    pub meta: Value,
    pub tree: Value,
    /// Auxiliary archive entries (reserved for future formats such as segmented trees or
    /// encryption manifests).
    pub extra_entries: BTreeMap<String, Vec<u8>>,
}

impl SnapshotPayload {
    #[must_use]
    pub const fn new(version: usize, meta: Value, tree: Value) -> Self {
        Self {
            version,
            meta,
            tree,
            extra_entries: BTreeMap::new(),
        }
    }
}

/// A single forward-only schema upgrade step between two `.hashed` format versions.
pub trait FormatMigration: Send + Sync {
    /// Source format version upgraded by this migration.
    fn source_version(&self) -> usize;

    /// Target format version produced by this migration (must be strictly greater than
    /// [`Self::source_version`]).
    fn target_version(&self) -> usize;

    /// Short human-readable description of the transformation performed by this step.
    fn description(&self) -> &'static str;

    /// Transforms `payload` in place from [`Self::source_version`] to [`Self::target_version`],
    /// returning optional human-readable notes describing what was adjusted.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::MigrationFailed`] if the payload violates the expected source
    /// schema or cannot be converted safely.
    fn migrate(&self, payload: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError>;
}

/// Registry and execution engine for sequential `.hashed` format migrations.
pub struct MigrationRegistry {
    min_supported_version: usize,
    target_version: usize,
    migrations: BTreeMap<usize, Box<dyn FormatMigration>>,
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::with_builtin_migrations()
    }
}

impl MigrationRegistry {
    /// Creates an empty registry covering `min_supported_version..=target_version`.
    #[must_use]
    pub const fn new(min_supported_version: usize, target_version: usize) -> Self {
        Self {
            min_supported_version,
            target_version,
            migrations: BTreeMap::new(),
        }
    }

    /// Creates the default registry populated with all built-in `.hashed` migrations
    /// up to [`CURRENT_FORMAT_VERSION`].
    #[must_use]
    pub fn with_builtin_migrations() -> Self {
        let mut registry = Self::new(MIN_SUPPORTED_FORMAT_VERSION, CURRENT_FORMAT_VERSION);
        // Built-in chain invariants are verified by unit tests; registration cannot fail here.
        let _ = registry.register(Box::new(V1ToV2Migration));
        let _ = registry.register(Box::new(V2ToV3Migration));
        registry
    }

    #[must_use]
    pub const fn min_supported_version(&self) -> usize {
        self.min_supported_version
    }

    #[must_use]
    pub const fn target_version(&self) -> usize {
        self.target_version
    }

    /// Registers a forward migration step.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::MigrationFailed`] if `from_version == 0`,
    /// `to_version <= from_version`, or a migration for `from_version` is already registered.
    pub fn register(&mut self, migration: Box<dyn FormatMigration>) -> Result<(), BulkHashError> {
        let from_version = migration.source_version();
        let to_version = migration.target_version();

        if from_version == 0 {
            return Err(BulkHashError::MigrationFailed {
                from_version,
                to_version,
                reason: String::from("source format version must be at least 1"),
            });
        }

        if to_version <= from_version {
            return Err(BulkHashError::MigrationFailed {
                from_version,
                to_version,
                reason: String::from("target format version must be strictly greater than source"),
            });
        }

        if self.migrations.contains_key(&from_version) {
            return Err(BulkHashError::MigrationFailed {
                from_version,
                to_version,
                reason: format!(
                    "a migration starting from format version {from_version} is already registered"
                ),
            });
        }

        self.migrations.insert(from_version, migration);
        Ok(())
    }

    /// Classifies how `version` relates to this registry's supported version window.
    #[must_use]
    pub fn check_compatibility(&self, version: usize) -> VersionCompatibility {
        if version < self.min_supported_version || version > self.target_version {
            return VersionCompatibility::Unsupported {
                found_version: version,
                min_supported: self.min_supported_version,
                max_supported: self.target_version,
            };
        }

        if version == self.target_version {
            return VersionCompatibility::Current;
        }

        match self.plan_path(version) {
            Ok(steps) => VersionCompatibility::NeedsMigration {
                from_version: version,
                to_version: self.target_version,
                steps_required: steps.len(),
            },
            Err(_) => VersionCompatibility::Unsupported {
                found_version: version,
                min_supported: self.min_supported_version,
                max_supported: self.target_version,
            },
        }
    }

    /// Resolves the ordered sequence of `(from, to, description)` hops required to upgrade
    /// `from_version` to [`Self::target_version`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::UnsupportedVersion`] if `from_version` is outside the supported
    /// range, or [`BulkHashError::MigrationFailed`] if the registered chain has a gap or
    /// overshoots [`Self::target_version`].
    pub fn plan_path(
        &self,
        from_version: usize,
    ) -> Result<Vec<(usize, usize, &'static str)>, BulkHashError> {
        if from_version < self.min_supported_version || from_version > self.target_version {
            return Err(BulkHashError::UnsupportedVersion(from_version));
        }

        let mut plan = Vec::new();
        let mut cursor = from_version;
        let max_hops = self.target_version.saturating_sub(from_version);

        while cursor < self.target_version {
            let Some(step) = self.migrations.get(&cursor) else {
                return Err(BulkHashError::MigrationFailed {
                    from_version: cursor,
                    to_version: self.target_version,
                    reason: format!(
                        "no migration registered for format version {cursor} toward v{}",
                        self.target_version
                    ),
                });
            };

            let next = step.target_version();
            if next <= cursor || next > self.target_version {
                return Err(BulkHashError::MigrationFailed {
                    from_version: cursor,
                    to_version: next,
                    reason: format!(
                        "invalid migration hop v{cursor} -> v{next} for target v{}",
                        self.target_version
                    ),
                });
            }

            plan.push((cursor, next, step.description()));
            cursor = next;

            if plan.len() > max_hops {
                return Err(BulkHashError::MigrationFailed {
                    from_version,
                    to_version: self.target_version,
                    reason: String::from("migration chain exceeded maximum allowed hops"),
                });
            }
        }

        Ok(plan)
    }

    /// Validates that every format version in `min_supported_version..=target_version` has a
    /// complete, valid migration path to [`Self::target_version`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::MigrationFailed`] if the version window is invalid or any
    /// supported version lacks a complete path to [`Self::target_version`].
    pub fn validate_chain(&self) -> Result<(), BulkHashError> {
        if self.min_supported_version == 0 || self.min_supported_version > self.target_version {
            return Err(BulkHashError::MigrationFailed {
                from_version: self.min_supported_version,
                to_version: self.target_version,
                reason: String::from("invalid supported version range"),
            });
        }

        for version in self.min_supported_version..=self.target_version {
            let _ = self.plan_path(version)?;
        }

        Ok(())
    }

    /// Migrates `payload` in place through all required hops up to [`Self::target_version`].
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::UnsupportedVersion`] if `payload.version` is outside the supported
    /// range, or [`BulkHashError::MigrationFailed`] if metadata version stamps disagree, the chain
    /// is incomplete, or any migration step fails.
    pub fn migrate(&self, payload: &mut SnapshotPayload) -> Result<MigrationReport, BulkHashError> {
        let original_version = payload.version;

        if let Some(meta_obj) = payload.meta.as_object()
            && let Some(meta_ver) = meta_obj.get("version")
        {
            let parsed_meta_ver = meta_ver
                .as_u64()
                .and_then(|v| usize::try_from(v).ok())
                .ok_or_else(|| BulkHashError::MigrationFailed {
                    from_version: original_version,
                    to_version: self.target_version,
                    reason: String::from("metadata 'version' field is not a valid integer"),
                })?;

            if parsed_meta_ver != original_version {
                return Err(BulkHashError::MigrationFailed {
                    from_version: original_version,
                    to_version: self.target_version,
                    reason: format!(
                        "payload version ({original_version}) does not match metadata version ({parsed_meta_ver})"
                    ),
                });
            }
        }

        let plan = self.plan_path(original_version)?;
        if plan.is_empty() {
            return Ok(MigrationReport::up_to_date(self.target_version));
        }

        let mut applied_steps = Vec::with_capacity(plan.len());

        for (expected_from, expected_to, description) in plan {
            let Some(step) = self.migrations.get(&expected_from) else {
                return Err(BulkHashError::MigrationFailed {
                    from_version: expected_from,
                    to_version: expected_to,
                    reason: format!("migration step for v{expected_from} disappeared"),
                });
            };

            let notes = step.migrate(payload)?;

            // Enforce canonical post-step version stamping and preserve original provenance.
            payload.version = expected_to;
            let meta_obj =
                payload
                    .meta
                    .as_object_mut()
                    .ok_or_else(|| BulkHashError::MigrationFailed {
                        from_version: expected_from,
                        to_version: expected_to,
                        reason: String::from("metadata must remain a JSON object after migration"),
                    })?;
            meta_obj.insert(String::from("version"), Value::from(expected_to as u64));
            let has_provenance = meta_obj
                .get("migrated_from")
                .is_some_and(|val| !val.is_null());
            if !has_provenance {
                meta_obj.insert(
                    String::from("migrated_from"),
                    Value::from(original_version as u64),
                );
            }

            applied_steps.push(MigrationStepRecord {
                from_version: expected_from,
                to_version: expected_to,
                description: String::from(description),
                notes,
            });
        }

        Ok(MigrationReport {
            original_version,
            target_version: self.target_version,
            steps: applied_steps,
            backup_path: None,
        })
    }
}

/// Built-in migration upgrading `.hashed` snapshots from format v1 to format v2.
///
/// Transformations performed:
/// - Converts legacy v1 `Result<String, String>` file entries (`{"Ok": "..."}` / `{"Err": "..."}`)
///   into canonical v2 `FileEntry` objects (`{"hash": "..."}` / `{"error": "..."}`) using an
///   iterative traversal (safe for arbitrarily deep directory trees).
/// - Preserves any transitional v1 extended file entries (`hash`/`error`, `size`, `modified_utc`).
/// - Updates `meta.version` from `1` to `2` and records `meta.migrated_from = 1` if unset.
/// - Derives `meta.local_time` from `meta.date_utc` if missing or null in minimal v1 metadata.
/// - Backfills `meta.total_size` when absent if and only if at least one hashed file exists and
///   every hashed file carries a known byte size (never fabricating `0` for legacy size-less
///   archives).
pub struct V1ToV2Migration;

#[derive(Default)]
struct V1TreeMigrationStats {
    converted_ok_entries: usize,
    converted_err_entries: usize,
    hashed_entries: usize,
    hashed_entries_with_size: usize,
    known_hashed_bytes: u64,
}

impl FormatMigration for V1ToV2Migration {
    fn source_version(&self) -> usize {
        FORMAT_VERSION_V1
    }

    fn target_version(&self) -> usize {
        FORMAT_VERSION_V2
    }

    fn description(&self) -> &'static str {
        "Upgrade .hashed snapshot from v1 to v2 (canonical FileEntry schema & extended metadata)"
    }

    fn migrate(&self, payload: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError> {
        let mut notes = Vec::new();
        let stats = migrate_v1_tree_iterative(&mut payload.tree)?;

        if stats.converted_ok_entries > 0 || stats.converted_err_entries > 0 {
            notes.push(format!(
                "Converted {} legacy 'Ok' and {} legacy 'Err' file entries to v2 FileEntry format",
                stats.converted_ok_entries, stats.converted_err_entries
            ));
        }

        let meta_obj = payload
            .meta
            .as_object_mut()
            .ok_or_else(|| v1_to_v2_err("metadata must be a JSON object"))?;

        // Ensure `local_time` exists if an older/minimal v1 file omitted it.
        let needs_local_time = meta_obj
            .get("local_time")
            .is_none_or(|val| val.is_null() || val.as_str().is_some_and(str::is_empty));
        if needs_local_time
            && let Some(date_str) = meta_obj.get("date_utc").and_then(Value::as_str)
            && let Ok(parsed) = DateTime::parse_from_rfc3339(date_str)
        {
            let derived = parsed
                .with_timezone(&Utc)
                .with_timezone(&Local)
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            meta_obj.insert(String::from("local_time"), Value::String(derived));
            notes.push(String::from("Derived missing 'local_time' from 'date_utc'"));
        }

        // Backfill `total_size` only when absent and EVERY hashed file has a known size.
        let has_total_size = meta_obj.get("total_size").is_some_and(|val| !val.is_null());
        if !has_total_size
            && stats.hashed_entries > 0
            && stats.hashed_entries == stats.hashed_entries_with_size
        {
            meta_obj.insert(
                String::from("total_size"),
                Value::from(stats.known_hashed_bytes),
            );
            notes.push(format!(
                "Backfilled 'total_size' ({} bytes) from per-file metadata",
                stats.known_hashed_bytes
            ));
        }

        meta_obj.insert(
            String::from("version"),
            Value::from(FORMAT_VERSION_V2 as u64),
        );
        let has_provenance = meta_obj
            .get("migrated_from")
            .is_some_and(|val| !val.is_null());
        if !has_provenance {
            meta_obj.insert(
                String::from("migrated_from"),
                Value::from(FORMAT_VERSION_V1 as u64),
            );
        }

        if notes.is_empty() {
            notes.push(String::from("Normalized v1 snapshot metadata to format v2"));
        }

        Ok(notes)
    }
}

fn migrate_v1_tree_iterative(root: &mut Value) -> Result<V1TreeMigrationStats, BulkHashError> {
    let mut stats = V1TreeMigrationStats::default();
    let mut stack: Vec<&mut Value> = vec![root];

    while let Some(node_val) = stack.pop() {
        let node_obj = node_val
            .as_object_mut()
            .ok_or_else(|| v1_to_v2_err("directory node in 'tree.json' must be a JSON object"))?;

        match node_obj.get("name") {
            Some(Value::String(_)) => {}
            _ => {
                return Err(v1_to_v2_err(
                    "directory node in 'tree.json' is missing a valid string 'name' field",
                ));
            }
        }

        if let Some(files_val) = node_obj.get_mut("files") {
            let files_map = files_val.as_object_mut().ok_or_else(|| {
                v1_to_v2_err("directory node 'files' field must be a JSON object")
            })?;

            for (file_name, entry_val) in files_map.iter_mut() {
                let entry_obj = entry_val.as_object_mut().ok_or_else(|| {
                    v1_to_v2_err(format!("file entry '{file_name}' must be a JSON object"))
                })?;

                migrate_v1_file_entry(file_name, entry_obj, &mut stats)?;
            }
        }

        if let Some(subdirs_val) = node_obj.get_mut("sub_directories") {
            let subdirs_map = subdirs_val.as_object_mut().ok_or_else(|| {
                v1_to_v2_err("directory node 'sub_directories' field must be a JSON object")
            })?;

            for child in subdirs_map.values_mut() {
                stack.push(child);
            }
        }
    }

    Ok(stats)
}

fn migrate_v1_file_entry(
    file_name: &str,
    entry_obj: &mut Map<String, Value>,
    stats: &mut V1TreeMigrationStats,
) -> Result<(), BulkHashError> {
    let has_legacy_ok = entry_obj.contains_key("Ok");
    let has_legacy_err = entry_obj.contains_key("Err");
    let has_hash = entry_obj.contains_key("hash");
    let has_error = entry_obj.contains_key("error");

    let kind_count = usize::from(has_legacy_ok)
        + usize::from(has_legacy_err)
        + usize::from(has_hash)
        + usize::from(has_error);

    if kind_count == 0 {
        return Err(v1_to_v2_err(format!(
            "file entry '{file_name}' must specify 'Ok'/'Err' or 'hash'/'error'"
        )));
    }
    if kind_count > 1 {
        return Err(v1_to_v2_err(format!(
            "file entry '{file_name}' specifies conflicting hash/error fields"
        )));
    }

    let is_hashed = if has_legacy_ok {
        let Some(val) = entry_obj.remove("Ok") else {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' is missing 'Ok' value"
            )));
        };
        if !val.is_string() {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' has non-string 'Ok' hash value"
            )));
        }
        entry_obj.insert(String::from("hash"), val);
        stats.converted_ok_entries = stats.converted_ok_entries.saturating_add(1);
        true
    } else if has_legacy_err {
        let Some(val) = entry_obj.remove("Err") else {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' is missing 'Err' value"
            )));
        };
        if !val.is_string() {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' has non-string 'Err' error value"
            )));
        }
        entry_obj.insert(String::from("error"), val);
        stats.converted_err_entries = stats.converted_err_entries.saturating_add(1);
        false
    } else if has_hash {
        if !entry_obj.get("hash").is_some_and(Value::is_string) {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' has non-string 'hash' value"
            )));
        }
        true
    } else {
        if !entry_obj.get("error").is_some_and(Value::is_string) {
            return Err(v1_to_v2_err(format!(
                "file entry '{file_name}' has non-string 'error' value"
            )));
        }
        false
    };

    if let Some(size_val) = entry_obj.get("size")
        && !size_val.is_null()
        && size_val.as_u64().is_none()
    {
        return Err(v1_to_v2_err(format!(
            "file entry '{file_name}' has invalid 'size' value"
        )));
    }

    if is_hashed {
        stats.hashed_entries = stats.hashed_entries.saturating_add(1);
        if let Some(size) = entry_obj.get("size").and_then(Value::as_u64) {
            stats.hashed_entries_with_size = stats.hashed_entries_with_size.saturating_add(1);
            stats.known_hashed_bytes = stats.known_hashed_bytes.saturating_add(size);
        }
    }

    Ok(())
}

fn v1_to_v2_err(reason: impl Into<String>) -> BulkHashError {
    BulkHashError::MigrationFailed {
        from_version: FORMAT_VERSION_V1,
        to_version: FORMAT_VERSION_V2,
        reason: reason.into(),
    }
}

/// Built-in migration upgrading `.hashed` snapshots from format v2 to format v3.
///
/// Transformations performed:
/// - Validates that `meta.json` and `tree.json` are well-formed JSON objects and that the v2
///   archive does not carry an invalid pre-v3 `encryption` header.
/// - Advances `meta.version` from `2` to `3` while preserving any earlier `migrated_from`
///   provenance (e.g. `1` across a `v1 -> v2 -> v3` chain) or recording `migrated_from = 2`.
pub struct V2ToV3Migration;

impl FormatMigration for V2ToV3Migration {
    fn source_version(&self) -> usize {
        FORMAT_VERSION_V2
    }

    fn target_version(&self) -> usize {
        FORMAT_VERSION_V3
    }

    fn description(&self) -> &'static str {
        "Upgrade .hashed snapshot from v2 to v3 (encryption-capable format schema)"
    }

    fn migrate(&self, payload: &mut SnapshotPayload) -> Result<Vec<String>, BulkHashError> {
        let tree_obj = payload
            .tree
            .as_object()
            .ok_or_else(|| v2_to_v3_err("root node in 'tree.json' must be a JSON object"))?;
        if !matches!(tree_obj.get("name"), Some(Value::String(_))) {
            return Err(v2_to_v3_err(
                "root node in 'tree.json' is missing a valid string 'name' field",
            ));
        }

        let meta_obj = payload
            .meta
            .as_object_mut()
            .ok_or_else(|| v2_to_v3_err("metadata must be a JSON object"))?;

        if meta_obj
            .get("encryption")
            .is_some_and(|val| !val.is_null())
        {
            return Err(v2_to_v3_err(
                "format v2 snapshots cannot contain an 'encryption' header",
            ));
        }

        meta_obj.insert(
            String::from("version"),
            Value::from(FORMAT_VERSION_V3 as u64),
        );
        let has_provenance = meta_obj
            .get("migrated_from")
            .is_some_and(|val| !val.is_null());
        if !has_provenance {
            meta_obj.insert(
                String::from("migrated_from"),
                Value::from(FORMAT_VERSION_V2 as u64),
            );
        }

        Ok(vec![String::from(
            "Upgraded unencrypted v2 snapshot metadata to format v3",
        )])
    }
}

fn v2_to_v3_err(reason: impl Into<String>) -> BulkHashError {
    BulkHashError::MigrationFailed {
        from_version: FORMAT_VERSION_V2,
        to_version: FORMAT_VERSION_V3,
        reason: reason.into(),
    }
}
