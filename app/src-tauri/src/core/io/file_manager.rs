use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use zeroize::Zeroizing;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::core::{
    hash_manager::HashAlgorithm,
    io::{
        bulk_hash_error::BulkHashError,
        directory_node::DirectoryNode,
        encryption::{
            ENCRYPTED_TREE_ENTRY, EncryptionOptions, build_tree_aad, decrypt_tree_payload,
            encrypt_tree_payload, parse_encryption_metadata, prepare_encryption_metadata,
        },
        meta_data::MetaData,
        migration::{
            ArchiveVersionInfo, CURRENT_FORMAT_VERSION, FORMAT_VERSION_V3, MigrationRegistry,
            MigrationReport, SnapshotPayload, extract_format_version,
            required_entries_for_archive,
        },
    },
    structs::bulk_hash_file_struct::BulkHashFileStruct,
};

const MAX_META_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_HASH_BYTES: u64 = 1024; // 1 KiB
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
/// Accommodates worst-case Deflate expansion (~0.03%) plus the 16-byte AES-GCM authentication tag.
const MAX_ENCRYPTED_TREE_BYTES: u64 = MAX_TREE_BYTES + (1024 * 1024); // 513 MiB
const MAX_UNIQUE_PATH_ATTEMPTS: usize = 10_000;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ProbedArchive {
    archive: ZipArchive<BufReader<File>>,
    entries: Vec<String>,
    meta_bytes: Vec<u8>,
    meta_value: Value,
    version: usize,
    encrypted: bool,
    path_display: String,
}

pub struct FileManager {}

impl FileManager {
    /// Saves an unencrypted snapshot into `folder` using the current `.hashed` format version.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::PathNotFound`], [`BulkHashError::NotADirectory`],
    /// [`BulkHashError::UnsupportedVersion`], or I/O / serialization errors.
    pub fn save_file(
        folder: impl AsRef<Path>,
        json: &DirectoryNode,
        meta: &MetaData,
    ) -> Result<PathBuf, BulkHashError> {
        Self::save_file_with_encryption(folder, json, meta, None)
    }

    /// Saves a password-protected (AES-256-GCM + Argon2id) snapshot into `folder` using the
    /// current `.hashed` format version.
    ///
    /// A fresh cryptographically random 128-bit salt and 96-bit nonce are generated on every call,
    /// and the serialized `meta.json` bytes are cryptographically bound as AES-GCM AAD.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::PathNotFound`], [`BulkHashError::NotADirectory`],
    /// [`BulkHashError::UnsupportedVersion`], [`BulkHashError::EmptyPassword`],
    /// [`BulkHashError::InvalidEncryptionParameters`], [`BulkHashError::EncryptionFailed`], or
    /// I/O / serialization errors.
    pub fn save_file_encrypted(
        folder: impl AsRef<Path>,
        json: &DirectoryNode,
        meta: &MetaData,
        options: &EncryptionOptions,
    ) -> Result<PathBuf, BulkHashError> {
        Self::save_file_with_encryption(folder, json, meta, Some(options))
    }

    /// Saves a snapshot into `folder`, optionally encrypting the file tree when `encryption` is
    /// `Some`.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::PathNotFound`], [`BulkHashError::NotADirectory`],
    /// [`BulkHashError::UnsupportedVersion`], encryption errors, or I/O / serialization errors.
    pub fn save_file_with_encryption(
        folder: impl AsRef<Path>,
        json: &DirectoryNode,
        meta: &MetaData,
        encryption: Option<&EncryptionOptions>,
    ) -> Result<PathBuf, BulkHashError> {
        let folder_path = folder.as_ref();
        let folder_display = folder_path.to_string_lossy().into_owned();

        let exists = folder_path
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, folder_display.clone()))?;

        if !exists {
            return Err(BulkHashError::PathNotFound(folder_display));
        }

        if !folder_path.is_dir() {
            return Err(BulkHashError::NotADirectory(folder_display));
        }

        if meta.get_version() != CURRENT_FORMAT_VERSION {
            return Err(BulkHashError::UnsupportedVersion(meta.get_version()));
        }

        if let Some(opts) = encryption {
            opts.validate()?;
        }

        let file_name = format!(
            "{}-{}.hashed",
            meta.get_current_os(),
            meta.get_filename_timestamp()
        );
        let output_path = folder_path.join(file_name);

        let write_result = Self::write_archive(&output_path, json, meta, encryption);
        if let Err(err) = write_result {
            let _ = fs::remove_file(&output_path);
            return Err(err);
        }

        Ok(output_path)
    }

    /// Inspects a `.hashed` archive's format version, encryption status, and entry list without
    /// reading, decrypting, or deserializing `tree.json` / `tree.enc`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, has an invalid extension, is not a valid ZIP
    /// archive, has a missing/corrupted `meta.json`, or has invalid encryption parameters in a
    /// supported format version.
    pub fn inspect_version(path: impl AsRef<Path>) -> Result<ArchiveVersionInfo, BulkHashError> {
        let probed = Self::open_and_probe_archive(path.as_ref())?;
        let registry = MigrationRegistry::with_builtin_migrations();
        let compatibility = registry.check_compatibility(probed.version);

        let encryption = if probed.encrypted {
            if compatibility.is_supported() {
                if probed.version < FORMAT_VERSION_V3 {
                    return Err(BulkHashError::FileIsCorrupted(format!(
                        "{}: encryption is not supported in format version {}",
                        probed.path_display, probed.version
                    )));
                }
                let enc_val = probed.meta_value.get("encryption").ok_or_else(|| {
                    BulkHashError::InvalidEncryptionParameters(format!(
                        "{}: encrypted snapshot is missing 'encryption' metadata",
                        probed.path_display
                    ))
                })?;
                Some(parse_encryption_metadata(enc_val)?)
            } else {
                probed
                    .meta_value
                    .get("encryption")
                    .and_then(|val| parse_encryption_metadata(val).ok())
            }
        } else {
            None
        };

        Ok(ArchiveVersionInfo {
            version: probed.version,
            current_version: CURRENT_FORMAT_VERSION,
            compatibility,
            encrypted: probed.encrypted,
            encryption,
            entries: probed.entries,
        })
    }

    /// Returns `true` if the `.hashed` snapshot at `path` is password-encrypted, without requiring
    /// a password or reading `tree.json` / `tree.enc`.
    ///
    /// # Errors
    ///
    /// Propagates inspection errors from [`Self::inspect_version`].
    pub fn is_encrypted(path: impl AsRef<Path>) -> Result<bool, BulkHashError> {
        Ok(Self::inspect_version(path)?.is_encrypted())
    }

    /// Opens an unencrypted `.hashed` snapshot, verifying integrity and transparently migrating
    /// older supported format versions in memory to [`CURRENT_FORMAT_VERSION`].
    ///
    /// If the snapshot is encrypted, returns [`BulkHashError::PasswordRequired`]; call
    /// [`Self::open_file_with_password`] to unlock it.
    ///
    /// # Errors
    ///
    /// Returns an error if the file is missing, invalid, corrupted, tampered with, encrypted
    /// without a password, uses an unsupported format version, or fails migration.
    pub fn open_file(path: impl AsRef<Path>) -> Result<BulkHashFileStruct, BulkHashError> {
        Self::open_file_internal(path.as_ref(), None)
    }

    /// Opens a `.hashed` snapshot using `password` to decrypt `tree.enc` when the archive is
    /// encrypted (or opens normally if the archive is unencrypted).
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::EmptyPassword`], [`BulkHashError::DecryptionFailed`],
    /// [`BulkHashError::InvalidEncryptionParameters`], [`BulkHashError::HashMismatch`],
    /// [`BulkHashError::UnsupportedVersion`], or I/O / corruption errors.
    pub fn open_file_with_password(
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<BulkHashFileStruct, BulkHashError> {
        Self::open_file_internal(path.as_ref(), Some(password))
    }

    /// Encrypts an existing unencrypted `.hashed` snapshot (`source`) with AES-256-GCM + Argon2id
    /// and writes the encrypted v3 archive atomically to `destination` (safe even when `source`
    /// and `destination` refer to the same path).
    ///
    /// Older unencrypted v1/v2 snapshots are verified and upgraded to [`CURRENT_FORMAT_VERSION`]
    /// as part of the operation; the returned [`MigrationReport`] records any format upgrade.
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::PasswordRequired`] if `source` is already encrypted (use
    /// [`Self::reencrypt_file`] to rotate passwords), or validation / I/O / encryption errors.
    pub fn encrypt_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        options: &EncryptionOptions,
    ) -> Result<MigrationReport, BulkHashError> {
        options.validate()?;

        let source_ref = source.as_ref();
        let dest_ref = destination.as_ref();
        let (dest_parent, dest_display) = Self::validate_destination_path(dest_ref)?;

        let loaded = Self::open_file(source_ref)?;
        let report = loaded
            .get_migration()
            .cloned()
            .unwrap_or_else(|| MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));

        let staged_path = Self::write_archive_staged(
            dest_parent,
            loaded.get_tree(),
            loaded.get_meta(),
            Some(options),
        )?;
        if let Err(err) = Self::replace_file_from_staged(&staged_path, dest_ref, &dest_display) {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }

        Ok(report)
    }

    /// Decrypts an encrypted `.hashed` snapshot (`source`) using `password` and writes an
    /// unencrypted v3 archive atomically to `destination` (safe even when `source` and
    /// `destination` refer to the same path).
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::SnapshotNotEncrypted`] if `source` is not encrypted,
    /// [`BulkHashError::EmptyPassword`] / [`BulkHashError::DecryptionFailed`] on invalid
    /// credentials or tampering, or validation / I/O errors.
    pub fn decrypt_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        password: &str,
    ) -> Result<MigrationReport, BulkHashError> {
        let source_ref = source.as_ref();
        let dest_ref = destination.as_ref();
        let (dest_parent, dest_display) = Self::validate_destination_path(dest_ref)?;

        let loaded = Self::open_file_with_password(source_ref, password)?;
        if !loaded.is_encrypted() {
            return Err(BulkHashError::SnapshotNotEncrypted(
                source_ref.to_string_lossy().into_owned(),
            ));
        }

        let report = loaded
            .get_migration()
            .cloned()
            .unwrap_or_else(|| MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));

        let staged_path =
            Self::write_archive_staged(dest_parent, loaded.get_tree(), loaded.get_meta(), None)?;
        if let Err(err) = Self::replace_file_from_staged(&staged_path, dest_ref, &dest_display) {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }

        Ok(report)
    }

    /// Re-encrypts an encrypted `.hashed` snapshot (`source`) with a new password and/or updated
    /// KDF/compression settings (`new_options`), generating a fresh random salt and nonce and
    /// writing atomically to `destination` (safe even when `source` and `destination` refer to
    /// the same path).
    ///
    /// # Errors
    ///
    /// Returns [`BulkHashError::SnapshotNotEncrypted`] if `source` is not encrypted,
    /// [`BulkHashError::EmptyPassword`] / [`BulkHashError::DecryptionFailed`] if
    /// `current_password` is wrong or the archive is tampered, or validation / I/O errors.
    pub fn reencrypt_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        current_password: &str,
        new_options: &EncryptionOptions,
    ) -> Result<MigrationReport, BulkHashError> {
        new_options.validate()?;

        let source_ref = source.as_ref();
        let dest_ref = destination.as_ref();
        let (dest_parent, dest_display) = Self::validate_destination_path(dest_ref)?;

        let loaded = Self::open_file_with_password(source_ref, current_password)?;
        if !loaded.is_encrypted() {
            return Err(BulkHashError::SnapshotNotEncrypted(
                source_ref.to_string_lossy().into_owned(),
            ));
        }

        let report = loaded
            .get_migration()
            .cloned()
            .unwrap_or_else(|| MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));

        let staged_path = Self::write_archive_staged(
            dest_parent,
            loaded.get_tree(),
            loaded.get_meta(),
            Some(new_options),
        )?;
        if let Err(err) = Self::replace_file_from_staged(&staged_path, dest_ref, &dest_display) {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }

        Ok(report)
    }

    /// Migrates `source` to [`CURRENT_FORMAT_VERSION`] and writes the upgraded `.hashed` archive
    /// atomically to `destination`.
    ///
    /// If `source` is already at [`CURRENT_FORMAT_VERSION`], writes a verified copy to
    /// `destination` (or acts as a no-op if `source` and `destination` refer to the same file)
    /// and returns an up-to-date [`MigrationReport`].
    ///
    /// # Errors
    ///
    /// Returns an error if `source` fails validation/migration, is encrypted without a password
    /// (use [`Self::migrate_file_with_password`]), or `destination` is invalid.
    pub fn migrate_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<MigrationReport, BulkHashError> {
        Self::migrate_file_with_password(source, destination, None)
    }

    /// Password-aware counterpart to [`Self::migrate_file`] that preserves encryption on
    /// password-protected archives (generating a fresh salt and nonce if written).
    ///
    /// # Errors
    ///
    /// Returns an error if `source` fails validation/decryption/migration or `destination` is
    /// invalid.
    pub fn migrate_file_with_password(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
        password: Option<&str>,
    ) -> Result<MigrationReport, BulkHashError> {
        let source_ref = source.as_ref();
        let dest_ref = destination.as_ref();
        let (dest_parent, dest_display) = Self::validate_destination_path(dest_ref)?;

        let loaded = Self::open_file_internal(source_ref, password)?;
        let report = loaded
            .get_migration()
            .cloned()
            .unwrap_or_else(|| MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));

        if !report.was_migrated() && Self::is_same_existing_file(source_ref, dest_ref) {
            return Ok(report);
        }

        let preserved_encryption = Self::preserve_encryption_options(&loaded, password)?;
        let staged_path = Self::write_archive_staged(
            dest_parent,
            loaded.get_tree(),
            loaded.get_meta(),
            preserved_encryption.as_ref(),
        )?;
        if let Err(err) = Self::replace_file_from_staged(&staged_path, dest_ref, &dest_display) {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }

        Ok(report)
    }

    /// Migrates a `.hashed` snapshot in place to [`CURRENT_FORMAT_VERSION`], optionally creating
    /// a non-clobbering `.v<N>.bak` backup of the original file before replacing it.
    ///
    /// If the archive is already at [`CURRENT_FORMAT_VERSION`], this verifies the archive and
    /// returns an up-to-date [`MigrationReport`] without rewriting the file or creating a backup.
    ///
    /// # Errors
    ///
    /// Returns an error if the archive fails validation/migration, is encrypted without a password
    /// (use [`Self::migrate_file_in_place_with_password`]), backup creation fails, or atomic
    /// replacement fails.
    pub fn migrate_file_in_place(
        path: impl AsRef<Path>,
        create_backup: bool,
    ) -> Result<MigrationReport, BulkHashError> {
        Self::migrate_file_in_place_with_password(path, create_backup, None)
    }

    /// Password-aware counterpart to [`Self::migrate_file_in_place`].
    ///
    /// # Errors
    ///
    /// Returns an error if the archive fails validation/decryption/migration, backup creation
    /// fails, or atomic replacement fails.
    pub fn migrate_file_in_place_with_password(
        path: impl AsRef<Path>,
        create_backup: bool,
        password: Option<&str>,
    ) -> Result<MigrationReport, BulkHashError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();

        let loaded = Self::open_file_internal(path_ref, password)?;
        let Some(report) = loaded.get_migration().cloned() else {
            return Ok(MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));
        };

        let parent_dir = Self::resolve_parent_dir(path_ref);
        let preserved_encryption = Self::preserve_encryption_options(&loaded, password)?;
        let staged_path = Self::write_archive_staged(
            parent_dir,
            loaded.get_tree(),
            loaded.get_meta(),
            preserved_encryption.as_ref(),
        )?;

        let backup_path = if create_backup {
            match Self::create_backup_file(path_ref, report.original_version()) {
                Ok(backup) => Some(backup),
                Err(err) => {
                    let _ = fs::remove_file(&staged_path);
                    return Err(err);
                }
            }
        } else {
            None
        };

        if let Err(err) = Self::replace_file_from_staged(&staged_path, path_ref, &path_display) {
            let _ = fs::remove_file(&staged_path);
            return Err(err);
        }

        Ok(match backup_path {
            Some(backup) => report.with_backup_path(backup),
            None => report,
        })
    }

    fn open_file_internal(
        path_ref: &Path,
        password: Option<&str>,
    ) -> Result<BulkHashFileStruct, BulkHashError> {
        let mut probed = Self::open_and_probe_archive(path_ref)?;
        let registry = MigrationRegistry::with_builtin_migrations();

        // Check format version BEFORE checking version-specific entries or latest-schema fields
        // so future format versions always report `UnsupportedVersion` cleanly.
        if probed.version < registry.min_supported_version()
            || probed.version > registry.target_version()
        {
            return Err(BulkHashError::UnsupportedVersion(probed.version));
        }

        let required_entries =
            required_entries_for_archive(probed.version, probed.encrypted).ok_or_else(|| {
                    BulkHashError::FileIsCorrupted(format!(
                        "{}: encryption is not supported in format version {}",
                        probed.path_display, probed.version
                    ))
                })?;
        Self::validate_required_entries(&probed.entries, required_entries, &probed.path_display)?;

        if probed.encrypted && probed.entries.iter().any(|name| name == "tree.json") {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{}: encrypted archive must not contain plaintext 'tree.json'",
                probed.path_display
            )));
        }
        if !probed.encrypted && probed.entries.iter().any(|name| name == ENCRYPTED_TREE_ENTRY) {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{}: unencrypted archive must not contain '{ENCRYPTED_TREE_ENTRY}'",
                probed.path_display
            )));
        }

        if probed.encrypted {
            let enc_val = probed.meta_value.get("encryption").ok_or_else(|| {
                BulkHashError::InvalidEncryptionParameters(format!(
                    "{}: encrypted snapshot is missing 'encryption' metadata",
                    probed.path_display
                ))
            })?;
            let enc_meta = parse_encryption_metadata(enc_val)?;

            let Some(pwd) = password else {
                return Err(BulkHashError::PasswordRequired(probed.path_display));
            };
            if pwd.is_empty() {
                return Err(BulkHashError::EmptyPassword);
            }

            let expected_hash =
                Self::read_expected_hash(&mut probed.archive, &probed.path_display)?;
            let ciphertext = Self::read_entry_bounded(
                &mut probed.archive,
                ENCRYPTED_TREE_ENTRY,
                MAX_ENCRYPTED_TREE_BYTES,
                &probed.path_display,
            )?;

            // Verify ciphertext digest BEFORE Argon2id so on-disk corruption fails fast and
            // reports `HashMismatch` rather than misleadingly blaming the password.
            let actual_ciphertext_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&ciphertext);
            if !expected_hash.eq_ignore_ascii_case(&actual_ciphertext_hash) {
                return Err(BulkHashError::HashMismatch {
                    expected: expected_hash,
                    actual: actual_ciphertext_hash,
                });
            }

            let aad = build_tree_aad(probed.version, &probed.meta_bytes);
            let tree_bytes = decrypt_tree_payload(
                &ciphertext,
                pwd,
                &enc_meta,
                &aad,
                MAX_TREE_BYTES,
                &probed.path_display,
            )?;
            let plaintext_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree_bytes);

            Self::finalize_loaded_snapshot(
                probed.version,
                probed.meta_value,
                &tree_bytes,
                plaintext_hash,
                &registry,
            )
        } else {
            let expected_hash =
                Self::read_expected_hash(&mut probed.archive, &probed.path_display)?;
            let tree_bytes = Self::read_entry_bounded(
                &mut probed.archive,
                "tree.json",
                MAX_TREE_BYTES,
                &probed.path_display,
            )?;

            let actual_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree_bytes);
            if !expected_hash.eq_ignore_ascii_case(&actual_hash) {
                return Err(BulkHashError::HashMismatch {
                    expected: expected_hash,
                    actual: actual_hash,
                });
            }

            Self::finalize_loaded_snapshot(
                probed.version,
                probed.meta_value,
                &tree_bytes,
                actual_hash,
                &registry,
            )
        }
    }

    fn finalize_loaded_snapshot(
        version: usize,
        meta_value: Value,
        tree_bytes: &[u8],
        tree_hash: String,
        registry: &MigrationRegistry,
    ) -> Result<BulkHashFileStruct, BulkHashError> {
        // Fast path: archive is already at the latest format version — avoid parsing `tree.json`
        // into a generic `serde_json::Value` DOM so large snapshots load with minimal RAM.
        if version == CURRENT_FORMAT_VERSION {
            let meta: MetaData = serde_json::from_value(meta_value)?;
            let tree: DirectoryNode = serde_json::from_slice(tree_bytes)?;
            return Ok(BulkHashFileStruct::new(meta, tree, tree_hash));
        }

        // Migration path: parse raw tree JSON and run registered sequential migrations.
        let tree_value: Value = serde_json::from_slice(tree_bytes)?;
        let mut payload = SnapshotPayload::new(version, meta_value, tree_value);
        let report = registry.migrate(&mut payload)?;

        let meta: MetaData = serde_json::from_value(payload.meta)?;
        let tree: DirectoryNode = serde_json::from_value(payload.tree)?;
        if meta.get_version() != CURRENT_FORMAT_VERSION {
            return Err(BulkHashError::MigrationFailed {
                from_version: version,
                to_version: CURRENT_FORMAT_VERSION,
                reason: format!(
                    "post-migration metadata version is {} instead of {}",
                    meta.get_version(),
                    CURRENT_FORMAT_VERSION
                ),
            });
        }

        Ok(BulkHashFileStruct::new(meta, tree, tree_hash).with_migration(report))
    }

    fn read_expected_hash(
        archive: &mut ZipArchive<BufReader<File>>,
        path_display: &str,
    ) -> Result<String, BulkHashError> {
        let hash_bytes =
            Self::read_entry_bounded(archive, "hash.sha256", MAX_HASH_BYTES, path_display)?;
        let hash_text = String::from_utf8(hash_bytes).map_err(|_| {
            BulkHashError::FileIsCorrupted(format!(
                "{path_display}: 'hash.sha256' is not valid UTF-8"
            ))
        })?;
        let trimmed = hash_text.trim().to_string();
        if trimmed.is_empty() {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{path_display}: 'hash.sha256' is empty"
            )));
        }
        Ok(trimmed)
    }

    fn preserve_encryption_options(
        loaded: &BulkHashFileStruct,
        password: Option<&str>,
    ) -> Result<Option<EncryptionOptions>, BulkHashError> {
        let Some(enc_meta) = loaded.get_encryption() else {
            return Ok(None);
        };
        let Some(pwd) = password else {
            return Err(BulkHashError::PasswordRequired(String::from(
                "encrypted snapshot",
            )));
        };
        let opts = EncryptionOptions::new(pwd)?
            .with_kdf_params(enc_meta.kdf_params)?
            .with_payload_compression(enc_meta.payload_compression);
        Ok(Some(opts))
    }

    fn validate_destination_path(dest_ref: &Path) -> Result<(&Path, String), BulkHashError> {
        let dest_display = dest_ref.to_string_lossy().into_owned();
        Self::validate_hashed_extension(dest_ref, &dest_display)?;

        let dest_parent = Self::resolve_parent_dir(dest_ref);
        let parent_display = dest_parent.to_string_lossy().into_owned();
        let parent_exists = dest_parent
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, parent_display.clone()))?;
        if !parent_exists {
            return Err(BulkHashError::PathNotFound(parent_display));
        }
        if !dest_parent.is_dir() {
            return Err(BulkHashError::NotADirectory(parent_display));
        }

        let dest_exists = dest_ref
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, dest_display.clone()))?;
        if dest_exists && dest_ref.is_dir() {
            return Err(BulkHashError::NotAFile(dest_display));
        }

        Ok((dest_parent, dest_display))
    }

    fn open_and_probe_archive(path_ref: &Path) -> Result<ProbedArchive, BulkHashError> {
        let path_display = path_ref.to_string_lossy().into_owned();

        let exists = path_ref
            .try_exists()
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;

        if !exists {
            return Err(BulkHashError::FileNotFound(path_display));
        }

        if !path_ref.is_file() {
            return Err(BulkHashError::NotAFile(path_display));
        }

        Self::validate_hashed_extension(path_ref, &path_display)?;

        let file = File::open(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;
        let reader = BufReader::new(file);

        let mut archive = ZipArchive::new(reader)?;
        let entries: Vec<String> = archive
            .file_names()
            .map(|res| res.map(std::borrow::Cow::into_owned))
            .collect::<Result<Vec<_>, _>>()?;

        if !entries.iter().any(|name| name == "meta.json") {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{path_display}: missing required entry 'meta.json'"
            )));
        }

        let meta_bytes =
            Self::read_entry_bounded(&mut archive, "meta.json", MAX_META_BYTES, &path_display)?;
        let meta_value: Value = serde_json::from_slice(&meta_bytes)?;
        let version = extract_format_version(&meta_value, &path_display)?;

        let encrypted = meta_value.as_object().is_some_and(|obj| {
            obj.get("encryption").is_some_and(|val| !val.is_null())
                || obj
                    .get("encrypted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
        });

        Ok(ProbedArchive {
            archive,
            entries,
            meta_bytes,
            meta_value,
            version,
            encrypted,
            path_display,
        })
    }

    fn validate_hashed_extension(path_ref: &Path, path_display: &str) -> Result<(), BulkHashError> {
        let has_valid_ending = path_ref
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("hashed"));

        if !has_valid_ending {
            return Err(BulkHashError::InvalidEnding(path_display.to_owned()));
        }

        Ok(())
    }

    fn validate_required_entries(
        present_entries: &[String],
        required_entries: &[&str],
        path: &str,
    ) -> Result<(), BulkHashError> {
        for &required in required_entries {
            if !present_entries.iter().any(|name| name == required) {
                return Err(BulkHashError::FileIsCorrupted(format!(
                    "{path}: missing required entry '{required}'"
                )));
            }
        }

        Ok(())
    }

    fn write_archive(
        output_path: &Path,
        json: &DirectoryNode,
        meta: &MetaData,
        encryption: Option<&EncryptionOptions>,
    ) -> Result<(), BulkHashError> {
        let output_display = output_path.to_string_lossy().into_owned();
        let file = File::create(output_path)
            .map_err(|err| BulkHashError::from_io(err, output_display.clone()))?;
        Self::write_archive_to_file(file, json, meta, encryption, &output_display)
    }

    fn write_archive_staged(
        parent_dir: &Path,
        json: &DirectoryNode,
        meta: &MetaData,
        encryption: Option<&EncryptionOptions>,
    ) -> Result<PathBuf, BulkHashError> {
        let (temp_path, file) = Self::create_unique_temp_file(parent_dir)?;
        let temp_display = temp_path.to_string_lossy().into_owned();

        if let Err(err) = Self::write_archive_to_file(file, json, meta, encryption, &temp_display) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }

        Ok(temp_path)
    }

    fn write_archive_to_file(
        file: File,
        json: &DirectoryNode,
        meta: &MetaData,
        encryption: Option<&EncryptionOptions>,
        output_display: &str,
    ) -> Result<(), BulkHashError> {
        let writer = BufWriter::new(file);
        let mut zip = ZipWriter::new(writer);

        let deflated_options =
            SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        if let Some(enc_options) = encryption {
            let enc_meta = prepare_encryption_metadata(enc_options)?;
            let effective_meta = meta.clone().with_encryption_metadata(Some(enc_meta.clone()));
            let meta_bytes = serde_json::to_vec(&effective_meta)?;

            let aad = build_tree_aad(effective_meta.get_version(), &meta_bytes);
            let tree_bytes = Zeroizing::new(serde_json::to_vec(json)?);
            let ciphertext = encrypt_tree_payload(&tree_bytes, enc_options, &enc_meta, &aad)?;
            let ciphertext_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&ciphertext);

            zip.start_file("meta.json", deflated_options)?;
            zip.write_all(&meta_bytes)
                .map_err(|err| BulkHashError::from_io(err, output_display))?;

            // Ciphertext is incompressible random bytes, so store `tree.enc` without wasting ZIP
            // DEFLATE CPU cycles (inner plaintext compression is handled before encryption).
            let stored_options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
            zip.start_file(ENCRYPTED_TREE_ENTRY, stored_options)?;
            zip.write_all(&ciphertext)
                .map_err(|err| BulkHashError::from_io(err, output_display))?;

            zip.start_file("hash.sha256", deflated_options)?;
            zip.write_all(ciphertext_hash.as_bytes())
                .map_err(|err| BulkHashError::from_io(err, output_display))?;
        } else {
            let clean_meta = meta.clone().with_encryption_metadata(None);
            zip.start_file("meta.json", deflated_options)?;
            serde_json::to_writer(&mut zip, &clean_meta)?;

            let tree = serde_json::to_vec(json)?;
            let hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree);

            zip.start_file("tree.json", deflated_options)?;
            zip.write_all(&tree)
                .map_err(|err| BulkHashError::from_io(err, output_display))?;

            zip.start_file("hash.sha256", deflated_options)?;
            zip.write_all(hash.as_bytes())
                .map_err(|err| BulkHashError::from_io(err, output_display))?;
        }

        let mut writer = zip.finish()?;
        writer
            .flush()
            .map_err(|err| BulkHashError::from_io(err, output_display))?;
        let file = writer
            .into_inner()
            .map_err(|err| BulkHashError::from_io(err.into_error(), output_display))?;
        file.sync_all()
            .map_err(|err| BulkHashError::from_io(err, output_display))?;

        Ok(())
    }

    fn create_unique_temp_file(parent_dir: &Path) -> Result<(PathBuf, File), BulkHashError> {
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for _ in 0..MAX_UNIQUE_PATH_ATTEMPTS {
            let seq = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let candidate = parent_dir.join(format!(".bulkhash_staging_{pid}_{nanos}_{seq}.tmp"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(file) => return Ok((candidate, file)),
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(BulkHashError::from_io(
                        err,
                        candidate.to_string_lossy().into_owned(),
                    ));
                }
            }
        }

        Err(BulkHashError::Io {
            path: Some(parent_dir.to_string_lossy().into_owned()),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique temporary file for archive write",
            ),
        })
    }

    fn create_backup_file(
        source_path: &Path,
        original_version: usize,
    ) -> Result<PathBuf, BulkHashError> {
        let parent_dir = Self::resolve_parent_dir(source_path);
        let file_name = source_path
            .file_name()
            .map_or_else(|| String::from("snapshot.hashed"), |n| n.to_string_lossy().into_owned());

        for attempt in 0..MAX_UNIQUE_PATH_ATTEMPTS {
            let backup_name = if attempt == 0 {
                format!("{file_name}.v{original_version}.bak")
            } else {
                format!("{file_name}.v{original_version}.bak.{attempt}")
            };
            let candidate = parent_dir.join(backup_name);
            let candidate_display = candidate.to_string_lossy().into_owned();

            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(mut dst_file) => {
                    let copy_res = (|| -> Result<(), BulkHashError> {
                        let mut src_file = File::open(source_path).map_err(|err| {
                            BulkHashError::from_io(err, source_path.to_string_lossy().into_owned())
                        })?;
                        io::copy(&mut src_file, &mut dst_file)
                            .map_err(|err| BulkHashError::from_io(err, candidate_display.clone()))?;
                        dst_file
                            .flush()
                            .map_err(|err| BulkHashError::from_io(err, candidate_display.clone()))?;
                        dst_file
                            .sync_all()
                            .map_err(|err| BulkHashError::from_io(err, candidate_display.clone()))?;
                        Ok(())
                    })();

                    if let Err(err) = copy_res {
                        drop(dst_file);
                        let _ = fs::remove_file(&candidate);
                        return Err(err);
                    }

                    return Ok(candidate);
                }
                Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(BulkHashError::from_io(err, candidate_display)),
            }
        }

        Err(BulkHashError::Io {
            path: Some(source_path.to_string_lossy().into_owned()),
            source: io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique backup filename for migration",
            ),
        })
    }

    fn replace_file_from_staged(
        staged_path: &Path,
        destination: &Path,
        destination_display: &str,
    ) -> Result<(), BulkHashError> {
        #[cfg(unix)]
        {
            fs::rename(staged_path, destination)
                .map_err(|err| BulkHashError::from_io(err, destination_display))?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            match fs::rename(staged_path, destination) {
                Ok(()) => Ok(()),
                Err(_) if destination.exists() => {
                    let parent = Self::resolve_parent_dir(destination);
                    let (rollback_path, rollback_file) = Self::create_unique_temp_file(parent)?;
                    drop(rollback_file);
                    let _ = fs::remove_file(&rollback_path);

                    fs::rename(destination, &rollback_path)
                        .map_err(|err| BulkHashError::from_io(err, destination_display))?;

                    if let Err(err) = fs::rename(staged_path, destination) {
                        let _ = fs::rename(&rollback_path, destination);
                        return Err(BulkHashError::from_io(err, destination_display));
                    }

                    let _ = fs::remove_file(&rollback_path);
                    Ok(())
                }
                Err(err) => Err(BulkHashError::from_io(err, destination_display)),
            }
        }
    }

    fn resolve_parent_dir(path: &Path) -> &Path {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    fn is_same_existing_file(a: &Path, b: &Path) -> bool {
        match (fs::canonicalize(a), fs::canonicalize(b)) {
            (Ok(ca), Ok(cb)) => ca == cb,
            _ => false,
        }
    }

    fn read_entry_bounded(
        archive: &mut ZipArchive<BufReader<File>>,
        entry_name: &str,
        max_bytes: u64,
        archive_path: &str,
    ) -> Result<Vec<u8>, BulkHashError> {
        let entry = archive.by_name(entry_name)?;
        let mut buf = Vec::new();
        entry
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|err| BulkHashError::from_io(err, archive_path))?;

        if (buf.len() as u64) > max_bytes {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{archive_path}: entry '{entry_name}' exceeds maximum allowed size"
            )));
        }

        Ok(buf)
    }
}
