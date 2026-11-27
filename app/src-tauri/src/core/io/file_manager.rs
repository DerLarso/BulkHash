use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::core::{
    hash_manager::HashAlgorithm,
    io::{
        bulk_hash_error::BulkHashError,
        directory_node::DirectoryNode,
        meta_data::MetaData,
        migration::{
            ArchiveVersionInfo, CURRENT_FORMAT_VERSION, MigrationRegistry, MigrationReport,
            SnapshotPayload, extract_format_version, required_entries_for_version,
        },
    },
    structs::bulk_hash_file_struct::BulkHashFileStruct,
};

const MAX_META_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_HASH_BYTES: u64 = 1024; // 1 KiB
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
const MAX_UNIQUE_PATH_ATTEMPTS: usize = 10_000;

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ProbedArchive {
    archive: ZipArchive<BufReader<File>>,
    entries: Vec<String>,
    meta_value: Value,
    version: usize,
    path_display: String,
}

pub struct FileManager {}

impl FileManager {
    /// Saves a snapshot into `folder` using the current `.hashed` format version.
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

        let file_name = format!(
            "{}-{}.hashed",
            meta.get_current_os(),
            meta.get_filename_timestamp()
        );
        let output_path = folder_path.join(file_name);

        let write_result = Self::write_archive(&output_path, json, meta);
        if let Err(err) = write_result {
            let _ = fs::remove_file(&output_path);
            return Err(err);
        }

        Ok(output_path)
    }

    /// Inspects a `.hashed` archive's format version and entry list without reading or
    /// deserializing `tree.json`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file does not exist, has an invalid extension, is not a valid ZIP
    /// archive, or has a missing/corrupted `meta.json`.
    pub fn inspect_version(path: impl AsRef<Path>) -> Result<ArchiveVersionInfo, BulkHashError> {
        let probed = Self::open_and_probe_archive(path.as_ref())?;
        let registry = MigrationRegistry::with_builtin_migrations();
        let compatibility = registry.check_compatibility(probed.version);

        Ok(ArchiveVersionInfo {
            version: probed.version,
            current_version: CURRENT_FORMAT_VERSION,
            compatibility,
            entries: probed.entries,
        })
    }

    /// Opens a `.hashed` snapshot, verifying integrity and transparently migrating older
    /// supported format versions in memory to [`CURRENT_FORMAT_VERSION`].
    ///
    /// # Errors
    ///
    /// Returns an error if the file is missing, invalid, corrupted, tampered with, uses an
    /// unsupported format version, or fails migration.
    pub fn open_file(path: impl AsRef<Path>) -> Result<BulkHashFileStruct, BulkHashError> {
        let mut probed = Self::open_and_probe_archive(path.as_ref())?;
        let registry = MigrationRegistry::with_builtin_migrations();

        // Check format version BEFORE checking version-specific entries or latest-schema fields
        // so future format versions always report `UnsupportedVersion` cleanly.
        if probed.version < registry.min_supported_version()
            || probed.version > registry.target_version()
        {
            return Err(BulkHashError::UnsupportedVersion(probed.version));
        }

        let required_entries = required_entries_for_version(probed.version)
            .ok_or(BulkHashError::UnsupportedVersion(probed.version))?;
        Self::validate_required_entries(&probed.entries, required_entries, &probed.path_display)?;

        let hash_bytes = Self::read_entry_bounded(
            &mut probed.archive,
            "hash.sha256",
            MAX_HASH_BYTES,
            &probed.path_display,
        )?;
        let hash_of_tree = String::from_utf8(hash_bytes).map_err(|_| {
            BulkHashError::FileIsCorrupted(format!(
                "{}: 'hash.sha256' is not valid UTF-8",
                probed.path_display
            ))
        })?;
        let trimmed = hash_of_tree.trim().to_string();
        if trimmed.is_empty() {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{}: 'hash.sha256' is empty",
                probed.path_display
            )));
        }

        let tree_bytes = Self::read_entry_bounded(
            &mut probed.archive,
            "tree.json",
            MAX_TREE_BYTES,
            &probed.path_display,
        )?;

        let actual_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree_bytes);

        if !trimmed.eq_ignore_ascii_case(&actual_hash) {
            return Err(BulkHashError::HashMismatch {
                expected: trimmed,
                actual: actual_hash,
            });
        }

        // Fast path: archive is already at the latest format version — avoid parsing `tree.json`
        // into a generic `serde_json::Value` DOM so large snapshots load with minimal RAM.
        if probed.version == CURRENT_FORMAT_VERSION {
            let meta: MetaData = serde_json::from_value(probed.meta_value)?;
            let tree: DirectoryNode = serde_json::from_slice(&tree_bytes)?;
            return Ok(BulkHashFileStruct::new(meta, tree, actual_hash));
        }

        // Migration path: parse raw tree JSON and run registered sequential migrations.
        let tree_value: Value = serde_json::from_slice(&tree_bytes)?;
        let mut payload = SnapshotPayload::new(probed.version, probed.meta_value, tree_value);
        let report = registry.migrate(&mut payload)?;

        let meta: MetaData = serde_json::from_value(payload.meta)?;
        let tree: DirectoryNode = serde_json::from_value(payload.tree)?;
        if meta.get_version() != CURRENT_FORMAT_VERSION {
            return Err(BulkHashError::MigrationFailed {
                from_version: probed.version,
                to_version: CURRENT_FORMAT_VERSION,
                reason: format!(
                    "post-migration metadata version is {} instead of {}",
                    meta.get_version(),
                    CURRENT_FORMAT_VERSION
                ),
            });
        }

        Ok(BulkHashFileStruct::new(meta, tree, actual_hash).with_migration(report))
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
    /// Returns an error if `source` fails validation/migration or `destination` is invalid.
    pub fn migrate_file(
        source: impl AsRef<Path>,
        destination: impl AsRef<Path>,
    ) -> Result<MigrationReport, BulkHashError> {
        let source_ref = source.as_ref();
        let dest_ref = destination.as_ref();
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

        let loaded = Self::open_file(source_ref)?;
        let report = loaded
            .get_migration()
            .cloned()
            .unwrap_or_else(|| MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));

        if !report.was_migrated() && Self::is_same_existing_file(source_ref, dest_ref) {
            return Ok(report);
        }

        let staged_path =
            Self::write_archive_staged(dest_parent, loaded.get_tree(), loaded.get_meta())?;
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
    /// Returns an error if the archive fails validation/migration, backup creation fails, or
    /// atomic replacement fails.
    pub fn migrate_file_in_place(
        path: impl AsRef<Path>,
        create_backup: bool,
    ) -> Result<MigrationReport, BulkHashError> {
        let path_ref = path.as_ref();
        let path_display = path_ref.to_string_lossy().into_owned();

        let loaded = Self::open_file(path_ref)?;
        let Some(report) = loaded.get_migration().cloned() else {
            return Ok(MigrationReport::up_to_date(CURRENT_FORMAT_VERSION));
        };

        let parent_dir = Self::resolve_parent_dir(path_ref);
        let staged_path =
            Self::write_archive_staged(parent_dir, loaded.get_tree(), loaded.get_meta())?;

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

        Ok(ProbedArchive {
            archive,
            entries,
            meta_value,
            version,
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
    ) -> Result<(), BulkHashError> {
        let output_display = output_path.to_string_lossy().into_owned();
        let file = File::create(output_path)
            .map_err(|err| BulkHashError::from_io(err, output_display.clone()))?;
        Self::write_archive_to_file(file, json, meta, &output_display)
    }

    fn write_archive_staged(
        parent_dir: &Path,
        json: &DirectoryNode,
        meta: &MetaData,
    ) -> Result<PathBuf, BulkHashError> {
        let (temp_path, file) = Self::create_unique_temp_file(parent_dir)?;
        let temp_display = temp_path.to_string_lossy().into_owned();

        if let Err(err) = Self::write_archive_to_file(file, json, meta, &temp_display) {
            let _ = fs::remove_file(&temp_path);
            return Err(err);
        }

        Ok(temp_path)
    }

    fn write_archive_to_file(
        file: File,
        json: &DirectoryNode,
        meta: &MetaData,
        output_display: &str,
    ) -> Result<(), BulkHashError> {
        let writer = BufWriter::new(file);
        let mut zip = ZipWriter::new(writer);

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("meta.json", options)?;
        serde_json::to_writer(&mut zip, meta)?;

        let tree = serde_json::to_vec(json)?;
        let hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree);

        zip.start_file("tree.json", options)?;
        zip.write_all(&tree)
            .map_err(|err| BulkHashError::from_io(err, output_display))?;

        zip.start_file("hash.sha256", options)?;
        zip.write_all(hash.as_bytes())
            .map_err(|err| BulkHashError::from_io(err, output_display))?;

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
            let candidate = parent_dir.join(format!(".bulkhash_migrating_{pid}_{nanos}_{seq}.tmp"));
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
                "could not allocate a unique temporary file for migration",
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
