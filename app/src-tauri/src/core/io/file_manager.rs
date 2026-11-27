use std::{
    borrow::Cow,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use zip::{ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::core::{
    hash_manager::HashAlgorithm,
    io::{bulk_hash_error::BulkHashError, directory_node::DirectoryNode, meta_data::MetaData},
    structs::bulk_hash_file_struct::BulkHashFileStruct,
};

const SUPPORTED_FORMAT_VERSION: usize = 1;
const MAX_META_BYTES: u64 = 1024 * 1024; // 1 MiB
const MAX_HASH_BYTES: u64 = 1024; // 1 KiB
const MAX_TREE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

pub struct FileManager {}

impl FileManager {
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

    fn write_archive(
        output_path: &Path,
        json: &DirectoryNode,
        meta: &MetaData,
    ) -> Result<(), BulkHashError> {
        let output_display = output_path.to_string_lossy().into_owned();
        let file = File::create(output_path)
            .map_err(|err| BulkHashError::from_io(err, output_display.clone()))?;
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
            .map_err(|err| BulkHashError::from_io(err, output_display.clone()))?;

        zip.start_file("hash.sha256", options)?;
        zip.write_all(hash.as_bytes())
            .map_err(|err| BulkHashError::from_io(err, output_display.clone()))?;

        let mut writer = zip.finish()?;
        writer
            .flush()
            .map_err(|err| BulkHashError::from_io(err, output_display))?;

        Ok(())
    }

    pub fn open_file(path: impl AsRef<Path>) -> Result<BulkHashFileStruct, BulkHashError> {
        let path_ref = path.as_ref();
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

        let has_valid_ending = path_ref
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("hashed"));

        if !has_valid_ending {
            return Err(BulkHashError::InvalidEnding(path_display));
        }

        let file = File::open(path_ref)
            .map_err(|err| BulkHashError::from_io(err, path_display.clone()))?;
        let reader = BufReader::new(file);

        let mut content = ZipArchive::new(reader)?;
        Self::validate_zip(&content, &path_display)?;

        let meta_bytes =
            Self::read_entry_bounded(&mut content, "meta.json", MAX_META_BYTES, &path_display)?;
        let meta: MetaData = serde_json::from_slice(&meta_bytes)?;

        let version = meta.get_version();
        if version != SUPPORTED_FORMAT_VERSION {
            return Err(BulkHashError::UnsupportedVersion(version));
        }

        let hash_bytes =
            Self::read_entry_bounded(&mut content, "hash.sha256", MAX_HASH_BYTES, &path_display)?;
        let hash_of_tree = String::from_utf8(hash_bytes).map_err(|_| {
            BulkHashError::FileIsCorrupted(format!(
                "{path_display}: 'hash.sha256' is not valid UTF-8"
            ))
        })?;
        let trimmed = hash_of_tree.trim().to_string();
        if trimmed.is_empty() {
            return Err(BulkHashError::FileIsCorrupted(format!(
                "{path_display}: 'hash.sha256' is empty"
            )));
        }

        let tree_bytes =
            Self::read_entry_bounded(&mut content, "tree.json", MAX_TREE_BYTES, &path_display)?;

        let actual_hash = HashAlgorithm::Sha256.get_hash_from_bytes(&tree_bytes);

        if !trimmed.eq_ignore_ascii_case(&actual_hash) {
            return Err(BulkHashError::HashMismatch {
                expected: trimmed,
                actual: actual_hash,
            });
        }

        let tree: DirectoryNode = serde_json::from_slice(&tree_bytes)?;
        Ok(BulkHashFileStruct::new(meta, tree, actual_hash))
    }

    fn validate_zip(
        archive: &ZipArchive<BufReader<File>>,
        path: &str,
    ) -> Result<(), BulkHashError> {
        let required_entries = ["meta.json", "hash.sha256", "tree.json"];
        let present_entries: Vec<Cow<'_, str>> =
            archive.file_names().collect::<Result<Vec<_>, _>>()?;

        for required in required_entries {
            if !present_entries.iter().any(|name| name.as_ref() == required) {
                return Err(BulkHashError::FileIsCorrupted(format!(
                    "{path}: missing required entry '{required}'"
                )));
            }
        }

        Ok(())
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
