use chrono::{DateTime, Utc};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path};

use crate::core::structs::file_info::FileInfo;
pub use crate::core::structs::file_metadata::FileMetadata;

/// Per-file entry stored inside a [`DirectoryNode`], combining the hash result
/// (or error message) with extended file metadata such as size and last
/// modification timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub result: Result<String, String>,
    pub size: Option<u64>,
    pub modified_utc: Option<DateTime<Utc>>,
}

impl FileEntry {
    #[must_use]
    pub const fn new(
        result: Result<String, String>,
        size: Option<u64>,
        modified_utc: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            result,
            size,
            modified_utc,
        }
    }

    #[must_use]
    pub const fn from_result(result: Result<String, String>) -> Self {
        Self {
            result,
            size: None,
            modified_utc: None,
        }
    }

    #[must_use]
    pub const fn from_hash(
        hash: String,
        size: Option<u64>,
        modified_utc: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            result: Ok(hash),
            size,
            modified_utc,
        }
    }

    #[must_use]
    pub const fn from_error(
        error: String,
        size: Option<u64>,
        modified_utc: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            result: Err(error),
            size,
            modified_utc,
        }
    }

    #[must_use]
    pub const fn with_metadata(result: Result<String, String>, metadata: FileMetadata) -> Self {
        Self {
            result,
            size: metadata.size(),
            modified_utc: metadata.modified_utc(),
        }
    }

    #[must_use]
    pub fn from_file_info(file: &FileInfo) -> Self {
        let result = match file.get_result() {
            Ok(hash) => Ok(hash.clone()),
            Err(err) => Err(err.to_string()),
        };
        Self::with_metadata(result, file.get_metadata())
    }

    #[must_use]
    pub fn hash(&self) -> Option<&str> {
        self.result.as_deref().ok()
    }

    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.result.as_ref().err().map(String::as_str)
    }

    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    #[must_use]
    pub const fn is_err(&self) -> bool {
        self.result.is_err()
    }

    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    #[must_use]
    pub const fn modified_utc(&self) -> Option<DateTime<Utc>> {
        self.modified_utc
    }

    #[must_use]
    pub const fn metadata(&self) -> FileMetadata {
        FileMetadata::new(self.size, self.modified_utc)
    }
}

impl From<Result<String, String>> for FileEntry {
    fn from(result: Result<String, String>) -> Self {
        Self::from_result(result)
    }
}

impl From<&FileInfo> for FileEntry {
    fn from(file: &FileInfo) -> Self {
        Self::from_file_info(file)
    }
}

impl Serialize for FileEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count =
            1 + usize::from(self.size.is_some()) + usize::from(self.modified_utc.is_some());
        let mut state = serializer.serialize_struct("FileEntry", field_count)?;
        match &self.result {
            Ok(hash) => state.serialize_field("hash", hash)?,
            Err(error) => state.serialize_field("error", error)?,
        }
        if let Some(size) = self.size {
            state.serialize_field("size", &size)?;
        }
        if let Some(modified_utc) = self.modified_utc {
            state.serialize_field("modified_utc", &modified_utc)?;
        }
        state.end()
    }
}

#[derive(Deserialize)]
enum FileEntryField {
    #[serde(rename = "hash")]
    Hash,
    #[serde(rename = "error")]
    Error,
    #[serde(rename = "Ok")]
    LegacyOk,
    #[serde(rename = "Err")]
    LegacyErr,
    #[serde(rename = "size")]
    Size,
    #[serde(rename = "modified_utc")]
    ModifiedUtc,
    #[serde(other)]
    Ignore,
}

struct FileEntryVisitor;

impl<'de> Visitor<'de> for FileEntryVisitor {
    type Value = FileEntry;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a file entry object with 'hash'/'error' (or legacy 'Ok'/'Err')")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut hash: Option<String> = None;
        let mut error: Option<String> = None;
        let mut size: Option<Option<u64>> = None;
        let mut modified_utc: Option<Option<DateTime<Utc>>> = None;

        while let Some(field) = map.next_key::<FileEntryField>()? {
            match field {
                FileEntryField::Hash | FileEntryField::LegacyOk => {
                    if hash.is_some() {
                        return Err(de::Error::duplicate_field("hash"));
                    }
                    hash = Some(map.next_value()?);
                }
                FileEntryField::Error | FileEntryField::LegacyErr => {
                    if error.is_some() {
                        return Err(de::Error::duplicate_field("error"));
                    }
                    error = Some(map.next_value()?);
                }
                FileEntryField::Size => {
                    if size.is_some() {
                        return Err(de::Error::duplicate_field("size"));
                    }
                    size = Some(map.next_value()?);
                }
                FileEntryField::ModifiedUtc => {
                    if modified_utc.is_some() {
                        return Err(de::Error::duplicate_field("modified_utc"));
                    }
                    modified_utc = Some(map.next_value()?);
                }
                FileEntryField::Ignore => {
                    let _ = map.next_value::<de::IgnoredAny>()?;
                }
            }
        }

        let result = match (hash, error) {
            (Some(h), None) => Ok(h),
            (None, Some(e)) => Err(e),
            (Some(_), Some(_)) => {
                return Err(de::Error::custom(
                    "file entry cannot specify both 'hash' and 'error'",
                ));
            }
            (None, None) => {
                return Err(de::Error::custom(
                    "file entry must specify either 'hash' or 'error'",
                ));
            }
        };

        Ok(FileEntry {
            result,
            size: size.flatten(),
            modified_utc: modified_utc.flatten(),
        })
    }
}

impl<'de> Deserialize<'de> for FileEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(FileEntryVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryNode {
    pub name: String,
    pub files: BTreeMap<String, FileEntry>,
    pub sub_directories: BTreeMap<String, DirectoryNode>,
}

impl Drop for DirectoryNode {
    fn drop(&mut self) {
        if self.sub_directories.is_empty() {
            return;
        }
        let mut stack: Vec<Self> = std::mem::take(&mut self.sub_directories)
            .into_values()
            .collect();
        while let Some(mut node) = stack.pop() {
            stack.extend(std::mem::take(&mut node.sub_directories).into_values());
        }
    }
}

impl DirectoryNode {
    #[must_use]
    pub const fn new(name: String) -> Self {
        Self {
            name,
            files: BTreeMap::new(),
            sub_directories: BTreeMap::new(),
        }
    }

    pub fn insert_path(&mut self, path_parts: &[&str], entry: impl Into<FileEntry>) {
        let Some((&file_name, dirs)) = path_parts.split_last() else {
            return;
        };

        let mut current = self;
        for &folder in dirs {
            current = current.get_or_create_subdir(folder);
        }

        current.files.insert(file_name.to_string(), entry.into());
    }

    fn get_or_create_subdir(&mut self, folder: &str) -> &mut Self {
        if !self.sub_directories.contains_key(folder) {
            self.sub_directories
                .insert(folder.to_owned(), Self::new(folder.to_owned()));
        }
        self.sub_directories
            .get_mut(folder)
            .expect("subdirectory was just inserted or already existed")
    }

    #[must_use]
    pub fn build_tree(start_path: &str, file_list: &[FileInfo]) -> Self {
        let mut root = Self::new(start_path.to_string());
        let base_path = Path::new(start_path);
        let mut parts_buf: Vec<Cow<'_, str>> = Vec::new();

        for file in file_list {
            let full_path = Path::new(file.get_path());
            let relative_path = full_path.strip_prefix(base_path).unwrap_or(full_path);

            parts_buf.clear();
            for component in relative_path.components() {
                if let Component::Normal(part) = component {
                    parts_buf.push(part.to_string_lossy());
                }
            }

            if parts_buf.is_empty()
                && let Some(name) = full_path.file_name()
            {
                parts_buf.push(name.to_string_lossy());
            }

            let Some((file_name, dirs)) = parts_buf.split_last() else {
                continue;
            };

            let mut current = &mut root;
            for folder in dirs {
                current = current.get_or_create_subdir(folder.as_ref());
            }

            current
                .files
                .insert(file_name.as_ref().to_owned(), FileEntry::from_file_info(file));
        }

        root
    }

    /// Returns the total known file size in bytes across this directory and all subdirectories.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        let mut total = 0u64;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            for entry in node.files.values() {
                if let Some(size) = entry.size {
                    total = total.saturating_add(size);
                }
            }
            stack.extend(node.sub_directories.values());
        }
        total
    }

    /// Returns the total known file size in bytes across all successfully hashed files
    /// in this directory and all subdirectories.
    #[must_use]
    pub fn hashed_size(&self) -> u64 {
        let mut total = 0u64;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            for entry in node.files.values() {
                if entry.is_ok()
                    && let Some(size) = entry.size
                {
                    total = total.saturating_add(size);
                }
            }
            stack.extend(node.sub_directories.values());
        }
        total
    }

    /// Returns the total number of file entries (both hashed and errored) in this subtree.
    #[must_use]
    pub fn file_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            count = count.saturating_add(node.files.len());
            stack.extend(node.sub_directories.values());
        }
        count
    }

    /// Returns the number of successfully hashed file entries in this subtree.
    #[must_use]
    pub fn hashed_file_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            let ok_count = node.files.values().filter(|entry| entry.is_ok()).count();
            count = count.saturating_add(ok_count);
            stack.extend(node.sub_directories.values());
        }
        count
    }

    /// Returns the number of errored file entries in this subtree.
    #[must_use]
    pub fn error_count(&self) -> usize {
        let mut count = 0usize;
        let mut stack = vec![self];
        while let Some(node) = stack.pop() {
            let err_count = node.files.values().filter(|entry| entry.is_err()).count();
            count = count.saturating_add(err_count);
            stack.extend(node.sub_directories.values());
        }
        count
    }

    /// Looks up a file entry by canonical relative path (accepting both `/` and `\` separators).
    #[must_use]
    pub fn find_file(&self, relative_path: &str) -> Option<&FileEntry> {
        let parts: Vec<&str> = relative_path
            .split(['/', '\\'])
            .filter(|segment| !segment.is_empty() && *segment != ".")
            .collect();
        let (&file_name, dirs) = parts.split_last()?;
        let mut current = self;
        for &dir in dirs {
            current = current.sub_directories.get(dir)?;
        }
        current.files.get(file_name)
    }

    /// Looks up a subdirectory by relative path (accepting both `/` and `\` separators).
    /// Returns `Some(self)` for `""`, `"."`, or `"/"`.
    #[must_use]
    pub fn find_directory(&self, relative_path: &str) -> Option<&Self> {
        let mut current = self;
        for dir in relative_path
            .split(['/', '\\'])
            .filter(|segment| !segment.is_empty() && *segment != ".")
        {
            current = current.sub_directories.get(dir)?;
        }
        Some(current)
    }
}
