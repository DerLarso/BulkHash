use std::collections::BTreeMap;
use std::path::{Component, Path};

use crate::core::structs::file_info::FileInfo;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DirectoryNode {
    pub name: String,
    pub files: BTreeMap<String, Result<String, String>>,
    pub sub_directories: BTreeMap<String, DirectoryNode>,
}

impl DirectoryNode {
    pub fn new(name: String) -> Self {
        Self {
            name,
            files: BTreeMap::new(),
            sub_directories: BTreeMap::new(),
        }
    }

    pub fn insert_path(&mut self, path_parts: &[&str], result: Result<String, String>) {
        let Some((&file_name, dirs)) = path_parts.split_last() else {
            return;
        };

        let mut current = self;
        for &folder in dirs {
            current = current
                .sub_directories
                .entry(folder.to_string())
                .or_insert_with(|| Self::new(folder.to_string()));
        }

        current.files.insert(file_name.to_string(), result);
    }

    pub fn build_tree(start_path: &str, file_list: &[FileInfo]) -> Self {
        let mut root = Self::new(start_path.to_string());
        let base_path = Path::new(start_path);

        for file in file_list {
            let full_path = Path::new(file.get_path());
            let relative_path = full_path.strip_prefix(base_path).unwrap_or(full_path);

            let owned_parts: Vec<String> = relative_path
                .components()
                .filter_map(|component| match component {
                    Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect();

            let owned_parts = if owned_parts.is_empty() {
                full_path
                    .file_name()
                    .map(|name| vec![name.to_string_lossy().into_owned()])
                    .unwrap_or_default()
            } else {
                owned_parts
            };

            let path_parts: Vec<&str> = owned_parts.iter().map(String::as_str).collect();

            let result = match file.get_result() {
                Ok(hash) => Ok(hash.clone()),
                Err(err) => Err(err.to_string()),
            };

            root.insert_path(&path_parts, result);
        }

        root
    }
}
