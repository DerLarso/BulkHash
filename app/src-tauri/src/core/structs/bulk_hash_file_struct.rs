use crate::core::io::{directory_node::DirectoryNode, meta_data::MetaData};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BulkHashFileStruct {
    meta: MetaData,
    tree: DirectoryNode,
    hash: String,
}

impl BulkHashFileStruct {
    pub fn new(meta: MetaData, tree: DirectoryNode, hash: String) -> Self {
        Self { meta, tree, hash }
    }

    pub fn get_meta(&self) -> &MetaData {
        &self.meta
    }

    pub fn get_tree(&self) -> &DirectoryNode {
        &self.tree
    }

    pub fn get_hash(&self) -> &str {
        &self.hash
    }
}
