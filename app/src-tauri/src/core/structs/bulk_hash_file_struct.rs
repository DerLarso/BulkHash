use crate::core::io::{directory_node::DirectoryNode, meta_data::MetaData};

pub struct BulkHashFileStruct {
    meta: MetaData,
    tree: DirectoryNode,
    hash: String,
}

impl BulkHashFileStruct {
    pub fn new(meta: MetaData, tree: DirectoryNode, hash: String) -> BulkHashFileStruct {
        BulkHashFileStruct { meta, tree, hash }
    }
    pub fn get_meta(&self) -> &MetaData {
        &self.meta
    }
    pub fn get_tree(&self) -> &DirectoryNode {
        &self.tree
    }
    pub fn get_hash(&self) -> &String {
        &self.hash
    }
}
