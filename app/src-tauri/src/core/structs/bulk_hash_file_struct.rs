use crate::core::io::{
    compression::{CompressionLevel, CompressionMetadata},
    directory_node::DirectoryNode,
    encryption::EncryptionMetadata,
    meta_data::MetaData,
    migration::MigrationReport,
};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct BulkHashFileStruct {
    meta: MetaData,
    tree: DirectoryNode,
    hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    migration: Option<MigrationReport>,
}

impl BulkHashFileStruct {
    #[must_use]
    pub const fn new(meta: MetaData, tree: DirectoryNode, hash: String) -> Self {
        Self {
            meta,
            tree,
            hash,
            migration: None,
        }
    }

    #[must_use]
    pub fn with_migration(mut self, report: MigrationReport) -> Self {
        self.migration = report.was_migrated().then_some(report);
        self
    }

    #[must_use]
    pub const fn get_meta(&self) -> &MetaData {
        &self.meta
    }

    #[must_use]
    pub const fn get_tree(&self) -> &DirectoryNode {
        &self.tree
    }

    #[must_use]
    pub fn get_hash(&self) -> &str {
        &self.hash
    }

    #[must_use]
    pub const fn get_migration(&self) -> Option<&MigrationReport> {
        self.migration.as_ref()
    }

    #[must_use]
    pub fn was_migrated(&self) -> bool {
        self.migration
            .as_ref()
            .is_some_and(MigrationReport::was_migrated)
    }

    #[must_use]
    pub fn get_original_version(&self) -> usize {
        self.migration
            .as_ref()
            .map_or_else(|| self.meta.get_version(), MigrationReport::original_version)
    }

    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.meta.is_encrypted()
    }

    #[must_use]
    pub const fn get_encryption(&self) -> Option<&EncryptionMetadata> {
        self.meta.get_encryption()
    }

    #[must_use]
    pub const fn get_compression(&self) -> Option<CompressionMetadata> {
        self.meta.get_compression()
    }

    #[must_use]
    pub const fn get_compression_level(&self) -> Option<CompressionLevel> {
        self.meta.get_compression_level()
    }
}
