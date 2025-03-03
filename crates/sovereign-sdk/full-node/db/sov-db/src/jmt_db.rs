#![allow(missing_docs)]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use jmt::storage::TreeWriter;
use jmt::{KeyHash, OwnedValue, Sha256Jmt, Version};
use sha2::Sha256;
use sov_rollup_interface::zk::{SparseMerkleProofSha2, StorageRootHash, UpdateMerkleProofSha2};

use crate::rocks_db_config::RocksdbConfig;
use crate::state_db::StateDB;

#[derive(Debug, Clone)]
pub struct JmtDB {
    db: StateDB,
    init_version: u64,
    version: Arc<AtomicU64>,
    db_handle: Arc<sov_schema_db::DB>,
}

impl JmtDB {
    /// JmtDB path suffix
    pub const DB_PATH_SUFFIX: &'static str = "jmt";
    const DB_NAME: &'static str = "jmt-db";

    /// Initialize [`DB`] that should be globally used
    pub fn new(cfg: &RocksdbConfig) -> anyhow::Result<Self> {
        let inner_db = Arc::new(StateDB::setup_schema_db_with_path_and_suffix(
            cfg,
            Self::DB_NAME,
            Self::DB_PATH_SUFFIX,
        )?);
        let db = StateDB::new(inner_db.clone());

        let version = db.next_version().saturating_sub(1);
        Ok(Self {
            db,
            init_version: version,
            version: Arc::new(AtomicU64::new(version)),
            db_handle: inner_db,
        })
    }

    pub fn db_handle(&self) -> Arc<sov_schema_db::DB> {
        self.db_handle.clone()
    }

    pub fn hash_key(key: &[u8]) -> KeyHash {
        KeyHash::with::<Sha256>(key)
    }

    /// Insert the (key, val) and returns the new root hash
    pub fn insert(&self, key: &[u8], value: &[u8]) -> anyhow::Result<[u8; 32]> {
        let current_version = self.version.load(Ordering::SeqCst);
        let next_version = current_version + 1;

        let jmt = Sha256Jmt::new(&self.db);
        let value: OwnedValue = value.to_vec();
        let key_hash = Self::hash_key(key);

        self.db.put_preimages(vec![(key_hash, key)])?;

        let (root_hash, tree_update) =
            jmt.put_value_set(vec![(key_hash, Some(value))], next_version)?;

        self.db
            .write_node_batch(&tree_update.node_batch)
            .expect("db write must succeed");

        self.version.store(next_version, Ordering::SeqCst);

        Ok(root_hash.0)
    }

    pub fn get_current_root_hash(&self) -> anyhow::Result<StorageRootHash> {
        self.get_root_hash(self.version.load(Ordering::SeqCst))
    }

    fn get_root_hash(&self, version: Version) -> anyhow::Result<StorageRootHash> {
        let temp_merkle = Sha256Jmt::new(&self.db);
        temp_merkle.get_root_hash(version).map(Into::into)
    }

    pub fn contains(&self, key: &[u8]) -> anyhow::Result<bool> {
        let jmt = Sha256Jmt::new(&self.db);
        let version = self.version.load(Ordering::SeqCst);
        let key_hash = Self::hash_key(key);

        Ok(jmt.get(key_hash, version)?.is_some())
    }

    pub fn generate_proof(&self, key: &[u8]) -> anyhow::Result<SparseMerkleProofSha2> {
        let jmt = Sha256Jmt::<StateDB>::new(&self.db);
        let version = self.version.load(Ordering::SeqCst);
        let key_hash = Self::hash_key(key);

        jmt.get_with_proof(key_hash, version)
            .map(|(_, proof)| proof)
    }

    pub fn create_update_proof(&self, key: &[u8]) -> anyhow::Result<UpdateMerkleProofSha2> {
        let proof = self.generate_proof(key)?;
        let update_proof = UpdateMerkleProofSha2::new(vec![proof]);

        Ok(update_proof)
    }
}
