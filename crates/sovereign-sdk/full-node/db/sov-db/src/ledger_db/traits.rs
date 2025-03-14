use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use sov_rollup_interface::block::L2Block;
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::zk::{Proof, StorageRootHash};
use sov_schema_db::SchemaBatch;

use crate::schema::types::batch_proof::{StoredBatchProof, StoredBatchProofOutput};
use crate::schema::types::l2_block::StoredL2Block;
use crate::schema::types::light_client_proof::{
    StoredLightClientProof, StoredLightClientProofOutput,
};
use crate::schema::types::{L2BlockNumber, L2HeightRange, SlotNumber};

/// Shared ledger operations
pub trait SharedLedgerOps {
    /// Return DB path
    fn path(&self) -> &Path;

    /// Returns the inner DB instance
    fn inner(&self) -> Arc<sov_schema_db::DB>;

    /// Put L2 block to db
    fn put_l2_block(
        &self,
        l2_block: &StoredL2Block,
        l2_block_number: &L2BlockNumber,
        schema_batch: &mut SchemaBatch,
    ) -> Result<()>;

    /// Commits a l2 block to the database by inserting its transactions and batches before
    fn commit_l2_block(
        &self,
        l2_block: L2Block,
        tx_hashes: Vec<[u8; 32]>,
        tx_bodies: Option<Vec<Vec<u8>>>,
    ) -> Result<()>;

    /// Records the L2 height that was created as a l2 block of an L1 height
    fn extend_l2_range_of_l1_slot(
        &self,
        l1_height: SlotNumber,
        l2_height: L2BlockNumber,
    ) -> Result<()>;

    /// Sets l1 height of l1 hash
    fn set_l1_height_of_l1_hash(&self, hash: [u8; 32], height: u64) -> Result<()>;

    /// Gets l1 height of l1 hash
    fn get_l1_height_of_l1_hash(&self, hash: [u8; 32]) -> Result<Option<u64>>;

    /// Saves a l2 block status for a given L1 height
    fn put_l2_block_status(
        &self,
        height: L2BlockNumber,
        status: sov_rollup_interface::rpc::L2BlockStatus,
    ) -> Result<()>;

    /// Returns a l2 block status for a given L1 height
    fn get_l2_block_status(
        &self,
        height: L2BlockNumber,
    ) -> Result<Option<sov_rollup_interface::rpc::L2BlockStatus>>;

    /// Gets the commitments in the da slot with given height if any
    /// Adds the new coming commitment info
    fn update_commitments_on_da_slot(
        &self,
        height: u64,
        commitment: SequencerCommitment,
    ) -> Result<()>;

    /// Set the genesis state root
    fn set_l2_genesis_state_root(&self, state_root: &StorageRootHash) -> anyhow::Result<()>;

    /// Gets the L2 genesis state root
    fn get_l2_state_root(&self, l2_height: u64) -> anyhow::Result<Option<StorageRootHash>>;

    /// Get the most recent committed l2 block, if any
    fn get_head_l2_block(&self) -> Result<Option<(L2BlockNumber, StoredL2Block)>>;

    /// Get the most recent committed l2 block height, if any
    fn get_head_l2_block_height(&self) -> Result<Option<u64>>;

    /// Gets all l2 blocks with numbers `range.start` to `range.end`. If `range.end` is outside
    /// the range of the database, the result will smaller than the requested range.
    /// Note that this method blindly preallocates for the requested range, so it should not be exposed
    /// directly via rpc.
    fn get_l2_block_range(
        &self,
        range: &std::ops::RangeInclusive<L2BlockNumber>,
    ) -> Result<Vec<StoredL2Block>>;

    /// Gets all l2 blocks by numbers

    fn get_l2_block_by_number(&self, number: &L2BlockNumber) -> Result<Option<StoredL2Block>>;

    /// Used by the sequencer to record that it has committed to soft confirmations on a given L2 height
    fn set_last_commitment(&self, seqcomm: &SequencerCommitment) -> Result<()>;

    /// Get the most recent committed batch
    /// Returns last sequencer commitment.
    fn get_last_commitment(&self) -> anyhow::Result<Option<SequencerCommitment>>;

    /// Get the last scanned slot
    fn get_last_scanned_l1_height(&self) -> Result<Option<SlotNumber>>;

    /// Set the last scanned slot
    fn set_last_scanned_l1_height(&self, l1_height: SlotNumber) -> Result<()>;

    /// Get the last pruned block number
    fn get_last_pruned_l2_height(&self) -> Result<Option<u64>>;

    /// Set the last pruned block number
    fn set_last_pruned_l2_height(&self, l2_height: u64) -> Result<()>;

    /// Gets all executed migrations.
    fn get_executed_migrations(&self) -> anyhow::Result<Vec<(String, u64)>>;

    /// Put a pending commitment l2 range
    fn put_executed_migration(&self, migration: (String, u64)) -> anyhow::Result<()>;

    /// Stores a short header proof by l1 hash
    fn put_short_header_proof_by_l1_hash(
        &self,
        hash: &[u8; 32],
        short_header_proof: Vec<u8>,
    ) -> anyhow::Result<()>;

    /// Returns stored short header proof by l1 hash
    fn get_short_header_proof_by_l1_hash(&self, hash: &[u8; 32])
        -> anyhow::Result<Option<Vec<u8>>>;
    /// Set L2 range by l2 block hash merkle root
    fn set_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
        range: L2HeightRange,
    ) -> anyhow::Result<()>;

    /// Get L2 range by l2 block hash merkle root
    fn get_l2_range_by_commitment_merkle_root(
        &self,
        root: [u8; 32],
    ) -> anyhow::Result<Option<L2HeightRange>>;

    /// Store commitment by index
    fn put_commitment_by_index(&self, commitment: &SequencerCommitment) -> anyhow::Result<()>;

    /// Get commitment by index
    fn get_commitment_by_index(&self, index: u32) -> anyhow::Result<Option<SequencerCommitment>>;
}

/// Node ledger operations
pub trait NodeLedgerOps: SharedLedgerOps {
    /// Stores proof related data on disk, accessible via l1 slot height
    fn update_verified_proof_data(
        &self,
        l1_height: u64,
        proof: Proof,
        output: StoredBatchProofOutput,
    ) -> Result<()>;

    /// Gets the commitments in the da slot with given height if any
    fn get_commitments_on_da_slot(&self, height: u64) -> Result<Option<Vec<SequencerCommitment>>>;
}

/// Prover ledger operations
pub trait BatchProverLedgerOps: SharedLedgerOps + Send + Sync {
    /// Stores proof related data on disk, accessible via l1 slot height
    /// Inserts proofs of state transitions of multiple ranges of sequencer commitments found in an l1 block
    fn insert_batch_proof_data_by_l1_height(
        &self,
        l1_height: u64,
        l1_tx_id: [u8; 32],
        proof: Proof,
        output: StoredBatchProofOutput,
    ) -> Result<()>;

    /// Gets proofs by L1 height
    fn get_proofs_by_l1_height(&self, l1_height: u64) -> Result<Option<Vec<StoredBatchProof>>>;

    /// Save a specific L2 range state diff
    fn set_l2_state_diff(&self, l2_height: L2BlockNumber, state_diff: StateDiff) -> Result<()>;

    /// Returns an L2 state diff
    fn get_l2_state_diff(&self, l2_height: L2BlockNumber) -> Result<Option<StateDiff>>;

    /// Clears all pending proving sessions
    fn clear_pending_proving_sessions(&self) -> Result<()>;
}

/// Light client prover ledger operations
pub trait LightClientProverLedgerOps: SharedLedgerOps + Send + Sync {
    /// Inserts light client proof data by L1 height
    fn insert_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
        proof: Proof,
        light_client_proof_output: StoredLightClientProofOutput,
    ) -> Result<()>;

    /// Gets light client proof data by L1 height
    fn get_light_client_proof_data_by_l1_height(
        &self,
        l1_height: u64,
    ) -> Result<Option<StoredLightClientProof>>;
}

/// Ledger operations for the prover service
pub trait ProvingServiceLedgerOps: BatchProverLedgerOps + SharedLedgerOps + Send + Sync {
    /// Gets all pending sessions and step numbers
    fn get_pending_proving_sessions(&self) -> Result<Vec<Vec<u8>>>;

    /// Adds a pending proving session
    fn add_pending_proving_session(&self, session: Vec<u8>) -> Result<()>;

    /// Removes a pending proving session
    fn remove_pending_proving_session(&self, session: Vec<u8>) -> Result<()>;

    /// Clears all pending proving sessions
    fn clear_pending_proving_sessions(&self) -> Result<()>;
}

/// Sequencer ledger operations
pub trait SequencerLedgerOps: SharedLedgerOps {
    /// Gets all pending commitments.
    fn get_pending_commitments(&self) -> Result<Vec<SequencerCommitment>>;

    /// Put a pending commitment
    fn put_pending_commitment(&self, seqcomm: &SequencerCommitment) -> Result<()>;

    /// Delete a pending commitment l2 range
    fn delete_pending_commitment(&self, index: u32) -> Result<()>;

    /// Gets the latest state diff
    fn get_state_diff(&self) -> Result<StateDiff>;

    /// Sets the latest state diff
    fn set_state_diff(&self, state_diff: &StateDiff) -> Result<()>;

    /// Get the most recent commitment's l1 height
    fn get_l1_height_of_last_commitment(&self) -> anyhow::Result<Option<SlotNumber>>;

    /// Insert mempool transaction
    fn insert_mempool_tx(&self, tx_hash: Vec<u8>, tx: Vec<u8>) -> anyhow::Result<()>;

    /// Insert mempool transaction
    fn remove_mempool_txs(&self, tx_hashes: Vec<Vec<u8>>) -> anyhow::Result<()>;

    /// Fetch mempool transactions
    fn get_mempool_txs(&self) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>>;
}

/// Test ledger operations
#[cfg(test)]
pub trait TestLedgerOps {
    /// Fetch the test values
    fn get_values(&self) -> anyhow::Result<Vec<(u64, (u64, u64))>>;
    /// Insert the test values
    fn put_value(&self, key: u64, value: (u64, u64)) -> anyhow::Result<()>;
}
