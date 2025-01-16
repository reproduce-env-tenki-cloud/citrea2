use std::fmt::Debug;
use std::sync::Arc;

use alloy_primitives::{U32, U64};
use borsh::{BorshDeserialize, BorshSerialize};
use sov_rollup_interface::da::LatestDaState;
use sov_rollup_interface::mmr::MMRGuest;
use sov_rollup_interface::rpc::{
    BatchProofMethodIdRpcResponse, BatchProofOutputRpcResponse, BatchProofResponse, HexTx,
    LatestDaStateRpcResponse, LightClientProofOutputRpcResponse, LightClientProofResponse,
    SoftConfirmationResponse, VerifiedBatchProofResponse,
};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::zk::{
    BatchProofInfo, CumulativeStateDiff, LightClientCircuitOutput, Proof,
};

/// A cheaply cloneable bytes abstraction for use within the trust boundary of the node
/// (i.e. when interfacing with the database). Serializes and deserializes more efficiently,
/// than most bytes abstractions, but is vulnerable to out-of-memory attacks
/// when read from an untrusted source.
///
/// # Warning
/// Do not use this type when deserializing data from an untrusted source!!
#[derive(
    Clone, PartialEq, PartialOrd, Eq, Ord, Debug, Default, BorshDeserialize, BorshSerialize,
)]
pub struct DbBytes(Arc<Vec<u8>>);

impl DbBytes {
    /// Create `DbBytes` from a `Vec<u8>`
    pub fn new(contents: Vec<u8>) -> Self {
        Self(Arc::new(contents))
    }
}

impl From<Vec<u8>> for DbBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::new(value))
    }
}

impl AsRef<[u8]> for DbBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Latest da state to verify and apply da block changes
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq)]
pub struct StoredLatestDaState {
    /// Proved DA block's header hash
    /// This is used to compare the previous DA block hash with first batch proof's DA block hash
    pub block_hash: [u8; 32],
    /// Height of the blockchain
    pub block_height: u64,
    /// Total work done in the DA blockchain
    pub total_work: [u8; 32],
    /// Current target bits of DA
    pub current_target_bits: u32,
    /// The time of the first block in the current epoch (the difficulty adjustment timestamp)
    pub epoch_start_time: u32,
    /// The UNIX timestamps in seconds of the previous 11 blocks
    pub prev_11_timestamps: [u32; 11],
}

/// The "key" half of a key/value pair from accessory state.
///
/// See [`NativeDB`](crate::native_db::NativeDB) for more information.
pub type AccessoryKey = Vec<u8>;
/// The "value" half of a key/value pair from accessory state.
///
/// See [`NativeDB`](crate::native_db::NativeDB) for more information.
pub type AccessoryStateValue = Option<Vec<u8>>;

/// A hash stored in the database
pub type DbHash = [u8; 32];
/// The "value" half of a key/value pair from the JMT
pub type JmtValue = Option<Vec<u8>>;
pub(crate) type StateKey = Vec<u8>;

/// The on-disk format for a light client proof output
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredLightClientProofOutput {
    /// State root of the node after the light client proof
    pub state_root: [u8; 32],
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    pub light_client_proof_method_id: [u32; 8],
    /// Latest DA state after proof
    pub latest_da_state: StoredLatestDaState,
    /// Unchained batch proofs are proofs that are not consecutive,
    /// hence can not be proven yet kproofs.
    pub unchained_batch_proofs_info: Vec<BatchProofInfo>,
    /// Last l2 height after proof.
    pub last_l2_height: u64,
    /// L2 activation height of the fork and the Method ids of the batch proofs that were verified in the light client proof
    pub batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    /// A list of unprocessed chunks
    pub mmr_guest: MMRGuest,
}

impl From<StoredLightClientProofOutput> for LightClientProofOutputRpcResponse {
    fn from(value: StoredLightClientProofOutput) -> Self {
        Self {
            state_root: value.state_root,
            light_client_proof_method_id: value.light_client_proof_method_id.into(),
            latest_da_state: LatestDaStateRpcResponse {
                block_hash: value.latest_da_state.block_hash,
                block_height: U64::from(value.latest_da_state.block_height),
                total_work: value.latest_da_state.total_work,
                current_target_bits: U32::from(value.latest_da_state.current_target_bits),
                epoch_start_time: U32::from(value.latest_da_state.epoch_start_time),
                prev_11_timestamps: value
                    .latest_da_state
                    .prev_11_timestamps
                    .into_iter()
                    .map(U32::from)
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("should have 11 elements"),
            },
            unchained_batch_proofs_info: value
                .unchained_batch_proofs_info
                .into_iter()
                .map(Into::into)
                .collect(),
            last_l2_height: U64::from(value.last_l2_height),
            batch_proof_method_ids: value
                .batch_proof_method_ids
                .into_iter()
                .map(|(height, method_id)| {
                    BatchProofMethodIdRpcResponse::new(U64::from(height), method_id.into())
                })
                .collect(),
            mmr_guest: value.mmr_guest.into(),
        }
    }
}

impl From<LightClientCircuitOutput> for StoredLightClientProofOutput {
    fn from(circuit_output: LightClientCircuitOutput) -> Self {
        let latest_da_state = circuit_output.latest_da_state;
        StoredLightClientProofOutput {
            state_root: circuit_output.state_root,
            light_client_proof_method_id: circuit_output.light_client_proof_method_id,
            latest_da_state: StoredLatestDaState {
                block_hash: latest_da_state.block_hash,
                block_height: latest_da_state.block_height,
                total_work: latest_da_state.total_work,
                current_target_bits: latest_da_state.current_target_bits,
                epoch_start_time: latest_da_state.epoch_start_time,
                prev_11_timestamps: latest_da_state.prev_11_timestamps,
            },
            unchained_batch_proofs_info: circuit_output.unchained_batch_proofs_info,
            last_l2_height: circuit_output.last_l2_height,
            batch_proof_method_ids: circuit_output.batch_proof_method_ids,
            mmr_guest: circuit_output.mmr_guest,
        }
    }
}

impl From<StoredLightClientProofOutput> for LightClientCircuitOutput {
    fn from(db_output: StoredLightClientProofOutput) -> Self {
        let latest_da_state = db_output.latest_da_state;
        LightClientCircuitOutput {
            state_root: db_output.state_root,
            light_client_proof_method_id: db_output.light_client_proof_method_id,
            latest_da_state: LatestDaState {
                block_hash: latest_da_state.block_hash,
                block_height: latest_da_state.block_height,
                total_work: latest_da_state.total_work,
                current_target_bits: latest_da_state.current_target_bits,
                epoch_start_time: latest_da_state.epoch_start_time,
                prev_11_timestamps: latest_da_state.prev_11_timestamps,
            },
            unchained_batch_proofs_info: db_output.unchained_batch_proofs_info,
            last_l2_height: db_output.last_l2_height,
            batch_proof_method_ids: db_output.batch_proof_method_ids,
            mmr_guest: db_output.mmr_guest,
        }
    }
}

/// The on-disk format for a light client proof
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredLightClientProof {
    /// The proof
    pub proof: Proof,
    /// The light client circuit proof output
    pub light_client_proof_output: StoredLightClientProofOutput,
}

impl From<StoredLightClientProof> for LightClientProofResponse {
    fn from(value: StoredLightClientProof) -> Self {
        Self {
            proof: value.proof,
            light_client_proof_output: LightClientProofOutputRpcResponse::from(
                value.light_client_proof_output,
            ),
        }
    }
}

/// The on-disk format for a state transition.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize, Clone)]
pub struct StoredBatchProofOutput {
    /// The state of the rollup before the transition
    pub initial_state_root: Vec<u8>,
    /// The state of the rollup after the transition
    pub final_state_root: Vec<u8>,
    /// The hash of the last soft confirmation before the state transition
    pub prev_soft_confirmation_hash: [u8; 32],
    /// The hash of the last soft confirmation in the state transition
    pub final_soft_confirmation_hash: [u8; 32],
    /// State diff of L2 blocks in the processed sequencer commitments.
    pub state_diff: CumulativeStateDiff,
    /// The DA slot hash that the sequencer commitments causing this state transition were found in.
    pub da_slot_hash: [u8; 32],
    /// The range of sequencer commitments in the DA slot that were processed.
    /// The range is inclusive.
    pub sequencer_commitments_range: (u32, u32),
    /// Sequencer public key.
    pub sequencer_public_key: Vec<u8>,
    /// Sequencer DA public key.
    pub sequencer_da_public_key: Vec<u8>,
    /// Pre-proven commitments L2 ranges which also exist in the current L1 `da_data`.
    pub preproven_commitments: Vec<usize>,
    /// The last processed l2 height in the processed sequencer commitments.
    pub last_l2_height: u64,
}

/// The on-disk format for a proof. Stores the tx id of the proof sent to da, proof data and state transition
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredBatchProof {
    /// Tx id
    pub l1_tx_id: [u8; 32],
    /// Proof
    pub proof: Proof,
    /// Output
    pub proof_output: StoredBatchProofOutput,
}

impl From<StoredBatchProof> for BatchProofResponse {
    fn from(value: StoredBatchProof) -> Self {
        Self {
            l1_tx_id: value.l1_tx_id,
            proof: value.proof,
            proof_output: BatchProofOutputRpcResponse::from(value.proof_output),
        }
    }
}

/// The on-disk format for a proof verified by full node. Stores proof data and state transition
#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredVerifiedProof {
    /// Verified Proof
    pub proof: Proof,
    /// State transition
    pub proof_output: StoredBatchProofOutput,
}

impl From<StoredVerifiedProof> for VerifiedBatchProofResponse {
    fn from(value: StoredVerifiedProof) -> Self {
        Self {
            proof: value.proof,
            proof_output: BatchProofOutputRpcResponse::from(value.proof_output),
        }
    }
}

impl From<StoredBatchProofOutput> for BatchProofOutputRpcResponse {
    fn from(value: StoredBatchProofOutput) -> Self {
        Self {
            initial_state_root: value.initial_state_root,
            final_state_root: value.final_state_root,
            state_diff: value.state_diff,
            da_slot_hash: value.da_slot_hash,
            sequencer_da_public_key: value.sequencer_da_public_key,
            sequencer_public_key: value.sequencer_public_key,
            sequencer_commitments_range: value.sequencer_commitments_range,
            preproven_commitments: value.preproven_commitments,
            prev_soft_confirmation_hash: value.prev_soft_confirmation_hash,
            final_soft_confirmation_hash: value.final_soft_confirmation_hash,
            last_l2_height: value.last_l2_height,
        }
    }
}

/// The on-disk format for a batch. Stores the hash and identifies the range of transactions
/// included in the batch.
#[derive(Debug, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct StoredSoftConfirmation {
    /// The l2 height of the soft confirmation
    pub l2_height: u64,
    /// The number of the batch
    pub da_slot_height: u64,
    /// The da hash of the batch
    pub da_slot_hash: [u8; 32],
    /// The da transactions commitment of the batch
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the batch
    pub hash: DbHash,
    /// The hash of the previous batch
    pub prev_hash: DbHash,
    /// The transactions which occurred in this batch.
    pub txs: Vec<StoredTransaction>,
    /// Deposit data coming from the L1 chain
    pub deposit_data: Vec<Vec<u8>>,
    /// State root
    pub state_root: Vec<u8>,
    /// Sequencer signature
    pub soft_confirmation_signature: Vec<u8>,
    /// Sequencer public key
    pub pub_key: Vec<u8>,
    /// L1 fee rate
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp
    pub timestamp: u64,
}

impl<'txs, Tx> TryFrom<StoredSoftConfirmation> for SignedSoftConfirmation<'txs, Tx>
where
    Tx: Clone + BorshDeserialize,
{
    type Error = borsh::io::Error;
    fn try_from(val: StoredSoftConfirmation) -> Result<Self, Self::Error> {
        let parsed_txs = val
            .txs
            .iter()
            .map(|tx| {
                let body = tx.body.as_ref().unwrap();
                borsh::from_slice::<Tx>(body)
            })
            .collect::<Result<Vec<_>, Self::Error>>()?;
        let res = SignedSoftConfirmation::new(
            val.l2_height,
            val.hash,
            val.prev_hash,
            val.da_slot_height,
            val.da_slot_hash,
            val.da_slot_txs_commitment,
            val.l1_fee_rate,
            val.txs.into_iter().map(|tx| tx.body.unwrap()).collect(),
            parsed_txs.into(),
            val.deposit_data,
            val.soft_confirmation_signature,
            val.pub_key,
            val.timestamp,
        );
        Ok(res)
    }
}

/// The range of L2 heights (soft confirmations) for a given L1 block
/// (start, end) inclusive
pub type L2HeightRange = (SoftConfirmationNumber, SoftConfirmationNumber);

impl TryFrom<StoredSoftConfirmation> for SoftConfirmationResponse {
    type Error = anyhow::Error;
    fn try_from(value: StoredSoftConfirmation) -> Result<Self, Self::Error> {
        Ok(Self {
            da_slot_hash: value.da_slot_hash,
            l2_height: value.l2_height,
            da_slot_height: value.da_slot_height,
            da_slot_txs_commitment: value.da_slot_txs_commitment,
            hash: value.hash,
            prev_hash: value.prev_hash,
            txs: Some(
                value
                    .txs
                    .into_iter()
                    .filter_map(|tx| tx.body.map(Into::into))
                    .collect(),
            ), // Rollup full nodes don't store tx bodies
            state_root: value.state_root,
            soft_confirmation_signature: value.soft_confirmation_signature,
            pub_key: value.pub_key,
            deposit_data: value
                .deposit_data
                .into_iter()
                .map(|tx_vec| HexTx { tx: tx_vec })
                .collect(),
            l1_fee_rate: value.l1_fee_rate,
            timestamp: value.timestamp,
        })
    }
}

/// The on-disk format of a transaction. Includes the txhash, the serialized tx data,
/// and identifies the events emitted by this transaction
#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize, Clone)]
pub struct StoredTransaction {
    /// The hash of the transaction.
    pub hash: DbHash,
    /// The serialized transaction data, if the rollup decides to store it.
    pub body: Option<Vec<u8>>,
}

macro_rules! u64_wrapper {
    ($name:ident) => {
        /// A typed wrapper around u64 implementing `Encode` and `Decode`
        #[derive(
            Clone,
            Copy,
            ::core::fmt::Debug,
            Default,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            ::borsh::BorshDeserialize,
            ::borsh::BorshSerialize,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        pub struct $name(pub u64);

        impl From<$name> for u64 {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

u64_wrapper!(SlotNumber);
u64_wrapper!(SoftConfirmationNumber);
