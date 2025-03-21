use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::da::LatestDaState;
use crate::zk::StorageRootHash;

/// The output of light client proof
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq)]
pub struct LightClientCircuitOutput {
    /// State root of the node after the light client proof
    pub l2_state_root: StorageRootHash,
    /// Light client proof JMT state root
    pub lcp_state_root: StorageRootHash,
    /// The method id of the light client proof
    /// This is used to compare the previous light client proof method id with the input (current) method id
    pub light_client_proof_method_id: [u32; 8],
    /// Latest da state output of the previous light client proof
    /// If None, initial hardcoded da block will be used for verification
    pub latest_da_state: LatestDaState,
    /// Batch proof info from current or previous light client proofs that were not changed and unable to update the state root yet
    pub unchained_batch_proofs_info: Vec<BatchProofInfo>,
    /// Last l2 height the light client proof verifies
    pub last_l2_height: u64,
    /// L2 activation height of the fork and the Method ids of the batch proofs that were verified in the light client proof
    pub batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    /// The last sequencer commitment index of the last fully stitched and verified batch proof
    pub last_sequencer_commitment_index: u32,
    /// Info about batch proof with missing sequencer commitments
    pub batch_proofs_with_missing_sequencer_commitments: Vec<BatchProofInfo>,
}

/// The batch proof that was not verified in the light client circuit because it was missing another proof for state root chaining
/// This struct is passed as an output to the light client circuit
/// After that the new circuit will read that info to update the state root if possible
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, PartialEq, Serialize, Deserialize)]
pub struct BatchProofInfo {
    /// Initial state root of the batch proof
    pub initial_state_root: [u8; 32],
    /// Final state root of the batch proof
    pub final_state_root: [u8; 32],
    /// The last processed l2 height in the batch proof
    pub last_l2_height: u64,
    /// The sequencer commitment range of the batch proof
    pub sequencer_commitment_range: (u32, u32),
    /// (Commitment index, commitment hash)
    pub missing_commitments: Vec<(u32, [u8; 32])>,
}

impl BatchProofInfo {
    /// Create a new `BatchProofInfo` instance.
    pub fn new(
        initial_state_root: [u8; 32],
        final_state_root: [u8; 32],
        last_l2_height: u64,
        sequencer_commitment_range: (u32, u32),
        missing_commitments: Option<Vec<(u32, [u8; 32])>>,
    ) -> Self {
        Self {
            initial_state_root,
            final_state_root,
            last_l2_height,
            sequencer_commitment_range,
            missing_commitments: missing_commitments.unwrap_or_default(),
        }
    }
}
