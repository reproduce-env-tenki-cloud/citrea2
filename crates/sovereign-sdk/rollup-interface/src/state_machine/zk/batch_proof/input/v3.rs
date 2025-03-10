use std::collections::VecDeque;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::da::SequencerCommitment;
use crate::soft_confirmation::L2Block;
use crate::witness::Witness;
use crate::zk::StorageRootHash;

type InputV3Part2<'txs, Tx, Witness> = VecDeque<Vec<(u64, L2Block<'txs, Tx>, Witness, Witness)>>;

#[derive(BorshDeserialize, BorshSerialize)]
/// Second part of the Fork2 elf input
/// This is going to be read per-need basis to not go out of memory
/// in the zkvm
pub struct BatchProofCircuitInputV3Part2<'txs, Tx: Clone + BorshSerialize>(
    pub InputV3Part2<'txs, Tx, Witness>,
);

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// First part of the Kumquat elf input
pub struct BatchProofCircuitInputV3Part1 {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// Sequencer commitments being proven
    /// Since `SequencerCommitment` does not have the sequencer's signature,
    /// the light client prover will be doing the signature verification
    /// when it is extracting the commitments from L1
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// Short header proofs for verifying system transactions
    pub short_header_proofs: VecDeque<Vec<u8>>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    pub cache_prune_l2_heights: Vec<u64>,
    /// The witness needed to access the last L1 hash on the bitcoin light client contract
    pub last_l1_hash_witness: Witness,
}

#[derive(BorshDeserialize, BorshSerialize)]
// Prevent serde from generating spurious trait bounds. The correct serde bounds are already enforced by the
// StateTransitionFunction, DA, and Zkvm traits.
/// Data required to verify a state transition.
/// This is more like a glue type to create V1/V2 batch proof circuit inputs later in the program
pub struct BatchProofCircuitInputV3<'txs, Tx: Clone + BorshSerialize> {
    /// The state root before the state transition
    pub initial_state_root: StorageRootHash,
    /// The state root after the state transition
    pub final_state_root: StorageRootHash,
    /// The L2 blocks that are inside the sequencer commitments.
    pub l2_blocks: VecDeque<Vec<L2Block<'txs, Tx>>>,
    /// Corresponding witness for the soft confirmations.
    pub state_transition_witnesses: VecDeque<Vec<(Witness, Witness)>>,
    /// Short header proofs for verifying system transactions
    pub short_header_proofs: VecDeque<Vec<u8>>,
    /// Sequencer commitments that will be proven.
    /// Only applies to V3
    pub sequencer_commitments: Vec<SequencerCommitment>,
    /// L2 heights in which the guest should prune the log caches to avoid OOM.
    /// Only applies to V3
    pub cache_prune_l2_heights: Vec<u64>,
    /// Witness needed to get the last Bitcoin hash on Bitcoin Light Client contract
    pub last_l1_hash_witness: Witness,
}

impl<'txs, Tx> BatchProofCircuitInputV3<'txs, Tx>
where
    Tx: Clone + BorshSerialize,
{
    /// Into Kumquat expected inputs
    pub fn into_v3_parts(
        self,
    ) -> (
        BatchProofCircuitInputV3Part1,
        BatchProofCircuitInputV3Part2<'txs, Tx>,
    ) {
        assert_eq!(self.l2_blocks.len(), self.state_transition_witnesses.len());
        let mut x = VecDeque::with_capacity(self.l2_blocks.len());

        for (confirmations, witnesses) in self
            .l2_blocks
            .into_iter()
            .zip(self.state_transition_witnesses)
        {
            assert_eq!(confirmations.len(), witnesses.len());

            let v: Vec<_> = confirmations
                .into_iter()
                .zip(witnesses)
                .map(|(confirmation, (state_witness, offchain_witness))| {
                    (
                        confirmation.l2_height(),
                        confirmation,
                        state_witness,
                        offchain_witness,
                    )
                })
                .collect();

            x.push_back(v);
        }

        (
            BatchProofCircuitInputV3Part1 {
                initial_state_root: self.initial_state_root,
                short_header_proofs: self.short_header_proofs,
                sequencer_commitments: self.sequencer_commitments,
                cache_prune_l2_heights: self.cache_prune_l2_heights,
                last_l1_hash_witness: self.last_l1_hash_witness,
            },
            BatchProofCircuitInputV3Part2(x),
        )
    }
}
