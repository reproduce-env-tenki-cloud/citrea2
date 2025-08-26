#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

//! # Sovereign SDK STF Blueprint Module
//!
//! This module provides the core State Transition Function (STF) blueprint implementation
//! for the Sovereign SDK. It defines the framework for processing L2 blocks and managing
//! state transitions in a rollup system.
//!
//! ## Core Components
//!
//! ### StfBlueprint
//! The main implementation of the State Transition Function that works with the module system.
//! It provides:
//! - L2 block processing and validation
//! - Transaction execution and state management
//! - Genesis initialization
//! - Sequencer commitment handling
//!
//! ### Runtime Integration
//! The `Runtime` trait defines the interface that runtimes must implement to work with the STF:
//! - Transaction hooks for context setup
//! - Slot hooks for block processing
//! - Genesis configuration
//! - RPC method definitions
//!
//! ## Public Interface
//!
//! ### Block Processing
//! ```rust
//! impl<C, RT, Da> StfBlueprint<C, Da, RT> {
//!     /// Begin processing an L2 block
//!     pub fn begin_l2_block(
//!         &mut self,
//!         sequencer_public_key: &K256PublicKey,
//!         working_set: &mut WorkingSet<C::Storage>,
//!         l2_block_info: &HookL2BlockInfo,
//!     ) -> Result<(), StateTransitionError>
//!
//!     /// Apply transactions from an L2 block
//!     pub fn apply_l2_block_txs(
//!         &mut self,
//!         l2_block_info: &HookL2BlockInfo,
//!         txs: &[Transaction],
//!         batch_workspace: &mut WorkingSet<C::Storage>,
//!     ) -> Result<(), StateTransitionError>
//!
//!     /// Verify L2 block hash and signature
//!     pub fn verify_l2_block(
//!         &self,
//!         l2_block: &L2Block,
//!         sequencer_public_key: &K256PublicKey,
//!     ) -> Result<(), StateTransitionError>
//!
//!     /// End L2 block processing
//!     pub fn end_l2_block(
//!         &mut self,
//!         l2_block_info: HookL2BlockInfo,
//!         working_set: &mut WorkingSet<C::Storage>,
//!     ) -> Result<(), StateTransitionError>
//! }
//! ```
//!
//! ### State Management
//! ```rust
//! impl<C, RT, Da> StfBlueprint<C, Da, RT> {
//!     /// Finalize an L2 block and compute state transitions
//!     pub fn finalize_l2_block(
//!         &self,
//!         current_spec: SpecId,
//!         working_set: WorkingSet<C::Storage>,
//!         pre_state: C::Storage,
//!     ) -> L2BlockResult<C::Storage, Witness, ReadWriteLog>
//!
//!     /// Initialize chain from genesis configuration
//!     pub fn init_chain(
//!         &self,
//!         pre_state: C::Storage,
//!         params: GenesisParams<<RT as Genesis>::Config>,
//!     ) -> (StorageRootHash, C::Storage)
//! }
//! ```
//!
//! ### Sequencer Commitment Processing
//! ```rust
//! impl<C, RT, Da> StfBlueprint<C, Da, RT> {
//!     /// Apply L2 blocks from sequencer commitments
//!     pub fn apply_l2_blocks_from_sequencer_commitments(
//!         &mut self,
//!         guest: &impl ZkvmGuest,
//!         sequencer_public_key: &[u8],
//!         initial_state_root: &StorageRootHash,
//!         pre_state: C::Storage,
//!         previous_sequencer_commitment: Option<SequencerCommitment>,
//!         sequencer_commitments: Vec<SequencerCommitment>,
//!         cache_prune_l2_heights: &[u64],
//!         forks: &[Fork],
//!     ) -> ApplySequencerCommitmentsOutput
//! }
//! ```
//!
//! ## Type Parameters
//!
//! - `C`: Context type implementing the `Context` trait
//! - `Da`: Data availability specification implementing `DaSpec`
//! - `RT`: Runtime type implementing the `Runtime` trait
//!
//! ## Error Handling
//!
//! The module uses several error types:
//! - `StateTransitionError`: General state transition errors
//! - `L2BlockError`: Specific L2 block processing errors
//! - `HookError`: Errors from runtime hooks
//!
//! ## Security Considerations
//!
//! The STF blueprint implements several security measures:
//! - Sequencer public key verification
//! - Block signature validation
//! - Transaction merkle root verification
//! - State root validation
//!
//! ## Integration Guide
//!
//! To use the STF blueprint in a rollup:
//!
//! 1. Implement the `Runtime` trait for your runtime
//! 2. Configure genesis parameters
//! 3. Initialize the STF with your runtime
//! 4. Use the block processing methods to handle L2 blocks
//! 5. Implement proper error handling and recovery
//!
//! ## Example Usage
//!
//! ```rust
//! // Initialize STF with runtime
//! let stf = StfBlueprint::<MyContext, MyDaSpec, MyRuntime>::new();
//!
//! // Process L2 block
//! stf.begin_l2_block(&sequencer_key, &mut working_set, &block_info)?;
//! stf.apply_l2_block_txs(&block_info, &transactions, &mut working_set)?;
//! stf.end_l2_block(block_info, &mut working_set)?;
//!
//! // Finalize block
//! let result = stf.finalize_l2_block(current_spec, working_set, pre_state);
//! ```

use borsh::BorshDeserialize;
use citrea_primitives::merkle::verify_tx_merkle_root;
use rs_merkle::algorithms::Sha256;
use rs_merkle::{MerkleProof, MerkleTree};
#[cfg(feature = "native")]
use sov_db::ledger_db::LedgerDB;
use sov_keys::default_signature::{K256PublicKey, K256Signature};
use sov_keys::Signature;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::{
    ApplyL2BlockHooks, FinalizeHook, HookL2BlockInfo, SlotHooks, TxHooks,
};
use sov_modules_api::{native_debug, Context, DaSpec, DispatchCall, Genesis, WorkingSet};
use sov_rollup_interface::block::{L2Block, SignedL2Header};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{L2BlockError, L2BlockResult, StateTransitionError};
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::batch_proof::input::v3::PrevHashProof;
use sov_rollup_interface::zk::batch_proof::output::CumulativeStateDiff;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_state::{ReadWriteLog, Storage, Witness};

mod stf_blueprint;

pub use stf_blueprint::StfBlueprint;

/// The tx hook for a blueprint runtime
pub struct RuntimeTxHook {
    /// Height to initialize the context
    pub height: u64,
    /// Current spec
    pub current_spec: SpecId,
    /// L1 fee rate
    pub l1_fee_rate: u128,
}

/// This trait has to be implemented by a runtime in order to be used in `StfBlueprint`.
///
/// The `TxHooks` implementation sets up a transaction context based on the height at which it is
/// to be executed.
pub trait Runtime<C: Context, Da: DaSpec>:
    DispatchCall<Context = C>
    + Genesis<Context = C, Config = Self::GenesisConfig>
    + TxHooks<Context = C, PreArg = RuntimeTxHook, PreResult = C>
    + SlotHooks<Da, Context = C>
    + FinalizeHook<Da, Context = C>
    + ApplyL2BlockHooks<Da, Context = C>
    + Default
{
    /// GenesisConfig type.
    type GenesisConfig: Send + Sync;

    #[cfg(feature = "native")]
    /// GenesisPaths type.
    type GenesisPaths: Send + Sync;

    #[cfg(feature = "native")]
    /// Default rpc methods.
    fn rpc_methods(storage: C::Storage, ledger: crate::LedgerDB) -> jsonrpsee::RpcModule<()>;

    #[cfg(feature = "native")]
    /// Reads genesis configs.
    fn genesis_config(
        genesis_paths: &Self::GenesisPaths,
    ) -> Result<Self::GenesisConfig, anyhow::Error>;
}

/// Genesis parameters for a blueprint
pub struct GenesisParams<RT> {
    /// The runtime genesis parameters
    pub runtime: RT,
}

/// The output of the function that applies sequencer commitments to the state in the verifier
pub struct ApplySequencerCommitmentsOutput {
    /// All of the state roots of commitments from initial state (previous commitments state root) to the last sequencer commitment
    pub state_roots: Vec<StorageRootHash>,
    /// State diff generated after applying
    pub state_diff: CumulativeStateDiff,
    /// Last processed L2 block height
    pub last_l2_height: u64,
    /// Last l2 block hash
    pub final_l2_block_hash: [u8; 32],
    /// Sequencer commitment hashes
    pub sequencer_commitment_hashes: Vec<[u8; 32]>,
    /// The range of sequencer commitments that were processed.
    pub sequencer_commitment_index_range: (u32, u32),
    /// Cumulative state log
    pub cumulative_state_log: ReadWriteLog,
    /// The index of the previous commitment that was given as input in the batch proof
    pub previous_commitment_index: Option<u32>,
    /// The hash of the previous commitment that was given as input in the batch proof
    pub previous_commitment_hash: Option<[u8; 32]>,
}

impl<C, RT, Da> StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Begin a l2 block for blocks post tangerine
    /// There are no slot hash comparisons with l2 blocks
    pub fn begin_l2_block(
        &mut self,
        working_set: &mut WorkingSet<C::Storage>,
        l2_block_info: &HookL2BlockInfo,
    ) -> Result<(), StateTransitionError> {
        self.begin_l2_block_inner(working_set, l2_block_info)
            .map_err(StateTransitionError::HookError)
    }

    /// Apply l2 block transactions
    pub fn apply_l2_block_txs(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        txs: &[Transaction],
        batch_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.apply_sov_txs_inner(l2_block_info, txs, batch_workspace)
    }

    /// Verify l2_block hash and signature post tangerine
    /// No da slot hash, height and txs commitment checks are done here
    pub fn verify_l2_block(
        &self,
        l2_block: &L2Block,
        sequencer_public_key: &K256PublicKey,
        current_spec: SpecId,
    ) -> Result<(), StateTransitionError> {
        let l2_header = &l2_block.header;

        if !verify_tx_merkle_root(&l2_block.txs, l2_block.tx_merkle_root(), current_spec) {
            return Err(StateTransitionError::L2BlockError(
                L2BlockError::InvalidTxMerkleRoot,
            ));
        }

        let expected_hash = l2_header.inner.compute_digest();

        if l2_block.hash() != expected_hash {
            return Err(StateTransitionError::L2BlockError(
                L2BlockError::InvalidL2BlockHash,
            ));
        }

        verify_signature(l2_header, sequencer_public_key)
            .map_err(|_| StateTransitionError::L2BlockError(L2BlockError::InvalidL2BlockSignature))
    }

    /// End a l2 block
    pub fn end_l2_block(
        &mut self,
        l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.end_l2_block_inner(l2_block_info, working_set)
            .map_err(StateTransitionError::HookError)
    }

    /// Finalizes a l2 block
    pub fn finalize_l2_block(
        &self,
        _current_spec: SpecId,
        working_set: WorkingSet<C::Storage>,
        pre_state: C::Storage,
    ) -> L2BlockResult<C::Storage, Witness, ReadWriteLog> {
        let (
            state_root_transition,
            state_log,
            offchain_log,
            witness,
            offchain_witness,
            storage,
            state_diff,
        ) = {
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (state_log, mut witness) = checkpoint.freeze();

            let (state_root_transition, state_update, state_diff) = pre_state
                .compute_state_update(&state_log, &mut witness, true)
                .expect("jellyfish merkle tree update must succeed");

            let mut working_set = checkpoint.to_revertable();

            self.runtime.finalize_hook(
                &state_root_transition.final_root,
                &mut working_set.accessory_state(),
            );

            let mut checkpoint = working_set.checkpoint();
            let accessory_log = checkpoint.freeze_non_provable();
            let (offchain_log, offchain_witness) = checkpoint.freeze_offchain();

            pre_state.commit(&state_update, &accessory_log, &offchain_log);

            (
                state_root_transition,
                state_log,
                offchain_log,
                witness,
                offchain_witness,
                pre_state,
                state_diff,
            )
        };

        L2BlockResult {
            state_root_transition,
            state_log,
            offchain_log,
            change_set: storage,
            witness,
            offchain_witness,
            state_diff,
        }
    }
}

impl<C, RT, Da> StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Initialize chain from genesis config
    pub fn init_chain(
        &self,
        pre_state: C::Storage,
        params: GenesisParams<<RT as Genesis>::Config>,
    ) -> (StorageRootHash, C::Storage) {
        let mut working_set = WorkingSet::new(pre_state.clone());

        self.runtime.genesis(&params.runtime, &mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let (state_root_transition, state_update, _) = pre_state
            .compute_state_update(&state_log, &mut witness, true)
            .expect("Storage update must succeed");
        let genesis_hash = state_root_transition.final_root;

        let mut working_set = checkpoint.to_revertable();

        self.runtime
            .finalize_hook(&genesis_hash, &mut working_set.accessory_state());

        let mut checkpoint = working_set.checkpoint();
        let accessory_log = checkpoint.freeze_non_provable();
        let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();

        pre_state.commit(&state_update, &accessory_log, &offchain_log);

        (genesis_hash, pre_state)
    }

    /// Apply l2 block
    #[allow(clippy::too_many_arguments)]
    pub fn apply_l2_block(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &K256PublicKey,
        pre_state_root: &StorageRootHash,
        pre_state: C::Storage,
        cumulative_state_log: Option<ReadWriteLog>,
        cumulative_offchain_log: Option<ReadWriteLog>,
        state_witness: Witness,
        offchain_witness: Witness,
        l2_block: &L2Block,
    ) -> Result<L2BlockResult<C::Storage, Witness, ReadWriteLog>, StateTransitionError> {
        let l2_block_info = HookL2BlockInfo::new(
            l2_block,
            *pre_state_root,
            current_spec,
            sequencer_public_key.clone(),
        );

        let mut working_set = if let Some(state_log) = cumulative_state_log {
            WorkingSet::with_witness_and_log(
                pre_state.clone(),
                state_witness,
                offchain_witness,
                state_log,
                cumulative_offchain_log.expect("Both logs must be provided"),
            )
        } else {
            WorkingSet::with_witness(pre_state.clone(), state_witness, offchain_witness)
        };

        native_debug!("Applying l2 block in STF Blueprint");

        self.verify_l2_block(l2_block, sequencer_public_key, current_spec)?;

        self.begin_l2_block(&mut working_set, &l2_block_info)?;

        self.apply_l2_block_txs(&l2_block_info, &l2_block.txs, &mut working_set)?;

        self.end_l2_block(l2_block_info, &mut working_set)?;

        let res = self.finalize_l2_block(current_spec, working_set, pre_state);

        native_debug!(
            "l2 block with hash: {:?} has been successfully applied",
            hex::encode(l2_block.hash()),
        );

        Ok(res)
    }

    /// Apply l2 block from sequencer commitments
    #[allow(clippy::too_many_arguments)]
    pub fn apply_l2_blocks_from_sequencer_commitments(
        &mut self,
        guest: &impl ZkvmGuest,
        sequencer_public_key: &[u8],
        initial_prev_l2_block_hash: Option<[u8; 32]>,
        initial_state_root: &StorageRootHash,
        pre_state: C::Storage,
        previous_sequencer_commitment: Option<SequencerCommitment>,
        prev_hash_proof: Option<PrevHashProof>,
        sequencer_commitments: Vec<SequencerCommitment>,
        cache_prune_l2_heights: &[u64],
        forks: &[Fork],
    ) -> ApplySequencerCommitmentsOutput {
        let sequencer_public_key = K256PublicKey::try_from_slice(sequencer_public_key)
            .expect("Sequencer public key must be valid");

        let mut state_diff = CumulativeStateDiff::default();

        let sequencer_commitment_hashes = sequencer_commitments
            .iter()
            .map(|c| c.serialize_and_calculate_sha_256())
            .collect::<Vec<_>>();

        let sequencer_commitment_index_range = (
            sequencer_commitments.first().unwrap().index,
            sequencer_commitments.last().unwrap().index,
        );

        // Verify these soft confirmations.
        let mut current_state_root = *initial_state_root;

        // prev_l2_block_hash is extracted from the previous_sequencer_commitment, but previous_sequencer_commitment
        // is always None for the first proof of each network. Hence, we hardcode the initial_prev_l2_block_hash as
        // constant into the guest binary. But for the TestNetworkWithForks we can't know the initial_prev_l2_block_hash
        // because it changes on every test run, hence, in that case, prev_l2_block_hash becomes None.
        let mut prev_l2_block_hash: Option<[u8; 32]> = match &previous_sequencer_commitment {
            Some(commitment) => {
                let prev_hash_proof = prev_hash_proof
                    .expect("Previous sequencer commitment must have a prev hash proof");

                let merkle_proof = MerkleProof::<Sha256>::from_bytes(
                    prev_hash_proof.merkle_proof_bytes.as_slice(),
                )
                .expect("Merkle proof must be valid");

                // This means we could actually bake in the genesis root into the batch proof
                // and we could start from the first l2 block
                assert_eq!(
                    prev_hash_proof.last_header.state_root(),
                    *initial_state_root,
                    "Initial state root must match the last header state root"
                );

                let index = commitment
                    .l2_end_block_number
                    .checked_sub(prev_hash_proof.prev_sequencer_commitment_start)
                    .expect("Index underflow") as usize;

                let count = index.checked_add(1).expect("Count overflow");
                let last_header_hash = prev_hash_proof.last_header.compute_digest();

                assert!(
                    merkle_proof.verify(
                        commitment.merkle_root,
                        &[index],
                        &[last_header_hash],
                        count
                    ),
                    "Prev hash proof must be valid"
                );

                Some(last_header_hash)
            }
            None => {
                assert!(prev_hash_proof.is_none());
                initial_prev_l2_block_hash
            }
        };

        let group_count: u32 = guest.read_from_host();

        assert_eq!(group_count, sequencer_commitments.len() as u32);
        // Proofs start when Tangerine fork is activated.
        // As proofs are only generated post tangerine, >= is safe to do
        // As with the introudction of Fork3, nightly tests run on Fork3 fork only
        let proving_activation_height = forks
            .iter()
            .find(|f| f.spec_id >= SpecId::Tangerine)
            .expect("A fork GTE to Tangerine must exist")
            .activation_height;

        // If tangerine start height is not 0 meaning there are other forks before tangerine,
        // then the previous batch proof l2 end height should be the tangerine start height - 1
        // Because the first l2 height of the first tangerine batch proof must be non-zero tangerine activation height
        let mut previous_batch_proof_l2_end_height = proving_activation_height.saturating_sub(1);

        // If there is no previous commitment, then this is the first batch proof
        // and this should start from proving the first l2 block
        let (previous_commitment_index, previous_commitment_hash) =
            if let Some(previous_sequencer_commitment) = previous_sequencer_commitment {
                // The only way there would be a 0 indexed commitment is if the previous commitment somehow has index 0
                // This assertion will block that
                assert!(
                    previous_sequencer_commitment.index != 0,
                    "Previous sequencer commitment index must be non-zero"
                );

                // The index of the previous commitment should be one less than the first commitment
                assert_eq!(
                    previous_sequencer_commitment.index + 1,
                    sequencer_commitments[0].index,
                    "Sequencer commitments must be sequential"
                );
                // If there exists a previous commitment, then the first l2 block to prove
                // should be the one after the last commitment
                previous_batch_proof_l2_end_height =
                    previous_sequencer_commitment.l2_end_block_number;
                (
                    Some(previous_sequencer_commitment.index),
                    Some(previous_sequencer_commitment.serialize_and_calculate_sha_256()),
                )
            } else {
                // If this is the first batch proof, then the first commitment idx should be 1
                assert_eq!(
                    sequencer_commitments[0].index, 1,
                    "First commitment must be index 1"
                );
                (None, None)
            };
        let current_batch_proof_first_l2_height = previous_batch_proof_l2_end_height + 1;
        let mut fork_manager = ForkManager::new(forks, current_batch_proof_first_l2_height);
        let mut sequencer_commitment_l2_start_height = current_batch_proof_first_l2_height;

        let mut last_commitment_end_height = previous_batch_proof_l2_end_height;

        // Reusable log caches
        let mut cumulative_state_log = None;
        let mut cumulative_offchain_log = None;
        let mut cache_prune_l2_heights_iter = cache_prune_l2_heights.iter().peekable();

        // State roots are pushed to this vector at the end of each sequencer commitment applied
        let mut state_roots = Vec::with_capacity(sequencer_commitments.len() + 1);
        state_roots.push(*initial_state_root);

        for sequencer_commitment in sequencer_commitments.into_iter() {
            // if the commitment is not sequential, then the proof is invalid.

            assert_eq!(
                last_commitment_end_height + 1,
                sequencer_commitment_l2_start_height,
                "Sequencer commitments must be sequential"
            );

            last_commitment_end_height = sequencer_commitment.l2_end_block_number;

            // we must verify given DA headers match the commitments

            let mut l2_height = sequencer_commitment_l2_start_height;

            let state_change_count: u32 = guest.read_from_host();
            let mut l2_block_hashes = Vec::with_capacity(state_change_count as usize);

            for _ in 0..state_change_count {
                // there used to be a need for height to be passed before L2 block
                // now this is not needed but deployed provers still have the same input generation in place
                // so don't use this variable
                let _l2_block_l2_height = guest.read_from_host::<u64>();

                let (l2_block, state_witness, offchain_witness) =
                    guest.read_from_host::<(L2Block, Witness, Witness)>();

                assert_eq!(
                    l2_block.height(),
                    l2_height,
                    "L2 block height is not equal to the expected height"
                );

                if let Some(prev_hash) = prev_l2_block_hash {
                    assert_eq!(
                        l2_block.prev_hash(),
                        prev_hash,
                        "L2 block previous hash must match the hash of the block before"
                    );
                }

                fork_manager.register_block(l2_height).unwrap();

                let result = self
                    .apply_l2_block(
                        fork_manager.active_fork().spec_id,
                        &sequencer_public_key,
                        &current_state_root,
                        pre_state.clone(),
                        cumulative_state_log,
                        cumulative_offchain_log,
                        state_witness,
                        offchain_witness,
                        &l2_block,
                    )
                    // TODO: this can be just ignoring the failing seq. com.
                    // We can count a failed l2 block as a valid state transition.
                    // for now we don't allow "broken" seq. com.s
                    .expect("L2 block must succeed");

                assert_eq!(current_state_root, result.state_root_transition.init_root);
                current_state_root = result.state_root_transition.final_root;
                state_diff.extend(result.state_diff);

                // The state root of prover should match l2 block coming from sequencer
                assert_eq!(current_state_root, l2_block.state_root());

                let mut state_log = result.state_log;
                let mut offchain_log = result.offchain_log;
                // prune cache logs if it is hinted from native
                if cache_prune_l2_heights_iter
                    .next_if_eq(&&l2_height)
                    .is_some()
                {
                    state_log.prune_half();
                    offchain_log.prune_half();
                }

                l2_height += 1;
                prev_l2_block_hash = Some(l2_block.hash());
                l2_block_hashes.push(l2_block.hash());

                cumulative_state_log = Some(state_log);
                cumulative_offchain_log = Some(offchain_log);
            }

            // now verify the claimed merkle root of l2 block hashes
            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(l2_block_hashes.as_slice()).root();

            assert_eq!(
                calculated_root,
                Some(sequencer_commitment.merkle_root),
                "Invalid merkle root"
            );

            assert_eq!(sequencer_commitment.l2_end_block_number, l2_height - 1);
            // Update next sequencer commitment start height
            sequencer_commitment_l2_start_height = l2_height;

            state_roots.push(current_state_root);
        }

        ApplySequencerCommitmentsOutput {
            state_roots,
            state_diff,
            // There has to be a height
            last_l2_height: last_commitment_end_height,
            final_l2_block_hash: prev_l2_block_hash.unwrap(),
            sequencer_commitment_hashes,
            sequencer_commitment_index_range,
            cumulative_state_log: cumulative_state_log.unwrap(),
            previous_commitment_index,
            previous_commitment_hash,
        }
    }
}

fn verify_signature(
    header: &SignedL2Header,
    sequencer_public_key: &K256PublicKey,
) -> Result<(), anyhow::Error> {
    let signature = K256Signature::try_from(header.signature.as_slice())?;

    signature.verify(sequencer_public_key, &header.hash)?;

    Ok(())
}
