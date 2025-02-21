#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use std::collections::VecDeque;

use borsh::BorshSerialize;
use citrea_primitives::EMPTY_TX_ROOT;
use itertools::Itertools;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::default_signature::{
    DefaultPublicKey, DefaultSignature, K256PublicKey, K256Signature,
};
use sov_modules_api::digest::Digest;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::{
    ApplySoftConfirmationHooks, FinalizeHook, HookSoftConfirmationInfo, SlotHooks, TxHooks,
};
use sov_modules_api::transaction::{PreFork2Transaction, Transaction};
use sov_modules_api::{
    native_debug, BasicAddress, Context, DaSpec, DispatchCall, Genesis, Signature, Spec,
    UnsignedSoftConfirmation, WorkingSet,
};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::soft_confirmation::{
    L2Block, SignedL2Header, UnsignedSoftConfirmationV1,
};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{
    ApplySequencerCommitmentsOutput, SoftConfirmationError, SoftConfirmationResult,
    StateTransitionError, StateTransitionFunction, TransactionDigest,
};
use sov_rollup_interface::zk::batch_proof::output::CumulativeStateDiff;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_state::{ReadWriteLog, Storage};

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
    + ApplySoftConfirmationHooks<Da, Context = C>
    + Default
{
    /// GenesisConfig type.
    type GenesisConfig: Send + Sync;

    #[cfg(feature = "native")]
    /// GenesisPaths type.
    type GenesisPaths: Send + Sync;

    #[cfg(feature = "native")]
    /// Default rpc methods.
    fn rpc_methods(storage: C::Storage) -> jsonrpsee::RpcModule<()>;

    #[cfg(feature = "native")]
    /// Reads genesis configs.
    fn genesis_config(
        genesis_paths: &Self::GenesisPaths,
    ) -> Result<Self::GenesisConfig, anyhow::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
/// Represents the different outcomes that can occur for a sequencer after batch processing.
pub enum SequencerOutcome<A: BasicAddress> {
    /// Sequencer receives reward amount in defined token and can withdraw its deposit
    Rewarded(u64),
    /// Sequencer loses its deposit and receives no reward
    Slashed {
        /// Reason why sequencer was slashed.
        reason: SlashingReason,
        #[serde(bound(deserialize = ""))]
        /// Sequencer address on DA.
        sequencer_da_address: A,
    },
    /// Batch was ignored, sequencer deposit left untouched.
    Ignored,
}

/// Genesis parameters for a blueprint
pub struct GenesisParams<RT> {
    /// The runtime genesis parameters
    pub runtime: RT,
}

/// Reason why sequencer was slashed.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SlashingReason {
    /// This status indicates problem with batch deserialization.
    InvalidBatchEncoding,
    /// Stateless verification failed, for example deserialized transactions have invalid signatures.
    StatelessVerificationFailed,
    /// This status indicates problem with transaction deserialization.
    InvalidTransactionEncoding,
}

impl<C, RT, Da> StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Begin a soft confirmation
    pub fn begin_soft_confirmation(
        &mut self,
        sequencer_public_key: &[u8],
        working_set: &mut WorkingSet<C::Storage>,
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> Result<(), StateTransitionError> {
        // check if soft confirmation is coming from our sequencer
        if soft_confirmation_info.sequencer_pub_key() != sequencer_public_key {
            return Err(StateTransitionError::SoftConfirmationError(
                SoftConfirmationError::SequencerPublicKeyMismatch,
            ));
        };

        // then verify da hashes match
        if soft_confirmation_info.da_slot_hash() != slot_header.hash().into() {
            return Err(StateTransitionError::SoftConfirmationError(
                SoftConfirmationError::InvalidDaHash,
            ));
        }

        // then verify da transactions commitment match
        if soft_confirmation_info.da_slot_txs_commitment() != slot_header.txs_commitment().into() {
            return Err(StateTransitionError::SoftConfirmationError(
                SoftConfirmationError::InvalidDaTxsCommitment,
            ));
        }

        self.begin_soft_confirmation_inner(working_set, soft_confirmation_info)
            .map_err(StateTransitionError::HookError)
    }

    /// Apply soft confirmation transactions
    pub fn apply_soft_confirmation_txs(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        blobs: &[Vec<u8>],
        txs: &[<Self as StateTransitionFunction<Da>>::Transaction],
        batch_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.apply_sov_txs_inner(soft_confirmation_info, blobs, txs, batch_workspace)
    }

    /// Verify l2_block hash and signature
    pub fn verify_soft_confirmation(
        &self,
        current_spec: SpecId,
        l2_block: &L2Block<<Self as StateTransitionFunction<Da>>::Transaction>,
        sequencer_public_key: &[u8],
    ) -> Result<(), StateTransitionError> {
        let l2_header = &l2_block.header;

        verify_tx_merkle_root::<C, <Self as StateTransitionFunction<Da>>::Transaction>(
            current_spec,
            l2_block,
        )
        .map_err(|_| {
            StateTransitionError::SoftConfirmationError(SoftConfirmationError::InvalidTxMerkleRoot)
        })?;

        match current_spec {
            SpecId::Genesis => {
                // PreFork2Transaction
                let unsigned = UnsignedSoftConfirmationV1::from(l2_block);
                let raw = borsh::to_vec(&unsigned).map_err(|_| {
                    StateTransitionError::SoftConfirmationError(
                        SoftConfirmationError::NonSerializableSovTx,
                    )
                })?;

                let expected_hash: [u8; 32] = <C as Spec>::Hasher::digest(&raw).into();
                if l2_block.hash() != expected_hash {
                    return Err(StateTransitionError::SoftConfirmationError(
                        SoftConfirmationError::InvalidSoftConfirmationHash,
                    ));
                }

                verify_genesis_signature(&raw, &l2_header.signature, sequencer_public_key)
            }
            SpecId::Kumquat => {
                let unsigned = UnsignedSoftConfirmation::from(l2_block);
                let expected_hash =
                    Into::<[u8; 32]>::into(unsigned.compute_digest::<<C as Spec>::Hasher>());

                if l2_block.hash() != expected_hash {
                    return Err(StateTransitionError::SoftConfirmationError(
                        SoftConfirmationError::InvalidSoftConfirmationHash,
                    ));
                }

                verify_kumquat_signature(l2_header, sequencer_public_key)
            }
            _ => {
                let expected_hash =
                    Into::<[u8; 32]>::into(l2_header.inner.compute_digest::<<C as Spec>::Hasher>());

                if l2_block.hash() != expected_hash {
                    return Err(StateTransitionError::SoftConfirmationError(
                        SoftConfirmationError::InvalidSoftConfirmationHash,
                    ));
                }

                verify_soft_confirmation_signature(l2_header, sequencer_public_key)
            }
        }
        .map_err(|_| {
            StateTransitionError::SoftConfirmationError(
                SoftConfirmationError::InvalidSoftConfirmationSignature,
            )
        })
    }

    /// End a soft confirmation
    pub fn end_soft_confirmation(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.end_soft_confirmation_inner(soft_confirmation_info, working_set)
            .map_err(StateTransitionError::HookError)
    }

    /// Finalizes a soft confirmation
    pub fn finalize_soft_confirmation(
        &self,
        _current_spec: SpecId,
        working_set: WorkingSet<C::Storage>,
        pre_state: <Self as StateTransitionFunction<Da>>::PreState,
    ) -> SoftConfirmationResult<
        C::Storage,
        <C::Storage as Storage>::Witness,
        <Self as StateTransitionFunction<Da>>::StateLog,
    > {
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
                .compute_state_update(&state_log, &mut witness)
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

        SoftConfirmationResult {
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

impl<C, RT, Da> StateTransitionFunction<Da> for StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    type Transaction = Transaction;

    type GenesisParams = GenesisParams<<RT as Genesis>::Config>;
    type PreState = C::Storage;
    type ChangeSet = C::Storage;
    type StateLog = ReadWriteLog;

    type Witness = <C::Storage as Storage>::Witness;

    fn init_chain(
        &self,
        pre_state: Self::PreState,
        params: Self::GenesisParams,
    ) -> (StorageRootHash, Self::ChangeSet) {
        let mut working_set = WorkingSet::new(pre_state.clone());

        self.runtime.genesis(&params.runtime, &mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let (state_root_transition, state_update, _) = pre_state
            .compute_state_update(&state_log, &mut witness)
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

    fn apply_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &[u8],
        pre_state_root: &StorageRootHash,
        pre_state: Self::PreState,
        cumulative_state_log: Option<Self::StateLog>,
        cumulative_offchain_log: Option<Self::StateLog>,
        state_witness: Self::Witness,
        offchain_witness: Self::Witness,
        // the header hash does not need to be verified here because the full
        // nodes construct the header on their own
        slot_header: &<Da as DaSpec>::BlockHeader,
        l2_block: &L2Block<Self::Transaction>,
    ) -> Result<
        SoftConfirmationResult<Self::ChangeSet, Self::Witness, Self::StateLog>,
        StateTransitionError,
    > {
        let soft_confirmation_info =
            HookSoftConfirmationInfo::new(l2_block, *pre_state_root, current_spec);

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

        native_debug!("Applying soft confirmation in STF Blueprint");

        self.verify_soft_confirmation(current_spec, l2_block, sequencer_public_key)?;

        self.begin_soft_confirmation(
            sequencer_public_key,
            &mut working_set,
            slot_header,
            &soft_confirmation_info,
        )?;

        self.apply_soft_confirmation_txs(
            &soft_confirmation_info,
            &l2_block.blobs,
            &l2_block.txs,
            &mut working_set,
        )?;

        self.end_soft_confirmation(soft_confirmation_info, &mut working_set)?;

        let res = self.finalize_soft_confirmation(current_spec, working_set, pre_state);

        native_debug!(
            "soft confirmation with hash: {:?} from sequencer {:?} has been successfully applied",
            hex::encode(l2_block.hash()),
            hex::encode(l2_block.sequencer_pub_key()),
        );

        Ok(res)
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        guest: &impl ZkvmGuest,
        sequencer_public_key: &[u8],
        sequencer_k256_public_key: &[u8],
        initial_state_root: &StorageRootHash,
        pre_state: Self::PreState,
        sequencer_commitments: Vec<SequencerCommitment>,
        slot_headers: VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        cache_prune_l2_heights: &[u64],
        forks: &[Fork],
    ) -> ApplySequencerCommitmentsOutput {
        let mut state_diff = CumulativeStateDiff::default();

        let sequencer_commitment_merkle_roots = sequencer_commitments
            .iter()
            .map(|c| c.merkle_root)
            .collect::<Vec<_>>();

        // Verify these soft confirmations.
        let mut current_state_root = *initial_state_root;
        let mut prev_soft_confirmation_hash: Option<[u8; 32]> = None;
        let mut last_commitment_end_height: Option<u64> = None;

        let group_count: u32 = guest.read_from_host();

        assert_eq!(group_count, sequencer_commitments.len() as u32);

        let mut fork_manager =
            ForkManager::new(forks, sequencer_commitments[0].l2_start_block_number);

        // Reuseable log caches
        let mut cumulative_state_log = None;
        let mut cumulative_offchain_log = None;
        let mut cache_prune_l2_heights_iter = cache_prune_l2_heights.iter().peekable();

        for (sequencer_commitment, da_block_headers) in
            sequencer_commitments.into_iter().zip_eq(slot_headers)
        {
            // if the commitment is not sequential, then the proof is invalid.
            if let Some(end_height) = last_commitment_end_height {
                assert_eq!(
                    end_height + 1,
                    sequencer_commitment.l2_start_block_number,
                    "Sequencer commitments must be sequential"
                );
            }
            last_commitment_end_height = Some(sequencer_commitment.l2_end_block_number);

            // we must verify given DA headers match the commitments
            let mut index_headers = 0;
            let mut current_da_height = da_block_headers[index_headers].height();
            let mut l2_height = sequencer_commitment.l2_start_block_number;

            let state_change_count: u32 = guest.read_from_host();
            let mut soft_confirmation_hashes = Vec::with_capacity(state_change_count as usize);

            for _ in 0..state_change_count {
                let soft_confirmation_l2_height = guest.read_from_host::<u64>();
                fork_manager
                    .register_block(soft_confirmation_l2_height)
                    .unwrap();

                let spec_id = fork_manager.active_fork().spec_id;
                let (l2_block, state_witness, offchain_witness) = if spec_id >= SpecId::Kumquat {
                    guest.read_from_host::<(
                        L2Block<Self::Transaction>,
                        <C::Storage as Storage>::Witness,
                        <C::Storage as Storage>::Witness,
                    )>()
                } else {
                    let (l2_block, state_witness, offchain_witness) = guest.read_from_host::<(
                        L2Block<PreFork2Transaction<C>>,
                        <C::Storage as Storage>::Witness,
                        <C::Storage as Storage>::Witness,
                    )>();
                    let (parsed_txs, blobs): (Vec<Self::Transaction>, Vec<Vec<u8>>) = l2_block
                        .txs
                        .iter()
                        .map(|tx| {
                            let blob =
                                borsh::to_vec(tx).expect("Failed to serialize Prefork2Transaction");
                            let tx: Self::Transaction = tx.clone().into();
                            (tx, blob)
                        })
                        .unzip();

                    let sc = L2Block::new(
                        l2_block.header,
                        parsed_txs.into(),
                        blobs.into(),
                        l2_block.deposit_data,
                        l2_block.da_slot_height,
                        l2_block.da_slot_hash,
                    );
                    (sc, state_witness, offchain_witness)
                };

                assert_eq!(
                    l2_block.l2_height(),
                    l2_height,
                    "Soft confirmation height is not equal to the expected height"
                );

                if let Some(hash) = prev_soft_confirmation_hash {
                    assert_eq!(
                        l2_block.prev_hash(),
                        hash,
                        "Soft confirmation previous hash must match the hash of the block before"
                    );
                }

                // the soft confirmations DA hash must equal to da hash in index_headers
                // if it's not matching, and if it's not matching the next one, then state transition is invalid.
                if l2_block.da_slot_hash() == da_block_headers[index_headers].hash().into() {
                    assert_eq!(
                        l2_block.da_slot_height(),
                        da_block_headers[index_headers].height(),
                        "Soft confirmation DA slot height must match DA block header height"
                    );
                } else {
                    // before going to the next DA block header, we must check if it's hash was supplied
                    // correctly
                    assert!(
                        da_block_headers[index_headers].verify_hash(),
                        "Invalid DA block header hash"
                    );

                    index_headers += 1;

                    // this can also be done in soft confirmation rule enforcer?
                    assert_eq!(
                        da_block_headers[index_headers].height(),
                        current_da_height + 1,
                        "DA block headers must be in order"
                    );

                    assert_eq!(
                        da_block_headers[index_headers - 1].hash(),
                        da_block_headers[index_headers].prev_hash(),
                        "DA block headers must be in order"
                    );

                    current_da_height += 1;

                    // if the next one is not matching, then the state transition is invalid.
                    assert_eq!(
                        l2_block.da_slot_hash(),
                        da_block_headers[index_headers].hash().into(),
                        "Soft confirmation DA slot hash must match DA block header hash"
                    );

                    assert_eq!(
                        l2_block.da_slot_height(),
                        da_block_headers[index_headers].height(),
                        "Soft confirmation DA slot height must match DA block header height"
                    );
                }

                assert_eq!(
                    l2_block.l2_height(),
                    l2_height,
                    "Soft confirmation heights not sequential"
                );

                let sequencer_pub_key = if fork_manager.active_fork().spec_id >= SpecId::Fork2 {
                    sequencer_k256_public_key
                } else {
                    sequencer_public_key
                };

                let result = self
                    .apply_soft_confirmation(
                        fork_manager.active_fork().spec_id,
                        sequencer_pub_key,
                        &current_state_root,
                        pre_state.clone(),
                        cumulative_state_log,
                        cumulative_offchain_log,
                        state_witness,
                        offchain_witness,
                        &da_block_headers[index_headers],
                        &l2_block,
                    )
                    // TODO: this can be just ignoring the failing seq. com.
                    // We can count a failed soft confirmation as a valid state transition.
                    // for now we don't allow "broken" seq. com.s
                    .expect("Soft confirmation must succeed");

                assert_eq!(current_state_root, result.state_root_transition.init_root);
                current_state_root = result.state_root_transition.final_root;
                state_diff.extend(result.state_diff);

                l2_height += 1;

                prev_soft_confirmation_hash = Some(l2_block.hash());

                soft_confirmation_hashes.push(l2_block.hash());

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

                cumulative_state_log = Some(state_log);
                cumulative_offchain_log = Some(offchain_log);
            }

            assert_eq!(
                index_headers,
                da_block_headers.len() - 1,
                "All DA headers must be checked"
            );
            // also it's hash wasn't verified
            assert!(
                da_block_headers[index_headers].verify_hash(),
                "Invalid DA block header hash"
            );

            // now verify the claimed merkle root of soft confirmation hashes
            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice()).root();

            assert_eq!(
                calculated_root,
                Some(sequencer_commitment.merkle_root),
                "Invalid merkle root"
            );

            assert_eq!(sequencer_commitment.l2_end_block_number, l2_height - 1);
        }

        ApplySequencerCommitmentsOutput {
            final_state_root: current_state_root,
            state_diff,
            // There has to be a height
            last_l2_height: last_commitment_end_height.unwrap(),
            final_soft_confirmation_hash: prev_soft_confirmation_hash.unwrap(),
            sequencer_commitment_merkle_roots,
        }
    }
}

fn verify_soft_confirmation_signature(
    header: &SignedL2Header,
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let signature = K256Signature::try_from(header.signature.as_slice())?;

    signature.verify(
        &K256PublicKey::try_from(sequencer_public_key)?,
        &header.hash,
    )?;

    Ok(())
}

fn verify_kumquat_signature(
    header: &SignedL2Header,
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let signature = DefaultSignature::try_from(header.signature.as_slice())?;

    signature.verify(
        &DefaultPublicKey::try_from(sequencer_public_key)?,
        &header.hash,
    )?;

    Ok(())
}

fn verify_genesis_signature(
    message: &[u8],
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> anyhow::Result<()> {
    let signature = DefaultSignature::try_from(signature)?;
    let public_key = DefaultPublicKey::try_from(sequencer_public_key)?;

    signature.verify(&public_key, message)?;
    Ok(())
}

fn verify_tx_merkle_root<C: Context + Spec, Tx: Clone + BorshSerialize + TransactionDigest>(
    current_spec: SpecId,
    l2_block: &L2Block<'_, Tx>,
) -> Result<(), StateTransitionError> {
    let tx_hashes: Vec<[u8; 32]> = if current_spec >= SpecId::Kumquat {
        l2_block
            .txs
            .iter()
            .map(|tx| tx.compute_digest::<<C as Spec>::Hasher>().into())
            .collect()
    } else {
        l2_block
            .txs
            .iter()
            .map(|tx| {
                let serialized = borsh::to_vec(tx).expect("Tx serialization shouldn't fail");
                <C as Spec>::Hasher::digest(&serialized).into()
            })
            .collect()
    };

    let tx_merkle_root = if tx_hashes.is_empty() {
        EMPTY_TX_ROOT
    } else {
        MerkleTree::<Sha256>::from_leaves(&tx_hashes)
            .root()
            .expect("Couldn't compute merkle root")
    };

    if tx_merkle_root != l2_block.tx_merkle_root() {
        return Err(StateTransitionError::SoftConfirmationError(
            SoftConfirmationError::InvalidTxMerkleRoot,
        ));
    }
    Ok(())
}
