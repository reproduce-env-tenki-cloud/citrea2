#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use borsh::BorshDeserialize;
use itertools::Itertools;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::default_signature::{
    DefaultPublicKey, DefaultSignature, K256PublicKey, K256Signature,
};
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::{
    ApplySoftConfirmationHooks, FinalizeHook, HookSoftConfirmationInfo, SlotHooks, TxHooks,
};
use sov_modules_api::transaction::{PreFork2Transaction, Transaction};
use sov_modules_api::{
    native_debug, BasicAddress, BlobReaderTrait, Context, DaSpec, DispatchCall, Genesis, Signature,
    Spec, StateCheckpoint, UnsignedSoftConfirmation, WorkingSet,
};
use sov_rollup_interface::da::DaDataBatchProof;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::soft_confirmation::{SignedSoftConfirmation, UnsignedSoftConfirmationV1};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{
    ApplySequencerCommitmentsOutput, SoftConfirmationError, SoftConfirmationResult,
    StateTransitionError, StateTransitionFunction,
};
use sov_rollup_interface::zk::batch_proof::output::CumulativeStateDiff;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_state::Storage;

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
        soft_confirmation_info: HookSoftConfirmationInfo,
        txs: &[Vec<u8>],
        txs_new: &[<Self as StateTransitionFunction<Da>>::Transaction],
        batch_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.apply_sov_txs_inner(soft_confirmation_info, txs, txs_new, batch_workspace)
    }

    /// End a soft confirmation
    pub fn end_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        pre_state_root: StorageRootHash,
        sequencer_public_key: &[u8],
        soft_confirmation: &mut SignedSoftConfirmation<
            <Self as StateTransitionFunction<Da>>::Transaction,
        >,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        let unsigned = UnsignedSoftConfirmation::new(
            soft_confirmation.l2_height(),
            soft_confirmation.da_slot_height(),
            soft_confirmation.da_slot_hash(),
            soft_confirmation.da_slot_txs_commitment(),
            soft_confirmation.blobs(),
            soft_confirmation.txs(),
            soft_confirmation.deposit_data().to_vec(),
            soft_confirmation.l1_fee_rate(),
            soft_confirmation.timestamp(),
        );

        // check the claimed hash
        if current_spec >= SpecId::Fork2 {
            let digest = unsigned.compute_digest::<<C as Spec>::Hasher>();
            let hash = Into::<[u8; 32]>::into(digest);
            if soft_confirmation.hash() != hash {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationHash,
                ));
            }

            // verify signature
            if verify_soft_confirmation_signature(
                soft_confirmation,
                soft_confirmation.signature(),
                sequencer_public_key,
            )
            .is_err()
            {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationSignature,
                ));
            }
        } else if current_spec >= SpecId::Kumquat {
            let digest = unsigned.compute_digest::<<C as Spec>::Hasher>();
            let hash = Into::<[u8; 32]>::into(digest);
            if soft_confirmation.hash() != hash {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationHash,
                ));
            }

            // verify signature
            if pre_fork2_verify_soft_confirmation_signature(
                soft_confirmation,
                soft_confirmation.signature(),
                sequencer_public_key,
            )
            .is_err()
            {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationSignature,
                ));
            }
        } else {
            let unsigned = UnsignedSoftConfirmationV1::from(unsigned);
            let digest = unsigned.hash::<<C as Spec>::Hasher>();
            let hash = Into::<[u8; 32]>::into(digest);
            if soft_confirmation.hash() != hash {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationHash,
                ));
            }

            // verify signature
            if pre_fork1_verify_soft_confirmation_signature(
                &unsigned,
                soft_confirmation.signature(),
                sequencer_public_key,
            )
            .is_err()
            {
                return Err(StateTransitionError::SoftConfirmationError(
                    SoftConfirmationError::InvalidSoftConfirmationSignature,
                ));
            }
        };

        self.end_soft_confirmation_inner(
            current_spec,
            pre_state_root,
            soft_confirmation,
            working_set,
        )
        .map_err(StateTransitionError::HookError)
    }

    /// Finalizes a soft confirmation
    pub fn finalize_soft_confirmation(
        &self,
        _current_spec: SpecId,
        working_set: WorkingSet<C::Storage>,
        pre_state: <Self as StateTransitionFunction<Da>>::PreState,
        soft_confirmation: &mut SignedSoftConfirmation<
            <Self as StateTransitionFunction<Da>>::Transaction,
        >,
    ) -> SoftConfirmationResult<C::Storage, <C::Storage as Storage>::Witness> {
        native_debug!(
            "soft confirmation with hash: {:?} from sequencer {:?} successfully applied",
            hex::encode(soft_confirmation.hash()),
            hex::encode(soft_confirmation.sequencer_pub_key()),
        );

        let (state_root_transition, witness, offchain_witness, storage, state_diff) = {
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (cache_log, mut witness) = checkpoint.freeze();

            let (state_root_transition, state_update, state_diff) = pre_state
                .compute_state_update(cache_log, &mut witness)
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
                witness,
                offchain_witness,
                pre_state,
                state_diff,
            )
        };

        SoftConfirmationResult {
            state_root_transition,
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

    type Witness = <C::Storage as Storage>::Witness;

    fn init_chain(
        &self,
        pre_state: Self::PreState,
        params: Self::GenesisParams,
    ) -> (StorageRootHash, Self::ChangeSet) {
        let mut working_set = StateCheckpoint::new(pre_state.clone()).to_revertable();

        self.runtime.genesis(&params.runtime, &mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (log, mut witness) = checkpoint.freeze();

        let (state_root_transition, state_update, _) = pre_state
            .compute_state_update(log, &mut witness)
            .expect("Storage update must succeed");
        let genesis_hash = state_root_transition.final_root;

        let mut working_set = checkpoint.to_revertable();

        self.runtime
            .finalize_hook(&genesis_hash, &mut working_set.accessory_state());

        let mut checkpoint = working_set.checkpoint();
        let accessory_log = checkpoint.freeze_non_provable();
        let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();

        // TODO: Commit here for now, but probably this can be done outside of STF
        // TODO: Commit is fine
        pre_state.commit(&state_update, &accessory_log, &offchain_log);

        (genesis_hash, pre_state)
    }

    fn apply_soft_confirmation(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &[u8],
        pre_state_root: &StorageRootHash,
        pre_state: Self::PreState,
        state_witness: Self::Witness,
        offchain_witness: Self::Witness,
        // the header hash does not need to be verified here because the full
        // nodes construct the header on their own
        slot_header: &<Da as DaSpec>::BlockHeader,
        soft_confirmation: &mut SignedSoftConfirmation<Self::Transaction>,
    ) -> Result<SoftConfirmationResult<Self::ChangeSet, Self::Witness>, StateTransitionError> {
        let soft_confirmation_info =
            HookSoftConfirmationInfo::new(soft_confirmation, *pre_state_root, current_spec);

        let checkpoint =
            StateCheckpoint::with_witness(pre_state.clone(), state_witness, offchain_witness);
        let mut working_set = checkpoint.to_revertable();

        native_debug!("Applying soft confirmation in STF Blueprint");

        self.begin_soft_confirmation(
            sequencer_public_key,
            &mut working_set,
            slot_header,
            &soft_confirmation_info,
        )?;

        self.apply_soft_confirmation_txs(
            soft_confirmation_info,
            soft_confirmation.blobs(),
            soft_confirmation.txs(),
            &mut working_set,
        )?;

        self.end_soft_confirmation(
            current_spec,
            *pre_state_root,
            sequencer_public_key,
            soft_confirmation,
            &mut working_set,
        )?;

        Ok(
            self.finalize_soft_confirmation(
                current_spec,
                working_set,
                pre_state,
                soft_confirmation,
            ),
        )
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        guest: &impl ZkvmGuest,
        sequencer_public_key: &[u8],
        sequencer_k256_public_key: &[u8],
        sequencer_da_public_key: &[u8],
        initial_state_root: &StorageRootHash,
        pre_state: Self::PreState,
        da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        sequencer_commitments_range: (u32, u32),
        slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        preproven_commitment_indices: Vec<usize>,
        forks: &[Fork],
    ) -> ApplySequencerCommitmentsOutput {
        let mut state_diff = CumulativeStateDiff::default();

        // Extract all sequencer commitments.
        // Ignore broken DaData and zk proofs. Also ignore ForcedTransaction's (will be implemented in the future).
        let mut sequencer_commitments = da_data
            .into_iter()
            .filter_map(|blob| {
                if blob.sender().as_ref() == sequencer_da_public_key {
                    let da_data = DaDataBatchProof::try_from_slice(blob.full_data());

                    if let Ok(DaDataBatchProof::SequencerCommitment(commitment)) = da_data {
                        return Some(commitment);
                    }
                }

                None
            })
            .collect::<Vec<_>>();

        // A breakdown of why we sort the sequencer commitments, and why we need fields
        // `StateTransitionData::preproven_commitments` and `StateTransitionData::sequencer_commitment_range`:
        //
        // There is a chance of your "relevant transaction" being replayed on da layer, if the da layer does not have
        // a publickey-nonce check. To prevent from these attacks stopping our proving, we need to have a way to input the
        // the commitments we will ignore. This does not break any trust assumptions, as the zk circuit checks the
        // state transitions. So the prover can not leave out any commitments, beacuse it would break the state root checks
        // done by the zk circuit.
        //
        // If there is limitations on da on for the size of a single transaction (all blockchains have this), then
        // it's a good idea to allow proving of a single sequencer commitment at a time. Because more sequencer commmitments being
        // processed means there will be a bigger state diff. But sometimes it's efficient to
        // prove multiple commitments at a time. So we need to have a way to input the range of commitments we are proving.
        //
        // Now, why do we sort?
        //
        // Again, if the da layer doesn't have a publickey-nonce relation, there is a chance of sequencer commitment #10
        // landing on the da layer before sequencer commitment #9. If DA layer ordering is enforced in the zk circuit,
        // then this will break your rollup. So we need to sort the commitments by their l2_start_block_number, or something else.
        //
        // As long as the zk circuit and the prover (the entity providing the zk circuit inputs) are in agreement on the
        // ordering, the range of commitments, and which commitments to ignore, the zk circuit will be able to verify the state transition.
        //
        // Again, since the zk circuit verify the state transition, the prover can not leave out any commitments or change the ordering of
        // rollup state transitions.
        sequencer_commitments.sort();

        // The preproven indices are sorted by the prover when originally passed.
        // Therefore, we can iterate of sequencer commitments and filter out
        // matching preproven indices.
        let mut preproven_commitments_iter = preproven_commitment_indices.into_iter().peekable();
        let sequencer_commitments_iter = sequencer_commitments
            .into_iter()
            .enumerate()
            .filter(|(idx, _)| {
                if let Some(preproven_idx) = preproven_commitments_iter.peek() {
                    if preproven_idx == idx {
                        preproven_commitments_iter.next();
                        return false;
                    }
                }
                true
            })
            .map(|(_, commitment)| commitment);

        // Then verify these soft confirmations.
        let mut current_state_root = *initial_state_root;
        let mut prev_soft_confirmation_hash: Option<[u8; 32]> = None;
        let mut last_commitment_end_height: Option<u64> = None;

        let group_count: u32 = guest.read_from_host();

        assert_eq!(
            group_count,
            sequencer_commitments_range.1 - sequencer_commitments_range.0 + 1
        );

        for (sequencer_commitment, da_block_headers) in sequencer_commitments_iter
            .skip(sequencer_commitments_range.0 as usize)
            .take(group_count as usize)
            .zip_eq(slot_headers)
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
            let mut fork_manager = ForkManager::new(forks, l2_height);

            let state_change_count: u32 = guest.read_from_host();
            let mut soft_confirmation_hashes = Vec::with_capacity(state_change_count as usize);

            for _ in 0..state_change_count {
                let soft_confirmation_l2_height = guest.read_from_host::<u64>();
                fork_manager
                    .register_block(soft_confirmation_l2_height)
                    .unwrap();

                let spec_id = fork_manager.active_fork().spec_id;
                let (mut soft_confirmation, state_witness, offchain_witness) =
                    if spec_id >= SpecId::Kumquat {
                        guest.read_from_host::<(
                            SignedSoftConfirmation<Self::Transaction>,
                            <C::Storage as Storage>::Witness,
                            <C::Storage as Storage>::Witness,
                        )>()
                    } else {
                        let (soft_confirmation, state_witness, offchain_witness) = guest
                            .read_from_host::<(
                                SignedSoftConfirmation<PreFork2Transaction<C>>,
                                <C::Storage as Storage>::Witness,
                                <C::Storage as Storage>::Witness,
                            )>();
                        let parsed_txs = soft_confirmation
                            .txs()
                            .iter()
                            .map(|tx| {
                                let tx: Self::Transaction = tx.clone().into();
                                tx
                            })
                            .collect::<Vec<_>>();
                        let sc = SignedSoftConfirmation::new(
                            soft_confirmation.l2_height(),
                            soft_confirmation.hash(),
                            soft_confirmation.prev_hash(),
                            soft_confirmation.da_slot_height(),
                            soft_confirmation.da_slot_hash(),
                            soft_confirmation.da_slot_txs_commitment(),
                            soft_confirmation.l1_fee_rate(),
                            soft_confirmation.blobs().to_vec().into(),
                            parsed_txs.into(),
                            soft_confirmation.deposit_data().to_vec(),
                            soft_confirmation.signature().to_vec(),
                            soft_confirmation.pub_key().to_vec(),
                            soft_confirmation.timestamp(),
                        );
                        (sc, state_witness, offchain_witness)
                    };

                assert_eq!(
                    soft_confirmation.l2_height(),
                    l2_height,
                    "Soft confirmation height is not equal to the expected height"
                );

                if let Some(hash) = prev_soft_confirmation_hash {
                    assert_eq!(
                        soft_confirmation.prev_hash(),
                        hash,
                        "Soft confirmation previous hash must match the hash of the block before"
                    );
                }

                // the soft confirmations DA hash must equal to da hash in index_headers
                // if it's not matching, and if it's not matching the next one, then state transition is invalid.
                if soft_confirmation.da_slot_hash() == da_block_headers[index_headers].hash().into()
                {
                    assert_eq!(
                        soft_confirmation.da_slot_height(),
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
                        soft_confirmation.da_slot_hash(),
                        da_block_headers[index_headers].hash().into(),
                        "Soft confirmation DA slot hash must match DA block header hash"
                    );

                    assert_eq!(
                        soft_confirmation.da_slot_height(),
                        da_block_headers[index_headers].height(),
                        "Soft confirmation DA slot height must match DA block header height"
                    );
                }

                assert_eq!(
                    soft_confirmation.l2_height(),
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
                        state_witness,
                        offchain_witness,
                        &da_block_headers[index_headers],
                        &mut soft_confirmation,
                    )
                    // TODO: this can be just ignoring the failing seq. com.
                    // We can count a failed soft confirmation as a valid state transition.
                    // for now we don't allow "broken" seq. com.s
                    .expect("Soft confirmation must succeed");

                assert_eq!(current_state_root, result.state_root_transition.init_root);
                current_state_root = result.state_root_transition.final_root;
                state_diff.extend(result.state_diff);

                l2_height += 1;

                prev_soft_confirmation_hash = Some(soft_confirmation.hash());

                soft_confirmation_hashes.push(soft_confirmation.hash());
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
        }
    }
}

fn verify_soft_confirmation_signature<Tx: Clone>(
    signed_soft_confirmation: &SignedSoftConfirmation<Tx>,
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let message = signed_soft_confirmation.hash();

    let signature = K256Signature::try_from(signature)?;

    signature.verify(
        &K256PublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}

fn pre_fork2_verify_soft_confirmation_signature<Tx: Clone>(
    signed_soft_confirmation: &SignedSoftConfirmation<Tx>,
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let message = signed_soft_confirmation.hash();

    let signature = DefaultSignature::try_from(signature)?;

    signature.verify(
        &DefaultPublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}

// Old version of verify_soft_confirmation_signature
// TODO: Remove derive(BorshSerialize) for UnsignedSoftConfirmation
//   when removing this fn
// FIXME: ^
fn pre_fork1_verify_soft_confirmation_signature(
    unsigned_soft_confirmation: &UnsignedSoftConfirmationV1,
    signature: &[u8],
    sequencer_public_key: &[u8],
) -> Result<(), anyhow::Error> {
    let message = borsh::to_vec(&unsigned_soft_confirmation).unwrap();

    let signature = DefaultSignature::try_from(signature)?;

    signature.verify(
        &DefaultPublicKey::try_from(sequencer_public_key)?,
        message.as_slice(),
    )?;

    Ok(())
}
