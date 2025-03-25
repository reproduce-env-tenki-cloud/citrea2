use std::collections::BTreeMap;

use accessors::{BlockHashAccessor, ChunkAccessor, SequencerCommitmentAccessor};
use borsh::BorshDeserialize;
use initial_values::LCP_JMT_GENESIS_ROOT;
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{BlobReaderTrait, DaSpec, WorkingSet, Zkvm};
use sov_modules_core::{ReadWriteLog, Storage};
use sov_rollup_interface::da::{BatchProofMethodId, DaVerifier, DataOnDa};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::batch_proof::output::BatchProofCircuitOutput;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    BatchProofInfo, IndexAndHashOfCommitment, LightClientCircuitOutput,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use utils::prune_batch_proofs_with_missing_commitments;

use crate::circuit::utils::{collect_unchained_outputs, recursive_match_state_roots};

/// Accessor (helpers) that are used inside the light client proof circuit.
/// To access certain information that was saved to its state at one point.
pub(crate) mod accessors;
/// Initial values that are used to initialize the light client proof circuit.
pub mod initial_values;
pub(crate) mod utils;

// L2 activation height of the fork, and the batch proof method ID
type InitialBatchProofMethodIds = Vec<(u64, [u32; 8])>;

type CircuitError = &'static str;

#[derive(Debug)]
pub enum LightClientVerificationError<DaV: DaVerifier> {
    DaTxsCouldntBeVerified(DaV::Error),
    HeaderChainVerificationFailed(DaV::Error),
    InvalidPreviousLightClientProof,
}

pub enum ProofProcess {
    Correct,
    MissingSequencerCommitment(Vec<IndexAndHashOfCommitment>),
    Discard(String),
}

impl ProofProcess {
    pub fn push_missing_sequencer_commitment_data(&mut self, idx: u32, hash: [u8; 32]) {
        if let ProofProcess::MissingSequencerCommitment(vec) = self {
            vec.push((idx, hash));
        } else {
            panic!("Should be missing sequencer commitment");
        }
    }
}

pub struct RunL1BlockResult<S: Storage> {
    l2_state_root: [u8; 32],
    lcp_state_root: [u8; 32],
    unchained_batch_proofs_info: Vec<BatchProofInfo>,
    last_l2_height: u64,
    batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    pub witness: Witness,
    pub change_set: S,
    last_sequencer_commitment_index: u32,
    semi_unstitched: Vec<BatchProofInfo>,
}

pub struct LightClientProofCircuit<S: Storage, DS: DaSpec, Z: Zkvm> {
    phantom: core::marker::PhantomData<(S, DS, Z)>,
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> LightClientProofCircuit<S, DS, Z> {
    pub fn new() -> Self {
        Self {
            phantom: core::marker::PhantomData,
        }
    }

    fn verify_seq_comm_relation(
        &self,
        batch_proof_output: &BatchProofCircuitOutput,
        working_set: &mut WorkingSet<S>,
    ) -> ProofProcess {
        if !BlockHashAccessor::<S>::exists(
            batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract(),
            working_set,
        ) {
            return ProofProcess::Discard(format!(
                "Block hash does not exist in the jmt state: {:?}",
                batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract()
            ));
        }

        let mut proof_process = ProofProcess::Correct;

        let (first_index, last_index) = batch_proof_output.sequencer_commitment_index_range();
        let batch_proof_output_sequencer_commitment_hashes =
            batch_proof_output.sequencer_commitment_hashes();

        // TODO: even if bp cant produce such an output, just discard on this
        // The index range len should be equal to the number of sequencer commitment hashes in the batch proof output
        if (last_index - first_index + 1) as usize
            != batch_proof_output_sequencer_commitment_hashes.len()
        {
            return ProofProcess::Discard(format!(
                "Sequencer commitment index range length mismatch, expected: {}, got: {}",
                (last_index - first_index + 1),
                batch_proof_output_sequencer_commitment_hashes.len()
            ));
        }

        for (batch_proof_sequencer_commitment_index, batch_proof_sequencer_commitment_hash) in
            (first_index..=last_index).zip(batch_proof_output_sequencer_commitment_hashes)
        {
            let jmt_commitment = match SequencerCommitmentAccessor::<S>::get(
                batch_proof_sequencer_commitment_index,
                working_set,
            ) {
                Some(commitment) => commitment,
                None => {
                    if matches!(proof_process, ProofProcess::Correct) {
                        proof_process = ProofProcess::MissingSequencerCommitment(vec![]);
                    }
                    proof_process.push_missing_sequencer_commitment_data(
                        batch_proof_sequencer_commitment_index,
                        batch_proof_sequencer_commitment_hash,
                    );
                    continue;
                }
            };
            let jmt_commitment_hash = jmt_commitment.serialize_and_calculate_sha_256();
            if jmt_commitment_hash != batch_proof_sequencer_commitment_hash {
                return ProofProcess::Discard(format!(
                    "Sequencer commitment hash mismatch, expected: {:?}, got: {:?}",
                    jmt_commitment_hash, batch_proof_sequencer_commitment_hash
                ));
            }
        }

        proof_process
    }

    // TODO: Too many args
    fn process_complete_proof(
        &self,
        proof: &[u8],
        batch_proof_method_ids: &InitialBatchProofMethodIds,
        last_l2_height: &mut u64,
        last_commitment_index: &mut u32,
        last_l2_state_root: &mut [u8; 32],
        fully_unstitched: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64, u32)>,
        batch_proofs_with_missing_sequencer_commitments: &mut Vec<BatchProofInfo>,
        working_set: &mut WorkingSet<S>,
    ) -> Result<(), CircuitError> {
        let Ok(journal) = Z::extract_raw_output(proof) else {
            return Err("Failed to extract output from proof");
        };

        let batch_proof_output = Z::deserialize_output::<BatchProofCircuitOutput>(&journal)
            .map_err(|_| "Failed to deserialize output")?;
        if !BlockHashAccessor::<S>::exists(
            batch_proof_output.last_l1_hash_on_bitcoin_light_client_contract(),
            working_set,
        ) {
            return Err("Batch proof with unknown header chain");
        }

        let batch_proof_output_initial_state_root = batch_proof_output.initial_state_root();
        let batch_proof_output_final_state_root = batch_proof_output.final_state_root();
        let batch_proof_output_last_l2_height = batch_proof_output.last_l2_height();
        let batch_proof_output_sequencer_commitment_index_range =
            batch_proof_output.sequencer_commitment_index_range();

        // Do not add if last l2 height is smaller or equal to previous output
        // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
        if batch_proof_output_last_l2_height <= *last_l2_height && *last_l2_height != 0 {
            return Err("Last L2 height is less than proof's last l2 height");
        }

        let batch_proof_method_id = if batch_proof_method_ids.len() == 1 {
            batch_proof_method_ids[0].1
        } else {
            let idx = match batch_proof_method_ids
                // Returns err and the index to be inserted, which is the index of the first element greater than the key
                // That is why we need to subtract 1 to get the last element smaller than the key
                .binary_search_by_key(&batch_proof_output_last_l2_height, |(height, _)| *height)
            {
                Ok(idx) => idx,
                Err(idx) => idx.saturating_sub(1),
            };
            batch_proof_method_ids[idx].1
        };

        println!("Using batch proof method id {:?}", batch_proof_method_id);

        Z::verify(proof, &batch_proof_method_id.into()).map_err(|_| "Failed to verify proof")?;

        match self.verify_seq_comm_relation(&batch_proof_output, working_set) {
            ProofProcess::Correct => {
                // Both checks match, this is the expected case
                if batch_proof_output_sequencer_commitment_index_range.0
                    == *last_commitment_index + 1
                    && batch_proof_output.initial_state_root() == *last_l2_state_root
                {
                    *last_l2_state_root = batch_proof_output_final_state_root;
                    *last_l2_height = batch_proof_output_last_l2_height;
                    *last_commitment_index = batch_proof_output_sequencer_commitment_index_range.0;

                    // Do recursive matching for previous state root
                    recursive_match_state_roots(
                        fully_unstitched,
                        &BatchProofInfo::new(
                            *last_l2_state_root,
                            *last_l2_state_root,
                            *last_l2_height,
                            *last_commitment_index,
                            None,
                        ),
                    );
                    return Ok(());
                }
                // None of the checks match, proof order is wrong, put it to unstitched
                else if batch_proof_output_sequencer_commitment_index_range.0
                    != *last_commitment_index + 1
                    && batch_proof_output.initial_state_root() != *last_l2_state_root
                {
                    fully_unstitched.insert(
                        batch_proof_output_initial_state_root,
                        (
                            batch_proof_output_final_state_root,
                            batch_proof_output_last_l2_height,
                            batch_proof_output_sequencer_commitment_index_range.1,
                        ),
                    );
                }
                // One of the checks is wrong, this should never happen, in this case the proof is discarded
                else {
                    println!("Discarding proof, sequencer commitment index or initial state root is wrong\n Expected index: {}, got: {}\nExpected initial state root: {:?}, got: {:?}", *last_commitment_index + 1, batch_proof_output_sequencer_commitment_index_range.0, *last_l2_state_root, batch_proof_output.initial_state_root());
                    return Err("Proof discarded");
                }
            }
            ProofProcess::MissingSequencerCommitment(missing_commitments) => {
                batch_proofs_with_missing_sequencer_commitments.push(BatchProofInfo::new(
                    batch_proof_output_initial_state_root,
                    batch_proof_output_final_state_root,
                    batch_proof_output_last_l2_height,
                    batch_proof_output_sequencer_commitment_index_range.1,
                    Some(missing_commitments),
                ));
                return Ok(());
            }
            ProofProcess::Discard(_) => {
                return Err("Proof discarded");
            }
        }

        recursive_match_state_roots(
            fully_unstitched,
            &BatchProofInfo::new(
                batch_proof_output_initial_state_root,
                batch_proof_output_final_state_root,
                batch_proof_output_last_l2_height,
                batch_proof_output_sequencer_commitment_index_range.1,
                None,
            ),
        );

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    // will be called by the circuit and native
    pub fn run_l1_block(
        &self,
        storage: S,
        witness: Witness,
        da_txs: Vec<DS::BlobTransaction>,
        da_block_header: DS::BlockHeader,
        previous_light_client_proof_output: Option<LightClientCircuitOutput>,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> RunL1BlockResult<S> {
        let mut working_set =
            WorkingSet::with_witness(storage.clone(), witness, Default::default());

        // first insert the block hash into the JMT
        BlockHashAccessor::<S>::insert(da_block_header.hash().into(), &mut working_set);

        // Mapping from initial state root to final state root, last L2 height and sequencer commitment range
        let mut initial_to_final = BTreeMap::<[u8; 32], ([u8; 32], u64, u32)>::new();

        let (
            mut last_l2_state_root,
            mut last_l2_height,
            mut last_sequencer_commitment_index,
            mut batch_proofs_with_missing_sequencer_commitments,
        ) = previous_light_client_proof_output.as_ref().map_or_else(
            || {
                // if no previous proof, we start from genesis state root
                (l2_genesis_root, 0, 0, vec![])
            },
            |prev_journal| {
                (
                    prev_journal.l2_state_root,
                    prev_journal.last_l2_height,
                    prev_journal.last_sequencer_commitment_index,
                    prev_journal
                        .batch_proofs_with_missing_sequencer_commitments
                        .clone(),
                )
            },
        );

        // If we have a previous light client proof, check they can be chained
        // If not, skip for now
        if let Some(previous_output) = &previous_light_client_proof_output {
            for unchained_info in previous_output.unchained_batch_proofs_info.iter() {
                // Add them directly as they are the ones that could not be matched
                initial_to_final.insert(
                    unchained_info.initial_state_root,
                    (
                        unchained_info.final_state_root,
                        unchained_info.last_l2_height,
                        unchained_info.last_sequencer_commitment_index,
                    ),
                );
            }
        }

        let mut batch_proof_method_ids = previous_light_client_proof_output
            .as_ref()
            .map_or(initial_batch_proof_method_ids, |o| {
                o.batch_proof_method_ids.clone()
            });

        'blob_loop: for blob in da_txs {
            let Ok(data) = DataOnDa::try_from_slice(blob.full_data()) else {
                println!("Unparseable blob in da_data, wtxid={:?}", blob.wtxid());
                continue;
            };

            match data {
                // No need to check sender for chunk
                DataOnDa::Chunk(chunk) => {
                    println!("Found chunk");

                    ChunkAccessor::<S>::insert(
                        blob.wtxid().expect("Chunk should have wtxid"),
                        chunk,
                        &mut working_set,
                    );
                }
                DataOnDa::Complete(proof) => {
                    println!("Found complete proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        println!(
                            "Complete proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    match self.process_complete_proof(
                        &proof,
                        &batch_proof_method_ids,
                        &mut last_l2_height,
                        &mut last_sequencer_commitment_index,
                        &mut last_l2_state_root,
                        &mut initial_to_final,
                        &mut batch_proofs_with_missing_sequencer_commitments,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        Err(e) => println!("Error processing complete proof: {e}"),
                    }
                }
                DataOnDa::Aggregate(_, wtxids) => {
                    println!("Found aggregate proof");
                    if blob.sender().as_ref() != batch_prover_da_public_key {
                        println!(
                            "Aggregate proof sender is not batch prover, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let mut complete_proof = Vec::new();

                    // Ensure that aggregate has all the needed chunks.
                    for wtxid in &wtxids {
                        match ChunkAccessor::<S>::get(*wtxid, &mut working_set) {
                            Some(body) => complete_proof.extend_from_slice(body.as_ref()),
                            None => {
                                println!(
                                    "Unknown chunk in aggregate proof, wtxid={:?} skipping",
                                    wtxid
                                );
                                continue 'blob_loop;
                            }
                        }
                    }

                    println!("Aggregate has all needed chunks!");

                    let Ok(complete_proof) = DS::decompress_chunks(&complete_proof) else {
                        println!("Failed to decompress and deserialize completed chunks");
                        continue;
                    };

                    match self.process_complete_proof(
                        &complete_proof,
                        &batch_proof_method_ids,
                        &mut last_l2_height,
                        &mut last_sequencer_commitment_index,
                        &mut last_l2_state_root,
                        &mut initial_to_final,
                        &mut batch_proofs_with_missing_sequencer_commitments,
                        &mut working_set,
                    ) {
                        Ok(()) => {}
                        // proof resulting from chunk concatanation is not valid
                        // either due to ZK proof being invalid
                        // a deserialization error
                        // or the resulting output was ZK-valid but included an L1 hash
                        // that was not know to the prover
                        Err(e) => {
                            println!("Error processing aggregated proof: {e}");
                        }
                    }
                }
                DataOnDa::BatchProofMethodId(BatchProofMethodId {
                    method_id,
                    activation_l2_height,
                }) => {
                    println!("Found batch proof method id");
                    if blob.sender().as_ref() != method_id_upgrade_authority_da_public_key {
                        println!(
                            "Batch proof method id sender is not upgrade authority, wtxid={:?}",
                            blob.wtxid()
                        );
                        continue;
                    }

                    let last_activation_height = batch_proof_method_ids
                        .last()
                        .expect("Should be at least one")
                        .0;

                    if activation_l2_height > last_activation_height {
                        batch_proof_method_ids.push((activation_l2_height, method_id));
                    }
                }
                DataOnDa::SequencerCommitment(commitment) => {
                    println!("Found sequencer commitment with index {}", commitment.index);
                    if SequencerCommitmentAccessor::<S>::get(commitment.index, &mut working_set)
                        .is_none()
                    {
                        SequencerCommitmentAccessor::<S>::insert(
                            commitment.index,
                            commitment.clone(),
                            &mut working_set,
                        );
                        // TODO: Optimize below, use sth like:
                        /*
                            particles.retain(|particle| {
                                let delete = {
                                    // Do stuff ...
                                };
                                !delete
                           })
                        */
                        let mut remove_batch_proof_indexes = vec![];
                        for (proof_index, batch_proof_with_missing_seq_comms) in
                            batch_proofs_with_missing_sequencer_commitments
                                .iter_mut()
                                .enumerate()
                        {
                            let mut missing_comm_idx_to_remove = vec![];
                            for (idx, missing_seq_comm) in batch_proof_with_missing_seq_comms
                                .missing_commitments
                                .iter()
                                .enumerate()
                            {
                                if missing_seq_comm.0 == commitment.index
                                    && missing_seq_comm.1
                                        == commitment.serialize_and_calculate_sha_256()
                                {
                                    missing_comm_idx_to_remove.push(idx);
                                }
                            }
                            for idx in missing_comm_idx_to_remove.iter().rev() {
                                batch_proof_with_missing_seq_comms
                                    .missing_commitments
                                    .remove(*idx);
                            }

                            if batch_proof_with_missing_seq_comms
                                .missing_commitments
                                .is_empty()
                            {
                                remove_batch_proof_indexes.push(proof_index);
                            }
                        }

                        for idx in remove_batch_proof_indexes.iter().rev() {
                            initial_to_final.insert(
                                batch_proofs_with_missing_sequencer_commitments[*idx]
                                    .initial_state_root,
                                (
                                    batch_proofs_with_missing_sequencer_commitments[*idx]
                                        .final_state_root,
                                    batch_proofs_with_missing_sequencer_commitments[*idx]
                                        .last_l2_height,
                                    batch_proofs_with_missing_sequencer_commitments[*idx]
                                        .last_sequencer_commitment_index,
                                ),
                            );
                            batch_proofs_with_missing_sequencer_commitments.remove(*idx);
                        }
                    } else {
                        println!("Found a commitment that already exists in the JMT with index: {:?}, The invalid commitment's l2 end height is: {:?} and merkle root is: {:?}", commitment.index, commitment.l2_end_block_number, commitment.merkle_root);
                    }
                }
            }
        }

        // Do recursive matching for previous state root
        recursive_match_state_roots(
            &mut initial_to_final,
            &BatchProofInfo::new(
                last_l2_state_root,
                last_l2_state_root,
                last_l2_height,
                last_sequencer_commitment_index,
                None,
            ),
        );

        // Now only thing left is the state update if exists and others are unchained
        if let Some((final_root, last_l2, last_commitment_index)) =
            initial_to_final.remove(&last_l2_state_root)
        {
            last_l2_height = last_l2;
            last_l2_state_root = final_root;
            last_sequencer_commitment_index = last_commitment_index;
        }

        // Collect unchained outputs
        let unchained_outputs = collect_unchained_outputs(
            &initial_to_final,
            last_l2_height,
            last_sequencer_commitment_index,
        );

        // Prune batch proofs with missing commitments
        // Remove proofs below last l2 height and index
        prune_batch_proofs_with_missing_commitments(
            &mut batch_proofs_with_missing_sequencer_commitments,
            last_l2_height,
            last_sequencer_commitment_index,
        );

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        let (lcp_state_root_transition, jmt_state_update, _) = storage
            .compute_state_update(&read_write_log, &mut witness, false)
            .expect("jellyfish merkle tree update must succeed");

        if let Some(output) = previous_light_client_proof_output {
            // If we had a previous light client proof, make sure the prev_root used in the JMT update proof
            // was the same as the previous light client proof's
            assert_eq!(
                lcp_state_root_transition.init_root, output.lcp_state_root,
                "Witness prev root is wrong!"
            );
        } else {
            // if running for the first time, we are going to be initializing the JMT
            // so the genesis root must this constant
            assert_eq!(lcp_state_root_transition.init_root, LCP_JMT_GENESIS_ROOT);
        }

        storage.commit(&jmt_state_update, &vec![], &ReadWriteLog::default());

        RunL1BlockResult {
            l2_state_root: last_l2_state_root,
            lcp_state_root: lcp_state_root_transition.final_root,
            unchained_batch_proofs_info: unchained_outputs,
            last_l2_height,
            batch_proof_method_ids,
            witness,
            change_set: storage,
            last_sequencer_commitment_index,
            semi_unstitched: batch_proofs_with_missing_sequencer_commitments,
        }
    }

    #[allow(clippy::too_many_arguments)]
    // will only called by the circuit
    pub fn run_circuit<DaV>(
        &self,
        da_verifier: DaV,
        input: LightClientCircuitInput<DaV::Spec>,
        storage: S,
        network: Network,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>>
    where
        DaV: DaVerifier<Spec = DS>,
        Z: ZkvmGuest,
    {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output =
            if let Some(journal) = input.previous_light_client_proof_journal {
                // previous LCP is verified with the assumption API
                // this would panic if the prev LCP cant be verified
                Z::verify_with_assumptions(&journal, &input.light_client_proof_method_id.into());

                let prev_output: LightClientCircuitOutput = Z::deserialize_output(&journal)
                    .map_err(|_| {
                        LightClientVerificationError::<DaV>::InvalidPreviousLightClientProof
                    })?;

                // Ensure method IDs match
                assert_eq!(
                    input.light_client_proof_method_id,
                    prev_output.light_client_proof_method_id,
                );
                Some(prev_output)
            } else {
                None
            };

        let new_da_state = da_verifier
            .verify_header_chain(
                previous_light_client_proof_output
                    .as_ref()
                    .map(|output| &output.latest_da_state),
                &input.da_block_header,
                network,
            )
            .map_err(|err| LightClientVerificationError::HeaderChainVerificationFailed(err))?;

        // extract DA transactions from the block
        let da_txs = da_verifier
            .verify_transactions(
                &input.da_block_header,
                input.inclusion_proof,
                input.completeness_proof,
            )
            .map_err(|err| LightClientVerificationError::DaTxsCouldntBeVerified(err))?;

        // then we can call run_l1_block to run the logic of the circuit
        let result = self.run_l1_block(
            storage,
            input.witness,
            da_txs,
            input.da_block_header,
            previous_light_client_proof_output,
            l2_genesis_root,
            initial_batch_proof_method_ids,
            batch_prover_da_public_key,
            method_id_upgrade_authority_da_public_key,
        );

        Ok(LightClientCircuitOutput {
            l2_state_root: result.l2_state_root,
            light_client_proof_method_id: input.light_client_proof_method_id,
            latest_da_state: new_da_state,
            unchained_batch_proofs_info: result.unchained_batch_proofs_info,
            last_l2_height: result.last_l2_height,
            batch_proof_method_ids: result.batch_proof_method_ids,
            lcp_state_root: result.lcp_state_root,
            last_sequencer_commitment_index: result.last_sequencer_commitment_index,
            batch_proofs_with_missing_sequencer_commitments: result.semi_unstitched,
        })
    }
}

impl<S: Storage, DS: DaSpec, Z: Zkvm> Default for LightClientProofCircuit<S, DS, Z> {
    fn default() -> Self {
        Self::new()
    }
}
