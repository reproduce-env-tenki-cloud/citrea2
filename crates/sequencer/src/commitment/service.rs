use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use citrea_common::utils::get_tangerine_activation_height_non_zero;
use citrea_evm::{get_last_l1_height_in_light_client, Evm};
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::DefaultContext;
use reth_tasks::shutdown::GracefulShutdown;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_modules_api::WorkingSet;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::da::{BlockHeaderTrait, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use sov_state::ProverStorage;
use tokio::select;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, instrument, warn};

use super::controller::CommitmentController;
use crate::metrics::SEQUENCER_METRICS;

/// L2 heights to commit
pub(crate) type CommitmentRange = RangeInclusive<L2BlockNumber>;

/// Service responsible for managing and processing sequencer commitments
pub struct CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps,
{
    /// The ledger database interface for state operations
    ledger_db: Db,
    /// Data availability service interface
    da_service: Arc<Da>,
    /// Public key used for signing commitments
    sequencer_da_pub_key: Vec<u8>,
    /// Maximum number of L2 blocks that can be included in a single commitment
    max_l2_blocks: u64,
    /// Channel for receiving halt signals from the runner
    halt_rx: mpsc::UnboundedReceiver<bool>,
    /// Current commitment production state
    is_producing_commitments: bool,
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    /// Creates a new commitment service instance
    ///
    /// # Arguments
    /// * `ledger_db` - The ledger database interface
    /// * `da_service` - Data availability service interface
    /// * `sequencer_da_pub_key` - Public key for signing commitments
    /// * `max_l2_blocks` - Maximum number of L2 blocks per commitment
    /// * `halt_rx` - Channel for receiving halt signals
    ///
    /// # Returns
    /// A new CommitmentService instance
    pub fn new(
        ledger_db: Db,
        da_service: Arc<Da>,
        sequencer_da_pub_key: Vec<u8>,
        max_l2_blocks: u64,
        halt_rx: mpsc::UnboundedReceiver<bool>,
    ) -> Self {
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key,
            max_l2_blocks,
            halt_rx,
            is_producing_commitments: true,
        }
    }

    #[instrument(name = "CommitmentService", skip_all)]
    pub async fn run(
        mut self,
        storage_manager: ProverStorageManager,
        l2_block_hash: L2BlockHash,
        mut shutdown_signal: GracefulShutdown,
    ) {
        if l2_block_hash != [0; 32] {
            let prestate = storage_manager.create_final_view_storage();
            let working_set = WorkingSet::new(prestate.clone());

            // Resubmit if there were pending commitments on restart, skip it on first init
            if let Err(e) = self.resubmit_pending_commitments(working_set).await {
                error!("Could not resubmit pending commitments: {:?}", e);
            }
        }

        let commitment_controller = Arc::new(CommitmentController::new(
            self.ledger_db.clone(),
            self.max_l2_blocks,
        ));
        // This is not the head l2 height but the latest commitment's l2 height
        let mut last_l2_height = commitment_controller.last_l2_height();

        let mut check_new_block_tick = tokio::time::interval(Duration::from_secs(2));
        check_new_block_tick.tick().await;

        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("CommitmentService shutting down");
                    return;
                },
                // Handle halt signals from the runner
                halt_signal = self.halt_rx.recv() => {
                    match halt_signal {
                        Some(should_halt) => {
                            let should_run = !should_halt;
                            if self.is_producing_commitments != should_run {
                                self.is_producing_commitments = should_run;
                                if should_halt {
                                    warn!("CommitmentService: Commitments halted via RPC");
                                } else {
                                    info!("CommitmentService: Commitments resumed via RPC");
                                }
                            }
                        }
                        None => {
                            // Channel closed, should shutdown
                            warn!("CommitmentService: Halt signal channel closed");
                            return;
                        }
                    }
                },
                _ = check_new_block_tick.tick() => {
                    // Skip commitment processing if not running
                    if !self.is_producing_commitments {
                        debug!("CommitmentService: Skipping commitment processing (halted)");
                        continue;
                    }

                    let head_l2_height = self.ledger_db.get_head_l2_block_height().expect("Failed to fetch head L2 height").unwrap_or(0);
                    // No need to check commitment criteria if the start L2 block number did not change.
                    if head_l2_height <= last_l2_height {
                        continue;
                    }

                    // Checking the possibility of a commitment up to the head block means that
                    // the state diff might have exceeded the limit by a significant portion and/or
                    // the max amount of blocks we commit for.
                    // Instead, we loop here from the last commitment height + 1 incrementally and commit
                    // as soon as we find a block which signals the possibility of a commitment.
                    for current_l2_height in (last_l2_height + 1)..=head_l2_height {
                        let cc = commitment_controller.clone();

                        let should_commit = tokio::task::spawn_blocking(move || {
                            cc.should_commit(L2BlockNumber(current_l2_height))
                        }).await;
                        if let Some((index, commitment_range)) = should_commit
                            .expect("Commit check tokio blocking task failed")
                            .expect("Commitment criteria check failed")
                        {
                            if let Err(e) = self.commit(index, commitment_range).await {
                                // We just log error and continue here as the controller updated its internal state and it can
                                // continue functioning correctly. We just need to resubmit the failed commitment to DA.
                                error!("Failed to submit commitment: {:?}", e);
                            }
                        };

                        last_l2_height = current_l2_height;
                    }
                },
            }
        }
    }

    /// Commits a range of L2 blocks to the data availability layer
    ///
    /// # Arguments
    /// * `commitment_index` - Index of the commitment
    /// * `commitment_range` - Range of L2 blocks to commit
    /// * `processed_storage_update` - Processed storage updates to include
    /// * `l1_head` - Current L1 block height
    ///
    /// # Returns
    /// Result indicating success or failure of the commitment operation
    pub async fn commit(
        &mut self,
        commitment_index: u32,
        commitment_range: CommitmentRange,
    ) -> anyhow::Result<()> {
        let l2_start = *commitment_range.start();
        let l2_end = *commitment_range.end();

        let l2_block_hashes = self
            .ledger_db
            .get_l2_block_range(&commitment_range)?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        SEQUENCER_METRICS
            .commitment_blocks_count
            .set(l2_block_hashes.len() as f64);

        let commitment =
            self.get_commitment(commitment_index, &commitment_range, l2_block_hashes)?;

        debug!("Sequencer: submitting commitment: {:?}", commitment);

        let tx_request = DaTxRequest::SequencerCommitment(commitment.clone());
        let (notify, rx) = oneshot::channel();
        let request = TxRequestWithNotifier { tx_request, notify };
        self.da_service
            .get_send_transaction_queue()
            .send(request)
            .map_err(|_| anyhow!("Bitcoin service already stopped!"))?;

        info!(
            "Sent commitment to DA queue. L2 range: #{}-{}, index: {}",
            l2_start.0, l2_end.0, commitment_index,
        );

        let start = Instant::now();
        let ledger_db = self.ledger_db.clone();

        // Even though the commitment service does not shutdown before we get a response from the DA service,
        // we still need to store the commitment in the pending commitments, so that if anything happens
        // from the time we send the tx to the DA service and until we get a response (so the tx wasn't even submitted yet),
        // e.g. server shutdown, we can resubmit the pending commitments.
        //
        // So pending status for a commitment spans from da service submission to entrance to mempool.
        ledger_db.put_pending_commitment(&commitment).map_err(|_| {
            anyhow!("Sequencer: Failed to store sequencer commitment in pending commitments")
        })?;

        let _tx_id = rx
            .await
            .map_err(|_| anyhow!("DA service is dead!"))?
            .map_err(|_| anyhow!("Send transaction cannot fail"))?;

        SEQUENCER_METRICS.send_commitment_execution.record(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );

        ledger_db
            .put_commitment_by_index(&commitment)
            .map_err(|_| anyhow!("Sequencer: Failed to store sequencer commitment by index"))?;

        ledger_db.delete_pending_commitment(commitment.index)?;

        self.ledger_db
            .delete_state_diff_by_range(commitment_range)?;

        info!("New commitment. L2 range: #{}-{}", l2_start.0, l2_end.0);

        Ok(())
    }

    #[instrument(level = "trace", skip(self, working_set), err, ret)]
    pub async fn resubmit_pending_commitments(
        &mut self,
        mut working_set: WorkingSet<ProverStorage>,
    ) -> anyhow::Result<()> {
        info!("Resubmitting pending commitments");

        let mut pending_db_commitments = self.ledger_db.get_pending_commitments()?;
        pending_db_commitments.sort();
        info!("Pending db commitments: {:?}", pending_db_commitments);

        let mut pending_mempool_commitments = self.get_pending_mempool_commitments().await;
        pending_mempool_commitments.sort();
        info!(
            "Commitments that are already in DA mempool: {:?}",
            pending_mempool_commitments
        );

        // to determine which L1 block to start scanning from
        let start_scanning_l1_from: u64 = {
            let l2_height = self
                .ledger_db
                .get_last_commitment()?
                .map(|c| c.l2_end_block_number)
                .unwrap_or(1);

            // set state to end of evm block l2_height
            working_set.set_archival_version(l2_height + 1);

            let l1_height = get_last_l1_height_in_light_client(
                &Evm::<DefaultContext>::default(),
                &mut working_set,
            )
            .expect("There must be a last l1 height");

            l1_height.to::<u64>() + 1
        };

        let mut mined_commitments = self
            .get_mined_commitments_from(start_scanning_l1_from)
            .await?;
        mined_commitments.sort();
        info!(
            "Commitments that are already mined by DA: {:?}",
            mined_commitments
        );

        let mut pending_commitments_to_remove = vec![];
        pending_commitments_to_remove.extend(pending_mempool_commitments);
        pending_commitments_to_remove.extend(mined_commitments);

        pending_commitments_to_remove.sort();
        pending_commitments_to_remove.dedup();
        info!(
            "Pending commitments to remove: {:?}",
            pending_commitments_to_remove
        );

        for pending_db_comm in pending_db_commitments {
            if pending_commitments_to_remove
                .iter()
                .any(|commitment| commitment.index == pending_db_comm.index)
            {
                // this pending commitment is either mined or in the L1 mempool
                // so we can delete it from the pending db and put it to commitment by index
                self.ledger_db.put_commitment_by_index(&pending_db_comm)?;
                self.ledger_db
                    .delete_pending_commitment(pending_db_comm.index)?;
            } else {
                // Submit commitment
                let l2_start_block_number = if pending_db_comm.index == 1 {
                    get_tangerine_activation_height_non_zero()
                } else {
                    self.ledger_db
                        .get_commitment_by_index(pending_db_comm.index - 1)?
                        .unwrap()
                        .l2_end_block_number
                        + 1
                };
                let range = L2BlockNumber(l2_start_block_number)
                    ..=L2BlockNumber(pending_db_comm.l2_end_block_number);

                self.commit(pending_db_comm.index, range).await?;
            }
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub fn get_commitment(
        &self,
        commitment_index: u32,
        commitment_range: &CommitmentRange,
        l2_block_hashes: Vec<[u8; 32]>,
    ) -> anyhow::Result<SequencerCommitment> {
        // sanity check
        assert_eq!(
            commitment_range.end().0 - commitment_range.start().0 + 1u64,
            l2_block_hashes.len() as u64,
            "Sequencer: Soft confirmation hashes length does not match the commitment info"
        );
        // build merkle tree over soft confirmations
        let merkle_root = MerkleTree::<Sha256>::from_leaves(l2_block_hashes.as_slice())
            .root()
            .ok_or(anyhow!("Couldn't compute merkle root"))?;
        Ok(SequencerCommitment {
            merkle_root,
            index: commitment_index,
            l2_end_block_number: commitment_range.end().0,
        })
    }

    /// Retrieves pending sequencer commitments from the mempool
    ///
    /// # Returns
    /// A vector of pending sequencer commitments
    async fn get_pending_mempool_commitments(&self) -> Vec<SequencerCommitment> {
        self.da_service
            .get_pending_sequencer_commitments(&self.sequencer_da_pub_key)
            .await
    }

    /// Retrieves mined commitments starting from a specific height
    ///
    /// # Arguments
    /// * `start_height` - Starting L1 block height to search from
    ///
    /// # Returns
    /// Result containing a vector of mined sequencer commitments
    async fn get_mined_commitments_from(
        &self,
        start_height: u64,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        info!(
            "Getting mined commitments from DA service starting from height: {}",
            start_height
        );

        let head_da_height = self
            .da_service
            .get_head_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();
        let mut mined_commitments = vec![];

        for height in start_height..=head_da_height {
            let block = self
                .da_service
                .get_block_at(height)
                .await
                .map_err(|e| anyhow!(e))?;
            let iter = self
                .da_service
                .extract_relevant_sequencer_commitments(&block, &self.sequencer_da_pub_key)
                .into_iter()
                .map(|(_, commitment)| commitment);
            mined_commitments.extend(iter);
        }

        Ok(mined_commitments)
    }
}
