use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Instant;

use anyhow::anyhow;
use citrea_primitives::forks::get_fork2_activation_height_non_zero;
use parking_lot::RwLock;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::{L2BlockNumber, SlotNumber};
use sov_modules_api::StateDiff;
use sov_rollup_interface::da::{BlockHeaderTrait, DaTxRequest, SequencerCommitment};
use sov_rollup_interface::services::da::{DaService, TxRequestWithNotifier};
use tokio::select;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, instrument};

use self::controller::CommitmentController;
use crate::metrics::SEQUENCER_METRICS;

mod controller;

/// L2 heights to commit
type CommitmentRange = RangeInclusive<L2BlockNumber>;

pub struct CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps,
{
    ledger_db: Db,
    da_service: Arc<Da>,
    sequencer_da_pub_key: Vec<u8>,
    next_commitment_index: u32,
    l2_block_rx: UnboundedReceiver<(u64, StateDiff)>,
    commitment_controller: Arc<RwLock<CommitmentController<Db>>>,
}

fn load_next_commitment_index<Db: SequencerLedgerOps>(db: &Db) -> u32 {
    // max index from pending:
    let max_pending = db
        .get_pending_commitments()
        .unwrap()
        .into_iter()
        .map(|s| s.index)
        .max();
    // max index from last commitment:
    let max_last = db.get_last_commitment().unwrap().map(|s| s.index);
    // maximum of pending and last:
    let max_db = max_pending.max(max_last);
    if let Some(max_db) = max_db {
        max_db + 1
    } else {
        // if comms are empty, then index is 0
        0
    }
}

impl<Da, Db> CommitmentService<Da, Db>
where
    Da: DaService,
    Db: SequencerLedgerOps + Clone + Send + Sync + 'static,
{
    pub fn new(
        ledger_db: Db,
        da_service: Arc<Da>,
        sequencer_da_pub_key: Vec<u8>,
        min_l2_blocks: u64,
        l2_block_rx: UnboundedReceiver<(u64, StateDiff)>,
    ) -> Self {
        let commitment_controller = Arc::new(RwLock::new(CommitmentController::new(
            ledger_db.clone(),
            min_l2_blocks,
        )));
        let next_commitment_index = load_next_commitment_index(&ledger_db);
        Self {
            ledger_db,
            da_service,
            sequencer_da_pub_key,
            l2_block_rx,
            next_commitment_index,
            commitment_controller,
        }
    }

    pub async fn run(mut self, cancellation_token: CancellationToken) {
        loop {
            select! {
                biased;
                _ = cancellation_token.cancelled() => {
                    self.l2_block_rx.close();
                    return;
                },
                info = self.l2_block_rx.recv() => {
                    let Some((height, state_diff)) = info else {
                        // An error is returned because the channel is either
                        // closed or lagged.
                        error!("Commitment service l2 block channel closed abruptly");
                        return;
                    };

                    let commitment_controller = self.commitment_controller.clone();

                    // Given that `should_commit` calls are blocking, as some strategies might
                    // decide to write to rocksdb, others might try to execute CPU-bound operations,
                    // we use `parking_lot::RwLock` here to lock the commitment controller inside
                    // the blocking thread so that we can execute these strategies.
                    let Ok(commitment_info) = tokio::task::spawn_blocking(move || {
                        commitment_controller.write().should_commit(height, state_diff)
                    }).await else {
                        error!("Could not decide on commitment. Blocking thread panicked");
                        continue;
                    };

                    let commitment_info = match commitment_info {
                        Ok(Some(commitment_info)) => {
                            commitment_info
                        },
                        Err(e) => {
                            error!("Error while checking commitment criteria: {:?}", e);
                            continue;
                        },
                        _ => {
                            continue;
                        }
                    };

                    let index = self.next_commitment_index;
                    self.next_commitment_index += 1;

                    if let Err(e) = self.commit(index, commitment_info).await {
                        error!("Could not submit commitment: {:?}", e);
                    }
                }
            }
        }
    }

    pub async fn commit(
        &mut self,
        commitment_index: u32,
        commitment_info: CommitmentRange,
    ) -> anyhow::Result<()> {
        let l2_start = *commitment_info.start();
        let l2_end = *commitment_info.end();

        let l2_block_hashes = self
            .ledger_db
            .get_l2_block_range(&commitment_info)?
            .iter()
            .map(|sb| sb.hash)
            .collect::<Vec<[u8; 32]>>();

        SEQUENCER_METRICS
            .commitment_blocks_count
            .set(l2_block_hashes.len() as f64);

        let commitment = self.get_commitment(commitment_index, commitment_info, l2_block_hashes)?;

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

        ledger_db
            .put_commitment_by_index(&commitment)
            .map_err(|_| anyhow!("Sequencer: Failed to store sequencer commitment by index"))?;
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

        ledger_db.delete_pending_commitment(commitment.index)?;
        ledger_db
            .set_last_commitment(&commitment)
            .map_err(|_| anyhow!("Sequencer: Failed to set last sequencer commitment L2 height"))?;

        info!("New commitment. L2 range: #{}-{}", l2_start.0, l2_end.0);

        Ok(())
    }

    // TODO Re-write since da_slot_height is not indexed as part of L2Block. Ref https://github.com/chainwayxyz/citrea/issues/1998
    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn resubmit_pending_commitments(&mut self) -> anyhow::Result<()> {
        info!("Resubmitting pending commitments");

        let pending_db_commitments = self.ledger_db.get_pending_commitments()?;
        info!("Pending db commitments: {:?}", pending_db_commitments);

        let pending_mempool_commitments = self.get_pending_mempool_commitments().await;
        info!(
            "Commitments that are already in DA mempool: {:?}",
            pending_mempool_commitments
        );

        let last_commitment_l1_height = self
            .ledger_db
            .get_l1_height_of_last_commitment()?
            .unwrap_or(SlotNumber(1));
        let mined_commitments = self
            .get_mined_commitments_from(last_commitment_l1_height)
            .await?;
        info!(
            "Commitments that are already mined by DA: {:?}",
            mined_commitments
        );

        let mut pending_commitments_to_remove = vec![];
        pending_commitments_to_remove.extend(pending_mempool_commitments);
        pending_commitments_to_remove.extend(mined_commitments);

        for pending_db_comm in pending_db_commitments {
            if pending_commitments_to_remove
                .iter()
                .any(|commitment| commitment.index == pending_db_comm.index)
            {
                // Update last sequencer commitment l2 height
                match self.ledger_db.get_last_commitment()? {
                    Some(last_commitment_l2_height)
                        if last_commitment_l2_height.index >= pending_db_comm.index => {}
                    _ => {
                        self.ledger_db.set_last_commitment(&pending_db_comm)?;
                    }
                };

                // Delete from pending db if it is already in DA mempool or mined
                self.ledger_db
                    .delete_pending_commitment(pending_db_comm.index)?;
            } else {
                // Submit commitment
                let l2_start_block_number = if pending_db_comm.index == 0 {
                    get_fork2_activation_height_non_zero()
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
        commitment_info: CommitmentRange,
        l2_block_hashes: Vec<[u8; 32]>,
    ) -> anyhow::Result<SequencerCommitment> {
        // sanity check
        assert_eq!(
            commitment_info.end().0 - commitment_info.start().0 + 1u64,
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
            l2_end_block_number: commitment_info.end().0,
        })
    }

    async fn get_pending_mempool_commitments(&self) -> Vec<SequencerCommitment> {
        self.da_service
            .get_pending_sequencer_commitments(&self.sequencer_da_pub_key)
            .await
    }

    async fn get_mined_commitments_from(
        &self,
        _da_height: SlotNumber,
    ) -> anyhow::Result<Vec<SequencerCommitment>> {
        let head_da_height = self
            .da_service
            .get_head_block_header()
            .await
            .map_err(|e| anyhow!(e))?
            .height();
        let mut mined_commitments = vec![];
        // TODO: UPDATE RESUBMISSION LOGIC BECAUSE AFTER FORK2 DA HEIGHT OF SC IS 0
        // TODO: https://github.com/chainwayxyz/citrea/issues/1998
        for height in 1..=head_da_height {
            let block = self
                .da_service
                .get_block_at(height)
                .await
                .map_err(|e| anyhow!(e))?;
            let iter = self
                .da_service
                .extract_relevant_sequencer_commitments(&block, &self.sequencer_da_pub_key);
            mined_commitments.extend(iter);
        }

        Ok(mined_commitments)
    }
}
