use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{error, info, instrument};

use bitcoin::{BlockHash, Transaction, Txid};
use bitcoincore_rpc::json::GetTransactionResult;
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;

use crate::service::FINALITY_DEPTH;

// Todo pass down lower value for test
// const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_millis(10);
const DEFAULT_HISTORY_LIMIT: usize = 1_000; // Keep track of last 1k txs

type BlockHeight = u64;
type Result<T> = std::result::Result<T, MonitorError>;

#[derive(Debug, Clone)]
pub struct MonitoringMetrics {
    pub total_monitored: usize,
    pub pending: usize,
    pub confirmed: usize,
    pub finalized: usize,
    pub evicted: usize,
    pub replaced: usize,
    pub current_height: BlockHeight,
    pub latest_block: BlockHash,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TxStatus {
    Pending {
        in_mempool: bool,
        fee_rate: Option<f64>,
        timestamp: Instant,
    },
    Confirmed {
        block_hash: BlockHash,
        block_height: BlockHeight,
        confirmations: u64,
    },
    Finalized {
        block_hash: BlockHash,
        block_height: BlockHeight,
    },
    Replaced {
        by_txid: Txid,
    },
    Evicted,
}

#[derive(Debug, Clone)]
pub struct MonitoredTx {
    pub tx: Transaction,
    pub initial_broadcast: Instant,
    pub last_checked: Instant,
    pub status: TxStatus,
    pub prev_tx: Option<Txid>, // Previous tx in chain
    pub next_tx: Option<Txid>, // Next tx in chain
}

#[derive(Debug, Clone)]
pub struct ChainState {
    current_height: BlockHeight,
    current_tip: BlockHash,
    recent_blocks: Vec<(BlockHash, BlockHeight)>,
}

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Transaction already monitored")]
    AlreadyMonitored,
    #[error("Transaction not found")]
    TxNotFound,
    #[error("BlockHash not found")]
    BlockHashNotFound,
    #[error("Previous transaction not monitored: {0}")]
    PrevTxNotMonitored(Txid),
    #[error("Invalid tx chain, odd number of txs")]
    OddNumberOfTxs,
    #[error(transparent)]
    BitcoinRpcError(#[from] bitcoincore_rpc::Error),
    #[error(transparent)]
    BitcoinEncodeError(#[from] bitcoin::consensus::encode::Error),
}

#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    pub check_interval: Duration,
    pub history_limit: usize,
    pub reorg_depth_threshold: u64,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            history_limit: DEFAULT_HISTORY_LIMIT,
            reorg_depth_threshold: FINALITY_DEPTH,
        }
    }
}

impl MonitoringConfig {
    fn new(check_interval: Option<Duration>, history_limit: Option<usize>) -> Self {
        Self {
            check_interval: check_interval.unwrap_or(DEFAULT_CHECK_INTERVAL),
            history_limit: history_limit.unwrap_or(DEFAULT_HISTORY_LIMIT),
            ..Default::default()
        }
    }
}

#[derive(Debug)]
pub struct MonitoringService {
    client: Arc<Client>,
    monitored_txs: RwLock<HashMap<Txid, MonitoredTx>>,
    chain_state: RwLock<ChainState>,
    config: MonitoringConfig,
    last_tx: Mutex<Option<Txid>>,
}

impl MonitoringService {
    pub async fn new(
        client: Arc<Client>,
        check_interval: Option<Duration>,
        history_limit: Option<usize>,
    ) -> Result<Self> {
        let config = MonitoringConfig::new(check_interval, history_limit);

        let current_height = client.get_block_count().await?;
        let current_tip = client.get_best_block_hash().await?;

        let mut recent_blocks = Vec::with_capacity(config.reorg_depth_threshold as usize);
        let mut current_hash: BlockHash;

        for height in (0..config.reorg_depth_threshold).map(|i| current_height.saturating_sub(i)) {
            current_hash = client.get_block_hash(height.into()).await?;
            recent_blocks.push((current_hash, height));
        }

        Ok(Self {
            client,
            monitored_txs: RwLock::new(HashMap::new()),
            chain_state: RwLock::new(ChainState {
                current_height,
                current_tip,
                recent_blocks,
            }),
            config,
            last_tx: Mutex::new(None),
        })
    }

    /// Spawn a tokio task to keep track of TX status and chain re-orgs
    pub fn spawn(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = interval(self.config.check_interval);
            loop {
                interval.tick().await;
                if let Err(e) = self.check_chain_state().await {
                    error!("Error checking chain state: {}", e);
                }
                if let Err(e) = self.check_transactions().await {
                    error!("Error checking transactions: {}", e);
                }
                self.prune_old_transactions().await;
            }
        });
    }

    /// Monitor a chain of transactions (commit/reveal pairs and any intermediate chunks)
    /// The txids are expected to be in order: [commit1, reveal1, commit2, reveal2, ..., commitN, revealN]
    /// where intermediate pairs are chunks leading to the final commit/reveal pair
    #[instrument(level = "trace", skip(self))]
    pub async fn monitor_transaction_chain(&self, txids: Vec<Txid>) -> Result<()> {
        if txids.len() % 2 != 0 {
            return Err(MonitorError::OddNumberOfTxs);
        }

        let mut last_tx = *self.last_tx.lock().await;

        let mut txids_iter = txids.into_iter();
        while let (Some(commit_txid), Some(reveal_txid)) = (txids_iter.next(), txids_iter.next()) {
            self.monitor_transaction(commit_txid, last_tx, Some(reveal_txid))
                .await?;

            self.monitor_transaction(reveal_txid, Some(commit_txid), None)
                .await?;

            last_tx = Some(reveal_txid)
        }

        *self.last_tx.lock().await = last_tx;

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn monitor_transaction(
        &self,
        txid: Txid,
        prev_tx: Option<Txid>,
        next_tx: Option<Txid>,
    ) -> Result<()> {
        if self.monitored_txs.read().await.contains_key(&txid) {
            return Err(MonitorError::AlreadyMonitored);
        }

        if let Some(prev_txid) = prev_tx {
            if !self.monitored_txs.read().await.contains_key(&prev_txid) {
                return Err(MonitorError::PrevTxNotMonitored(prev_txid));
            }
        }

        let tx_result = self.client.get_transaction(&txid, None).await?;
        let tx = tx_result.transaction()?;

        let status = self.determine_tx_status(&tx_result).await?;
        let monitored_tx = MonitoredTx {
            tx,
            initial_broadcast: Instant::now(),
            last_checked: Instant::now(),
            status,
            prev_tx,
            next_tx,
        };

        self.monitored_txs.write().await.insert(txid, monitored_tx);

        Ok(())
    }

    #[instrument(skip(self))]
    async fn check_chain_state(&self) -> Result<()> {
        let new_height = self.client.get_block_count().await?;
        let new_tip = self.client.get_best_block_hash().await?;

        let mut chain_state = self.chain_state.write().await;

        if new_tip != chain_state.current_tip {
            let mut current_hash: BlockHash;
            let mut new_blocks = vec![(new_tip, new_height)];
            let mut reorg_detected = false;
            let mut reorg_depth = 0;

            for i in 1..=self.config.reorg_depth_threshold {
                let height = new_height.saturating_sub(i);
                current_hash = self.client.get_block_hash(height.into()).await?;
                new_blocks.push((current_hash, height));

                if let Some(pos) = chain_state
                    .recent_blocks
                    .iter()
                    .position(|&(hash, _)| hash == current_hash)
                {
                    if pos != i as usize {
                        reorg_detected = true;
                        reorg_depth = i;
                    }
                    break;
                }
            }

            if reorg_detected {
                // Handle transaction status updates due to reorg
                self.handle_reorg(reorg_depth).await?;
            }

            chain_state.current_height = new_height;
            chain_state.current_tip = new_tip;
            chain_state.recent_blocks = new_blocks;
        }

        Ok(())
    }

    async fn handle_reorg(&self, depth: u64) -> Result<()> {
        let mut txs = self.monitored_txs.write().await;

        for (txid, tx) in txs.iter_mut() {
            if let TxStatus::Confirmed { confirmations, .. } = tx.status {
                if confirmations <= depth {
                    let tx_result = self.client.get_transaction(&txid, None).await?;
                    tx.status = self.determine_tx_status(&tx_result).await?;

                    if let TxStatus::Pending { .. } = tx.status {
                        info!("Rebroadcasting tx {tx:?}");
                        let raw_tx = self.client.get_raw_transaction_hex(&txid, None).await?;
                        self.client.send_raw_transaction(raw_tx).await?;
                    }
                }
            }
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn check_transactions(&self) -> Result<()> {
        let mut txs = self.monitored_txs.write().await;

        for (txid, monitored_tx) in txs.iter_mut() {
            match &monitored_tx.status {
                // Check non-finalized TXs
                TxStatus::Pending { .. }
                | TxStatus::Confirmed { .. }
                | TxStatus::Replaced { .. } => {
                    let tx_result = self.client.get_transaction(txid, None).await?;
                    let new_status = self.determine_tx_status(&tx_result).await?;

                    monitored_tx.status = new_status;
                }
                _ => {}
            }
            monitored_tx.last_checked = Instant::now();
        }

        Ok(())
    }

    async fn determine_tx_status(&self, tx_result: &GetTransactionResult) -> Result<TxStatus> {
        let status = if tx_result.info.confirmations > 0 {
            let block_hash = tx_result
                .info
                .blockhash
                .ok_or(MonitorError::BlockHashNotFound)?;
            let block_height = self
                .client
                .get_block_info(&block_hash)
                .await
                .map(|header| header.height as u64)
                .unwrap_or(0);

            if tx_result.info.confirmations > 0
                && tx_result.info.confirmations as u64 >= FINALITY_DEPTH
            {
                TxStatus::Finalized {
                    block_hash,
                    block_height,
                }
            } else {
                TxStatus::Confirmed {
                    block_hash,
                    block_height,
                    confirmations: tx_result.info.confirmations as u64,
                }
            }
        } else {
            let in_mempool = self
                .client
                .get_mempool_entry(&tx_result.info.txid)
                .await
                .is_ok();

            let fee_rate = if in_mempool {
                self.client
                    .get_mempool_entry(&tx_result.info.txid)
                    .await
                    .ok()
                    .map(|entry| {
                        entry.fees.base.to_sat() as f64
                            / tx_result.transaction().unwrap().vsize() as f64
                    })
            } else {
                None
            };

            TxStatus::Pending {
                in_mempool,
                fee_rate,
                timestamp: Instant::now(),
            }
        };
        Ok(status)
    }

    async fn prune_old_transactions(&self) {
        let mut txs = self.monitored_txs.write().await;

        if txs.len() > self.config.history_limit {
            let to_remove: Vec<_> = txs
                .iter()
                .filter(|(_, tx)| matches!(tx.status, TxStatus::Finalized { .. }))
                .map(|(txid, tx)| (*txid, tx.initial_broadcast))
                .collect();

            let mut to_remove = to_remove;
            to_remove.sort_by_key(|&(_, time)| time);

            for (txid, _) in to_remove {
                if txs.len() <= self.config.history_limit {
                    break;
                }
                txs.remove(&txid);
            }
        }
    }

    // pub async fn get_tx_status(&self, txid: &Txid) -> Option<TxStatus> {
    //     self.monitored_txs
    //         .read()
    //         .await
    //         .get(txid)
    //         .map(|tx| tx.status.clone())
    // }

    // pub async fn get_chain_details(&self) -> (BlockHash, BlockHeight) {
    //     let state = self.chain_state.read().await;
    //     (state.current_tip, state.current_height)
    // }

    // pub async fn get_tx_chain(&self, txid: &Txid) -> Option<Vec<Txid>> {
    //     let txs = self.monitored_txs.read().await;
    //     let mut chain = Vec::new();
    //     let mut current_txid = *txid;

    //     while let Some(tx) = txs.get(&current_txid) {
    //         if let Some(prev_txid) = tx.prev_tx {
    //             chain.insert(0, prev_txid);
    //             current_txid = prev_txid;
    //         } else {
    //             break;
    //         }
    //     }

    //     chain.push(*txid);

    //     current_txid = *txid;
    //     while let Some(tx) = txs.get(&current_txid) {
    //         if let Some(next_txid) = tx.next_tx {
    //             chain.push(next_txid);
    //             current_txid = next_txid;
    //         } else {
    //             break;
    //         }
    //     }

    //     if chain.is_empty() {
    //         None
    //     } else {
    //         Some(chain)
    //     }
    // }

    // pub async fn get_chain_status(&self, txid: &Txid) -> Option<Vec<(Txid, TxStatus)>> {
    //     let chain = self.get_tx_chain(txid).await?;
    //     let txs = self.monitored_txs.read().await;

    //     Some(
    //         chain
    //             .into_iter()
    //             .filter_map(|tx_id| txs.get(&tx_id).map(|tx| (tx_id, tx.status.clone())))
    //             .collect(),
    //     )
    // }

    // pub async fn get_monitored_transactions(&self) -> Vec<(Txid, MonitoredTx)> {
    //     self.monitored_txs
    //         .read()
    //         .await
    //         .iter()
    //         .map(|(txid, tx)| (*txid, tx.clone()))
    //         .collect()
    // }

    // pub async fn get_pending_transactions(&self) -> Vec<(Txid, MonitoredTx)> {
    //     self.monitored_txs
    //         .read()
    //         .await
    //         .iter()
    //         .filter(|(_, tx)| matches!(tx.status, TxStatus::Pending { .. }))
    //         .map(|(txid, tx)| (*txid, tx.clone()))
    //         .collect()
    // }

    // #[instrument(skip(self))]
    // pub async fn get_metrics(&self) -> MonitoringMetrics {
    //     let txs = self.monitored_txs.read().await;

    //     let (pending, confirmed, finalized, evicted, replaced) =
    //         txs.values().fold((0, 0, 0, 0, 0), |mut acc, tx| {
    //             match tx.status {
    //                 TxStatus::Pending { .. } => acc.0 += 1,
    //                 TxStatus::Confirmed { .. } => acc.1 += 1,
    //                 TxStatus::Finalized { .. } => acc.2 += 1,
    //                 TxStatus::Evicted { .. } => acc.3 += 1,
    //                 TxStatus::Replaced { .. } => acc.4 += 1,
    //             }
    //             acc
    //         });

    //     let state = self.chain_state.read().await;

    //     MonitoringMetrics {
    //         total_monitored: txs.len(),
    //         pending,
    //         confirmed,
    //         finalized,
    //         evicted,
    //         replaced,
    //         current_height: state.current_height,
    //         latest_block: state.current_tip,
    //     }
    // }
}
