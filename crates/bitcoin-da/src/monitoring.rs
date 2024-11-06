use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script;
use bitcoin::transaction::Version;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{debug, error, info, instrument};

use bitcoin::{Amount, BlockHash, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoincore_rpc::json::GetTransactionResult;
use bitcoincore_rpc::{Client, RpcApi};
use thiserror::Error;

use crate::service::FINALITY_DEPTH;

const DEFAULT_CHECK_INTERVAL: u64 = 60;
const DEFAULT_HISTORY_LIMIT: usize = 1_000; // Keep track of last 1k txs

type BlockHeight = u64;
type Result<T> = std::result::Result<T, MonitorError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TxStatus {
    Pending {
        in_mempool: bool,
        base_fee: u64,
        timestamp: u64,
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
    pub initial_broadcast: u64,
    pub initial_height: BlockHeight,
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
    #[error("Empty tx monitoring chain")]
    EmptyChain,
    #[error("Unexpected TX status {0:?}")]
    WrongStatus(TxStatus),
    #[error("Insufficient funds to cover fee bump")]
    InsufficientFunds,
    #[error("Tx not accepted in mempool : {0}")]
    MempoolRejection(String),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub check_interval: u64,
    pub history_limit: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            history_limit: DEFAULT_HISTORY_LIMIT,
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
    pub async fn new(client: Arc<Client>, config: MonitoringConfig) -> Result<Self> {
        let current_height = client.get_block_count().await?;
        let current_tip = client.get_best_block_hash().await?;

        let mut recent_blocks = Vec::with_capacity(FINALITY_DEPTH as usize);
        let mut current_hash: BlockHash;

        for height in (0..FINALITY_DEPTH).map(|i| current_height.saturating_sub(i)) {
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
            let mut interval = interval(Duration::from_secs(self.config.check_interval));
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

        let current_height = self.client.get_block_count().await?;
        let tx_result = self.client.get_transaction(&txid, None).await?;
        let tx = tx_result.transaction()?;

        let status = self.determine_tx_status(&tx_result).await?;
        let monitored_tx = MonitoredTx {
            tx,
            initial_broadcast: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            initial_height: current_height,
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

            for i in 1..=FINALITY_DEPTH {
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
            match self.client.get_mempool_entry(&tx_result.info.txid).await {
                Ok(entry) => {
                    let base_fee = entry.fees.base.to_sat();
                    TxStatus::Pending {
                        in_mempool: true,
                        base_fee,
                        timestamp: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs(),
                    }
                }
                Err(_) => TxStatus::Evicted,
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

    pub async fn get_tx_status(&self, txid: &Txid) -> Option<TxStatus> {
        self.monitored_txs
            .read()
            .await
            .get(txid)
            .map(|tx| tx.status.clone())
    }

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

    pub async fn get_pending_transactions(&self) -> Vec<(Txid, MonitoredTx)> {
        self.monitored_txs
            .read()
            .await
            .iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::Pending { .. }))
            .map(|(txid, tx)| (*txid, tx.clone()))
            .collect()
    }

    pub async fn get_last_tx(&self) -> Option<(Txid, MonitoredTx)> {
        let last_txid = (*self.last_tx.lock().await)?;
        let tx = self.monitored_txs.read().await.get(&last_txid)?.to_owned();
        Some((last_txid, tx))
    }

    /// Bump TX fee via cpfp.
    /// If txid is None, resolves to the latest TX in chain
    pub async fn bump_fee_cpfp(&self, txid: Option<Txid>, fee_rate: f64) -> Result<Txid> {
        // Look for passed tx or resolve to last_tx monitored
        let parent_txid = match txid {
            None => self.last_tx.lock().await.ok_or(MonitorError::EmptyChain)?,
            Some(txid) => txid,
        };

        let monitored_tx = self
            .monitored_txs
            .read()
            .await
            .get(&parent_txid)
            .cloned()
            .ok_or(MonitorError::TxNotFound)?;

        let TxStatus::Pending {
            base_fee: parent_fee,
            ..
        } = monitored_tx.status
        else {
            return Err(MonitorError::WrongStatus(monitored_tx.status.to_owned()));
        };
        debug!("Creating cpfp TX for {parent_txid}");

        let parent_tx = &monitored_tx.tx;
        let output_index = 0;
        let output_value = parent_tx.output[output_index].value;

        let create_tx_input = |outpoint: OutPoint| TxIn {
            previous_output: outpoint,
            script_sig: script::Builder::new().into_script(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        };

        let mut child_tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![create_tx_input(OutPoint {
                txid: parent_txid,
                vout: output_index as u32,
            })],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: parent_tx.output[output_index].script_pubkey.clone(),
            }],
        };

        let parent_vsize = parent_tx.vsize() as f64;
        let child_vsize = child_tx.vsize() as f64;
        let total_vsize = parent_vsize + child_vsize;

        let total_required_fee = (fee_rate as f64 * total_vsize).ceil() as u64;

        let child_required_fee = total_required_fee.saturating_sub(parent_fee);
        let required_fee = Amount::from_sat(child_required_fee);

        let mut total_input = output_value;
        if total_input <= required_fee {
            // If first input value is not enough, use parent tx remaning outputs
            // else take any available utxo
            for (idx, utxo) in parent_tx.output.iter().enumerate().skip(1) {
                if total_input > required_fee {
                    break;
                }
                child_tx.input.push(create_tx_input(OutPoint {
                    txid: parent_txid,
                    vout: idx as u32,
                }));
                total_input += utxo.value;
            }

            let unspent = self
                .client
                .list_unspent(None, None, None, None, None)
                .await?;

            for utxo in unspent {
                if total_input > required_fee {
                    break;
                }

                child_tx.input.push(create_tx_input(OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                }));

                total_input += utxo.amount;
            }

            if total_input <= required_fee {
                return Err(MonitorError::InsufficientFunds);
            }
        }

        child_tx.output[0].value = total_input - required_fee;

        let signed_tx = self
            .client
            .sign_raw_transaction_with_wallet(&child_tx, None, None)
            .await?;

        if let Err(e) = self.client.test_mempool_accept(&[&signed_tx.hex]).await {
            return Err(MonitorError::MempoolRejection(e.to_string()));
        }

        let child_txid = self.client.send_raw_transaction(&signed_tx.hex).await?;

        self.monitor_transaction(child_txid, Some(parent_txid), None)
            .await?;

        let mut monitored_txs = self.monitored_txs.write().await;
        if let Some(parent) = monitored_txs.get_mut(&parent_txid) {
            parent.next_tx = Some(child_txid);
        }

        Ok(child_txid)
    }
}
