use std::sync::Arc;

use alloy_rpc_types::{Block, BlockNumHash, BlockNumberOrTag, Filter, FilteredParams, Log};
use alloy_serde::WithOtherFields;
use citrea_evm::Evm;
use futures::future;
use jsonrpsee::{SubscriptionMessage, SubscriptionSink};
use reth_rpc_eth_types::logs_utils::log_matches_filter;
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::WorkingSet;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::task::JoinHandle;

pub(crate) struct SubscriptionManager {
    l2_block_handle: JoinHandle<()>,
    logs_notifier_handle: JoinHandle<()>,
    heads_notifier_handle: JoinHandle<()>,
    head_subscriptions: Arc<RwLock<Vec<SubscriptionSink>>>,
    logs_subscriptions: Arc<RwLock<Vec<(Filter, SubscriptionSink)>>>,
}

impl SubscriptionManager {
    pub(crate) fn new<C: sov_modules_api::Context>(
        storage: C::Storage,
        ledger_db: LedgerDB,
        l2_block_rx: broadcast::Receiver<u64>,
    ) -> Self {
        let (new_heads_tx, new_heads_rx) = mpsc::channel(16);
        let (logs_tx, logs_rx) = mpsc::channel(16);

        let head_subscriptions = Arc::new(RwLock::new(vec![]));
        let logs_subscriptions = Arc::new(RwLock::new(vec![]));

        let l2_block_rx = l2_block_rx;
        // Spawn the task that will listen for new l2 block heights
        // and send the corresponding ethereum block to subscribers
        let l2_block_handle = tokio::spawn(l2_block_event_handler::<C>(
            storage,
            ledger_db,
            l2_block_rx,
            new_heads_tx.clone(),
            logs_tx.clone(),
        ));

        let logs_notifier_handle = tokio::spawn(logs_notifier(logs_rx, logs_subscriptions.clone()));
        let heads_notifier_handle =
            tokio::spawn(new_heads_notifier(new_heads_rx, head_subscriptions.clone()));

        Self {
            l2_block_handle,
            logs_notifier_handle,
            heads_notifier_handle,
            head_subscriptions,
            logs_subscriptions,
        }
    }

    pub async fn register_new_heads_subscription(&self, subscription: SubscriptionSink) {
        let mut head_subscriptions = self.head_subscriptions.write().await;
        head_subscriptions.retain(|s| !s.is_closed());
        head_subscriptions.push(subscription);
    }

    pub async fn register_new_logs_subscription(
        &self,
        filter: Filter,
        subscription: SubscriptionSink,
    ) {
        let mut logs_subscriptions = self.logs_subscriptions.write().await;
        logs_subscriptions.retain(|(_, s)| !s.is_closed());
        logs_subscriptions.push((filter, subscription));
    }
}

impl Drop for SubscriptionManager {
    fn drop(&mut self) {
        self.l2_block_handle.abort();
        self.logs_notifier_handle.abort();
        self.heads_notifier_handle.abort();
    }
}

pub async fn new_heads_notifier(
    mut rx: mpsc::Receiver<WithOtherFields<Block>>,
    head_subscriptions: Arc<RwLock<Vec<SubscriptionSink>>>,
) {
    while let Some(block) = rx.recv().await {
        // Acquire the read lock here to prevent starving the writes.
        let subscriptions = head_subscriptions.read().await;
        let mut send_tasks = vec![];
        for subscription in subscriptions.iter() {
            let msg = SubscriptionMessage::new(
                subscription.method_name(),
                subscription.subscription_id(),
                &block,
            )
            .unwrap();
            send_tasks.push(subscription.send(msg));
        }
        let _ = future::join_all(send_tasks).await;
        // Drop lock to release the read lock.
        drop(subscriptions);
    }
}

pub async fn logs_notifier(
    mut rx: mpsc::Receiver<Vec<Log>>,
    logs_subscriptions: Arc<RwLock<Vec<(Filter, SubscriptionSink)>>>,
) {
    while let Some(logs) = rx.recv().await {
        // Acquire the read lock here to prevent starving the writes.
        let subscriptions = logs_subscriptions.read().await;
        let mut send_tasks = vec![];
        for log in logs {
            for (filter, subscription) in subscriptions.iter() {
                let num_hash = BlockNumHash::new(
                    *log.block_number.as_ref().unwrap(),
                    *log.block_hash.as_ref().unwrap(),
                );

                if log_matches_filter(
                    num_hash,
                    &log.inner,
                    &FilteredParams::new(Some(filter.clone())),
                ) {
                    let msg = SubscriptionMessage::new(
                        subscription.method_name(),
                        subscription.subscription_id(),
                        &log,
                    )
                    .unwrap();
                    send_tasks.push(subscription.send(msg));
                }
            }
        }
        let _ = future::join_all(send_tasks).await;
        // Drop lock to release the read lock.
        drop(subscriptions);
    }
}

pub async fn l2_block_event_handler<C: sov_modules_api::Context>(
    storage: C::Storage,
    ledger_db: LedgerDB,
    mut l2_block_rx: broadcast::Receiver<u64>,
    new_heads_tx: mpsc::Sender<WithOtherFields<Block>>,
    logs_tx: mpsc::Sender<Vec<Log>>,
) {
    let evm = Evm::<C>::default();
    while let Ok(height) = l2_block_rx.recv().await {
        let mut working_set = WorkingSet::new(storage.clone());
        let block = evm
            .get_block_by_number(
                Some(BlockNumberOrTag::Number(height)),
                None,
                &mut working_set,
                &ledger_db,
            )
            .expect("Error querying block from evm")
            .expect("Received signal but evm block is not found");

        // Only possible error is no receiver
        let _ = new_heads_tx.send(block.clone()).await;

        let mut working_set = WorkingSet::new(storage.clone());
        let logs = evm
            .get_logs_in_block_range(&mut working_set, &Filter::default(), height, height)
            .expect("Error getting logs in block range");

        // Only possible error is no receiver
        let _ = logs_tx.send(logs).await;
    }
}
