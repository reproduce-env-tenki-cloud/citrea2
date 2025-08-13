//! L2 block synchronization for Citrea nodes
//!
//! This module contains functionality for synchronizing L2 blocks from the sequencer
//! and processing them to maintain the node's state.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::U64;
use anyhow::{bail, Context as _};
use backoff::backoff::Backoff;
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoff;
use borsh::BorshDeserialize;
use citrea_primitives::merkle::compute_tx_hashes;
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::CitreaRuntime;
use jsonrpsee::core::client::{Error as JsonrpseeError, SubscriptionClientT};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::ws_client::WsClientBuilder;
use reth_tasks::shutdown::GracefulShutdown;
use sov_db::ledger_db::SharedLedgerOps;
use sov_keys::default_signature::K256PublicKey;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{L2Block, StateDiff};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use tokio::select;
use tokio::sync::{broadcast, Mutex, Notify};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, instrument, warn};

use crate::backup::BackupManager;
use crate::cache::L1BlockCache;
use crate::utils::decode_sov_tx_and_update_short_header_proofs;
use crate::{InitParams, RollupPublicKeys};

/// Maximum number of L2BlockResponse ahead of next_expected_height to buffer from subscription
const SUBSCRIPTION_LOOKAHEAD_LIMIT: u64 = 100;

pub struct ProcessL2BlockResult {
    pub l2_height: u64,
    pub l2_block_hash: L2BlockHash,
    pub state_root: StorageRootHash,
    pub state_diff: StateDiff,
    pub process_duration: f64,
    pub block_size: usize,
}

enum SyncError {
    ResponseOverLimit,
    Call(String),
    Connection(String),
    Unknown(String),
}

struct SequentialL2BlockBuffer {
    blocks: BTreeMap<u64, L2BlockResponse>,
    next_expected_height: u64,
    notify: Arc<Notify>,
}

impl SequentialL2BlockBuffer {
    fn new(start_height: u64) -> Self {
        Self {
            blocks: BTreeMap::new(),
            next_expected_height: start_height,
            notify: Arc::new(Notify::new()),
        }
    }

    fn add_block(&mut self, block: L2BlockResponse) {
        let height = block.header.height.to();

        if height < self.next_expected_height
            || self.blocks.contains_key(&height)
            // Don't store subscription too far off the current expected block
            // This would happen on startup when catching up to tip
            || height - self.next_expected_height > SUBSCRIPTION_LOOKAHEAD_LIMIT
        {
            return;
        }

        self.blocks.insert(height, block);
        self.notify.notify_one();
    }

    fn extend_blocks(&mut self, blocks: BTreeMap<u64, L2BlockResponse>) {
        let mut should_notify = false;

        for (height, block) in blocks {
            if height >= self.next_expected_height && !self.blocks.contains_key(&height) {
                self.blocks.insert(height, block);
                should_notify = true;
            }
        }

        if should_notify {
            self.notify.notify_one();
        }
    }

    /// Drain from next_expected_height until the first gap or until the buffer is fully consumed
    /// Returns an ordered vector of `L2BlockResponse`
    fn drain_sequential(&mut self) -> Vec<L2BlockResponse> {
        let mut sequential_blocks = Vec::new();

        while let Some(block) = self.blocks.remove(&self.next_expected_height) {
            self.next_expected_height += 1;
            sequential_blocks.push(block);
        }

        sequential_blocks
    }

    fn notifier(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn process_l2_block<Da: DaService, DB: SharedLedgerOps>(
    l2_block_response: &L2BlockResponse,
    storage_manager: &ProverStorageManager,
    fork_manager: &mut ForkManager<'_>,
    da_service: Arc<Da>,
    ledger_db: &DB,
    stf: &mut StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    current_l2_block_hash: L2BlockHash,
    current_state_root: StorageRootHash,
    sequencer_pub_key: &K256PublicKey,
    include_tx_body: bool,
) -> anyhow::Result<ProcessL2BlockResult> {
    let start = Instant::now();

    let l2_height = l2_block_response.header.height.to();

    info!(
        "Running l2 block batch #{} with hash: 0x{}",
        l2_height,
        hex::encode(l2_block_response.header.hash),
    );

    if current_l2_block_hash != l2_block_response.header.prev_hash {
        bail!("Previous hash mismatch at height: {}", l2_height);
    }

    let pre_state = storage_manager.create_storage_for_next_l2_height();
    assert_eq!(
        pre_state.version(),
        l2_height,
        "Prover storage version is corrupted"
    );
    let tx_bodies = Some(
        l2_block_response
            .txs
            .clone()
            .into_iter()
            .map(|tx| tx.tx)
            .collect::<Vec<_>>(),
    );

    // Register this new block with the fork manager to active
    // the new fork on the next block.
    fork_manager.register_block(l2_height)?;
    let current_spec = fork_manager.active_fork().spec_id;

    let l2_block: L2Block = l2_block_response
        .clone()
        .try_into()
        .context("Failed to parse transactions")?;

    let block_size = l2_block.calculate_size();

    let l2_block_result = {
        // Post tangerine, we do not have the slot hash in l2 blocks we inspect the txs and get the slot hashes from set block infos
        // Then store the short header proofs of those blocks in the ledger db

        decode_sov_tx_and_update_short_header_proofs(l2_block_response, ledger_db, da_service)
            .await?;

        stf.apply_l2_block(
            current_spec,
            sequencer_pub_key,
            &current_state_root,
            pre_state,
            None,
            None,
            Default::default(),
            Default::default(),
            &l2_block,
        )?
    };

    let next_state_root = l2_block_result.state_root_transition.final_root;
    // Check if post state root is the same as the one in the l2 block
    if next_state_root.as_ref().to_vec() != l2_block.state_root() {
        bail!("Post state root mismatch at height: {}", l2_height)
    }

    storage_manager.finalize_storage(l2_block_result.change_set);

    let tx_hashes = compute_tx_hashes(&l2_block.txs, current_spec);
    let tx_bodies = if include_tx_body { tx_bodies } else { None };

    ledger_db.commit_l2_block(l2_block, tx_hashes, tx_bodies)?;

    info!(
        "New State Root after l2 block #{} is: 0x{}",
        l2_height,
        hex::encode(next_state_root)
    );

    let duration = Instant::now()
        .saturating_duration_since(start)
        .as_secs_f64();

    Ok(ProcessL2BlockResult {
        l2_height,
        l2_block_hash: l2_block_response.header.hash,
        state_root: next_state_root,
        state_diff: l2_block_result.state_diff,
        process_duration: duration,
        block_size,
    })
}

async fn sync_l2(
    mut start_l2_height: u64,
    sequencer_client: HttpClient,
    block_buffer: Arc<Mutex<SequentialL2BlockBuffer>>,
    sync_blocks_count: u64,
) {
    let mut current_sync_blocks_count = sync_blocks_count;

    info!("Starting to sync from L2 height {}", start_l2_height);
    loop {
        // Make sure we don't poll for blocks that have already been processed
        let next_expected_height = block_buffer.lock().await.next_expected_height;
        if next_expected_height > start_l2_height {
            start_l2_height = next_expected_height
        }

        let end_l2_height = start_l2_height + current_sync_blocks_count - 1;

        let inner_client = &sequencer_client;
        let l2_blocks = match get_l2_blocks_range(inner_client, start_l2_height, end_l2_height)
            .await
        {
            Ok(l2_blocks) => {
                // request has succeeded, try to increase sync blocks back up until original
                current_sync_blocks_count *= 2;
                if current_sync_blocks_count > sync_blocks_count {
                    current_sync_blocks_count = sync_blocks_count;
                }
                l2_blocks
            }
            Err(e) => match e {
                SyncError::ResponseOverLimit => {
                    debug!("Sync response size over limit, retrying...");
                    current_sync_blocks_count /= 2;
                    if current_sync_blocks_count == 1 {
                        warn!("Very slow sync at 1 block/s");
                    } else if current_sync_blocks_count == 0 {
                        error!("L2 blocks are getting too big. It is recommended to increase response size");
                        // Stop the sync since we cannot fetch new soft confirmations.
                        return;
                    }
                    continue;
                }
                SyncError::Connection(e) => {
                    error!("L2 sync: RPC connection error: {:?}", e);
                    continue;
                }
                SyncError::Call(e) => {
                    error!("L2 sync: RPC call error: {:?}", e);
                    continue;
                }
                SyncError::Unknown(e) => {
                    error!("L2 sync: RPC unknown error: {:?}", e);
                    continue;
                }
            },
        };

        if l2_blocks.is_empty() {
            debug!(
                "L2 block: no batch at starting height {}, retrying...",
                start_l2_height
            );

            sleep(Duration::from_secs(1)).await;
            continue;
        }

        start_l2_height += l2_blocks.len() as u64;

        block_buffer.lock().await.extend_blocks(l2_blocks);
    }
}

async fn get_l2_blocks_range(
    sequencer_client: &HttpClient,
    start_l2_height: u64,
    end_l2_height: u64,
) -> Result<BTreeMap<u64, L2BlockResponse>, SyncError> {
    let inner_client = &sequencer_client;

    let exponential_backoff = ExponentialBackoffBuilder::<backoff::SystemClock>::new()
        .with_initial_interval(Duration::from_secs(1))
        .with_max_elapsed_time(Some(Duration::from_secs(15 * 60)))
        .with_multiplier(1.5)
        .build();

    retry_backoff(exponential_backoff, || async move {
        let l2_blocks = inner_client
            .get_l2_block_range(U64::from(start_l2_height), U64::from(end_l2_height))
            .await;
        match l2_blocks {
            Ok(l2_blocks) => Ok(l2_blocks
                .into_iter()
                .flatten()
                .map(|block| (block.header.height.to(), block))
                .collect::<BTreeMap<u64, _>>()),
            Err(e) => match e {
                JsonrpseeError::Call(e) => {
                    if e.message().eq("Response is too big") {
                        return Err(backoff::Error::Permanent(SyncError::ResponseOverLimit));
                    }
                    let error_msg = format!("L2 block: call error during RPC call: {:?}", e);
                    error!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Call(error_msg),
                        retry_after: None,
                    })
                }
                JsonrpseeError::Transport(e) => {
                    let error_msg = format!("L2 block: connection error during RPC call: {:?}", e);
                    error!(error_msg);
                    Err(backoff::Error::Transient {
                        err: SyncError::Connection(error_msg),
                        retry_after: None,
                    })
                }
                _ => Err(backoff::Error::Transient {
                    err: SyncError::Unknown(format!(
                        "L2 block: unknown error from RPC call: {:?}",
                        e
                    )),
                    retry_after: None,
                }),
            },
        }
    })
    .await
}

pub trait L2BlockProcessor<DB> {
    ///// Process the result of an L2 block
    ///
    /// # Arguments
    /// * `result` - The processed l2 block result
    /// * `db` - Database handle for storage
    fn process_result(result: &ProcessL2BlockResult, db: &DB) -> anyhow::Result<()>;
    /// Record metrics for the processed block
    fn record_metrics(result: &ProcessL2BlockResult);
}

/// Component responsible for synchronizing and processing L2 blocks
///
/// The L2Syncer maintains the state of the L2 chain by:
/// - Fetching new blocks from the sequencer
/// - Validating block signatures and contents
/// - Processing blocks to update the local state
/// - Managing forks and state transitions
pub struct L2Syncer<DA, DB, P>
where
    DA: DaService,
    DB: SharedLedgerOps + Clone + Send + Sync + 'static,
    P: L2BlockProcessor<DB>,
{
    /// Starting height for L2 block synchronization
    start_l2_height: u64,
    /// Data availability service instance
    da_service: Arc<DA>,
    /// State transition function blueprint
    stf: StfBlueprint<DefaultContext, DA::Spec, CitreaRuntime<DefaultContext, DA::Spec>>,
    /// Manager for prover storage
    storage_manager: ProverStorageManager,
    /// Database for ledger operations
    ledger_db: DB,
    /// Current state root hash
    state_root: StorageRootHash,
    /// Current L2 block hash
    l2_block_hash: L2BlockHash,
    /// HTTP client for connecting to the sequencer
    sequencer_client: HttpClient,
    /// sequencer websocket endpoint
    sequencer_ws_endpoint: Option<String>,
    /// Sequencer's public key for signature verification
    sequencer_pub_key: K256PublicKey,
    /// Whether to include transaction bodies in block storage
    include_tx_body: bool,
    /// Cache for L1 block data
    _l1_block_cache: Arc<Mutex<L1BlockCache<DA>>>,
    /// Number of blocks to sync at a time
    sync_blocks_count: u64,
    /// Manager for handling chain forks
    fork_manager: ForkManager<'static>,
    /// Channel for L2 block notifications
    l2_block_tx: broadcast::Sender<u64>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
    /// L2 block queue
    block_queue: Arc<Mutex<SequentialL2BlockBuffer>>,
    /// L2 Block processor
    _phantom_processor: PhantomData<P>,
}

impl<DA, DB, P> L2Syncer<DA, DB, P>
where
    DA: DaService,
    DB: SharedLedgerOps + Clone + Send + Sync + 'static,
    P: L2BlockProcessor<DB>,
{
    /// Creates a new L2Syncer instance
    ///
    /// # Arguments
    /// * `runner_config` - Configuration for the syncer
    /// * `init_params` - Initial parameters including previous state root and block hash
    /// * `stf` - State transition function blueprint
    /// * `public_keys` - Public keys for cryptographic operations
    /// * `da_service` - Data availability service
    /// * `ledger_db` - Database for ledger operations
    /// * `storage_manager` - Manager for prover storage
    /// * `fork_manager` - Manager for handling chain forks
    /// * `l2_block_tx` - Channel for L2 block notifications
    /// * `backup_manager` - Manager for backup operations
    /// * `include_tx_body` - Whether to include transaction bodies in block processing
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequencer_client_url: String,
        sync_blocks_count: u64,
        init_params: InitParams,
        stf: StfBlueprint<DefaultContext, DA::Spec, CitreaRuntime<DefaultContext, DA::Spec>>,
        public_keys: RollupPublicKeys,
        da_service: Arc<DA>,
        ledger_db: DB,
        storage_manager: ProverStorageManager,
        fork_manager: ForkManager<'static>,
        l2_block_tx: broadcast::Sender<u64>,
        backup_manager: Arc<BackupManager>,
        include_tx_body: bool,
        with_subscription: bool,
    ) -> Result<Self, anyhow::Error> {
        let start_l2_height = ledger_db.get_head_l2_block_height()?.unwrap_or(0) + 1;

        info!("Starting L2 height: {}", start_l2_height);

        Ok(Self {
            start_l2_height,
            da_service,
            stf,
            storage_manager,
            ledger_db,
            state_root: init_params.prev_state_root,
            l2_block_hash: init_params.prev_l2_block_hash,
            sequencer_ws_endpoint: with_subscription
                .then(|| sequencer_client_url.replace("http://", "ws://")),
            sequencer_client: HttpClientBuilder::default().build(sequencer_client_url)?,
            sequencer_pub_key: K256PublicKey::try_from_slice(&public_keys.sequencer_public_key)?,
            include_tx_body,
            sync_blocks_count,
            _l1_block_cache: Arc::new(Mutex::new(L1BlockCache::new())),
            fork_manager,
            l2_block_tx,
            backup_manager,
            block_queue: Arc::new(Mutex::new(SequentialL2BlockBuffer::new(start_l2_height))),
            _phantom_processor: PhantomData,
        })
    }

    /// Runs the L2Syncer until shutdown is signaled
    ///
    /// This method continuously:
    /// 1. Fetches new L2 blocks from the sequencer
    /// 2. Processes each block to update the local state
    /// 3. Handles any errors with exponential backoff
    /// 4. Maintains metrics about syncing progress
    #[instrument(name = "L2Syncer", skip_all)]
    pub async fn run(mut self, mut shutdown_signal: GracefulShutdown) {
        tokio::spawn(sync_l2(
            self.start_l2_height,
            self.sequencer_client.clone(),
            self.block_queue.clone(),
            self.sync_blocks_count,
        ));

        if let Some(ws_endpoint) = self.sequencer_ws_endpoint.clone() {
            tokio::spawn(run_subscription_task(ws_endpoint, self.block_queue.clone()));
        }

        let backup_manager = self.backup_manager.clone();

        let notifier = self.block_queue.lock().await.notifier();
        loop {
            select! {
                biased;
                _ = &mut shutdown_signal => {
                    info!("Shutting down L2 syncer");
                    return;
                },
                _ = notifier.notified() => {
                    let blocks_to_process = {
                        let mut queue = self.block_queue.lock().await;
                        queue.drain_sequential()
                    };

                    for l2_block in blocks_to_process {
                        let mut backoff = ExponentialBackoff::default();
                        loop {
                            let _l2_lock = backup_manager.start_l2_processing().await;
                            match self.process_l2_block(&l2_block).await {
                                Ok(_) => break,
                                Err(e) => {
                                    error!("Failed to process L2 block {}: {}", l2_block.header.height, e);
                                    let backoff_duration = backoff.next_backoff().expect("Failed to process L2 block multiple times. Killing L2Syncer...");
                                    tokio::time::sleep(backoff_duration).await;
                                }
                            }
                        }
                    }
                },
            }
        }
    }

    /// Processes a single L2 block
    ///
    /// # Arguments
    /// * `l2_block_response` - Block data from the sequencer
    ///
    /// # Returns
    /// Success if the block was processed and state was updated, error otherwise
    async fn process_l2_block(
        &mut self,
        l2_block_response: &L2BlockResponse,
    ) -> anyhow::Result<()> {
        let l2_block_result = process_l2_block(
            l2_block_response,
            &self.storage_manager,
            &mut self.fork_manager,
            self.da_service.clone(),
            &self.ledger_db,
            &mut self.stf,
            self.l2_block_hash,
            self.state_root,
            &self.sequencer_pub_key,
            self.include_tx_body,
        )
        .await?;

        self.state_root = l2_block_result.state_root;
        self.l2_block_hash = l2_block_result.l2_block_hash;

        P::process_result(&l2_block_result, &self.ledger_db)?;
        P::record_metrics(&l2_block_result);

        // Only errors when there are no receivers
        let _ = self.l2_block_tx.send(l2_block_result.l2_height);

        Ok(())
    }
}

async fn subscribe_to_new_l2_blocks(
    sequencer_ws_url: &str,
    block_buffer: Arc<Mutex<SequentialL2BlockBuffer>>,
) -> anyhow::Result<()> {
    debug!(
        "Connecting to sequencer subscription at {}",
        sequencer_ws_url
    );

    let ws_client = WsClientBuilder::default().build(&sequencer_ws_url).await?;
    let mut subscription = ws_client
        .subscribe(
            "citrea_subscribe",
            rpc_params!["newL2Blocks"],
            "citrea_unsubscribe",
        )
        .await?;

    while let Some(notification) = subscription.next().await {
        match notification {
            Ok(block) => {
                block_buffer.lock().await.add_block(block);
            }
            Err(e) => {
                error!("Subscription notification error: {}", e);
                return Err(e.into());
            }
        }
    }

    Ok(())
}

async fn run_subscription_task(
    sequencer_ws_url: String,
    block_buffer: Arc<Mutex<SequentialL2BlockBuffer>>,
) {
    loop {
        let exponential_backoff = ExponentialBackoff::default();
        let _ = retry_backoff(exponential_backoff, || async {
            subscribe_to_new_l2_blocks(&sequencer_ws_url, block_buffer.clone())
                .await
                .map_err(|e| {
                    error!("Subscription error: {}", e);
                    backoff::Error::Transient {
                        err: e,
                        retry_after: None,
                    }
                })
        })
        .await;
    }
}
