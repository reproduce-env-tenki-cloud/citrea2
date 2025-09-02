#![warn(clippy::missing_docs_in_private_items)]
//! # Citrea Sequencer
//!
//! The sequencer is a critical component of the Citrea rollup system that manages transaction ordering,
//! block production, and data availability. It serves as the primary coordinator for the rollup's
//! transaction processing pipeline.
//!
//! ## Core Responsibilities
//!
//! * **Transaction Management**: Maintains a mempool for pending transactions and deposit data,
//!   ensuring efficient transaction processing and ordering.
//!
//! * **Block Production**: Drives the state transition function to create new L2 blocks, processing
//!   transactions and updating the rollup state.
//!
//! * **Data Availability**: The sequencer groups L2 blocks (which contain the transactions) into
//!   sequencer commitments. These commitments are then published to the DA (Data Availability) layer,
//!   where they serve to finalize all L2 blocks included within the commitment. This mechanism
//!   ensures proper ordering and finalization of blocks in the rollup chain.
//!
//! * **Node Synchronization**: Provides necessary information and services for full nodes to
//!   synchronize with the current state of the rollup.
//!
//! ## Key Components
//!
//! * **Mempool**: Manages pending transactions and ensures efficient transaction processing.
//! * **RPC Interface**: Provides external communication endpoints for interaction with the sequencer.
//! * **State Management**: Handles state transitions and maintains the rollup's state integrity.
//! * **Database Operations**: Manages persistent storage for ledger and other critical data.
//! * **Fork Management**: Handles chain reorganizations and maintains chain consistency.
//!
//! The sequencer operates differently from full nodes by directly interacting with the State
//! Transition Function's inner workings, allowing it to preview transaction results before
//! finalizing L2 blocks.

use std::sync::Arc;

use anyhow::Result;
use citrea_common::backup::BackupManager;
pub use citrea_common::SequencerConfig;
use citrea_common::{InitParams, RollupPublicKeys};
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use db_provider::DbProvider;
use deposit_data_mempool::DepositDataMempool;
use jsonrpsee::RpcModule;
use mempool::CitreaMempool;
use parking_lot::Mutex;
use reth_provider::CanonStateNotification;
use reth_tasks::TaskExecutor;
pub use rpc::SequencerRpcClient;
pub use runner::{CitreaSequencer, MAX_MISSED_DA_BLOCKS_PER_L2_BLOCK};
use sov_db::ledger_db::LedgerDB;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::UnboundedReceiverStream;

/// Module containing commitment-related functionality
mod commitment;
/// Module containing DA (Data Availability) service functionality
mod da;
/// Provides access to DB migration definitions.
pub mod db_migrations;
/// Database provider implementation that abstracts over reth's mempool functionality,
/// providing a custom interface for the sequencer's needs
mod db_provider;
/// Separate mempool implementation only for handling deposit data in FIFO (First-In-First-Out) order
mod deposit_data_mempool;
/// Module containing mempool functionality for transaction management
mod mempool;
/// Module containing metrics collection and reporting functionality
mod metrics;
/// Provides access to sequencer RPC functionality
pub mod rpc;
/// Module implementing the main sequencer running logic
mod runner;
/// Module for declaring types used by the sequencer
mod types;
/// Module containing utility functions and helpers
mod utils;

/// Builds and initializes all sequencer services
///
/// # Arguments
/// * `sequencer_config` - Configuration for the sequencer
/// * `init_params` - Initial parameters for sequencer setup
/// * `native_stf` - State transition function blueprint
/// * `public_keys` - Rollup public keys for cryptographic operations
/// * `da_service` - Data availability service implementation
/// * `ledger_db` - Database for ledger operations
/// * `storage_manager` - Manager for prover storage
/// * `l2_block_tx` - Channel for L2 block notifications
/// * `fork_manager` - Manager for handling chain forks
/// * `rpc_module` - RPC module for external communication
/// * `backup_manager` - Manager for backup operations
/// * `task_executor` - Executor for async tasks
///
/// # Returns
/// A tuple containing the initialized sequencer and RPC module
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_services<Da>(
    sequencer_config: SequencerConfig,
    init_params: InitParams,
    native_stf: StfBlueprint<
        DefaultContext,
        <Da as DaService>::Spec,
        CitreaRuntime<DefaultContext, <Da as DaService>::Spec>,
    >,
    public_keys: RollupPublicKeys,
    da_service: Arc<Da>,
    ledger_db: LedgerDB,
    storage_manager: ProverStorageManager,
    l2_block_tx: broadcast::Sender<u64>,
    fork_manager: ForkManager<'static>,
    rpc_module: RpcModule<()>,
    backup_manager: Arc<BackupManager>,
    task_executor: TaskExecutor,
) -> Result<(CitreaSequencer<Da>, RpcModule<()>)>
where
    Da: DaService,
{
    let (rpc_message_tx, rpc_message_rx) = unbounded_channel();
    // used as client of reth's mempool
    let db_provider_storage = storage_manager.create_final_view_storage();
    let db_provider = DbProvider::new(db_provider_storage, ledger_db.clone());
    let mempool = Arc::new(CitreaMempool::new(
        db_provider.clone(),
        sequencer_config.mempool_conf.clone(),
        task_executor.clone(),
    )?);
    let deposit_mempool = Arc::new(Mutex::new(DepositDataMempool::new()));

    // Create the canonical state notification channel for mempool maintenance
    let (canon_state_tx, canon_state_rx) = mpsc::unbounded_channel::<CanonStateNotification>();

    // Spawn the mempool maintenance task
    {
        let pool = mempool.inner_pool().clone();
        let client = db_provider.clone();
        let events_stream = UnboundedReceiverStream::new(canon_state_rx);

        // Build MaintainPoolConfig from mempool config
        let mut maintain_config = reth_transaction_pool::maintain::MaintainPoolConfig::default();
        if let Some(max_update_depth) = sequencer_config.mempool_conf.max_update_depth {
            maintain_config.max_update_depth = max_update_depth;
        }
        if let Some(max_reload_accounts) = sequencer_config.mempool_conf.max_reload_accounts {
            maintain_config.max_reload_accounts = max_reload_accounts;
        }
        if let Some(max_tx_lifetime_secs) = sequencer_config.mempool_conf.max_tx_lifetime_secs {
            maintain_config.max_tx_lifetime = std::time::Duration::from_secs(max_tx_lifetime_secs);
        }
        // Note: no_local_exemptions field doesn't exist in reth v1.3.7

        let maintenance_future = reth_transaction_pool::maintain::maintain_transaction_pool_future(
            client,
            pool,
            events_stream,
            task_executor.clone(),
            maintain_config,
        );
        task_executor.spawn_critical("mempool-maintenance", maintenance_future);
    }

    let rpc_storage = storage_manager.create_final_view_storage();
    let rpc_context = rpc::create_rpc_context(
        mempool.clone(),
        deposit_mempool.clone(),
        rpc_message_tx,
        rpc_storage,
        ledger_db.clone(),
        sequencer_config.test_mode,
    );
    let rpc_module = rpc::register_rpc_methods(rpc_context, rpc_module)?;

    let seq = CitreaSequencer::new(
        da_service,
        sequencer_config,
        init_params,
        native_stf,
        storage_manager,
        public_keys,
        ledger_db,
        db_provider,
        mempool,
        deposit_mempool,
        fork_manager,
        l2_block_tx,
        backup_manager,
        rpc_message_rx,
        canon_state_tx,
    )
    .unwrap();

    Ok((seq, rpc_module))
}
