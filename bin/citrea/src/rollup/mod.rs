use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use citrea_batch_prover::CitreaBatchProver;
use citrea_common::tasks::manager::TaskManager;
use citrea_common::{BatchProverConfig, FullNodeConfig, LightClientProverConfig, SequencerConfig};
use citrea_fullnode::CitreaFullnode;
use citrea_light_client_prover::runner::CitreaLightClientProver;
use citrea_primitives::forks::get_forks;
use citrea_sequencer::CitreaSequencer;
use jsonrpsee::RpcModule;
use sov_db::ledger_db::migrations::LedgerDBMigrator;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::mmr_db::MmrDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::Spec;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_modules_stf_blueprint::{Runtime as RuntimeTrait, StfBlueprint};
use sov_rollup_interface::fork::ForkManager;
use sov_state::storage::NativeStorage;
use sov_stf_runner::InitVariant;
use tokio::sync::broadcast;
use tracing::{info, instrument};

mod bitcoin;
mod mock;
pub use bitcoin::*;
pub use mock::*;

/// Overrides RollupBlueprint methods
#[async_trait]
pub trait CitreaRollupBlueprint: RollupBlueprint {
    /// Creates a new sequencer
    #[instrument(level = "trace", skip_all)]
    async fn create_new_sequencer(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        sequencer_config: SequencerConfig,
    ) -> Result<
        (
            CitreaSequencer<Self::NativeContext, Self::DaService, LedgerDB, Self::NativeRuntime>,
            RpcModule<()>,
        ),
        anyhow::Error,
    >
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(&rollup_config, true, &mut task_manager)
            .await?;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(
            rollup_config.storage.path.as_path(),
            citrea_sequencer::db_migrations::migrations(),
        );

        let sequencer_tables = SEQUENCER_LEDGER_TABLES
            .iter()
            .map(|table| table.to_string())
            .collect::<Vec<_>>();

        migrator.migrate(
            rollup_config.storage.db_max_open_files,
            sequencer_tables.clone(),
        )?;

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
            Some(sequencer_tables),
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);
        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            None,
            soft_confirmation_rx,
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                info!("Initialize sequencer at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, prover_storage.get_root_hash(number.0 + 1)?.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize sequencer at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let seq = CitreaSequencer::new(
            da_service,
            prover_storage,
            sequencer_config,
            native_stf,
            storage_manager,
            init_variant,
            rollup_config.public_keys,
            ledger_db,
            rollup_config.rpc,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        )
        .unwrap();

        Ok((seq, rpc_methods))
    }

    /// Creates a new rollup.
    #[instrument(level = "trace", skip_all)]
    async fn create_new_rollup(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: FullNodeConfig<Self::DaConfig>,
    ) -> Result<
        (
            CitreaFullnode<
                Self::DaService,
                Self::Vm,
                Self::NativeContext,
                LedgerDB,
                Self::NativeRuntime,
            >,
            RpcModule<()>,
        ),
        anyhow::Error,
    >
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(&rollup_config, false, &mut task_manager)
            .await?;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(
            rollup_config.storage.path.as_path(),
            citrea_fullnode::db_migrations::migrations(),
        );

        let full_node_tables = FULL_NODE_LEDGER_TABLES
            .iter()
            .map(|table| table.to_string())
            .collect::<Vec<_>>();

        migrator.migrate(
            rollup_config.storage.db_max_open_files,
            full_node_tables.clone(),
        )?;

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
            Some(full_node_tables),
        );

        let ledger_db = self.create_ledger_db(&rocksdb_config);

        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;

        let prover_storage = storage_manager.create_finalized_storage()?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");
        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
            soft_confirmation_rx,
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let head_sc = ledger_db.get_head_soft_confirmation()?;

        let init_variant = match head_sc {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                let state_root = prover_storage.get_root_hash(number.0 + 1)?;
                info!("Initialize node at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, state_root.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize node at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };

        let code_commitments_by_spec = self.get_batch_proof_code_commitments();

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaFullnode::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            code_commitments_by_spec,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        )?;

        Ok((runner, rpc_methods))
    }

    /// Creates a new prover
    #[instrument(level = "trace", skip_all)]
    async fn create_new_batch_prover(
        &self,
        runtime_genesis_paths: &<Self::NativeRuntime as RuntimeTrait<
            Self::NativeContext,
            Self::DaSpec,
        >>::GenesisPaths,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        prover_config: BatchProverConfig,
    ) -> Result<
        (
            CitreaBatchProver<
                Self::NativeContext,
                Self::DaService,
                Self::Vm,
                Self::ProverService,
                LedgerDB,
                Self::NativeRuntime,
            >,
            RpcModule<()>,
        ),
        anyhow::Error,
    >
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(&rollup_config, true, &mut task_manager)
            .await?;

        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(
            rollup_config.storage.path.as_path(),
            citrea_batch_prover::db_migrations::migrations(),
        );

        let batch_prover_tables = BATCH_PROVER_LEDGER_TABLES
            .iter()
            .map(|table| table.to_string())
            .collect::<Vec<_>>();

        migrator.migrate(
            rollup_config.storage.db_max_open_files,
            batch_prover_tables.clone(),
        )?;

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
            Some(batch_prover_tables),
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);

        let prover_service = self
            .create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
            )
            .await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let genesis_config = self.create_genesis_config(runtime_genesis_paths, &rollup_config)?;

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let (soft_confirmation_tx, soft_confirmation_rx) = broadcast::channel(10);
        // If subscriptions disabled, pass None
        let soft_confirmation_rx = if rollup_config.rpc.enable_subscriptions {
            Some(soft_confirmation_rx)
        } else {
            None
        };
        let runner_config = rollup_config.runner.expect("Runner config is missing");
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
            soft_confirmation_rx,
        )?;

        let native_stf = StfBlueprint::new();

        let genesis_root = prover_storage.get_root_hash(1);

        let init_variant = match ledger_db.get_head_soft_confirmation()? {
            // At least one soft confirmation was processed
            Some((number, soft_confirmation)) => {
                info!("Initialize prover at batch number {:?}. State root: {:?}. Last soft confirmation hash: {:?}.", number, prover_storage.get_root_hash(number.0 + 1)?.as_ref(), soft_confirmation.hash);

                InitVariant::Initialized((
                    prover_storage.get_root_hash(number.0 + 1)?,
                    soft_confirmation.hash,
                ))
            }
            None => {
                info!("Initialize prover at genesis.");
                match genesis_root {
                    // Chain was initialized but no soft confirmations was processed
                    Ok(root_hash) => InitVariant::Initialized((root_hash, [0; 32])),
                    // Not even initialized
                    _ => InitVariant::Genesis(genesis_config),
                }
            }
        };

        let code_commitments_by_spec = self.get_batch_proof_code_commitments();
        let elfs_by_spec = self.get_batch_proof_elfs();

        let current_l2_height = ledger_db
            .get_head_soft_confirmation_height()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .unwrap_or(0);

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaBatchProver::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            native_stf,
            storage_manager,
            init_variant,
            Arc::new(prover_service),
            prover_config,
            code_commitments_by_spec,
            elfs_by_spec,
            fork_manager,
            soft_confirmation_tx,
            task_manager,
        )?;

        Ok((runner, rpc_methods))
    }

    /// Creates a new light client prover
    #[instrument(level = "trace", skip_all)]
    async fn create_new_light_client_prover(
        &self,
        rollup_config: FullNodeConfig<Self::DaConfig>,
        prover_config: LightClientProverConfig,
    ) -> Result<
        (
            CitreaLightClientProver<Self::DaService, Self::Vm, Self::ProverService, LedgerDB>,
            RpcModule<()>,
        ),
        anyhow::Error,
    >
    where
        <Self::NativeContext as Spec>::Storage: NativeStorage,
    {
        // Migrate before constructing ledger_db instance so that no lock is present.
        let migrator = LedgerDBMigrator::new(
            rollup_config.storage.path.as_path(),
            citrea_light_client_prover::db_migrations::migrations(),
        );

        let light_client_prover_tables = LIGHT_CLIENT_PROVER_LEDGER_TABLES
            .iter()
            .map(|table| table.to_string())
            .collect::<Vec<_>>();

        migrator.migrate(
            rollup_config.storage.db_max_open_files,
            light_client_prover_tables.clone(),
        )?;

        let mut task_manager = TaskManager::default();
        let da_service = self
            .create_da_service(&rollup_config, true, &mut task_manager)
            .await?;

        let rocksdb_config = RocksdbConfig::new(
            rollup_config.storage.path.as_path(),
            rollup_config.storage.db_max_open_files,
            Some(light_client_prover_tables),
        );
        let ledger_db = self.create_ledger_db(&rocksdb_config);
        let mmr_db = MmrDB::new(&rocksdb_config)?;

        let prover_service = self
            .create_prover_service(
                prover_config.proving_mode,
                &da_service,
                ledger_db.clone(),
                prover_config.proof_sampling_number,
            )
            .await;

        // TODO: Double check what kind of storage needed here.
        // Maybe whole "prev_root" can be initialized inside runner
        // Getting block here, so prover_service doesn't have to be `Send`

        let mut storage_manager = self.create_storage_manager(&rollup_config)?;
        let prover_storage = storage_manager.create_finalized_storage()?;

        let runner_config = rollup_config.runner.expect("Runner config is missing");
        // TODO(https://github.com/Sovereign-Labs/sovereign-sdk/issues/1218)
        let rpc_methods = self.create_rpc_methods(
            &prover_storage,
            &ledger_db,
            &da_service,
            Some(runner_config.sequencer_client_url.clone()),
            None,
        )?;

        let batch_prover_code_commitments_by_spec = self.get_batch_proof_code_commitments();
        let light_client_prover_code_commitment = self.get_light_client_proof_code_commitment();
        let light_client_prover_elfs = self.get_light_client_elfs();

        let current_l2_height = ledger_db
            .get_head_soft_confirmation()
            .map_err(|e| anyhow!("Failed to get head soft confirmation: {}", e))?
            .map(|(l2_height, _)| l2_height)
            .unwrap_or(SoftConfirmationNumber(0));

        let mut fork_manager = ForkManager::new(get_forks(), current_l2_height.0);
        fork_manager.register_handler(Box::new(ledger_db.clone()));

        let runner = CitreaLightClientProver::new(
            runner_config,
            rollup_config.public_keys,
            rollup_config.rpc,
            da_service,
            ledger_db,
            Arc::new(prover_service),
            prover_config,
            batch_prover_code_commitments_by_spec,
            light_client_prover_code_commitment,
            light_client_prover_elfs,
            mmr_db,
            task_manager,
        )?;

        Ok((runner, rpc_methods))
    }
}
