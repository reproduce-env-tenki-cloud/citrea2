use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxHash, U256};
use anyhow::{anyhow, bail};
use backoff::future::retry as retry_backoff;
use backoff::ExponentialBackoffBuilder;
use citrea_common::backup::BackupManager;
use citrea_common::{InitParams, RollupPublicKeys, SequencerConfig};
use citrea_evm::system_events::{create_system_transactions, SystemEvent};
use citrea_evm::{
    create_initial_system_events, get_last_l1_height_in_light_client,
    populate_deposit_system_events, populate_set_block_info_event, AccountInfo, CallMessage, Evm,
    RlpEvmTransaction, MIN_TRANSACTION_GAS, SYSTEM_SIGNER,
};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use citrea_primitives::forks::fork_from_block_number;
use citrea_primitives::merkle::{compute_tx_hashes, compute_tx_merkle_root};
use citrea_primitives::types::L2BlockHash;
use citrea_stf::runtime::{CitreaRuntime, DefaultContext};
use parking_lot::Mutex;
use reth_execution_types::ChangedAccount;
use reth_provider::{AccountReader, BlockReaderIdExt};
use reth_tasks::shutdown::GracefulShutdown;
use reth_transaction_pool::error::InvalidPoolTransactionError;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, EthPooledTransaction, PoolTransaction,
    ValidPoolTransaction,
};
use sov_accounts::Accounts;
use sov_accounts::Response::{AccountEmpty, AccountExists};
use sov_db::ledger_db::{LedgerDB, SequencerLedgerOps, SharedLedgerOps};
use sov_db::schema::types::L2BlockNumber;
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::{
    EncodeCall, L2Block, L2BlockModuleCallError, PrivateKey, SlotData, Spec, SpecId,
    StateValueAccessor, WorkingSet,
};
use sov_modules_stf_blueprint::StfBlueprint;
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::block::{L2Header, SignedL2Header};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::{L2BlockResult, StateTransitionError};
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::StorageRootHash;
use sov_state::storage::NativeStorage;
use sov_state::ProverStorage;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::{broadcast, mpsc};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::layer::SubscriberExt;

use crate::commitment::service::CommitmentService;
use crate::da::{da_block_monitor, get_da_block_data};
use crate::db_provider::DbProvider;
use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::metrics::SEQUENCER_METRICS as SM;
use crate::types::SequencerRpcMessage;
use crate::utils::recover_raw_transaction;

/// Maximum number of DA blocks that can be missed per L2 block
pub const MAX_MISSED_DA_BLOCKS_PER_L2_BLOCK: u64 = 10;

/// The main sequencer implementation that manages block production and transaction processing
///
/// This struct is responsible for:
/// - Managing the transaction mempool
/// - Producing L2 blocks
/// - Processing system transactions
/// - Handling DA layer synchronization
/// - Managing state transitions
pub struct CitreaSequencer<Da>
where
    Da: DaService,
{
    /// Data availability service instance
    da_service: Arc<Da>,
    /// Transaction mempool
    mempool: Arc<CitreaMempool>,
    /// Private key for signing transactions
    pub(crate) sov_tx_signer_priv_key: K256PrivateKey,
    /// Channel for receiving messages from RPC.
    rpc_message_rx: UnboundedReceiver<SequencerRpcMessage>,
    /// Database provider for blockchain data access
    db_provider: DbProvider,
    /// Database for ledger operations
    pub(crate) ledger_db: LedgerDB,
    /// Sequencer configuration
    pub(crate) config: SequencerConfig,
    /// State transition function blueprint
    pub(crate) stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
    /// Mempool for deposit transactions
    pub(crate) deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    /// Manager for prover storage
    pub(crate) storage_manager: ProverStorageManager,
    /// Current state root hash
    pub(crate) state_root: StorageRootHash,
    /// Current L2 block hash
    pub(crate) l2_block_hash: L2BlockHash,
    /// Sequencer's DA public key
    sequencer_da_pub_key: Vec<u8>,
    /// Manager for handling chain forks
    pub(crate) fork_manager: ForkManager<'static>,
    /// Channel for broadcasting L2 block updates
    l2_block_tx: broadcast::Sender<u64>,
    /// Manager for backup operations
    backup_manager: Arc<BackupManager>,
}

impl<Da> CitreaSequencer<Da>
where
    Da: DaService,
{
    /// Creates a new CitreaSequencer instance
    ///
    /// # Arguments
    /// * `da_service` - Data availability service
    /// * `config` - Sequencer configuration
    /// * `init_params` - Initial parameters for sequencer setup
    /// * `stf` - State transition function blueprint
    /// * `storage_manager` - Manager for prover storage
    /// * `public_keys` - Public keys for the rollup
    /// * `ledger_db` - Database for ledger operations
    /// * `db_provider` - Provider for database operations
    /// * `mempool` - Transaction mempool
    /// * `deposit_mempool` - Mempool for deposit transactions
    /// * `fork_manager` - Manager for handling chain forks
    /// * `l2_block_tx` - Channel for L2 block notifications
    /// * `backup_manager` - Manager for backup operations
    /// * `rpc_message_rx` - Channel for receiving messages from RPC
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        da_service: Arc<Da>,
        config: SequencerConfig,
        init_params: InitParams,
        stf: StfBlueprint<DefaultContext, Da::Spec, CitreaRuntime<DefaultContext, Da::Spec>>,
        storage_manager: ProverStorageManager,
        public_keys: RollupPublicKeys,
        ledger_db: LedgerDB,
        db_provider: DbProvider,
        mempool: Arc<CitreaMempool>,
        deposit_mempool: Arc<Mutex<DepositDataMempool>>,
        fork_manager: ForkManager<'static>,
        l2_block_tx: broadcast::Sender<u64>,
        backup_manager: Arc<BackupManager>,
        rpc_message_rx: UnboundedReceiver<SequencerRpcMessage>,
    ) -> anyhow::Result<Self> {
        let sov_tx_signer_priv_key =
            K256PrivateKey::try_from(hex::decode(&config.private_key)?.as_slice())?;

        Ok(Self {
            da_service,
            mempool,
            sov_tx_signer_priv_key,
            rpc_message_rx,
            db_provider,
            ledger_db,
            config,
            stf,
            deposit_mempool,
            storage_manager,
            state_root: init_params.prev_state_root,
            l2_block_hash: init_params.prev_l2_block_hash,
            sequencer_da_pub_key: public_keys.sequencer_da_pub_key,
            fork_manager,
            l2_block_tx,
            backup_manager,
        })
    }

    /// Performs a dry run of transactions to validate them before inclusion in a block
    ///
    /// # Arguments
    /// * `transactions` - Transactions to validate
    /// * `prestate` - Initial state for the dry run
    /// * `l2_block_info` - Block information for hooks
    /// * `deposit_data` - Deposit transaction data
    /// * `da_blocks` - Data availability blocks
    ///
    /// # Returns
    /// A tuple containing the validated transactions and their hashes
    #[allow(clippy::too_many_arguments)]
    async fn dry_run_transactions(
        &mut self,
        mut transactions: Box<
            dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>,
        >,
        prestate: ProverStorage,
        l2_block_info: HookL2BlockInfo,
        deposit_data: &[Vec<u8>],
        da_blocks: Vec<Da::FilteredBlock>,
    ) -> anyhow::Result<(Vec<RlpEvmTransaction>, Vec<TxHash>)> {
        let start = Instant::now();

        // Disable logging during dry run to avoid noise
        let silent_subscriber = tracing_subscriber::registry().with(LevelFilter::OFF);

        tracing::subscriber::with_default(silent_subscriber, || {
            let mut working_set_to_discard = WorkingSet::new(prestate.clone());

            let mut nonce = self.get_nonce(&mut working_set_to_discard)?;

            // Apply L2 block hook before processing transactions
            if let Err(err) = self
                .stf
                .begin_l2_block(&mut working_set_to_discard, &l2_block_info)
            {
                warn!(
                    "DryRun: Failed to apply l2 block hook: {:?} \n reverting batch workspace",
                    err
                );
                bail!("DryRun: Failed to apply begin l2 block hook: {:?}", err)
            }

            let evm = citrea_evm::Evm::<DefaultContext>::default();
            let start_dry_run_system_txs = Instant::now();
            // Initially fill with system transactions if any
            let (mut all_txs, mut working_set_to_discard) = self
                .produce_and_run_system_transactions(
                    &l2_block_info,
                    &evm,
                    working_set_to_discard,
                    deposit_data,
                    da_blocks,
                    &mut nonce,
                )?;
            SM.dry_run_system_txs_duration_secs.set(
                Instant::now()
                    .saturating_duration_since(start_dry_run_system_txs)
                    .as_secs_f64(),
            );

            // Track transactions that failed due to insufficient L1 fee balance
            let mut l1_fee_failed_txs = vec![];

            // using .next() instead of a for loop because its the intended
            // behaviour for the BestTransactions implementations
            // when we update reth we'll need to call transactions.mark_invalid()
            #[allow(clippy::while_let_on_iterator)]
            while let Some(evm_tx) = transactions.next() {
                let start_tx = Instant::now();
                let buf = evm_tx.to_consensus().into_inner().encoded_2718();
                let rlp_tx = RlpEvmTransaction { rlp: buf };
                let call_txs = CallMessage {
                    txs: vec![rlp_tx.clone()],
                };
                let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                    citrea_evm::Evm<DefaultContext>,
                >>::encode_call(call_txs);

                let signed_tx = self.sign_tx(l2_block_info.current_spec, raw_message, nonce)?;
                nonce += 1;

                let txs = vec![signed_tx];

                let mut working_set = working_set_to_discard.checkpoint().to_revertable();

                if let Err(e) = self
                    .stf
                    .apply_l2_block_txs(&l2_block_info, &txs, &mut working_set)
                {
                    // Decrement nonce if the transaction failed
                    nonce = nonce.saturating_sub(1);
                    match e {
                        // Since this is the sequencer, it should never get a soft confirmation error or a hook error
                        StateTransitionError::L2BlockError(l2_block_error) => {
                            panic!("L2 block error: {:?}", l2_block_error)
                        }
                        StateTransitionError::HookError(soft_confirmation_hook_error) => {
                            panic!("Hook error: {:?}", soft_confirmation_hook_error)
                        }
                        StateTransitionError::ModuleCallError(
                            soft_confirmation_module_call_error,
                        ) => match soft_confirmation_module_call_error {
                            L2BlockModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                                cumulative_gas,
                                tx_gas_used,
                                block_gas_limit,
                            } => {
                                if block_gas_limit - cumulative_gas < MIN_TRANSACTION_GAS {
                                    break;
                                } else {
                                    transactions.mark_invalid(
                                        &evm_tx,
                                        InvalidPoolTransactionError::ExceedsGasLimit(
                                            tx_gas_used,
                                            block_gas_limit - cumulative_gas,
                                        ),
                                    );
                                    working_set_to_discard = working_set.revert().to_revertable();
                                    continue;
                                }
                            }
                            L2BlockModuleCallError::EvmTxTypeNotSupported(_) => {
                                panic!("got unsupported tx type")
                            }
                            L2BlockModuleCallError::EvmTransactionExecutionError(_) => {
                                transactions.mark_invalid(
                                    &evm_tx,
                                    // don't really have a way to know the underlying EVM error due to
                                    // our APIs so passing a generic overdraft error
                                    // as it doesn't matter (the kind field is never used)
                                    InvalidPoolTransactionError::Overdraft {
                                        cost: U256::from(1),
                                        balance: U256::ZERO,
                                    },
                                );
                                working_set_to_discard = working_set.revert().to_revertable();
                                continue;
                            }
                            L2BlockModuleCallError::EvmMisplacedSystemTx => {
                                panic!("tried to execute system transaction")
                            }
                            L2BlockModuleCallError::EvmNotEnoughFundsForL1Fee => {
                                l1_fee_failed_txs.push(*evm_tx.hash());
                                transactions.mark_invalid(
                                    &evm_tx,
                                    // don't really have a way to know the cost right now
                                    // passing 1 & 0 as it doesn't matter (the kind field is never used)
                                    InvalidPoolTransactionError::Overdraft {
                                        cost: U256::from(1),
                                        balance: U256::ZERO,
                                    },
                                );
                                working_set_to_discard = working_set.revert().to_revertable();
                                continue;
                            }
                            L2BlockModuleCallError::EvmTxNotSerializable => {
                                panic!("Fed a non-serializable tx")
                            }
                            L2BlockModuleCallError::RuleEnforcerUnauthorized => unreachable!(),
                            L2BlockModuleCallError::ShortHeaderProofNotFound => unreachable!(),
                            L2BlockModuleCallError::ShortHeaderProofVerificationError => {
                                unreachable!()
                            }
                            L2BlockModuleCallError::EvmSystemTransactionPlacedAfterUserTx => {
                                panic!("System tx after user tx")
                            }
                            L2BlockModuleCallError::EvmSystemTxParseError => {
                                panic!("Sequencer produced incorrectly formatted system tx")
                            }
                            L2BlockModuleCallError::EvmSystemTransactionNotSuccessful => {
                                panic!("System tx failed")
                            }
                            L2BlockModuleCallError::ShortHeaderProofAllocationError(e) => {
                                panic!("Short header proof error: {:?}", e);
                            }
                        },
                    }
                };

                // if no errors
                // we can include the transaction in the block
                working_set_to_discard = working_set.checkpoint().to_revertable();
                all_txs.push(rlp_tx);
                SM.dry_run_single_tx_time.record(
                    Instant::now()
                        .saturating_duration_since(start_tx)
                        .as_secs_f64(),
                );
            }
            let dry_run_execution_duration = Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64();
            SM.dry_run_execution.record(dry_run_execution_duration);
            SM.dry_run_execution_gauge.set(dry_run_execution_duration);
            SM.l1_fee_failed_txs_count
                .set(l1_fee_failed_txs.len() as f64);

            Ok((all_txs, l1_fee_failed_txs))
        })
    }

    /// Saves proofs for short headers from DA blocks
    fn save_short_header_proofs(&self, da_blocks: Vec<Da::FilteredBlock>) {
        debug!("Saving short header proofs to ledger db");
        for da_block in da_blocks {
            let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
                Da::block_to_short_header_proof(da_block.clone());
            self.ledger_db
                .put_short_header_proof_by_l1_hash(
                    &da_block.hash(),
                    borsh::to_vec(&short_header_proof)
                        .expect("Should serialize short header proof"),
                )
                .expect("Should save short header proof to ledger db");
            info!(
                "Saved short header proof for block: {}",
                hex::encode(da_block.hash())
            );
        }
    }

    /// Produces a new L2 block with the given DA blocks
    ///
    /// # Arguments
    /// * `da_blocks` - Data availability blocks to process
    /// * `l1_fee_rate` - Current L1 fee rate
    /// * `last_used_l1_height` - Last processed L1 block height
    ///
    /// # Returns
    /// The height of the produced L2 block
    async fn produce_l2_block(
        &mut self,
        mut da_blocks: Vec<Da::FilteredBlock>,
        l1_fee_rate: u128,
        last_used_l1_height: &mut u64,
    ) -> anyhow::Result<u64> {
        let start: Instant = Instant::now();
        let l2_height = self.ledger_db.get_head_l2_block_height()?.unwrap_or(0) + 1;
        self.fork_manager.register_block(l2_height)?;
        let result = {
            if da_blocks.len() == 1 && da_blocks[0].header().height() == *last_used_l1_height {
                // If we are producing regular blocks, not for missed da blocks, and if the last used L1 block is the same as the last finalized block
                // then there is no need to pass da data to the sequencer
                da_blocks.clear();
            }
            self.produce_l2_block_inner(da_blocks, l1_fee_rate, l2_height, last_used_l1_height)
                .await
        };

        let block_production_time = Instant::now()
            .saturating_duration_since(start)
            .as_secs_f64();
        SM.block_production_execution.record(block_production_time);
        SM.entire_block_production_duration_gauge
            .set(block_production_time);
        SM.l1_fee_rate.set(l1_fee_rate as f64);
        SM.current_l2_block.set(l2_height as f64);

        result
    }

    /// Inner implementation of L2 block production
    ///
    /// # Arguments
    /// * `da_blocks` - Data availability blocks to process
    /// * `l1_fee_rate` - Current L1 fee rate
    /// * `l2_height` - Height of the L2 block to produce
    /// * `last_used_l1_height` - Last processed L1 block height
    ///
    /// # Returns
    /// The height of the produced L2 block
    async fn produce_l2_block_inner(
        &mut self,
        da_blocks: Vec<Da::FilteredBlock>,
        l1_fee_rate: u128,
        l2_height: u64,
        last_used_l1_height: &mut u64,
    ) -> anyhow::Result<u64> {
        let start_dry_run_preparation = Instant::now();
        let active_fork_spec = self.fork_manager.active_fork().spec_id;

        // TODO: after L2Block refactor PR, we'll need to change native provider
        // Save short header proof to ledger db for Native Short Header Proof Provider Service
        self.save_short_header_proofs(da_blocks.clone());

        let timestamp = chrono::Local::now().timestamp() as u64;

        // Get pending deposits up to configured limit
        let deposit_data = self
            .deposit_mempool
            .lock()
            .fetch_deposits(self.config.deposit_mempool_fetch_limit);

        let pub_key = self.sov_tx_signer_priv_key.pub_key();

        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: self.state_root,
            current_spec: active_fork_spec,
            sequencer_pub_key: pub_key.clone(),
            l1_fee_rate,
            timestamp,
        };

        // Create storage for the next L2 block
        let prestate = self.storage_manager.create_storage_for_next_l2_height();

        // Get best transactions from mempool based on gas price
        let evm_txs = self.get_best_transactions()?;

        let last_da_block_height = da_blocks.last().map(|b| b.header().height());
        SM.dry_run_preparation_time.set(
            Instant::now()
                .saturating_duration_since(start_dry_run_preparation)
                .as_secs_f64(),
        );

        // Dry running transactions would basically allow for figuring out a list of
        // all transactions that would fit into the current block and the list of transactions
        // which do not have enough balance to pay for the L1 fee.
        let (txs_to_run, l1_fee_failed_txs) = self
            .dry_run_transactions(
                evm_txs,
                prestate.clone(),
                l2_block_info.clone(),
                &deposit_data,
                da_blocks,
            )
            .await?;

        let block_production_start = Instant::now();
        let prestate = self.storage_manager.create_storage_for_next_l2_height();
        assert_eq!(
            prestate.version(),
            l2_height,
            "Prover storage version is corrupted"
        );

        let evm_txs_count = txs_to_run.len();

        let mut working_set = WorkingSet::new(prestate.clone());

        self.instrumented_begin_l2_block(&mut working_set, &l2_block_info)?;

        let (signed_txs, blobs) = self.encode_and_sign_evm_txs_into_sov_txs(
            &mut working_set,
            &l2_block_info,
            txs_to_run,
        )?;

        self.instrumented_apply_l2_block_txs(&l2_block_info, &signed_txs, &mut working_set)?;
        self.instrumented_end_l2_block(l2_block_info, &mut working_set)?;
        let l2_block_result =
            self.instrumented_finalize_l2_block(active_fork_spec, working_set, prestate);

        // Calculate tx hashes and merkle root
        let (tx_merkle_root, tx_hashes) =
            self.calculate_txs_merkle_root(&signed_txs, active_fork_spec);

        // create the l2 block header
        let header = L2Header::new(
            l2_height,
            self.l2_block_hash,
            l2_block_result.state_root_transition.final_root,
            l1_fee_rate,
            tx_merkle_root,
            timestamp,
        );

        let signed_header = self.sign_l2_block_header(header)?;
        // TODO: cleanup l2 block structure once we decide how to pull data from the running sequencer in the existing form
        let l2_block = L2Block::new(signed_header, signed_txs);

        info!(
            "New block #{}, Tx count: #{}",
            l2_block.height(),
            evm_txs_count
        );

        // First set the state diff before committing the L2 block
        // This prevents race conditions where the sequencer might shut down
        // between committing the L2 block and saving the state diff
        self.ledger_db
            .set_state_diff(L2BlockNumber(l2_height), &l2_block_result.state_diff)?;

        self.save_l2_block(l2_block, l2_block_result, tx_hashes, blobs)?;

        self.maintain_mempool(l1_fee_failed_txs)?;

        SM.no_dry_run_block_production_duration_secs.set(
            Instant::now()
                .saturating_duration_since(block_production_start)
                .as_secs_f64(),
        );
        SM.l2_block_tx_count.set(evm_txs_count as f64);

        // Update last used l1 height if this is a new da block
        if let Some(l1_height) = last_da_block_height {
            *last_used_l1_height = l1_height;
        }

        Ok(l2_height)
    }

    /// Calculates the transaction merkle root and records the time taken
    fn calculate_txs_merkle_root(
        &self,
        txs: &[Transaction],
        active_fork_spec: SpecId,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let start = Instant::now();
        let tx_hashes = compute_tx_hashes(txs, active_fork_spec);
        let merkle_root = compute_tx_merkle_root(&tx_hashes, active_fork_spec);
        SM.calculate_tx_merkle_root_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        (merkle_root, tx_hashes)
    }

    /// Begins an L2 block and records the time taken
    fn instrumented_begin_l2_block(
        &mut self,
        working_set: &mut WorkingSet<ProverStorage>,
        l2_block_info: &HookL2BlockInfo,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        if let Err(err) = self.stf.begin_l2_block(working_set, l2_block_info) {
            warn!(
                "Failed to apply l2 block hook: {:?} \n reverting batch workspace",
                err
            );
            bail!("Failed to apply begin l2 block hook: {:?}", err)
        }
        SM.begin_l2_block_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(())
    }

    /// Encodes and signs EVM transactions into Sov txs, and records the time taken
    fn encode_and_sign_evm_txs_into_sov_txs(
        &self,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
        l2_block_info: &HookL2BlockInfo,
        txs: Vec<RlpEvmTransaction>,
    ) -> anyhow::Result<(Vec<Transaction>, Vec<Vec<u8>>)> {
        let start_encode_and_sign_sov_tx = Instant::now();
        let mut blobs = vec![];
        let mut signed_txs = vec![];

        // if a batch failed need to refetch nonce
        // so sticking to fetching from state makes sense
        let nonce = self.get_nonce(working_set)?;

        if !txs.is_empty() {
            let call_txs = CallMessage { txs };
            let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                citrea_evm::Evm<DefaultContext>,
            >>::encode_call(call_txs);

            let signed_tx = self.sign_tx(l2_block_info.current_spec, raw_message, nonce)?;
            blobs.push(signed_tx.to_blob()?);
            signed_txs.push(signed_tx);
        }
        SM.encode_and_sign_sov_tx_time.set(
            Instant::now()
                .saturating_duration_since(start_encode_and_sign_sov_tx)
                .as_secs_f64(),
        );

        Ok((signed_txs, blobs))
    }

    /// Applies the L2 block transactions and records the time taken
    fn instrumented_apply_l2_block_txs(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        txs: &[Transaction],
        working_set: &mut WorkingSet<ProverStorage>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        self.stf
            .apply_l2_block_txs(l2_block_info, txs, working_set)?;
        SM.apply_l2_block_txs_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(())
    }

    /// Ends the L2 block and records the time taken
    fn instrumented_end_l2_block(
        &mut self,
        l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<ProverStorage>,
    ) -> anyhow::Result<()> {
        let start = Instant::now();
        self.stf.end_l2_block(l2_block_info, working_set)?;
        SM.end_l2_block_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(())
    }

    /// Finalizes the L2 block and records the time taken
    fn instrumented_finalize_l2_block(
        &mut self,
        active_fork_spec: SpecId,
        working_set: WorkingSet<ProverStorage>,
        prestate: ProverStorage,
    ) -> L2BlockResult<ProverStorage, sov_state::Witness, sov_state::ReadWriteLog> {
        let start = Instant::now();
        let result = self
            .stf
            .finalize_l2_block(active_fork_spec, working_set, prestate);
        SM.finalize_l2_block_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        result
    }

    /// Saves an L2 block and its associated data to storage
    ///
    /// # Arguments
    /// * `l2_block` - The L2 block to save
    /// * `l2_block_result` - Result of block execution
    /// * `tx_hashes` - Transaction hashes in the block
    /// * `blobs` - Associated blob data
    pub(crate) fn save_l2_block(
        &mut self,
        l2_block: L2Block,
        l2_block_result: L2BlockResult<ProverStorage, sov_state::Witness, sov_state::ReadWriteLog>,
        tx_hashes: Vec<[u8; 32]>,
        blobs: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        let save_l2_block_start = Instant::now();

        debug!("New L2 block with hash: {:?}", hex::encode(l2_block.hash()));

        let state_root_transition = l2_block_result.state_root_transition;

        // Check if state has actually changed
        if state_root_transition.final_root.as_ref() == self.state_root.as_ref() {
            bail!("Max L2 blocks per L1 is reached for the current L1 block. State root is the same as before, skipping");
        }

        trace!(
            "State root after applying slot: {:?}",
            state_root_transition.final_root,
        );

        let next_state_root = state_root_transition.final_root;

        // Finalize storage changes from block execution
        self.storage_manager
            .finalize_storage(l2_block_result.change_set);

        let l2_block_hash = l2_block.hash();

        // Persist block data to storage
        self.ledger_db
            .commit_l2_block(l2_block, tx_hashes, Some(blobs))?;

        // TODO: https://github.com/chainwayxyz/citrea/issues/1992
        // // connect L1 and L2 height
        // self.ledger_db.extend_l2_range_of_l1_slot(
        //     SlotNumber(da_block.header().height()),
        //     L2BlockNumber(l2_height),
        // )?;

        self.state_root = next_state_root;
        self.l2_block_hash = l2_block_hash;

        SM.save_l2_block_time.set(
            Instant::now()
                .saturating_duration_since(save_l2_block_start)
                .as_secs_f64(),
        );

        Ok(())
    }

    /// Maintains the mempool by removing failed transactions
    ///
    /// # Arguments
    /// * `l1_fee_failed_txs` - Transactions that failed due to L1 fee issues
    pub(crate) fn maintain_mempool(&self, l1_fee_failed_txs: Vec<TxHash>) -> anyhow::Result<()> {
        let start_maintain_mempool = Instant::now();
        // Combine transactions from last block and those that failed L1 fee check
        let mut txs_to_remove = self.db_provider.last_block_tx_hashes()?;
        txs_to_remove.extend(l1_fee_failed_txs);

        // Remove processed/failed transactions from mempool
        self.mempool.remove_transactions(txs_to_remove.clone());

        // Update account states in mempool
        let account_updates = self.get_account_updates()?;

        self.mempool.update_accounts(account_updates);

        // Remove transactions from persistent storage
        let txs = txs_to_remove
            .iter()
            .map(|tx_hash| tx_hash.to_vec())
            .collect::<Vec<Vec<u8>>>();
        if let Err(e) = self.ledger_db.remove_mempool_txs(txs) {
            warn!("Failed to remove txs from mempool: {:?}", e);
        }

        SM.mempool_txs.set(self.mempool.len() as f64);
        SM.maintain_mempool_time.set(
            Instant::now()
                .saturating_duration_since(start_maintain_mempool)
                .as_secs_f64(),
        );
        Ok(())
    }

    /// Main sequencer run loop
    ///
    /// # Arguments
    /// * `shutdown_signal` - Signal for graceful shutdown
    pub async fn run(
        &mut self,
        mut shutdown_signal: GracefulShutdown,
    ) -> Result<(), anyhow::Error> {
        // TODO: hotfix for mock da
        self.da_service
            .get_block_at(1)
            .await
            .map_err(|e| anyhow!(e))?;

        // Restore mempool state from persistent storage
        match self.restore_mempool().await {
            Ok(()) => debug!("Sequencer: Mempool restored"),
            Err(e) => {
                warn!("Sequencer: Mempool restore error: {:?}", e);
            }
        }

        // Get initial DA block data and fee rate
        let (mut last_finalized_block, mut l1_fee_rate) =
            match get_da_block_data(self.da_service.clone()).await {
                Ok(l1_data) => l1_data,
                Err(e) => {
                    error!("{}", e);
                    return Err(e);
                }
            };
        let mut last_finalized_l1_height = last_finalized_block.header().height();
        let prestate = self.storage_manager.create_final_view_storage();
        let mut working_set = WorkingSet::new(prestate.clone());
        let evm = Evm::<DefaultContext>::default();
        let head_l2_height = self.ledger_db.get_head_l2_block_height()?.unwrap_or(0);
        let _spec_id = fork_from_block_number(head_l2_height).spec_id;

        // Get last processed L1 height from light client
        let mut last_used_l1_height =
            match get_last_l1_height_in_light_client(&evm, &mut working_set) {
                Some(l1_height) => l1_height.to(),
                // Set to 1 less so that we do not skip processing the first l1 block
                None => last_finalized_l1_height - 1,
            };

        // Setup required workers to update our knowledge of the DA layer every X seconds (configurable).
        let (da_height_update_tx, mut da_height_update_rx) = mpsc::channel(1);

        // Create channel for communicating halt signals to the commitment service
        let (halt_commitment_tx, halt_commitment_rx) = mpsc::unbounded_channel();

        // Initialize commitment service for DA layer publication
        let commitment_service = CommitmentService::new(
            self.ledger_db.clone(),
            self.da_service.clone(),
            self.sequencer_da_pub_key.clone(),
            self.config.max_l2_blocks_per_commitment,
            halt_commitment_rx,
        );

        // Spawn commitment service task
        tokio::spawn(commitment_service.run(
            self.storage_manager.clone(),
            self.l2_block_hash,
            shutdown_signal.clone(),
        ));

        // Spawn DA block monitor task
        tokio::spawn(da_block_monitor(
            self.da_service.clone(),
            da_height_update_tx,
            self.config.da_update_interval_ms,
            shutdown_signal.clone(),
        ));

        let target_block_time = Duration::from_millis(self.config.block_production_interval_ms);

        // In case the sequencer falls behind on DA blocks, we need to produce at least 1
        // empty block per DA block. Which means that we have to keep count of missed blocks
        // and only resume normal operations once the sequencer has caught up.
        let mut missed_da_blocks_count =
            self.da_blocks_missed(last_finalized_l1_height, last_used_l1_height);

        let mut block_production_tick = tokio::time::interval(target_block_time);
        block_production_tick.tick().await;

        let backup_manager = self.backup_manager.clone();
        loop {
            tokio::select! {
                // Receive updates from DA layer worker.
                l1_data = da_height_update_rx.recv() => {
                    if let Some(l1_data) = l1_data {
                        (last_finalized_block, l1_fee_rate) = l1_data;
                        let new_finalized_l1_height = last_finalized_block.header().height();
                        if new_finalized_l1_height < last_finalized_l1_height {
                            info!("DA potential fork detected, known last finalized L1 height: {last_finalized_l1_height}, new finalized L1 height: {new_finalized_l1_height}")
                        }
                        last_finalized_l1_height = new_finalized_l1_height;

                        info!("New finalized L1 block at height {}", last_finalized_l1_height);

                        missed_da_blocks_count = self.da_blocks_missed(last_finalized_l1_height, last_used_l1_height);
                    }
                    SM.current_l1_block.set(last_finalized_l1_height as f64);
                },
                // Handle RPC messages (both test mode and halt signals)
                rpc_message = self.rpc_message_rx.recv() => {
                    match rpc_message {
                        Some(SequencerRpcMessage::ProduceTestBlock) => {
                            if !self.config.test_mode {
                                // Test block request received but not in test mode
                                warn!("Received test block request but sequencer is not in test mode");
                                continue;
                            }
                            if missed_da_blocks_count > 0 {
                                if let Err(e) = self.process_missed_da_blocks(missed_da_blocks_count, &mut last_used_l1_height, l1_fee_rate).await {
                                    error!("Sequencer error: {}", e);
                                    // Cancel child tasks
                                    drop(shutdown_signal);
                                    // we never want to continue if we have missed blocks
                                    return Err(e);
                                }
                                missed_da_blocks_count = 0;
                            }
                            let _l2_lock = backup_manager.start_l2_processing().await;
                            match self.produce_l2_block(vec![last_finalized_block.clone()], l1_fee_rate, &mut last_used_l1_height).await {
                                Ok(l2_height) => {
                                    // Only errors when there are no receivers
                                    let _ = self.l2_block_tx.send(l2_height);
                                },
                                Err(e) => {
                                    error!("Sequencer error: {}", e);
                                }
                            }
                        },
                        Some(SequencerRpcMessage::HaltCommitments) => {
                            // Forward halt signal to commitment service
                            if let Err(e) = halt_commitment_tx.send(true) {
                                error!("Failed to send halt signal to commitment service: {}", e);
                            } else {
                                info!("Sequencer: Halted commitments via RPC");
                            }
                        },
                        Some(SequencerRpcMessage::ResumeCommitments) => {
                            // Forward resume signal to commitment service
                            if let Err(e) = halt_commitment_tx.send(false) {
                                error!("Failed to send resume signal to commitment service: {}", e);
                            } else {
                                info!("Sequencer: Resumed commitments via RPC");
                            }
                        },
                        None => {
                            // Channel closed
                            warn!("RPC message channel closed");
                        }
                    }
                },
                // If sequencer is in production mode, it will build a block every 2 seconds
                _ = block_production_tick.tick(), if !self.config.test_mode => {
                    // By default, we produce a non-empty block IFF we were caught up all the way to
                    // last_finalized_block. If there are missed DA blocks, we start producing
                    // empty blocks at ~2 second rate, 1 L2 block per respective missed DA block
                    // until we know we caught up with L1.
                    let da_block = last_finalized_block.clone();

                    if missed_da_blocks_count > 0 {
                        if let Err(e) = self.process_missed_da_blocks(missed_da_blocks_count, &mut last_used_l1_height, l1_fee_rate).await {
                            error!("Sequencer error: {}", e);
                            // Cancel child tasks
                            drop(shutdown_signal);
                            // we never want to continue if we have missed blocks
                            return Err(e);
                        }
                        missed_da_blocks_count = 0;
                    }

                    let _l2_lock = backup_manager.start_l2_processing().await;
                    match self.produce_l2_block(vec![da_block.clone()], l1_fee_rate, &mut last_used_l1_height).await {
                        Ok(l2_height) => {
                            // Only errors when there are no receivers
                            let _ = self.l2_block_tx.send(l2_height);
                        },
                        Err(e) => {
                            error!("Sequencer error: {}", e);
                        }
                    };
                },
                _ = &mut shutdown_signal => {
                    info!("Shutting down sequencer");
                    da_height_update_rx.close();
                    self.rpc_message_rx.close();
                    return Ok(());
                }
            }
        }
    }

    /// Gets the best transactions from the mempool for inclusion in the next block
    ///
    /// This method considers base fee and other transaction attributes to select
    /// the most appropriate transactions.
    ///
    /// # Returns
    /// A boxed iterator of valid pool transactions
    pub(crate) fn get_best_transactions(
        &self,
    ) -> anyhow::Result<
        Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<EthPooledTransaction>>>>,
    > {
        let cfg = self.db_provider.cfg();
        let latest_header = self
            .db_provider
            .latest_header()
            .map_err(|e| anyhow!("Failed to get latest header: {}", e))?
            .ok_or(anyhow!("Latest header must always exist"))?
            .unseal();

        let base_fee = calculate_next_block_base_fee(
            latest_header.gas_used,
            latest_header.gas_limit,
            latest_header
                .base_fee_per_gas
                .expect("Base fee always set in Citrea"),
            cfg.base_fee_params,
        ) as u64;

        let best_txs_with_base_fee = self
            .mempool
            .best_transactions_with_attributes(BestTransactionsAttributes::base_fee(base_fee));

        Ok(best_txs_with_base_fee)
    }

    /// Signs a transaction with the sequencer's private key
    ///
    /// # Arguments
    /// * `raw_message` - Raw transaction message to sign
    /// * `nonce` - Nonce for the transaction
    ///
    /// # Returns
    /// A signed transaction
    pub(crate) fn sign_tx(
        &self,
        spec: SpecId,
        raw_message: Vec<u8>,
        nonce: u64,
    ) -> anyhow::Result<Transaction> {
        // TODO: figure out what to do with sov-tx fields
        // chain id gas tip and gas limit

        let tx =
            Transaction::new_signed_tx(spec, &self.sov_tx_signer_priv_key, raw_message, 0, nonce);
        Ok(tx)
    }

    /// Signs an L2 block header with the sequencer's private key
    ///
    /// # Arguments
    /// * `header` - The L2 block header to sign
    ///
    /// # Returns
    /// A signed L2 block header
    fn sign_l2_block_header(&mut self, header: L2Header) -> anyhow::Result<SignedL2Header> {
        let start = Instant::now();
        let hash = header.compute_digest();

        let signature = self.sov_tx_signer_priv_key.sign(&hash);
        let signature = borsh::to_vec(&signature)?;
        SM.sign_l2_block_header_time.set(
            Instant::now()
                .saturating_duration_since(start)
                .as_secs_f64(),
        );
        Ok(SignedL2Header::new(header, hash, signature))
    }

    /// Gets the current nonce for the sequencer account
    ///
    /// # Arguments
    /// * `working_set` - Working set for state access
    ///
    /// # Returns
    /// The current nonce value
    pub(crate) fn get_nonce(
        &self,
        working_set: &mut WorkingSet<<DefaultContext as Spec>::Storage>,
    ) -> anyhow::Result<u64> {
        let accounts = Accounts::<DefaultContext>::default();

        let pub_key = self.sov_tx_signer_priv_key.pub_key();

        match accounts
            .get_account(pub_key, working_set)
            .map_err(|e| anyhow!("Sequencer: Failed to get sov-account: {}", e))?
        {
            AccountExists { addr: _, nonce } => Ok(nonce),
            AccountEmpty => Ok(0),
        }
    }

    /// Restores the mempool state after a restart
    pub async fn restore_mempool(&self) -> Result<(), anyhow::Error> {
        // Load transactions from persistent storage
        let mempool_txs = self.ledger_db.get_mempool_txs()?;
        for (_, tx) in mempool_txs {
            // Recover and add each transaction back to mempool
            let recovered = recover_raw_transaction(Bytes::from(tx.as_slice().to_vec()))?;
            let pooled_tx = EthPooledTransaction::from_pooled(recovered);

            let _ = self.mempool.add_external_transaction(pooled_tx).await?;
        }
        Ok(())
    }

    /// Gets account updates for mempool maintenance
    ///
    /// This method retrieves account updates that occurred in the last block
    /// to help maintain accurate account states in the mempool.
    ///
    /// # Returns
    /// A vector of changed accounts with their updated states
    fn get_account_updates(&self) -> Result<Vec<ChangedAccount>, anyhow::Error> {
        // Get the most recent block
        let head = self
            .db_provider
            .last_block()?
            .expect("Unrecoverable: Head must exist");

        // Extract unique addresses from block transactions
        let addresses: HashSet<Address> = match head.transactions {
            alloy_rpc_types::BlockTransactions::Full(ref txs) => {
                txs.iter().map(|tx| tx.inner.signer()).collect()
            }
            _ => panic!("Block should have full transactions"),
        };

        let mut updates = vec![];

        // Get updated account state for each address
        for address in addresses {
            let account = self
                .db_provider
                .basic_account(&address)?
                .expect("Account must exist");
            updates.push(ChangedAccount {
                address,
                nonce: account.nonce,
                balance: account.balance,
            });
        }

        Ok(updates)
    }

    /// Processes missed DA blocks to catch up with L1
    ///
    /// # Arguments
    /// * `missed_da_blocks_count` - Number of DA blocks missed
    /// * `last_used_l1_height` - Last processed L1 block height
    /// * `l1_fee_rate` - Current L1 fee rate
    pub async fn process_missed_da_blocks(
        &mut self,
        missed_da_blocks_count: u64,
        last_used_l1_height: &mut u64,
        l1_fee_rate: u128,
    ) -> anyhow::Result<()> {
        debug!("We have {} missed DA blocks", missed_da_blocks_count);

        // Configure exponential backoff for DA block fetching retries
        let exponential_backoff = ExponentialBackoffBuilder::new()
            .with_initial_interval(Duration::from_millis(200))
            .with_max_elapsed_time(Some(Duration::from_secs(30)))
            .with_multiplier(1.5)
            .build();

        let mut filtered_blocks = vec![];

        // Fetch all missed DA blocks with retry logic
        for i in 1..=missed_da_blocks_count {
            let needed_da_block_height = *last_used_l1_height + i;

            // if we can't fetch da block and fail to produce a block the caller will return Err stopping
            // the sequencer. This is very problematic.
            // Hence, we retry fetching the DA block and producing the L2 block.

            let da_service = self.da_service.as_ref();
            let da_block = retry_backoff(exponential_backoff.clone(), || async move {
                da_service
                    .get_block_at(needed_da_block_height)
                    .await
                    .map_err(|e| backoff::Error::Transient {
                        err: anyhow!(e),
                        retry_after: None,
                    })
            })
            .await?;
            filtered_blocks.push(da_block);
        }

        // In order to not exceed the gas limit, we need to chunk the filtered blocks
        for chunk_of_filtered_blocks in
            filtered_blocks.chunks(MAX_MISSED_DA_BLOCKS_PER_L2_BLOCK as usize)
        {
            self.produce_l2_block(
                chunk_of_filtered_blocks.to_vec(),
                l1_fee_rate,
                // l2 block mode is ignored for post tangerine block production
                last_used_l1_height,
            )
            .await?;
        }

        Ok(())
    }

    /// Calculates the number of DA blocks missed
    ///
    /// # Arguments
    /// * `last_finalized_block_height` - Height of the last finalized L1 block
    /// * `last_used_l1_height` - Last processed L1 block height
    pub fn da_blocks_missed(
        &self,
        last_finalized_block_height: u64,
        last_used_l1_height: u64,
    ) -> u64 {
        // No blocks missed if we're caught up or behind
        if last_finalized_block_height <= last_used_l1_height {
            return 0;
        }

        // Calculate number of blocks we've skipped
        let skipped_blocks = last_finalized_block_height - last_used_l1_height - 1;
        if skipped_blocks > 0 {
            // This shouldn't happen. If it does, then we should produce at least 1 block for the blocks in between
            warn!(
                "Sequencer is falling behind on L1 blocks by {:?} blocks",
                skipped_blocks
            );
        }
        // Missed DA blocks means that we produce n - 1 empty blocks, 1 per missed DA block.
        skipped_blocks
    }

    /// Produces and runs system transactions for a block
    ///
    /// # Arguments
    /// * `l2_block_info` - Block information for hooks
    /// * `evm` - EVM instance
    /// * `working_set_to_discard` - Working set for state changes
    /// * `deposit_data` - Deposit transaction data
    /// * `da_blocks` - Data availability blocks
    /// * `nonce` - Current nonce
    fn produce_and_run_system_transactions(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        evm: &Evm<DefaultContext>,
        working_set_to_discard: WorkingSet<<DefaultContext as Spec>::Storage>,
        deposit_data: &[Vec<u8>],
        da_blocks: Vec<Da::FilteredBlock>,
        nonce: &mut u64,
    ) -> anyhow::Result<(
        Vec<RlpEvmTransaction>,
        WorkingSet<<DefaultContext as Spec>::Storage>,
    )> {
        let mut system_events = vec![];

        for (index, l1_block) in da_blocks.into_iter().enumerate() {
            // First l1 block of first l2 block
            if l2_block_info.l2_height() == 1 && index == 0 {
                let bridge_init_param = hex::decode(self.config.bridge_initialize_params.clone())
                    .expect("should deserialize");

                info!("Initializing Bitcoin Light Client with L1 block: #{} with hash {}, tx commitment {}, and coinbase depth {}. Using {:?} for bridge initialization params.", l1_block.header().height(), hex::encode(Into::<[u8; 32]>::into(l1_block.header().txs_commitment())), hex::encode(l1_block.hash()), l1_block.header().coinbase_txid_merkle_proof_height(), bridge_init_param);

                let initialize_events = create_initial_system_events(
                    l1_block.header().hash().into(),
                    l1_block.header().txs_commitment().into(),
                    l1_block.header().coinbase_txid_merkle_proof_height(),
                    l1_block.header().height(),
                    bridge_init_param,
                );
                // Initialize contracts
                system_events.extend(initialize_events);
                continue;
            }

            let da_block_header = l1_block.header();
            let coinbase_depth = da_block_header.coinbase_txid_merkle_proof_height();

            let set_block_info_event = populate_set_block_info_event(
                da_block_header.hash().into(),
                da_block_header.txs_commitment().into(),
                coinbase_depth,
            );
            system_events.push(set_block_info_event);
        }

        let deposit_events = populate_deposit_system_events(deposit_data);

        system_events.extend(deposit_events);

        self.process_sys_txs(
            l2_block_info,
            working_set_to_discard,
            nonce,
            evm,
            system_events,
        )
    }

    /// Processes system transactions
    ///
    /// # Arguments
    /// * `l2_block_info` - Block information for hooks
    /// * `working_set_to_discard` - Working set for state changes
    /// * `nonce` - Current nonce
    /// * `evm` - EVM instance
    /// * `system_events` - System events to process
    fn process_sys_txs(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        mut working_set_to_discard: WorkingSet<<DefaultContext as Spec>::Storage>,
        nonce: &mut u64,
        evm: &Evm<DefaultContext>,
        system_events: Vec<SystemEvent>,
    ) -> anyhow::Result<(
        Vec<RlpEvmTransaction>,
        WorkingSet<<DefaultContext as Spec>::Storage>,
    )> {
        info!("Processing {} system transactions", system_events.len());

        let mut all_txs = vec![];
        // Get system account info or use default if not exists
        let system_signer = evm
            .account_info(&SYSTEM_SIGNER, &mut working_set_to_discard)
            .unwrap_or(AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: None,
            });

        // Get chain configuration for transaction creation
        let cfg = evm.cfg.get(&mut working_set_to_discard).unwrap();
        let chain_id = cfg.chain_id;

        // Store deposit txs by index
        let is_deposit_tx = system_events
            .iter()
            .map(|ev| matches!(ev, SystemEvent::BridgeDeposit(_)))
            .collect::<Vec<_>>();
        // Create and process each system transaction
        let sys_txs = create_system_transactions(system_events, system_signer.nonce, chain_id);
        for (sys_tx, is_deposit) in sys_txs.iter().zip(is_deposit_tx) {
            // Encode transaction in EIP-2718 format
            let buf = sys_tx.encoded_2718();
            let sys_tx_rlp = RlpEvmTransaction { rlp: buf };

            let call_txs = CallMessage {
                txs: vec![sys_tx_rlp.clone()],
            };
            let raw_message = <CitreaRuntime<DefaultContext, Da::Spec> as EncodeCall<
                citrea_evm::Evm<DefaultContext>,
            >>::encode_call(call_txs);

            // Sign and increment nonce
            let signed_tx = self.sign_tx(l2_block_info.current_spec, raw_message, *nonce)?;
            *nonce += 1;

            let txs = vec![signed_tx];

            // Create checkpoint for potential revert
            let mut working_set = working_set_to_discard.checkpoint().to_revertable();

            if let Err(e) = self
                .stf
                .apply_l2_block_txs(l2_block_info, &txs, &mut working_set)
            {
                // If a deposit failed, revert back the working set and continue,
                // as deposits to non-EOA addresses can revert
                // Decrement nonce to be able to process other system and non-system transactions
                if matches!(
                    e,
                    StateTransitionError::ModuleCallError(
                        L2BlockModuleCallError::EvmSystemTransactionNotSuccessful
                    )
                ) && is_deposit
                {
                    warn!("Deposit transaction failed: {:?}", e);
                    *nonce = nonce.saturating_sub(1);
                    working_set_to_discard = working_set.revert().to_revertable();
                    continue;
                }
                return Err(anyhow!("Failed to apply system transaction: {:?}", e));
            }
            working_set_to_discard = working_set.checkpoint().to_revertable();
            all_txs.push(sys_tx_rlp);
        }

        Ok((all_txs, working_set_to_discard))
    }
}
