use std::sync::Arc;

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, B256};
use alloy_rpc_types::Transaction;
use citrea_common::rpc::utils::internal_rpc_error;
use citrea_evm::Evm;
use citrea_stf::runtime::DefaultContext;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::{ErrorCode, ErrorObject};
use parking_lot::Mutex;
use reth_rpc::eth::EthTxBuilder;
use reth_rpc_eth_types::error::EthApiError;
use reth_rpc_types_compat::TransactionCompat;
use reth_transaction_pool::{EthPooledTransaction, PoolTransaction};
use sov_db::ledger_db::SequencerLedgerOps;
use sov_modules_api::{Spec, WorkingSet};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, error};

use crate::deposit_data_mempool::DepositDataMempool;
use crate::mempool::CitreaMempool;
use crate::metrics::SEQUENCER_METRICS;
use crate::utils::recover_raw_transaction;

pub struct RpcContext<DB: SequencerLedgerOps> {
    pub mempool: Arc<CitreaMempool>,
    pub deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    pub l2_force_block_tx: UnboundedSender<()>,
    pub storage: <DefaultContext as Spec>::Storage,
    pub ledger: DB,
    pub test_mode: bool,
}

/// Creates a shared RpcContext with all required data.
pub fn create_rpc_context<DB>(
    mempool: Arc<CitreaMempool>,
    deposit_mempool: Arc<Mutex<DepositDataMempool>>,
    l2_force_block_tx: UnboundedSender<()>,
    storage: <DefaultContext as Spec>::Storage,
    ledger_db: DB,
    test_mode: bool,
) -> RpcContext<DB>
where
    DB: SequencerLedgerOps + Send + Clone + 'static,
{
    RpcContext {
        mempool,
        deposit_mempool,
        l2_force_block_tx,
        storage,
        ledger: ledger_db,
        test_mode,
    }
}

/// Updates the given RpcModule with Sequencer methods.
pub fn register_rpc_methods<DB: SequencerLedgerOps + Send + Sync + 'static>(
    rpc_context: RpcContext<DB>,
    mut rpc_methods: jsonrpsee::RpcModule<()>,
) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::core::RegisterMethodError> {
    let rpc = create_rpc_module(rpc_context);
    rpc_methods.merge(rpc)?;
    Ok(rpc_methods)
}

#[rpc(client, server)]
pub trait SequencerRpc {
    #[method(name = "eth_sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256>;

    #[method(name = "eth_getTransactionByHash")]
    #[blocking]
    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>>;

    #[method(name = "citrea_sendRawDepositTransaction")]
    #[blocking]
    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()>;

    #[method(name = "citrea_testPublishBlock")]
    async fn publish_test_block(&self) -> RpcResult<()>;
}

pub struct SequencerRpcServerImpl<DB: SequencerLedgerOps + Send + Sync + 'static> {
    context: Arc<RpcContext<DB>>,
}

impl<DB: SequencerLedgerOps + Send + Sync + 'static> SequencerRpcServerImpl<DB> {
    pub fn new(context: RpcContext<DB>) -> Self {
        Self {
            context: Arc::new(context),
        }
    }
}

#[async_trait::async_trait]
impl<DB: SequencerLedgerOps + Send + Sync + 'static> SequencerRpcServer
    for SequencerRpcServerImpl<DB>
{
    async fn eth_send_raw_transaction(&self, data: Bytes) -> RpcResult<B256> {
        debug!("Sequencer: eth_sendRawTransaction");

        let recovered = recover_raw_transaction(data.clone())?;
        let pool_transaction = EthPooledTransaction::from_pooled(recovered);

        let rlp_encoded_tx = pool_transaction.transaction().inner().encoded_2718();

        let hash = self
            .context
            .mempool
            .add_external_transaction(pool_transaction)
            .await
            .map_err(EthApiError::from)?;

        // Do not return error here just log
        if let Err(e) = self
            .context
            .ledger
            .insert_mempool_tx(hash.to_vec(), rlp_encoded_tx)
        {
            tracing::warn!("Failed to insert mempool tx into db: {:?}", e);
        } else {
            SEQUENCER_METRICS.mempool_txs.increment(1);
            SEQUENCER_METRICS.mempool_txs_inc.increment(1);
        }

        Ok(hash)
    }

    fn eth_get_transaction_by_hash(
        &self,
        hash: B256,
        mempool_only: Option<bool>,
    ) -> RpcResult<Option<Transaction>> {
        debug!(
            "Sequencer: eth_getTransactionByHash({}, {:?})",
            hash, mempool_only
        );

        match self.context.mempool.get(&hash) {
            Some(tx) => {
                let tx_signed_ec_recovered = tx.to_consensus(); // tx signed ec recovered
                let tx = EthTxBuilder::default()
                    .fill_pending(tx_signed_ec_recovered)
                    .expect("EthTxBuilder fill can't fail");
                Ok(Some(tx))
            }
            None => match mempool_only {
                Some(true) => Ok(None),
                _ => {
                    let evm = Evm::<DefaultContext>::default();
                    let mut working_set = WorkingSet::new(self.context.storage.clone());

                    match evm.get_transaction_by_hash(hash, &mut working_set) {
                        Ok(tx) => Ok(tx),
                        Err(e) => Err(e),
                    }
                }
            },
        }
    }

    fn send_raw_deposit_transaction(&self, deposit: Bytes) -> RpcResult<()> {
        debug!("Sequencer: citrea_sendRawDepositTransaction");

        let evm = Evm::<DefaultContext>::default();
        let mut working_set = WorkingSet::new(self.context.storage.clone());

        let dep_tx = self
            .context
            .deposit_mempool
            .lock()
            .make_deposit_tx_from_data(deposit.clone().into());

        let tx_res = evm.get_call(dep_tx, None, None, None, &mut working_set);

        match tx_res {
            Ok(hex_res) => {
                tracing::debug!("Deposit tx processed successfully {}", hex_res);
                self.context
                    .deposit_mempool
                    .lock()
                    .add_deposit_tx(deposit.to_vec());
                Ok(())
            }
            Err(e) => {
                error!("Error processing deposit tx: {:?}", e);
                Err(e)
            }
        }
    }

    async fn publish_test_block(&self) -> RpcResult<()> {
        if !self.context.test_mode {
            return Err(ErrorObject::from(ErrorCode::MethodNotFound).to_owned());
        }

        debug!("Sequencer: citrea_testPublishBlock");
        self.context.l2_force_block_tx.send(()).map_err(|e| {
            internal_rpc_error(format!("Could not send L2 force block transaction: {e}"))
        })
    }
}

pub fn create_rpc_module<DB: SequencerLedgerOps + Send + Sync + 'static>(
    rpc_context: RpcContext<DB>,
) -> jsonrpsee::RpcModule<SequencerRpcServerImpl<DB>> {
    let server = SequencerRpcServerImpl::new(rpc_context);

    SequencerRpcServer::into_rpc(server)
}
