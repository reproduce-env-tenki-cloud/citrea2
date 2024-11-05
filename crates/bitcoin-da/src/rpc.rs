use crate::{monitoring::TxStatus, service::BitcoinService};

use bitcoin::Txid;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
// use tracing::{debug, error};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListPendingTransactionsResponse {
    pub txid: Txid,
    pub fee_rate: Option<f64>,
    pub initial_broadcast: u64,
    pub initial_height: u64,
    pub prev_tx: Option<Txid>,
    pub next_tx: Option<Txid>,
}

#[rpc(client, server, namespace = "da")]
pub trait DaRpc {
    #[method(name = "getPendingTransactions")]
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<ListPendingTransactionsResponse>>;

    #[method(name = "getTxStatus")]
    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>>;
}

#[async_trait::async_trait]
impl DaRpcServer for DaRpcServerImpl {
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<ListPendingTransactionsResponse>> {
        let txs = self
            .da
            .monitoring
            .get_pending_transactions()
            .await
            .into_iter()
            .map(|(txid, tx)| {
                let TxStatus::Pending { fee_rate, .. } = tx.status else {
                    unreachable!("get_pending_transactions guarantees Pending status")
                };

                ListPendingTransactionsResponse {
                    txid,
                    fee_rate,
                    initial_broadcast: tx.initial_broadcast,
                    initial_height: tx.initial_height,
                    prev_tx: tx.prev_tx,
                    next_tx: tx.next_tx,
                }
            })
            .collect::<Vec<_>>();

        Ok(txs)
    }
    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>> {
        Ok(self.da.monitoring.get_tx_status(&txid).await)
    }
}

pub struct DaRpcServerImpl {
    da: Arc<BitcoinService>,
}

impl DaRpcServerImpl {
    pub fn new(da: Arc<BitcoinService>) -> Self {
        Self { da }
    }
}

pub fn create_rpc_module(da: Arc<BitcoinService>) -> jsonrpsee::RpcModule<DaRpcServerImpl>
where
    DaRpcServerImpl: DaRpcServer,
{
    let server = DaRpcServerImpl::new(da);

    DaRpcServer::into_rpc(server)
}
