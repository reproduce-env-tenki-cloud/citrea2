use bitcoin::Txid;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
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
}
