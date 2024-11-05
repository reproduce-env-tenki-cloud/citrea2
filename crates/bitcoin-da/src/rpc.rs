use crate::{monitoring::TxStatus, service::BitcoinService};

use citrea_common::rpc::da::{DaRpcServer, ListPendingTransactionsResponse};
use jsonrpsee::core::RpcResult;
use std::sync::Arc;

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
