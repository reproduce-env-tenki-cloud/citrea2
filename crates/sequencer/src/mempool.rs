use std::str::FromStr;
use std::sync::Arc;

use alloy_genesis::Genesis;
use alloy_primitives::{Address, Bytes, TxHash, B256, U256};
use anyhow::{anyhow, bail};
use citrea_common::SequencerMempoolConfig;
use citrea_evm::SYSTEM_SIGNER;
use reth_chainspec::{Chain, ChainSpecBuilder};
use reth_execution_types::ChangedAccount;
use reth_tasks::TokioTaskExecutor;
use reth_transaction_pool::blobstore::NoopBlobStore;
use reth_transaction_pool::error::PoolError;
use reth_transaction_pool::{
    BestTransactions, BestTransactionsAttributes, CoinbaseTipOrdering, EthPooledTransaction,
    EthTransactionValidator, Pool, PoolConfig, PoolResult, SubPoolLimit, TransactionPool,
    TransactionPoolExt, TransactionValidationTaskExecutor, ValidPoolTransaction,
};

pub use crate::db_provider::DbProvider;

type CitreaMempoolImpl<C> = Pool<
    TransactionValidationTaskExecutor<EthTransactionValidator<DbProvider<C>, EthPooledTransaction>>,
    CoinbaseTipOrdering<EthPooledTransaction>,
    NoopBlobStore,
>;

type Transaction<C> = <CitreaMempoolImpl<C> as TransactionPool>::Transaction;

pub(crate) struct CitreaMempool<C: sov_modules_api::Context>(CitreaMempoolImpl<C>);

impl<C: sov_modules_api::Context> CitreaMempool<C> {
    pub(crate) fn new(
        client: DbProvider<C>,
        mempool_conf: SequencerMempoolConfig,
    ) -> anyhow::Result<Self> {
        let blob_store = NoopBlobStore::default();

        let evm_config = client.cfg();

        let chain_spec = ChainSpecBuilder::default()
            .chain(Chain::from_id(evm_config.chain_id))
            .shanghai_activated()
            .genesis(
                Genesis::default()
                    .with_nonce(0)
                    .with_timestamp(0)
                    .with_extra_data(Bytes::default())
                    .with_gas_limit(8_000_000)
                    .with_difficulty(U256::ZERO)
                    .with_mix_hash(B256::default())
                    .with_coinbase(
                        Address::from_str("3100000000000000000000000000000000000005").unwrap(),
                    )
                    .with_base_fee(Some(1_000_000_000)),
            )
            .build();

        // Default 10x'ed from standard limits
        let pool_config = Default::default();
        let pool_config = PoolConfig {
            pending_limit: SubPoolLimit {
                max_txs: mempool_conf.pending_tx_limit as usize,
                max_size: (mempool_conf.pending_tx_size * 1024 * 1024) as usize,
            },
            basefee_limit: SubPoolLimit {
                max_txs: mempool_conf.base_fee_tx_limit as usize,
                max_size: (mempool_conf.base_fee_tx_size * 1024 * 1024) as usize,
            },
            queued_limit: SubPoolLimit {
                max_txs: mempool_conf.queue_tx_limit as usize,
                max_size: (mempool_conf.queue_tx_size * 1024 * 1024) as usize,
            },
            blob_limit: SubPoolLimit {
                max_txs: 0,
                max_size: 0,
            },
            max_account_slots: mempool_conf.max_account_slots as usize,
            ..pool_config
        };

        let validator = TransactionValidationTaskExecutor::eth_builder(Arc::new(chain_spec))
            .no_cancun()
            .no_eip4844()
            // TODO: if we ever increase block gas limits, we need to pull this from
            // somewhere else
            .set_block_gas_limit(evm_config.block_gas_limit)
            .set_shanghai(true)
            .with_additional_tasks(0)
            .build_with_tasks(client, TokioTaskExecutor::default(), blob_store);

        Ok(Self(Pool::eth_pool(validator, blob_store, pool_config)))
    }

    pub(crate) async fn add_external_transaction(
        &self,
        transaction: EthPooledTransaction,
    ) -> PoolResult<TxHash> {
        if transaction.transaction().signer() == SYSTEM_SIGNER {
            return Err(PoolError::other(
                transaction.transaction().hash(),
                "system transactions from rpc are not allowed",
            ));
        }
        self.0.add_external_transaction(transaction).await
    }

    pub(crate) fn get(&self, hash: &TxHash) -> Option<Arc<ValidPoolTransaction<Transaction<C>>>> {
        self.0.get(hash)
    }

    pub(crate) fn remove_transactions(
        &self,
        tx_hashes: Vec<TxHash>,
    ) -> Vec<Arc<ValidPoolTransaction<Transaction<C>>>> {
        self.0.remove_transactions(tx_hashes)
    }

    pub(crate) fn update_accounts(&self, account_updates: Vec<ChangedAccount>) {
        self.0.update_accounts(account_updates);
    }

    pub(crate) fn best_transactions_with_attributes(
        &self,
        best_transactions_attributes: BestTransactionsAttributes,
    ) -> Box<dyn BestTransactions<Item = Arc<ValidPoolTransaction<Transaction<C>>>>> {
        self.0
            .best_transactions_with_attributes(best_transactions_attributes)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}
