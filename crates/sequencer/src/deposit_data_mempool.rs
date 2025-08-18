use std::collections::{HashSet, VecDeque};

use alloy_primitives::TxKind;
use alloy_rpc_types_eth::transaction::{TransactionInput, TransactionRequest};
use citrea_evm::system_contracts::BridgeWrapper;
use citrea_evm::SYSTEM_SIGNER;
use tracing::instrument;

use crate::metrics::SEQUENCER_METRICS as SM;

/// A mempool specifically for handling deposit transaction data
#[derive(Clone, Debug, Default)]
pub struct DepositDataMempool {
    /// Queue of accepted deposit transaction data
    accepted_deposit_txs: VecDeque<Vec<u8>>,
    /// Set of pending deposit hashes to prevent duplicates
    pending_deposits: HashSet<Vec<u8>>,
}

impl DepositDataMempool {
    /// Creates a new empty deposit data mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a transaction request for a deposit from raw deposit data
    ///
    /// # Arguments
    /// * `deposit_tx_data` - Raw deposit transaction data to be processed
    ///
    /// # Returns
    /// A transaction request configured for the bridge contract
    pub fn make_deposit_tx_from_data(&mut self, deposit_tx_data: Vec<u8>) -> TransactionRequest {
        TransactionRequest {
            from: Some(SYSTEM_SIGNER),
            to: Some(TxKind::Call(BridgeWrapper::address())),
            input: TransactionInput::new(BridgeWrapper::deposit(deposit_tx_data)),
            ..Default::default()
        }
    }

    /// Retrieves a limited number of deposit transactions from the mempool
    ///
    /// # Arguments
    /// * `limit_per_block` - Maximum number of deposits to return
    ///
    /// # Returns
    /// A vector of deposit transaction data, limited by the specified amount
    pub fn fetch_deposits(&mut self, limit_per_block: usize) -> Vec<Vec<u8>> {
        let number_of_deposits = self.accepted_deposit_txs.len().min(limit_per_block);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);
        let deposits: Vec<Vec<u8>> = self
            .accepted_deposit_txs
            .drain(..number_of_deposits)
            .collect();

        // Remove fetched deposits from the pending set
        for deposit in &deposits {
            self.pending_deposits.remove(deposit);
        }

        deposits
    }

    /// Adds a new deposit transaction to the mempool
    ///
    /// # Arguments
    /// * `req` - Raw deposit transaction data to be added
    ///
    /// # Returns
    /// `true` if the deposit was added, `false` if it was already pending
    #[instrument(level = "trace", skip_all, ret)]
    pub fn add_deposit_tx(&mut self, req: Vec<u8>) -> bool {
        // Check if deposit is already pending
        if !self.pending_deposits.insert(req.clone()) {
            tracing::debug!("Deposit already pending in mempool");
            return false;
        }

        self.accepted_deposit_txs.push_back(req);
        SM.deposit_data_mempool_txs_inc.increment(1);
        SM.deposit_data_mempool_txs
            .set(self.accepted_deposit_txs.len() as f64);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_deposit_tx_prevents_duplicates() {
        let mut mempool = DepositDataMempool::new();
        let deposit_data = vec![1, 2, 3, 4, 5];

        // First addition should succeed
        assert!(mempool.add_deposit_tx(deposit_data.clone()));
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
        assert_eq!(mempool.pending_deposits.len(), 1);

        // Second addition of the same deposit should fail
        assert!(!mempool.add_deposit_tx(deposit_data.clone()));
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
        assert_eq!(mempool.pending_deposits.len(), 1);

        // Adding a different deposit should succeed
        let different_deposit = vec![6, 7, 8, 9, 10];
        assert!(mempool.add_deposit_tx(different_deposit));
        assert_eq!(mempool.accepted_deposit_txs.len(), 2);
        assert_eq!(mempool.pending_deposits.len(), 2);
    }

    #[test]
    fn test_fetch_deposits_removes_from_pending() {
        let mut mempool = DepositDataMempool::new();
        let deposit1 = vec![1, 2, 3];
        let deposit2 = vec![4, 5, 6];
        let deposit3 = vec![7, 8, 9];

        // Add deposits
        assert!(mempool.add_deposit_tx(deposit1.clone()));
        assert!(mempool.add_deposit_tx(deposit2.clone()));
        assert!(mempool.add_deposit_tx(deposit3.clone()));
        assert_eq!(mempool.pending_deposits.len(), 3);

        // Fetch 2 deposits
        let fetched = mempool.fetch_deposits(2);
        assert_eq!(fetched.len(), 2);
        assert_eq!(fetched[0], deposit1);
        assert_eq!(fetched[1], deposit2);

        // Check that fetched deposits are removed from pending
        assert_eq!(mempool.pending_deposits.len(), 1);
        assert!(mempool.pending_deposits.contains(&deposit3));
        assert!(!mempool.pending_deposits.contains(&deposit1));
        assert!(!mempool.pending_deposits.contains(&deposit2));

        // Now these deposits can be added again
        assert!(mempool.add_deposit_tx(deposit1.clone()));
        assert!(mempool.add_deposit_tx(deposit2.clone()));
        assert_eq!(mempool.pending_deposits.len(), 3);
    }

    #[test]
    fn test_deposit_lifecycle() {
        let mut mempool = DepositDataMempool::new();
        let deposit = vec![10, 20, 30];

        // Add deposit
        assert!(mempool.add_deposit_tx(deposit.clone()));

        // Cannot add duplicate
        assert!(!mempool.add_deposit_tx(deposit.clone()));

        // Fetch the deposit
        let fetched = mempool.fetch_deposits(10);
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0], deposit);

        // Now the same deposit can be added again
        assert!(mempool.add_deposit_tx(deposit.clone()));
        assert_eq!(mempool.pending_deposits.len(), 1);
        assert_eq!(mempool.accepted_deposit_txs.len(), 1);
    }
}
