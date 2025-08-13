use alloy_consensus::constants::{EMPTY_OMMER_ROOT_HASH, EMPTY_WITHDRAWALS, KECCAK_EMPTY};
use alloy_consensus::{proofs, Header as AlloyHeader, TxReceipt};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::{Bloom, Bytes, B256, B64, U256};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use revm::context::BlockEnv;
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::primitives::hardfork::SpecId;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::prelude::*;
use sov_modules_api::{AccessoryWorkingSet, WorkingSet};
use sov_rollup_interface::zk::StorageRootHash;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::evm::primitive_types::Block;
#[cfg(feature = "native")]
use crate::evm::system_events::SystemEvent;
#[cfg(feature = "native")]
use crate::metrics::EVM_METRICS as EM;
use crate::{citrea_spec_id_to_evm_spec_id, Evm};

impl<C: sov_modules_api::Context> Evm<C> {
    /// Logic executed at the beginning of the slot. Here we set the state root of the previous head.
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), ret)
    )]
    pub fn begin_l2_block_hook(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        // just to be sure, we clear the pending transactions
        // do not ever think about removing this line
        // it has implications way beyond our understanding
        // a holy line
        self.pending_transactions.clear();

        let parent_block = {
            let mut parent_block = self
                .head
                .get(working_set)
                .expect("Head block should always be set");

            parent_block.header.state_root = B256::from_slice(&l2_block_info.pre_state_root());

            self.head.set(&parent_block, working_set);

            parent_block
        };

        let parent_block_number = parent_block.header.number;
        let parent_block_base_fee_per_gas =
            parent_block.header.base_fee_per_gas.unwrap_or_default();
        let parent_block_gas_used = parent_block.header.gas_used;
        let parent_block_gas_limit = parent_block.header.gas_limit;

        let sealed_parent_block = parent_block.seal();
        let last_block_hash = sealed_parent_block.header.hash();

        // since we know the previous state root only here, we can set the last block hash
        self.blockhash_set(parent_block_number, &last_block_hash, working_set);

        let cfg = self
            .cfg
            .get(working_set)
            .expect("EVM chain config should be set");
        let basefee = calculate_next_block_base_fee(
            parent_block_gas_used,
            parent_block_gas_limit,
            parent_block_base_fee_per_gas,
            cfg.base_fee_params,
        );

        let evm_spec = citrea_spec_id_to_evm_spec_id(l2_block_info.current_spec);

        let blob_excess_gas_and_price = Some(BlobExcessGasAndPrice::new(
            0,
            evm_spec.is_enabled_in(SpecId::PRAGUE),
        ));

        let new_pending_env = BlockEnv {
            number: parent_block_number + 1,
            beneficiary: cfg.coinbase,
            timestamp: l2_block_info.timestamp(),
            prevrandao: Some(B256::ZERO),
            basefee,
            gas_limit: cfg.block_gas_limit,
            difficulty: U256::ZERO,
            blob_excess_gas_and_price,
        };

        // set early. so that if underlying calls use `self.block_env`
        // they don't use the wrong value
        self.block_env = new_pending_env;

        self.should_be_end_of_sys_txs = false;
    }

    /// Logic executed at the end of the slot. Here, we generate an authenticated block and set it as the new head of the chain.
    /// It's important to note that the state root hash is not known at this moment, so we postpone setting this field until the begin_slot_hook of the next slot.
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    pub fn end_l2_block_hook(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let parent_block = self
            .head
            .get(working_set)
            .expect("Head block should always be set");

        let parent_block_hash = self
            .blockhash_get(parent_block.header.number, working_set)
            .expect("Should have parent block hash");

        let expected_block_number = parent_block.header.number + 1;
        assert_eq!(
            self.block_env.number, expected_block_number,
            "Pending head must be set to block {}, but found block {}",
            expected_block_number, self.block_env.number
        );

        let pending_transactions = &mut self.pending_transactions;

        let start_tx_index = parent_block.transactions.end;

        let gas_used = pending_transactions
            .last()
            .map_or(0u64, |tx| tx.receipt.receipt.cumulative_gas_used());

        let (transactions, receipts): (Vec<_>, Vec<_>) = pending_transactions
            .iter()
            .map(|tx| (&tx.transaction.signed_transaction, &tx.receipt.receipt))
            .unzip();

        let evm_spec = citrea_spec_id_to_evm_spec_id(l2_block_info.current_spec);

        let header = AlloyHeader {
            parent_hash: parent_block_hash,
            timestamp: self.block_env.timestamp,
            number: self.block_env.number,
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: parent_block.header.beneficiary,
            // This will be set in finalize_hook or in the next begin_slot_hook
            state_root: KECCAK_EMPTY,
            transactions_root: proofs::calculate_transaction_root(transactions.as_slice()),
            receipts_root: proofs::calculate_receipt_root(receipts.as_slice()),
            logs_bloom: receipts
                .iter()
                .fold(Bloom::ZERO, |bloom, r| bloom | r.bloom()),
            difficulty: U256::ZERO,
            gas_limit: self.block_env.gas_limit,
            gas_used,
            mix_hash: self.block_env.prevrandao.unwrap_or_default(),
            nonce: B64::ZERO,
            base_fee_per_gas: Some(self.block_env.basefee),
            extra_data: Bytes::default(),
            // EIP-4844 related fields
            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            withdrawals_root: Some(EMPTY_WITHDRAWALS),
            // EIP-4788 related field
            // unrelated for rollups
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: if let SpecId::PRAGUE = evm_spec {
                Some(EMPTY_REQUESTS_HASH)
            } else {
                None
            },
        };

        let block = Block {
            header,
            l1_fee_rate: l2_block_info.l1_fee_rate(),
            transactions: start_tx_index..start_tx_index + pending_transactions.len() as u64,
        };

        self.head.set(&block, working_set);

        self.should_be_end_of_sys_txs = false;

        #[cfg(not(feature = "native"))]
        pending_transactions.clear();

        #[cfg(feature = "native")]
        {
            use crate::PendingTransaction;

            let mut accessory_state = working_set.accessory_state();

            self.pending_head.set(&block, &mut accessory_state);

            let mut tx_index = start_tx_index;
            for PendingTransaction {
                transaction,
                receipt,
            } in pending_transactions
            {
                self.transactions.push(transaction, &mut accessory_state);
                self.receipts.push(receipt, &mut accessory_state);

                self.transaction_hashes.set(
                    transaction.signed_transaction.hash(),
                    &tx_index,
                    &mut accessory_state,
                );

                tx_index += 1
            }
            self.pending_transactions.clear();
        }
    }

    /// This logic is executed after calculating the root hash.
    /// At this point, it is impossible to alter state variables because the state root is fixed.
    /// However, non-state data can be modified.
    /// This function's purpose is to add the block to the (non-authenticated) blocks structure,
    /// enabling block-related RPC queries.
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, accessory_working_set), ret)
    )]
    #[cfg_attr(not(feature = "native"), allow(unused_variables))]
    pub fn finalize_hook(
        &self,
        root_hash: &StorageRootHash,
        accessory_working_set: &mut AccessoryWorkingSet<C::Storage>,
    ) {
        #[cfg(feature = "native")]
        {
            let expected_block_number = self.blocks.len(accessory_working_set) as u64;

            let mut block = self
                .pending_head
                .get(accessory_working_set)
                .unwrap_or_else(|| {
                    panic!(
                        "Pending head must be set to block {}, but was empty",
                        expected_block_number
                    )
                });

            assert_eq!(
                block.header.number, expected_block_number,
                "Pending head must be set to block {}, but found block {}",
                expected_block_number, block.header.number
            );

            block.header.state_root = root_hash.into();

            let sealed_block = block.seal();

            self.blocks.push(&sealed_block, accessory_working_set);

            let base_fee_gwei =
                sealed_block.header.base_fee_per_gas.unwrap_or_default() as f64 / 1_000_000_000.0; // Convert to Gwei
                                                                                                   // Update the metrics with the new block count
            EM.block_gas_usage.set(sealed_block.header.gas_used as f64);
            EM.block_base_fee.set(base_fee_gwei);

            self.block_hashes.set(
                &sealed_block.header.hash(),
                &sealed_block.header.number,
                accessory_working_set,
            );
            self.pending_head.delete(accessory_working_set);
        }
    }
}

/// Initializes system contracts
#[cfg(feature = "native")]
pub fn create_initial_system_events(
    current_slot_hash: [u8; 32],
    current_da_txs_commitment: [u8; 32],
    coinbase_depth: u64,
    current_da_height: u64,
    bridge_initialize_params: Vec<u8>,
) -> Vec<SystemEvent> {
    let system_events = vec![
        SystemEvent::BitcoinLightClientInitialize(current_da_height),
        SystemEvent::BitcoinLightClientSetBlockInfo(
            current_slot_hash,
            current_da_txs_commitment,
            coinbase_depth,
        ),
        SystemEvent::BridgeInitialize(bridge_initialize_params),
    ];
    system_events
}

/// If new l1 block arrives we set it in light client contract
#[cfg(feature = "native")]
pub fn populate_set_block_info_event(
    current_slot_hash: [u8; 32],
    current_da_txs_commitment: [u8; 32],
    coinbase_depth: u64,
) -> SystemEvent {
    tracing::info!("Populating BitcoinLightClientSetBlockInfo event with block hash {}, commitment {}, coinbase depth {}", hex::encode(current_slot_hash), hex::encode(current_da_txs_commitment), coinbase_depth);
    SystemEvent::BitcoinLightClientSetBlockInfo(
        current_slot_hash,
        current_da_txs_commitment,
        coinbase_depth,
    )
}

/// Populates deposit system events.
#[cfg(feature = "native")]
pub fn populate_deposit_system_events(deposit_data: &[Vec<u8>]) -> Vec<SystemEvent> {
    tracing::info!("Populating {} deposit transactions", deposit_data.len());
    let mut system_events = vec![];
    deposit_data.iter().for_each(|params| {
        system_events.push(SystemEvent::BridgeDeposit(params.clone()));
    });
    system_events
}
