#![deny(missing_docs)]
#![doc = include_str!("../README.md")]
mod call;
mod evm;
mod genesis;
mod hooks;
#[cfg(feature = "native")]
mod metrics;
mod provider_functions;

use alloy_consensus::TxReceipt;
pub use alloy_primitives::{keccak256, U256};
use alloy_rlp::{RlpDecodable, RlpEncodable};
pub use call::*;
pub use evm::*;
pub use genesis::*;
#[cfg(feature = "native")]
pub use hooks::{
    create_initial_system_events, populate_deposit_system_events, populate_set_block_info_event,
};
#[cfg(feature = "native")]
pub use metrics::EVM_METRICS;
use revm::context::BlockEnv;
use revm::primitives::hardfork::SpecId as EvmSpecId;
#[cfg(feature = "native")]
use sov_db::ledger_db::LedgerDB;
use sov_state::codec::BorshCodec;
pub use system_events::SYSTEM_SIGNER;

#[cfg(feature = "native")]
mod rpc_helpers;
#[cfg(feature = "native")]
pub use rpc_helpers::*;
#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;
#[cfg(test)]
mod signer;

#[cfg(feature = "native")]
pub mod smart_contracts;

#[cfg(all(test, feature = "native"))]
mod tests;

use alloy_consensus::Header as AlloyHeader;
use alloy_primitives::{Address, TxHash, B256};
use evm::db::EvmDb;
use sov_modules_api::{L2BlockModuleCallError, ModuleInfo, SpecId as CitreaSpecId, WorkingSet};
use sov_state::codec::{BcsCodec, RlpCodec};

#[cfg(feature = "native")]
use crate::evm::primitive_types::SealedBlock;
use crate::evm::primitive_types::{Block, CitreaReceiptWithBloom, TransactionSignedAndRecovered};
pub use crate::EvmConfig;

#[derive(
    Clone, Debug, serde::Serialize, serde::Deserialize, RlpEncodable, RlpDecodable, PartialEq, Eq,
)]
/// Pending EVM transaction
pub struct PendingTransaction {
    pub(crate) transaction: TransactionSignedAndRecovered,
    pub(crate) receipt: CitreaReceiptWithBloom,
}

impl PendingTransaction {
    /// Returns the transaction's hash
    pub fn hash(&self) -> &TxHash {
        self.transaction.signed_transaction.hash()
    }

    /// Returns the cumulative gas used for this transaction
    pub fn cumulative_gas_used(&self) -> u64 {
        self.receipt.receipt.cumulative_gas_used()
    }
}

/// A unique id of account inside our evm state. 64 bits is enough.
type AccountId = u64;

/// The citrea-evm module provides compatibility with the EVM.
// #[cfg_attr(feature = "native", derive(sov_modules_api::ModuleCallJsonSchema))]
#[derive(ModuleInfo, Clone)]
#[module(rename = "E")]
pub struct Evm<C: sov_modules_api::Context> {
    /// The address of the evm module.
    #[address]
    pub(crate) address: C::Address,

    /// Mapping from account address to account id.
    #[state(rename = "i")]
    pub account_idxs: sov_modules_api::StateMap<Address, AccountId, BorshCodec>,

    /// Mapping from account id to account state.
    #[state(rename = "a")]
    pub accounts: sov_modules_api::StateMap<AccountId, AccountInfo, BorshCodec>,

    /// The total number of accounts.
    #[state(rename = "n")]
    pub(crate) account_amount: sov_modules_api::StateValue<u64, BorshCodec>,

    /// Mapping from storage hash ( sha256(address | key) ) to storage value.
    #[state(rename = "s")]
    pub storage: sov_modules_api::StateMap<U256, U256, BorshCodec>,

    /// Mapping from code hash to code. Used for lazy-loading code into a contract account.
    #[state(rename = "c")]
    pub offchain_code: sov_modules_api::OffchainStateMap<B256, revm::state::Bytecode, BcsCodec>,

    /// Chain configuration. This field is set in genesis.
    #[state(rename = "S")]
    pub cfg: sov_modules_api::StateValue<EvmChainConfig, BcsCodec>,

    /// Block environment used by the evm. This field is set in `begin_slot_hook`.
    /// WARNING: only use in the L2 block hook & tx execution path.
    /// And not in any place such as functions that might be called from RPC etc.
    #[memory]
    pub(crate) block_env: BlockEnv,

    /// Module level flag used to indicate that the current L2 block should not contain system
    /// transactions after a user transaction has been processed.
    #[memory]
    pub(crate) should_be_end_of_sys_txs: bool,

    /// Transactions that will be added to the current block.
    /// Valid transactions are added to the vec on every call message.
    /// WARNING: only use in the L2 block hook & tx execution path.
    /// And not in any place such as functions that might be called from RPC etc.
    #[memory]
    pub(crate) pending_transactions: Vec<PendingTransaction>,

    /// Head of the rlp encoded chain. The new head is set in `end_slot_hook` but without the inclusion of the `state_root` field.
    /// The `state_root` is added in `begin_slot_hook` of the next block because its calculation occurs after the `end_slot_hook`.
    #[state(rename = "h")]
    pub(crate) head: sov_modules_api::StateValue<Block<AlloyHeader>, RlpCodec>,

    /// Last 256 block hashes. Latest blockhash is populated in `begin_slot_hook`.
    /// Removes the oldest blockhash in `finalize_hook`
    /// Used by the EVM to calculate the `blockhash` opcode.
    #[state(rename = "H")]
    pub(crate) latest_block_hashes: sov_modules_api::StateMap<u64, B256, BorshCodec>,

    /// Used only by the RPC: This represents the head of the chain and is set in two distinct stages:
    /// 1. `end_slot_hook`: the pending head is populated with data from pending_transactions.
    /// 2. `finalize_hook` the `root_hash` is populated.
    ///
    /// Since this value is not authenticated, it can be modified in the `finalize_hook` with the correct `state_root`.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) pending_head: sov_modules_api::AccessoryStateValue<Block<AlloyHeader>, RlpCodec>,

    #[cfg(feature = "native")]
    #[state]
    pub(crate) blocks: sov_modules_api::AccessoryStateVec<SealedBlock, RlpCodec>,

    /// Used only by the RPC: block_hash => block_number mapping,
    #[cfg(feature = "native")]
    #[state]
    pub(crate) block_hashes: sov_modules_api::AccessoryStateMap<B256, u64, BorshCodec>,

    #[cfg(feature = "native")]
    #[state]
    pub(crate) transactions:
        sov_modules_api::AccessoryStateVec<TransactionSignedAndRecovered, RlpCodec>,

    /// Used only by the RPC: transaction_hash => transaction_index mapping.
    #[cfg(feature = "native")]
    #[state]
    pub(crate) transaction_hashes: sov_modules_api::AccessoryStateMap<B256, u64, BorshCodec>,

    #[cfg(feature = "native")]
    #[state]
    pub(crate) receipts: sov_modules_api::AccessoryStateVec<CitreaReceiptWithBloom, RlpCodec>,
}

impl<C: sov_modules_api::Context> sov_modules_api::Module for Evm<C> {
    type Context = C;

    type Config = EvmConfig;

    type CallMessage = call::CallMessage;

    fn genesis(&self, config: &Self::Config, working_set: &mut WorkingSet<C::Storage>) {
        self.init_module(config, working_set)
    }

    fn call(
        &mut self,
        msg: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, L2BlockModuleCallError> {
        self.execute_call(msg.txs, context, working_set)
    }
}

impl<C: sov_modules_api::Context> Evm<C> {
    pub(crate) fn get_db<'a>(
        &'a self,
        working_set: &'a mut WorkingSet<C::Storage>,
    ) -> EvmDb<'a, C> {
        EvmDb::new(self, working_set)
    }
}

const fn citrea_spec_id_to_evm_spec_id(spec_id: CitreaSpecId) -> EvmSpecId {
    match spec_id {
        CitreaSpecId::Kumquat | CitreaSpecId::Genesis => EvmSpecId::CANCUN,
        // Any other citrea spec id mapped to Prague
        _ => EvmSpecId::PRAGUE,
    }
}
