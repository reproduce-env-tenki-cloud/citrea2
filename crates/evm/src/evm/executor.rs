use alloy_consensus::Transaction;
use alloy_eips::Typed2718;
use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolCall;
use reth_primitives::{Recovered, TransactionSigned};
use revm::context::result::{EVMError, ExecutionResult, ResultAndState};
use revm::context::{BlockEnv, Cfg, CfgEnv, ContextTr, JournalTr};
use revm::handler::EvmTr;
use revm::state::EvmState;
use revm::{self, Context, Database, DatabaseCommit, ExecuteEvm, Journal};
use short_header_proof_provider::{ShortHeaderProofProviderError, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::{native_error, native_trace, L2BlockModuleCallError, WorkingSet};
#[cfg(feature = "native")]
use tracing::trace_span;

use super::conversions::create_tx_env;
use super::db::AccountExistsProvider;
use super::handler::{CitreaBuilder, CitreaChain, CitreaChainExt, CitreaContext};
use super::system_contracts::BitcoinLightClientContract;
use super::BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS;
use crate::{Evm, EvmDb, SYSTEM_SIGNER};

pub(crate) struct CitreaEvm<'a, DB: Database> {
    pub(crate) evm: super::handler::CitreaEvm<CitreaContext<'a, DB>, ()>,
}

impl<'a, DB> CitreaEvm<'a, DB>
where
    DB: Database + AccountExistsProvider,
{
    /// Creates a new Citrea EVM with the given parameters.
    pub fn new(db: DB, block_env: BlockEnv, config_env: CfgEnv, ext: &'a mut CitreaChain) -> Self {
        let mut journal = Journal::<DB>::new(db);
        journal.set_spec_id(config_env.spec());
        let evm = Context {
            block: block_env,
            cfg: config_env,
            chain: ext,
            tx: Default::default(),
            error: Ok(()),
            journaled_state: journal,
        }
        .build_citrea();
        Self { evm }
    }

    /// Runs a single transaction in the configured environment and proceeds
    /// to return the result and state diff (without applying it).
    pub(crate) fn transact(
        &mut self,
        tx: &Recovered<TransactionSigned>,
    ) -> Result<ResultAndState, EVMError<DB::Error>> {
        self.evm.ctx().chain().set_current_tx_hash(tx.hash());
        self.evm.transact(create_tx_env(tx))
    }

    /// Commits the given state diff to the database.
    pub(crate) fn commit(&mut self, state: EvmState)
    where
        DB: DatabaseCommit,
    {
        self.evm.ctx().db().commit(state)
    }
}

/// Will fail on the first error.
/// Rendering the l2 block invalid
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_multiple_tx<C: sov_modules_api::Context>(
    db: EvmDb<C>,
    block_env: BlockEnv,
    txs: &[Recovered<TransactionSigned>],
    config_env: CfgEnv,
    ext: &mut CitreaChain,
    prev_gas_used: u64,
    l2_height: u64,
    should_be_end_of_sys_txs: &mut bool,
) -> Result<Vec<ExecutionResult>, L2BlockModuleCallError> {
    if txs.is_empty() {
        return Ok(vec![]);
    }

    let block_gas_limit: u64 = block_env.gas_limit;

    let mut cumulative_gas_used = prev_gas_used;

    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);

    let mut tx_results = Vec::with_capacity(txs.len());

    for (_i, tx) in txs.iter().enumerate() {
        #[cfg(feature = "native")]
        let _span =
            trace_span!("Processing tx", i = _i, signer = %tx.signer(), tx_hash = %tx.hash())
                .entered();

        if tx.signer() == SYSTEM_SIGNER {
            if *should_be_end_of_sys_txs {
                native_error!("System transaction found after user txs");
                return Err(L2BlockModuleCallError::EvmSystemTransactionPlacedAfterUserTx);
            }

            verify_system_tx(evm.evm.ctx().db(), tx, l2_height)?;
        } else {
            // Set to true as soon as a user tx is found
            // If a sys tx is encountered after a user tx it is an error
            *should_be_end_of_sys_txs = true;
        }

        // if tx is eip4844 error out
        if tx.is_eip4844() {
            native_error!("EIP-4844 transaction is not supported");
            return Err(L2BlockModuleCallError::EvmTxTypeNotSupported(
                "EIP-4844".to_string(),
            ));
        }

        let result_and_state = evm.transact(tx).map_err(|e| {
            native_error!("Invalid tx {}. Error: {}", tx.hash(), e);
            match e {
                // only custom error we use is for not enough funds for L1 fee
                EVMError::Custom(_) => L2BlockModuleCallError::EvmNotEnoughFundsForL1Fee,
                _ => L2BlockModuleCallError::EvmTransactionExecutionError(e.to_string()),
            }
        })?;

        if !*should_be_end_of_sys_txs && !result_and_state.result.is_success() {
            native_error!(
                "System transaction not successful. Result: {:?}",
                result_and_state.result
            );
            return Err(L2BlockModuleCallError::EvmSystemTransactionNotSuccessful);
        }

        // Check if the transaction used more gas than the available block gas limit
        if cumulative_gas_used + result_and_state.result.gas_used() > block_gas_limit {
            native_error!("Gas used exceeds block gas limit");
            return Err(L2BlockModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                cumulative_gas: cumulative_gas_used,
                tx_gas_used: result_and_state.result.gas_used(),
                block_gas_limit,
            });
        }

        native_trace!("Committing tx to DB");
        evm.commit(result_and_state.state);
        cumulative_gas_used += result_and_state.result.gas_used();

        tx_results.push(result_and_state.result);
    }

    Ok(tx_results)
}

fn verify_system_tx<C: sov_modules_api::Context>(
    db: &mut EvmDb<C>,
    tx: &Recovered<TransactionSigned>,
    l2_height: u64,
) -> Result<(), L2BlockModuleCallError> {
    // Early return if this is the first block because sequencer will not have any L1 block hash in system contract before setblock info call
    if l2_height == 1 {
        return Ok(());
    }

    let function_selector: [u8; 4] = tx
        .input()
        .get(0..4)
        .ok_or(L2BlockModuleCallError::EvmSystemTxParseError)?
        .try_into()
        .map_err(|_| L2BlockModuleCallError::EvmSystemTxParseError)?;

    if function_selector == BitcoinLightClientContract::setBlockInfoCall::SELECTOR {
        let call = BitcoinLightClientContract::setBlockInfoCall::abi_decode(
            tx.input(),
            /*validate*/ true,
        )
        .map_err(|_| L2BlockModuleCallError::EvmSystemTxParseError)?;

        let l1_block_hash = call._blockHash;
        let txs_commitment = call._witnessRoot;
        let coinbase_depth = call._coinbaseDepth.to::<u8>();

        let (last_l1_height, prev_hash) =
            get_last_l1_height_and_hash_in_light_client::<C>(db.evm, db.working_set);

        // counter intuitively the contract stores next block height (expected on setBlockInfo)
        let next_l1_height: u64 = last_l1_height.to::<u64>();

        let shp_provider = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .expect("Short header proof provider not set");
        match shp_provider.get_and_verify_short_header_proof_by_l1_hash(
            l1_block_hash.0,
            prev_hash.unwrap().to_be_bytes(),
            next_l1_height,
            txs_commitment.0,
            coinbase_depth,
            l2_height,
        ) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // Failed to verify shp
                return Err(L2BlockModuleCallError::ShortHeaderProofVerificationError);
            }
            Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound) => {
                return Err(L2BlockModuleCallError::ShortHeaderProofNotFound);
            }
        }
    }

    // TODO: should we check for other system txs?

    Ok(())
}

/// Returns the last set l1 block height in bitcoin light client contract
pub fn get_last_l1_height_in_light_client<C: sov_modules_api::Context>(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C::Storage>,
) -> Option<U256> {
    evm.storage_get(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &U256::ZERO,
        working_set,
    )
    .map(|v| v.saturating_sub(U256::from(1u64)))
}

/// Returns the last set l1 block hash in bitcoin light client contract
pub fn get_last_l1_height_and_hash_in_light_client<C: sov_modules_api::Context>(
    evm: &Evm<C>,
    working_set: &mut WorkingSet<C::Storage>,
) -> (U256, Option<U256>) {
    let last_l1_height_in_contract = evm
        .storage_get(
            &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
            &U256::ZERO,
            working_set,
        )
        .unwrap_or(U256::ZERO);
    let mut bytes = [0u8; 64];
    bytes[0..32].copy_from_slice(
        &(last_l1_height_in_contract.saturating_sub(U256::from(1u64))).to_be_bytes::<32>(),
    );
    // counter intuitively the contract stores next block height (expected on setBlockInfo)
    bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());
    let last_l1_hash = evm.storage_get(
        &BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
        &keccak256(bytes).into(),
        working_set,
    );

    (last_l1_height_in_contract, last_l1_hash)
}
