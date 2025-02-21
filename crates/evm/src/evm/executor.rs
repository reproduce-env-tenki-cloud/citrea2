use alloy_primitives::{keccak256, U256};
use alloy_sol_types::SolCall;
use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{
    BlockEnv, CfgEnvWithHandlerCfg, EVMError, Env, EvmState, ExecutionResult, ResultAndState,
};
use revm::{self, Context, Database, DatabaseCommit, EvmContext};
use short_header_proof_provider::{ShortHeaderProofProviderError, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::{
    native_error, native_trace, SoftConfirmationModuleCallError, SpecId as CitreaSpecId,
};
#[cfg(feature = "native")]
use tracing::trace_span;

use super::conversions::create_tx_env;
use super::handler::{citrea_handler, CitreaExternalExt};
use super::BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS;
use crate::system_contracts::BitcoinLightClientContract;
use crate::{EvmDb, SYSTEM_SIGNER};

pub(crate) struct CitreaEvm<'a, EXT, DB: Database> {
    pub(crate) evm: revm::Evm<'a, EXT, DB>,
}

impl<'a, EXT, DB> CitreaEvm<'a, EXT, DB>
where
    DB: Database,
    EXT: CitreaExternalExt,
{
    /// Creates a new Citrea EVM with the given parameters.
    pub fn new(
        db: DB,
        citrea_spec: CitreaSpecId,
        block_env: BlockEnv,
        config_env: CfgEnvWithHandlerCfg,
        ext: EXT,
    ) -> Self {
        let evm_env = Env::boxed(config_env.cfg_env, block_env, Default::default());
        let evm_context = EvmContext::new_with_env(db, evm_env);
        let context = Context::new(evm_context, ext);
        let handler = citrea_handler(citrea_spec, config_env.handler_cfg);
        let evm = revm::Evm::new(context, handler);
        Self { evm }
    }

    /// Sets all required parameters and executes a transaction.
    pub(crate) fn transact_commit(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ExecutionResult, EVMError<DB::Error>>
    where
        DB: DatabaseCommit,
    {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx, self.evm.spec_id());
        self.evm.transact_commit()
    }

    /// Runs a single transaction in the configured environment and proceeds
    /// to return the result and state diff (without applying it).
    fn transact(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ResultAndState, EVMError<DB::Error>> {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx, self.evm.spec_id());
        self.evm.transact()
    }

    /// Commits the given state diff to the database.
    fn commit(&mut self, state: EvmState)
    where
        DB: DatabaseCommit,
    {
        self.evm.context.evm.db.commit(state)
    }
}

/// Will fail on the first error.
/// Rendering the soft confirmation invalid
pub(crate) fn execute_multiple_tx<C: sov_modules_api::Context, EXT: CitreaExternalExt>(
    db: EvmDb<C>,
    block_env: BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
    prev_gas_used: u64,
    l2_height: u64,
) -> Result<Vec<ExecutionResult>, SoftConfirmationModuleCallError> {
    if txs.is_empty() {
        return Ok(vec![]);
    }

    let block_gas_limit: u64 = block_env.gas_limit.saturating_to();

    let mut cumulative_gas_used = prev_gas_used;

    let citrea_spec = db.citrea_spec;
    let mut evm = CitreaEvm::new(db, citrea_spec, block_env, config_env, ext);

    let mut tx_results = Vec::with_capacity(txs.len());

    // Set to true as soon as a user tx is found
    // If a sys tx is encountered after a user tx it is an error
    let mut should_be_end_of_sys_txs = false;

    for (_i, tx) in txs.iter().enumerate() {
        #[cfg(feature = "native")]
        let _span =
            trace_span!("Processing tx", i = _i, signer = %tx.signer(), tx_hash = %tx.hash())
                .entered();

        if tx.signer() == SYSTEM_SIGNER {
            if citrea_spec < CitreaSpecId::Fork2 {
                native_error!("System transaction found in user txs");
                return Err(SoftConfirmationModuleCallError::EvmMisplacedSystemTx);
            }

            if should_be_end_of_sys_txs {
                native_error!("System transaction found after user txs");
                return Err(SoftConfirmationModuleCallError::EvmSystemTransactionPlacedAfterUserTx);
            }

            post_fork2_system_tx_verifier(evm.evm.db_mut(), tx, l2_height)?;
        } else {
            should_be_end_of_sys_txs = true;
        }

        // if tx is eip4844 error out
        if tx.is_eip4844() {
            native_error!("EIP-4844 transaction is not supported");
            return Err(SoftConfirmationModuleCallError::EvmTxTypeNotSupported(
                "EIP-4844".to_string(),
            ));
        }

        let result_and_state = evm.transact(tx).map_err(|e| {
            native_error!("Invalid tx {}. Error: {}", tx.hash(), e);
            match e {
                // only custom error we use is for not enough funds for L1 fee
                EVMError::Custom(_) => SoftConfirmationModuleCallError::EvmNotEnoughFundsForL1Fee,
                _ => SoftConfirmationModuleCallError::EvmTransactionExecutionError,
            }
        })?;

        // Check if the transaction used more gas than the available block gas limit
        if cumulative_gas_used + result_and_state.result.gas_used() > block_gas_limit {
            native_error!("Gas used exceeds block gas limit");
            return Err(
                SoftConfirmationModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                    cumulative_gas: cumulative_gas_used,
                    tx_gas_used: result_and_state.result.gas_used(),
                    block_gas_limit,
                },
            );
        }

        native_trace!("Commiting tx to DB");
        evm.commit(result_and_state.state);
        cumulative_gas_used += result_and_state.result.gas_used();

        tx_results.push(result_and_state.result);
    }

    Ok(tx_results)
}

fn post_fork2_system_tx_verifier<C: sov_modules_api::Context>(
    db: &mut EvmDb<C>,
    tx: &TransactionSignedEcRecovered,
    l2_height: u64,
) -> Result<(), SoftConfirmationModuleCallError> {
    let function_selector: [u8; 4] = tx.input()[0..4]
        .try_into()
        .map_err(|_| SoftConfirmationModuleCallError::EvmSystemTxParseError)?;

    if function_selector == BitcoinLightClientContract::setBlockInfoCall::SELECTOR {
        let l1_block_hash: [u8; 32] = tx.input()[4..36]
            .try_into()
            .map_err(|_| SoftConfirmationModuleCallError::EvmSystemTxParseError)?;
        let shp_provider = SHORT_HEADER_PROOF_PROVIDER
            .get()
            .expect("Short header proof provider not set");
        let txs_commitment: [u8; 32] = tx.input()[36..68]
            .try_into()
            .map_err(|_| SoftConfirmationModuleCallError::EvmSystemTxParseError)?;

        let last_l1_height = db
            .storage(BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, U256::ZERO)
            .unwrap();

        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&(last_l1_height - U256::from(1)).to_be_bytes::<32>());
        // counter intuitively the contract stores next block height (expected on setBlockInfo)x
        bytes[32..64].copy_from_slice(&U256::from(1).to_be_bytes::<32>());

        let prev_hash = db
            .storage(
                BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                keccak256(bytes).into(),
            )
            .unwrap();

        // counter intuitively the contract stores next block height (expected on setBlockInfo)
        let next_l1_height: u64 = last_l1_height.to::<u64>();

        match shp_provider.get_and_verify_short_header_proof_by_l1_hash(
            l1_block_hash,
            prev_hash.to_be_bytes(),
            next_l1_height,
            txs_commitment,
            l2_height,
        ) {
            Ok(true) => return Ok(()),
            Ok(false) => {
                // Failed to verify shp
                return Err(SoftConfirmationModuleCallError::ShortHeaderProofVerificationError);
            }
            Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound) => {
                return Err(SoftConfirmationModuleCallError::ShortHeaderProofNotFound);
            }
        }
    }

    Ok(())
}

pub(crate) fn execute_system_txs<C: sov_modules_api::Context, EXT: CitreaExternalExt>(
    db: EvmDb<C>,
    block_env: BlockEnv,
    system_txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Vec<ExecutionResult> {
    let citrea_spec = db.citrea_spec;
    let mut evm = CitreaEvm::new(db, citrea_spec, block_env, config_env, ext);

    system_txs
        .iter()
        .map(|tx| {
            evm.transact_commit(tx)
                .expect("System transactions must never fail")
        })
        .collect()
}
