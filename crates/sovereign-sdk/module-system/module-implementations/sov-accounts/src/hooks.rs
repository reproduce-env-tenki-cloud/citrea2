use sov_modules_api::hooks::TxHooks;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Context, SoftConfirmationHookError, SpecId, StateMapAccessor, WorkingSet};

use crate::{Account, Accounts};

/// The computed addresses of a pre-dispatch tx hook.
pub struct AccountsTxHook<C: Context> {
    /// The tx sender address
    pub sender: C::Address,
}

impl<C: Context> Accounts<C> {
    fn get_or_create_default(
        &self,
        pubkey: &[u8],
        working_set: &mut WorkingSet<C::Storage>,
        spec_id: SpecId,
    ) -> Result<Account<C>, SoftConfirmationHookError> {
        self.accounts.get(pubkey, working_set).map_or_else(
            || self.create_default_account(pubkey, working_set, spec_id),
            Ok,
        )
    }
}

impl<C: Context> TxHooks for Accounts<C> {
    type Context = C;
    type PreArg = Option<()>;
    type PreResult = AccountsTxHook<C>;

    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        working_set: &mut WorkingSet<C::Storage>,
        _sequencer: &Self::PreArg,
        spec_id: SpecId,
    ) -> Result<AccountsTxHook<C>, SoftConfirmationHookError> {
        let sender = self.get_or_create_default(tx.pub_key(), working_set, spec_id)?;
        let tx_nonce = tx.nonce();

        if sender.nonce != tx_nonce {
            return Err(SoftConfirmationHookError::SovTxBadNonce);
        }

        Ok(AccountsTxHook {
            sender: sender.addr,
        })
    }

    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction,
        _ctx: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), SoftConfirmationHookError> {
        let mut account = self
            .accounts
            .get_or_err(tx.pub_key(), working_set)
            .map_err(|_| SoftConfirmationHookError::SovTxAccountNotFound)?;
        account.nonce += 1;
        self.accounts.set(tx.pub_key(), &account, working_set);
        Ok(())
    }
}
