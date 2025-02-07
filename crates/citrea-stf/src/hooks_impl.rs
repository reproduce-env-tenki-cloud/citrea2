use sov_accounts::AccountsTxHook;
use sov_modules_api::hooks::{
    ApplySoftConfirmationHooks, FinalizeHook, HookSoftConfirmationInfo, SlotHooks, TxHooks,
};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{AccessoryWorkingSet, Context, SoftConfirmationHookError, WorkingSet};
use sov_modules_stf_blueprint::{RuntimeTxHook, SequencerOutcome};
use sov_rollup_interface::da::{BlobReaderTrait, DaSpec};
use sov_rollup_interface::zk::StorageRootHash;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::runtime::Runtime;

impl<C: Context, Da: DaSpec> TxHooks for Runtime<C, Da> {
    type Context = C;
    type PreArg = RuntimeTxHook;
    type PreResult = C;

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err))]
    fn pre_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        working_set: &mut WorkingSet<C::Storage>,
        arg: &RuntimeTxHook,
    ) -> Result<C, SoftConfirmationHookError> {
        let RuntimeTxHook {
            height,
            current_spec,
            l1_fee_rate,
        } = arg;
        let AccountsTxHook { sender } =
            self.accounts.pre_dispatch_tx_hook(tx, working_set, &None)?;

        Ok(C::new(sender, *height, *current_spec, *l1_fee_rate))
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    fn post_dispatch_tx_hook(
        &self,
        tx: &Transaction<Self::Context>,
        ctx: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), SoftConfirmationHookError> {
        self.accounts.post_dispatch_tx_hook(tx, ctx, working_set)?;

        Ok(())
    }
}

impl<C: Context, Da: DaSpec> ApplySoftConfirmationHooks<Da> for Runtime<C, Da> {
    type Context = C;
    type SoftConfirmationResult =
        SequencerOutcome<<<Da as DaSpec>::BlobTransaction as BlobReaderTrait>::Address>;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), err, ret)
    )]
    fn begin_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), SoftConfirmationHookError> {
        self.soft_confirmation_rule_enforcer
            .begin_soft_confirmation_hook(soft_confirmation_info, working_set)?;

        self.evm
            .begin_soft_confirmation_hook(soft_confirmation_info, working_set);

        Ok(())
    }

    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, err, ret))]
    fn end_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), SoftConfirmationHookError> {
        self.evm
            .end_soft_confirmation_hook(&soft_confirmation_info, working_set);
        Ok(())
    }
}

impl<C: Context, Da: DaSpec> SlotHooks<Da> for Runtime<C, Da> {
    type Context = C;

    fn begin_slot_hook(
        &self,
        _slot_header: &Da::BlockHeader,
        _pre_state_root: &StorageRootHash,
        _working_set: &mut sov_modules_api::WorkingSet<C::Storage>,
    ) {
    }

    fn end_slot_hook(&self, _working_set: &mut sov_modules_api::WorkingSet<C::Storage>) {}
}

impl<C: Context, Da: sov_modules_api::DaSpec> FinalizeHook<Da> for Runtime<C, Da> {
    type Context = C;

    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, accessory_working_set), ret)
    )]
    fn finalize_hook(
        &self,
        root_hash: &StorageRootHash,
        accessory_working_set: &mut AccessoryWorkingSet<C::Storage>,
    ) {
        self.evm.finalize_hook(root_hash, accessory_working_set);
    }
}
