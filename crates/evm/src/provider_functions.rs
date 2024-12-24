use alloy_primitives::Address;
use reth_primitives::{Account, SealedHeader};
use sov_modules_api::AccessoryWorkingSet;
use sov_modules_api::{
    AccessoryStateMap, AccessoryStateVec, StateMapAccessor, StateVecAccessor, WorkingSet,
};
use sov_state::codec::BcsCodec;
use sov_state::codec::RlpCodec;
use sov_state::{ProverStorage, Storage};

use crate::Evm;

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<Account> {
        Some(
            self.accounts
                .get(address, working_set)
                .unwrap_or_default()
                .into(),
        )
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C::Storage>) -> SealedHeader {
        let q: AccessoryStateVec<crate::primitive_types::SealedBlock, RlpCodec> = self.blocks;
        let len = self
            .blocks
            .len(&mut working_set.accessory_state())
            .checked_sub(1)
            .unwrap();

        let prefix = q.prefix();

        match self.blocks.last(&mut working_set.accessory_state()) {
            Some(block) => block.header,
            None => {
                let block: crate::evm::primitive_types::SealedBlock =
                    AccessoryStateVec::with_codec(prefix.clone(), BcsCodec {})
                        .last(&mut working_set.accessory_state())
                        .unwrap();
                block.header
            }
        }
    }
}
