mod call;
mod genesis;
mod hooks;
use borsh::{BorshDeserialize, BorshSerialize};
pub use call::*;
pub use genesis::*;

#[cfg(feature = "native")]
mod query;
#[cfg(feature = "native")]
pub use query::*;

#[cfg(all(test, feature = "native"))]
mod tests;

// "Given DA slot hasn't been used for more than N l2 block blocks."
use sov_modules_api::{Address, Context, DaSpec, ModuleInfo, StateValue, WorkingSet};
use sov_state::codec::{BcsCodec, BorshCodec};
use sov_state::storage::StateValueCodec;

#[derive(Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
struct RuleEnforcerData {
    ///  Maximum number of L2 blocks per L1 slot.
    max_l2_blocks_per_l1: u32,
    /// Last DA slot hash.
    last_da_root_hash: [u8; 32],
    /// How many L2 blocks were published for a specific L1 block.
    counter: u32,
    /// Sequencer's block timestamp
    last_timestamp: u64,
}

impl StateValueCodec<RuleEnforcerData> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &RuleEnforcerData) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + 32 + 4 + 8);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<RuleEnforcerData, Self::Error> {
        borsh::from_slice(bytes)
    }
}

#[derive(ModuleInfo, Clone)]
#[module(rename = "L")]
pub struct L2BlockRuleEnforcer<C: Context, Da: DaSpec> {
    /// Address of the L2BlockRuleEnforcer module.
    #[address]
    address: C::Address,
    #[state]
    pub(crate) data: StateValue<RuleEnforcerData, BorshCodec>,
    /// Authority address. Address of the sequencer.
    /// This address is allowed to modify the max L2 blocks per L1.
    #[state]
    pub(crate) authority: StateValue<Address, BorshCodec>,
    /// Phantom state using the da type.
    /// This is used to make sure that the state is generic over the DA type.
    #[allow(dead_code)]
    #[state]
    pub(crate) phantom: StateValue<Da::SlotHash, BcsCodec>,
}

impl<C: Context, Da: DaSpec> sov_modules_api::Module for L2BlockRuleEnforcer<C, Da> {
    type Context = C;

    type Config = L2BlockRuleEnforcerConfig;

    type CallMessage = CallMessage;

    fn call(
        &mut self,
        message: Self::CallMessage,
        context: &Self::Context,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<sov_modules_api::CallResponse, sov_modules_api::L2BlockModuleCallError> {
        match message {
            CallMessage::ChangeAuthority { new_authority } => {
                Ok(self.change_authority(new_authority, context, working_set)?)
            }
            CallMessage::ModifyMaxL2BlocksPerL1 {
                max_l2_blocks_per_l1,
            } => {
                Ok(self.modify_max_l2_blocks_per_l1(max_l2_blocks_per_l1, context, working_set)?)
            }
        }
    }

    fn genesis(&self, config: &Self::Config, working_set: &mut WorkingSet<C::Storage>) {
        self.init_module(config, working_set)
    }
}
