#![allow(clippy::module_inception)]
use core::hash::Hash;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Currently available Citrea fork specs.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    PartialOrd,
    Default,
    BorshDeserialize,
    BorshSerialize,
    Serialize,
    Deserialize,
    Hash,
)]
#[borsh(use_discriminant = true)]
pub enum SpecId {
    /// Genesis spec
    #[default]
    Genesis = 0,
    /// First fork activates:
    /// 1. the light client proof
    /// 2. EVM cancun upgrade (with no kzg precompile)
    /// 3. Don't use borsh when signing SoftConfirmation's
    Fork1 = 1,
    /// Fork2 spec
    #[cfg(feature = "testing")]
    Fork2 = 2,
    /// Fork3 spec
    #[cfg(feature = "testing")]
    Fork3 = 3,
}

impl SpecId {
    /// Const fn to convert u8 to corresponding SpecId. Valid values are
    /// 0, 1, 2 and 3.
    pub const fn from_u8(n: u8) -> Option<SpecId> {
        match n {
            0 => Some(SpecId::Genesis),
            1 => Some(SpecId::Fork1),
            #[cfg(feature = "testing")]
            2 => Some(SpecId::Fork2),
            #[cfg(feature = "testing")]
            3 => Some(SpecId::Fork3),
            _ => None,
        }
    }
}
