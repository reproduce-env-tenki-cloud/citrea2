//! This crate defines the core traits and types used by all Sovereign SDK rollups.
//! It specifies the interfaces which allow the same "business logic" to run on different
//! DA layers and be proven with different zkVMS, all while retaining compatibility
//! with the same basic full node implementation.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

/// The current version of Citrea.
///
/// Mostly used for web3_clientVersion RPC calls and might be used for other purposes.
#[cfg(feature = "native")]
pub const CITREA_VERSION: &str = "v0.6.1";

/// Fork module
pub mod fork;
pub mod mmr;
mod network;
mod node;
/// Specs module
pub mod spec;
mod state_machine;

#[cfg(not(target_has_atomic = "ptr"))]
pub use alloc::rc::Rc as RefCount;
#[cfg(target_has_atomic = "ptr")]
pub use alloc::sync::Arc as RefCount;

pub use network::*;
pub use node::*;
pub use state_machine::*;
pub use {anyhow, digest};
