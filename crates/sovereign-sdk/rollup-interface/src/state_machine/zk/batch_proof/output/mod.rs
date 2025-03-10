use std::collections::BTreeMap;

use crate::RefCount;

/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<RefCount<[u8]>, Option<RefCount<[u8]>>>;
