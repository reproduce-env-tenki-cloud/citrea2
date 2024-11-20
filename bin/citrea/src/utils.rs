use citrea_primitives::forks::FORKS;
use citrea_risc0_adapter::Digest;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::fork::fork_from_block_number;

use crate::guests::{
    BATCH_PROOF_MAINNET_GUESTS, BATCH_PROOF_MOCK_GUESTS, BATCH_PROOF_TESTNET_GUESTS,
    LIGHT_CLIENT_MAINNET_GUESTS, LIGHT_CLIENT_MOCK_GUESTS, LIGHT_CLIENT_TESTNET_GUESTS,
};
use crate::Network;

pub enum NodeType {
    MockBatch,
    MockLight,
    Batch,
    Light,
}

pub fn guest(node_type: NodeType, network: Network, ledger_db: &LedgerDB) -> (Digest, Vec<u8>) {
    let guests = match node_type {
        NodeType::MockBatch => match network {
            Network::Mainnet => &*BATCH_PROOF_MOCK_GUESTS,
            Network::Testnet => &*BATCH_PROOF_MOCK_GUESTS,
        },
        NodeType::MockLight => match network {
            Network::Mainnet => &*LIGHT_CLIENT_MOCK_GUESTS,
            Network::Testnet => &*LIGHT_CLIENT_MOCK_GUESTS,
        },
        NodeType::Batch => match network {
            Network::Mainnet => &*BATCH_PROOF_MAINNET_GUESTS,
            Network::Testnet => &*BATCH_PROOF_TESTNET_GUESTS,
        },
        NodeType::Light => match network {
            Network::Mainnet => &*LIGHT_CLIENT_MAINNET_GUESTS,
            Network::Testnet => &*LIGHT_CLIENT_TESTNET_GUESTS,
        },
    };

    let last_l2_height = ledger_db
        .get_last_commitment_l2_height()
        .ok()
        .flatten()
        .expect("Should be able to fetch last l2 height");
    let fork = fork_from_block_number(FORKS, last_l2_height.into());
    let guest = guests
        .get(&fork.spec_id)
        .cloned()
        .expect("A fork should have a guest code attached");
    guest
}
