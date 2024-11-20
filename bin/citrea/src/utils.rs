use citrea_primitives::forks::FORKS;
use citrea_risc0_adapter::Digest;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::fork::fork_from_block_number;

use crate::guests::{
    BATCH_PROOF_MAINNET_GUESTS, BATCH_PROOF_MOCK_GUESTS, BATCH_PROOF_TESTNET_GUESTS,
    LIGHT_CLIENT_MAINNET_GUESTS, LIGHT_CLIENT_MOCK_GUESTS, LIGHT_CLIENT_TESTNET_GUESTS,
};
use crate::RunMode;

pub enum NodeType {
    MockBatch,
    MockLight,
    Batch,
    Light,
}

pub fn guest(node_type: NodeType, run_mode: RunMode, ledger_db: &LedgerDB) -> (Digest, Vec<u8>) {
    let guests = match node_type {
        NodeType::MockBatch => match run_mode {
            RunMode::Mainnet => &*BATCH_PROOF_MOCK_GUESTS,
            RunMode::Testnet => &*BATCH_PROOF_MOCK_GUESTS,
        },
        NodeType::MockLight => match run_mode {
            RunMode::Mainnet => &*LIGHT_CLIENT_MOCK_GUESTS,
            RunMode::Testnet => &*LIGHT_CLIENT_MOCK_GUESTS,
        },
        NodeType::Batch => match run_mode {
            RunMode::Mainnet => &*BATCH_PROOF_MAINNET_GUESTS,
            RunMode::Testnet => &*BATCH_PROOF_TESTNET_GUESTS,
        },
        NodeType::Light => match run_mode {
            RunMode::Mainnet => &*LIGHT_CLIENT_MAINNET_GUESTS,
            RunMode::Testnet => &*LIGHT_CLIENT_TESTNET_GUESTS,
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
