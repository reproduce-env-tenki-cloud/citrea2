use crypto_bigint::U256;
use sov_rollup_interface::da::LatestDaState;

pub const MAINNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
};
pub const TESTNET4_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1D00FFFF,
    max_target: U256::from_be_hex(
        "00000000FFFF0000000000000000000000000000000000000000000000000000",
    ),
};
pub const SIGNET_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x1E0377AE,
    max_target: U256::from_be_hex(
        "00000377AE000000000000000000000000000000000000000000000000000000",
    ),
};
pub const REGTEST_CONSTANTS: NetworkConstants = NetworkConstants {
    max_bits: 0x207FFFFF,
    max_target: U256::from_be_hex(
        "7FFFFF0000000000000000000000000000000000000000000000000000000000",
    ),
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConstants {
    /// Maximum bits of the chain
    pub max_bits: u32,
    /// Maximum target of the chain
    pub max_target: U256,
}

pub const INITIAL_MAINNET_STATE: LatestDaState = LatestDaState {
    block_hash: [0; 32],
    block_height: 0,
    total_work: [0; 32],
    current_target_bits: 0,
    epoch_start_time: 0,
    prev_11_timestamps: [0; 11],
};

pub const INITIAL_TESTNET4_STATE: LatestDaState = LatestDaState {
    block_hash: [
        253, 141, 137, 197, 72, 182, 238, 141, 195, 224, 44, 112, 232, 183, 106, 255, 111, 137, 74,
        189, 16, 223, 156, 44, 40, 109, 0, 0, 0, 0, 0, 0,
    ],
    block_height: 72357,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 210, 125, 105, 23,
        206, 165, 249, 85, 237,
    ],
    current_target_bits: 0x190455c3,
    epoch_start_time: 1739833936,
    prev_11_timestamps: [
        1740948525, 1740949726, 1740950927, 1740947325, 1740948526, 1740949727, 1740950928,
        1740948527, 1740949728, 1740950929, 1740952130,
    ],
};

pub const INITIAL_SIGNET_STATE: LatestDaState = LatestDaState {
    block_hash: [
        195, 231, 238, 18, 219, 138, 28, 49, 67, 111, 70, 30, 22, 196, 205, 86, 220, 247, 116, 52,
        98, 251, 105, 153, 152, 53, 36, 217, 0, 0, 0, 0,
    ],
    block_height: 29999,
    total_work: [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 248, 208,
        52, 42, 132,
    ],
    current_target_bits: 0x1d00f27e,
    epoch_start_time: 1743078157,
    prev_11_timestamps: [
        1744094019, 1744095015, 1744096351, 1744090144, 1744090180, 1744090255, 1744090821,
        1744091059, 1744091830, 1744093263, 1744093286,
    ],
};

#[test]
fn verify_constants() {
    use crypto_bigint::Encoding;

    use crate::verifier::target_to_bits;

    assert_eq!(
        target_to_bits(&MAINNET_CONSTANTS.max_target.to_be_bytes()),
        MAINNET_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&TESTNET4_CONSTANTS.max_target.to_be_bytes()),
        TESTNET4_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&SIGNET_CONSTANTS.max_target.to_be_bytes()),
        SIGNET_CONSTANTS.max_bits
    );
    assert_eq!(
        target_to_bits(&REGTEST_CONSTANTS.max_target.to_be_bytes()),
        REGTEST_CONSTANTS.max_bits
    );
}
