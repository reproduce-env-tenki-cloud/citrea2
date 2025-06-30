use alloy_consensus::constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS, EMPTY_WITHDRAWALS};
use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
use alloy_eips::eip1559::{BaseFeeParams, ETHEREUM_BLOCK_GAS_LIMIT_30M};
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::hex_literal::hex;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use lazy_static::lazy_static;
use reth_primitives::{Header, SealedHeader};
use sov_modules_api::prelude::*;

use crate::evm::primitive_types::SealedBlock;
use crate::evm::{AccountInfo, EvmChainConfig};
use crate::tests::utils::{get_evm, get_evm_test_config, GENESIS_HASH, GENESIS_STATE_ROOT};

lazy_static! {
    pub(crate) static ref GENESIS_DA_TXS_COMMITMENT: B256 = B256::from(hex!(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    ));
    pub(crate) static ref BENEFICIARY: Address = Address::from([3u8; 20]);
}

#[test]
fn genesis_data() {
    let config = get_evm_test_config();
    let (evm, mut working_set, _spec_id, ledger_db) = get_evm(&config);

    let account = &config.data[0];

    let db_account = evm
        .account_info(&account.address, &mut working_set)
        .unwrap();

    let contract = &config.data[1];

    let contract_account = evm
        .account_info(&contract.address, &mut working_set)
        .unwrap();

    let contract_storage1 = evm
        .get_storage_at(
            contract.address,
            U256::from(0),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap();

    let contract_storage2 = evm
        .get_storage_at(
            contract.address,
            U256::from_be_slice(
                &hex::decode("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")
                    .unwrap(),
            ),
            None,
            &mut working_set,
            &ledger_db,
        )
        .unwrap();

    assert_eq!(
        db_account,
        AccountInfo {
            balance: account.balance,
            code_hash: None,
            nonce: account.nonce,
        }
    );

    assert_eq!(
        contract_account,
        AccountInfo {
            balance: contract.balance,
            code_hash: Some(contract.code_hash),
            nonce: contract.nonce,
        }
    );

    assert_eq!(
        contract_storage1,
        B256::from_slice(
            hex::decode("0000000000000000000000000000000000000000000000000000000000004321")
                .unwrap()
                .as_slice()
        )
    );
    assert_eq!(
        contract_storage2,
        B256::from_slice(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000008")
                .unwrap()
                .as_slice()
        )
    );
}

#[test]
fn genesis_cfg() {
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&get_evm_test_config());

    let cfg = evm.cfg.get(&mut working_set).unwrap();
    assert_eq!(
        cfg,
        EvmChainConfig {
            chain_id: 1000,
            block_gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M,
            coinbase: Address::from([3u8; 20]),
            limit_contract_code_size: Some(5000),
            base_fee_params: BaseFeeParams::ethereum(),
        }
    );
}

#[test]
fn genesis_block() {
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&get_evm_test_config());

    let mut accessory_state = working_set.accessory_state();

    let block = evm.blocks.get(0, &mut accessory_state).unwrap();

    assert_eq!(
        block,
        SealedBlock {
            header: SealedHeader::new(
                Header {
                    parent_hash: B256::default(),
                    state_root: *GENESIS_STATE_ROOT,
                    transactions_root: EMPTY_TRANSACTIONS,
                    receipts_root: EMPTY_RECEIPTS,
                    logs_bloom: Bloom::default(),
                    difficulty: U256::ZERO,
                    number: 0,
                    gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M,
                    gas_used: 0,
                    timestamp: 0,
                    extra_data: Bytes::default(),
                    mix_hash: B256::default(),
                    nonce: B64::ZERO,
                    base_fee_per_gas: Some(1000000000),
                    ommers_hash: EMPTY_OMMER_ROOT_HASH,
                    beneficiary: *BENEFICIARY,
                    withdrawals_root: Some(EMPTY_WITHDRAWALS),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::ZERO),
                    requests_hash: Some(EMPTY_REQUESTS_HASH),
                },
                *GENESIS_HASH
            ),
            l1_fee_rate: 0,
            transactions: (0u64..0u64),
        }
    );
}

#[test]
fn genesis_head() {
    let (evm, mut working_set, _spec_id, _ledger_db) = get_evm(&get_evm_test_config());
    let head = evm.head.get(&mut working_set).unwrap();
    assert_eq!(head.header.parent_hash, *GENESIS_HASH);
    let genesis_block = evm
        .blocks
        .get(0, &mut working_set.accessory_state())
        .unwrap();

    assert_eq!(
        *genesis_block.header.header(),
        Header {
            parent_hash: B256::default(),
            state_root: *GENESIS_STATE_ROOT,
            transactions_root: EMPTY_TRANSACTIONS,
            receipts_root: EMPTY_RECEIPTS,
            logs_bloom: Bloom::default(),
            difficulty: U256::ZERO,
            number: 0,
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT_30M,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::default(),
            mix_hash: B256::default(),
            nonce: B64::ZERO,
            base_fee_per_gas: Some(1000000000),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: *BENEFICIARY,
            withdrawals_root: Some(EMPTY_WITHDRAWALS),
            blob_gas_used: Some(0),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some(B256::ZERO),
            requests_hash: Some(EMPTY_REQUESTS_HASH),
        }
    );

    assert_eq!(genesis_block.l1_fee_rate, 0);

    assert_eq!(genesis_block.transactions, (0u64..0u64));
}
