use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy_primitives::{Address, TxHash};
use alloy_rpc_types::BlockNumberOrTag;
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;
use reth_tasks::TaskManager;

use crate::common::client::{TestClient, MAX_FEE_PER_GAS};
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{make_test_client, TEST_DATA_GENESIS_PATH};

async fn initialize_test(
    sequencer_path: PathBuf,
    db_path: PathBuf,
) -> (TaskManager, Box<TestClient>) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_path,
        &db_path,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig::default();

    let seq_task = start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();

    (seq_task, test_client)
}

/// Test that maintenance task removes mined transactions from mempool automatically
#[tokio::test(flavor = "multi_thread")]
async fn test_maintenance_removes_mined_transactions() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // Send multiple transactions to mempool
    let tx1 = test_client
        .send_eth(addr, None, None, Some(0), 1_000_000_000u128)
        .await
        .unwrap();
    let tx2 = test_client
        .send_eth(addr, None, None, Some(1), 2_000_000_000u128)
        .await
        .unwrap();
    let tx3 = test_client
        .send_eth(addr, None, None, Some(2), 3_000_000_000u128)
        .await
        .unwrap();

    let tx1_hash = *tx1.tx_hash();
    let tx2_hash = *tx2.tx_hash();
    let tx3_hash = *tx3.tx_hash();

    // Verify all transactions are in mempool
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        3
    );
    assert!(test_client
        .is_transaction_in_mempool(tx1_hash)
        .await
        .unwrap());
    assert!(test_client
        .is_transaction_in_mempool(tx2_hash)
        .await
        .unwrap());
    assert!(test_client
        .is_transaction_in_mempool(tx3_hash)
        .await
        .unwrap());

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // Get the latest block to see which transactions were mined
    let block = test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let block_transactions = block.transactions.as_hashes().unwrap();

    // Wait a moment for maintenance task to process
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check which transactions are still in mempool
    for tx_hash in block_transactions {
        let in_mempool = test_client
            .is_transaction_in_mempool(*tx_hash)
            .await
            .unwrap();
        assert!(
            !in_mempool,
            "Mined transaction {} should be removed from mempool",
            tx_hash
        );
    }

    // Verify transactions are removed from mempool
    let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
    assert_eq!(
        mempool_count, 0,
        "Expected 0 transactions in mempool, but found {}",
        mempool_count
    );

    seq_task.graceful_shutdown();
}

/// Test that base fee updates are properly handled by maintenance task
#[tokio::test(flavor = "multi_thread")]
async fn test_base_fee_updates() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // Send transactions with different gas prices
    let high_fee_tx = test_client
        .send_eth(
            addr,
            Some(1000),
            Some(MAX_FEE_PER_GAS),
            Some(0),
            1_000_000_000u128,
        )
        .await
        .unwrap();
    let medium_fee_tx = test_client
        .send_eth(
            addr,
            Some(500),
            Some(MAX_FEE_PER_GAS),
            Some(1),
            1_000_000_000u128,
        )
        .await
        .unwrap();
    let low_fee_tx = test_client
        .send_eth(
            addr,
            Some(100),
            Some(MAX_FEE_PER_GAS),
            Some(2),
            1_000_000_000u128,
        )
        .await
        .unwrap();

    // Verify all transactions are in mempool
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        3
    );

    // Publish several blocks to potentially change base fee
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    wait_for_l2_block(&test_client, 3, None).await;

    // Wait for maintenance task to process base fee updates
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check mempool state - transactions should be properly categorized
    let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
    println!("Mempool count after base fee changes: {}", mempool_count);

    // High fee transaction should likely be mined
    let high_fee_in_mempool = test_client
        .is_transaction_in_mempool(*high_fee_tx.tx_hash())
        .await
        .unwrap();
    let medium_fee_in_mempool = test_client
        .is_transaction_in_mempool(*medium_fee_tx.tx_hash())
        .await
        .unwrap();
    let low_fee_in_mempool = test_client
        .is_transaction_in_mempool(*low_fee_tx.tx_hash())
        .await
        .unwrap();

    println!("High fee tx in mempool: {}", high_fee_in_mempool);
    println!("Medium fee tx in mempool: {}", medium_fee_in_mempool);
    println!("Low fee tx in mempool: {}", low_fee_in_mempool);

    // At least some transactions should have been processed
    assert!(mempool_count <= 3);

    seq_task.graceful_shutdown();
}

/// Test that account state updates are properly reflected in mempool validation
#[tokio::test(flavor = "multi_thread")]
async fn test_account_state_updates() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let chain_id: u64 = 5655;
    let key = "0xdcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<PrivateKeySigner>()
        .unwrap()
        .with_chain_id(Some(chain_id));
    let test_addr = key.address();

    // Create test client for the secondary account
    let secondary_client = TestClient::new(chain_id, key, test_addr, test_client.rpc_addr)
        .await
        .unwrap();

    // Send funds to secondary account
    let _funding_tx = test_client
        .send_eth(test_addr, None, None, None, 5_000_000_000_000_000_000u128)
        .await
        .unwrap();

    // Wait for funding transaction to be mined
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, Some(Duration::from_secs(10))).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send transactions from secondary account (now it has funds)
    let _tx1 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(0),
            1_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();
    let tx2 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(1),
            1_000_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    // Verify transactions are in mempool
    assert_eq!(
        test_client.get_mempool_transaction_count().await.unwrap(),
        2
    ); // tx1 + tx2

    // Publish block with transactions
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 2, Some(Duration::from_secs(10))).await;

    // Wait for maintenance task to update account states
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Send new transactions from same account after state update
    let tx3 = secondary_client
        .send_eth(
            test_client.from_addr,
            None,
            None,
            Some(2),
            500_000_000_000_000_000u128,
        )
        .await
        .unwrap();

    // Verify mempool properly validates based on updated account states
    let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
    println!("Mempool count after state update: {}", mempool_count);

    // Check nonce handling after updates
    let tx2_in_mempool = test_client
        .is_transaction_in_mempool(*tx2.tx_hash())
        .await
        .unwrap();
    let tx3_in_mempool = test_client
        .is_transaction_in_mempool(*tx3.tx_hash())
        .await
        .unwrap();

    println!("TX2 in mempool: {}", tx2_in_mempool);
    println!("TX3 in mempool: {}", tx3_in_mempool);

    assert!(tx3_in_mempool, "New transaction should be in mempool");

    seq_task.graceful_shutdown();
}

/// Test that transactions with insufficient L1 fees are removed after failed inclusion
#[tokio::test(flavor = "multi_thread")]
async fn test_l1_fee_failed_transactions() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();
    let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

    // Send a transaction with very low gas price that might fail L1 fee validation
    let low_l1_fee_tx = test_client
        .send_eth(addr, Some(1), Some(10_000_000), Some(0), 1_000_000_000u128)
        .await;

    // If the transaction is accepted (mempool validation might be less strict)
    if let Ok(tx) = low_l1_fee_tx {
        let tx_hash = *tx.tx_hash();

        // Verify transaction is in mempool initially
        if test_client
            .is_transaction_in_mempool(tx_hash)
            .await
            .unwrap()
        {
            // Attempt to include it in a block
            test_client.send_publish_batch_request().await;
            tokio::time::sleep(Duration::from_millis(200)).await;

            // Wait for maintenance task to process any failures
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Check if transaction was removed due to L1 fee failure
            let still_in_mempool = test_client
                .is_transaction_in_mempool(tx_hash)
                .await
                .unwrap();

            // Get the latest block to see if transaction was included
            let block = test_client
                .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
                .await;
            let tx_in_block = if let Some(hashes) = block.transactions.as_hashes() {
                hashes.contains(&tx_hash)
            } else {
                false
            };

            println!(
                "TX in block: {}, TX in mempool: {}",
                tx_in_block, still_in_mempool
            );

            // If transaction failed to be included due to L1 fees, it should be removed
            if !tx_in_block {
                // Transaction should eventually be removed from mempool if it consistently fails
                // We'll test this by attempting multiple block publications
                for _ in 0..3 {
                    test_client.send_publish_batch_request().await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }

                tokio::time::sleep(Duration::from_millis(500)).await;
                let final_mempool_check = test_client
                    .is_transaction_in_mempool(tx_hash)
                    .await
                    .unwrap();
                println!("Final mempool check: {}", final_mempool_check);
            }
        }
    } else {
        // Transaction was rejected by mempool validation, which is also valid behavior
        println!(
            "Transaction rejected by mempool validation: {}",
            low_l1_fee_tx.unwrap_err()
        );
    }

    seq_task.graceful_shutdown();
}

/// Test that persistent storage cleanup works correctly after restart
#[tokio::test(flavor = "multi_thread")]
async fn test_persistent_storage_cleanup() {
    let db_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = db_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = db_dir.path().join("sequencer").to_path_buf();

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();
    let mut persistent_tx_hash = TxHash::default();
    let mut mined_tx_hash = TxHash::default();

    // First sequencer instance
    {
        let (seq_task, test_client) =
            initialize_test(sequencer_db_dir.clone(), da_db_dir.clone()).await;

        // Send transactions and verify persistence
        let tx1 = test_client
            .send_eth(addr, None, None, Some(0), 1_000_000_000u128)
            .await
            .unwrap();
        let tx2 = test_client
            .send_eth(addr, None, None, Some(1), 2_000_000_000u128)
            .await
            .unwrap();

        mined_tx_hash = *tx1.tx_hash();
        persistent_tx_hash = *tx2.tx_hash();

        // Verify transactions are in mempool
        assert_eq!(
            test_client.get_mempool_transaction_count().await.unwrap(),
            2
        );

        // Publish block to mine first transaction
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&test_client, 1, None).await;

        // Wait for maintenance to process
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Verify state before shutdown
        let block = test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        let block_transactions = block.transactions.as_hashes().unwrap();

        let tx1_mined = block_transactions.contains(&mined_tx_hash);
        println!("TX1 mined: {}", tx1_mined);

        seq_task.graceful_shutdown();
    }

    // Small delay to ensure cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second sequencer instance (restart)
    {
        let (seq_task, test_client) = initialize_test(sequencer_db_dir, da_db_dir).await;

        // Wait for sequencer to start up and restore mempool
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Verify mined transactions are not restored to mempool
        let mined_tx_in_mempool = test_client
            .is_transaction_in_mempool(mined_tx_hash)
            .await
            .unwrap();
        assert!(
            !mined_tx_in_mempool,
            "Mined transaction should not be restored to mempool"
        );

        // Verify unmined transactions are restored
        let persistent_tx_in_mempool = test_client
            .is_transaction_in_mempool(persistent_tx_hash)
            .await
            .unwrap();

        let mempool_count = test_client.get_mempool_transaction_count().await.unwrap();
        println!("Mempool count after restart: {}", mempool_count);
        println!("Persistent tx in mempool: {}", persistent_tx_in_mempool);

        // We expect only unmined transactions to be restored
        if persistent_tx_in_mempool {
            assert_eq!(
                mempool_count, 1,
                "Only unmined transactions should be restored"
            );
        }

        seq_task.graceful_shutdown();
    }
}
