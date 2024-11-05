use std::time::Duration;

use super::get_citrea_path;
use anyhow::bail;
use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::json::IndexStatus;
use bitcoincore_rpc::RpcApi;
use citrea_common::rpc::da::DaRpcClient;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;

struct BasicSyncTest;

#[async_trait]
impl TestCase for BasicSyncTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: false,
            n_nodes: 2,
            timeout: Duration::from_secs(60),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (Some(da0), Some(da1)) = (f.bitcoin_nodes.get(0), f.bitcoin_nodes.get(1)) else {
            bail!("bitcoind not running. Test should run with two da nodes")
        };
        let initial_height = f.initial_da_height;

        // Generate some blocks on node0
        da0.generate(5, None).await?;

        let height0 = da0.get_block_count().await?;
        let height1 = da1.get_block_count().await?;

        // Nodes are now out of sync
        assert_eq!(height0, initial_height + 5);
        assert_eq!(height1, 0);

        // Sync both nodes
        f.bitcoin_nodes.wait_for_sync(None).await?;

        let height0 = da0.get_block_count().await?;
        let height1 = da1.get_block_count().await?;

        // Assert that nodes are in sync
        assert_eq!(height0, height1, "Block heights don't match");

        Ok(())
    }
}

#[tokio::test]
async fn test_basic_sync() -> Result<()> {
    TestCaseRunner::new(BasicSyncTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct RestartBitcoinTest;

#[async_trait]
impl TestCase for RestartBitcoinTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-txindex=0"],
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get_mut(0).unwrap();
        // Add txindex flag to check that restart takes into account the extra args
        let new_conf = BitcoinConfig {
            extra_args: vec!["-txindex=1"],
            ..da.config.clone()
        };

        let block_before = da.get_block_count().await?;
        let info = da.get_index_info().await?;

        assert_eq!(info.txindex, None);

        // Restart node with txindex
        da.restart(Some(new_conf)).await?;

        let block_after = da.get_block_count().await?;
        let info = da.get_index_info().await?;

        assert!(matches!(
            info.txindex,
            Some(IndexStatus { synced: true, .. })
        ));
        // Assert that state is kept between restarts
        assert_eq!(block_before, block_after);

        Ok(())
    }
}

#[tokio::test]
async fn test_restart_bitcoin() -> Result<()> {
    TestCaseRunner::new(RestartBitcoinTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct BitcoinReorgTest;

#[async_trait]
impl TestCase for BitcoinReorgTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            n_nodes: 2,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let (Some(da0), Some(da1)) = (f.bitcoin_nodes.get(0), f.bitcoin_nodes.get(1)) else {
            bail!("Bitcoin nodes not running. Test requires two DA nodes")
        };

        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // Disconnect nodes before generating commitment
        f.bitcoin_nodes.disconnect_nodes().await?;

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for the sequencer commitments to hit the mempool
        da0.wait_mempool_len(2, None).await?;

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 2);
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 0);

        // Mine block with the sequencer commitment on the main chain
        da0.generate(1, None).await?;

        let original_chain_height = da0.get_block_count().await?;
        let original_chain_hash = da0.get_block_hash(original_chain_height).await?;
        let block = da0.get_block(&original_chain_hash).await?;
        assert_eq!(block.txdata.len(), 3); // Coinbase + seq commit/reveal txs

        let da1_generated_blocks = 2;
        da1.generate(da1_generated_blocks, None).await?;

        // Reconnect nodes and wait for sync
        f.bitcoin_nodes.connect_nodes().await?;
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Assert that re-org occured
        let new_hash = da0.get_block_hash(original_chain_height).await?;
        assert_ne!(original_chain_hash, new_hash, "Re-org did not occur");

        let mempool0 = da0.get_raw_mempool().await?;
        assert_eq!(mempool0.len(), 2);

        let pending_txs = sequencer
            .client
            .http_client()
            .da_get_pending_transactions()
            .await?;

        assert_eq!(mempool0[0], pending_txs[0].txid);
        assert_eq!(mempool0[1], pending_txs[1].txid);

        // Wait for re-org monitoring
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Seq TXs should be rebroadcasted after re-org
        let mempool1 = da1.get_raw_mempool().await?;
        assert_eq!(mempool1.len(), 2);

        da1.generate(1, None).await?;
        let height = da0.get_block_count().await?;
        let hash = da0.get_block_hash(height).await?;
        let block = da0.get_block(&hash).await?;
        assert_eq!(block.txdata.len(), 3); // Coinbase + seq commit/reveal txs

        da1.generate(FINALITY_DEPTH - 1, None).await?;
        let finalized_height = da1.get_finalized_height().await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Generate on da1 and wait for da0 to be back in sync
        f.bitcoin_nodes.wait_for_sync(None).await?;

        // Verify that commitments are included
        let original_commitments = batch_prover
            .client
            .ledger_get_sequencer_commitments_on_slot_by_number(finalized_height)
            .await?
            .unwrap_or_default();

        assert_eq!(original_commitments.len(), 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_bitcoin_reorg() -> Result<()> {
    TestCaseRunner::new(BitcoinReorgTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
