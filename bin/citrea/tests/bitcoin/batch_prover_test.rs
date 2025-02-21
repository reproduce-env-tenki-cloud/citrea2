use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::{Address, U64};
use anyhow::bail;
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, FINALITY_DEPTH};
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::RpcApi;
use borsh::BorshDeserialize;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::{
    BatchProverConfig, CitreaMode, LightClientProverConfig, ProverGuestRunConfig, SequencerConfig,
    SequencerMempoolConfig, TestCaseConfig, TestCaseEnv,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::{FullNode, NodeKind};
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use citrea_primitives::forks::{fork_from_block_number, get_forks, use_network_forks};
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_stf::runtime::DefaultContext;
use sov_ledger_rpc::LedgerRpcClient;
use sov_modules_api::default_signature::K256PublicKey;
use sov_modules_api::fork::ForkManager;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{PublicKey, Spec, SpecId};
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};
use sov_rollup_interface::rpc::VerifiedBatchProofResponse;
use sov_rollup_interface::Network;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::common::make_test_client;

pub async fn wait_for_zkproofs(
    full_node: &FullNode,
    height: u64,
    timeout: Option<Duration>,
) -> Result<Vec<VerifiedBatchProofResponse>> {
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(240));

    loop {
        if start.elapsed() >= timeout {
            bail!("FullNode failed to get zkproofs within the specified timeout");
        }

        match full_node
            .client
            .http_client()
            .get_verified_batch_proofs_by_slot_height(U64::from(height))
            .await?
        {
            Some(proofs) => return Ok(proofs),
            None => sleep(Duration::from_millis(500)).await,
        }
    }
}

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates soft confirmations and wait until it reaches the first commitment.
/// It asserts that the blob inscribe txs have been sent.
/// This catches regression to the default prover flow, such as the one introduced by [#942](https://github.com/chainwayxyz/citrea/pull/942) and [#973](https://github.com/chainwayxyz/citrea/pull/973)
struct BasicProverTest;

#[async_trait]
impl TestCase for BasicProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height + FINALITY_DEPTH,
            Some(Duration::from_secs(120)),
        )
        .await
        .unwrap();

        {
            // print some debug info about state diff
            let state_diff = &proofs[0].proof_output.state_diff;
            let state_diff_size: usize = state_diff
                .iter()
                .map(|(k, v)| k.len() + v.as_ref().map(|v| v.len()).unwrap_or_default())
                .sum();
            let borshed_state_diff = borsh::to_vec(state_diff).unwrap();
            let compressed_state_diff =
                citrea_primitives::compression::compress_blob(&borshed_state_diff);
            println!(
                "StateDiff: size {}, compressed {}",
                state_diff_size,
                compressed_state_diff.len()
            );
        }

        Ok(())
    }
}

#[tokio::test]
async fn basic_prover_test() -> Result<()> {
    TestCaseRunner::new(BasicProverTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

#[derive(Default)]
struct SkipPreprovenCommitmentsTest {
    task_manager: TaskManager<()>,
}

#[async_trait]
impl TestCase for SkipPreprovenCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 1,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let da_config = &f.bitcoin_nodes.get(0).unwrap().config;
        let bitcoin_da_service_config = BitcoinServiceConfig {
            node_url: format!(
                "http://127.0.0.1:{}/wallet/{}",
                da_config.rpc_port,
                NodeKind::Bitcoin
            ),
            node_username: da_config.rpc_user.clone(),
            node_password: da_config.rpc_password.clone(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(
                // This is because the prover has a check to make sure that the commitment was
                // submitted by the sequencer and NOT any other key. Which means that arbitrary keys
                // CANNOT submit preproven commitments.
                // Using the sequencer DA private key means that we simulate the fact that the sequencer
                // somehow resubmitted the same commitment.
                sequencer
                    .config()
                    .rollup
                    .da
                    .da_private_key
                    .as_ref()
                    .unwrap()
                    .clone(),
            ),
            tx_backup_dir: Self::test_config()
                .dir
                .join("tx_backup_dir")
                .display()
                .to_string(),
            monitoring: Default::default(),
            mempool_space_url: None,
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let bitcoin_da_service = Arc::new(
            BitcoinService::new_with_wallet_check(
                bitcoin_da_service_config,
                RollupParams {
                    to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
                    to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );

        self.task_manager
            .spawn(|tk| bitcoin_da_service.clone().run_da_queue(rx, tk));

        // Generate FINALIZED DA block.
        da.generate(FINALITY_DEPTH).await?;

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let _proofs = wait_for_zkproofs(full_node, finalized_height + FINALITY_DEPTH, None)
            .await
            .unwrap();

        // TODO: this test will need refactor
        // assert!(proofs
        //     .first()
        //     .unwrap()
        //     .proof_output
        //     .preproven_commitments
        //     .is_empty());

        // Make sure the mempool is mined.
        da.wait_mempool_len(0, None).await?;

        // Fetch the commitment created from the previous L1 range
        let commitments: Vec<SequencerCommitment> = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height))
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "Failed to get sequencer commitments at {}",
                    finalized_height
                )
            })
            .unwrap_or_else(|| panic!("No sequencer commitments found at {}", finalized_height))
            .into_iter()
            .map(|response| SequencerCommitment {
                merkle_root: response.merkle_root,
                l2_start_block_number: response.l2_start_block_number.to(),
                l2_end_block_number: response.l2_end_block_number.to(),
            })
            .collect();

        // Send the same commitment that was already proven.
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(commitments.first().unwrap().clone()),
                1,
            )
            .await
            .unwrap();

        // Wait for the duplicate commitment transaction to be accepted.
        da.wait_mempool_len(2, None).await?;

        // Trigger a new commitment.
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for the sequencer commitment to be submitted & accepted.
        da.wait_mempool_len(4, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for the full node to see all process verify and store all batch proofs
        full_node.wait_for_l1_height(finalized_height, None).await?;
        let _proofs =
            wait_for_zkproofs(full_node, finalized_height, Some(Duration::from_secs(600)))
                .await
                .unwrap();

        // TODO: this test will need refactor
        // assert_eq!(
        //     proofs
        //         .first()
        //         .unwrap()
        //         .proof_output
        //         .preproven_commitments
        //         .len(),
        //     1
        // );

        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        self.task_manager.abort().await;
        Ok(())
    }
}

#[tokio::test]
async fn prover_skips_preproven_commitments_test() -> Result<()> {
    TestCaseRunner::new(SkipPreprovenCommitmentsTest::default())
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LocalProvingTest;

#[async_trait]
impl TestCase for LocalProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![("BONSAI_API_URL", ""), ("BONSAI_API_KEY", "")],
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Prove,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            // Made this 1 or-else proving takes forever
            min_soft_confirmations_per_commitment: 1,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        // citrea::initialize_logging(tracing::Level::INFO);

        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();
        // Generate soft confirmations to invoke commitment creation
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for commitment tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make commitment tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for batch prover to process the proof
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(7200)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Make batch proof tx into a finalized block
        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;
        // Wait for full node to see zkproofs
        let proofs =
            wait_for_zkproofs(full_node, finalized_height, Some(Duration::from_secs(7200)))
                .await
                .unwrap();

        assert_eq!(proofs.len(), 1);

        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn local_proving_test() -> Result<()> {
    TestCaseRunner::new(LocalProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct ParallelProvingTest;

#[async_trait]
impl TestCase for ParallelProvingTest {
    fn test_env() -> TestCaseEnv {
        TestCaseEnv {
            test: vec![("RISC0_DEV_MODE", "1"), ("PARALLEL_PROOF_LIMIT", "2")],
            ..Default::default()
        }
    }

    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 106,
            mempool_conf: SequencerMempoolConfig {
                max_account_slots: 1000,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        // Invoke 2 sequencer commitments
        for _ in 0..min_soft_confirmations_per_commitment * 2 {
            // 7 txs in each block
            for _ in 0..7 {
                let _ = seq_test_client
                    .send_eth(Address::random(), None, None, None, 100)
                    .await
                    .unwrap();
            }

            sequencer.client.send_publish_batch_request().await?;
        }

        // Wait for 2 commitments (4 txs) to hit DA mempool
        da.wait_mempool_len(4, Some(Duration::from_secs(420)))
            .await?;

        // Write commitments to a finalized DA block
        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Wait until batch prover processes the commitments
        batch_prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(1800)))
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        // Write 2 batch proofs to a finalized DA block
        da.generate(FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        // Retrieve proofs from fullnode
        let proofs = wait_for_zkproofs(full_node, finalized_height, None)
            .await
            .unwrap();
        dbg!(proofs.len());

        Ok(())
    }
}

#[ignore]
#[tokio::test]
async fn parallel_proving_test() -> Result<()> {
    TestCaseRunner::new(ParallelProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct ForkElfSwitchingTest;

#[async_trait]
impl TestCase for ForkElfSwitchingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            with_light_client_prover: true,
            mode: CitreaMode::DevAllForks,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            initial_da_height: 171,
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        let kumquat_height = ForkManager::new(get_forks(), 0)
            .next_fork()
            .unwrap()
            .activation_height;

        // Set just below kumquat height so we can generate first soft com txs in genesis
        // and second batch above kumquat
        SequencerConfig {
            min_soft_confirmations_per_commitment: kumquat_height - 5,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();

        // send evm tx
        let evm_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        let pending_evm_tx = evm_client
            .send_eth(Address::random(), None, None, None, 100)
            .await
            .unwrap();

        let min_soft_confirmations = sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations {
            sequencer.client.send_publish_batch_request().await?;
        }

        // assert that evm tx is mined
        let evm_tx = evm_client
            .eth_get_transaction_by_hash(*pending_evm_tx.tx_hash(), None)
            .await
            .unwrap();

        assert!(evm_tx.block_number.is_some());

        let height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;

        assert_eq!(fork_from_block_number(height).spec_id, SpecId::Genesis);

        // Generate softcom in kumquat
        for _ in 0..min_soft_confirmations {
            sequencer.client.send_publish_batch_request().await?;
        }

        let height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;
        assert_eq!(fork_from_block_number(height).spec_id, SpecId::Kumquat);

        // Generate softcom in fork2
        for _ in 0..min_soft_confirmations {
            sequencer.client.send_publish_batch_request().await?;
        }

        let last_sc_before_fork2 = sequencer
            .client
            .http_client()
            .get_soft_confirmation_by_number(U64::from(199u64))
            .await
            .unwrap()
            .unwrap();

        // the last tx of last soft confirmation before fork2 should be the change authority sov tx
        let last_tx_hex = last_sc_before_fork2
            .clone()
            .txs
            .clone()
            .unwrap()
            .last()
            .expect("should have last tx")
            .clone();

        let tx_vec = last_tx_hex.tx.clone();

        let tx = Transaction::try_from_slice(&tx_vec).expect("Should be the tx");

        let k256_pub_key_sequencer = K256PublicKey::try_from(
            sequencer
                .config()
                .rollup
                .public_keys
                .sequencer_k256_public_key
                .as_slice(),
        )
        .unwrap();

        let address = k256_pub_key_sequencer.to_address::<<DefaultContext as Spec>::Address>();

        // Going to ignore the first byte here because it's the call prefix
        // It is an enum of modules:
        // 0 is accounts,1 is evm, 2 is soft confirmation rule enforcer
        // assert the first byte is 2 as in sc rule enforcer
        assert_eq!(tx.runtime_msg()[0], 2);

        let change_authority_call_message: soft_confirmation_rule_enforcer::CallMessage
        // Going to ignore the first byte here because it's the call prefix as explained above
        = soft_confirmation_rule_enforcer::CallMessage::try_from_slice(&tx.runtime_msg()[1..])
            .expect("Should be the tx");

        match change_authority_call_message {
            soft_confirmation_rule_enforcer::CallMessage::ChangeAuthority { new_authority } => {
                assert_eq!(new_authority, address);
                println!("New authority: {:?}", new_authority);
            }
            _ => panic!("Should be change authority"),
        }

        let height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;
        assert_eq!(fork_from_block_number(height).spec_id, SpecId::Fork2);

        da.wait_mempool_len(6, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(6, None).await?;
        da.generate(FINALITY_DEPTH).await?;

        full_node
            .wait_for_l1_height(finalized_height + FINALITY_DEPTH, None)
            .await?;
        let proofs = wait_for_zkproofs(full_node, finalized_height + FINALITY_DEPTH, None)
            .await
            .unwrap();

        assert_eq!(proofs.len(), 3);
        assert_eq!(
            SpecId::from_u8(
                proofs[0]
                    .proof_output
                    .last_active_spec_id
                    .expect("should have field")
                    .to()
            )
            .expect("should be valid"),
            SpecId::Genesis
        );
        assert_eq!(
            fork_from_block_number(
                proofs[1]
                    .proof_output
                    .last_l2_height
                    .expect("should have field")
                    .to()
            )
            .spec_id,
            SpecId::Kumquat
        );
        assert_eq!(
            fork_from_block_number(proofs[2].proof_output.last_l2_height.unwrap().to()).spec_id,
            SpecId::Fork2
        );

        light_client_prover
            .wait_for_l1_height(finalized_height + FINALITY_DEPTH, None)
            .await?;
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(finalized_height + FINALITY_DEPTH)
            .await
            .unwrap()
            .unwrap();

        assert!(lcp
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        assert_eq!(
            lcp.light_client_proof_output.state_root.to_vec(),
            proofs[2].proof_output.final_state_root
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_fork_elf_switching() -> Result<()> {
    use_network_forks(Network::TestNetworkWithForks);

    TestCaseRunner::new(ForkElfSwitchingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct L1HashOutputTest;

#[async_trait]
impl TestCase for L1HashOutputTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 50,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();

        sequencer.client.send_publish_batch_request().await?;
        let start_l1_height = da.get_finalized_height(None).await?;

        sequencer.client.wait_for_l2_block(1, None).await?;

        da.generate(100).await?;

        tokio::time::sleep(Duration::from_secs(10)).await;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.send_publish_batch_request().await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        // Wait for batch proof tx to hit mempool
        da.wait_mempool_len(2, None).await?;

        let zkp = batch_prover
            .client
            .http_client()
            .get_batch_proofs_by_slot_height(U64::from(finalized_height))
            .await?
            .expect("Should exist");

        assert_eq!(zkp.len(), 1);

        let l1_hashes: Vec<[u8; 32]> = zkp[0]
            .proof_output
            .l1_hashes_added_to_light_client_contract
            .iter()
            .map(|h| h.0)
            .collect();

        assert_eq!(l1_hashes.len(), 101);

        for (height, hash) in (start_l1_height..=start_l1_height + 100).zip(l1_hashes) {
            let hash_from_rpc = sequencer.da.get_block_hash(height).await?;

            assert_eq!(hash_from_rpc.as_raw_hash().to_byte_array(), hash);
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_batch_proof_l1_hashes_added_output() -> Result<()> {
    TestCaseRunner::new(L1HashOutputTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
