use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::utils::parse_ether;
use alloy_primitives::U256;
use anyhow::Context;
use boundless_market::alloy::network::EthereumWallet;
use boundless_market::alloy::primitives::Address;
use boundless_market::alloy::providers::fillers::{FillProvider, JoinFill, WalletFiller};
use boundless_market::alloy::providers::utils::JoinedRecommendedFillers;
use boundless_market::alloy::providers::RootProvider;
use boundless_market::alloy::signers::local::PrivateKeySigner;
use boundless_market::balance_alerts_layer::BalanceAlertProvider;
use boundless_market::client::{Client, ClientBuilder};
use boundless_market::contracts::{Offer, Predicate, ProofRequestBuilder, Requirements};
use boundless_market::input::InputBuilder;
use boundless_market::storage::BuiltinStorageProvider;
use citrea_common::utils::read_env;
use citrea_common::FromEnv;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    compute_image_id, default_executor, AssumptionReceipt, Digest, ExecutorEnvBuilder,
    Groth16Receipt, InnerReceipt, Journal, MaybePruned, Receipt, ReceiptClaim,
};
use sov_db::ledger_db::{BoundlessLedgerOps, LedgerDB};
use sov_db::schema::types::BoundlessSession;
use sov_rollup_interface::zk::{ProofWithJob, ReceiptType};
use tokio::sync::oneshot;
use url::Url;
use uuid::Uuid;

type BoundlessClient = Client<
    FillProvider<
        JoinFill<JoinedRecommendedFillers, WalletFiller<EthereumWallet>>,
        BalanceAlertProvider<RootProvider>,
    >,
    boundless_market::storage::BuiltinStorageProvider,
>;

#[derive(Debug, Clone)]
pub struct BoundlessConfig {
    wallet_private_key: String,
    rpc_url: String,
    boundless_market_address: String,
    set_verifier_address: String,
    order_stream_url: Option<String>,
}

impl citrea_common::FromEnv for BoundlessConfig {
    fn from_env() -> anyhow::Result<Self> {
        let wallet_private_key = read_env("BOUNDLESS_WALLET_PRIVATE_KEY")?;
        let rpc_url = read_env("BOUNDLESS_RPC_URL")?;
        let boundless_market_address = read_env("BOUNDLESS_MARKET_ADDRESS")?;
        let set_verifier_address = read_env("BOUNDLESS_SET_VERIFIER_ADDRESS")?;
        let order_stream_url = read_env("BOUNDLESS_ORDER_STREAM_URL").ok();

        Ok(Self {
            wallet_private_key,
            rpc_url,
            boundless_market_address,
            set_verifier_address,
            order_stream_url,
        })
    }
}

#[derive(Clone)]
pub struct BoundlessProver {
    pub client: BoundlessClient,
    pub ledger_db: LedgerDB,
}

impl BoundlessProver {
    pub async fn new(ledger_db: LedgerDB) -> Self {
        let client = Self::boundless_client()
            .await
            .expect("Failed to create boundless client");

        assert!(
            client.storage_provider.is_some(),
            "a storage provider is required to upload the zkVM guest ELF"
        );
        Self { client, ledger_db }
    }

    async fn boundless_client() -> anyhow::Result<BoundlessClient> {
        let config = BoundlessConfig::from_env().expect("Failed to load boundless config");

        let local_signer = PrivateKeySigner::from_str(&config.wallet_private_key)
            .context("Failed to parse wallet private key")?;

        // If in dev mode, uses a temporary file as storage provider
        // Otherwise first tries to parse pinata env variables
        // If fails then tries to parse s3 env variables
        // If the environment variable `RISC0_DEV_MODE` is set, a temporary file storage provider is used.
        // Otherwise, the following environment variables are checked in order:
        // - `PINATA_JWT`, `PINATA_API_URL`, `IPFS_GATEWAY_URL`: Pinata storage provider;
        // - `S3_ACCESS`, `S3_SECRET`, `S3_BUCKET`, `S3_URL`, `AWS_REGION`: S3 storage provider.
        let storage_provider = BuiltinStorageProvider::from_env().await.ok();

        // Create a Boundless client from the provided parameters.
        let boundless_client = ClientBuilder::new()
            .with_rpc_url(Url::parse(&config.rpc_url).expect("Invalid RPC URL"))
            .with_boundless_market_address(
                Address::from_str(&config.boundless_market_address).unwrap(),
            )
            .with_set_verifier_address(Address::from_str(&config.set_verifier_address).unwrap())
            .with_order_stream_url(
                config
                    .order_stream_url
                    .and_then(|url| Url::parse(&url).ok()),
            )
            .with_storage_provider(storage_provider)
            .with_private_key(local_signer.clone())
            .build()
            .await?;

        Ok(boundless_client)
    }

    pub async fn prove(
        &self,
        job_id: Uuid,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        // Upload image id
        let image_id = compute_image_id(&elf).expect("Invalid elf program");

        assert!(!risc0_zkvm::is_dev_mode(), "Boundless should not be run with dev mode as provers do not accept fake receipt requests" );

        assert!(
            matches!(receipt_type, ReceiptType::Groth16),
            "Currently, only Groth16 receipts are supported for boundless"
        );

        let image_url = self.client.upload_program(&elf).await?;
        tracing::info!("Image URL: {}", image_url);

        // move non-Send logic to blocking thread
        // I had to do this because the executor env builder is not Send
        let (guest_env_bytes, journal, mcycles_count) = tokio::task::spawn_blocking({
            let elf = elf.clone(); // clone since we move into thread
            let input = input.clone();
            let assumptions = assumptions.clone();

            move || -> anyhow::Result<(Vec<u8>, Journal, u64)> {
                let mut env = ExecutorEnvBuilder::default();
                for assumption in assumptions {
                    env.add_assumption(assumption);
                }
                let env = env.write_slice(&input).build()?;

                let session_info = default_executor().execute(env, &elf)?;

                let total_cycles_approx = session_info
                    .segments
                    .iter()
                    .map(|segment| 1 << segment.po2)
                    .sum::<u64>();
                let mcycles_count = total_cycles_approx.div_ceil(1_000_000);
                tracing::info!(
                    "Boundless proving session with job id: {} takes {} cycles",
                    job_id,
                    total_cycles_approx
                );

                let input_builder = InputBuilder::new().write_slice(&input);
                let guest_env = input_builder.build_env()?;
                let bytes = guest_env.encode()?.to_vec();

                Ok((bytes, session_info.journal, mcycles_count))
            }
        })
        .await??;
        // Upload input
        let input_url = self.client.upload_input(&guest_env_bytes.clone()).await?;
        tracing::info!("Uploaded input to {}", input_url);

        let request = ProofRequestBuilder::new()
            .with_image_url(image_url.to_string())
            .with_input(input_url.clone())
            .with_requirements(
                Requirements::new(image_id, Predicate::digest_match(journal.clone().digest()))
                    .with_groth16_proof(),
            )
            .with_offer(
                Offer::default()
                    // TODO: Get this from config maybe? or dynamically fetch from some 3rd party api
                    .with_min_price_per_mcycle(parse_ether("0.00001")?, mcycles_count)
                    .with_max_price_per_mcycle(parse_ether("0.005")?, mcycles_count)
                    .with_timeout(1000)
                    .with_lock_timeout(500)
                    .with_ramp_up_period(100),
            )
            .build()
            .unwrap();

        // Start boundless proving session
        let (req_id, request_expiry) = match self.client.offchain_client {
            Some(_) => {
                let (req_id, exp) = self.client.submit_request_offchain(&request).await?;
                tracing::info!("Request submitted to offchain boundless service");
                (req_id.to_string(), exp)
            }
            None => {
                let (req_id, exp) = self.client.submit_request(&request).await?;
                tracing::info!("Request submitted to onchain boundless service");
                (req_id.to_string(), exp)
            }
        };

        tracing::info!(
            "Started boundless proving session, job_id={} request_id={}",
            job_id,
            req_id
        );

        let db_session = BoundlessSession {
            request_id: req_id.clone(),
            request_expiry,
            image_id: image_id.into(),
            receipt_type,
        };
        self.ledger_db
            .upsert_pending_boundless_session(job_id, db_session)
            .context("Failed to upsert boundless session")?;

        let rx = self
            .spawn_handler(job_id, req_id, image_id, request_expiry)
            .await;

        Ok(rx)
    }

    async fn spawn_handler(
        &self,
        job_id: Uuid,
        request_id: String,
        image_id: Digest,
        request_expiry: u64,
    ) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            match this.handle_session(request_id.clone(), image_id, request_expiry).await {
                Ok(receipt) => {
                    let serialized_receipt = bincode::serialize(&receipt.inner).expect("Receipt serialization cannot fail");

                    let Ok(_) = tx.send(ProofWithJob {
                        job_id,
                        proof: serialized_receipt,
                    })else {
                        tracing::error!("Boundless proof receiver channel is closed");
                        return;
                    };


                    if let Err(e) = this.ledger_db.remove_pending_boundless_session(job_id) {
                        tracing::error!(
                            "Failed to remove pending boundless session job: {} err={}",
                            job_id, e
                        );
                    }
                    tracing::info!(
                        "Boundless proving job finished: {} | Boundless request id: {}",
                        job_id, request_id
                    );

                }
                Err(e)=>tracing::error!(
                    "Failed to handle Boundless proving session job: {} | Boundless request id: {} | err={}",
                    job_id, request_id, e
                ),
            }
        });

        rx
    }

    async fn handle_session(
        &self,
        request_id: String,
        image_id: Digest,
        request_expiry: u64,
    ) -> anyhow::Result<Receipt> {
        let (journal, seal) = self
            .client
            .wait_for_request_fulfillment(
                U256::from_str(&request_id).unwrap(),
                Duration::from_secs(5),
                request_expiry,
            )
            .await?;

        let claim = ReceiptClaim::ok(image_id, journal.clone().to_vec());

        // The first 4 bytes of the seal are reserved for metadata; the actual data starts at index 4.
        const SEAL_DATA_OFFSET: usize = 4;
        let inner = InnerReceipt::Groth16(Groth16Receipt::new(
            seal.clone().0.to_vec()[SEAL_DATA_OFFSET..].to_vec(),
            MaybePruned::Value(claim),
            risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
        ));
        let full_snark_receipt = Receipt::new(inner, journal.to_vec());
        full_snark_receipt.verify(image_id).unwrap();

        Ok(full_snark_receipt)
    }

    // Starts the recovery of proving jobs from db by starting a background task, returning list of
    /// receiver channels that return the associated job id and proof result on finish.
    pub async fn start_recovery(&self) -> anyhow::Result<Vec<oneshot::Receiver<ProofWithJob>>> {
        let sessions = self.ledger_db.get_pending_boundless_sessions()?;
        if sessions.is_empty() {
            return Ok(vec![]);
        }

        let mut rxs = vec![];
        for (job_id, session) in sessions {
            tracing::info!(
                "Recovering boundless session, job_id={} session={:?}",
                job_id,
                session
            );

            let rx = self
                .spawn_handler(
                    job_id,
                    session.request_id,
                    session.image_id.into(),
                    session.request_expiry,
                )
                .await;
            rxs.push(rx);
        }
        Ok(rxs)
    }
}
