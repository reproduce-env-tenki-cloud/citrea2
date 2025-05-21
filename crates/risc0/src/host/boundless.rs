use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::utils::{format_units, parse_ether};
use alloy_primitives::U256;
use boundless_market::alloy::primitives::Address;
use boundless_market::alloy::signers::local::PrivateKeySigner;
use boundless_market::alloy::sol_types::SolValue;
use boundless_market::client::{Client, ClientBuilder};
use boundless_market::contracts::{Input, Offer, Predicate, ProofRequestBuilder, Requirements};
use boundless_market::input::InputBuilder;
use boundless_market::storage::StorageProviderConfig;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    compute_image_id, default_executor, AssumptionReceipt, Digest, ExecutorEnvBuilder,
    Groth16Receipt, InnerReceipt, MaybePruned, Receipt, ReceiptClaim,
};
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{ProofWithJob, ReceiptType};
use tokio::sync::oneshot;
use url::Url;
use uuid::Uuid;

type BoundlessClient = Client<
    boundless_market::alloy::providers::fillers::FillProvider<
        boundless_market::alloy::providers::fillers::JoinFill<
            boundless_market::alloy::providers::fillers::JoinFill<
                boundless_market::alloy::providers::Identity,
                boundless_market::alloy::providers::fillers::JoinFill<
                    boundless_market::alloy::providers::fillers::GasFiller,
                    boundless_market::alloy::providers::fillers::JoinFill<
                        boundless_market::alloy::providers::fillers::BlobGasFiller,
                        boundless_market::alloy::providers::fillers::JoinFill<
                            boundless_market::alloy::providers::fillers::NonceFiller,
                            boundless_market::alloy::providers::fillers::ChainIdFiller,
                        >,
                    >,
                >,
            >,
            boundless_market::alloy::providers::fillers::WalletFiller<
                boundless_market::alloy::network::EthereumWallet,
            >,
        >,
        boundless_market::balance_alerts_layer::BalanceAlertProvider<
            boundless_market::alloy::providers::RootProvider,
        >,
    >,
    boundless_market::storage::BuiltinStorageProvider,
>;

#[derive(Clone, Debug)]
pub enum BoundlessNetwork {
    Offchain,
    Onchain,
}

#[derive(Clone)]
pub struct BoundlessProver {
    pub client: BoundlessClient,
    pub signer: PrivateKeySigner,
    pub network: BoundlessNetwork,
    pub ledger_db: LedgerDB,
}

// TODO: Impl recovery
impl BoundlessProver {
    pub async fn new(ledger_db: LedgerDB, network: BoundlessNetwork) -> Self {
        // TODO: Better config management
        // TODO: Copy some logic from boundless/examples/composition/apps/src/main.rs
        let wallet_private_key = std::env::var("WALLET_PRIVATE_KEY").unwrap();
        let rpc_url = std::env::var("RPC_URL").unwrap();
        let boundless_market_address = std::env::var("BOUNDLESS_MARKET_ADDRESS").unwrap();
        let set_verifier_address = std::env::var("SET_VERIFIER_ADDRESS").unwrap();
        let order_stream_url = std::env::var("ORDER_STREAM_URL").unwrap();
        let pinata_jwt = std::env::var("PINATA_JWT").unwrap();
        let pinata_api_url = std::env::var("PINATA_API_URL").unwrap();
        let pinata_ipfs_gateway = std::env::var("PINATA_IPFS_GATEWAY").unwrap();

        let local_signer = PrivateKeySigner::from_str(&wallet_private_key).unwrap();

        let storage_provider_config = StorageProviderConfig {
            storage_provider: boundless_market::storage::StorageProviderType::Pinata,
            s3_access_key: None,
            s3_secret_key: None,
            s3_bucket: None,
            s3_url: None,
            s3_use_presigned: None,
            aws_region: None,
            pinata_jwt: Some(pinata_jwt),
            pinata_api_url: Some(Url::parse(&pinata_api_url).unwrap()),
            ipfs_gateway_url: Some(Url::parse(&pinata_ipfs_gateway).unwrap()),
            file_path: None,
        };

        let offchain = match network {
            BoundlessNetwork::Offchain => true,
            BoundlessNetwork::Onchain => false,
        };

        // Create a Boundless client from the provided parameters.
        let boundless_client = ClientBuilder::new()
            .with_rpc_url(Url::parse(&rpc_url).expect("Invalid RPC URL"))
            .with_boundless_market_address(Address::from_str(&boundless_market_address).unwrap())
            .with_set_verifier_address(Address::from_str(&set_verifier_address).unwrap())
            .with_order_stream_url(if offchain {
                Url::parse(&order_stream_url).ok()
            } else {
                None
            })
            .with_storage_provider_config(Some(storage_provider_config))
            .await
            .unwrap()
            .with_private_key(local_signer.clone())
            .build()
            .await
            .unwrap();

        assert!(
            boundless_client.storage_provider.is_some(),
            "a storage provider is required to upload the zkVM guest ELF"
        );
        Self {
            client: boundless_client,
            signer: local_signer,
            network,
            ledger_db,
        }
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

        // TODO: Store this in the ledger db
        let image_url = self.client.upload_program(&elf).await?;
        tracing::info!("Image URL: {}", image_url);

        let mut env = ExecutorEnvBuilder::default();
        for assumption in assumptions {
            env.add_assumption(assumption);
        }

        let env = env.write_slice(&input).build().unwrap();

        let session_info = default_executor().execute(env, &elf)?;

        let total_cycles_approx = session_info
            .segments
            .iter()
            .map(|segment| 1 << segment.po2)
            .sum::<u64>();
        let mcycles_count = total_cycles_approx.div_ceil(1_000_000);
        let journal = session_info.journal;

        tracing::info!(
            "Boundless proving session with job id: {} takes {} cycles",
            job_id,
            total_cycles_approx
        );

        let input_builder = InputBuilder::new().write_slice(&input);
        let guest_env = input_builder.clone().build_env()?;
        let guest_env_bytes = guest_env.encode()?.to_vec();
        // Upload input
        let input_url = self.client.upload_input(&guest_env_bytes.clone()).await?;
        // tracing::info!("Uploaded input to {}", input_url);

        // let request = ProofRequestBuilder::new()
        //     .with_image_url(image_url.to_string())
        //     .with_input(input_url.clone())
        //     .with_requirements(
        //         Requirements::new(image_id, Predicate::digest_match(journal.clone().digest()))
        //             .with_groth16_proof(),
        //     )
        //     .with_offer(
        //         Offer::default()
        //             // TODO: Get this from config maybe?
        //             .with_min_price_per_mcycle(parse_ether("0.001")?, mcycles_count)
        //             .with_max_price_per_mcycle(parse_ether("0.05")?, mcycles_count)
        //             .with_timeout(1000)
        //             .with_lock_timeout(500)
        //             .with_ramp_up_period(100),
        //     )
        //     .build()
        //     .unwrap();

        // // Start boundless proving session
        // let (req_id, request_expiry) = match self.network {
        //     BoundlessNetwork::Offchain => {
        //         let req_id = self.client.submit_request_offchain(&request).await?;
        //         tracing::info!("Request submitted to offchain boundless service");
        //         (req_id.0.to_string(), req_id.1)
        //     }
        //     BoundlessNetwork::Onchain => {
        //         let req_id = self.client.submit_request(&request).await?;
        //         tracing::info!("Request submitted to onchain boundless service");
        //         (req_id.0.to_string(), req_id.1)
        //     }
        // };
        // tracing::info!(
        //     "Started boundless proving session, job_id={} request_id={}",
        //     job_id,
        //     req_id
        // );

        // // TODO: Handle db stuff
        // // let db_session = BonsaiSession {
        // //     kind: BonsaiSessionKind::StarkSession(session.uuid.clone()),
        // //     image_id: image_id.into(),
        // //     receipt_type,
        // // };
        // // self.ledger_db
        // //     .upsert_pending_bonsai_session(job_id, db_session)
        // //     .context("Failed to upsert bonsai stark session")?;

        // let rx = self
        //     .spawn_handler(job_id, req_id, image_id, receipt_type, request_expiry)
        //     .await;

        let (tx, rx) = oneshot::channel();

        Ok(rx)

        // Upload assumptions
    }

    async fn spawn_handler(
        &self,
        job_id: Uuid,
        request_id: String,
        image_id: Digest,
        receipt_type: ReceiptType,
        request_expiry: u64,
    ) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            match this.handle_session(job_id, request_id.clone(), image_id, receipt_type, request_expiry).await {
                Ok(receipt) => {
                    let serialized_receipt = bincode::serialize(&receipt.inner).expect("Receipt serialization cannot fail");

                    let Ok(_) = tx.send(ProofWithJob {
                        job_id,
                        proof: serialized_receipt,
                    })else {
                        tracing::error!("Boundless proof receiver channel is closed");
                        return;
                    };

                    // TODO: Handle ledger db session handling stuff
                    // if let Err(e) = this.ledger_db.remove_pending_bonsai_session(job_id) {
                    //     error!(
                    //         "Failed to remove pending bonsai session job: {} err={}",
                    //         job_id, e
                    //     );
                    // }

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
        job_id: Uuid,
        request_id: String,
        image_id: Digest,
        receipt_type: ReceiptType,
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
        let inner = InnerReceipt::Groth16(Groth16Receipt::new(
            seal.clone().0.to_vec()[4..].to_vec(),
            MaybePruned::Value(claim),
            risc0_zkvm::Groth16ReceiptVerifierParameters::default().digest(),
        ));
        let full_snark_receipt = Receipt::new(inner, journal.to_vec());
        full_snark_receipt.verify(image_id).unwrap();

        Ok(full_snark_receipt)
    }
}
