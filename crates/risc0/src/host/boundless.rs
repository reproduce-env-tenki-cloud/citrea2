use std::str::FromStr;

use alloy_primitives::utils::{format_units, parse_ether};
use alloy_primitives::U256;
use boundless_market::alloy::primitives::Address;
use boundless_market::alloy::signers::local::PrivateKeySigner;
use boundless_market::alloy::sol_types::SolValue;
use boundless_market::client::{Client, ClientBuilder};
use boundless_market::contracts::{Input, Offer, Predicate, ProofRequestBuilder, Requirements};
use boundless_market::input::InputBuilder;
use boundless_market::storage::StorageProviderConfig;
use risc0_zkvm::{
    compute_image_id, default_executor, Groth16Receipt, InnerReceipt, MaybePruned, Receipt,
    ReceiptClaim,
};
use sov_db::ledger_db::LedgerDB;
use url::Url;

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

impl BoundlessProver {
    pub async fn new(ledger_db: LedgerDB, network: BoundlessNetwork) -> Self {
        // TODO: Better config management
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
}
