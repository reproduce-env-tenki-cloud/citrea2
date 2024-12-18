use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
mod bitcoin;
mod prover;
mod rollup;
pub use bitcoin::*;
pub use prover::ProverGuestRunConfig;
pub use rollup::*;

/// Telemetry configuration.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Server host.
    pub bind_host: Option<String>,
    /// Server port.
    pub bind_port: Option<u16>,
}

impl FromEnv for TelemetryConfig {
    fn from_env() -> anyhow::Result<Self> {
        let bind_host = std::env::var("TELEMETRY_BIND_HOST").ok();
        let bind_port = std::env::var("TELEMETRY_BIND_PORT").ok();
        Ok(Self {
            bind_host,
            bind_port: bind_port.map(|p| p.parse()).transpose()?,
        })
    }
}

pub trait FromEnv: Sized {
    fn from_env() -> anyhow::Result<Self>;
}

/// A configuration type to define the behaviour of the pruner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PruningConfig {
    /// Defines the number of blocks from the tip of the chain to remove.
    pub distance: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self { distance: 256 }
    }
}

impl FromEnv for PruningConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(PruningConfig {
            distance: std::env::var("PRUNING_DISTANCE")?.parse()?,
        })
    }
}

#[cfg(feature = "mock")]
/// The configuration for mock da
#[derive(Debug, Clone, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MockDaConfig {
    /// The address to use to "submit" blobs on the mock da layer
    pub sender_address: sov_mock_da::MockAddress,
    /// The path in which DA db is stored
    pub db_path: PathBuf,
}

#[cfg(feature = "mock")]
impl FromEnv for MockDaConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            sender_address: std::env::var("SENDER_ADDRESS")?.parse()?,
            db_path: std::env::var("DB_PATH")?.into(),
        })
    }
}

/// Prover configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BatchProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// If true prover will try to recover ongoing proving sessions
    pub enable_recovery: bool,
}

/// Prover configuration
///
/// TODO: leaving as the same with batch prover config for now
/// but it will most probably have different fields in the future
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct LightClientProverConfig {
    /// Prover run mode
    pub proving_mode: ProverGuestRunConfig,
    /// Average number of commitments to prove
    pub proof_sampling_number: usize,
    /// If true prover will try to recover ongoing proving sessions
    pub enable_recovery: bool,
    /// The starting DA block to sync from
    pub initial_da_height: u64,
}

impl Default for BatchProverConfig {
    fn default() -> Self {
        Self {
            proving_mode: ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
        }
    }
}

impl Default for LightClientProverConfig {
    fn default() -> Self {
        Self {
            proving_mode: ProverGuestRunConfig::Execute,
            proof_sampling_number: 0,
            enable_recovery: true,
            initial_da_height: 1,
        }
    }
}

impl FromEnv for BatchProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(BatchProverConfig {
            proving_mode: serde_json::from_str(&format!("\"{}\"", std::env::var("PROVING_MODE")?))?,
            proof_sampling_number: std::env::var("PROOF_SAMPLING_NUMBER")?.parse()?,
            enable_recovery: std::env::var("ENABLE_RECOVERY")?.parse()?,
        })
    }
}

impl FromEnv for LightClientProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(LightClientProverConfig {
            proving_mode: serde_json::from_str(&format!("\"{}\"", std::env::var("PROVING_MODE")?))?,
            proof_sampling_number: std::env::var("PROOF_SAMPLING_NUMBER")?.parse()?,
            enable_recovery: std::env::var("ENABLE_RECOVERY")?.parse()?,
            initial_da_height: std::env::var("INITIAL_DA_HEIGHT")?.parse()?,
        })
    }
}

/// Reads toml file as a specific type.
pub fn from_toml_path<P: AsRef<Path>, R: DeserializeOwned>(path: P) -> anyhow::Result<R> {
    let mut contents = String::new();
    {
        let mut file = File::open(path)?;
        file.read_to_string(&mut contents)?;
    }
    tracing::debug!("Config file size: {} bytes", contents.len());
    tracing::trace!("Config file contents: {}", &contents);

    let result: R = toml::from_str(&contents)?;

    Ok(result)
}

/// Rollup Configuration
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SequencerConfig {
    /// Private key of the sequencer
    pub private_key: String,
    /// Min. soft confirmaitons for sequencer to commit
    pub min_soft_confirmations_per_commitment: u64,
    /// Whether or not the sequencer is running in test mode
    pub test_mode: bool,
    /// Limit for the number of deposit transactions to be included in the block
    pub deposit_mempool_fetch_limit: usize,
    /// Sequencer specific mempool config
    pub mempool_conf: SequencerMempoolConfig,
    /// DA layer update loop interval in ms
    pub da_update_interval_ms: u64,
    /// Block production interval in ms
    pub block_production_interval_ms: u64,
}

impl Default for SequencerConfig {
    fn default() -> Self {
        SequencerConfig {
            private_key: "1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            min_soft_confirmations_per_commitment: 4,
            test_mode: true,
            deposit_mempool_fetch_limit: 10,
            block_production_interval_ms: 100,
            da_update_interval_ms: 100,
            mempool_conf: Default::default(),
        }
    }
}

impl FromEnv for SequencerConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            private_key: std::env::var("PRIVATE_KEY")?,
            min_soft_confirmations_per_commitment: std::env::var(
                "MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT",
            )?
            .parse()?,
            test_mode: std::env::var("TEST_MODE")?.parse()?,
            deposit_mempool_fetch_limit: std::env::var("DEPOSIT_MEMPOOL_FETCH_LIMIT")?.parse()?,
            mempool_conf: SequencerMempoolConfig::from_env()?,
            da_update_interval_ms: std::env::var("DA_UPDATE_INTERVAL_MS")?.parse()?,
            block_production_interval_ms: std::env::var("BLOCK_PRODUCTION_INTERVAL_MS")?.parse()?,
        })
    }
}

/// Mempool Config for the sequencer
/// Read: https://github.com/ledgerwatch/erigon/wiki/Transaction-Pool-Design
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct SequencerMempoolConfig {
    /// Max number of transactions in the pending sub-pool
    pub pending_tx_limit: u64,
    /// Max megabytes of transactions in the pending sub-pool
    pub pending_tx_size: u64,
    /// Max number of transactions in the queued sub-pool
    pub queue_tx_limit: u64,
    /// Max megabytes of transactions in the queued sub-pool
    pub queue_tx_size: u64,
    /// Max number of transactions in the base-fee sub-pool
    pub base_fee_tx_limit: u64,
    /// Max megabytes of transactions in the base-fee sub-pool
    pub base_fee_tx_size: u64,
    /// Max number of executable transaction slots guaranteed per account
    pub max_account_slots: u64,
}

impl Default for SequencerMempoolConfig {
    fn default() -> Self {
        Self {
            pending_tx_limit: 100000,
            pending_tx_size: 200,
            queue_tx_limit: 100000,
            queue_tx_size: 200,
            base_fee_tx_limit: 100000,
            base_fee_tx_size: 200,
            max_account_slots: 16,
        }
    }
}

impl FromEnv for SequencerMempoolConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            pending_tx_limit: std::env::var("PENDING_TX_LIMIT")?.parse()?,
            pending_tx_size: std::env::var("PENDING_TX_SIZE")?.parse()?,
            queue_tx_limit: std::env::var("QUEUE_TX_LIMIT")?.parse()?,
            queue_tx_size: std::env::var("QUEUE_TX_SIZE")?.parse()?,
            base_fee_tx_limit: std::env::var("BASE_FEE_TX_LIMIT")?.parse()?,
            base_fee_tx_size: std::env::var("BASE_FEE_TX_SIZE")?.parse()?,
            max_account_slots: std::env::var("MAX_ACCOUNT_SLOTS")?.parse()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::rollup::*;
    use super::*;

    fn create_config_from(content: &str) -> NamedTempFile {
        let mut config_file = NamedTempFile::new().unwrap();
        config_file.write_all(content.as_bytes()).unwrap();
        config_file
    }

    #[test]
    fn test_correct_rollup_config() {
        let config =
            r#"
            [public_keys]
            sequencer_public_key = "0000000000000000000000000000000000000000000000000000000000000000"
            sequencer_da_pub_key = "7777777777777777777777777777777777777777777777777777777777777777"
            prover_da_pub_key = ""

            [rpc]
            bind_host = "127.0.0.1"
            bind_port = 12345
            max_connections = 500
            enable_subscriptions = true
            max_subscriptions_per_connection = 200

            [da]
            sender_address = "0000000000000000000000000000000000000000000000000000000000000000"
            db_path = "/tmp/da"

            [storage]
            path = "/tmp/rollup"
            db_max_open_files = 123

            [runner]
            include_tx_body = true
            sequencer_client_url = "http://0.0.0.0:12346"

            [telemetry]
            bind_host = "0.0.0.0"
            bind_port = 8001
        "#.to_owned();

        let config_file = create_config_from(&config);

        let config: FullNodeConfig<crate::MockDaConfig> =
            from_toml_path(config_file.path()).unwrap();

        let expected = FullNodeConfig {
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_owned(),
                include_tx_body: true,
                sync_blocks_count: 10,
                pruning_config: None,
            }),
            da: crate::MockDaConfig {
                sender_address: [0; 32].into(),
                db_path: "/tmp/da".into(),
            },
            storage: StorageConfig {
                path: "/tmp/rollup".into(),
                db_max_open_files: Some(123),
            },
            rpc: RpcConfig {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 12345,
                max_connections: 500,
                max_request_body_size: 10 * 1024 * 1024,
                max_response_body_size: 10 * 1024 * 1024,
                batch_requests_limit: 50,
                enable_subscriptions: true,
                max_subscriptions_per_connection: 200,
            },
            public_keys: RollupPublicKeys {
                sequencer_public_key: vec![0; 32],
                sequencer_da_pub_key: vec![119; 32],
                prover_da_pub_key: vec![],
            },
            telemetry: TelemetryConfig {
                bind_host: Some("0.0.0.0".to_owned()),
                bind_port: Some(8001),
            },
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn test_correct_prover_config() {
        let config = r#"
            proving_mode = "skip"
            proof_sampling_number = 500
            enable_recovery = true
        "#;

        let config_file = create_config_from(config);

        let config: BatchProverConfig = from_toml_path(config_file.path()).unwrap();
        let expected = BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            enable_recovery: true,
        };
        assert_eq!(config, expected);
    }
    #[test]
    fn test_correct_sequencer_config() {
        let config = r#"
            private_key = "1212121212121212121212121212121212121212121212121212121212121212"
            min_soft_confirmations_per_commitment = 123
            test_mode = false
            deposit_mempool_fetch_limit = 10
            da_update_interval_ms = 1000
            block_production_interval_ms = 1000
            [mempool_conf]
            pending_tx_limit = 100000
            pending_tx_size = 200
            queue_tx_limit = 100000
            queue_tx_size = 200
            base_fee_tx_limit = 100000
            base_fee_tx_size = 200
            max_account_slots = 16
        "#;

        let config_file = create_config_from(config);

        let config: SequencerConfig = from_toml_path(config_file.path()).unwrap();

        let expected = SequencerConfig {
            private_key: "1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            min_soft_confirmations_per_commitment: 123,
            test_mode: false,
            deposit_mempool_fetch_limit: 10,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 100000,
                pending_tx_size: 200,
                queue_tx_limit: 100000,
                queue_tx_size: 200,
                base_fee_tx_limit: 100000,
                base_fee_tx_size: 200,
                max_account_slots: 16,
            },
            da_update_interval_ms: 1000,
            block_production_interval_ms: 1000,
        };
        assert_eq!(config, expected);
    }

    #[test]
    fn test_correct_prover_config_from_env() {
        std::env::set_var("PROVING_MODE", "skip");
        std::env::set_var("PROOF_SAMPLING_NUMBER", "500");
        std::env::set_var("ENABLE_RECOVERY", "true");

        let prover_config = BatchProverConfig::from_env().unwrap();

        let expected = BatchProverConfig {
            proving_mode: ProverGuestRunConfig::Skip,
            proof_sampling_number: 500,
            enable_recovery: true,
        };
        assert_eq!(prover_config, expected);
    }
    #[test]
    fn test_correct_sequencer_config_from_env() {
        std::env::set_var(
            "PRIVATE_KEY",
            "1212121212121212121212121212121212121212121212121212121212121212",
        );
        std::env::set_var("MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT", "123");
        std::env::set_var("TEST_MODE", "false");
        std::env::set_var("DEPOSIT_MEMPOOL_FETCH_LIMIT", "10");
        std::env::set_var("DA_UPDATE_INTERVAL_MS", "1000");
        std::env::set_var("BLOCK_PRODUCTION_INTERVAL_MS", "1000");
        std::env::set_var("PENDING_TX_LIMIT", "100000");
        std::env::set_var("PENDING_TX_SIZE", "200");
        std::env::set_var("QUEUE_TX_LIMIT", "100000");
        std::env::set_var("QUEUE_TX_SIZE", "200");
        std::env::set_var("BASE_FEE_TX_LIMIT", "100000");
        std::env::set_var("BASE_FEE_TX_SIZE", "200");
        std::env::set_var("MAX_ACCOUNT_SLOTS", "16");

        let sequencer_config = SequencerConfig::from_env().unwrap();

        let expected = SequencerConfig {
            private_key: "1212121212121212121212121212121212121212121212121212121212121212"
                .to_string(),
            min_soft_confirmations_per_commitment: 123,
            test_mode: false,
            deposit_mempool_fetch_limit: 10,
            mempool_conf: SequencerMempoolConfig {
                pending_tx_limit: 100000,
                pending_tx_size: 200,
                queue_tx_limit: 100000,
                queue_tx_size: 200,
                base_fee_tx_limit: 100000,
                base_fee_tx_size: 200,
                max_account_slots: 16,
            },
            da_update_interval_ms: 1000,
            block_production_interval_ms: 1000,
        };
        assert_eq!(sequencer_config, expected);
    }

    #[test]
    fn test_correct_full_node_config_from_env() {
        std::env::set_var(
            "SEQUENCER_PUBLIC_KEY",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var(
            "SEQUENCER_DA_PUB_KEY",
            "7777777777777777777777777777777777777777777777777777777777777777",
        );
        std::env::set_var("PROVER_DA_PUB_KEY", "");

        std::env::set_var("RPC_BIND_HOST", "127.0.0.1");
        std::env::set_var("RPC_BIND_PORT", "12345");
        std::env::set_var("RPC_MAX_CONNECTIONS", "500");
        std::env::set_var("RPC_ENABLE_SUBSCRIPTIONS", "true");
        std::env::set_var("RPC_MAX_SUBSCRIPTIONS_PER_CONNECTION", "200");

        std::env::set_var(
            "SENDER_ADDRESS",
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var("DB_PATH", "/tmp/da");

        std::env::set_var("STORAGE_PATH", "/tmp/rollup");
        std::env::set_var("DB_MAX_OPEN_FILES", "123");

        std::env::set_var("INCLUDE_TX_BODY", "true");
        std::env::set_var("SEQUENCER_CLIENT_URL", "http://0.0.0.0:12346");
        std::env::set_var("PRUNING_DISTANCE", "1000");

        std::env::set_var("TELEMETRY_BIND_HOST", "0.0.0.0");
        std::env::set_var("TELEMETRY_BIND_PORT", "8082");
        let full_node_config: FullNodeConfig<crate::MockDaConfig> =
            FullNodeConfig::from_env().unwrap();

        let expected = FullNodeConfig {
            rpc: RpcConfig {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 12345,
                max_connections: 500,
                max_request_body_size: default_max_request_body_size(),
                max_response_body_size: default_max_response_body_size(),
                batch_requests_limit: default_batch_requests_limit(),
                enable_subscriptions: true,
                max_subscriptions_per_connection: 200,
            },
            storage: StorageConfig {
                path: "/tmp/rollup".into(),
                db_max_open_files: Some(123),
            },
            runner: Some(RunnerConfig {
                sequencer_client_url: "http://0.0.0.0:12346".to_string(),
                include_tx_body: true,
                sync_blocks_count: default_sync_blocks_count(),
                pruning_config: Some(PruningConfig { distance: 1000 }),
            }),
            da: crate::MockDaConfig {
                sender_address: [0; 32].into(),
                db_path: "/tmp/da".into(),
            },
            public_keys: RollupPublicKeys {
                sequencer_public_key: vec![0; 32],
                sequencer_da_pub_key: vec![119; 32],
                prover_da_pub_key: vec![],
            },
            telemetry: TelemetryConfig {
                bind_host: Some("0.0.0.0".to_owned()),
                bind_port: Some(8082),
            },
        };
        assert_eq!(full_node_config, expected);
    }

    #[test]
    fn test_optional_telemetry_config_from_env() {
        let telemetry_config = TelemetryConfig::from_env().unwrap();

        let expected = TelemetryConfig {
            bind_host: None,
            bind_port: None,
        };
        assert_eq!(telemetry_config, expected);

        std::env::set_var("TELEMETRY_BIND_HOST", "0.0.0.0");
        std::env::set_var("TELEMETRY_BIND_PORT", "5000");
        let telemetry_config = TelemetryConfig::from_env().unwrap();

        let expected = TelemetryConfig {
            bind_host: Some("0.0.0.0".to_owned()),
            bind_port: Some(5000),
        };
        assert_eq!(telemetry_config, expected);
    }
}
