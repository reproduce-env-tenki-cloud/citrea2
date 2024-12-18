use serde::{Deserialize, Serialize};

const DEFAULT_CHECK_INTERVAL: u64 = 60;
const DEFAULT_HISTORY_LIMIT: usize = 1_000; // Keep track of last 1k txs
const DEFAULT_MAX_HISTORY_SIZE: usize = 200_000_000; // Default max monitored tx total size to 200mb

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct MonitoringConfig {
    pub check_interval: u64,
    pub history_limit: usize,
    pub max_history_size: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            check_interval: DEFAULT_CHECK_INTERVAL,
            history_limit: DEFAULT_HISTORY_LIMIT,
            max_history_size: DEFAULT_MAX_HISTORY_SIZE,
        }
    }
}

/// Runtime configuration for the DA service
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct BitcoinServiceConfig {
    /// The URL of the Bitcoin node to connect to
    pub node_url: String,
    pub node_username: String,
    pub node_password: String,

    // network of the bitcoin node
    pub network: bitcoin::Network,

    // da private key of the sequencer
    pub da_private_key: Option<String>,

    // absolute path to the directory where the txs will be written to
    pub tx_backup_dir: String,

    pub monitoring: Option<MonitoringConfig>,
}

impl super::FromEnv for BitcoinServiceConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            node_url: std::env::var("NODE_URL")?,
            node_username: std::env::var("NODE_USERNAME")?,
            node_password: std::env::var("NODE_PASSWORD")?,
            network: serde_json::from_str(&format!("\"{}\"", std::env::var("NETWORK")?))?,
            da_private_key: std::env::var("DA_PRIVATE_KEY").ok(),
            tx_backup_dir: std::env::var("TX_BACKUP_DIR")?,
            monitoring: Some(MonitoringConfig {
                check_interval: std::env::var("DA_MONITORING_CHECK_INTERVAL")?.parse()?,
                history_limit: std::env::var("DA_MONITORING_HISTORY_LIMIT")?.parse()?,
                max_history_size: std::env::var("DA_MONITORING_MAX_HISTORY_SIZE")?.parse()?,
            }),
        })
    }
}
