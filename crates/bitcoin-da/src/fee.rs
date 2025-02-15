// fix clippy for tracing::instrument
#![allow(clippy::blocks_in_conditions)]

use core::result::Result::Ok;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use bitcoin::{Amount, Network, Sequence, Txid};
use bitcoincore_rpc::json::{
    BumpFeeResult, CreateRawTransactionInput, WalletCreateFundedPsbtOptions,
};
use bitcoincore_rpc::{Client, RpcApi};
use tracing::{debug, instrument, trace, warn};

use crate::monitoring::{MonitoredTx, MonitoredTxKind};
use crate::spec::utxo::UTXO;

const DEFAULT_MEMPOOL_SPACE_URL: &str = "https://mempool.space/";
const MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT: &str = "api/v1/fees/recommended";

pub type Psbt = String;

pub enum BumpFeeMethod {
    Cpfp,
    Rbf,
}

#[derive(Debug)]
pub struct FeeService {
    client: Arc<Client>,
    network: Network,
    mempool_space_url: String,
}

impl FeeService {
    pub fn new(
        client: Arc<Client>,
        network: bitcoin::Network,
        mempool_space_url: Option<String>,
    ) -> Self {
        let mempool_space_url =
            mempool_space_url.unwrap_or_else(|| DEFAULT_MEMPOOL_SPACE_URL.to_string());
        Self {
            client,
            network,
            mempool_space_url,
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate(&self) -> Result<u64> {
        match self.get_fee_rate_as_sat_vb().await {
            Ok(fee) => Ok(fee),
            Err(e) => {
                if self.network == bitcoin::Network::Regtest
                    || self.network == bitcoin::Network::Testnet
                {
                    Ok(1)
                } else {
                    Err(e)
                }
            }
        }
    }

    #[instrument(level = "trace", skip_all, ret)]
    pub async fn get_fee_rate_as_sat_vb(&self) -> Result<u64> {
        // If network is regtest or signet, mempool space is not available
        let smart_fee =
            match get_fee_rate_from_mempool_space(self.network, &self.mempool_space_url).await {
                Ok(fee_rate) => fee_rate,
                Err(e) => {
                    tracing::error!(?e, "Failed to get fee rate from mempool.space");
                    self.client.estimate_smart_fee(1, None).await?.fee_rate
                }
            };
        let sat_vkb = smart_fee.map_or(1000, |rate| rate.to_sat());

        tracing::debug!("Fee rate: {} sat/vb", sat_vkb / 1000);
        Ok(sat_vkb / 1000)
    }

    /// Bump TX fee via cpfp.
    pub async fn bump_fee_cpfp(
        &self,
        monitored_tx: &MonitoredTx,
        parent_txid: &Txid,
        fee_rate: f64,
        force: Option<bool>,
        utxo: UTXO,
    ) -> Result<Psbt> {
        let force = force.unwrap_or_default();
        match (monitored_tx.kind, force) {
            (MonitoredTxKind::Commit, false) => {
                bail!("Trying to bump a commit TX.")
            }
            (MonitoredTxKind::Commit, true) => {
                warn!("Force creating CPFP TX for commit TX {parent_txid}");
            }
            _ => debug!("Creating CPFP TX for {parent_txid}"),
        }

        let parent_tx = &monitored_tx.tx;
        let change_address = utxo
            .address
            .clone()
            .context("Missing address")?
            .require_network(self.network)
            .context("Invalid network for address")?;

        let mut outputs = HashMap::new();
        outputs.insert(change_address.to_string(), parent_tx.output[0].value);
        let options = WalletCreateFundedPsbtOptions {
            add_inputs: Some(true),
            fee_rate: Some(Amount::from_btc(fee_rate / 100_000.0)?), // sat/vB to BTC/kB
            replaceable: Some(true),
            ..Default::default()
        };

        let funded_psbt = self
            .client
            .wallet_create_funded_psbt(
                &[CreateRawTransactionInput {
                    txid: utxo.tx_id,
                    vout: utxo.vout,
                    sequence: Some(Sequence::ENABLE_RBF_NO_LOCKTIME.to_consensus_u32()),
                }],
                &outputs,
                None,
                Some(options),
                None,
            )
            .await?;

        Ok(funded_psbt.psbt)
    }

    /// Bump TX fee via rbf.
    pub async fn bump_fee_rbf(&self, kind: MonitoredTxKind, parent_txid: &Txid) -> Result<Psbt> {
        match kind {
            MonitoredTxKind::Cpfp => {}
            _ => bail!("RBF only supported on cpfp TX"), // TODO Add support for bumping reveal TX
        }

        let BumpFeeResult {
            psbt: Some(funded_psbt),
            ..
        } = self.client.psbt_bump_fee(parent_txid, None).await?
        else {
            bail!("Not able to retrieve funded_psbt from bumpfee RPC")
        };

        Ok(funded_psbt)
    }
}

pub(crate) async fn get_fee_rate_from_mempool_space(
    network: bitcoin::Network,
    mempool_space_url: &str,
) -> Result<Option<Amount>> {
    let url = match network {
        bitcoin::Network::Bitcoin => format!(
            // Mainnet
            "{}{}",
            mempool_space_url, MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT
        ),
        bitcoin::Network::Testnet => format!(
            "{}testnet4/{}",
            mempool_space_url, MEMPOOL_SPACE_RECOMMENDED_FEE_ENDPOINT
        ),
        _ => {
            trace!("Unsupported network for mempool space fee estimation");
            return Ok(None);
        }
    };
    let fee_rate = reqwest::get(url)
        .await?
        .json::<serde_json::Value>()
        .await?
        .get("fastestFee")
        .and_then(|fee| fee.as_u64())
        .map(|fee| Amount::from_sat(fee * 1000)) // multiply by 1000 to convert to sat/vkb
        .context("Failed to get fee rate from mempool space")?;

    Ok(Some(fee_rate))
}

#[cfg(test)]
mod tests {

    use super::{get_fee_rate_from_mempool_space, DEFAULT_MEMPOOL_SPACE_URL};

    #[tokio::test]
    async fn test_mempool_space_fee_rate() {
        let mempool_space_url = DEFAULT_MEMPOOL_SPACE_URL;

        let _fee_rate =
            get_fee_rate_from_mempool_space(bitcoin::Network::Bitcoin, mempool_space_url)
                .await
                .unwrap();
        let _fee_rate =
            get_fee_rate_from_mempool_space(bitcoin::Network::Testnet, mempool_space_url)
                .await
                .unwrap();
        assert_eq!(
            None,
            get_fee_rate_from_mempool_space(bitcoin::Network::Regtest, mempool_space_url)
                .await
                .unwrap()
        );
        assert_eq!(
            None,
            get_fee_rate_from_mempool_space(bitcoin::Network::Signet, mempool_space_url)
                .await
                .unwrap()
        );
    }
}
