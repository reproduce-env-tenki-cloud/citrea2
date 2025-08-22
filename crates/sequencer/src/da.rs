use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use reth_tasks::shutdown::GracefulShutdown;
use sov_modules_api::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::DaService;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{debug, error, instrument};

/// Represents information about the current DA state.
///
/// Contains latest finalized block and fee rate.
pub(crate) type L1Data<Da> = (<Da as DaService>::FilteredBlock, u128);

/// Run a DA block monitor which sends L1 data signals
/// when a new L1 block is detected.
#[instrument(name = "L1BlockMonitor", skip_all)]
pub(crate) async fn da_block_monitor<Da>(
    da_service: Arc<Da>,
    sender: mpsc::Sender<L1Data<Da>>,
    loop_interval: u64,
    mut shutdown_signal: GracefulShutdown,
) where
    Da: DaService,
{
    let mut last_l1_data = None;
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown_signal => {
                return;
            }
            l1_data = get_da_block_data(da_service.clone()) => {
                match l1_data {
                    Ok(l1_data) => {
                        let l1_data = Some(l1_data);
                        if l1_data != last_l1_data {
                            last_l1_data = l1_data;
                            let _ = sender.send(last_l1_data.clone().unwrap()).await;
                        }
                    },
                    Err(e) => error!("Could not fetch L1 data, {}", e)
                }
                sleep(Duration::from_millis(loop_interval)).await;
            },
        }
    }
}

/// Fetch the finalized height and it's corresponding fee rate.
pub(crate) async fn get_da_block_data<Da>(da_service: Arc<Da>) -> anyhow::Result<L1Data<Da>>
where
    Da: DaService,
{
    let last_finalized_height = da_service
        .get_last_finalized_block_header()
        .await
        .map(|v| v.height())
        .map_err(|e| anyhow!("{:?}", e))?;

    let last_finalized_block = da_service
        .get_block_at(last_finalized_height)
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    debug!(
        "Sequencer: last finalized L1 height: {:?}",
        last_finalized_height
    );

    let l1_fee_rate = da_service
        .get_fee_rate()
        .await
        .map_err(|e| anyhow!("{:?}", e))?;

    Ok((last_finalized_block, l1_fee_rate))
}
