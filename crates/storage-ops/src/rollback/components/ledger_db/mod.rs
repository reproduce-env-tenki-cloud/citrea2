use std::sync::Arc;

use l2_blocks::rollback_l2_blocks;
use slots::{rollback_light_client_slots, rollback_slots};
use tracing::debug;

use crate::log_result_or_error;
use crate::pruning::types::StorageNodeType;

mod l2_blocks;
mod slots;

/// Rollback native DB
pub(crate) fn rollback_ledger_db(
    node_type: StorageNodeType,
    ledger_db: Arc<sov_schema_db::DB>,
    target_l2: u64,
    target_l1: u64,
    last_sequencer_commitment_index: u32,
) {
    debug!(
        "Rolling back Ledger, down to L2 block {}, L1 block {}",
        target_l2, target_l1
    );

    log_result_or_error!(
        "l2_blocks",
        rollback_l2_blocks(
            node_type,
            &ledger_db,
            target_l2,
            last_sequencer_commitment_index,
        )
    );
    match node_type {
        StorageNodeType::LightClient => {
            log_result_or_error!(
                "slots",
                rollback_light_client_slots(node_type, &ledger_db, target_l1,)
            );
        }
        _ => {
            log_result_or_error!("slots", rollback_slots(node_type, &ledger_db, target_l1,));
        }
    }

    let _ = ledger_db.flush();
}
