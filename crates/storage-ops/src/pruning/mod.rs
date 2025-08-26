use std::sync::Arc;

use citrea_common::config::PruningConfig;
use citrea_common::NodeType;
use futures::future;
use ledger::prune_ledger;
use native::prune_native_db;
use sov_db::schema::tables::{LastPrunedBlock, LastPrunedL2Height};
use tracing::info;

use self::criteria::{Criteria, DistanceCriteria};
pub use self::service::*;

pub(crate) mod criteria;
pub(crate) mod ledger;
pub(crate) mod native;
pub(crate) mod service;
pub(crate) mod state;

pub struct Pruner {
    /// Access to ledger tables.
    ledger_db: Arc<sov_schema_db::DB>,
    /// Access to native DB.
    native_db: Arc<sov_schema_db::DB>,
    /// Access to state DB.
    #[allow(dead_code)]
    state_db: Arc<sov_schema_db::DB>,
    /// Criteria to decide pruning
    criteria: Box<dyn Criteria + Send + Sync>,
}

impl Pruner {
    pub fn new(
        config: PruningConfig,
        ledger_db: Arc<sov_schema_db::DB>,
        state_db: Arc<sov_schema_db::DB>,
        native_db: Arc<sov_schema_db::DB>,
    ) -> Self {
        // distance is the only criteria implemented at the moment.
        let criteria = Box::new(DistanceCriteria {
            distance: config.distance,
        });
        Self {
            ledger_db,
            state_db,
            native_db,
            criteria,
        }
    }

    pub fn store_last_pruned_l2_height(&self, last_pruned_l2_height: u64) -> anyhow::Result<()> {
        self.ledger_db
            .put::<LastPrunedBlock>(&(), &last_pruned_l2_height)?;

        self.native_db
            .put::<LastPrunedL2Height>(&(), &last_pruned_l2_height)
    }

    pub fn should_prune(&self, last_pruned_l2_height: u64, current_l2_height: u64) -> Option<u64> {
        self.criteria
            .should_prune(last_pruned_l2_height, current_l2_height)
    }

    /// Prune everything
    pub async fn prune(&self, node_type: NodeType, up_to_block: u64) {
        info!("Pruning up to L2 block: {}", up_to_block);
        let ledger_db = self.ledger_db.clone();

        let native_db = self.native_db.clone();

        // let state_db = self.state_db.clone();

        let ledger_pruning_handle =
            tokio::task::spawn_blocking(move || prune_ledger(node_type, ledger_db, up_to_block));

        // TODO: Fix me
        // let state_db_pruning_handle =
        //     tokio::task::spawn_blocking(move || prune_state_db(state_db, up_to_block));

        let native_db_pruning_handle =
            tokio::task::spawn_blocking(move || prune_native_db(native_db, up_to_block));

        future::join_all([
            ledger_pruning_handle,
            // state_db_pruning_handle,
            native_db_pruning_handle,
        ])
        .await;
    }
}
