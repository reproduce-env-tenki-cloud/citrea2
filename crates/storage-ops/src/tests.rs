use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_db::native_db::NativeDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::{
    CommitmentsByNumber, L2RangeByL1Height, L2Witness, LightClientProofBySlotNumber,
    ProofsBySlotNumber, ProofsBySlotNumberV2, ProverStateDiffs, SlotByHash, SoftConfirmationByHash,
    SoftConfirmationByNumber, SoftConfirmationStatus, VerifiedBatchProofsBySlotNumber,
};
use sov_db::schema::types::light_client_proof::{
    StoredLatestDaState, StoredLightClientProof, StoredLightClientProofOutput,
};
use sov_db::schema::types::soft_confirmation::StoredSoftConfirmation;
use sov_db::schema::types::{SlotNumber, SoftConfirmationNumber};
use sov_db::state_db::StateDB;
use sov_rollup_interface::mmr::MMRGuest;
use sov_schema_db::DB;
use sov_state::Storage;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::pruning::components::prune_ledger;
use crate::pruning::criteria::{Criteria, DistanceCriteria};
use crate::pruning::types::PruningNodeType;
use crate::pruning::{Pruner, PrunerService, PruningConfig};

#[tokio::test(flavor = "multi_thread")]
async fn test_pruning_simple_run() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap();
    {
        let (sender, receiver) = broadcast::channel(1);
        let cancellation_token = CancellationToken::new();

        let native_db = NativeDB::setup_schema_db(&rocksdb_config).unwrap();
        let state_db = StateDB::setup_schema_db(&rocksdb_config).unwrap();

        let pruner = Pruner::new(
            PruningConfig { distance: 5 },
            ledger_db.inner(),
            Arc::new(state_db),
            Arc::new(native_db),
        );
        let pruner_service = PrunerService::new(pruner, 0, receiver);

        tokio::spawn(pruner_service.run(PruningNodeType::Sequencer, cancellation_token.clone()));

        sleep(Duration::from_secs(1));

        for i in 1..=10 {
            let _ = sender.send(i);
        }

        sleep(Duration::from_secs(1));

        cancellation_token.cancel();
    }
    tokio::time::sleep(Duration::from_secs(1)).await;

    let storage_manager =
        sov_prover_storage_manager::ProverStorageManager::new(sov_state::Config {
            path: tmpdir.path().to_path_buf(),
            db_max_open_files: None,
        })
        .unwrap();
    let finalized_storage = storage_manager.create_final_view_storage();

    let native_height = finalized_storage
        .get_last_pruned_l2_height()
        .unwrap()
        .expect("Last pruned L2 height should be set");
    let ledger_height = ledger_db
        .get_last_pruned_l2_height()
        .unwrap()
        .expect("Last pruned L2 height should be set");

    assert_eq!(native_height, 5);
    assert_eq!(ledger_height, 5);
}

#[test]
pub fn test_pruning_should_prune() {
    let criteria = DistanceCriteria { distance: 1000 };
    assert_eq!(criteria.should_prune(0, 1000), None);
    assert_eq!(criteria.should_prune(0, 1999), None);
    assert_eq!(criteria.should_prune(0, 2000), Some(1000));

    assert_eq!(criteria.should_prune(1000, 2500), None);
    assert_eq!(criteria.should_prune(1000, 2999), None);
    assert_eq!(criteria.should_prune(1000, 3000), Some(2000));
}

#[test]
pub fn test_pruning_ledger_db_soft_confirmations() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap().inner();

    let mut da_slot_height = 1;

    for i in 1u64..=20 {
        let soft_confirmation = StoredSoftConfirmation {
            l2_height: i,
            da_slot_height,
            da_slot_hash: [i as u8; 32],
            da_slot_txs_commitment: [i as u8; 32],
            hash: [i as u8; 32],
            prev_hash: [(i as u8) - 1; 32],
            txs: vec![],
            deposit_data: vec![],
            state_root: [i as u8; 32],
            soft_confirmation_signature: vec![],
            pub_key: vec![0; 32],
            tx_merkle_root: [0; 32],
            l1_fee_rate: 0,
            timestamp: i,
        };

        ledger_db
            .put::<SoftConfirmationByNumber>(&SoftConfirmationNumber(i), &soft_confirmation)
            .unwrap();
        ledger_db
            .put::<SoftConfirmationByHash>(&[i as u8; 32], &SoftConfirmationNumber(i))
            .unwrap();
        ledger_db
            .put::<SoftConfirmationStatus>(
                &SoftConfirmationNumber(i),
                &sov_rollup_interface::rpc::SoftConfirmationStatus::Finalized,
            )
            .unwrap();
        ledger_db
            .put::<L2Witness>(&SoftConfirmationNumber(i), &(vec![5; 32], vec![6; 32]))
            .unwrap();
        ledger_db
            .put::<ProverStateDiffs>(&SoftConfirmationNumber(i), &vec![])
            .unwrap();

        da_slot_height += 1;
    }

    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[1; 32])
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[10; 32])
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[20; 32])
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    prune_ledger(PruningNodeType::Sequencer, ledger_db.clone(), 10);

    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_none());
    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_none());
    // NOT Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[1; 32])
        .unwrap()
        .is_none());
    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[10; 32])
        .unwrap()
        .is_none());
    // NOT Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByHash>(&[20; 32])
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<SoftConfirmationStatus>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());
}

#[test]
pub fn test_pruning_ledger_db_batch_prover_soft_confirmations() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap().inner();

    let mut da_slot_height = 1;

    for i in 1u64..=20 {
        let soft_confirmation = StoredSoftConfirmation {
            l2_height: i,
            da_slot_height,
            da_slot_hash: [i as u8; 32],
            da_slot_txs_commitment: [i as u8; 32],
            hash: [i as u8; 32],
            prev_hash: [(i as u8) - 1; 32],
            txs: vec![],
            deposit_data: vec![],
            state_root: [i as u8; 32],
            soft_confirmation_signature: vec![],
            pub_key: vec![0; 32],
            tx_merkle_root: [0; 32],
            l1_fee_rate: 0,
            timestamp: i,
        };

        ledger_db
            .put::<SoftConfirmationByNumber>(&SoftConfirmationNumber(i), &soft_confirmation)
            .unwrap();
        ledger_db
            .put::<L2Witness>(&SoftConfirmationNumber(i), &(vec![5; 32], vec![6; 32]))
            .unwrap();
        ledger_db
            .put::<ProverStateDiffs>(&SoftConfirmationNumber(i), &vec![])
            .unwrap();

        da_slot_height += 1;
    }

    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    prune_ledger(PruningNodeType::BatchProver, ledger_db.clone(), 10);

    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_none());
    // Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_none());
    // NOT Pruned
    assert!(ledger_db
        .get::<SoftConfirmationByNumber>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2Witness>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(1))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProverStateDiffs>(&SoftConfirmationNumber(20))
        .unwrap()
        .is_some());
}

fn prepare_slots_data(ledger_db: &DB) {
    for da_slot_height in 2u64..=20 {
        ledger_db
            .put::<L2RangeByL1Height>(
                &SlotNumber(da_slot_height),
                &(
                    SoftConfirmationNumber(da_slot_height - 1),
                    SoftConfirmationNumber(da_slot_height),
                ),
            )
            .unwrap();
        ledger_db
            .put::<CommitmentsByNumber>(&SlotNumber(da_slot_height), &vec![])
            .unwrap();
        ledger_db
            .put::<ProofsBySlotNumber>(&SlotNumber(da_slot_height), &vec![])
            .unwrap();
        ledger_db
            .put::<ProofsBySlotNumberV2>(&SlotNumber(da_slot_height), &vec![])
            .unwrap();
        ledger_db
            .put::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(da_slot_height), &vec![])
            .unwrap();
        ledger_db
            .put::<LightClientProofBySlotNumber>(
                &SlotNumber(da_slot_height),
                &StoredLightClientProof {
                    proof: vec![1; 32],
                    light_client_proof_output: StoredLightClientProofOutput {
                        state_root: [0u8; 32],
                        light_client_proof_method_id: [1u32; 8],
                        latest_da_state: StoredLatestDaState {
                            block_hash: [0; 32],
                            block_height: da_slot_height,
                            total_work: [0; 32],
                            current_target_bits: 0,
                            epoch_start_time: 0,
                            prev_11_timestamps: [0; 11],
                        },
                        unchained_batch_proofs_info: vec![],
                        last_l2_height: da_slot_height,
                        batch_proof_method_ids: vec![],
                        mmr_guest: MMRGuest::new(),
                    },
                },
            )
            .unwrap();
        ledger_db
            .put::<SlotByHash>(&[da_slot_height as u8; 32], &SlotNumber(da_slot_height))
            .unwrap();
    }

    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());
}

#[test]
pub fn test_pruning_ledger_db_fullnode_slots() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap().inner();

    prepare_slots_data(&ledger_db);

    prune_ledger(PruningNodeType::FullNode, ledger_db.clone(), 10);

    // SHOULD NOT CHANGE
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    // SHOULD BE PRUNED UP TO 10
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());
}

#[test]
pub fn test_pruning_ledger_db_light_client_slots() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap().inner();

    prepare_slots_data(&ledger_db);

    prune_ledger(PruningNodeType::LightClient, ledger_db.clone(), 10);

    // SHOULD NOT CHANGE
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    // SHOULD BE PRUNED UP TO 10
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());
}

#[test]
pub fn test_pruning_ledger_db_batch_prover_slots() {
    let tmpdir = tempfile::tempdir().unwrap();
    let rocksdb_config = RocksdbConfig::new(tmpdir.path(), None, None);
    let ledger_db = LedgerDB::with_config(&rocksdb_config).unwrap().inner();

    prepare_slots_data(&ledger_db);

    prune_ledger(PruningNodeType::BatchProver, ledger_db.clone(), 10);

    // SHOULD NOT CHANGE
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<LightClientProofBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_some());
    assert!(ledger_db
        .get::<VerifiedBatchProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    // SHOULD BE PRUNED UP TO 10
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<L2RangeByL1Height>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<CommitmentsByNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProofsBySlotNumber>(&SlotNumber(20))
        .unwrap()
        .is_some());

    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(2))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(10))
        .unwrap()
        .is_none());
    assert!(ledger_db
        .get::<ProofsBySlotNumberV2>(&SlotNumber(20))
        .unwrap()
        .is_some());
}
