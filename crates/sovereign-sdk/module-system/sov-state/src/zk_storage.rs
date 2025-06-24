use jmt::KeyHash;
use sov_modules_core::{OrderedWrites, ReadWriteLog, Storage, StorageKey, StorageValue};
use sov_rollup_interface::stf::{StateDiff, StateRootTransition};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::StorageRootHash;

use crate::DefaultHasher;

/// A [`Storage`] implementation designed to be used inside the zkVM. Used for
/// reading ordered witnesses that are populated initially by the `ProverStorage` in zkVM.
#[derive(Default, Clone)]
pub struct ZkStorage;

impl ZkStorage {
    /// Creates a new [`ZkStorage`] instance. Identical to [`Default::default`].
    pub fn new() -> Self {
        Self {}
    }
}

impl Storage for ZkStorage {
    type RuntimeConfig = ();
    type StateUpdate = ();

    fn get(&self, _key: &StorageKey, witness: &mut Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn get_and_prove(
        &self,
        key: &StorageKey,
        witness: &mut Witness,
        state_root: StorageRootHash,
    ) -> Option<StorageValue> {
        let val: Option<StorageValue> = witness.get_hint();
        let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();

        let key_hash = KeyHash::with::<DefaultHasher>(key.as_ref());
        proof
            .verify(
                jmt::RootHash(state_root),
                key_hash,
                val.as_ref().map(|val| val.value()),
            )
            .expect("JMT proof verification failed");

        val
    }

    fn get_offchain(&self, _key: &StorageKey, witness: &mut Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn compute_state_update(
        &self,
        state_log: &ReadWriteLog,
        witness: &mut Witness,
        accumulate_diff: bool,
    ) -> Result<(StateRootTransition, Self::StateUpdate, StateDiff), anyhow::Error> {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided jmt proof
        for (key, read_value) in state_log.ordered_reads() {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();
            let value = read_value.as_ref().map(|val| val.value.as_ref());
            proof.verify(jmt::RootHash(prev_state_root), key_hash, value)?;
        }

        let mut diff = vec![];

        // Compute the jmt update from the write batch
        let batch = if accumulate_diff {
            state_log
                .iter_ordered_writes()
                .map(|(key, value)| {
                    let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());

                    let key_bytes = key.key.clone();
                    let value_bytes = value.as_ref().map(|v| v.value.clone());

                    diff.push((key_bytes, value_bytes.clone()));

                    (key_hash, value_bytes)
                })
                .collect::<Vec<_>>()
        } else {
            state_log
                .iter_ordered_writes()
                .map(|(key, value)| {
                    let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());

                    let value_bytes = value.as_ref().map(|v| v.value.clone());

                    (key_hash, value_bytes)
                })
                .collect::<Vec<_>>()
        };

        let update_proof: jmt::proof::UpdateMerkleProof<DefaultHasher> = witness.get_hint();
        let new_root: [u8; 32] = witness.get_hint();
        update_proof
            .verify_update(
                jmt::RootHash(prev_state_root),
                jmt::RootHash(new_root),
                batch,
            )
            .expect("Updates must be valid");

        Ok((
            StateRootTransition {
                init_root: prev_state_root,
                final_root: new_root,
            },
            (),
            diff,
        ))
    }

    fn commit(
        &self,
        _node_batch: &Self::StateUpdate,
        _accessory_writes: &OrderedWrites,
        _offchain_log: &ReadWriteLog,
    ) {
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }

    fn clone_with_version(&self, _version: jmt::Version) -> Self {
        unimplemented!("ZkStorage::clone_with_version should never be called")
    }
}
