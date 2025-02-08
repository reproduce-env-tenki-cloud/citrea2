use std::marker::PhantomData;

use jmt::KeyHash;
use sov_modules_core::{
    OrderedReadsAndWrites, Storage, StorageKey, StorageProof, StorageValue, Witness,
};
use sov_rollup_interface::stf::{StateDiff, StateRootTransition};
use sov_rollup_interface::zk::StorageRootHash;
use sov_rollup_interface::RefCount;

use crate::DefaultHasher;

/// A [`Storage`] implementation designed to be used inside the zkVM.
#[derive(Default)]
pub struct ZkStorage<W>
where
    W: Witness + Send + Sync,
{
    _phantom_data: PhantomData<W>,
}

impl<W> Clone for ZkStorage<W>
where
    W: Witness + Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

impl<W> ZkStorage<W>
where
    W: Witness + Send + Sync,
{
    /// Creates a new [`ZkStorage`] instance. Identical to [`Default::default`].
    pub fn new() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

impl<W> Storage for ZkStorage<W>
where
    W: Witness + Send + Sync,
{
    type Witness = W;
    type RuntimeConfig = ();
    type StateUpdate = ();

    fn get(
        &self,
        _key: &StorageKey,
        _version: Option<u64>,
        witness: &mut Self::Witness,
    ) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn get_offchain(
        &self,
        _key: &StorageKey,
        _version: Option<jmt::Version>,
        witness: &mut Self::Witness,
    ) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn compute_state_update(
        &self,
        state_accesses: OrderedReadsAndWrites,
        witness: &mut Self::Witness,
    ) -> Result<(StateRootTransition, Self::StateUpdate, StateDiff), anyhow::Error> {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided jmt proof
        for (key, read_value) in state_accesses.ordered_reads {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();
            match read_value {
                Some(val) => proof.verify_existence(
                    jmt::RootHash(prev_state_root),
                    key_hash,
                    val.value.as_ref(),
                )?,
                None => proof.verify_nonexistence(jmt::RootHash(prev_state_root), key_hash)?,
            }
        }

        let mut diff = Vec::with_capacity(state_accesses.ordered_writes.len());

        // Compute the jmt update from the write batch
        let batch = state_accesses
            .ordered_writes
            .into_iter()
            .map(|(key, value)| {
                let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());

                let key_bytes = RefCount::try_unwrap(key.key).unwrap_or_else(|arc| (*arc).clone());
                let value_bytes = value
                    .map(|v| RefCount::try_unwrap(v.value).unwrap_or_else(|arc| (*arc).clone()));

                diff.push((key_bytes, value_bytes.clone()));

                (key_hash, value_bytes)
            })
            .collect::<Vec<_>>();

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
        _accessory_writes: &OrderedReadsAndWrites,
        _offchain_writes: &OrderedReadsAndWrites,
    ) {
    }

    fn open_proof(
        state_root: StorageRootHash,
        state_proof: StorageProof,
    ) -> Result<(StorageKey, Option<StorageValue>), anyhow::Error> {
        let StorageProof { key, value, proof } = state_proof;
        let key_hash = KeyHash::with::<DefaultHasher>(key.as_ref());

        proof.verify(
            jmt::RootHash(state_root),
            key_hash,
            value.as_ref().map(|v| v.value()),
        )?;
        Ok((key, value))
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }
}
