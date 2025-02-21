use std::cell::RefCell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::ops::RangeInclusive;

use borsh::BorshDeserialize;
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::ShortHeaderProofProvider;
use crate::ShortHeaderProofProviderError;

pub struct ZkShortHeaderProofProviderService<Da: DaSpec> {
    queried_and_verified_hashes: RefCell<Vec<[u8; 32]>>,
    short_header_proofs: RefCell<VecDeque<Vec<u8>>>,
    phantom: PhantomData<Da>,
}

impl<Da: DaSpec> ZkShortHeaderProofProviderService<Da> {
    pub fn new(short_header_proofs: VecDeque<Vec<u8>>) -> Self {
        Self {
            short_header_proofs: RefCell::new(short_header_proofs),
            queried_and_verified_hashes: RefCell::new(Vec::new()),
            phantom: PhantomData,
        }
    }
}

// This is safe to do because zk environment is single-threaded
unsafe impl<Da: DaSpec> Send for ZkShortHeaderProofProviderService<Da> {}
unsafe impl<Da: DaSpec> Sync for ZkShortHeaderProofProviderService<Da> {}

impl<Da: DaSpec> ShortHeaderProofProvider for ZkShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
        prev_block_hash: [u8; 32],
        l1_height: u64,
        txs_commitment: [u8; 32],
        _l2_height: u64,
    ) -> Result<bool, ShortHeaderProofProviderError> {
        let shp = self
            .short_header_proofs
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| {
                panic!(
                    "Should have short header proof for l1 hash: {:?}",
                    block_hash
                )
            });

        let shp = Da::ShortHeaderProof::try_from_slice(&shp)
            .expect("Should deserialize short header proof");

        if let Ok(l1_update_info) = shp.verify() {
            self.queried_and_verified_hashes
                .borrow_mut()
                .push(block_hash);

            let prev_hash_cond = if prev_block_hash == [0; 32] {
                true
            } else {
                prev_block_hash == l1_update_info.prev_header_hash
            };

            return Ok(txs_commitment == l1_update_info.tx_commitment
                && block_hash == l1_update_info.header_hash
                && prev_hash_cond
                && l1_height == l1_update_info.block_height);
        }
        Ok(false)
    }

    fn clear_queried_hashes(&self) {
        self.queried_and_verified_hashes.borrow_mut().clear();
    }

    fn take_queried_hashes(&self, _l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]> {
        self.queried_and_verified_hashes
            .borrow_mut()
            .drain(..)
            .collect()
    }
}
