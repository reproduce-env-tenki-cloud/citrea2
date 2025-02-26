use std::collections::HashMap;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};

use borsh::BorshDeserialize;
use sov_db::ledger_db::{LedgerDB, SharedLedgerOps};
use sov_modules_api::DaSpec;
use sov_rollup_interface::da::VerifableShortHeaderProof;

use super::{ShortHeaderProofProvider, ShortHeaderProofProviderError};

pub struct NativeShortHeaderProofProviderService<Da: DaSpec> {
    pub queried_and_verified_hashes: Arc<Mutex<HashMap<u64, [u8; 32]>>>,
    pub ledger_db: LedgerDB,
    pub _phantom: PhantomData<Da>,
}

impl<Da: DaSpec> NativeShortHeaderProofProviderService<Da> {
    pub fn new(ledger_db: LedgerDB) -> Self {
        Self {
            ledger_db,
            queried_and_verified_hashes: Arc::new(Mutex::new(HashMap::new())),
            _phantom: PhantomData,
        }
    }
}

impl<Da: DaSpec> ShortHeaderProofProvider for NativeShortHeaderProofProviderService<Da> {
    fn get_and_verify_short_header_proof_by_l1_hash(
        &self,
        block_hash: [u8; 32],
        prev_block_hash: [u8; 32],
        l1_height: u64,
        txs_commitment: [u8; 32],
        l2_height: u64,
    ) -> Result<bool, ShortHeaderProofProviderError> {
        if let Some(shp_serialized) = self
            .ledger_db
            .get_short_header_proof_by_l1_hash(&block_hash)
            // TODO: Return error here and make process l2 block run again
            .expect("Should save short header proof")
        {
            let shp = Da::ShortHeaderProof::try_from_slice(&shp_serialized)
                .expect("Should deserialize short header proof");

            if let Ok(l1_update_info) = shp.verify() {
                // the contract will return 0000...00 if we are pushing the first L1 block
                // hence we accept given prev_hash
                let prev_hash_cond = prev_block_hash == [0; 32]
                    || prev_block_hash == l1_update_info.prev_header_hash;

                let return_cond = txs_commitment == l1_update_info.tx_commitment
                    && block_hash == l1_update_info.header_hash
                    && prev_hash_cond
                    && l1_height == l1_update_info.block_height;

                if return_cond {
                    self.queried_and_verified_hashes
                        .lock()
                        .expect("Should lock queried and verified hashes")
                        .insert(l2_height, block_hash);
                }

                return Ok(return_cond);
            }
            return Ok(false);
        }
        Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound)
    }

    fn clear_queried_hashes(&self) {
        self.queried_and_verified_hashes.lock().unwrap().clear();
    }

    fn take_queried_hashes(&self, l2_range: RangeInclusive<u64>) -> Vec<[u8; 32]> {
        let queried_and_verified_hashes = self.queried_and_verified_hashes.lock().unwrap();
        let mut hashes = Vec::new();
        for l2_height in l2_range {
            if let Some(hash) = queried_and_verified_hashes.get(&l2_height) {
                hashes.push(*hash);
            }
        }
        hashes
    }

    fn take_last_queried_hash(&self) -> Option<[u8; 32]> {
        unimplemented!(
            "take_last_queried_hash is not implemented for NativeShortHeaderProofProviderService"
        );
    }
}
