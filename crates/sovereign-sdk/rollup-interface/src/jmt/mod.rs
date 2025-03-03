#![allow(missing_docs)]
use jmt::KeyHash;
use sha2::Sha256;

use crate::zk::UpdateMerkleProofSha2;

pub fn verify_jmt_update(
    update_proof: UpdateMerkleProofSha2,
    prev_root: [u8; 32],
    new_root: [u8; 32],
    key: &[u8],
    value: &[u8],
) -> anyhow::Result<()> {
    let key_hash = KeyHash::with::<Sha256>(key);

    update_proof.verify_update(prev_root.into(), new_root.into(), [(key_hash, Some(value))])
}
