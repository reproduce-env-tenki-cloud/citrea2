//! This module implements the `ZkvmGuest` trait for the RISC0 VM.
//! However the implementation is different
//!  for host(native) and guest(zkvm) part.
//! The host implementation is used for tests only and brings no real value.

use borsh::BorshDeserialize;
use risc0_zkvm::guest::env;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::Receipt;
use sov_rollup_interface::zk::Zkvm;

use crate::Risc0MethodId;

// Here goes the host/guest implementation:

#[cfg(not(target_os = "zkvm"))]
mod native;
#[cfg(target_os = "zkvm")]
mod zkvm;

#[cfg(not(target_os = "zkvm"))]
pub use native::Risc0Guest;
#[cfg(target_os = "zkvm")]
pub use zkvm::Risc0Guest;

// Here goes the common implementation:

// This is a dummy impl because T: ZkvmGuest where T: Zkvm.
impl Zkvm for Risc0Guest {
    type CodeCommitment = Vec<u8>;

    type Error = anyhow::Error;

    fn verify(
        journal: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let cc = vec_to_u32_array(code_commitment.clone()).unwrap();
        println!("Commitment converted!!: {:?}", cc);
        // let cc = Digest::ZERO;
        env::verify(cc, journal).expect("Guest side verification error should be Infallible");
        Ok(journal.to_vec())
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        // let receipt: Receipt = bincode::deserialize(serialized_proof)?;
        // env::verify(code_commitment.0, receipt.journal.bytes.as_slice())
        //     .expect("Guest side verification error should be Infallible");

        // Ok(BorshDeserialize::deserialize(
        //     &mut receipt.journal.bytes.as_slice(),
        // )?)
        unimplemented!()
    }
}

fn vec_to_u32_array(vec: Vec<u8>) -> Result<[u32; 8], &'static str> {
    // Ensure the Vec has exactly 32 elements (8 u32s x 4 u8s)
    if vec.len() != 32 {
        return Err("Input Vec must have exactly 32 elements");
    }

    // Initialize an array of u32s with a length of 8
    let mut array = [0u32; 8];

    // Fill the array by combining every four u8 elements into a u32
    for i in 0..8 {
        array[i] = ((vec[i * 4] as u32) << 24)
            | ((vec[i * 4 + 1] as u32) << 16)
            | ((vec[i * 4 + 2] as u32) << 8)
            | (vec[i * 4 + 3] as u32);
    }

    Ok(array)
}
