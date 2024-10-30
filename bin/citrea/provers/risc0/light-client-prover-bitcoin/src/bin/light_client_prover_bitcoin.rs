#![no_main]
use bitcoin_da::spec::{BitcoinSpec, RollupParams};
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_light_client_prover::circuit::run_circuit;
use citrea_light_client_prover::input::LightClientCircuitInput;
use citrea_primitives::{REVEAL_BATCH_PROOF_PREFIX, REVEAL_LIGHT_CLIENT_PREFIX};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();

    let input: LightClientCircuitInput<BitcoinSpec> = guest.read_from_host();
    let batch_prover_journals = input.batch_prover_journals.clone();
    let batch_prover_method_id = input.batch_prover_method_id.clone();
    // TODO: Handle ordering
    for journal in batch_prover_journals {
        Risc0Guest::verify(&journal, &batch_prover_method_id).unwrap();
    }

    let da_verifier = BitcoinVerifier::new(RollupParams {
        reveal_batch_prover_prefix: REVEAL_BATCH_PROOF_PREFIX.to_vec(),
        reveal_light_client_prefix: REVEAL_LIGHT_CLIENT_PREFIX.to_vec(),
    });

    let output = run_circuit::<BitcoinVerifier>(input, da_verifier).unwrap();

    guest.commit(&output);
}
