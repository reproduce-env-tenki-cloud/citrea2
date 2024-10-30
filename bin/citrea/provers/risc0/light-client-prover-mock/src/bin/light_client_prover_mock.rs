#![no_main]
use citrea_light_client_prover::circuit::run_circuit;
use citrea_light_client_prover::input::LightClientCircuitInput;
use sov_mock_da::{MockDaSpec, MockDaVerifier};
use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::zk::{Zkvm, ZkvmGuest};

risc0_zkvm::guest::entry!(main);

pub fn main() {
    let guest = Risc0Guest::new();

    let input: LightClientCircuitInput<MockDaSpec> = guest.read_from_host();
    // let batch_prover_journal = input.batch_prover_journal.clone();
    // let batch_proof_method_id = input.batch_proof_method_id.clone();
    // Risc0Guest::verify(&batch_prover_journal.unwrap(), &batch_proof_method_id).unwrap();

    let da_verifier = MockDaVerifier {};

    let output = run_circuit::<MockDaVerifier>(input, da_verifier).unwrap();

    guest.commit(&output);
}
