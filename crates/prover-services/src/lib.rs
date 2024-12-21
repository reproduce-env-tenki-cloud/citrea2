use std::sync::Arc;

use citrea_stf::verifier::StateTransitionVerifier;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::zk::ZkvmHost;
use tokio::sync::Mutex;

mod parallel;
pub use parallel::*;

type Simulator<Stf, DaVerifier, VmGuest> =
    Arc<Mutex<StateTransitionVerifier<Stf, DaVerifier, VmGuest>>>;

pub enum ProofGenMode<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec>,
{
    /// Skips proving.
    Skip,
    /// The simulator runs the rollup verifier logic without even emulating the zkVM
    Simulate(Simulator<Stf, Da::Verifier, Vm::Guest>),
    /// The executor runs the rollup verification logic in the zkVM, but does not actually
    /// produce a zk proof
    Execute,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk proof
    ProveWithSampling,
    /// The prover runs the rollup verification logic in the zkVM and produces a zk/fake proof
    ProveWithSamplingWithFakeProofs(
        /// Average number of _REAL_ commitments to prove
        /// If proof_sampling_number is 0, then we always produce real proofs
        /// Otherwise we prove with a probability of 1/proof_sampling_number,
        ///  but produce fake proofs with a probability of (1-1/proof_sampling_number).
        ///
        /// proof_sampling_number:
        usize,
    ),
}

impl<Da, Vm, Stf> Clone for ProofGenMode<Da, Vm, Stf>
where
    Da: DaService,
    Vm: ZkvmHost,
    Stf: StateTransitionFunction<Da::Spec>,
{
    fn clone(&self) -> Self {
        match self {
            Self::Skip => Self::Skip,
            Self::Execute => Self::Execute,
            Self::ProveWithSampling => Self::ProveWithSampling,
            Self::ProveWithSamplingWithFakeProofs(proof_sampling_number) => {
                Self::ProveWithSamplingWithFakeProofs(*proof_sampling_number)
            }
            Self::Simulate(simulate) => Self::Simulate(Arc::clone(simulate)),
        }
    }
}
