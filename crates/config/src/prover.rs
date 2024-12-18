use serde::{Deserialize, Serialize};

/// The possible configurations of the prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProverGuestRunConfig {
    /// Skip proving.
    Skip,
    /// Run the rollup verification logic inside the current process.
    Simulate,
    /// Run the rollup verifier in a zkVM executor.
    Execute,
    /// Run the rollup verifier and create a SNARK of execution.
    Prove,
}

impl<'de> Deserialize<'de> for ProverGuestRunConfig {
    fn deserialize<D>(deserializer: D) -> Result<ProverGuestRunConfig, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::string::String as Deserialize>::deserialize(deserializer)?;
        match s.as_str() {
            "skip" => Ok(ProverGuestRunConfig::Skip),
            "simulate" => Ok(ProverGuestRunConfig::Simulate),
            "execute" => Ok(ProverGuestRunConfig::Execute),
            "prove" => Ok(ProverGuestRunConfig::Prove),
            _ => Err(serde::de::Error::custom("invalid prover guest run config")),
        }
    }
}
