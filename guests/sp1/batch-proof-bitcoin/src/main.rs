#![no_main]
sp1_zkvm::entrypoint!(main);

use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_primitives::forks::{DEVNET_FORKS, MAINNET_FORKS, NIGHTLY_FORKS, TESTNET_FORKS};
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use citrea_sp1::guest::SP1Guest;
use citrea_stf::runtime::Runtime;
use citrea_stf::StfVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::da::DaVerifier;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

const NETWORK: Network = match option_env!("CITREA_NETWORK") {
    Some(network) => {
        match Network::const_from_str(network) {
            Some(network) => network,
            None => panic!("Invalid CITREA_NETWORK value"),
        } 
    }
    None => Network::Nightly,
};

const SEQUENCER_PUBLIC_KEY: [u8; 32] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "4682a70af1d3fae53a5a26b682e2e75f7a1de21ad5fc8d61794ca889880d39d1",
        Network::Testnet => "4682a70af1d3fae53a5a26b682e2e75f7a1de21ad5fc8d61794ca889880d39d1",
        Network::Devnet => "52f41a5076498d1ae8bdfa57d19e91e3c2c94b6de21985d099cd48cfa7aef174",
        Network::Nightly => {
            match option_env!("SEQUENCER_PUBLIC_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_PUBLIC_KEY must be valid 32-byte hex string"),
    }
};

const SEQUENCER_DA_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b",
        Network::Testnet => "03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b",
        Network::Devnet => "039cd55f9b3dcf306c4d54f66cd7c4b27cc788632cd6fb73d80c99d303c6536486",
        Network::Nightly => {
            match option_env!("SEQUENCER_DA_PUBLIC_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "02588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_DA_PUBLIC_KEY must be valid 33-byte hex string"),
    }
};

const FORKS: &[Fork] = match NETWORK {
    Network::Mainnet => &MAINNET_FORKS,
    Network::Testnet => &TESTNET_FORKS,
    Network::Devnet => &DEVNET_FORKS,
    Network::Nightly => &NIGHTLY_FORKS,
};


pub fn main() {
    let guest = SP1Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StfVerifier<_, ZkDefaultContext, Runtime<_, _>> = StfVerifier::new(
        stf,
        BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
        }),
    );

    let data = guest.read_from_host();

    let out = stf_verifier
        .run_sequencer_commitments_in_da_slot(data, storage, &SEQUENCER_PUBLIC_KEY, &SEQUENCER_DA_PUBLIC_KEY, FORKS)
        .expect("Prover must be honest");

    guest.commit(&out);
}
