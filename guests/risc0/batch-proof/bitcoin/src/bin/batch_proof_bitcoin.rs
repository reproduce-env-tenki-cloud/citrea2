#![no_main]
use bitcoin_da::spec::BitcoinSpec;
use citrea_primitives::forks::{
    ALL_FORKS, DEVNET_FORKS, MAINNET_FORKS, NIGHTLY_FORKS, TESTNET_FORKS,
};
use citrea_risc0_adapter::guest::Risc0Guest;
use citrea_stf::runtime::CitreaRuntime;
use citrea_stf::verifier::StateTransitionVerifier;
use sov_modules_api::default_context::ZkDefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_stf_blueprint::StfBlueprint;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;
use sov_state::ZkStorage;

risc0_zkvm::guest::entry!(main);

const NETWORK: Network = match option_env!("CITREA_NETWORK") {
    Some(network) => match Network::const_from_str(network) {
        Some(network) => network,
        None => panic!("Invalid CITREA_NETWORK value"),
    },
    None => Network::Nightly,
};

const SEQUENCER_PUBLIC_KEY: [u8; 33] = {
    let hex_pub_key = match NETWORK {
        Network::Mainnet => "000000000000000000000000000000000000000000000000000000000000000000",
        Network::Testnet => "0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364",
        Network::Devnet => "03745871636b11562a7f2d7c0e883a960b54c7e2c0a5427d4b99ac403588530589",
        Network::Nightly | Network::TestNetworkWithForks => {
            match option_env!("SEQUENCER_PUBLIC_KEY") {
                Some(hex_pub_key) => hex_pub_key,
                None => "036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7",
            }
        }
    };

    match const_hex::const_decode_to_array(hex_pub_key.as_bytes()) {
        Ok(pub_key) => pub_key,
        Err(_) => panic!("SEQUENCER_PUBLIC_KEY must be valid 33-byte hex string"),
    }
};

const INITIAL_PREV_L2_BLOCK_HASH: Option<[u8; 32]> = {
    let hex_block_hash: Option<&str> = match NETWORK {
        Network::Mainnet => {
            Some("0000000000000000000000000000000000000000000000000000000000000000")
        }
        Network::Testnet => {
            Some("00f60fc8c66032c232912aa89ba702e6fd5bb95a748c161285cbd62d4b72550a")
        } // block #9056999
        Network::Devnet => Some("0000000000000000000000000000000000000000000000000000000000000000"),
        Network::Nightly => match option_env!("INITIAL_PREV_L2_BLOCK_HASH") {
            Some(hex) => Some(hex),
            None => Some("0000000000000000000000000000000000000000000000000000000000000000"),
        },
        Network::TestNetworkWithForks => match option_env!("INITIAL_PREV_L2_BLOCK_HASH") {
            Some(hex) => Some(hex),
            None => None,
        },
    };

    match hex_block_hash {
        Some(hex) => match const_hex::const_decode_to_array(hex.as_bytes()) {
            Ok(hash) => Some(hash),
            Err(_) => panic!("INITIAL_PREV_L2_BLOCK_HASH must be valid 32-byte hex string"),
        },
        None => None,
    }
};

const FORKS: &[Fork] = match NETWORK {
    Network::Mainnet => &MAINNET_FORKS,
    Network::Testnet => &TESTNET_FORKS,
    Network::Devnet => &DEVNET_FORKS,
    Network::Nightly => &NIGHTLY_FORKS,
    Network::TestNetworkWithForks => &ALL_FORKS,
};

fn get_forks() -> &'static [Fork] {
    #[cfg(feature = "testing")]
    {
        if std::env::var("ALL_FORKS").is_ok() {
            println!("Enabling ALL_FORKS");
            return &ALL_FORKS;
        }
    }
    FORKS
}

pub fn main() {
    let guest = Risc0Guest::new();
    let storage = ZkStorage::new();
    let stf = StfBlueprint::new();

    let mut stf_verifier: StateTransitionVerifier<
        ZkDefaultContext,
        BitcoinSpec,
        CitreaRuntime<_, _>,
    > = StateTransitionVerifier::new(stf);

    let forks = get_forks();

    // if all forks enabled, we can't know the previous l2 block hash
    let initial_prev_l2_block_hash = if forks == &ALL_FORKS {
        None
    } else {
        INITIAL_PREV_L2_BLOCK_HASH
    };

    let out = stf_verifier.run_sequencer_commitments_in_da_slot(
        &guest,
        storage,
        &SEQUENCER_PUBLIC_KEY,
        initial_prev_l2_block_hash,
        forks,
    );

    guest.commit(&out);
}
