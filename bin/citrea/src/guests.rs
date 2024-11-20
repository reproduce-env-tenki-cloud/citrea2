use std::collections::HashMap;

use citrea_risc0_adapter::Digest;
use lazy_static::lazy_static;
use risc0_binfmt::compute_image_id;
use sov_rollup_interface::spec::SpecId;

#[cfg(feature = "testing")]
lazy_static! {
    pub(crate) static ref MOCK_GUESTS: HashMap<SpecId, Vec<u8>> = {
        let mut m = HashMap::new();
        m.insert(SpecId::Genesis, citrea_risc0::BATCH_PROOF_BITCOIN_ELF);
        m
    };
}

#[cfg(not(feature = "testing"))]
lazy_static! {
    pub(crate) static ref BATCH_PROOF_MAINNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();
        let code = include_bytes!("../../../resources/guests/risc0/mainnet/batch-0.elf").to_vec();
        let id = compute_image_id(&code).unwrap();

        m.insert(SpecId::Genesis, (id, code));
        m
    };
    pub(crate) static ref BATCH_PROOF_TESTNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();
        let code = include_bytes!("../../../resources/guests/risc0/testnet/batch-0.elf").to_vec();
        let id = compute_image_id(&code).unwrap();
        m.insert(SpecId::Genesis, (id, code));
        m
    };
    pub(crate) static ref LIGHT_CLIENT_MAINNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();
        let code = include_bytes!("../../../resources/guests/risc0/mainnet/light-0.elf").to_vec();
        let id = compute_image_id(&code).unwrap();
        m.insert(SpecId::Genesis, (id, code));
        m
    };
    pub(crate) static ref LIGHT_CLIENT_TESTNET_GUESTS: HashMap<SpecId, (Digest, Vec<u8>)> = {
        let mut m = HashMap::new();
        let code = include_bytes!("../../../resources/guests/risc0/testnet/light-0.elf").to_vec();
        let id = compute_image_id(&code).unwrap();
        m.insert(SpecId::Genesis, (id, code));
        m
    };
}
