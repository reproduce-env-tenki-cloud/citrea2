use core::result::Result;

use borsh::BorshDeserialize;
use hex::FromHex;
use serde::{Deserialize, Deserializer};
use sov_modules_api::default_signature::{DefaultPublicKey, K256PublicKey};
use sov_modules_api::{
    Address, PublicKey, SoftConfirmationHookError, SpecId, StateMapAccessor, WorkingSet,
};

use crate::{Account, Accounts};

/// Initial configuration for sov-accounts module.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccountConfig {
    /// Public keys to initialize the rollup.
    #[serde(deserialize_with = "deserialize_hex_vec")]
    pub pub_keys: Vec<Vec<u8>>,
}

/// Custom deserializer for converting Vec<String> of hex into Vec<Vec<u8>>
fn deserialize_hex_vec<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    hex_strings
        .into_iter()
        .map(|s| Vec::from_hex(&s).map_err(serde::de::Error::custom))
        .collect()
}

impl<C: sov_modules_api::Context> Accounts<C> {
    pub(crate) fn init_module(
        &self,
        config: &<Self as sov_modules_api::Module>::Config,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        for pub_key in config.pub_keys.iter() {
            if self
                .accounts_pre_fork2
                .get(
                    &DefaultPublicKey::try_from_slice(pub_key).expect("Should be a valid pub key"),
                    working_set,
                )
                .is_some()
            {
                panic!("No account should exist in init_module");
            }

            // Called only in genesis so spec id should be Genesis
            self.create_default_account(pub_key, working_set, SpecId::Genesis)
                .expect("Accounts should create account in init_module");
        }
    }

    pub(crate) fn create_default_account(
        &self,
        pub_key: &[u8],
        working_set: &mut WorkingSet<C::Storage>,
        spec_id: SpecId,
    ) -> Result<Account, SoftConfirmationHookError> {
        let default_address: Address = if spec_id >= SpecId::Fork2 {
            let pub_key: K256PublicKey = K256PublicKey::try_from_slice(pub_key)
                // TODO: Update error handling
                .map_err(|_| SoftConfirmationHookError::SovTxAccountNotFound)?;
            pub_key.to_address()
        } else {
            let pub_key = C::PublicKey::try_from_slice(pub_key)
                // TODO: Update error handling
                .map_err(|_| SoftConfirmationHookError::SovTxAccountNotFound)?;
            pub_key.to_address()
        };

        self.exit_if_address_exists(&default_address, working_set, spec_id)?;

        let new_account = Account {
            addr: default_address,
            nonce: 0,
        };

        if spec_id >= SpecId::Fork2 {
            self.accounts.set(pub_key, &new_account, working_set);

            self.public_keys
                .set(&default_address, &pub_key.to_vec(), working_set);
        } else {
            let pub_key =
                DefaultPublicKey::try_from_slice(pub_key).expect("Should be valid public key");
            self.accounts_pre_fork2
                .set(&pub_key, &new_account, working_set);

            self.public_keys_pre_fork2
                .set(&default_address, &pub_key, working_set);
        }

        Ok(new_account)
    }

    fn exit_if_address_exists(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
        spec_id: SpecId,
    ) -> Result<(), SoftConfirmationHookError> {
        if spec_id >= SpecId::Fork2 {
            if self.public_keys.get(address, working_set).is_some() {
                return Err(SoftConfirmationHookError::SovTxAccountAlreadyExists);
            }
        } else if self
            .public_keys_pre_fork2
            .get(address, working_set)
            .is_some()
        {
            return Err(SoftConfirmationHookError::SovTxAccountAlreadyExists);
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use sov_modules_api::default_signature::DefaultPublicKey;
    use sov_modules_api::PublicKeyHex;

    use super::*;

    #[test]
    fn test_config_serialization() {
        let pub_key_hex = PublicKeyHex::try_from(
            "1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf",
        )
        .unwrap();

        let _ = DefaultPublicKey::try_from(&pub_key_hex).unwrap();

        let config = AccountConfig {
            pub_keys: vec![hex::decode(
                "1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf",
            )
            .unwrap()],
        };

        let data = r#"
        {
            "pub_keys":["1cd4e2d9d5943e6f3d12589d31feee6bb6c11e7b8cd996a393623e207da72cbf"]
        }"#;

        let parsed_config: AccountConfig = serde_json::from_str(data).unwrap();
        assert_eq!(parsed_config, config);
    }
}
