//! Provides functions to build Bitcoin transactions
//! related to commit-reveal pattern for Citrea rollup.

pub mod body_builders;
#[cfg(feature = "testing")]
pub mod test_utils;

#[cfg(test)]
mod tests;

use core::fmt;
use core::result::Result::Ok;

use anyhow::anyhow;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::{self, All, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapNodeHash, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use secp256k1::SECP256K1;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::{instrument, trace, warn};

use super::TransactionKind;
use crate::spec::utxo::UTXO;
use crate::REVEAL_OUTPUT_AMOUNT;

/// Both transaction and its hash
#[derive(Clone, Serialize)]
pub struct TxWithId {
    /// ID (hash)
    pub id: Txid,
    /// Transaction
    pub tx: Transaction,
}

impl fmt::Debug for TxWithId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxWithId")
            .field("id", &self.id)
            .field("tx", &"...")
            .finish()
    }
}

/// Build the commit part of commit-reveal pair
/// Return (tx, leftover_utxos)
/// Always includes an indirect change of at least 546 sats to
///  enable mining optimization (see `update_witness`).
#[instrument(level = "trace", skip(utxos), err)]
fn build_commit_transaction(
    prev_utxo: Option<UTXO>, // reuse outputs to add commit tx order
    utxos: Vec<UTXO>,
    recipient: Address,
    change_address: Address,
    output_value: u64,
    fee_rate: u64,
) -> Result<(Transaction, Vec<UTXO>), anyhow::Error> {
    // Non-dust change - is a minimal change to make change non_dust
    let non_dust_change = 546;
    // get single input single output transaction size
    let size = get_size_commit(
        &[TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0; 32]),
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(),
            witness: Witness::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        }],
        &[
            TxOut {
                script_pubkey: recipient.clone().script_pubkey(),
                value: Amount::from_sat(output_value),
            },
            TxOut {
                script_pubkey: change_address.script_pubkey(),
                value: Amount::from_sat(non_dust_change),
            },
        ],
    );

    let mut iteration = 0;
    let mut last_size = size;

    let (leftover_utxos, tx) = loop {
        if iteration % 10 == 0 {
            trace!(iteration, "Trying to find commitment size");
            if iteration > 100 {
                warn!("Too many iterations choosing UTXOs");
            }
        }
        let fee = (last_size as u64) * fee_rate;

        let input_total = output_value + fee + non_dust_change;

        let (chosen_utxos, sum, leftover_utxos) =
            choose_utxos(prev_utxo.clone(), &utxos, input_total)?;
        let has_change = (sum - input_total) >= REVEAL_OUTPUT_AMOUNT;
        let direct_return = !has_change;

        let outputs = if !has_change {
            vec![
                TxOut {
                    value: Amount::from_sat(output_value),
                    script_pubkey: recipient.script_pubkey(),
                },
                TxOut {
                    script_pubkey: change_address.script_pubkey(),
                    value: Amount::from_sat(non_dust_change),
                },
            ]
        } else {
            vec![
                TxOut {
                    value: Amount::from_sat(output_value),
                    script_pubkey: recipient.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(sum - input_total + non_dust_change),
                    script_pubkey: change_address.script_pubkey(),
                },
            ]
        };

        let inputs: Vec<_> = chosen_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint {
                    txid: u.tx_id,
                    vout: u.vout,
                },
                script_sig: script::Builder::new().into_script(),
                witness: Witness::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            })
            .collect();

        if direct_return {
            break (
                leftover_utxos,
                Transaction {
                    lock_time: LockTime::ZERO,
                    version: bitcoin::transaction::Version(2),
                    input: inputs,
                    output: outputs,
                },
            );
        }

        let size = get_size_commit(&inputs, &outputs);

        if size == last_size {
            break (
                leftover_utxos,
                Transaction {
                    lock_time: LockTime::ZERO,
                    version: bitcoin::transaction::Version(2),
                    input: inputs,
                    output: outputs,
                },
            );
        }

        last_size = size;
        iteration += 1;
    };

    Ok((tx, leftover_utxos))
}

/// Build the reveal part of commit-reveal pair
#[allow(clippy::too_many_arguments)]
fn build_reveal_transaction(
    input_utxo: TxOut,
    input_txid: Txid,
    input_vout: u32,
    recipient: Address,
    output_value: u64,
    fee_rate: u64,
    reveal_script: &ScriptBuf,
    control_block: &ControlBlock,
) -> Result<Transaction, anyhow::Error> {
    let outputs: Vec<TxOut> = vec![TxOut {
        value: Amount::from_sat(output_value),
        script_pubkey: recipient.script_pubkey(),
    }];

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: input_txid,
            vout: input_vout,
        },
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    // sanity check
    // the reveal input should already have calculated the reveal output size + reveal fee
    let size = get_size_reveal(
        recipient.script_pubkey(),
        output_value,
        reveal_script,
        control_block,
    );

    let fee = (size as u64) * fee_rate;

    let input_total = output_value + fee;

    if input_utxo.value < Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        || input_utxo.value < Amount::from_sat(input_total)
    {
        return Err(anyhow::anyhow!("input UTXO not big enough"));
    }

    let tx = Transaction {
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
        input: inputs,
        output: outputs,
    };

    Ok(tx)
}

/// Build control block for the reveal script with taproot spend info.
/// This is a heavy operation because we need to hash the reveal script.
fn build_control_block(
    reveal_script: &ScriptBuf,
    public_key: XOnlyPublicKey,
    secp256k1: &Secp256k1<All>,
) -> (ControlBlock, Option<TapNodeHash>, TapLeafHash) {
    // create spend info for tapscript
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("Cannot add reveal script to taptree")
        .finalize(secp256k1, public_key)
        .expect("Cannot finalize taptree");

    // create tapleaf hash
    let tapleaf_hash = TapLeafHash::from_script(reveal_script, LeafVersion::TapScript);

    // create control block for tapscript
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block");

    (
        control_block,
        taproot_spend_info.merkle_root(),
        tapleaf_hash,
    )
}

/// Build witness in the form of [signature, reveal_script, control_block]
fn build_witness(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    reveal_script: ScriptBuf,
    control_block: ControlBlock,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
) {
    // start signing reveal tx
    let mut sighash_cache = SighashCache::new(reveal_tx);

    // create data to sign
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("Cannot create hash for signature");

    // sign reveal tx data
    let signature = secp256k1.sign_schnorr(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("should be cryptographically secure hash"),
        key_pair,
    );

    // add signature to witness and finalize reveal tx
    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.clear();
    witness.push(signature.as_ref());
    witness.push(reveal_script);
    witness.push(control_block.serialize());
}

/// Update witness' signature only from the form of [signature, reveal_script, control_block]
///  without touching reveal_script, control_block.
/// This is an optimization of mining to get the necessary wtxid prefix.
/// The optimization is that we don't have to hash the reveal script again and again
///  which can be costly when the reveal script is huge.
/// It's possible only when reveal script is the same (hence nonce is the same)
///  but only the outputs are changed.
fn update_witness(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
) {
    // start signing reveal tx
    let mut sighash_cache = SighashCache::new(reveal_tx);

    // create data to sign
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("Cannot create hash for signature");

    // sign reveal tx data
    let signature = secp256k1.sign_schnorr(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("should be cryptographically secure hash"),
        key_pair,
    );

    // add signature to witness and finalize reveal tx
    let witness = sighash_cache.witness_mut(0).unwrap();

    let reveal_script = witness.nth(1).unwrap();
    let control_block = witness.nth(2).unwrap();

    let mut new_witness = Witness::new();
    new_witness.push(signature.as_ref());
    new_witness.push(reveal_script);
    new_witness.push(control_block);

    *witness = new_witness;
}

/// Get an approximate virtual size of a commit transaction
fn get_size_commit(inputs: &[TxIn], outputs: &[TxOut]) -> usize {
    let mut tx = Transaction {
        input: inputs.to_vec(),
        output: outputs.to_vec(),
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
    };

    // TODO: adjust size of sig. for different types of addresses
    for i in 0..tx.input.len() {
        tx.input[i].witness.push([0; SCHNORR_SIGNATURE_SIZE]);
    }

    tx.vsize()
}

/// Assumes one input one output inscription transaction
fn get_size_reveal(
    recipient: ScriptBuf,
    output_amount: u64,
    script: &ScriptBuf,
    control_block: &ControlBlock,
) -> usize {
    let mut witness = Witness::new();

    witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
    witness.push(script);
    witness.push(control_block.serialize());

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([0; 32]),
            vout: 0,
        },
        script_sig: script::Builder::new().into_script(),
        witness,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    let outputs = vec![TxOut {
        value: Amount::from_sat(output_amount),
        script_pubkey: recipient,
    }];

    let tx = Transaction {
        input: inputs.to_owned(),
        output: outputs.to_owned(),
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
    };

    tx.vsize()
}

/// Return (chosen_utxos, sum(chosen.amount), leftover_utxos)
fn choose_utxos(
    required_utxo: Option<UTXO>,
    utxos: &[UTXO],
    amount: u64,
) -> Result<(Vec<UTXO>, u64, Vec<UTXO>), anyhow::Error> {
    let mut chosen_utxos = vec![];
    let mut sum = 0;

    // First include required utxo if specified
    if let Some(required) = required_utxo {
        chosen_utxos.push(required.clone());
        sum += required.amount;
    }

    // Check if we already have enough with just the required UTXO
    if sum >= amount {
        // Filter out the chosen UTXOs (just the required one) from the original list
        let leftovers = utxos
            .iter()
            .filter(|u| {
                !chosen_utxos
                    .iter()
                    .any(|chosen| chosen.tx_id == u.tx_id && chosen.vout == u.vout)
            })
            .cloned()
            .collect();
        return Ok((chosen_utxos, sum, leftovers));
    }

    // Filter available UTXOs (excluding any already chosen)
    let available_utxos: Vec<&UTXO> = utxos
        .iter()
        .filter(|u| {
            !chosen_utxos
                .iter()
                .any(|chosen| chosen.tx_id == u.tx_id && chosen.vout == u.vout)
        })
        .collect();

    // Find UTXOs that can cover remaining amount alone
    let remaining_needed = amount - sum;
    let mut adequate_utxos: Vec<&UTXO> = available_utxos
        .iter()
        .filter(|u| u.amount >= remaining_needed)
        .copied()
        .collect();

    if !adequate_utxos.is_empty() {
        // Sort by amount ascending (choose smallest sufficient UTXO)
        adequate_utxos.sort_by(|a, b| a.amount.cmp(&b.amount));
        let best_utxo = adequate_utxos[0];
        chosen_utxos.push(best_utxo.clone());
        sum += best_utxo.amount;
    } else {
        // Use multiple smaller UTXOs to reach target
        let mut smaller_utxos: Vec<&UTXO> = available_utxos
            .iter()
            .filter(|u| u.amount < remaining_needed)
            .copied()
            .collect();

        // Sort descending to use larger UTXOs first
        smaller_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in smaller_utxos {
            if sum >= amount {
                break;
            }
            chosen_utxos.push(utxo.clone());
            sum += utxo.amount;
        }

        if sum < amount {
            return Err(anyhow!("not enough UTXOs"));
        }
    }

    // Calculate leftovers by filtering out chosen UTXOs
    let leftovers = utxos
        .iter()
        .filter(|u| {
            !chosen_utxos
                .iter()
                .any(|chosen| chosen.tx_id == u.tx_id && chosen.vout == u.vout)
        })
        .cloned()
        .collect();

    Ok((chosen_utxos, sum, leftovers))
}

/// Signs a message with a private key
/// Returns (signature, public_key)
pub fn sign_blob_with_private_key(blob: &[u8], private_key: &SecretKey) -> (Vec<u8>, Vec<u8>) {
    let message = calculate_sha256(blob);
    let public_key = secp256k1::PublicKey::from_secret_key(SECP256K1, private_key);
    let msg = secp256k1::Message::from_digest(message);
    let sig = SECP256K1.sign_ecdsa(&msg, private_key);
    (
        sig.serialize_compact().to_vec(),
        public_key.serialize().to_vec(),
    )
}

fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}
