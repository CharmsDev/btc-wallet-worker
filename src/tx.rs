use crate::locks::{refuse_locked, AllowLocked, InputChoice, Lockbook, Scope};
use crate::policy::enforce_input_cap;
use crate::scan::ScanCache;
use crate::wallet::{xonly_of, ChainKind, ScriptKind, Wallet};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bitcoin::absolute::LockTime;
use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use bitcoin::consensus::encode::{deserialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    ecdsa, taproot, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

const DUST_SATS: u64 = 546;

#[derive(Clone, Debug)]
pub struct Coin {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: ScriptBuf,
    pub path: DerivationPath,
    pub public_key: PublicKey,
    pub confirmed: bool,
}

impl Coin {
    pub fn outpoint(&self) -> OutPoint {
        OutPoint {
            txid: self.txid,
            vout: self.vout,
        }
    }
}

pub fn coins_for_send(
    coins: Vec<Coin>,
    choice: &InputChoice,
    book: &Lockbook,
    auto_lock_sats: u64,
) -> Result<Vec<Coin>, String> {
    match choice {
        InputChoice::Auto => {
            let found = !coins.is_empty();
            let pool: Vec<Coin> = coins
                .into_iter()
                .filter(|coin| {
                    book.reason(coin.outpoint(), coin.value, Scope::Wallet, auto_lock_sats)
                        .is_none()
                })
                .collect();
            if found && pool.is_empty() {
                return Err("no selectable utxos; locked outputs were skipped".into());
            }
            Ok(pool)
        }
        InputChoice::Exactly(listed) => {
            let mut by_outpoint: BTreeMap<OutPoint, Coin> = coins
                .into_iter()
                .map(|coin| (coin.outpoint(), coin))
                .collect();
            listed
                .outpoints()
                .iter()
                .map(|outpoint| {
                    by_outpoint
                        .remove(outpoint)
                        .ok_or_else(|| format!("input {outpoint} is not an unspent wallet output"))
                })
                .collect()
        }
    }
}

pub fn utxo_rows(
    coins: &[Coin],
    book: &Lockbook,
    auto_lock_sats: u64,
    script: ScriptKind,
    network: Network,
) -> Result<Vec<Value>, String> {
    let script_type = match script {
        ScriptKind::Bip84 => "p2wpkh",
        ScriptKind::Bip86 => "p2tr",
    };
    coins
        .iter()
        .map(|coin| {
            let address = Address::from_script(&coin.script_pubkey, network)
                .map_err(|_| "utxo script has no address".to_string())?;
            let [.., chain, index] = coin.path.as_ref() else {
                return Err("utxo path is too short".into());
            };
            let reason = book.reason(coin.outpoint(), coin.value, Scope::Wallet, auto_lock_sats);
            let mut row = json!({
                "txid": coin.txid.to_string(),
                "vout": coin.vout,
                "value_sats": coin.value,
                "confirmed": coin.confirmed,
                "address": address.to_string(),
                "script_pubkey": hex::encode(coin.script_pubkey.as_bytes()),
                "script_type": script_type,
                "path": format!("{chain}/{index}"),
                "locked": reason.is_some(),
            });
            if let Some(reason) = reason {
                row["lock_reason"] = json!(reason);
            }
            Ok(row)
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct BuiltOutput {
    pub address: String,
    pub sats: u64,
    pub change: bool,
}

#[derive(Clone, Debug)]
pub struct Built {
    pub psbt: Psbt,
    pub fee_sats: u64,
    pub vsize: u64,
    pub feerate_sat_vb: u64,
    pub outputs: Vec<BuiltOutput>,
    pub used_unconfirmed: bool,
}

pub struct Payment<'a> {
    pub script: ScriptKind,
    pub fingerprint: Fingerprint,
    pub coins: &'a [Coin],
    pub dest: &'a Address,
    pub amount: u64,
    pub feerate: u64,
    pub change: &'a Address,
    pub max_input_sats: u64,
}

pub fn build_payment(payment: &Payment<'_>) -> Result<Built, String> {
    if payment.amount < DUST_SATS {
        return Err(format!(
            "amount {} sats is below the dust limit of {DUST_SATS}",
            payment.amount
        ));
    }
    let mut pool: Vec<&Coin> = payment
        .coins
        .iter()
        .filter(|coin| coin.value <= payment.max_input_sats)
        .collect();
    pool.sort_by(|left, right| {
        right
            .confirmed
            .cmp(&left.confirmed)
            .then(right.value.cmp(&left.value))
    });
    let attempts = pool.len().min(16);
    for _ in 0..attempts {
        if let Some(built) = select_fitting(payment, &pool)? {
            return Ok(built);
        }
        if pool.len() <= 1 {
            break;
        }
        pool.remove(0);
    }
    if payment.coins.is_empty()
        || payment
            .coins
            .iter()
            .any(|coin| coin.value <= payment.max_input_sats)
    {
        Err("not enough funds".into())
    } else {
        Err(format!(
            "no coin selection fits MAX_TX_INPUT_SATS ({})",
            payment.max_input_sats
        ))
    }
}

fn select_fitting(payment: &Payment<'_>, ordered: &[&Coin]) -> Result<Option<Built>, String> {
    let mut selected: Vec<&Coin> = Vec::new();
    let mut total = 0u64;
    for coin in ordered {
        let Some(next) = total.checked_add(coin.value) else {
            continue;
        };
        if next > payment.max_input_sats {
            continue;
        }
        selected.push(coin);
        total = next;
        if let Some(built) = try_selection(payment, &selected, total, true)? {
            return Ok(Some(built));
        }
        if let Some(built) = try_selection(payment, &selected, total, false)? {
            return Ok(Some(built));
        }
    }
    Ok(None)
}

fn try_selection(
    payment: &Payment<'_>,
    coins: &[&Coin],
    total: u64,
    with_change: bool,
) -> Result<Option<Built>, String> {
    let script = payment.script;
    let dest = payment.dest;
    let amount = payment.amount;
    let feerate = payment.feerate;
    let change = payment.change;
    let fingerprint = payment.fingerprint;
    let outputs_for_size = if with_change {
        vec![
            tx_out(dest, amount)?,
            tx_out(change, DUST_SATS.max(amount))?,
        ]
    } else {
        vec![tx_out(dest, amount)?]
    };
    let provisional = unsigned_tx(coins, &outputs_for_size);
    let vsize = witnessed_vsize(&provisional, script);
    let Some(fee) = feerate.checked_mul(vsize) else {
        return Err("fee overflow".into());
    };
    let need = amount.saturating_add(fee);
    if total < need {
        return Ok(None);
    }
    let (fee, outputs) = if with_change {
        let change_sats = total - need;
        if change_sats < DUST_SATS {
            return Ok(None);
        }
        (
            fee,
            vec![
                BuiltOutput {
                    address: dest.to_string(),
                    sats: amount,
                    change: false,
                },
                BuiltOutput {
                    address: change.to_string(),
                    sats: change_sats,
                    change: true,
                },
            ],
        )
    } else {
        let fee = total - amount;
        (
            fee,
            vec![BuiltOutput {
                address: dest.to_string(),
                sats: amount,
                change: false,
            }],
        )
    };
    let tx_outputs = outputs
        .iter()
        .map(|output| {
            let address = if output.change { change } else { dest };
            tx_out(address, output.sats)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tx = unsigned_tx(coins, &tx_outputs);
    let actual_vsize = witnessed_vsize(&tx, script);
    if actual_vsize == 0 {
        return Err("transaction size is zero".into());
    }
    let rate = fee.div_ceil(actual_vsize);
    let psbt = fill_psbt(tx, coins, fingerprint, script)?;
    Ok(Some(Built {
        psbt,
        fee_sats: fee,
        vsize: actual_vsize,
        feerate_sat_vb: rate,
        outputs,
        used_unconfirmed: coins.iter().any(|coin| !coin.confirmed),
    }))
}

fn tx_out(address: &Address, sats: u64) -> Result<TxOut, String> {
    Ok(TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: address.script_pubkey(),
    })
}

fn unsigned_tx(coins: &[&Coin], outputs: &[TxOut]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: coins
            .iter()
            .map(|coin| TxIn {
                previous_output: coin.outpoint(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: outputs.to_vec(),
    }
}

fn witnessed_vsize(tx: &Transaction, script: ScriptKind) -> u64 {
    let mut tx = tx.clone();
    for input in &mut tx.input {
        if input.witness.is_empty() {
            input.witness = dummy_witness(script);
        }
    }
    tx.weight().to_vbytes_ceil()
}

fn dummy_witness(script: ScriptKind) -> Witness {
    let mut witness = Witness::new();
    match script {
        ScriptKind::Bip84 => {
            witness.push([0u8; 72]);
            witness.push([0u8; 33]);
        }
        ScriptKind::Bip86 => {
            witness.push([0u8; 65]);
        }
    }
    witness
}

fn fill_psbt(
    tx: Transaction,
    coins: &[&Coin],
    fingerprint: Fingerprint,
    script: ScriptKind,
) -> Result<Psbt, String> {
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| "could not build psbt")?;
    for (index, coin) in coins.iter().enumerate() {
        let input = &mut psbt.inputs[index];
        input.witness_utxo = Some(TxOut {
            value: Amount::from_sat(coin.value),
            script_pubkey: coin.script_pubkey.clone(),
        });
        input
            .bip32_derivation
            .insert(coin.public_key, (fingerprint, coin.path.clone()));
        if script == ScriptKind::Bip86 {
            let xonly = xonly_of(&coin.public_key);
            input.tap_internal_key = Some(xonly);
            input
                .tap_key_origins
                .insert(xonly, (Vec::new(), (fingerprint, coin.path.clone())));
        }
    }
    Ok(psbt)
}

pub fn psbt_to_base64(psbt: &Psbt) -> String {
    STANDARD.encode(psbt.serialize())
}

pub fn psbt_from_base64(data: &str) -> Result<Psbt, String> {
    if data.len() > 256_000 {
        return Err("psbt is too large".into());
    }
    let bytes = STANDARD
        .decode(data.trim().as_bytes())
        .map_err(|_| "psbt is not base64")?;
    Psbt::deserialize(&bytes).map_err(|_| "psbt could not be decoded".to_string())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    pub fee_sats: u64,
    pub vsize: u64,
    pub outflow_sats: u64,
    pub dest: String,
    pub our_inputs: usize,
    pub broadcastable_after_sign: bool,
}

pub fn inspect_psbt(
    psbt: &Psbt,
    owned: &BTreeMap<ScriptBuf, (ChainKind, u32)>,
    script: ScriptKind,
    network: Network,
) -> Result<Inspection, String> {
    let mut our_in = 0u64;
    let mut all_in = 0u64;
    let mut our_inputs = 0usize;
    let mut tx = psbt.unsigned_tx.clone();
    let broadcastable = true;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let utxo = input_utxo(input, &psbt.unsigned_tx.input[index])?;
        all_in = all_in.saturating_add(utxo.value.to_sat());
        let ours = owned.contains_key(&utxo.script_pubkey);
        if ours {
            our_in = our_in.saturating_add(utxo.value.to_sat());
            our_inputs += 1;
            tx.input[index].witness = dummy_witness(script);
        } else if let Some(witness) = &input.final_script_witness {
            tx.input[index].witness = witness.clone();
        } else {
            return Err("cannot price a psbt input that is neither ours nor finalized".into());
        }
    }
    if our_inputs == 0 {
        return Err("psbt spends no outputs from this wallet".into());
    }
    let all_out: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .map(|output| output.value.to_sat())
        .sum();
    if all_in < all_out {
        return Err("psbt outputs exceed inputs".into());
    }
    let fee_sats = all_in - all_out;
    let our_out: u64 = psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|output| owned.contains_key(&output.script_pubkey))
        .map(|output| output.value.to_sat())
        .sum();
    let outflow_sats = our_in.saturating_sub(our_out);
    let vsize = tx.weight().to_vbytes_ceil();
    Ok(Inspection {
        fee_sats,
        vsize,
        outflow_sats,
        dest: external_dest(&psbt.unsigned_tx, owned, network),
        our_inputs,
        broadcastable_after_sign: broadcastable,
    })
}

fn input_utxo(input: &bitcoin::psbt::Input, txin: &TxIn) -> Result<TxOut, String> {
    if let Some(utxo) = &input.witness_utxo {
        return Ok(utxo.clone());
    }
    if let Some(prev) = &input.non_witness_utxo {
        return prev
            .output
            .get(txin.previous_output.vout as usize)
            .cloned()
            .ok_or_else(|| "psbt input is missing witness_utxo".into());
    }
    Err("psbt input is missing witness_utxo".into())
}

fn external_dest(
    tx: &Transaction,
    owned: &BTreeMap<ScriptBuf, (ChainKind, u32)>,
    network: Network,
) -> String {
    let mut labels = Vec::new();
    for output in &tx.output {
        if owned.contains_key(&output.script_pubkey) {
            continue;
        }
        let label = Address::from_script(&output.script_pubkey, network)
            .map(|address| address.to_string())
            .unwrap_or_else(|_| hex::encode(output.script_pubkey.as_bytes()));
        labels.push(label);
        if labels.len() == 3 {
            break;
        }
    }
    if labels.is_empty() {
        "wallet".to_string()
    } else {
        labels.join(",")
    }
}

pub fn annotate_owned_inputs(
    wallet: &Wallet,
    psbt: &mut Psbt,
    owned: &BTreeMap<ScriptBuf, (ChainKind, u32)>,
) -> Result<(), String> {
    for (index, input) in psbt.inputs.iter_mut().enumerate() {
        let utxo = input_utxo(input, &psbt.unsigned_tx.input[index])?;
        let Some((chain, child)) = owned.get(&utxo.script_pubkey) else {
            continue;
        };
        let derived = wallet.derive(*chain, *child)?;
        input
            .bip32_derivation
            .entry(derived.public_key)
            .or_insert_with(|| (wallet.fingerprint(), derived.path.clone()));
        if wallet.script() == ScriptKind::Bip86 && input.tap_internal_key.is_none() {
            let xonly = xonly_of(&derived.public_key);
            input.tap_internal_key = Some(xonly);
            input
                .tap_key_origins
                .insert(xonly, (Vec::new(), (wallet.fingerprint(), derived.path)));
        }
    }
    Ok(())
}

pub fn transaction_input_sats(psbt: &Psbt) -> Result<u64, String> {
    if psbt.inputs.is_empty() {
        return Err("transaction has no inputs".into());
    }
    let mut total = 0u64;
    for (index, input) in psbt.inputs.iter().enumerate() {
        let value = match input_utxo(input, &psbt.unsigned_tx.input[index]) {
            Ok(utxo) => utxo.value.to_sat(),
            Err(_) => {
                return Err(format!("psbt input {index} is missing a value"));
            }
        };
        total = total
            .checked_add(value)
            .ok_or_else(|| "input sum overflow".to_string())?;
    }
    Ok(total)
}

pub fn sign_psbt(
    wallet: &Wallet,
    psbt: &mut Psbt,
    book: &Lockbook,
    allow: AllowLocked,
    max_input_sats: u64,
    auto_lock_sats: u64,
) -> Result<u64, String> {
    let input_sats = transaction_input_sats(psbt)?;
    enforce_input_cap(input_sats, max_input_sats)?;
    refuse_locked(
        &psbt_spends(psbt, wallet.fingerprint())?,
        book,
        allow,
        auto_lock_sats,
    )?;
    require_committing_sighash(psbt, wallet)?;
    let secp = Secp256k1::new();
    match psbt.sign(wallet.master_key(), &secp) {
        Ok(_) => {}
        Err(err) => {
            if !has_our_signature(psbt) {
                return Err(format!("signing failed: {err:?}"));
            }
        }
    }
    finalize_signed_inputs(psbt);
    Ok(input_sats)
}

fn psbt_spends(
    psbt: &Psbt,
    fingerprint: Fingerprint,
) -> Result<Vec<(OutPoint, u64, Scope)>, String> {
    psbt.inputs
        .iter()
        .zip(&psbt.unsigned_tx.input)
        .map(|(input, txin)| {
            let scope = if signs_input(input, fingerprint) {
                Scope::Wallet
            } else {
                Scope::Foreign
            };
            let value = input_utxo(input, txin)?.value.to_sat();
            Ok((txin.previous_output, value, scope))
        })
        .collect()
}

fn signs_input(input: &bitcoin::psbt::Input, fingerprint: Fingerprint) -> bool {
    input
        .bip32_derivation
        .values()
        .any(|(origin, _)| *origin == fingerprint)
        || input
            .tap_key_origins
            .values()
            .any(|(_, (origin, _))| *origin == fingerprint)
}

fn require_committing_sighash(psbt: &Psbt, wallet: &Wallet) -> Result<(), String> {
    let fingerprint = wallet.fingerprint();
    for (index, input) in psbt.inputs.iter().enumerate() {
        if !signs_input(input, fingerprint) {
            continue;
        }
        match wallet.script() {
            ScriptKind::Bip84 => {
                let sighash = input
                    .ecdsa_hash_ty()
                    .map_err(|_| format!("input {index} uses a sighash this wallet cannot sign"))?;
                if sighash != EcdsaSighashType::All {
                    return Err(format!(
                        "input {index} sighash {sighash} is not allowed; only SIGHASH_ALL can be signed"
                    ));
                }
            }
            ScriptKind::Bip86 => {
                let sighash = input
                    .taproot_hash_ty()
                    .map_err(|_| format!("input {index} uses a sighash this wallet cannot sign"))?;
                if sighash != TapSighashType::Default && sighash != TapSighashType::All {
                    return Err(format!(
                        "input {index} sighash {sighash} is not allowed; only SIGHASH_DEFAULT and SIGHASH_ALL can be signed"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn has_our_signature(psbt: &Psbt) -> bool {
    psbt.inputs.iter().any(|input| {
        !input.partial_sigs.is_empty()
            || input.tap_key_sig.is_some()
            || input.final_script_witness.is_some()
    })
}

fn finalize_signed_inputs(psbt: &mut Psbt) {
    for input in &mut psbt.inputs {
        if input.final_script_witness.is_some() {
            continue;
        }
        if let Some(sig) = input.tap_key_sig {
            let mut witness = Witness::new();
            witness.push(sig.to_vec());
            input.final_script_witness = Some(witness);
            continue;
        }
        if let Some((public_key, signature)) = input.partial_sigs.iter().next() {
            let mut witness = Witness::new();
            witness.push(signature.to_vec());
            witness.push(public_key.to_bytes());
            input.final_script_witness = Some(witness);
        }
    }
}

pub fn extract_signed(psbt: &Psbt) -> Result<(String, String), String> {
    let tx = psbt
        .clone()
        .extract_tx()
        .map_err(|_| "psbt is not fully signed")?;
    let txid = tx.compute_txid().to_string();
    Ok((txid, serialize_hex(&tx)))
}

pub fn parse_raw_tx(tx_hex: &str) -> Result<(Vec<u8>, Transaction), String> {
    if tx_hex.len() > 256_000 {
        return Err("transaction is too large".into());
    }
    let raw = hex::decode(tx_hex.trim()).map_err(|_| "tx_hex is not hex")?;
    let tx = deserialize(&raw).map_err(|_| "tx_hex could not be decoded")?;
    Ok((raw, tx))
}

pub fn resolve_prevouts(
    tx: &Transaction,
    funding: &BTreeMap<Txid, Transaction>,
) -> Result<Vec<TxOut>, String> {
    tx.input
        .iter()
        .map(|input| {
            let OutPoint { txid, vout } = input.previous_output;
            funding
                .get(&txid)
                .and_then(|parent| parent.output.get(vout as usize))
                .cloned()
                .ok_or_else(|| format!("prevout {txid}:{vout} could not be resolved"))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRaw {
    pub txid: String,
    pub tx_hex: String,
    pub input_sats: u64,
    pub fee_sats: u64,
    pub dest: String,
    pub complete: bool,
}

/// `prevouts[i]` is the output `tx.input[i]` spends.
#[allow(clippy::too_many_arguments)]
pub fn sign_raw(
    wallet: &Wallet,
    tx: &Transaction,
    prevouts: &[TxOut],
    owned: &BTreeMap<ScriptBuf, (ChainKind, u32)>,
    book: &Lockbook,
    allow: AllowLocked,
    max_input_sats: u64,
    auto_lock_sats: u64,
) -> Result<SignedRaw, String> {
    if prevouts.len() != tx.input.len() {
        return Err("every input needs its prevout".into());
    }
    let spends: Vec<(OutPoint, u64, Scope)> = tx
        .input
        .iter()
        .zip(prevouts)
        .map(|(input, prevout)| {
            let scope = if owned.contains_key(&prevout.script_pubkey) {
                Scope::Wallet
            } else {
                Scope::Foreign
            };
            (input.previous_output, prevout.value.to_sat(), scope)
        })
        .collect();
    let input_sats = spends
        .iter()
        .try_fold(0u64, |total, (_, value, _)| total.checked_add(*value))
        .ok_or("input sum overflow")?;
    enforce_input_cap(input_sats, max_input_sats)?;
    refuse_locked(&spends, book, allow, auto_lock_sats)?;
    if !spends.iter().any(|(_, _, scope)| *scope == Scope::Wallet) {
        return Err("transaction spends no outputs from this wallet".into());
    }
    let output_sats = tx
        .output
        .iter()
        .try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat())
        })
        .ok_or("output sum overflow")?;
    let fee_sats = input_sats
        .checked_sub(output_sats)
        .ok_or("transaction outputs exceed inputs")?;
    let secp = Secp256k1::new();
    let mut cache = SighashCache::new(tx.clone());
    for (index, prevout) in prevouts.iter().enumerate() {
        let Some(&(chain, child)) = owned.get(&prevout.script_pubkey) else {
            continue;
        };
        let derived = wallet.derive(chain, child)?;
        let secret = wallet
            .master_key()
            .derive_priv(&secp, &derived.path)
            .map_err(|_| "derivation path could not be derived".to_string())?
            .private_key;
        let witness = match wallet.script() {
            ScriptKind::Bip84 => {
                let sighash = cache
                    .p2wpkh_signature_hash(
                        index,
                        &prevout.script_pubkey,
                        prevout.value,
                        EcdsaSighashType::All,
                    )
                    .map_err(|_| format!("input {index} could not be hashed"))?;
                let signature = ecdsa::Signature {
                    signature: secp
                        .sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &secret),
                    sighash_type: EcdsaSighashType::All,
                };
                Witness::p2wpkh(&signature, &derived.public_key)
            }
            ScriptKind::Bip86 => {
                let sighash = cache
                    .taproot_key_spend_signature_hash(
                        index,
                        &Prevouts::All(prevouts),
                        TapSighashType::Default,
                    )
                    .map_err(|_| format!("input {index} could not be hashed"))?;
                let keypair = Keypair::from_secret_key(&secp, &secret)
                    .tap_tweak(&secp, None)
                    .to_keypair();
                let signature = taproot::Signature {
                    signature: secp
                        .sign_schnorr(&Message::from_digest(sighash.to_byte_array()), &keypair),
                    sighash_type: TapSighashType::Default,
                };
                Witness::p2tr_key_spend(&signature)
            }
        };
        *cache
            .witness_mut(index)
            .ok_or_else(|| format!("input {index} has no witness"))? = witness;
    }
    let signed = cache.into_transaction();
    Ok(SignedRaw {
        txid: signed.compute_txid().to_string(),
        tx_hex: serialize_hex(&signed),
        input_sats,
        fee_sats,
        dest: external_dest(&signed, owned, wallet.network().bitcoin()),
        complete: signed
            .input
            .iter()
            .all(|input| !input.witness.is_empty() || !input.script_sig.is_empty()),
    })
}

#[cfg(test)]
pub fn verify_p2wpkh_witness(
    tx: &Transaction,
    index: usize,
    input_value: u64,
    script_pubkey: &bitcoin::Script,
) -> Result<(), String> {
    let witness = &tx.input[index].witness;
    if witness.len() != 2 {
        return Err("witness is missing".into());
    }
    let signature = bitcoin::ecdsa::Signature::from_slice(&witness[0])
        .map_err(|_| "witness signature is invalid")?;
    let public_key =
        bitcoin::PublicKey::from_slice(&witness[1]).map_err(|_| "witness pubkey is invalid")?;
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            index,
            script_pubkey,
            Amount::from_sat(input_value),
            signature.sighash_type,
        )
        .map_err(|_| "sighash failed")?;
    let message = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let secp = Secp256k1::new();
    secp.verify_ecdsa(&message, &signature.signature, &public_key.inner)
        .map_err(|_| "signature does not match the spent output".to_string())
}

pub fn parse_txid(value: &str) -> Result<Txid, String> {
    Txid::from_str(value).map_err(|_| "utxo txid is invalid".to_string())
}

pub fn owned_scripts(
    wallet: &Wallet,
    cache: &ScanCache,
    max_index: u32,
    hinted: BTreeSet<(ChainKind, u32)>,
) -> Result<BTreeMap<ScriptBuf, (ChainKind, u32)>, String> {
    let extent = |used: &[u32]| {
        used.iter()
            .copied()
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(cache.receive_cursor)
            .min(max_index)
    };
    let mut indexes = hinted;
    for index in 0..=extent(&cache.used_external) {
        indexes.insert((ChainKind::External, index));
    }
    for index in 0..=extent(&cache.used_change) {
        indexes.insert((ChainKind::Change, index));
    }
    indexes
        .into_iter()
        .map(|(chain, index)| {
            let derived = wallet.derive(chain, index)?;
            Ok((derived.address.script_pubkey(), (chain, index)))
        })
        .collect()
}

pub fn indexes_from_origins(wallet: &Wallet, psbt: &Psbt) -> BTreeSet<(ChainKind, u32)> {
    let mut indexes = BTreeSet::new();
    for input in &psbt.inputs {
        for (fingerprint, path) in input.bip32_derivation.values() {
            remember_origin(wallet, *fingerprint, path, &mut indexes);
        }
        for (_, (fingerprint, path)) in input.tap_key_origins.values() {
            remember_origin(wallet, *fingerprint, path, &mut indexes);
        }
    }
    indexes
}

fn remember_origin(
    wallet: &Wallet,
    fingerprint: Fingerprint,
    path: &DerivationPath,
    indexes: &mut BTreeSet<(ChainKind, u32)>,
) {
    if fingerprint != wallet.fingerprint() {
        return;
    }
    if let Some(index) = path_index(wallet, path) {
        indexes.insert(index);
    }
}

fn path_index(wallet: &Wallet, path: &DerivationPath) -> Option<(ChainKind, u32)> {
    let parts: Vec<ChildNumber> = path.into_iter().copied().collect();
    if parts.len() != 5 {
        return None;
    }
    let purpose = hardened(&parts[0])?;
    let coin = hardened(&parts[1])?;
    let account = hardened(&parts[2])?;
    if purpose != wallet.script().purpose() || coin != wallet.network().coin_type() {
        return None;
    }
    if account != wallet.account() {
        return None;
    }
    let chain = match normal(&parts[3])? {
        0 => ChainKind::External,
        1 => ChainKind::Change,
        _ => return None,
    };
    Some((chain, normal(&parts[4])?))
}

fn hardened(child: &ChildNumber) -> Option<u32> {
    match *child {
        ChildNumber::Hardened { index } => Some(index),
        ChildNumber::Normal { .. } => None,
    }
}

fn normal(child: &ChildNumber) -> Option<u32> {
    match *child {
        ChildNumber::Normal { index } => Some(index),
        ChildNumber::Hardened { .. } => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locks::{InputSet, LockAction};
    use crate::wallet::{ChainKind, NetworkKind, ScriptKind, Wallet, BIP84_MNEMONIC};
    use bitcoin::XOnlyPublicKey;

    const FOREIGN: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn wallet(script: ScriptKind) -> Wallet {
        Wallet::open(BIP84_MNEMONIC.into(), NetworkKind::Mainnet, script, 0).unwrap()
    }

    fn pay<'a>(
        wallet: &'a Wallet,
        coins: &'a [Coin],
        dest: &'a Address,
        change: &'a Address,
        amount: u64,
        feerate: u64,
    ) -> Result<Built, String> {
        pay_capped(wallet, coins, dest, change, amount, feerate, u64::MAX)
    }

    fn pay_capped<'a>(
        wallet: &'a Wallet,
        coins: &'a [Coin],
        dest: &'a Address,
        change: &'a Address,
        amount: u64,
        feerate: u64,
        max_input_sats: u64,
    ) -> Result<Built, String> {
        build_payment(&Payment {
            script: wallet.script(),
            fingerprint: wallet.fingerprint(),
            coins,
            dest,
            amount,
            feerate,
            change,
            max_input_sats,
        })
    }

    fn coin_at(wallet: &Wallet, index: u32, value: u64) -> Coin {
        let derived = wallet.derive(ChainKind::External, index).unwrap();
        Coin {
            txid: Txid::from_str(&format!("{:064x}", index + 1)).unwrap(),
            vout: 0,
            value,
            script_pubkey: derived.address.script_pubkey(),
            path: derived.path,
            public_key: derived.public_key,
            confirmed: true,
        }
    }

    fn psbt_for(coin: &Coin, wallet: Option<&Wallet>) -> Psbt {
        let tx = raw_tx(
            vec![(coin.outpoint(), Witness::new())],
            vec![foreign_out(coin.value - 100)],
        );
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(prevout_of(coin));
        if let Some(wallet) = wallet {
            psbt.inputs[0]
                .bip32_derivation
                .insert(coin.public_key, (wallet.fingerprint(), coin.path.clone()));
        }
        psbt
    }

    fn sign_unlocked(wallet: &Wallet, psbt: &mut Psbt, max_input_sats: u64) -> Result<u64, String> {
        sign_psbt(
            wallet,
            psbt,
            &Lockbook::default(),
            AllowLocked::No,
            max_input_sats,
            330,
        )
    }

    fn foreign_out(sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: Address::from_str(FOREIGN)
                .unwrap()
                .require_network(Network::Bitcoin)
                .unwrap()
                .script_pubkey(),
        }
    }

    fn prevout_of(coin: &Coin) -> TxOut {
        TxOut {
            value: Amount::from_sat(coin.value),
            script_pubkey: coin.script_pubkey.clone(),
        }
    }

    fn theirs(vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_str(&format!("{:064x}", 0xf00)).unwrap(),
            vout,
        }
    }

    fn raw_tx(inputs: Vec<(OutPoint, Witness)>, output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .into_iter()
                .map(|(previous_output, witness)| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness,
                })
                .collect(),
            output,
        }
    }

    fn sign_with(
        wallet: &Wallet,
        tx: &Transaction,
        prevouts: &[TxOut],
        allow: AllowLocked,
        max_input_sats: u64,
    ) -> Result<SignedRaw, String> {
        let owned = owned_scripts(wallet, &ScanCache::default(), 200, BTreeSet::new())?;
        sign_raw(
            wallet,
            tx,
            prevouts,
            &owned,
            &Lockbook::default(),
            allow,
            max_input_sats,
            330,
        )
    }

    fn decode(tx_hex: &str) -> Transaction {
        deserialize(&hex::decode(tx_hex).unwrap()).unwrap()
    }

    fn listed(coins: &[&Coin]) -> InputChoice {
        let items: Vec<String> = coins
            .iter()
            .map(|coin| coin.outpoint().to_string())
            .collect();
        let items: Vec<&str> = items.iter().map(String::as_str).collect();
        InputChoice::Exactly(InputSet::parse("inputs", &items).unwrap())
    }

    fn outpoints_of(coins: &[Coin]) -> Vec<OutPoint> {
        coins.iter().map(Coin::outpoint).collect()
    }

    #[test]
    fn automatic_send_skips_locked_coins_and_listed_inputs_limit_the_pool() {
        let wallet = wallet(ScriptKind::Bip84);
        let charm = coin_at(&wallet, 0, 330);
        let fuel = coin_at(&wallet, 1, 50_000);
        let spare = coin_at(&wallet, 2, 60_000);
        let every = vec![charm.clone(), fuel.clone(), spare.clone()];
        let book = Lockbook::default();

        let pool = coins_for_send(every.clone(), &InputChoice::Auto, &book, 330).unwrap();
        assert_eq!(outpoints_of(&pool), vec![fuel.outpoint(), spare.outpoint()]);
        assert_eq!(
            coins_for_send(vec![charm.clone()], &InputChoice::Auto, &book, 330).unwrap_err(),
            "no selectable utxos; locked outputs were skipped"
        );

        let pool = coins_for_send(every.clone(), &listed(&[&fuel, &charm]), &book, 330).unwrap();
        assert_eq!(outpoints_of(&pool), vec![charm.outpoint(), fuel.outpoint()]);
        let dest = wallet.derive(ChainKind::External, 5).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay(&wallet, &pool, &dest, &change, 20_000, 2).unwrap();
        let spent: Vec<OutPoint> = built
            .psbt
            .unsigned_tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();
        assert_eq!(spent, vec![fuel.outpoint()]);

        let gone = coin_at(&wallet, 9, 1_000);
        assert_eq!(
            coins_for_send(every, &listed(&[&fuel, &gone]), &book, 330).unwrap_err(),
            format!("input {} is not an unspent wallet output", gone.outpoint())
        );
    }

    #[test]
    fn sign_psbt_refuses_a_locked_input_unless_allowed() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let dest = wallet.derive(ChainKind::External, 1).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let mut psbt = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            20_000,
            2,
        )
        .unwrap()
        .psbt;
        let mut book = Lockbook::default();
        let outpoint = coin.outpoint().to_string();
        book.apply(
            LockAction::Lock,
            &InputSet::parse("outpoints", &[&outpoint]).unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(
            sign_psbt(&wallet, &mut psbt, &book, AllowLocked::No, 100_000, 330),
            Err(format!(
                "refusing to spend locked output {outpoint} (manual); pass allow_locked true to spend it"
            ))
        );
        assert!(psbt.inputs[0].final_script_witness.is_none());
        sign_psbt(&wallet, &mut psbt, &book, AllowLocked::Yes, 100_000, 330).unwrap();
        let tx = psbt.extract_tx().unwrap();
        verify_p2wpkh_witness(&tx, 0, coin.value, coin.script_pubkey.as_script()).unwrap();
    }

    #[test]
    fn sign_psbt_auto_lock_follows_the_bip32_origin() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 330);
        let mut owned = psbt_for(&coin, Some(&wallet));
        assert_eq!(
            sign_psbt(
                &wallet,
                &mut owned,
                &Lockbook::default(),
                AllowLocked::No,
                100_000,
                330
            ),
            Err(format!(
                "refusing to spend locked output {} (auto-small); pass allow_locked true to spend it",
                coin.outpoint()
            ))
        );
        assert!(owned.inputs[0].final_script_witness.is_none());

        let mut allowed = psbt_for(&coin, Some(&wallet));
        sign_psbt(
            &wallet,
            &mut allowed,
            &Lockbook::default(),
            AllowLocked::Yes,
            100_000,
            330,
        )
        .unwrap();
        let tx = allowed.extract_tx().unwrap();
        verify_p2wpkh_witness(&tx, 0, 330, coin.script_pubkey.as_script()).unwrap();

        let mut bare = psbt_for(&coin, None);
        assert_eq!(
            sign_psbt(
                &wallet,
                &mut bare,
                &Lockbook::default(),
                AllowLocked::No,
                100_000,
                330
            ),
            Ok(330)
        );
        assert!(bare.inputs[0].partial_sigs.is_empty());
        assert!(bare.inputs[0].final_script_witness.is_none());

        let mut book = Lockbook::default();
        let outpoint = coin.outpoint().to_string();
        book.apply(
            LockAction::Lock,
            &InputSet::parse("outpoints", &[&outpoint]).unwrap(),
            None,
        )
        .unwrap();
        let mut marked = psbt_for(&coin, None);
        assert_eq!(
            sign_psbt(&wallet, &mut marked, &book, AllowLocked::No, 100_000, 330),
            Err(format!(
                "refusing to spend locked output {outpoint} (manual); pass allow_locked true to spend it"
            ))
        );
    }

    #[test]
    fn sign_raw_signs_a_p2wpkh_input_that_verifies() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let tx = raw_tx(
            vec![(coin.outpoint(), Witness::new())],
            vec![foreign_out(49_000)],
        );
        let signed =
            sign_with(&wallet, &tx, &[prevout_of(&coin)], AllowLocked::No, 100_000).unwrap();
        let decoded = decode(&signed.tx_hex);
        verify_p2wpkh_witness(&decoded, 0, coin.value, coin.script_pubkey.as_script()).unwrap();
        assert_eq!(signed.txid, tx.compute_txid().to_string());
        assert_eq!(signed.input_sats, 50_000);
        assert_eq!(signed.fee_sats, 1_000);
        assert_eq!(signed.dest, FOREIGN);
        assert!(signed.complete);
    }

    #[test]
    fn sign_raw_signs_a_p2tr_key_spend_for_the_tweaked_output_key() {
        let wallet = wallet(ScriptKind::Bip86);
        let coin = coin_at(&wallet, 0, 40_000);
        let tx = raw_tx(
            vec![(coin.outpoint(), Witness::new())],
            vec![foreign_out(39_000)],
        );
        let prevouts = [prevout_of(&coin)];
        let signed = sign_with(&wallet, &tx, &prevouts, AllowLocked::No, 100_000).unwrap();
        let decoded = decode(&signed.tx_hex);
        let witness = &decoded.input[0].witness;
        assert_eq!(witness.len(), 1);
        assert_eq!(witness[0].len(), 64);
        let signature = taproot::Signature::from_slice(&witness[0]).unwrap();
        let sighash = SighashCache::new(&decoded)
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .unwrap();
        let output_key = XOnlyPublicKey::from_slice(&coin.script_pubkey.as_bytes()[2..]).unwrap();
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature.signature,
                &Message::from_digest(sighash.to_byte_array()),
                &output_key,
            )
            .unwrap();
    }

    #[test]
    fn sign_raw_leaves_the_foreign_witness_the_op_return_and_the_txid() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let foreign_witness = Witness::from_slice(&[vec![0xde, 0xad], vec![0xbe, 0xef]]);
        let op_return = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([0x73, 0x70, 0x65, 0x6c]),
        };
        let tx = raw_tx(
            vec![
                (theirs(3), foreign_witness.clone()),
                (coin.outpoint(), Witness::new()),
            ],
            vec![op_return.clone(), foreign_out(60_000)],
        );
        let prevouts = [foreign_out(20_000), prevout_of(&coin)];
        let signed = sign_with(&wallet, &tx, &prevouts, AllowLocked::No, 100_000).unwrap();
        let decoded = decode(&signed.tx_hex);
        assert_eq!(decoded.input[0].witness, foreign_witness);
        verify_p2wpkh_witness(&decoded, 1, coin.value, coin.script_pubkey.as_script()).unwrap();
        assert_eq!(decoded.output, vec![op_return, foreign_out(60_000)]);
        assert_eq!(signed.txid, tx.compute_txid().to_string());
        assert_eq!(signed.fee_sats, 10_000);
        assert!(signed.complete);
    }

    #[test]
    fn sign_raw_counts_foreign_inputs_toward_the_cap() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let tx = raw_tx(
            vec![
                (theirs(0), Witness::new()),
                (coin.outpoint(), Witness::new()),
            ],
            vec![foreign_out(90_000)],
        );
        let prevouts = [foreign_out(50_001), prevout_of(&coin)];
        assert_eq!(
            sign_with(&wallet, &tx, &prevouts, AllowLocked::No, 100_000),
            Err("transaction inputs total 100001 sats, above MAX_TX_INPUT_SATS 100000".into())
        );
        let at_cap = sign_with(&wallet, &tx, &prevouts, AllowLocked::No, 100_001).unwrap();
        assert_eq!(at_cap.input_sats, 100_001);
        assert!(!at_cap.complete);
    }

    #[test]
    fn sign_raw_refuses_a_locked_wallet_input_unless_allowed() {
        let wallet = wallet(ScriptKind::Bip84);
        let charm = coin_at(&wallet, 0, 330);
        let fuel = coin_at(&wallet, 1, 50_000);
        let tx = raw_tx(
            vec![
                (charm.outpoint(), Witness::new()),
                (fuel.outpoint(), Witness::new()),
            ],
            vec![foreign_out(330), foreign_out(49_000)],
        );
        let prevouts = [prevout_of(&charm), prevout_of(&fuel)];
        assert_eq!(
            sign_with(&wallet, &tx, &prevouts, AllowLocked::No, 100_000),
            Err(format!(
                "refusing to spend locked output {} (auto-small); pass allow_locked true to spend it",
                charm.outpoint()
            ))
        );
        let signed = sign_with(&wallet, &tx, &prevouts, AllowLocked::Yes, 100_000).unwrap();
        let decoded = decode(&signed.tx_hex);
        verify_p2wpkh_witness(&decoded, 0, 330, charm.script_pubkey.as_script()).unwrap();
        verify_p2wpkh_witness(&decoded, 1, 50_000, fuel.script_pubkey.as_script()).unwrap();

        let foreign_only = raw_tx(vec![(theirs(0), Witness::new())], vec![foreign_out(1_000)]);
        assert_eq!(
            sign_with(
                &wallet,
                &foreign_only,
                &[foreign_out(2_000)],
                AllowLocked::No,
                100_000
            ),
            Err("transaction spends no outputs from this wallet".into())
        );
    }

    #[test]
    fn a_prevout_outside_the_funding_transactions_is_not_resolved() {
        let funding = raw_tx(
            vec![(theirs(0), Witness::new())],
            vec![foreign_out(1_000), foreign_out(2_000)],
        );
        let txid = funding.compute_txid();
        let parents = BTreeMap::from([(txid, funding)]);
        let spend = |vout| raw_tx(vec![(OutPoint { txid, vout }, Witness::new())], vec![]);
        assert_eq!(
            resolve_prevouts(&spend(1), &parents),
            Ok(vec![foreign_out(2_000)])
        );
        assert_eq!(
            resolve_prevouts(&spend(2), &parents),
            Err(format!("prevout {txid}:2 could not be resolved"))
        );
        assert_eq!(
            resolve_prevouts(&spend(1), &BTreeMap::new()),
            Err(format!("prevout {txid}:1 could not be resolved"))
        );
    }

    #[test]
    fn utxo_rows_show_the_lock_verdict_and_where_each_coin_lives() {
        let wallet = wallet(ScriptKind::Bip84);
        let charm = coin_at(&wallet, 0, 330);
        let fuel = coin_at(&wallet, 1, 50_000);
        let derived = wallet.derive(ChainKind::Change, 0).unwrap();
        let change = Coin {
            txid: Txid::from_str(&format!("{:064x}", 0xc0)).unwrap(),
            vout: 2,
            value: 60_000,
            script_pubkey: derived.address.script_pubkey(),
            path: derived.path,
            public_key: derived.public_key,
            confirmed: false,
        };
        let mut book = Lockbook::default();
        let fuel_outpoint = fuel.outpoint().to_string();
        book.apply(
            LockAction::Lock,
            &InputSet::parse("outpoints", &[&fuel_outpoint]).unwrap(),
            None,
        )
        .unwrap();
        let rows = utxo_rows(
            &[charm.clone(), fuel.clone(), change.clone()],
            &book,
            330,
            ScriptKind::Bip84,
            Network::Bitcoin,
        )
        .unwrap();
        assert_eq!(
            rows,
            vec![
                json!({
                    "txid": charm.txid.to_string(),
                    "vout": 0,
                    "value_sats": 330,
                    "confirmed": true,
                    "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                    "script_pubkey": "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2",
                    "script_type": "p2wpkh",
                    "path": "0/0",
                    "locked": true,
                    "lock_reason": "auto-small",
                }),
                json!({
                    "txid": fuel.txid.to_string(),
                    "vout": 0,
                    "value_sats": 50_000,
                    "confirmed": true,
                    "address": "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
                    "script_pubkey": "00149c90f934ea51fa0f6504177043e0908da6929983",
                    "script_type": "p2wpkh",
                    "path": "0/1",
                    "locked": true,
                    "lock_reason": "manual",
                }),
                json!({
                    "txid": change.txid.to_string(),
                    "vout": 2,
                    "value_sats": 60_000,
                    "confirmed": false,
                    "address": "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
                    "script_pubkey": "00143e34985dca6fddc9fb369940e4c7d8e2873f529c",
                    "script_type": "p2wpkh",
                    "path": "1/0",
                    "locked": false,
                }),
            ]
        );
    }

    #[test]
    fn raw_tx_hex_must_decode_to_exactly_one_transaction() {
        let tx = raw_tx(
            vec![(theirs(0), Witness::from_slice(&[[0xde]]))],
            vec![foreign_out(1_000)],
        );
        let tx_hex = serialize_hex(&tx);
        assert_eq!(
            parse_raw_tx(&tx_hex),
            Ok((hex::decode(&tx_hex).unwrap(), tx))
        );
        assert_eq!(
            parse_raw_tx(&format!("{tx_hex}00")),
            Err("tx_hex could not be decoded".into())
        );
        assert_eq!(parse_raw_tx("zz"), Err("tx_hex is not hex".into()));
    }

    #[test]
    fn bip84_psbt_signs_and_the_witness_verifies() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let dest = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            20_000,
            2,
        )
        .unwrap();
        assert!(built.fee_sats > 0);
        assert!(built.fee_sats <= 20_000);
        assert_eq!(built.feerate_sat_vb, 2);
        assert!(!built.outputs.is_empty());
        let unsigned = psbt_from_base64(&psbt_to_base64(&built.psbt)).unwrap();
        assert!(unsigned.inputs[0].partial_sigs.is_empty());

        let mut signed = built.psbt.clone();
        sign_unlocked(&wallet, &mut signed, 100_000).unwrap();
        let (txid, _hex) = extract_signed(&signed).unwrap();
        assert_eq!(txid.len(), 64);
        let tx = signed.extract_tx().unwrap();
        verify_p2wpkh_witness(&tx, 0, coin.value, coin.script_pubkey.as_script()).unwrap();
        assert_eq!(tx.output[0].value.to_sat(), 20_000);
    }

    #[test]
    fn bip86_psbt_signs() {
        let wallet = wallet(ScriptKind::Bip86);
        let coin = coin_at(&wallet, 0, 40_000);
        let dest = wallet.derive(ChainKind::External, 1).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            10_000,
            1,
        )
        .unwrap();
        let mut signed = built.psbt.clone();
        sign_unlocked(&wallet, &mut signed, 100_000).unwrap();
        let (txid, _) = extract_signed(&signed).unwrap();
        assert_eq!(txid.len(), 64);
    }

    #[test]
    fn dust_is_rejected_and_a_high_feerate_is_not_a_cap() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let dest = wallet.derive(ChainKind::External, 1).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            20_000,
            201,
        )
        .unwrap();
        assert!(built.feerate_sat_vb >= 201);
        let err = pay(&wallet, std::slice::from_ref(&coin), &dest, &change, 100, 1).unwrap_err();
        assert!(err.contains("dust"));
    }

    #[test]
    fn the_input_cap_runs_before_a_signature_exists() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let dest = wallet.derive(ChainKind::External, 1).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let mut psbt = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            20_000,
            2,
        )
        .unwrap()
        .psbt;
        let err = sign_unlocked(&wallet, &mut psbt, 49_999).unwrap_err();
        assert!(err.contains("MAX_TX_INPUT_SATS"));
        assert!(psbt.inputs[0].partial_sigs.is_empty());
        sign_unlocked(&wallet, &mut psbt, 50_000).unwrap();

        psbt.inputs[0].witness_utxo = None;
        psbt.inputs[0].non_witness_utxo = None;
        let err = sign_unlocked(&wallet, &mut psbt, 100_000).unwrap_err();
        assert!(err.contains("missing a value"));
    }

    #[test]
    fn sign_psbt_outflow_counts_only_value_leaving_the_wallet() {
        let wallet = wallet(ScriptKind::Bip84);
        let coin = coin_at(&wallet, 0, 50_000);
        let foreign = Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
            .unwrap()
            .require_network(Network::Bitcoin)
            .unwrap();
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &foreign,
            &change,
            20_000,
            2,
        )
        .unwrap();
        let mut owned = BTreeMap::new();
        owned.insert(coin.script_pubkey.clone(), (ChainKind::External, 0));
        owned.insert(change.script_pubkey(), (ChainKind::Change, 0));
        let inspection =
            inspect_psbt(&built.psbt, &owned, ScriptKind::Bip84, Network::Bitcoin).unwrap();
        assert_eq!(inspection.our_inputs, 1);
        assert_eq!(
            inspection.outflow_sats,
            50_000 - (50_000 - 20_000 - inspection.fee_sats)
        );
        assert_eq!(inspection.outflow_sats, 20_000 + inspection.fee_sats);
        assert!(inspection
            .dest
            .contains("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
    }

    #[test]
    fn non_committing_sighash_is_rejected_before_a_signature_exists() {
        let segwit = wallet(ScriptKind::Bip84);
        let coin = coin_at(&segwit, 0, 50_000);
        let dest = segwit.derive(ChainKind::External, 1).unwrap().address;
        let change = segwit.derive(ChainKind::Change, 0).unwrap().address;
        for sighash in [
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay,
        ] {
            let mut psbt = pay(
                &segwit,
                std::slice::from_ref(&coin),
                &dest,
                &change,
                20_000,
                2,
            )
            .unwrap()
            .psbt;
            psbt.inputs[0].sighash_type = Some(sighash.into());
            let err = sign_unlocked(&segwit, &mut psbt, 100_000).unwrap_err();
            assert!(err.contains("not allowed"), "{err}");
            assert!(psbt.inputs[0].partial_sigs.is_empty());
        }

        let tap = wallet(ScriptKind::Bip86);
        let coin = coin_at(&tap, 0, 40_000);
        let dest = tap.derive(ChainKind::External, 1).unwrap().address;
        let change = tap.derive(ChainKind::Change, 0).unwrap().address;
        let mut allowed = pay(&tap, std::slice::from_ref(&coin), &dest, &change, 10_000, 1)
            .unwrap()
            .psbt;
        allowed.inputs[0].sighash_type = Some(TapSighashType::All.into());
        sign_unlocked(&tap, &mut allowed, 100_000).unwrap();

        let mut rejected = pay(&tap, std::slice::from_ref(&coin), &dest, &change, 10_000, 1)
            .unwrap()
            .psbt;
        rejected.inputs[0].sighash_type = Some(TapSighashType::None.into());
        assert!(sign_unlocked(&tap, &mut rejected, 100_000)
            .unwrap_err()
            .contains("not allowed"));
        assert!(rejected.inputs[0].tap_key_sig.is_none());
    }

    #[test]
    fn a_smaller_coin_funds_a_payment_the_largest_coin_cannot() {
        let wallet = wallet(ScriptKind::Bip84);
        let big = coin_at(&wallet, 0, 150_000);
        let small = coin_at(&wallet, 1, 50_000);
        let dest = wallet.derive(ChainKind::External, 2).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let built = pay_capped(
            &wallet,
            &[big, small.clone()],
            &dest,
            &change,
            20_000,
            2,
            100_000,
        )
        .unwrap();
        assert_eq!(built.psbt.unsigned_tx.input.len(), 1);
        assert_eq!(
            built.psbt.unsigned_tx.input[0].previous_output.txid,
            small.txid
        );
        assert_eq!(transaction_input_sats(&built.psbt).unwrap(), 50_000);

        let blocked = coin_at(&wallet, 3, 60_000);
        let left = coin_at(&wallet, 4, 45_000);
        let right = coin_at(&wallet, 5, 45_000);
        let split = pay_capped(
            &wallet,
            &[blocked, left, right],
            &dest,
            &change,
            70_000,
            1,
            100_000,
        )
        .unwrap();
        assert_eq!(split.psbt.unsigned_tx.input.len(), 2);
        assert_eq!(transaction_input_sats(&split.psbt).unwrap(), 90_000);

        let oversized = coin_at(&wallet, 6, 150_000);
        let err = pay_capped(
            &wallet,
            std::slice::from_ref(&oversized),
            &dest,
            &change,
            20_000,
            1,
            100_000,
        )
        .unwrap_err();
        assert!(err.contains("MAX_TX_INPUT_SATS"), "{err}");
    }

    #[test]
    fn taproot_key_origins_identify_an_owned_input() {
        let wallet = wallet(ScriptKind::Bip86);
        let coin = coin_at(&wallet, 50, 40_000);
        let dest = wallet.derive(ChainKind::External, 1).unwrap().address;
        let change = wallet.derive(ChainKind::Change, 0).unwrap().address;
        let mut psbt = pay(
            &wallet,
            std::slice::from_ref(&coin),
            &dest,
            &change,
            10_000,
            1,
        )
        .unwrap()
        .psbt;
        psbt.inputs[0].bip32_derivation.clear();
        assert!(!psbt.inputs[0].tap_key_origins.is_empty());
        let indexes = indexes_from_origins(&wallet, &psbt);
        assert!(indexes.contains(&(ChainKind::External, 50)));
        let mut owned = BTreeMap::new();
        for (chain, index) in indexes {
            let derived = wallet.derive(chain, index).unwrap();
            owned.insert(derived.address.script_pubkey(), (chain, index));
        }
        inspect_psbt(&psbt, &owned, ScriptKind::Bip86, Network::Bitcoin).unwrap();
    }
}
