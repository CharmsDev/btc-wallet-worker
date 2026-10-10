use crate::guard::{SpendKind, SpendRecord};
use crate::locks::{AllowLocked, InputSet};
use crate::wallet::{NetworkKind, ScriptKind, Wallet};
use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

/// The claim is taken before the UTXO scan, and that scan can use the default
/// MAX_CHAIN_CALLS of 80 Esplora calls. Three minutes covers the scan plus signing.
pub const CLAIM_LEASE_MS: u64 = 180_000;
pub const MAX_LIVE: usize = 512;
/// Stays under the 2 MB Durable Object value limit.
pub const MAX_BODY_BYTES: usize = 900_000;
pub const INDEX_KEY: &str = "idem";
const DOMAIN: &[u8] = b"satchel.idem.v1\0";

pub fn body_key(id: u64) -> String {
    format!("idb/{id}")
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RequestId(String);

impl RequestId {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let value = raw.trim();
        let valid = !value.is_empty()
            && value.len() <= 80
            && value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c));
        if !valid {
            return Err("request_id must be 1-80 characters of letters, digits, or . _ : -".into());
        }
        Ok(Self(value.to_string()))
    }
}

impl TryFrom<String> for RequestId {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        Self::parse(&value)
    }
}

impl From<RequestId> for String {
    fn from(id: RequestId) -> Self {
        id.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Stored as `client/request_id` so the index stays a string-keyed map. Client
/// names come from `Clients::parse`, which does not allow `/`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Slot {
    client: String,
    request_id: RequestId,
}

impl Slot {
    pub fn new(client: &str, request_id: RequestId) -> Self {
        Self {
            client: client.to_string(),
            request_id,
        }
    }

    pub fn request_id(&self) -> &RequestId {
        &self.request_id
    }
}

impl TryFrom<String> for Slot {
    type Error = String;

    fn try_from(value: String) -> Result<Self, String> {
        let (client, id) = value
            .split_once('/')
            .filter(|(client, _)| !client.is_empty())
            .ok_or("idempotency slot is malformed")?;
        Ok(Self::new(client, RequestId::parse(id)?))
    }
}

impl From<Slot> for String {
    fn from(slot: Slot) -> Self {
        format!("{}/{}", slot.client, slot.request_id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalletStamp {
    pub network: NetworkKind,
    pub script: ScriptKind,
    pub account: u32,
    pub fingerprint: [u8; 4],
}

impl WalletStamp {
    pub fn of(wallet: &Wallet) -> Self {
        Self {
            network: wallet.network(),
            script: wallet.script(),
            account: wallet.account(),
            fingerprint: wallet.fingerprint().to_bytes(),
        }
    }

    fn prefix(&self, kind: u8) -> Vec<u8> {
        let network = match self.network {
            NetworkKind::Mainnet => 0,
            NetworkKind::Testnet => 1,
            NetworkKind::Signet => 2,
            NetworkKind::Regtest => 3,
        };
        let script = match self.script {
            ScriptKind::Bip84 => 84,
            ScriptKind::Bip86 => 86,
        };
        let mut bytes = DOMAIN.to_vec();
        bytes.extend_from_slice(&[kind, network, script]);
        bytes.extend_from_slice(&self.account.to_be_bytes());
        bytes.extend_from_slice(&self.fingerprint);
        bytes
    }
}

fn push_len_bytes(bytes: &mut Vec<u8>, payload: &[u8]) {
    let length = u64::try_from(payload.len()).expect("payload length fits in u64");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Canon([u8; 32]);

impl Canon {
    /// `feerate` is the client's argument, not the estimate a build substitutes,
    /// so a retry after estimates move is the same request. Omitted `inputs`
    /// writes nothing, so a send without them keeps the hash it had before locks.
    pub fn send(
        wallet: &WalletStamp,
        script_pubkey: &[u8],
        sats: u64,
        feerate: Option<u64>,
        inputs: Option<&InputSet>,
    ) -> Self {
        let mut bytes = wallet.prefix(1);
        push_len_bytes(&mut bytes, script_pubkey);
        bytes.extend_from_slice(&sats.to_be_bytes());
        match feerate {
            None => bytes.push(0),
            Some(rate) => {
                bytes.push(1);
                bytes.extend_from_slice(&rate.to_be_bytes());
            }
        }
        if let Some(inputs) = inputs {
            let outpoints = inputs.outpoints();
            let count = u32::try_from(outpoints.len()).expect("input count fits in u32");
            bytes.push(1);
            bytes.extend_from_slice(&count.to_be_bytes());
            for outpoint in outpoints {
                bytes.extend_from_slice(&outpoint.txid.to_byte_array());
                bytes.extend_from_slice(&outpoint.vout.to_be_bytes());
            }
        }
        Self::digest(&bytes)
    }

    /// `AllowLocked::No` writes nothing, so it keeps the hash a sign had before locks.
    pub fn sign(
        wallet: &WalletStamp,
        unsigned_txid: [u8; 32],
        broadcast: bool,
        allow: AllowLocked,
    ) -> Self {
        let mut bytes = wallet.prefix(2);
        bytes.extend_from_slice(&unsigned_txid);
        bytes.push(u8::from(broadcast));
        match allow {
            AllowLocked::No => {}
            AllowLocked::Yes => bytes.push(1),
        }
        Self::digest(&bytes)
    }

    /// Hashes the client's bytes, not the txid, so a changed witness is a new request.
    pub fn sign_tx(
        wallet: &WalletStamp,
        raw_tx: &[u8],
        broadcast: bool,
        allow: AllowLocked,
    ) -> Self {
        let mut bytes = wallet.prefix(3);
        push_len_bytes(&mut bytes, raw_tx);
        bytes.push(u8::from(broadcast));
        bytes.push(match allow {
            AllowLocked::No => 0,
            AllowLocked::Yes => 1,
        });
        Self::digest(&bytes)
    }

    fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Claimed { deadline_ms: u64 },
    Ready { disposition: Disposition },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Disposition {
    SignedOnly,
    Pending,
    Accepted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Meta {
    body_id: Option<u64>,
    hash: Canon,
    generation: u64,
    created_ms: u64,
    expires_ms: u64,
    phase: Phase,
    txid: Option<String>,
}

impl Meta {
    fn replay(&self, disposition: Disposition, loaded: Option<&Body>) -> Decision {
        let Some(body) = loaded else {
            return Decision::Missing;
        };
        match disposition {
            Disposition::SignedOnly | Disposition::Accepted => Decision::Return {
                response: body.response.clone(),
            },
            Disposition::Pending => match (&self.txid, &body.raw_tx_hex) {
                (Some(txid), Some(raw_tx_hex)) => Decision::Rebroadcast {
                    generation: self.generation,
                    txid: txid.clone(),
                    raw_tx_hex: raw_tx_hex.clone(),
                    response: body.response.clone(),
                },
                _ => Decision::Missing,
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    next_body_id: u64,
    next_generation: u64,
    records: BTreeMap<Slot, Meta>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            next_body_id: 1,
            next_generation: 1,
            records: BTreeMap::new(),
        }
    }
}

impl Index {
    pub fn stored_body_id(&self, slot: &Slot) -> Option<u64> {
        self.records.get(slot).and_then(|meta| meta.body_id)
    }

    fn sweep(&mut self, now_ms: u64) -> Vec<u64> {
        let mut dropped = Vec::new();
        self.records.retain(|_, meta| {
            let lapsed = match meta.phase {
                Phase::Claimed { deadline_ms } => deadline_ms <= now_ms,
                Phase::Ready { .. } => false,
            };
            let keep = now_ms < meta.expires_ms && !lapsed;
            if !keep {
                dropped.extend(meta.body_id);
            }
            keep
        });
        dropped
    }

    fn begin(
        &mut self,
        slot: Slot,
        hash: Canon,
        ttl_ms: u64,
        loaded: Option<&Body>,
        now_ms: u64,
    ) -> Decision {
        let live = self.records.len();
        let Some(meta) = self.records.get(&slot) else {
            if live >= MAX_LIVE {
                return Decision::StorageFull;
            }
            let generation = bump(&mut self.next_generation);
            self.records.insert(
                slot,
                Meta {
                    body_id: None,
                    hash,
                    generation,
                    created_ms: now_ms,
                    expires_ms: now_ms.saturating_add(ttl_ms),
                    phase: Phase::Claimed {
                        deadline_ms: now_ms.saturating_add(CLAIM_LEASE_MS),
                    },
                    txid: None,
                },
            );
            return Decision::Proceed { generation };
        };
        if meta.hash != hash {
            return Decision::Mismatch {
                txid: meta.txid.clone(),
            };
        }
        match meta.phase {
            // The sweep already dropped every claim whose lease ran out, so this one is live.
            Phase::Claimed { .. } => Decision::InProgress,
            Phase::Ready { disposition } => meta.replay(disposition, loaded),
        }
    }

    fn commit(
        &mut self,
        slot: Slot,
        generation: u64,
        hash: Canon,
        artifact: Artifact,
        loaded: Option<&Body>,
    ) -> (Decision, Option<SpendDraft>, Option<(u64, Body)>) {
        let Some(meta) = self.records.get_mut(&slot) else {
            return (Decision::Stale, None, None);
        };
        if meta.hash != hash {
            let txid = meta.txid.clone();
            return (Decision::Mismatch { txid }, None, None);
        }
        match meta.phase {
            Phase::Ready { disposition } => (meta.replay(disposition, loaded), None, None),
            Phase::Claimed { .. } if meta.generation != generation => {
                (Decision::InProgress, None, None)
            }
            Phase::Claimed { .. } => {
                let (body, disposition, txid, facts) = artifact.seal();
                if body.weight() > MAX_BODY_BYTES {
                    self.records.remove(&slot);
                    return (Decision::TooLarge, None, None);
                }
                let body_id = bump(&mut self.next_body_id);
                meta.body_id = Some(body_id);
                meta.phase = Phase::Ready { disposition };
                meta.txid = Some(txid.clone());
                let decision = meta.replay(disposition, Some(&body));
                let spend = SpendDraft {
                    txid,
                    input_sats: facts.input_sats,
                    dest: facts.dest,
                    fee_sats: facts.fee_sats,
                    kind: facts.kind,
                    client: slot.client.clone(),
                    request_id: slot.request_id.to_string(),
                    id: format!("idem-{body_id}"),
                };
                (decision, Some(spend), Some((body_id, body)))
            }
        }
    }

    fn note_accepted(&mut self, slot: &Slot, generation: u64, loaded: Option<&Body>) -> Decision {
        let Some(meta) = self.records.get_mut(slot) else {
            return Decision::Stale;
        };
        if meta.generation != generation {
            return Decision::Stale;
        }
        match meta.phase {
            Phase::Ready {
                disposition: Disposition::Pending | Disposition::Accepted,
            } => {
                meta.phase = Phase::Ready {
                    disposition: Disposition::Accepted,
                };
                meta.replay(Disposition::Accepted, loaded)
            }
            Phase::Ready {
                disposition: Disposition::SignedOnly,
            }
            | Phase::Claimed { .. } => Decision::Stale,
        }
    }

    fn abort(&mut self, slot: &Slot, generation: u64) -> Decision {
        let Some(meta) = self.records.get(slot) else {
            return Decision::Stale;
        };
        match meta.phase {
            Phase::Claimed { .. } if meta.generation == generation => {
                self.records.remove(slot);
                Decision::Cleared
            }
            Phase::Claimed { .. } | Phase::Ready { .. } => Decision::Stale,
        }
    }
}

fn bump(counter: &mut u64) -> u64 {
    let value = *counter;
    *counter += 1;
    value
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Body {
    raw_tx_hex: Option<String>,
    response: Value,
}

impl Body {
    fn weight(&self) -> usize {
        serde_json::to_vec(self).map_or(usize::MAX, |bytes| bytes.len())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendFacts {
    pub kind: SpendKind,
    pub input_sats: u64,
    pub dest: String,
    pub fee_sats: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Artifact {
    Broadcast {
        raw_tx_hex: String,
        response: Value,
        txid: String,
        facts: SpendFacts,
    },
    SignedOnly {
        response: Value,
        txid: String,
        facts: SpendFacts,
    },
}

impl Artifact {
    fn seal(self) -> (Body, Disposition, String, SpendFacts) {
        match self {
            Artifact::Broadcast {
                raw_tx_hex,
                response,
                txid,
                facts,
            } => (
                Body {
                    raw_tx_hex: Some(raw_tx_hex),
                    response,
                },
                Disposition::Pending,
                txid,
                facts,
            ),
            Artifact::SignedOnly {
                response,
                txid,
                facts,
            } => (
                Body {
                    raw_tx_hex: None,
                    response,
                },
                Disposition::SignedOnly,
                txid,
                facts,
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum Op {
    Begin {
        slot: Slot,
        hash: Canon,
        ttl_ms: u64,
    },
    Commit {
        slot: Slot,
        generation: u64,
        hash: Canon,
        artifact: Artifact,
    },
    NoteAccepted {
        slot: Slot,
        generation: u64,
    },
    Abort {
        slot: Slot,
        generation: u64,
    },
}

impl Op {
    pub fn slot(&self) -> &Slot {
        match self {
            Op::Begin { slot, .. }
            | Op::Commit { slot, .. }
            | Op::NoteAccepted { slot, .. }
            | Op::Abort { slot, .. } => slot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    Proceed {
        generation: u64,
    },
    Return {
        response: Value,
    },
    Rebroadcast {
        generation: u64,
        txid: String,
        raw_tx_hex: String,
        response: Value,
    },
    InProgress,
    Mismatch {
        txid: Option<String>,
    },
    StorageFull,
    TooLarge,
    Missing,
    Stale,
    Cleared,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendDraft {
    txid: String,
    input_sats: u64,
    dest: String,
    fee_sats: u64,
    kind: SpendKind,
    client: String,
    request_id: String,
    id: String,
}

impl SpendDraft {
    pub fn into_record(self, at_ms: u64) -> SpendRecord {
        SpendRecord {
            txid: self.txid,
            input_sats: self.input_sats,
            dest: self.dest,
            fee_sats: self.fee_sats,
            at_ms,
            client: self.client,
            kind: self.kind,
            id: self.id,
            request_id: self.request_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub decision: Decision,
    pub spend: Option<SpendDraft>,
    pub put_body: Option<(u64, Body)>,
    pub delete_body_ids: Vec<u64>,
}

/// `loaded` is the stored body for the op's slot, read in the same storage
/// transaction that will persist the outcome.
pub fn apply(index: &mut Index, loaded: Option<&Body>, now_ms: u64, op: Op) -> Outcome {
    let delete_body_ids = index.sweep(now_ms);
    let (decision, spend, put_body) = match op {
        Op::Begin { slot, hash, ttl_ms } => {
            (index.begin(slot, hash, ttl_ms, loaded, now_ms), None, None)
        }
        Op::Commit {
            slot,
            generation,
            hash,
            artifact,
        } => index.commit(slot, generation, hash, artifact, loaded),
        Op::NoteAccepted { slot, generation } => {
            (index.note_accepted(&slot, generation, loaded), None, None)
        }
        Op::Abort { slot, generation } => (index.abort(&slot, generation), None, None),
    };
    Outcome {
        decision,
        spend,
        put_body,
        delete_body_ids,
    }
}

pub fn client_message(decision: &Decision, request_id: &RequestId) -> String {
    match decision {
        Decision::InProgress => format!(
            "request_id {request_id} is in progress. Retry the same arguments with the same request_id"
        ),
        Decision::Mismatch { txid: None } => {
            format!("request_id {request_id} was already used with different parameters")
        }
        Decision::Mismatch { txid: Some(txid) } => format!(
            "request_id {request_id} was already used with different parameters for txid {txid}"
        ),
        Decision::StorageFull => "idempotency store is full".into(),
        Decision::TooLarge => "signed transaction is too large to store".into(),
        Decision::Missing => format!(
            "stored transaction for request_id {request_id} is missing. Wait for it to expire before reusing this request_id"
        ),
        Decision::Stale => format!(
            "request_id {request_id} moved on. Retry the same arguments with the same request_id"
        ),
        Decision::Proceed { .. }
        | Decision::Return { .. }
        | Decision::Rebroadcast { .. }
        | Decision::Cleared => {
            format!("request_id {request_id} got an unexpected reply from the idempotency store")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::parse_address;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};
    use serde_json::json;

    const T0: u64 = 1_800_000_000_000;
    const TTL: u64 = 604_800_000;
    const TXID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TXID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const DEST: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    #[derive(Default)]
    struct Store {
        index: Index,
        bodies: BTreeMap<u64, Body>,
        spends: Vec<String>,
    }

    impl Store {
        fn run(&mut self, now_ms: u64, op: Op) -> Decision {
            let loaded = self
                .index
                .stored_body_id(op.slot())
                .and_then(|id| self.bodies.get(&id).cloned());
            let outcome = apply(&mut self.index, loaded.as_ref(), now_ms, op);
            self.spends.extend(outcome.spend.map(|spend| spend.id));
            if let Some((id, body)) = outcome.put_body {
                self.bodies.insert(id, body);
            }
            for id in outcome.delete_body_ids {
                self.bodies.remove(&id);
            }
            outcome.decision
        }

        fn raw_hexes(&self) -> Vec<String> {
            self.bodies
                .values()
                .filter_map(|body| body.raw_tx_hex.clone())
                .collect()
        }
    }

    fn stamp() -> WalletStamp {
        WalletStamp {
            network: NetworkKind::Mainnet,
            script: ScriptKind::Bip84,
            account: 0,
            fingerprint: [0x73, 0xc5, 0xda, 0x0a],
        }
    }

    fn key(id: &str) -> Slot {
        Slot::new("cursor", RequestId::parse(id).unwrap())
    }

    fn script_of(address: &str) -> Vec<u8> {
        parse_address(address, NetworkKind::Mainnet)
            .unwrap()
            .script_pubkey()
            .to_bytes()
    }

    fn send_hash(feerate: Option<u64>) -> Canon {
        Canon::send(&stamp(), &script_of(DEST), 25_000, feerate, None)
    }

    fn preimage(kind: u8) -> Vec<u8> {
        let mut bytes = b"satchel.idem.v1\0".to_vec();
        bytes.extend_from_slice(&[kind, 0, 84, 0, 0, 0, 0, 0x73, 0xc5, 0xda, 0x0a]);
        bytes
    }

    fn inputs(items: &[&str]) -> InputSet {
        InputSet::parse("inputs", items).unwrap()
    }

    fn begin(slot: &Slot, hash: Canon) -> Op {
        Op::Begin {
            slot: slot.clone(),
            hash,
            ttl_ms: TTL,
        }
    }

    fn commit(slot: &Slot, generation: u64, hash: Canon, raw_tx_hex: &str, txid: &str) -> Op {
        Op::Commit {
            slot: slot.clone(),
            generation,
            hash,
            artifact: Artifact::Broadcast {
                raw_tx_hex: raw_tx_hex.into(),
                response: receipt(txid),
                txid: txid.into(),
                facts: SpendFacts {
                    kind: SpendKind::Send,
                    input_sats: 30_000,
                    dest: DEST.into(),
                    fee_sats: 141,
                },
            },
        }
    }

    fn receipt(txid: &str) -> Value {
        json!({ "broadcast": true, "signed": true, "txid": txid, "fee_sats": 141 })
    }

    fn rebroadcast(generation: u64, raw_tx_hex: &str, txid: &str) -> Decision {
        Decision::Rebroadcast {
            generation,
            txid: txid.into(),
            raw_tx_hex: raw_tx_hex.into(),
            response: receipt(txid),
        }
    }

    #[test]
    fn replay_same_params() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        assert_eq!(
            store.run(T0, begin(&slot, hash)),
            Decision::Proceed { generation: 1 }
        );
        assert_eq!(
            store.run(T0 + 2_000, commit(&slot, 1, hash, "aaaa", TXID_A)),
            rebroadcast(1, "aaaa", TXID_A)
        );
        assert_eq!(store.spends, ["idem-1"]);
        assert_eq!(
            store.run(T0 + 60_000, begin(&slot, hash)),
            Decision::Rebroadcast {
                generation: 1,
                txid: TXID_A.into(),
                raw_tx_hex: "aaaa".into(),
                response: json!({ "broadcast": true, "signed": true, "txid": TXID_A, "fee_sats": 141 }),
            }
        );
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn mismatched_params_are_rejected() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        assert_eq!(
            store.run(T0, begin(&slot, send_hash(Some(5)))),
            Decision::Proceed { generation: 1 }
        );
        let while_claimed = store.run(T0, begin(&slot, send_hash(Some(6))));
        assert_eq!(while_claimed, Decision::Mismatch { txid: None });
        assert_eq!(
            client_message(&while_claimed, slot.request_id()),
            "request_id invoice-8841 was already used with different parameters"
        );
        store.run(T0, commit(&slot, 1, send_hash(Some(5)), "aaaa", TXID_A));
        for feerate in [Some(6), None] {
            let decision = store.run(T0 + 1_000, begin(&slot, send_hash(feerate)));
            assert_eq!(
                decision,
                Decision::Mismatch {
                    txid: Some(TXID_A.into())
                }
            );
            assert_eq!(
                client_message(&decision, slot.request_id()),
                format!("request_id invoice-8841 was already used with different parameters for txid {TXID_A}")
            );
        }
        assert_eq!(
            store.run(
                T0 + 1_000,
                commit(&slot, 1, send_hash(Some(6)), "bbbb", TXID_B)
            ),
            Decision::Mismatch {
                txid: Some(TXID_A.into())
            }
        );
        assert_eq!(store.raw_hexes(), ["aaaa"]);
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn rebroadcast_after_lost_response() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(None);
        store.run(T0, begin(&slot, hash));
        store.run(T0 + 1_000, commit(&slot, 1, hash, "bbbb", TXID_B));
        assert_eq!(
            store.run(T0 + 30_000, begin(&slot, hash)),
            rebroadcast(1, "bbbb", TXID_B)
        );
        assert_eq!(
            store.run(
                T0 + 31_000,
                Op::NoteAccepted {
                    slot: slot.clone(),
                    generation: 1
                }
            ),
            Decision::Return {
                response: receipt(TXID_B)
            }
        );
        assert_eq!(
            store.run(T0 + 32_000, begin(&slot, hash)),
            Decision::Return {
                response: receipt(TXID_B)
            }
        );
        assert_eq!(
            store.run(
                T0 + 33_000,
                Op::NoteAccepted {
                    slot: slot.clone(),
                    generation: 1
                }
            ),
            Decision::Return {
                response: receipt(TXID_B)
            }
        );
        assert_eq!(
            store.run(
                T0 + 33_000,
                Op::NoteAccepted {
                    slot,
                    generation: 2
                }
            ),
            Decision::Stale
        );
        assert_eq!(store.raw_hexes(), ["bbbb"]);
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn concurrent_same_key_signs_once() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        assert_eq!(
            store.run(T0, begin(&slot, hash)),
            Decision::Proceed { generation: 1 }
        );
        let second = store.run(T0, begin(&slot, hash));
        assert_eq!(second, Decision::InProgress);
        assert_eq!(
            client_message(&second, slot.request_id()),
            "request_id invoice-8841 is in progress. Retry the same arguments with the same request_id"
        );
        assert_eq!(
            store.run(T0 + 1_000, commit(&slot, 2, hash, "loser", TXID_B)),
            Decision::InProgress
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());
        assert_eq!(
            store.run(T0 + 2_000, commit(&slot, 1, hash, "winner", TXID_A)),
            rebroadcast(1, "winner", TXID_A)
        );
        assert_eq!(
            store.run(T0 + 3_000, commit(&slot, 2, hash, "loser", TXID_B)),
            rebroadcast(1, "winner", TXID_A)
        );
        assert_eq!(store.raw_hexes(), ["winner"]);
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn ttl_expiry_frees_the_key() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        store.run(T0, begin(&slot, hash));
        store.run(T0, commit(&slot, 1, hash, "aaaa", TXID_A));
        assert_eq!(
            store.run(T0 + TTL - 1, begin(&slot, hash)),
            rebroadcast(1, "aaaa", TXID_A)
        );
        assert_eq!(
            store.run(T0 + TTL, begin(&slot, hash)),
            Decision::Proceed { generation: 2 }
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());
        assert_eq!(
            store.run(T0 + TTL, commit(&slot, 1, hash, "cccc", TXID_B)),
            Decision::InProgress
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());

        let mut reused = Store::default();
        reused.run(T0, begin(&slot, hash));
        reused.run(T0, commit(&slot, 1, hash, "aaaa", TXID_A));
        assert_eq!(
            reused.run(T0 + TTL, begin(&slot, send_hash(Some(6)))),
            Decision::Proceed { generation: 2 }
        );
        assert_eq!(reused.spends, ["idem-1"]);
    }

    #[test]
    fn lease_takeover_discards_the_stale_signature() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        assert_eq!(
            store.run(T0, begin(&slot, hash)),
            Decision::Proceed { generation: 1 }
        );
        assert_eq!(
            store.run(T0 + CLAIM_LEASE_MS - 1, begin(&slot, hash)),
            Decision::InProgress
        );
        assert_eq!(
            store.run(T0 + CLAIM_LEASE_MS, begin(&slot, hash)),
            Decision::Proceed { generation: 2 }
        );
        assert_eq!(
            store.run(
                T0 + CLAIM_LEASE_MS + 1,
                commit(&slot, 1, hash, "stale", TXID_B)
            ),
            Decision::InProgress
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());
        assert_eq!(
            store.run(
                T0 + CLAIM_LEASE_MS + 2,
                commit(&slot, 2, hash, "fresh", TXID_A)
            ),
            rebroadcast(2, "fresh", TXID_A)
        );
        assert_eq!(store.raw_hexes(), ["fresh"]);
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn a_full_store_refuses_a_new_key_without_dropping_a_live_one() {
        let mut store = Store::default();
        for n in 0..MAX_LIVE as u64 {
            let slot = key(&format!("pay-{n}"));
            let hash = send_hash(Some(n));
            assert_eq!(
                store.run(T0, begin(&slot, hash)),
                Decision::Proceed { generation: n + 1 }
            );
            store.run(
                T0,
                commit(
                    &slot,
                    n + 1,
                    hash,
                    &format!("{n:04x}"),
                    &format!("{n:064x}"),
                ),
            );
        }
        let overflow = key("pay-overflow");
        let refused = store.run(T0 + 1, begin(&overflow, send_hash(None)));
        assert_eq!(refused, Decision::StorageFull);
        assert_eq!(
            client_message(&refused, overflow.request_id()),
            "idempotency store is full"
        );
        for n in 0..MAX_LIVE as u64 {
            assert_eq!(
                store.run(T0 + 2, begin(&key(&format!("pay-{n}")), send_hash(Some(n)))),
                rebroadcast(n + 1, &format!("{n:04x}"), &format!("{n:064x}"))
            );
        }
    }

    #[test]
    fn omitted_feerate_hashes_apart_from_an_explicit_rate() {
        let lower = script_of(DEST);
        let upper = script_of("BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU");
        assert_ne!(
            Canon::send(&stamp(), &lower, 25_000, None, None),
            Canon::send(&stamp(), &lower, 25_000, Some(5), None)
        );
        assert_eq!(
            Canon::send(&stamp(), &lower, 25_000, Some(5), None),
            Canon::send(&stamp(), &upper, 25_000, Some(5), None)
        );
        let other_seed = WalletStamp {
            fingerprint: [0, 0, 0, 0],
            ..stamp()
        };
        assert_ne!(
            Canon::send(&other_seed, &lower, 25_000, Some(5), None),
            Canon::send(&stamp(), &lower, 25_000, Some(5), None)
        );
    }

    #[test]
    fn a_send_without_inputs_hashes_the_bytes_it_hashed_before_locks() {
        let script = script_of(DEST);
        let mut bytes = preimage(1);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 22]);
        bytes.extend_from_slice(&script);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x61, 0xa8]);
        bytes.push(0);
        assert_eq!(
            Canon::send(&stamp(), &script, 25_000, None, None),
            Canon(Sha256::digest(&bytes).into())
        );
    }

    #[test]
    fn listed_inputs_hash_as_a_set() {
        let script = script_of(DEST);
        let first = format!("{TXID_A}:0");
        let second = format!("{TXID_B}:1");
        let send = |listed: Option<&InputSet>| Canon::send(&stamp(), &script, 25_000, None, listed);
        assert_eq!(
            send(Some(&inputs(&[&first, &second]))),
            send(Some(&inputs(&[&second, &first])))
        );
        assert_ne!(
            send(Some(&inputs(&[&first]))),
            send(Some(&inputs(&[&first, &second])))
        );
        assert_ne!(send(None), send(Some(&inputs(&[&first]))));

        let mut bytes = preimage(1);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 22]);
        bytes.extend_from_slice(&script);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0x61, 0xa8]);
        bytes.extend_from_slice(&[0, 1, 0, 0, 0, 1]);
        bytes.extend_from_slice(&[0xaa; 32]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            send(Some(&inputs(&[&first]))),
            Canon(Sha256::digest(&bytes).into())
        );
    }

    #[test]
    fn a_sign_hash_covers_the_versioned_bytes_and_the_broadcast_flag() {
        let mut bytes = preimage(2);
        bytes.extend_from_slice(&[0xab; 32]);
        bytes.push(1);
        assert_eq!(
            Canon::sign(&stamp(), [0xab; 32], true, AllowLocked::No),
            Canon(Sha256::digest(&bytes).into())
        );
        assert_ne!(
            Canon::sign(&stamp(), [0xab; 32], false, AllowLocked::No),
            Canon::sign(&stamp(), [0xab; 32], true, AllowLocked::No)
        );
        bytes.push(1);
        assert_eq!(
            Canon::sign(&stamp(), [0xab; 32], true, AllowLocked::Yes),
            Canon(Sha256::digest(&bytes).into())
        );
    }

    #[test]
    fn a_sign_tx_hash_covers_the_raw_bytes_including_the_witness() {
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::from_slice(&[[0xde]]),
            }],
            output: vec![],
        };
        let raw = serialize(&tx);
        tx.input[0].witness = Witness::from_slice(&[[0xdf]]);
        let rewitnessed = serialize(&tx);
        assert_eq!(raw.len(), rewitnessed.len());
        assert_ne!(
            Canon::sign_tx(&stamp(), &raw, false, AllowLocked::No),
            Canon::sign_tx(&stamp(), &rewitnessed, false, AllowLocked::No)
        );
        assert_ne!(
            Canon::sign_tx(&stamp(), &[0xab; 32], true, AllowLocked::No),
            Canon::sign(&stamp(), [0xab; 32], true, AllowLocked::No)
        );

        let mut bytes = preimage(3);
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 2, 0x02, 0x00]);
        bytes.extend_from_slice(&[1, 0]);
        assert_eq!(
            Canon::sign_tx(&stamp(), &[0x02, 0x00], true, AllowLocked::No),
            Canon(Sha256::digest(&bytes).into())
        );
        assert_ne!(
            Canon::sign_tx(&stamp(), &[0x02, 0x00], true, AllowLocked::Yes),
            Canon(Sha256::digest(&bytes).into())
        );
    }

    #[test]
    fn a_signed_only_sign_tx_replays_the_stored_hex() {
        let mut store = Store::default();
        let slot = key("coinjoin-12");
        let hash = Canon::sign_tx(&stamp(), &[0x02, 0x00], false, AllowLocked::No);
        let response =
            json!({ "broadcast": false, "signed": true, "txid": TXID_A, "tx_hex": "0200beef" });
        assert_eq!(
            store.run(T0, begin(&slot, hash)),
            Decision::Proceed { generation: 1 }
        );
        let committed = store.run(
            T0 + 1,
            Op::Commit {
                slot: slot.clone(),
                generation: 1,
                hash,
                artifact: Artifact::SignedOnly {
                    response: response.clone(),
                    txid: TXID_A.into(),
                    facts: SpendFacts {
                        kind: SpendKind::SignTx,
                        input_sats: 50_000,
                        dest: DEST.into(),
                        fee_sats: 1_000,
                    },
                },
            },
        );
        assert_eq!(
            committed,
            Decision::Return {
                response: response.clone()
            }
        );
        assert_eq!(
            store.run(T0 + 60_000, begin(&slot, hash)),
            Decision::Return { response }
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());
        assert_eq!(store.spends, ["idem-1"]);
    }

    #[test]
    fn abort_after_a_commit_keeps_the_stored_transaction() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        store.run(T0, begin(&slot, hash));
        store.run(T0 + 1, commit(&slot, 1, hash, "aaaa", TXID_A));
        assert_eq!(
            store.run(
                T0 + 2,
                Op::Abort {
                    slot: slot.clone(),
                    generation: 1
                }
            ),
            Decision::Stale
        );
        assert_eq!(store.raw_hexes(), ["aaaa"]);
        assert_eq!(store.spends, ["idem-1"]);
        assert_eq!(
            store.run(T0 + 3, begin(&slot, hash)),
            rebroadcast(1, "aaaa", TXID_A)
        );
    }

    #[test]
    fn abort_frees_only_the_matching_claim() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        store.run(T0, begin(&slot, hash));
        let abort = |generation| Op::Abort {
            slot: slot.clone(),
            generation,
        };
        assert_eq!(store.run(T0 + 1, abort(1)), Decision::Cleared);
        assert_eq!(
            store.run(T0 + 2, begin(&slot, hash)),
            Decision::Proceed { generation: 2 }
        );
        assert_eq!(store.run(T0 + 3, abort(1)), Decision::Stale);
        assert_eq!(store.run(T0 + 4, begin(&slot, hash)), Decision::InProgress);
    }

    #[test]
    fn an_oversized_signature_is_not_stored_and_frees_the_key() {
        let mut store = Store::default();
        let slot = key("invoice-8841");
        let hash = send_hash(Some(5));
        store.run(T0, begin(&slot, hash));
        let refused = store.run(
            T0 + 1,
            commit(&slot, 1, hash, &"ab".repeat(MAX_BODY_BYTES / 2), TXID_A),
        );
        assert_eq!(refused, Decision::TooLarge);
        assert_eq!(
            client_message(&refused, slot.request_id()),
            "signed transaction is too large to store"
        );
        assert_eq!(store.raw_hexes(), Vec::<String>::new());
        assert_eq!(store.spends, Vec::<String>::new());
        assert_eq!(
            store.run(T0 + 2, begin(&slot, hash)),
            Decision::Proceed { generation: 2 }
        );
    }

    #[test]
    fn a_commit_survives_the_json_hop_to_the_durable_object() {
        let op = commit(&key("invoice-8841"), 1, send_hash(Some(5)), "aaaa", TXID_A);
        let wire = serde_json::to_value(&op).unwrap();
        assert_eq!(wire["slot"], "cursor/invoice-8841");
        assert_eq!(wire["artifact"]["raw_tx_hex"], "aaaa");
        assert_eq!(serde_json::from_value::<Op>(wire).unwrap(), op);
    }
}
