use crate::idempotency::{Decision, Op};
use crate::locks::{InputSet, LockAction, Lockbook};
use crate::scan::{allocate_receive, merge_used, ScanCache};
use serde::{Deserialize, Serialize};

const DAY_MS: u64 = 86_400_000;
const RETAIN_MS: u64 = 30 * DAY_MS;
const MAX_RECORDS: usize = 500;
const MAX_DEST_CHARS: usize = 240;
/// SQLite Durable Objects reject a key and value that together exceed 2 MB.
/// One mebibyte of JSON stays under that cap after the runtime stores the note.
const MAX_LOG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendKind {
    Send,
    Sign,
    SignTx,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRecord {
    pub txid: String,
    pub input_sats: u64,
    pub dest: String,
    pub fee_sats: u64,
    pub at_ms: u64,
    pub client: String,
    pub kind: SpendKind,
    /// Stable for one signing call, including a retry after a lost reply.
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub request_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendLog {
    spends: Vec<SpendRecord>,
}

impl SpendLog {
    pub fn append(&mut self, record: SpendRecord, now_ms: u64) {
        let start = now_ms.saturating_sub(RETAIN_MS);
        self.spends.retain(|spend| spend.at_ms >= start);
        if !record.id.is_empty() && self.spends.iter().any(|spend| spend.id == record.id) {
            return;
        }
        let mut record = record;
        record.dest = shorten_dest(&record.dest);
        for spend in &mut self.spends {
            spend.dest = shorten_dest(&spend.dest);
        }
        self.spends.push(record);
        if self.spends.len() > MAX_RECORDS {
            let overflow = self.spends.len() - MAX_RECORDS;
            self.spends.drain(0..overflow);
        }
        while self.spends.len() > 1 && stored_len(self) > MAX_LOG_BYTES {
            self.spends.remove(0);
        }
    }

    pub fn recent(&self, limit: u32) -> Vec<SpendRecord> {
        let limit = limit.clamp(1, 200) as usize;
        let mut spends = self.spends.clone();
        spends.sort_by_key(|spend| std::cmp::Reverse(spend.at_ms));
        spends.truncate(limit);
        spends
    }
}

fn shorten_dest(dest: &str) -> String {
    if dest.chars().count() <= MAX_DEST_CHARS {
        return dest.to_string();
    }
    let mut out: String = dest.chars().take(MAX_DEST_CHARS - 3).collect();
    out.push_str("...");
    out
}

fn stored_len(log: &SpendLog) -> usize {
    serde_json::to_vec(log)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuardOp {
    Idempotency {
        call: Op,
    },
    SpendLog {
        limit: u32,
    },
    GetScan,
    MergeScan {
        used_external: Vec<u32>,
        used_change: Vec<u32>,
    },
    AllocateReceive {
        advance: bool,
        max_index: u32,
        gap: u32,
    },
    GetOauth,
    PutOauth {
        access_token: String,
        exp_ms: u64,
    },
    GetLocks,
    EditLocks {
        action: LockAction,
        outpoints: InputSet,
        note: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuardReply {
    Idempotency { decision: Decision },
    Log { spends: Vec<SpendRecord> },
    Scan { cache: ScanCache },
    ReceiveIndex { index: u32 },
    Oauth { access_token: String, exp_ms: u64 },
    OauthMiss,
    Locks { book: Lockbook },
    LocksSaved,
    Error { message: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OauthCache {
    pub access_token: String,
    pub exp_ms: u64,
}

pub fn merge_scan(cache: &ScanCache, external: &[u32], change: &[u32]) -> ScanCache {
    ScanCache {
        used_external: merge_used(&cache.used_external, external),
        used_change: merge_used(&cache.used_change, change),
        receive_cursor: cache.receive_cursor,
    }
}

pub fn take_receive(
    cache: &mut ScanCache,
    advance: bool,
    max_index: u32,
    gap: u32,
) -> Result<u32, String> {
    allocate_receive(cache, advance, max_index, gap)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(txid: &str, at_ms: u64) -> SpendRecord {
        SpendRecord {
            txid: txid.to_string(),
            input_sats: 50_000,
            dest: "bc1qexample".into(),
            fee_sats: 200,
            at_ms,
            client: "cursor".into(),
            kind: SpendKind::Send,
            id: format!("send:{txid}:{at_ms}"),
            request_id: "invoice-8841".into(),
        }
    }

    #[test]
    fn old_sign_rows_still_parse_and_sign_tx_rows_name_their_signer() {
        let mut row = serde_json::to_value(record(&"aa".repeat(32), 10)).unwrap();
        row["kind"] = "sign".into();
        assert_eq!(
            serde_json::from_value::<SpendRecord>(row).unwrap().kind,
            SpendKind::Sign
        );
        assert_eq!(
            serde_json::to_value(SpendKind::SignTx).unwrap(),
            serde_json::json!("sign_tx")
        );
    }

    #[test]
    fn a_lock_edit_survives_the_json_hop_to_the_durable_object() {
        let outpoint = format!("{}:0", "aa".repeat(32));
        let op = GuardOp::EditLocks {
            action: LockAction::Lock,
            outpoints: InputSet::parse("outpoints", &[&outpoint]).unwrap(),
            note: Some("charm".into()),
        };
        let wire = serde_json::to_value(&op).unwrap();
        assert_eq!(
            wire,
            serde_json::json!({ "op": "edit_locks", "action": "lock", "outpoints": [outpoint], "note": "charm" })
        );
        assert_eq!(serde_json::from_value::<GuardOp>(wire).unwrap(), op);
    }

    #[test]
    fn the_log_appends_and_returns_newest_first() {
        let mut log = SpendLog::default();
        log.append(record(&"aa".repeat(32), 10), 30);
        log.append(record(&"bb".repeat(32), 20), 30);
        let recent = log.recent(10);
        assert_eq!(recent[0].txid, "bb".repeat(32));
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].input_sats, 50_000);
    }

    #[test]
    fn rows_older_than_thirty_days_drop_off_the_log() {
        let mut log = SpendLog::default();
        log.append(record(&"aa".repeat(32), 10), 10);
        log.append(
            record(&"bb".repeat(32), 20 + RETAIN_MS + 1),
            20 + RETAIN_MS + 1,
        );
        let recent = log.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].txid, "bb".repeat(32));
    }

    #[test]
    fn different_ids_keep_two_calls_from_the_same_millisecond() {
        let mut log = SpendLog::default();
        let mut first = record(&"aa".repeat(32), 10);
        let mut second = record(&"aa".repeat(32), 10);
        first.id = "call-1".into();
        second.id = "call-2".into();
        log.append(first, 30);
        log.append(second.clone(), 30);
        log.append(second, 30);
        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert!(recent.iter().any(|row| row.id == "call-1"));
        assert!(recent.iter().any(|row| row.id == "call-2"));
    }

    #[test]
    fn a_repeated_append_with_the_same_id_is_one_row() {
        let mut log = SpendLog::default();
        let row = record(&"aa".repeat(32), 10);
        log.append(row.clone(), 30);
        log.append(row, 30);
        assert_eq!(log.recent(10).len(), 1);
        let other = record(&"bb".repeat(32), 11);
        log.append(other, 30);
        assert_eq!(log.recent(10).len(), 2);
    }

    #[test]
    fn a_long_destination_is_shortened_and_a_later_row_still_fits() {
        let mut log = SpendLog::default();
        let huge = "ab".repeat(8_192);
        for n in 0..40 {
            let mut row = record(&format!("{n:064x}"), 1_000 + n);
            row.dest = huge.clone();
            row.id = format!("idem-{n}");
            log.append(row, 2_000);
        }
        let mut ordinary = record(&format!("{:064x}", 41), 2_000);
        ordinary.dest = "bc1qexample".into();
        ordinary.id = "idem-ordinary".into();
        log.append(ordinary, 2_000);
        let rows = log.recent(200);
        let latest = rows.iter().find(|row| row.id == "idem-ordinary").unwrap();
        assert_eq!(latest.dest, "bc1qexample");
        let shortened = format!(
            "{}...",
            "ab".repeat(8_192).chars().take(237).collect::<String>()
        );
        assert!(rows
            .iter()
            .filter(|row| row.id != "idem-ordinary")
            .all(|row| row.dest == shortened));
        assert!(stored_len(&log) <= MAX_LOG_BYTES);
    }
}
