use crate::policy::{check_fee, check_outflow, SpendPolicy, DAY_MS};
use crate::scan::{allocate_receive, merge_used, ScanCache};
use serde::{Deserialize, Serialize};

const PENDING_TTL_MS: u64 = 120_000;
const RETAIN_MS: u64 = 30 * DAY_MS;
const MAX_RECORDS: usize = 2_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendKind {
    Send,
    Sign,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendIntent {
    pub outflow_sats: u64,
    pub fee_sats: u64,
    pub vsize: u64,
    pub dest: String,
    pub client: String,
    pub kind: SpendKind,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Pending {
    id: u64,
    at_ms: u64,
    intent: SpendIntent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendRecord {
    pub id: u64,
    pub txid: String,
    pub outflow_sats: u64,
    pub dest: String,
    pub fee_sats: u64,
    pub at_ms: u64,
    pub client: String,
    pub kind: SpendKind,
    pub request_id: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendState {
    next_id: u64,
    pending: Vec<Pending>,
    spends: Vec<SpendRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Command {
    Preview(SpendIntent),
    Reserve(SpendIntent),
    Commit { id: u64, txid: String },
    Abort { id: u64 },
    Release { id: u64 },
    Log { limit: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapStatus {
    pub allowed: bool,
    pub reason: Option<String>,
    pub outflow_sats: u64,
    pub fee_sats: u64,
    pub feerate_sat_vb: u64,
    pub rolling_24h_sats: u64,
    pub pending_sats: u64,
    pub per_tx_cap_sats: u64,
    pub rolling_24h_cap_sats: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ApplyResult {
    Preview { status: CapStatus },
    Reserved { id: u64, status: CapStatus },
    Replay { id: u64, txid: String },
    InProgress { id: u64 },
    Denied { status: CapStatus },
    Committed { id: u64 },
    Aborted,
    Conflict { message: String },
    Log { spends: Vec<SpendRecord> },
}

pub fn apply(
    mut state: SpendState,
    command: Command,
    now_ms: u64,
    policy: &SpendPolicy,
) -> (SpendState, ApplyResult) {
    prune(&mut state, now_ms, RETAIN_MS, MAX_RECORDS);
    expire_pending(&mut state, now_ms);
    let result = match command {
        Command::Preview(intent) => ApplyResult::Preview {
            status: judge(&state, &intent, policy, now_ms),
        },
        Command::Reserve(intent) => reserve(&mut state, intent, now_ms, policy),
        Command::Commit { id, txid } => commit(&mut state, id, txid, now_ms),
        Command::Abort { id } => {
            state.pending.retain(|pending| pending.id != id);
            ApplyResult::Aborted
        }
        Command::Release { id } => {
            state.pending.retain(|pending| pending.id != id);
            state.spends.retain(|spend| spend.id != id);
            ApplyResult::Aborted
        }
        Command::Log { limit } => ApplyResult::Log {
            spends: log_entries(&state, limit),
        },
    };
    (state, result)
}

fn reserve(
    state: &mut SpendState,
    intent: SpendIntent,
    now_ms: u64,
    policy: &SpendPolicy,
) -> ApplyResult {
    if let Some(request_id) = intent.request_id.as_deref() {
        if let Some(result) = replay(state, &intent, request_id) {
            return result;
        }
    }
    let mut status = judge(state, &intent, policy, now_ms);
    if !status.allowed {
        return ApplyResult::Denied { status };
    }
    state.next_id = state.next_id.saturating_add(1);
    let id = state.next_id;
    status.rolling_24h_sats = status.rolling_24h_sats.saturating_add(intent.outflow_sats);
    status.pending_sats = status.pending_sats.saturating_add(intent.outflow_sats);
    state.pending.push(Pending {
        id,
        at_ms: now_ms,
        intent,
    });
    ApplyResult::Reserved { id, status }
}

fn replay(state: &SpendState, intent: &SpendIntent, request_id: &str) -> Option<ApplyResult> {
    if let Some(pending) = state.pending.iter().find(|pending| {
        pending.intent.client == intent.client
            && pending.intent.request_id.as_deref() == Some(request_id)
    }) {
        if same_intent(&pending.intent, intent) {
            return Some(ApplyResult::InProgress { id: pending.id });
        }
        return Some(ApplyResult::Conflict {
            message: "request_id was already used for a different spend".into(),
        });
    }
    if let Some(spend) = state.spends.iter().rev().find(|spend| {
        spend.client == intent.client && spend.request_id.as_deref() == Some(request_id)
    }) {
        if spend.outflow_sats == intent.outflow_sats
            && spend.fee_sats == intent.fee_sats
            && spend.dest == intent.dest
            && spend.kind == intent.kind
        {
            return Some(ApplyResult::Replay {
                id: spend.id,
                txid: spend.txid.clone(),
            });
        }
        return Some(ApplyResult::Conflict {
            message: "request_id was already used for a different spend".into(),
        });
    }
    None
}

fn same_intent(left: &SpendIntent, right: &SpendIntent) -> bool {
    left.outflow_sats == right.outflow_sats
        && left.fee_sats == right.fee_sats
        && left.vsize == right.vsize
        && left.dest == right.dest
        && left.kind == right.kind
}

fn commit(state: &mut SpendState, id: u64, txid: String, now_ms: u64) -> ApplyResult {
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return ApplyResult::Conflict {
            message: "txid must be 64 hex characters".into(),
        };
    }
    let txid = txid.to_ascii_lowercase();
    if let Some(existing) = state.spends.iter().find(|spend| spend.id == id) {
        return if existing.txid == txid {
            ApplyResult::Committed { id }
        } else {
            ApplyResult::Conflict {
                message: "reservation was already committed with a different txid".into(),
            }
        };
    }
    let Some(pos) = state.pending.iter().position(|pending| pending.id == id) else {
        return ApplyResult::Conflict {
            message: "unknown reservation".into(),
        };
    };
    if state.spends.iter().any(|spend| spend.txid == txid) {
        state.pending.remove(pos);
        return ApplyResult::Committed { id };
    }
    let pending = state.pending.remove(pos);
    state.spends.push(SpendRecord {
        id,
        txid,
        outflow_sats: pending.intent.outflow_sats,
        dest: pending.intent.dest,
        fee_sats: pending.intent.fee_sats,
        at_ms: pending.at_ms.min(now_ms),
        client: pending.intent.client,
        kind: pending.intent.kind,
        request_id: pending.intent.request_id,
    });
    ApplyResult::Committed { id }
}

fn judge(
    state: &SpendState,
    intent: &SpendIntent,
    policy: &SpendPolicy,
    _now_ms: u64,
) -> CapStatus {
    let (rolling, pending) = window(state, _now_ms);
    let rate = match check_fee(intent.fee_sats, intent.vsize, policy) {
        Ok(rate) => rate,
        Err(err) => {
            return denied(intent, policy, rolling, pending, 0, err.to_string());
        }
    };
    if let Err(err) = check_outflow(intent.outflow_sats, rolling, policy) {
        return denied(intent, policy, rolling, pending, rate, err.to_string());
    }
    CapStatus {
        allowed: true,
        reason: None,
        outflow_sats: intent.outflow_sats,
        fee_sats: intent.fee_sats,
        feerate_sat_vb: rate,
        rolling_24h_sats: rolling,
        pending_sats: pending,
        per_tx_cap_sats: policy.per_tx_cap_sats,
        rolling_24h_cap_sats: policy.rolling_24h_cap_sats,
    }
}

fn denied(
    intent: &SpendIntent,
    policy: &SpendPolicy,
    rolling: u64,
    pending: u64,
    rate: u64,
    reason: String,
) -> CapStatus {
    CapStatus {
        allowed: false,
        reason: Some(reason),
        outflow_sats: intent.outflow_sats,
        fee_sats: intent.fee_sats,
        feerate_sat_vb: rate,
        rolling_24h_sats: rolling,
        pending_sats: pending,
        per_tx_cap_sats: policy.per_tx_cap_sats,
        rolling_24h_cap_sats: policy.rolling_24h_cap_sats,
    }
}

fn window(state: &SpendState, now_ms: u64) -> (u64, u64) {
    let start = now_ms.saturating_sub(DAY_MS);
    let spent: u64 = state
        .spends
        .iter()
        .filter(|spend| spend.at_ms >= start)
        .map(|spend| spend.outflow_sats)
        .sum();
    let pending: u64 = state
        .pending
        .iter()
        .map(|pending| pending.intent.outflow_sats)
        .sum();
    (spent.saturating_add(pending), pending)
}

fn expire_pending(state: &mut SpendState, now_ms: u64) {
    state
        .pending
        .retain(|pending| now_ms.saturating_sub(pending.at_ms) < PENDING_TTL_MS);
}

fn prune(state: &mut SpendState, now_ms: u64, retain_ms: u64, max_records: usize) {
    let start = now_ms.saturating_sub(retain_ms);
    state.spends.retain(|spend| spend.at_ms >= start);
    if state.spends.len() > max_records {
        let overflow = state.spends.len() - max_records;
        let window_start = now_ms.saturating_sub(DAY_MS);
        let mut dropped = 0usize;
        state.spends.retain(|spend| {
            if dropped < overflow && spend.at_ms < window_start {
                dropped += 1;
                false
            } else {
                true
            }
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum GuardOp {
    Apply {
        command: Command,
        policy: SpendPolicy,
    },
    GetScan,
    MergeScan {
        used_external: Vec<u32>,
        used_change: Vec<u32>,
    },
    AllocateReceive {
        advance: bool,
    },
    GetOauth,
    PutOauth {
        access_token: String,
        exp_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GuardReply {
    Apply { result: ApplyResult },
    Scan { cache: ScanCache },
    ReceiveIndex { index: u32 },
    Oauth { access_token: String, exp_ms: u64 },
    OauthMiss,
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

pub fn take_receive(cache: &mut ScanCache, advance: bool) -> u32 {
    allocate_receive(cache, advance)
}

fn log_entries(state: &SpendState, limit: u32) -> Vec<SpendRecord> {
    let limit = limit.clamp(1, 200) as usize;
    let mut spends = state.spends.clone();
    spends.sort_by(|left, right| right.at_ms.cmp(&left.at_ms).then(right.id.cmp(&left.id)));
    spends.truncate(limit);
    spends
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SpendPolicy {
        SpendPolicy::default()
    }

    fn intent(outflow: u64, fee: u64) -> SpendIntent {
        SpendIntent {
            outflow_sats: outflow,
            fee_sats: fee,
            vsize: 100,
            dest: "bc1qexample".into(),
            client: "cursor".into(),
            kind: SpendKind::Send,
            request_id: None,
        }
    }

    fn reserve_id(state: &SpendState, intent: SpendIntent, now: u64) -> (SpendState, u64) {
        let (state, result) = apply(state.clone(), Command::Reserve(intent), now, &policy());
        match result {
            ApplyResult::Reserved { id, .. } => (state, id),
            other => panic!("expected reserve, got {other:?}"),
        }
    }

    #[test]
    fn preview_does_not_consume_the_cap_and_reserve_does() {
        let now = 1_000_000_u64;
        let (preview_state, preview) = apply(
            SpendState::default(),
            Command::Preview(intent(40_000, 200)),
            now,
            &policy(),
        );
        assert!(matches!(preview, ApplyResult::Preview { status } if status.allowed));
        assert!(preview_state.pending.is_empty());

        let (once, _) = reserve_id(&SpendState::default(), intent(100_000, 200), now);
        let (twice, _) = reserve_id(&once, intent(100_000, 200), now);
        let (_, second) = apply(twice, Command::Reserve(intent(60_000, 200)), now, &policy());
        match second {
            ApplyResult::Denied { status } => {
                assert!(!status.allowed);
                assert!(status.reason.unwrap().contains("rolling 24h"));
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn commit_counts_once_and_abort_counts_zero() {
        let now = 5_000_000_u64;
        let (reserved, id) = reserve_id(&SpendState::default(), intent(80_000, 1_000), now);
        let (committed, result) = apply(
            reserved.clone(),
            Command::Commit {
                id,
                txid: "ab".repeat(32),
            },
            now,
            &policy(),
        );
        assert!(matches!(result, ApplyResult::Committed { .. }));
        let (again, result) = apply(
            committed.clone(),
            Command::Commit {
                id,
                txid: "ab".repeat(32),
            },
            now,
            &policy(),
        );
        assert!(matches!(result, ApplyResult::Committed { .. }));
        assert_eq!(again.spends.len(), 1);
        assert_eq!(window(&again, now).0, 80_000);

        let (aborted, _) = apply(reserved, Command::Abort { id }, now, &policy());
        assert!(aborted.pending.is_empty());
        assert_eq!(window(&aborted, now).0, 0);
        let (released, _) = apply(committed, Command::Release { id }, now, &policy());
        assert!(released.spends.is_empty());
        assert_eq!(window(&released, now).0, 0);
    }

    #[test]
    fn the_same_txid_does_not_count_twice() {
        let now = 9_000_u64;
        let (first, id_a) = reserve_id(&SpendState::default(), intent(10_000, 100), now);
        let (first, _) = apply(
            first,
            Command::Commit {
                id: id_a,
                txid: "cd".repeat(32),
            },
            now,
            &policy(),
        );
        let (second, id_b) = reserve_id(&first, intent(10_000, 100), now);
        let (second, _) = apply(
            second,
            Command::Commit {
                id: id_b,
                txid: "cd".repeat(32),
            },
            now,
            &policy(),
        );
        assert_eq!(second.spends.len(), 1);
        assert_eq!(window(&second, now).0, 10_000);
    }

    #[test]
    fn expired_pending_and_old_spends_leave_the_window() {
        let start = 10_000_000_u64;
        let (state, id) = reserve_id(&SpendState::default(), intent(70_000, 100), start);
        let (state, _) = apply(
            state,
            Command::Commit {
                id,
                txid: "11".repeat(32),
            },
            start,
            &policy(),
        );
        let later = start + DAY_MS + 1;
        assert_eq!(window(&state, later).0, 0);

        let (held, _) = reserve_id(&SpendState::default(), intent(40_000, 100), start);
        let (held, result) = apply(
            held,
            Command::Reserve(intent(40_000, 100)),
            start + PENDING_TTL_MS,
            &policy(),
        );
        assert!(matches!(result, ApplyResult::Reserved { .. }));
        assert_eq!(held.pending.len(), 1);
    }

    #[test]
    fn fee_caps_are_enforced_inside_the_guard() {
        let now = 50_u64;
        let (_, high_fee) = apply(
            SpendState::default(),
            Command::Reserve(intent(1_000, 20_001)),
            now,
            &policy(),
        );
        assert!(matches!(high_fee, ApplyResult::Denied { .. }));

        let mut fast = intent(1_000, 20_000);
        fast.vsize = 50;
        let (_, high_rate) = apply(
            SpendState::default(),
            Command::Reserve(fast),
            now,
            &policy(),
        );
        match high_rate {
            ApplyResult::Denied { status } => {
                assert!(status.reason.unwrap().contains("feerate"));
            }
            other => panic!("expected feerate denial, got {other:?}"),
        }
    }

    #[test]
    fn request_id_replays_instead_of_reserving_twice() {
        let now = 80_000_u64;
        let mut first = intent(15_000, 200);
        first.request_id = Some("pay-1".into());
        let (state, id) = reserve_id(&SpendState::default(), first.clone(), now);
        let (_, again) = apply(
            state.clone(),
            Command::Reserve(first.clone()),
            now,
            &policy(),
        );
        assert!(matches!(again, ApplyResult::InProgress { id: seen } if seen == id));
        let (state, _) = apply(
            state,
            Command::Commit {
                id,
                txid: "22".repeat(32),
            },
            now,
            &policy(),
        );
        let (_, replay) = apply(state, Command::Reserve(first), now, &policy());
        assert!(matches!(replay, ApplyResult::Replay { txid, .. } if txid == "22".repeat(32)));
    }

    #[test]
    fn spend_log_is_newest_first_and_drops_month_old_rows() {
        let mut state = SpendState::default();
        for (offset, txid) in [(10_u64, "aa"), (20_u64, "bb")] {
            let (next, id) = reserve_id(&state, intent(1_000, 10), offset);
            let (next, _) = apply(
                next,
                Command::Commit {
                    id,
                    txid: txid.repeat(32),
                },
                offset,
                &policy(),
            );
            state = next;
        }
        let (_, result) = apply(state.clone(), Command::Log { limit: 10 }, 30, &policy());
        match result {
            ApplyResult::Log { spends } => {
                assert_eq!(spends[0].txid, "bb".repeat(32));
                assert_eq!(spends.len(), 2);
            }
            other => panic!("expected log, got {other:?}"),
        }
        let (_, result) = apply(
            state,
            Command::Log { limit: 10 },
            20 + RETAIN_MS + 1,
            &policy(),
        );
        match result {
            ApplyResult::Log { spends } => assert!(spends.is_empty()),
            other => panic!("expected empty log, got {other:?}"),
        }
    }
}
