use bitcoin::OutPoint;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

pub const LOCKS_KEY: &str = "locks";
/// Bounds the stored book well under the Durable Object's 2 MB value cap.
const MAX_MARKS: usize = 2048;

/// Iterates in `OutPoint` order, so the order a client lists outpoints in never
/// reaches a hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct InputSet(BTreeSet<OutPoint>);

impl InputSet {
    pub fn parse(field: &str, items: &[&str]) -> Result<Self, String> {
        if items.is_empty() {
            return Err(format!("{field} must list at least one outpoint"));
        }
        let mut outpoints = BTreeSet::new();
        for item in items {
            let outpoint = OutPoint::from_str(item.trim())
                .map_err(|_| format!("{field} entry {item} is not a txid:vout outpoint"))?;
            if !outpoints.insert(outpoint) {
                return Err(format!("{field} lists {outpoint} more than once"));
            }
        }
        Ok(Self(outpoints))
    }

    pub fn outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.0
    }
}

impl TryFrom<Vec<String>> for InputSet {
    type Error = String;

    fn try_from(items: Vec<String>) -> Result<Self, String> {
        let items: Vec<&str> = items.iter().map(String::as_str).collect();
        Self::parse("outpoints", &items)
    }
}

impl From<InputSet> for Vec<String> {
    fn from(set: InputSet) -> Self {
        set.0.iter().map(ToString::to_string).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputChoice {
    Auto,
    Exactly(InputSet),
}

impl InputChoice {
    /// Listing a coin in `inputs` is consent to spend it while it is locked.
    pub fn allow_locked(&self) -> AllowLocked {
        match self {
            Self::Auto => AllowLocked::No,
            Self::Exactly(_) => AllowLocked::Yes,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowLocked {
    No,
    Yes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Wallet,
    Foreign,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockReason {
    Manual,
    AutoSmall,
}

impl fmt::Display for LockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Manual => "manual",
            Self::AutoSmall => "auto-small",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockAction {
    Lock,
    Unlock,
}

/// Holds only what `lock` and `unlock` said. Auto-lock is decided from the live
/// value on every read, so a changed AUTO_LOCK_SATS applies to every coin at once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Entry>", into = "Vec<Entry>")]
pub struct Lockbook {
    marks: BTreeMap<OutPoint, Mark>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Mark {
    Locked { note: Option<String> },
    Unlocked { note: Option<String> },
}

impl Lockbook {
    /// Auto-lock covers only wallet outputs. A small foreign prevout is another
    /// party's coin, so only a manual mark can lock it.
    pub fn reason(
        &self,
        outpoint: OutPoint,
        value: u64,
        scope: Scope,
        auto_lock_sats: u64,
    ) -> Option<LockReason> {
        match (self.marks.get(&outpoint), scope) {
            (Some(Mark::Locked { .. }), _) => Some(LockReason::Manual),
            (Some(Mark::Unlocked { .. }), _) => None,
            (None, Scope::Wallet) if value <= auto_lock_sats => Some(LockReason::AutoSmall),
            (None, Scope::Wallet | Scope::Foreign) => None,
        }
    }

    pub fn apply(
        &mut self,
        action: LockAction,
        outpoints: &InputSet,
        note: Option<String>,
    ) -> Result<(), String> {
        let added = outpoints
            .0
            .iter()
            .filter(|outpoint| !self.marks.contains_key(outpoint))
            .count();
        if self.marks.len() + added > MAX_MARKS {
            return Err(format!("lockbook is full at {MAX_MARKS} outpoints"));
        }
        for outpoint in &outpoints.0 {
            let note = note.clone();
            let mark = match action {
                LockAction::Lock => Mark::Locked { note },
                LockAction::Unlock => Mark::Unlocked { note },
            };
            self.marks.insert(*outpoint, mark);
        }
        Ok(())
    }
}

/// `bitcoin` is built without its serde feature, so outpoints are stored as `txid:vout`.
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    outpoint: String,
    mark: MarkKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum MarkKind {
    Locked,
    Unlocked,
}

impl TryFrom<Vec<Entry>> for Lockbook {
    type Error = String;

    fn try_from(entries: Vec<Entry>) -> Result<Self, String> {
        let mut marks = BTreeMap::new();
        for Entry {
            outpoint,
            mark,
            note,
        } in entries
        {
            let outpoint = OutPoint::from_str(&outpoint)
                .map_err(|_| "stored lock outpoint is invalid".to_string())?;
            let mark = match mark {
                MarkKind::Locked => Mark::Locked { note },
                MarkKind::Unlocked => Mark::Unlocked { note },
            };
            if marks.insert(outpoint, mark).is_some() {
                return Err(format!("stored locks list {outpoint} more than once"));
            }
        }
        Ok(Self { marks })
    }
}

impl From<Lockbook> for Vec<Entry> {
    fn from(book: Lockbook) -> Self {
        book.marks
            .into_iter()
            .map(|(outpoint, mark)| {
                let (mark, note) = match mark {
                    Mark::Locked { note } => (MarkKind::Locked, note),
                    Mark::Unlocked { note } => (MarkKind::Unlocked, note),
                };
                Entry {
                    outpoint: outpoint.to_string(),
                    mark,
                    note,
                }
            })
            .collect()
    }
}

pub fn refuse_locked(
    spends: &[(OutPoint, u64, Scope)],
    book: &Lockbook,
    allow: AllowLocked,
    auto_lock_sats: u64,
) -> Result<(), String> {
    match allow {
        AllowLocked::Yes => Ok(()),
        AllowLocked::No => {
            let locked: Vec<String> = spends
                .iter()
                .filter_map(|&(outpoint, value, scope)| {
                    book.reason(outpoint, value, scope, auto_lock_sats)
                        .map(|reason| format!("{outpoint} ({reason})"))
                })
                .collect();
            if locked.is_empty() {
                return Ok(());
            }
            Err(format!(
                "refusing to spend locked output {}; pass allow_locked true to spend it",
                locked.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TXID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn outpoint(vout: u32) -> OutPoint {
        OutPoint::from_str(&format!("{TXID}:{vout}")).unwrap()
    }

    fn set(vouts: impl IntoIterator<Item = u32>) -> InputSet {
        let items: Vec<String> = vouts
            .into_iter()
            .map(|vout| format!("{TXID}:{vout}"))
            .collect();
        InputSet::try_from(items).unwrap()
    }

    #[test]
    fn auto_lock_covers_wallet_outputs_at_or_under_the_threshold() {
        let book = Lockbook::default();
        assert_eq!(
            book.reason(outpoint(0), 330, Scope::Wallet, 330),
            Some(LockReason::AutoSmall)
        );
        assert_eq!(book.reason(outpoint(0), 331, Scope::Wallet, 330), None);
        assert_eq!(book.reason(outpoint(0), 330, Scope::Wallet, 0), None);
    }

    #[test]
    fn unlock_frees_a_small_output_until_a_later_lock() {
        let mut book = Lockbook::default();
        book.apply(LockAction::Unlock, &set([0]), None).unwrap();
        assert_eq!(book.reason(outpoint(0), 330, Scope::Wallet, 330), None);
        let once = book.clone();
        book.apply(LockAction::Unlock, &set([0]), None).unwrap();
        assert_eq!(book, once);
        assert_eq!(book.reason(outpoint(0), 330, Scope::Wallet, 330), None);
        book.apply(LockAction::Lock, &set([0]), None).unwrap();
        assert_eq!(
            book.reason(outpoint(0), 330, Scope::Wallet, 330),
            Some(LockReason::Manual)
        );
    }

    #[test]
    fn an_unknown_outpoint_is_locked_and_stored_with_its_note() {
        let mut book = Lockbook::default();
        book.apply(LockAction::Lock, &set([7]), Some("charm".into()))
            .unwrap();
        assert_eq!(
            book.reason(outpoint(7), 50_000, Scope::Wallet, 330),
            Some(LockReason::Manual)
        );
        assert_eq!(
            serde_json::to_value(&book).unwrap(),
            json!([{ "outpoint": format!("{TXID}:7"), "mark": "locked", "note": "charm" }])
        );
    }

    #[test]
    fn a_batch_past_the_cap_adds_nothing_but_a_full_book_can_rewrite() {
        let mut book = Lockbook::default();
        book.apply(LockAction::Lock, &set(0..2047), None).unwrap();
        let before = book.clone();
        assert_eq!(
            book.apply(LockAction::Lock, &set([2047, 2048]), None),
            Err("lockbook is full at 2048 outpoints".into())
        );
        assert_eq!(book, before);
        assert_eq!(
            book.reason(outpoint(2047), 50_000, Scope::Wallet, 330),
            None
        );
        book.apply(LockAction::Lock, &set([2047]), None).unwrap();
        book.apply(LockAction::Unlock, &set([0]), None).unwrap();
        assert_eq!(book.reason(outpoint(0), 330, Scope::Wallet, 330), None);
    }

    #[test]
    fn a_foreign_output_is_locked_only_by_a_manual_mark() {
        let mut book = Lockbook::default();
        assert_eq!(book.reason(outpoint(0), 330, Scope::Foreign, 330), None);
        book.apply(LockAction::Lock, &set([0]), None).unwrap();
        assert_eq!(
            book.reason(outpoint(0), 330, Scope::Foreign, 330),
            Some(LockReason::Manual)
        );
    }

    #[test]
    fn refusal_names_every_locked_input_in_order_unless_allowed() {
        let mut book = Lockbook::default();
        book.apply(LockAction::Lock, &set([1]), None).unwrap();
        let spends = [
            (outpoint(0), 330, Scope::Wallet),
            (outpoint(1), 50_000, Scope::Foreign),
            (outpoint(2), 50_000, Scope::Wallet),
        ];
        assert_eq!(
            refuse_locked(&spends, &book, AllowLocked::No, 330),
            Err(format!(
                "refusing to spend locked output {TXID}:0 (auto-small), {TXID}:1 (manual); pass allow_locked true to spend it"
            ))
        );
        assert_eq!(refuse_locked(&spends, &book, AllowLocked::Yes, 330), Ok(()));
        assert_eq!(
            refuse_locked(&spends[2..], &book, AllowLocked::No, 330),
            Ok(())
        );
    }

    #[test]
    fn stored_marks_load_and_a_corrupt_book_fails_the_read() {
        let stored = format!(
            r#"[{{"outpoint":"{TXID}:0","mark":"unlocked"}},{{"outpoint":"{TXID}:1","mark":"locked","note":"spell"}}]"#
        );
        let book: Lockbook = serde_json::from_str(&stored).unwrap();
        assert_eq!(book.reason(outpoint(0), 330, Scope::Wallet, 330), None);
        assert_eq!(
            book.reason(outpoint(1), 50_000, Scope::Wallet, 330),
            Some(LockReason::Manual)
        );
        assert_eq!(serde_json::to_string(&book).unwrap(), stored);
        for corrupt in [
            r#"[{"outpoint":"nope","mark":"locked"}]"#.to_string(),
            format!(r#"[{{"outpoint":"{TXID}:0","mark":"frozen"}}]"#),
            format!(
                r#"[{{"outpoint":"{TXID}:0","mark":"locked"}},{{"outpoint":"{TXID}:0","mark":"unlocked"}}]"#
            ),
        ] {
            assert!(
                serde_json::from_str::<Lockbook>(&corrupt).is_err(),
                "{corrupt}"
            );
        }
    }
}
