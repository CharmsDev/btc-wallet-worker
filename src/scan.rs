use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanCache {
    pub used_external: Vec<u32>,
    pub used_change: Vec<u32>,
    pub receive_cursor: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeStep {
    Probe(u32),
    Done,
    Exceeded { index: u32 },
}

pub fn next_probe(
    used: &[u32],
    gap: u32,
    max_index: u32,
    probed: &BTreeMap<u32, bool>,
    issued_until: u32,
) -> ProbeStep {
    if gap == 0 {
        return ProbeStep::Exceeded { index: 0 };
    }
    let mut streak = 0u32;
    let mut index = 0u32;
    loop {
        let used_here = used.binary_search(&index).is_ok() || probed.get(&index) == Some(&true);
        let issued = index < issued_until;
        if used_here {
            streak = 0;
        } else if let Some(false) = probed.get(&index) {
            if issued {
                streak = 0;
            } else {
                streak = streak.saturating_add(1);
                if streak >= gap {
                    return ProbeStep::Done;
                }
            }
        } else if index > max_index {
            return ProbeStep::Exceeded { index };
        } else {
            return ProbeStep::Probe(index);
        }
        if index == u32::MAX {
            return ProbeStep::Exceeded { index };
        }
        index += 1;
        if !used_here && index > max_index && streak < gap && !probed.contains_key(&(index - 1)) {
            return ProbeStep::Exceeded { index };
        }
    }
}

pub fn merge_used(existing: &[u32], observed: &[u32]) -> Vec<u32> {
    let mut out = existing.to_vec();
    for index in observed {
        if out.binary_search(index).is_err() {
            out.push(*index);
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

pub fn history_indexes(external: &[u32], change: &[u32]) -> Vec<(u8, u32)> {
    let mut out = Vec::with_capacity(external.len() + change.len());
    for index in external {
        out.push((0, *index));
    }
    for index in change {
        out.push((1, *index));
    }
    out
}

pub fn next_unused(used: &[u32], start: u32) -> u32 {
    let mut index = start;
    while used.binary_search(&index).is_ok() {
        if index == u32::MAX {
            return index;
        }
        index += 1;
    }
    index
}

pub fn allocate_receive(
    cache: &mut ScanCache,
    advance: bool,
    max_index: u32,
    gap: u32,
) -> Result<u32, String> {
    let index = next_unused(&cache.used_external, cache.receive_cursor);
    if index > max_index || index.saturating_add(gap) > max_index {
        return Err(format!(
            "receive index {index} would scan past MAX_SCAN_INDEX {max_index}"
        ));
    }
    if advance {
        cache.receive_cursor = index.saturating_add(1);
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_scan_stops_after_consecutive_unused_indexes() {
        let used = vec![0];
        let mut probed = BTreeMap::new();
        assert_eq!(next_probe(&used, 2, 20, &probed, 0), ProbeStep::Probe(1));
        probed.insert(1, false);
        assert_eq!(next_probe(&used, 2, 20, &probed, 0), ProbeStep::Probe(2));
        probed.insert(2, false);
        assert_eq!(next_probe(&used, 2, 20, &probed, 0), ProbeStep::Done);
    }

    #[test]
    fn a_used_hole_resets_the_gap() {
        let used = Vec::new();
        let mut probed = BTreeMap::new();
        probed.insert(0, false);
        probed.insert(1, true);
        assert_eq!(next_probe(&used, 2, 20, &probed, 0), ProbeStep::Probe(2));
        probed.insert(2, false);
        probed.insert(3, false);
        assert_eq!(next_probe(&used, 2, 20, &probed, 0), ProbeStep::Done);
        assert_eq!(merge_used(&[], &[1]), vec![1]);
    }

    #[test]
    fn scan_refuses_to_pass_the_max_index() {
        assert_eq!(
            next_probe(&[], 5, 1, &BTreeMap::new(), 0),
            ProbeStep::Probe(0)
        );
        let mut probed = BTreeMap::from([(0, true), (1, true)]);
        assert_eq!(
            next_probe(&[], 2, 1, &probed, 0),
            ProbeStep::Exceeded { index: 2 }
        );
        probed.insert(2, false);
        let _ = probed;
    }

    #[test]
    fn history_includes_every_used_index() {
        let external: Vec<u32> = (0..12).collect();
        let change: Vec<u32> = (0..6).collect();
        let indexes = history_indexes(&external, &change);
        assert_eq!(indexes.len(), 18);
        assert!(indexes.contains(&(0, 0)));
        assert!(indexes.contains(&(0, 11)));
        assert!(indexes.contains(&(1, 5)));
    }

    #[test]
    fn receive_cursor_skips_used_indexes_and_can_advance() {
        let mut cache = ScanCache {
            used_external: vec![0, 2],
            used_change: vec![],
            receive_cursor: 0,
        };
        assert_eq!(allocate_receive(&mut cache, false, 200, 20).unwrap(), 1);
        assert_eq!(cache.receive_cursor, 0);
        assert_eq!(allocate_receive(&mut cache, true, 200, 20).unwrap(), 1);
        assert_eq!(cache.receive_cursor, 2);
        assert_eq!(allocate_receive(&mut cache, false, 200, 20).unwrap(), 3);
        assert_eq!(next_unused(&[0], 0), 1);
    }

    #[test]
    fn issued_indexes_are_probed_before_the_gap() {
        let mut probed = BTreeMap::new();
        let mut last = 0;
        for _ in 0..21 {
            match next_probe(&[], 20, 200, &probed, 21) {
                ProbeStep::Probe(index) => {
                    probed.insert(index, false);
                    last = index;
                }
                other => panic!("expected a probe, got {other:?}"),
            }
        }
        assert_eq!(last, 20);
        assert_eq!(next_probe(&[], 20, 200, &probed, 21), ProbeStep::Probe(21));
    }

    #[test]
    fn allocation_refuses_an_index_whose_gap_passes_the_max() {
        let mut cache = ScanCache {
            receive_cursor: 181,
            ..ScanCache::default()
        };
        let err = allocate_receive(&mut cache, true, 200, 20).unwrap_err();
        assert!(err.contains("MAX_SCAN_INDEX"), "{err}");
        assert_eq!(cache.receive_cursor, 181);
        cache.receive_cursor = 180;
        assert_eq!(allocate_receive(&mut cache, true, 200, 20).unwrap(), 180);
        assert_eq!(cache.receive_cursor, 181);
    }
}
