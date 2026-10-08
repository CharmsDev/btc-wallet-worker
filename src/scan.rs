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
) -> ProbeStep {
    if gap == 0 {
        return ProbeStep::Exceeded { index: 0 };
    }
    let mut streak = 0u32;
    let mut index = 0u32;
    loop {
        let used_here = used.binary_search(&index).is_ok() || probed.get(&index) == Some(&true);
        if used_here {
            streak = 0;
        } else if let Some(false) = probed.get(&index) {
            streak = streak.saturating_add(1);
            if streak >= gap {
                return ProbeStep::Done;
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

pub fn allocate_receive(cache: &mut ScanCache, advance: bool) -> u32 {
    let index = next_unused(&cache.used_external, cache.receive_cursor);
    if advance {
        cache.receive_cursor = index.saturating_add(1);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_scan_stops_after_consecutive_unused_indexes() {
        let used = vec![0];
        let mut probed = BTreeMap::new();
        assert_eq!(next_probe(&used, 2, 20, &probed), ProbeStep::Probe(1));
        probed.insert(1, false);
        assert_eq!(next_probe(&used, 2, 20, &probed), ProbeStep::Probe(2));
        probed.insert(2, false);
        assert_eq!(next_probe(&used, 2, 20, &probed), ProbeStep::Done);
    }

    #[test]
    fn a_used_hole_resets_the_gap() {
        let used = Vec::new();
        let mut probed = BTreeMap::new();
        probed.insert(0, false);
        probed.insert(1, true);
        assert_eq!(next_probe(&used, 2, 20, &probed), ProbeStep::Probe(2));
        probed.insert(2, false);
        probed.insert(3, false);
        assert_eq!(next_probe(&used, 2, 20, &probed), ProbeStep::Done);
        assert_eq!(merge_used(&[], &[1]), vec![1]);
    }

    #[test]
    fn scan_refuses_to_pass_the_max_index() {
        assert_eq!(next_probe(&[], 5, 1, &BTreeMap::new()), ProbeStep::Probe(0));
        let mut probed = BTreeMap::from([(0, true), (1, true)]);
        assert_eq!(
            next_probe(&[], 2, 1, &probed),
            ProbeStep::Exceeded { index: 2 }
        );
        probed.insert(2, false);
        let _ = probed;
    }

    #[test]
    fn receive_cursor_skips_used_indexes_and_can_advance() {
        let mut cache = ScanCache {
            used_external: vec![0, 2],
            used_change: vec![],
            receive_cursor: 0,
        };
        assert_eq!(allocate_receive(&mut cache, false), 1);
        assert_eq!(cache.receive_cursor, 0);
        assert_eq!(allocate_receive(&mut cache, true), 1);
        assert_eq!(cache.receive_cursor, 2);
        assert_eq!(allocate_receive(&mut cache, false), 3);
        assert_eq!(next_unused(&[0], 0), 1);
    }
}
