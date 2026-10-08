//! The bookkeeping of the ledger's segments, the refusal quota and the merging of
//! summaries: pure state, with every input explicit, so that the rules of design
//! 6.4.8 are tested without a disk.
//!
//! * **Rotation and retention.** Retention is by size only: `retain_segments`
//!   segments of `segment_bytes`. A rotation creates the next segment, so before it
//!   the newest `retain - 1` existing segments are kept and the older ones are the
//!   victims; the first record of the new segment (its `Continue`) says what the
//!   first surviving sequence number will be.
//! * **Hard cap.** If pruning keeps failing, the count of segments grows. At twice
//!   the retention the writer refuses new `Pending` and `Armed` records
//!   (`Capacity`) until a prune succeeds.
//! * **Refusal quota.** A flood of distinct refusals must not push admitted-flow
//!   evidence out of the ledger: per segment, `Denied` records may use
//!   `denied_share_percent` and `Summary` records `summary_share_percent` of
//!   `segment_bytes`.

use std::collections::BTreeMap;

use super::input::SummaryEvent;
use super::record::RepeatCount;
use super::verify::{ClassBytes, SegmentSummary};

/// The most keys a `Summary` names.
pub const MAX_REPEATED_KEYS: usize = 16;

/// One segment, as the writer keeps track of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentInfo {
    pub first_seq: u64,
    pub records: u64,
    pub bytes: u64,
}

impl From<&SegmentSummary> for SegmentInfo {
    fn from(summary: &SegmentSummary) -> Self {
        Self {
            first_seq: summary.first_seq,
            records: summary.records,
            bytes: summary.bytes,
        }
    }
}

/// What a rotation will do to the old segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationPlan {
    /// Oldest first.
    pub victims: Vec<u64>,
    /// The first sequence number that survives, when something is pruned: what the
    /// new segment's `Continue` records.
    pub pruned_before_seq: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentBook {
    /// Ascending; the last is the active segment.
    segments: Vec<SegmentInfo>,
    retain: usize,
}

impl SegmentBook {
    #[must_use]
    pub fn new(segments: Vec<SegmentInfo>, retain_segments: u32) -> Self {
        Self {
            segments,
            retain: usize::try_from(retain_segments)
                .unwrap_or(usize::MAX)
                .max(1),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    #[must_use]
    pub fn first_seqs(&self) -> Vec<u64> {
        self.segments.iter().map(|s| s.first_seq).collect()
    }

    #[must_use]
    pub fn entries(&self) -> u64 {
        self.segments
            .iter()
            .fold(0_u64, |sum, s| sum.saturating_add(s.records))
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.segments
            .iter()
            .fold(0_u64, |sum, s| sum.saturating_add(s.bytes))
    }

    /// Bytes of the active segment.
    #[must_use]
    pub fn active_bytes(&self) -> u64 {
        self.segments.last().map_or(0, |s| s.bytes)
    }

    #[must_use]
    pub fn oldest_first_seq(&self) -> Option<u64> {
        self.segments.first().map(|s| s.first_seq)
    }

    /// Records that were pruned before the oldest retained one (the sequence is
    /// dense from 1).
    #[must_use]
    pub fn pruned_entries(&self) -> u64 {
        self.oldest_first_seq()
            .map_or(0, |seq| seq.saturating_sub(1))
    }

    /// Lines were appended to the active segment.
    pub fn appended(&mut self, records: u64, bytes: u64) {
        if let Some(active) = self.segments.last_mut() {
            active.records = active.records.saturating_add(records);
            active.bytes = active.bytes.saturating_add(bytes);
        }
    }

    /// The plan of a rotation to a segment named `next_first_seq`: keep the newest
    /// `retain - 1` of what exists now.
    #[must_use]
    pub fn plan_rotation(&self, next_first_seq: u64) -> RotationPlan {
        let keep = self.retain.saturating_sub(1);
        let count = self.segments.len().saturating_sub(keep);
        if count == 0 {
            return RotationPlan {
                victims: Vec::new(),
                pruned_before_seq: None,
            };
        }
        let victims = self
            .segments
            .iter()
            .take(count)
            .map(|s| s.first_seq)
            .collect();
        let survivor = self
            .segments
            .get(count)
            .map_or(next_first_seq, |s| s.first_seq);
        RotationPlan {
            victims,
            pruned_before_seq: Some(survivor),
        }
    }

    /// The next segment is now the active one.
    pub fn rotated(&mut self, next_first_seq: u64, records: u64, bytes: u64) {
        self.segments.push(SegmentInfo {
            first_seq: next_first_seq,
            records,
            bytes,
        });
    }

    /// These segments are gone.
    pub fn pruned(&mut self, removed: &[u64]) {
        self.segments.retain(|s| !removed.contains(&s.first_seq));
    }

    /// Between rotations: the segments beyond the retention, to try to remove again
    /// (only ever the ones an earlier round failed to remove).
    #[must_use]
    pub fn leftovers(&self) -> Vec<u64> {
        let count = self.segments.len().saturating_sub(self.retain);
        self.segments
            .iter()
            .take(count)
            .map(|s| s.first_seq)
            .collect()
    }

    /// Pruning has failed for so long that the count reached twice the retention:
    /// new admissions are refused until a prune succeeds.
    #[must_use]
    pub fn over_capacity(&self) -> bool {
        self.segments.len() >= self.retain.saturating_mul(2)
    }
}

/// `percent` of `segment_bytes`, rounded down.
#[must_use]
pub fn share_bytes(segment_bytes: u64, percent: u8) -> u64 {
    segment_bytes
        .checked_mul(u64::from(percent))
        .and_then(|product| product.checked_div(100))
        .unwrap_or(u64::MAX)
}

/// The two budgets of a segment, and what is already spent in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub denied: u64,
    pub summary: u64,
}

impl Quota {
    #[must_use]
    pub fn new(segment_bytes: u64, denied_percent: u8, summary_percent: u8) -> Self {
        Self {
            denied: share_bytes(segment_bytes, denied_percent),
            summary: share_bytes(segment_bytes, summary_percent),
        }
    }

    /// May a `Denied` line of `len` bytes be written, given the bytes the class
    /// already has in this segment (`used`) and in the batch being built (`batch`)?
    #[must_use]
    pub fn denied_fits(&self, used: &ClassBytes, batch: u64, len: u64) -> bool {
        used.denied.saturating_add(batch).saturating_add(len) <= self.denied
    }

    /// May a `Summary` line of `len` bytes be written? A batch carries at most one
    /// (the writer folds them), so there is no batch term.
    #[must_use]
    pub fn summary_fits(&self, used: &ClassBytes, len: u64) -> bool {
        used.summary.saturating_add(len) <= self.summary
    }
}

fn add_counts(into: &mut BTreeMap<String, u64>, from: &BTreeMap<String, u64>) {
    for (key, count) in from {
        let entry = into.entry(key.clone()).or_insert(0);
        *entry = entry.saturating_add(*count);
    }
}

type RepeatKey = (String, String, u16, String, Option<String>);

fn key_of(repeat: &RepeatCount) -> RepeatKey {
    (
        repeat.profile.clone(),
        repeat.host.clone(),
        repeat.port,
        repeat.reason.clone(),
        repeat.rule.clone(),
    )
}

/// Folds `from` into `into`: the counters add, the repeated keys add by key and the
/// most repeated sixteen are kept; the keys that no longer fit are counted in
/// `other_keys`. Nothing is lost silently, and the totals stay exact.
pub fn merge_summary(into: &mut SummaryEvent, from: SummaryEvent) {
    into.window_ms = into.window_ms.saturating_add(from.window_ms);
    add_counts(&mut into.pre_admission_rejects, &from.pre_admission_rejects);
    add_counts(&mut into.denials_suppressed, &from.denials_suppressed);
    add_counts(&mut into.denials_over_quota, &from.denials_over_quota);
    into.other_keys = into.other_keys.saturating_add(from.other_keys);

    let mut by_key: BTreeMap<RepeatKey, RepeatCount> = BTreeMap::new();
    for repeat in into.denials_repeated.drain(..).chain(from.denials_repeated) {
        let key = key_of(&repeat);
        match by_key.get_mut(&key) {
            Some(existing) => existing.count = existing.count.saturating_add(repeat.count),
            None => {
                by_key.insert(key, repeat);
            }
        }
    }
    let mut merged: Vec<RepeatCount> = by_key.into_values().collect();
    // Most repeated first. `into_values` yields the keys in key order and the sort
    // is stable, so equal counts keep that order.
    merged.sort_by_key(|repeat| std::cmp::Reverse(repeat.count));
    let dropped = merged.len().saturating_sub(MAX_REPEATED_KEYS);
    into.other_keys = into
        .other_keys
        .saturating_add(u64::try_from(dropped).unwrap_or(u64::MAX));
    merged.truncate(MAX_REPEATED_KEYS);
    into.denials_repeated = merged;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book(firsts: &[u64], retain: u32) -> SegmentBook {
        SegmentBook::new(
            firsts
                .iter()
                .map(|first_seq| SegmentInfo {
                    first_seq: *first_seq,
                    records: 10,
                    bytes: 100,
                })
                .collect(),
            retain,
        )
    }

    // -- retention ---------------------------------------------------------------------

    #[test]
    fn a_rotation_keeps_the_newest_retain_minus_one_and_names_the_first_survivor() {
        let b = book(&[1, 11, 21, 31], 4);
        // Four exist, four are allowed once the next is made: keep the newest three.
        assert_eq!(
            b.plan_rotation(41),
            RotationPlan {
                victims: vec![1],
                pruned_before_seq: Some(11)
            }
        );
        // Fewer than the retention: nothing is pruned and nothing is announced.
        let b = book(&[1, 11, 21], 4);
        assert_eq!(
            b.plan_rotation(31),
            RotationPlan {
                victims: Vec::new(),
                pruned_before_seq: None
            }
        );
        let b = book(&[1], 4);
        assert_eq!(b.plan_rotation(11).victims, Vec::<u64>::new());
    }

    #[test]
    fn leftovers_from_failed_prunes_are_swept_by_the_next_rotation() {
        // Pruning failed for two rounds: six segments exist, and after the next one
        // is made four are allowed, so the three oldest go.
        let b = book(&[1, 11, 21, 31, 41, 51], 4);
        assert_eq!(
            b.plan_rotation(61),
            RotationPlan {
                victims: vec![1, 11, 21],
                pruned_before_seq: Some(31)
            }
        );
    }

    #[test]
    fn a_retention_of_one_prunes_everything_old_and_the_new_segment_is_the_survivor() {
        let b = book(&[1, 11], 1);
        assert_eq!(
            b.plan_rotation(21),
            RotationPlan {
                victims: vec![1, 11],
                pruned_before_seq: Some(21)
            }
        );
        // And a retention of zero is read as one.
        assert_eq!(book(&[1], 0).plan_rotation(5).victims, vec![1]);
    }

    #[test]
    fn the_book_follows_appends_rotations_and_prunes() {
        let mut b = book(&[1, 11], 4);
        assert_eq!((b.entries(), b.bytes(), b.len()), (20, 200, 2));
        b.appended(3, 30);
        assert_eq!((b.entries(), b.bytes(), b.active_bytes()), (23, 230, 130));
        b.rotated(21, 1, 80);
        assert_eq!(b.first_seqs(), [1, 11, 21]);
        assert_eq!(b.active_bytes(), 80);
        b.pruned(&[1]);
        assert_eq!(b.first_seqs(), [11, 21]);
        assert_eq!(b.oldest_first_seq(), Some(11));
        assert_eq!(b.pruned_entries(), 10, "the sequence is dense from 1");
        // Pruning something that is not there changes nothing.
        b.pruned(&[99]);
        assert_eq!(b.len(), 2);
        assert!(!b.is_empty());
        assert!(SegmentBook::new(Vec::new(), 4).is_empty());
        assert_eq!(SegmentBook::new(Vec::new(), 4).pruned_entries(), 0);
    }

    #[test]
    fn the_hard_cap_is_twice_the_retention() {
        assert!(!book(&[1, 2, 3, 4, 5, 6, 7], 4).over_capacity());
        assert!(book(&[1, 2, 3, 4, 5, 6, 7, 8], 4).over_capacity());
        assert!(book(&[1, 2], 1).over_capacity());
        assert!(!book(&[1], 1).over_capacity());
    }

    #[test]
    fn leftovers_are_the_segments_beyond_the_retention() {
        assert_eq!(book(&[1, 2, 3, 4], 4).leftovers(), Vec::<u64>::new());
        assert_eq!(book(&[1, 2, 3, 4, 5, 6], 4).leftovers(), vec![1, 2]);
    }

    // -- the quota ------------------------------------------------------------------------

    #[test]
    fn shares_are_integer_percentages_of_the_segment() {
        assert_eq!(share_bytes(32 * 1024 * 1024, 20), 6_710_886);
        assert_eq!(share_bytes(32 * 1024 * 1024, 5), 1_677_721);
        assert_eq!(share_bytes(1000, 20), 200);
        assert_eq!(share_bytes(999, 20), 199, "rounded down");
        assert_eq!(share_bytes(0, 20), 0);
        // A product that does not fit is no limit at all, not a wrapped one.
        assert_eq!(share_bytes(u64::MAX, 100), u64::MAX);
    }

    #[test]
    fn a_class_fits_while_used_plus_batch_plus_line_stays_within_its_share() {
        let quota = Quota::new(1000, 20, 5);
        assert_eq!((quota.denied, quota.summary), (200, 50));
        let used = ClassBytes {
            denied: 100,
            summary: 10,
        };
        assert!(quota.denied_fits(&used, 0, 100));
        assert!(!quota.denied_fits(&used, 0, 101));
        assert!(quota.denied_fits(&used, 60, 40));
        assert!(!quota.denied_fits(&used, 60, 41));
        assert!(quota.summary_fits(&used, 40));
        assert!(!quota.summary_fits(&used, 41));
        // Saturating: nothing wraps into "fits".
        let full = ClassBytes {
            denied: u64::MAX,
            summary: u64::MAX,
        };
        assert!(!quota.denied_fits(&full, u64::MAX, u64::MAX));
        assert!(!quota.summary_fits(&full, 1));
    }

    // -- merging summaries -----------------------------------------------------------------

    fn repeat(host: &str, count: u64) -> RepeatCount {
        RepeatCount {
            profile: "main".into(),
            host: host.into(),
            port: 25,
            reason: "POLICY_DENY".into(),
            rule: None,
            count,
        }
    }

    fn counts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect()
    }

    #[test]
    fn counters_add_and_repeated_keys_add_by_key() {
        let mut into = SummaryEvent {
            window_ms: 100,
            pre_admission_rejects: counts(&[("busy", 2)]),
            denials_suppressed: counts(&[("POLICY_DENY", 5)]),
            denials_over_quota: BTreeMap::new(),
            denials_repeated: vec![repeat("a.example", 4), repeat("b.example", 2)],
            other_keys: 1,
        };
        let from = SummaryEvent {
            window_ms: 50,
            pre_admission_rejects: counts(&[("busy", 3), ("slow", 1)]),
            denials_suppressed: counts(&[("POLICY_DENY", 1)]),
            denials_over_quota: counts(&[("NOT_ARMED", 7)]),
            denials_repeated: vec![repeat("b.example", 10), repeat("c.example", 1)],
            other_keys: 2,
        };
        merge_summary(&mut into, from);
        assert_eq!(into.window_ms, 150);
        assert_eq!(
            into.pre_admission_rejects,
            counts(&[("busy", 5), ("slow", 1)])
        );
        assert_eq!(into.denials_suppressed, counts(&[("POLICY_DENY", 6)]));
        assert_eq!(into.denials_over_quota, counts(&[("NOT_ARMED", 7)]));
        assert_eq!(into.other_keys, 3);
        let repeated: Vec<(String, u64)> = into
            .denials_repeated
            .iter()
            .map(|r| (r.host.clone(), r.count))
            .collect();
        assert_eq!(
            repeated,
            [
                ("b.example".to_owned(), 12),
                ("a.example".to_owned(), 4),
                ("c.example".to_owned(), 1)
            ]
        );
    }

    #[test]
    fn only_the_sixteen_most_repeated_keys_are_kept_and_the_rest_are_counted() {
        let mut into = SummaryEvent::default();
        let from = SummaryEvent {
            denials_repeated: (0..20)
                .map(|n: u32| repeat(&format!("h{n:02}.example"), u64::from(n) + 1))
                .collect(),
            ..SummaryEvent::default()
        };
        merge_summary(&mut into, from);
        assert_eq!(into.denials_repeated.len(), MAX_REPEATED_KEYS);
        assert_eq!(into.other_keys, 4);
        // The ones with the largest counts survived, largest first.
        assert_eq!(into.denials_repeated.first().map(|r| r.count), Some(20));
        assert_eq!(into.denials_repeated.last().map(|r| r.count), Some(5));
    }

    #[test]
    fn equal_counts_keep_a_stable_order_and_counters_saturate() {
        let mut a = SummaryEvent {
            denials_repeated: vec![repeat("b.example", 3), repeat("a.example", 3)],
            denials_suppressed: counts(&[("X", u64::MAX)]),
            ..SummaryEvent::default()
        };
        let b = a.clone();
        merge_summary(&mut a, b);
        let hosts: Vec<&str> = a.denials_repeated.iter().map(|r| r.host.as_str()).collect();
        assert_eq!(hosts, ["a.example", "b.example"]);
        assert_eq!(a.denials_suppressed, counts(&[("X", u64::MAX)]));
        assert_eq!(a.denials_repeated.first().map(|r| r.count), Some(6));
    }

    #[test]
    fn a_retention_of_zero_is_read_as_one() {
        // Not reachable through the configuration (2 to 64), but the book must not
        // report a capacity breach or leftovers for a single segment.
        let b = book(&[1], 0);
        assert!(!b.over_capacity());
        assert_eq!(b.leftovers(), Vec::<u64>::new());
        assert_eq!(b.plan_rotation(11).victims, [1]);
    }

    #[test]
    fn a_repeated_key_is_one_only_if_every_part_of_it_agrees() {
        let base = repeat("a.example", 2);
        let variants = [
            RepeatCount {
                profile: "other".into(),
                ..base.clone()
            },
            RepeatCount {
                port: 26,
                ..base.clone()
            },
            RepeatCount {
                reason: "NOT_ARMED".into(),
                ..base.clone()
            },
            RepeatCount {
                rule: Some("rule-1".into()),
                ..base.clone()
            },
        ];
        for variant in variants {
            let mut into = SummaryEvent {
                denials_repeated: vec![base.clone()],
                ..SummaryEvent::default()
            };
            let from = SummaryEvent {
                denials_repeated: vec![variant],
                ..SummaryEvent::default()
            };
            merge_summary(&mut into, from);
            assert_eq!(into.denials_repeated.len(), 2, "kept apart");
            assert!(into.denials_repeated.iter().all(|r| r.count == 2));
        }
        // The same in every part, a rule included, is one key.
        let ruled = RepeatCount {
            rule: Some("rule-1".into()),
            ..base
        };
        let mut into = SummaryEvent {
            denials_repeated: vec![ruled.clone()],
            ..SummaryEvent::default()
        };
        merge_summary(
            &mut into,
            SummaryEvent {
                denials_repeated: vec![ruled],
                ..SummaryEvent::default()
            },
        );
        assert_eq!(
            into.denials_repeated
                .iter()
                .map(|r| r.count)
                .collect::<Vec<_>>(),
            [4]
        );
    }

    #[test]
    fn the_count_of_a_repeated_key_saturates() {
        let mut into = SummaryEvent {
            denials_repeated: vec![repeat("a.example", u64::MAX)],
            ..SummaryEvent::default()
        };
        merge_summary(
            &mut into,
            SummaryEvent {
                denials_repeated: vec![repeat("a.example", 5)],
                ..SummaryEvent::default()
            },
        );
        assert_eq!(
            into.denials_repeated
                .iter()
                .map(|r| r.count)
                .collect::<Vec<_>>(),
            [u64::MAX]
        );
    }
}
