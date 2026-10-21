//! Rate limits and bounded bookkeeping for the accept path (design 6.5, 7.1).
//!
//! Everything here is deterministic: every method that depends on time takes
//! `now` as an argument, and no code subtracts two `Instant`s with `-` (that can
//! panic); [`Instant::saturating_duration_since`] is used instead. Nothing here
//! reads a clock, sleeps or spawns.
//!
//! * [`RateLimiter`]: the accept bucket (burst `max_connections`, refill
//!   `accept_rate_per_s`).
//! * [`PeerBudget`]: what a socket costs between `accept()` and the end of its
//!   handshake: a cheap token bucket and one of 64 slots. A hostile local
//!   process that opens connections and says nothing spends only these; the
//!   shared budgets (accept bucket, flow permits, the ledger) are charged after
//!   the handshake.
//! * [`DenialCoalescer`]: the first occurrence of a refusal is written before
//!   the reply, repeats are counted into a summary, and the table that tells
//!   them apart is bounded.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::types::{lock_unpoisoned, Tuning};

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// A token is this many units. The bucket counts in billionths of a token and
/// refills `per_second` units per nanosecond, so it needs no division, no
/// floating point and loses no fraction between calls however often it is
/// called.
const UNITS_PER_TOKEN: u64 = 1_000_000_000;

#[derive(Debug)]
struct TokenBucket {
    capacity: u64,
    tokens: u64,
    per_second: u64,
    last: Instant,
}

impl TokenBucket {
    /// Starts full: the burst is available at once.
    fn new(burst: u32, per_second: u32, now: Instant) -> Self {
        let capacity = u64::from(burst).saturating_mul(UNITS_PER_TOKEN);
        Self {
            capacity,
            tokens: capacity,
            per_second: u64::from(per_second),
            last: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last);
        if elapsed.is_zero() {
            // Also the case when `now` is earlier than `last`: time does not run
            // backwards for a bucket, it just waits.
            return;
        }
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        let added = nanos.saturating_mul(self.per_second);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
        self.last = now;
    }

    fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        match self.tokens.checked_sub(UNITS_PER_TOKEN) {
            Some(rest) => {
                self.tokens = rest;
                true
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Accept bucket
// ---------------------------------------------------------------------------

/// The accept bucket: charged once per connection that has completed a valid
/// handshake (step 6 of 7.1), so a socket that never speaks costs it nothing.
#[derive(Debug)]
pub struct RateLimiter {
    bucket: TokenBucket,
}

impl RateLimiter {
    /// `burst` is `max_connections` (the effective one) and `per_second` is
    /// `accept_rate_per_s`.
    #[must_use]
    pub fn new(burst: u32, per_second: u32, now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new(burst, per_second, now),
        }
    }

    /// `true` and one token spent, or `false`.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.bucket.try_take(now)
    }
}

// ---------------------------------------------------------------------------
// Pre-admission budget
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SlotCtl {
    started: Instant,
    complete: AtomicBool,
    cancelled: AtomicBool,
    wake: Notify,
}

impl SlotCtl {
    fn new(started: Instant) -> Self {
        Self {
            started,
            complete: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            wake: Notify::new(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        // `notify_one` leaves a permit when nobody waits yet, so a cancel that
        // lands between the owner's check and its await is not lost.
        self.wake.notify_one();
    }
}

#[derive(Debug, Default)]
struct SlotTable {
    live: Mutex<Vec<Arc<SlotCtl>>>,
    evicted: AtomicU64,
}

/// One of the pre-admission slots. Dropping it frees the slot. The owner races
/// its work against [`PreAdmissionSlot::cancelled`] and closes the socket when
/// the slot is taken away from it.
#[derive(Debug)]
pub struct PreAdmissionSlot {
    ctl: Arc<SlotCtl>,
    table: Arc<SlotTable>,
}

impl PreAdmissionSlot {
    /// Completes when this slot has been evicted for a newcomer. Cancel-safe.
    pub async fn cancelled(&self) {
        loop {
            if self.ctl.cancelled.load(Ordering::Acquire) {
                return;
            }
            self.ctl.wake.notified().await;
        }
    }

    /// A complete, valid request has been read: this socket is no longer a
    /// candidate for eviction.
    pub fn request_complete(&self) {
        self.ctl.complete.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn was_evicted(&self) -> bool {
        self.ctl.cancelled.load(Ordering::Acquire)
    }
}

impl Drop for PreAdmissionSlot {
    fn drop(&mut self) {
        // An evicted slot has already been replaced in the table and is not
        // found here, so it frees nothing it no longer owns.
        let mut live = lock_unpoisoned(&self.table.live);
        if let Some(at) = live.iter().position(|ctl| Arc::ptr_eq(ctl, &self.ctl)) {
            live.swap_remove(at);
        }
    }
}

/// The cheap budget of a socket that has not finished its handshake: a token
/// bucket (256 burst, 1024 per second) and 64 slots shared by the peer check and
/// the handshake.
#[derive(Debug)]
pub struct PeerBudget {
    bucket: TokenBucket,
    max_slots: usize,
    evict_after: Duration,
    table: Arc<SlotTable>,
}

impl PeerBudget {
    #[must_use]
    pub fn new(tuning: &Tuning, now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new(tuning.peer_burst, tuning.peer_refill_per_s, now),
            max_slots: tuning.pre_admission_slots,
            evict_after: tuning.handshake_evict_after,
            table: Arc::new(SlotTable::default()),
        }
    }

    /// A slot for a new socket, or `None`.
    ///
    /// The bucket is charged first. With every slot taken, the oldest slot whose
    /// request is still incomplete and that is at least `handshake_evict_after`
    /// old is cancelled and its place given to the newcomer; when there is no such
    /// slot the newcomer is refused. An evicted socket may keep its descriptor
    /// for as long as its owner takes to notice, so the descriptor budget (7.3)
    /// has to absorb a few; evictions are limited by the bucket.
    pub fn try_start(&mut self, now: Instant) -> Option<PreAdmissionSlot> {
        if !self.bucket.try_take(now) {
            return None;
        }
        let ctl = Arc::new(SlotCtl::new(now));
        let mut live = lock_unpoisoned(&self.table.live);
        if live.len() < self.max_slots {
            live.push(Arc::clone(&ctl));
        } else {
            let victim = live
                .iter()
                .enumerate()
                .filter(|(_, other)| {
                    !other.complete.load(Ordering::Acquire)
                        && now.saturating_duration_since(other.started) >= self.evict_after
                })
                .min_by_key(|(_, other)| other.started)
                .map(|(at, _)| at)?;
            let old = live
                .get_mut(victim)
                .map(|place| std::mem::replace(place, Arc::clone(&ctl)))?;
            old.cancel();
            self.table.evicted.fetch_add(1, Ordering::Relaxed);
        }
        drop(live);
        Some(PreAdmissionSlot {
            ctl,
            table: Arc::clone(&self.table),
        })
    }

    /// Slots in use right now.
    #[must_use]
    pub fn in_use(&self) -> usize {
        lock_unpoisoned(&self.table.live).len()
    }

    /// Sockets cancelled to make room since this budget was created
    /// (`evicted_handshake`).
    #[must_use]
    pub fn evicted_total(&self) -> u64 {
        self.table.evicted.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Denial coalescing
// ---------------------------------------------------------------------------

/// What a denial is keyed by: the same client asking again for the same thing
/// under the same rule is one event, not a thousand.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DenialKey {
    pub profile: String,
    pub host: String,
    pub port: u16,
    /// A closed machine code (`SPECIAL_USE_NEEDS_EXACT_RULE`, `RULE_DENY`, ...).
    pub reason: &'static str,
    pub rule: Option<String>,
}

/// What to do with one occurrence of a denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Write a `Denied` record before the reply.
    FirstDurable,
    /// An occurrence of a key whose window is open: counted, not written.
    Repeat,
    /// A first occurrence that cannot be written now (the burst is spent, or the
    /// table is full): counted by reason only.
    Suppressed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepeatCount {
    pub key: DenialKey,
    pub count: u64,
}

/// What `take_summary` drains. The writer adds what only it knows (refusals over
/// its byte quota, pre-admission rejects) when it builds the `Summary` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenialSummary {
    /// Time since the previous summary (or since creation).
    pub window: Duration,
    /// Per reason: every refusal that was not written individually, the repeats
    /// and the suppressed ones together.
    pub suppressed: BTreeMap<&'static str, u64>,
    /// The most repeated keys, at most [`SUMMARY_KEYS`], most repeated first.
    pub repeated: Vec<RepeatCount>,
    /// Repeated keys that did not fit the list.
    pub other_keys: u64,
}

/// How many keys a summary names.
pub const SUMMARY_KEYS: usize = 16;

#[derive(Debug)]
struct Live {
    window_end: Instant,
    repeats: u64,
}

#[derive(Debug)]
pub struct DenialCoalescer {
    window: Duration,
    max_keys: usize,
    bucket: TokenBucket,
    live: BTreeMap<DenialKey, Live>,
    /// Keys whose window closed since the last summary, with repeats to report.
    retired: BTreeMap<DenialKey, u64>,
    /// Keys that did not fit `retired`; their repeats are in `suppressed`.
    retired_overflow: u64,
    suppressed: BTreeMap<&'static str, u64>,
    since: Instant,
}

impl DenialCoalescer {
    #[must_use]
    pub fn new(tuning: &Tuning, now: Instant) -> Self {
        Self {
            window: tuning.denial_window,
            max_keys: tuning.denial_keys,
            bucket: TokenBucket::new(tuning.denial_burst, tuning.denial_refill_per_s, now),
            live: BTreeMap::new(),
            retired: BTreeMap::new(),
            retired_overflow: 0,
            suppressed: BTreeMap::new(),
            since: now,
        }
    }

    /// Live keys right now (never more than `denial_keys`).
    #[must_use]
    pub fn live_keys(&self) -> usize {
        self.live.len()
    }

    /// Classifies one occurrence. Exactly one of the three outcomes, and every
    /// occurrence that is not `FirstDurable` is in the next summary's totals.
    pub fn classify(&mut self, key: DenialKey, now: Instant) -> Disposition {
        self.expire(now);
        if let Some(live) = self.live.get_mut(&key) {
            live.repeats = live.repeats.saturating_add(1);
            self.count_suppressed(key.reason);
            return Disposition::Repeat;
        }
        if self.live.len() >= self.max_keys || !self.bucket.try_take(now) {
            self.count_suppressed(key.reason);
            return Disposition::Suppressed;
        }
        let window_end = now.checked_add(self.window).unwrap_or(now);
        self.live.insert(
            key,
            Live {
                window_end,
                repeats: 0,
            },
        );
        Disposition::FirstDurable
    }

    /// Drains the totals and the per-key detail. `None` when nothing was
    /// suppressed or repeated since the last call.
    pub fn take_summary(&mut self, now: Instant) -> Option<DenialSummary> {
        self.expire(now);
        let mut by_key = std::mem::take(&mut self.retired);
        for (key, live) in &mut self.live {
            if live.repeats > 0 {
                let entry = by_key.entry(key.clone()).or_insert(0);
                *entry = entry.saturating_add(live.repeats);
                live.repeats = 0;
            }
        }
        let suppressed = std::mem::take(&mut self.suppressed);
        let overflow = std::mem::take(&mut self.retired_overflow);
        if suppressed.is_empty() && by_key.is_empty() && overflow == 0 {
            return None;
        }
        let mut ranked: Vec<RepeatCount> = by_key
            .into_iter()
            .map(|(key, count)| RepeatCount { key, count })
            .collect();
        // Most repeated first; the key order makes ties deterministic.
        ranked.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.key.cmp(&b.key)));
        let others = ranked.len().saturating_sub(SUMMARY_KEYS);
        ranked.truncate(SUMMARY_KEYS);
        let window = now.saturating_duration_since(self.since);
        self.since = self.since.max(now);
        Some(DenialSummary {
            window,
            suppressed,
            repeated: ranked,
            other_keys: u64::try_from(others)
                .unwrap_or(u64::MAX)
                .saturating_add(overflow),
        })
    }

    fn count_suppressed(&mut self, reason: &'static str) {
        let slot = self.suppressed.entry(reason).or_insert(0);
        *slot = slot.saturating_add(1);
    }

    /// Closes the windows that have ended, keeping their repeat counts for the
    /// next summary within the same bound as the live table.
    fn expire(&mut self, now: Instant) {
        let ended: Vec<DenialKey> = self
            .live
            .iter()
            .filter(|(_, live)| now >= live.window_end)
            .map(|(key, _)| key.clone())
            .collect();
        for key in ended {
            let Some(live) = self.live.remove(&key) else {
                continue;
            };
            if live.repeats == 0 {
                continue;
            }
            if self.retired.len() < self.max_keys || self.retired.contains_key(&key) {
                let entry = self.retired.entry(key).or_insert(0);
                *entry = entry.saturating_add(live.repeats);
            } else {
                self.retired_overflow = self.retired_overflow.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    fn key(host: &str) -> DenialKey {
        DenialKey {
            profile: "work".into(),
            host: host.into(),
            port: 443,
            reason: "SPECIAL_USE_NEEDS_EXACT_RULE",
            rule: Some("rule-1".into()),
        }
    }

    // -- accept bucket ------------------------------------------------------

    #[test]
    fn defaults_admit_a_burst_up_to_max_connections() {
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(256, 50, t0);
        let admitted = (0..300).filter(|_| limiter.try_take(t0)).count();
        assert_eq!(admitted, 256);
        assert!(!limiter.try_take(t0));
    }

    #[test]
    fn rate_limiter_refills_deterministically() {
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(5, 50, t0);
        assert_eq!((0..5).filter(|_| limiter.try_take(t0)).count(), 5);
        // 50 per second is one token every 20 ms.
        assert!(!limiter.try_take(t0 + ms(19)));
        assert!(limiter.try_take(t0 + ms(20)));
        assert!(!limiter.try_take(t0 + ms(20)));
        // The fraction is kept: 19 ms then 1 ms later is a whole token.
        let mut limiter = RateLimiter::new(1, 50, t0);
        assert!(limiter.try_take(t0));
        assert!(!limiter.try_take(t0 + ms(19)));
        assert!(limiter.try_take(t0 + ms(20)));
        // A second refills 50, no more than the burst.
        let mut limiter = RateLimiter::new(100, 50, t0);
        assert_eq!((0..100).filter(|_| limiter.try_take(t0)).count(), 100);
        assert_eq!(
            (0..100).filter(|_| limiter.try_take(t0 + ms(1000))).count(),
            50
        );
    }

    #[test]
    fn a_connect_loop_is_throttled_to_the_configured_rate() {
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(5, 50, t0);
        // One attempt per millisecond for ten seconds.
        let admitted = (0..10_000_u64)
            .filter(|n| limiter.try_take(t0 + ms(*n)))
            .count();
        assert!(
            (504..=506).contains(&admitted),
            "burst 5 + 50/s x 10 s is about 505, got {admitted}"
        );
    }

    #[test]
    fn an_idle_hour_never_banks_more_than_the_burst() {
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(7, 50, t0);
        let later = t0 + Duration::from_secs(3600);
        assert_eq!((0..100).filter(|_| limiter.try_take(later)).count(), 7);
    }

    #[test]
    fn a_fast_caller_still_gets_its_refill() {
        // Called every 100 microseconds, far below a token's period: nothing
        // may be lost between calls.
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(1, 50, t0);
        assert!(limiter.try_take(t0));
        let admitted = (1..=10_000_u64)
            .filter(|n| limiter.try_take(t0 + Duration::from_micros(n * 100)))
            .count();
        // One second elapsed: 50 tokens.
        assert!((49..=50).contains(&admitted), "{admitted}");
    }

    #[test]
    fn time_running_backwards_neither_panics_nor_refills() {
        let t0 = Instant::now();
        let mut limiter = RateLimiter::new(1, 50, t0 + ms(500));
        assert!(limiter.try_take(t0 + ms(500)));
        assert!(!limiter.try_take(t0));
        assert!(!limiter.try_take(t0 + ms(510)));
        assert!(limiter.try_take(t0 + ms(520)));
    }

    #[test]
    fn a_zero_burst_or_zero_rate_is_safe() {
        let t0 = Instant::now();
        let mut none = RateLimiter::new(0, 50, t0);
        assert!(!none.try_take(t0 + Duration::from_secs(10)));
        let mut once = RateLimiter::new(1, 0, t0);
        assert!(once.try_take(t0));
        assert!(!once.try_take(t0 + Duration::from_secs(3600)));
    }

    proptest! {
        /// Whatever the schedule, a bucket never admits more than its burst plus
        /// what the elapsed time paid for.
        #[test]
        fn the_bucket_never_exceeds_burst_plus_rate_times_time(
            burst in 0_u32..40,
            rate in 0_u32..2000,
            gaps in proptest::collection::vec(0_u64..400, 1..200),
        ) {
            let t0 = Instant::now();
            let mut limiter = RateLimiter::new(burst, rate, t0);
            let mut now = t0;
            let mut admitted = 0_u64;
            let mut elapsed_us = 0_u64;
            for gap in gaps {
                now += Duration::from_micros(gap);
                elapsed_us += gap;
                if limiter.try_take(now) {
                    admitted += 1;
                }
            }
            let allowance = u64::from(burst) + u64::from(rate) * elapsed_us / 1_000_000 + 1;
            prop_assert!(admitted <= allowance, "{admitted} > {allowance}");
        }
    }

    // -- pre-admission budget -----------------------------------------------

    fn tuning() -> Tuning {
        Tuning::default()
    }

    #[test]
    fn peer_budget_caps_slots_and_evicts_the_oldest_silent_socket_after_one_second() {
        let t0 = Instant::now();
        let mut budget = PeerBudget::new(&tuning(), t0);
        let mut slots: Vec<PreAdmissionSlot> = (0..64)
            .map(|n| budget.try_start(t0 + ms(n)).expect("a free slot"))
            .collect();
        assert_eq!(budget.in_use(), 64);
        // Full, and nobody is a second old yet.
        assert!(budget.try_start(t0 + ms(500)).is_none());
        assert!(
            budget.try_start(t0 + ms(999)).is_none(),
            "the oldest is 999 ms old: one millisecond short"
        );
        // The oldest was started at t0 and is exactly 1 s old: it is evicted.
        let newcomer = budget.try_start(t0 + ms(1000)).expect("evicts the oldest");
        assert_eq!(budget.evicted_total(), 1);
        assert_eq!(budget.in_use(), 64, "the place passed to the newcomer");
        assert!(slots.first().expect("slot 0").was_evicted());
        assert!(!slots.get(1).expect("slot 1").was_evicted());
        assert!(!newcomer.was_evicted());
        // Dropping the evicted socket's slot frees nothing: the place is the
        // newcomer's.
        slots.remove(0);
        assert_eq!(budget.in_use(), 64);
        drop(newcomer);
        assert_eq!(budget.in_use(), 63);
    }

    #[test]
    fn eviction_takes_the_oldest_incomplete_slot_and_never_a_complete_one() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.pre_admission_slots = 3;
        let mut budget = PeerBudget::new(&tuned, t0);
        let oldest = budget.try_start(t0).expect("slot");
        let middle = budget.try_start(t0 + ms(100)).expect("slot");
        let young = budget.try_start(t0 + ms(1900)).expect("slot");
        // The oldest has a complete request: it is not eligible.
        oldest.request_complete();
        let newcomer = budget.try_start(t0 + ms(2000)).expect("evicts someone");
        assert!(!oldest.was_evicted(), "a complete request is never evicted");
        assert!(middle.was_evicted(), "the oldest incomplete one is");
        assert!(!young.was_evicted());
        drop(newcomer);
    }

    #[test]
    fn among_several_eligible_slots_the_oldest_loses_its_place() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.pre_admission_slots = 3;
        let mut budget = PeerBudget::new(&tuned, t0);
        // Started out of age order on purpose, so that neither "the first in the
        // table" nor "the last" is the oldest.
        let second = budget.try_start(t0 + ms(500)).expect("slot");
        let oldest = budget.try_start(t0).expect("slot");
        let third = budget.try_start(t0 + ms(900)).expect("slot");
        // All three are at least a second old: 3 s, 2.5 s and 2.1 s.
        let newcomer = budget
            .try_start(t0 + Duration::from_secs(3))
            .expect("evicts one");
        assert!(oldest.was_evicted());
        assert!(!second.was_evicted() && !third.was_evicted());
        // The next newcomer takes the next oldest.
        let another = budget
            .try_start(t0 + Duration::from_secs(4))
            .expect("evicts one");
        assert!(second.was_evicted() && !third.was_evicted());
        drop((newcomer, another));
    }

    #[test]
    fn when_every_old_slot_is_complete_nobody_is_evicted() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.pre_admission_slots = 2;
        let mut budget = PeerBudget::new(&tuned, t0);
        let a = budget.try_start(t0).expect("slot");
        let b = budget.try_start(t0).expect("slot");
        a.request_complete();
        b.request_complete();
        assert!(budget.try_start(t0 + Duration::from_secs(60)).is_none());
        assert_eq!(budget.evicted_total(), 0);
    }

    #[test]
    fn a_dropped_slot_frees_its_place_without_an_eviction() {
        let t0 = Instant::now();
        let mut budget = PeerBudget::new(&tuning(), t0);
        let mut slots: Vec<_> = (0..64).filter_map(|_| budget.try_start(t0)).collect();
        assert_eq!(slots.len(), 64);
        slots.pop();
        assert!(budget.try_start(t0).is_some());
        assert_eq!(budget.evicted_total(), 0);
    }

    #[test]
    fn the_cheap_bucket_limits_attempts_even_when_slots_are_free() {
        let t0 = Instant::now();
        let mut budget = PeerBudget::new(&tuning(), t0);
        // Each socket is gone at once, so slots are never the limit.
        let admitted = (0..300).filter(|_| budget.try_start(t0).is_some()).count();
        assert_eq!(admitted, 256);
        // 1024 per second refills the whole burst in a quarter of a second.
        let later = t0 + ms(250);
        assert_eq!(
            (0..300)
                .filter(|_| budget.try_start(later).is_some())
                .count(),
            256
        );
    }

    #[test]
    fn a_refused_newcomer_still_paid_the_bucket() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.pre_admission_slots = 1;
        tuned.peer_burst = 3;
        tuned.peer_refill_per_s = 0;
        let mut budget = PeerBudget::new(&tuned, t0);
        let held = budget.try_start(t0).expect("the one slot"); // 2 tokens left
        assert!(budget.try_start(t0).is_none(), "no slot, nobody old"); // 1 left
                                                                        // Two seconds on, the held slot can be evicted: the third token is spent.
        let second = budget
            .try_start(t0 + Duration::from_secs(2))
            .expect("evicts the held slot"); // 0 left
        assert!(held.was_evicted());
        // Two more seconds on, the second slot is old enough, but the bucket is
        // empty. Had the refused attempt not paid, a token would be left.
        assert!(budget.try_start(t0 + Duration::from_secs(4)).is_none());
        assert!(!second.was_evicted());
    }

    #[tokio::test]
    async fn an_evicted_owner_is_woken_and_an_untouched_one_is_not() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.pre_admission_slots = 2;
        let mut budget = PeerBudget::new(&tuned, t0);
        let old = budget.try_start(t0).expect("slot");
        let young = budget.try_start(t0 + ms(1500)).expect("slot");
        // Nothing has happened yet: neither is cancelled.
        assert!(
            tokio::time::timeout(ms(30), old.cancelled()).await.is_err(),
            "no eviction, no wake"
        );
        let waiting = tokio::spawn(async move {
            old.cancelled().await;
            old
        });
        tokio::task::yield_now().await;
        let _newcomer = budget.try_start(t0 + ms(1600)).expect("evicts the old one");
        let old = tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("woken")
            .expect("task");
        assert!(old.was_evicted());
        assert!(
            tokio::time::timeout(ms(30), young.cancelled())
                .await
                .is_err(),
            "the young one keeps its place"
        );
        // A cancel that happened before anyone waited is not lost.
        tokio::time::timeout(ms(30), old.cancelled())
            .await
            .expect("already cancelled completes at once");
    }

    #[test]
    fn slots_are_released_even_when_the_table_lock_was_poisoned() {
        let t0 = Instant::now();
        let mut budget = PeerBudget::new(&tuning(), t0);
        let slot = budget.try_start(t0).expect("slot");
        let table = Arc::clone(&budget.table);
        let _ = std::thread::spawn(move || {
            let _guard = table.live.lock().expect("fresh lock");
            panic!("poison the slot table");
        })
        .join();
        assert_eq!(budget.in_use(), 1);
        drop(slot);
        assert_eq!(budget.in_use(), 0);
    }

    // -- denial coalescing --------------------------------------------------

    #[test]
    fn denial_coalescer_first_occurrence_durable_repeats_counted() {
        let t0 = Instant::now();
        let mut coalescer = DenialCoalescer::new(&tuning(), t0);
        assert_eq!(
            coalescer.classify(key("a.example"), t0),
            Disposition::FirstDurable
        );
        for n in 1..=5 {
            assert_eq!(
                coalescer.classify(key("a.example"), t0 + ms(n)),
                Disposition::Repeat
            );
        }
        // Another key, another reason, another port, another rule: new events.
        assert_eq!(
            coalescer.classify(key("b.example"), t0),
            Disposition::FirstDurable
        );
        let mut other_reason = key("a.example");
        other_reason.reason = "RULE_DENY";
        assert_eq!(
            coalescer.classify(other_reason, t0),
            Disposition::FirstDurable
        );
        let mut other_port = key("a.example");
        other_port.port = 80;
        assert_eq!(
            coalescer.classify(other_port, t0),
            Disposition::FirstDurable
        );
        let mut other_rule = key("a.example");
        other_rule.rule = None;
        assert_eq!(
            coalescer.classify(other_rule, t0),
            Disposition::FirstDurable
        );
        let mut other_profile = key("a.example");
        other_profile.profile = "home".into();
        assert_eq!(
            coalescer.classify(other_profile, t0),
            Disposition::FirstDurable
        );

        let summary = coalescer
            .take_summary(t0 + ms(10))
            .expect("repeats to report");
        assert_eq!(
            summary.suppressed.get("SPECIAL_USE_NEEDS_EXACT_RULE"),
            Some(&5)
        );
        assert_eq!(
            summary.repeated,
            vec![RepeatCount {
                key: key("a.example"),
                count: 5
            }]
        );
        assert_eq!(summary.other_keys, 0);
        assert_eq!(summary.window, ms(10));
    }

    #[test]
    fn the_window_closes_after_sixty_seconds_and_the_next_denial_is_written_again() {
        let t0 = Instant::now();
        let mut coalescer = DenialCoalescer::new(&tuning(), t0);
        assert_eq!(
            coalescer.classify(key("a.example"), t0),
            Disposition::FirstDurable
        );
        // The window does not slide: a steady repeater does not keep it open.
        for n in 1..60 {
            assert_eq!(
                coalescer.classify(key("a.example"), t0 + Duration::from_secs(n)),
                Disposition::Repeat,
                "second {n}"
            );
        }
        assert_eq!(
            coalescer.classify(key("a.example"), t0 + Duration::from_secs(60)),
            Disposition::FirstDurable
        );
        // The repeats of the closed window were kept for the summary.
        let summary = coalescer
            .take_summary(t0 + Duration::from_secs(61))
            .expect("summary");
        assert_eq!(summary.repeated.first().map(|r| r.count), Some(59));
    }

    #[test]
    fn a_burst_of_distinct_denials_writes_twenty_and_then_one_per_second() {
        let t0 = Instant::now();
        let mut coalescer = DenialCoalescer::new(&tuning(), t0);
        let firsts = (0..100)
            .filter(|n| {
                coalescer.classify(key(&format!("h{n}.example")), t0) == Disposition::FirstDurable
            })
            .count();
        assert_eq!(firsts, 20);
        // One second later exactly one more.
        let later = t0 + Duration::from_secs(1);
        let firsts = (100..200)
            .filter(|n| {
                coalescer.classify(key(&format!("h{n}.example")), later)
                    == Disposition::FirstDurable
            })
            .count();
        assert_eq!(firsts, 1);
        let summary = coalescer.take_summary(later).expect("suppressed denials");
        assert_eq!(summary.suppressed.values().sum::<u64>(), 80 + 99);
        assert!(summary.repeated.is_empty());
    }

    #[test]
    fn key_table_is_bounded_at_128() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.denial_burst = 10_000;
        let mut coalescer = DenialCoalescer::new(&tuned, t0);
        let firsts = (0..1000)
            .filter(|n| {
                coalescer.classify(key(&format!("h{n}.example")), t0) == Disposition::FirstDurable
            })
            .count();
        assert_eq!(
            firsts, 128,
            "the 129th distinct key is suppressed, not tracked"
        );
        assert_eq!(coalescer.live_keys(), 128);
        // Known keys still repeat; the table did not forget them.
        assert_eq!(
            coalescer.classify(key("h0.example"), t0),
            Disposition::Repeat
        );
        // After the windows close the table has room again.
        let later = t0 + Duration::from_secs(61);
        assert_eq!(
            coalescer.classify(key("h500.example"), later),
            Disposition::FirstDurable
        );
        assert!(coalescer.live_keys() <= 128);
    }

    #[test]
    fn summary_reconciles_exactly() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.denial_burst = 30;
        let mut coalescer = DenialCoalescer::new(&tuned, t0);
        let mut calls = 0_u64;
        let mut firsts = 0_u64;
        for step in 0..400_u64 {
            let host = format!("h{}.example", step % 45);
            let now = t0 + ms(step * 37);
            calls += 1;
            if coalescer.classify(key(&host), now) == Disposition::FirstDurable {
                firsts += 1;
            }
        }
        let summary = coalescer
            .take_summary(t0 + Duration::from_secs(20))
            .expect("summary");
        assert_eq!(
            firsts + summary.suppressed.values().sum::<u64>(),
            calls,
            "every occurrence is either written or in the totals"
        );
        let listed: u64 = summary.repeated.iter().map(|r| r.count).sum();
        assert!(listed <= summary.suppressed.values().sum::<u64>());
        assert!(summary.repeated.len() <= SUMMARY_KEYS);
        // Drained: nothing is reported twice.
        assert_eq!(coalescer.take_summary(t0 + Duration::from_secs(21)), None);
    }

    #[test]
    fn the_summary_names_the_most_repeated_keys_and_counts_the_rest() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.denial_burst = 100;
        let mut coalescer = DenialCoalescer::new(&tuned, t0);
        // 20 keys; key n is seen n + 2 times (1 first + n + 1 repeats).
        for n in 0..20_u64 {
            let host = format!("h{n:02}.example");
            assert_eq!(
                coalescer.classify(key(&host), t0),
                Disposition::FirstDurable
            );
            for _ in 0..=n {
                assert_eq!(coalescer.classify(key(&host), t0), Disposition::Repeat);
            }
        }
        let summary = coalescer.take_summary(t0).expect("summary");
        assert_eq!(summary.repeated.len(), SUMMARY_KEYS);
        assert_eq!(summary.other_keys, 4);
        let counts: Vec<u64> = summary.repeated.iter().map(|r| r.count).collect();
        assert_eq!(counts, (4..=19).rev().map(|n| n + 1).collect::<Vec<u64>>());
        assert_eq!(
            summary.repeated.first().map(|r| r.key.host.as_str()),
            Some("h19.example")
        );
    }

    #[test]
    fn repeats_of_a_key_whose_window_closed_are_still_reported() {
        let t0 = Instant::now();
        let mut coalescer = DenialCoalescer::new(&tuning(), t0);
        assert_eq!(
            coalescer.classify(key("a.example"), t0),
            Disposition::FirstDurable
        );
        for _ in 0..3 {
            coalescer.classify(key("a.example"), t0 + ms(10));
        }
        // Long after the window, another key arrives, which closes the first
        // window; its repeats must survive until the summary.
        let later = t0 + Duration::from_secs(300);
        assert_eq!(
            coalescer.classify(key("b.example"), later),
            Disposition::FirstDurable
        );
        let summary = coalescer.take_summary(later).expect("summary");
        assert_eq!(
            summary.repeated,
            vec![RepeatCount {
                key: key("a.example"),
                count: 3
            }]
        );
        assert_eq!(summary.window, Duration::from_secs(300));
    }

    #[test]
    fn nothing_to_report_is_none_and_the_window_restarts_at_each_summary() {
        let t0 = Instant::now();
        let mut coalescer = DenialCoalescer::new(&tuning(), t0);
        assert_eq!(coalescer.take_summary(t0 + ms(5)), None);
        coalescer.classify(key("a.example"), t0 + ms(6));
        assert_eq!(
            coalescer.take_summary(t0 + ms(7)),
            None,
            "a first occurrence is not a repeat"
        );
        coalescer.classify(key("a.example"), t0 + ms(8));
        let first = coalescer.take_summary(t0 + ms(10)).expect("one repeat");
        assert_eq!(first.window, ms(10));
        coalescer.classify(key("a.example"), t0 + ms(20));
        let second = coalescer.take_summary(t0 + ms(30)).expect("one more");
        assert_eq!(second.window, ms(20), "counted from the previous summary");
        assert_eq!(second.suppressed.values().sum::<u64>(), 1);
    }

    #[test]
    fn retired_detail_is_bounded_and_the_overflow_is_counted() {
        let t0 = Instant::now();
        let mut tuned = tuning();
        tuned.denial_burst = 10_000;
        tuned.denial_keys = 4;
        let mut coalescer = DenialCoalescer::new(&tuned, t0);
        // Eight rounds of four keys, each seen twice, each round after the last
        // window: 32 keys retire with a repeat each, the table keeps four.
        for round in 0..8_u64 {
            let at = t0 + Duration::from_secs(round * 61);
            for n in 0..4 {
                let host = format!("r{round}-{n}.example");
                coalescer.classify(key(&host), at);
                coalescer.classify(key(&host), at);
            }
        }
        // Taken while the last round is still inside its window.
        let summary = coalescer
            .take_summary(t0 + Duration::from_secs(7 * 61 + 30))
            .expect("summary");
        assert_eq!(summary.suppressed.values().sum::<u64>(), 32);
        // 28 keys retired and 4 are live: four of the retired ones kept their
        // detail, so 8 keys are named and the other 24 are only counted.
        assert_eq!(summary.repeated.len(), 8);
        assert_eq!(summary.other_keys, 24);
    }

    proptest! {
        #[test]
        fn the_coalescer_is_bounded_and_reconciles_for_any_schedule(
            events in proptest::collection::vec((0_u8..200, 0_u64..5000), 1..400),
        ) {
            let t0 = Instant::now();
            let mut tuned = tuning();
            tuned.denial_keys = 16;
            let mut coalescer = DenialCoalescer::new(&tuned, t0);
            let mut now = t0;
            let mut calls = 0_u64;
            let mut firsts = 0_u64;
            for (host, gap) in events {
                now += ms(gap);
                calls += 1;
                if coalescer.classify(key(&format!("h{host}.example")), now) == Disposition::FirstDurable {
                    firsts += 1;
                }
                prop_assert!(coalescer.live_keys() <= 16);
            }
            let totals = coalescer
                .take_summary(now)
                .map_or(0, |s| s.suppressed.values().sum::<u64>());
            prop_assert_eq!(firsts + totals, calls);
        }
    }
}
