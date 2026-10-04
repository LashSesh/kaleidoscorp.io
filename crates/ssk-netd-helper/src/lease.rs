//! Cross-session refcounting for the kill-switch (roadmap P3).
//!
//! # Why not a counter
//!
//! The obvious implementation is a `u32` in the ACL'd store. It leaks: holder A
//! engages (count 1), A crashes, the count is 1 forever, and the machine stays
//! severed with no holder and no way to decrement. That is exactly the strand
//! this phase exists to remove, reintroduced one level up.
//!
//! So the refcount is a **set of leases**, each carrying its own liveness class.
//! A lease can be proven dead; a number cannot.
//!
//! # The two classes are a real product split, not a tuning knob
//!
//! * [`LeaseKind::Session`] is bound to one authenticated connection. No
//!   connection outlives the process that accepted it, so **every persisted
//!   `Session` lease is provably dead after a restart** and is discarded by
//!   [`crate::Broker::reconcile_startup`]. That is what makes the refcount
//!   structurally unable to leak.
//! * [`LeaseKind::Pinned`] is explicitly durable: it survives a restart and a
//!   reboot, and goes away only when someone says so.
//!
//! Therefore an operator typing `killswitch engage` takes a `Pinned` lease — the
//! machine should still be severed after a reboot — while a GUI toggle takes a
//! `Session` lease, because "keep egress severed while I am connected" is what
//! a toggle means, and holding it severed after the holder is gone is the
//! strand.
//!
//! # The lease id is not a secret
//!
//! It is minted by the server side of the transport (see
//! [`crate::server::LeaseIdSource`]) and returned to the holder in the
//! handshake. Guessing one buys nothing on its own: presenting an id still
//! requires a connection that got past the pipe DACL **and** a
//! [`crate::authz::PeerAuthorizer`] decision for the verb. The id distinguishes
//! *which* claim is being dropped; it does not authorize dropping it. Anything
//! that treats it as a bearer credential is a defect.

use serde::{Deserialize, Serialize};

/// Identifies one claim on the engaged kill-switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseId(pub [u8; 16]);

impl LeaseId {
    /// The single implicit lease used by [`crate::Broker::handle`], the
    /// peer-less in-process entry point. Distinct from anything a
    /// [`crate::server::LeaseIdSource`] mints, so an in-process caller and a
    /// pipe client can never collide.
    pub const IN_PROCESS: LeaseId = LeaseId([0xff; 16]);

    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// How long a lease is allowed to outlive its holder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum LeaseKind {
    /// Dies with the connection that took it, and — because no connection
    /// survives the process — with a broker restart.
    Session,
    /// Durable. Survives restart and reboot; released only by an explicit
    /// release naming it, or by the operator override.
    Pinned,
}

impl LeaseKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseKind::Session => "session",
            LeaseKind::Pinned => "pinned",
        }
    }

    /// Whether this lease may still be held after the broker process restarts.
    #[must_use]
    pub fn survives_restart(self) -> bool {
        match self {
            LeaseKind::Session => false,
            LeaseKind::Pinned => true,
        }
    }
}

/// One claim on the engaged kill-switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub id: LeaseId,
    pub kind: LeaseKind,
    /// The authenticated principal that took it — **for the audit line only**.
    /// It is the peer's SID as the transport authenticated it, never a
    /// caller-supplied string.
    pub holder: String,
    /// The state version current when the lease was taken.
    pub taken_at_version: u64,
}

/// The set of live claims. Ordered by id so the persisted snapshot is stable
/// (an unstable ordering would make otherwise-identical snapshots differ, which
/// matters for a store whose whole job is crash-comparability).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseSet {
    leases: Vec<Lease>,
}

impl LeaseSet {
    #[must_use]
    pub fn new() -> Self {
        LeaseSet::default()
    }

    /// Rebuild from a persisted snapshot, discarding duplicates by id.
    ///
    /// A duplicate id in the store is corruption, not a doubled claim: two
    /// claims cannot share an id, and counting one twice would keep the machine
    /// severed after every legitimate holder let go. The first occurrence wins
    /// and the duplicate count is returned so the caller can audit it.
    #[must_use]
    pub fn from_persisted(leases: Vec<Lease>) -> (Self, usize) {
        let mut set = LeaseSet::new();
        let mut duplicates = 0usize;
        for lease in leases {
            if !set.insert(lease) {
                duplicates += 1;
            }
        }
        (set, duplicates)
    }

    /// Insert a claim. Returns `false` (and changes nothing) if that id is
    /// already held — re-taking a lease you already hold is not a second claim.
    pub fn insert(&mut self, lease: Lease) -> bool {
        match self.leases.binary_search_by(|l| l.id.cmp(&lease.id)) {
            Ok(_) => false,
            Err(at) => {
                self.leases.insert(at, lease);
                true
            }
        }
    }

    /// Drop a claim, returning it if it was held.
    pub fn remove(&mut self, id: &LeaseId) -> Option<Lease> {
        match self.leases.binary_search_by(|l| l.id.cmp(id)) {
            Ok(at) => Some(self.leases.remove(at)),
            Err(_) => None,
        }
    }

    #[must_use]
    pub fn contains(&self, id: &LeaseId) -> bool {
        self.leases.binary_search_by(|l| l.id.cmp(id)).is_ok()
    }

    #[must_use]
    pub fn get(&self, id: &LeaseId) -> Option<&Lease> {
        self.leases
            .binary_search_by(|l| l.id.cmp(id))
            .ok()
            .map(|at| &self.leases[at])
    }

    /// Discard every lease that cannot survive a restart, returning the
    /// discarded ones so each can be audited.
    ///
    /// This is the operation that makes the refcount leak-proof, and it is
    /// deliberately **not** performed by [`crate::Broker::recover`]: rehydrating
    /// the journal and deciding that a claim is dead are different decisions,
    /// and the second one belongs to the explicit service-start reconciliation
    /// (which can then also make the OS agree).
    pub fn retain_restart_survivors(&mut self) -> Vec<Lease> {
        let mut discarded = Vec::new();
        self.leases.retain(|l| {
            if l.kind.survives_restart() {
                true
            } else {
                discarded.push(l.clone());
                false
            }
        });
        discarded
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Lease] {
        &self.leases
    }

    #[must_use]
    pub fn to_vec(&self) -> Vec<Lease> {
        self.leases.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(byte: u8, kind: LeaseKind) -> Lease {
        Lease {
            id: LeaseId([byte; 16]),
            kind,
            holder: format!("S-1-5-21-1-2-3-{}", u32::from(byte) + 1000),
            taken_at_version: u64::from(byte),
        }
    }

    #[test]
    fn insert_is_idempotent_on_the_same_id() {
        let mut set = LeaseSet::new();
        assert!(set.insert(lease(1, LeaseKind::Session)));
        assert!(
            !set.insert(lease(1, LeaseKind::Pinned)),
            "same id, not a second claim"
        );
        assert_eq!(set.len(), 1);
        assert_eq!(
            set.get(&LeaseId([1; 16])).unwrap().kind,
            LeaseKind::Session,
            "the first claim is preserved verbatim; a re-take must not upgrade it"
        );
    }

    #[test]
    fn remove_returns_the_claim_and_is_idempotent() {
        let mut set = LeaseSet::new();
        set.insert(lease(2, LeaseKind::Pinned));
        assert_eq!(
            set.remove(&LeaseId([2; 16])).unwrap().kind,
            LeaseKind::Pinned
        );
        assert!(set.is_empty());
        assert!(
            set.remove(&LeaseId([2; 16])).is_none(),
            "releasing a lease that is already gone is a no-op, not an error: the transport retries"
        );
    }

    #[test]
    fn the_set_stays_ordered_by_id_whatever_the_insertion_order() {
        let mut forward = LeaseSet::new();
        let mut backward = LeaseSet::new();
        for b in [3u8, 1, 2] {
            forward.insert(lease(b, LeaseKind::Session));
        }
        for b in [2u8, 3, 1] {
            backward.insert(lease(b, LeaseKind::Session));
        }
        assert_eq!(
            forward, backward,
            "the snapshot must not depend on arrival order"
        );
        let ids: Vec<u8> = forward.as_slice().iter().map(|l| l.id.0[0]).collect();
        assert_eq!(ids, vec![1, 2, 3]);
    }

    #[test]
    fn only_pinned_leases_survive_a_restart() {
        let mut set = LeaseSet::new();
        set.insert(lease(1, LeaseKind::Session));
        set.insert(lease(2, LeaseKind::Pinned));
        set.insert(lease(3, LeaseKind::Session));
        let discarded = set.retain_restart_survivors();

        assert_eq!(discarded.len(), 2, "both session leases are provably dead");
        assert!(discarded.iter().all(|l| l.kind == LeaseKind::Session));
        assert_eq!(set.len(), 1);
        assert_eq!(set.as_slice()[0].kind, LeaseKind::Pinned);

        // Idempotent: a second sweep discards nothing.
        assert!(set.retain_restart_survivors().is_empty());
    }

    #[test]
    fn a_duplicate_id_in_the_store_is_counted_once_and_reported() {
        let (set, duplicates) = LeaseSet::from_persisted(vec![
            lease(1, LeaseKind::Pinned),
            lease(1, LeaseKind::Pinned),
            lease(2, LeaseKind::Session),
        ]);
        assert_eq!(set.len(), 2);
        assert_eq!(
            duplicates, 1,
            "a duplicate must be visible, not silently doubled into the refcount"
        );
    }

    #[test]
    fn the_in_process_lease_is_distinct_from_a_zero_lease() {
        assert_ne!(LeaseId::IN_PROCESS, LeaseId([0; 16]));
        assert_eq!(LeaseId::IN_PROCESS.to_hex().len(), 32);
    }

    #[test]
    fn lease_kind_liveness_is_explicit() {
        assert!(!LeaseKind::Session.survives_restart());
        assert!(LeaseKind::Pinned.survives_restart());
        assert_eq!(LeaseKind::Session.as_str(), "session");
        assert_eq!(LeaseKind::Pinned.as_str(), "pinned");
    }

    #[test]
    fn a_lease_round_trips_through_cbor_with_unknown_fields_refused() {
        let l = lease(7, LeaseKind::Pinned);
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&l, &mut bytes).unwrap();
        let back: Lease = ciborium::de::from_reader(&bytes[..]).unwrap();
        assert_eq!(back, l);
    }
}
