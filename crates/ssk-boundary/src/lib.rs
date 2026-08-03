#![forbid(unsafe_code)]

//! # ssk-boundary — the session-local system-wide kill-switch (SSCL-7)
//!
//! An authorization-gated, audited, **reversible** switch that severs a
//! session's egress. It owns a [`KillSwitchState`] machine (Armed → Engaged →
//! Released), a [`BoundaryPolicy`] (which authorizations may engage / override),
//! a hash-chained append-only audit ledger, and a rollback path: releasing
//! restores whatever the enforcement changed, via the receipt captured on
//! engage. An authorized [`KillSwitch::override_engage`] can force engagement
//! and is itself audited.
//!
//! The crate is pure and deterministic. The concrete privileged enforcement that
//! actually tears down egress binds a [`BoundaryEnforcer`] at the integration
//! layer; tests inject fakes. The switch is **session-local**: it is bound to a
//! `SessionId`, and release reverts it — nothing persists beyond the session.

use serde::{Deserialize, Serialize};
use ssk_signature::AuthorizationManifest;
use ssk_types::{digest_of, Digest, HashAlg, SessionId};

/// Authorization use required to engage/release the switch.
pub const BOUNDARY_CONTROL_USE: &str = "boundary_control";
/// Authorization use required to override the switch.
pub const BOUNDARY_OVERRIDE_USE: &str = "boundary_override";

/// Errors the boundary layer can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BoundaryError {
    #[error("boundary operation requires authorization")]
    Unauthorized,
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    #[error("no active enforcement to release")]
    NotEngaged,
    #[error("enforcement failed: {0}")]
    Enforcement(String),
    /// The enforcing action itself reported success, but the enforcer could
    /// **not confirm the post-condition** (e.g. it could not observe that the
    /// egress block is actually in place).
    ///
    /// This is deliberately *not* `Ok`: a claim of protection must never be
    /// stronger than the evidence for it. It is equally deliberately *not* a
    /// plain [`BoundaryError::Enforcement`]: it carries the
    /// [`EnforcementReceipt`] so the (possibly real) enforcement stays
    /// releasable. Dropping the receipt here would strand the host with an
    /// enforcement nobody can roll back — a denial-of-rollback with no
    /// attacker required.
    ///
    /// A caller that persists receipts **must persist this one too**, then
    /// report the failure.
    #[error("enforcement applied but could not be verified: {detail}")]
    EnforcementUnverified {
        receipt: Box<EnforcementReceipt>,
        detail: String,
    },
    #[error("cannot rehydrate: corrupt or incoherent journal: {0}")]
    CorruptJournal(String),
}

/// The kill-switch state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KillSwitchState {
    Armed,
    Engaged,
    Released,
}

impl KillSwitchState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KillSwitchState::Armed => "armed",
            KillSwitchState::Engaged => "engaged",
            KillSwitchState::Released => "released",
        }
    }
}

/// What the switch severs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryScope {
    pub label: String,
    pub targets: Vec<String>,
}

impl BoundaryScope {
    /// The whole session's egress.
    #[must_use]
    pub fn all_egress() -> Self {
        BoundaryScope {
            label: "all_egress".to_owned(),
            targets: vec!["*".to_owned()],
        }
    }

    #[must_use]
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(
        label: impl Into<String>,
        targets: I,
    ) -> Self {
        BoundaryScope {
            label: label.into(),
            targets: targets.into_iter().map(Into::into).collect(),
        }
    }
}

/// A receipt of an enforcement action — captures what changed so it can be
/// reverted on release (rollback).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReceipt {
    pub receipt_id: Digest,
    pub scope_label: String,
    /// The boundary state that was in effect before engagement (restored on release).
    pub prior_state: String,
}

/// Why an [`EnforcementReceipt`] failed its integrity check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptIntegrityError {
    #[error("receipt is for scope {found:?}, not {expected:?}")]
    ScopeLabelMismatch { expected: String, found: String },
    #[error("receipt_id does not match its own contents (expected {expected}, found {found})")]
    DigestMismatch { expected: String, found: String },
}

impl EnforcementReceipt {
    #[must_use]
    pub fn new(scope: &BoundaryScope, prior_state: impl Into<String>) -> Self {
        let prior_state = prior_state.into();
        let receipt_id = Self::expected_id(scope, &prior_state);
        EnforcementReceipt {
            receipt_id,
            scope_label: scope.label.clone(),
            prior_state,
        }
    }

    /// The `receipt_id` a receipt for this `(scope, prior_state)` pair must
    /// carry. Exposed so a loader can recompute rather than trust.
    #[must_use]
    pub fn expected_id(scope: &BoundaryScope, prior_state: &str) -> Digest {
        #[derive(Serialize)]
        struct Form<'a> {
            scope: &'a BoundaryScope,
            prior_state: &'a str,
        }
        digest_of(&Form { scope, prior_state }, HashAlg::Blake3)
            .expect("receipt form is serializable")
    }

    /// Recompute `receipt_id` from `scope` + this receipt's own `prior_state`
    /// and compare, after checking the receipt is for that scope at all.
    ///
    /// # What this detects, and what it does **not**
    ///
    /// `receipt_id` is an **unkeyed** Blake3 hash over `{scope, prior_state}`
    /// (see [`EnforcementReceipt::new`]). Anyone who can write a receipt can
    /// therefore also compute a matching `receipt_id` for a `prior_state` of
    /// their choosing. This check consequently detects:
    ///
    /// * corruption, truncation and torn writes of a persisted receipt,
    /// * a receipt paired with the **wrong scope**,
    /// * naive tampering that edits `prior_state` without rehashing,
    ///
    /// and it does **not** detect forgery. Forgery is bounded elsewhere:
    /// by the DACL on wherever receipts are stored, and — decisively — by the
    /// enforcer validating the *contents* of `prior_state` before acting on
    /// them (see `ssk_winhost::firewall::KillSwitchRuleName`). Do not treat a
    /// passing `verify_against` as authentication.
    ///
    /// # Errors
    /// [`ReceiptIntegrityError`] when the scope label or the digest disagree.
    pub fn verify_against(&self, scope: &BoundaryScope) -> Result<(), ReceiptIntegrityError> {
        if self.scope_label != scope.label {
            return Err(ReceiptIntegrityError::ScopeLabelMismatch {
                expected: scope.label.clone(),
                found: self.scope_label.clone(),
            });
        }
        let expected = Self::expected_id(scope, &self.prior_state);
        if expected != self.receipt_id {
            return Err(ReceiptIntegrityError::DigestMismatch {
                expected: expected.to_hex(),
                found: self.receipt_id.to_hex(),
            });
        }
        Ok(())
    }
}

/// Three-valued presence of an enforcement, as **observed** rather than as
/// believed.
///
/// The third value is the point: a probe that cannot answer must say so.
/// Collapsing `Indeterminate` into `Absent` is how a kill-switch comes to
/// report restored egress it never restored, so it is spelled out as its own
/// variant and no constructor produces `Absent` from a failed observation.
///
/// This is the same fail-closed contract `ssk_netd_helper::status::EgressObserver`
/// already specifies as `Option<bool>`; [`Presence::as_option_bool`] is the
/// lossless bridge to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Presence {
    /// Positively observed to be in place.
    Present,
    /// Positively observed to be gone.
    Absent,
    /// The probe could not answer. **Never** treat as `Absent`.
    Indeterminate { detail: String },
}

impl Presence {
    #[must_use]
    pub fn is_present(&self) -> bool {
        matches!(self, Presence::Present)
    }

    /// `Some(true)`/`Some(false)` when observed, `None` when indeterminate —
    /// the shape `EgressObserver::rule_present` speaks.
    #[must_use]
    pub fn as_option_bool(&self) -> Option<bool> {
        match self {
            Presence::Present => Some(true),
            Presence::Absent => Some(false),
            Presence::Indeterminate { .. } => None,
        }
    }
}

/// One observation of the boundary, with the mechanism that produced it and
/// opaque human-readable evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryObservation {
    pub presence: Presence,
    /// Which actuator observed this, e.g. `"netsh-advfirewall"`,
    /// `"wfp-session-filter"`. Stable identifiers, not prose.
    pub mechanism: &'static str,
    /// Diagnostic payload for a human or a log. **No branch may read this** —
    /// it is whatever the underlying tool emitted, in whatever locale and
    /// encoding it chose.
    pub evidence: String,
}

/// Observe the boundary without mutating it. Deliberately distinct from
/// [`BoundaryEnforcer`]: a status/recovery path must be able to look without
/// any possibility of changing anything.
pub trait BoundaryProbe {
    fn observe(&self, scope: &BoundaryScope) -> BoundaryObservation;
}

/// What a release actually did — so a caller can report the truth instead of
/// assuming `Ok(())` means "removed".
///
/// Deliberately carries no "number of things removed": a count is only
/// available from some mechanisms (and only by reading localized tool prose),
/// so it cannot be a success criterion. The criterion is the post-condition
/// probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReleaseOutcome {
    /// The removal reported success and the post-condition (enforcement no
    /// longer present) was confirmed.
    Reverted,
    /// The removal did not report success, but the post-condition holds
    /// anyway: nothing this receipt names is in place. Egress is not severed
    /// by us.
    AlreadyAbsent,
    /// The enforcement pre-existed this engagement, so this engagement did not
    /// create it and must not remove it. **Nothing was deleted and egress may
    /// well still be severed** by whoever did create it.
    SkippedPreexisting,
    /// The enforcer only reports success/failure and cannot say which of the
    /// above occurred. Never treat this as evidence that anything was removed.
    Unreported,
}

impl ReleaseOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ReleaseOutcome::Reverted => "reverted",
            ReleaseOutcome::AlreadyAbsent => "already_absent",
            ReleaseOutcome::SkippedPreexisting => "skipped_preexisting",
            ReleaseOutcome::Unreported => "unreported",
        }
    }

    /// Whether this outcome is evidence that *this* engagement's enforcement is
    /// gone. False for [`ReleaseOutcome::SkippedPreexisting`] (nothing was
    /// removed) and for [`ReleaseOutcome::Unreported`] (nothing was proven).
    #[must_use]
    pub fn enforcement_confirmed_gone(self) -> bool {
        matches!(
            self,
            ReleaseOutcome::Reverted | ReleaseOutcome::AlreadyAbsent
        )
    }
}

/// The pluggable enforcement seam. The privileged, system-wide teardown binds
/// this at the integration layer.
pub trait BoundaryEnforcer {
    /// Sever egress for the scope, returning a receipt for later rollback.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] on failure, or
    /// [`BoundaryError::EnforcementUnverified`] when the action was applied but
    /// its post-condition could not be confirmed — that variant still carries a
    /// releasable receipt and must not be discarded.
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError>;
    /// Revert the enforcement described by the receipt (rollback).
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] on failure.
    fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError>;

    /// Revert, given both the receipt **and** the scope it claims to belong to,
    /// and report what actually happened.
    ///
    /// Supplying the scope is what lets an enforcer re-derive what it is
    /// allowed to touch instead of trusting a name carried inside the receipt,
    /// which is the difference between "a forged receipt names one of our own
    /// rules" and "a forged receipt names any rule at all".
    ///
    /// The default implementation delegates to [`BoundaryEnforcer::release`]
    /// and reports [`ReleaseOutcome::Unreported`], because an enforcer that
    /// only returns `()` has told us nothing more than that.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] on failure.
    fn release_scoped(
        &self,
        scope: &BoundaryScope,
        receipt: &EnforcementReceipt,
    ) -> Result<ReleaseOutcome, BoundaryError> {
        let _ = scope;
        self.release(receipt).map(|()| ReleaseOutcome::Unreported)
    }
}

/// Which authorizations may control the switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundaryPolicy {
    pub control_use: String,
    pub override_use: String,
}

impl Default for BoundaryPolicy {
    fn default() -> Self {
        BoundaryPolicy {
            control_use: BOUNDARY_CONTROL_USE.to_owned(),
            override_use: BOUNDARY_OVERRIDE_USE.to_owned(),
        }
    }
}

/// One audited boundary transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryEvent {
    pub kind: String,
    pub from_state: String,
    pub to_state: String,
    pub actor: String,
    pub reason: Option<String>,
}

/// A hash-chained audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryAuditEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub event: BoundaryEvent,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct AuditForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    event: &'a BoundaryEvent,
}

fn audit_hash(seq: u64, prev_hash: &Digest, event: &BoundaryEvent) -> Digest {
    digest_of(
        &AuditForm {
            seq,
            prev_hash,
            event,
        },
        HashAlg::Blake3,
    )
    .expect("audit entry is serializable")
}

/// The session-local kill-switch.
#[derive(Clone, Debug)]
pub struct KillSwitch {
    session: SessionId,
    scope: BoundaryScope,
    policy: BoundaryPolicy,
    state: KillSwitchState,
    receipt: Option<EnforcementReceipt>,
    ledger: Vec<BoundaryAuditEntry>,
}

impl KillSwitch {
    /// Arm a switch for a session and scope.
    #[must_use]
    pub fn arm(session: SessionId, scope: BoundaryScope, policy: BoundaryPolicy) -> Self {
        KillSwitch {
            session,
            scope,
            policy,
            state: KillSwitchState::Armed,
            receipt: None,
            ledger: Vec::new(),
        }
    }

    /// Reconstruct a switch from persisted parts after a crash/restart, so a
    /// privileged broker can restore the authoritative state and still
    /// [`release`](Self::release) using the receipt captured on the original
    /// engage. This is the durable-recovery counterpart to [`arm`](Self::arm).
    ///
    /// The reconstruction is **validated** — it is not a blind assignment:
    /// * the audit `ledger` must be a well-formed hash chain (same check as
    ///   [`verify_audit`](Self::verify_audit)), and
    /// * receipt/state coherence must hold — an `Engaged` switch must carry a
    ///   held receipt (needed to release), and an `Armed`/`Released` switch must
    ///   carry none.
    ///
    /// # Errors
    /// [`BoundaryError::CorruptJournal`] if the chain is broken or the
    /// receipt/state pairing is incoherent.
    pub fn rehydrate(
        session: SessionId,
        scope: BoundaryScope,
        policy: BoundaryPolicy,
        state: KillSwitchState,
        receipt: Option<EnforcementReceipt>,
        ledger: Vec<BoundaryAuditEntry>,
    ) -> Result<Self, BoundaryError> {
        // 1. The persisted audit chain must be intact.
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return Err(BoundaryError::CorruptJournal(format!(
                    "broken link at seq {}",
                    entry.seq
                )));
            }
            if entry.entry_hash != audit_hash(entry.seq, &entry.prev_hash, &entry.event) {
                return Err(BoundaryError::CorruptJournal(format!(
                    "entry hash mismatch at seq {}",
                    entry.seq
                )));
            }
            expected_prev = entry.entry_hash;
        }
        // 2. Receipt/state coherence — an Engaged switch must be able to release.
        match (state, &receipt) {
            (KillSwitchState::Engaged, None) => {
                return Err(BoundaryError::CorruptJournal(
                    "engaged state without a held receipt".to_owned(),
                ));
            }
            (KillSwitchState::Armed | KillSwitchState::Released, Some(_)) => {
                return Err(BoundaryError::CorruptJournal(format!(
                    "{} state must not hold a receipt",
                    state.as_str()
                )));
            }
            _ => {}
        }
        Ok(KillSwitch {
            session,
            scope,
            policy,
            state,
            receipt,
            ledger,
        })
    }

    #[must_use]
    pub fn state(&self) -> KillSwitchState {
        self.state
    }

    /// The held rollback receipt, if the switch is currently engaged. A broker
    /// persists this so it can rehydrate and release after a restart.
    #[must_use]
    pub fn receipt(&self) -> Option<&EnforcementReceipt> {
        self.receipt.as_ref()
    }

    #[must_use]
    pub fn session(&self) -> &SessionId {
        &self.session
    }

    #[must_use]
    pub fn audit_entries(&self) -> &[BoundaryAuditEntry] {
        &self.ledger
    }

    fn record(
        &mut self,
        kind: &str,
        from: KillSwitchState,
        to: KillSwitchState,
        actor: &str,
        reason: Option<String>,
    ) {
        let event = BoundaryEvent {
            kind: kind.to_owned(),
            from_state: from.as_str().to_owned(),
            to_state: to.as_str().to_owned(),
            actor: actor.to_owned(),
            reason: reason.clone(),
        };
        let seq = self.ledger.len() as u64;
        let prev_hash = self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = audit_hash(seq, &prev_hash, &event);
        self.ledger.push(BoundaryAuditEntry {
            seq,
            prev_hash,
            event,
            entry_hash,
        });

        // A kill-switch transition is a security-critical event by definition
        // (it severs or restores egress) — always logged at warn, regardless
        // of direction, so it is never lost in routine info-level noise.
        tracing::warn!(
            target: "ssk.killswitch",
            event = "kill_switch_transition",
            kind,
            from = from.as_str(),
            to = to.as_str(),
            actor,
            reason = ?reason,
            session = %self.session.0 .0,
            entry_hash = %entry_hash.to_hex(),
        );
    }

    /// Adopt an engagement whose enforcement was applied but **not** confirmed.
    ///
    /// The switch takes ownership of the receipt and moves to `Engaged` — so
    /// the enforcement stays releasable and the transition is audited — and the
    /// caller still gets the error back. Losing the receipt here would leave an
    /// applied enforcement that nothing can roll back, which is a strictly
    /// worse failure than an unverified engagement.
    fn adopt_unverified(
        &mut self,
        kind: &str,
        actor: &str,
        receipt: Box<EnforcementReceipt>,
        detail: String,
        reason: Option<String>,
    ) -> BoundaryError {
        let from = self.state;
        self.state = KillSwitchState::Engaged;
        self.receipt = Some((*receipt).clone());
        let note = match reason {
            Some(r) => format!("{r}; unverified: {detail}"),
            None => format!("unverified: {detail}"),
        };
        self.record(kind, from, self.state, actor, Some(note));
        BoundaryError::EnforcementUnverified { receipt, detail }
    }

    /// Engage the switch: sever egress. Requires a control authorization.
    ///
    /// # Errors
    /// [`BoundaryError::Unauthorized`], [`BoundaryError::InvalidTransition`] if
    /// already engaged, [`BoundaryError::Enforcement`], or
    /// [`BoundaryError::EnforcementUnverified`] — in which case the switch is
    /// nevertheless left `Engaged` holding the receipt (see
    /// [`KillSwitch::adopt_unverified`]).
    pub fn engage(
        &mut self,
        authorization: &AuthorizationManifest,
        enforcer: &dyn BoundaryEnforcer,
    ) -> Result<(), BoundaryError> {
        if !authorization.is_valid_for(&self.policy.control_use) {
            return Err(BoundaryError::Unauthorized);
        }
        if self.state == KillSwitchState::Engaged {
            return Err(BoundaryError::InvalidTransition(
                "already engaged".to_owned(),
            ));
        }
        let receipt = match enforcer.engage(&self.scope) {
            Ok(receipt) => receipt,
            Err(BoundaryError::EnforcementUnverified { receipt, detail }) => {
                return Err(self.adopt_unverified(
                    "engage",
                    &authorization.source_name,
                    receipt,
                    detail,
                    None,
                ));
            }
            Err(other) => return Err(other),
        };
        let from = self.state;
        self.state = KillSwitchState::Engaged;
        self.receipt = Some(receipt);
        self.record("engage", from, self.state, &authorization.source_name, None);
        Ok(())
    }

    /// Release the switch: revert the enforcement (rollback). Requires a control
    /// authorization.
    ///
    /// # Errors
    /// [`BoundaryError::Unauthorized`], [`BoundaryError::NotEngaged`], or
    /// [`BoundaryError::Enforcement`].
    pub fn release(
        &mut self,
        authorization: &AuthorizationManifest,
        enforcer: &dyn BoundaryEnforcer,
    ) -> Result<(), BoundaryError> {
        self.release_reporting(authorization, enforcer).map(|_| ())
    }

    /// Release, returning what the enforcer actually did.
    ///
    /// Identical to [`KillSwitch::release`] except that the [`ReleaseOutcome`]
    /// is handed back rather than discarded, so a caller can report the truth
    /// (e.g. distinguish "the rule was deleted" from "the rule pre-existed and
    /// was deliberately left in place" — a distinction `Ok(())` erases).
    ///
    /// # Errors
    /// Same as [`KillSwitch::release`].
    pub fn release_reporting(
        &mut self,
        authorization: &AuthorizationManifest,
        enforcer: &dyn BoundaryEnforcer,
    ) -> Result<ReleaseOutcome, BoundaryError> {
        if !authorization.is_valid_for(&self.policy.control_use) {
            return Err(BoundaryError::Unauthorized);
        }
        if self.state != KillSwitchState::Engaged {
            return Err(BoundaryError::NotEngaged);
        }
        let receipt = self.receipt.take().ok_or(BoundaryError::NotEngaged)?;
        // Hand the enforcer the scope as well as the receipt: an enforcer that
        // can re-derive what it owns from the scope need not trust anything the
        // receipt claims. Implementations that cannot use it ignore it.
        let outcome = match enforcer.release_scoped(&self.scope, &receipt) {
            Ok(outcome) => outcome,
            Err(e) => {
                // The enforcement is still in place (or its state is unknown);
                // keep the receipt so a retry is possible.
                self.receipt = Some(receipt);
                return Err(e);
            }
        };
        let from = self.state;
        self.state = KillSwitchState::Released;
        // The audited reason records what the enforcer actually did, so the
        // ledger never says "released" where the truth was "left in place".
        self.record(
            "release",
            from,
            self.state,
            &authorization.source_name,
            Some(format!("outcome={}", outcome.as_str())),
        );
        Ok(outcome)
    }

    /// Force engagement via the authorized override path (e.g., to engage from an
    /// unexpected state). Requires an override authorization and is audited.
    ///
    /// If the switch is already `Engaged`, this does **not** re-engage via the
    /// enforcer or overwrite the held receipt: doing so would capture the
    /// already-severed boundary as the receipt's `prior_state`, destroying the
    /// only record of the true pre-engagement state and making a later
    /// [`KillSwitch::release`] restore to the wrong place. Re-engaging is a
    /// no-op that only appends an audit entry documenting the override request.
    ///
    /// # Errors
    /// [`BoundaryError::Unauthorized`] or [`BoundaryError::Enforcement`].
    pub fn override_engage(
        &mut self,
        authorization: &AuthorizationManifest,
        reason: impl Into<String>,
        enforcer: &dyn BoundaryEnforcer,
    ) -> Result<(), BoundaryError> {
        if !authorization.is_valid_for(&self.policy.override_use) {
            return Err(BoundaryError::Unauthorized);
        }
        let from = self.state;
        let reason = reason.into();
        if self.state == KillSwitchState::Engaged {
            self.record(
                "override_engage",
                from,
                self.state,
                &authorization.source_name,
                Some(format!("{reason} (already engaged; receipt preserved)")),
            );
            return Ok(());
        }
        let receipt = match enforcer.engage(&self.scope) {
            Ok(receipt) => receipt,
            Err(BoundaryError::EnforcementUnverified { receipt, detail }) => {
                return Err(self.adopt_unverified(
                    "override_engage",
                    &authorization.source_name,
                    receipt,
                    detail,
                    Some(reason),
                ));
            }
            Err(other) => return Err(other),
        };
        self.state = KillSwitchState::Engaged;
        self.receipt = Some(receipt);
        self.record(
            "override_engage",
            from,
            self.state,
            &authorization.source_name,
            Some(reason),
        );
        Ok(())
    }

    /// Verify the audit chain: each entry recomputes and links to the prior.
    #[must_use]
    pub fn verify_audit(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash != audit_hash(entry.seq, &entry.prev_hash, &entry.event) {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A fake enforcer that tracks whether egress is currently severed.
    struct FakeEnforcer {
        severed: Cell<bool>,
    }
    impl FakeEnforcer {
        fn new() -> Self {
            FakeEnforcer {
                severed: Cell::new(false),
            }
        }
    }
    impl BoundaryEnforcer for FakeEnforcer {
        fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
            let prior = if self.severed.get() {
                "severed"
            } else {
                "flowing"
            };
            let receipt = EnforcementReceipt::new(scope, prior);
            self.severed.set(true);
            Ok(receipt)
        }
        fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
            self.severed.set(false);
            Ok(())
        }
    }

    fn control_auth() -> AuthorizationManifest {
        AuthorizationManifest::new("operator", "me", "session control")
            .with_allowed_uses([BOUNDARY_CONTROL_USE])
    }

    fn override_auth() -> AuthorizationManifest {
        AuthorizationManifest::new("operator", "me", "override control")
            .with_allowed_uses([BOUNDARY_CONTROL_USE, BOUNDARY_OVERRIDE_USE])
    }

    fn switch() -> KillSwitch {
        KillSwitch::arm(
            SessionId::new("sess-1"),
            BoundaryScope::all_egress(),
            BoundaryPolicy::default(),
        )
    }

    // ---- receipt integrity (unkeyed digest: corruption, not forgery) -------

    #[test]
    fn a_pristine_receipt_verifies_against_its_scope() {
        let scope = BoundaryScope::all_egress();
        let receipt = EnforcementReceipt::new(&scope, "v2;mech=netsh;own=created;rule=X");
        assert_eq!(receipt.verify_against(&scope), Ok(()));
    }

    #[test]
    fn a_tampered_prior_state_is_rejected() {
        let scope = BoundaryScope::all_egress();
        let mut receipt = EnforcementReceipt::new(&scope, "v2;mech=netsh;own=created;rule=ours");
        // Edit the payload without rehashing — the classic naive tamper.
        receipt.prior_state = "v2;mech=netsh;own=created;rule=all".to_owned();
        assert!(matches!(
            receipt.verify_against(&scope),
            Err(ReceiptIntegrityError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn a_receipt_for_another_scope_is_rejected() {
        let scope = BoundaryScope::all_egress();
        let other = BoundaryScope::new("other", ["*"]);
        let receipt = EnforcementReceipt::new(&other, "flowing");
        assert!(matches!(
            receipt.verify_against(&scope),
            Err(ReceiptIntegrityError::ScopeLabelMismatch { .. })
        ));
    }

    #[test]
    fn a_truncated_or_zeroed_receipt_id_is_rejected() {
        let scope = BoundaryScope::all_egress();
        let mut receipt = EnforcementReceipt::new(&scope, "flowing");
        receipt.receipt_id = Digest::GENESIS;
        assert!(matches!(
            receipt.verify_against(&scope),
            Err(ReceiptIntegrityError::DigestMismatch { .. })
        ));
    }

    // The honest limitation, asserted rather than merely documented: the digest
    // is UNKEYED, so an attacker who can write a receipt can also write a
    // matching receipt_id. `verify_against` is a corruption check, not
    // authentication — this test exists so nobody later mistakes it for one.
    #[test]
    fn a_fully_recomputed_forgery_passes_verification_by_design() {
        let scope = BoundaryScope::all_egress();
        let forged = EnforcementReceipt::new(&scope, "flowing;rule=anything-at-all");
        assert_eq!(
            forged.verify_against(&scope),
            Ok(()),
            "an unkeyed digest cannot detect a forgery that rehashes; the \
             enforcer must validate prior_state's CONTENTS, not its hash"
        );
    }

    // ---- tri-state presence bridges to the EgressObserver contract ---------

    #[test]
    fn presence_maps_to_the_fail_closed_option_bool() {
        assert_eq!(Presence::Present.as_option_bool(), Some(true));
        assert_eq!(Presence::Absent.as_option_bool(), Some(false));
        assert_eq!(
            Presence::Indeterminate {
                detail: "exit 1".into()
            }
            .as_option_bool(),
            None,
            "an unanswerable probe must be None, never Some(false)"
        );
        assert!(!Presence::Indeterminate {
            detail: String::new()
        }
        .is_present());
    }

    #[test]
    fn release_outcome_only_claims_removal_when_it_happened() {
        assert!(ReleaseOutcome::Reverted.enforcement_confirmed_gone());
        assert!(ReleaseOutcome::AlreadyAbsent.enforcement_confirmed_gone());
        assert!(
            !ReleaseOutcome::SkippedPreexisting.enforcement_confirmed_gone(),
            "a skipped release removed nothing; egress may still be severed"
        );
        assert!(
            !ReleaseOutcome::Unreported.enforcement_confirmed_gone(),
            "an enforcer that only returned Ok(()) proved nothing"
        );
    }

    // An enforcer written against the old two-method trait keeps working and is
    // honest about how little it said.
    #[test]
    fn release_scoped_defaults_to_delegating_and_reports_unreported() {
        let enforcer = FakeEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let receipt = enforcer.engage(&scope).unwrap();
        assert_eq!(
            enforcer.release_scoped(&scope, &receipt),
            Ok(ReleaseOutcome::Unreported)
        );
        assert!(!enforcer.severed.get());
    }

    // ---- an unverified engagement is never Ok, but is never lost either ----

    struct UnverifiedEnforcer;
    impl BoundaryEnforcer for UnverifiedEnforcer {
        fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
            Err(BoundaryError::EnforcementUnverified {
                receipt: Box::new(EnforcementReceipt::new(scope, "flowing;rule=ours")),
                detail: "post-condition probe was indeterminate".to_owned(),
            })
        }
        fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
            Ok(())
        }
    }

    #[test]
    fn an_unverified_engage_still_leaves_a_releasable_receipt() {
        let mut ks = switch();
        let err = ks.engage(&control_auth(), &UnverifiedEnforcer).unwrap_err();
        assert!(matches!(err, BoundaryError::EnforcementUnverified { .. }));
        assert_eq!(
            ks.state(),
            KillSwitchState::Engaged,
            "the enforcement was applied; the switch must not pretend otherwise"
        );
        assert!(
            ks.receipt().is_some(),
            "dropping the receipt would strand an enforcement nobody can roll back"
        );
        let entry = ks.audit_entries().last().expect("the attempt is audited");
        assert_eq!(entry.event.kind, "engage");
        assert!(entry
            .event
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("unverified")));
        assert!(ks.verify_audit());

        // And it really is releasable.
        ks.release(&control_auth(), &FakeEnforcer::new()).unwrap();
        assert_eq!(ks.state(), KillSwitchState::Released);
    }

    #[test]
    fn an_unverified_override_engage_is_also_retained_and_audited() {
        let mut ks = switch();
        let err = ks
            .override_engage(&override_auth(), "incident-9", &UnverifiedEnforcer)
            .unwrap_err();
        assert!(matches!(err, BoundaryError::EnforcementUnverified { .. }));
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(ks.receipt().is_some());
        let entry = ks.audit_entries().last().unwrap();
        assert_eq!(entry.event.kind, "override_engage");
        assert!(entry
            .event
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("incident-9") && r.contains("unverified")));
    }

    // A failed release must not consume the receipt: without it the switch is
    // Engaged with nothing to roll back, which `rehydrate` itself calls corrupt.
    #[test]
    fn a_failed_release_keeps_the_receipt_for_a_retry() {
        struct FailingRelease;
        impl BoundaryEnforcer for FailingRelease {
            fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
                Ok(EnforcementReceipt::new(scope, "flowing;rule=ours"))
            }
            fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
                Err(BoundaryError::Enforcement("netsh unreachable".to_owned()))
            }
        }
        let mut ks = switch();
        ks.engage(&control_auth(), &FailingRelease).unwrap();
        let err = ks.release(&control_auth(), &FailingRelease).unwrap_err();
        assert!(matches!(err, BoundaryError::Enforcement(_)));
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(
            ks.receipt().is_some(),
            "a failed release must leave the switch releasable"
        );
    }

    #[test]
    fn engage_severs_and_is_audited() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        assert_eq!(ks.state(), KillSwitchState::Armed);
        ks.engage(&control_auth(), &enforcer).unwrap();
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(enforcer.severed.get(), "engaging must sever egress");
        assert_eq!(ks.audit_entries().len(), 1);
        assert_eq!(ks.audit_entries()[0].event.kind, "engage");
        assert!(ks.verify_audit());
    }

    // A broker can persist an engaged switch's parts and rehydrate it after a
    // restart, then release using the recovered receipt.
    #[test]
    fn rehydrate_restores_an_engaged_switch_and_can_release() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        ks.engage(&control_auth(), &enforcer).unwrap();

        // Snapshot the parts a durable broker would persist.
        let state = ks.state();
        let receipt = ks.receipt().cloned();
        let ledger = ks.audit_entries().to_vec();
        assert_eq!(state, KillSwitchState::Engaged);
        assert!(receipt.is_some());

        // Rehydrate a fresh switch from the persisted parts.
        let mut restored = KillSwitch::rehydrate(
            SessionId::new("sess-1"),
            BoundaryScope::all_egress(),
            BoundaryPolicy::default(),
            state,
            receipt,
            ledger,
        )
        .expect("valid parts rehydrate");
        assert_eq!(restored.state(), KillSwitchState::Engaged);
        assert!(restored.verify_audit());

        // The recovered switch can release using its recovered receipt.
        let enforcer2 = FakeEnforcer::new();
        restored.release(&control_auth(), &enforcer2).unwrap();
        assert_eq!(restored.state(), KillSwitchState::Released);
    }

    // Rehydration is validated: a broken chain or an incoherent receipt/state
    // pairing is rejected rather than silently trusted.
    #[test]
    fn rehydrate_rejects_corrupt_or_incoherent_parts() {
        let mut ks = switch();
        ks.engage(&control_auth(), &FakeEnforcer::new()).unwrap();
        let good_ledger = ks.audit_entries().to_vec();

        // Engaged state but no held receipt → cannot ever release → rejected.
        let err = KillSwitch::rehydrate(
            SessionId::new("s"),
            BoundaryScope::all_egress(),
            BoundaryPolicy::default(),
            KillSwitchState::Engaged,
            None,
            good_ledger.clone(),
        )
        .unwrap_err();
        assert!(matches!(err, BoundaryError::CorruptJournal(_)));

        // Released state but holding a receipt → incoherent → rejected.
        let err = KillSwitch::rehydrate(
            SessionId::new("s"),
            BoundaryScope::all_egress(),
            BoundaryPolicy::default(),
            KillSwitchState::Released,
            ks.receipt().cloned(),
            good_ledger.clone(),
        )
        .unwrap_err();
        assert!(matches!(err, BoundaryError::CorruptJournal(_)));

        // A tampered audit chain → rejected.
        let mut bad_ledger = good_ledger;
        bad_ledger[0].event.actor = "someone-else".to_owned();
        let err = KillSwitch::rehydrate(
            SessionId::new("s"),
            BoundaryScope::all_egress(),
            BoundaryPolicy::default(),
            KillSwitchState::Engaged,
            ks.receipt().cloned(),
            bad_ledger,
        )
        .unwrap_err();
        assert!(matches!(err, BoundaryError::CorruptJournal(_)));
    }

    #[test]
    fn engage_requires_authorization() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        let no_control =
            AuthorizationManifest::new("x", "me", "none").with_allowed_uses(["offline_analysis"]);
        assert_eq!(
            ks.engage(&no_control, &enforcer).unwrap_err(),
            BoundaryError::Unauthorized
        );
        assert_eq!(
            ks.state(),
            KillSwitchState::Armed,
            "an unauthorized engage must not change state"
        );
        assert!(!enforcer.severed.get());
        assert!(ks.audit_entries().is_empty());
    }

    #[test]
    fn release_reverts_enforcement_rollback() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        ks.engage(&control_auth(), &enforcer).unwrap();
        assert!(enforcer.severed.get());
        ks.release(&control_auth(), &enforcer).unwrap();
        assert_eq!(ks.state(), KillSwitchState::Released);
        assert!(
            !enforcer.severed.get(),
            "release must revert the enforcement"
        );
        assert_eq!(ks.audit_entries().len(), 2);
        assert_eq!(ks.audit_entries()[1].event.kind, "release");
        // Releasing when not engaged fails.
        assert_eq!(
            ks.release(&control_auth(), &enforcer).unwrap_err(),
            BoundaryError::NotEngaged
        );
    }

    #[test]
    fn override_is_authorized_and_audited() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        // Control-only auth cannot override.
        assert_eq!(
            ks.override_engage(&control_auth(), "incident", &enforcer)
                .unwrap_err(),
            BoundaryError::Unauthorized
        );
        // Override auth can, and it is audited with the reason.
        ks.override_engage(&override_auth(), "incident-42", &enforcer)
            .unwrap();
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert!(enforcer.severed.get());
        let last = ks.audit_entries().last().unwrap();
        assert_eq!(last.event.kind, "override_engage");
        assert_eq!(last.event.reason.as_deref(), Some("incident-42"));
    }

    /// An enforcer that actually honors `EnforcementReceipt::prior_state` on
    /// release, unlike `FakeEnforcer` (which always sets `severed = false`
    /// regardless of the receipt). This is the enforcer needed to detect a
    /// wrong or lost receipt — a faithful enforcer restores to whatever the
    /// receipt says, not to a hardcoded "flowing".
    struct FaithfulEnforcer {
        state: Cell<&'static str>,
    }
    impl FaithfulEnforcer {
        fn new() -> Self {
            FaithfulEnforcer {
                state: Cell::new("flowing"),
            }
        }
    }
    impl BoundaryEnforcer for FaithfulEnforcer {
        fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
            let receipt = EnforcementReceipt::new(scope, self.state.get());
            self.state.set("severed");
            Ok(receipt)
        }
        fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
            self.state.set(match receipt.prior_state.as_str() {
                "flowing" => "flowing",
                _ => "severed",
            });
            Ok(())
        }
    }

    // Regression: overriding an already-Engaged switch must not clobber the
    // receipt captured by the original engage(). Before the fix, override_engage
    // re-called enforcer.engage() unconditionally, capturing the already-severed
    // boundary as the new receipt's prior_state; a later release() then restored
    // to "severed" instead of the true pre-engagement "flowing".
    #[test]
    fn override_while_engaged_preserves_the_original_receipt() {
        let mut ks = switch();
        let enforcer = FaithfulEnforcer::new();

        ks.engage(&control_auth(), &enforcer).unwrap();
        assert_eq!(enforcer.state.get(), "severed");

        // Overriding while already Engaged must not touch the receipt.
        ks.override_engage(&override_auth(), "re-assert", &enforcer)
            .unwrap();
        assert_eq!(ks.state(), KillSwitchState::Engaged);
        assert_eq!(
            enforcer.state.get(),
            "severed",
            "override_engage while already engaged must not re-invoke the enforcer"
        );

        ks.release(&control_auth(), &enforcer).unwrap();
        assert_eq!(
            enforcer.state.get(),
            "flowing",
            "release must restore the TRUE pre-engagement state, not the \
             intermediate state an overwritten receipt would have captured"
        );
        assert!(ks.verify_audit());
        // The override was still audited, just without mutating the receipt.
        assert!(ks
            .audit_entries()
            .iter()
            .any(|e| e.event.kind == "override_engage"
                && e.event.reason.as_deref()
                    == Some("re-assert (already engaged; receipt preserved)")));
    }

    #[test]
    fn audit_is_append_only() {
        let mut ks = switch();
        let enforcer = FakeEnforcer::new();
        ks.engage(&control_auth(), &enforcer).unwrap();
        ks.release(&control_auth(), &enforcer).unwrap();
        ks.override_engage(&override_auth(), "again", &enforcer)
            .unwrap();
        assert!(ks.verify_audit());
        // Tampering a past event without rebuilding the tail breaks the chain.
        let mut tampered = ks.clone();
        tampered.ledger[0].event.actor = "someone-else".to_owned();
        assert!(!tampered.verify_audit());
    }

    // --- Ledger tamper-depth (property-based) -------------------------------

    mod ledger_tamper_properties {
        use super::*;
        use proptest::prelude::*;

        // 0 = engage, 1 = release, 2 = override_engage.
        fn ops_strategy() -> impl Strategy<Value = Vec<u8>> {
            proptest::collection::vec(0u8..3, 1..12)
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(300))]

            // Whatever sequence of engage/release/override_engage produced the
            // ledger, mutating any single field of any single entry -- not
            // just the most recent one -- must always be caught by
            // `verify_audit`, proving tamper-detection has no blind depth into
            // the chain's history (mirrors the same property proven for
            // ssk-crown's emission ledger).
            #[test]
            fn mid_chain_tamper_is_always_caught(
                ops in ops_strategy(),
                tamper_index in 0usize..12,
                tamper_field in 0u8..4,
            ) {
                let mut ks = switch();
                let enforcer = FakeEnforcer::new();
                for op in ops {
                    match op {
                        0 => {
                            let _ = ks.engage(&control_auth(), &enforcer);
                        }
                        1 => {
                            let _ = ks.release(&control_auth(), &enforcer);
                        }
                        _ => {
                            let _ = ks.override_engage(&override_auth(), "prop", &enforcer);
                        }
                    }
                }
                prop_assume!(!ks.audit_entries().is_empty());
                prop_assert!(ks.verify_audit());

                let index = tamper_index % ks.audit_entries().len();
                let mut tampered = ks.clone();
                match tamper_field % 4 {
                    0 => tampered.ledger[index].seq = tampered.ledger[index].seq.wrapping_add(1),
                    1 => tampered.ledger[index].prev_hash = Digest::GENESIS,
                    2 => {
                        tampered.ledger[index].event.actor =
                            format!("{}-tampered", tampered.ledger[index].event.actor);
                    }
                    _ => tampered.ledger[index].entry_hash = Digest::GENESIS,
                }
                // A mutation that happens to reproduce the exact original
                // bytes (e.g. prev_hash was already GENESIS) is not a real
                // tamper.
                if tampered.ledger[index] == ks.ledger[index] {
                    return Ok(());
                }
                prop_assert!(
                    !tampered.verify_audit(),
                    "tampering entry {index} field-group {tamper_field} went undetected"
                );
            }
        }
    }
}
