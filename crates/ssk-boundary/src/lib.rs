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

impl EnforcementReceipt {
    #[must_use]
    pub fn new(scope: &BoundaryScope, prior_state: impl Into<String>) -> Self {
        let prior_state = prior_state.into();
        #[derive(Serialize)]
        struct Form<'a> {
            scope: &'a BoundaryScope,
            prior_state: &'a str,
        }
        let receipt_id = digest_of(
            &Form {
                scope,
                prior_state: &prior_state,
            },
            HashAlg::Blake3,
        )
        .expect("receipt form is serializable");
        EnforcementReceipt {
            receipt_id,
            scope_label: scope.label.clone(),
            prior_state,
        }
    }
}

/// The pluggable enforcement seam. The privileged, system-wide teardown binds
/// this at the integration layer.
pub trait BoundaryEnforcer {
    /// Sever egress for the scope, returning a receipt for later rollback.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] on failure.
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError>;
    /// Revert the enforcement described by the receipt (rollback).
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] on failure.
    fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError>;
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

    #[must_use]
    pub fn state(&self) -> KillSwitchState {
        self.state
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

    /// Engage the switch: sever egress. Requires a control authorization.
    ///
    /// # Errors
    /// [`BoundaryError::Unauthorized`], [`BoundaryError::InvalidTransition`] if
    /// already engaged, or [`BoundaryError::Enforcement`].
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
        let receipt = enforcer.engage(&self.scope)?;
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
        if !authorization.is_valid_for(&self.policy.control_use) {
            return Err(BoundaryError::Unauthorized);
        }
        if self.state != KillSwitchState::Engaged {
            return Err(BoundaryError::NotEngaged);
        }
        let receipt = self.receipt.take().ok_or(BoundaryError::NotEngaged)?;
        enforcer.release(&receipt)?;
        let from = self.state;
        self.state = KillSwitchState::Released;
        self.record(
            "release",
            from,
            self.state,
            &authorization.source_name,
            None,
        );
        Ok(())
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
        let receipt = enforcer.engage(&self.scope)?;
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
}
