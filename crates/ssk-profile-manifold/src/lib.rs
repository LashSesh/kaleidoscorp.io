#![forbid(unsafe_code)]

//! # ssk-profile-manifold — the SSCL ProfileManifold (SSCL-3)
//!
//! Versioned privacy/routing **posture profiles** with **gated, audited
//! transitions**. A [`Profile`] is content-addressed from its name, version,
//! privacy rank, and settings. The [`ProfileManifold`] holds a set of registered
//! profiles and exactly one active profile; changing the active profile is a
//! [`ProfileManifold::transition`], which is:
//!
//! * **Gated.** A transition requires a `profile_control` authorization. A
//!   transition that *weakens privacy* (a lower privacy rank) additionally
//!   requires an elevated `profile_downgrade` authorization — you cannot quietly
//!   downgrade the system's privacy posture.
//! * **Audited.** Every transition, applied or rejected, is appended to a
//!   hash-chained ledger (tamper-evident), and the whole history replays.
//! * **Reversible.** Rolling back to a prior version is itself a gated,
//!   audited transition.
//!
//! ## Status — deferred with a plan; zero consumers is the design
//!
//! Nothing depends on this crate, and nothing is meant to yet. It is the SSCL-3
//! ProfileManifold, scheduled as phase **P6** (Band C) with the gates
//! "Kill-Switch, Rollback, Emission Gate, config/profile", marked
//! `[SSCL-UNVERIFIED]` and requiring explicit authorization
//! (`FCHL_MPK_INTEGRATION_STRATEGY.md:218`; object row `:112`). It is **Block P**
//! of the integration sequence — "thread validated config into a real
//! multi-profile model driving the daemon (retire the hardcoded reference
//! policy)" (`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:268`, described at `:29`).
//! Its consumer is that daemon wiring, which does not exist yet. Do not retire
//! this crate as unreferenced. (`FCHL_MPK_INTEGRATION_STRATEGY.md:112` and
//! `SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:252` still call ProfileManifold
//! "absent"; those rows predate this crate and are stale.)

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ssk_signature::AuthorizationManifest;
use ssk_types::{content_id, digest_of, Digest, HashAlg};

content_id!(ProfileId);

/// Authorization use required for any profile transition.
pub const PROFILE_CONTROL_USE: &str = "profile_control";
/// Additional authorization use required to weaken the privacy posture.
pub const PROFILE_DOWNGRADE_USE: &str = "profile_downgrade";

/// Errors the manifold can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifoldError {
    #[error("no such profile")]
    NotFound,
    #[error("no active profile")]
    NoActive,
    #[error("a profile with that name and version is already registered")]
    AlreadyRegistered,
}

/// A versioned privacy/routing posture.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: ProfileId,
    pub name: String,
    pub version: String,
    /// Higher rank = stronger privacy. A transition to a lower rank is a
    /// downgrade and needs elevated authorization.
    pub privacy_rank: u8,
    pub settings: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct ProfileForm<'a> {
    domain: &'a str,
    name: &'a str,
    version: &'a str,
    privacy_rank: u8,
    settings: &'a BTreeMap<String, String>,
}

impl Profile {
    /// Build a content-addressed profile.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        privacy_rank: u8,
        settings: BTreeMap<String, String>,
    ) -> Self {
        let name = name.into();
        let version = version.into();
        let id = ProfileId::of(
            &ProfileForm {
                domain: "sscl/profile/v1",
                name: &name,
                version: &version,
                privacy_rank,
                settings: &settings,
            },
            HashAlg::Blake3,
        )
        .expect("profile form is serializable");
        Profile {
            id,
            name,
            version,
            privacy_rank,
            settings,
        }
    }
}

/// Whether a transition was applied or rejected (with a reason).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionOutcome {
    Applied,
    Rejected(String),
}

impl TransitionOutcome {
    #[must_use]
    pub fn is_applied(&self) -> bool {
        matches!(self, TransitionOutcome::Applied)
    }
}

/// One hash-chained transition-audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionAuditEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub from: Option<ProfileId>,
    pub to: ProfileId,
    pub actor: String,
    pub reason: String,
    pub outcome: TransitionOutcome,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct AuditForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    from: &'a Option<ProfileId>,
    to: &'a ProfileId,
    actor: &'a str,
    reason: &'a str,
    outcome: &'a TransitionOutcome,
}

fn audit_hash(
    seq: u64,
    prev_hash: &Digest,
    from: &Option<ProfileId>,
    to: &ProfileId,
    actor: &str,
    reason: &str,
    outcome: &TransitionOutcome,
) -> Digest {
    digest_of(
        &AuditForm {
            seq,
            prev_hash,
            from,
            to,
            actor,
            reason,
            outcome,
        },
        HashAlg::Blake3,
    )
    .expect("audit form is serializable")
}

/// A versioned manifold of profiles with gated, audited transitions.
#[derive(Clone, Debug, Default)]
pub struct ProfileManifold {
    profiles: BTreeMap<Digest, Profile>,
    active: Option<ProfileId>,
    ledger: Vec<TransitionAuditEntry>,
}

impl ProfileManifold {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a profile.
    ///
    /// # Errors
    /// [`ManifoldError::AlreadyRegistered`] if the same name+version exists.
    pub fn register(&mut self, profile: Profile) -> Result<ProfileId, ManifoldError> {
        if self
            .profiles
            .values()
            .any(|p| p.name == profile.name && p.version == profile.version)
        {
            return Err(ManifoldError::AlreadyRegistered);
        }
        let id = profile.id;
        self.profiles.insert(id.0, profile);
        Ok(id)
    }

    #[must_use]
    pub fn get(&self, id: ProfileId) -> Option<&Profile> {
        self.profiles.get(&id.0)
    }

    #[must_use]
    pub fn active(&self) -> Option<&Profile> {
        self.active.and_then(|id| self.profiles.get(&id.0))
    }

    /// Transition the active profile to `to`, gated and audited. The first
    /// transition (no active profile) sets the initial profile.
    ///
    /// # Errors
    /// [`ManifoldError::NotFound`] if the target is not registered.
    pub fn transition(
        &mut self,
        to: ProfileId,
        authorization: &AuthorizationManifest,
        reason: impl Into<String>,
    ) -> Result<TransitionOutcome, ManifoldError> {
        let target = self
            .profiles
            .get(&to.0)
            .ok_or(ManifoldError::NotFound)?
            .clone();
        let reason = reason.into();
        let from = self.active;

        // Gate: control authorization is always required; a privacy downgrade
        // requires the elevated downgrade authorization.
        let outcome = if !authorization.is_valid_for(PROFILE_CONTROL_USE) {
            TransitionOutcome::Rejected("missing_profile_control_authorization".to_owned())
        } else {
            let is_downgrade = from
                .and_then(|id| self.profiles.get(&id.0))
                .is_some_and(|current| target.privacy_rank < current.privacy_rank);
            if is_downgrade && !authorization.is_valid_for(PROFILE_DOWNGRADE_USE) {
                TransitionOutcome::Rejected(
                    "privacy_downgrade_requires_elevated_authorization".to_owned(),
                )
            } else {
                TransitionOutcome::Applied
            }
        };

        if outcome.is_applied() {
            self.active = Some(to);
        }
        self.record(
            from,
            to,
            &authorization.source_name,
            &reason,
            outcome.clone(),
        );
        Ok(outcome)
    }

    fn record(
        &mut self,
        from: Option<ProfileId>,
        to: ProfileId,
        actor: &str,
        reason: &str,
        outcome: TransitionOutcome,
    ) {
        let seq = self.ledger.len() as u64;
        let prev_hash = self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = audit_hash(seq, &prev_hash, &from, &to, actor, reason, &outcome);
        self.ledger.push(TransitionAuditEntry {
            seq,
            prev_hash,
            from,
            to,
            actor: actor.to_owned(),
            reason: reason.to_owned(),
            outcome,
            entry_hash,
        });
    }

    #[must_use]
    pub fn history(&self) -> &[TransitionAuditEntry] {
        &self.ledger
    }

    /// Verify the transition-audit chain.
    #[must_use]
    pub fn verify_ledger(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            let recomputed = audit_hash(
                entry.seq,
                &entry.prev_hash,
                &entry.from,
                &entry.to,
                &entry.actor,
                &entry.reason,
                &entry.outcome,
            );
            if entry.entry_hash != recomputed {
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

    fn profile(name: &str, version: &str, rank: u8) -> Profile {
        let mut settings = BTreeMap::new();
        settings.insert("dns_protected".to_owned(), "true".to_owned());
        Profile::new(name, version, rank, settings)
    }

    fn control_auth() -> AuthorizationManifest {
        AuthorizationManifest::new("operator", "me", "profile control")
            .with_allowed_uses([PROFILE_CONTROL_USE])
    }

    fn downgrade_auth() -> AuthorizationManifest {
        AuthorizationManifest::new("operator", "me", "downgrade")
            .with_allowed_uses([PROFILE_CONTROL_USE, PROFILE_DOWNGRADE_USE])
    }

    #[test]
    fn register_is_content_addressed_and_deduped() {
        let mut m = ProfileManifold::new();
        let a = m.register(profile("strict", "1.0.0", 9)).unwrap();
        // Same content -> same id.
        assert_eq!(
            Profile::new("strict", "1.0.0", 9, {
                let mut s = BTreeMap::new();
                s.insert("dns_protected".to_owned(), "true".to_owned());
                s
            })
            .id,
            a
        );
        // Same name+version rejected.
        assert_eq!(
            m.register(profile("strict", "1.0.0", 9)).unwrap_err(),
            ManifoldError::AlreadyRegistered
        );
    }

    #[test]
    fn gated_transition_applies_and_audits() {
        let mut m = ProfileManifold::new();
        let strict = m.register(profile("strict", "1.0.0", 9)).unwrap();
        let outcome = m.transition(strict, &control_auth(), "initial").unwrap();
        assert_eq!(outcome, TransitionOutcome::Applied);
        assert_eq!(m.active().unwrap().name, "strict");
        assert_eq!(m.history().len(), 1);
        assert!(m.verify_ledger());
    }

    #[test]
    fn unauthorized_transition_is_rejected_and_audited() {
        let mut m = ProfileManifold::new();
        let strict = m.register(profile("strict", "1.0.0", 9)).unwrap();
        let no_control =
            AuthorizationManifest::new("x", "me", "none").with_allowed_uses(["offline_analysis"]);
        let outcome = m.transition(strict, &no_control, "attempt").unwrap();
        assert!(matches!(outcome, TransitionOutcome::Rejected(_)));
        assert!(
            m.active().is_none(),
            "a rejected transition does not change the active profile"
        );
        // The rejection is still audited.
        assert_eq!(m.history().len(), 1);
        assert!(!m.history()[0].outcome.is_applied());
    }

    #[test]
    fn privacy_downgrade_requires_elevated_authorization() {
        let mut m = ProfileManifold::new();
        let strict = m.register(profile("strict", "1.0.0", 9)).unwrap();
        let relaxed = m.register(profile("relaxed", "1.0.0", 3)).unwrap();
        m.transition(strict, &control_auth(), "start").unwrap();

        // Downgrade with only control authorization -> rejected.
        let rejected = m.transition(relaxed, &control_auth(), "loosen").unwrap();
        assert_eq!(
            rejected,
            TransitionOutcome::Rejected(
                "privacy_downgrade_requires_elevated_authorization".to_owned()
            )
        );
        assert_eq!(
            m.active().unwrap().name,
            "strict",
            "the downgrade did not take effect"
        );

        // Downgrade with elevated authorization -> applied.
        let applied = m
            .transition(relaxed, &downgrade_auth(), "loosen, authorized")
            .unwrap();
        assert_eq!(applied, TransitionOutcome::Applied);
        assert_eq!(m.active().unwrap().name, "relaxed");

        // Rolling back UP to strict needs only control authorization (an upgrade).
        assert_eq!(
            m.transition(strict, &control_auth(), "rollback").unwrap(),
            TransitionOutcome::Applied
        );
        assert_eq!(m.active().unwrap().name, "strict");
        assert!(m.verify_ledger());
    }

    #[test]
    fn history_is_tamper_evident() {
        let mut m = ProfileManifold::new();
        let strict = m.register(profile("strict", "1.0.0", 9)).unwrap();
        m.transition(strict, &control_auth(), "one").unwrap();
        m.transition(strict, &control_auth(), "two").unwrap();
        assert!(m.verify_ledger());
        m.ledger[0].reason = "forged".to_owned();
        assert!(!m.verify_ledger());
    }

    #[test]
    fn unknown_target_errors() {
        let mut m = ProfileManifold::new();
        let bogus = ProfileId(ssk_types::digest_of(&"nope", HashAlg::Blake3).unwrap());
        assert_eq!(
            m.transition(bogus, &control_auth(), "x").unwrap_err(),
            ManifoldError::NotFound
        );
    }
}
