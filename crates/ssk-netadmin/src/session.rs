#![forbid(unsafe_code)]

//! Session Integrity — deterministic, hash-chained session decision records.
//!
//! Each `SessionDecision` is chained via its `prev_hash`/`decision_hash`
//! fields using the same Blake3 hash-chain pattern as `ssk-tensor`.
//!
//! `SessionLedger` is generic over its storage backend (defaulting to an
//! in-memory `ssk_tensor::GenericMemoryBackend`); use
//! [`SessionLedger::persisted`] for a disk-backed ledger whose decisions
//! survive a process restart.

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationBinding;
use crate::error::NetAdminError;
use crate::policy::PolicyDecision;
use crate::route::RouteCandidate;
use ssk_tensor::{GenericFileLedgerBackend, GenericLedgerBackend, GenericMemoryBackend};

/// A single, hash-chained session decision record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDecision {
    /// Unique decision identifier (e.g. `"sd-001"`).
    pub decision_id: String,
    /// The flow this decision was made for.
    pub flow_id: String,
    /// The policy decision.
    pub policy_decision: PolicyDecision,
    /// The computed route candidate.
    pub route_candidate: RouteCandidate,
    /// Attestation binding, if attestation was performed.
    pub attestation: Option<AttestationBinding>,
    /// Hash of the previous decision in the chain (`"genesis"` for the first).
    pub prev_hash: String,
    /// Blake3 hash of this record (covers all fields except `decision_hash`).
    pub decision_hash: String,
}

fn hash_session_decision_body(d: &SessionDecision) -> Result<String, NetAdminError> {
    // Serialize all fields except decision_hash itself.
    let body = serde_json::json!({
        "decision_id": d.decision_id,
        "flow_id": d.flow_id,
        "policy_decision": d.policy_decision,
        "route_candidate": d.route_candidate,
        "attestation": d.attestation,
        "prev_hash": d.prev_hash,
    });
    let bytes =
        serde_json::to_vec(&body).map_err(|e| NetAdminError::Serialization(e.to_string()))?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

/// Append-only, hash-chained ledger of session decisions, generic over its
/// storage backend. Defaults to an ephemeral in-memory backend; use
/// [`SessionLedger::persisted`] for a disk-backed ledger.
#[derive(Debug)]
pub struct SessionLedger<B = GenericMemoryBackend<SessionDecision>>
where
    B: GenericLedgerBackend<SessionDecision>,
{
    backend: B,
}

impl Default for SessionLedger<GenericMemoryBackend<SessionDecision>> {
    fn default() -> Self {
        Self {
            backend: GenericMemoryBackend::new(),
        }
    }
}

impl SessionLedger<GenericMemoryBackend<SessionDecision>> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionLedger<GenericFileLedgerBackend<SessionDecision>> {
    /// A disk-persisted session ledger: every `record()` call is durably
    /// written, so `verify()` succeeds across a process restart at the same
    /// `path`.
    #[must_use]
    pub fn persisted(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            backend: GenericFileLedgerBackend::new(path),
        }
    }
}

impl<B: GenericLedgerBackend<SessionDecision>> SessionLedger<B> {
    /// Record a new decision, chaining it to the previous entry.
    pub fn record(
        &mut self,
        decision_id: impl Into<String>,
        flow_id: impl Into<String>,
        policy_decision: PolicyDecision,
        route_candidate: RouteCandidate,
        attestation: Option<AttestationBinding>,
    ) -> Result<SessionDecision, NetAdminError> {
        let prev_hash = self
            .backend
            .entries()?
            .last()
            .map(|d| d.decision_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        let mut entry = SessionDecision {
            decision_id: decision_id.into(),
            flow_id: flow_id.into(),
            policy_decision,
            route_candidate,
            attestation,
            prev_hash,
            decision_hash: String::new(),
        };
        entry.decision_hash = hash_session_decision_body(&entry)?;
        self.backend.append(entry.clone())?;
        Ok(entry)
    }

    /// Verify the hash chain of all decisions.
    pub fn verify(&self) -> Result<(), NetAdminError> {
        let mut prev = "genesis".to_string();
        for d in self.backend.entries()? {
            // Recompute expected hash.
            let expected = hash_session_decision_body(&d)?;
            if expected != d.decision_hash {
                return Err(NetAdminError::AuditChainBroken(d.decision_id.clone()));
            }
            if d.prev_hash != prev {
                return Err(NetAdminError::AuditChainBroken(d.decision_id.clone()));
            }
            prev = d.decision_hash.clone();
        }
        Ok(())
    }

    pub fn decisions(&self) -> Result<Vec<SessionDecision>, NetAdminError> {
        Ok(self.backend.entries()?)
    }

    pub fn len(&self) -> Result<usize, NetAdminError> {
        Ok(self.backend.entries()?.len())
    }

    pub fn is_empty(&self) -> Result<bool, NetAdminError> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyAction;
    use crate::route::RouteKind;

    fn sample_decision(_id: &str, flow_id: &str) -> (PolicyDecision, RouteCandidate) {
        (
            PolicyDecision {
                flow_id: flow_id.into(),
                matched_rule: Some("r1".into()),
                action: PolicyAction::Allow,
                rationale: "test".into(),
            },
            RouteCandidate {
                flow_id: flow_id.into(),
                route: RouteKind::Direct,
                requires_attestation: false,
            },
        )
    }

    #[test]
    fn record_and_verify_chain() {
        let mut ledger = SessionLedger::new();
        for i in 0..5u32 {
            let (pd, rc) = sample_decision(&format!("sd-{i}"), &format!("f-{i}"));
            ledger
                .record(format!("sd-{i}"), format!("f-{i}"), pd, rc, None)
                .expect("record must succeed");
        }
        ledger.verify().expect("chain must be intact");
        assert_eq!(ledger.len().expect("len"), 5);
    }

    #[test]
    fn tampered_hash_detected() {
        let mut ledger = SessionLedger::new();
        let (pd, rc) = sample_decision("sd-0", "f-0");
        ledger.record("sd-0", "f-0", pd, rc, None).expect("record");
        // Tamper with the decision hash.
        let mut decisions = ledger.decisions().expect("decisions");
        decisions[0].decision_hash = "tampered".into();
        ledger.backend.replace_all(decisions);
        assert!(ledger.verify().is_err());
    }

    #[test]
    fn persisted_chain_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("session.json");

        {
            let mut ledger = SessionLedger::persisted(&path);
            for i in 0..3u32 {
                let (pd, rc) = sample_decision(&format!("sd-{i}"), &format!("f-{i}"));
                ledger
                    .record(format!("sd-{i}"), format!("f-{i}"), pd, rc, None)
                    .expect("record must succeed");
            }
            ledger.verify().expect("chain valid before reopen");
        }

        let reopened = SessionLedger::persisted(&path);
        reopened.verify().expect("chain valid after reopen");
        assert_eq!(reopened.len().expect("len"), 3);
        assert_eq!(
            reopened.decisions().expect("decisions")[2].decision_id,
            "sd-2"
        );
    }
}
