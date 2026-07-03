#![forbid(unsafe_code)]

//! Session Integrity — deterministic, hash-chained session decision records.
//!
//! Each `SessionDecision` is chained via its `prev_hash`/`decision_hash`
//! fields using the same Blake3 hash-chain pattern as `ssk-tensor`.

use serde::{Deserialize, Serialize};

use crate::attestation::AttestationBinding;
use crate::error::NetAdminError;
use crate::policy::PolicyDecision;
use crate::route::RouteCandidate;

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
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| NetAdminError::Serialization(e.to_string()))?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

/// Append-only, hash-chained ledger of session decisions.
#[derive(Debug, Default)]
pub struct SessionLedger {
    decisions: Vec<SessionDecision>,
}

impl SessionLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new decision, chaining it to the previous entry.
    pub fn record(
        &mut self,
        decision_id: impl Into<String>,
        flow_id: impl Into<String>,
        policy_decision: PolicyDecision,
        route_candidate: RouteCandidate,
        attestation: Option<AttestationBinding>,
    ) -> Result<&SessionDecision, NetAdminError> {
        let prev_hash = self
            .decisions
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
        self.decisions.push(entry);
        Ok(self.decisions.last().expect("just pushed"))
    }

    /// Verify the hash chain of all decisions.
    pub fn verify(&self) -> Result<(), NetAdminError> {
        let mut prev = "genesis".to_string();
        for d in &self.decisions {
            // Recompute expected hash.
            let expected = hash_session_decision_body(d)?;
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

    #[must_use]
    pub fn decisions(&self) -> &[SessionDecision] {
        &self.decisions
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.decisions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.decisions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyAction;
    use crate::route::RouteKind;

    fn sample_decision(id: &str, flow_id: &str) -> (PolicyDecision, RouteCandidate) {
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
            ledger.record(format!("sd-{i}"), format!("f-{i}"), pd, rc, None)
                .expect("record must succeed");
        }
        ledger.verify().expect("chain must be intact");
        assert_eq!(ledger.len(), 5);
    }

    #[test]
    fn tampered_hash_detected() {
        let mut ledger = SessionLedger::new();
        let (pd, rc) = sample_decision("sd-0", "f-0");
        ledger.record("sd-0", "f-0", pd, rc, None).expect("record");
        // Tamper with the decision hash.
        ledger.decisions[0].decision_hash = "tampered".into();
        assert!(ledger.verify().is_err());
    }
}
