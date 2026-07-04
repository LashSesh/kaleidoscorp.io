#![forbid(unsafe_code)]

//! Audit & Forensics — immutable, hash-chained decision and traffic metadata
//! for incident investigation.
//!
//! `AuditLedger` is generic over its storage backend (defaulting to an
//! in-memory `ssk_tensor::GenericMemoryBackend`); use [`AuditLedger::persisted`]
//! to get a disk-backed ledger whose entries survive a process restart. The
//! hash-chain itself (hex-string `prev_hash`/`entry_hash` over a hand-built
//! JSON body) is unchanged from the original in-memory-only implementation —
//! only *where the entries live* is now pluggable.

use serde::{Deserialize, Serialize};

use crate::error::NetAdminError;
use crate::route::RouteKind;
use ssk_tensor::{GenericFileLedgerBackend, GenericLedgerBackend, GenericMemoryBackend};

/// Outcome of a dispatched (or denied) flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// The flow was allowed and dispatched.
    Dispatched,
    /// The flow was denied by policy.
    Denied,
    /// The flow was denied by the fail-closed rule (no matching policy).
    FailClosed,
    /// The flow was denied because attestation verification failed.
    AttestationFailed,
    /// The flow was allowed in shadow/audit mode (not enforced).
    ShadowAllowed,
    /// Reserved: an adapter's circuit breaker opened mid-flow. Not yet
    /// produced by any code path until the `ssk-netcore` data-plane runtime
    /// ships (Phase 3).
    AdapterUnreachable,
    /// Reserved: the kill switch was armed and blocked egress. Not yet
    /// produced until `ssk-netcore`/`ssk-daemon` ship (Phase 3/4).
    KillSwitchBlocked,
    /// Reserved: a `RouteKind::Fallback` route executed its fallback branch.
    /// Not yet produced until `ssk-netcore` ships (Phase 3).
    FallbackDispatched,
}

/// A single immutable forensic audit entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForensicEntry {
    /// Unique entry identifier.
    pub entry_id: String,
    /// The flow this entry records.
    pub flow_id: String,
    /// The session decision identifier (if one was recorded).
    pub decision_id: Option<String>,
    /// Description of the adapter used (or `None` when denied).
    pub adapter_id: Option<String>,
    /// Computed route kind at time of dispatch.
    pub route_kind_summary: String,
    /// Final outcome.
    pub outcome: AuditOutcome,
    /// Deterministic clock epoch at the time of the event.
    pub epoch: u64,
    /// Hash of the previous forensic entry (`"genesis"` for the first).
    pub prev_hash: String,
    /// Blake3 hash of this entry (covers all fields except `entry_hash`).
    pub entry_hash: String,
}

fn summarise_route(route: &RouteKind) -> String {
    match route {
        RouteKind::Direct => "Direct".into(),
        RouteKind::SingleHop(h) => format!("SingleHop({})", h.adapter_id),
        RouteKind::MultiHop(hops) => {
            let ids: Vec<_> = hops.iter().map(|h| h.adapter_id.as_str()).collect();
            format!("MultiHop({})", ids.join("->"))
        }
        RouteKind::Fallback { primary, fallback } => {
            format!(
                "Fallback({} | {})",
                summarise_route(primary),
                summarise_route(fallback)
            )
        }
        RouteKind::Denied { reason } => format!("Denied({reason})"),
    }
}

fn hash_forensic_body(e: &ForensicEntry) -> Result<String, NetAdminError> {
    let body = serde_json::json!({
        "entry_id": e.entry_id,
        "flow_id": e.flow_id,
        "decision_id": e.decision_id,
        "adapter_id": e.adapter_id,
        "route_kind_summary": e.route_kind_summary,
        "outcome": e.outcome,
        "epoch": e.epoch,
        "prev_hash": e.prev_hash,
    });
    let bytes =
        serde_json::to_vec(&body).map_err(|err| NetAdminError::Serialization(err.to_string()))?;
    Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
}

/// Append-only, hash-chained forensic audit ledger, generic over its storage
/// backend. Defaults to an ephemeral in-memory backend; use
/// [`AuditLedger::persisted`] for a disk-backed ledger.
#[derive(Debug)]
pub struct AuditLedger<B = GenericMemoryBackend<ForensicEntry>>
where
    B: GenericLedgerBackend<ForensicEntry>,
{
    backend: B,
}

impl Default for AuditLedger<GenericMemoryBackend<ForensicEntry>> {
    fn default() -> Self {
        Self {
            backend: GenericMemoryBackend::new(),
        }
    }
}

impl AuditLedger<GenericMemoryBackend<ForensicEntry>> {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuditLedger<GenericFileLedgerBackend<ForensicEntry>> {
    /// A disk-persisted audit ledger: every `record()` call is durably
    /// written, so `verify()` succeeds across a process restart at the same
    /// `path`.
    #[must_use]
    pub fn persisted(path: impl AsRef<std::path::Path>) -> Self {
        Self {
            backend: GenericFileLedgerBackend::new(path),
        }
    }
}

impl<B: GenericLedgerBackend<ForensicEntry>> AuditLedger<B> {
    /// Append a new forensic entry for a flow event.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        entry_id: impl Into<String>,
        flow_id: impl Into<String>,
        decision_id: Option<String>,
        adapter_id: Option<String>,
        route: &RouteKind,
        outcome: AuditOutcome,
        epoch: u64,
    ) -> Result<ForensicEntry, NetAdminError> {
        let prev_hash = self
            .backend
            .entries()?
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| "genesis".to_string());

        let mut entry = ForensicEntry {
            entry_id: entry_id.into(),
            flow_id: flow_id.into(),
            decision_id,
            adapter_id,
            route_kind_summary: summarise_route(route),
            outcome,
            epoch,
            prev_hash,
            entry_hash: String::new(),
        };
        entry.entry_hash = hash_forensic_body(&entry)?;
        self.backend.append(entry.clone())?;
        Ok(entry)
    }

    /// Verify the integrity of the entire hash chain.
    pub fn verify(&self) -> Result<(), NetAdminError> {
        let mut prev = "genesis".to_string();
        for e in self.backend.entries()? {
            let expected = hash_forensic_body(&e)?;
            if expected != e.entry_hash {
                return Err(NetAdminError::AuditChainBroken(e.entry_id.clone()));
            }
            if e.prev_hash != prev {
                return Err(NetAdminError::AuditChainBroken(e.entry_id.clone()));
            }
            prev = e.entry_hash.clone();
        }
        Ok(())
    }

    pub fn entries(&self) -> Result<Vec<ForensicEntry>, NetAdminError> {
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

    #[test]
    fn record_and_verify() {
        let mut ledger = AuditLedger::new();
        ledger
            .record(
                "e-0",
                "f-0",
                Some("sd-0".into()),
                Some("socks5-exit".into()),
                &RouteKind::Direct,
                AuditOutcome::Dispatched,
                42,
            )
            .expect("record must succeed");
        ledger
            .record(
                "e-1",
                "f-1",
                None,
                None,
                &RouteKind::Denied {
                    reason: "policy-deny".into(),
                },
                AuditOutcome::Denied,
                43,
            )
            .expect("record must succeed");
        ledger.verify().expect("chain must be valid");
        assert_eq!(ledger.len().expect("len"), 2);
    }

    #[test]
    fn tampered_entry_detected() {
        let mut ledger = AuditLedger::new();
        ledger
            .record(
                "e-0",
                "f-0",
                None,
                None,
                &RouteKind::Direct,
                AuditOutcome::Dispatched,
                1,
            )
            .expect("record");
        let mut entries = ledger.entries().expect("entries");
        entries[0].entry_hash = "tampered".into();
        ledger.backend.replace_all(entries);
        assert!(ledger.verify().is_err());
    }

    #[test]
    fn route_summary_multi_hop() {
        use crate::route::HopSpec;
        let route = RouteKind::MultiHop(vec![
            HopSpec::new("hop1", "a.example.com", 1080),
            HopSpec::new("hop2", "b.example.com", 8080),
        ]);
        let summary = summarise_route(&route);
        assert!(summary.contains("hop1"));
        assert!(summary.contains("hop2"));
    }

    #[test]
    fn persisted_chain_survives_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.json");

        {
            let mut ledger = AuditLedger::persisted(&path);
            ledger
                .record(
                    "e-0",
                    "f-0",
                    None,
                    None,
                    &RouteKind::Direct,
                    AuditOutcome::Dispatched,
                    1,
                )
                .expect("record");
            ledger
                .record(
                    "e-1",
                    "f-1",
                    None,
                    None,
                    &RouteKind::Denied {
                        reason: "policy-deny".into(),
                    },
                    AuditOutcome::Denied,
                    2,
                )
                .expect("record");
            ledger.verify().expect("chain valid before reopen");
        }

        let reopened = AuditLedger::persisted(&path);
        reopened.verify().expect("chain valid after reopen");
        assert_eq!(reopened.len().expect("len"), 2);
        assert_eq!(reopened.entries().expect("entries")[1].entry_id, "e-1");
    }
}
