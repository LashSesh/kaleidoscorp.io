#![forbid(unsafe_code)]

//! # ssk-crown — the SSCL System Surface Crown (CrownSupervisor)
//!
//! The top-level **emission gate**. Nothing leaves the system without the Crown
//! saying [`EmissionDecision::Emit`], and it says so only when *every* subsystem
//! agrees — it is **fail-closed**. The Crown clamps together the decisions the
//! rest of the stack produces:
//!
//! * the signature gate ([`ssk_signature`] → `GateOutcomeKind`),
//! * the Mirror-Dome QLOGIC verdict ([`ssk_imdf`] → `GateOutcomeKind`),
//! * the session kill-switch state ([`ssk_boundary`]),
//! * the MetaResonance response ([`ssk_meta_resonance`]) — which can only hold,
//!   never promote,
//! * and any open residue obligations.
//!
//! Every evaluation is appended to a hash-chained emission ledger, and the
//! decision is a pure function of its inputs (replay-stable).

use serde::{Deserialize, Serialize};
use ssk_audit_store::{AuditSink, AuditStoreError, StoredRecord};
use ssk_boundary::KillSwitchState;
use ssk_meta_resonance::{ResonanceAction, ResonanceResponse};
use ssk_types::{digest_of, Digest, GateOutcomeKind, HashAlg};
use std::sync::Arc;

/// Errors restoring a `CrownSupervisor` from a durable sink can return.
#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("audit store error: {0}")]
    Store(#[from] AuditStoreError),
    #[error("stored record could not be decoded: {0}")]
    Decode(String),
    #[error("restored emission ledger fails chain verification")]
    CorruptChain,
}

/// The Crown's verdict on whether output may leave the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmissionDecision {
    /// All subsystems pass; output may be emitted.
    Emit,
    /// Recoverable; hold and retry (drift, unresolved obligation, a subsystem hold).
    Hold,
    /// Hard stop; output is denied (a reject/quarantine or the kill-switch).
    Deny,
}

impl EmissionDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EmissionDecision::Emit => "emit",
            EmissionDecision::Hold => "hold",
            EmissionDecision::Deny => "deny",
        }
    }
}

/// The inputs the Crown clamps together.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmissionInputs {
    pub signature_gate: GateOutcomeKind,
    pub qlogic_gate: GateOutcomeKind,
    pub kill_switch: KillSwitchState,
    pub resonance: ResonanceResponse,
    pub open_obligations: usize,
}

/// The Crown's report for one evaluation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmissionReport {
    pub decision: EmissionDecision,
    pub reasons: Vec<String>,
}

/// One hash-chained emission-ledger entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmissionAuditEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub decision: String,
    pub reasons: Vec<String>,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct AuditForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    decision: &'a str,
    reasons: &'a [String],
}

fn audit_hash(seq: u64, prev_hash: &Digest, decision: &str, reasons: &[String]) -> Digest {
    digest_of(
        &AuditForm {
            seq,
            prev_hash,
            decision,
            reasons,
        },
        HashAlg::Blake3,
    )
    .expect("emission entry is serializable")
}

fn is_hard_stop(outcome: GateOutcomeKind) -> bool {
    matches!(
        outcome,
        GateOutcomeKind::Reject | GateOutcomeKind::Quarantine
    )
}

fn is_hold(outcome: GateOutcomeKind) -> bool {
    matches!(outcome, GateOutcomeKind::Hold | GateOutcomeKind::Refine)
}

/// The CrownSupervisor: the fail-closed emission gate with an audited ledger.
///
/// The ledger is always the in-memory `Vec` — that keeps the supervisor pure
/// and deterministic with no sink at all, the default. An optional
/// [`AuditSink`] ([`CrownSupervisor::with_sink`]) makes every successful
/// `evaluate()` call **also** durably persist its entry, so the emission
/// history survives a process restart or crash; [`CrownSupervisor::restore`]
/// reconstructs a supervisor from what a sink already holds, verifying the
/// recovered chain before trusting it. The sink is a side channel: a write
/// failure never blocks or alters the emission decision itself (see
/// [`CrownSupervisor::last_sink_error`]), because the decision must stay a
/// pure function of its inputs regardless of durability.
#[derive(Default)]
pub struct CrownSupervisor {
    ledger: Vec<EmissionAuditEntry>,
    sink: Option<Arc<dyn AuditSink>>,
    last_sink_error: Option<String>,
}

impl Clone for CrownSupervisor {
    fn clone(&self) -> Self {
        CrownSupervisor {
            ledger: self.ledger.clone(),
            sink: self.sink.clone(),
            last_sink_error: self.last_sink_error.clone(),
        }
    }
}

impl std::fmt::Debug for CrownSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrownSupervisor")
            .field("ledger", &self.ledger)
            .field("sink_attached", &self.sink.is_some())
            .field("last_sink_error", &self.last_sink_error)
            .finish()
    }
}

fn encode_entry(entry: &EmissionAuditEntry) -> Vec<u8> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(entry, &mut body).expect("emission entry is serializable");
    body
}

impl CrownSupervisor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh supervisor (empty ledger) that also durably persists every
    /// future `evaluate()` call through `sink`. Does not read any history the
    /// sink may already hold — use [`CrownSupervisor::restore`] for that.
    #[must_use]
    pub fn with_sink(sink: Arc<dyn AuditSink>) -> Self {
        CrownSupervisor {
            ledger: Vec::new(),
            sink: Some(sink),
            last_sink_error: None,
        }
    }

    /// Reconstruct a supervisor from a sink's durably-persisted history,
    /// verifying the recovered chain before trusting it. Future `evaluate()`
    /// calls continue to persist through the same sink.
    ///
    /// # Errors
    /// [`RestoreError::Store`] on an I/O failure, [`RestoreError::Decode`] if a
    /// record's body is not a valid `EmissionAuditEntry`, or
    /// [`RestoreError::CorruptChain`] if the recovered ledger fails
    /// [`CrownSupervisor::verify_ledger`].
    pub fn restore(sink: Arc<dyn AuditSink>) -> Result<Self, RestoreError> {
        let report = sink.load()?;
        let mut ledger = Vec::with_capacity(report.records.len());
        for record in &report.records {
            let entry: EmissionAuditEntry = ciborium::de::from_reader(record.body.as_slice())
                .map_err(|e| RestoreError::Decode(e.to_string()))?;
            ledger.push(entry);
        }
        let supervisor = CrownSupervisor {
            ledger,
            sink: Some(sink),
            last_sink_error: None,
        };
        if !supervisor.verify_ledger() {
            return Err(RestoreError::CorruptChain);
        }
        Ok(supervisor)
    }

    /// The most recent durability-sink failure, if the last `evaluate()` call
    /// with a sink attached could not persist its entry. `None` if there is no
    /// sink, or the most recent attempt succeeded. Never affects the emission
    /// decision itself — see the type-level doc.
    #[must_use]
    pub fn last_sink_error(&self) -> Option<&str> {
        self.last_sink_error.as_deref()
    }

    /// Aggregate the inputs into a fail-closed emission decision and audit it.
    /// The order of checks encodes the fail-closed priority: a kill-switch or a
    /// hard-stop subsystem denies; an open obligation or a holding subsystem or
    /// elevated resonance holds; only a fully-clean state emits.
    pub fn evaluate(&mut self, inputs: &EmissionInputs) -> EmissionReport {
        let mut reasons = Vec::new();

        let decision = if inputs.kill_switch == KillSwitchState::Engaged {
            reasons.push("kill_switch_engaged".to_owned());
            EmissionDecision::Deny
        } else if is_hard_stop(inputs.signature_gate) {
            reasons.push("signature_gate_hard_stop".to_owned());
            EmissionDecision::Deny
        } else if is_hard_stop(inputs.qlogic_gate) {
            reasons.push("qlogic_gate_hard_stop".to_owned());
            EmissionDecision::Deny
        } else if inputs.open_obligations > 0 {
            reasons.push(format!("open_obligations:{}", inputs.open_obligations));
            EmissionDecision::Hold
        } else if is_hold(inputs.signature_gate) {
            reasons.push("signature_gate_hold".to_owned());
            EmissionDecision::Hold
        } else if is_hold(inputs.qlogic_gate) {
            reasons.push("qlogic_gate_hold".to_owned());
            EmissionDecision::Hold
        } else if inputs.resonance.action != ResonanceAction::Stabilize {
            // MetaResonance can only hold a would-be emit, never bypass a gate.
            reasons.push(format!(
                "resonance_{}",
                resonance_label(inputs.resonance.action)
            ));
            EmissionDecision::Hold
        } else {
            reasons.push("all_clear".to_owned());
            EmissionDecision::Emit
        };

        let seq = self.ledger.len() as u64;
        let prev_hash = self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = audit_hash(seq, &prev_hash, decision.as_str(), &reasons);
        let entry = EmissionAuditEntry {
            seq,
            prev_hash,
            decision: decision.as_str().to_owned(),
            reasons: reasons.clone(),
            entry_hash,
        };

        if let Some(sink) = &self.sink {
            let record = StoredRecord {
                seq: entry.seq,
                prev_hash: entry.prev_hash,
                entry_hash: entry.entry_hash,
                body: encode_entry(&entry),
            };
            self.last_sink_error = sink.append(&record).err().map(|e| e.to_string());
        }
        self.ledger.push(entry);

        EmissionReport { decision, reasons }
    }

    #[must_use]
    pub fn ledger(&self) -> &[EmissionAuditEntry] {
        &self.ledger
    }

    /// The current emission-ledger head.
    #[must_use]
    pub fn head(&self) -> Digest {
        self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash)
    }

    /// Verify the emission ledger chain.
    #[must_use]
    pub fn verify_ledger(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash
                != audit_hash(entry.seq, &entry.prev_hash, &entry.decision, &entry.reasons)
            {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }
}

fn resonance_label(action: ResonanceAction) -> &'static str {
    match action {
        ResonanceAction::Stabilize => "stabilize",
        ResonanceAction::Delay => "delay",
        ResonanceAction::Hold => "hold",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_meta_resonance::MetaResonanceController;

    fn resonance(drift: f64) -> ResonanceResponse {
        MetaResonanceController::default().step(drift)
    }

    fn clean_inputs() -> EmissionInputs {
        EmissionInputs {
            signature_gate: GateOutcomeKind::Pass,
            qlogic_gate: GateOutcomeKind::Pass,
            kill_switch: KillSwitchState::Armed,
            resonance: resonance(0.0),
            open_obligations: 0,
        }
    }

    #[test]
    fn all_clear_emits() {
        let mut crown = CrownSupervisor::new();
        let report = crown.evaluate(&clean_inputs());
        assert_eq!(report.decision, EmissionDecision::Emit);
        assert!(crown.verify_ledger());
    }

    #[test]
    fn kill_switch_denies_everything() {
        let mut crown = CrownSupervisor::new();
        let mut inputs = clean_inputs();
        inputs.kill_switch = KillSwitchState::Engaged;
        let report = crown.evaluate(&inputs);
        assert_eq!(report.decision, EmissionDecision::Deny);
        assert!(report.reasons.iter().any(|r| r == "kill_switch_engaged"));
    }

    #[test]
    fn fail_closed_priority() {
        let mut crown = CrownSupervisor::new();
        // A hard stop from any gate denies, even with everything else clean.
        let mut deny = clean_inputs();
        deny.qlogic_gate = GateOutcomeKind::Reject;
        assert_eq!(crown.evaluate(&deny).decision, EmissionDecision::Deny);
        // An open obligation holds.
        let mut hold = clean_inputs();
        hold.open_obligations = 1;
        assert_eq!(crown.evaluate(&hold).decision, EmissionDecision::Hold);
        // A subsystem hold holds.
        let mut sig_hold = clean_inputs();
        sig_hold.signature_gate = GateOutcomeKind::Hold;
        assert_eq!(crown.evaluate(&sig_hold).decision, EmissionDecision::Hold);
        // Elevated resonance holds a would-be emit (never bypasses).
        let mut drifting = clean_inputs();
        drifting.resonance = resonance(0.3);
        assert_eq!(crown.evaluate(&drifting).decision, EmissionDecision::Hold);
    }

    #[test]
    fn evaluation_is_replay_stable_and_audited() {
        let a = {
            let mut c = CrownSupervisor::new();
            c.evaluate(&clean_inputs());
            let mut k = clean_inputs();
            k.kill_switch = KillSwitchState::Engaged;
            c.evaluate(&k);
            c
        };
        let b = {
            let mut c = CrownSupervisor::new();
            c.evaluate(&clean_inputs());
            let mut k = clean_inputs();
            k.kill_switch = KillSwitchState::Engaged;
            c.evaluate(&k);
            c
        };
        // Same input sequence -> same ledger head (replay).
        assert_eq!(a.head(), b.head());
        assert!(a.verify_ledger());
        // Tampering a past decision breaks the chain.
        let mut tampered = a.clone();
        tampered.ledger[0].decision = "emit_forced".to_owned();
        assert!(!tampered.verify_ledger());
    }

    // End-to-end: drive the real subsystems into the Crown.
    #[test]
    fn clamps_the_real_stack() {
        use ssk_imdf::{QLogicGate, QLogicInput};
        use ssk_signature::{
            signature_for, GateBundle, OrderedMap, ResidueReport, SurfaceObject, TargetProfile,
            Value,
        };

        // A signature gate outcome from ssk-signature.
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text("GET".to_owned())),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        let sig = signature_for(
            &SurfaceObject::new("application/trace+json", fields)
                .with_declared_protocol_class("http"),
        );
        let target = TargetProfile::new("t", sig.clone());
        let signature_gate = GateBundle
            .evaluate(&sig, &sig, &target, &ResidueReport::new(), None)
            .decision
            .to_ssk();

        // A QLOGIC verdict from ssk-imdf.
        let qlogic_gate = QLogicGate::default()
            .evaluate(&QLogicInput {
                coherence: 1.0,
                entropy: 0.1,
                entropy_bound: 0.5,
                parallax_consistent: true,
                replay_equal: true,
                open_obligations: 0,
                drift: 0.0,
                drift_bound: 0.35,
            })
            .to_ssk();

        let mut crown = CrownSupervisor::new();
        let report = crown.evaluate(&EmissionInputs {
            signature_gate,
            qlogic_gate,
            kill_switch: KillSwitchState::Armed,
            resonance: resonance(0.0),
            open_obligations: 0,
        });
        assert_eq!(
            report.decision,
            EmissionDecision::Emit,
            "a clean real stack emits"
        );

        // Now engage the kill-switch: the same clean gates are denied.
        let denied = crown.evaluate(&EmissionInputs {
            signature_gate,
            qlogic_gate,
            kill_switch: KillSwitchState::Engaged,
            resonance: resonance(0.0),
            open_obligations: 0,
        });
        assert_eq!(denied.decision, EmissionDecision::Deny);
    }

    // Enterprise durability: a sink-attached supervisor's emission history
    // survives a process restart -- restore() over the same durable file
    // reconstructs an identical, verified ledger.
    #[test]
    fn emission_ledger_survives_restart_via_a_durable_sink() {
        use ssk_audit_store::FileAuditStore;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crown.bin");

        let head_before = {
            let sink = Arc::new(FileAuditStore::new(&path));
            let mut crown = CrownSupervisor::with_sink(sink);
            crown.evaluate(&clean_inputs());
            let mut engaged = clean_inputs();
            engaged.kill_switch = KillSwitchState::Engaged;
            crown.evaluate(&engaged);
            assert!(crown.last_sink_error().is_none());
            crown.head()
            // `crown` (and its Arc<FileAuditStore>) drops here -- simulating
            // process exit.
        };

        let sink = Arc::new(FileAuditStore::new(&path));
        let restored = CrownSupervisor::restore(sink).expect("restore");
        assert_eq!(restored.ledger().len(), 2);
        assert_eq!(
            restored.head(),
            head_before,
            "restored head matches the pre-restart head"
        );
        assert!(restored.verify_ledger());

        // Restored history matches a fresh, non-durable run over the same
        // input sequence -- the sink changes nothing about the decisions.
        let mut fresh = CrownSupervisor::new();
        fresh.evaluate(&clean_inputs());
        let mut engaged = clean_inputs();
        engaged.kill_switch = KillSwitchState::Engaged;
        fresh.evaluate(&engaged);
        assert_eq!(restored.head(), fresh.head());
    }

    // restore() must not trust a tampered durable log -- a corrupted chain is
    // rejected, not silently accepted.
    #[test]
    fn restore_rejects_a_tampered_durable_log() {
        use ssk_audit_store::{AuditSink, FileAuditStore};
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("crown.bin");

        {
            let sink = Arc::new(FileAuditStore::new(&path));
            let mut crown = CrownSupervisor::with_sink(sink);
            crown.evaluate(&clean_inputs());
        }

        // Tamper: append a bogus, non-chained record directly to the file.
        let raw = FileAuditStore::new(&path);
        raw.append(&ssk_audit_store::StoredRecord {
            seq: 1,
            prev_hash: Digest::GENESIS, // wrong: should chain from entry 0's hash
            entry_hash: Digest::GENESIS,
            body: encode_entry(&EmissionAuditEntry {
                seq: 1,
                prev_hash: Digest::GENESIS,
                decision: "emit".to_owned(),
                reasons: vec!["forged".to_owned()],
                entry_hash: Digest::GENESIS,
            }),
        })
        .unwrap();

        let sink = Arc::new(FileAuditStore::new(&path));
        assert!(matches!(
            CrownSupervisor::restore(sink),
            Err(RestoreError::CorruptChain)
        ));
    }

    // A sink failure (e.g. an unwritable path) never blocks or alters the
    // emission decision -- it is a side channel, not a gate input.
    #[test]
    fn sink_failure_does_not_block_the_emission_decision() {
        struct AlwaysFailsSink;
        impl AuditSink for AlwaysFailsSink {
            fn append(&self, _record: &StoredRecord) -> Result<(), AuditStoreError> {
                Err(AuditStoreError::Io(std::io::Error::other("disk full")))
            }
            fn load(&self) -> Result<ssk_audit_store::LoadReport, AuditStoreError> {
                Ok(ssk_audit_store::LoadReport::default())
            }
        }

        let mut crown = CrownSupervisor::with_sink(Arc::new(AlwaysFailsSink));
        let report = crown.evaluate(&clean_inputs());
        assert_eq!(
            report.decision,
            EmissionDecision::Emit,
            "a sink failure must not alter the emission decision"
        );
        assert!(crown.last_sink_error().is_some());
        // The in-memory ledger is still correct and verifiable even though
        // durability failed.
        assert_eq!(crown.ledger().len(), 1);
        assert!(crown.verify_ledger());
    }
}
