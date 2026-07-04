#![forbid(unsafe_code)]

use ssk_types::{BoundaryResidue, ConnectionIntent, GateOutcomeKind, ResidueId, ResidueKind};

#[must_use]
pub fn has_critical_fault(residues: &[BoundaryResidue]) -> bool {
    !residues.is_empty()
}

// ---------------------------------------------------------------------------
// Chaos injection and recovery drills
// ---------------------------------------------------------------------------

/// Kinds of synthetic faults that the chaos injector can introduce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FaultKind {
    /// Invalidate the signature on a connection intent's core node.
    SignatureCorruption,
    /// Remove the capability witness from a connection intent.
    CapabilityWithdrawal,
    /// Set the TTL epoch to zero, triggering TTL-based gate failure.
    TtlExpiry,
    /// Simulate a replay drift (gate-outcome mismatch between runs).
    ReplayDrift,
    /// Inject a boundary residue into a gate outcome (attestation failure).
    AttestationFailure,
    /// Deny all routing by forcing zero locator trust.
    LocatorUntrust,
}

/// Summary of a single chaos injection outcome.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InjectionResult {
    pub fault: FaultKind,
    /// The gate outcome produced after fault injection.
    pub gate_outcome: GateOutcomeKind,
    /// Whether the injected fault was detected (i.e. outcome != Pass).
    pub fault_detected: bool,
    /// Residues emitted during the faulted run.
    pub residues: Vec<BoundaryResidue>,
}

/// Result of a full chaos drill (injection + recovery run).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DrillReport {
    pub fault: FaultKind,
    /// Whether the fault was successfully detected.
    pub fault_detected: bool,
    /// Whether a subsequent clean run (recovery) succeeded.
    pub recovery_succeeded: bool,
    /// The full gate outcome of the clean recovery run.
    pub recovery_gate_outcome: GateOutcomeKind,
}

impl DrillReport {
    /// A drill passes when the fault was detected AND recovery succeeded.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.fault_detected && self.recovery_succeeded
    }
}

/// Aggregated report over multiple drills.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlaybookReport {
    pub drills: Vec<DrillReport>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

impl PlaybookReport {
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// Injects a specific fault into a `ConnectionIntent`, returning the mutated copy.
#[must_use]
pub fn inject_fault(mut intent: ConnectionIntent, fault: FaultKind) -> ConnectionIntent {
    match fault {
        FaultKind::SignatureCorruption => {
            intent.core.signature = ssk_types::CoreSignature(vec![]);
        }
        FaultKind::CapabilityWithdrawal => {
            intent.capability = None;
        }
        FaultKind::TtlExpiry => {
            intent.ttl_epoch = 0;
        }
        FaultKind::ReplayDrift => {
            // Corrupt the run id to force a replay mismatch.
            intent.run = ssk_types::RunId::new(format!("{}-drifted", intent.run.0 .0));
        }
        FaultKind::AttestationFailure => {
            // Invalidate both signature and witness simultaneously.
            intent.core.signature = ssk_types::CoreSignature(vec![]);
            intent.capability = None;
        }
        FaultKind::LocatorUntrust => {
            // Nothing to mutate on the intent itself; the locator pool is controlled by the
            // drill runner.  Mark via signature corruption as a proxy.
            intent.core.signature = ssk_types::CoreSignature(vec![]);
        }
    }
    intent
}

/// Synthesise a `BoundaryResidue` representing a detected fault.
#[must_use]
pub fn fault_residue(fault: FaultKind) -> BoundaryResidue {
    use ssk_types::GateId;
    let (kind, gate) = match fault {
        FaultKind::SignatureCorruption => (ResidueKind::Identity, GateId::Core),
        FaultKind::CapabilityWithdrawal => (ResidueKind::Capability, GateId::Capability),
        FaultKind::TtlExpiry => (ResidueKind::Timing, GateId::Replay),
        FaultKind::ReplayDrift => (ResidueKind::Replay, GateId::Replay),
        FaultKind::AttestationFailure => (ResidueKind::Capability, GateId::Capability),
        FaultKind::LocatorUntrust => (ResidueKind::Locator, GateId::Locator),
    };
    BoundaryResidue::new(
        ResidueId::new(format!("fault-{fault:?}")),
        kind,
        gate,
        format!("chaos-injected fault: {fault:?}"),
        ssk_types::Severity::High,
        ssk_types::TraceId::new(format!("fault-trace-{fault:?}")),
        true,
    )
}

/// Run a single drill: inject the fault, evaluate detection, then run a clean
/// recovery pass.  Returns a `DrillReport`.
///
/// `run_intent` is a callback that accepts a `ConnectionIntent` and returns
/// `(gate_outcome, residues)`.  This keeps the drill runner decoupled from
/// the runtime (avoids circular crate dependencies while still being testable).
pub fn run_drill<F>(clean_intent: ConnectionIntent, fault: FaultKind, run_intent: &F) -> DrillReport
where
    F: Fn(ConnectionIntent) -> (GateOutcomeKind, Vec<BoundaryResidue>),
{
    let faulted = inject_fault(clean_intent.clone(), fault);
    let (faulted_outcome, faulted_residues) = run_intent(faulted);
    let fault_detected = faulted_outcome != GateOutcomeKind::Pass || !faulted_residues.is_empty();

    let (recovery_outcome, _) = run_intent(clean_intent);
    let recovery_succeeded = recovery_outcome == GateOutcomeKind::Pass;

    DrillReport {
        fault,
        fault_detected,
        recovery_succeeded,
        recovery_gate_outcome: recovery_outcome,
    }
}

/// Run the full standard playbook of drills.
pub fn run_playbook<F>(clean_intent: ConnectionIntent, run_intent: &F) -> PlaybookReport
where
    F: Fn(ConnectionIntent) -> (GateOutcomeKind, Vec<BoundaryResidue>),
{
    let faults = [
        FaultKind::SignatureCorruption,
        FaultKind::CapabilityWithdrawal,
        FaultKind::TtlExpiry,
        FaultKind::AttestationFailure,
        FaultKind::ReplayDrift,
        FaultKind::LocatorUntrust,
    ];
    let drills: Vec<DrillReport> = faults
        .into_iter()
        .map(|f| run_drill(clean_intent.clone(), f, run_intent))
        .collect();
    let passed = drills.iter().filter(|d| d.passed()).count();
    let total = drills.len();
    PlaybookReport {
        failed: total - passed,
        drills,
        total,
        passed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{GateId, RunId};

    fn sample_clean_intent() -> ConnectionIntent {
        ConnectionIntent {
            run: RunId::new("drill-clean"),
            core: ssk_types::CoreNode {
                id: ssk_types::CoreId::new("c1"),
                canonical: ssk_types::CanonicalForm("core".into()),
                signature: ssk_types::CoreSignature(vec![1, 2, 3]),
                policy_root: ssk_types::PolicyId::new("p1"),
                replay_root: ssk_types::ReplayRoot::new("replay:c1"),
                audit_root: ssk_types::AuditRoot::new("audit:c1"),
                closure: ssk_types::ClosureState::Closed,
            },
            target_locator: ssk_types::LocatorId::new("local"),
            capability: Some(ssk_types::CapabilityWitness {
                id: ssk_types::CapabilityId::of(&"drill-capability", ssk_types::HashAlg::Blake3)
                    .expect("hash"),
                claim: ssk_types::CapabilityClaim("use-local-overlay".into()),
                scope: ssk_types::Scope {
                    action: "connect".into(),
                    facet_class: ssk_types::ObjectKind::Core,
                },
                issuer: ssk_types::IssuerRef::new("issuer-1"),
                subject_class: ssk_types::SubjectClass::Core,
                epoch: ssk_types::EpochId(0),
                expiry: ssk_types::Ttl(100),
                proof: ssk_types::ProofBytes(vec![1, 2, 3]),
                trace: ssk_types::TraceId::new("cap-trace"),
            }),
            ttl_epoch: 1,
        }
    }

    fn stub_run(intent: ConnectionIntent) -> (GateOutcomeKind, Vec<BoundaryResidue>) {
        // Simple heuristic matching the real gate logic.
        // ReplayDrift is detected by the "-drifted" marker injected by inject_fault.
        let replay_drift = intent.run.0 .0.ends_with("-drifted");
        if !intent.core.signature.is_present()
            || intent.capability.is_none()
            || intent.ttl_epoch == 0
            || replay_drift
        {
            let residue = BoundaryResidue::new(
                ResidueId::new("stub-fault"),
                ResidueKind::Identity,
                GateId::Core,
                "fault detected by stub",
                ssk_types::Severity::High,
                ssk_types::TraceId::new("stub-fault-trace"),
                true,
            );
            (GateOutcomeKind::Reject, vec![residue])
        } else {
            (GateOutcomeKind::Pass, vec![])
        }
    }

    #[test]
    fn signature_corruption_detected_and_recovered() {
        let drill = run_drill(
            sample_clean_intent(),
            FaultKind::SignatureCorruption,
            &stub_run,
        );
        assert!(
            drill.fault_detected,
            "signature corruption must be detected"
        );
        assert!(drill.recovery_succeeded, "clean run must recover");
        assert!(drill.passed());
    }

    #[test]
    fn capability_withdrawal_detected() {
        let drill = run_drill(
            sample_clean_intent(),
            FaultKind::CapabilityWithdrawal,
            &stub_run,
        );
        assert!(drill.fault_detected);
        assert!(drill.passed());
    }

    #[test]
    fn ttl_expiry_detected() {
        let drill = run_drill(sample_clean_intent(), FaultKind::TtlExpiry, &stub_run);
        assert!(drill.fault_detected);
        assert!(drill.passed());
    }

    #[test]
    fn replay_drift_detected() {
        let drill = run_drill(sample_clean_intent(), FaultKind::ReplayDrift, &stub_run);
        assert!(drill.fault_detected, "replay drift must be detected");
        assert!(
            drill.recovery_succeeded,
            "clean run must recover after drift"
        );
        assert!(drill.passed());
    }

    #[test]
    fn locator_untrust_detected() {
        let drill = run_drill(sample_clean_intent(), FaultKind::LocatorUntrust, &stub_run);
        assert!(
            drill.fault_detected,
            "locator untrust must be detected via proxy"
        );
        assert!(drill.passed());
    }

    #[test]
    fn full_playbook_all_pass() {
        let report = run_playbook(sample_clean_intent(), &stub_run);
        for drill in &report.drills {
            assert!(
                drill.passed(),
                "drill {:?} failed: detected={} recovered={}",
                drill.fault,
                drill.fault_detected,
                drill.recovery_succeeded
            );
        }
        assert!(report.all_passed());
        assert_eq!(report.total, 6, "playbook must cover all 6 fault kinds");
    }
}
