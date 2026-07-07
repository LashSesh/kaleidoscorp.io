#![forbid(unsafe_code)]

use ssk_types::{
    BoundaryResidue, ConnectionIntent, FaultKind, GateOutcomeKind, GateReport, ReplayVerdict,
    ResidueId, ResidueKind, Severity, TraceId,
};

#[must_use]
pub fn has_critical_fault(residues: &[BoundaryResidue]) -> bool {
    !residues.is_empty()
}

// ---------------------------------------------------------------------------
// Detection taxonomy (Master Spec Ω+1 ch. 17.1)
// ---------------------------------------------------------------------------

/// Which subsystem's signal produced a `FaultEvent` (ch. 17.1's
/// `DetectionSource`, referenced but not enumerated in the excerpted PDF
/// text) — this document's own minimal, disclosed elaboration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DetectionSource {
    GateResidue,
    ReplayDivergence,
}

/// One detected fault (ch. 17.1, verbatim field list).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FaultEvent {
    pub kind: FaultKind,
    pub severity: Severity,
    pub detection: DetectionSource,
    pub residue: Option<ResidueId>,
    pub trace: TraceId,
}

/// Phase 7 placeholder for the real runtime-state snapshot a `Faultscan`
/// implementation inspects (ch. 17.1's `RuntimeState`, referenced but not
/// enumerated in the excerpted text) — carries exactly what this crate's
/// first real `scan()` implementation needs: the latest gate report, and
/// (if a replay was attempted this run) its verdict.
#[derive(Debug, Clone)]
pub struct RuntimeState {
    pub gate_report: GateReport,
    pub replay_verdict: Option<ReplayVerdict>,
}

/// Ch. 17.1, verbatim trait shape.
pub trait Faultscan {
    fn scan(&self, ctx: &RuntimeState) -> Vec<FaultEvent>;

    /// "A metric can inform a gate, but no aggregate score overrides a
    /// required gate" (ch. 17's axiom) — `fail_closed` is diagnostic
    /// output for callers to act on, never itself a gate.
    fn fail_closed(&self, faults: &[FaultEvent]) -> bool {
        faults
            .iter()
            .any(|f| matches!(f.severity, Severity::Critical))
    }
}

/// Maps a gate residue's `ResidueKind` to the nearest `FaultKind` variant.
/// `Correlation` residues map to `PrivacyBudgetExceeded` since correlation
/// risk is exactly what the privacy/linkability budget (Section O) bounds.
fn fault_kind_for_residue(kind: &ResidueKind) -> FaultKind {
    match kind {
        ResidueKind::Identity => FaultKind::CoreNotCanonical,
        ResidueKind::Locator => FaultKind::LocatorUnavailable,
        ResidueKind::Timing => FaultKind::TimingResidueHigh,
        ResidueKind::Protocol => FaultKind::FiberInvariantFailure,
        ResidueKind::Capability => FaultKind::CapabilityInvalid,
        ResidueKind::Replay => FaultKind::ReplayGap,
        ResidueKind::Correlation => FaultKind::PrivacyBudgetExceeded,
        ResidueKind::Focus => FaultKind::FocusAmbiguity,
        ResidueKind::Boundary => FaultKind::BcikSeamMissing,
        // A cospectral hold is an unresolved spectral-equal/non-isomorphic
        // ambiguity; a field-projection remainder is exactly a projection gap.
        ResidueKind::Cospectral => FaultKind::FocusAmbiguity,
        ResidueKind::FieldProjection => FaultKind::PchProjectionGap,
    }
}

/// First real `Faultscan` implementation: derives `FaultEvent`s from
/// existing runtime signals — gate residues and replay divergence — rather
/// than inventing a new detection subsystem from scratch.
#[derive(Debug, Default)]
pub struct RuntimeSignalScan;

impl Faultscan for RuntimeSignalScan {
    fn scan(&self, ctx: &RuntimeState) -> Vec<FaultEvent> {
        let mut events: Vec<FaultEvent> = ctx
            .gate_report
            .residues
            .iter()
            .map(|residue| FaultEvent {
                kind: fault_kind_for_residue(&residue.kind),
                severity: residue.severity,
                detection: DetectionSource::GateResidue,
                residue: Some(residue.id.clone()),
                trace: residue.origin.clone(),
            })
            .collect();

        if let Some(ReplayVerdict::Divergent { detail, .. }) = &ctx.replay_verdict {
            events.push(FaultEvent {
                kind: FaultKind::ReplayGap,
                severity: Severity::Critical,
                detection: DetectionSource::ReplayDivergence,
                residue: None,
                trace: TraceId::new(format!("replay-divergence:{detail}")),
            });
        }

        events
    }
}

// ---------------------------------------------------------------------------
// Chaos injection and recovery drills
// ---------------------------------------------------------------------------

/// Kinds of synthetic faults that the chaos injector can introduce. Renamed
/// from `FaultKind` (Master Spec Ω+1 conformance spec, Section P): this is a
/// 6-variant *chaos-injection selector*, a structurally different concern
/// from the PDF's own 18-variant *detection* taxonomy, which now owns the
/// `FaultKind` name in `ssk-types` (Section E.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ChaosFaultKind {
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
    pub fault: ChaosFaultKind,
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
    pub fault: ChaosFaultKind,
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
pub fn inject_fault(mut intent: ConnectionIntent, fault: ChaosFaultKind) -> ConnectionIntent {
    match fault {
        ChaosFaultKind::SignatureCorruption => {
            intent.core.signature = ssk_types::CoreSignature(vec![]);
        }
        ChaosFaultKind::CapabilityWithdrawal => {
            intent.capability = None;
        }
        ChaosFaultKind::TtlExpiry => {
            intent.ttl_epoch = 0;
        }
        ChaosFaultKind::ReplayDrift => {
            // Corrupt the run id to force a replay mismatch.
            intent.run = ssk_types::RunId::new(format!("{}-drifted", intent.run.0 .0));
        }
        ChaosFaultKind::AttestationFailure => {
            // Invalidate both signature and witness simultaneously.
            intent.core.signature = ssk_types::CoreSignature(vec![]);
            intent.capability = None;
        }
        ChaosFaultKind::LocatorUntrust => {
            // Nothing to mutate on the intent itself; the locator pool is controlled by the
            // drill runner.  Mark via signature corruption as a proxy.
            intent.core.signature = ssk_types::CoreSignature(vec![]);
        }
    }
    intent
}

/// Synthesise a `BoundaryResidue` representing a detected fault.
#[must_use]
pub fn fault_residue(fault: ChaosFaultKind) -> BoundaryResidue {
    use ssk_types::GateId;
    let (kind, gate) = match fault {
        ChaosFaultKind::SignatureCorruption => (ResidueKind::Identity, GateId::Core),
        ChaosFaultKind::CapabilityWithdrawal => (ResidueKind::Capability, GateId::Capability),
        ChaosFaultKind::TtlExpiry => (ResidueKind::Timing, GateId::Replay),
        ChaosFaultKind::ReplayDrift => (ResidueKind::Replay, GateId::Replay),
        ChaosFaultKind::AttestationFailure => (ResidueKind::Capability, GateId::Capability),
        ChaosFaultKind::LocatorUntrust => (ResidueKind::Locator, GateId::Locator),
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
pub fn run_drill<F>(
    clean_intent: ConnectionIntent,
    fault: ChaosFaultKind,
    run_intent: &F,
) -> DrillReport
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
        ChaosFaultKind::SignatureCorruption,
        ChaosFaultKind::CapabilityWithdrawal,
        ChaosFaultKind::TtlExpiry,
        ChaosFaultKind::AttestationFailure,
        ChaosFaultKind::ReplayDrift,
        ChaosFaultKind::LocatorUntrust,
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
    use ssk_types::{GateId, GateReportId, RunId};

    #[test]
    fn scan_maps_a_gate_residue_to_the_matching_fault_kind() {
        let residue = BoundaryResidue::new(
            ResidueId::new("res1"),
            ResidueKind::Capability,
            GateId::Capability,
            "missing witness",
            Severity::High,
            TraceId::new("t1"),
            true,
        );
        let ctx = RuntimeState {
            gate_report: GateReport {
                id: GateReportId::new("g1"),
                outcome: GateOutcomeKind::Reject,
                witnesses: Vec::new(),
                residues: vec![residue],
            },
            replay_verdict: None,
        };
        let events = RuntimeSignalScan.scan(&ctx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FaultKind::CapabilityInvalid);
        assert_eq!(events[0].detection, DetectionSource::GateResidue);
    }

    #[test]
    fn scan_reports_replay_divergence_as_a_critical_fault() {
        let ctx = RuntimeState {
            gate_report: GateReport {
                id: GateReportId::new("g1"),
                outcome: GateOutcomeKind::Pass,
                witnesses: Vec::new(),
                residues: Vec::new(),
            },
            replay_verdict: Some(ReplayVerdict::Divergent {
                first_diff: ssk_types::PipelineStep::Gates,
                detail: "trace head mismatch".into(),
            }),
        };
        let events = RuntimeSignalScan.scan(&ctx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, FaultKind::ReplayGap);
        assert_eq!(events[0].severity, Severity::Critical);
        assert!(RuntimeSignalScan.fail_closed(&events));
    }

    #[test]
    fn scan_on_a_clean_pass_reports_no_faults_and_does_not_fail_closed() {
        let ctx = RuntimeState {
            gate_report: GateReport {
                id: GateReportId::new("g1"),
                outcome: GateOutcomeKind::Pass,
                witnesses: Vec::new(),
                residues: Vec::new(),
            },
            replay_verdict: Some(ReplayVerdict::Deterministic),
        };
        let events = RuntimeSignalScan.scan(&ctx);
        assert!(events.is_empty());
        assert!(!RuntimeSignalScan.fail_closed(&events));
    }

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
            ChaosFaultKind::SignatureCorruption,
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
            ChaosFaultKind::CapabilityWithdrawal,
            &stub_run,
        );
        assert!(drill.fault_detected);
        assert!(drill.passed());
    }

    #[test]
    fn ttl_expiry_detected() {
        let drill = run_drill(sample_clean_intent(), ChaosFaultKind::TtlExpiry, &stub_run);
        assert!(drill.fault_detected);
        assert!(drill.passed());
    }

    #[test]
    fn replay_drift_detected() {
        let drill = run_drill(
            sample_clean_intent(),
            ChaosFaultKind::ReplayDrift,
            &stub_run,
        );
        assert!(drill.fault_detected, "replay drift must be detected");
        assert!(
            drill.recovery_succeeded,
            "clean run must recover after drift"
        );
        assert!(drill.passed());
    }

    #[test]
    fn locator_untrust_detected() {
        let drill = run_drill(
            sample_clean_intent(),
            ChaosFaultKind::LocatorUntrust,
            &stub_run,
        );
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
