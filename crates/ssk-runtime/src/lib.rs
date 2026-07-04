#![forbid(unsafe_code)]

use ssk_audit::chain_trace;
use ssk_focus::{refocuses, FocusReport};
use ssk_gates::GateVector;
use ssk_identity::derive_identity_facet;
use ssk_locator::StaticLocatorPool;
use ssk_scheduler::HypertoroidalScheduler;
use ssk_stitch::from_intent;
use ssk_tensor::{make_entry, LedgerBackend, TensorError};
use ssk_types::{
    digest_of, AuditRef, ConnectionIntent, FrequencyVector, GateOutcomeKind, GateReport, HashAlg,
    PipelineStep, ReplayManifest, ReplayReportRef, ResidueId, RunDescriptor, RuntimeOutcome,
    SchedulerState, StitchCandidate, StitchId, TraceId, TraceRecord,
};

/// A connection event's terminal outcome (Master Spec Ω+1 ch. 14.2, verbatim
/// three-variant shape) — "ends in exactly one of three legitimate
/// outcomes. Silent loss is not a legitimate outcome." Lands here rather
/// than in `ssk-types` (a disclosed placement correction from the spec's
/// original suggestion): `Pass`'s `focus: FocusReport` field means this type
/// can only live somewhere that already depends on both `ssk-focus` and
/// `ssk-types`, and `ssk-types` cannot depend on `ssk-focus` without a
/// cycle (`ssk-focus` already depends on `ssk-types`).
///
/// **Not yet wired into `Runtime::run_once_with_context`.** Building a real
/// `Pass` variant needs a genuine `FocusReport`, which needs real
/// `Response` evidence from a `FiberExecution`/`ResponseCapture` pipeline
/// stage — neither exists yet (ch. 14.1's spine names them, but no fiber
/// execution or response-capture subsystem is implemented anywhere in this
/// workspace). `resolve` below is real and tested against `GateOutcomeKind`
/// today; wiring a live call site is future work once those stages land.
#[derive(Debug, Clone, PartialEq)]
pub enum RunOutcome {
    Pass {
        stitches: Vec<StitchId>,
        focus: FocusReport,
        replay: ReplayReportRef,
    },
    HoldRefine {
        residues: Vec<ResidueId>,
    },
    DissolveRejectQuarantine {
        residues: Vec<ResidueId>,
        audit: AuditRef,
    },
}

impl RunOutcome {
    /// Resolves a gate report into the PDF's three-way outcome taxonomy:
    /// `Hold`/`Refine` are diagnosable and non-persistent (`HoldRefine`);
    /// `Reject`/`Quarantine` dissolve with an audit trail
    /// (`DissolveRejectQuarantine`); only `Pass` materializes.
    #[must_use]
    pub fn resolve(
        gate_report: &GateReport,
        stitches: Vec<StitchId>,
        focus: FocusReport,
        replay: ReplayReportRef,
        audit: AuditRef,
    ) -> Self {
        let residues: Vec<ResidueId> = gate_report.residues.iter().map(|r| r.id.clone()).collect();
        match gate_report.outcome {
            GateOutcomeKind::Pass => RunOutcome::Pass {
                stitches,
                focus,
                replay,
            },
            GateOutcomeKind::Hold | GateOutcomeKind::Refine => RunOutcome::HoldRefine { residues },
            GateOutcomeKind::Reject | GateOutcomeKind::Quarantine => {
                RunOutcome::DissolveRejectQuarantine { residues, audit }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("locator not found")]
    LocatorNotFound,
    #[error("tensor error: {0}")]
    Tensor(#[from] TensorError),
    #[error("types error: {0}")]
    Types(#[from] ssk_types::TypeError),
}

/// The pure decision-core's output up to (but not including) tensor
/// mutation: scheduler tick, orbit derivation, locator selection, stitch
/// candidate construction, gate evaluation, and trace chaining (Master Spec
/// Ω+1 ch. 14.1's spine, minus `TensorMaterialization`). Shared by
/// `Runtime::run_once_with_context` (which additionally mutates the tensor)
/// and `ssk-replay` (which re-executes this same pipeline and diffs against
/// a `ReplayManifest` instead) — this is the extraction Section Q of
/// `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` calls for, landed here rather than
/// in `ssk-core` because the pipeline genuinely needs `ssk-identity`/
/// `ssk-stitch` (both of which already depend on `ssk-core`, so `ssk-core`
/// itself cannot add a dependency on either without a cycle).
#[derive(Debug, Clone)]
pub struct PipelineExecution {
    pub candidate: StitchCandidate,
    pub gate_report: GateReport,
    pub traces: Vec<TraceRecord>,
    pub scheduler_state: SchedulerState,
}

/// Runs the pure decision core once: deterministic given identical `intent`,
/// `pool`, `determinism`, and `gate_vector` (ch. 16.3's replay-determinism
/// obligation) — no wall-clock time, no randomness outside `determinism`'s
/// declared seed, no tensor mutation.
pub fn execute_pipeline(
    intent: &ConnectionIntent,
    pool: &StaticLocatorPool,
    determinism: &DeterminismContext,
    gate_vector: &GateVector,
) -> Result<PipelineExecution, RuntimeError> {
    let mode = if determinism.seeded {
        ssk_types::SchedulerMode::Seeded(ssk_types::SchedulerSeed(determinism.epoch))
    } else {
        ssk_types::SchedulerMode::Deterministic
    };
    let mut scheduler = HypertoroidalScheduler::new(
        ssk_types::PhaseVector::zero(),
        FrequencyVector::deterministic(),
        mode,
        determinism.epoch,
    );
    let _phase = scheduler.tick();

    let facet = derive_identity_facet(&intent.core);
    let locator = pool
        .get(&intent.target_locator)
        .or_else(|| pool.select_first_viable())
        .ok_or(RuntimeError::LocatorNotFound)?;

    let candidate = from_intent(intent.clone(), facet, locator);
    let gate_report = gate_vector.evaluate(&candidate);

    let mut traces = Vec::new();
    let mut prev_hash = ssk_types::Digest::GENESIS;
    for step in [
        PipelineStep::Scheduler,
        PipelineStep::Orbit,
        PipelineStep::Locator,
        PipelineStep::Bcik,
        PipelineStep::Gates,
    ] {
        let trace = TraceRecord {
            id: TraceId::new(format!("{}:{step:?}", intent.run.0 .0)),
            run: intent.run.clone(),
            step,
            inputs: vec![digest_of(&candidate, HashAlg::Blake3)?],
            outputs: vec![digest_of(&gate_report, HashAlg::Blake3)?],
            gate_report: Some(gate_report.id.clone()),
            residues: gate_report.residues.iter().map(|r| r.id.clone()).collect(),
            prev_hash,
            entry_hash: ssk_types::Digest::PENDING,
        };
        let trace = chain_trace(&prev_hash, trace)?;
        prev_hash = trace.entry_hash;
        traces.push(trace);
    }

    Ok(PipelineExecution {
        candidate,
        gate_report,
        traces,
        scheduler_state: scheduler.state(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeterminismContext {
    pub seeded: bool,
    pub epoch: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event: String,
    pub run_id: String,
    pub replay_id: String,
    pub seeded: bool,
    pub epoch: u64,
    pub gate_outcome: GateOutcomeKind,
    pub residues: usize,
    pub trace_count: usize,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq, Default)]
pub struct RuntimeMetrics {
    pub run_count: u64,
    pub gate_failures: u64,
    pub replay_drifts: u64,
}

impl RuntimeMetrics {
    pub fn record_run(&mut self, outcome: GateOutcomeKind) {
        self.run_count += 1;
        if outcome != GateOutcomeKind::Pass {
            self.gate_failures += 1;
        }
    }

    pub fn record_replay_drift(&mut self) {
        self.replay_drifts += 1;
    }
}

pub struct Runtime<'a, L: LedgerBackend> {
    pub gate_vector: GateVector,
    pub tensor: &'a L,
}

impl<'a, L: LedgerBackend> Runtime<'a, L> {
    pub fn run_once(
        &self,
        intent: ConnectionIntent,
        pool: &StaticLocatorPool,
    ) -> Result<(RuntimeOutcome, ReplayManifest), RuntimeError> {
        self.run_once_with_context(intent, pool, &DeterminismContext::default())
    }

    pub fn run_once_with_context(
        &self,
        intent: ConnectionIntent,
        pool: &StaticLocatorPool,
        determinism: &DeterminismContext,
    ) -> Result<(RuntimeOutcome, ReplayManifest), RuntimeError> {
        let execution = execute_pipeline(&intent, pool, determinism, &self.gate_vector)?;
        let PipelineExecution {
            candidate,
            gate_report,
            traces,
            scheduler_state,
        } = execution;

        let stitch = if gate_report.outcome == GateOutcomeKind::Pass && refocuses(&candidate) {
            let prior_hash = self
                .tensor
                .entries()?
                .last()
                .map(|e| e.entry_hash)
                .unwrap_or_else(|| ssk_types::Digest::GENESIS);
            let entry = make_entry(
                intent.run.clone(),
                candidate.id.clone(),
                &gate_report,
                candidate.replay_ready,
                prior_hash,
            )?;
            self.tensor.append(entry.clone())?;
            Some(entry)
        } else {
            None
        };

        let manifest = ReplayManifest {
            run: intent.run.clone(),
            descriptor: RunDescriptor {
                run_id: intent.run.clone(),
                policy_hash: digest_of(&"policy", HashAlg::Blake3)?,
                scheduler: scheduler_state,
                crypto_algs: ssk_types::CryptoAlgSet::default(),
                input_digest: digest_of(&intent, HashAlg::Blake3)?,
                prior_tensor_head: self
                    .tensor
                    .entries()?
                    .last()
                    .map(|e| e.entry_hash)
                    .unwrap_or_else(|| ssk_types::Digest::GENESIS),
            },
            trace_head: traces
                .last()
                .map(|t| t.entry_hash)
                .unwrap_or_else(|| ssk_types::Digest::GENESIS),
            expected_outcome_digest: digest_of(&gate_report, HashAlg::Blake3)?,
        };

        Ok((
            RuntimeOutcome {
                run: intent.run,
                gate_report: gate_report.clone(),
                stitch,
                residues: gate_report.residues.clone(),
                traces,
            },
            manifest,
        ))
    }

    #[must_use]
    pub fn runtime_event(
        &self,
        outcome: &RuntimeOutcome,
        manifest: &ReplayManifest,
        determinism: &DeterminismContext,
    ) -> RuntimeEvent {
        RuntimeEvent {
            event: "runtime.run.completed".into(),
            run_id: outcome.run.0 .0.clone(),
            replay_id: manifest.trace_head.to_hex(),
            seeded: determinism.seeded,
            epoch: determinism.epoch,
            gate_outcome: outcome.gate_report.outcome,
            residues: outcome.residues.len(),
            trace_count: outcome.traces.len(),
        }
    }
}

#[must_use]
pub fn sample_capability_witness() -> ssk_types::CapabilityWitness {
    ssk_types::CapabilityWitness {
        id: ssk_types::CapabilityId::of(&"sample-capability", ssk_types::HashAlg::Blake3)
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
    }
}

pub fn sample_intent(valid: bool) -> ConnectionIntent {
    let mut intent = ConnectionIntent {
        run: ssk_types::RunId::new(if valid { "run-valid" } else { "run-invalid" }),
        core: ssk_types::CoreNode {
            id: ssk_types::CoreId::new("core-1"),
            canonical: ssk_types::CanonicalForm("core".into()),
            signature: ssk_types::CoreSignature(vec![1, 2, 3]),
            policy_root: ssk_types::PolicyId::new("policy-1"),
            replay_root: ssk_types::ReplayRoot::new("replay:core-1"),
            audit_root: ssk_types::AuditRoot::new("audit:core-1"),
            closure: ssk_types::ClosureState::Closed,
        },
        target_locator: ssk_types::LocatorId::new("local"),
        capability: valid.then(sample_capability_witness),
        ttl_epoch: if valid { 1 } else { 0 },
    };
    if !valid {
        intent.core.signature = ssk_types::CoreSignature(vec![]);
    }
    intent
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_tensor::GenericLedgerBackend;
    use ssk_types::{
        CostClass, EndpointRef, EpochId, HealthStatus, LocatorFacet, LocatorKind, RiskClass,
        RouteClass, TransportClass, TrustClass, Ttl,
    };

    fn mk_locator_facet() -> LocatorFacet {
        LocatorFacet {
            id: ssk_types::LocatorId::new("local"),
            kind: LocatorKind::LocalOverlay,
            endpoint: EndpointRef::new("local-endpoint"),
            route: RouteClass::Direct,
            transport: TransportClass::Tcp,
            epoch: EpochId(0),
            ttl: Ttl(100),
            trust: TrustClass::Owned,
            cost: CostClass::Free,
            risk: RiskClass::Low,
            health: HealthStatus::Live,
            trace: TraceId::new("trace-local"),
            trusted: true,
            risk_score: 10,
        }
    }

    fn sample_focus_report() -> FocusReport {
        FocusReport {
            reconstructed: ssk_focus::CoreSessionClass::Reconstructed(ssk_types::CoreId::new("c1")),
            residues: Vec::new(),
            replay: ReplayReportRef::new("focus-replay:c1"),
            linkability: ssk_privacy::LinkabilityReport {
                score: ssk_privacy::LinkRisk(0.0),
                adversary_model: ssk_privacy::AdversaryModel::PartialNetworkObserver,
                high_risk_components: Vec::new(),
            },
            verdict: ssk_focus::FocusVerdict::Pass,
        }
    }

    #[test]
    fn run_outcome_resolves_pass_from_a_passing_gate_report() {
        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: GateOutcomeKind::Pass,
            witnesses: Vec::new(),
            residues: Vec::new(),
        };
        let outcome = RunOutcome::resolve(
            &report,
            vec![StitchId::new("s1")],
            sample_focus_report(),
            ReplayReportRef::new("r1"),
            AuditRef::new("a1"),
        );
        assert!(matches!(outcome, RunOutcome::Pass { .. }));
    }

    #[test]
    fn run_outcome_resolves_hold_refine_from_a_holding_gate_report() {
        let residue = ssk_types::BoundaryResidue::new(
            ssk_types::ResidueId::new("res1"),
            ssk_types::ResidueKind::Timing,
            ssk_types::GateId::Dissolution,
            "held",
            ssk_types::Severity::Low,
            TraceId::new("t1"),
            true,
        );
        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: GateOutcomeKind::Hold,
            witnesses: Vec::new(),
            residues: vec![residue],
        };
        let outcome = RunOutcome::resolve(
            &report,
            Vec::new(),
            sample_focus_report(),
            ReplayReportRef::new("r1"),
            AuditRef::new("a1"),
        );
        assert!(matches!(
            outcome,
            RunOutcome::HoldRefine { residues } if residues.len() == 1
        ));
    }

    #[test]
    fn run_outcome_resolves_dissolve_from_a_rejecting_gate_report() {
        let residue = ssk_types::BoundaryResidue::new(
            ssk_types::ResidueId::new("res1"),
            ssk_types::ResidueKind::Identity,
            ssk_types::GateId::Core,
            "rejected",
            ssk_types::Severity::High,
            TraceId::new("t1"),
            true,
        );
        let report = GateReport {
            id: ssk_types::GateReportId::new("g1"),
            outcome: GateOutcomeKind::Reject,
            witnesses: Vec::new(),
            residues: vec![residue],
        };
        let outcome = RunOutcome::resolve(
            &report,
            Vec::new(),
            sample_focus_report(),
            ReplayReportRef::new("r1"),
            AuditRef::new("a1"),
        );
        assert!(matches!(
            outcome,
            RunOutcome::DissolveRejectQuarantine { residues, .. } if residues.len() == 1
        ));
    }

    #[test]
    fn failed_gate_preserves_tensor() {
        let tensor = ssk_tensor::MemoryBackend::new();
        let runtime = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor,
        };
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let (outcome, _) = runtime
            .run_once(sample_intent(false), &pool)
            .expect("runtime should execute");
        assert_ne!(outcome.gate_report.outcome, GateOutcomeKind::Pass);
        assert!(tensor.entries().expect("entries readable").is_empty());
    }

    #[test]
    fn deterministic_context_is_reproducible() {
        let tensor_a = ssk_tensor::MemoryBackend::new();
        let tensor_b = ssk_tensor::MemoryBackend::new();
        let runtime_a = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor_a,
        };
        let runtime_b = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor_b,
        };
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let ctx = DeterminismContext {
            seeded: true,
            epoch: 77,
        };

        let (a, ma) = runtime_a
            .run_once_with_context(sample_intent(true), &pool, &ctx)
            .expect("first run");
        let (b, mb) = runtime_b
            .run_once_with_context(sample_intent(true), &pool, &ctx)
            .expect("second run");

        assert_eq!(a.gate_report, b.gate_report);
        assert_eq!(ma.trace_head, mb.trace_head);
        assert_eq!(ma.descriptor.scheduler, mb.descriptor.scheduler);
    }
}
