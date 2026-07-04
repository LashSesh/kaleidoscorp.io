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
/// Produced for real by `run_to_outcome` (below): a `Pass` carries the
/// materialized stitch ids, a genuine `FocusReport` from
/// `ssk_focus::FocusEngine::reanalyze` over a real captured `Response`, and
/// its replay reference. `resolve` remains available as the pure
/// gate-report → outcome mapping, tested independently of the full driver.
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

/// Executes a closed stitch's fiber and captures its response (Master Spec
/// Ω+1 ch. 14.1's `FiberExecution` + `ResponseCapture` stages). This is the
/// abstraction boundary the PDF's own non-goals draw: a *real network*
/// execution is exclusively `ssk-netcore`'s (Desktop track's) job and never
/// this crate's — so the only executor implemented here is
/// `LocalFiberExecutor`, a deterministic local echo suitable for
/// local-overlay / test-harness locators. It fabricates no network
/// liveness: the captured `Response`'s `payload_digest` is a content hash
/// of the stitch itself, honestly labeled as a local execution, never
/// presented as evidence a remote peer answered.
pub trait FiberExecutor {
    fn execute(&self, stitch: &ssk_types::BcikStitch) -> ssk_focus::Response;
}

/// Deterministic, non-network fiber executor: echoes a `Response` derived
/// entirely from the stitch's own content. Suitable for `LocalOverlay`/
/// `TestHarness` locators (the only kinds this workspace's core layer
/// serves); a real egress executor lives in the Desktop track, out of
/// scope here (Section X).
#[derive(Debug, Default)]
pub struct LocalFiberExecutor;

impl FiberExecutor for LocalFiberExecutor {
    fn execute(&self, stitch: &ssk_types::BcikStitch) -> ssk_focus::Response {
        // Content-address the stitch's identifying fields into a payload
        // digest — deterministic, so replay reproduces it bit-for-bit.
        let payload_digest = digest_of(
            &format!(
                "{}:{}:{:?}",
                stitch.facet.0.to_hex(),
                stitch.locator.0 .0,
                stitch.fiber
            ),
            HashAlg::Blake3,
        )
        .unwrap_or(ssk_types::Digest::GENESIS);
        ssk_focus::Response {
            facet: stitch.facet,
            locator: stitch.locator.clone(),
            fiber: stitch.fiber,
            trace: stitch.trace.clone(),
            payload_digest,
        }
    }
}

/// Drives the full decision-core pipeline through to one of the PDF's three
/// legitimate terminal outcomes (Master Spec Ω+1 ch. 14.2's `RunOutcome`),
/// including the stages `run_once_with_context` omits: real BCIK crossing
/// (`ssk_bcik::Bcik::cross`, not just `BcikGate`'s pass/fail), tensor
/// materialization into a real `StitchTensor` (`apply_sorted`, not a flat
/// `TensorEntry`), fiber execution + response capture (`FiberExecutor`),
/// and concave focus (`ssk_focus::FocusEngine::reanalyze`).
///
/// "A connection event ends in exactly one of three legitimate outcomes.
/// Silent loss is not a legitimate outcome" (ch. 14.2) — this function has
/// no path that drops a candidate without returning a variant.
///
/// # Errors
/// Returns `RuntimeError` if locator resolution, hashing, or tensor
/// materialization fails.
pub fn run_to_outcome(
    intent: &ConnectionIntent,
    pool: &StaticLocatorPool,
    determinism: &DeterminismContext,
    gate_vector: &GateVector,
    tensor: &mut ssk_tensor::StitchTensor,
    fiber_exec: &impl FiberExecutor,
    current_epoch: ssk_types::EpochId,
) -> Result<RunOutcome, RuntimeError> {
    let execution = execute_pipeline(intent, pool, determinism, gate_vector)?;
    let PipelineExecution {
        candidate,
        gate_report,
        scheduler_state,
        ..
    } = execution;

    let audit = AuditRef::new(format!("audit:{}", intent.run.0 .0));

    // Non-pass gate outcomes dissolve or hold — never silently — before any
    // crossing or materialization is attempted (fail-closed).
    match gate_report.outcome {
        GateOutcomeKind::Hold | GateOutcomeKind::Refine => {
            return Ok(RunOutcome::HoldRefine {
                residues: gate_report.residues.iter().map(|r| r.id.clone()).collect(),
            });
        }
        GateOutcomeKind::Reject | GateOutcomeKind::Quarantine => {
            return Ok(RunOutcome::DissolveRejectQuarantine {
                residues: gate_report.residues.iter().map(|r| r.id.clone()).collect(),
                audit,
            });
        }
        GateOutcomeKind::Pass => {}
    }

    // Gate passed: cross the seam for real. An open crossing is a boundary
    // residue, which dissolves (still not a silent loss).
    let provider = ssk_crypto::Blake3HashProvider;
    let mut bcik = ssk_bcik::Bcik::new(&provider);
    let stitch = match bcik.cross(
        &candidate.facet,
        &candidate.locator,
        ssk_types::FiberType::Data,
        &candidate,
    ) {
        ssk_types::CrossOutcome::Closed(stitch) => stitch,
        ssk_types::CrossOutcome::Residue(residue) => {
            return Ok(RunOutcome::DissolveRejectQuarantine {
                residues: vec![residue.id],
                audit,
            });
        }
    };

    // Materialize into the real persistent tensor (apply_sorted).
    let accepted = ssk_types::Accepted {
        stitch: stitch.clone(),
        gate_report: gate_report.id.clone(),
        accepted_at: ssk_types::Tick(scheduler_state.ticks),
        epoch: current_epoch,
        ttl: ssk_types::Ttl(candidate.ttl_epoch),
    };
    let stitches = tensor
        .apply_sorted(vec![accepted])
        .map_err(|_| RuntimeError::Tensor(TensorError::VerificationFailed))?;

    // FiberExecution + ResponseCapture → ConcaveFocus.
    let response = fiber_exec.execute(&stitch);
    let focus = ssk_focus::FocusEngine::new(&provider).reanalyze(
        &[response],
        &candidate.core,
        &ssk_focus::Policy,
    );
    let replay = focus.replay.clone();

    Ok(RunOutcome::Pass {
        stitches,
        focus,
        replay,
    })
}

/// The real `PathProjectionCheck` (`ssk-locator`'s dependency-inverted trait)
/// backed by the PCH's own facet-level axis predicates
/// (`ssk_gates::pch::locator_axes_consistent`). This is the concrete bridge
/// that lets `ssk_locator::select_path` consult the real Projective
/// Connection Hypercube without `ssk-locator` depending on `ssk-gates` (which
/// would cycle, since `ssk-gates` already depends on `ssk-locator` via
/// `ssk-bcik`): the trait lives in the low crate, the implementation lives
/// here in `ssk-runtime` where both crates are visible.
#[derive(Debug, Default)]
pub struct HypercubePathCheck;

impl ssk_locator::PathProjectionCheck for HypercubePathCheck {
    fn passes(&self, facet: &ssk_types::LocatorFacet, _theta: &ssk_types::PhaseVector) -> bool {
        ssk_gates::pch::locator_axes_consistent(facet)
    }
}

/// Selects the nearest PCH-consistent egress locator from a pool's funnel-DAG
/// view, driving the real `HypercubePathCheck` (above) — the production entry
/// point that ties `ssk_locator::select_path` (Section G.2) to the real
/// hypercube (Section I). With a flat pool (no relay `StitchEdge`s configured),
/// the reachable set is exactly the pool's own directly-usable locators; real
/// multi-hop edges come from a routing policy not yet modeled.
///
/// # Errors
/// Returns `FaultKind::LocatorUnavailable` if `start` is not in the pool or no
/// reachable locator is PCH-consistent.
pub fn select_egress(
    pool: &StaticLocatorPool,
    start: &ssk_types::LocatorId,
    theta: &ssk_types::PhaseVector,
) -> Result<ssk_types::LocatorPath, ssk_types::FaultKind> {
    let graph = ssk_types::LocatorGraph {
        nodes: pool.locators.clone(),
        edges: Vec::new(),
        hyperedges: Vec::new(),
    };
    ssk_locator::select_path(
        theta,
        &graph,
        &HypercubePathCheck,
        start,
        &ssk_locator::Policy,
    )
}

/// Real `PlacementAuthority` for the `Connection<Split>::place` typestate
/// transition — the facet-level PCH pre-check, same predicate as
/// `HypercubePathCheck`.
impl ssk_core::connection::PlacementAuthority for HypercubePathCheck {
    fn placement_ok(&self, sc: &StitchCandidate) -> bool {
        ssk_gates::pch::locator_axes_consistent(&sc.locator)
    }
}

/// Real `MaterializationSink` for the `Connection<GatePassed>::materialize`
/// typestate transition: composes the genuine BCIK crossing
/// (`ssk_bcik::Bcik::cross`) with `ssk_tensor::StitchTensor::apply_sorted` —
/// exactly the chain `run_to_outcome` performs, exposed through the
/// typestate so a caller holding a gate-passed connection materializes it
/// (and, by the typestate, *only* then) with real persistence. Borrows the
/// tensor for the sink's lifetime.
pub struct TensorMaterializationSink<'t> {
    tensor: &'t mut ssk_tensor::StitchTensor,
    epoch: ssk_types::EpochId,
    accepted_at: ssk_types::Tick,
}

impl<'t> TensorMaterializationSink<'t> {
    #[must_use]
    pub fn new(
        tensor: &'t mut ssk_tensor::StitchTensor,
        epoch: ssk_types::EpochId,
        accepted_at: ssk_types::Tick,
    ) -> Self {
        Self {
            tensor,
            epoch,
            accepted_at,
        }
    }
}

impl ssk_core::connection::MaterializationSink for TensorMaterializationSink<'_> {
    fn materialize(&mut self, sc: &StitchCandidate) -> Result<Vec<StitchId>, ssk_types::FaultKind> {
        let provider = ssk_crypto::Blake3HashProvider;
        let mut bcik = ssk_bcik::Bcik::new(&provider);
        let stitch = match bcik.cross(&sc.facet, &sc.locator, ssk_types::FiberType::Data, sc) {
            ssk_types::CrossOutcome::Closed(stitch) => stitch,
            ssk_types::CrossOutcome::Residue(_) => {
                return Err(ssk_types::FaultKind::BcikSeamMissing);
            }
        };
        let accepted = ssk_types::Accepted {
            stitch,
            gate_report: ssk_types::GateReportId::new(format!("gr:{}", sc.id.0 .0)),
            accepted_at: self.accepted_at,
            epoch: self.epoch,
            ttl: ssk_types::Ttl(sc.ttl_epoch),
        };
        self.tensor.apply_sorted(vec![accepted])
    }
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

    fn fresh_stitch_tensor() -> ssk_tensor::StitchTensor {
        ssk_tensor::StitchTensor::open(Box::new(ssk_tensor::GenericMemoryBackend::<
            ssk_types::StitchTensorEntry,
        >::new()))
        .expect("open")
    }

    #[test]
    fn run_to_outcome_materializes_and_passes_on_a_valid_intent() {
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let mut tensor = fresh_stitch_tensor();
        let outcome = run_to_outcome(
            &sample_intent(true),
            &pool,
            &DeterminismContext::default(),
            &GateVector::with_all_default(),
            &mut tensor,
            &LocalFiberExecutor,
            EpochId(0),
        )
        .expect("run");

        match outcome {
            RunOutcome::Pass {
                stitches, focus, ..
            } => {
                assert_eq!(stitches.len(), 1);
                assert_eq!(focus.verdict, ssk_focus::FocusVerdict::Pass);
            }
            other => panic!("expected Pass, got {other:?}"),
        }
        // The tensor genuinely mutated.
        assert_eq!(tensor.graph().len(), 1);
    }

    #[test]
    fn run_to_outcome_dissolves_and_preserves_the_tensor_on_a_failed_gate() {
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let mut tensor = fresh_stitch_tensor();
        let head_before = tensor.head();
        let outcome = run_to_outcome(
            &sample_intent(false),
            &pool,
            &DeterminismContext::default(),
            &GateVector::with_all_default(),
            &mut tensor,
            &LocalFiberExecutor,
            EpochId(0),
        )
        .expect("run");

        assert!(matches!(
            outcome,
            RunOutcome::DissolveRejectQuarantine { .. }
        ));
        // Fail-closed: no crossing, no materialization.
        assert_eq!(tensor.head(), head_before);
        assert!(tensor.graph().is_empty());
    }

    #[test]
    fn select_egress_returns_a_trusted_low_risk_locator() {
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let path = select_egress(
            &pool,
            &ssk_types::LocatorId::new("local"),
            &ssk_types::PhaseVector::zero(),
        )
        .expect("egress");
        assert_eq!(path.destination, ssk_types::LocatorId::new("local"));
    }

    #[test]
    fn select_egress_rejects_an_untrusted_locator() {
        let mut facet = mk_locator_facet();
        facet.trusted = false;
        facet.trust = TrustClass::Untrusted;
        let pool = StaticLocatorPool::new(vec![facet]);
        let result = select_egress(
            &pool,
            &ssk_types::LocatorId::new("local"),
            &ssk_types::PhaseVector::zero(),
        );
        assert!(matches!(
            result,
            Err(ssk_types::FaultKind::LocatorUnavailable)
        ));
    }

    #[test]
    fn select_egress_rejects_a_high_risk_locator() {
        let mut facet = mk_locator_facet();
        facet.risk_score = 90;
        let pool = StaticLocatorPool::new(vec![facet]);
        let result = select_egress(
            &pool,
            &ssk_types::LocatorId::new("local"),
            &ssk_types::PhaseVector::zero(),
        );
        assert!(matches!(
            result,
            Err(ssk_types::FaultKind::LocatorUnavailable)
        ));
    }

    #[test]
    fn connection_typestate_drives_to_materialized_with_real_collaborators() {
        use ssk_core::connection::{Connection, ConnectionInner, GateOutcome, Intent};

        // Build a real candidate exactly as the pipeline does.
        let facet = ssk_identity::derive_identity_facet(&sample_intent(true).core);
        let candidate = ssk_stitch::from_intent(sample_intent(true), facet, mk_locator_facet());

        let mut tensor = fresh_stitch_tensor();
        let gate_vector = GateVector::with_all_default();

        let c = Connection::<Intent>::new(ConnectionInner::new(candidate));
        let c = c.canonicalize().expect("canonicalize");
        let c = c.birefract().expect("birefract");
        let c = c.place(&HypercubePathCheck).expect("place");
        let c = match c.gate(&gate_vector) {
            GateOutcome::Pass(c) => c,
            _ => panic!("expected GateOutcome::Pass"),
        };
        let mut sink = TensorMaterializationSink::new(&mut tensor, EpochId(0), ssk_types::Tick(1));
        let c = c.materialize(&mut sink).expect("materialize");

        assert_eq!(c.inner().stitches().len(), 1);
        assert_eq!(tensor.graph().len(), 1);
    }

    #[test]
    fn connection_typestate_place_rejects_an_untrusted_locator() {
        use ssk_core::connection::{Connection, ConnectionInner, Intent};

        let mut loc = mk_locator_facet();
        loc.trusted = false;
        loc.trust = TrustClass::Untrusted;
        let facet = ssk_identity::derive_identity_facet(&sample_intent(true).core);
        let candidate = ssk_stitch::from_intent(sample_intent(true), facet, loc);

        let c = Connection::<Intent>::new(ConnectionInner::new(candidate));
        let c = c.canonicalize().expect("canonicalize");
        let c = c.birefract().expect("birefract");
        assert!(matches!(
            c.place(&HypercubePathCheck),
            Err(ssk_types::FaultKind::PchProjectionGap)
        ));
    }

    #[test]
    fn run_to_outcome_is_deterministic() {
        let pool = StaticLocatorPool::new(vec![mk_locator_facet()]);
        let ctx = DeterminismContext {
            seeded: true,
            epoch: 9,
        };
        let mut tensor_a = fresh_stitch_tensor();
        let mut tensor_b = fresh_stitch_tensor();
        let a = run_to_outcome(
            &sample_intent(true),
            &pool,
            &ctx,
            &GateVector::with_all_default(),
            &mut tensor_a,
            &LocalFiberExecutor,
            EpochId(3),
        )
        .expect("run a");
        let b = run_to_outcome(
            &sample_intent(true),
            &pool,
            &ctx,
            &GateVector::with_all_default(),
            &mut tensor_b,
            &LocalFiberExecutor,
            EpochId(3),
        )
        .expect("run b");
        assert_eq!(a, b);
        assert_eq!(tensor_a.head(), tensor_b.head());
    }
}
