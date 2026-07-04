#![forbid(unsafe_code)]

use ssk_audit::chain_trace;
use ssk_focus::refocuses;
use ssk_gates::GateVector;
use ssk_identity::derive_identity_facet;
use ssk_locator::StaticLocatorPool;
use ssk_scheduler::HypertoroidalScheduler;
use ssk_stitch::from_intent;
use ssk_tensor::{make_entry, LedgerBackend, TensorError};
use ssk_types::{
    digest_of, ConnectionIntent, FrequencyVector, GateOutcomeKind, HashAlg, PipelineStep,
    ReplayManifest, RunDescriptor, RuntimeOutcome, TraceId, TraceRecord,
};

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("locator not found")]
    LocatorNotFound,
    #[error("tensor error: {0}")]
    Tensor(#[from] TensorError),
    #[error("types error: {0}")]
    Types(#[from] ssk_types::TypeError),
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
        let gate_report = self.gate_vector.evaluate(&candidate);

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

        let scheduler_state = scheduler.state();

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
