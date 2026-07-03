#![forbid(unsafe_code)]

use ssk_audit::chain_trace;
use ssk_focus::refocuses;
use ssk_gates::GateVector;
use ssk_identity::derive_identity_facet;
use ssk_locator::LocatorPool;
use ssk_scheduler::DeterministicScheduler;
use ssk_stitch::from_intent;
use ssk_tensor::{make_entry, LedgerBackend, TensorError};
use ssk_types::{
    digest_of, ConnectionIntent, FrequencyVector, GateOutcomeKind, HashAlg, Id, PipelineStep, ReplayManifest,
    ReplayRoot, RunDescriptor, RuntimeOutcome, SchedulerState, Sector, TraceId, TraceRecord,
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

pub struct Runtime<'a, L: LedgerBackend> {
    pub gate_vector: GateVector,
    pub tensor: &'a L,
}

impl<'a, L: LedgerBackend> Runtime<'a, L> {
    pub fn run_once(&self, intent: ConnectionIntent, pool: &LocatorPool) -> Result<(RuntimeOutcome, ReplayManifest), RuntimeError> {
        let mut scheduler = DeterministicScheduler::new(
            ssk_types::PhaseVector::zero(),
            FrequencyVector::deterministic(),
            false,
            0,
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
        let mut prev_hash = ssk_types::Digest::new("genesis");
        for step in [
            PipelineStep::Scheduler,
            PipelineStep::Orbit,
            PipelineStep::Locator,
            PipelineStep::Bcik,
            PipelineStep::Gates,
        ] {
            let trace = TraceRecord {
                id: TraceId::new(format!("{}:{step:?}", intent.run.0.0)),
                run: intent.run.clone(),
                step,
                inputs: vec![digest_of(&candidate, HashAlg::Blake3)?],
                outputs: vec![digest_of(&gate_report, HashAlg::Blake3)?],
                gate_report: Some(gate_report.id.clone()),
                residues: gate_report.residues.iter().map(|r| r.id.clone()).collect(),
                prev_hash: prev_hash.clone(),
                entry_hash: ssk_types::Digest::new("pending"),
            };
            let trace = chain_trace(&prev_hash, trace)?;
            prev_hash = trace.entry_hash.clone();
            traces.push(trace);
        }

        let stitch = if gate_report.outcome == GateOutcomeKind::Pass && refocuses(&candidate) {
            let prior_hash = self
                .tensor
                .entries()?
                .last()
                .map(|e| e.entry_hash.clone())
                .unwrap_or_else(|| ssk_types::Digest::new("genesis"));
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

        let scheduler_state = SchedulerState {
            theta0: ssk_types::PhaseVector::zero(),
            freq: FrequencyVector::deterministic(),
            seeded: false,
            epoch: 0,
            ticks: 1,
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
                    .map(|e| e.entry_hash.clone())
                    .unwrap_or_else(|| ssk_types::Digest::new("genesis")),
            },
            trace_head: traces
                .last()
                .map(|t| t.entry_hash.clone())
                .unwrap_or_else(|| ssk_types::Digest::new("genesis")),
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
}

pub fn sample_intent(valid: bool) -> ConnectionIntent {
    let mut intent = ConnectionIntent {
        run: ssk_types::RunId::new(if valid { "run-valid" } else { "run-invalid" }),
        core: ssk_types::CoreNode {
            id: ssk_types::CoreId::new("core-1"),
            canonical_name: "core".into(),
            policy_root: ssk_types::PolicyId::new("policy-1"),
            signature_ok: true,
        },
        target_locator: ssk_types::LocatorId::new("local"),
        capability_witness: valid,
        ttl_epoch: if valid { 1 } else { 0 },
    };
    if !valid {
        intent.core.signature_ok = false;
    }
    intent
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{Locator, LocatorType};

    #[test]
    fn failed_gate_preserves_tensor() {
        let tensor = ssk_tensor::MemoryBackend::new();
        let runtime = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor,
        };
        let pool = LocatorPool::new(vec![Locator {
            id: ssk_types::LocatorId::new("local"),
            locator_type: LocatorType::LocalOverlay,
            trusted: true,
            risk_score: 10,
        }]);
        let (outcome, _) = runtime
            .run_once(sample_intent(false), &pool)
            .expect("runtime should execute");
        assert_ne!(outcome.gate_report.outcome, GateOutcomeKind::Pass);
        assert!(tensor.entries().expect("entries readable").is_empty());
    }
}
