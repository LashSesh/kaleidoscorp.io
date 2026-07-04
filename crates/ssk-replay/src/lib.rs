#![forbid(unsafe_code)]

use ssk_gates::GateVector;
use ssk_locator::StaticLocatorPool;
use ssk_runtime::{execute_pipeline, DeterminismContext, RuntimeError};
use ssk_types::{digest_of, ConnectionIntent, HashAlg, ReplayManifest, ReplayVerdict};

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("runtime error: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("types error: {0}")]
    Types(#[from] ssk_types::TypeError),
}

/// Re-executes the decision core under a manifest and diffs every step
/// (Master Spec Ω+1 ch. 16.3, verbatim contract) — a single call, not two
/// externally-run outcomes handed in for a field-equality diff. The
/// original `intent`/`pool`/`determinism`/`gate_vector` are required
/// because a `ReplayManifest` is a compact commitment (digests and a
/// scheduler-state snapshot), not an archive of the original request; this
/// document's own disclosed elaboration of the PDF's referenced
/// `RuntimeState` parameter, whose fields aren't enumerated in the
/// excerpted text.
pub trait ReplayEngine {
    fn replay(
        &self,
        manifest: &ReplayManifest,
        intent: ConnectionIntent,
        pool: &StaticLocatorPool,
        determinism: &DeterminismContext,
        gate_vector: &GateVector,
    ) -> Result<ReplayVerdict, ReplayError>;
}

#[derive(Default)]
pub struct DeterministicReplayEngine;

impl ReplayEngine for DeterministicReplayEngine {
    fn replay(
        &self,
        manifest: &ReplayManifest,
        intent: ConnectionIntent,
        pool: &StaticLocatorPool,
        determinism: &DeterminismContext,
        gate_vector: &GateVector,
    ) -> Result<ReplayVerdict, ReplayError> {
        if manifest.run != intent.run {
            return Ok(ReplayVerdict::Divergent {
                first_diff: ssk_types::PipelineStep::Scheduler,
                detail: "manifest run id does not match replay intent".to_string(),
            });
        }

        let execution = execute_pipeline(&intent, pool, determinism, gate_vector)?;

        let trace_head = execution
            .traces
            .last()
            .map(|t| t.entry_hash)
            .unwrap_or(ssk_types::Digest::GENESIS);
        let outcome_digest = digest_of(&execution.gate_report, HashAlg::Blake3)?;

        if trace_head != manifest.trace_head {
            return Ok(ReplayVerdict::Divergent {
                first_diff: ssk_types::PipelineStep::Gates,
                detail: "re-executed trace head does not match manifest trace head".to_string(),
            });
        }
        if outcome_digest != manifest.expected_outcome_digest {
            return Ok(ReplayVerdict::Divergent {
                first_diff: ssk_types::PipelineStep::Gates,
                detail: "re-executed gate report digest does not match manifest".to_string(),
            });
        }

        Ok(ReplayVerdict::Deterministic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_runtime::{sample_intent, Runtime};
    use ssk_tensor::MemoryBackend;
    use ssk_types::{
        CostClass, EndpointRef, EpochId, HealthStatus, LocatorFacet, LocatorId, LocatorKind,
        RiskClass, RouteClass, TraceId, TransportClass, TrustClass, Ttl,
    };

    fn pool() -> StaticLocatorPool {
        StaticLocatorPool::new(vec![LocatorFacet {
            id: LocatorId::new("local"),
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
        }])
    }

    #[test]
    fn genuinely_re_executed_run_matches_its_own_manifest() {
        let tensor = MemoryBackend::new();
        let runtime = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor,
        };
        let determinism = DeterminismContext {
            seeded: true,
            epoch: 42,
        };
        let (_, manifest) = runtime
            .run_once_with_context(sample_intent(true), &pool(), &determinism)
            .expect("first run");

        let engine = DeterministicReplayEngine;
        let verdict = engine
            .replay(
                &manifest,
                sample_intent(true),
                &pool(),
                &determinism,
                &runtime.gate_vector,
            )
            .expect("replay should execute");

        assert!(matches!(verdict, ReplayVerdict::Deterministic));
    }

    #[test]
    fn a_mismatched_manifest_is_reported_as_divergent() {
        let tensor = MemoryBackend::new();
        let runtime = Runtime {
            gate_vector: GateVector::with_all_default(),
            tensor: &tensor,
        };
        let determinism = DeterminismContext {
            seeded: true,
            epoch: 42,
        };
        let (_, mut manifest) = runtime
            .run_once_with_context(sample_intent(true), &pool(), &determinism)
            .expect("first run");
        manifest.trace_head = ssk_types::Digest::GENESIS;

        let engine = DeterministicReplayEngine;
        let verdict = engine
            .replay(
                &manifest,
                sample_intent(true),
                &pool(),
                &determinism,
                &runtime.gate_vector,
            )
            .expect("replay should execute");

        assert!(matches!(verdict, ReplayVerdict::Divergent { .. }));
    }
}
