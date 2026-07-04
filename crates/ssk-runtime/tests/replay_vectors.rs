use ssk_gates::GateVector;
use ssk_locator::StaticLocatorPool;
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::MemoryBackend;
use ssk_types::{
    CostClass, EndpointRef, EpochId, HealthStatus, LocatorFacet, LocatorId, LocatorKind,
    ReplayVerdict, RiskClass, TraceId, TrustClass, Ttl,
};

fn pool() -> StaticLocatorPool {
    StaticLocatorPool::new(vec![LocatorFacet {
        id: LocatorId::new("local"),
        kind: LocatorKind::LocalOverlay,
        endpoint: EndpointRef::new("local-endpoint"),
        route: ssk_types::RouteClass::Direct,
        transport: ssk_types::TransportClass::Tcp,
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
fn deterministic_replay_vector_matches() {
    let tensor_a = MemoryBackend::new();
    let runtime_a = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor_a,
    };
    let determinism = ssk_runtime::DeterminismContext::default();
    let (_, manifest) = runtime_a
        .run_once(sample_intent(true), &pool())
        .expect("first run should work");

    // The engine re-executes the pipeline itself from the original intent —
    // it is not handed a second pre-computed outcome to diff against.
    let engine = DeterministicReplayEngine;
    let verdict = engine
        .replay(
            &manifest,
            sample_intent(true),
            &pool(),
            &determinism,
            &runtime_a.gate_vector,
        )
        .expect("replay should re-execute");
    assert!(matches!(verdict, ReplayVerdict::Deterministic));
}
