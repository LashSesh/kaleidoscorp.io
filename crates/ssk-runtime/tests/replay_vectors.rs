use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::MemoryBackend;
use ssk_types::{Locator, LocatorId, LocatorType, ReplayVerdict};

fn pool() -> LocatorPool {
    LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
        trusted: true,
        risk_score: 10,
    }])
}

#[test]
fn deterministic_replay_vector_matches() {
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let (first, manifest) = runtime
        .run_once(sample_intent(true), &pool())
        .expect("first run should work");
    let (second, _) = runtime
        .run_once(sample_intent(true), &pool())
        .expect("second run should work");

    let engine = DeterministicReplayEngine;
    let verdict = engine.replay(&manifest, &second, &first);
    assert!(matches!(verdict, ReplayVerdict::Deterministic));
}
