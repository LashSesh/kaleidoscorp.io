use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::{LedgerBackend, MemoryBackend};
use ssk_types::{GateOutcomeKind, Locator, LocatorId, LocatorType};

fn pool() -> LocatorPool {
    LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
        trusted: true,
        risk_score: 10,
    }])
}

#[test]
fn valid_fixture_materializes_stitch() {
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let (outcome, _) = runtime
        .run_once(sample_intent(true), &pool())
        .expect("valid fixture should execute");

    assert_eq!(outcome.gate_report.outcome, GateOutcomeKind::Pass);
    assert!(outcome.stitch.is_some());
    assert_eq!(tensor.entries().expect("entries should load").len(), 1);
}

#[test]
fn invalid_fixture_emits_residue_and_no_stitch() {
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let (outcome, _) = runtime
        .run_once(sample_intent(false), &pool())
        .expect("invalid fixture should execute");

    assert_ne!(outcome.gate_report.outcome, GateOutcomeKind::Pass);
    assert!(outcome.stitch.is_none());
    assert!(!outcome.residues.is_empty());
}
