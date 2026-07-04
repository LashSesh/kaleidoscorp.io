//! Cross-cutting conformance obligations (Master Spec Ω+1 ch. 18, Section W
//! of `docs/OMEGA_CORE_CONFORMANCE_SPEC.md`) exercised end-to-end through the
//! real `run_to_outcome` pipeline. Complements the per-crate property tests;
//! these assert the invariants that only hold across the whole decision core.

use ssk_core::MirrorOrbit;
use ssk_gates::GateVector;
use ssk_locator::StaticLocatorPool;
use ssk_runtime::{
    run_to_outcome, sample_intent, DeterminismContext, LocalFiberExecutor, RunOutcome,
};
use ssk_tensor::{GenericMemoryBackend, StitchTensor};
use ssk_types::{
    CostClass, EndpointRef, EpochId, HealthStatus, LocatorFacet, LocatorId, LocatorKind, RiskClass,
    RouteClass, StitchTensorEntry, TraceId, TransportClass, TrustClass, Ttl,
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

fn tensor() -> StitchTensor {
    StitchTensor::open(Box::new(GenericMemoryBackend::<StitchTensorEntry>::new())).expect("open")
}

/// ch. 18.1 — every candidate facet recovers to its own core, and only its own.
#[test]
fn facet_recovers_to_core() {
    let intent = sample_intent(true);
    let facet = ssk_identity::derive_identity_facet(&intent.core);
    let orbit = MirrorOrbit::for_core(&intent.core);
    assert!(orbit.recover(&facet).is_ok());
}

/// ch. 18.2 / ch. 12.2 — a failed gate leaves the tensor byte-for-byte intact.
#[test]
fn failed_gate_preserves_the_tensor() {
    let mut t = tensor();
    let head_before = t.head();
    let outcome = run_to_outcome(
        &sample_intent(false),
        &pool(),
        &DeterminismContext::default(),
        &GateVector::with_all_default(),
        &mut t,
        &LocalFiberExecutor,
        EpochId(0),
    )
    .expect("run");
    assert!(matches!(
        outcome,
        RunOutcome::DissolveRejectQuarantine { .. }
    ));
    assert_eq!(t.head(), head_before);
    assert!(t.graph().is_empty());
}

/// ch. 18.3 — no silent loss: every run, valid or not, ends in exactly one of
/// the three legitimate outcomes; a dissolve always carries at least one
/// residue id.
#[test]
fn no_silent_loss() {
    for valid in [true, false] {
        let mut t = tensor();
        let outcome = run_to_outcome(
            &sample_intent(valid),
            &pool(),
            &DeterminismContext::default(),
            &GateVector::with_all_default(),
            &mut t,
            &LocalFiberExecutor,
            EpochId(0),
        )
        .expect("run");
        match outcome {
            RunOutcome::Pass { stitches, .. } => assert!(!stitches.is_empty()),
            RunOutcome::HoldRefine { residues } => assert!(!residues.is_empty()),
            RunOutcome::DissolveRejectQuarantine { residues, .. } => {
                assert!(!residues.is_empty());
            }
        }
    }
}

/// ch. 16.3 — the decision core is deterministic: same inputs, bit-identical
/// outcome and tensor head across independent runs.
#[test]
fn decision_core_is_deterministic() {
    let ctx = DeterminismContext {
        seeded: true,
        epoch: 5,
    };
    let mut a = tensor();
    let mut b = tensor();
    let oa = run_to_outcome(
        &sample_intent(true),
        &pool(),
        &ctx,
        &GateVector::with_all_default(),
        &mut a,
        &LocalFiberExecutor,
        EpochId(1),
    )
    .expect("a");
    let ob = run_to_outcome(
        &sample_intent(true),
        &pool(),
        &ctx,
        &GateVector::with_all_default(),
        &mut b,
        &LocalFiberExecutor,
        EpochId(1),
    )
    .expect("b");
    assert_eq!(oa, ob);
    assert_eq!(a.head(), b.head());
}
