//! Reachability integration test for S1's completion (docs/BCIK_IMPLEMENTATION_SPEC.md
//! Teil VII, spec section 22's "reachability obligations, not test obligations"): proves
//! `CrossOutcome::Closed` is genuinely reachable through `ssk-runtime`'s real, public
//! `run_to_outcome` entry point -- not merely inside `ssk-bcik`'s own unit tests beside
//! `Bcik::cross`'s definition.
//!
//! Corrected claim (verified by direct grep of `ssk-daemon`'s source tree, zero matches
//! for `run_to_outcome`/`ssk_runtime`/`GateVector`/`Bcik::`): `sskd`'s supervisor does
//! **not** call into this pipeline at all today. As of `docs/adr/0008-flow-path-owns-the-
//! per-connection-decision.md`, it no longer depends on `ssk-gates` in any form, not even
//! transitively -- that one edge (`ssk-config`'s former use of `ssk_gates::pch::Axis`) was
//! severed by relocating `Axis` into `ssk-types`, which also settled the architecture
//! question this comment used to leave open: the per-connection decision path is
//! `ssk-netadmin`'s `FlowDescriptor -> PolicyEngine -> RouteOrchestrator -> RouteExecutor`
//! spine, not this one. The only real production caller of `run_to_outcome` anywhere in
//! the workspace is `ssk-cli`'s `connect_command` (`main.rs:4030`), and even that call
//! passes a hardcoded `sample_intent(valid_fixture)` rather than a caller-supplied
//! `ConnectionIntent`. This is a real, pre-existing architectural fact -- not something S1
//! introduced or was scoped to close -- recorded in `docs/BCIK_IMPLEMENTATION_SPEC.md`
//! Teil VII's S1 status and resolved by ADR 0008. This test proves the mechanism is
//! reachable and load-bearing through `ssk-runtime`'s own public API; it does not, and by
//! design now never will, prove reachability from `sskd`'s live, running daemon process.
//!
//! What makes this an honest positive proof rather than a restated unit test: it drives
//! the *whole* pipeline (`execute_pipeline` -> `GateVector::evaluate` -> `BcikGate`'s real
//! pre-check crossing -> `run_to_outcome`'s own real materialization crossing) through
//! `run_to_outcome`'s public signature only, and asserts on the real, already-existing
//! public outcome: a `RunOutcome::Pass` carrying a materialized stitch that is actually
//! present in the tensor with its gate report attached -- never by inspecting the internal
//! `FourPiClosure` accumulator's state directly (this test cannot see it; `run_to_outcome`
//! does not expose it).
//!
//! The mechanism this proves reachable: `execute_pipeline` builds one `FourPiClosure` per
//! candidate and hands it to `GateVector::evaluate`, whose `BcikGate` entry performs a
//! real first orientation pass over the seam, unconditionally, for every candidate, before
//! any other gate runs (`GateVector::evaluate` has no early exit -- "every gate, always").
//! If (and only if) the whole gate vector passes, `run_to_outcome` performs its own,
//! separate crossing over the *same* `facet`/`locator`/`FiberType::Data` identity, reusing
//! that same accumulator -- a genuine, non-fabricated second pass that Satz 12.4 allows to
//! close. Because `BcikGate` always runs first and unconditionally, `run_to_outcome`'s own
//! crossing is *never* reachable on a lone first pass -- by the time it runs at all, the
//! accumulator already holds `BcikGate`'s real pass. A candidate that forces `evaluate()`
//! to report `Closed` unconditionally is therefore invisible to this test not from a
//! coverage gap, but because the reachable control flow structurally cannot present
//! `Bcik::cross` with fewer than two real passes before a `Closed` verdict can affect any
//! observable outcome; the "lone pass is `Residue`, not `Closed`" invariant itself remains
//! covered at `ssk-bcik`'s own crate boundary (`crates/ssk-bcik/tests/reachability.rs`).

use ssk_gates::GateVector;
use ssk_locator::StaticLocatorPool;
use ssk_runtime::{
    run_to_outcome, sample_intent, DeterminismContext, LocalFiberExecutor, RunOutcome,
};
use ssk_types::{
    CostClass, EndpointRef, EpochId, HealthStatus, LocatorFacet, LocatorId, LocatorKind, RiskClass,
    RouteClass, TraceId, TransportClass, TrustClass, Ttl,
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

fn fresh_stitch_tensor() -> ssk_tensor::StitchTensor {
    ssk_tensor::StitchTensor::open(Box::new(ssk_tensor::GenericMemoryBackend::<
        ssk_types::StitchTensorEntry,
    >::new()))
    .expect("open")
}

/// The positive reachability claim: a real `ConnectionIntent`, driven only through
/// `run_to_outcome`'s public API, produces `RunOutcome::Pass` with a stitch genuinely
/// materialized in the tensor and carrying its gate report -- proof that `BcikGate`'s
/// real pre-check crossing and `run_to_outcome`'s own real materialization crossing
/// shared one `FourPiClosure` and closed on a genuine second, agreeing pass.
#[test]
fn run_to_outcome_reaches_a_genuinely_closed_bcik_crossing_through_the_public_api() {
    let pool = pool();
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
    .expect("run_to_outcome should execute for a valid intent");

    let materialized_id = match outcome {
        RunOutcome::Pass { stitches, .. } => {
            assert_eq!(
                stitches.len(),
                1,
                "a genuinely closed crossing materializes exactly one stitch"
            );
            stitches[0].clone()
        }
        RunOutcome::HoldRefine { residues } => {
            panic!("expected RunOutcome::Pass, got HoldRefine({residues:?})")
        }
        RunOutcome::DissolveRejectQuarantine { residues, .. } => panic!(
            "expected RunOutcome::Pass, got DissolveRejectQuarantine({residues:?}) -- \
             the BCIK crossing did not close, so the shared-FourPiClosure wiring is broken"
        ),
    };

    // The tensor genuinely mutated -- not a fabricated success value.
    assert_eq!(
        tensor.graph().len(),
        1,
        "the closed stitch must be real, persisted state, not just a returned value"
    );
    let stitch = tensor
        .graph()
        .get(&materialized_id)
        .expect("the materialized id must resolve to a real stitch in the tensor");
    assert!(
        stitch.gate_report.is_some(),
        "SSK\u{3a9}-3: every real crossing carries its gate report"
    );
}

/// Negative control: a structurally invalid intent (unsigned core) must never reach a
/// closed crossing -- the gate vector rejects before either BCIK crossing (BcikGate's
/// pre-check, run_to_outcome's own materialization) can even run, so the tensor stays
/// empty. Proves the positive test above is not vacuously true.
#[test]
fn run_to_outcome_does_not_close_or_materialize_on_a_rejected_candidate() {
    let pool = pool();
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
    .expect("run_to_outcome should execute even for an invalid intent");

    assert!(matches!(
        outcome,
        RunOutcome::DissolveRejectQuarantine { .. }
    ));
    assert_eq!(tensor.head(), head_before, "fail-closed: no mutation");
    assert!(tensor.graph().is_empty());
}
