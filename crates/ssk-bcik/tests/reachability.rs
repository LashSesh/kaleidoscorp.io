//! Reachability integration test for S1 item 1 (Wiring by Construction,
//! spec section 21) and the S1 exit gate's "reachable from sskd ... with a
//! passing reachability test" obligation (spec section 22, "Reachability
//! obligations, not test obligations").
//!
//! This file deliberately lives outside `crates/ssk-bcik/src/lib.rs`: an
//! integration test can only reach [`Bcik::cross`] through its public API,
//! the exact same surface `ssk-gates`'s `BcikGate` and `ssk-runtime`'s
//! crossing sites drive it through — it cannot be fooled by internals a unit
//! test living beside the definition could quietly assume. A unit test
//! proving "wired" from inside the module it is meant to prove wired is
//! exactly the failure mode this whole effort exists to close.
//!
//! What this test proves: `Bcik::cross` no longer decides `CrossOutcome`
//! from `candidate.seam_ok && candidate.boundary_complete` alone (the old
//! two-boolean shortcut) — closure now requires a real
//! `ssk_imdf::closure::FourPiClosure` evaluation to say `Closed`, driven
//! through the crate's real, public entry point.
//!
//! What this test does NOT prove (named honestly, not papered over): a full
//! `sskd`-rooted path. That additionally requires the cross-crate
//! `FourPiClosure` accumulator plumbing (a `HashMap<Digest, FourPiClosure>`
//! surviving across calls, owned above `Bcik`'s per-call lifetime) in
//! `ssk-runtime`/`ssk-daemon`, which this track's file scope does not cover
//! (see the design's "real plumbing gap" and "what remains honestly
//! unresolved" sections). This test is the reachable-through-the-real-API
//! half of that obligation; the daemon-rooted half is carried forward as a
//! named follow-up.

use ssk_bcik::Bcik;
use ssk_crypto::Blake3HashProvider;
use ssk_imdf::closure::{FourPiClosure, OrientationPass};
use ssk_types::*;

fn wired_candidate(canonical: &str) -> StitchCandidate {
    StitchCandidate {
        id: StitchId::new("reach-s1"),
        run: RunId::new("reach-r1"),
        core: CoreNode {
            id: CoreId::new("reach-c1"),
            canonical: CanonicalForm(canonical.into()),
            signature: CoreSignature(vec![9, 9, 9]),
            policy_root: PolicyId::new("reach-p1"),
            replay_root: ReplayRoot::new("reach-rr"),
            audit_root: AuditRoot::new("reach-ar"),
            closure: ClosureState::Closed,
        },
        facet: MirrorFacet {
            id: FacetId::of(&"reach-f1", HashAlg::Blake3).expect("hash"),
            core: CoreId::new("reach-c1"),
            phase: PhaseVector::zero(),
            orientation: FacetOrientation::Forward,
            sector: Sector::Identity,
            key_ctx: KeyContextRef::new("reach-kc"),
            session: SessionId::new("reach-sess"),
            policy: PolicyId::new("reach-p1"),
            trace: TraceId::new("reach-tr"),
            boundary: BoundaryRef::new("reach-bd"),
            residue: ResidueRef::new("reach-rs"),
        },
        locator: LocatorFacet {
            id: LocatorId::new("reach-l1"),
            kind: LocatorKind::LocalOverlay,
            endpoint: EndpointRef::new("reach-ep1"),
            route: RouteClass::Direct,
            transport: TransportClass::Tcp,
            epoch: EpochId(0),
            ttl: Ttl(100),
            trust: TrustClass::Owned,
            cost: CostClass::Free,
            risk: RiskClass::Low,
            health: HealthStatus::Live,
            trace: TraceId::new("reach-loc-trace"),
            trusted: true,
            risk_score: 1,
        },
        capability: None,
        seam_ok: true,
        boundary_complete: true,
        replay_ready: true,
        focus_ready: true,
        ttl_epoch: 10,
    }
}

/// The single most important reachability claim of S1 item 1: `Bcik::cross`
/// — reached only through its real public API, exactly the way `ssk-gates`'s
/// `BcikGate` and `ssk-runtime`'s crossing sites reach it — cannot be closed
/// by the old two-boolean shortcut alone. A single pass over a fresh
/// `FourPiClosure`, even with `seam_ok && boundary_complete` both true, must
/// come back as `CrossOutcome::Residue`.
#[test]
fn bcik_cross_does_not_close_on_a_single_pass_even_when_seam_and_boundary_hold() {
    let provider = Blake3HashProvider;
    let mut bcik = Bcik::new(&provider);
    let sc = wired_candidate("reach-class");
    let mut closure = FourPiClosure::new(TraceId::new("reach-trace-single"));

    let outcome = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);

    assert!(
        matches!(outcome, CrossOutcome::Residue(_)),
        "a lone 2pi orientation pass must not be mistaken for real 4pi closure \
         -- if this ever returns Closed, Bcik::cross has regressed to deciding \
         closure from seam_ok/boundary_complete alone"
    );
    assert_eq!(
        closure.pass_count(),
        1,
        "the pass must have been genuinely recorded into the real accumulator"
    );
}

/// The positive reachability claim: `CrossOutcome::Closed` IS genuinely
/// reachable through `Bcik::cross`'s real public API — but only by driving a
/// second, agreeing orientation pass through the same `FourPiClosure`
/// accumulator, i.e. only via an actual `Closed` `FourPiClosure::evaluate`
/// verdict, never as a side effect of the structural booleans alone.
#[test]
fn bcik_cross_closes_only_after_a_real_four_pi_closure_evaluation_says_so() {
    let provider = Blake3HashProvider;
    let mut bcik = Bcik::new(&provider);
    let sc = wired_candidate("reach-class");
    let mut closure = FourPiClosure::new(TraceId::new("reach-trace-double"));

    let first = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
    assert!(
        matches!(first, CrossOutcome::Residue(_)),
        "sanity: the first pass alone must not close"
    );

    let second = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
    match second {
        CrossOutcome::Closed(stitch) => {
            assert_eq!(stitch.facet, sc.facet.id);
            assert_eq!(stitch.locator, sc.locator.id);
            assert!(stitch.boundary.closed);
        }
        CrossOutcome::Residue(_) => panic!(
            "expected Closed: two agreeing orientation passes over the same seam \
             and self-class is a genuine Satz 12.4 4pi closure"
        ),
    }
    assert!(
        closure.is_closed(),
        "the accumulator Bcik::cross recorded into must itself independently \
         confirm closure -- proving Bcik::cross did not fabricate the verdict \
         it reported"
    );
}

/// Negative control proving the closure decision is not reducible to either
/// input alone: an already-closed `FourPiClosure` accumulator must not let a
/// structurally unsound candidate (`seam_ok == false`) cross. `Bcik::cross`
/// must require both the structural check AND a real closure evaluation, not
/// substitute one for the other.
#[test]
fn bcik_cross_still_rejects_a_structurally_unsound_candidate_even_with_an_already_closed_closure() {
    let provider = Blake3HashProvider;
    let mut bcik = Bcik::new(&provider);
    let mut sc = wired_candidate("reach-class");
    sc.seam_ok = false;
    let mut closure = FourPiClosure::new(TraceId::new("reach-trace-unsound"));

    // Pre-close the accumulator via two genuine, agreeing passes (simulating
    // a closure already established for this seam by prior crossings).
    let digest = digest_of(&"reach-fixed-digest", HashAlg::Blake3).unwrap();
    let class = digest_of(&sc.core.canonical, HashAlg::Blake3).unwrap();
    closure.record_pass(OrientationPass::new(digest, class));
    closure.record_pass(OrientationPass::new(digest, class));
    assert!(
        closure.is_closed(),
        "sanity: the accumulator itself is closed"
    );

    let outcome = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
    assert!(
        matches!(outcome, CrossOutcome::Residue(_)),
        "an already-closed FourPiClosure must not let a structurally unsound \
         seam/boundary crossing through -- Bcik::cross must require both \
         conjuncts, not either"
    );
}
