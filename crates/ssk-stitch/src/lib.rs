#![forbid(unsafe_code)]

use ssk_types::{
    ConnectionIntent, FacetOrientation, HealthStatus, MirrorFacet, RouteClass, StitchCandidate,
    StitchId,
};

/// Whether the `facet`/`locator` crossing this candidate is about to attempt
/// is structurally sound: a real identity trace to anchor the crossing on,
/// and a locator that has actually been probed live and not already refused a
/// route. Distinct from `LocatorGate`/`LocatorProjector`/`TrustProjector`/
/// `RiskProjector` (which already gate `trusted`/`trust`/`risk_score`) —
/// `health`/`route` are read by no gate today, so this is a new fact about
/// the seam, not a second name for an axis another gate already covers.
fn seam_ok(facet: &MirrorFacet, locator: &ssk_types::LocatorFacet) -> bool {
    !facet.trace.0 .0.is_empty()
        && locator.health == HealthStatus::Live
        && locator.route != RouteClass::Denied
}

/// Whether the facet's boundary bookkeeping is fully wired: both "where this
/// crossing's boundary record lives" (`boundary`) and "where its residue
/// obligations get tracked" (`residue`) are present. Mirrors
/// `CoreSignature::is_present()`'s "non-empty bytes are the real check"
/// pattern — `BoundaryRef`/`ResidueRef` are opaque ids with no internal
/// structure to inspect beyond presence.
fn boundary_complete(facet: &MirrorFacet) -> bool {
    !facet.boundary.0 .0.is_empty() && !facet.residue.0 .0.is_empty()
}

/// Whether this crossing is genuinely replayable: a real trace to chain
/// reconstruction off, a real session id to reconstruct against, and a
/// locator whose own lifetime counter has not already reached zero.
/// Deliberately does not reuse `candidate.ttl_epoch != 0` — that is
/// `DissolutionGate`'s exact check; `locator.ttl` is a distinct field no
/// other check reads.
fn replay_ready(facet: &MirrorFacet, locator: &ssk_types::LocatorFacet) -> bool {
    !facet.trace.0 .0.is_empty() && !facet.session.0 .0.is_empty() && locator.ttl.0 > 0
}

/// Whether this facet is oriented for a fresh forward stitch, as opposed to
/// e.g. one recovered/mirrored back from a residue-recovery path.
/// `ssk_focus::refocuses` already ANDs this with the structural facet↔core
/// correspondence check, so this only needs to name the one remaining
/// `MirrorFacet` field about the facet's own relationship to its core that
/// isn't already spoken for elsewhere.
fn focus_ready(facet: &MirrorFacet) -> bool {
    facet.orientation == FacetOrientation::Forward
}

pub fn from_intent(
    intent: ConnectionIntent,
    facet: MirrorFacet,
    locator: ssk_types::LocatorFacet,
) -> StitchCandidate {
    let seam_ok = seam_ok(&facet, &locator);
    let boundary_complete = boundary_complete(&facet);
    let replay_ready = replay_ready(&facet, &locator);
    let focus_ready = focus_ready(&facet);
    StitchCandidate {
        id: StitchId::new(format!("stitch:{}:{}", intent.run.0 .0, locator.id.0 .0)),
        run: intent.run,
        core: intent.core,
        facet,
        locator,
        capability: intent.capability,
        seam_ok,
        boundary_complete,
        replay_ready,
        focus_ready,
        ttl_epoch: intent.ttl_epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_gates::{BcikGate, BoundaryGate, FocusGate, Gate, GateCtx, ReplayGate};
    use ssk_imdf::closure::FourPiClosure;
    use ssk_types::*;

    fn fresh_closure() -> FourPiClosure {
        FourPiClosure::new(TraceId::new("stitch-test-closure"))
    }

    fn sample_core() -> CoreNode {
        CoreNode {
            id: CoreId::new("c1"),
            canonical: CanonicalForm("n".into()),
            signature: CoreSignature(vec![1, 2, 3]),
            policy_root: PolicyId::new("p1"),
            replay_root: ReplayRoot::new("rr"),
            audit_root: AuditRoot::new("ar"),
            closure: ClosureState::Closed,
        }
    }

    fn sample_facet() -> MirrorFacet {
        MirrorFacet {
            id: FacetId::of(&"f1", HashAlg::Blake3).expect("hash"),
            core: CoreId::new("c1"),
            phase: PhaseVector::zero(),
            orientation: FacetOrientation::Forward,
            sector: Sector::Identity,
            key_ctx: KeyContextRef::new("kc"),
            session: SessionId::new("sess"),
            policy: PolicyId::new("p1"),
            trace: TraceId::new("tr"),
            boundary: BoundaryRef::new("bd"),
            residue: ResidueRef::new("rs"),
        }
    }

    fn sample_locator() -> LocatorFacet {
        LocatorFacet {
            id: LocatorId::new("l1"),
            kind: LocatorKind::LocalOverlay,
            endpoint: EndpointRef::new("ep1"),
            route: RouteClass::Direct,
            transport: TransportClass::Tcp,
            epoch: EpochId(0),
            ttl: Ttl(100),
            trust: TrustClass::Owned,
            cost: CostClass::Free,
            risk: RiskClass::Low,
            health: HealthStatus::Live,
            trace: TraceId::new("loc-trace"),
            trusted: true,
            risk_score: 1,
        }
    }

    fn sample_intent() -> ConnectionIntent {
        ConnectionIntent {
            run: RunId::new("r1"),
            core: sample_core(),
            target_locator: LocatorId::new("l1"),
            capability: None,
            ttl_epoch: 10,
        }
    }

    // Sanity baseline: a fully-wired facet/locator (the shape every real
    // producer in the tree — MirrorOrbit::derive, the ssk-bcik/ssk-gates test
    // fixtures — actually constructs) makes all four flags true.
    #[test]
    fn from_intent_sets_all_four_flags_true_for_a_fully_wired_facet_and_locator() {
        let sc = from_intent(sample_intent(), sample_facet(), sample_locator());
        assert!(sc.seam_ok, "seam_ok");
        assert!(sc.boundary_complete, "boundary_complete");
        assert!(sc.replay_ready, "replay_ready");
        assert!(sc.focus_ready, "focus_ready");
    }

    // --- seam_ok ---------------------------------------------------------

    #[test]
    fn seam_ok_is_false_when_facet_trace_is_empty_and_bcik_gate_rejects() {
        let mut facet = sample_facet();
        facet.trace = TraceId::new("");
        let sc = from_intent(sample_intent(), facet, sample_locator());
        assert!(!sc.seam_ok, "seam_ok must be false with an empty trace");
        assert!(
            matches!(
                BcikGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "BcikGate must reject a candidate whose seam_ok is false"
        );
    }

    #[test]
    fn seam_ok_is_false_when_locator_is_not_live_and_bcik_gate_rejects() {
        let mut locator = sample_locator();
        locator.health = HealthStatus::Down;
        let sc = from_intent(sample_intent(), sample_facet(), locator);
        assert!(!sc.seam_ok, "seam_ok must be false when locator is Down");
        assert!(
            matches!(
                BcikGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "BcikGate must reject a candidate whose locator health is not Live"
        );
    }

    #[test]
    fn seam_ok_is_false_when_locator_route_is_denied_and_bcik_gate_rejects() {
        let mut locator = sample_locator();
        locator.route = RouteClass::Denied;
        let sc = from_intent(sample_intent(), sample_facet(), locator);
        assert!(
            !sc.seam_ok,
            "seam_ok must be false when the route is Denied"
        );
        assert!(
            matches!(
                BcikGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "BcikGate must reject a candidate whose route is Denied"
        );
    }

    #[test]
    fn seam_ok_true_lets_bcik_gate_pass() {
        let sc = from_intent(sample_intent(), sample_facet(), sample_locator());
        assert!(sc.seam_ok);
        assert!(matches!(
            BcikGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
            GateVerdict::Pass(_)
        ));
    }

    // --- boundary_complete -------------------------------------------------

    #[test]
    fn boundary_complete_is_false_when_facet_boundary_is_empty_and_boundary_gate_rejects() {
        let mut facet = sample_facet();
        facet.boundary = BoundaryRef::new("");
        let sc = from_intent(sample_intent(), facet, sample_locator());
        assert!(
            !sc.boundary_complete,
            "boundary_complete must be false with an empty BoundaryRef"
        );
        assert!(
            matches!(
                BoundaryGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "BoundaryGate must reject a candidate whose boundary_complete is false"
        );
    }

    #[test]
    fn boundary_complete_is_false_when_facet_residue_is_empty_and_boundary_gate_rejects() {
        let mut facet = sample_facet();
        facet.residue = ResidueRef::new("");
        let sc = from_intent(sample_intent(), facet, sample_locator());
        assert!(
            !sc.boundary_complete,
            "boundary_complete must be false with an empty ResidueRef"
        );
        assert!(
            matches!(
                BoundaryGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "BoundaryGate must reject a candidate whose boundary_complete is false"
        );
    }

    #[test]
    fn boundary_complete_true_lets_boundary_gate_pass() {
        let sc = from_intent(sample_intent(), sample_facet(), sample_locator());
        assert!(sc.boundary_complete);
        assert!(matches!(
            BoundaryGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
            GateVerdict::Pass(_)
        ));
    }

    // --- replay_ready ------------------------------------------------------

    #[test]
    fn replay_ready_is_false_when_facet_session_is_empty_and_replay_gate_rejects() {
        let mut facet = sample_facet();
        facet.session = SessionId::new("");
        let sc = from_intent(sample_intent(), facet, sample_locator());
        assert!(
            !sc.replay_ready,
            "replay_ready must be false with an empty session id"
        );
        assert!(
            matches!(
                ReplayGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "ReplayGate must reject a candidate whose replay_ready is false"
        );
    }

    #[test]
    fn replay_ready_is_false_when_locator_ttl_is_zero_and_replay_gate_rejects() {
        let mut locator = sample_locator();
        locator.ttl = Ttl(0);
        let sc = from_intent(sample_intent(), sample_facet(), locator);
        assert!(
            !sc.replay_ready,
            "replay_ready must be false when locator.ttl is zero"
        );
        assert!(
            matches!(
                ReplayGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "ReplayGate must reject a candidate whose replay_ready is false"
        );
    }

    #[test]
    fn replay_ready_true_lets_replay_gate_pass() {
        let sc = from_intent(sample_intent(), sample_facet(), sample_locator());
        assert!(sc.replay_ready);
        assert!(matches!(
            ReplayGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
            GateVerdict::Pass(_)
        ));
    }

    // --- focus_ready ---------------------------------------------------

    #[test]
    fn focus_ready_is_false_when_facet_orientation_is_reverse_and_focus_gate_rejects() {
        let mut facet = sample_facet();
        facet.orientation = FacetOrientation::Reverse;
        let sc = from_intent(sample_intent(), facet, sample_locator());
        assert!(
            !sc.focus_ready,
            "focus_ready must be false for a Reverse-oriented facet"
        );
        assert!(
            matches!(
                FocusGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
                GateVerdict::Reject(_)
            ),
            "FocusGate must reject a candidate whose focus_ready is false"
        );
    }

    #[test]
    fn focus_ready_true_lets_focus_gate_pass() {
        let sc = from_intent(sample_intent(), sample_facet(), sample_locator());
        assert!(sc.focus_ready);
        assert!(matches!(
            FocusGate.evaluate(&sc, &GateCtx, &mut fresh_closure()),
            GateVerdict::Pass(_)
        ));
    }
}
