#![forbid(unsafe_code)]

use ssk_crypto::HashProvider;
use ssk_types::{
    BcikStitch, BoundaryRecord, BoundaryResidue, CrossOutcome, FiberType, GateId, LocatorFacet,
    MirrorFacet, ResidueKind, ResidueRegister, SeamWitness, Severity, StitchCandidate, StitchId,
};

/// External null reference (Master Spec Ω+1 ch. 9.1's `Z`) — a marker
/// distinguishing "no externally observable locator" from a real one. Phase 2
/// placeholder: crate-internal, not part of `Bcik`'s public API surface.
#[derive(Debug, Clone, Copy, Default)]
struct NullRef;

/// The boundary operator (ch. 9.1's `partial-d`). Phase 2 placeholder —
/// carries no state yet; boundary evaluation is currently a pure function of
/// `cross()`'s own inputs.
#[derive(Debug, Clone, Copy, Default)]
struct BoundaryOperator;

/// The seam interface (ch. 9.1's `Sigma`). Phase 2 placeholder, same
/// disclosure as `BoundaryOperator`.
#[derive(Debug, Clone, Copy, Default)]
struct SeamInterface;

/// The Boundary-Closed Invariant Kernel (Master Spec Ω+1 ch. 9.1): makes an
/// identity/locator crossing a closure object, not merely a routing
/// decision. Every crossing produces a seam witness, a boundary record, and
/// either full closure or a visible residue.
pub struct Bcik<'p> {
    _null_ref: NullRef,
    _boundary: BoundaryOperator,
    _seam: SeamInterface,
    residue: ResidueRegister,
    provider: &'p dyn HashProvider,
}

impl<'p> Bcik<'p> {
    #[must_use]
    pub fn new(provider: &'p dyn HashProvider) -> Self {
        Self {
            _null_ref: NullRef,
            _boundary: BoundaryOperator,
            _seam: SeamInterface,
            residue: ResidueRegister::new(),
            provider,
        }
    }

    #[must_use]
    pub fn residue_register(&self) -> &ResidueRegister {
        &self.residue
    }

    /// Cross the seam. Either returns a closed stitch OR a boundary residue;
    /// never a silent success and never a silent drop (ch. 9.1's "no silent
    /// crossing" invariant — `CrossOutcome` has no unit success variant).
    ///
    /// S1 item 1 (Wiring by Construction, spec section 21): closure is no
    /// longer decided from the two structural booleans alone. Once
    /// `candidate.seam_ok && candidate.boundary_complete` hold, this records
    /// a real [`ssk_imdf::closure::OrientationPass`] — built from data this
    /// call already has honestly in hand: the seam witness digest this
    /// function computes below, and the candidate's own canonical self-class
    /// digest — into the caller-owned `closure` accumulator, and evaluates it
    /// **inside this call**, in the same statement. The `ClosureReport` that
    /// decides `Closed` vs `Residue` can therefore only ever be the fresh
    /// result of this crossing's own evaluation, never a detached,
    /// hand-constructible value passed in from outside.
    ///
    /// Because [`ssk_imdf::closure::FourPiClosure::evaluate`] requires two
    /// agreeing passes (Satz 12.4: a single 2π turn is a residual pole, not a
    /// closure), **the first-ever crossing of a fresh `closure` accumulator
    /// can never return `Closed`** even when `seam_ok`/`boundary_complete`
    /// both hold — this is the honest 4π-closure contract, not a regression.
    /// The caller is responsible for reusing the *same* `closure` across
    /// repeated crossings of the same seam so a genuine second pass can ever
    /// be recorded (S1 leaves that cross-call plumbing to the runtime layer;
    /// see the design's "real plumbing gap" note).
    ///
    /// Phase 2 scope carried forward unchanged: real per-fiber invariant
    /// checking is Phase 3's `FiberGate` job, not this kernel's, and the
    /// `&Policy` parameter the PDF's signature carries is still dropped since
    /// no real policy-driven crossing logic exists yet.
    pub fn cross(
        &mut self,
        facet: &MirrorFacet,
        loc: &LocatorFacet,
        fiber: FiberType,
        candidate: &StitchCandidate,
        closure: &mut ssk_imdf::closure::FourPiClosure,
    ) -> CrossOutcome {
        if candidate.seam_ok && candidate.boundary_complete {
            let seam_bytes = self
                .provider
                .digest(format!("{}:{}:{fiber:?}", facet.id.0.to_hex(), loc.id.0 .0).as_bytes());
            // Pre-existing N-BCIK-16 defect (all-zero fallback on a hash that
            // cannot actually fail): unchanged here, S2 scope.
            let seam_array: [u8; 32] = seam_bytes.try_into().unwrap_or([0u8; 32]);
            let seam_digest = ssk_types::Digest(seam_array);
            let seam = SeamWitness(seam_digest);

            // The canonical self-class digest at this pass (Satz 12.4's
            // second conjunct input) — an honest reading of "[S]_can", not an
            // invented stand-in: `CoreNode::canonical` already is the
            // crossing identity's canonical form.
            let anchor_class =
                ssk_types::digest_of(&candidate.core.canonical, ssk_types::HashAlg::Blake3)
                    .unwrap_or(ssk_types::Digest::GENESIS);
            closure.record_pass(ssk_imdf::closure::OrientationPass::new(
                seam_digest,
                anchor_class,
            ));
            let report = closure.evaluate();

            match report.state {
                ssk_imdf::closure::ClosureState::Closed => {
                    let stitch = BcikStitch {
                        id: StitchId::new(format!(
                            "stitch:{}:{}",
                            facet.id.0.to_hex(),
                            loc.id.0 .0
                        )),
                        facet: facet.id,
                        locator: loc.id.clone(),
                        fiber,
                        phase: facet.phase.clone(),
                        capability: candidate.capability.as_ref().map(|c| c.id),
                        seam,
                        boundary: BoundaryRecord {
                            closed: true,
                            detail: "seam and boundary both closed".into(),
                        },
                        residues: Vec::new(),
                        gate_report: None,
                        trace: facet.trace.clone(),
                        replay: ssk_types::ReplayRef::new(format!(
                            "replay:{}",
                            facet.id.0.to_hex()
                        )),
                    };
                    CrossOutcome::Closed(stitch)
                }
                ssk_imdf::closure::ClosureState::Open => {
                    // S1 item 3: Gegenhorizontmasse enters the real
                    // ResidueRegister below via `self.residue.emit`, using an
                    // already-defined, under-used taxonomy member
                    // (`FieldProjection`) rather than a new concept, and kept
                    // distinct from the plain "not yet closed" case so the
                    // message names the invariant that actually failed.
                    let (kind, detail) = if let Some(gegenhorizont) = &report.gegenhorizont {
                        (
                            ResidueKind::FieldProjection,
                            format!(
                                "BCIK crossing not 4\u{3c0}-closed: orientation returned but \
                                 self-class drifted (Gegenhorizontmasse): {}",
                                gegenhorizont.detail
                            ),
                        )
                    } else {
                        (
                            ResidueKind::Boundary,
                            format!(
                                "BCIK crossing not 4\u{3c0}-closed: {} orientation pass(es) recorded",
                                closure.pass_count()
                            ),
                        )
                    };
                    let residue = BoundaryResidue::new(
                        ssk_types::ResidueId::new(format!("residue:{}", candidate.id.0 .0)),
                        kind,
                        GateId::Bcik,
                        detail,
                        Severity::Critical,
                        facet.trace.clone(),
                        true,
                    );
                    self.residue.emit(residue.clone());
                    CrossOutcome::Residue(residue)
                }
            }
        } else {
            let residue = BoundaryResidue::new(
                ssk_types::ResidueId::new(format!("residue:{}", candidate.id.0 .0)),
                ResidueKind::Boundary,
                GateId::Bcik,
                "BCIK crossing not boundary-closed",
                Severity::Critical,
                facet.trace.clone(),
                true,
            );
            self.residue.emit(residue.clone());
            CrossOutcome::Residue(residue)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_crypto::Blake3HashProvider;
    use ssk_types::*;

    fn candidate(seam_ok: bool, boundary_complete: bool) -> StitchCandidate {
        StitchCandidate {
            id: StitchId::new("s1"),
            run: RunId::new("r1"),
            core: CoreNode {
                id: CoreId::new("c1"),
                canonical: CanonicalForm("n".into()),
                signature: CoreSignature(vec![1, 2, 3]),
                policy_root: PolicyId::new("p1"),
                replay_root: ReplayRoot::new("rr"),
                audit_root: AuditRoot::new("ar"),
                closure: ClosureState::Closed,
            },
            facet: MirrorFacet {
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
            },
            locator: LocatorFacet {
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
            },
            capability: Some(CapabilityWitness {
                id: CapabilityId::of(&"bcik-test-capability", HashAlg::Blake3).expect("hash"),
                claim: CapabilityClaim("use-local-overlay".into()),
                scope: Scope {
                    action: "connect".into(),
                    facet_class: ObjectKind::Core,
                },
                issuer: IssuerRef::new("issuer-1"),
                subject_class: SubjectClass::Core,
                epoch: EpochId(0),
                expiry: Ttl(100),
                proof: ProofBytes(vec![1, 2, 3]),
                trace: TraceId::new("cap-trace"),
            }),
            seam_ok,
            boundary_complete,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 10,
        }
    }

    fn fresh_closure(trace: &str) -> ssk_imdf::closure::FourPiClosure {
        ssk_imdf::closure::FourPiClosure::new(TraceId::new(trace))
    }

    #[test]
    fn cross_returns_residue_when_open() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(false, true);
        let mut closure = fresh_closure("t-open");
        let out = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        assert!(matches!(out, CrossOutcome::Residue(_)));
    }

    // S1 item 1 (Wiring by Construction): a single pass over a fresh
    // `FourPiClosure` can never close, even when seam_ok/boundary_complete
    // both hold — Satz 12.4 requires a second, agreeing orientation pass
    // (4pi, not 2pi). This is the load-bearing new behavior the real
    // `FourPiClosure::evaluate` call introduces; it must NOT be papered over
    // by keeping the old one-call-closes assertion.
    #[test]
    fn a_single_pass_over_a_fresh_closure_is_residue_not_closed_even_when_seam_and_boundary_hold() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(true, true);
        let mut closure = fresh_closure("t-single-pass");
        let out = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        assert!(
            matches!(out, CrossOutcome::Residue(_)),
            "a lone 2pi orientation pass must not be mistaken for 4pi closure"
        );
        assert_eq!(closure.pass_count(), 1);
    }

    // The rewritten two-pass contract: the first crossing of a fresh seam is
    // a residue (see the test above); only a SECOND crossing that reuses the
    // same `closure` accumulator, over the same facet/locator/fiber/candidate
    // (so both orientation passes genuinely agree), returns Closed. This
    // replaces the old, pre-Pi-Seam single-call assertion, which described
    // the wrong (two-boolean-only) contract.
    #[test]
    fn cross_returns_a_closed_stitch_with_populated_fields_when_seam_and_boundary_hold_over_two_agreeing_passes(
    ) {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(true, true);
        let mut closure = fresh_closure("t-two-pass");

        let first = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        assert!(
            matches!(first, CrossOutcome::Residue(_)),
            "first pass: orientation has not returned yet"
        );

        let second = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        match second {
            CrossOutcome::Closed(stitch) => {
                assert_eq!(stitch.facet, sc.facet.id);
                assert_eq!(stitch.locator, sc.locator.id);
                assert!(stitch.boundary.closed);
                assert!(stitch.capability.is_some());
            }
            CrossOutcome::Residue(_) => panic!("expected Closed on the second, agreeing pass"),
        }
        assert_eq!(closure.pass_count(), 2);
    }

    #[test]
    fn residue_from_an_open_crossing_is_recorded_in_the_register() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(false, true);
        let mut closure = fresh_closure("t-register");
        let _ = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        assert_eq!(bcik.residue_register().entries().len(), 1);
        assert_eq!(bcik.residue_register().open_obligations().count(), 1);
    }

    // S1 item 3: the "orientation returned but self-class drifted"
    // (Gegenhorizontmasse) case is distinguishable in the register from the
    // plain "orientation has not returned yet" case, via `ResidueKind`.
    #[test]
    fn gegenhorizontmasse_uses_field_projection_kind_distinct_from_plain_open_residue() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);

        // Two crossings whose seam digest agrees (oriented_return true) but
        // whose canonical self-class differs (self_class_preserved false) —
        // the seam key is (facet.id, loc.id, fiber), so keeping those fixed
        // while changing `core.canonical` isolates the drift.
        let mut sc = candidate(true, true);
        sc.core.canonical = CanonicalForm("class-a".into());
        let mut closure = fresh_closure("t-gegenhorizont");
        let first = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        assert!(matches!(first, CrossOutcome::Residue(_)));

        sc.core.canonical = CanonicalForm("class-b".into());
        let second = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc, &mut closure);
        match second {
            CrossOutcome::Residue(residue) => {
                assert_eq!(
                    residue.kind,
                    ResidueKind::FieldProjection,
                    "a drifted self-class after orientation return must be visible as \
                     Gegenhorizontmasse (FieldProjection), not a plain Boundary residue"
                );
            }
            CrossOutcome::Closed(_) => panic!("self-class drifted, must not close"),
        }
    }
}
