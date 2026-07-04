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
    /// Phase 2 scope: closure is decided from `candidate.seam_ok`/
    /// `boundary_complete` — real per-fiber invariant checking is Phase 3's
    /// `FiberGate` job, not this kernel's. The `&Policy` parameter the PDF's
    /// signature carries is dropped here since no real policy-driven
    /// crossing logic exists yet (nothing would read it); it can be added
    /// back once `ssk-config`'s policy model is threaded through gates.
    pub fn cross(
        &mut self,
        facet: &MirrorFacet,
        loc: &LocatorFacet,
        fiber: FiberType,
        candidate: &StitchCandidate,
    ) -> CrossOutcome {
        if candidate.seam_ok && candidate.boundary_complete {
            let seam_bytes = self
                .provider
                .digest(format!("{}:{}:{fiber:?}", facet.id.0.to_hex(), loc.id.0 .0).as_bytes());
            let seam_array: [u8; 32] = seam_bytes.try_into().unwrap_or([0u8; 32]);
            let seam = SeamWitness(ssk_types::Digest(seam_array));
            let stitch = BcikStitch {
                id: StitchId::new(format!("stitch:{}:{}", facet.id.0.to_hex(), loc.id.0 .0)),
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
                replay: ssk_types::ReplayRef::new(format!("replay:{}", facet.id.0.to_hex())),
            };
            CrossOutcome::Closed(stitch)
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
                orientation: Orientation::Forward,
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

    #[test]
    fn cross_returns_residue_when_open() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(false, true);
        let out = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc);
        assert!(matches!(out, CrossOutcome::Residue(_)));
    }

    #[test]
    fn cross_returns_a_closed_stitch_with_populated_fields_when_seam_and_boundary_hold() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(true, true);
        let out = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc);
        match out {
            CrossOutcome::Closed(stitch) => {
                assert_eq!(stitch.facet, sc.facet.id);
                assert_eq!(stitch.locator, sc.locator.id);
                assert!(stitch.boundary.closed);
                assert!(stitch.capability.is_some());
            }
            CrossOutcome::Residue(_) => panic!("expected Closed"),
        }
    }

    #[test]
    fn residue_from_an_open_crossing_is_recorded_in_the_register() {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        let sc = candidate(false, true);
        let _ = bcik.cross(&sc.facet, &sc.locator, FiberType::Data, &sc);
        assert_eq!(bcik.residue_register().entries().len(), 1);
        assert_eq!(bcik.residue_register().open_obligations().count(), 1);
    }
}
