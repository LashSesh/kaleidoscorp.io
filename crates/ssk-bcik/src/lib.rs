#![forbid(unsafe_code)]

use ssk_types::{BoundaryResidue, GateId, Id, ResidueId, ResidueKind, StitchCandidate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossOutcome {
    Closed,
    Residue(BoundaryResidue),
}

#[must_use]
pub fn cross(candidate: &StitchCandidate) -> CrossOutcome {
    if candidate.seam_ok && candidate.boundary_complete {
        CrossOutcome::Closed
    } else {
        CrossOutcome::Residue(BoundaryResidue {
            id: ResidueId(Id::new(format!("residue:{}", candidate.id.0 .0))),
            kind: ResidueKind::Boundary,
            source_gate: GateId::Bcik,
            detail: "BCIK crossing not boundary-closed".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            locator: Locator {
                id: LocatorId::new("l1"),
                locator_type: LocatorType::LocalOverlay,
                trusted: true,
                risk_score: 1,
            },
            capability_witness: true,
            seam_ok,
            boundary_complete,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 10,
        }
    }

    #[test]
    fn cross_returns_residue_when_open() {
        let out = cross(&candidate(false, true));
        assert!(matches!(out, CrossOutcome::Residue(_)));
    }
}
