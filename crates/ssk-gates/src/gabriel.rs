//! Gabriel Constraint Cells (Master Spec Ω+1 ch. 10). Local, advisory
//! constraint evaluators over the seam and PCH cells. They are not
//! authorities and hold no persistence rights: a cell may propose, hold,
//! refine, reject or quarantine a local candidate, but only the global gate
//! vector can authorize a tensor mutation.

use ssk_types::StitchCandidate;

/// A short human-readable reason attached to a non-`Propose` verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(pub String);

/// A short human-readable refinement hint (ch. 10, verbatim `Refine(Hint)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hint(pub String);

/// Which concern a cell evaluates (ch. 10, verbatim 9 variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellRole {
    Identity,
    Locator,
    Protocol,
    Timing,
    Risk,
    Capability,
    Boundary,
    Replay,
    Focus,
}

/// A cell's verdict on one local evaluation (ch. 10, verbatim variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellVerdict {
    Propose,
    Hold(Reason),
    Refine(Hint),
    Reject(Reason),
    Quarantine(Reason),
}

/// A bounded local view a cell evaluates against (ch. 10's `LocalView`).
/// Phase 3 placeholder — cells here evaluate directly against the candidate,
/// so this carries no fields yet; it exists so the trait's real signature
/// (matching the PDF exactly) is in place for a richer view later.
#[derive(Debug, Clone, Copy, Default)]
pub struct LocalView;

/// Phase 3 placeholder for the real `ssk-config::Policy` collaborator — same
/// disclosed pattern as `ssk_core::connection::Policy` (Phase 0).
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy;

/// `fn evaluate(&self, cand, view, p) -> CellVerdict` (ch. 10, verbatim).
/// Enforced by the signature itself: a cell receives only `&self` and shared
/// references, so it cannot mutate persistent runtime state (ch. 10's
/// "cellular non-persistence" contract).
pub trait ConstraintCell: Send + Sync {
    fn role(&self) -> CellRole;
    fn evaluate(&self, cand: &StitchCandidate, view: &LocalView, p: &Policy) -> CellVerdict;
}

macro_rules! simple_cell {
    ($name:ident, $role:expr, $check:expr, $on_fail:expr) => {
        pub struct $name;
        impl ConstraintCell for $name {
            fn role(&self) -> CellRole {
                $role
            }

            fn evaluate(
                &self,
                cand: &StitchCandidate,
                _view: &LocalView,
                _p: &Policy,
            ) -> CellVerdict {
                if $check(cand) {
                    CellVerdict::Propose
                } else {
                    $on_fail
                }
            }
        }
    };
}

simple_cell!(
    IdentityCell,
    CellRole::Identity,
    |c: &StitchCandidate| c.core.signature.is_present(),
    CellVerdict::Reject(Reason("core signature missing".into()))
);
simple_cell!(
    LocatorCell,
    CellRole::Locator,
    |c: &StitchCandidate| c.locator.trusted,
    CellVerdict::Hold(Reason("locator not yet trusted".into()))
);
simple_cell!(
    ProtocolCell,
    CellRole::Protocol,
    |_c: &StitchCandidate| true, // Phase 3 placeholder: no fiber-invariant model yet.
    CellVerdict::Hold(Reason("protocol invariant unmodeled".into()))
);
simple_cell!(
    TimingCell,
    CellRole::Timing,
    |c: &StitchCandidate| c.ttl_epoch > 0,
    CellVerdict::Refine(Hint("assign a non-zero ttl epoch".into()))
);
simple_cell!(
    RiskCell,
    CellRole::Risk,
    |c: &StitchCandidate| c.locator.risk_score <= 80,
    CellVerdict::Quarantine(Reason("locator risk score above cell tolerance".into()))
);
simple_cell!(
    CapabilityCell,
    CellRole::Capability,
    |c: &StitchCandidate| c.capability.is_some(),
    CellVerdict::Reject(Reason("no capability witness present".into()))
);
simple_cell!(
    BoundaryCell,
    CellRole::Boundary,
    |c: &StitchCandidate| c.boundary_complete,
    CellVerdict::Hold(Reason("boundary not yet complete".into()))
);
simple_cell!(
    ReplayCell,
    CellRole::Replay,
    |c: &StitchCandidate| c.replay_ready,
    CellVerdict::Refine(Hint("attach a replay witness".into()))
);
simple_cell!(
    FocusCell,
    CellRole::Focus,
    |c: &StitchCandidate| c.focus_ready,
    CellVerdict::Hold(Reason("focus recovery not yet ready".into()))
);

/// The Gabriel film: all active cells at a phase state (ch. 10, verbatim).
pub struct GabrielFilm {
    cells: Vec<Box<dyn ConstraintCell>>,
}

impl Default for GabrielFilm {
    /// The nine real per-role cells above.
    fn default() -> Self {
        Self {
            cells: vec![
                Box::new(IdentityCell),
                Box::new(LocatorCell),
                Box::new(ProtocolCell),
                Box::new(TimingCell),
                Box::new(RiskCell),
                Box::new(CapabilityCell),
                Box::new(BoundaryCell),
                Box::new(ReplayCell),
                Box::new(FocusCell),
            ],
        }
    }
}

impl GabrielFilm {
    #[must_use]
    pub fn evaluate_all(&self, cand: &StitchCandidate, p: &Policy) -> Vec<CellVerdict> {
        let view = LocalView;
        self.cells
            .iter()
            .map(|c| c.evaluate(cand, &view, p))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::*;

    fn candidate() -> StitchCandidate {
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
                id: CapabilityId::of(&"gabriel-test-capability", HashAlg::Blake3).expect("hash"),
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
            seam_ok: true,
            boundary_complete: true,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 1,
        }
    }

    #[test]
    fn intact_candidate_proposes_on_all_nine_cells() {
        let film = GabrielFilm::default();
        let verdicts = film.evaluate_all(&candidate(), &Policy);
        assert_eq!(verdicts.len(), 9);
        assert!(verdicts.iter().all(|v| matches!(v, CellVerdict::Propose)));
    }

    #[test]
    fn missing_capability_yields_a_reject_verdict() {
        let film = GabrielFilm::default();
        let mut sc = candidate();
        sc.capability = None;
        let verdicts = film.evaluate_all(&sc, &Policy);
        assert!(verdicts.iter().any(|v| matches!(v, CellVerdict::Reject(_))));
    }

    #[test]
    fn high_risk_yields_a_quarantine_verdict() {
        let film = GabrielFilm::default();
        let mut sc = candidate();
        sc.locator.risk_score = 95;
        let verdicts = film.evaluate_all(&sc, &Policy);
        assert!(verdicts
            .iter()
            .any(|v| matches!(v, CellVerdict::Quarantine(_))));
    }
}
