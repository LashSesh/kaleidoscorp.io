//! Projective Connection Hypercube (Master Spec Ω+1 ch. 8). A stitch
//! candidate is a point in the product space of connection axes, and it
//! must project consistently onto every required axis. The PDF's own repo
//! blueprint is silent on which crate owns this — landing it in `ssk-gates`
//! (this module) is a deliberate, disclosed choice: `HypercubeGate` is its
//! sole consumer (see `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` Section I).

use ssk_types::{BoundaryRef, ResidueRef, StitchCandidate, TraceId, TrustClass};

/// The nine axes of the hypercube (ch. 8.1, verbatim). Serde derives added
/// in Phase 8 so `ssk-config`'s `projective_connection_hypercube.axes` list
/// (Section S) can reuse this type directly instead of duplicating it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    Identity,
    Locator,
    Protocol,
    Timing,
    Trust,
    Risk,
    Capability,
    Replay,
    Boundary,
}

/// A confidence weight for a passing projection (ch. 8.1). Phase 3
/// placeholder scale (0-100).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxisWeight(pub u8);

/// A short human-readable reason attached to a failing/holding projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(pub String);

/// The projection of a candidate onto one axis (ch. 8.1, verbatim variants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    Ok(AxisWeight),
    Undefined,
    Inconsistent(Reason),
    /// Yields `Hold`, not `Fail` (ch. 8.2's invariant).
    OverBudget(Reason),
    ReplayGap(Reason),
}

/// A point (or path) in the product space of connection axes (ch. 8.1,
/// verbatim field list). Phase 3 placeholder — not yet consumed by
/// `Hypercube::check`, which works directly over `Projection`s; this exists
/// so the PDF's own type surface is present and testable.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectionCell {
    pub addr: CellAddr,
    pub weight: CellWeight,
    pub constraints: Vec<Constraint>,
    pub gate: GateStatus,
    pub boundary: BoundaryRef,
    pub trace: TraceId,
    pub residue: ResidueRef,
}

/// One coordinate per axis (ch. 8.1's `CellAddr`). Phase 3 placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CellAddr(pub [u32; 9]);

/// `(mass, coherence, phase_ready, risk, ...)` per ch. 8.1's comment on
/// `ConnectionCell.weight`. Phase 3 placeholder.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CellWeight {
    pub mass: f32,
    pub coherence: f32,
    pub phase_ready: bool,
    pub risk: f32,
}

/// A named constraint attached to a cell. Phase 3 placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint(pub String);

/// A cell's own gate status (ch. 8.1's `GateStatus`). Phase 3 placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Unevaluated,
    Pass,
    Hold,
    Reject,
}

/// Outcome of checking a candidate against every axis (ch. 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PchOutcome {
    Pass,
    Hold { axis: Axis, reason: String },
    Fail { axis: Axis, reason: String },
}

/// `fn project(&self, sc: &StitchCandidate) -> Projection` (ch. 8.2, verbatim).
pub trait AxisProjector: Send + Sync {
    fn axis(&self) -> Axis;
    fn project(&self, sc: &StitchCandidate) -> Projection;
}

macro_rules! simple_projector {
    ($name:ident, $axis:expr, $check:expr, $on_fail:expr) => {
        struct $name;
        impl AxisProjector for $name {
            fn axis(&self) -> Axis {
                $axis
            }

            fn project(&self, sc: &StitchCandidate) -> Projection {
                if $check(sc) {
                    Projection::Ok(AxisWeight(100))
                } else {
                    $on_fail
                }
            }
        }
    };
}

simple_projector!(
    IdentityProjector,
    Axis::Identity,
    |sc: &StitchCandidate| sc.core.signature.is_present() && sc.facet.core == sc.core.id,
    Projection::Undefined
);
simple_projector!(
    LocatorProjector,
    Axis::Locator,
    |sc: &StitchCandidate| sc.locator.trusted,
    Projection::Inconsistent(Reason("locator not trusted".into()))
);
simple_projector!(
    ProtocolProjector,
    Axis::Protocol,
    |_sc: &StitchCandidate| true, // Phase 3 placeholder: no fiber-invariant model yet (see FiberGate).
    Projection::Undefined
);
simple_projector!(
    TimingProjector,
    Axis::Timing,
    |sc: &StitchCandidate| sc.ttl_epoch > 0,
    Projection::Undefined
);
simple_projector!(
    TrustProjector,
    Axis::Trust,
    |sc: &StitchCandidate| sc.locator.trust != TrustClass::Untrusted,
    Projection::Inconsistent(Reason("locator trust class is Untrusted".into()))
);
simple_projector!(
    RiskProjector,
    Axis::Risk,
    |sc: &StitchCandidate| sc.locator.risk_score <= 70,
    Projection::OverBudget(Reason("locator risk score exceeds 70".into()))
);
simple_projector!(
    CapabilityProjector,
    Axis::Capability,
    |sc: &StitchCandidate| sc.capability.is_some(),
    Projection::Undefined
);
simple_projector!(
    ReplayProjector,
    Axis::Replay,
    |sc: &StitchCandidate| sc.replay_ready,
    Projection::ReplayGap(Reason("replay witness missing".into()))
);
simple_projector!(
    BoundaryProjector,
    Axis::Boundary,
    |sc: &StitchCandidate| sc.boundary_complete && sc.seam_ok,
    Projection::Inconsistent(Reason("boundary/seam not closed".into()))
);

/// `Hypercube { projectors: [Box<dyn AxisProjector>; 9] }` (ch. 8.2, verbatim).
pub struct Hypercube {
    projectors: [Box<dyn AxisProjector>; 9],
}

impl Default for Hypercube {
    /// The nine real per-axis projectors above, in the PDF's own axis order.
    fn default() -> Self {
        Self {
            projectors: [
                Box::new(IdentityProjector),
                Box::new(LocatorProjector),
                Box::new(ProtocolProjector),
                Box::new(TimingProjector),
                Box::new(TrustProjector),
                Box::new(RiskProjector),
                Box::new(CapabilityProjector),
                Box::new(ReplayProjector),
                Box::new(BoundaryProjector),
            ],
        }
    }
}

impl Hypercube {
    /// Invariant — projection consistency (ch. 8.2, verbatim): a candidate
    /// may not pass PCH if any required axis projection is undefined,
    /// contradictory, or non-replayable. `OverBudget` yields `Hold`
    /// (diagnosable, non-persistent); all other failures yield `Fail` with a
    /// typed residue.
    #[must_use]
    pub fn check(&self, sc: &StitchCandidate) -> PchOutcome {
        for p in &self.projectors {
            match p.project(sc) {
                Projection::Ok(_) => continue,
                Projection::Undefined => {
                    return PchOutcome::Fail {
                        axis: p.axis(),
                        reason: "undefined".into(),
                    }
                }
                Projection::Inconsistent(r) => {
                    return PchOutcome::Fail {
                        axis: p.axis(),
                        reason: r.0,
                    }
                }
                Projection::ReplayGap(r) => {
                    return PchOutcome::Fail {
                        axis: p.axis(),
                        reason: r.0,
                    }
                }
                Projection::OverBudget(r) => {
                    return PchOutcome::Hold {
                        axis: p.axis(),
                        reason: r.0,
                    }
                }
            }
        }
        PchOutcome::Pass
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
                id: CapabilityId::of(&"pch-test-capability", HashAlg::Blake3).expect("hash"),
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
    fn intact_candidate_passes_all_nine_axes() {
        let cube = Hypercube::default();
        assert_eq!(cube.check(&candidate()), PchOutcome::Pass);
    }

    #[test]
    fn undefined_axis_fails_not_holds() {
        let cube = Hypercube::default();
        let mut sc = candidate();
        sc.capability = None; // Capability axis -> Undefined
        assert!(matches!(
            cube.check(&sc),
            PchOutcome::Fail {
                axis: Axis::Capability,
                ..
            }
        ));
    }

    #[test]
    fn over_budget_risk_holds_rather_than_fails() {
        let cube = Hypercube::default();
        let mut sc = candidate();
        sc.locator.risk_score = 90;
        assert!(matches!(
            cube.check(&sc),
            PchOutcome::Hold {
                axis: Axis::Risk,
                ..
            }
        ));
    }

    #[test]
    fn broken_seam_fails_the_boundary_axis() {
        let cube = Hypercube::default();
        let mut sc = candidate();
        sc.seam_ok = false;
        assert!(matches!(
            cube.check(&sc),
            PchOutcome::Fail {
                axis: Axis::Boundary,
                ..
            }
        ));
    }
}
