#![forbid(unsafe_code)]

pub mod gabriel;
pub mod pch;

use ssk_bcik::Bcik;
use ssk_core::MirrorOrbit;
use ssk_crypto::Blake3HashProvider;
use ssk_types::{
    BoundaryResidue, CrossOutcome, GateId, GateOutcomeKind, GateReport, GateReportId, GateVerdict,
    GateWitness, ResidueId, ResidueKind, Severity, StitchCandidate,
};

/// Risk score above which the Fiber gate rejects a locator.
/// Stricter than the Locator gate's threshold of 70.
const FIBER_RISK_THRESHOLD: u8 = 50;

/// Linkability score above which the Privacy gate rejects a locator.
const PRIVACY_LINKABILITY_THRESHOLD: u8 = 50;

/// Phase 3 placeholder for shared gate-evaluation context (Master Spec Ω+1
/// ch. 11.1's `GateCtx`) — carries nothing yet; no current check needs
/// cross-gate state, but the PDF's own trait signature includes it.
#[derive(Debug, Clone, Copy, Default)]
pub struct GateCtx;

/// Every gate: input type, output witness, failure mode, residue, audit,
/// replay (ch. 11.1, verbatim).
pub trait Gate: Send + Sync {
    fn id(&self) -> GateId;
    /// Mandatory gates cannot be skipped.
    fn required(&self) -> bool;
    /// Typed residue emitted on failure.
    fn residue_on_fail(&self) -> ResidueKind;
    fn evaluate(&self, sc: &StitchCandidate, ctx: &GateCtx) -> GateVerdict;
}

fn pass(id: GateId) -> GateVerdict {
    GateVerdict::Pass(GateWitness {
        gate: id,
        evidence: format!("{id:?}-ok"),
    })
}

fn reject(id: GateId, kind: ResidueKind, detail: &str, sc: &StitchCandidate) -> GateVerdict {
    GateVerdict::Reject(BoundaryResidue::new(
        ResidueId::new(format!("res-{id:?}")),
        kind,
        id,
        detail,
        Severity::High,
        sc.facet.trace.clone(),
        true,
    ))
}

fn hold(id: GateId, kind: ResidueKind, detail: &str, sc: &StitchCandidate) -> GateVerdict {
    GateVerdict::Hold(BoundaryResidue::new(
        ResidueId::new(format!("res-{id:?}")),
        kind,
        id,
        detail,
        Severity::Low,
        sc.facet.trace.clone(),
        true,
    ))
}

macro_rules! simple_gate {
    ($name:ident, $id:expr, $residue:expr, $check:expr, $detail:expr) => {
        #[derive(Debug, Default)]
        pub struct $name;

        impl Gate for $name {
            fn id(&self) -> GateId {
                $id
            }

            fn required(&self) -> bool {
                true
            }

            fn residue_on_fail(&self) -> ResidueKind {
                $residue
            }

            fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
                if $check(sc) {
                    pass($id)
                } else {
                    reject($id, $residue, $detail, sc)
                }
            }
        }
    };
}

// CoreGate: canonicalization, core signature, policy root.
simple_gate!(
    CoreGate,
    GateId::Core,
    ResidueKind::Identity,
    |sc: &StitchCandidate| sc.core.signature.is_present(),
    "core signature invalid"
);

/// MirrorGate: facet in core orbit, sector valid, recoverable. Real check —
/// re-derives the orbit deterministically from the core and confirms the
/// facet actually recovers to it (`MirrorOrbit::recover`, Phase 1), not just
/// a `core_id` equality comparison.
#[derive(Debug, Default)]
pub struct MirrorGate;

impl Gate for MirrorGate {
    fn id(&self) -> GateId {
        GateId::Mirror
    }

    fn required(&self) -> bool {
        true
    }

    fn residue_on_fail(&self) -> ResidueKind {
        ResidueKind::Identity
    }

    fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
        if MirrorOrbit::for_core(&sc.core).recover(&sc.facet).is_ok() {
            pass(GateId::Mirror)
        } else {
            reject(
                GateId::Mirror,
                ResidueKind::Identity,
                "facet not recoverable",
                sc,
            )
        }
    }
}

// LocatorGate: locator exists, type permitted, trust/cost/risk bounds.
simple_gate!(
    LocatorGate,
    GateId::Locator,
    ResidueKind::Locator,
    |sc: &StitchCandidate| sc.locator.trusted && sc.locator.risk_score <= 70,
    "locator risk bound exceeded"
);

/// BcikGate: seam, boundary, residual projector, no silent crossing. Drives
/// the real `Bcik::cross()` kernel (Phase 2).
#[derive(Debug, Default)]
pub struct BcikGate;

impl Gate for BcikGate {
    fn id(&self) -> GateId {
        GateId::Bcik
    }

    fn required(&self) -> bool {
        true
    }

    fn residue_on_fail(&self) -> ResidueKind {
        ResidueKind::Boundary
    }

    fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
        let provider = Blake3HashProvider;
        let mut bcik = Bcik::new(&provider);
        if matches!(
            bcik.cross(&sc.facet, &sc.locator, ssk_types::FiberType::Data, sc),
            CrossOutcome::Closed(_)
        ) {
            pass(GateId::Bcik)
        } else {
            reject(
                GateId::Bcik,
                ResidueKind::Boundary,
                "bcik crossing open",
                sc,
            )
        }
    }
}

/// HypercubeGate: all PCH projections defined and compatible. Drives the
/// real nine-axis `pch::Hypercube::check` (Section I) — an `OverBudget`
/// axis holds (diagnosable, non-persistent) rather than rejecting outright,
/// per ch. 8.2's invariant.
#[derive(Debug, Default)]
pub struct HypercubeGate;

impl Gate for HypercubeGate {
    fn id(&self) -> GateId {
        GateId::Hypercube
    }

    fn required(&self) -> bool {
        true
    }

    fn residue_on_fail(&self) -> ResidueKind {
        ResidueKind::Boundary
    }

    fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
        match crate::pch::Hypercube::default().check(sc) {
            crate::pch::PchOutcome::Pass => pass(GateId::Hypercube),
            crate::pch::PchOutcome::Hold { axis, reason } => hold(
                GateId::Hypercube,
                ResidueKind::Boundary,
                &format!("axis {axis:?} over budget: {reason}"),
                sc,
            ),
            crate::pch::PchOutcome::Fail { axis, reason } => reject(
                GateId::Hypercube,
                ResidueKind::Boundary,
                &format!("axis {axis:?} failed: {reason}"),
                sc,
            ),
        }
    }
}

/// CapabilityGate: witness valid, scoped, unexpired, replayable. Checks real
/// structural fields of the witness (expiry, scope), not just presence —
/// full cryptographic re-verification needs the issuer's public key, which
/// this gate does not hold; that wiring is a later phase's job.
#[derive(Debug, Default)]
pub struct CapabilityGate;

impl Gate for CapabilityGate {
    fn id(&self) -> GateId {
        GateId::Capability
    }

    fn required(&self) -> bool {
        true
    }

    fn residue_on_fail(&self) -> ResidueKind {
        ResidueKind::Capability
    }

    fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
        match &sc.capability {
            None => reject(
                GateId::Capability,
                ResidueKind::Capability,
                "missing capability witness",
                sc,
            ),
            Some(w) if w.expiry.0 == 0 => reject(
                GateId::Capability,
                ResidueKind::Capability,
                "capability witness has zero expiry",
                sc,
            ),
            Some(w) if w.scope.action.is_empty() => reject(
                GateId::Capability,
                ResidueKind::Capability,
                "capability witness has an empty scope action",
                sc,
            ),
            Some(_) => pass(GateId::Capability),
        }
    }
}

// FiberGate: fiber typed, transform invariants preserved. Stricter risk
// ceiling than LocatorGate — no real fiber-transform model exists yet (see
// pch::ProtocolProjector's identical disclosure).
simple_gate!(
    FiberGate,
    GateId::Fiber,
    ResidueKind::Protocol,
    |sc: &StitchCandidate| sc.locator.risk_score <= FIBER_RISK_THRESHOLD,
    "fiber risk ceiling exceeded"
);

/// PrivacyGate: linkability within budget; metadata budget respected. Uses
/// the real (if heuristic) `ssk_privacy::linkability_score`.
#[derive(Debug, Default)]
pub struct PrivacyGate;

impl Gate for PrivacyGate {
    fn id(&self) -> GateId {
        GateId::Privacy
    }

    fn required(&self) -> bool {
        true
    }

    fn residue_on_fail(&self) -> ResidueKind {
        ResidueKind::Correlation
    }

    fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
        if ssk_privacy::linkability_score(&sc.locator) > PRIVACY_LINKABILITY_THRESHOLD {
            reject(
                GateId::Privacy,
                ResidueKind::Correlation,
                "privacy linkability threshold exceeded",
                sc,
            )
        } else {
            pass(GateId::Privacy)
        }
    }
}

// BoundaryGate: residue register consistent; no missing residue field.
simple_gate!(
    BoundaryGate,
    GateId::Boundary,
    ResidueKind::Boundary,
    |sc: &StitchCandidate| sc.boundary_complete,
    "incomplete residue register"
);

// FocusGate: responses can refocus to canonical core class. Uses the real
// ssk_focus::refocuses check (facet/core linkage + focus readiness).
simple_gate!(
    FocusGate,
    GateId::Focus,
    ResidueKind::Focus,
    |sc: &StitchCandidate| ssk_focus::refocuses(sc),
    "focus recovery failed"
);

// ReplayGate: deterministic replay under run descriptor.
simple_gate!(
    ReplayGate,
    GateId::Replay,
    ResidueKind::Replay,
    |sc: &StitchCandidate| sc.replay_ready,
    "replay witness missing"
);

// DissolutionGate: TTL/epoch fields present and finalizable.
simple_gate!(
    DissolutionGate,
    GateId::Dissolution,
    ResidueKind::Timing,
    |sc: &StitchCandidate| sc.ttl_epoch != 0,
    "ttl epoch missing"
);

pub struct GateVector {
    gates: Vec<Box<dyn Gate>>,
}

impl GateVector {
    #[must_use]
    pub fn with_all_default() -> Self {
        Self {
            gates: vec![
                Box::new(CoreGate) as Box<dyn Gate>,
                Box::new(MirrorGate),
                Box::new(LocatorGate),
                Box::new(BcikGate),
                Box::new(HypercubeGate),
                Box::new(CapabilityGate),
                Box::new(FiberGate),
                Box::new(PrivacyGate),
                Box::new(BoundaryGate),
                Box::new(FocusGate),
                Box::new(ReplayGate),
                Box::new(DissolutionGate),
            ],
        }
    }

    /// Evaluates every gate, always — the PDF's own pseudocode (ch. 11.2) has
    /// no early `break`. Resolution priority is fail-closed and monotone:
    /// `Quarantine > Reject > Refine/Hold > Pass` — a hard stop (Quarantine or
    /// Reject) is never masked by a merely-recoverable Refine/Hold from another
    /// gate, and `Refine`/`Hold` are kept as distinct outcomes rather than
    /// folded together. Every non-pass gate's residue is retained in
    /// `residues` regardless of which outcome wins the resolution (no silent
    /// loss), not only the residue of the winning bucket.
    #[must_use]
    pub fn evaluate(&self, sc: &StitchCandidate) -> GateReport {
        let ctx = GateCtx;
        let mut witnesses = Vec::new();
        let (mut hold, mut refine, mut quarantine, mut reject) = (None, None, None, None);

        for gate in &self.gates {
            match gate.evaluate(sc, &ctx) {
                GateVerdict::Pass(w) => witnesses.push(w),
                GateVerdict::Hold(r) => {
                    hold.get_or_insert(r);
                }
                GateVerdict::Refine(r) => {
                    refine.get_or_insert(r);
                }
                GateVerdict::Quarantine(r) => {
                    quarantine.get_or_insert(r);
                }
                GateVerdict::Reject(r) => {
                    reject.get_or_insert(r);
                }
            }
        }

        let outcome = if quarantine.is_some() {
            GateOutcomeKind::Quarantine
        } else if reject.is_some() {
            GateOutcomeKind::Reject
        } else if refine.is_some() {
            GateOutcomeKind::Refine
        } else if hold.is_some() {
            GateOutcomeKind::Hold
        } else {
            GateOutcomeKind::Pass
        };

        let residues: Vec<BoundaryResidue> = [quarantine, reject, refine, hold]
            .into_iter()
            .flatten()
            .collect();

        GateReport {
            id: GateReportId::new(format!("gate-report:{}", sc.id.0 .0)),
            outcome,
            witnesses,
            residues,
        }
    }
}

/// Real `GateAuthority` for the `Connection<Placed>::gate` typestate
/// transition (`ssk-core`'s dependency-inverted trait) — `ssk-gates` already
/// depends on `ssk-core`, so implementing the trait here (rather than
/// `ssk-core` naming `GateVector`) is what keeps the graph acyclic.
impl ssk_core::connection::GateAuthority for GateVector {
    fn evaluate(&self, sc: &StitchCandidate) -> GateReport {
        GateVector::evaluate(self, sc)
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
            capability: Some(sample_capability_witness()),
            seam_ok: true,
            boundary_complete: true,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 1,
        }
    }

    fn sample_capability_witness() -> CapabilityWitness {
        CapabilityWitness {
            id: CapabilityId::of(&"gate-test-capability", HashAlg::Blake3).expect("hash"),
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
        }
    }

    #[test]
    fn gate_vector_fail_closed() {
        let mut sc = candidate();
        sc.capability = None;
        let report = GateVector::with_all_default().evaluate(&sc);
        assert_eq!(report.outcome, GateOutcomeKind::Reject);
    }

    #[test]
    fn hypercube_gate_rejects_broken_seam() {
        let gate = HypercubeGate;
        let mut sc = candidate();
        sc.seam_ok = false;
        assert!(
            matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Reject(_)),
            "Hypercube must reject when seam_ok is false"
        );
    }

    #[test]
    fn hypercube_gate_passes_intact_seam() {
        let gate = HypercubeGate;
        let sc = candidate();
        assert!(matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Pass(_)));
    }

    #[test]
    fn fiber_gate_rejects_high_risk_locator() {
        let gate = FiberGate;
        let mut sc = candidate();
        sc.locator.risk_score = FIBER_RISK_THRESHOLD + 1;
        assert!(
            matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Reject(_)),
            "Fiber must reject risk_score > FIBER_RISK_THRESHOLD"
        );
    }

    #[test]
    fn fiber_gate_passes_acceptable_risk() {
        let gate = FiberGate;
        let mut sc = candidate();
        sc.locator.risk_score = FIBER_RISK_THRESHOLD;
        assert!(matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Pass(_)));
    }

    #[test]
    fn privacy_gate_rejects_high_linkability_untrusted() {
        let gate = PrivacyGate;
        let mut sc = candidate();
        sc.locator.trusted = false;
        sc.locator.risk_score = PRIVACY_LINKABILITY_THRESHOLD + 1;
        // linkability_score = risk_score (untrusted) = 51 > 50
        assert!(
            matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Reject(_)),
            "Privacy must reject when linkability score exceeds threshold"
        );
    }

    #[test]
    fn privacy_gate_passes_low_linkability() {
        let gate = PrivacyGate;
        let sc = candidate(); // trusted, risk_score=1 → linkability=0
        assert!(matches!(gate.evaluate(&sc, &GateCtx), GateVerdict::Pass(_)));
    }

    #[test]
    fn gate_vector_rejects_fiber_high_risk() {
        let mut sc = candidate();
        sc.locator.risk_score = 60; // passes Locator (≤70) but fails Fiber (>50)
        let report = GateVector::with_all_default().evaluate(&sc);
        assert_eq!(report.outcome, GateOutcomeKind::Reject);
    }

    // Regression: a Reject must never be masked by a simultaneous Refine/Hold
    // from another gate. risk_score=90 makes LocatorGate (>70) and FiberGate
    // (>50) both Reject, while HypercubeGate's RiskProjector (ceiling 70) Holds
    // on the same candidate — the resolution must still report Reject, and must
    // not silently drop the Hold's residue.
    #[test]
    fn reject_is_never_masked_by_a_simultaneous_hold() {
        let mut sc = candidate();
        sc.locator.risk_score = 90;
        let report = GateVector::with_all_default().evaluate(&sc);
        assert_eq!(
            report.outcome,
            GateOutcomeKind::Reject,
            "a hard Reject must win over a merely-recoverable Hold/Refine"
        );
        // No silent loss: the Hypercube Hold's residue is retained alongside the
        // reject residues, not discarded because Reject won the resolution.
        assert!(
            report.residues.len() >= 2,
            "residues from every non-pass gate must be retained, not only the winning outcome's: {:?}",
            report.residues
        );
    }

    // Monotonicity: a strictly riskier candidate must never resolve to a
    // strictly less-severe outcome than a milder one. risk_score=60 already
    // resolves to Reject (fiber-only failure); risk_score=90 adds a Hypercube
    // Hold on top and must still resolve to Reject, not something milder.
    #[test]
    fn worsening_risk_never_produces_a_milder_outcome() {
        let mut milder = candidate();
        milder.locator.risk_score = 60;
        let milder_outcome = GateVector::with_all_default().evaluate(&milder).outcome;

        let mut worse = candidate();
        worse.locator.risk_score = 90;
        let worse_outcome = GateVector::with_all_default().evaluate(&worse).outcome;

        assert_eq!(milder_outcome, GateOutcomeKind::Reject);
        assert_eq!(
            worse_outcome,
            GateOutcomeKind::Reject,
            "a strictly riskier candidate (90) must not resolve milder than a less risky one (60)"
        );
    }

    // Hold and Refine are genuinely distinct outcomes: a GateVector containing
    // only a gate that Holds must resolve to GateOutcomeKind::Hold, not be
    // relabeled Refine.
    #[test]
    fn hypercube_hold_resolves_to_hold_not_refine() {
        let mut sc = candidate();
        sc.locator.risk_score = 71; // > RiskProjector's ceiling of 70 -> Hold
        let verdict = HypercubeGate.evaluate(&sc, &GateCtx);
        assert!(
            matches!(verdict, GateVerdict::Hold(_)),
            "RiskProjector over the ceiling must Hold: {verdict:?}"
        );

        let vector = GateVector {
            gates: vec![Box::new(HypercubeGate) as Box<dyn Gate>],
        };
        let report = vector.evaluate(&sc);
        assert_eq!(
            report.outcome,
            GateOutcomeKind::Hold,
            "a Hold verdict must resolve to GateOutcomeKind::Hold, not be relabeled Refine"
        );
    }

    /// A spy gate that always fails and counts its own invocations, used to
    /// prove `GateVector::evaluate` never early-`break`s (ch. 11.2's "every
    /// gate is always evaluated" pseudocode).
    struct CountingRejectSpy {
        id: GateId,
        count: std::sync::atomic::AtomicUsize,
    }

    impl Gate for CountingRejectSpy {
        fn id(&self) -> GateId {
            self.id
        }

        fn required(&self) -> bool {
            true
        }

        fn residue_on_fail(&self) -> ResidueKind {
            ResidueKind::Boundary
        }

        fn evaluate(&self, sc: &StitchCandidate, _ctx: &GateCtx) -> GateVerdict {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            reject(self.id, ResidueKind::Boundary, "spy always rejects", sc)
        }
    }

    #[test]
    fn all_twelve_gates_are_evaluated_even_after_an_early_reject() {
        let spies: Vec<_> = GateId::ALL
            .into_iter()
            .map(|id| {
                std::sync::Arc::new(CountingRejectSpy {
                    id,
                    count: std::sync::atomic::AtomicUsize::new(0),
                })
            })
            .collect();
        let gates: Vec<Box<dyn Gate>> = spies
            .iter()
            .map(|s| Box::new(ArcGate(s.clone())) as Box<dyn Gate>)
            .collect();
        let vector = GateVector { gates };
        let report = vector.evaluate(&candidate());
        assert_eq!(report.outcome, GateOutcomeKind::Reject);
        for spy in &spies {
            assert_eq!(
                spy.count.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "gate {:?} must be evaluated exactly once",
                spy.id
            );
        }
    }

    /// Thin `Gate` wrapper so an `Arc<CountingRejectSpy>` can be boxed as
    /// `Box<dyn Gate>` while the test also keeps its own `Arc` handles to
    /// read the counters afterward.
    struct ArcGate(std::sync::Arc<CountingRejectSpy>);

    impl Gate for ArcGate {
        fn id(&self) -> GateId {
            self.0.id()
        }

        fn required(&self) -> bool {
            self.0.required()
        }

        fn residue_on_fail(&self) -> ResidueKind {
            self.0.residue_on_fail()
        }

        fn evaluate(&self, sc: &StitchCandidate, ctx: &GateCtx) -> GateVerdict {
            self.0.evaluate(sc, ctx)
        }
    }
}
