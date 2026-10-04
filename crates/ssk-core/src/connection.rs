//! Typestate machine for the connection lifecycle (Master Spec Ω+1 ch. 3.3).
//! An illegal transition is a compile error, not a runtime bug: each state's
//! impl block exposes only the one transition method the spec allows from
//! that state, so there is no public path, for example, from `Split` or
//! `Placed` directly to `Materialized`.
//!
//! The transitions carry **real behavior** (hardening iteration C): each
//! stage validates the carried `StitchCandidate` and the two stages with
//! genuine cross-crate collaborators (`gate`, `materialize`) are
//! dependency-inverted — they are generic over the `GateAuthority` /
//! `MaterializationSink` traits defined here, which the higher crates
//! implement (`ssk-gates`' `GateVector`, and an `ssk-runtime` sink composing
//! the real BCIK crossing + `ssk_tensor::StitchTensor::apply_sorted`). This
//! avoids the dependency cycle that a direct reference to `ssk-gates`/
//! `ssk-tensor` would create — `ssk-gates` already depends on `ssk-core`, so
//! the trait lives in the low crate and the implementation lives above it.

use alloc::vec::Vec;
use core::marker::PhantomData;
use ssk_types::{FaultKind, GateOutcomeKind, GateReport, StitchCandidate, StitchId};

pub struct Intent;
pub struct Canonical;
pub struct Split;
pub struct Placed;
pub struct GatePassed;
pub struct Materialized;

/// Placeholder for the real `ssk-config::Policy` collaborator, consumed by
/// the standalone `ssk_core::birefract` ray-construction function (Section
/// F.3). Config-driven ray policy is not threaded through this crate yet
/// (Section S); this keeps the signature in place until it is.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy;

/// Decides whether a placed candidate projects consistently onto the
/// facet-derivable PCH axes (ch. 8.2). Implemented in `ssk-runtime`
/// (`HypercubePathCheck`-backed) so `ssk-core` need not see `ssk-gates`.
pub trait PlacementAuthority {
    fn placement_ok(&self, sc: &StitchCandidate) -> bool;
}

/// Evaluates the full gate vector over a candidate (ch. 11.2). Implemented
/// in `ssk-gates` for `GateVector` (which already depends on `ssk-core`).
pub trait GateAuthority {
    fn evaluate(&self, sc: &StitchCandidate) -> GateReport;
}

/// Crosses and persists a gate-passed candidate (ch. 9 + ch. 12). Only
/// reachable from `Connection<GatePassed>`, so the type system guarantees a
/// failed candidate can never reach this sink. Implemented in `ssk-runtime`
/// (composing `ssk_bcik::Bcik::cross` + `ssk_tensor::StitchTensor`).
pub trait MaterializationSink {
    /// # Errors
    /// Returns a typed `FaultKind` if the crossing is open or storage fails.
    fn materialize(&mut self, sc: &StitchCandidate) -> Result<Vec<StitchId>, FaultKind>;
}

/// Generic gate-outcome wrapper (Master Spec Ω+1 ch. 3.3): mirrors
/// `GateVerdict`'s five-way resolution but carries the passing payload
/// generically, since `Connection::gate`'s success value is a typestate, not
/// a `GateWitness`.
#[derive(Debug)]
pub enum GateOutcome<T> {
    Pass(T),
    Hold(GateReport),
    Refine(GateReport),
    Reject(GateReport),
    Quarantine(GateReport),
}

/// The connection's carried state: the assembled candidate plus whatever
/// each transition accumulates (the gate report once gated, the materialized
/// stitch ids once persisted).
#[derive(Debug, Clone)]
pub struct ConnectionInner {
    candidate: StitchCandidate,
    gate_report: Option<GateReport>,
    stitches: Vec<StitchId>,
}

impl ConnectionInner {
    #[must_use]
    pub fn new(candidate: StitchCandidate) -> Self {
        Self {
            candidate,
            gate_report: None,
            stitches: Vec::new(),
        }
    }

    #[must_use]
    pub fn candidate(&self) -> &StitchCandidate {
        &self.candidate
    }

    #[must_use]
    pub fn gate_report(&self) -> Option<&GateReport> {
        self.gate_report.as_ref()
    }

    #[must_use]
    pub fn stitches(&self) -> &[StitchId] {
        &self.stitches
    }
}

/// The typestate-carrying connection value. `S` is a phantom marker for the
/// connection's current lifecycle stage; it carries no runtime data of its
/// own.
pub struct Connection<S> {
    inner: ConnectionInner,
    _s: PhantomData<S>,
}

impl<S> Connection<S> {
    #[must_use]
    pub fn inner(&self) -> &ConnectionInner {
        &self.inner
    }

    fn advance<T>(inner: ConnectionInner) -> Connection<T> {
        Connection {
            inner,
            _s: PhantomData,
        }
    }
}

impl Connection<Intent> {
    #[must_use]
    pub fn new(inner: ConnectionInner) -> Self {
        Self {
            inner,
            _s: PhantomData,
        }
    }

    /// Canonicalization + core-signature check (ch. 14.1's first stages): a
    /// candidate whose core is not canonically signed cannot proceed.
    ///
    /// # Errors
    /// `FaultKind::CoreNotCanonical` if the core signature is absent.
    pub fn canonicalize(self) -> Result<Connection<Canonical>, FaultKind> {
        if !self.inner.candidate.core.signature.is_present() {
            return Err(FaultKind::CoreNotCanonical);
        }
        Ok(Self::advance(self.inner))
    }
}

impl Connection<Canonical> {
    /// Birefringent split (ch. 4.2): the facet must belong to its core's
    /// orbit — enforced here as the facet's back-reference matching the core.
    ///
    /// # Errors
    /// `FaultKind::FacetNotRecoverable` if the facet does not reference its core.
    pub fn birefract(self) -> Result<Connection<Split>, FaultKind> {
        if self.inner.candidate.facet.core != self.inner.candidate.core.id {
            return Err(FaultKind::FacetNotRecoverable);
        }
        Ok(Self::advance(self.inner))
    }
}

impl Connection<Split> {
    /// PCH placement (ch. 8.2): the candidate must project consistently onto
    /// the required axes, decided by the injected `PlacementAuthority`.
    ///
    /// # Errors
    /// `FaultKind::PchProjectionGap` if placement is rejected.
    pub fn place(
        self,
        authority: &impl PlacementAuthority,
    ) -> Result<Connection<Placed>, FaultKind> {
        if !authority.placement_ok(&self.inner.candidate) {
            return Err(FaultKind::PchProjectionGap);
        }
        Ok(Self::advance(self.inner))
    }
}

impl Connection<Placed> {
    /// Gate evaluation (ch. 11.2). Only a `Placed` connection can be gated;
    /// only a `GatePassed` connection can be materialized — enforced at
    /// compile time, there is no other public path to either transition.
    pub fn gate(self, authority: &impl GateAuthority) -> GateOutcome<Connection<GatePassed>> {
        let report = authority.evaluate(&self.inner.candidate);
        let mut inner = self.inner;
        let outcome = report.outcome;
        inner.gate_report = Some(report.clone());
        match outcome {
            GateOutcomeKind::Pass => GateOutcome::Pass(Self::advance(inner)),
            GateOutcomeKind::Hold => GateOutcome::Hold(report),
            GateOutcomeKind::Refine => GateOutcome::Refine(report),
            GateOutcomeKind::Reject => GateOutcome::Reject(report),
            GateOutcomeKind::Quarantine => GateOutcome::Quarantine(report),
        }
    }
}

impl Connection<GatePassed> {
    /// Tensor materialization (ch. 12.2). Reachable only from
    /// `Connection<GatePassed>` — there is no public path from `Placed` or
    /// `Split` to a tensor mutation. This makes fail-closed materialization a
    /// property of the API shape, not merely of runtime logic.
    ///
    /// # Errors
    /// A typed `FaultKind` if the crossing is open or storage fails.
    pub fn materialize(
        self,
        sink: &mut impl MaterializationSink,
    ) -> Result<Connection<Materialized>, FaultKind> {
        let stitches = sink.materialize(&self.inner.candidate)?;
        let mut inner = self.inner;
        inner.stitches = stitches;
        Ok(Self::advance(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::*;

    fn candidate(valid_facet: bool, signed: bool) -> StitchCandidate {
        StitchCandidate {
            id: StitchId::new("s1"),
            run: RunId::new("r1"),
            core: CoreNode {
                id: CoreId::new("c1"),
                canonical: CanonicalForm("n".into()),
                signature: if signed {
                    CoreSignature(vec![1, 2, 3])
                } else {
                    CoreSignature(vec![])
                },
                policy_root: PolicyId::new("p1"),
                replay_root: ReplayRoot::new("rr"),
                audit_root: AuditRoot::new("ar"),
                closure: ClosureState::Closed,
            },
            facet: MirrorFacet {
                id: FacetId::of(&"f1", HashAlg::Blake3).expect("hash"),
                core: if valid_facet {
                    CoreId::new("c1")
                } else {
                    CoreId::new("other")
                },
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
            capability: None,
            seam_ok: true,
            boundary_complete: true,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 1,
        }
    }

    struct AlwaysPlace;
    impl PlacementAuthority for AlwaysPlace {
        fn placement_ok(&self, _sc: &StitchCandidate) -> bool {
            true
        }
    }

    struct PassGate;
    impl GateAuthority for PassGate {
        fn evaluate(&self, sc: &StitchCandidate) -> GateReport {
            GateReport {
                id: GateReportId::new(format!("gr:{}", sc.id.0 .0)),
                outcome: GateOutcomeKind::Pass,
                witnesses: Vec::new(),
                residues: Vec::new(),
            }
        }
    }

    struct RejectGate;
    impl GateAuthority for RejectGate {
        fn evaluate(&self, sc: &StitchCandidate) -> GateReport {
            GateReport {
                id: GateReportId::new(format!("gr:{}", sc.id.0 .0)),
                outcome: GateOutcomeKind::Reject,
                witnesses: Vec::new(),
                residues: Vec::new(),
            }
        }
    }

    struct CountingSink {
        count: usize,
    }
    impl MaterializationSink for CountingSink {
        fn materialize(&mut self, sc: &StitchCandidate) -> Result<Vec<StitchId>, FaultKind> {
            self.count += 1;
            Ok(vec![sc.id.clone()])
        }
    }

    #[test]
    fn full_lifecycle_materializes_a_valid_candidate() {
        let c = Connection::<Intent>::new(ConnectionInner::new(candidate(true, true)));
        let c = c.canonicalize().expect("canonicalize");
        let c = c.birefract().expect("birefract");
        let c = c.place(&AlwaysPlace).expect("place");
        let c = match c.gate(&PassGate) {
            GateOutcome::Pass(c) => c,
            _ => panic!("expected Pass"),
        };
        let mut sink = CountingSink { count: 0 };
        let c = c.materialize(&mut sink).expect("materialize");
        assert_eq!(sink.count, 1);
        assert_eq!(c.inner().stitches().len(), 1);
    }

    #[test]
    fn an_unsigned_core_fails_canonicalization() {
        let c = Connection::<Intent>::new(ConnectionInner::new(candidate(true, false)));
        assert!(matches!(c.canonicalize(), Err(FaultKind::CoreNotCanonical)));
    }

    #[test]
    fn a_facet_not_in_its_core_orbit_fails_birefraction() {
        let c = Connection::<Intent>::new(ConnectionInner::new(candidate(false, true)));
        let c = c.canonicalize().expect("canonicalize");
        assert!(matches!(c.birefract(), Err(FaultKind::FacetNotRecoverable)));
    }

    #[test]
    fn a_rejecting_gate_yields_no_gatepassed_connection() {
        let c = Connection::<Intent>::new(ConnectionInner::new(candidate(true, true)));
        let c = c.canonicalize().expect("canonicalize");
        let c = c.birefract().expect("birefract");
        let c = c.place(&AlwaysPlace).expect("place");
        assert!(matches!(c.gate(&RejectGate), GateOutcome::Reject(_)));
    }
}
