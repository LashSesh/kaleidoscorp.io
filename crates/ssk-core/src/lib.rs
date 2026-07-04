#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::format;
use alloc::vec;
use ssk_types::{
    ConnectionIntent, CoreNode, CostBudget, FacetId, FaultKind, HashAlg, IdentityRay,
    KeyContextRef, LocatorKind, LocatorRay, LocatorTypeSet, MirrorFacet, ObjectKind, OrbitSeed,
    Orientation, PhaseVector, ReplayNeed, ResidueKind, ResiduePolicy, ResidueRef, RiskBudget,
    RouteClass, Sector, SessionId, SessionIntent, TimingClass, TraceId, TransportClass,
};

pub mod connection;

/// Split a connection intent into its identity ray and locator ray
/// (Master Spec Ω+1 ch. 4.2). Pure function, no I/O — this is the real body
/// for `connection::Connection<Canonical>::birefract`.
///
/// Phase 1 placeholder: the locator ray is populated with conservative,
/// policy-independent defaults (local-overlay only, direct route, minimal
/// budgets) since real policy-driven ray construction depends on
/// `ssk-config`'s richer schema (Section S, Phase 8) — not yet wired here.
pub fn birefract(
    intent: &ConnectionIntent,
    core: &CoreNode,
    _p: &connection::Policy,
) -> Result<(IdentityRay, LocatorRay), FaultKind> {
    let identity = IdentityRay {
        core_ref: core.id.clone(),
        session_intent: SessionIntent::new(format!("session-intent:{}", intent.run.0 .0)),
        key_context: KeyContextRef::new(format!("birefract:{}:key-ctx", core.id.0 .0)),
        app_policy: core.policy_root.clone(),
        replay_need: ReplayNeed::Required,
        residue_policy: ResiduePolicy(ResidueKind::Identity),
    };
    let locator = LocatorRay {
        allowed_locator_types: LocatorTypeSet(vec![LocatorKind::LocalOverlay]),
        route_class: RouteClass::Direct,
        transport_class: TransportClass::Unknown,
        timing_class: TimingClass::Immediate,
        risk_budget: RiskBudget(100),
        cost_budget: CostBudget(100),
    };
    Ok((identity, locator))
}

/// Deterministic set of facets derived from one core at a phase state
/// (Master Spec Ω+1 ch. 4.1). Replaces the old string-formatting `Orbit`:
/// `derive`/`recover` are now genuinely content-addressed via `FacetId`'s
/// `content_id!` derivation, not string-pattern matching.
pub struct MirrorOrbit<'c> {
    core: &'c CoreNode,
    seed: OrbitSeed,
}

impl<'c> MirrorOrbit<'c> {
    #[must_use]
    pub fn new(core: &'c CoreNode, seed: OrbitSeed) -> Self {
        Self { core, seed }
    }

    /// Convenience constructor using the core's deterministic default seed
    /// (`OrbitSeed::for_core`) — the common case when a caller has no
    /// separate seed of its own to thread through.
    #[must_use]
    pub fn for_core(core: &'c CoreNode) -> Self {
        Self::new(core, OrbitSeed::for_core(&core.id))
    }

    /// Derive a facet for `sector` at phase `phase`. The facet's id is
    /// computed from `(core id, seed, phase, sector)`'s canonical bytes, so
    /// it is deterministic and reproducible — the same inputs always
    /// produce the same `FacetId`.
    #[must_use]
    pub fn derive(&self, phase: &PhaseVector, sector: Sector) -> MirrorFacet {
        let id = FacetId::of(
            &(self.core.id.clone(), self.seed, phase.clone(), sector),
            HashAlg::Blake3,
        )
        .expect("a (CoreId, OrbitSeed, PhaseVector, Sector) tuple always hashes");
        MirrorFacet {
            id,
            core: self.core.id.clone(),
            phase: phase.clone(),
            // Phase 1 placeholder — no orientation logic exists yet.
            orientation: Orientation::Forward,
            sector,
            key_ctx: KeyContextRef::new(format!("orbit:{}:key-ctx", self.core.id.0 .0)),
            session: SessionId::new(format!("orbit:{}:session", self.core.id.0 .0)),
            policy: self.core.policy_root.clone(),
            trace: TraceId::new(format!("orbit:{}:trace", self.core.id.0 .0)),
            boundary: ssk_types::BoundaryRef::new(format!("orbit:{}:boundary", self.core.id.0 .0)),
            residue: ResidueRef::new(format!("orbit:{}:residue", self.core.id.0 .0)),
        }
    }

    /// Recover the core a facet belongs to by re-deriving it from this orbit
    /// and comparing ids — total over facets produced by this same orbit
    /// (ch. 4.1's projection-recoverability invariant).
    pub fn recover(&self, facet: &MirrorFacet) -> Result<ssk_types::CoreId, FaultKind> {
        let expected = self.derive(&facet.phase, facet.sector);
        if expected.id == facet.id && facet.core == self.core.id {
            Ok(self.core.id.clone())
        } else {
            Err(FaultKind::FacetNotRecoverable)
        }
    }
}

/// Only foundation types implement `CoreObject`; downstream crates cannot,
/// since `sealed::Sealed` is not exported (Master Spec Ω+1 ch. 3.2).
pub trait CoreObject: sealed::Sealed {
    fn object_kind(&self) -> ObjectKind;
    fn residue_policy(&self) -> ResiduePolicy;
}

impl CoreObject for CoreNode {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::Core
    }

    fn residue_policy(&self) -> ResiduePolicy {
        // Matches the gate table's "residue on fail" column for CoreGate (ch. 11.2).
        ResiduePolicy(ResidueKind::Identity)
    }
}

impl CoreObject for MirrorFacet {
    fn object_kind(&self) -> ObjectKind {
        ObjectKind::MirrorFacet
    }

    fn residue_policy(&self) -> ResiduePolicy {
        // Matches the gate table's "residue on fail" column for MirrorGate (ch. 11.2).
        ResiduePolicy(ResidueKind::Identity)
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for ssk_types::CoreNode {}
    impl Sealed for ssk_types::MirrorFacet {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use ssk_types::{AuditRoot, ClosureState, CoreId, CoreSignature, PolicyId};

    fn mk_core(seed: u64) -> CoreNode {
        CoreNode {
            id: CoreId::new(format!("core-{seed}")),
            canonical: ssk_types::CanonicalForm("alpha".to_string()),
            signature: CoreSignature(alloc::vec![1, 2, 3]),
            policy_root: PolicyId::new("policy"),
            replay_root: ssk_types::ReplayRoot::new(format!("replay:{seed}")),
            audit_root: AuditRoot::new(format!("audit:{seed}")),
            closure: ClosureState::Closed,
        }
    }

    proptest! {
        #[test]
        fn facet_recovers_to_core(seed in any::<u64>()) {
            let c = mk_core(seed);
            let orbit = MirrorOrbit::for_core(&c);
            let f = orbit.derive(&PhaseVector::zero(), Sector::Identity);
            prop_assert_eq!(orbit.recover(&f).expect("must recover"), c.id);
        }
    }

    #[test]
    fn core_node_object_kind_and_residue_policy() {
        let c = mk_core(1);
        assert_eq!(c.object_kind(), ObjectKind::Core);
        assert_eq!(c.residue_policy(), ResiduePolicy(ResidueKind::Identity));
    }

    #[test]
    fn mirror_facet_object_kind_and_residue_policy() {
        let c = mk_core(1);
        let orbit = MirrorOrbit::for_core(&c);
        let f = orbit.derive(&PhaseVector::zero(), Sector::Identity);
        assert_eq!(f.object_kind(), ObjectKind::MirrorFacet);
        assert_eq!(f.residue_policy(), ResiduePolicy(ResidueKind::Identity));
    }

    #[test]
    fn recover_fails_for_a_facet_from_a_different_core() {
        let a = mk_core(1);
        let b = mk_core(2);
        let facet_from_b = MirrorOrbit::for_core(&b).derive(&PhaseVector::zero(), Sector::Identity);
        assert!(MirrorOrbit::for_core(&a).recover(&facet_from_b).is_err());
    }

    #[test]
    fn birefract_splits_into_an_identity_ray_and_a_locator_ray() {
        let core = mk_core(1);
        let intent = ssk_types::ConnectionIntent {
            run: ssk_types::RunId::new("run-1"),
            core: core.clone(),
            target_locator: ssk_types::LocatorId::new("local"),
            capability: None,
            ttl_epoch: 1,
        };
        let (identity, locator) =
            birefract(&intent, &core, &connection::Policy).expect("birefract must succeed");
        assert_eq!(identity.core_ref, core.id);
        assert_eq!(
            locator.allowed_locator_types.0,
            vec![ssk_types::LocatorKind::LocalOverlay]
        );
    }
}
