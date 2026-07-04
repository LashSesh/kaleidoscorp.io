#![forbid(unsafe_code)]

use std::collections::HashSet;

use ssk_types::{
    EndpointRef, EpochId, FaultKind, HealthStatus, LocatorFacet, LocatorId, LocatorKind, LocatorRay,
};

/// Minimal request for resolving a locator endpoint (Master Spec Ω+1
/// ch. 6.2). Phase 1 placeholder — carries just enough for a local-overlay
/// resolve/probe; real request shaping lands with the funnel-DAG work
/// (Section G.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRequest {
    pub locator: LocatorId,
}

/// Records one accounted use of a locator (ch. 6.2). Phase 1 placeholder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatorUse {
    pub epoch: EpochId,
}

/// Concrete adapter backend for one `LocatorKind` (ch. 6.2). The adapter
/// surface is deliberately minimal: resolve, probe, release. It never
/// receives the `CoreId` — identity/locator plane separation (ch. 4.2) holds
/// even at the adapter boundary.
pub trait LocatorAdapter: Send + Sync {
    fn kind(&self) -> LocatorKind;
    fn resolve(&self, req: &EgressRequest) -> Result<EndpointRef, FaultKind>;
    fn probe(&self, ep: &EndpointRef) -> HealthStatus;
    fn release(&self, ep: EndpointRef);
}

/// Owns available locators and their health (ch. 6.2).
pub trait LocatorPool: Send + Sync {
    /// Axiom — locator reality condition (ch. 4.3): true only if this pool
    /// has at least two distinct, live locator facets whose observable
    /// endpoints differ. A pool with a single facet — or several facets
    /// sharing one endpoint — must return `false`, never a fabricated
    /// `true`. This is the honesty check the conformance audit
    /// (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md` Section A) flags: it is
    /// re-checked here per call, not cached as a static claim.
    fn claims_external_plurality(&self) -> bool;
    fn candidates(&self, ray: &LocatorRay, epoch: EpochId) -> Vec<LocatorFacet>;
    fn health(&self, id: LocatorId) -> HealthStatus;
    fn account(&mut self, id: LocatorId, use_record: LocatorUse);
}

/// Default in-process `LocatorPool` implementation: an in-memory
/// `Vec<LocatorFacet>`, no adapters wired in yet (real adapters are non-network
/// egress work, Phase 6). Named `StaticLocatorPool` since `LocatorPool` is now
/// the trait name — this replaces the old concrete `LocatorPool` struct.
#[derive(Debug, Clone, Default)]
pub struct StaticLocatorPool {
    pub locators: Vec<LocatorFacet>,
}

impl StaticLocatorPool {
    #[must_use]
    pub fn new(locators: Vec<LocatorFacet>) -> Self {
        Self { locators }
    }

    #[must_use]
    pub fn get(&self, id: &LocatorId) -> Option<LocatorFacet> {
        self.locators.iter().find(|l| &l.id == id).cloned()
    }

    #[must_use]
    pub fn select_first_viable(&self) -> Option<LocatorFacet> {
        self.locators
            .iter()
            .find(|l| l.trusted && l.risk_score <= 70)
            .cloned()
    }
}

impl LocatorPool for StaticLocatorPool {
    fn claims_external_plurality(&self) -> bool {
        let live_distinct: HashSet<_> = self
            .locators
            .iter()
            .filter(|l| l.health == HealthStatus::Live)
            .map(|l| l.endpoint.clone())
            .collect();
        live_distinct.len() >= 2
    }

    fn candidates(&self, ray: &LocatorRay, _epoch: EpochId) -> Vec<LocatorFacet> {
        self.locators
            .iter()
            .filter(|l| ray.allowed_locator_types.0.contains(&l.kind))
            .cloned()
            .collect()
    }

    fn health(&self, id: LocatorId) -> HealthStatus {
        self.get(&id).map_or(HealthStatus::Unknown, |l| l.health)
    }

    fn account(&mut self, _id: LocatorId, _use_record: LocatorUse) {
        // Phase 1 placeholder: no usage accounting yet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{
        CostClass, LocatorTypeSet, RiskClass, RouteClass, TraceId, TransportClass, TrustClass, Ttl,
    };

    fn facet(id: &str, endpoint: &str, health: HealthStatus) -> LocatorFacet {
        LocatorFacet {
            id: LocatorId::new(id),
            kind: LocatorKind::LocalOverlay,
            endpoint: EndpointRef::new(endpoint),
            route: RouteClass::Direct,
            transport: TransportClass::Tcp,
            epoch: EpochId(0),
            ttl: Ttl(100),
            trust: TrustClass::Owned,
            cost: CostClass::Free,
            risk: RiskClass::Low,
            health,
            trace: TraceId::new("trace"),
            trusted: true,
            risk_score: 1,
        }
    }

    #[test]
    fn single_locator_never_claims_plurality() {
        let pool = StaticLocatorPool::new(vec![facet("l1", "ep1", HealthStatus::Live)]);
        assert!(!pool.claims_external_plurality());
    }

    #[test]
    fn two_distinct_live_locators_claim_plurality() {
        let pool = StaticLocatorPool::new(vec![
            facet("l1", "ep1", HealthStatus::Live),
            facet("l2", "ep2", HealthStatus::Live),
        ]);
        assert!(pool.claims_external_plurality());
    }

    #[test]
    fn two_locators_sharing_an_endpoint_do_not_claim_plurality() {
        let pool = StaticLocatorPool::new(vec![
            facet("l1", "ep1", HealthStatus::Live),
            facet("l2", "ep1", HealthStatus::Live),
        ]);
        assert!(!pool.claims_external_plurality());
    }

    #[test]
    fn a_non_live_locator_does_not_count_toward_plurality() {
        let pool = StaticLocatorPool::new(vec![
            facet("l1", "ep1", HealthStatus::Live),
            facet("l2", "ep2", HealthStatus::Degraded),
        ]);
        assert!(!pool.claims_external_plurality());
    }

    #[test]
    fn candidates_filters_by_allowed_locator_types() {
        let pool = StaticLocatorPool::new(vec![facet("l1", "ep1", HealthStatus::Live)]);
        let ray = LocatorRay {
            allowed_locator_types: LocatorTypeSet(vec![LocatorKind::LocalOverlay]),
            route_class: RouteClass::Direct,
            transport_class: TransportClass::Tcp,
            timing_class: ssk_types::TimingClass::Immediate,
            risk_budget: ssk_types::RiskBudget(100),
            cost_budget: ssk_types::CostBudget(100),
        };
        assert_eq!(pool.candidates(&ray, EpochId(0)).len(), 1);

        let empty_ray = LocatorRay {
            allowed_locator_types: LocatorTypeSet(vec![LocatorKind::VpnExit]),
            ..ray
        };
        assert!(pool.candidates(&empty_ray, EpochId(0)).is_empty());
    }
}
