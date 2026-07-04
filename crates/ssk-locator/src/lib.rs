#![forbid(unsafe_code)]

use std::collections::{HashSet, VecDeque};

use ssk_types::{
    EdgeId, EndpointRef, EpochId, FaultKind, HealthStatus, LocatorFacet, LocatorGraph, LocatorId,
    LocatorKind, LocatorPath, LocatorRay, PhaseVector,
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

/// Phase 6 placeholder for the real `ssk-config::Policy` collaborator, same
/// disclosed pattern as `ssk_core::connection::Policy`/`ssk_gates::Policy`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy;

/// Dependency-inverted PCH-consistency check for `select_path` (ch. 6.4).
/// `ssk-locator` cannot depend on `ssk-gates::pch::Hypercube` directly:
/// `ssk-gates` already depends on `ssk-locator` (transitively, via
/// `ssk-bcik`), so the reverse edge would cycle. A further reason this is
/// generic rather than naming `Hypercube` even ignoring the cycle:
/// `Hypercube::check` takes a full `StitchCandidate`, which does not exist
/// yet at path-selection time — ch. 14.1's pipeline spine places
/// `LocatorPath` *before* the second `PCH Projection` stage. `ssk-gates`
/// (or a caller one layer up, e.g. `ssk-runtime`) may implement this trait
/// once a facet-level PCH pre-check makes sense; no implementation is
/// wired in yet, so `select_path` below only ever receives `AlwaysPass` in
/// this codebase's own call sites.
pub trait PathProjectionCheck {
    fn passes(&self, facet: &LocatorFacet, theta: &PhaseVector) -> bool;
}

/// The trivial `PathProjectionCheck`: every phase-visibility decision is
/// deferred to the real `GateVector`/`HypercubeGate` stage later in the
/// pipeline (Section K/I) rather than pre-filtered here.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysPass;

impl PathProjectionCheck for AlwaysPass {
    fn passes(&self, _facet: &LocatorFacet, _theta: &PhaseVector) -> bool {
        true
    }
}

/// Selects the shortest available path through the funnel-DAG from `start`
/// to the nearest reachable, phase-consistent locator (Master Spec Ω+1
/// ch. 6.4). A breadth-first search over both `StitchEdge`s (ordinary
/// `src → dst` transitions) and `HyperEdge`s (unlocked only once every
/// `requires` locator has already been reached) — the first node the
/// search settles that passes `check` is the nearest valid egress, which is
/// what "select a path" means absent a specified destination (the PDF's
/// excerpted signature names no target parameter). An edge with
/// `lifetime.0 == 0` is treated as already expired and is never traversed
/// (same "non-zero TTL" convention as `DissolutionGate`/`TimingCell`
/// elsewhere in this workspace). `start` and `p: &Policy` are this
/// document's own necessary elaboration of the PDF's 4-parameter
/// signature — a shortest-path search needs an origin, and the PDF's
/// excerpted text does not say where one comes from.
///
/// # Errors
/// Returns `FaultKind::LocatorUnavailable` if `start` is not a graph node,
/// or if no reachable node passes `check`.
pub fn select_path<P: PathProjectionCheck>(
    theta: &PhaseVector,
    g: &LocatorGraph,
    check: &P,
    start: &LocatorId,
    _p: &Policy,
) -> Result<LocatorPath, FaultKind> {
    let node_by_id: std::collections::HashMap<&LocatorId, &LocatorFacet> =
        g.nodes.iter().map(|n| (&n.id, n)).collect();
    let Some(&start_facet) = node_by_id.get(start) else {
        return Err(FaultKind::LocatorUnavailable);
    };

    if check.passes(start_facet, theta) {
        return Ok(LocatorPath {
            edges: Vec::new(),
            destination: start.clone(),
        });
    }

    let mut visited: HashSet<LocatorId> = HashSet::from([start.clone()]);
    let mut queue: VecDeque<(LocatorId, Vec<EdgeId>)> =
        VecDeque::from([(start.clone(), Vec::new())]);

    while let Some((current, path_so_far)) = queue.pop_front() {
        for edge in &g.edges {
            if edge.src != current || edge.lifetime.0 == 0 || visited.contains(&edge.dst) {
                continue;
            }
            let Some(&facet) = node_by_id.get(&edge.dst) else {
                continue;
            };
            let mut next_path = path_so_far.clone();
            next_path.push(edge.id.clone());
            if check.passes(facet, theta) {
                return Ok(LocatorPath {
                    edges: next_path,
                    destination: edge.dst.clone(),
                });
            }
            visited.insert(edge.dst.clone());
            queue.push_back((edge.dst.clone(), next_path));
        }

        for hyper in &g.hyperedges {
            if hyper.lifetime.0 == 0
                || visited.contains(&hyper.produces)
                || hyper.requires.iter().any(|r| !visited.contains(r))
            {
                continue;
            }
            let Some(&facet) = node_by_id.get(&hyper.produces) else {
                continue;
            };
            let mut next_path = path_so_far.clone();
            next_path.push(hyper.id.clone());
            if check.passes(facet, theta) {
                return Ok(LocatorPath {
                    edges: next_path,
                    destination: hyper.produces.clone(),
                });
            }
            visited.insert(hyper.produces.clone());
            queue.push_back((hyper.produces.clone(), next_path));
        }
    }

    Err(FaultKind::LocatorUnavailable)
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

    fn edge(id: &str, src: &str, dst: &str, lifetime: u64) -> ssk_types::StitchEdge {
        ssk_types::StitchEdge {
            id: EdgeId::new(id),
            src: LocatorId::new(src),
            dst: LocatorId::new(dst),
            map: ssk_types::EdgeTransform::Routing,
            lifetime: Ttl(lifetime),
            policy_reason: ssk_types::PolicyReason("test-edge".into()),
            capability: None,
            boundary: ssk_types::BoundaryRef::new("bd"),
            trace: TraceId::new("trace"),
        }
    }

    #[test]
    fn a_locator_already_passing_is_a_zero_hop_path() {
        let graph = LocatorGraph {
            nodes: vec![facet("l1", "ep1", HealthStatus::Live)],
            edges: Vec::new(),
            hyperedges: Vec::new(),
        };
        let path = select_path(
            &PhaseVector::zero(),
            &graph,
            &AlwaysPass,
            &LocatorId::new("l1"),
            &Policy,
        )
        .expect("start already passes");
        assert!(path.edges.is_empty());
        assert_eq!(path.destination, LocatorId::new("l1"));
    }

    #[test]
    fn select_path_finds_the_shortest_edge_chain() {
        let graph = LocatorGraph {
            nodes: vec![
                facet("l1", "ep1", HealthStatus::Live),
                facet("l2", "ep2", HealthStatus::Live),
                facet("l3", "ep3", HealthStatus::Live),
            ],
            edges: vec![edge("e1", "l1", "l2", 100), edge("e2", "l2", "l3", 100)],
            hyperedges: Vec::new(),
        };

        struct RejectStart;
        impl PathProjectionCheck for RejectStart {
            fn passes(&self, facet: &LocatorFacet, _theta: &PhaseVector) -> bool {
                facet.id != LocatorId::new("l1")
            }
        }

        let path = select_path(
            &PhaseVector::zero(),
            &graph,
            &RejectStart,
            &LocatorId::new("l1"),
            &Policy,
        )
        .expect("l2 should be reachable");
        assert_eq!(path.edges, vec![EdgeId::new("e1")]);
        assert_eq!(path.destination, LocatorId::new("l2"));
    }

    #[test]
    fn expired_edges_are_never_traversed() {
        let graph = LocatorGraph {
            nodes: vec![
                facet("l1", "ep1", HealthStatus::Live),
                facet("l2", "ep2", HealthStatus::Live),
            ],
            edges: vec![edge("e1", "l1", "l2", 0)],
            hyperedges: Vec::new(),
        };

        struct RejectStart;
        impl PathProjectionCheck for RejectStart {
            fn passes(&self, facet: &LocatorFacet, _theta: &PhaseVector) -> bool {
                facet.id != LocatorId::new("l1")
            }
        }

        let result = select_path(
            &PhaseVector::zero(),
            &graph,
            &RejectStart,
            &LocatorId::new("l1"),
            &Policy,
        );
        assert!(matches!(result, Err(FaultKind::LocatorUnavailable)));
    }

    #[test]
    fn a_hyperedge_unlocks_only_once_every_requirement_is_reached() {
        let graph = LocatorGraph {
            nodes: vec![
                facet("l1", "ep1", HealthStatus::Live),
                facet("l2", "ep2", HealthStatus::Live),
                facet("l3", "ep3", HealthStatus::Live),
            ],
            edges: vec![edge("e1", "l1", "l2", 100)],
            hyperedges: vec![ssk_types::HyperEdge {
                id: EdgeId::new("h1"),
                requires: vec![LocatorId::new("l1"), LocatorId::new("l2")],
                produces: LocatorId::new("l3"),
                lifetime: Ttl(100),
                policy_reason: ssk_types::PolicyReason("test-hyperedge".into()),
                trace: TraceId::new("trace"),
            }],
        };

        struct OnlyL3;
        impl PathProjectionCheck for OnlyL3 {
            fn passes(&self, facet: &LocatorFacet, _theta: &PhaseVector) -> bool {
                facet.id == LocatorId::new("l3")
            }
        }

        let path = select_path(
            &PhaseVector::zero(),
            &graph,
            &OnlyL3,
            &LocatorId::new("l1"),
            &Policy,
        )
        .expect("l3 should be reachable once l1 and l2 are both visited");
        assert_eq!(path.destination, LocatorId::new("l3"));
    }

    #[test]
    fn unknown_start_locator_is_unavailable() {
        let graph = LocatorGraph::default();
        let result = select_path(
            &PhaseVector::zero(),
            &graph,
            &AlwaysPass,
            &LocatorId::new("ghost"),
            &Policy,
        );
        assert!(matches!(result, Err(FaultKind::LocatorUnavailable)));
    }
}
