#![forbid(unsafe_code)]

use ssk_types::{LocatorFacet, LocatorId};

#[must_use]
pub fn linkability_score(locator: &LocatorFacet) -> u8 {
    if locator.trusted {
        locator.risk_score / 2
    } else {
        locator.risk_score
    }
}

/// Which adversary class an estimate is bounded against (Master Spec Ω+1
/// ch. 15.2's honest-capability matrix). `GlobalPassiveObserver` exists
/// because the PDF's own table names it — but per ch. 15.2's axiom, no
/// `LinkabilityEstimator` may ever declare it as its `adversary_model()`
/// (Section U's non-claim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AdversaryModel {
    PartialNetworkObserver,
    GlobalPassiveObserver,
}

/// A bounded risk estimate in `[0, 1]` (ch. 15.3). The bound is an
/// invariant estimators are expected to uphold, not one this newtype
/// enforces by construction — consistent with this codebase's other
/// bounded-scale types (e.g. `ssk-gates::pch::AxisWeight`).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinkRisk(pub f32);

/// One component of a connection's externally observable surface (ch.
/// 15.3's referenced but unenumerated `SurfaceComponent`) — this document's
/// own minimal, disclosed elaboration: which locator contributed how much
/// risk, so `LinkabilityReport::high_risk_components` can name the actual
/// offending component rather than only a bare aggregate score.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SurfaceComponent {
    pub locator: LocatorId,
    pub risk_score: u8,
}

/// The observable surface an estimate is computed over (ch. 15.3). Phase 5
/// placeholder shape: today this is exactly the one locator a
/// `StitchCandidate` carries; a richer, cross-run observable surface
/// (multiple locators/fibers over time) is future work once a caller needs
/// it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservedSurface {
    pub components: Vec<SurfaceComponent>,
}

impl ObservedSurface {
    #[must_use]
    pub fn of_locator(locator: &LocatorFacet) -> Self {
        Self {
            components: vec![SurfaceComponent {
                locator: locator.id.clone(),
                risk_score: locator.risk_score,
            }],
        }
    }
}

/// Phase 5 placeholder for threat-context parameters (ch. 15.3's `ThreatCtx`)
/// — carries nothing yet; no current estimator needs contextual state
/// beyond the observed surface itself, but the PDF's own trait signature
/// includes it (same disclosed pattern as `ssk-gates::GateCtx`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ThreatCtx;

/// `LinkabilityEstimator`/`LinkabilityReport` (Master Spec Ω+1 ch. 15.3,
/// verbatim shape).
pub trait LinkabilityEstimator: Send + Sync {
    /// Returns a bounded risk score in `[0,1]` under the declared adversary
    /// model.
    fn estimate(&self, obs: &ObservedSurface, ctx: &ThreatCtx) -> LinkRisk;
    /// Recorded in the report — never `AdversaryModel::GlobalPassiveObserver`
    /// (ch. 15.2's axiom).
    fn adversary_model(&self) -> AdversaryModel;

    fn report(&self, obs: &ObservedSurface, ctx: &ThreatCtx) -> LinkabilityReport {
        let score = self.estimate(obs, ctx);
        let high_risk_components = obs
            .components
            .iter()
            .filter(|c| c.risk_score > 70)
            .cloned()
            .collect();
        LinkabilityReport {
            score,
            adversary_model: self.adversary_model(),
            high_risk_components,
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LinkabilityReport {
    pub score: LinkRisk,
    pub adversary_model: AdversaryModel,
    pub high_risk_components: Vec<SurfaceComponent>,
}

/// Wraps the existing `linkability_score` heuristic in the real
/// `LinkabilityEstimator` trait shape, declaring
/// `AdversaryModel::PartialNetworkObserver` — the honest posture already
/// implied by a one-line, risk-score-only heuristic: a bounded,
/// budget-checked estimate, not an anonymity claim (Section U).
#[derive(Debug, Default)]
pub struct HeuristicLinkabilityEstimator;

impl LinkabilityEstimator for HeuristicLinkabilityEstimator {
    fn estimate(&self, obs: &ObservedSurface, _ctx: &ThreatCtx) -> LinkRisk {
        let max_risk = obs
            .components
            .iter()
            .map(|c| c.risk_score)
            .max()
            .unwrap_or(0);
        LinkRisk(f32::from(max_risk) / 100.0)
    }

    fn adversary_model(&self) -> AdversaryModel {
        AdversaryModel::PartialNetworkObserver
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_types::{
        CostClass, EndpointRef, EpochId, HealthStatus, LocatorKind, RiskClass, RouteClass, TraceId,
        TransportClass, TrustClass, Ttl,
    };

    fn facet(trusted: bool, risk_score: u8) -> LocatorFacet {
        LocatorFacet {
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
            trace: TraceId::new("trace"),
            trusted,
            risk_score,
        }
    }

    #[test]
    fn heuristic_estimator_declares_partial_network_observer() {
        let estimator = HeuristicLinkabilityEstimator;
        assert_eq!(
            estimator.adversary_model(),
            AdversaryModel::PartialNetworkObserver
        );
    }

    #[test]
    fn report_flags_high_risk_components() {
        let estimator = HeuristicLinkabilityEstimator;
        let obs = ObservedSurface::of_locator(&facet(false, 90));
        let report = estimator.report(&obs, &ThreatCtx);
        assert_eq!(report.score, LinkRisk(0.9));
        assert_eq!(report.high_risk_components.len(), 1);
    }

    #[test]
    fn report_omits_low_risk_components() {
        let estimator = HeuristicLinkabilityEstimator;
        let obs = ObservedSurface::of_locator(&facet(true, 10));
        let report = estimator.report(&obs, &ThreatCtx);
        assert!(report.high_risk_components.is_empty());
    }
}
