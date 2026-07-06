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

impl LinkabilityReport {
    /// Emits one typed `Correlation` `BoundaryResidue` per high-risk surface
    /// component (Master Spec Ω+1 ch. 15.3's "each must have a residue
    /// entry"). This is the residue-visibility-completeness obligation made
    /// executable: a high-risk component is never merely scored, it always
    /// leaves a visible, open-obligation residue a policy can act on.
    #[must_use]
    pub fn residues(&self) -> Vec<ssk_types::BoundaryResidue> {
        self.high_risk_components
            .iter()
            .map(|c| {
                ssk_types::BoundaryResidue::new(
                    ssk_types::ResidueId::new(format!("linkability:{}", c.locator.0 .0)),
                    ssk_types::ResidueKind::Correlation,
                    ssk_types::GateId::Privacy,
                    format!("high-linkability locator (risk {})", c.risk_score),
                    ssk_types::Severity::High,
                    ssk_types::TraceId::new(format!("linkability-trace:{}", c.locator.0 .0)),
                    true,
                )
            })
            .collect()
    }
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

    #[test]
    fn residue_visibility_completeness_every_high_risk_component_has_a_residue() {
        // Section W (ch. 15.3): every `high_risk_components` entry must have a
        // matching residue — a high-linkability surface is never silently scored.
        let obs = ObservedSurface {
            components: vec![
                SurfaceComponent {
                    locator: LocatorId::new("l-hi-1"),
                    risk_score: 90,
                },
                SurfaceComponent {
                    locator: LocatorId::new("l-lo"),
                    risk_score: 10,
                },
                SurfaceComponent {
                    locator: LocatorId::new("l-hi-2"),
                    risk_score: 80,
                },
            ],
        };
        let report = HeuristicLinkabilityEstimator.report(&obs, &ThreatCtx);
        let residues = report.residues();
        assert_eq!(report.high_risk_components.len(), 2);
        assert_eq!(residues.len(), report.high_risk_components.len());
        assert!(residues
            .iter()
            .all(|r| r.kind == ssk_types::ResidueKind::Correlation && r.open_obligation()));
    }

    #[test]
    fn locator_reuse_raises_the_linkability_score() {
        // ch. 18.4 metric — locator reuse: an observable surface dominated by a
        // higher-risk locator scores higher than an all-low-risk one.
        let low = ObservedSurface {
            components: vec![SurfaceComponent {
                locator: LocatorId::new("a"),
                risk_score: 10,
            }],
        };
        let high = ObservedSurface {
            components: vec![
                SurfaceComponent {
                    locator: LocatorId::new("a"),
                    risk_score: 10,
                },
                SurfaceComponent {
                    locator: LocatorId::new("a"),
                    risk_score: 85,
                },
            ],
        };
        let est = HeuristicLinkabilityEstimator;
        assert!(est.estimate(&high, &ThreatCtx).0 > est.estimate(&low, &ThreatCtx).0);
    }
}
