#![forbid(unsafe_code)]

use ssk_bcik::CrossOutcome;
use ssk_types::{
    BoundaryResidue, GateId, GateOutcomeKind, GateReport, GateReportId, GateVerdict, GateWitness,
    Id, ResidueId, ResidueKind, StitchCandidate,
};

/// Risk score above which the Fiber gate rejects a locator.
/// Stricter than the Locator gate's threshold of 70.
const FIBER_RISK_THRESHOLD: u8 = 50;

/// Linkability score above which the Privacy gate rejects a locator.
const PRIVACY_LINKABILITY_THRESHOLD: u8 = 50;

pub trait Gate: Send + Sync {
    fn id(&self) -> GateId;
    fn required(&self) -> bool;
    fn evaluate(&self, sc: &StitchCandidate) -> GateVerdict;
}

#[derive(Debug)]
pub struct BasicGate {
    id: GateId,
}

impl BasicGate {
    #[must_use]
    pub fn new(id: GateId) -> Self {
        Self { id }
    }
}

fn pass(id: GateId) -> GateVerdict {
    GateVerdict::Pass(GateWitness {
        gate: id,
        evidence: format!("{id:?}-ok"),
    })
}

fn reject(id: GateId, kind: ResidueKind, detail: &str) -> GateVerdict {
    GateVerdict::Reject(BoundaryResidue {
        id: ResidueId(Id::new(format!("res-{id:?}"))),
        kind,
        source_gate: id,
        detail: detail.to_owned(),
    })
}

impl Gate for BasicGate {
    fn id(&self) -> GateId {
        self.id
    }

    fn required(&self) -> bool {
        true
    }

    fn evaluate(&self, sc: &StitchCandidate) -> GateVerdict {
        match self.id {
            GateId::Core if !sc.core.signature_ok => {
                reject(self.id, ResidueKind::Identity, "core signature invalid")
            }
            GateId::Mirror if sc.facet.core_id != sc.core.id => {
                reject(self.id, ResidueKind::Identity, "facet not recoverable")
            }
            GateId::Locator if !sc.locator.trusted || sc.locator.risk_score > 70 => {
                reject(self.id, ResidueKind::Locator, "locator risk bound exceeded")
            }
            GateId::Bcik => {
                if matches!(ssk_bcik::cross(sc), CrossOutcome::Closed) {
                    pass(self.id)
                } else {
                    reject(self.id, ResidueKind::Boundary, "bcik crossing open")
                }
            }
            // Defense-in-depth: Hypercube independently checks seam integrity.
            // BCIK also checks seam_ok; this gate catches any bypass of BCIK.
            GateId::Hypercube if !sc.seam_ok => {
                reject(self.id, ResidueKind::Boundary, "hypercube seam integrity failed")
            }
            GateId::Capability if !sc.capability_witness => reject(
                self.id,
                ResidueKind::Capability,
                "missing capability witness",
            ),
            // Fiber enforces a stricter risk ceiling than the Locator gate.
            GateId::Fiber if sc.locator.risk_score > FIBER_RISK_THRESHOLD => {
                reject(self.id, ResidueKind::Locator, "fiber risk ceiling exceeded")
            }
            // Privacy enforces a maximum linkability score on the locator.
            GateId::Privacy
                if ssk_privacy::linkability_score(&sc.locator)
                    > PRIVACY_LINKABILITY_THRESHOLD =>
            {
                reject(self.id, ResidueKind::Correlation, "privacy linkability threshold exceeded")
            }
            GateId::Boundary if !sc.boundary_complete => reject(
                self.id,
                ResidueKind::Boundary,
                "incomplete residue register",
            ),
            GateId::Focus if !sc.focus_ready => {
                reject(self.id, ResidueKind::Focus, "focus recovery failed")
            }
            GateId::Replay if !sc.replay_ready => {
                reject(self.id, ResidueKind::Replay, "replay witness missing")
            }
            GateId::Dissolution if sc.ttl_epoch == 0 => {
                reject(self.id, ResidueKind::Timing, "ttl epoch missing")
            }
            _ => pass(self.id),
        }
    }
}

pub struct GateVector {
    gates: Vec<Box<dyn Gate>>,
}

impl GateVector {
    #[must_use]
    pub fn with_all_default() -> Self {
        Self {
            gates: GateId::ALL
                .into_iter()
                .map(|id| Box::new(BasicGate::new(id)) as Box<dyn Gate>)
                .collect(),
        }
    }

    #[must_use]
    pub fn evaluate(&self, sc: &StitchCandidate) -> GateReport {
        let mut witnesses = Vec::new();
        let (mut refine, mut quarantine, mut reject) = (None, None, None);

        for gate in &self.gates {
            match gate.evaluate(sc) {
                GateVerdict::Pass(w) => witnesses.push(w),
                GateVerdict::Hold(r) | GateVerdict::Refine(r) => {
                    refine.get_or_insert(r);
                }
                GateVerdict::Quarantine(r) => {
                    quarantine.get_or_insert(r);
                    break;
                }
                GateVerdict::Reject(r) => {
                    reject.get_or_insert(r);
                    break;
                }
            }
        }

        let (outcome, residues) = if let Some(r) = quarantine {
            (GateOutcomeKind::Quarantine, vec![r])
        } else if let Some(r) = refine {
            (GateOutcomeKind::Refine, vec![r])
        } else if let Some(r) = reject {
            (GateOutcomeKind::Reject, vec![r])
        } else {
            (GateOutcomeKind::Pass, Vec::new())
        };

        GateReport {
            id: GateReportId::new(format!("gate-report:{}", sc.id.0 .0)),
            outcome,
            witnesses,
            residues,
        }
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
                canonical_name: "n".into(),
                policy_root: PolicyId::new("p1"),
                signature_ok: true,
            },
            facet: MirrorFacet {
                facet_id: Id::new("f1"),
                core_id: CoreId::new("c1"),
                sector: Sector::Identity,
                replay_root: ReplayRoot::new("rr"),
            },
            locator: Locator {
                id: LocatorId::new("l1"),
                locator_type: LocatorType::LocalOverlay,
                trusted: true,
                risk_score: 1,
            },
            capability_witness: true,
            seam_ok: true,
            boundary_complete: true,
            replay_ready: true,
            focus_ready: true,
            ttl_epoch: 1,
        }
    }

    #[test]
    fn gate_vector_fail_closed() {
        let mut sc = candidate();
        sc.capability_witness = false;
        let report = GateVector::with_all_default().evaluate(&sc);
        assert_eq!(report.outcome, GateOutcomeKind::Reject);
    }

    #[test]
    fn hypercube_gate_rejects_broken_seam() {
        let gate = BasicGate::new(GateId::Hypercube);
        let mut sc = candidate();
        sc.seam_ok = false;
        assert!(
            matches!(gate.evaluate(&sc), GateVerdict::Reject(_)),
            "Hypercube must reject when seam_ok is false"
        );
    }

    #[test]
    fn hypercube_gate_passes_intact_seam() {
        let gate = BasicGate::new(GateId::Hypercube);
        let sc = candidate();
        assert!(matches!(gate.evaluate(&sc), GateVerdict::Pass(_)));
    }

    #[test]
    fn fiber_gate_rejects_high_risk_locator() {
        let gate = BasicGate::new(GateId::Fiber);
        let mut sc = candidate();
        sc.locator.risk_score = FIBER_RISK_THRESHOLD + 1;
        assert!(
            matches!(gate.evaluate(&sc), GateVerdict::Reject(_)),
            "Fiber must reject risk_score > FIBER_RISK_THRESHOLD"
        );
    }

    #[test]
    fn fiber_gate_passes_acceptable_risk() {
        let gate = BasicGate::new(GateId::Fiber);
        let mut sc = candidate();
        sc.locator.risk_score = FIBER_RISK_THRESHOLD;
        assert!(matches!(gate.evaluate(&sc), GateVerdict::Pass(_)));
    }

    #[test]
    fn privacy_gate_rejects_high_linkability_untrusted() {
        let gate = BasicGate::new(GateId::Privacy);
        let mut sc = candidate();
        sc.locator.trusted = false;
        sc.locator.risk_score = PRIVACY_LINKABILITY_THRESHOLD + 1;
        // linkability_score = risk_score (untrusted) = 51 > 50
        assert!(
            matches!(gate.evaluate(&sc), GateVerdict::Reject(_)),
            "Privacy must reject when linkability score exceeds threshold"
        );
    }

    #[test]
    fn privacy_gate_passes_low_linkability() {
        let gate = BasicGate::new(GateId::Privacy);
        let sc = candidate(); // trusted, risk_score=1 → linkability=0
        assert!(matches!(gate.evaluate(&sc), GateVerdict::Pass(_)));
    }

    #[test]
    fn gate_vector_rejects_fiber_high_risk() {
        let mut sc = candidate();
        sc.locator.risk_score = 60; // passes Locator (≤70) but fails Fiber (>50)
        let report = GateVector::with_all_default().evaluate(&sc);
        assert_eq!(report.outcome, GateOutcomeKind::Reject);
    }
}
