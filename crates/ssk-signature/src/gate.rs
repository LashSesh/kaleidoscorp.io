//! The signature gate — Chameleon `gate_bundle`.
//!
//! [`GateBundle::evaluate`] produces a [`GateVector`] whose decision is
//! `Pass` / `Optimize` / `Fail` from the *full vector* of per-dimension
//! distances, the residue report, and the policy decision — never a single
//! score. The decision maps onto `ssk_types::GateOutcomeKind`
//! (`Pass`/`Hold`/`Reject`), so this gate composes with the SSK gate stack.

use std::collections::BTreeMap;

use ssk_types::GateOutcomeKind;

use crate::policy::PolicyDecision;
use crate::residue::{ResidueReport, ResidueSeverity};
use crate::signature::SpectralSignature;
use crate::target::TargetProfile;

/// Gate decision (Chameleon `PASS` / `OPTIMIZE` / `FAIL`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateDecision {
    Pass,
    Optimize,
    Fail,
}

impl GateDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            GateDecision::Pass => "PASS",
            GateDecision::Optimize => "OPTIMIZE",
            GateDecision::Fail => "FAIL",
        }
    }

    /// Map onto the SSK gate outcome kind: `Optimize` is a `Hold` (recoverable,
    /// improve-and-retry), `Fail` is a hard `Reject`.
    #[must_use]
    pub fn to_ssk(self) -> GateOutcomeKind {
        match self {
            GateDecision::Pass => GateOutcomeKind::Pass,
            GateDecision::Optimize => GateOutcomeKind::Hold,
            GateDecision::Fail => GateOutcomeKind::Reject,
        }
    }
}

/// The gate's output: a decision plus the evidence it was computed from.
#[derive(Clone, Debug, PartialEq)]
pub struct GateVector {
    pub decision: GateDecision,
    pub global_distance: f64,
    pub dimension_distances: BTreeMap<String, f64>,
    pub failed_dimensions: Vec<String>,
    pub reasons: Vec<String>,
}

impl GateVector {
    /// Convenience accessor for the mapped SSK outcome kind.
    #[must_use]
    pub fn to_ssk_decision(&self) -> GateOutcomeKind {
        self.decision.to_ssk()
    }
}

/// Evaluates a transformed signature against a target, folding in residues and
/// the operation-policy decision.
#[derive(Clone, Copy, Debug, Default)]
pub struct GateBundle;

impl GateBundle {
    #[must_use]
    pub fn evaluate(
        &self,
        source_signature: &SpectralSignature,
        transformed_signature: &SpectralSignature,
        target: &TargetProfile,
        residue_report: &ResidueReport,
        policy_decision: Option<&PolicyDecision>,
    ) -> GateVector {
        // A non-passing policy decision hard-fails the gate, carrying the
        // policy reason and the source→transformed distance for context.
        if let Some(pd) = policy_decision {
            if !pd.outcome.is_pass() {
                return GateVector {
                    decision: GateDecision::Fail,
                    global_distance: source_signature.global_distance(transformed_signature),
                    dimension_distances: transformed_signature
                        .distance_by_dimension(&target.signature),
                    failed_dimensions: vec!["policy".to_owned()],
                    reasons: vec![pd.reason.clone()],
                };
            }
        }

        let dimension_distances = transformed_signature.distance_by_dimension(&target.signature);
        let global_distance = transformed_signature.global_distance(&target.signature);

        let failed: Vec<String> = dimension_distances
            .iter()
            .filter(|(dim, &dist)| {
                let tol = target
                    .dimension_tolerances
                    .get(*dim)
                    .copied()
                    .unwrap_or(target.global_tolerance);
                dist > tol
            })
            .map(|(dim, _)| dim.clone())
            .collect();

        let mut reasons: Vec<String> = Vec::new();
        if !failed.is_empty() {
            reasons.push(format!("distance_exceeds_tolerance:{}", failed.join(",")));
        }
        if global_distance > target.global_tolerance {
            reasons.push("global_distance_exceeds_tolerance".to_owned());
        }
        let mut critical_residue = false;
        if residue_report.has_forbidden(&target.forbidden_residue_surfaces) {
            reasons.push("critical_residue_surface".to_owned());
            critical_residue = true;
        } else if residue_report
            .externalize(
                "post_transform",
                &target.residue_externalization_surfaces,
                ResidueSeverity::Medium,
            )
            .is_some()
        {
            reasons.push("residue_externalized".to_owned());
        }

        let decision = if critical_residue {
            GateDecision::Fail
        } else if !failed.is_empty()
            || !reasons.is_empty()
            || residue_report.max_severity().rank() >= ResidueSeverity::Medium.rank()
        {
            GateDecision::Optimize
        } else {
            GateDecision::Pass
        };

        let reasons = if reasons.is_empty() {
            vec!["gate_pass".to_owned()]
        } else {
            reasons
        };

        GateVector {
            decision,
            global_distance,
            dimension_distances,
            failed_dimensions: failed,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::SurfaceObject;
    use crate::policy::PolicyOutcome;
    use crate::signature_for;
    use crate::value::{OrderedMap, Value};

    fn surface(method: &str) -> SurfaceObject {
        let fields = OrderedMap::from_iter([
            ("method".to_owned(), Value::Text(method.to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/api".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
        ]);
        SurfaceObject::new("application/trace+json", fields).with_declared_protocol_class("http")
    }

    #[test]
    fn identical_signature_passes_with_no_residue() {
        let sig = signature_for(&surface("GET"));
        let target = TargetProfile::new("t", sig.clone());
        let gate = GateBundle;
        let gv = gate.evaluate(&sig, &sig, &target, &ResidueReport::new(), None);
        assert_eq!(gv.decision, GateDecision::Pass);
        assert_eq!(gv.to_ssk_decision(), GateOutcomeKind::Pass);
        assert_eq!(gv.reasons, vec!["gate_pass".to_owned()]);
    }

    #[test]
    fn non_passing_policy_hard_fails() {
        let sig = signature_for(&surface("GET"));
        let target = TargetProfile::new("t", sig.clone());
        let denied = PolicyDecision {
            outcome: PolicyOutcome::Fail,
            reason: "authorization_manifest_missing".to_owned(),
        };
        let gv = GateBundle.evaluate(&sig, &sig, &target, &ResidueReport::new(), Some(&denied));
        assert_eq!(gv.decision, GateDecision::Fail);
        assert_eq!(gv.failed_dimensions, vec!["policy".to_owned()]);
        assert_eq!(
            gv.reasons,
            vec!["authorization_manifest_missing".to_owned()]
        );
    }

    #[test]
    fn externalizable_residue_drives_optimize() {
        let sig = signature_for(&surface("GET"));
        let target = TargetProfile::new("t", sig.clone());
        let residue =
            ResidueReport::new().add("linkability", ResidueSeverity::Medium, "redacted 1 field");
        let gv = GateBundle.evaluate(&sig, &sig, &target, &residue, None);
        assert_eq!(gv.decision, GateDecision::Optimize);
        assert!(gv.reasons.iter().any(|r| r == "residue_externalized"));
    }
}
