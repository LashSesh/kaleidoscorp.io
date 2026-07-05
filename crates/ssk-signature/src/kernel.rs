//! The kernel — Chameleon `kernel`.
//!
//! [`ChameleonKernel::evaluate`] runs one surface + operator against a target:
//! canonicalize both source and transformed surfaces, build their signatures,
//! gate the result, compare against the target, and produce a replay manifest,
//! effectiveness feedback, and reanalysis — all folded into one immutable
//! [`ChameleonEvent`]. This is the join point of every layer built so far.

use crate::canonical::canonicalize;
use crate::features::extract_features;
use crate::gate::{GateBundle, GateVector};
use crate::object::SurfaceObject;
use crate::operators::TransformOperator;
use crate::policy::{AuthorizationManifest, ChameleonPolicy, PolicyDecision};
use crate::reanalysis::{reanalyze, ReanalysisResult, DEFAULT_MAX_SIGNATURE_DRIFT};
use crate::replay::{build_replay_feedback, build_replay_manifest, ReplayFeedback, ReplayManifest};
use crate::residue::ResidueReport;
use crate::signature::{SignatureComparisonReport, SpectralSignature};
use crate::target::TargetProfile;
use std::collections::BTreeMap;

/// The default evaluation mode.
pub const DEFAULT_MODE: &str = "offline_analysis";

/// The full, immutable record of one kernel evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct ChameleonEvent {
    pub operator_name: String,
    pub source_signature_digest: String,
    pub transformed_signature_digest: String,
    pub target_name: String,
    pub gate_vector: GateVector,
    pub signature_report: SignatureComparisonReport,
    pub residue_report: ResidueReport,
    pub replay_manifest: ReplayManifest,
    pub replay_feedback: ReplayFeedback,
    pub reanalysis_result: ReanalysisResult,
    pub policy_decision: PolicyDecision,
}

/// The result of a batch evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchAnalysisResult {
    pub events: Vec<ChameleonEvent>,
}

impl BatchAnalysisResult {
    /// Count events by gate decision (Chameleon `BatchAnalysisResult.decisions`).
    #[must_use]
    pub fn decisions(&self) -> BTreeMap<&'static str, usize> {
        let mut counts = BTreeMap::new();
        for event in &self.events {
            *counts
                .entry(event.gate_vector.decision.as_str())
                .or_insert(0) += 1;
        }
        counts
    }
}

/// The signature kernel: an operation policy + the gate bundle.
#[derive(Clone, Debug, Default)]
pub struct ChameleonKernel {
    pub policy: ChameleonPolicy,
    pub gates: GateBundle,
}

impl ChameleonKernel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_policy(policy: ChameleonPolicy) -> Self {
        ChameleonKernel {
            policy,
            gates: GateBundle,
        }
    }

    /// Compute a surface's spectral signature.
    #[must_use]
    pub fn signature_for(&self, obj: &SurfaceObject) -> SpectralSignature {
        crate::signature_for(obj)
    }

    /// Evaluate one surface + operator against a target.
    #[must_use]
    pub fn evaluate(
        &self,
        obj: &SurfaceObject,
        operator: &dyn TransformOperator,
        target: &TargetProfile,
        authorization: Option<&AuthorizationManifest>,
        mode: &str,
    ) -> ChameleonEvent {
        let policy_decision = self.policy.evaluate(mode, authorization);

        let source_canonical = canonicalize(obj);
        let source_signature =
            SpectralSignature::from_features(&extract_features(&source_canonical, obj));

        let transform_result = operator.apply(obj);
        let transformed_canonical = canonicalize(&transform_result.transformed);
        let transformed_signature = SpectralSignature::from_features(&extract_features(
            &transformed_canonical,
            &transform_result.transformed,
        ));

        let gate_vector = self.gates.evaluate(
            &source_signature,
            &transformed_signature,
            target,
            &transform_result.residue_report,
            Some(&policy_decision),
        );

        let signature_report = transformed_signature.compare(
            &target.signature,
            &target.dimension_tolerances,
            target.global_tolerance,
            5,
        );

        let replay_manifest = build_replay_manifest(
            &source_canonical,
            &transformed_canonical,
            &transformed_signature,
            operator.name(),
        );
        let replay_feedback = build_replay_feedback(
            &replay_manifest,
            &source_signature,
            &transformed_signature,
            &target.signature,
        );

        let reanalysis_result = reanalyze(
            &source_canonical,
            &transformed_canonical,
            &source_signature,
            &transformed_signature,
            DEFAULT_MAX_SIGNATURE_DRIFT,
        );

        ChameleonEvent {
            operator_name: operator.name().to_owned(),
            source_signature_digest: source_signature.digest.to_hex(),
            transformed_signature_digest: transformed_signature.digest.to_hex(),
            target_name: target.name.clone(),
            gate_vector,
            signature_report,
            residue_report: transform_result.residue_report,
            replay_manifest,
            replay_feedback,
            reanalysis_result,
            policy_decision,
        }
    }

    /// Evaluate a batch of surfaces under the same operator/target.
    #[must_use]
    pub fn analyze_batch(
        &self,
        objects: &[SurfaceObject],
        operator: &dyn TransformOperator,
        target: &TargetProfile,
        authorization: Option<&AuthorizationManifest>,
        mode: &str,
    ) -> BatchAnalysisResult {
        BatchAnalysisResult {
            events: objects
                .iter()
                .map(|obj| self.evaluate(obj, operator, target, authorization, mode))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::GateDecision;
    use crate::operators::{
        BucketTimingOperator, NormalizeTraceShapeOperator, RedactIdentifierFieldsOperator,
    };
    use crate::policy::PolicyOutcome;
    use crate::signature::Decision;
    use crate::value::{OrderedMap, Value};

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-trace", "me", "self-owned")
            .with_allowed_uses(["offline_analysis", "offline_redaction"])
    }

    fn obj(with_sensitive: bool) -> SurfaceObject {
        let mut headers =
            OrderedMap::from_iter([("User-Agent".to_owned(), Value::Text("Demo/1.0".to_owned()))]);
        let mut fields = OrderedMap::from_iter([
            ("protocol".to_owned(), Value::Text("http".to_owned())),
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/api".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
            ("interarrival_ms".to_owned(), Value::Num(123.0)),
            ("jitter_ms".to_owned(), Value::Num(17.0)),
        ]);
        if with_sensitive {
            headers.insert("Authorization", Value::Text("Bearer local-demo".to_owned()));
            fields.insert("client_ip", Value::Text("192.0.2.10".to_owned()));
        }
        fields.insert("headers", Value::Object(headers));
        let timing = OrderedMap::from_iter([
            ("interarrival_ms".to_owned(), Value::Num(123.0)),
            ("jitter_ms".to_owned(), Value::Num(17.0)),
        ]);
        SurfaceObject::new("application/trace+json", fields)
            .with_declared_protocol_class("http")
            .with_timing_model(timing)
    }

    fn target_for(o: &SurfaceObject) -> TargetProfile {
        let tolerances: BTreeMap<String, f64> = [
            ("shape", 0.5),
            ("ordering", 0.5),
            ("entropy", 1.0),
            ("timing", 1.0),
            ("semantic", 0.5),
            ("linkability", 0.5),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        TargetProfile::new("target", crate::signature_for(o))
            .with_dimension_tolerances(tolerances)
            .with_global_tolerance(0.8)
    }

    // Chameleon test_normalize_trace_shape_can_pass_or_hold_against_self_target.
    #[test]
    fn normalize_trace_shape_passes_or_holds_against_self_target() {
        let o = obj(false);
        let kernel = ChameleonKernel::new();
        let event = kernel.evaluate(
            &o,
            &NormalizeTraceShapeOperator,
            &target_for(&o),
            Some(&auth()),
            DEFAULT_MODE,
        );
        assert!(matches!(
            event.gate_vector.decision,
            GateDecision::Pass | GateDecision::Optimize
        ));
        assert_eq!(event.policy_decision.outcome, PolicyOutcome::Pass);
        assert!(!event.replay_manifest.digest().is_empty());
        assert!(matches!(
            event.replay_feedback.decision,
            Decision::Pass | Decision::Optimize
        ));
    }

    // Chameleon test_redaction_externalizes_linkability_residue_for_optimization.
    #[test]
    fn redaction_externalizes_linkability_residue_for_optimization() {
        let source = obj(true);
        let clean = obj(false);
        let kernel = ChameleonKernel::new();
        let event = kernel.evaluate(
            &source,
            &RedactIdentifierFieldsOperator::default(),
            &target_for(&clean),
            Some(&auth()),
            DEFAULT_MODE,
        );
        assert_eq!(event.gate_vector.decision, GateDecision::Optimize);
        assert!(event
            .gate_vector
            .reasons
            .iter()
            .any(|r| r == "residue_externalized"));
        assert!(event.residue_report.externalize_default().is_some());
    }

    // Chameleon test_bucket_timing_is_not_live_action_and_produces_timing_residue.
    #[test]
    fn bucket_timing_produces_timing_residue_under_offline_mode() {
        let o = obj(false);
        let kernel = ChameleonKernel::new();
        let event = kernel.evaluate(
            &o,
            &BucketTimingOperator { bucket_ms: 100 },
            &target_for(&o),
            Some(&auth()),
            "offline_analysis",
        );
        assert_eq!(event.policy_decision.outcome, PolicyOutcome::Pass);
        assert!(!event.residue_report.by_surface("timing").is_empty());
    }

    // Chameleon test_missing_authorization_fails_even_if_signature_close.
    #[test]
    fn missing_authorization_hard_fails() {
        let o = obj(false);
        let kernel = ChameleonKernel::new();
        let event = kernel.evaluate(
            &o,
            &NormalizeTraceShapeOperator,
            &target_for(&o),
            None,
            DEFAULT_MODE,
        );
        assert_eq!(event.gate_vector.decision, GateDecision::Fail);
        assert_eq!(
            event.gate_vector.failed_dimensions,
            vec!["policy".to_owned()]
        );
    }

    // Chameleon test_batch_analysis_counts_decisions.
    #[test]
    fn batch_analysis_counts_decisions() {
        let objs = [obj(false), obj(false)];
        let kernel = ChameleonKernel::new();
        let result = kernel.analyze_batch(
            &objs,
            &NormalizeTraceShapeOperator,
            &target_for(&objs[0]),
            Some(&auth()),
            DEFAULT_MODE,
        );
        assert_eq!(result.decisions().values().sum::<usize>(), 2);
    }
}
