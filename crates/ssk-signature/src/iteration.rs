//! Recursive signature iteration — Chameleon `iteration`.
//!
//! A local improvement loop: each round, every operator is tried on every
//! object, the best *improving* candidate is selected, and the objects advance.
//! The loop stops on convergence, when no candidate improves, or when
//! improvement stalls. This is the mechanism behind the 5D-Cube acceptance
//! criterion — the average distance to the target (the Bündigkeitsindex) moves
//! monotonically toward zero and never flickers.

use serde::Serialize;
use ssk_types::{digest_of, HashAlg};

use crate::kernel::ChameleonKernel;
use crate::object::SurfaceObject;
use crate::operators::TransformOperator;
use crate::policy::AuthorizationManifest;
use crate::signature::Decision;
use crate::target::TargetProfile;
use crate::value::round6;

/// Errors the iterator can return before it produces a result.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IterationError {
    #[error("at least one object is required")]
    NoObjects,
    #[error("at least one operator is required")]
    NoOperators,
    #[error("max_rounds must be at least 1")]
    BadRounds,
    #[error("policy denied iteration: {0}")]
    PolicyDenied(String),
}

/// One candidate transform considered in a round.
#[derive(Clone, Debug, PartialEq)]
pub struct IterationCandidate {
    pub round_index: usize,
    pub object_index: usize,
    pub operator_name: String,
    pub source_ref: String,
    pub transformed_ref: String,
    pub source_signature_digest: String,
    pub transformed_signature_digest: String,
    pub distance_before: f64,
    pub distance_after: f64,
    pub improvement: f64,
    pub decision: Decision,
    pub top_drift_dimensions: Vec<String>,
    pub residue_ref: Option<String>,
    pub selected: bool,
}

/// One round of the iteration.
#[derive(Clone, Debug, PartialEq)]
pub struct IterationRound {
    pub round_index: usize,
    pub candidates: Vec<IterationCandidate>,
    pub selected_candidates: Vec<IterationCandidate>,
    pub average_distance_before: f64,
    pub average_distance_after: f64,
    pub improvement: f64,
    pub decision: Decision,
    pub top_drift_dimensions: Vec<String>,
}

/// The full iteration outcome.
#[derive(Clone, Debug, PartialEq)]
pub struct RecursiveIterationResult {
    pub iteration_id: String,
    pub target_name: String,
    pub rounds: Vec<IterationRound>,
    pub final_object_refs: Vec<String>,
    pub final_average_distance: f64,
    pub converged: bool,
    pub stop_reason: String,
}

impl RecursiveIterationResult {
    /// How many times each operator was selected across all rounds.
    #[must_use]
    pub fn selected_operator_counts(&self) -> std::collections::BTreeMap<String, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for round in &self.rounds {
            for c in &round.selected_candidates {
                *counts.entry(c.operator_name.clone()).or_insert(0) += 1;
            }
        }
        counts
    }
}

/// A stable reference to a surface that does not export raw field content —
/// Chameleon `surface_ref`.
#[must_use]
pub fn surface_ref(obj: &SurfaceObject) -> String {
    #[derive(Serialize)]
    struct Prov {
        source: Option<String>,
        record_id: Option<String>,
        adapter: Option<String>,
    }
    #[derive(Serialize)]
    struct Ref {
        media_type: String,
        declared_protocol_class: String,
        field_names: Vec<String>,
        ordering: Vec<String>,
        timing_keys: Vec<String>,
        provenance: Prov,
    }
    let mut field_names: Vec<String> = obj.fields.keys().map(str::to_owned).collect();
    field_names.sort();
    let mut timing_keys: Vec<String> = obj.timing_model.keys().map(str::to_owned).collect();
    timing_keys.sort();
    let prov_text = |k1: &str, k2: &str| {
        obj.provenance
            .get(k1)
            .or_else(|| obj.provenance.get(k2))
            .and_then(|v| v.as_text())
            .map(str::to_owned)
    };
    let payload = Ref {
        media_type: obj.media_type.clone(),
        declared_protocol_class: obj.declared_protocol_class.clone(),
        field_names,
        ordering: obj.ordering.clone(),
        timing_keys,
        provenance: Prov {
            source: prov_text("source", "source_name"),
            record_id: prov_text("record_id", "record_index"),
            adapter: obj
                .provenance
                .get("adapter")
                .and_then(|v| v.as_text())
                .map(str::to_owned),
        },
    };
    digest_of(&payload, HashAlg::Blake3)
        .expect("surface ref is serializable")
        .to_hex()
}

/// Tuning knobs for a run (Chameleon `run` keyword args).
#[derive(Clone, Debug, PartialEq)]
pub struct IterationParams {
    pub mode: String,
    pub max_rounds: usize,
    pub min_improvement: f64,
}

impl Default for IterationParams {
    fn default() -> Self {
        IterationParams {
            mode: "adapter_operation".to_owned(),
            max_rounds: 3,
            min_improvement: 1e-6,
        }
    }
}

/// The recursive local-improvement loop over signatures and operators.
#[derive(Default)]
pub struct RecursiveSignatureIterator {
    pub kernel: ChameleonKernel,
}

impl RecursiveSignatureIterator {
    #[must_use]
    pub fn new(kernel: ChameleonKernel) -> Self {
        RecursiveSignatureIterator { kernel }
    }

    /// Run the iteration. Mirrors Chameleon `RecursiveSignatureIterator.run`.
    ///
    /// # Errors
    /// Returns [`IterationError`] for empty inputs, `max_rounds < 1`, or a
    /// non-passing policy decision.
    pub fn run(
        &self,
        objects: &[SurfaceObject],
        operators: &[&dyn TransformOperator],
        target: &TargetProfile,
        authorization: Option<&AuthorizationManifest>,
        params: &IterationParams,
    ) -> Result<RecursiveIterationResult, IterationError> {
        let IterationParams {
            mode,
            max_rounds,
            min_improvement,
        } = params;
        let (max_rounds, min_improvement) = (*max_rounds, *min_improvement);
        if objects.is_empty() {
            return Err(IterationError::NoObjects);
        }
        if operators.is_empty() {
            return Err(IterationError::NoOperators);
        }
        if max_rounds < 1 {
            return Err(IterationError::BadRounds);
        }
        let policy_decision = self.kernel.policy.evaluate(mode, authorization);
        if !policy_decision.outcome.is_pass() {
            return Err(IterationError::PolicyDenied(policy_decision.reason));
        }

        let mut current: Vec<SurfaceObject> = objects.to_vec();
        let mut rounds: Vec<IterationRound> = Vec::new();
        let mut previous_average = self.average_distance(&current, target);
        let mut stop_reason = "max_rounds".to_owned();

        let already_converged = previous_average <= target.global_tolerance;
        if already_converged {
            stop_reason = "already_converged".to_owned();
        }

        if !already_converged {
            for round_index in 0..max_rounds {
                let mut next_objects: Vec<SurfaceObject> = Vec::new();
                let mut round_candidates: Vec<IterationCandidate> = Vec::new();
                let mut selected_candidates: Vec<IterationCandidate> = Vec::new();

                for (object_index, obj) in current.iter().enumerate() {
                    let source_signature = self.kernel.signature_for(obj);
                    let source_report = source_signature.compare(
                        &target.signature,
                        &target.dimension_tolerances,
                        target.global_tolerance,
                        5,
                    );
                    let mut best: Option<IterationCandidate> = None;
                    let mut best_index: Option<usize> = None;
                    let mut best_object = obj.clone();

                    for operator in operators {
                        let transform = operator.apply(obj);
                        let transformed = transform.transformed;
                        let transformed_signature = self.kernel.signature_for(&transformed);
                        let report = transformed_signature.compare(
                            &target.signature,
                            &target.dimension_tolerances,
                            target.global_tolerance,
                            5,
                        );
                        let disposition = transform.residue_report.externalize(
                            "post_transform",
                            &target.residue_externalization_surfaces,
                            crate::residue::ResidueSeverity::Medium,
                        );
                        let improvement =
                            round6(source_report.global_distance - report.global_distance);
                        let candidate = IterationCandidate {
                            round_index,
                            object_index,
                            operator_name: operator.name().to_owned(),
                            source_ref: surface_ref(obj),
                            transformed_ref: surface_ref(&transformed),
                            source_signature_digest: source_signature.digest.to_hex(),
                            transformed_signature_digest: transformed_signature.digest.to_hex(),
                            distance_before: source_report.global_distance,
                            distance_after: report.global_distance,
                            improvement,
                            decision: report.decision,
                            top_drift_dimensions: report.top_dimensions,
                            residue_ref: disposition.map(|d| d.residue_ref),
                            selected: false,
                        };
                        round_candidates.push(candidate.clone());
                        if is_better(&candidate, best.as_ref()) {
                            best = Some(candidate);
                            best_index = Some(round_candidates.len() - 1);
                            best_object = transformed;
                        }
                    }

                    match &best {
                        Some(b) if b.improvement > min_improvement => {
                            let mut selected = b.clone();
                            selected.selected = true;
                            if let Some(idx) = best_index {
                                round_candidates[idx] = selected.clone();
                            }
                            selected_candidates.push(selected);
                            next_objects.push(best_object);
                        }
                        _ => next_objects.push(obj.clone()),
                    }
                }

                let average_after = self.average_distance(&next_objects, target);
                let improvement = round6(previous_average - average_after);
                let top_dimensions = self.top_dimensions(&next_objects, target);
                let decision = if average_after <= target.global_tolerance {
                    Decision::Pass
                } else {
                    Decision::Optimize
                };
                let no_selected = selected_candidates.is_empty();
                rounds.push(IterationRound {
                    round_index,
                    candidates: round_candidates,
                    selected_candidates,
                    average_distance_before: previous_average,
                    average_distance_after: average_after,
                    improvement,
                    decision,
                    top_drift_dimensions: top_dimensions,
                });

                current = next_objects;
                previous_average = average_after;
                if average_after <= target.global_tolerance {
                    stop_reason = "converged".to_owned();
                    break;
                }
                if no_selected {
                    stop_reason = "no_candidate_improved".to_owned();
                    break;
                }
                if improvement <= min_improvement {
                    stop_reason = "no_significant_improvement".to_owned();
                    break;
                }
            }
        }

        let final_average = self.average_distance(&current, target);
        let final_object_refs: Vec<String> = current.iter().map(surface_ref).collect();

        #[derive(Serialize)]
        struct IdRound {
            round_index: usize,
            average_distance_before: f64,
            average_distance_after: f64,
            improvement: f64,
        }
        #[derive(Serialize)]
        struct IdPayload<'a> {
            target: &'a str,
            rounds: Vec<IdRound>,
            final_refs: &'a [String],
            final_average: f64,
            stop_reason: &'a str,
        }
        let iteration_id = digest_of(
            &IdPayload {
                target: &target.name,
                rounds: rounds
                    .iter()
                    .map(|r| IdRound {
                        round_index: r.round_index,
                        average_distance_before: r.average_distance_before,
                        average_distance_after: r.average_distance_after,
                        improvement: r.improvement,
                    })
                    .collect(),
                final_refs: &final_object_refs,
                final_average,
                stop_reason: &stop_reason,
            },
            HashAlg::Blake3,
        )
        .expect("iteration id payload is serializable")
        .to_hex();

        Ok(RecursiveIterationResult {
            iteration_id,
            target_name: target.name.clone(),
            rounds,
            final_object_refs,
            final_average_distance: final_average,
            converged: final_average <= target.global_tolerance,
            stop_reason,
        })
    }

    fn average_distance(&self, objects: &[SurfaceObject], target: &TargetProfile) -> f64 {
        if objects.is_empty() {
            return 0.0;
        }
        let sum: f64 = objects
            .iter()
            .map(|o| {
                self.kernel
                    .signature_for(o)
                    .global_distance(&target.signature)
            })
            .sum();
        round6(sum / objects.len() as f64)
    }

    fn top_dimensions(&self, objects: &[SurfaceObject], target: &TargetProfile) -> Vec<String> {
        let mut ranked: std::collections::BTreeMap<String, f64> = std::collections::BTreeMap::new();
        for obj in objects {
            let report = self.kernel.signature_for(obj).compare(
                &target.signature,
                &target.dimension_tolerances,
                target.global_tolerance,
                5,
            );
            for delta in report.dimension_deltas {
                let entry = ranked.entry(delta.dimension).or_insert(0.0);
                *entry = entry.max(delta.distance);
            }
        }
        let mut ranked: Vec<(String, f64)> = ranked.into_iter().filter(|(_, d)| *d > 0.0).collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        ranked.into_iter().take(5).map(|(dim, _)| dim).collect()
    }
}

fn is_better(candidate: &IterationCandidate, best: Option<&IterationCandidate>) -> bool {
    match best {
        None => true,
        Some(b) => {
            if candidate.improvement != b.improvement {
                candidate.improvement > b.improvement
            } else {
                candidate.distance_after < b.distance_after
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::SurfaceObject;
    use crate::operators::{TransformOperator, TransformResult};
    use crate::residue::{ResidueReport, ResidueSeverity};
    use crate::value::{OrderedMap, Value};
    use std::collections::BTreeMap;

    fn status_obj(status: f64) -> SurfaceObject {
        let headers = OrderedMap::from_iter([(
            "Content-Type".to_owned(),
            Value::Text("application/json".to_owned()),
        )]);
        let body = OrderedMap::from_iter([("status".to_owned(), Value::Num(status))]);
        let fields = OrderedMap::from_iter([
            ("protocol".to_owned(), Value::Text("http".to_owned())),
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.test/status".to_owned()),
            ),
            ("status".to_owned(), Value::Num(status)),
            ("headers".to_owned(), Value::Object(headers)),
            (
                "response_header_order".to_owned(),
                Value::Array(vec![Value::Text("Content-Type".to_owned())]),
            ),
            ("duration_ms".to_owned(), Value::Num(25.0)),
            ("body".to_owned(), Value::Object(body)),
            ("body_length".to_owned(), Value::Num(16.0)),
        ]);
        let timing = OrderedMap::from_iter([("duration_ms".to_owned(), Value::Num(25.0))]);
        SurfaceObject::new("application/network-observation+http", fields)
            .with_declared_protocol_class("http")
            .with_timing_model(timing)
    }

    struct SetStatusOperator {
        status: f64,
    }
    impl TransformOperator for SetStatusOperator {
        fn name(&self) -> &str {
            "set_status"
        }
        fn risk_level(&self) -> &str {
            "low"
        }
        fn preserves_semantics(&self) -> bool {
            true
        }
        fn apply(&self, obj: &SurfaceObject) -> TransformResult {
            let mut fields = obj.fields.clone();
            fields.insert("status", Value::Num(self.status));
            let body = OrderedMap::from_iter([("status".to_owned(), Value::Num(self.status))]);
            fields.insert("body", Value::Object(body));
            let residue =
                ResidueReport::new().add("semantic", ResidueSeverity::Low, "status aligned");
            TransformResult {
                transformed: obj.with_fields(fields, Some(self.name())),
                residue_report: residue,
                explanation: "Align status for test.".to_owned(),
            }
        }
    }

    struct NoOpOperator;
    impl TransformOperator for NoOpOperator {
        fn name(&self) -> &str {
            "noop"
        }
        fn risk_level(&self) -> &str {
            "low"
        }
        fn preserves_semantics(&self) -> bool {
            true
        }
        fn apply(&self, obj: &SurfaceObject) -> TransformResult {
            TransformResult {
                transformed: obj.clone(),
                residue_report: ResidueReport::new(),
                explanation: "No operation.".to_owned(),
            }
        }
    }

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned", "tester", "approved")
            .with_allowed_uses(["adapter_operation"])
    }

    // Chameleon test_recursive_iterator_selects_best_improving_candidate.
    #[test]
    fn iterator_selects_best_improving_candidate() {
        let kernel = ChameleonKernel::new();
        let source = status_obj(200.0);
        let target_obj = status_obj(404.0);
        let tolerances: BTreeMap<String, f64> = [
            ("http_surface", 0.01),
            ("body_schema", 0.01),
            ("semantic", 0.01),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let target = TargetProfile::new("status_target", kernel.signature_for(&target_obj))
            .with_global_tolerance(0.01)
            .with_dimension_tolerances(tolerances);

        let noop = NoOpOperator;
        let set = SetStatusOperator { status: 404.0 };
        let operators: Vec<&dyn TransformOperator> = vec![&noop, &set];
        let result = RecursiveSignatureIterator::new(kernel)
            .run(
                &[source],
                &operators,
                &target,
                Some(&auth()),
                &IterationParams::default(),
            )
            .unwrap();

        assert!(!result.rounds.is_empty());
        assert_eq!(
            result.rounds[0].selected_candidates[0].operator_name,
            "set_status"
        );
        assert!(result.rounds[0].improvement > 0.0);
        assert!(result.final_average_distance < result.rounds[0].average_distance_before);
        assert_eq!(result.selected_operator_counts()["set_status"], 1);
    }

    // Chameleon test_recursive_iterator_stops_when_no_candidate_improves.
    #[test]
    fn iterator_stops_when_already_converged() {
        let kernel = ChameleonKernel::new();
        let source = status_obj(200.0);
        let target =
            TargetProfile::new("same", kernel.signature_for(&source)).with_global_tolerance(0.01);
        let noop = NoOpOperator;
        let operators: Vec<&dyn TransformOperator> = vec![&noop];
        let result = RecursiveSignatureIterator::new(kernel)
            .run(
                &[source],
                &operators,
                &target,
                Some(&auth()),
                &IterationParams {
                    max_rounds: 2,
                    ..IterationParams::default()
                },
            )
            .unwrap();
        assert!(result.converged);
        assert_eq!(result.stop_reason, "already_converged");
        assert!(result.rounds.is_empty());
    }
}
