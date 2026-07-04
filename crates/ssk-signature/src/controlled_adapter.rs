//! Controlled adapter framework — Chameleon `controlled_adapter`.
//!
//! Turns kernel evaluations into an exportable, audited **operational plan**:
//! per (object, operator) it records the gate decision, the residue reference
//! (never the raw residue), the signature distance, and the replay
//! effectiveness — but never the raw trace fields. This is the IMDF *Controlled
//! Adapter Framework* role: a plan an orchestrator or UI can act on, with a
//! machine-checkable execution contract, without ever exporting payload content.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use ssk_types::{digest_of, HashAlg};

use crate::kernel::{ChameleonEvent, ChameleonKernel};
use crate::object::SurfaceObject;
use crate::operators::TransformOperator;
use crate::policy::AuthorizationManifest;
use crate::target::TargetProfile;

/// Placeholder timestamp: the port carries no implicit clock, so `created_at`
/// is a stable empty string (the plan id is derived without it, matching the
/// kernel, so this does not affect content addressing).
const NO_CLOCK: &str = "";

/// A stable reference to a surface that does not export raw field content —
/// Chameleon `object_ref` (adds the authorization source to `surface_ref`).
#[must_use]
pub fn object_ref(obj: &SurfaceObject) -> String {
    #[derive(Serialize)]
    struct Prov {
        source: Option<String>,
        record_id: Option<String>,
        adapter: Option<String>,
        authorization_source: Option<String>,
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
    let text = |k1: &str, k2: &str| {
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
            source: text("source", "source_name"),
            record_id: text("record_id", "record_index"),
            adapter: obj
                .provenance
                .get("adapter")
                .and_then(|v| v.as_text())
                .map(str::to_owned),
            authorization_source: text("authorization_source", "authorization_evidence_ref"),
        },
    };
    digest_of(&payload, HashAlg::Blake3)
        .expect("object ref is serializable")
        .to_hex()
}

/// Runtime intent for an adapter operation.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ControlIntent {
    pub objective: String,
    pub target_profile_name: String,
    pub mode: String,
    pub requested_live_action: bool,
    pub requested_network_io: bool,
    pub export_level: String,
    pub allowed_decisions: Vec<String>,
    pub capabilities: Vec<String>,
    pub notes: Vec<String>,
}

impl ControlIntent {
    #[must_use]
    pub fn new(objective: impl Into<String>, target_profile_name: impl Into<String>) -> Self {
        ControlIntent {
            objective: objective.into(),
            target_profile_name: target_profile_name.into(),
            mode: "adapter_operation".to_owned(),
            requested_live_action: false,
            requested_network_io: false,
            export_level: "operational_plan".to_owned(),
            allowed_decisions: vec!["PASS".to_owned(), "OPTIMIZE".to_owned()],
            capabilities: vec!["network_observation".to_owned()],
            notes: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    #[must_use]
    pub fn with_export_level(mut self, level: impl Into<String>) -> Self {
        self.export_level = level.into();
        self
    }

    #[must_use]
    pub fn with_requested_network_io(mut self, on: bool) -> Self {
        self.requested_network_io = on;
        self
    }

    #[must_use]
    pub fn with_capabilities<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        caps: I,
    ) -> Self {
        self.capabilities = caps.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn wants_network_io(&self) -> bool {
        self.requested_network_io || self.requested_live_action
    }
}

/// An adapter-policy decision (three-state, string-valued to match the kernel).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AdapterPolicyDecision {
    pub decision: String,
    pub reason: String,
}

/// Execution contract for adapter operation planning.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlledAdapterPolicy {
    pub allow_network_io: bool,
    pub allowed_modes: Vec<String>,
    pub allowed_export_levels: Vec<String>,
    pub unsupported_capabilities: Vec<String>,
    pub unsupported_objective_terms: Vec<String>,
}

impl Default for ControlledAdapterPolicy {
    fn default() -> Self {
        let s = |xs: &[&str]| xs.iter().map(|x| (*x).to_owned()).collect();
        ControlledAdapterPolicy {
            allow_network_io: true,
            allowed_modes: s(&[
                "adapter_operation",
                "network_observation",
                "network_reanalysis",
                "offline_analysis",
                "audit_export",
                "policy_planning",
            ]),
            allowed_export_levels: s(&[
                "operational_plan",
                "effectiveness_feedback",
                "audit_summary",
                "machine_plan",
            ]),
            unsupported_capabilities: s(&[
                "live_packet_manipulation",
                "proxy_or_vpn_control",
                "credential_use",
                "detector_bypass",
                "covert_channel",
                "packet_injection",
            ]),
            unsupported_objective_terms: s(&[
                "detector_bypass",
                "stealth_bypass",
                "avoid_detection",
                "disable_detection",
                "covert_channel",
                "packet_injection",
                "rotate_proxy",
                "spoof_live_tls",
            ]),
        }
    }
}

impl ControlledAdapterPolicy {
    #[must_use]
    pub fn evaluate_intent(&self, intent: &ControlIntent) -> AdapterPolicyDecision {
        let fail = |reason: String| AdapterPolicyDecision {
            decision: "FAIL".to_owned(),
            reason,
        };
        if !self.allowed_modes.iter().any(|m| m == &intent.mode) {
            return fail(format!("adapter_mode_not_supported:{}", intent.mode));
        }
        if !self
            .allowed_export_levels
            .iter()
            .any(|l| l == &intent.export_level)
        {
            return fail(format!(
                "export_level_not_supported:{}",
                intent.export_level
            ));
        }
        if intent.wants_network_io() && !self.allow_network_io {
            return AdapterPolicyDecision {
                decision: "OPTIMIZE".to_owned(),
                reason: "network_io_requires_adapter_configuration".to_owned(),
            };
        }
        let mut unsupported: Vec<&String> = intent
            .capabilities
            .iter()
            .filter(|c| self.unsupported_capabilities.contains(c))
            .collect();
        unsupported.sort();
        if !unsupported.is_empty() {
            let joined = unsupported
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",");
            return fail(format!("unsupported_capability:{joined}"));
        }
        let objective_l = intent.objective.to_lowercase().replace(' ', "_");
        for term in &self.unsupported_objective_terms {
            if objective_l.contains(term) {
                return fail(format!("unsupported_objective:{term}"));
            }
        }
        AdapterPolicyDecision {
            decision: "PASS".to_owned(),
            reason: "adapter_execution_contract_pass".to_owned(),
        }
    }
}

/// One planned step — flattened, payload-free.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ControlPlanStep {
    pub step_id: String,
    pub object_ref: String,
    pub operator_name: String,
    pub target_name: String,
    pub gate_decision: String,
    pub operation_decision: String,
    pub failed_dimensions: Vec<String>,
    pub reasons: Vec<String>,
    pub residue_phase: String,
    pub residue_ref: Option<String>,
    pub optimization_state: String,
    pub signature_distance: f64,
    pub top_drift_dimensions: Vec<String>,
    pub signature_decision: String,
    pub replay_effectiveness: f64,
    pub replay_decision: String,
}

/// The full operational plan.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ControlPlan {
    pub plan_id: String,
    pub created_at: String,
    pub intent: ControlIntent,
    pub adapter_policy_decision: AdapterPolicyDecision,
    pub target_name: String,
    pub steps: Vec<ControlPlanStep>,
    pub overall_decision: String,
    pub blocked_capabilities: Vec<String>,
    pub feedback_score: f64,
    pub notes: Vec<String>,
}

impl ControlPlan {
    /// Count steps by gate decision.
    #[must_use]
    pub fn decision_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for step in &self.steps {
            *counts.entry(step.gate_decision.clone()).or_insert(0) += 1;
        }
        counts
    }
}

/// A serializable export bundle for control UIs or adapter orchestrators.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AdapterExportBundle {
    pub export_id: String,
    pub created_at: String,
    pub plan: ControlPlan,
    pub audit_summary: serde_json::Value,
    pub execution_contract: serde_json::Value,
}

impl AdapterExportBundle {
    /// Serialize the bundle to pretty JSON.
    ///
    /// # Errors
    /// Returns a serialization error string if encoding fails.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Write the bundle to `path` as JSON.
    ///
    /// # Errors
    /// Returns an io/serialization error string on failure.
    pub fn write_json(&self, path: impl AsRef<Path>) -> Result<PathBuf, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&path, format!("{}\n", self.to_json()?)).map_err(|e| e.to_string())?;
        Ok(path)
    }
}

/// Builds executable adapter plans from kernel evaluations.
#[derive(Default)]
pub struct ControlledAdapterFramework {
    pub kernel: ChameleonKernel,
    pub adapter_policy: ControlledAdapterPolicy,
}

impl ControlledAdapterFramework {
    #[must_use]
    pub fn new(kernel: ChameleonKernel) -> Self {
        ControlledAdapterFramework {
            kernel,
            adapter_policy: ControlledAdapterPolicy::default(),
        }
    }

    /// Build a plan from an intent, objects, operators, and target.
    #[must_use]
    pub fn build_plan(
        &self,
        intent: &ControlIntent,
        objects: &[SurfaceObject],
        operators: &[&dyn TransformOperator],
        target: &TargetProfile,
        authorization: Option<&AuthorizationManifest>,
    ) -> ControlPlan {
        let execution_decision = self.adapter_policy.evaluate_intent(intent);
        let mut steps: Vec<ControlPlanStep> = Vec::new();
        if execution_decision.decision == "PASS" {
            let kernel_mode = self.kernel_mode_for(intent);
            for (obj_index, obj) in objects.iter().enumerate() {
                for (op_index, operator) in operators.iter().enumerate() {
                    let event =
                        self.kernel
                            .evaluate(obj, *operator, target, authorization, kernel_mode);
                    steps.push(event_to_step(&event, obj, obj_index, op_index));
                }
            }
        }
        let overall = overall_decision(&execution_decision, &steps);
        let feedback_score = if steps.is_empty() {
            0.0
        } else {
            crate::value::round6(
                steps.iter().map(|s| s.replay_effectiveness).sum::<f64>() / steps.len() as f64,
            )
        };

        #[derive(Serialize)]
        struct IdPayload<'a> {
            intent: &'a ControlIntent,
            target: &'a str,
            steps: &'a [ControlPlanStep],
            execution: &'a AdapterPolicyDecision,
            unsupported: &'a [String],
            feedback_score: f64,
        }
        let plan_id = digest_of(
            &IdPayload {
                intent,
                target: &target.name,
                steps: &steps,
                execution: &execution_decision,
                unsupported: &self.adapter_policy.unsupported_capabilities,
                feedback_score,
            },
            HashAlg::Blake3,
        )
        .expect("plan payload is serializable")
        .to_hex();

        ControlPlan {
            plan_id,
            created_at: NO_CLOCK.to_owned(),
            intent: intent.clone(),
            adapter_policy_decision: execution_decision,
            target_name: target.name.clone(),
            steps,
            overall_decision: overall,
            blocked_capabilities: self.adapter_policy.unsupported_capabilities.clone(),
            feedback_score,
            notes: vec![
                "network_observation_supported_by_configured_adapters".to_owned(),
                "residue_details_externalized".to_owned(),
                "replay_feedback_enabled".to_owned(),
            ],
        }
    }

    /// Produce the exportable, payload-free bundle for a plan.
    #[must_use]
    pub fn export_bundle(&self, plan: &ControlPlan) -> AdapterExportBundle {
        let operator_names: BTreeSet<&str> = plan
            .steps
            .iter()
            .map(|s| s.operator_name.as_str())
            .collect();
        let top_drift: BTreeSet<&str> = plan
            .steps
            .iter()
            .flat_map(|s| s.top_drift_dimensions.iter().map(String::as_str))
            .collect();
        let audit_summary = serde_json::json!({
            "plan_id": plan.plan_id,
            "overall_decision": plan.overall_decision,
            "decision_counts": plan.decision_counts(),
            "step_count": plan.steps.len(),
            "target_name": plan.target_name,
            "operator_names": operator_names.into_iter().collect::<Vec<_>>(),
            "feedback_score": plan.feedback_score,
            "top_drift_dimensions": top_drift.into_iter().collect::<Vec<_>>(),
            "unsupported_capabilities": plan.blocked_capabilities,
        });
        let execution_contract = serde_json::json!({
            "execution": "supported_for_configured_adapters",
            "network_observation": "supported",
            "network_mutation": "unsupported",
            "proxy_vpn_control": "unsupported",
            "detector_bypass": "unsupported",
            "raw_trace_export": "not_included",
            "residue_details": "externalized_by_reference",
            "allowed_use": "authorized_adapter_operation",
        });
        #[derive(Serialize)]
        struct ExportKey<'a> {
            plan_id: &'a str,
            audit_summary: &'a serde_json::Value,
            execution_contract: &'a serde_json::Value,
        }
        let export_id = digest_of(
            &ExportKey {
                plan_id: &plan.plan_id,
                audit_summary: &audit_summary,
                execution_contract: &execution_contract,
            },
            HashAlg::Blake3,
        )
        .expect("export payload is serializable")
        .to_hex();
        AdapterExportBundle {
            export_id,
            created_at: NO_CLOCK.to_owned(),
            plan: plan.clone(),
            audit_summary,
            execution_contract,
        }
    }

    fn kernel_mode_for(&self, intent: &ControlIntent) -> &'static str {
        if matches!(
            intent.mode.as_str(),
            "network_observation" | "network_reanalysis"
        ) || intent.wants_network_io()
        {
            "network_observation"
        } else if intent.mode == "adapter_operation" {
            "adapter_operation"
        } else {
            "offline_analysis"
        }
    }
}

fn overall_decision(execution: &AdapterPolicyDecision, steps: &[ControlPlanStep]) -> String {
    if execution.decision == "FAIL" {
        return "FAIL".to_owned();
    }
    if execution.decision == "OPTIMIZE" {
        return "OPTIMIZE".to_owned();
    }
    if steps.is_empty() {
        return "OPTIMIZE".to_owned();
    }
    let decisions: BTreeSet<&str> = steps.iter().map(|s| s.gate_decision.as_str()).collect();
    if decisions.contains("FAIL") {
        "FAIL".to_owned()
    } else if decisions.contains("OPTIMIZE") {
        "OPTIMIZE".to_owned()
    } else {
        "PASS".to_owned()
    }
}

fn event_to_step(
    event: &ChameleonEvent,
    obj: &SurfaceObject,
    obj_index: usize,
    op_index: usize,
) -> ControlPlanStep {
    let disposition = event.residue_report.externalize_default();
    let optimization_state = match event.gate_vector.decision {
        crate::gate::GateDecision::Pass => "ready",
        crate::gate::GateDecision::Optimize => "improve",
        crate::gate::GateDecision::Fail => "blocked",
    }
    .to_owned();
    ControlPlanStep {
        step_id: format!("step-{obj_index:03}-{op_index:03}"),
        object_ref: object_ref(obj),
        operator_name: event.operator_name.clone(),
        target_name: event.target_name.clone(),
        gate_decision: event.gate_vector.decision.as_str().to_owned(),
        operation_decision: event.policy_decision.outcome.as_str().to_owned(),
        failed_dimensions: event.gate_vector.failed_dimensions.clone(),
        reasons: event.gate_vector.reasons.clone(),
        residue_phase: disposition
            .as_ref()
            .map_or("none".to_owned(), |d| d.phase.clone()),
        residue_ref: disposition.map(|d| d.residue_ref),
        optimization_state,
        signature_distance: event.signature_report.global_distance,
        top_drift_dimensions: event.signature_report.top_dimensions.clone(),
        signature_decision: event.signature_report.decision.as_str().to_owned(),
        replay_effectiveness: event.replay_feedback.effectiveness_score,
        replay_decision: event.replay_feedback.decision.as_str().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operators::{BucketTimingOperator, NormalizeTraceShapeOperator};
    use crate::trace_adapter::TraceAdapter;
    use crate::value::{OrderedMap, Value};
    use crate::ProfileCorpus;

    fn record(id: &str, url: &str, duration: f64, delta: f64) -> OrderedMap {
        let headers = OrderedMap::from_iter([(
            "User-Agent".to_owned(),
            Value::Text("TestClient/1.0".to_owned()),
        )]);
        OrderedMap::from_iter([
            ("id".to_owned(), Value::Text(id.to_owned())),
            ("method".to_owned(), Value::Text("GET".to_owned())),
            ("url".to_owned(), Value::Text(url.to_owned())),
            ("status".to_owned(), Value::Num(200.0)),
            ("headers".to_owned(), Value::Object(headers)),
            ("duration_ms".to_owned(), Value::Num(duration)),
            ("delta_ms".to_owned(), Value::Num(delta)),
        ])
    }

    fn fixture() -> (
        AuthorizationManifest,
        Vec<SurfaceObject>,
        ChameleonKernel,
        TargetProfile,
    ) {
        let auth =
            AuthorizationManifest::new("test-local", "tester", "synthetic unit test fixture");
        let adapter = TraceAdapter::new(auth.clone()).unwrap();
        let records = [
            record("r1", "https://example.local/a", 100.0, 20.0),
            record("r2", "https://example.local/b", 110.0, 25.0),
        ];
        let objects = adapter.from_records(&records, "application/trace+json");
        let kernel = ChameleonKernel::new();
        let mut corpus = ProfileCorpus::new();
        let sigs: Vec<_> = objects.iter().map(|o| kernel.signature_for(o)).collect();
        let record = corpus
            .build_profile("test_profile", "1.0.0", &sigs, vec![], None, vec![])
            .unwrap();
        let target = record.to_target_profile().with_global_tolerance(0.75);
        (auth, objects, kernel, target)
    }

    // Chameleon test_controlled_adapter_builds_plan_without_raw_trace_export.
    #[test]
    fn builds_plan_without_raw_trace_export() {
        let (auth, objects, kernel, target) = fixture();
        let framework = ControlledAdapterFramework::new(kernel);
        let intent = ControlIntent::new(
            "authorized adapter operation for signature normalization",
            &target.name,
        );
        let normalize = NormalizeTraceShapeOperator;
        let bucket = BucketTimingOperator::default();
        let operators: Vec<&dyn TransformOperator> = vec![&normalize, &bucket];
        let plan = framework.build_plan(&intent, &objects, &operators, &target, Some(&auth));
        let bundle = framework.export_bundle(&plan);
        let encoded = bundle.to_json().unwrap();

        assert_eq!(plan.adapter_policy_decision.decision, "PASS");
        assert_eq!(plan.steps.len(), 4);
        assert!(["PASS", "OPTIMIZE"].contains(&plan.overall_decision.as_str()));
        assert_eq!(
            bundle.execution_contract["execution"],
            "supported_for_configured_adapters"
        );
        assert!(!encoded.contains("https://example.local/a"));
        assert!(!encoded.contains("https://example.local/b"));
        assert!(encoded.contains("object_ref"));
        assert!(encoded.contains("residue_ref"));
    }

    // Chameleon test_controlled_adapter_rejects_unsupported_capabilities.
    #[test]
    fn rejects_unsupported_capabilities() {
        let (auth, objects, kernel, target) = fixture();
        let framework = ControlledAdapterFramework::new(kernel);
        let intent = ControlIntent::new("authorized adapter operation", &target.name)
            .with_capabilities(["network_observation", "live_packet_manipulation"]);
        let normalize = NormalizeTraceShapeOperator;
        let operators: Vec<&dyn TransformOperator> = vec![&normalize];
        let plan = framework.build_plan(&intent, &objects, &operators, &target, Some(&auth));
        assert_eq!(plan.overall_decision, "FAIL");
        assert!(plan
            .adapter_policy_decision
            .reason
            .starts_with("unsupported_capability:"));
        assert!(plan.steps.is_empty());
    }

    // Chameleon test_export_bundle_can_write_json.
    #[test]
    fn export_bundle_can_write_json() {
        let (auth, objects, kernel, target) = fixture();
        let framework = ControlledAdapterFramework::new(kernel);
        let intent = ControlIntent::new("adapter feedback export", &target.name)
            .with_mode("audit_export")
            .with_export_level("effectiveness_feedback");
        let normalize = NormalizeTraceShapeOperator;
        let operators: Vec<&dyn TransformOperator> = vec![&normalize];
        let plan = framework.build_plan(&intent, &objects[..1], &operators, &target, Some(&auth));
        let dir = std::env::temp_dir().join(format!("ssk-sig-plan-{}", std::process::id()));
        let path = framework
            .export_bundle(&plan)
            .write_json(dir.join("plan.json"))
            .unwrap();
        let loaded: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded["plan"]["plan_id"], plan.plan_id);
        assert_eq!(
            loaded["execution_contract"]["raw_trace_export"],
            "not_included"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
