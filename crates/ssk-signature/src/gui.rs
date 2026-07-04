//! Headless application model — Chameleon `gui.ChameleonGuiModel`.
//!
//! The Tkinter view is not ported (it is a desktop shell, not part of the
//! kernel). What *is* ported is the application model: the closed workflow that
//! ties import → mask → iterate → plan → export together, plus the derived
//! action-state a UI uses to enable/disable steps. This is the session /
//! orchestration struct the SSK surface layer drives.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::audit_ledger::AuditLedger;
use crate::calibration::get_calibration_preset;
use crate::controlled_adapter::{
    AdapterExportBundle, ControlIntent, ControlPlan, ControlledAdapterFramework,
};
use crate::corpus::ProfileCorpus;
use crate::iteration::{IterationParams, RecursiveIterationResult, RecursiveSignatureIterator};
use crate::kernel::ChameleonKernel;
use crate::network_adapter::{
    NetworkAdapter, NetworkAdapterConfig, NetworkRequest, NetworkTransport,
};
use crate::object::SurfaceObject;
use crate::operators::{
    BucketTimingOperator, NormalizeTraceShapeOperator, RedactIdentifierFieldsOperator,
    SortFieldsOperator, TransformOperator,
};
use crate::policy::AuthorizationManifest;
use crate::target::OperationalMask;
use crate::trace_adapter::TraceAdapter;
use crate::url::urlparse;
use crate::value::OrderedMap;

/// Errors surfaced by the application model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GuiError {
    #[error("{0}")]
    Invalid(String),
    #[error("unknown operator: {0}")]
    UnknownOperator(String),
    #[error("trace import error: {0}")]
    Trace(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("corpus error: {0}")]
    Corpus(String),
    #[error("iteration error: {0}")]
    Iteration(String),
    #[error("ledger error: {0}")]
    Ledger(String),
    #[error("export error: {0}")]
    Export(String),
}

/// A snapshot of the model's state.
#[derive(Clone, Debug, PartialEq)]
pub struct GuiSnapshot {
    pub object_count: usize,
    pub mask_name: Option<String>,
    pub plan_decision: Option<String>,
    pub feedback_score: Option<f64>,
    pub ledger_entries: usize,
    pub iteration_stop_reason: Option<String>,
}

/// Which workflow actions are currently available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuiActionState {
    pub import_trace: bool,
    pub fetch_network: bool,
    pub calibrate_target: bool,
    pub build_mask: bool,
    pub build_plan: bool,
    pub run_iteration: bool,
    pub export_plan: bool,
    pub export_ledger: bool,
}

/// The result of a target calibration.
#[derive(Clone, Debug, PartialEq)]
pub struct TargetCalibrationResult {
    pub urls: Vec<String>,
    pub object_count: usize,
    pub mask_name: String,
}

/// Inputs to [`ChameleonGuiModel::action_state`].
#[derive(Clone, Copy, Debug)]
pub struct ActionInputs {
    pub auth_ready: bool,
    pub url_ready: bool,
    pub network_authorized: bool,
    pub selected_operator_count: usize,
    pub calibration_ready: bool,
}

/// The headless Chameleon application model.
#[derive(Default)]
pub struct ChameleonGuiModel {
    pub kernel: ChameleonKernel,
    pub ledger: AuditLedger,
    pub objects: Vec<SurfaceObject>,
    pub mask: Option<OperationalMask>,
    pub plan: Option<ControlPlan>,
    pub bundle: Option<AdapterExportBundle>,
    pub iteration_result: Option<RecursiveIterationResult>,
}

impl ChameleonGuiModel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build an authorization manifest for the workflow.
    #[must_use]
    pub fn build_authorization(
        &self,
        source_name: &str,
        owner_or_controller: &str,
        permission_basis: &str,
        evidence_ref: Option<&str>,
        allow_network: bool,
    ) -> AuthorizationManifest {
        let mut uses = vec![
            "offline_analysis".to_owned(),
            "offline_redaction".to_owned(),
            "adapter_operation".to_owned(),
        ];
        if allow_network {
            uses.push("network_observation".to_owned());
        }
        let mut manifest = AuthorizationManifest::new(
            source_name.trim(),
            owner_or_controller.trim(),
            permission_basis.trim(),
        )
        .with_allowed_uses(uses);
        if let Some(ev) = evidence_ref.map(str::trim).filter(|e| !e.is_empty()) {
            manifest = manifest.with_evidence_ref(ev);
        }
        manifest
    }

    /// Import record maps as surfaces.
    ///
    /// # Errors
    /// [`GuiError::Trace`] if the authorization is not valid for import.
    pub fn import_records(
        &mut self,
        records: &[OrderedMap],
        authorization: &AuthorizationManifest,
    ) -> Result<Vec<SurfaceObject>, GuiError> {
        let adapter =
            TraceAdapter::new(authorization.clone()).map_err(|e| GuiError::Trace(e.to_string()))?;
        let objects = adapter.from_records(records, "application/trace+json");
        self.objects.extend(objects.iter().cloned());
        self.reset_derived();
        Ok(objects)
    }

    /// Fetch an authorized network observation through an injected transport.
    ///
    /// # Errors
    /// [`GuiError::Invalid`] / [`GuiError::Network`] on validation or transport failure.
    pub fn fetch_network_observation(
        &mut self,
        url: &str,
        authorization: &AuthorizationManifest,
        allowed_hosts: &[String],
        include_body: bool,
        transport: &dyn NetworkTransport,
    ) -> Result<SurfaceObject, GuiError> {
        let url = url.trim();
        if url.is_empty() {
            return Err(GuiError::Invalid("url is required".to_owned()));
        }
        let host = urlparse(url).hostname.to_lowercase();
        let hosts = resolve_hosts(allowed_hosts, &host);
        let config = NetworkAdapterConfig::default()
            .with_allowed_hosts(hosts)
            .with_include_body(include_body);
        let adapter = NetworkAdapter::new(authorization.clone(), config, transport)
            .map_err(|e| GuiError::Network(e.to_string()))?;
        let obj = adapter
            .fetch(&NetworkRequest::new(url))
            .map_err(|e| GuiError::Network(e.to_string()))?;
        self.objects.push(obj.clone());
        self.reset_derived();
        Ok(obj)
    }

    /// Calibrate a target from a base URL and paths, building an operational mask.
    ///
    /// # Errors
    /// [`GuiError`] on URL validation, transport, or mask-build failure.
    #[allow(clippy::too_many_arguments)]
    pub fn calibrate_target(
        &mut self,
        base_url: &str,
        paths: &[String],
        authorization: &AuthorizationManifest,
        mask_name: &str,
        version: &str,
        global_tolerance: Option<f64>,
        calibration_preset: &str,
        include_body: bool,
        transport: &dyn NetworkTransport,
    ) -> Result<TargetCalibrationResult, GuiError> {
        let urls = self.calibration_urls(base_url, paths)?;
        let host = urlparse(&urls[0]).hostname.to_lowercase();
        let config = NetworkAdapterConfig::default()
            .with_allowed_hosts([host.clone()])
            .with_include_body(include_body);
        let adapter = NetworkAdapter::new(authorization.clone(), config, transport)
            .map_err(|e| GuiError::Network(e.to_string()))?;
        let mut objects = Vec::with_capacity(urls.len());
        for url in &urls {
            objects.push(
                adapter
                    .fetch(&NetworkRequest::new(url))
                    .map_err(|e| GuiError::Network(e.to_string()))?,
            );
        }
        let object_count = objects.len();
        self.objects = objects;
        self.mask = None;
        self.reset_derived();
        let name = if mask_name.trim().is_empty() {
            host.as_str()
        } else {
            mask_name
        };
        let mask = self.build_mask(name, version, global_tolerance, calibration_preset)?;
        Ok(TargetCalibrationResult {
            urls,
            object_count,
            mask_name: mask.name,
        })
    }

    /// Build an operational mask over the current objects.
    ///
    /// # Errors
    /// [`GuiError::Invalid`] if there are no objects or the preset is unknown;
    /// [`GuiError::Corpus`] on profile build failure.
    pub fn build_mask(
        &mut self,
        name: &str,
        version: &str,
        global_tolerance: Option<f64>,
        calibration_preset: &str,
    ) -> Result<OperationalMask, GuiError> {
        if self.objects.is_empty() {
            return Err(GuiError::Invalid(
                "at least one observation is required".to_owned(),
            ));
        }
        let preset = get_calibration_preset(Some(calibration_preset)).map_err(GuiError::Invalid)?;
        let normalize = NormalizeTraceShapeOperator;
        let signatures: Vec<_> = self
            .objects
            .iter()
            .map(|o| self.kernel.signature_for(&normalize.apply(o).transformed))
            .collect();
        let name_use = {
            let t = name.trim();
            if t.is_empty() {
                "gui_mask"
            } else {
                t
            }
        };
        let ver_use = {
            let t = version.trim();
            if t.is_empty() {
                "1.0.0"
            } else {
                t
            }
        };
        let mut corpus = ProfileCorpus::new();
        let mut tags = vec!["gui".to_owned(), "operational".to_owned()];
        tags.push(preset.name.clone());
        let signature = corpus
            .build_profile(
                name_use,
                ver_use,
                &signatures,
                tags,
                None,
                preset.notes.clone(),
            )
            .map_err(|e| GuiError::Corpus(e.to_string()))?
            .signature
            .clone();
        let mask = OperationalMask {
            name: format!("{name_use}@{ver_use}"),
            signature,
            dimension_tolerances: preset.dimension_tolerances.clone(),
            global_tolerance: global_tolerance.unwrap_or(preset.global_tolerance),
            residue_externalization_surfaces: preset.residue_externalization_surfaces.clone(),
            enforcement_level: "optimize".to_owned(),
        };
        self.mask = Some(mask.clone());
        self.reset_derived();
        Ok(mask)
    }

    /// Build an adapter plan from the current objects, mask, and named operators.
    ///
    /// # Errors
    /// [`GuiError`] if prerequisites are missing or an operator name is unknown.
    pub fn build_plan(
        &mut self,
        authorization: &AuthorizationManifest,
        objective: &str,
        operator_names: &[&str],
    ) -> Result<ControlPlan, GuiError> {
        if self.objects.is_empty() {
            return Err(GuiError::Invalid(
                "at least one observation is required".to_owned(),
            ));
        }
        let mask = self
            .mask
            .clone()
            .ok_or_else(|| GuiError::Invalid("an operational mask is required".to_owned()))?;
        let operators = self.operators_for(operator_names)?;
        let op_refs: Vec<&dyn TransformOperator> = operators.iter().map(AsRef::as_ref).collect();
        let objective = {
            let t = objective.trim();
            if t.is_empty() {
                "authorized adapter operation"
            } else {
                t
            }
        };
        let requested_network_io = self
            .objects
            .iter()
            .any(|o| o.media_type.starts_with("application/network"));
        let intent = ControlIntent::new(objective, &mask.name)
            .with_requested_network_io(requested_network_io);
        let framework = ControlledAdapterFramework::new(self.kernel.clone());
        let plan = framework.build_plan(
            &intent,
            &self.objects,
            &op_refs,
            &mask.to_target_profile(),
            Some(authorization),
        );
        let bundle = framework.export_bundle(&plan);
        self.ledger
            .append(&plan)
            .map_err(|e| GuiError::Ledger(e.to_string()))?;
        self.plan = Some(plan.clone());
        self.bundle = Some(bundle);
        Ok(plan)
    }

    /// Run the recursive iterator over the current objects and mask.
    ///
    /// # Errors
    /// [`GuiError`] if prerequisites are missing or the run fails.
    pub fn run_iteration(
        &mut self,
        authorization: &AuthorizationManifest,
        operator_names: &[&str],
        max_rounds: usize,
        min_improvement: f64,
    ) -> Result<RecursiveIterationResult, GuiError> {
        if self.objects.is_empty() {
            return Err(GuiError::Invalid(
                "at least one observation is required".to_owned(),
            ));
        }
        let mask = self
            .mask
            .clone()
            .ok_or_else(|| GuiError::Invalid("an operational mask is required".to_owned()))?;
        let operators = self.operators_for(operator_names)?;
        let op_refs: Vec<&dyn TransformOperator> = operators.iter().map(AsRef::as_ref).collect();
        let iterator = RecursiveSignatureIterator::new(self.kernel.clone());
        let params = IterationParams {
            mode: "adapter_operation".to_owned(),
            max_rounds,
            min_improvement,
        };
        let result = iterator
            .run(
                &self.objects,
                &op_refs,
                &mask.to_target_profile(),
                Some(authorization),
                &params,
            )
            .map_err(|e| GuiError::Iteration(e.to_string()))?;
        self.ledger
            .append(&result)
            .map_err(|e| GuiError::Ledger(e.to_string()))?;
        self.iteration_result = Some(result.clone());
        Ok(result)
    }

    /// Export the current plan bundle as JSON.
    ///
    /// # Errors
    /// [`GuiError::Invalid`] if no plan is available; [`GuiError::Export`] on write failure.
    pub fn export_plan(&self, path: impl AsRef<Path>) -> Result<PathBuf, GuiError> {
        let bundle = self
            .bundle
            .as_ref()
            .ok_or_else(|| GuiError::Invalid("no plan is available".to_owned()))?;
        bundle.write_json(path).map_err(GuiError::Export)
    }

    /// Export the audit ledger as JSONL.
    ///
    /// # Errors
    /// [`GuiError::Ledger`] on write failure.
    pub fn export_ledger(&self, path: impl AsRef<Path>) -> Result<PathBuf, GuiError> {
        self.ledger
            .write_jsonl(Some(path.as_ref()))
            .map_err(|e| GuiError::Ledger(e.to_string()))
    }

    /// A snapshot of the model state.
    #[must_use]
    pub fn snapshot(&self) -> GuiSnapshot {
        GuiSnapshot {
            object_count: self.objects.len(),
            mask_name: self.mask.as_ref().map(|m| m.name.clone()),
            plan_decision: self.plan.as_ref().map(|p| p.overall_decision.clone()),
            feedback_score: self.plan.as_ref().map(|p| p.feedback_score),
            ledger_entries: self.ledger.len(),
            iteration_stop_reason: self
                .iteration_result
                .as_ref()
                .map(|r| r.stop_reason.clone()),
        }
    }

    /// Which workflow actions are currently available.
    #[must_use]
    pub fn action_state(&self, inputs: ActionInputs) -> GuiActionState {
        let has_objects = !self.objects.is_empty();
        let has_mask = self.mask.is_some();
        let needs_network_auth = self
            .objects
            .iter()
            .any(|o| o.media_type.starts_with("application/network"));
        let ready_to_plan = inputs.auth_ready
            && has_objects
            && has_mask
            && inputs.selected_operator_count > 0
            && (!needs_network_auth || inputs.network_authorized);
        GuiActionState {
            import_trace: inputs.auth_ready,
            fetch_network: inputs.auth_ready && inputs.network_authorized && inputs.url_ready,
            calibrate_target: inputs.auth_ready
                && inputs.network_authorized
                && inputs.calibration_ready,
            build_mask: has_objects,
            build_plan: ready_to_plan,
            run_iteration: ready_to_plan,
            export_plan: self.plan.is_some(),
            export_ledger: !self.ledger.is_empty(),
        }
    }

    /// Resolve base URL + paths into a same-host URL list (Chameleon
    /// `_calibration_urls`).
    ///
    /// # Errors
    /// [`GuiError::Invalid`] if the base URL is invalid or a path leaves the host.
    pub fn calibration_urls(
        &self,
        base_url: &str,
        paths: &[String],
    ) -> Result<Vec<String>, GuiError> {
        let base_url = base_url.trim();
        if base_url.is_empty() {
            return Err(GuiError::Invalid(
                "calibration base URL is required".to_owned(),
            ));
        }
        let base = urlparse(base_url);
        if !matches!(base.scheme.as_str(), "http" | "https") || base.hostname.is_empty() {
            return Err(GuiError::Invalid(
                "calibration base URL must be http or https".to_owned(),
            ));
        }
        let base_context = if base_url.ends_with('/') {
            base_url.to_owned()
        } else {
            format!("{base_url}/")
        };
        let base_host = base.hostname.to_lowercase();
        let authority = match base.port {
            Some(p) => format!("{}:{}", base.hostname, p),
            None => base.hostname.clone(),
        };
        let base_root = format!("{}://{}", base.scheme, authority);

        let mut raw_paths: Vec<String> = paths
            .iter()
            .map(|p| p.trim().to_owned())
            .filter(|p| !p.is_empty())
            .collect();
        if raw_paths.is_empty() {
            raw_paths.push(if base.path.is_empty() {
                "/".to_owned()
            } else {
                base.path.clone()
            });
        }

        let mut urls: Vec<String> = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for raw in raw_paths {
            let candidate = if !urlparse(&raw).scheme.is_empty() {
                raw.clone()
            } else if raw.starts_with('/') {
                format!("{base_root}{raw}")
            } else {
                format!("{base_context}{raw}")
            };
            let pc = urlparse(&candidate);
            if pc.scheme != base.scheme || pc.hostname.to_lowercase() != base_host {
                return Err(GuiError::Invalid(
                    "calibration paths must stay within the base host".to_owned(),
                ));
            }
            if seen.insert(candidate.clone()) {
                urls.push(candidate);
            }
        }
        if urls.is_empty() {
            return Err(GuiError::Invalid(
                "at least one calibration URL is required".to_owned(),
            ));
        }
        Ok(urls)
    }

    fn operators_for(&self, names: &[&str]) -> Result<Vec<Box<dyn TransformOperator>>, GuiError> {
        if names.is_empty() {
            return Err(GuiError::Invalid(
                "at least one operator is required".to_owned(),
            ));
        }
        names.iter().map(|n| operator_for(n)).collect()
    }

    fn reset_derived(&mut self) {
        self.plan = None;
        self.bundle = None;
        self.iteration_result = None;
    }
}

fn resolve_hosts(allowed_hosts: &[String], fallback: &str) -> Vec<String> {
    let filtered: Vec<String> = allowed_hosts
        .iter()
        .map(|h| h.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    if !filtered.is_empty() {
        filtered
    } else if fallback.is_empty() {
        Vec::new()
    } else {
        vec![fallback.to_owned()]
    }
}

fn operator_for(name: &str) -> Result<Box<dyn TransformOperator>, GuiError> {
    match name {
        "Normalize shape" => Ok(Box::new(NormalizeTraceShapeOperator)),
        "Sort fields" => Ok(Box::new(SortFieldsOperator)),
        "Bucket timing" => Ok(Box::new(BucketTimingOperator::default())),
        "Redact identifiers" => Ok(Box::new(RedactIdentifierFieldsOperator::default())),
        other => Err(GuiError::UnknownOperator(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calibration::{calibration_spectrum, DEFAULT_CALIBRATION_PRESET};
    use crate::network_adapter::{NetworkAdapterError, NetworkResponse};
    use crate::value::{OrderedMap, Value};
    use std::cell::RefCell;

    struct FakeTransport;
    impl NetworkTransport for FakeTransport {
        fn send(
            &self,
            request: &NetworkRequest,
            _config: &NetworkAdapterConfig,
        ) -> Result<NetworkResponse, NetworkAdapterError> {
            Ok(NetworkResponse {
                url: request.url.clone(),
                method: request.method.clone(),
                status: 200,
                headers: vec![("Content-Type".to_owned(), "text/plain".to_owned())],
                body: b"ok".to_vec(),
                duration_ms: 9,
                truncated: false,
            })
        }
    }

    #[derive(Default)]
    struct RecordingTransport {
        urls: RefCell<Vec<String>>,
    }
    impl NetworkTransport for RecordingTransport {
        fn send(
            &self,
            request: &NetworkRequest,
            _config: &NetworkAdapterConfig,
        ) -> Result<NetworkResponse, NetworkAdapterError> {
            self.urls.borrow_mut().push(request.url.clone());
            Ok(NetworkResponse {
                url: request.url.clone(),
                method: request.method.clone(),
                status: 200,
                headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
                body: b"{\"ok\":true}".to_vec(),
                duration_ms: 11,
                truncated: false,
            })
        }
    }

    fn http_record() -> OrderedMap {
        OrderedMap::from_iter([
            ("protocol".to_owned(), Value::Text("http".to_owned())),
            ("method".to_owned(), Value::Text("GET".to_owned())),
            (
                "url".to_owned(),
                Value::Text("https://example.local/a".to_owned()),
            ),
            ("status".to_owned(), Value::Num(200.0)),
            ("duration_ms".to_owned(), Value::Num(25.0)),
        ])
    }

    // Chameleon test_calibration_spectrum_exposes_operational_presets.
    #[test]
    fn calibration_spectrum_exposes_operational_presets() {
        let presets = calibration_spectrum();
        let names: BTreeSet<&str> = presets.iter().map(|p| p.name.as_str()).collect();
        for expected in [
            "Domain surface",
            "HTTP fingerprint",
            "Endpoint shape",
            "API family",
            "Timing stability",
            "Header/body surface",
        ] {
            assert!(names.contains(expected));
        }
        let dims: BTreeSet<&str> = presets
            .iter()
            .flat_map(|p| p.dimensions.iter().map(String::as_str))
            .collect();
        for d in [
            "shape",
            "ordering",
            "entropy",
            "timing",
            "semantic",
            "linkability",
            "http_surface",
            "body_schema",
        ] {
            assert!(dims.contains(d), "missing dimension {d}");
        }
    }

    // Chameleon test_gui_model_runs_closed_trace_workflow.
    #[test]
    fn runs_closed_trace_workflow() {
        let dir = std::env::temp_dir().join(format!("ssk-sig-gui-{}", std::process::id()));
        let mut model = ChameleonGuiModel::new();
        let auth = model.build_authorization("gui-fixture", "tester", "owned fixture", None, false);
        model.import_records(&[http_record()], &auth).unwrap();
        model
            .build_mask("gui_mask", "1.0.0", None, DEFAULT_CALIBRATION_PRESET)
            .unwrap();
        let iteration = model
            .run_iteration(&auth, &["Normalize shape"], 2, 1e-6)
            .unwrap();
        model
            .build_plan(
                &auth,
                "authorized adapter operation",
                &["Normalize shape", "Sort fields"],
            )
            .unwrap();
        let plan_path = model.export_plan(dir.join("plan.json")).unwrap();
        let ledger_path = model.export_ledger(dir.join("audit.jsonl")).unwrap();

        let payload: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&plan_path).unwrap()).unwrap();
        assert_eq!(
            payload["execution_contract"]["execution"],
            "supported_for_configured_adapters"
        );
        assert!(
            ["PASS", "OPTIMIZE"].contains(&payload["plan"]["overall_decision"].as_str().unwrap())
        );
        assert!([
            "already_converged",
            "converged",
            "no_candidate_improved",
            "no_significant_improvement",
            "max_rounds"
        ]
        .contains(&iteration.stop_reason.as_str()));
        assert!(!std::fs::read_to_string(&ledger_path)
            .unwrap()
            .trim()
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Chameleon test_gui_model_fetches_network_observation_with_injected_transport.
    #[test]
    fn fetches_network_observation_with_injected_transport() {
        let mut model = ChameleonGuiModel::new();
        let auth = model.build_authorization(
            "owned-service",
            "tester",
            "approved observation",
            None,
            true,
        );
        let obj = model
            .fetch_network_observation(
                "https://example.test/status",
                &auth,
                &[],
                false,
                &FakeTransport,
            )
            .unwrap();
        assert_eq!(obj.fields.get("status"), Some(&Value::Num(200.0)));
        assert_eq!(model.snapshot().object_count, 1);
    }

    // Chameleon test_gui_model_calibrates_domain_target_with_selected_preset.
    #[test]
    fn calibrates_domain_target_with_selected_preset() {
        let mut model = ChameleonGuiModel::new();
        let auth = model.build_authorization(
            "owned-service",
            "tester",
            "approved observation",
            None,
            true,
        );
        let transport = RecordingTransport::default();
        let paths = ["/".to_owned(), "/health".to_owned(), "api/items".to_owned()];
        let result = model
            .calibrate_target(
                "https://example.test",
                &paths,
                &auth,
                "example_api",
                "1.0.0",
                None,
                "Endpoint shape",
                false,
                &transport,
            )
            .unwrap();
        let preset = get_calibration_preset(Some("Endpoint shape")).unwrap();
        assert_eq!(result.object_count, 3);
        assert_eq!(result.mask_name, "example_api@1.0.0");
        assert_eq!(*transport.urls.borrow(), result.urls);
        let mask = model.mask.as_ref().unwrap();
        assert_eq!(mask.dimension_tolerances, preset.dimension_tolerances);
    }

    // Chameleon test_gui_model_rejects_cross_host_calibration_path.
    #[test]
    fn rejects_cross_host_calibration_path() {
        let mut model = ChameleonGuiModel::new();
        let auth = model.build_authorization(
            "owned-service",
            "tester",
            "approved observation",
            None,
            true,
        );
        let err = model
            .calibrate_target(
                "https://example.test",
                &["https://other.test/status".to_owned()],
                &auth,
                "bad",
                "1.0.0",
                None,
                DEFAULT_CALIBRATION_PRESET,
                false,
                &FakeTransport,
            )
            .unwrap_err();
        assert!(err.to_string().contains("base host"));
    }

    // Chameleon test_gui_model_calibration_paths_can_be_relative_to_base_path.
    #[test]
    fn calibration_paths_relative_to_base_path() {
        let model = ChameleonGuiModel::new();
        let urls = model
            .calibration_urls(
                "https://example.test/api",
                &["users".to_owned(), "orders".to_owned()],
            )
            .unwrap();
        assert_eq!(
            urls,
            vec![
                "https://example.test/api/users",
                "https://example.test/api/orders"
            ]
        );
    }

    // Chameleon test_gui_model_can_rebuild_mask_without_duplicate_profile_error.
    #[test]
    fn rebuild_mask_without_duplicate_error() {
        let mut model = ChameleonGuiModel::new();
        let auth = model.build_authorization("gui-fixture", "tester", "owned fixture", None, false);
        model
            .import_records(
                &[OrderedMap::from_iter([
                    ("protocol".to_owned(), Value::Text("http".to_owned())),
                    ("method".to_owned(), Value::Text("GET".to_owned())),
                    ("status".to_owned(), Value::Num(200.0)),
                ])],
                &auth,
            )
            .unwrap();
        let first = model
            .build_mask("repeatable", "1.0.0", None, DEFAULT_CALIBRATION_PRESET)
            .unwrap();
        let second = model
            .build_mask("repeatable", "1.0.0", None, DEFAULT_CALIBRATION_PRESET)
            .unwrap();
        assert_eq!(first.name, "repeatable@1.0.0");
        assert_eq!(second.name, "repeatable@1.0.0");
    }

    // Chameleon test_gui_action_state_matches_closed_workflow.
    #[test]
    fn action_state_matches_closed_workflow() {
        let mut model = ChameleonGuiModel::new();
        let ready = ActionInputs {
            auth_ready: true,
            url_ready: true,
            network_authorized: true,
            selected_operator_count: 1,
            calibration_ready: false,
        };
        let state = model.action_state(ready);
        assert!(state.import_trace);
        assert!(state.fetch_network);
        assert!(!state.calibrate_target);
        assert!(!state.build_mask);
        assert!(!state.build_plan);
        assert!(!state.run_iteration);
        assert!(!state.export_plan);

        let state = model.action_state(ActionInputs {
            calibration_ready: true,
            ..ready
        });
        assert!(state.calibrate_target);

        let auth = model.build_authorization("gui-fixture", "tester", "owned fixture", None, false);
        model
            .import_records(
                &[OrderedMap::from_iter([
                    ("protocol".to_owned(), Value::Text("http".to_owned())),
                    ("method".to_owned(), Value::Text("GET".to_owned())),
                    ("status".to_owned(), Value::Num(200.0)),
                ])],
                &auth,
            )
            .unwrap();
        let state = model.action_state(ready);
        assert!(state.build_mask);
        assert!(!state.build_plan);

        model
            .build_mask("actions", "1.0.0", None, DEFAULT_CALIBRATION_PRESET)
            .unwrap();
        let state = model.action_state(ready);
        assert!(state.build_plan);
        assert!(state.run_iteration);
        assert!(!state.export_plan);

        model
            .build_plan(&auth, "authorized adapter operation", &["Normalize shape"])
            .unwrap();
        let state = model.action_state(ready);
        assert!(state.export_plan);
        assert!(state.export_ledger);
    }
}
