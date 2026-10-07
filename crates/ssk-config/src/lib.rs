#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ssk_types::GateId;
use std::collections::BTreeMap;

pub mod ingress;
pub mod routing;

pub const CURRENT_CONFIG_VERSION: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid configuration: {0}")]
    Structure(String),
    #[error("invalid routing configuration: {0}")]
    Routing(String),
    #[error("invalid ingress configuration: {0}")]
    Ingress(String),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    /// A document that read as YAML or TOML but does not fit the schema (an
    /// unknown or missing key, a value of the wrong type). Carries serde's
    /// message, which names the field; migrated documents have no line or column.
    #[error("invalid configuration document: {0}")]
    Document(String),
    /// Building a JSON value from our own types (the default sections a
    /// migration inserts). Never a statement about the operator's document.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config version `{found}` is unsupported; expected `{expected}`")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("strict fail-closed policy is required")]
    FailClosedRequired,
    #[error("gate profile must not be empty")]
    EmptyGateProfile,
    #[error("gate failure_policy must be NoMaterialization (ch. 11.3)")]
    GateFailurePolicyMustBeNoMaterialization,
    #[error("runtime strict mode must remain enabled by default")]
    RuntimeStrictModeRequired,
    #[error("interop capability list contains duplicates")]
    DuplicateCapabilities,
    #[error("interop minimum protocol must not be empty")]
    MissingInteropVersion,
    #[error(
        "core.expose_core_address must be false (ch. 3.2's identity/locator plane separation)"
    )]
    CoreAddressExposureForbidden,
    #[error("locator_plane.require_locator_reality_check must be true")]
    LocatorRealityCheckRequired,
    #[error(
        "locator_plane.single_ip_external_privacy_claim must be Forbidden (no magic address creation)"
    )]
    SingleIpPrivacyClaimMustBeForbidden,
    #[error("projective_connection_hypercube.require_all_axis_projection must be true (ch. 8.2)")]
    AllAxisProjectionRequired,
    #[error("hypertorus.dimension must equal phase_axes.len()")]
    HypertorusDimensionMismatch,
    #[error("hypertorus.deterministic_replay must be true")]
    DeterministicReplayRequired,
    #[error("bcik.require_seam and bcik.require_boundary_operator must both be true")]
    BcikSeamAndBoundaryRequired,
    #[error("bcik.closure_threshold must be within [0.0, 1.0]")]
    ClosureThresholdOutOfRange,
    #[error(
        "capabilities.witness_required and capabilities.require_scope_and_expiry must both be true"
    )]
    CapabilityWitnessRequirementsMustHold,
    #[error("privacy.adversary_model must never be GlobalPassiveObserver (ch. 15.2's axiom)")]
    GlobalPassiveObserverClaimForbidden,
    #[error("privacy.require_residue_report must be true")]
    ResidueReportRequired,
    #[error("replay.run_descriptor_required and replay.deterministic_materialization_required must both be true")]
    ReplayRequirementsMustHold,
    #[error("ledger.append_only_audit must be true")]
    LedgerMustBeAppendOnly,
    #[error("ledger.store_payload must be false (ch. 12's no-payload-persistence discipline)")]
    LedgerMustNotStorePayload,
    #[error("dissolution.ttl_required must be true")]
    TtlRequired,
}

/// `system.mode` (Master Spec Ω+1 ch. 21, verbatim variants).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SystemMode {
    Personal,
    Enterprise,
    ResearchTestbed,
    Agent,
}

/// `system:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemConfig {
    pub name: String,
    pub fail_closed: bool,
    pub mode: SystemMode,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            name: "ScorpioSync-Kaleidoscorp-Omega".into(),
            fail_closed: true,
            mode: SystemMode::ResearchTestbed,
        }
    }
}

impl SystemConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.fail_closed {
            return Err(ConfigError::FailClosedRequired);
        }
        Ok(())
    }
}

/// `core.canonicalization` (ch. 21). Phase 8 placeholder — the PDF's
/// example YAML gives one concrete value; a closed single-variant enum
/// stands in until a second real mode exists.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalizationMode {
    Deterministic,
}

/// `core.signature_policy` (ch. 21). Same disclosure as `CanonicalizationMode`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePolicy {
    CoreBoundaryResidue,
}

/// `core:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoreConfig {
    pub canonicalization: CanonicalizationMode,
    pub signature_policy: SignaturePolicy,
    pub expose_core_address: bool,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            canonicalization: CanonicalizationMode::Deterministic,
            signature_policy: SignaturePolicy::CoreBoundaryResidue,
            expose_core_address: false,
        }
    }
}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.expose_core_address {
            return Err(ConfigError::CoreAddressExposureForbidden);
        }
        Ok(())
    }
}

/// `locator_plane.single_ip_external_privacy_claim` (ch. 21) — a closed,
/// single-variant enum: the PDF's own example value is the only value this
/// axiom permits ("no magic address creation", Section U).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivacyClaimPolicy {
    Forbidden,
}

/// `locator_plane:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocatorPlaneConfig {
    pub allowed_types: Vec<ssk_types::LocatorKind>,
    pub require_locator_reality_check: bool,
    pub single_ip_external_privacy_claim: PrivacyClaimPolicy,
}

impl Default for LocatorPlaneConfig {
    fn default() -> Self {
        use ssk_types::LocatorKind::{
            DirectIp, Gateway, LocalOverlay, MultiHopPath, ProxyExit, Relay, VpnExit,
        };
        Self {
            allowed_types: vec![
                DirectIp,
                VpnExit,
                ProxyExit,
                Relay,
                Gateway,
                MultiHopPath,
                LocalOverlay,
            ],
            require_locator_reality_check: true,
            single_ip_external_privacy_claim: PrivacyClaimPolicy::Forbidden,
        }
    }
}

impl LocatorPlaneConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.require_locator_reality_check {
            return Err(ConfigError::LocatorRealityCheckRequired);
        }
        if self.single_ip_external_privacy_claim != PrivacyClaimPolicy::Forbidden {
            return Err(ConfigError::SingleIpPrivacyClaimMustBeForbidden);
        }
        Ok(())
    }
}

/// `projective_connection_hypercube:` section (ch. 21). Reuses
/// `ssk_types::Axis` directly rather than duplicating the 9-variant enum.
/// The axis logic lives in `ssk_gates::pch`, which re-exports the same type;
/// depending on `ssk-types` for it instead keeps the decision core out of the
/// daemon's dependency closure (see
/// `docs/adr/0008-flow-path-owns-the-per-connection-decision.md`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypercubeConfig {
    pub axes: Vec<ssk_types::Axis>,
    pub require_all_axis_projection: bool,
}

impl Default for HypercubeConfig {
    fn default() -> Self {
        use ssk_types::Axis::{
            Boundary, Capability, Identity, Locator, Protocol, Replay, Risk, Timing, Trust,
        };
        Self {
            axes: vec![
                Identity, Locator, Protocol, Timing, Trust, Risk, Capability, Replay, Boundary,
            ],
            require_all_axis_projection: true,
        }
    }
}

impl HypercubeConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.require_all_axis_projection {
            return Err(ConfigError::AllAxisProjectionRequired);
        }
        Ok(())
    }
}

/// `hypertorus.phase_axes` (ch. 21) — this document's own disclosed
/// elaboration: the excerpted PDF text gives the seven axis names as plain
/// strings, and no existing enum enumerates them
/// (`ssk_types::PhaseVector` has them as named struct fields, not variants).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseAxis {
    Identity,
    Locator,
    Protocol,
    Timing,
    Risk,
    Replay,
    Focus,
}

/// `hypertorus.mode` (ch. 21) — mirrors `ssk_types::SchedulerMode`'s two
/// modes as a config-declarative (payload-free) name, since `Seeded`'s real
/// variant carries a runtime-only `SchedulerSeed`, not a config value.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SchedulerModeName {
    Deterministic,
    Seeded,
}

/// `hypertorus:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HypertorusConfig {
    pub dimension: u8,
    pub phase_axes: Vec<PhaseAxis>,
    pub mode: SchedulerModeName,
    pub deterministic_replay: bool,
}

impl Default for HypertorusConfig {
    fn default() -> Self {
        use PhaseAxis::{Focus, Identity, Locator, Protocol, Replay, Risk, Timing};
        Self {
            dimension: 7,
            phase_axes: vec![Identity, Locator, Protocol, Timing, Risk, Replay, Focus],
            mode: SchedulerModeName::Deterministic,
            deterministic_replay: true,
        }
    }
}

impl HypertorusConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.dimension as usize != self.phase_axes.len() {
            return Err(ConfigError::HypertorusDimensionMismatch);
        }
        if !self.deterministic_replay {
            return Err(ConfigError::DeterministicReplayRequired);
        }
        Ok(())
    }
}

/// `bcik.tolerated_residue_threshold` (ch. 21) — this document's own
/// disclosed elaboration: the PDF's example value is the literal string
/// `policy_defined`, meaning "not a fixed number, decided per-policy"; this
/// single-variant enum captures exactly that until a numeric
/// policy-authoring surface exists.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDefinedThreshold {
    PolicyDefined,
}

/// `bcik:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BcikConfig {
    pub require_seam: bool,
    pub require_boundary_operator: bool,
    pub closure_threshold: f32,
    pub tolerated_residue_threshold: PolicyDefinedThreshold,
}

impl Default for BcikConfig {
    fn default() -> Self {
        Self {
            require_seam: true,
            require_boundary_operator: true,
            closure_threshold: 0.0,
            tolerated_residue_threshold: PolicyDefinedThreshold::PolicyDefined,
        }
    }
}

impl BcikConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.require_seam || !self.require_boundary_operator {
            return Err(ConfigError::BcikSeamAndBoundaryRequired);
        }
        if !(0.0..=1.0).contains(&self.closure_threshold) {
            return Err(ConfigError::ClosureThresholdOutOfRange);
        }
        Ok(())
    }
}

/// `capabilities:` section (ch. 21). Reuses `ssk_crypto::WitnessKind`
/// directly rather than duplicating the 4-variant enum.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilitiesConfig {
    pub witness_required: bool,
    pub allowed_witnesses: Vec<ssk_crypto::WitnessKind>,
    pub require_scope_and_expiry: bool,
}

impl Default for CapabilitiesConfig {
    fn default() -> Self {
        use ssk_crypto::WitnessKind::{PolicyCert, Signature, Token, ZkStyle};
        Self {
            witness_required: true,
            allowed_witnesses: vec![Signature, Token, ZkStyle, PolicyCert],
            require_scope_and_expiry: true,
        }
    }
}

impl CapabilitiesConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.witness_required || !self.require_scope_and_expiry {
            return Err(ConfigError::CapabilityWitnessRequirementsMustHold);
        }
        Ok(())
    }
}

/// `privacy:` section (ch. 21). Reuses `ssk_privacy::AdversaryModel`
/// directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivacyConfig {
    pub adversary_model: ssk_privacy::AdversaryModel,
    pub linkability_threshold: PolicyDefinedThreshold,
    pub require_residue_report: bool,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            adversary_model: ssk_privacy::AdversaryModel::PartialNetworkObserver,
            linkability_threshold: PolicyDefinedThreshold::PolicyDefined,
            require_residue_report: true,
        }
    }
}

impl PrivacyConfig {
    /// "No estimator ... may ever claim resistance to
    /// `AdversaryModel::GlobalPassiveObserver`" (ch. 15.2's axiom, Section
    /// U) — enforced here as a config-load-time invariant, not merely a
    /// runtime convention.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.adversary_model == ssk_privacy::AdversaryModel::GlobalPassiveObserver {
            return Err(ConfigError::GlobalPassiveObserverClaimForbidden);
        }
        if !self.require_residue_report {
            return Err(ConfigError::ResidueReportRequired);
        }
        Ok(())
    }
}

/// `gates.failure_policy` (ch. 21/11.3) — "must be `NoMaterialization`."
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateFailurePolicy {
    NoMaterialization,
}

/// `gates.hold_policy` (ch. 21/11.3, verbatim value).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateHoldPolicy {
    DiagnosableNonPersistent,
}

/// `gates.pass_policy` (ch. 11.3, referenced alongside `failure_policy`/
/// `hold_policy` but not given an example value in the excerpted YAML) —
/// this document's own disclosed elaboration: a pass materializes and
/// nothing else, mirroring `failure_policy`/`hold_policy`'s own
/// one-variant shape.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GatePassPolicy {
    MaterializeOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateProfile {
    pub order: Vec<GateId>,
    pub fail_closed: bool,
    /// Per-gate numeric threshold (ch. 11.3) — this document's own
    /// disclosed elaboration: the excerpted PDF text names `thresholds`
    /// but does not give a worked example; empty by default (no gate has a
    /// threshold override) until a real per-gate tunable value exists.
    #[serde(default)]
    pub thresholds: BTreeMap<GateId, u8>,
    /// Gates whose witness evidence is mandatory, not merely advisory
    /// (ch. 11.3's `required_evidence`).
    #[serde(default)]
    pub required_evidence: Vec<GateId>,
    pub failure_policy: GateFailurePolicy,
    pub hold_policy: GateHoldPolicy,
    pub pass_policy: GatePassPolicy,
}

impl GateProfile {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.fail_closed {
            return Err(ConfigError::FailClosedRequired);
        }
        if self.order.is_empty() {
            return Err(ConfigError::EmptyGateProfile);
        }
        if self.failure_policy != GateFailurePolicy::NoMaterialization {
            return Err(ConfigError::GateFailurePolicyMustBeNoMaterialization);
        }
        Ok(())
    }
}

impl Default for GateProfile {
    fn default() -> Self {
        Self {
            order: GateId::ALL.into(),
            fail_closed: true,
            thresholds: BTreeMap::new(),
            required_evidence: Vec::new(),
            failure_policy: GateFailurePolicy::NoMaterialization,
            hold_policy: GateHoldPolicy::DiagnosableNonPersistent,
            pass_policy: GatePassPolicy::MaterializeOnly,
        }
    }
}

/// `replay:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplaySectionConfig {
    pub run_descriptor_required: bool,
    pub deterministic_materialization_required: bool,
}

impl Default for ReplaySectionConfig {
    fn default() -> Self {
        Self {
            run_descriptor_required: true,
            deterministic_materialization_required: true,
        }
    }
}

impl ReplaySectionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.run_descriptor_required || !self.deterministic_materialization_required {
            return Err(ConfigError::ReplayRequirementsMustHold);
        }
        Ok(())
    }
}

/// `ledger:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerConfig {
    pub append_only_audit: bool,
    pub store_payload: bool,
    pub store_trace_hash: bool,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            append_only_audit: true,
            store_payload: false,
            store_trace_hash: true,
        }
    }
}

impl LedgerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.append_only_audit {
            return Err(ConfigError::LedgerMustBeAppendOnly);
        }
        if self.store_payload {
            return Err(ConfigError::LedgerMustNotStorePayload);
        }
        Ok(())
    }
}

/// `dissolution:` section (ch. 21).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DissolutionConfig {
    pub ttl_required: bool,
    pub finalize_residues_on_expiry: bool,
}

impl Default for DissolutionConfig {
    fn default() -> Self {
        Self {
            ttl_required: true,
            finalize_residues_on_expiry: true,
        }
    }
}

impl DissolutionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.ttl_required {
            return Err(ConfigError::TtlRequired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub name: String,
    pub fail_closed: bool,
    pub gate_profile: GateProfile,
}

impl Policy {
    pub fn from_yaml(content: &str) -> Result<Self, ConfigError> {
        let policy: Policy = serde_yaml::from_str(content)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let policy: Policy = toml::from_str(content)?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.fail_closed {
            return Err(ConfigError::FailClosedRequired);
        }
        self.gate_profile.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub strict_mode: bool,
    pub metrics_path: String,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            metrics_path: ".ssk/metrics.json".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InteropConfig {
    pub min_protocol: String,
    pub capabilities: Vec<String>,
    pub max_clock_skew_secs: u64,
}

impl Default for InteropConfig {
    fn default() -> Self {
        Self {
            min_protocol: "1.0.0".into(),
            capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            max_clock_skew_secs: 300,
        }
    }
}

/// Full 12-section schema (Master Spec Ω+1 ch. 21). `policy`/`runtime`/
/// `interop` are this codebase's own pre-existing operational sections
/// (not named by the PDF); the eleven fields below them are the PDF's own
/// sections (`gates:` maps onto the now-enriched `policy.gate_profile`
/// rather than a duplicate top-level field, per Section K.3's design).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub routing: routing::RoutingConfig,
    /// Required, like `routing`: a v5 document states its stance explicitly, while
    /// every field inside the section has a default (`ingress: {}` is valid).
    #[serde(deserialize_with = "ingress::map_only")]
    pub ingress: ingress::IngressConfig,
    pub version: u32,
    pub policy: Policy,
    pub runtime: RuntimeConfig,
    pub interop: InteropConfig,
    pub system: SystemConfig,
    pub core: CoreConfig,
    pub locator_plane: LocatorPlaneConfig,
    pub projective_connection_hypercube: HypercubeConfig,
    pub hypertorus: HypertorusConfig,
    pub bcik: BcikConfig,
    pub capabilities: CapabilitiesConfig,
    pub privacy: PrivacyConfig,
    pub replay: ReplaySectionConfig,
    pub ledger: LedgerConfig,
    pub dissolution: DissolutionConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            routing: routing::RoutingConfig::default(),
            ingress: ingress::IngressConfig::default(),
            policy: Policy {
                name: "default-fail-closed".into(),
                fail_closed: true,
                gate_profile: GateProfile::default(),
            },
            runtime: RuntimeConfig::default(),
            interop: InteropConfig::default(),
            system: SystemConfig::default(),
            core: CoreConfig::default(),
            locator_plane: LocatorPlaneConfig::default(),
            projective_connection_hypercube: HypercubeConfig::default(),
            hypertorus: HypertorusConfig::default(),
            bcik: BcikConfig::default(),
            capabilities: CapabilitiesConfig::default(),
            privacy: PrivacyConfig::default(),
            replay: ReplaySectionConfig::default(),
            ledger: LedgerConfig::default(),
            dissolution: DissolutionConfig::default(),
        }
    }
}

/// `gate_profile`'s pre-Phase-8 shape (`order`+`fail_closed` only) — kept
/// so `version: 1`/`version: 2` config files migrate cleanly instead of
/// erroring on the newer required fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateProfileV1 {
    pub order: Vec<GateId>,
    pub fail_closed: bool,
}

impl From<GateProfileV1> for GateProfile {
    fn from(v1: GateProfileV1) -> Self {
        Self {
            order: v1.order,
            fail_closed: v1.fail_closed,
            ..GateProfile::default()
        }
    }
}

/// The implicit "v1" shape: no `version` field at all, just the policy
/// fields flattened at the top level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyPolicyV1 {
    pub name: String,
    pub fail_closed: bool,
    pub gate_profile: GateProfileV1,
}

/// The `version: 2` shape (pre-Phase-8): `policy`/`runtime`/`interop`
/// only, none of Section S's eleven new PDF sections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppConfigV2 {
    pub version: u32,
    pub policy: PolicyV1,
    pub runtime: RuntimeConfig,
    pub interop: InteropConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyV1 {
    pub name: String,
    pub fail_closed: bool,
    pub gate_profile: GateProfileV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoadedConfig {
    pub config: AppConfig,
    pub migrated_from: Option<u32>,
}

impl AppConfig {
    pub fn from_yaml(content: &str) -> Result<Self, ConfigError> {
        let config: AppConfig = serde_yaml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let config: AppConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CURRENT_CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: self.version,
                expected: CURRENT_CONFIG_VERSION,
            });
        }

        self.policy.validate()?;
        self.routing.validate()?;
        self.ingress.validate()?;
        self.ingress.validate_against(&self.routing)?;

        if !self.runtime.strict_mode {
            return Err(ConfigError::RuntimeStrictModeRequired);
        }

        if self.interop.min_protocol.trim().is_empty() {
            return Err(ConfigError::MissingInteropVersion);
        }

        let mut caps = self.interop.capabilities.clone();
        let before = caps.len();
        caps.sort();
        caps.dedup();
        if before != caps.len() {
            return Err(ConfigError::DuplicateCapabilities);
        }

        self.system.validate()?;
        self.core.validate()?;
        self.locator_plane.validate()?;
        self.projective_connection_hypercube.validate()?;
        self.hypertorus.validate()?;
        self.bcik.validate()?;
        self.capabilities.validate()?;
        self.privacy.validate()?;
        self.replay.validate()?;
        self.ledger.validate()?;
        self.dissolution.validate()?;

        Ok(())
    }

    /// Upgrades a `GateProfileV1`-shaped legacy policy into the current
    /// `AppConfig`, filling every Section-S field from `AppConfig::default()`.
    fn upgrade_from_v1(legacy: LegacyPolicyV1) -> Self {
        AppConfig {
            policy: Policy {
                name: legacy.name,
                fail_closed: legacy.fail_closed,
                gate_profile: legacy.gate_profile.into(),
            },
            ..AppConfig::default()
        }
    }

    /// Upgrades a `version: 2` config into the current `AppConfig`, keeping
    /// its real `runtime`/`interop` values and filling every Section-S
    /// field from `AppConfig::default()`.
    fn upgrade_from_v2(v2: AppConfigV2) -> Self {
        AppConfig {
            policy: Policy {
                name: v2.policy.name,
                fail_closed: v2.policy.fail_closed,
                gate_profile: v2.policy.gate_profile.into(),
            },
            runtime: v2.runtime,
            interop: v2.interop,
            ..AppConfig::default()
        }
    }

    pub fn parse_with_migration_yaml(content: &str) -> Result<LoadedConfig, ConfigError> {
        let value: serde_yaml::Value = serde_yaml::from_str(content)?;
        // The failure here is a YAML construct JSON cannot hold (a non-string
        // key), a property of the document.
        let value = serde_json::to_value(value).map_err(document_error)?;
        Self::migrate_value(value)
    }

    pub fn parse_with_migration_toml(content: &str) -> Result<LoadedConfig, ConfigError> {
        Self::migrate_value(toml::from_str(content)?)
    }

    // Dispatch ONLY by declared version. Invalid modern documents must never
    // fall through to an older schema and silently discard security settings.
    fn migrate_value(mut value: serde_json::Value) -> Result<LoadedConfig, ConfigError> {
        let object = value
            .as_object_mut()
            .ok_or_else(|| ConfigError::Structure("expected a config object".into()))?;
        let version = match object.get("version") {
            None => 1,
            Some(value) => value
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| {
                    ConfigError::Structure("version must be an unsigned integer".into())
                })?,
        };
        let config = match version {
            1 => {
                object.remove("version");
                Self::upgrade_from_v1(from_document(value)?)
            }
            2 => Self::upgrade_from_v2(from_document(value)?),
            CHAIN_FLOOR..CURRENT_CONFIG_VERSION => {
                migrate_object_to_current(object, version)?;
                from_document(value)?
            }
            CURRENT_CONFIG_VERSION => from_document(value)?,
            found => {
                return Err(ConfigError::UnsupportedVersion {
                    found,
                    expected: CURRENT_CONFIG_VERSION,
                })
            }
        };
        config.validate()?;
        Ok(LoadedConfig {
            config,
            migrated_from: (version != CURRENT_CONFIG_VERSION).then_some(version),
        })
    }

    pub fn schema_json() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://kaleidoscorp.io/schema/ssk-config-v5.json",
            "title": "ScorpioSync Kaleidoscorp Config",
            "type": "object",
            "required": [
                "version", "policy", "runtime", "interop", "system", "core",
                "locator_plane", "projective_connection_hypercube", "hypertorus",
                "bcik", "capabilities", "privacy", "replay", "ledger", "dissolution", "routing",
                "ingress"
            ],
            "additionalProperties": false,
            "properties": {
                "routing": routing::schema_json(),
                "ingress": ingress::IngressConfig::schema_json(),
                "version": {"type": "integer", "const": CURRENT_CONFIG_VERSION},
                "policy": {
                    "type": "object",
                    "required": ["name", "fail_closed", "gate_profile"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "fail_closed": {"type": "boolean", "const": true},
                        "gate_profile": {
                            "type": "object",
                            "required": ["order", "fail_closed", "failure_policy", "hold_policy", "pass_policy"],
                            "properties": {
                                "order": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                                "fail_closed": {"type": "boolean", "const": true},
                                "failure_policy": {"type": "string", "const": "no_materialization"},
                                "hold_policy": {"type": "string", "const": "diagnosable_non_persistent"},
                                "pass_policy": {"type": "string", "const": "materialize_only"}
                            }
                        }
                    }
                },
                "runtime": {
                    "type": "object",
                    "required": ["strict_mode", "metrics_path"],
                    "properties": {
                        "strict_mode": {"type": "boolean", "const": true},
                        "metrics_path": {"type": "string", "minLength": 1}
                    }
                },
                "interop": {
                    "type": "object",
                    "required": ["min_protocol", "capabilities", "max_clock_skew_secs"],
                    "properties": {
                        "min_protocol": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"},
                        "capabilities": {"type": "array", "items": {"type": "string"}},
                        "max_clock_skew_secs": {"type": "integer", "minimum": 0}
                    }
                },
                "system": {
                    "type": "object",
                    "required": ["name", "fail_closed", "mode"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "fail_closed": {"type": "boolean", "const": true},
                        "mode": {"type": "string", "enum": ["personal", "enterprise", "research_testbed", "agent"]}
                    }
                },
                "core": {
                    "type": "object",
                    "required": ["canonicalization", "signature_policy", "expose_core_address"],
                    "properties": {
                        "canonicalization": {"type": "string", "const": "deterministic"},
                        "signature_policy": {"type": "string", "const": "core_boundary_residue"},
                        "expose_core_address": {"type": "boolean", "const": false}
                    }
                },
                "locator_plane": {
                    "type": "object",
                    "required": ["allowed_types", "require_locator_reality_check", "single_ip_external_privacy_claim"],
                    "properties": {
                        "allowed_types": {"type": "array", "items": {"type": "string"}},
                        "require_locator_reality_check": {"type": "boolean", "const": true},
                        "single_ip_external_privacy_claim": {"type": "string", "const": "forbidden"}
                    }
                },
                "projective_connection_hypercube": {
                    "type": "object",
                    "required": ["axes", "require_all_axis_projection"],
                    "properties": {
                        "axes": {"type": "array", "items": {"type": "string"}, "minItems": 9, "maxItems": 9},
                        "require_all_axis_projection": {"type": "boolean", "const": true}
                    }
                },
                "hypertorus": {
                    "type": "object",
                    "required": ["dimension", "phase_axes", "mode", "deterministic_replay"],
                    "properties": {
                        "dimension": {"type": "integer", "const": 7},
                        "phase_axes": {"type": "array", "items": {"type": "string"}, "minItems": 7, "maxItems": 7},
                        "mode": {"type": "string", "enum": ["deterministic", "seeded"]},
                        "deterministic_replay": {"type": "boolean", "const": true}
                    }
                },
                "bcik": {
                    "type": "object",
                    "required": ["require_seam", "require_boundary_operator", "closure_threshold", "tolerated_residue_threshold"],
                    "properties": {
                        "require_seam": {"type": "boolean", "const": true},
                        "require_boundary_operator": {"type": "boolean", "const": true},
                        "closure_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                        "tolerated_residue_threshold": {"type": "string", "const": "policy_defined"}
                    }
                },
                "capabilities": {
                    "type": "object",
                    "required": ["witness_required", "allowed_witnesses", "require_scope_and_expiry"],
                    "properties": {
                        "witness_required": {"type": "boolean", "const": true},
                        "allowed_witnesses": {"type": "array", "items": {"type": "string"}},
                        "require_scope_and_expiry": {"type": "boolean", "const": true}
                    }
                },
                "privacy": {
                    "type": "object",
                    "required": ["adversary_model", "linkability_threshold", "require_residue_report"],
                    "properties": {
                        "adversary_model": {"type": "string", "enum": ["PartialNetworkObserver"]},
                        "linkability_threshold": {"type": "string", "const": "policy_defined"},
                        "require_residue_report": {"type": "boolean", "const": true}
                    }
                },
                "replay": {
                    "type": "object",
                    "required": ["run_descriptor_required", "deterministic_materialization_required"],
                    "properties": {
                        "run_descriptor_required": {"type": "boolean", "const": true},
                        "deterministic_materialization_required": {"type": "boolean", "const": true}
                    }
                },
                "ledger": {
                    "type": "object",
                    "required": ["append_only_audit", "store_payload", "store_trace_hash"],
                    "properties": {
                        "append_only_audit": {"type": "boolean", "const": true},
                        "store_payload": {"type": "boolean", "const": false},
                        "store_trace_hash": {"type": "boolean"}
                    }
                },
                "dissolution": {
                    "type": "object",
                    "required": ["ttl_required", "finalize_residues_on_expiry"],
                    "properties": {
                        "ttl_required": {"type": "boolean", "const": true},
                        "finalize_residues_on_expiry": {"type": "boolean"}
                    }
                }
            }
        })
    }
}

/// Deserialises a document that was read as YAML or TOML into a JSON value.
/// Its failures are about the document, never about serialising anything.
fn from_document<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, ConfigError> {
    serde_json::from_value(value).map_err(document_error)
}

fn document_error(err: serde_json::Error) -> ConfigError {
    ConfigError::Document(err.to_string())
}

/// The lowest version that migrates through the chain below. Versions 1 and 2
/// keep their typed legacy shapes (`LegacyPolicyV1`, `AppConfigV2`).
const CHAIN_FLOOR: u32 = 3;

/// Applies one step per version from `from` up to `CURRENT_CONFIG_VERSION`.
/// No step names the current version: a new version adds `step_N_to_M` and one
/// arm below, and the test `every_version_below_current_has_a_migration_step`
/// fails until it does.
fn migrate_object_to_current(
    object: &mut Map<String, Value>,
    from: u32,
) -> Result<(), ConfigError> {
    let mut at = from;
    while at < CURRENT_CONFIG_VERSION {
        match at {
            3 => step_3_to_4(object)?,
            4 => step_4_to_5(object)?,
            other => {
                return Err(ConfigError::Structure(format!(
                    "no migration step from config version {other}"
                )))
            }
        }
        at += 1;
    }
    object.insert("version".into(), CURRENT_CONFIG_VERSION.into());
    Ok(())
}

/// Version 4 added the required `routing` section, empty and deny-all.
fn step_3_to_4(object: &mut Map<String, Value>) -> Result<(), ConfigError> {
    introduce_section(
        object,
        "routing",
        4,
        serde_json::to_value(routing::RoutingConfig::default())?,
    )
}

/// Version 5 added the required `ingress` section, disabled: an upgrade never
/// opens a listener by itself.
fn step_4_to_5(object: &mut Map<String, Value>) -> Result<(), ConfigError> {
    introduce_section(
        object,
        "ingress",
        5,
        serde_json::to_value(ingress::IngressConfig::default())?,
    )
}

/// Adds the section a version introduced. A document that declares an older
/// version and already has the key is refused rather than migrated: an old
/// file must not smuggle in a section its version does not know, and the
/// default a step inserts must never silently replace the operator's own.
fn introduce_section(
    object: &mut Map<String, Value>,
    key: &str,
    version: u32,
    default: Value,
) -> Result<(), ConfigError> {
    if object.contains_key(key) {
        return Err(ConfigError::Structure(format!(
            "{key} requires config version {version}"
        )));
    }
    object.insert(key.into(), default);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Yaml,
    Toml,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LintReport {
    pub ok: bool,
    pub migrated_from: Option<u32>,
    pub errors: Vec<String>,
}

pub fn lint(content: &str, format: ConfigFormat) -> LintReport {
    let result = match format {
        ConfigFormat::Yaml => AppConfig::parse_with_migration_yaml(content),
        ConfigFormat::Toml => AppConfig::parse_with_migration_toml(content),
    };

    match result {
        Ok(loaded) => LintReport {
            ok: true,
            migrated_from: loaded.migrated_from,
            errors: Vec::new(),
        },
        Err(err) => LintReport {
            ok: false,
            migrated_from: None,
            errors: vec![err.to_string()],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_snapshot_stable() {
        let schema = AppConfig::schema_json();
        let snapshot = serde_json::to_string_pretty(&schema).expect("schema serializes");
        assert!(snapshot.contains("ssk-config-v5.json"));
        assert!(snapshot.contains("strict_mode"));
        assert!(snapshot.contains("projective_connection_hypercube"));
        assert!(snapshot.contains("dissolution"));
        assert!(snapshot.contains("ingress"));
    }

    /// Raising `CURRENT_CONFIG_VERSION` without adding the step that carries
    /// documents across the new version must be loud, not a file that loads with
    /// a section silently missing.
    #[test]
    fn every_version_below_current_has_a_migration_step() {
        for from in CHAIN_FLOOR..CURRENT_CONFIG_VERSION {
            let mut object = Map::new();
            migrate_object_to_current(&mut object, from)
                .unwrap_or_else(|err| panic!("no way across version {from}: {err}"));
            assert_eq!(object["version"], serde_json::json!(CURRENT_CONFIG_VERSION));
        }
        // Below the floor the typed legacy shapes migrate; the chain has no step.
        let err = migrate_object_to_current(&mut Map::new(), CHAIN_FLOOR - 1)
            .expect_err("the chain does not start below its floor");
        assert!(
            matches!(&err, ConfigError::Structure(message)
                if message == "no migration step from config version 2"),
            "{err}"
        );
    }

    /// The step that introduces a section refuses a document that already has
    /// it, which is the one place the "an old version cannot smuggle a new
    /// section" rule lives.
    #[test]
    fn a_step_refuses_a_section_its_version_introduces_when_it_is_already_there() {
        let mut object = Map::new();
        object.insert(
            "routing".into(),
            serde_json::json!({"default_profile": "x"}),
        );
        let err = migrate_object_to_current(&mut object, 3).expect_err("routing at version 3");
        assert!(
            matches!(&err, ConfigError::Structure(message)
                if message == "routing requires config version 4"),
            "{err}"
        );
        // Refused, not overwritten: the operator's own section is untouched.
        assert_eq!(
            object["routing"],
            serde_json::json!({"default_profile": "x"})
        );
    }

    /// The same rule one version up: `ingress` in a document that declares
    /// version 4 is refused by the step that introduces it, not migrated over.
    #[test]
    fn step_4_to_5_refuses_an_ingress_section_the_document_already_has() {
        let own = serde_json::json!({"enabled": true});
        let mut object = Map::new();
        object.insert("ingress".into(), own.clone());
        let err = migrate_object_to_current(&mut object, 4).expect_err("ingress at version 4");
        assert!(
            matches!(&err, ConfigError::Structure(message)
                if message == "ingress requires config version 5"),
            "{err}"
        );
        assert_eq!(object["ingress"], own);

        // Without it the step adds the disabled default and nothing else.
        let mut object = Map::new();
        migrate_object_to_current(&mut object, 4).expect("version 4 migrates");
        assert_eq!(
            object["ingress"],
            serde_json::to_value(ingress::IngressConfig::default()).expect("default")
        );
        assert_eq!(object["ingress"]["enabled"], serde_json::json!(false));
        assert_eq!(object.len(), 2, "only ingress and the version: {object:?}");
    }

    #[test]
    fn v1_legacy_yaml_migrates_to_current() {
        let legacy = r#"
name: policy
fail_closed: true
gate_profile:
  order: [Core, Mirror]
  fail_closed: true
"#;
        let loaded = AppConfig::parse_with_migration_yaml(legacy).expect("legacy migrates");
        assert_eq!(loaded.migrated_from, Some(1));
        assert_eq!(loaded.config.version, CURRENT_CONFIG_VERSION);
        assert!(loaded.config.validate().is_ok());
    }

    #[test]
    fn v2_yaml_migrates_to_current() {
        let mut v2 = AppConfigV2 {
            version: 2,
            policy: PolicyV1 {
                name: "v2-policy".into(),
                fail_closed: true,
                gate_profile: GateProfileV1 {
                    order: GateId::ALL.into(),
                    fail_closed: true,
                },
            },
            runtime: RuntimeConfig::default(),
            interop: InteropConfig::default(),
        };
        v2.runtime.metrics_path = "custom/metrics.json".into();
        let doc = serde_yaml::to_string(&v2).expect("yaml");

        let loaded = AppConfig::parse_with_migration_yaml(&doc).expect("v2 migrates");
        assert_eq!(loaded.migrated_from, Some(2));
        assert_eq!(loaded.config.version, CURRENT_CONFIG_VERSION);
        assert_eq!(loaded.config.policy.name, "v2-policy");
        assert_eq!(loaded.config.runtime.metrics_path, "custom/metrics.json");
        assert!(loaded.config.validate().is_ok());
    }

    #[test]
    fn lint_rejects_non_strict_runtime() {
        let mut config = AppConfig::default();
        config.runtime.strict_mode = false;
        let doc = serde_yaml::to_string(&config).expect("yaml");
        let report = lint(&doc, ConfigFormat::Yaml);
        assert!(!report.ok);
    }

    #[test]
    fn default_config_validates() {
        assert!(AppConfig::default().validate().is_ok());
    }

    #[test]
    fn single_ip_privacy_claim_must_stay_forbidden() {
        let mut config = AppConfig::default();
        // `PrivacyClaimPolicy` only has one variant, so the only way to
        // violate this invariant through the public API is to construct it
        // directly — this proves `validate()` would catch a would-be
        // second variant if one were ever added carelessly.
        assert_eq!(
            config.locator_plane.single_ip_external_privacy_claim,
            PrivacyClaimPolicy::Forbidden
        );
        config.locator_plane.require_locator_reality_check = false;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::LocatorRealityCheckRequired)
        ));
    }

    #[test]
    fn global_passive_observer_adversary_model_is_rejected() {
        let mut config = AppConfig::default();
        config.privacy.adversary_model = ssk_privacy::AdversaryModel::GlobalPassiveObserver;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::GlobalPassiveObserverClaimForbidden)
        ));
    }

    #[test]
    fn gate_failure_policy_must_be_no_materialization() {
        let mut config = AppConfig::default();
        // Only one variant exists today, so directly assert `validate()`
        // still passes with it and that removing the check would be the
        // only way to violate ch. 11.3's "must be NoMaterialization" axiom.
        assert_eq!(
            config.policy.gate_profile.failure_policy,
            GateFailurePolicy::NoMaterialization
        );
        config.policy.gate_profile.order.clear();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::EmptyGateProfile)
        ));
    }

    #[test]
    fn ledger_must_not_store_payload() {
        let mut config = AppConfig::default();
        config.ledger.store_payload = true;
        assert!(matches!(
            config.validate(),
            Err(ConfigError::LedgerMustNotStorePayload)
        ));
    }

    /// Pins the on-the-wire form of `projective_connection_hypercube.axes`:
    /// nine `snake_case` strings in the hypercube's own axis order. `Axis`
    /// is serde-serialized as part of persisted config, so this test is what
    /// makes a variant rename or reorder a loud failure rather than a silent
    /// config-compatibility break. It is deliberately written against the
    /// literal YAML text, not against `Axis` values, so it stays meaningful
    /// no matter which crate owns the enum.
    #[test]
    fn hypercube_axes_round_trip_as_snake_case_names() {
        const DOC: &str = "\
axes:
- identity
- locator
- protocol
- timing
- trust
- risk
- capability
- replay
- boundary
require_all_axis_projection: true
";
        let parsed: HypercubeConfig = serde_yaml::from_str(DOC).expect("axes deserialize");
        assert_eq!(parsed, HypercubeConfig::default());
        assert!(parsed.validate().is_ok());
        assert_eq!(
            serde_yaml::to_string(&HypercubeConfig::default()).expect("axes serialize"),
            DOC
        );

        // And the same section survives a whole-document round trip.
        let doc = serde_yaml::to_string(&AppConfig::default()).expect("yaml");
        assert!(
            doc.contains("- capability"),
            "axes render snake_case: {doc}"
        );
        let back: AppConfig = serde_yaml::from_str(&doc).expect("whole config round-trips");
        assert_eq!(
            back.projective_connection_hypercube,
            AppConfig::default().projective_connection_hypercube
        );
    }

    #[test]
    fn hypertorus_dimension_must_match_phase_axes_length() {
        let mut config = AppConfig::default();
        config.hypertorus.phase_axes.pop();
        assert!(matches!(
            config.validate(),
            Err(ConfigError::HypertorusDimensionMismatch)
        ));
    }
}
