#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use ssk_types::GateId;

pub const CURRENT_CONFIG_VERSION: u32 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("config version `{found}` is unsupported; expected `{expected}`")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("strict fail-closed policy is required")]
    FailClosedRequired,
    #[error("gate profile must not be empty")]
    EmptyGateProfile,
    #[error("runtime strict mode must remain enabled by default")]
    RuntimeStrictModeRequired,
    #[error("interop capability list contains duplicates")]
    DuplicateCapabilities,
    #[error("interop minimum protocol must not be empty")]
    MissingInteropVersion,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GateProfile {
    pub order: Vec<GateId>,
    pub fail_closed: bool,
}

impl GateProfile {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.fail_closed {
            return Err(ConfigError::FailClosedRequired);
        }
        if self.order.is_empty() {
            return Err(ConfigError::EmptyGateProfile);
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
            max_clock_skew_secs: 86_400,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppConfig {
    pub version: u32,
    pub policy: Policy,
    pub runtime: RuntimeConfig,
    pub interop: InteropConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            policy: Policy {
                name: "default-fail-closed".into(),
                fail_closed: true,
                gate_profile: GateProfile {
                    order: GateId::ALL.into(),
                    fail_closed: true,
                },
            },
            runtime: RuntimeConfig::default(),
            interop: InteropConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegacyPolicyV1 {
    pub name: String,
    pub fail_closed: bool,
    pub gate_profile: GateProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

        Ok(())
    }

    pub fn parse_with_migration_yaml(content: &str) -> Result<LoadedConfig, ConfigError> {
        if let Ok(config) = Self::from_yaml(content) {
            return Ok(LoadedConfig {
                config,
                migrated_from: None,
            });
        }

        let legacy: LegacyPolicyV1 = serde_yaml::from_str(content)?;
        let config = AppConfig {
            policy: Policy {
                name: legacy.name,
                fail_closed: legacy.fail_closed,
                gate_profile: legacy.gate_profile,
            },
            ..AppConfig::default()
        };
        config.validate()?;
        Ok(LoadedConfig {
            config,
            migrated_from: Some(1),
        })
    }

    pub fn parse_with_migration_toml(content: &str) -> Result<LoadedConfig, ConfigError> {
        if let Ok(config) = Self::from_toml(content) {
            return Ok(LoadedConfig {
                config,
                migrated_from: None,
            });
        }

        let legacy: LegacyPolicyV1 = toml::from_str(content)?;
        let config = AppConfig {
            policy: Policy {
                name: legacy.name,
                fail_closed: legacy.fail_closed,
                gate_profile: legacy.gate_profile,
            },
            ..AppConfig::default()
        };
        config.validate()?;
        Ok(LoadedConfig {
            config,
            migrated_from: Some(1),
        })
    }

    pub fn schema_json() -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://kaleidoscorp.io/schema/ssk-config-v2.json",
            "title": "ScorpioSync Kaleidoscorp Config",
            "type": "object",
            "required": ["version", "policy", "runtime", "interop"],
            "properties": {
                "version": {"type": "integer", "const": CURRENT_CONFIG_VERSION},
                "policy": {
                    "type": "object",
                    "required": ["name", "fail_closed", "gate_profile"],
                    "properties": {
                        "name": {"type": "string", "minLength": 1},
                        "fail_closed": {"type": "boolean", "const": true},
                        "gate_profile": {
                            "type": "object",
                            "required": ["order", "fail_closed"],
                            "properties": {
                                "order": {"type": "array", "items": {"type": "string"}, "minItems": 1},
                                "fail_closed": {"type": "boolean", "const": true}
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
                        "min_protocol": {"type": "string", "pattern": "^[0-9]+\\\\.[0-9]+\\\\.[0-9]+$"},
                        "capabilities": {"type": "array", "items": {"type": "string"}},
                        "max_clock_skew_secs": {"type": "integer", "minimum": 0}
                    }
                }
            }
        })
    }
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
        assert!(snapshot.contains("ssk-config-v2.json"));
        assert!(snapshot.contains("strict_mode"));
    }

    #[test]
    fn legacy_yaml_migrates_to_v2() {
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
    }

    #[test]
    fn lint_rejects_non_strict_runtime() {
        let mut config = AppConfig::default();
        config.runtime.strict_mode = false;
        let doc = serde_yaml::to_string(&config).expect("yaml");
        let report = lint(&doc, ConfigFormat::Yaml);
        assert!(!report.ok);
    }
}
