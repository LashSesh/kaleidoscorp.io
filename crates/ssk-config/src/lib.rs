#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use ssk_types::GateId;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("positive-only gate profile is invalid")]
    PositiveOnlyProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateProfile {
    pub order: Vec<GateId>,
    pub fail_closed: bool,
}

impl GateProfile {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.fail_closed {
            return Err(ConfigError::PositiveOnlyProfile);
        }
        if self.order.is_empty() {
            return Err(ConfigError::PositiveOnlyProfile);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub fail_closed: bool,
    pub gate_profile: GateProfile,
}

impl Policy {
    pub fn from_yaml(content: &str) -> Result<Self, ConfigError> {
        let policy: Policy = serde_yaml::from_str(content)?;
        policy.gate_profile.validate()?;
        Ok(policy)
    }

    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        let policy: Policy = toml::from_str(content)?;
        policy.gate_profile.validate()?;
        Ok(policy)
    }
}
