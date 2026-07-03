#![forbid(unsafe_code)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

impl ProtocolVersion {
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    #[must_use]
    pub fn as_semver(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl PartialOrd for ProtocolVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ProtocolVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

pub const CURRENT_PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);
pub const MIN_COMPATIBLE_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0, 0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Capabilities {
    pub features: Vec<String>,
}

impl Capabilities {
    pub fn validate(&self) -> Result<(), InteropError> {
        let mut seen = BTreeSet::new();
        for feature in &self.features {
            if feature.is_empty() {
                return Err(InteropError::CapabilityInvalid(
                    "capability must not be empty".into(),
                ));
            }
            if !feature
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_'))
            {
                return Err(InteropError::CapabilityInvalid(format!(
                    "invalid capability name: {feature}"
                )));
            }
            if !seen.insert(feature.clone()) {
                return Err(InteropError::CapabilityInvalid(format!(
                    "duplicate capability: {feature}"
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn intersection(&self, other: &Capabilities) -> Capabilities {
        let rhs: BTreeSet<_> = other.features.iter().cloned().collect();
        Capabilities {
            features: self
                .features
                .iter()
                .filter(|f| rhs.contains(*f))
                .cloned()
                .collect(),
        }
    }

    #[must_use]
    pub fn contains_all(&self, required: &[String]) -> bool {
        let set: BTreeSet<_> = self.features.iter().collect();
        required.iter().all(|r| set.contains(r))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub protocol: ProtocolVersion,
    pub min_compatible: ProtocolVersion,
    pub capabilities: Capabilities,
    pub strict_mode: bool,
    pub deterministic_clock_epoch: u64,
    pub deterministic_seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub negotiated: ProtocolVersion,
    pub capabilities: Capabilities,
    pub strict_mode: bool,
    pub error: Option<InteropErrorCode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DecodeMode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InteropErrorCode {
    VersionIncompatible,
    CapabilityMismatch,
    StrictModeRequired,
    ClockOutOfRange,
    NonCanonicalEncoding,
    DecodeRejected,
}

#[derive(Debug, thiserror::Error)]
pub enum InteropError {
    #[error("version incompatible")]
    VersionIncompatible,
    #[error("capability mismatch: {0}")]
    CapabilityMismatch(String),
    #[error("strict mode required")]
    StrictModeRequired,
    #[error("deterministic clock out of range")]
    ClockOutOfRange,
    #[error("capability invalid: {0}")]
    CapabilityInvalid(String),
    #[error("encode failed: {0}")]
    Encode(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("non-canonical wire encoding")]
    NonCanonicalEncoding,
}

impl InteropError {
    #[must_use]
    pub fn code(&self) -> InteropErrorCode {
        match self {
            Self::VersionIncompatible => InteropErrorCode::VersionIncompatible,
            Self::CapabilityMismatch(_) => InteropErrorCode::CapabilityMismatch,
            Self::StrictModeRequired => InteropErrorCode::StrictModeRequired,
            Self::ClockOutOfRange => InteropErrorCode::ClockOutOfRange,
            Self::CapabilityInvalid(_) | Self::Encode(_) => InteropErrorCode::DecodeRejected,
            Self::Decode(_) => InteropErrorCode::DecodeRejected,
            Self::NonCanonicalEncoding => InteropErrorCode::NonCanonicalEncoding,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityPolicy {
    pub current: ProtocolVersion,
    pub min_supported: ProtocolVersion,
    pub required_capabilities: Vec<String>,
    pub max_clock_skew_secs: u64,
    pub strict_mode_only: bool,
    pub local_capabilities: Capabilities,
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self {
            current: CURRENT_PROTOCOL_VERSION,
            min_supported: MIN_COMPATIBLE_VERSION,
            required_capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            max_clock_skew_secs: 86_400,
            strict_mode_only: true,
            local_capabilities: Capabilities {
                features: vec![
                    "gate-vector-12".into(),
                    "replay-v1".into(),
                    "canonical-cbor-v1".into(),
                    "doctor-v1".into(),
                ],
            },
        }
    }
}

impl CompatibilityPolicy {
    pub fn evaluate(&self, request: &HandshakeRequest) -> Result<HandshakeResponse, InteropError> {
        request.capabilities.validate()?;
        self.local_capabilities.validate()?;

        if request.protocol.major != self.current.major {
            return Err(InteropError::VersionIncompatible);
        }
        if request.protocol < self.min_supported || self.current < request.min_compatible {
            return Err(InteropError::VersionIncompatible);
        }
        if self.strict_mode_only && !request.strict_mode {
            return Err(InteropError::StrictModeRequired);
        }
        if request.deterministic_clock_epoch > self.max_clock_skew_secs {
            return Err(InteropError::ClockOutOfRange);
        }
        if !request
            .capabilities
            .contains_all(&self.required_capabilities)
        {
            return Err(InteropError::CapabilityMismatch(
                "required capabilities are missing".into(),
            ));
        }

        Ok(HandshakeResponse {
            accepted: true,
            negotiated: self.current.clone(),
            capabilities: request.capabilities.intersection(&self.local_capabilities),
            strict_mode: true,
            error: None,
        })
    }
}

pub fn encode_canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, InteropError> {
    ssk_types::canonical_bytes(value).map_err(|err| InteropError::Encode(err.to_string()))
}

pub fn decode_with_mode<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    mode: DecodeMode,
) -> Result<T, InteropError> {
    let decoded: T =
        ciborium::de::from_reader(bytes).map_err(|err| InteropError::Decode(err.to_string()))?;

    if mode == DecodeMode::Strict {
        let canonical = encode_canonical(&decoded)?;
        if canonical != bytes {
            return Err(InteropError::NonCanonicalEncoding);
        }
    }
    Ok(decoded)
}

pub fn decode_strict<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, InteropError> {
    decode_with_mode(bytes, DecodeMode::Strict)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_decode_rejects_non_canonical_integer() {
        let bytes = [0x18, 0x17];
        let err = decode_strict::<u8>(&bytes).expect_err("must reject non-canonical");
        assert_eq!(err.code(), InteropErrorCode::NonCanonicalEncoding);
    }

    #[test]
    fn compatibility_accepts_supported_peer() {
        let req = HandshakeRequest {
            protocol: ProtocolVersion::new(1, 0, 0),
            min_compatible: ProtocolVersion::new(1, 0, 0),
            capabilities: Capabilities {
                features: vec![
                    "gate-vector-12".into(),
                    "replay-v1".into(),
                    "doctor-v1".into(),
                ],
            },
            strict_mode: true,
            deterministic_clock_epoch: 10,
            deterministic_seed: 42,
        };
        let resp = CompatibilityPolicy::default()
            .evaluate(&req)
            .expect("must accept compatible peer");
        assert!(resp.accepted);
        assert_eq!(resp.negotiated, ProtocolVersion::new(1, 0, 0));
    }
}
