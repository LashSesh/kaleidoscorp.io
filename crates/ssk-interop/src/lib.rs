#![forbid(unsafe_code)]

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Attestation types
// ---------------------------------------------------------------------------

/// A capability attestation token that a peer presents during handshake.
/// The token binds a subject identity to a capability set and time epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationToken {
    /// Opaque subject identifier (e.g. peer canonical name or policy root id).
    pub subject_id: String,
    /// Capabilities the subject attests to holding.
    pub capabilities: Vec<String>,
    /// Deterministic clock epoch at which the token was issued.
    pub epoch: u64,
    /// Monotonic nonce to prevent replay of the same token bytes.
    pub nonce: u64,
}

impl AttestationToken {
    /// Produce the canonical byte representation used for signing/verifying.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, InteropError> {
        ssk_types::canonical_bytes(self).map_err(|e| InteropError::Encode(e.to_string()))
    }
}

/// A signed attestation: the raw token plus its hex-encoded Blake3-keyed-MAC
/// signature produced with the shared attestation key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedAttestation {
    pub token: AttestationToken,
    /// Hex-encoded signature bytes (64 hex chars for Blake3 keyed hash).
    pub signature_hex: String,
}

/// Pluggable verifier interface for attestation signatures.
/// Implementations may use Blake3-keyed-hash, Ed25519, or any other scheme.
pub trait AttestationVerifier: Send + Sync {
    fn verify_token(&self, token_bytes: &[u8], signature_hex: &str) -> bool;
}

/// Default verifier: Blake3 keyed-hash with a fixed well-known test key.
/// Not for production use; replace with a real asymmetric scheme.
#[derive(Debug, Clone)]
pub struct Blake3KeyedVerifier {
    key: [u8; 32],
}

impl Blake3KeyedVerifier {
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Sign a token with this key (for test/fixture generation).
    pub fn sign(&self, token_bytes: &[u8]) -> String {
        let hash = blake3::keyed_hash(&self.key, token_bytes);
        hex::encode(hash.as_bytes())
    }
}

impl AttestationVerifier for Blake3KeyedVerifier {
    fn verify_token(&self, token_bytes: &[u8], signature_hex: &str) -> bool {
        let expected = blake3::keyed_hash(&self.key, token_bytes);
        let expected_hex = hex::encode(expected.as_bytes());
        expected_hex == signature_hex
    }
}

// ---------------------------------------------------------------------------
// Conformance Suite
// ---------------------------------------------------------------------------

/// A named conformance profile: a specific handshake scenario with expected outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceProfile {
    pub name: String,
    pub description: String,
    pub request: HandshakeRequest,
    pub expected_accept: bool,
}

/// Result of running a single conformance profile against a policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Aggregated report for a full conformance run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub results: Vec<ConformanceResult>,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

impl ConformanceReport {
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// A suite of conformance profiles.  `ConformanceSuite::default()` provides
/// the standard cross-implementation reference profiles.
pub struct ConformanceSuite {
    pub profiles: Vec<ConformanceProfile>,
}

impl Default for ConformanceSuite {
    fn default() -> Self {
        Self {
            profiles: vec![
                ConformanceProfile {
                    name: "full-featured".into(),
                    description: "All required capabilities, strict mode, nominal epoch".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 0, 0),
                        capabilities: Capabilities {
                            features: vec![
                                "gate-vector-12".into(),
                                "replay-v1".into(),
                                "canonical-cbor-v1".into(),
                                "doctor-v1".into(),
                            ],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 120,
                        deterministic_seed: 42,
                        attestation: None,
                    },
                    expected_accept: true,
                },
                ConformanceProfile {
                    name: "min-capabilities".into(),
                    description: "Exactly the minimum required capabilities".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 0, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into(), "replay-v1".into()],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 0,
                        deterministic_seed: 1,
                        attestation: None,
                    },
                    expected_accept: true,
                },
                ConformanceProfile {
                    name: "major-version-mismatch".into(),
                    description: "Peer presents major version 2 which is incompatible".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(2, 0, 0),
                        min_compatible: ProtocolVersion::new(2, 0, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into(), "replay-v1".into()],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 0,
                        deterministic_seed: 0,
                        attestation: None,
                    },
                    expected_accept: false,
                },
                ConformanceProfile {
                    name: "missing-required-capability".into(),
                    description: "Peer is missing the replay-v1 required capability".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 0, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into()],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 0,
                        deterministic_seed: 0,
                        attestation: None,
                    },
                    expected_accept: false,
                },
                ConformanceProfile {
                    name: "non-strict-mode".into(),
                    description: "Peer requests non-strict mode; must be rejected".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 0, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into(), "replay-v1".into()],
                        },
                        strict_mode: false,
                        deterministic_clock_epoch: 0,
                        deterministic_seed: 0,
                        attestation: None,
                    },
                    expected_accept: false,
                },
                ConformanceProfile {
                    name: "clock-epoch-exceeded".into(),
                    description: "Epoch exceeds max_clock_skew_secs; must be rejected".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 0, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into(), "replay-v1".into()],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 999_999,
                        deterministic_seed: 0,
                        attestation: None,
                    },
                    expected_accept: false,
                },
                ConformanceProfile {
                    name: "future-min-compatible".into(),
                    description: "Peer demands min_compatible > our current version; reject".into(),
                    request: HandshakeRequest {
                        protocol: ProtocolVersion::new(1, 0, 0),
                        min_compatible: ProtocolVersion::new(1, 99, 0),
                        capabilities: Capabilities {
                            features: vec!["gate-vector-12".into(), "replay-v1".into()],
                        },
                        strict_mode: true,
                        deterministic_clock_epoch: 0,
                        deterministic_seed: 0,
                        attestation: None,
                    },
                    expected_accept: false,
                },
            ],
        }
    }
}

impl ConformanceSuite {
    /// Run all profiles against the given policy.
    /// Attestation verification is skipped for profiles without attestation.
    pub fn run(&self, policy: &CompatibilityPolicy) -> ConformanceReport {
        let results: Vec<ConformanceResult> = self
            .profiles
            .iter()
            .map(|p| {
                let outcome = policy.evaluate(&p.request, None);
                let accepted = outcome.is_ok();
                let passed = accepted == p.expected_accept;
                ConformanceResult {
                    name: p.name.clone(),
                    passed,
                    detail: if passed {
                        format!("ok (accepted={})", accepted)
                    } else {
                        match outcome {
                            Ok(_) => format!(
                                "expected reject but was accepted (profile: {})",
                                p.name
                            ),
                            Err(e) => format!(
                                "expected accept but was rejected: {e} (profile: {})",
                                p.name
                            ),
                        }
                    },
                }
            })
            .collect();

        let passed = results.iter().filter(|r| r.passed).count();
        let total = results.len();
        ConformanceReport {
            failed: total - passed,
            results,
            total,
            passed,
        }
    }
}

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
    /// Optional signed capability attestation.  When present and the policy
    /// `require_attestation` flag is set, the handshake verifies it before
    /// accepting the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<SignedAttestation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub negotiated: ProtocolVersion,
    pub capabilities: Capabilities,
    pub strict_mode: bool,
    pub error: Option<InteropErrorCode>,
    /// Whether a presented attestation was successfully verified.
    #[serde(default)]
    pub attestation_verified: bool,
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
    AttestationRequired,
    AttestationInvalid,
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
    #[error("signed capability attestation is required but was not presented")]
    AttestationRequired,
    #[error("signed capability attestation verification failed")]
    AttestationInvalid,
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
            Self::AttestationRequired => InteropErrorCode::AttestationRequired,
            Self::AttestationInvalid => InteropErrorCode::AttestationInvalid,
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
    /// When `true`, the peer must present a valid `SignedAttestation`.
    pub require_attestation: bool,
}

impl Default for CompatibilityPolicy {
    fn default() -> Self {
        Self {
            current: CURRENT_PROTOCOL_VERSION,
            min_supported: MIN_COMPATIBLE_VERSION,
            required_capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            max_clock_skew_secs: 300,
            strict_mode_only: true,
            local_capabilities: Capabilities {
                features: vec![
                    "gate-vector-12".into(),
                    "replay-v1".into(),
                    "canonical-cbor-v1".into(),
                    "doctor-v1".into(),
                ],
            },
            require_attestation: false,
        }
    }
}

impl CompatibilityPolicy {
    /// Evaluate a handshake request, optionally verifying its attestation.
    ///
    /// `verifier` is only consulted when the request carries an attestation or
    /// when `require_attestation` is set.  Pass `None` to skip verification
    /// (only valid when `require_attestation` is `false` and no attestation is
    /// present).
    pub fn evaluate(
        &self,
        request: &HandshakeRequest,
        verifier: Option<&dyn AttestationVerifier>,
    ) -> Result<HandshakeResponse, InteropError> {
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

        // Attestation check
        let attestation_verified = match &request.attestation {
            Some(signed) => {
                let v = verifier.ok_or(InteropError::AttestationInvalid)?;
                let token_bytes = signed.token.canonical_bytes()?;
                if !v.verify_token(&token_bytes, &signed.signature_hex) {
                    return Err(InteropError::AttestationInvalid);
                }
                true
            }
            None => {
                if self.require_attestation {
                    return Err(InteropError::AttestationRequired);
                }
                false
            }
        };

        Ok(HandshakeResponse {
            accepted: true,
            negotiated: self.current.clone(),
            capabilities: request.capabilities.intersection(&self.local_capabilities),
            strict_mode: true,
            error: None,
            attestation_verified,
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
            attestation: None,
        };
        let resp = CompatibilityPolicy::default()
            .evaluate(&req, None)
            .expect("must accept compatible peer");
        assert!(resp.accepted);
        assert!(!resp.attestation_verified);
        assert_eq!(resp.negotiated, ProtocolVersion::new(1, 0, 0));
    }

    #[test]
    fn attestation_verified_on_valid_token() {
        let verifier = Blake3KeyedVerifier::new([0u8; 32]);
        let token = AttestationToken {
            subject_id: "peer-alpha".into(),
            capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            epoch: 10,
            nonce: 99,
        };
        let token_bytes = token.canonical_bytes().expect("canonical bytes");
        let sig = verifier.sign(&token_bytes);
        let req = HandshakeRequest {
            protocol: ProtocolVersion::new(1, 0, 0),
            min_compatible: ProtocolVersion::new(1, 0, 0),
            capabilities: Capabilities {
                features: vec!["gate-vector-12".into(), "replay-v1".into()],
            },
            strict_mode: true,
            deterministic_clock_epoch: 10,
            deterministic_seed: 0,
            attestation: Some(SignedAttestation {
                token,
                signature_hex: sig,
            }),
        };
        let resp = CompatibilityPolicy::default()
            .evaluate(&req, Some(&verifier))
            .expect("attestation must be accepted");
        assert!(resp.attestation_verified);
    }

    #[test]
    fn attestation_invalid_signature_rejected() {
        let verifier = Blake3KeyedVerifier::new([0u8; 32]);
        let token = AttestationToken {
            subject_id: "peer-beta".into(),
            capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            epoch: 10,
            nonce: 1,
        };
        let req = HandshakeRequest {
            protocol: ProtocolVersion::new(1, 0, 0),
            min_compatible: ProtocolVersion::new(1, 0, 0),
            capabilities: Capabilities {
                features: vec!["gate-vector-12".into(), "replay-v1".into()],
            },
            strict_mode: true,
            deterministic_clock_epoch: 10,
            deterministic_seed: 0,
            attestation: Some(SignedAttestation {
                token,
                signature_hex: "deadbeef".into(),
            }),
        };
        let err = CompatibilityPolicy::default()
            .evaluate(&req, Some(&verifier))
            .expect_err("invalid attestation must be rejected");
        assert_eq!(err.code(), InteropErrorCode::AttestationInvalid);
    }

    #[test]
    fn require_attestation_rejects_missing_attestation() {
        let policy = CompatibilityPolicy {
            require_attestation: true,
            ..CompatibilityPolicy::default()
        };
        let req = HandshakeRequest {
            protocol: ProtocolVersion::new(1, 0, 0),
            min_compatible: ProtocolVersion::new(1, 0, 0),
            capabilities: Capabilities {
                features: vec!["gate-vector-12".into(), "replay-v1".into()],
            },
            strict_mode: true,
            deterministic_clock_epoch: 0,
            deterministic_seed: 0,
            attestation: None,
        };
        let err = policy
            .evaluate(&req, None)
            .expect_err("missing attestation must be rejected");
        assert_eq!(err.code(), InteropErrorCode::AttestationRequired);
    }

    #[test]
    fn conformance_suite_all_profiles_pass() {
        let suite = ConformanceSuite::default();
        let report = suite.run(&CompatibilityPolicy::default());
        for result in &report.results {
            assert!(
                result.passed,
                "conformance profile '{}' failed: {}",
                result.name, result.detail
            );
        }
        assert!(report.all_passed());
    }
}
