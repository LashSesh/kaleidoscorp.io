#![forbid(unsafe_code)]

//! Identity & Attestation Binder — signed peer/capability binding before flow release.
//!
//! Uses Blake3 keyed-hash (HMAC-equivalent) for the reference implementation.
//! Production deployments should replace `Blake3AttestationBinder` with an
//! implementation backed by Ed25519 or a HSM via the `ssk-crypto` traits.

use serde::{Deserialize, Serialize};

use crate::error::NetAdminError;
use crate::flow::FlowRecord;

/// A verified binding between a flow and a signed capability attestation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationBinding {
    /// Flow the binding was issued for.
    pub flow_id: String,
    /// Subject identifier from the attestation token.
    pub subject_id: String,
    /// Capabilities attested to by the peer.
    pub capabilities: Vec<String>,
    /// Epoch at which the token was issued.
    pub token_epoch: u64,
    /// Nonce preventing token replay.
    pub nonce: u64,
    /// Epoch at which verification was performed.
    pub verified_at_epoch: u64,
}

/// A raw signed attestation presented during flow setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAttestation {
    pub subject_id: String,
    pub capabilities: Vec<String>,
    pub token_epoch: u64,
    pub nonce: u64,
    /// Hex-encoded Blake3 keyed-hash MAC of the canonical token bytes.
    pub signature_hex: String,
}

/// Serialisable token body (used as the MAC input).
#[derive(serde::Serialize)]
struct TokenBody<'a> {
    subject_id: &'a str,
    capabilities: &'a [String],
    token_epoch: u64,
    nonce: u64,
}

/// Attestation binder backed by Blake3 keyed-hash (reference implementation).
///
/// The shared 32-byte key is the HMAC key.  In production, rotate this key
/// regularly and store it in a secret manager.
#[derive(Clone)]
pub struct AttestationBinder {
    key: [u8; 32],
}

impl AttestationBinder {
    #[must_use]
    pub const fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Sign a raw attestation token, returning the hex-encoded MAC.
    pub fn sign(&self, raw: &RawAttestation) -> Result<String, NetAdminError> {
        let body = TokenBody {
            subject_id: &raw.subject_id,
            capabilities: &raw.capabilities,
            token_epoch: raw.token_epoch,
            nonce: raw.nonce,
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| NetAdminError::Serialization(e.to_string()))?;
        let mac = blake3::keyed_hash(&self.key, &bytes);
        Ok(hex::encode(mac.as_bytes()))
    }

    /// Verify `raw` and, on success, produce an `AttestationBinding`.
    pub fn bind(
        &self,
        flow: &FlowRecord,
        raw: &RawAttestation,
        current_epoch: u64,
    ) -> Result<AttestationBinding, NetAdminError> {
        let body = TokenBody {
            subject_id: &raw.subject_id,
            capabilities: &raw.capabilities,
            token_epoch: raw.token_epoch,
            nonce: raw.nonce,
        };
        let bytes = serde_json::to_vec(&body)
            .map_err(|e| NetAdminError::Serialization(e.to_string()))?;
        let expected_mac = blake3::keyed_hash(&self.key, &bytes);
        let expected_hex = hex::encode(expected_mac.as_bytes());

        if expected_hex != raw.signature_hex {
            return Err(NetAdminError::AttestationInvalid(
                flow.flow_id.clone(),
                "MAC verification failed".into(),
            ));
        }

        Ok(AttestationBinding {
            flow_id: flow.flow_id.clone(),
            subject_id: raw.subject_id.clone(),
            capabilities: raw.capabilities.clone(),
            token_epoch: raw.token_epoch,
            nonce: raw.nonce,
            verified_at_epoch: current_epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel};

    fn sample_flow() -> FlowRecord {
        FlowRecord::new(
            "flow-attest-1",
            10,
            FlowDescriptor::new("app", "secure.example.com", 443, ProtocolKind::Tls, RiskLevel::High),
        )
    }

    fn sample_raw(binder: &AttestationBinder) -> RawAttestation {
        let mut raw = RawAttestation {
            subject_id: "peer-secure".into(),
            capabilities: vec!["gate-vector-12".into(), "replay-v1".into()],
            token_epoch: 10,
            nonce: 42,
            signature_hex: String::new(),
        };
        raw.signature_hex = binder.sign(&raw).expect("sign must succeed");
        raw
    }

    #[test]
    fn valid_attestation_produces_binding() {
        let binder = AttestationBinder::new([0u8; 32]);
        let flow = sample_flow();
        let raw = sample_raw(&binder);
        let binding = binder.bind(&flow, &raw, 10).expect("bind must succeed");
        assert_eq!(binding.flow_id, "flow-attest-1");
        assert_eq!(binding.subject_id, "peer-secure");
        assert!(binding.capabilities.contains(&"replay-v1".to_string()));
    }

    #[test]
    fn tampered_signature_rejected() {
        let binder = AttestationBinder::new([0u8; 32]);
        let flow = sample_flow();
        let mut raw = sample_raw(&binder);
        raw.signature_hex = "deadbeef00000000".into();
        let err = binder
            .bind(&flow, &raw, 10)
            .expect_err("tampered MAC must fail");
        assert!(matches!(err, NetAdminError::AttestationInvalid(_, _)));
    }

    #[test]
    fn different_key_rejected() {
        let signer = AttestationBinder::new([0u8; 32]);
        let verifier = AttestationBinder::new([1u8; 32]);
        let flow = sample_flow();
        let raw = sample_raw(&signer);
        let err = verifier
            .bind(&flow, &raw, 10)
            .expect_err("wrong key must fail");
        assert!(matches!(err, NetAdminError::AttestationInvalid(_, _)));
    }
}
