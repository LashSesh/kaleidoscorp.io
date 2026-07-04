use std::path::Path;

use proptest::prelude::*;
use serde::{Deserialize, Serialize};
use ssk_interop::{
    decode_strict, decode_with_mode, encode_canonical, AttestationVerifier, Blake3KeyedVerifier,
    Capabilities, CompatibilityPolicy, ConformanceSuite, DecodeMode, HandshakeRequest,
    ProtocolVersion,
};

#[derive(Debug, Deserialize, Serialize)]
struct Vector {
    request: HandshakeRequest,
    expected_accept: bool,
}

#[test]
fn golden_vector_roundtrip_and_compatibility() {
    let vector_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join("handshake_vector.json");
    let bytes = std::fs::read(vector_path).expect("golden vector must exist");
    let vector: Vector = serde_json::from_slice(&bytes).expect("golden vector must parse");

    let wire = encode_canonical(&vector.request).expect("canonical encode must work");
    let decoded: HandshakeRequest = decode_strict(&wire).expect("strict decode must work");

    let result = CompatibilityPolicy::default().evaluate(&decoded, None);
    assert_eq!(result.is_ok(), vector.expected_accept);
}

#[test]
fn strict_decoder_rejects_non_canonical_and_permissive_accepts() {
    let non_canonical = [0x18, 0x17];
    assert!(decode_strict::<u8>(&non_canonical).is_err());
    let permissive = decode_with_mode::<u8>(&non_canonical, DecodeMode::Permissive)
        .expect("permissive decode should accept");
    assert_eq!(permissive, 23);
}

#[test]
fn capability_mismatch_rejected() {
    let request = HandshakeRequest {
        protocol: ProtocolVersion::new(1, 0, 0),
        min_compatible: ProtocolVersion::new(1, 0, 0),
        capabilities: Capabilities {
            features: vec!["gate-vector-12".into()],
        },
        strict_mode: true,
        deterministic_clock_epoch: 10,
        deterministic_seed: 1,
        attestation: None,
    };
    let error = CompatibilityPolicy::default()
        .evaluate(&request, None)
        .expect_err("missing required capability must fail");
    assert_eq!(
        error.code(),
        ssk_interop::InteropErrorCode::CapabilityMismatch
    );
}

#[test]
fn conformance_suite_reference_run() {
    let suite = ConformanceSuite::default();
    let report = suite.run(&CompatibilityPolicy::default());
    assert!(
        report.all_passed(),
        "conformance failures: {:#?}",
        report
            .results
            .iter()
            .filter(|r| !r.passed)
            .collect::<Vec<_>>()
    );
}

#[test]
fn blake3_verifier_sign_and_verify_roundtrip() {
    let v = Blake3KeyedVerifier::new_test_key();
    let data = b"capability-attestation-test";
    let sig = v.sign(data);
    assert!(v.verify_token(data, &sig));
    assert!(!v.verify_token(data, "00000000"));
}

proptest::proptest! {
    #[test]
    fn fuzz_decoder_never_panics(data in proptest::collection::vec(any::<u8>(), 0..128)) {
        let _ = decode_with_mode::<HandshakeRequest>(&data, DecodeMode::Strict);
    }
}
