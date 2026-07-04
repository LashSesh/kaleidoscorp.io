//! Tests for the Phase 2 `CapabilityWitnessProvider`/`KeyAgreementProvider`
//! implementations (Master Spec Ω+1 ch. 5).

#![cfg(feature = "crypto")]

use ssk_crypto::{
    CapabilityRequest, CapabilityVerdict, CapabilityWitnessProvider,
    Ed25519CapabilityWitnessProvider, Ed25519KeyPair, KeyAgreementProvider, VerifyCtx, WitnessKind,
    X25519KeyPair,
};
use ssk_types::{CapabilityClaim, EpochId, IssuerRef, ObjectKind, Scope, SubjectClass, Ttl};

fn provider() -> Ed25519CapabilityWitnessProvider {
    Ed25519CapabilityWitnessProvider::new(Ed25519KeyPair::generate(), IssuerRef::new("issuer-1"))
}

fn sample_request() -> CapabilityRequest {
    CapabilityRequest {
        claim: CapabilityClaim("use locator class Relay in epoch 0".into()),
        scope: Scope {
            action: "connect".into(),
            facet_class: ObjectKind::Core,
        },
        subject_class: SubjectClass::Core,
        epoch: EpochId(0),
        expiry: Ttl(10),
    }
}

#[test]
fn issue_then_verify_round_trips_as_valid() {
    let p = provider();
    let req = sample_request();
    let witness = p.issue(&req).expect("issue must succeed");
    let ctx = VerifyCtx {
        epoch: EpochId(5),
        expected_scope: req.scope.clone(),
    };
    assert_eq!(p.verify(&witness, &ctx), CapabilityVerdict::Valid);
    assert_eq!(p.kind(), WitnessKind::Signature);
}

#[test]
fn tampered_proof_is_rejected() {
    let p = provider();
    let req = sample_request();
    let mut witness = p.issue(&req).expect("issue must succeed");
    witness.proof.0[0] ^= 0xff;
    let ctx = VerifyCtx {
        epoch: EpochId(0),
        expected_scope: req.scope.clone(),
    };
    assert_eq!(p.verify(&witness, &ctx), CapabilityVerdict::InvalidProof);
}

#[test]
fn expired_witness_is_rejected() {
    let p = provider();
    let req = sample_request();
    let witness = p.issue(&req).expect("issue must succeed");
    let ctx = VerifyCtx {
        epoch: EpochId(11), // epoch 0 + expiry 10 = valid through 10
        expected_scope: req.scope.clone(),
    };
    assert_eq!(p.verify(&witness, &ctx), CapabilityVerdict::Expired);
}

#[test]
fn scope_mismatch_is_rejected() {
    let p = provider();
    let req = sample_request();
    let witness = p.issue(&req).expect("issue must succeed");
    let ctx = VerifyCtx {
        epoch: EpochId(0),
        expected_scope: Scope {
            action: "different-action".into(),
            facet_class: ObjectKind::MirrorFacet,
        },
    };
    assert_eq!(p.verify(&witness, &ctx), CapabilityVerdict::ScopeMismatch);
}

#[test]
fn a_witness_from_a_different_issuer_key_fails_verification() {
    let issuer_a = provider();
    let issuer_b = provider();
    let req = sample_request();
    let witness = issuer_a.issue(&req).expect("issue must succeed");
    let ctx = VerifyCtx {
        epoch: EpochId(0),
        expected_scope: req.scope.clone(),
    };
    assert_eq!(
        issuer_b.verify(&witness, &ctx),
        CapabilityVerdict::InvalidProof
    );
}

#[test]
fn x25519_key_agreement_round_trips_to_the_same_shared_secret() {
    let alice = X25519KeyPair::generate();
    let bob = X25519KeyPair::generate();

    let alice_shared = alice
        .derive_shared_key(&bob.public_key_bytes())
        .expect("derive must succeed");
    let bob_shared = bob
        .derive_shared_key(&alice.public_key_bytes())
        .expect("derive must succeed");

    assert_eq!(alice_shared, bob_shared);
}

#[test]
fn x25519_rejects_a_malformed_peer_key() {
    let alice = X25519KeyPair::generate();
    assert!(alice.derive_shared_key(&[0u8; 4]).is_err());
}
