#![cfg(feature = "crypto")]

use ssk_crypto::{
    AeadProvider, ChaCha20Poly1305Provider, Ed25519KeyPair, Ed25519Verifier, SignatureProvider,
};

#[test]
fn sign_then_verify_round_trip_succeeds() {
    let keypair = Ed25519KeyPair::generate();
    let msg = b"kaleidoscorp desktop client attestation";
    let sig = keypair.sign(msg).expect("sign should succeed");
    assert!(keypair.verify(msg, &sig));
}

#[test]
fn verify_rejects_tampered_message() {
    let keypair = Ed25519KeyPair::generate();
    let sig = keypair.sign(b"original message").expect("sign");
    assert!(!keypair.verify(b"tampered message", &sig));
}

#[test]
fn verify_rejects_tampered_signature() {
    let keypair = Ed25519KeyPair::generate();
    let msg = b"original message";
    let mut sig = keypair.sign(msg).expect("sign");
    sig[0] ^= 0xFF;
    assert!(!keypair.verify(msg, &sig));
}

#[test]
fn verify_rejects_wrong_public_key() {
    let signer = Ed25519KeyPair::generate();
    let other = Ed25519KeyPair::generate();
    let msg = b"message signed by `signer`";
    let sig = signer.sign(msg).expect("sign");
    assert!(!other.verify(msg, &sig));
}

#[test]
fn verify_only_verifier_accepts_a_valid_signature_and_rejects_a_bad_one() {
    let signer = Ed25519KeyPair::generate();
    let msg = b"peer attestation payload";
    let sig = signer.sign(msg).expect("sign");

    let verifier =
        Ed25519Verifier::from_public_bytes(signer.public_key_bytes()).expect("valid public key");
    assert!(verifier.verify(msg, &sig));
    assert!(!verifier.verify(b"different payload", &sig));
    assert!(verifier.sign(msg).is_err(), "verifier holds no private key");
}

#[test]
fn deterministic_from_seed_produces_stable_keypair() {
    let seed = [7u8; 32];
    let a = Ed25519KeyPair::from_seed(seed);
    let b = Ed25519KeyPair::from_seed(seed);
    assert_eq!(a.public_key_bytes(), b.public_key_bytes());

    let msg = b"deterministic seed test";
    let sig = a.sign(msg).expect("sign");
    assert!(b.verify(msg, &sig));
}

#[test]
fn aead_seal_open_round_trip_succeeds() {
    let provider = ChaCha20Poly1305Provider::new([1u8; 32]);
    let plaintext = b"kaleidoscorp secret config value";
    let aad = b"config-context-v1";

    let ciphertext = provider.seal(plaintext, aad).expect("seal");
    let recovered = provider.open(&ciphertext, aad).expect("open");
    assert_eq!(recovered, plaintext);
}

#[test]
fn aead_open_rejects_tampered_ciphertext() {
    let provider = ChaCha20Poly1305Provider::new([2u8; 32]);
    let mut ciphertext = provider.seal(b"payload", b"aad").expect("seal");
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0xFF;
    assert!(provider.open(&ciphertext, b"aad").is_err());
}

#[test]
fn aead_open_rejects_wrong_aad() {
    let provider = ChaCha20Poly1305Provider::new([3u8; 32]);
    let ciphertext = provider.seal(b"payload", b"aad-a").expect("seal");
    assert!(provider.open(&ciphertext, b"aad-b").is_err());
}
