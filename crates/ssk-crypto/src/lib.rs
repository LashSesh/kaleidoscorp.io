#![forbid(unsafe_code)]

use ssk_types::HashAlg;

pub trait HashProvider {
    fn algorithm(&self) -> HashAlg;
    fn digest(&self, input: &[u8]) -> Vec<u8>;
}

pub trait SignatureProvider {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String>;
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

pub trait KeyAgreementProvider {
    fn derive_shared_key(&self, peer: &[u8]) -> Result<Vec<u8>, String>;
}

pub trait AeadProvider {
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
}

pub trait CapabilityWitnessProvider {
    fn issue(&self, subject: &[u8]) -> Result<Vec<u8>, String>;
    fn validate(&self, witness: &[u8]) -> bool;
}

/// Real ed25519 `SignatureProvider` and ChaCha20-Poly1305 `AeadProvider`
/// implementations, gated behind the `crypto` feature. `KeyAgreementProvider`
/// (x25519) and `CapabilityWitnessProvider` are intentionally not implemented
/// here yet — no acceptance criterion in the current implementation phases
/// requires them.
#[cfg(feature = "crypto")]
mod ed25519_impl {
    use super::SignatureProvider;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    /// An ed25519 keypair capable of both signing and verifying.
    pub struct Ed25519KeyPair {
        signing_key: SigningKey,
    }

    impl Ed25519KeyPair {
        /// Generate a fresh keypair from OS randomness.
        #[must_use]
        pub fn generate() -> Self {
            let seed: [u8; 32] = rand::random();
            Self {
                signing_key: SigningKey::from_bytes(&seed),
            }
        }

        /// Deterministically derive a keypair from a 32-byte seed.
        #[must_use]
        pub fn from_seed(seed: [u8; 32]) -> Self {
            Self {
                signing_key: SigningKey::from_bytes(&seed),
            }
        }

        /// The 32-byte public key, safe to share and to embed in config or
        /// `SignedAttestation`-style envelopes.
        #[must_use]
        pub fn public_key_bytes(&self) -> [u8; 32] {
            self.signing_key.verifying_key().to_bytes()
        }
    }

    impl SignatureProvider for Ed25519KeyPair {
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
            Ok(self.signing_key.sign(msg).to_bytes().to_vec())
        }

        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            let Ok(bytes): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            self.signing_key
                .verifying_key()
                .verify(msg, &Signature::from_bytes(&bytes))
                .is_ok()
        }
    }

    /// Verify-only counterpart holding no private key, for checking a peer's
    /// or a config file's signature against a known public key.
    pub struct Ed25519Verifier {
        verifying_key: VerifyingKey,
    }

    impl Ed25519Verifier {
        /// Build a verifier from a 32-byte ed25519 public key.
        pub fn from_public_bytes(bytes: [u8; 32]) -> Result<Self, String> {
            VerifyingKey::from_bytes(&bytes)
                .map(|verifying_key| Self { verifying_key })
                .map_err(|e| e.to_string())
        }
    }

    impl SignatureProvider for Ed25519Verifier {
        fn sign(&self, _msg: &[u8]) -> Result<Vec<u8>, String> {
            Err("Ed25519Verifier holds no private key".into())
        }

        fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
            let Ok(bytes): Result<[u8; 64], _> = sig.try_into() else {
                return false;
            };
            self.verifying_key
                .verify(msg, &Signature::from_bytes(&bytes))
                .is_ok()
        }
    }
}

#[cfg(feature = "crypto")]
pub use ed25519_impl::{Ed25519KeyPair, Ed25519Verifier};

#[cfg(feature = "crypto")]
mod chacha_impl {
    use super::AeadProvider;
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
        ChaCha20Poly1305, Key,
    };

    /// ChaCha20-Poly1305 AEAD provider. Each `seal` call generates a fresh
    /// random 12-byte nonce and prepends it to the returned ciphertext;
    /// `open` expects that same layout.
    pub struct ChaCha20Poly1305Provider {
        cipher: ChaCha20Poly1305,
    }

    impl ChaCha20Poly1305Provider {
        /// Build a provider from a 32-byte symmetric key.
        #[must_use]
        pub fn new(key_bytes: [u8; 32]) -> Self {
            Self {
                cipher: ChaCha20Poly1305::new(Key::from_slice(&key_bytes)),
            }
        }
    }

    impl AeadProvider for ChaCha20Poly1305Provider {
        fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let mut ciphertext = self
                .cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|e| e.to_string())?;
            let mut out = nonce.to_vec();
            out.append(&mut ciphertext);
            Ok(out)
        }

        fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
            if ciphertext.len() < 12 {
                return Err("ciphertext too short to contain a nonce".into());
            }
            let (nonce, body) = ciphertext.split_at(12);
            self.cipher
                .decrypt(nonce.into(), Payload { msg: body, aad })
                .map_err(|e| e.to_string())
        }
    }
}

#[cfg(feature = "crypto")]
pub use chacha_impl::ChaCha20Poly1305Provider;
