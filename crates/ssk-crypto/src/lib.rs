#![forbid(unsafe_code)]

use ssk_types::HashAlg;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ephemeral key material, capability secrets and session keys are wrapped
/// so they are zeroed on drop and never printed (Master Spec Ω+1 ch. 3.4).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

pub trait HashProvider: Send + Sync {
    fn algorithm(&self) -> HashAlg;
    fn digest(&self, input: &[u8]) -> Vec<u8>;
}

/// The first real `HashProvider` implementation — unconditional (not behind
/// the `crypto` feature), since BLAKE3 is already an unconditional workspace
/// dependency used throughout `ssk-types::digest_of`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Blake3HashProvider;

impl HashProvider for Blake3HashProvider {
    fn algorithm(&self) -> HashAlg {
        HashAlg::Blake3
    }

    fn digest(&self, input: &[u8]) -> Vec<u8> {
        blake3::hash(input).as_bytes().to_vec()
    }
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

/// Which capability-witness scheme a `CapabilityWitnessProvider` implements
/// (Master Spec Ω+1 ch. 5.1's `WitnessKind`: "Signature | Token | ZkStyle |
/// PolicyCert"). Only `Signature` gets a real implementation in this phase —
/// see `docs/OMEGA_CORE_CONFORMANCE_SPEC.md` Section X for why the other
/// three stay deliberately unimplemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessKind {
    Signature,
    Token,
    ZkStyle,
    PolicyCert,
}

/// Everything a caller must supply beyond the claim itself to issue a
/// witness (ch. 5.2's `CapabilityWitness` fields not derivable from the
/// claim alone). The PDF's own `issue(&self, claim, subject)` signature is
/// underspecified for a real implementation — bundling the rest into a
/// request struct is this document's own necessary elaboration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRequest {
    pub claim: ssk_types::CapabilityClaim,
    pub scope: ssk_types::Scope,
    pub subject_class: ssk_types::SubjectClass,
    pub epoch: ssk_types::EpochId,
    pub expiry: ssk_types::Ttl,
}

/// Context a verifier checks a witness against: the current epoch (for
/// expiry) and the scope the caller actually needs (ch. 5.2's proof-scope
/// axiom — a witness proves only its declared claim, nothing outside its
/// scope/epoch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyCtx {
    pub epoch: ssk_types::EpochId,
    pub expected_scope: ssk_types::Scope,
}

/// Outcome of verifying a `CapabilityWitness` (ch. 5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityVerdict {
    Valid,
    Expired,
    ScopeMismatch,
    InvalidProof,
}

/// Attests that an action/stitch is admissible under policy WITHOUT
/// exposing the core identity as a locator address (Master Spec Ω+1 ch. 5.1,
/// verbatim doc comment).
pub trait CapabilityWitnessProvider: Send + Sync {
    fn issue(&self, req: &CapabilityRequest) -> Result<ssk_types::CapabilityWitness, String>;
    fn verify(&self, w: &ssk_types::CapabilityWitness, ctx: &VerifyCtx) -> CapabilityVerdict;
    fn kind(&self) -> WitnessKind;
}

/// Real ed25519 `SignatureProvider`, ChaCha20-Poly1305 `AeadProvider`, x25519
/// `KeyAgreementProvider`, and ed25519-backed `CapabilityWitnessProvider`
/// implementations, gated behind the `crypto` feature. `WitnessKind::Token`/
/// `ZkStyle`/`PolicyCert` remain deliberately unimplemented (spec Section X).
#[cfg(feature = "crypto")]
mod ed25519_impl {
    use super::{
        CapabilityRequest, CapabilityVerdict, CapabilityWitnessProvider, SignatureProvider,
        VerifyCtx, WitnessKind,
    };
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use ssk_types::{CapabilityId, CapabilityWitness, HashAlg, ProofBytes, TraceId};

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

    /// `CapabilityWitnessProvider::WitnessKind::Signature` built directly on
    /// `Ed25519KeyPair` — issuing signs the claim's canonical bytes; verifying
    /// checks the signature plus scope/epoch/expiry locally (ch. 5.2's proof
    /// scope: a witness proves only its declared claim, nothing more).
    pub struct Ed25519CapabilityWitnessProvider {
        keypair: Ed25519KeyPair,
        issuer: ssk_types::IssuerRef,
    }

    impl Ed25519CapabilityWitnessProvider {
        #[must_use]
        pub fn new(keypair: Ed25519KeyPair, issuer: ssk_types::IssuerRef) -> Self {
            Self { keypair, issuer }
        }
    }

    impl CapabilityWitnessProvider for Ed25519CapabilityWitnessProvider {
        fn issue(&self, req: &CapabilityRequest) -> Result<CapabilityWitness, String> {
            let claim_bytes = ssk_types::canonical_bytes(&req.claim).map_err(|e| e.to_string())?;
            let proof = self.keypair.sign(&claim_bytes)?;
            let id = CapabilityId::of(&(req.claim.clone(), req.epoch), HashAlg::Blake3)
                .map_err(|e| e.to_string())?;
            Ok(CapabilityWitness {
                id,
                claim: req.claim.clone(),
                scope: req.scope.clone(),
                issuer: self.issuer.clone(),
                subject_class: req.subject_class,
                epoch: req.epoch,
                expiry: req.expiry,
                proof: ProofBytes(proof),
                trace: TraceId::new(format!("capability-issue:{}", req.epoch.0)),
            })
        }

        fn verify(&self, w: &CapabilityWitness, ctx: &VerifyCtx) -> CapabilityVerdict {
            if w.scope != ctx.expected_scope {
                return CapabilityVerdict::ScopeMismatch;
            }
            if ctx.epoch.0 > w.epoch.0 + w.expiry.0 {
                return CapabilityVerdict::Expired;
            }
            let Ok(claim_bytes) = ssk_types::canonical_bytes(&w.claim) else {
                return CapabilityVerdict::InvalidProof;
            };
            if self.keypair.verify(&claim_bytes, &w.proof.0) {
                CapabilityVerdict::Valid
            } else {
                CapabilityVerdict::InvalidProof
            }
        }

        fn kind(&self) -> WitnessKind {
            WitnessKind::Signature
        }
    }
}

#[cfg(feature = "crypto")]
pub use ed25519_impl::{Ed25519CapabilityWitnessProvider, Ed25519KeyPair, Ed25519Verifier};

#[cfg(feature = "crypto")]
mod x25519_impl {
    use super::KeyAgreementProvider;
    use x25519_dalek::{PublicKey, StaticSecret};

    /// x25519 `KeyAgreementProvider`. Uses a `StaticSecret` (reusable across
    /// calls) rather than `EphemeralSecret` (which consumes itself on first
    /// use), since a real keypair needs to derive shared keys with more than
    /// one peer over its lifetime.
    pub struct X25519KeyPair {
        secret: StaticSecret,
    }

    impl X25519KeyPair {
        /// Generate a fresh keypair from OS randomness.
        #[must_use]
        pub fn generate() -> Self {
            Self {
                secret: StaticSecret::random_from_rng(rand::rngs::OsRng),
            }
        }

        /// The 32-byte public key, safe to share with a peer for key agreement.
        #[must_use]
        pub fn public_key_bytes(&self) -> [u8; 32] {
            PublicKey::from(&self.secret).to_bytes()
        }
    }

    impl KeyAgreementProvider for X25519KeyPair {
        fn derive_shared_key(&self, peer: &[u8]) -> Result<Vec<u8>, String> {
            let peer_bytes: [u8; 32] = peer
                .try_into()
                .map_err(|_| "peer public key must be 32 bytes".to_string())?;
            let peer_public = PublicKey::from(peer_bytes);
            Ok(self.secret.diffie_hellman(&peer_public).as_bytes().to_vec())
        }
    }
}

#[cfg(feature = "crypto")]
pub use x25519_impl::X25519KeyPair;

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

#[cfg(test)]
mod secret_bytes_tests {
    use super::SecretBytes;

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
    }

    #[test]
    fn expose_returns_the_original_bytes() {
        let secret = SecretBytes::new(vec![9, 9, 9]);
        assert_eq!(secret.expose(), &[9, 9, 9]);
    }
}
