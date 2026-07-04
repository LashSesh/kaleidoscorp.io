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
