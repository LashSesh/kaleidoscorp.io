#![forbid(unsafe_code)]

use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetAdminError {
    #[error("policy engine: no matching rule for flow `{0}`")]
    NoPolicyMatch(String),
    #[error("attestation required but not presented for flow `{0}`")]
    AttestationRequired(String),
    #[error("attestation verification failed for flow `{0}`: {1}")]
    AttestationInvalid(String, String),
    #[error("route orchestrator: no viable route for flow `{0}`")]
    NoViableRoute(String),
    #[error("control plane: unknown tenant `{0}`")]
    UnknownTenant(String),
    #[error("control plane: unknown adapter `{0}`")]
    UnknownAdapter(String),
    #[error("audit ledger: hash-chain broken at entry `{0}`")]
    AuditChainBroken(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("flow denied: fail-closed policy for flow `{0}`")]
    FailClosed(String),
    #[error("ledger persistence error: {0}")]
    Tensor(#[from] ssk_tensor::TensorError),
    #[error(
        "insecure attestation key rejected: an all-zero key may not be used outside test builds"
    )]
    InsecureKey,
}
