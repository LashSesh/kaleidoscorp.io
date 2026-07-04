#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Error DTO returned to IPC clients. Mirrors `ssk-cli`'s `ErrorClass`/`AppError`
/// machine-readable contract (`crates/ssk-cli/src/main.rs`) so error handling
/// stays consistent between the CLI and any future GUI client.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct IpcError {
    pub code: String,
    pub class: String,
    pub message: String,
    pub next_steps: Vec<String>,
    pub retriable: bool,
}

impl IpcError {
    pub fn new(
        class: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            class: class.into(),
            message: message.into(),
            next_steps: Vec::new(),
            retriable: false,
        }
    }

    #[must_use]
    pub fn with_next_step(mut self, step: impl Into<String>) -> Self {
        self.next_steps.push(step.into());
        self
    }

    #[must_use]
    pub fn retriable(mut self) -> Self {
        self.retriable = true;
        self
    }
}

impl From<ssk_netadmin::NetAdminError> for IpcError {
    fn from(err: ssk_netadmin::NetAdminError) -> Self {
        use ssk_netadmin::NetAdminError as E;
        let message = err.to_string();
        match err {
            E::NoPolicyMatch(_) => IpcError::new("NetAdmin", "NO_POLICY_MATCH", message),
            E::AttestationRequired(_) => IpcError::new("NetAdmin", "ATTESTATION_REQUIRED", message),
            E::AttestationInvalid(_, _) => {
                IpcError::new("NetAdmin", "ATTESTATION_INVALID", message)
            }
            E::NoViableRoute(_) => IpcError::new("NetAdmin", "NO_VIABLE_ROUTE", message),
            E::UnknownTenant(_) => IpcError::new("NetAdmin", "UNKNOWN_TENANT", message),
            E::UnknownAdapter(_) => IpcError::new("NetAdmin", "UNKNOWN_ADAPTER", message),
            E::AuditChainBroken(_) => IpcError::new("Integrity", "AUDIT_CHAIN_BROKEN", message)
                .with_next_step("Freeze writes and export diagnostics."),
            E::Serialization(_) => IpcError::new("Runtime", "SERIALIZATION_FAILED", message),
            E::FailClosed(_) => IpcError::new("NetAdmin", "FAIL_CLOSED", message),
            E::Tensor(_) => IpcError::new("Integrity", "LEDGER_IO_FAILED", message).retriable(),
            E::InsecureKey => IpcError::new("Config", "INSECURE_KEY_REJECTED", message),
        }
    }
}

impl From<ssk_config::ConfigError> for IpcError {
    fn from(err: ssk_config::ConfigError) -> Self {
        IpcError::new("Config", "CONFIG_INVALID", err.to_string())
            .with_next_step("Fix the config file and reload.")
    }
}
