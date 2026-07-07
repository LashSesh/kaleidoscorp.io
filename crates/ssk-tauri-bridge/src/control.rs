//! P2 — the privileged control layer (SPEC_TAURI_GUI.md §5, §8, §12/P2).
//!
//! Turns a panel intent ("engage" / "release") into an authenticated
//! [`CommandEnvelope`] for the privileged broker: a fresh anti-replay nonce and
//! idempotency key, and the `expected_state_version` the bridge last observed
//! (optimistic concurrency). It sends over a [`ControlClient`] — in-process for
//! Linux CI (wrapping a [`ssk_netd_helper::Broker`] directly), a client of the
//! `ssk-ipc` named pipe on Windows (a later transport-wiring step) — and maps
//! the typed [`BrokerResponse`] back, refreshing and retrying **once** on a
//! stale version.
//!
//! This layer holds no privileged logic: the broker remains the single
//! authoritative owner (§2). The nonce source is injected so tests are
//! deterministic; production supplies a CSPRNG-backed source at the transport
//! seam (anti-replay wants unpredictable nonces).

use ssk_netd_helper::{
    BrokerResponse, CapabilityToken, Command, CommandEnvelope, IdempotencyKey, KillSwitchStatus,
    Nonce, RejectReason,
};

/// The transport a control command is sent over. In-process (a `&Broker`) for
/// P2/Linux; a named-pipe client on Windows later. Kept as a trait so the
/// control logic is transport-agnostic and Linux-testable end-to-end.
pub trait ControlClient {
    fn send(&self, envelope: CommandEnvelope) -> BrokerResponse;
}

/// A source of per-command 16-byte values (anti-replay nonces + idempotency
/// keys). Injected for determinism in tests; production supplies a CSPRNG.
pub trait NonceSource {
    fn next(&mut self) -> [u8; 16];
}

/// Why a privileged control command did not succeed — a typed, fail-closed
/// value (never a silent success).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ControlError {
    /// The broker refused the command before executing it (bad token, replay,
    /// still-stale version after a refresh, unauthorized, malformed).
    #[error("command rejected: {0:?}")]
    Rejected(RejectReason),
    /// The broker attempted the OS effect but it failed (state unchanged per the
    /// §6 rollback contract).
    #[error("command failed: {0}")]
    Failed(String),
}

/// Drives the privileged kill-switch verbs against the broker, tracking the last
/// observed authoritative version for optimistic concurrency.
pub struct KillSwitchControl<C: ControlClient, N: NonceSource> {
    client: C,
    nonces: N,
    token: CapabilityToken,
    known_version: u64,
}

impl<C: ControlClient, N: NonceSource> KillSwitchControl<C, N> {
    /// Build a control driver. `initial_version` is the version the bridge last
    /// observed (0 before the first `refresh`).
    pub fn new(client: C, nonces: N, token: CapabilityToken, initial_version: u64) -> Self {
        KillSwitchControl {
            client,
            nonces,
            token,
            known_version: initial_version,
        }
    }

    /// The version the driver currently believes is authoritative.
    #[must_use]
    pub fn known_version(&self) -> u64 {
        self.known_version
    }

    fn envelope(&mut self, command: Command) -> CommandEnvelope {
        CommandEnvelope {
            session_token: self.token,
            nonce: Nonce(self.nonces.next()),
            idempotency_key: IdempotencyKey(self.nonces.next()),
            expected_state_version: self.known_version,
            command,
        }
    }

    /// Read the authoritative status (updates the tracked version).
    ///
    /// # Errors
    /// [`ControlError`] if the broker rejects or fails the read.
    pub fn refresh(&mut self) -> Result<KillSwitchStatus, ControlError> {
        let env = self.envelope(Command::GetStatus);
        self.apply(self.client.send(env))
    }

    /// Engage the kill-switch (sever egress). Refreshes and retries once on a
    /// stale version.
    ///
    /// # Errors
    /// [`ControlError`] on a non-recoverable rejection or an OS-effect failure.
    pub fn engage(&mut self) -> Result<KillSwitchStatus, ControlError> {
        self.run(Command::EngageKillSwitch)
    }

    /// Release the kill-switch (restore egress) using the broker-held receipt.
    ///
    /// # Errors
    /// [`ControlError`] on a non-recoverable rejection or an OS-effect failure.
    pub fn release(&mut self) -> Result<KillSwitchStatus, ControlError> {
        self.run(Command::ReleaseKillSwitch)
    }

    /// Send a mutating command, refreshing + retrying **once** on a stale
    /// version (each attempt uses a fresh nonce, so the retry is not a replay).
    fn run(&mut self, command: Command) -> Result<KillSwitchStatus, ControlError> {
        for attempt in 0..2 {
            let env = self.envelope(command);
            match self.client.send(env) {
                BrokerResponse::Ok(status) => {
                    self.known_version = status.state_version;
                    return Ok(status);
                }
                BrokerResponse::Rejected(RejectReason::StaleVersion { actual, .. })
                    if attempt == 0 =>
                {
                    // Someone else moved the state: adopt the real version and
                    // retry once with a fresh nonce.
                    self.known_version = actual;
                }
                BrokerResponse::Rejected(reason) => return Err(ControlError::Rejected(reason)),
                BrokerResponse::Failed(msg) => return Err(ControlError::Failed(msg)),
            }
        }
        // A second stale is not retried again — surface it.
        Err(ControlError::Rejected(RejectReason::StaleVersion {
            expected: self.known_version,
            actual: self.known_version,
        }))
    }

    fn apply(&mut self, response: BrokerResponse) -> Result<KillSwitchStatus, ControlError> {
        match response {
            BrokerResponse::Ok(status) => {
                self.known_version = status.state_version;
                Ok(status)
            }
            BrokerResponse::Rejected(reason) => Err(ControlError::Rejected(reason)),
            BrokerResponse::Failed(msg) => Err(ControlError::Failed(msg)),
        }
    }
}
