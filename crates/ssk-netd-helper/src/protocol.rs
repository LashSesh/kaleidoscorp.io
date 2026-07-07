//! Broker command protocol (SPEC_TAURI_GUI.md §5): the authenticated,
//! anti-replay, strict-CBOR envelope every privileged verb arrives in.
//!
//! This is the portable, synchronous protocol layer. It does not open sockets;
//! the async `ssk-ipc` named-pipe transport (client-SID authenticated) decodes a
//! frame's bytes with [`decode_envelope`] and hands the result to the broker.

use serde::{Deserialize, Serialize};

use crate::status::KillSwitchStatus;

/// Hard cap on a single privileged command frame, far below the generic 16 MiB
/// IPC frame cap: a [`CommandEnvelope`] is tiny, so anything larger is hostile
/// and rejected before any decode work (SPEC §5.3).
pub const MAX_PRIV_FRAME: usize = 64 * 1024;

/// Per-session capability token, required on **every** command (SPEC §5.1).
///
/// Mirrors `ssk_ipc::auth::SessionToken` (the same `[u8; 16]` minted per
/// named-pipe connection); the transport seam populates this from that token so
/// the security core need not depend on the async transport crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken(pub [u8; 16]);

/// A per-command anti-replay nonce (SPEC §5.2): unique within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nonce(pub [u8; 16]);

/// An idempotency key (SPEC §8): a repeated key returns the cached result
/// without re-executing the OS effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyKey(pub [u8; 16]);

/// The privileged verbs P0 serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Command {
    /// Read-only: return the authoritative kill-switch status.
    GetStatus,
    /// Sever all outbound egress (engage the kill-switch).
    EngageKillSwitch,
    /// Restore egress (release the kill-switch) using the broker-held receipt.
    ReleaseKillSwitch,
}

impl Command {
    /// Whether this verb mutates state (and thus takes the write path:
    /// op-lock, nonce, idempotency, state-version).
    #[must_use]
    pub fn is_mutating(self) -> bool {
        !matches!(self, Command::GetStatus)
    }
}

/// The wire envelope for one privileged command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandEnvelope {
    pub session_token: CapabilityToken,
    pub nonce: Nonce,
    pub idempotency_key: IdempotencyKey,
    /// The state version the client believes is current (optimistic concurrency,
    /// SPEC §8). Ignored for read-only verbs.
    pub expected_state_version: u64,
    pub command: Command,
}

/// Why a command was refused before (or instead of) execution — always explicit,
/// never a silent drop (SPEC §5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RejectReason {
    /// The capability token did not match the session's token.
    BadToken,
    /// The nonce was already seen in this session (replay).
    ReplayedNonce,
    /// The frame exceeded [`MAX_PRIV_FRAME`].
    FrameTooLarge,
    /// The frame was not a well-formed, strict `CommandEnvelope`.
    MalformedCommand,
    /// The client's `expected_state_version` did not match the broker's.
    StaleVersion { expected: u64, actual: u64 },
    /// The broker is not authorized to actuate (its manifest is invalid).
    Unauthorized,
}

/// The broker's typed answer to a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum BrokerResponse {
    /// The verb succeeded (or a read completed); carries the authoritative status.
    Ok(KillSwitchStatus),
    /// The command was refused before execution.
    Rejected(RejectReason),
    /// The verb was attempted but the OS effect failed (state unchanged per the
    /// §6 rollback contract).
    Failed(String),
}

/// Strictly decode a privileged command frame (SPEC §5.3–§5.4):
/// * reject anything larger than [`MAX_PRIV_FRAME`] before decoding,
/// * reject unknown fields (via `deny_unknown_fields` on the DTOs), and
/// * reject trailing bytes after the CBOR value — a security command must be
///   exactly one well-formed envelope, nothing appended.
///
/// # Errors
/// [`RejectReason::FrameTooLarge`] or [`RejectReason::MalformedCommand`].
pub fn decode_envelope(bytes: &[u8]) -> Result<CommandEnvelope, RejectReason> {
    if bytes.len() > MAX_PRIV_FRAME {
        return Err(RejectReason::FrameTooLarge);
    }
    let mut cursor = std::io::Cursor::new(bytes);
    let envelope: CommandEnvelope =
        ciborium::de::from_reader(&mut cursor).map_err(|_| RejectReason::MalformedCommand)?;
    // Reject trailing bytes: exactly one value must fill the frame.
    if usize::try_from(cursor.position()).unwrap_or(usize::MAX) != bytes.len() {
        return Err(RejectReason::MalformedCommand);
    }
    Ok(envelope)
}

/// Encode an envelope to a frame (test/transport helper).
///
/// # Errors
/// Returns an error string if serialization fails (never expected for these
/// fixed-shape types).
pub fn encode_envelope(envelope: &CommandEnvelope) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(envelope, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}
