//! Broker command protocol (SPEC_TAURI_GUI.md §5): the authenticated,
//! anti-replay, strict-CBOR envelope every privileged verb arrives in.
//!
//! This is the portable, synchronous protocol layer. It does not open sockets.
//! Since P3 the privileged transport lives in this crate too — [`crate::framing`]
//! delimits a frame, [`crate::server`] decodes its bytes with [`decode_envelope`]
//! and hands the result to the broker — and the byte stream underneath it is an
//! injected [`crate::framing::FrameTransport`], implemented for Windows named
//! pipes in `ssk-winhost`. It is **not** the `ssk-ipc` transport, which serves
//! the separate, unprivileged `sskd` pipe with its own frame cap and its own
//! same-user authentication contract.

use serde::{Deserialize, Serialize};

use crate::status::KillSwitchStatus;

/// Hard cap on a single privileged command frame: a [`CommandEnvelope`] is
/// tiny, so anything larger is hostile and is rejected before any decode work
/// (SPEC §5.3).
///
/// This happens to equal `ssk_ipc::framing::MAX_REQUEST_FRAME_LEN` since P2
/// bounded the generic IPC frame to the same 64 KiB. The two are independent
/// caps on independent transports and neither derives from the other — do not
/// couple them, and do not describe either as a bound on the other.
pub const MAX_PRIV_FRAME: usize = 64 * 1024;

/// Per-session capability token, required on **every** command (SPEC §5.1).
///
/// **Transmitted since P3** by [`crate::handshake`]: the composition root mints
/// it, a client receives it in [`crate::handshake::ServerHello`], and puts it on
/// every subsequent envelope. It is per **broker**, not per connection, so a new
/// connection does not re-key it. This previously claimed to mirror
/// `ssk_ipc::auth::SessionToken`, which P2 deleted: that token was generated
/// per connection and handed to the handler, but was never transmitted and
/// never verified, so it authenticated nothing.
///
/// **What it proves is narrow, and stating it precisely matters.** It binds a
/// command to a completed handshake — a frame replayed onto a different
/// connection is refused — and nothing else. It is handed to *whoever* completed
/// the handshake, so every peer the pipe's DACL admitted holds one. It is not an
/// input to the authorization decision; that is
/// [`crate::authz::PeerAuthorizer`]'s, is made per request, and is made before
/// this token is even compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityToken(pub [u8; 16]);

impl CapabilityToken {
    /// Constant-time equality. **This is the only comparison the broker's
    /// auth check may use.**
    ///
    /// The derived `PartialEq` on `[u8; 16]` short-circuits on the first
    /// differing byte, so the time to reject leaks how many leading bytes a
    /// guess got right — enough to recover a 16-byte token one byte at a time
    /// over a local IPC channel an attacker can call in a tight loop.
    ///
    /// Implemented here rather than pulled from `subtle`: adding a direct
    /// dependency also rewrites the committed `Cargo.lock`, which is outside
    /// this change's file scope. The loop below is the same primitive —
    /// unconditional XOR-accumulate over the full length, with the accumulator
    /// passed through [`core::hint::black_box`] so the optimiser cannot
    /// reintroduce an early exit. `PartialEq` is retained on the type because
    /// [`CommandEnvelope`] derives it for test comparison; it must not be used
    /// on the auth path.
    #[must_use]
    pub fn ct_eq(&self, other: &CapabilityToken) -> bool {
        let mut diff = 0u8;
        for i in 0..16 {
            diff |= self.0[i] ^ other.0[i];
        }
        core::hint::black_box(diff) == 0
    }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[non_exhaustive]
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
    /// An idempotency key already used for one verb was resubmitted with a
    /// **different** verb.
    ///
    /// An idempotency key names one operation. Reusing it across verbs is
    /// either a client defect or an attempt to have a cached `engage` result
    /// returned for a `release` that never ran — which would report restored
    /// egress while the machine stays severed. Never silently accepted.
    IdempotencyKeyConflict { cached: Command, submitted: Command },
    /// The session's anti-replay bookkeeping is full.
    ///
    /// Refused rather than evicted: see [`crate::MAX_SESSION_MUTATIONS`].
    /// Read-only verbs are unaffected, so status remains observable.
    SessionMutationLimitReached { limit: u64 },
    /// The **peer** was refused this verb (P3).
    ///
    /// Distinct from [`RejectReason::Unauthorized`], which is about the
    /// *broker's* own authority to actuate at all. Conflating them would tell an
    /// operator to fix the wrong thing: `Unauthorized` means the service was
    /// deployed without a grant for itself, `PeerUnauthorized` means this caller
    /// is not on the allow-list. `code` is the stable
    /// [`crate::authz::AuthzDenied::code`]; `detail` is the human-readable
    /// reason, which no branch may parse.
    PeerUnauthorized { code: String, detail: String },
    /// A mutating verb arrived at the peer-less in-process entry point
    /// ([`crate::Broker::handle`]) on a broker that has a peer authorizer
    /// configured.
    ///
    /// Not reachable through the privileged transport, which always carries a
    /// peer. It exists so that the un-authorized entry point fails loudly on a
    /// privileged deployment instead of quietly acting without a peer decision.
    PeerAuthorizationRequired,
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
