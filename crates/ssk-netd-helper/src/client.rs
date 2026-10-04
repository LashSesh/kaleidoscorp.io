//! The privileged **client**: handshake, then request/response over
//! [`crate::framing`] (roadmap P3).
//!
//! Transport-agnostic by construction. It is generic over
//! [`crate::framing::FrameTransport`], so the same code drives a Windows named
//! pipe (implemented in `ssk-winhost`, which owns the FFI), a Unix socket, or an
//! in-memory pair in a test. Nothing here knows what a pipe is.
//!
//! # What the client must still do that this type cannot
//!
//! On Windows the client must verify that the pipe it connected to is **owned by
//! `S-1-5-18`** before it writes its first frame. The broker's endpoint name is
//! fixed and well known (a LocalSystem service cannot scope its name to a
//! per-user state directory the way `sskd` does), and a fixed name can be
//! squatted by an unprivileged process that starts first.
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` makes *our server's* bind fail closed, which
//! protects the server; nothing protects the client. A squatter that answers a
//! handshake and returns a forged `Ok(Status)` claiming `Engaged` while egress
//! flows is exactly the failure a green panel must never show.
//!
//! That check is a `GetSecurityInfo` call on the connected handle — a syscall,
//! so it belongs in `ssk-winhost`, and it must run **before**
//! [`PrivilegedClient::connect`] is handed the transport. This crate cannot
//! perform it and does not pretend to; the obligation is stated here so it
//! cannot be lost between the two crates.

use crate::framing::{read_frame, write_frame, FrameError, FrameTransport, MAX_HANDSHAKE_FRAME};
use crate::handshake::{
    ClientHello, HandshakeReject, ServerHandshake, ServerHello, PRIV_HANDSHAKE_MAGIC,
};
use crate::lease::{LeaseId, LeaseKind};
use crate::protocol::{
    BrokerResponse, CapabilityToken, Command, CommandEnvelope, IdempotencyKey, Nonce, RejectReason,
    MAX_PRIV_FRAME,
};
use crate::status::KillSwitchStatus;

/// A source of per-command 16-byte values (anti-replay nonces and idempotency
/// keys).
///
/// Injected rather than generated here for two reasons: this crate has no
/// CSPRNG dependency and must not grow one to serve a protocol type, and tests
/// need determinism. **Production must supply a CSPRNG** — a predictable nonce
/// is a nonce an attacker can burn ahead of a legitimate client, turning
/// anti-replay into denial-of-service.
pub trait NonceSource {
    fn next(&mut self) -> [u8; 16];
}

/// Why a privileged client call did not succeed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The framing or the underlying stream failed.
    #[error("{0}")]
    Frame(#[from] FrameError),
    /// The server refused the connection at the handshake.
    #[error("handshake refused: {0}")]
    Refused(#[from] HandshakeReject),
    /// The server answered, but not with something this protocol allows at this
    /// point (e.g. a second `ServerHello`, or a hello whose magic is wrong).
    #[error("protocol violation: {0}")]
    Protocol(String),
    /// The broker refused the command.
    #[error("command rejected: {0:?}")]
    Rejected(RejectReason),
    /// The broker attempted the OS effect and it failed (state unchanged per
    /// the §6 rollback contract).
    #[error("command failed: {0}")]
    Failed(String),
}

impl ClientError {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            ClientError::Frame(e) => e.code(),
            ClientError::Refused(e) => e.code(),
            ClientError::Protocol(_) => "PRIV_PROTOCOL_VIOLATION",
            ClientError::Rejected(_) => "PRIV_COMMAND_REJECTED",
            ClientError::Failed(_) => "PRIV_COMMAND_FAILED",
        }
    }
}

/// A connected, handshaken privileged client.
pub struct PrivilegedClient<T: FrameTransport, N: NonceSource> {
    transport: T,
    nonces: N,
    hello: ServerHello,
    known_version: u64,
}

/// Deliberately hand-written and deliberately partial: the transport and the
/// nonce source are not `Debug`, and the session token must never be printed
/// into a log by an accidental `{:?}`.
impl<T: FrameTransport, N: NonceSource> std::fmt::Debug for PrivilegedClient<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivilegedClient")
            .field("protocol_version", &self.hello.protocol_version)
            .field("lease", &self.hello.lease.to_hex())
            .field("known_version", &self.known_version)
            .finish_non_exhaustive()
    }
}

impl<T: FrameTransport, N: NonceSource> PrivilegedClient<T, N> {
    /// Perform the handshake and return a client ready to send verbs.
    ///
    /// # Errors
    /// [`ClientError`] — a refused handshake carries the server's typed
    /// [`HandshakeReject`], including which protocol versions each side speaks.
    pub fn connect(mut transport: T, nonces: N, hello: ClientHello) -> Result<Self, ClientError> {
        write_frame(&mut transport, &hello, MAX_HANDSHAKE_FRAME)?;
        let answer: ServerHandshake = read_frame(&mut transport, MAX_HANDSHAKE_FRAME)?;
        let server_hello = match answer {
            ServerHandshake::Accepted(h) => h,
            ServerHandshake::Rejected(reason) => return Err(ClientError::Refused(reason)),
        };
        if server_hello.magic != PRIV_HANDSHAKE_MAGIC {
            return Err(ClientError::Protocol(
                "server hello carried the wrong magic".to_owned(),
            ));
        }
        // A server that answers with a version outside what we offered is not
        // speaking our protocol. Refuse rather than adopt: adopting whatever the
        // far end says is how a downgrade becomes invisible.
        if server_hello.protocol_version < hello.min_protocol_version
            || server_hello.protocol_version > hello.max_protocol_version
        {
            return Err(ClientError::Protocol(format!(
                "server chose protocol version {} which is outside the offered {}..={}",
                server_hello.protocol_version,
                hello.min_protocol_version,
                hello.max_protocol_version
            )));
        }
        Ok(PrivilegedClient {
            transport,
            nonces,
            known_version: server_hello.state_version,
            hello: server_hello,
        })
    }

    /// The claim this connection holds.
    #[must_use]
    pub fn lease(&self) -> LeaseId {
        self.hello.lease
    }

    /// The negotiated protocol version.
    #[must_use]
    pub fn protocol_version(&self) -> u16 {
        self.hello.protocol_version
    }

    /// The session token the server minted.
    #[must_use]
    pub fn session_token(&self) -> CapabilityToken {
        self.hello.session_token
    }

    /// The state version this client believes is authoritative.
    #[must_use]
    pub fn known_version(&self) -> u64 {
        self.known_version
    }

    /// Read the authoritative status.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn status(&mut self) -> Result<KillSwitchStatus, ClientError> {
        self.run(Command::GetStatus)
    }

    /// Sever egress, taking this connection's claim.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn engage(&mut self) -> Result<KillSwitchStatus, ClientError> {
        self.run(Command::EngageKillSwitch)
    }

    /// Drop this connection's claim, restoring egress if it was the last.
    ///
    /// # Errors
    /// [`ClientError`].
    pub fn release(&mut self) -> Result<KillSwitchStatus, ClientError> {
        self.run(Command::ReleaseKillSwitch)
    }

    /// Send one command, refreshing and retrying **once** on a stale version.
    ///
    /// Each attempt uses a fresh nonce, so the retry is not a replay. A second
    /// stale is surfaced rather than retried again: two lost races in a row mean
    /// someone else is driving the switch, and a client that keeps retrying
    /// would fight them silently.
    fn run(&mut self, command: Command) -> Result<KillSwitchStatus, ClientError> {
        for attempt in 0..2u8 {
            let response = self.exchange(command)?;
            match response {
                BrokerResponse::Ok(status) => {
                    self.known_version = status.state_version;
                    return Ok(status);
                }
                BrokerResponse::Rejected(RejectReason::StaleVersion { actual, .. })
                    if attempt == 0 =>
                {
                    self.known_version = actual;
                }
                BrokerResponse::Rejected(reason) => return Err(ClientError::Rejected(reason)),
                BrokerResponse::Failed(message) => return Err(ClientError::Failed(message)),
            }
        }
        Err(ClientError::Rejected(RejectReason::StaleVersion {
            expected: self.known_version,
            actual: self.known_version,
        }))
    }

    /// One request/response round trip.
    ///
    /// # Errors
    /// [`ClientError::Frame`].
    pub fn exchange(&mut self, command: Command) -> Result<BrokerResponse, ClientError> {
        let envelope = CommandEnvelope {
            session_token: self.hello.session_token,
            nonce: Nonce(self.nonces.next()),
            idempotency_key: IdempotencyKey(self.nonces.next()),
            expected_state_version: self.known_version,
            command,
        };
        write_frame(&mut self.transport, &envelope, MAX_PRIV_FRAME)?;
        let response: BrokerResponse = read_frame(&mut self.transport, MAX_PRIV_FRAME)?;
        Ok(response)
    }

    /// Give the transport back, so a caller can close it deliberately.
    #[must_use]
    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// A [`ClientHello`] for a connection whose claim dies with it.
#[must_use]
pub fn session_hello() -> ClientHello {
    ClientHello::new(LeaseKind::Session)
}

/// A [`ClientHello`] for a connection taking a claim that survives a restart —
/// what an operator typing `killswitch engage` means.
#[must_use]
pub fn pinned_hello() -> ClientHello {
    ClientHello::new(LeaseKind::Pinned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{PRIV_MIN_PROTOCOL_VERSION, PRIV_PROTOCOL_VERSION};
    use crate::testing::{framed_value, FakeTransport};

    struct SeqNonces(u128);
    impl NonceSource for SeqNonces {
        fn next(&mut self) -> [u8; 16] {
            self.0 += 1;
            self.0.to_le_bytes()
        }
    }

    fn accepted(version: u16, state_version: u64) -> ServerHandshake {
        ServerHandshake::Accepted(ServerHello {
            magic: PRIV_HANDSHAKE_MAGIC,
            protocol_version: version,
            session_token: CapabilityToken([7u8; 16]),
            lease: LeaseId([5u8; 16]),
            state_version,
        })
    }

    #[test]
    fn connect_negotiates_and_adopts_the_servers_state_version() {
        let mut inbound = framed_value(&accepted(PRIV_PROTOCOL_VERSION, 42));
        inbound.extend(framed_value(&BrokerResponse::Rejected(
            RejectReason::BadToken,
        )));
        let t = FakeTransport::with_inbound(inbound);
        let client = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap();
        assert_eq!(client.known_version(), 42);
        assert_eq!(client.protocol_version(), PRIV_PROTOCOL_VERSION);
        assert_eq!(client.lease(), LeaseId([5u8; 16]));
        assert_eq!(client.session_token(), CapabilityToken([7u8; 16]));
    }

    #[test]
    fn the_first_frame_written_is_the_hello() {
        let t = FakeTransport::with_inbound(framed_value(&accepted(PRIV_PROTOCOL_VERSION, 0)));
        let client = PrivilegedClient::connect(t, SeqNonces(0), pinned_hello()).unwrap();
        let transport = client.into_transport();
        let frames = transport.written_frames();
        assert_eq!(frames.len(), 1);
        let hello: ClientHello = crate::framing::decode_strict(&frames[0]).unwrap();
        assert_eq!(hello.magic, PRIV_HANDSHAKE_MAGIC);
        assert_eq!(hello.lease_kind, LeaseKind::Pinned);
        assert_eq!(hello.min_protocol_version, PRIV_MIN_PROTOCOL_VERSION);
        assert_eq!(hello.max_protocol_version, PRIV_PROTOCOL_VERSION);
    }

    #[test]
    fn a_refused_handshake_surfaces_the_servers_typed_reason() {
        let t = FakeTransport::with_inbound(framed_value(&ServerHandshake::Rejected(
            HandshakeReject::VersionMismatch {
                server_min: 2,
                server_max: 3,
                client_min: 1,
                client_max: 1,
            },
        )));
        let err = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap_err();
        assert_eq!(err.code(), "PRIV_VERSION_MISMATCH");
        assert!(err.to_string().contains("server speaks 2..=3"), "{err}");
    }

    /// A server that answers with a version the client never offered is not
    /// speaking this protocol. Adopting it silently is how a downgrade attack
    /// (or a bad build) becomes invisible.
    #[test]
    fn a_server_chosen_version_outside_the_offered_range_is_refused() {
        for bad in [PRIV_PROTOCOL_VERSION + 1, PRIV_MIN_PROTOCOL_VERSION - 1] {
            let t = FakeTransport::with_inbound(framed_value(&accepted(bad, 0)));
            let err = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap_err();
            assert_eq!(err.code(), "PRIV_PROTOCOL_VIOLATION", "version {bad}");
        }
    }

    #[test]
    fn a_server_hello_with_the_wrong_magic_is_refused() {
        let mut hello = match accepted(PRIV_PROTOCOL_VERSION, 0) {
            ServerHandshake::Accepted(h) => h,
            ServerHandshake::Rejected(_) => unreachable!(),
        };
        hello.magic = *b"SQUATTER";
        let t = FakeTransport::with_inbound(framed_value(&ServerHandshake::Accepted(hello)));
        let err = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap_err();
        assert_eq!(err.code(), "PRIV_PROTOCOL_VIOLATION");
    }

    #[test]
    fn a_server_that_closes_before_answering_the_hello_is_a_transport_error() {
        let t = FakeTransport::default();
        let err = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap_err();
        assert_eq!(err.code(), "PRIV_PEER_CLOSED");
    }

    #[test]
    fn every_command_carries_a_fresh_nonce_and_key() {
        let mut inbound = framed_value(&accepted(PRIV_PROTOCOL_VERSION, 0));
        for _ in 0..2 {
            inbound.extend(framed_value(&BrokerResponse::Rejected(
                RejectReason::BadToken,
            )));
        }
        let t = FakeTransport::with_inbound(inbound);
        let mut client = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap();
        assert!(client.exchange(Command::GetStatus).is_ok());
        assert!(client.exchange(Command::GetStatus).is_ok());

        let frames = client.into_transport().written_frames();
        assert_eq!(frames.len(), 3, "hello + two envelopes");
        let a: CommandEnvelope = crate::framing::decode_strict(&frames[1]).unwrap();
        let b: CommandEnvelope = crate::framing::decode_strict(&frames[2]).unwrap();
        assert_ne!(
            a.nonce, b.nonce,
            "a reused nonce is a self-inflicted replay"
        );
        assert_ne!(a.idempotency_key, b.idempotency_key);
        assert_ne!(
            a.nonce.0, a.idempotency_key.0,
            "the nonce and the key must be independent draws"
        );
    }

    /// The stale-version retry: one refresh, one retry, then surface. The retry
    /// must use a *fresh* nonce or the broker would reject it as a replay.
    #[test]
    fn a_stale_version_is_refreshed_and_retried_exactly_once() {
        let mut inbound = framed_value(&accepted(PRIV_PROTOCOL_VERSION, 0));
        inbound.extend(framed_value(&BrokerResponse::Rejected(
            RejectReason::StaleVersion {
                expected: 0,
                actual: 9,
            },
        )));
        inbound.extend(framed_value(&BrokerResponse::Rejected(
            RejectReason::StaleVersion {
                expected: 9,
                actual: 11,
            },
        )));
        let t = FakeTransport::with_inbound(inbound);
        let mut client = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap();
        let err = client.engage().unwrap_err();
        assert!(
            matches!(
                err,
                ClientError::Rejected(RejectReason::StaleVersion { .. })
            ),
            "{err:?}"
        );
        let frames = client.into_transport().written_frames();
        assert_eq!(frames.len(), 3, "hello + exactly two attempts, not a loop");
        let first: CommandEnvelope = crate::framing::decode_strict(&frames[1]).unwrap();
        let second: CommandEnvelope = crate::framing::decode_strict(&frames[2]).unwrap();
        assert_eq!(first.expected_state_version, 0);
        assert_eq!(
            second.expected_state_version, 9,
            "the retry adopts the version the broker reported"
        );
        assert_ne!(first.nonce, second.nonce, "the retry must not be a replay");
    }

    #[test]
    fn a_failed_command_surfaces_as_failed_not_as_success() {
        let mut inbound = framed_value(&accepted(PRIV_PROTOCOL_VERSION, 0));
        inbound.extend(framed_value(&BrokerResponse::Failed(
            "netsh said no".to_owned(),
        )));
        let t = FakeTransport::with_inbound(inbound);
        let mut client = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap();
        let err = client.engage().unwrap_err();
        assert_eq!(err.code(), "PRIV_COMMAND_FAILED");
        assert!(err.to_string().contains("netsh said no"));
    }

    #[test]
    fn an_oversized_response_frame_is_refused_by_the_client_too() {
        let mut inbound = framed_value(&accepted(PRIV_PROTOCOL_VERSION, 0));
        inbound.extend((MAX_PRIV_FRAME as u32 + 1).to_be_bytes());
        let t = FakeTransport::with_inbound(inbound);
        let mut client = PrivilegedClient::connect(t, SeqNonces(0), session_hello()).unwrap();
        let err = client.exchange(Command::GetStatus).unwrap_err();
        assert_eq!(err.code(), "PRIV_FRAME_TOO_LARGE");
    }
}
