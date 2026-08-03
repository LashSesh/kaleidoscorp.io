//! The **versioned handshake** that opens a privileged connection (roadmap P3).
//!
//! Exactly one frame each way, before any [`crate::CommandEnvelope`] is decoded:
//!
//! ```text
//! client → server   ClientHello        (<= MAX_HANDSHAKE_FRAME)
//! server → client   ServerHandshake    (Accepted | Rejected)
//! ```
//!
//! # Why a handshake at all
//!
//! Three things have to be settled before a privileged verb can be trusted, and
//! none of them fit inside a command envelope:
//!
//! 1. **The protocol version.** A privileged control channel that changes shape
//!    across releases and has no version field fails as a *misparse*, not as a
//!    refusal — a `CommandEnvelope` whose field order changed could decode into
//!    a different verb. The version is negotiated as a *range* on both sides, so
//!    an old client meeting a new server gets
//!    [`HandshakeReject::VersionMismatch`] naming both ranges rather than an
//!    unexplained decode failure.
//! 2. **The capability token.** [`crate::CapabilityToken`]'s own doc has said
//!    since P0 that it is "not yet minted by any transport". This is that
//!    transport. See [`ServerHello::session_token`] for what it does and does
//!    not prove.
//! 3. **The lease.** Refcounting needs to know, *before* the first engage,
//!    whether this holder's claim dies with the connection or outlives it. That
//!    is a property of the client, not of an individual command, so it is
//!    declared once here instead of being carried on every verb.
//!
//! # What the client is *not* allowed to say
//!
//! No path, rule name, scope label or principal. The privileged verb set is
//! closed and parameterless by design: a confused deputy needs an
//! attacker-chosen object, and the broker offers none — scope and rule name are
//! re-derived inside the broker and the enforcer from the broker's own
//! configuration. The audit line's `holder` is the SID the *transport*
//! authenticated, never a name the client supplied. **Adding a caller-supplied
//! name, path or SID to this hello, or to [`crate::Command`], reopens that
//! question and must not be done without re-validating it against a closed set.**

use serde::{Deserialize, Serialize};

use crate::framing::{FrameError, MAX_HANDSHAKE_FRAME};
use crate::lease::{LeaseId, LeaseKind};
use crate::protocol::CapabilityToken;

/// Identifies this protocol on the wire, independently of its version.
///
/// A fixed, well-known pipe name is unavoidable for a LocalSystem broker
/// (clients cannot derive SYSTEM's state-directory digest the way P2's
/// per-state-dir daemon name is derived), and a fixed name invites squatting.
/// The magic is **not** a defence against that — a squatter can echo eight
/// bytes. It only makes "wrong protocol on this endpoint" fail immediately and
/// legibly instead of as a CBOR error. The real client-side defence is checking
/// that the pipe's owner is `S-1-5-18`, which is a syscall and therefore lives
/// in `ssk-winhost`.
pub const PRIV_HANDSHAKE_MAGIC: [u8; 8] = *b"SSKBROKR";

/// The newest protocol version this build speaks.
pub const PRIV_PROTOCOL_VERSION: u16 = 1;

/// The oldest protocol version this build still accepts.
///
/// Equal to [`PRIV_PROTOCOL_VERSION`] today because there has never been a
/// shipped version 0. It is a separate constant so that raising the floor is a
/// deliberate, reviewable edit rather than a side effect of bumping the ceiling.
pub const PRIV_MIN_PROTOCOL_VERSION: u16 = 1;

/// The client's opening frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientHello {
    pub magic: [u8; 8],
    /// The oldest version this client can speak.
    pub min_protocol_version: u16,
    /// The newest version this client can speak.
    pub max_protocol_version: u16,
    /// Whether this client's claim on the kill-switch dies with the connection.
    pub lease_kind: LeaseKind,
    /// Re-attach to an existing durable claim instead of taking a new one.
    ///
    /// Only meaningful for [`LeaseKind::Pinned`]: an operator who engaged in one
    /// session and wants to release in another must be able to name the claim
    /// they are releasing. Presenting an id is **not** authorization — the verb
    /// is still authorized per request — it only says *which* claim.
    pub adopt_lease: Option<LeaseId>,
}

impl ClientHello {
    /// A hello for this build, taking a fresh lease of `kind`.
    #[must_use]
    pub fn new(kind: LeaseKind) -> Self {
        ClientHello {
            magic: PRIV_HANDSHAKE_MAGIC,
            min_protocol_version: PRIV_MIN_PROTOCOL_VERSION,
            max_protocol_version: PRIV_PROTOCOL_VERSION,
            lease_kind: kind,
            adopt_lease: None,
        }
    }

    /// A hello that re-attaches to an existing durable claim.
    #[must_use]
    pub fn adopting(lease: LeaseId) -> Self {
        ClientHello {
            adopt_lease: Some(lease),
            ..ClientHello::new(LeaseKind::Pinned)
        }
    }
}

/// The server's answer when the connection is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerHello {
    pub magic: [u8; 8],
    /// The single version both sides will use for the rest of the connection.
    pub protocol_version: u16,
    /// The token every subsequent [`crate::CommandEnvelope`] must carry.
    ///
    /// **What it proves and what it does not.** It binds a command to a
    /// negotiated connection, so a frame replayed onto a different connection is
    /// refused; it is compared in constant time
    /// ([`CapabilityToken::ct_eq`]). It is **not** the authorization boundary:
    /// it is handed to whoever completed the handshake, so any peer the pipe's
    /// DACL admitted receives one. Authorization is the per-request
    /// [`crate::authz::PeerAuthorizer`] decision, and this token is not an input
    /// to it.
    pub session_token: CapabilityToken,
    /// The claim this connection holds on the kill-switch.
    pub lease: LeaseId,
    /// The state version the client should put in its first envelope.
    pub state_version: u64,
}

/// Why a connection was refused before any command was served.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum HandshakeReject {
    /// The first frame was not this protocol's hello.
    #[error("not the privileged broker protocol")]
    BadMagic,
    /// No version is acceptable to both sides. Both ranges are reported so an
    /// operator can tell which side is old.
    #[error(
        "no common protocol version: server speaks {server_min}..={server_max}, \
         client speaks {client_min}..={client_max}"
    )]
    VersionMismatch {
        server_min: u16,
        server_max: u16,
        client_min: u16,
        client_max: u16,
    },
    /// The hello frame was not a well-formed, strict `ClientHello`.
    #[error("malformed handshake: {0}")]
    Malformed(String),
    /// The server is already serving [`crate::framing::MAX_PRIV_CONNECTIONS`].
    #[error("the privileged broker is at its connection limit")]
    AtCapacity,
    /// The claim the client asked to adopt is not held, or is not adoptable.
    #[error("lease unavailable: {0}")]
    LeaseUnavailable(String),
    /// The peer is not permitted to open a privileged connection at all.
    #[error("peer refused: {0}")]
    PeerRefused(String),
}

impl HandshakeReject {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            HandshakeReject::BadMagic => "PRIV_BAD_MAGIC",
            HandshakeReject::VersionMismatch { .. } => "PRIV_VERSION_MISMATCH",
            HandshakeReject::Malformed(_) => "PRIV_HELLO_MALFORMED",
            HandshakeReject::AtCapacity => "PRIV_AT_CAPACITY",
            HandshakeReject::LeaseUnavailable(_) => "PRIV_LEASE_UNAVAILABLE",
            HandshakeReject::PeerRefused(_) => "PRIV_PEER_REFUSED",
        }
    }
}

/// The server's handshake frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ServerHandshake {
    Accepted(ServerHello),
    Rejected(HandshakeReject),
}

/// The version range this build speaks, as a pair.
#[must_use]
pub fn server_version_range() -> (u16, u16) {
    (PRIV_MIN_PROTOCOL_VERSION, PRIV_PROTOCOL_VERSION)
}

/// Negotiate one protocol version from the client's declared range.
///
/// Pure. The chosen version is the **highest** both sides speak, so two current
/// builds never silently fall back to an older wire shape; a range that does not
/// overlap the server's is refused rather than clamped, because clamping a
/// version is how a client ends up speaking a dialect it told you it could not
/// speak.
///
/// An inverted client range (`min > max`) is malformed input, not an empty
/// intersection, and is reported as such.
///
/// # Errors
/// [`HandshakeReject::BadMagic`], [`HandshakeReject::Malformed`] or
/// [`HandshakeReject::VersionMismatch`].
pub fn negotiate(hello: &ClientHello) -> Result<u16, HandshakeReject> {
    if hello.magic != PRIV_HANDSHAKE_MAGIC {
        return Err(HandshakeReject::BadMagic);
    }
    let (server_min, server_max) = server_version_range();
    if hello.min_protocol_version > hello.max_protocol_version {
        return Err(HandshakeReject::Malformed(format!(
            "client version range is inverted ({}..={})",
            hello.min_protocol_version, hello.max_protocol_version
        )));
    }
    let low = hello.min_protocol_version.max(server_min);
    let high = hello.max_protocol_version.min(server_max);
    if low > high {
        return Err(HandshakeReject::VersionMismatch {
            server_min,
            server_max,
            client_min: hello.min_protocol_version,
            client_max: hello.max_protocol_version,
        });
    }
    Ok(high)
}

/// Decode a hello frame body strictly, mapping any framing failure to the
/// handshake's own rejection type so the client always gets a typed answer.
///
/// # Errors
/// [`HandshakeReject::Malformed`].
pub fn decode_hello(body: &[u8]) -> Result<ClientHello, HandshakeReject> {
    if body.len() > MAX_HANDSHAKE_FRAME {
        return Err(HandshakeReject::Malformed(format!(
            "hello frame of {} bytes exceeds the {MAX_HANDSHAKE_FRAME}-byte cap",
            body.len()
        )));
    }
    crate::framing::decode_strict::<ClientHello>(body).map_err(|e| match e {
        FrameError::Malformed(detail) => HandshakeReject::Malformed(detail),
        other => HandshakeReject::Malformed(other.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(min: u16, max: u16) -> ClientHello {
        ClientHello {
            magic: PRIV_HANDSHAKE_MAGIC,
            min_protocol_version: min,
            max_protocol_version: max,
            lease_kind: LeaseKind::Session,
            adopt_lease: None,
        }
    }

    #[test]
    fn a_current_client_negotiates_the_current_version() {
        assert_eq!(
            negotiate(&ClientHello::new(LeaseKind::Session)).unwrap(),
            PRIV_PROTOCOL_VERSION
        );
    }

    /// The highest common version wins, not the lowest: two builds that both
    /// speak 1..=3 must not settle on 1.
    #[test]
    fn negotiation_picks_the_highest_common_version() {
        assert_eq!(negotiate(&hello(1, 9)).unwrap(), PRIV_PROTOCOL_VERSION);
        assert_eq!(
            negotiate(&hello(PRIV_PROTOCOL_VERSION, PRIV_PROTOCOL_VERSION)).unwrap(),
            PRIV_PROTOCOL_VERSION
        );
    }

    #[test]
    fn a_client_that_is_too_new_is_refused_with_both_ranges_named() {
        let err =
            negotiate(&hello(PRIV_PROTOCOL_VERSION + 1, PRIV_PROTOCOL_VERSION + 5)).unwrap_err();
        assert_eq!(
            err,
            HandshakeReject::VersionMismatch {
                server_min: PRIV_MIN_PROTOCOL_VERSION,
                server_max: PRIV_PROTOCOL_VERSION,
                client_min: PRIV_PROTOCOL_VERSION + 1,
                client_max: PRIV_PROTOCOL_VERSION + 5,
            }
        );
        let rendered = err.to_string();
        assert!(rendered.contains("server speaks"), "{rendered}");
        assert!(rendered.contains("client speaks"), "{rendered}");
        assert_eq!(err.code(), "PRIV_VERSION_MISMATCH");
    }

    #[test]
    fn a_client_that_is_too_old_is_refused_rather_than_clamped_up() {
        const { assert!(PRIV_MIN_PROTOCOL_VERSION > 0) };
        let err = negotiate(&hello(0, 0)).unwrap_err();
        assert!(
            matches!(err, HandshakeReject::VersionMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn an_inverted_client_range_is_malformed_not_a_version_mismatch() {
        let err = negotiate(&hello(9, 1)).unwrap_err();
        assert!(matches!(err, HandshakeReject::Malformed(_)), "{err:?}");
        assert_eq!(err.code(), "PRIV_HELLO_MALFORMED");
    }

    #[test]
    fn the_magic_is_checked_before_the_version() {
        let mut h = hello(1, 1);
        h.magic = *b"NOTAPROT";
        // The range would have negotiated fine; magic still wins.
        assert_eq!(negotiate(&h).unwrap_err(), HandshakeReject::BadMagic);
    }

    #[test]
    fn every_byte_of_the_magic_matters() {
        for i in 0..PRIV_HANDSHAKE_MAGIC.len() {
            let mut h = hello(1, 1);
            h.magic[i] ^= 0x20;
            assert_eq!(
                negotiate(&h).unwrap_err(),
                HandshakeReject::BadMagic,
                "byte {i} of the magic was not checked"
            );
        }
    }

    #[test]
    fn a_hello_round_trips_through_strict_cbor() {
        for h in [
            ClientHello::new(LeaseKind::Session),
            ClientHello::new(LeaseKind::Pinned),
            ClientHello::adopting(LeaseId([3u8; 16])),
        ] {
            let mut body = Vec::new();
            ciborium::ser::into_writer(&h, &mut body).unwrap();
            assert_eq!(decode_hello(&body).unwrap(), h);
        }
    }

    #[test]
    fn adopting_implies_a_durable_claim() {
        let h = ClientHello::adopting(LeaseId([1u8; 16]));
        assert_eq!(h.lease_kind, LeaseKind::Pinned);
        assert_eq!(h.adopt_lease, Some(LeaseId([1u8; 16])));
    }

    #[test]
    fn trailing_bytes_and_unknown_fields_are_both_refused() {
        let mut body = Vec::new();
        ciborium::ser::into_writer(&ClientHello::new(LeaseKind::Session), &mut body).unwrap();
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(matches!(
            decode_hello(&trailing).unwrap_err(),
            HandshakeReject::Malformed(_)
        ));

        assert!(matches!(
            decode_hello(&[0xff, 0xff]).unwrap_err(),
            HandshakeReject::Malformed(_)
        ));
    }

    #[test]
    fn an_oversized_hello_body_is_refused_by_the_handshake_cap() {
        let body = vec![0u8; MAX_HANDSHAKE_FRAME + 1];
        let err = decode_hello(&body).unwrap_err();
        assert!(
            err.to_string().contains(&MAX_HANDSHAKE_FRAME.to_string()),
            "{err}"
        );
    }

    #[test]
    fn the_server_handshake_frame_round_trips_in_both_shapes() {
        for value in [
            ServerHandshake::Accepted(ServerHello {
                magic: PRIV_HANDSHAKE_MAGIC,
                protocol_version: PRIV_PROTOCOL_VERSION,
                session_token: CapabilityToken([4u8; 16]),
                lease: LeaseId([5u8; 16]),
                state_version: 12,
            }),
            ServerHandshake::Rejected(HandshakeReject::AtCapacity),
            ServerHandshake::Rejected(HandshakeReject::PeerRefused("nope".to_owned())),
        ] {
            let mut body = Vec::new();
            ciborium::ser::into_writer(&value, &mut body).unwrap();
            let back: ServerHandshake =
                crate::framing::decode_strict(&body).expect("server handshake decodes");
            assert_eq!(back, value);
        }
    }

    #[test]
    fn reject_codes_are_distinct() {
        let codes = [
            HandshakeReject::BadMagic.code(),
            HandshakeReject::VersionMismatch {
                server_min: 1,
                server_max: 1,
                client_min: 2,
                client_max: 2,
            }
            .code(),
            HandshakeReject::Malformed(String::new()).code(),
            HandshakeReject::AtCapacity.code(),
            HandshakeReject::LeaseUnavailable(String::new()).code(),
            HandshakeReject::PeerRefused(String::new()).code(),
        ];
        let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len());
    }
}
