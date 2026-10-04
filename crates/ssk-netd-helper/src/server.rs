//! The privileged **server**: one connection, handshaken and then served
//! frame by frame (roadmap P3).
//!
//! Transport-agnostic, exactly like [`crate::client`]. The caller — on Windows,
//! `ssk-winhost`'s accept loop — creates the pipe with its SDDL, authenticates
//! the peer (`ImpersonateNamedPipeClient` + `TokenUser`), builds an
//! [`AuthenticatedPeer`], and hands both to
//! [`PrivilegedServer::serve_connection`]. Everything from that point on is pure
//! Rust in a `#![forbid(unsafe_code)]` crate and is fully testable on any
//! machine.
//!
//! # The order of the two checks, and why it is this way round
//!
//! Peer **authentication** happens once, at accept, before this function is
//! called — it must, because it depends on the impersonation quality of service
//! negotiated at connect time and on nothing the peer sends afterwards. Peer
//! **authorization** happens per request, inside
//! [`crate::Broker::handle_from_peer`], because the verb is not known at accept
//! time. Those are two different questions with two different lifetimes and
//! neither can be folded into the other.
//!
//! # What this loop does *not* do
//!
//! It does not decide the DACL, does not open the pipe, does not enforce the
//! read timeout. The first two are syscalls. The third is a syscall too — see
//! [`crate::framing::PRIV_READ_TIMEOUT`] for why naming the obligation is more
//! honest than faking it, and note that a transport which ignores it can never
//! produce [`crate::framing::TransportError::TimedOut`], which is what the tests
//! here inject.

use crate::authz::AuthenticatedPeer;
use crate::broker::{Broker, LeaseAdoptError};
use crate::framing::{
    read_frame_bytes, write_frame, ConnectionLimiter, FrameError, FrameTransport,
    MAX_HANDSHAKE_FRAME,
};
use crate::handshake::{
    decode_hello, negotiate, HandshakeReject, ServerHandshake, ServerHello, PRIV_HANDSHAKE_MAGIC,
};
use crate::lease::{LeaseId, LeaseKind};
use crate::protocol::{decode_envelope, BrokerResponse, MAX_PRIV_FRAME};

/// Mints the id for a connection's claim.
///
/// Injected so the composition root can supply a CSPRNG-backed source. The id
/// is **not a secret** (see [`crate::lease`]); the seam exists so that a
/// deployment which wants unpredictable ids can have them without this crate
/// growing a CSPRNG dependency, and so that tests are deterministic.
///
/// **One source per accept loop, not one per connection.** A source constructed
/// fresh for each connection restarts its sequence, so two live connections
/// would hold the same id and either could drop the other's claim.
pub trait LeaseIdSource {
    fn next(&mut self) -> LeaseId;
}

/// A counter-based source.
///
/// **Predictable by construction, and that is stated rather than hidden.** It is
/// adequate because presenting a lease id is not authorization — a peer that
/// guesses one still has to get past the pipe DACL and a
/// [`crate::authz::PeerAuthorizer`] decision for the verb it wants. A deployment
/// that would rather not rely on that layering should inject a CSPRNG-backed
/// source instead.
#[derive(Debug, Clone)]
pub struct SequentialLeaseIds {
    salt: [u8; 8],
    counter: u64,
}

impl SequentialLeaseIds {
    #[must_use]
    pub fn new(salt: [u8; 8]) -> Self {
        SequentialLeaseIds { salt, counter: 0 }
    }
}

impl LeaseIdSource for SequentialLeaseIds {
    fn next(&mut self) -> LeaseId {
        self.counter += 1;
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.salt);
        id[8..].copy_from_slice(&self.counter.to_be_bytes());
        // The in-process lease is all-0xff; a salt of all-0xff plus a counter
        // could not collide with it (the counter half would have to be 0xff…ff,
        // i.e. u64::MAX connections), but the check is cheap and the
        // consequence of a collision — one connection releasing another's
        // claim — is not.
        if id == LeaseId::IN_PROCESS.0 {
            id[15] ^= 0x01;
        }
        LeaseId(id)
    }
}

/// How a served connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectionOutcome {
    /// The peer disconnected cleanly after `frames` commands.
    Served {
        frames: u64,
        lease: LeaseId,
        lease_kind: LeaseKind,
        /// Whether this connection's claim was dropped when it ended. False for
        /// a [`LeaseKind::Pinned`] claim, which is the point of pinning.
        claim_dropped: bool,
    },
    /// The handshake was refused; nothing was served.
    Refused(HandshakeReject),
    /// The stream failed or desynchronised. The connection is gone.
    TransportFailed(FrameError),
}

/// Serves privileged connections against one [`Broker`].
pub struct PrivilegedServer<'a> {
    broker: &'a Broker,
    limiter: ConnectionLimiter,
    vpn: Option<&'a crate::vpn::Broker>,
}

impl<'a> PrivilegedServer<'a> {
    /// A server with the default [`crate::framing::MAX_PRIV_CONNECTIONS`] cap.
    #[must_use]
    pub fn new(broker: &'a Broker) -> Self {
        PrivilegedServer {
            broker,
            limiter: ConnectionLimiter::default(),
            vpn: None,
        }
    }

    /// A server sharing an existing limiter, so one process-wide cap can cover
    /// several accept loops.
    #[must_use]
    pub fn with_limiter(broker: &'a Broker, limiter: ConnectionLimiter) -> Self {
        PrivilegedServer {
            broker,
            limiter,
            vpn: None,
        }
    }

    pub fn with_vpn(mut self, vpn: Option<&'a crate::vpn::Broker>) -> Self {
        self.vpn = vpn;
        self
    }

    #[must_use]
    pub fn limiter(&self) -> &ConnectionLimiter {
        &self.limiter
    }

    /// Serve one connection to completion.
    ///
    /// Blocks on `transport` until the peer disconnects, the stream fails, or
    /// the handshake is refused. The connection slot is held by an RAII permit
    /// for exactly this call, so a panicking handler cannot leak the cap.
    pub fn serve_connection(
        &self,
        transport: &mut dyn FrameTransport,
        peer: &AuthenticatedPeer,
        lease_ids: &mut dyn LeaseIdSource,
    ) -> ConnectionOutcome {
        let Some(_permit) = self.limiter.try_acquire() else {
            // Refuse with a typed answer rather than dropping the connection:
            // a client that is told "at capacity" can back off, where a client
            // that sees a closed pipe retries immediately and makes it worse.
            return match write_frame(
                transport,
                &ServerHandshake::Rejected(HandshakeReject::AtCapacity),
                MAX_HANDSHAKE_FRAME,
            ) {
                Ok(()) => ConnectionOutcome::Refused(HandshakeReject::AtCapacity),
                Err(e) => ConnectionOutcome::TransportFailed(e),
            };
        };

        let hello = match read_frame_bytes(transport, MAX_HANDSHAKE_FRAME) {
            Ok(body) => match decode_hello(&body) {
                Ok(hello) => hello,
                Err(reason) => return self.refuse(transport, reason),
            },
            Err(e) => return ConnectionOutcome::TransportFailed(e),
        };

        // Version 3 is an explicit, VPN-only connection. Never reinterpret a
        // malformed VPN frame as a legacy boundary command (or vice versa).
        let vpn_connection = hello.min_protocol_version == crate::vpn::protocol::PROTOCOL_VERSION
            && hello.max_protocol_version == crate::vpn::protocol::PROTOCOL_VERSION
            && hello.magic == PRIV_HANDSHAKE_MAGIC;
        if vpn_connection && (hello.adopt_lease.is_some() || hello.lease_kind != LeaseKind::Session)
        {
            return self.refuse(
                transport,
                HandshakeReject::Malformed("VPN connections cannot adopt boundary claims".into()),
            );
        }
        let negotiation = if vpn_connection {
            Ok(crate::vpn::protocol::PROTOCOL_VERSION)
        } else {
            negotiate(&hello)
        };
        let version = match negotiation {
            Ok(v) => v,
            Err(reason) => return self.refuse(transport, reason),
        };

        let lease = match hello.adopt_lease {
            None => lease_ids.next(),
            Some(id) => {
                // Adopting is how an operator releases in session B a claim they
                // took in session A. It is refused unless the claim is actually
                // held and is actually durable — adopting a session claim would
                // let one connection take over another's live, connection-bound
                // claim, and adopting a claim that does not exist would silently
                // mint a new one under an id the client chose — **and** unless
                // this connecting peer clears the same `ControlVerb::
                // ReleaseKillSwitch` check an explicit release would require:
                // see `Broker::adopt_lease` for why taking over a claim you
                // could then let lapse is exactly as privileged as releasing it
                // directly, and must clear the same bar.
                match self.broker.adopt_lease(peer, id) {
                    Ok(id) => id,
                    Err(LeaseAdoptError::NotPinned(kind)) => {
                        return self.refuse(
                            transport,
                            HandshakeReject::LeaseUnavailable(format!(
                                "lease {} is {} and only a pinned claim may be adopted",
                                id.to_hex(),
                                kind.as_str()
                            )),
                        )
                    }
                    Err(LeaseAdoptError::NoSuchLease) => {
                        return self.refuse(
                            transport,
                            HandshakeReject::LeaseUnavailable(format!(
                                "no claim {} is held",
                                id.to_hex()
                            )),
                        )
                    }
                    Err(LeaseAdoptError::Unauthorized(denied)) => {
                        return self
                            .refuse(transport, HandshakeReject::PeerRefused(denied.to_string()))
                    }
                }
            }
        };

        let accepted = ServerHandshake::Accepted(ServerHello {
            magic: PRIV_HANDSHAKE_MAGIC,
            protocol_version: version,
            session_token: self.broker.session_token(),
            lease,
            state_version: if vpn_connection {
                0
            } else {
                self.broker.status().state_version
            },
        });
        if let Err(e) = write_frame(transport, &accepted, MAX_HANDSHAKE_FRAME) {
            return ConnectionOutcome::TransportFailed(e);
        }

        let mut frames = 0u64;
        loop {
            let frame_limit = if vpn_connection {
                crate::vpn::protocol::MAX_FRAME
            } else {
                MAX_PRIV_FRAME
            };
            let body = match read_frame_bytes(transport, frame_limit) {
                Ok(body) => body,
                Err(FrameError::Transport(crate::framing::TransportError::Closed)) => break,
                Err(e) => return ConnectionOutcome::TransportFailed(e),
            };
            if vpn_connection {
                use crate::vpn::{Reject, Response};
                let response = match crate::vpn::protocol::decode(&body) {
                    Err(reason) => Response::Rejected(reason),
                    Ok(request) => match self.vpn {
                        Some(vpn) => vpn.handle(peer, request),
                        None => Response::Rejected(Reject::Unavailable),
                    },
                };
                frames += 1;
                if let Err(e) = write_frame(transport, &response, frame_limit) {
                    return ConnectionOutcome::TransportFailed(e);
                }
                continue;
            }
            let response = match decode_envelope(&body) {
                // A malformed *body* is answerable: the peer gets a typed
                // rejection and the channel stays synchronised, because the
                // frame boundary came from the length prefix and not from the
                // body's contents.
                Err(reason) => BrokerResponse::Rejected(reason),
                Ok(envelope) => {
                    self.broker
                        .handle_from_peer(peer, lease, hello.lease_kind, envelope)
                }
            };
            frames += 1;
            if let Err(e) = write_frame(transport, &response, MAX_PRIV_FRAME) {
                return ConnectionOutcome::TransportFailed(e);
            }
        }

        if vpn_connection {
            return ConnectionOutcome::Served {
                frames,
                lease,
                lease_kind: LeaseKind::Session,
                claim_dropped: false,
            };
        }
        // The connection ended. A session claim dies with it — that is what
        // makes the refcount unable to leak — and a pinned claim deliberately
        // does not.
        //
        // **This must be decided from the claim's own recorded, immutable
        // kind — never from this connection's self-declared
        // `hello.lease_kind`.** Trusting the hello field here was the P3→P4
        // defect: a connection that adopted someone else's `Pinned` claim
        // could declare `lease_kind: Session` on its *own* hello, send zero
        // commands, disconnect, and have that claim dropped — restoring
        // egress — with no authorization check anywhere in the path, because
        // this decision never went through `handle_from_peer`. Adoption is now
        // gated (`Broker::adopt_lease`) and a claim's `kind` never changes
        // after mint, so reading the real, current kind is both the correct
        // fix and never observes anything a legitimate, non-adopting
        // connection's own `hello.lease_kind` would not already have said —
        // that lease exists (if at all) with exactly the kind this connection
        // itself minted it as.
        let recorded_kind = self
            .broker
            .leases()
            .into_iter()
            .find(|l| l.id == lease)
            .map(|l| l.kind);
        let claim_dropped = match recorded_kind {
            // No claim was ever taken on this connection (it never engaged,
            // or already released it itself) — nothing to drop.
            None => false,
            Some(kind) if kind.survives_restart() => false,
            Some(_) => {
                // A failure here is not returned: the connection is already gone
                // and there is nobody to tell. It is not swallowed either — the
                // claim stays in the set, so the switch keeps naming a holder
                // for enforcement that is still in place, and the next
                // `reconcile_startup` will discard it as a dead session claim.
                self.broker.close_lease(&lease).is_ok()
            }
        };

        ConnectionOutcome::Served {
            frames,
            lease,
            lease_kind: recorded_kind.unwrap_or(hello.lease_kind),
            claim_dropped,
        }
    }

    fn refuse(
        &self,
        transport: &mut dyn FrameTransport,
        reason: HandshakeReject,
    ) -> ConnectionOutcome {
        match write_frame(
            transport,
            &ServerHandshake::Rejected(reason.clone()),
            MAX_HANDSHAKE_FRAME,
        ) {
            Ok(()) => ConnectionOutcome::Refused(reason),
            Err(e) => ConnectionOutcome::TransportFailed(e),
        }
    }
}
