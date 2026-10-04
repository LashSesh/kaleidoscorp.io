//! Length-prefixed framing for the **privileged** command channel, and the
//! transport seam it runs over (roadmap P3).
//!
//! Wire shape: `[u32 big-endian body length][strict-CBOR body]` — the same
//! discipline `ssk_ipc::framing` already proved, restated here synchronously
//! because this crate is the portable, synchronous security core and must not
//! grow an async runtime dependency to serve a request-response protocol.
//!
//! # The two frame caps are independent
//!
//! [`crate::MAX_PRIV_FRAME`] and `ssk_ipc::framing::MAX_REQUEST_FRAME_LEN`
//! happen to be the same 64 KiB. They are caps on **independent transports**,
//! neither derives from the other, and neither bounds the other. P2 already
//! corrected a comment that claimed otherwise; do not reintroduce the coupling
//! by expressing one in terms of the other.
//!
//! [`MAX_HANDSHAKE_FRAME`] is a third, tighter cap for the one frame that is
//! read **before** anything about the peer's intent is known. It is separate for
//! the same reason: a cap chosen for command envelopes is not a cap anyone
//! chose for a hello.
//!
//! # What "bounded pre-auth allocation" means here, precisely
//!
//! Two distinct bounds, because they fail differently:
//!
//! 1. The declared length is compared against the cap **before a single body
//!    byte is read or allocated**, so a 4 GiB prefix costs four bytes.
//! 2. The body is then read incrementally in [`PRIV_READ_CHUNK_LEN`] pieces, so
//!    a peer that declares a legal-but-large length and then stalls costs
//!    `bytes_actually_delivered + PRIV_READ_CHUNK_LEN`, not the declared length.
//!
//! Without (2), (1) alone still lets an unauthenticated peer make a SYSTEM
//! process reserve the full cap per connection, multiplied by
//! [`MAX_PRIV_CONNECTIONS`].
//!
//! # The transport itself is not here
//!
//! [`FrameTransport`] is a byte-stream seam with no notion of pipes, sockets or
//! handles. The real Windows named-pipe I/O — `CreateNamedPipeW`,
//! `FILE_FLAG_FIRST_PIPE_INSTANCE`, the SDDL, `ImpersonateNamedPipeClient` —
//! belongs in `ssk-winhost`, the one crate exempt from the workspace's
//! `unsafe_code = "forbid"`. This crate stays `#![forbid(unsafe_code)]` and
//! therefore stays fully testable on any machine.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Bytes of length prefix in front of every frame.
pub const PRIV_FRAME_HEADER_LEN: usize = 4;

/// Granularity of the incremental body read. See the module header.
pub const PRIV_READ_CHUNK_LEN: usize = 4 * 1024;

/// Cap on the handshake frame, which is read before the peer has proved
/// anything about what it wants. A [`crate::handshake::ClientHello`] is a magic
/// number, two `u16`s, an enum and an optional 16-byte id; 1 KiB is already an
/// order of magnitude more than it can occupy.
pub const MAX_HANDSHAKE_FRAME: usize = 1024;

/// How many privileged connections may be in flight at once.
///
/// The privileged pipe is a control channel for a handful of verbs, not a
/// server. The cap exists so an unauthenticated peer cannot exhaust the
/// server's pipe instances (or its per-connection buffers) simply by connecting
/// in a loop. Refusal is immediate and typed; it does not queue, because a
/// queue is the same exhaustion with extra steps.
pub const MAX_PRIV_CONNECTIONS: usize = 16;

/// How long a transport may block waiting for bytes from a peer that has
/// already connected.
///
/// A privileged verb is answered in microseconds; a peer that has not finished
/// sending its frame after this long is either broken or holding a connection
/// slot deliberately. **Enforcing it is the [`FrameTransport`] implementation's
/// obligation** — this crate cannot enforce a timeout it has no clock or I/O
/// primitive for, and pretending otherwise with a `std::thread::sleep` would be
/// a worse lie than naming the boundary. The seam makes the requirement
/// checkable: an implementation that ignores it can never produce
/// [`TransportError::TimedOut`], and
/// [`crate::server::PrivilegedServer::serve_connection`] is tested against one
/// that does.
pub const PRIV_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// What the underlying byte stream can fail with.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The peer closed cleanly with no bytes pending. Not an error condition on
    /// its own — the server treats it as end-of-connection.
    #[error("peer closed the connection")]
    Closed,
    /// The read or write exceeded [`PRIV_READ_TIMEOUT`].
    #[error("transport timed out")]
    TimedOut,
    /// Anything else the OS reported.
    #[error("transport io error: {0}")]
    Io(String),
}

/// A synchronous, framed byte stream. One connection.
///
/// Deliberately minimal: `read` and `write_all`. Everything above it — framing,
/// handshake, dispatch — is pure Rust in this crate, so the un-runnable part of
/// P3 is confined to whatever implements these two methods.
pub trait FrameTransport {
    /// Read up to `buf.len()` bytes. `Ok(0)` means the peer closed.
    ///
    /// # Errors
    /// [`TransportError`].
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;

    /// Write every byte.
    ///
    /// # Errors
    /// [`TransportError`].
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Flush any buffering. The default does nothing.
    ///
    /// # Errors
    /// [`TransportError`].
    fn flush(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Why a frame could not be read or written.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The underlying stream failed.
    #[error("{0}")]
    Transport(#[from] TransportError),
    /// The declared body length exceeded the cap. Detected before any body byte
    /// is read.
    #[error("declared frame length {declared} exceeds the {cap}-byte cap")]
    TooLarge { declared: u64, cap: usize },
    /// The peer closed part-way through a body it had already declared.
    #[error("peer closed after {read} of {declared} declared body bytes")]
    Truncated { read: usize, declared: usize },
    /// The body was not exactly one well-formed CBOR value of the expected
    /// shape.
    #[error("malformed frame body: {0}")]
    Malformed(String),
}

impl FrameError {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            FrameError::Transport(TransportError::Closed) => "PRIV_PEER_CLOSED",
            FrameError::Transport(TransportError::TimedOut) => "PRIV_READ_TIMEOUT",
            FrameError::Transport(TransportError::Io(_)) => "PRIV_IO_FAILED",
            FrameError::TooLarge { .. } => "PRIV_FRAME_TOO_LARGE",
            FrameError::Truncated { .. } => "PRIV_FRAME_TRUNCATED",
            FrameError::Malformed(_) => "PRIV_FRAME_MALFORMED",
        }
    }

    /// Whether the connection must be torn down rather than answered.
    ///
    /// A malformed *body* is answerable — the peer gets a typed rejection and
    /// the channel stays usable. A bad *length prefix* is not: the stream is
    /// desynchronised and every subsequent byte would be misread, so continuing
    /// would let a peer smuggle a frame boundary of its own choosing.
    #[must_use]
    pub fn is_fatal_to_the_connection(&self) -> bool {
        match self {
            FrameError::Malformed(_) => false,
            FrameError::Transport(_)
            | FrameError::TooLarge { .. }
            | FrameError::Truncated { .. } => true,
        }
    }
}

/// Serialize `value` to strict CBOR and write it as one length-prefixed frame.
///
/// # Errors
/// [`FrameError::Malformed`] if the value cannot be encoded (never expected for
/// the fixed-shape protocol types), [`FrameError::TooLarge`] if the encoding
/// exceeds `cap`, or a transport failure.
pub fn write_frame<T: serde::Serialize>(
    transport: &mut dyn FrameTransport,
    value: &T,
    cap: usize,
) -> Result<(), FrameError> {
    let mut body = Vec::new();
    ciborium::ser::into_writer(value, &mut body)
        .map_err(|e| FrameError::Malformed(e.to_string()))?;
    if body.len() > cap {
        return Err(FrameError::TooLarge {
            declared: body.len() as u64,
            cap,
        });
    }
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        declared: body.len() as u64,
        cap,
    })?;
    transport.write_all(&len.to_be_bytes())?;
    transport.write_all(&body)?;
    transport.flush()?;
    Ok(())
}

/// Read one length-prefixed frame and decode it strictly.
///
/// "Strictly" means the same three things [`crate::decode_envelope`] means:
/// the length is refused before any allocation, unknown fields are rejected by
/// the DTOs' own `deny_unknown_fields`, and **trailing bytes after the CBOR
/// value are rejected** — a security command must be exactly one value, nothing
/// appended.
///
/// # Errors
/// [`FrameError`].
pub fn read_frame<T: serde::de::DeserializeOwned>(
    transport: &mut dyn FrameTransport,
    cap: usize,
) -> Result<T, FrameError> {
    let body = read_frame_bytes(transport, cap)?;
    decode_strict(&body)
}

/// The raw-bytes half of [`read_frame`], for the command path where the body is
/// handed to [`crate::decode_envelope`] (which owns its own strictness rules and
/// its own typed rejection).
///
/// # Errors
/// [`FrameError`].
pub fn read_frame_bytes(
    transport: &mut dyn FrameTransport,
    cap: usize,
) -> Result<Vec<u8>, FrameError> {
    let mut header = [0u8; PRIV_FRAME_HEADER_LEN];
    read_exact(transport, &mut header)?;
    let declared = u32::from_be_bytes(header) as usize;
    // (1) The cap check happens here, before a single body byte is read or a
    //     single byte of body buffer is allocated.
    if declared > cap {
        return Err(FrameError::TooLarge {
            declared: declared as u64,
            cap,
        });
    }
    if declared == 0 {
        return Ok(Vec::new());
    }
    // (2) Grow as bytes actually arrive. `Vec::new()` and a chunk bounded by
    //     PRIV_READ_CHUNK_LEN, never `vec![0; declared]`.
    let mut body: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; PRIV_READ_CHUNK_LEN.min(declared)];
    while body.len() < declared {
        let want = (declared - body.len()).min(chunk.len());
        let read = transport.read(&mut chunk[..want])?;
        if read == 0 {
            return Err(FrameError::Truncated {
                read: body.len(),
                declared,
            });
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

/// Decode exactly one CBOR value from `bytes`, refusing anything appended.
///
/// # Errors
/// [`FrameError::Malformed`].
pub fn decode_strict<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, FrameError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: T =
        ciborium::de::from_reader(&mut cursor).map_err(|e| FrameError::Malformed(e.to_string()))?;
    if usize::try_from(cursor.position()).unwrap_or(usize::MAX) != bytes.len() {
        return Err(FrameError::Malformed(
            "trailing bytes after the CBOR value".to_owned(),
        ));
    }
    Ok(value)
}

fn read_exact(transport: &mut dyn FrameTransport, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let read = transport.read(&mut buf[filled..])?;
        if read == 0 {
            if filled == 0 {
                return Err(FrameError::Transport(TransportError::Closed));
            }
            return Err(FrameError::Truncated {
                read: filled,
                declared: buf.len(),
            });
        }
        filled += read;
    }
    Ok(())
}

/// Bounds how many privileged connections exist at once.
///
/// Cloneable and shareable: one limiter is created by the composition root and
/// handed to every accept loop, so the bound is on the *process*, not on a loop.
#[derive(Clone, Debug)]
pub struct ConnectionLimiter {
    max: usize,
    active: Arc<AtomicUsize>,
}

impl ConnectionLimiter {
    #[must_use]
    pub fn new(max: usize) -> Self {
        ConnectionLimiter {
            max,
            active: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Take a slot, or `None` if the cap is reached.
    ///
    /// A compare-and-swap loop, not `fetch_add` + compare: `fetch_add` briefly
    /// records a slot it may have to give back, so two racing acceptors can each
    /// observe the other's transient increment and both refuse — or, worse, a
    /// caller that forgets the decrement leaks the cap downward permanently.
    #[must_use]
    pub fn try_acquire(&self) -> Option<ConnectionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnectionPermit {
                        active: Arc::clone(&self.active),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }

    #[must_use]
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn max(&self) -> usize {
        self.max
    }
}

impl Default for ConnectionLimiter {
    fn default() -> Self {
        ConnectionLimiter::new(MAX_PRIV_CONNECTIONS)
    }
}

/// A held connection slot. Released on drop — including on panic, which is why
/// it is an RAII guard rather than a paired release call the serve loop could
/// return past.
#[derive(Debug)]
pub struct ConnectionPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MAX_PRIV_FRAME;
    use crate::testing::{framed, FakeTransport};

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Ping {
        seq: u32,
    }

    #[test]
    fn a_frame_round_trips() {
        let mut out = FakeTransport::default();
        write_frame(&mut out, &Ping { seq: 9 }, MAX_PRIV_FRAME).unwrap();
        let mut back = FakeTransport::with_inbound(out.written.clone());
        let decoded: Ping = read_frame(&mut back, MAX_PRIV_FRAME).unwrap();
        assert_eq!(decoded, Ping { seq: 9 });
    }

    /// The pre-auth allocation bound, part 1: a hostile length prefix costs four
    /// bytes and one comparison. The body is never touched, so the transport
    /// records exactly one read.
    #[test]
    fn an_oversized_length_prefix_is_refused_before_any_body_byte() {
        let mut t = FakeTransport::with_inbound(u32::MAX.to_be_bytes().to_vec());
        let err = read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap_err();
        assert_eq!(
            err,
            FrameError::TooLarge {
                declared: u64::from(u32::MAX),
                cap: MAX_PRIV_FRAME,
            }
        );
        assert_eq!(err.code(), "PRIV_FRAME_TOO_LARGE");
        assert!(err.is_fatal_to_the_connection());
        assert_eq!(t.reads, 1, "only the 4-byte header was read");
        assert_eq!(t.read_cursor, PRIV_FRAME_HEADER_LEN);
    }

    /// The pre-auth allocation bound, part 2: a peer that declares a legal but
    /// large body and then stalls must not make the reader ask for the declared
    /// size in one go. The scratch chunk is what bounds the peak.
    #[test]
    fn a_large_declared_body_is_read_in_bounded_chunks() {
        let declared = MAX_PRIV_FRAME;
        let mut inbound = (declared as u32).to_be_bytes().to_vec();
        inbound.extend_from_slice(&[7u8; 32]); // then the peer stops talking
        let mut t = FakeTransport::with_inbound(inbound);
        let err = read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap_err();
        assert_eq!(
            err,
            FrameError::Truncated {
                read: 32,
                declared: MAX_PRIV_FRAME
            }
        );
        assert!(
            t.peak_read_request <= PRIV_READ_CHUNK_LEN,
            "a single read asked for {} bytes; the chunk cap is {PRIV_READ_CHUNK_LEN}",
            t.peak_read_request
        );
    }

    #[test]
    fn a_frame_exactly_at_the_cap_is_accepted_and_one_past_is_not() {
        let at_cap = vec![0xa1u8; MAX_PRIV_FRAME];
        let mut t = FakeTransport::with_inbound(framed(&at_cap));
        assert_eq!(
            read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap().len(),
            MAX_PRIV_FRAME
        );

        let over = vec![0xa1u8; MAX_PRIV_FRAME + 1];
        let mut t = FakeTransport::with_inbound(framed(&over));
        assert!(matches!(
            read_frame_bytes(&mut t, MAX_PRIV_FRAME),
            Err(FrameError::TooLarge { .. })
        ));
    }

    /// The handshake cap really is independent of the command cap: the same
    /// frame is accepted under one and refused under the other. Without this
    /// the two constants could drift into being the same number by accident and
    /// nobody would notice.
    #[test]
    fn the_handshake_cap_is_tighter_than_the_command_cap_and_separately_enforced() {
        const { assert!(MAX_HANDSHAKE_FRAME < MAX_PRIV_FRAME) };
        let body = vec![0u8; MAX_HANDSHAKE_FRAME + 1];

        let mut t = FakeTransport::with_inbound(framed(&body));
        assert!(matches!(
            read_frame_bytes(&mut t, MAX_HANDSHAKE_FRAME),
            Err(FrameError::TooLarge { cap, .. }) if cap == MAX_HANDSHAKE_FRAME
        ));

        let mut t = FakeTransport::with_inbound(framed(&body));
        assert!(read_frame_bytes(&mut t, MAX_PRIV_FRAME).is_ok());
    }

    #[test]
    fn a_clean_close_before_the_header_is_reported_as_closed_not_truncated() {
        let mut t = FakeTransport::default();
        assert_eq!(
            read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap_err(),
            FrameError::Transport(TransportError::Closed)
        );
    }

    #[test]
    fn a_partial_header_is_truncation_not_a_clean_close() {
        let mut t = FakeTransport::with_inbound(vec![0u8, 0u8]);
        assert_eq!(
            read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap_err(),
            FrameError::Truncated {
                read: 2,
                declared: PRIV_FRAME_HEADER_LEN
            }
        );
    }

    #[test]
    fn a_read_timeout_surfaces_as_itself_and_is_fatal() {
        let mut t = FakeTransport {
            exhausted_error: Some(TransportError::TimedOut),
            ..FakeTransport::default()
        };
        let err = read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap_err();
        assert_eq!(err.code(), "PRIV_READ_TIMEOUT");
        assert!(err.is_fatal_to_the_connection());
    }

    #[test]
    fn short_reads_are_reassembled() {
        let mut out = FakeTransport::default();
        write_frame(&mut out, &Ping { seq: 4242 }, MAX_PRIV_FRAME).unwrap();
        let mut t = FakeTransport::with_inbound(out.written.clone());
        t.read_chunk = Some(1);
        let decoded: Ping = read_frame(&mut t, MAX_PRIV_FRAME).unwrap();
        assert_eq!(decoded, Ping { seq: 4242 });
        assert!(t.reads > 4, "the fixture really did dribble bytes");
    }

    #[test]
    fn trailing_bytes_after_the_cbor_value_are_refused() {
        let mut body = Vec::new();
        ciborium::ser::into_writer(&Ping { seq: 1 }, &mut body).unwrap();
        body.push(0x00);
        let err = decode_strict::<Ping>(&body).unwrap_err();
        assert!(
            matches!(err, FrameError::Malformed(ref m) if m.contains("trailing")),
            "{err:?}"
        );
        assert!(
            !err.is_fatal_to_the_connection(),
            "a malformed body is answerable; only a bad length prefix desynchronises the stream"
        );
    }

    #[test]
    fn an_unknown_field_is_refused_by_the_dto() {
        // {"seq": 1, "extra": 2}
        let mut body = Vec::new();
        ciborium::ser::into_writer(
            &std::collections::BTreeMap::from([("seq", 1u32), ("extra", 2)]),
            &mut body,
        )
        .unwrap();
        assert!(matches!(
            decode_strict::<Ping>(&body),
            Err(FrameError::Malformed(_))
        ));
    }

    #[test]
    fn a_zero_length_body_decodes_as_malformed_rather_than_hanging() {
        let mut t = FakeTransport::with_inbound(0u32.to_be_bytes().to_vec());
        assert!(read_frame_bytes(&mut t, MAX_PRIV_FRAME).unwrap().is_empty());
        assert!(matches!(
            decode_strict::<Ping>(&[]),
            Err(FrameError::Malformed(_))
        ));
    }

    // ── the connection cap ──────────────────────────────────────────────────

    #[test]
    fn the_connection_cap_refuses_past_the_maximum_and_recovers_on_drop() {
        let limiter = ConnectionLimiter::new(2);
        let a = limiter.try_acquire().expect("first");
        let b = limiter.try_acquire().expect("second");
        assert_eq!(limiter.active(), 2);
        assert!(limiter.try_acquire().is_none(), "the third is refused");
        drop(a);
        assert_eq!(limiter.active(), 1);
        let c = limiter.try_acquire().expect("a freed slot is reusable");
        drop((b, c));
        assert_eq!(limiter.active(), 0);
    }

    #[test]
    fn the_cap_holds_under_concurrent_acceptors() {
        let limiter = ConnectionLimiter::new(4);
        let peak = Arc::new(AtomicUsize::new(0));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let limiter = limiter.clone();
                let peak = Arc::clone(&peak);
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        if let Some(permit) = limiter.try_acquire() {
                            peak.fetch_max(limiter.active(), Ordering::AcqRel);
                            drop(permit);
                        }
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(limiter.active(), 0, "every permit was returned");
        assert!(
            peak.load(Ordering::Acquire) <= 4,
            "observed {} concurrent slots against a cap of 4",
            peak.load(Ordering::Acquire)
        );
    }

    #[test]
    fn a_permit_is_returned_even_when_the_holder_panics() {
        let limiter = ConnectionLimiter::new(1);
        let l = limiter.clone();
        let result = std::thread::spawn(move || {
            let _permit = l.try_acquire().expect("slot");
            panic!("the serve loop died");
        })
        .join();
        assert!(result.is_err(), "the fixture really did panic");
        assert_eq!(
            limiter.active(),
            0,
            "an RAII permit must survive a panicking serve loop"
        );
    }

    #[test]
    fn the_default_limiter_uses_the_published_cap() {
        assert_eq!(ConnectionLimiter::default().max(), MAX_PRIV_CONNECTIONS);
    }
}
