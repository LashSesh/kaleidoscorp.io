//! The SOCKS5 server side (design 6.3): version negotiation, the CONNECT
//! request, and the replies. Nothing here decides anything; it turns bytes into
//! a [`RawTarget`] and back into reply bytes.
//!
//! * **Exact-length reads, no `BufReader`.** Only the bytes of the handshake
//!   are consumed. A client may send payload right behind its request; it stays
//!   in the kernel buffer and is pumped after admission. That payload belongs to
//!   the client and is delivered only once the flow is admitted, so it is not
//!   smuggling, but a buffered reader would swallow some of it.
//! * **Silent close for anything that is not SOCKS5.** A TLS ClientHello
//!   (`0x16`), `GET`, SOCKS4 (`0x04`): zero bytes written, so that a browser or
//!   a scanner pointed at the port learns nothing and cannot use it as an echo.
//! * **No semantic checks.** The address bytes are passed on untouched
//!   (a domain is `RawTarget::Name(bytes, port)`); what they mean, and whether a
//!   port of 0 or an empty domain is acceptable, is decided in one place,
//!   `target::canonicalize`, which answers with `Malformed` (SOCKS reply `08`).
//! * **The success reply needs a proof.** [`write_success`] takes a
//!   [`ResultProof`], which only the durable `ResultReceipt` of the audit
//!   ledger implements: no application byte, and no "connected", before the
//!   result is durable.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::target::RawTarget;
use super::types::ResultProof;

const VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Why a connection is closed without a single byte written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// The first byte of the greeting or of the request is not `0x05`.
    NotSocks5,
    /// `NMETHODS` is 0: not a SOCKS5 greeting.
    NoMethods,
    /// The reserved byte of the request is not 0.
    ReservedSet,
}

/// A refusal the client is told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// No offered method is `0x00` (no authentication). [`negotiate`] has
    /// already written `05 FF`; there is nothing left to send.
    NoAcceptableMethod,
    /// The command is not CONNECT (BIND, UDP ASSOCIATE, anything else).
    CommandNotSupported,
    /// The address type is not 1, 3 or 4.
    AddressTypeNotSupported,
}

impl Reject {
    /// The reply the CALLER still has to write with [`write_refusal`]. `None`
    /// when the reply has been written already.
    #[must_use]
    pub const fn rep(self) -> Option<Rep> {
        match self {
            Self::NoAcceptableMethod => None,
            Self::CommandNotSupported => Some(Rep::CommandNotSupported),
            Self::AddressTypeNotSupported => Some(Rep::AddressTypeNotSupported),
        }
    }
}

/// How a handshake ends when it does not produce a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Close silently.
    Violation(Violation),
    /// Close after the refusal described by the [`Reject`].
    Reject(Reject),
    /// The peer went away or the socket failed. Close silently.
    Io,
    /// The handshake did not complete in time. Close silently.
    Timeout,
}

/// The refusal codes of RFC 1928 section 6 that this proxy sends. `Succeeded`
/// is not among them: success has its own function and its own proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rep {
    GeneralFailure,
    NotAllowed,
    NetUnreachable,
    HostUnreachable,
    ConnectionRefused,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl Rep {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::GeneralFailure => 0x01,
            Self::NotAllowed => 0x02,
            Self::NetUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefused => 0x05,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

/// `05 | n | n methods`; requires `0x00` among them and answers `05 00`, or
/// `05 FF` when it is not offered.
pub async fn negotiate<S>(stream: &mut S) -> Result<(), Fault>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0_u8; 2];
    stream.read_exact(&mut head).await.map_err(|_| Fault::Io)?;
    let [version, count] = head;
    if version != VERSION {
        return Err(Fault::Violation(Violation::NotSocks5));
    }
    if count == 0 {
        return Err(Fault::Violation(Violation::NoMethods));
    }
    let mut methods = [0_u8; 255];
    let offered = methods
        .get_mut(..usize::from(count))
        .ok_or(Fault::Violation(Violation::NoMethods))?;
    stream.read_exact(offered).await.map_err(|_| Fault::Io)?;
    if offered.contains(&METHOD_NO_AUTH) {
        stream
            .write_all(&[VERSION, METHOD_NO_AUTH])
            .await
            .map_err(|_| Fault::Io)?;
        stream.flush().await.map_err(|_| Fault::Io)?;
        Ok(())
    } else {
        // The refusal is best effort: the connection ends either way.
        let _ = stream.write_all(&[VERSION, METHOD_NONE_ACCEPTABLE]).await;
        let _ = stream.flush().await;
        Err(Fault::Reject(Reject::NoAcceptableMethod))
    }
}

/// `05 01 00 ATYP ADDR PORT`, at most 4 + 1 + 255 + 2 bytes. Reads exactly the
/// request and nothing behind it.
pub async fn read_connect<S>(stream: &mut S) -> Result<RawTarget, Fault>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await.map_err(|_| Fault::Io)?;
    let [version, command, reserved, atyp] = head;
    if version != VERSION {
        return Err(Fault::Violation(Violation::NotSocks5));
    }
    if reserved != 0 {
        return Err(Fault::Violation(Violation::ReservedSet));
    }
    if command != CMD_CONNECT {
        return Err(Fault::Reject(Reject::CommandNotSupported));
    }
    match atyp {
        ATYP_IPV4 => {
            let mut tail = [0_u8; 6];
            stream.read_exact(&mut tail).await.map_err(|_| Fault::Io)?;
            let [a, b, c, d, hi, lo] = tail;
            Ok(RawTarget::V4(
                std::net::Ipv4Addr::new(a, b, c, d),
                u16::from_be_bytes([hi, lo]),
            ))
        }
        ATYP_IPV6 => {
            let mut tail = [0_u8; 18];
            stream.read_exact(&mut tail).await.map_err(|_| Fault::Io)?;
            let (address, port) = tail.split_at(16);
            let address: [u8; 16] = address.try_into().map_err(|_| Fault::Io)?;
            let port: [u8; 2] = port.try_into().map_err(|_| Fault::Io)?;
            Ok(RawTarget::V6(
                std::net::Ipv6Addr::from(address),
                u16::from_be_bytes(port),
            ))
        }
        ATYP_DOMAIN => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .await
                .map_err(|_| Fault::Io)?;
            let [length] = length;
            let mut name = vec![0_u8; usize::from(length)];
            stream.read_exact(&mut name).await.map_err(|_| Fault::Io)?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await.map_err(|_| Fault::Io)?;
            Ok(RawTarget::Name(name, u16::from_be_bytes(port)))
        }
        _ => Err(Fault::Reject(Reject::AddressTypeNotSupported)),
    }
}

/// Greeting and request under one deadline: the whole handshake of a socket
/// that holds a pre-admission slot and nothing else. A client that trickles
/// one byte per second is cut off at `limit` like one that sends nothing.
pub async fn handshake<S>(stream: &mut S, limit: Duration) -> Result<RawTarget, Fault>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let run = async {
        negotiate(stream).await?;
        read_connect(stream).await
    };
    tokio::time::timeout(limit, run)
        .await
        .unwrap_or(Err(Fault::Timeout))
}

/// `05 REP 00 01 0.0.0.0 0`: a refusal. The bound address is zeroed; the proxy
/// does not say which local address its upstream socket has.
pub async fn write_refusal<S>(stream: &mut S, rep: Rep) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_reply(stream, rep.code()).await
}

/// `05 00 00 01 0.0.0.0 0`: success. The proof is what makes this callable only
/// after the result of the dial is durable in the ledger.
pub async fn write_success<S, P>(stream: &mut S, _proof: &P) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
    P: ResultProof,
{
    write_reply(stream, 0x00).await
}

async fn write_reply<S>(stream: &mut S, code: u8) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[VERSION, code, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::types::sealed;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::io::{duplex, join};

    /// A stand-in for the `ResultReceipt` that does not exist yet.
    struct Proof;
    impl sealed::Sealed for Proof {}
    impl ResultProof for Proof {}

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    /// Runs `f` against a stream that reads `input` and records what is written.
    /// Returns the result, what the server wrote and the input left unread.
    fn drive<T, F>(input: &[u8], f: F) -> (T, Vec<u8>, usize)
    where
        F: for<'a> FnOnce(
            &'a mut tokio::io::Join<&[u8], Vec<u8>>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = T> + 'a>>,
    {
        runtime().block_on(async {
            let mut stream = join(input, Vec::new());
            let out = f(&mut stream).await;
            let (rest, written) = stream.into_inner();
            (out, written, rest.len())
        })
    }

    fn negotiate_bytes(input: &[u8]) -> (Result<(), Fault>, Vec<u8>, usize) {
        drive(input, |s| Box::pin(negotiate(s)))
    }

    fn connect_bytes(input: &[u8]) -> (Result<RawTarget, Fault>, Vec<u8>, usize) {
        drive(input, |s| Box::pin(read_connect(s)))
    }

    fn request(cmd: u8, atyp: u8, rest: &[u8]) -> Vec<u8> {
        let mut out = vec![0x05, cmd, 0x00, atyp];
        out.extend_from_slice(rest);
        out
    }

    fn domain_request(name: &[u8], port: u16) -> Vec<u8> {
        let mut rest = vec![u8::try_from(name.len()).expect("a domain field is at most 255")];
        rest.extend_from_slice(name);
        rest.extend_from_slice(&port.to_be_bytes());
        request(0x01, 0x03, &rest)
    }

    // -- greeting -----------------------------------------------------------

    #[test]
    fn a_greeting_offering_no_authentication_is_answered_05_00() {
        for greeting in [
            vec![0x05, 0x01, 0x00],
            vec![0x05, 0x03, 0x02, 0x00, 0x01],
            vec![0x05, 0x02, 0x00, 0x00],
            vec![0x05, 0x02, 0x80, 0x00],
        ] {
            let (result, written, unread) = negotiate_bytes(&greeting);
            assert_eq!(result, Ok(()), "{greeting:?}");
            assert_eq!(written, [0x05, 0x00]);
            assert_eq!(unread, 0);
        }
    }

    #[test]
    fn a_greeting_of_the_longest_method_list_is_read_in_full() {
        let mut greeting = vec![0x05, 0xff];
        greeting.extend(std::iter::repeat_n(0x02, 254));
        greeting.push(0x00);
        let (result, written, unread) = negotiate_bytes(&greeting);
        assert_eq!(result, Ok(()));
        assert_eq!(written, [0x05, 0x00]);
        assert_eq!(unread, 0);
    }

    #[test]
    fn a_greeting_without_the_no_auth_method_is_answered_05_ff() {
        for greeting in [
            vec![0x05, 0x01, 0x02],
            vec![0x05, 0x02, 0x01, 0x02],
            vec![0x05, 0x01, 0xff],
        ] {
            let (result, written, _) = negotiate_bytes(&greeting);
            assert_eq!(result, Err(Fault::Reject(Reject::NoAcceptableMethod)));
            assert_eq!(written, [0x05, 0xff], "{greeting:?}");
        }
        assert_eq!(Reject::NoAcceptableMethod.rep(), None);
    }

    #[test]
    fn anything_that_is_not_socks5_is_closed_without_a_byte() {
        let samples: [(&[u8], Violation); 6] = [
            (&[0x16, 0x03, 0x01, 0x02, 0x00], Violation::NotSocks5), // TLS ClientHello
            (b"GET / HTTP/1.1\r\n", Violation::NotSocks5),
            (
                &[0x04, 0x01, 0x00, 0x50, 1, 2, 3, 4, 0],
                Violation::NotSocks5,
            ), // SOCKS4
            (
                b"CONNECT example.com:443 HTTP/1.1\r\n",
                Violation::NotSocks5,
            ),
            (&[0x00, 0x01, 0x00], Violation::NotSocks5),
            (&[0x05, 0x00], Violation::NoMethods),
        ];
        for (bytes, violation) in samples {
            let (result, written, _) = negotiate_bytes(bytes);
            assert_eq!(result, Err(Fault::Violation(violation)), "{bytes:?}");
            assert!(written.is_empty(), "{bytes:?} got a reply: {written:?}");
        }
    }

    #[test]
    fn a_greeting_cut_short_anywhere_is_an_io_fault_with_nothing_written() {
        let greeting = [0x05, 0x03, 0x02, 0x01, 0x00];
        for cut in 0..greeting.len() {
            let (result, written, _) = negotiate_bytes(&greeting[..cut]);
            assert_eq!(result, Err(Fault::Io), "cut at {cut}");
            assert!(written.is_empty(), "cut at {cut}");
        }
    }

    // -- request ------------------------------------------------------------

    #[test]
    fn connect_requests_become_raw_targets_untouched() {
        let cases = [
            (
                request(0x01, 0x01, &[127, 0, 0, 1, 0x1f, 0x90]),
                RawTarget::V4(Ipv4Addr::LOCALHOST, 8080),
            ),
            (
                request(0x01, 0x01, &[0, 0, 0, 0, 0x00, 0x00]),
                RawTarget::V4(Ipv4Addr::UNSPECIFIED, 0),
            ),
            (
                request(
                    0x01,
                    0x04,
                    &[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0xbb,
                    ],
                ),
                RawTarget::V6("2001:db8::1".parse::<Ipv6Addr>().expect("addr"), 443),
            ),
            (
                domain_request(b"Example.COM", 443),
                RawTarget::Name(b"Example.COM".to_vec(), 443),
            ),
            // The parser does not look inside a domain: bytes, an empty name and
            // port 0 all reach canonicalize, which refuses them in one place.
            (
                domain_request(b"b\xc3\xbccher.example\x00 ", 80),
                RawTarget::Name(b"b\xc3\xbccher.example\x00 ".to_vec(), 80),
            ),
            (domain_request(b"", 80), RawTarget::Name(Vec::new(), 80)),
            (
                domain_request(b"example.com", 0),
                RawTarget::Name(b"example.com".to_vec(), 0),
            ),
            (
                domain_request(&[b'a'; 255], 65535),
                RawTarget::Name(vec![b'a'; 255], 65535),
            ),
        ];
        for (bytes, expected) in cases {
            let (result, written, unread) = connect_bytes(&bytes);
            assert_eq!(result, Ok(expected), "{bytes:?}");
            assert!(written.is_empty(), "read_connect never writes");
            assert_eq!(unread, 0);
        }
    }

    #[test]
    fn only_the_request_is_consumed_and_early_payload_stays_unread() {
        for (bytes, trailing) in [
            (request(0x01, 0x01, &[10, 0, 0, 1, 0, 80]), 17),
            (domain_request(b"example.com", 443), 1),
            (request(0x01, 0x04, &[0; 18]), 4096),
        ] {
            let mut input = bytes.clone();
            input.extend(std::iter::repeat_n(0xee, trailing));
            let (result, _, unread) = connect_bytes(&input);
            assert!(result.is_ok());
            assert_eq!(unread, trailing, "{} trailing bytes", trailing);
        }
    }

    #[test]
    fn a_request_is_complete_without_waiting_for_more_input() {
        // The client sends its request and then waits for the reply: reading
        // "a buffer's worth" would hang here.
        let outcome = runtime().block_on(async {
            let (mut server, mut client) = duplex(64);
            client
                .write_all(&domain_request(b"example.com", 443))
                .await
                .expect("write");
            tokio::time::timeout(Duration::from_secs(5), read_connect(&mut server)).await
        });
        assert_eq!(
            outcome.expect("did not hang"),
            Ok(RawTarget::Name(b"example.com".to_vec(), 443))
        );
    }

    #[test]
    fn a_request_for_another_command_or_address_type_is_refused_with_a_reply_code() {
        for cmd in [0x02, 0x03, 0x00, 0x04, 0xff] {
            let (result, written, _) = connect_bytes(&request(cmd, 0x01, &[1, 2, 3, 4, 0, 80]));
            assert_eq!(result, Err(Fault::Reject(Reject::CommandNotSupported)));
            assert!(written.is_empty());
        }
        for atyp in [0x00, 0x02, 0x05, 0x7f, 0xff] {
            let (result, written, _) = connect_bytes(&request(0x01, atyp, &[1, 2, 3, 4, 0, 80]));
            assert_eq!(result, Err(Fault::Reject(Reject::AddressTypeNotSupported)));
            assert!(written.is_empty());
        }
        assert_eq!(
            Reject::CommandNotSupported.rep(),
            Some(Rep::CommandNotSupported)
        );
        assert_eq!(
            Reject::AddressTypeNotSupported.rep(),
            Some(Rep::AddressTypeNotSupported)
        );
    }

    #[test]
    fn a_wrong_version_or_a_reserved_byte_closes_silently() {
        let mut wrong_version = request(0x01, 0x01, &[1, 2, 3, 4, 0, 80]);
        wrong_version[0] = 0x04;
        let (result, written, _) = connect_bytes(&wrong_version);
        assert_eq!(result, Err(Fault::Violation(Violation::NotSocks5)));
        assert!(written.is_empty());

        let mut reserved = request(0x01, 0x01, &[1, 2, 3, 4, 0, 80]);
        reserved[2] = 0x01;
        let (result, written, _) = connect_bytes(&reserved);
        assert_eq!(result, Err(Fault::Violation(Violation::ReservedSet)));
        assert!(written.is_empty());
    }

    #[test]
    fn a_request_cut_short_anywhere_is_an_io_fault() {
        for bytes in [
            request(0x01, 0x01, &[127, 0, 0, 1, 0x1f, 0x90]),
            request(0x01, 0x04, &[0; 18]),
            domain_request(b"example.com", 443),
        ] {
            for cut in 0..bytes.len() {
                let (result, written, _) = connect_bytes(&bytes[..cut]);
                assert_eq!(result, Err(Fault::Io), "cut at {cut} of {}", bytes.len());
                assert!(written.is_empty());
            }
        }
    }

    // -- replies ------------------------------------------------------------

    #[test]
    fn refusals_are_ten_bytes_with_the_rfc_code() {
        let table = [
            (Rep::GeneralFailure, 0x01),
            (Rep::NotAllowed, 0x02),
            (Rep::NetUnreachable, 0x03),
            (Rep::HostUnreachable, 0x04),
            (Rep::ConnectionRefused, 0x05),
            (Rep::CommandNotSupported, 0x07),
            (Rep::AddressTypeNotSupported, 0x08),
        ];
        for (rep, code) in table {
            let (result, written, _) = drive(&[], |s| Box::pin(write_refusal(s, rep)));
            result.expect("write");
            assert_eq!(written, [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            assert_eq!(rep.code(), code);
        }
    }

    #[test]
    fn success_is_05_00_with_a_zeroed_bound_address() {
        let (result, written, _) = drive(&[], |s| Box::pin(write_success(s, &Proof)));
        result.expect("write");
        assert_eq!(written, [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn no_refusal_code_is_the_success_code() {
        for rep in [
            Rep::GeneralFailure,
            Rep::NotAllowed,
            Rep::NetUnreachable,
            Rep::HostUnreachable,
            Rep::ConnectionRefused,
            Rep::CommandNotSupported,
            Rep::AddressTypeNotSupported,
        ] {
            assert_ne!(rep.code(), 0x00);
        }
    }

    /// A writer that, like a buffering layer, holds what it is given until it is
    /// flushed: `visible` is what a peer would have seen.
    #[derive(Default)]
    struct Buffering {
        pending: Vec<u8>,
        visible: Vec<u8>,
    }

    impl AsyncWrite for Buffering {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            self.pending.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let pending = std::mem::take(&mut self.pending);
            self.visible.extend_from_slice(&pending);
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn every_reply_is_flushed_not_left_in_a_buffering_layer() {
        runtime().block_on(async {
            let mut stream = join(&[0x05_u8, 0x01, 0x00][..], Buffering::default());
            negotiate(&mut stream).await.expect("negotiate");
            assert_eq!(stream.writer().visible, [0x05, 0x00], "method reply");

            let mut refusal = Buffering::default();
            write_refusal(&mut refusal, Rep::NotAllowed)
                .await
                .expect("write");
            assert_eq!(refusal.visible.len(), 10, "refusal");

            let mut success = Buffering::default();
            write_success(&mut success, &Proof).await.expect("write");
            assert_eq!(success.visible.len(), 10, "success");

            let mut none = join(&[0x05_u8, 0x01, 0x02][..], Buffering::default());
            let _ = negotiate(&mut none).await;
            assert_eq!(none.writer().visible, [0x05, 0xff], "05 ff");
        });
    }

    // -- the deadline -------------------------------------------------------

    #[test]
    fn the_handshake_returns_the_target_of_a_well_behaved_client() {
        let outcome = runtime().block_on(async {
            let (mut server, mut client) = duplex(256);
            let server_side =
                tokio::spawn(async move { handshake(&mut server, Duration::from_secs(5)).await });
            client.write_all(&[0x05, 0x01, 0x00]).await.expect("write");
            let mut method = [0_u8; 2];
            client.read_exact(&mut method).await.expect("read");
            assert_eq!(method, [0x05, 0x00]);
            client
                .write_all(&domain_request(b"example.com", 443))
                .await
                .expect("write");
            server_side.await.expect("join")
        });
        assert_eq!(outcome, Ok(RawTarget::Name(b"example.com".to_vec(), 443)));
    }

    #[test]
    fn a_silent_client_and_a_trickling_client_both_hit_the_deadline() {
        let silent = runtime().block_on(async {
            let (mut server, _client) = duplex(64);
            handshake(&mut server, Duration::from_millis(60)).await
        });
        assert_eq!(silent, Err(Fault::Timeout));

        // One byte, then nothing: still bounded by the one deadline.
        let trickle = runtime().block_on(async {
            let (mut server, mut client) = duplex(64);
            client.write_all(&[0x05]).await.expect("write");
            handshake(&mut server, Duration::from_millis(60)).await
        });
        assert_eq!(trickle, Err(Fault::Timeout));
    }

    #[test]
    fn the_deadline_covers_the_request_as_well_as_the_greeting() {
        let outcome = runtime().block_on(async {
            let (mut server, mut client) = duplex(64);
            client.write_all(&[0x05, 0x01, 0x00]).await.expect("write");
            // The greeting is complete; the request never comes.
            handshake(&mut server, Duration::from_millis(60)).await
        });
        assert_eq!(outcome, Err(Fault::Timeout));
    }

    // -- robustness ---------------------------------------------------------

    /// The request bytes a target was read from (the model for the property).
    fn encode(target: &RawTarget) -> Vec<u8> {
        match target {
            RawTarget::V4(addr, port) => {
                let mut rest = addr.octets().to_vec();
                rest.extend_from_slice(&port.to_be_bytes());
                request(0x01, 0x01, &rest)
            }
            RawTarget::V6(addr, port) => {
                let mut rest = addr.octets().to_vec();
                rest.extend_from_slice(&port.to_be_bytes());
                request(0x01, 0x04, &rest)
            }
            RawTarget::Name(name, port) => domain_request(name, *port),
        }
    }

    proptest! {
        /// A model of the greeting: whatever the bytes are, the outcome is the
        /// one RFC 1928 and the design prescribe, and nothing is read or written
        /// that should not be.
        #[test]
        fn the_greeting_does_what_the_model_says_for_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
            // Arbitrary bytes seldom start like a greeting; half the cases do.
            valid_start in any::<bool>(),
        ) {
            let mut input = bytes;
            if valid_start && !input.is_empty() {
                input[0] = 0x05;
            }
            let (result, written, unread) = negotiate_bytes(&input);
            let count = input.get(1).copied().map(usize::from);
            match result {
                Ok(()) => {
                    let count = count.expect("a greeting with a count");
                    let methods = &input[2..2 + count];
                    prop_assert_eq!(input[0], 0x05);
                    prop_assert!(count >= 1 && methods.contains(&0x00));
                    prop_assert_eq!(written, vec![0x05, 0x00]);
                    prop_assert_eq!(unread, input.len() - 2 - count);
                }
                Err(Fault::Reject(Reject::NoAcceptableMethod)) => {
                    let count = count.expect("a greeting with a count");
                    prop_assert_eq!(input[0], 0x05);
                    prop_assert!(count >= 1 && !input[2..2 + count].contains(&0x00));
                    prop_assert_eq!(written, vec![0x05, 0xff]);
                }
                Err(Fault::Violation(Violation::NotSocks5)) => {
                    prop_assert!(input[0] != 0x05);
                    prop_assert!(written.is_empty());
                }
                Err(Fault::Violation(Violation::NoMethods)) => {
                    prop_assert!(input[0] == 0x05 && count == Some(0));
                    prop_assert!(written.is_empty());
                }
                Err(Fault::Io) => {
                    // Truncated: fewer bytes than the greeting announces.
                    prop_assert!(input.len() < 2 || input.len() < 2 + count.unwrap_or(0));
                    prop_assert!(written.is_empty());
                }
                Err(other) => prop_assert!(false, "unexpected {other:?}"),
            }
        }

        /// The same for the request: an accepted request is exactly the bytes
        /// the target encodes to, and nothing behind it is touched.
        #[test]
        fn the_request_does_what_the_model_says_for_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..300),
            shape in 0_u8..4,
        ) {
            let mut input = bytes;
            // Make the interesting prefixes common: VER 5, CMD CONNECT, RSV 0.
            if input.len() >= 3 && shape != 0 {
                input[0] = 0x05;
                input[1] = 0x01;
                input[2] = 0x00;
            }
            if input.len() >= 4 && shape >= 2 {
                input[3] = [0x01, 0x03, 0x04][usize::from(shape - 2)];
            }
            let (result, written, unread) = connect_bytes(&input);
            prop_assert!(written.is_empty(), "read_connect never writes");
            match result {
                Ok(target) => {
                    let encoded = encode(&target);
                    prop_assert!(input.starts_with(&encoded));
                    prop_assert_eq!(unread, input.len() - encoded.len());
                }
                Err(Fault::Violation(Violation::NotSocks5)) => prop_assert!(input[0] != 0x05),
                Err(Fault::Violation(Violation::ReservedSet)) => {
                    prop_assert!(input[0] == 0x05 && input[2] != 0x00);
                }
                Err(Fault::Reject(Reject::CommandNotSupported)) => {
                    prop_assert!(input[0] == 0x05 && input[2] == 0x00 && input[1] != 0x01);
                }
                Err(Fault::Reject(Reject::AddressTypeNotSupported)) => {
                    prop_assert!(
                        input[0] == 0x05 && input[1] == 0x01 && input[2] == 0x00
                            && ![0x01, 0x03, 0x04].contains(&input[3])
                    );
                }
                Err(Fault::Io) => {
                    // Truncated, and only truncated: the head or the announced
                    // address did not fit.
                    let announced = match input.get(3) {
                        Some(0x01) => 6,
                        Some(0x04) => 18,
                        Some(0x03) => 1 + input.get(4).map_or(0, |n| usize::from(*n)) + 2,
                        _ => 0,
                    };
                    prop_assert!(input.len() < 4 + announced);
                }
                Err(other) => prop_assert!(false, "unexpected {other:?}"),
            }
        }

        #[test]
        fn a_well_formed_request_followed_by_noise_parses_to_the_same_target(
            name in proptest::collection::vec(any::<u8>(), 0..=255),
            port in any::<u16>(),
            noise in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut input = domain_request(&name, port);
            input.extend_from_slice(&noise);
            let (result, _, unread) = connect_bytes(&input);
            prop_assert_eq!(result, Ok(RawTarget::Name(name, port)));
            prop_assert_eq!(unread, noise.len());
        }
    }
}
