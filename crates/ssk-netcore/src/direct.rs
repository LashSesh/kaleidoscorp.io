#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::authority::{authority, unbracket};
use crate::error::NetcoreError;
use crate::resolve::{is_resolvable_name, normalise_answers, BoundedResolver};
use crate::session::{DialResolution, ResolutionMode};

/// Opens a real TCP connection to `host:port`, where `host` is an IP literal
/// (real syscalls, the baseline real network I/O the workspace previously had
/// none of anywhere).
///
/// Dials the `(host, port)` pair rather than a joined `"host:port"` string:
/// an IP literal (IPv4, or IPv6 bare or bracketed) is then used as an address
/// directly and never goes through the resolver, and `host` is never
/// re-parsed together with the port.
///
/// This is the literal path only. A host NAME handed to this function would be
/// resolved by tokio on the blocking pool with no bound and no record, so the
/// executor reaches it only through [`connect_host`], which decides first.
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream, NetcoreError> {
    let addr = authority(host, port);
    match timeout(connect_timeout, TcpStream::connect((unbracket(host), port))).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => {
            if err.kind() == std::io::ErrorKind::ConnectionRefused {
                Err(NetcoreError::ConnectionRefused(addr, err.to_string()))
            } else {
                Err(NetcoreError::Io(addr, err))
            }
        }
        Err(_) => Err(NetcoreError::Timeout(addr, connect_timeout)),
    }
}

/// Opens a real TCP connection to `host:port` for a host that is either an IP
/// literal or a DNS name, and says how it got the address.
///
/// * An IP literal takes the unchanged path of [`connect_tcp`]; no resolver is
///   involved and nothing is looked up.
/// * A name is looked up by the OS resolver exactly once, through the bounded
///   resolver (so a hung lookup cannot hold more than its permit). The dial
///   then goes to the answers themselves, one after another under one connect
///   budget, and never asks the resolver again: not for the next address, not
///   after a refusal. The address that was looked up is the address that is
///   dialled ("pinned"); the sockets are ordinary ones, with no bind and no
///   interface, so where they go is the operating system's decision.
/// * Anything else (a numeric alias such as `127.1`, text with whitespace or
///   control characters) is refused as `InvalidTarget` before any lookup.
///
/// Resolution time is not part of `connect_timeout`; the resolver has its own
/// deadline and the executor's dial deadline bounds both.
pub(crate) async fn connect_host(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    resolver: &BoundedResolver,
) -> Result<(TcpStream, DialResolution), NetcoreError> {
    let bare = unbracket(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        let stream = connect_tcp(host, port, connect_timeout).await?;
        let dialed = SocketAddr::new(ip, port);
        let resolution = DialResolution {
            mode: ResolutionMode::Literal,
            dialed: Some(dialed),
            attempted: vec![dialed],
            answers: 0,
            local_addr: stream.local_addr().ok(),
        };
        return Ok((stream, resolution));
    }
    if !is_resolvable_name(bare) {
        // The text is client-influenced and could carry line breaks into
        // logs, so it is not echoed.
        return Err(NetcoreError::InvalidTarget(
            "the host is neither an IP address nor a resolvable DNS name".into(),
        ));
    }
    let answers = normalise_answers(resolver.resolve_once(bare, port).await?);
    let (stream, dialed, attempted) =
        connect_in_order(&answers, &authority(host, port), connect_timeout).await?;
    let resolution = DialResolution {
        mode: ResolutionMode::OsResolver,
        dialed: Some(dialed),
        attempted,
        answers: u8::try_from(answers.len()).unwrap_or(u8::MAX),
        local_addr: stream.local_addr().ok(),
    };
    Ok((stream, resolution))
}

/// Connects to `addrs` one after another and keeps the first that answers. All
/// attempts share ONE budget, so a blackholed first address spends all of it
/// and later ones are never tried: the same bound the single
/// `TcpStream::connect((host, port))` had. Each attempt dials a `SocketAddr`,
/// which never touches a resolver.
async fn connect_in_order(
    addrs: &[SocketAddr],
    label: &str,
    connect_timeout: Duration,
) -> Result<(TcpStream, SocketAddr, Vec<SocketAddr>), NetcoreError> {
    let attempts = async {
        let mut attempted = Vec::with_capacity(addrs.len());
        let mut last: Option<std::io::Error> = None;
        let mut every_refusal = true;
        for addr in addrs {
            attempted.push(*addr);
            match TcpStream::connect(*addr).await {
                Ok(stream) => return Ok((stream, *addr, attempted)),
                Err(err) => {
                    every_refusal &= err.kind() == std::io::ErrorKind::ConnectionRefused;
                    last = Some(err);
                }
            }
        }
        Err((last, every_refusal))
    };
    match timeout(connect_timeout, attempts).await {
        Ok(Ok(dialed)) => Ok(dialed),
        Ok(Err((Some(err), true))) => Err(NetcoreError::ConnectionRefused(
            label.to_owned(),
            err.to_string(),
        )),
        Ok(Err((Some(err), false))) => Err(NetcoreError::Io(label.to_owned(), err)),
        // Unreachable while `resolve_once` refuses an empty answer; typed
        // anyway, so an empty list can never look like a success.
        Ok(Err((None, _))) => Err(NetcoreError::DnsResolutionFailed(
            label.to_owned(),
            "os-resolver".to_owned(),
            "no addresses".to_owned(),
        )),
        Err(_) => Err(NetcoreError::Timeout(label.to_owned(), connect_timeout)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::fakes::{addr, CountingResolver};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn connects_to_a_real_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        let stream = connect_tcp("127.0.0.1", addr.port(), Duration::from_secs(5))
            .await
            .expect("real tcp connect must succeed");
        assert_eq!(stream.peer_addr().expect("peer addr").port(), addr.port());
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn refused_when_nothing_listens() {
        // Bind then drop immediately to obtain a port that is guaranteed
        // free at the moment we connect, without racing another test.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let err = connect_tcp("127.0.0.1", port, Duration::from_secs(5))
            .await
            .expect_err("connecting to a closed port must fail");
        assert!(matches!(err, NetcoreError::ConnectionRefused(..)));
    }

    #[tokio::test]
    async fn times_out_against_a_non_routable_address() {
        // 10.255.255.1 is within a private, non-routable-from-here block;
        // used only to exercise the timeout path deterministically without
        // a live external host. If the sandbox has no route to it at all,
        // the OS may return an immediate unreachable error instead of
        // timing out — either is an honest, typed failure, so accept both.
        let err = connect_tcp("10.255.255.1", 9, Duration::from_millis(200))
            .await
            .expect_err("must not silently succeed");
        assert!(matches!(
            err,
            NetcoreError::Timeout(..) | NetcoreError::Io(..) | NetcoreError::ConnectionRefused(..)
        ));
    }

    /// What a test does when this host cannot bind `[::1]`: print why and let
    /// the caller skip, so IPv4-only machines can still run the suite. CI sets
    /// `SSK_REQUIRE_IPV6=1` (exactly) on a runner that must have IPv6, and a
    /// skip there would hide that the IPv6 dial was never exercised.
    fn ipv6_loopback_unavailable(require: Option<&str>, err: &std::io::Error) {
        assert!(
            require != Some("1"),
            "SSK_REQUIRE_IPV6=1 but this host cannot bind [::1] ({err}); the IPv6 dial cannot be exercised here"
        );
        eprintln!("SKIPPED: this host cannot bind [::1] ({err}); the IPv6 dial was not exercised");
    }

    /// `None` (with the reason printed) when this host has no IPv6 loopback,
    /// so the test skips instead of failing on IPv4-only runners.
    async fn bind_ipv6_loopback() -> Option<TcpListener> {
        match TcpListener::bind("[::1]:0").await {
            Ok(listener) => Some(listener),
            Err(err) => {
                ipv6_loopback_unavailable(std::env::var("SSK_REQUIRE_IPV6").ok().as_deref(), &err);
                None
            }
        }
    }

    #[test]
    #[should_panic(expected = "SSK_REQUIRE_IPV6=1")]
    fn a_missing_ipv6_loopback_fails_when_ci_requires_it() {
        let err = std::io::Error::from(std::io::ErrorKind::Unsupported);
        ipv6_loopback_unavailable(Some("1"), &err);
    }

    #[test]
    fn a_missing_ipv6_loopback_is_a_skip_unless_the_value_is_exactly_one() {
        // `0` is what the Windows leg sets; the others are near misses that must
        // not turn a skip into a failure by accident.
        let err = std::io::Error::from(std::io::ErrorKind::Unsupported);
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("11"),
            Some(" 1"),
        ] {
            ipv6_loopback_unavailable(value, &err);
        }
    }

    #[tokio::test]
    async fn connects_to_an_ipv6_literal_listener() {
        let Some(listener) = bind_ipv6_loopback().await else {
            return;
        };
        let port = listener.local_addr().expect("addr").port();
        let accept = tokio::spawn(async move {
            // Two dials below: bare and bracketed spelling of the same literal.
            for _ in 0..2 {
                listener.accept().await.expect("accept");
            }
        });
        for host in ["::1", "[::1]"] {
            let stream = connect_tcp(host, port, Duration::from_secs(5))
                .await
                .unwrap_or_else(|err| panic!("dialing {host:?} must succeed: {err}"));
            assert!(stream.peer_addr().expect("peer addr").is_ipv6());
        }
        accept.await.expect("join");
    }

    /// Far above how long any OS takes to answer a loopback connect; see the test.
    const RESOLVER_POOL_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

    #[test]
    fn ipv6_literal_dial_does_not_wait_for_the_resolver_pool() {
        // With the only blocking thread occupied, a dial that needs the
        // blocking resolver pool (`getaddrinfo`) cannot even start and burns
        // its WHOLE timeout. A literal needs no lookup, so it must reach the
        // socket layer at once. What the socket layer then says depends on
        // the host (connected, refused, or IPv6 unsupported); only "stuck
        // behind the resolver" is wrong, so that is all this asserts.
        //
        // The timeout is deliberately far above any socket-layer answer: Windows
        // reports a refused connect to a closed loopback port only after its SYN
        // retransmissions (about 2 s), so a short timeout would also fire for a
        // dial that is NOT stuck behind the resolver and the test could not tell
        // the two apart. Only a dial that really waits on the pool uses all of it.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("runtime");
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        runtime.block_on(async {
            let hog = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the blocking pool thread must start");
            // Concurrent, so a slow refusal costs the test one wait, not two.
            let (bare, bracketed) = tokio::join!(
                connect_tcp("::1", 9, RESOLVER_POOL_PROBE_TIMEOUT),
                connect_tcp("[::1]", 9, RESOLVER_POOL_PROBE_TIMEOUT),
            );
            for (host, result) in [("::1", bare), ("[::1]", bracketed)] {
                assert!(
                    !matches!(result, Err(NetcoreError::Timeout(..))),
                    "dialing the literal {host:?} waited on the resolver pool"
                );
            }
            let _ = release_tx.send(());
            hog.await.expect("join");
        });
    }

    /// An upper bound, far above any socket-layer answer: Windows reports a
    /// refused connect to a closed loopback port only after about 2 s, and the
    /// tests below dial several in turn under one budget. Only a dial that
    /// really hangs uses all of it.
    const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

    /// A port that refuses: bound then dropped, so nothing listens on it.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn resolver_called_exactly_once_per_dial_even_when_first_address_fails() {
        let closed = closed_port().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let first = addr(&format!("127.0.0.1:{closed}"));

        let fake = CountingResolver::answering(vec![first, open]);
        let resolver = BoundedResolver::new().with_resolver(fake.clone());
        let (stream, resolution) = connect_host("svc.test", 443, DIAL_TIMEOUT, &resolver)
            .await
            .expect("the second answer accepts");

        assert_eq!(
            fake.calls(),
            vec![("svc.test".to_owned(), 443)],
            "one lookup per dial, with the name and port of the dial"
        );
        assert_eq!(stream.peer_addr().expect("peer"), open);
        assert_eq!(resolution.mode, ResolutionMode::OsResolver);
        assert_eq!(resolution.answers, 2);
        assert_eq!(resolution.dialed, Some(open));
        assert_eq!(resolution.attempted, vec![first, open]);
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn numeric_alias_never_reaches_the_resolver() {
        // Each of these is dialled by the OS resolver as an IPv4 address. The
        // fake would answer a loopback address that is listening, so a dial
        // that reached it would succeed: only the refusal keeps them out.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let fake = CountingResolver::answering(vec![listener.local_addr().expect("addr")]);
        let resolver = BoundedResolver::new().with_resolver(fake.clone());
        for alias in [
            "2130706433",
            "127.1",
            "0x7f.1",
            "010.0.0.1",
            "0x7f000001",
            "127.0.0.1.",
            "1",
        ] {
            let err = connect_host(alias, 80, DIAL_TIMEOUT, &resolver)
                .await
                .expect_err("a numeric alias must be refused");
            assert_eq!(err.code(), "NETCORE_INVALID_TARGET", "{alias}: {err:?}");
            assert!(
                !err.to_string().contains(alias),
                "the target is echoed: {err}"
            );
        }
        assert_eq!(fake.calls(), Vec::new(), "the resolver was called");
    }

    #[tokio::test]
    async fn text_that_is_no_host_never_reaches_the_resolver() {
        let fake = CountingResolver::answering(vec![addr("127.0.0.1:9")]);
        let resolver = BoundedResolver::new().with_resolver(fake.clone());
        for text in [
            "",
            "bad host",
            "line\nbreak.test",
            "nul\0.test",
            "under_score.test",
            "[name.test]",
            "fe80::1%eth0",
            "a..b",
            "host.test:80",
        ] {
            let err = connect_host(text, 80, DIAL_TIMEOUT, &resolver)
                .await
                .expect_err("not a host");
            assert_eq!(err.code(), "NETCORE_INVALID_TARGET", "{text:?}: {err:?}");
        }
        assert_eq!(fake.calls(), Vec::new(), "the resolver was called");
    }

    #[tokio::test]
    async fn ipv6_and_ipv4_literals_never_call_the_resolver() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let fake = CountingResolver::answering(vec![addr("192.0.2.1:9")]);
        let resolver = BoundedResolver::new().with_resolver(fake.clone());

        let (_stream, resolution) = connect_host("127.0.0.1", open.port(), DIAL_TIMEOUT, &resolver)
            .await
            .expect("the IPv4 literal dials directly");
        assert_eq!(resolution.mode, ResolutionMode::Literal);
        assert_eq!(resolution.dialed, Some(open));
        assert_eq!(resolution.answers, 0);
        accept.await.expect("join").expect("accept");

        // The IPv6 spellings may well fail on a host without IPv6 or with
        // nothing listening (a timeout is as good as a refusal here); what they
        // must not do is ask the resolver.
        let closed = closed_port().await;
        for host in ["::1", "[::1]", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]"] {
            let outcome = connect_host(host, closed, Duration::from_millis(500), &resolver).await;
            if let Err(err) = &outcome {
                assert_ne!(err.code(), "NETCORE_INVALID_TARGET", "{host}: {err:?}");
                assert_ne!(err.code(), "NETCORE_DNS_FAILED", "{host}: {err:?}");
            }
        }
        assert_eq!(fake.calls(), Vec::new(), "a literal reached the resolver");
    }

    #[tokio::test]
    async fn mapped_and_duplicate_answers_are_dialed_once_as_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let mapped = addr(&format!("[::ffff:127.0.0.1]:{}", open.port()));

        let resolver = BoundedResolver::new()
            .with_resolver(CountingResolver::answering(vec![mapped, open, mapped]));
        let (_stream, resolution) = connect_host("svc.test", 443, DIAL_TIMEOUT, &resolver)
            .await
            .expect("the unmapped IPv4 address accepts");
        assert_eq!(resolution.answers, 1, "three answers are one address");
        assert_eq!(resolution.attempted, vec![open], "dialled once, as IPv4");
        assert_eq!(resolution.dialed, Some(open));
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn a_name_whose_every_answer_refuses_is_a_refusal_not_an_io_error() {
        let (one, two) = (closed_port().await, closed_port().await);
        let fake = CountingResolver::answering(vec![
            addr(&format!("127.0.0.1:{one}")),
            addr(&format!("127.0.0.1:{two}")),
        ]);
        let resolver = BoundedResolver::new().with_resolver(fake.clone());
        let err = connect_host("svc.test", 443, DIAL_TIMEOUT, &resolver)
            .await
            .expect_err("nothing listens");
        assert!(
            matches!(&err, NetcoreError::ConnectionRefused(label, _) if label == "svc.test:443"),
            "{err:?}"
        );
        assert_eq!(
            fake.calls().len(),
            1,
            "a refusal is not a reason to look up again"
        );
    }

    #[tokio::test]
    async fn connect_in_order_types_an_empty_list_instead_of_succeeding() {
        let err = connect_in_order(&[], "svc.test:443", DIAL_TIMEOUT)
            .await
            .expect_err("no address to dial");
        assert_eq!(err.code(), "NETCORE_DNS_FAILED");
    }

    /// The device an upstream socket is bound to (`SO_BINDTODEVICE`), as the
    /// kernel reports it: `None` for a socket nobody bound.
    #[cfg(target_os = "linux")]
    fn bound_device(stream: &TcpStream) -> Option<Vec<u8>> {
        socket2::SockRef::from(stream)
            .device()
            .expect("SO_BINDTODEVICE can be read back")
    }

    /// CO-1 (docs/M2_LOCAL_INGRESS_DESIGN.md 2.3, 24.2.1) read from real
    /// sockets: a Direct dial applies no interface binding, and its source
    /// address is the one the kernel gives a plain connection to the same
    /// listener. Both dial functions are read: the literal one and, behind a
    /// name, the pinned-address one.
    ///
    /// The listener is on the loopback alias 127.0.0.5 while the kernel picks
    /// 127.0.0.1 as the source, so the source differs from the destination and
    /// a dial that bound to the destination address would show.
    ///
    /// What this does and does not show. `device()` being `None` means no
    /// `SO_BINDTODEVICE` was applied. The source equality is consistent with
    /// an unbound socket but cannot tell it from an explicit `bind(127.0.0.1)`,
    /// which gives the same address, so it is not offered as proof that the OS
    /// chose the source. That nothing binds is the static scan of
    /// `ssk-daemon/tests/dial_path_binds_nothing.rs`; that the OS decides is
    /// the route-flip test (C-CO1b); what the Windows stack does is the manual
    /// run of ACCEPT-5.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_dial_leaves_device_and_source_to_the_os() {
        let listener = TcpListener::bind("127.0.0.5:0")
            .await
            .expect("127.0.0.5 is a loopback address on Linux");
        let target = listener.local_addr().expect("addr");

        // Nothing of ours touches the control: its source is what the kernel
        // chooses for this destination.
        let control = std::net::TcpStream::connect(target).expect("control connect");
        let control_source = control.local_addr().expect("control source").ip();
        assert_ne!(
            control_source,
            target.ip(),
            "the kernel chose the destination as the source: the source check cannot see a bind to it"
        );

        let literal = connect_tcp("127.0.0.5", target.port(), DIAL_TIMEOUT)
            .await
            .expect("the literal dial");
        assert_eq!(
            bound_device(&literal),
            None,
            "the literal dial binds a device"
        );
        assert_eq!(
            literal.local_addr().expect("local").ip(),
            control_source,
            "the literal dial's source is not the kernel's choice"
        );

        let resolver =
            BoundedResolver::new().with_resolver(CountingResolver::answering(vec![target]));
        let (named, resolution) = connect_host("svc.test", target.port(), DIAL_TIMEOUT, &resolver)
            .await
            .expect("the dial of a name");
        assert_eq!(
            resolution.mode,
            ResolutionMode::OsResolver,
            "not the name path"
        );
        assert_eq!(bound_device(&named), None, "the name dial binds a device");
        assert_eq!(
            named.local_addr().expect("local").ip(),
            control_source,
            "the name dial's source is not the kernel's choice"
        );
    }

    /// The device check above can fail: on a socket to which the test itself
    /// applies `SO_BINDTODEVICE`, the same reader reports the device. Without
    /// this, "no device" could be what a broken reader always says.
    ///
    /// Skips, saying why, where the kernel refuses the option for lack of
    /// permission (CAP_NET_RAW, on kernels that require it).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_device_check_has_teeth() {
        let listener = TcpListener::bind("127.0.0.5:0")
            .await
            .expect("127.0.0.5 is a loopback address on Linux");
        let target = listener.local_addr().expect("addr");

        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        if let Err(err) = socket.bind_device(Some(b"lo")) {
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "binding a socket to lo failed for a reason other than permission: {err}"
            );
            eprintln!(
                "SKIPPED: this process may not set SO_BINDTODEVICE ({err}); the device check was \
                 not shown to detect a bound socket"
            );
            return;
        }
        let stream = socket.connect(target).await.expect("the bound dial");
        assert_eq!(
            bound_device(&stream),
            Some(b"lo".to_vec()),
            "the device check does not see a device that was bound"
        );
    }
}
