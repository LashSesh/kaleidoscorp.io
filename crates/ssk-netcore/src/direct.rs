#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::authority::{authority, unbracket};
use crate::error::NetcoreError;

/// Opens a real TCP connection to `host:port`, resolving `host` via the OS
/// resolver (real DNS, real syscalls — this is the baseline real network I/O
/// the workspace previously had none of anywhere).
///
/// Dials the `(host, port)` pair rather than a joined `"host:port"` string:
/// an IP literal (IPv4, or IPv6 bare or bracketed) is then used as an address
/// directly and never goes through the resolver, and `host` is never
/// re-parsed together with the port.
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

#[cfg(test)]
mod tests {
    use super::*;
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

    /// `None` (with the reason printed) when this host has no IPv6 loopback,
    /// so the test skips instead of failing on IPv4-only runners.
    async fn bind_ipv6_loopback() -> Option<TcpListener> {
        match TcpListener::bind("[::1]:0").await {
            Ok(listener) => Some(listener),
            Err(err) => {
                eprintln!(
                    "SKIPPED: this host cannot bind [::1] ({err}); the IPv6 dial was not exercised"
                );
                None
            }
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
}
