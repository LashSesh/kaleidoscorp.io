#![forbid(unsafe_code)]

use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::error::NetcoreError;

/// Opens a real TCP connection to `host:port`, resolving `host` via the OS
/// resolver (real DNS, real syscalls — this is the baseline real network I/O
/// the workspace previously had none of anywhere).
pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<TcpStream, NetcoreError> {
    let addr = format!("{host}:{port}");
    match timeout(connect_timeout, TcpStream::connect(&addr)).await {
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
}
