#![forbid(unsafe_code)]

//! `ssk-netcore` — the real data-plane executor `ssk-netadmin` plans routes
//! for but does not itself execute.
//!
//! `ssk-netadmin`'s `RouteOrchestrator` computes a `RouteCandidate` (which
//! adapter, in which order) and its `DataPlaneAdapter` types only
//! `describe()` themselves — deliberately, so that crate stays
//! `no_std`-friendly and free of async/network dependencies. This crate is
//! the other half: given a planned `RouteKind` and a real `AdapterRegistry`,
//! it actually connects — real TCP, a real SOCKS5/HTTP-CONNECT handshake, a
//! real TLS handshake verified against the OS trust store, or a real DNS
//! query — and returns either a live [`EgressSession`] or a typed
//! [`NetcoreError`] naming exactly what failed. Nothing in this crate
//! fabricates liveness: every [`ProbeReport`] and every [`EgressSession`]
//! reflects a real attempt that really happened on the wire.

mod data_plane;
mod direct;
mod dns;
mod error;
mod executor;
mod http_connect;
mod probe;
mod session;
mod socks5;
mod tls;

pub use data_plane::{BoxFuture, DataPlane, NetcoreDataPlane};
pub use dns::RecordType;
pub use error::NetcoreError;
pub use executor::{AdapterRegistry, RouteExecutor};
pub use probe::{ProbeReport, ProbeStatus};
pub use session::{EgressSession, Transport};

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
    use ssk_netadmin::route::RouteKind;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn openvpn_cannot_be_disguised_as_a_tcp_proxy_hop() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut registry = AdapterRegistry::new();
        registry.register(AdapterDescriptor {
            adapter_id: "vpn".into(),
            kind: AdapterKind::OpenVpn,
            address: "127.0.0.1".into(),
            port,
            metadata: vec![],
        });
        let route = RouteKind::SingleHop(ssk_netadmin::HopSpec::new("vpn", "127.0.0.1", port));
        let error = RouteExecutor::new(registry)
            .connect(&route, ("127.0.0.1", port))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "OPENVPN_NOT_READY");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn direct_route_really_connects_to_a_real_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        let executor = RouteExecutor::new(AdapterRegistry::new());
        let session = executor
            .connect(&RouteKind::Direct, ("127.0.0.1", addr.port()))
            .await
            .expect("a Direct route must really connect");
        assert_eq!(session.chain(), &[AdapterKind::Direct]);
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn denied_route_never_attempts_a_connection() {
        let executor = RouteExecutor::new(AdapterRegistry::new());
        let err = executor
            .connect(
                &RouteKind::Denied {
                    reason: "policy: deny".into(),
                },
                ("127.0.0.1", 1),
            )
            .await
            .expect_err("a Denied route must fail closed, never connect");
        assert!(matches!(err, NetcoreError::PolicyDenied(_)));
    }

    #[tokio::test]
    async fn unknown_adapter_in_a_hop_fails_closed_instead_of_falling_back_to_direct() {
        let executor = RouteExecutor::new(AdapterRegistry::new());
        let route = RouteKind::SingleHop(ssk_netadmin::route::HopSpec::new(
            "ghost-adapter",
            "127.0.0.1",
            9,
        ));
        let err = executor
            .connect(&route, ("127.0.0.1", 9))
            .await
            .expect_err("an unregistered adapter must never silently resolve to Direct");
        assert!(matches!(err, NetcoreError::UnknownAdapter(_)));
    }

    /// Counts connections the sentinel has queued, waiting `grace` for each
    /// one. A dial that completed before this runs is already in the accept
    /// queue, so the grace only ever delays a passing (zero) result.
    async fn sentinel_connections(sentinel: &TcpListener) -> usize {
        let grace = std::time::Duration::from_millis(200);
        let mut seen = 0;
        while let Ok(Ok(_)) = tokio::time::timeout(grace, sentinel.accept()).await {
            seen += 1;
        }
        seen
    }

    #[tokio::test]
    async fn fallback_route_never_dials_direct() {
        // A bound, never-listening socket reserves its port for the whole
        // test (no free-then-reuse race) and refuses every connect.
        let dead_proxy = tokio::net::TcpSocket::new_v4().expect("socket");
        dead_proxy
            .bind("127.0.0.1:0".parse().expect("addr"))
            .expect("bind");
        let dead_port = dead_proxy.local_addr().expect("addr").port();

        let sentinel = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let sentinel_port = sentinel.local_addr().expect("addr").port();

        let mut registry = AdapterRegistry::new();
        registry.register(AdapterDescriptor {
            adapter_id: "dead-socks".into(),
            kind: AdapterKind::Socks5,
            address: "127.0.0.1".into(),
            port: dead_port,
            metadata: vec![],
        });
        let primary = RouteKind::SingleHop(ssk_netadmin::route::HopSpec::new(
            "dead-socks",
            "127.0.0.1",
            dead_port,
        ));
        let executor = RouteExecutor::new(registry);
        let target = ("127.0.0.1", sentinel_port);

        // Premise: the primary really fails on its own, so reaching the
        // sentinel can only mean the executor retried on the fallback.
        let primary_err = executor
            .connect(&primary, target)
            .await
            .expect_err("the dead SOCKS5 primary must fail");
        assert!(matches!(primary_err, NetcoreError::ConnectionRefused(..)));
        assert_eq!(sentinel_connections(&sentinel).await, 0);

        let route = RouteKind::Fallback {
            primary: Box::new(primary),
            fallback: Box::new(RouteKind::Direct),
        };
        let result = executor.connect(&route, target).await;
        assert_eq!(
            sentinel_connections(&sentinel).await,
            0,
            "a failed primary must never become a direct dial of the target"
        );
        assert!(
            matches!(&result, Err(NetcoreError::NoRoute(reason)) if reason.contains("fallback")),
            "a Fallback route must be refused as NoRoute, got {:?}",
            result.map(|session| session.chain().to_vec())
        );

        // `probe` goes through `connect`, so it must be just as inert.
        let report = executor.probe(&route, target).await;
        assert_eq!(report.status, ProbeStatus::Down);
        assert_eq!(sentinel_connections(&sentinel).await, 0);
        drop(dead_proxy);
    }

    #[tokio::test]
    async fn probe_reports_down_with_a_real_reason_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let executor = RouteExecutor::new(AdapterRegistry::new());
        let report = executor
            .probe(&RouteKind::Direct, ("127.0.0.1", port))
            .await;
        assert_eq!(report.status, ProbeStatus::Down);
        assert!(!report.reason.is_empty());
    }

    #[tokio::test]
    async fn probe_reports_live_with_real_latency_when_something_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        let executor = RouteExecutor::new(AdapterRegistry::new());
        let report = executor
            .probe(&RouteKind::Direct, ("127.0.0.1", addr.port()))
            .await;
        assert!(report.is_live());
        assert!(report.latency.is_some());
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn socks5_hop_end_to_end_through_the_real_registry_and_executor() {
        // A real SOCKS5 proxy (not our test's own fake) would sit here in
        // production; this test uses the same fake server as
        // `socks5::tests` but drives it through the full public
        // `RouteExecutor` path (registry -> chain -> handshake) to prove
        // the wiring, not just the protocol codec in isolation.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let proxy_addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.expect("greeting");
            let mut methods = vec![0u8; greeting[1] as usize];
            sock.read_exact(&mut methods).await.expect("methods");
            sock.write_all(&[0x05, 0x00]).await.expect("method reply");

            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.expect("req head");
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.expect("domain len");
            let mut domain = vec![0u8; len[0] as usize];
            sock.read_exact(&mut domain).await.expect("domain");
            let mut port = [0u8; 2];
            sock.read_exact(&mut port).await.expect("port");

            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("success reply");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });

        let mut registry = AdapterRegistry::new();
        registry.register(AdapterDescriptor {
            adapter_id: "socks5-exit".into(),
            kind: AdapterKind::Socks5,
            address: "127.0.0.1".into(),
            port: proxy_addr.port(),
            metadata: vec![],
        });
        let executor = RouteExecutor::new(registry);
        let route = RouteKind::SingleHop(ssk_netadmin::route::HopSpec::new(
            "socks5-exit",
            "127.0.0.1",
            proxy_addr.port(),
        ));
        let session = executor
            .connect(&route, ("upstream.internal", 443))
            .await
            .expect("real socks5 chain through the executor must succeed");
        assert_eq!(session.chain(), &[AdapterKind::Socks5]);
    }
}
