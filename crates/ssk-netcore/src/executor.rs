#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
use ssk_netadmin::route::{HopSpec, RouteKind};
use tokio::sync::OnceCell;
use tokio::time::timeout;

use crate::authority::authority;
use crate::dns::{self, RecordType};
use crate::error::NetcoreError;
use crate::probe::ProbeReport;
use crate::resolve::{BoundedResolver, NameResolver};
use crate::session::{BoxedTransport, DialResolution, EgressSession, SessionResolution};
use crate::{direct, http_connect, socks5, tls};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Bounds a whole `connect`. Longer than one TCP connect, since it also has to
/// cover every hop's handshake.
const DEFAULT_DIAL_DEADLINE: Duration = Duration::from_secs(30);

/// Maps the adapter ids a `RouteCandidate`'s `HopSpec`s reference back to
/// their real `AdapterDescriptor` (kind + address + port + metadata) — the
/// missing link between `ssk-netadmin`'s planning layer (which only knows
/// adapter ids as strings) and this crate's real dispatch (which needs to
/// know *what kind* of adapter each id names).
#[derive(Debug, Default, Clone)]
pub struct AdapterRegistry {
    entries: HashMap<String, AdapterDescriptor>,
}

impl AdapterRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, descriptor: AdapterDescriptor) {
        self.entries
            .insert(descriptor.adapter_id.clone(), descriptor);
    }

    #[must_use]
    pub fn get(&self, adapter_id: &str) -> Option<&AdapterDescriptor> {
        self.entries.get(adapter_id)
    }
}

/// The real, callable data-plane executor: given a `RouteKind` planned by
/// `ssk-netadmin::RouteOrchestrator`, actually dispatches it — opening a
/// real TCP connection and, hop by hop, performing each adapter's real
/// protocol handshake. This is the concrete answer to SSKΩ-7 ("real egress
/// adapters ... health probing"): every `EgressSession` this type returns
/// names only adapters a real handshake actually succeeded through.
pub struct RouteExecutor {
    registry: AdapterRegistry,
    connect_timeout: Duration,
    dial_deadline: Duration,
    tls_config: OnceCell<Arc<rustls::ClientConfig>>,
    resolver: BoundedResolver,
}

impl RouteExecutor {
    #[must_use]
    pub fn new(registry: AdapterRegistry) -> Self {
        Self {
            registry,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            dial_deadline: DEFAULT_DIAL_DEADLINE,
            tls_config: OnceCell::new(),
            resolver: BoundedResolver::new(),
        }
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Bounds the whole of [`Self::connect`] (and so [`Self::probe`]): name
    /// resolution, every hop's TCP connect and every SOCKS5/CONNECT/TLS
    /// handshake. `with_connect_timeout` only covers each TCP connect, so
    /// without this a proxy that accepts the connection and then stays silent
    /// would hold the dial forever.
    #[must_use]
    pub fn with_dial_deadline(mut self, deadline: Duration) -> Self {
        self.dial_deadline = deadline;
        self
    }

    /// Replaces the resolver that looks up the host names this executor dials
    /// itself (a `Direct` target and the first hop of a chain). The default is
    /// the OS resolver. Names are never resolved for a proxied target: the
    /// upstream proxy does that.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn NameResolver>) -> Self {
        self.resolver = self.resolver.with_resolver(resolver);
        self
    }

    /// Bounds one name lookup, counted from the call (the wait for a free
    /// lookup slot is inside it). Default 5 s. The dial deadline still bounds
    /// the whole dial, so a larger value than that deadline changes nothing.
    #[must_use]
    pub fn with_resolve_timeout(mut self, timeout: Duration) -> Self {
        self.resolver = self.resolver.with_timeout(timeout);
        self
    }

    /// How many name lookups may run at once; each can hold one thread of the
    /// runtime's blocking pool until the OS call returns, however the callers'
    /// deadlines went. Default 16. A dial that finds none free waits up to
    /// 500 ms and then fails with [`NetcoreError::ResolverBusy`]; literals and
    /// proxied targets never wait. Clamped to at least 1. Set it before the
    /// first dial.
    #[must_use]
    pub fn with_max_concurrent_lookups(mut self, lookups: usize) -> Self {
        self.resolver = self.resolver.with_max_concurrent(lookups);
        self
    }

    /// Name lookups that a caller stopped waiting for (the resolver deadline
    /// passed, or the dial was cut) while the OS call is still running. Each
    /// still holds one lookup slot until the call returns.
    #[must_use]
    pub fn abandoned_lookups(&self) -> usize {
        self.resolver.abandoned()
    }

    /// Real DNS resolution against a configured override resolver (the
    /// executor counterpart to `DnsOverrideAdapter`, which today only
    /// stores resolver host/port as inert data).
    pub async fn resolve_via(
        &self,
        adapter_id: &str,
        query_name: &str,
    ) -> Result<Vec<std::net::IpAddr>, NetcoreError> {
        let descriptor = self
            .registry
            .get(adapter_id)
            .ok_or_else(|| NetcoreError::UnknownAdapter(adapter_id.to_string()))?;
        if descriptor.kind != AdapterKind::DnsOverride {
            return Err(NetcoreError::Unsupported(descriptor.kind));
        }
        let mut addrs = dns::resolve(
            &descriptor.address,
            descriptor.port,
            query_name,
            RecordType::A,
            self.connect_timeout,
        )
        .await?;
        if let Ok(v6) = dns::resolve(
            &descriptor.address,
            descriptor.port,
            query_name,
            RecordType::Aaaa,
            self.connect_timeout,
        )
        .await
        {
            addrs.extend(v6);
        }
        Ok(addrs)
    }

    /// Dispatches `route` for real, connecting all the way to
    /// `target = (host, port)`. Fails closed with a typed [`NetcoreError`]
    /// on any real failure — never falls back to an unplanned adapter, and
    /// never retries one route on another: a `RouteKind::Fallback` is refused
    /// with `NoRoute` before any socket is opened. The whole dial is bounded
    /// by the dial deadline and fails with `Timeout`; the half-built transport
    /// is dropped, which closes the sockets.
    pub async fn connect(
        &self,
        route: &RouteKind,
        target: (&str, u16),
    ) -> Result<EgressSession, NetcoreError> {
        timeout(self.dial_deadline, self.dispatch(route, target))
            .await
            .unwrap_or_else(|_elapsed| {
                Err(NetcoreError::Timeout(
                    authority(target.0, target.1),
                    self.dial_deadline,
                ))
            })
    }

    async fn dispatch(
        &self,
        route: &RouteKind,
        target: (&str, u16),
    ) -> Result<EgressSession, NetcoreError> {
        match route {
            RouteKind::OpenVpn { profile_id, .. } => {
                Err(NetcoreError::OpenVpnNotReady(profile_id.clone()))
            }
            RouteKind::Denied { reason } => Err(NetcoreError::PolicyDenied(reason.clone())),
            RouteKind::Direct => self.connect_direct(target).await,
            RouteKind::SingleHop(hop) => {
                self.connect_chain(std::slice::from_ref(hop), target).await
            }
            RouteKind::MultiHop(hops) => self.connect_chain(hops, target).await,
            // Retrying a failed primary on `fallback` (which may be `Direct`)
            // is an unintended direct egress, so refusing it must not depend
            // on the planner happening never to emit this variant. The variant
            // stays only because `RouteKind` is public and serialisable.
            RouteKind::Fallback { .. } => Err(NetcoreError::NoRoute(
                "fallback routes are not executable".into(),
            )),
        }
    }

    /// Real health probe: attempts the actual connect/handshake chain and
    /// tears the session back down. Never returns a hardcoded status.
    pub async fn probe(&self, route: &RouteKind, target: (&str, u16)) -> ProbeReport {
        let start = Instant::now();
        match self.connect(route, target).await {
            Ok(mut session) => {
                let latency = start.elapsed();
                let chain_desc = format!("{:?}", session.chain());
                let _ = session.shutdown().await;
                ProbeReport::live(
                    latency,
                    format!("connected via {chain_desc} in {latency:?}"),
                )
            }
            Err(err) => ProbeReport::down(err.to_string()),
        }
    }

    async fn connect_direct(&self, target: (&str, u16)) -> Result<EgressSession, NetcoreError> {
        let (stream, resolution) =
            direct::connect_host(target.0, target.1, self.connect_timeout, &self.resolver).await?;
        Ok(EgressSession::new(
            Box::new(stream),
            vec![AdapterKind::Direct],
            (target.0.to_string(), target.1),
            SessionResolution {
                target: resolution,
                first_hop: None,
            },
        ))
    }

    async fn connect_chain(
        &self,
        hops: &[HopSpec],
        target: (&str, u16),
    ) -> Result<EgressSession, NetcoreError> {
        if hops.is_empty() {
            return Err(NetcoreError::NoRoute("empty hop chain".into()));
        }
        let descriptors: Vec<&AdapterDescriptor> = hops
            .iter()
            .map(|hop| {
                self.registry
                    .get(&hop.adapter_id)
                    .ok_or_else(|| NetcoreError::UnknownAdapter(hop.adapter_id.clone()))
            })
            .collect::<Result<_, _>>()?;
        if descriptors.iter().any(|d| d.kind == AdapterKind::OpenVpn) {
            return Err(NetcoreError::OpenVpnNotReady("unbound OpenVPN hop".into()));
        }

        let first = &hops[0];
        let (first_stream, first_hop) = direct::connect_host(
            &first.address,
            first.port,
            self.connect_timeout,
            &self.resolver,
        )
        .await?;
        let mut transport: BoxedTransport = Box::new(first_stream);

        let mut chain_kinds = Vec::with_capacity(hops.len());
        for (i, hop) in hops.iter().enumerate() {
            let descriptor = descriptors[i];
            let (next_host, next_port): (&str, u16) = if i + 1 < hops.len() {
                (hops[i + 1].address.as_str(), hops[i + 1].port)
            } else {
                target
            };
            transport = self
                .apply_hop(transport, descriptor, hop, next_host, next_port)
                .await?;
            chain_kinds.push(descriptor.kind);
        }
        Ok(EgressSession::new(
            transport,
            chain_kinds,
            (target.0.to_string(), target.1),
            SessionResolution {
                // Only the first hop is a socket of this process; the target
                // is forwarded for the last hop to dial.
                target: DialResolution::forwarded(target.0),
                first_hop: Some(first_hop),
            },
        ))
    }

    async fn apply_hop(
        &self,
        transport: BoxedTransport,
        descriptor: &AdapterDescriptor,
        hop: &HopSpec,
        next_host: &str,
        next_port: u16,
    ) -> Result<BoxedTransport, NetcoreError> {
        match descriptor.kind {
            AdapterKind::Direct => Ok(transport),
            AdapterKind::Socks5 => {
                let auth = hop
                    .auth
                    .as_deref()
                    .and_then(|combined| combined.split_once(':'));
                socks5::handshake_connect(
                    transport,
                    next_host,
                    next_port,
                    auth,
                    &descriptor.adapter_id,
                )
                .await
            }
            AdapterKind::HttpConnect => {
                let auth_header = descriptor
                    .metadata
                    .iter()
                    .find(|(k, _)| k == "proxy-authorization")
                    .map(|(_, v)| v.as_str());
                http_connect::handshake_connect(
                    transport,
                    next_host,
                    next_port,
                    auth_header,
                    &descriptor.adapter_id,
                )
                .await
            }
            AdapterKind::TlsTunnel => {
                let sni = descriptor
                    .metadata
                    .iter()
                    .find(|(k, _)| k == "sni")
                    .map_or(next_host, |(_, v)| v.as_str());
                let config = self.tls_config(&descriptor.adapter_id).await?;
                let wrapped = tls::wrap_tls(transport, sni, config, &descriptor.adapter_id).await?;
                Ok(Box::new(wrapped))
            }
            AdapterKind::OpenVpn => {
                Err(NetcoreError::OpenVpnNotReady(descriptor.adapter_id.clone()))
            }
            AdapterKind::DnsOverride => Err(NetcoreError::Unsupported(AdapterKind::DnsOverride)),
        }
    }

    async fn tls_config(
        &self,
        relay_label: &str,
    ) -> Result<Arc<rustls::ClientConfig>, NetcoreError> {
        // Built once and cached: native trust-store loading is documented
        // by `rustls-native-certs` as expensive (can read a ~300KB file).
        self.tls_config
            .get_or_try_init(|| async { tls::build_client_config(None, relay_label) })
            .await
            .map(Arc::clone)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;
    use crate::resolve::fakes::{
        addr, settle, until, CountingResolver, Gate, GatedResolver, ReleaseOnDrop,
    };
    use crate::resolve::{RESOLVER_WAIT, RESOLVE_TIMEOUT};
    use crate::session::ResolutionMode;

    #[test]
    fn dial_deadline_defaults_to_thirty_seconds_and_is_configurable() {
        let executor = RouteExecutor::new(AdapterRegistry::new());
        assert_eq!(executor.dial_deadline, Duration::from_secs(30));
        // The per-TCP-connect timeout is a separate, smaller bound.
        assert!(executor.connect_timeout < executor.dial_deadline);

        let executor = executor.with_dial_deadline(Duration::from_secs(7));
        assert_eq!(executor.dial_deadline, Duration::from_secs(7));
        assert_eq!(executor.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    }

    /// A SOCKS5 proxy that answers one CONNECT with success and reports the
    /// address the client connected from.
    async fn socks5_proxy_noting_its_peer() -> (u16, tokio::task::JoinHandle<SocketAddr>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let proxy = tokio::spawn(async move {
            let (mut sock, peer) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.expect("greeting");
            let mut methods = vec![0u8; usize::from(greeting[1])];
            sock.read_exact(&mut methods).await.expect("methods");
            sock.write_all(&[0x05, 0x00]).await.expect("method reply");
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.expect("request head");
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.expect("domain length");
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            sock.read_exact(&mut rest).await.expect("domain and port");
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .expect("success reply");
            peer
        });
        (port, proxy)
    }

    fn socks5_registry(host: &str, port: u16) -> AdapterRegistry {
        let mut registry = AdapterRegistry::new();
        registry.register(AdapterDescriptor {
            adapter_id: "socks".into(),
            kind: AdapterKind::Socks5,
            address: host.into(),
            port,
            metadata: vec![],
        });
        registry
    }

    #[tokio::test]
    async fn direct_session_reports_the_sockets_local_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let target = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        let session = RouteExecutor::new(AdapterRegistry::new())
            .connect(&RouteKind::Direct, ("127.0.0.1", target.port()))
            .await
            .expect("a Direct route must connect");
        let (_accepted, seen_as) = accept.await.expect("join").expect("accept");

        let resolution = session.resolution();
        assert_eq!(
            resolution.target.local_addr,
            Some(seen_as),
            "the local address is the one the listener saw the dial come from"
        );
        assert_eq!(resolution.target.mode, ResolutionMode::Literal);
        assert_eq!(resolution.target.dialed, Some(target));
        assert_eq!(resolution.first_hop, None);
    }

    #[tokio::test]
    async fn proxy_chain_session_reports_the_first_hop_local_address() {
        let (port, proxy) = socks5_proxy_noting_its_peer().await;
        let executor = RouteExecutor::new(socks5_registry("127.0.0.1", port));
        let route = RouteKind::SingleHop(HopSpec::new("socks", "127.0.0.1", port));
        let session = executor
            .connect(&route, ("upstream.internal", 443))
            .await
            .expect("the chain connects");
        let seen_as = proxy.await.expect("join");

        let resolution = session.resolution();
        let first_hop = resolution
            .first_hop
            .as_ref()
            .expect("a chain has a first hop");
        assert_eq!(first_hop.local_addr, Some(seen_as));
        assert_eq!(first_hop.mode, ResolutionMode::Literal);
        assert_eq!(first_hop.dialed, Some(addr(&format!("127.0.0.1:{port}"))));
        // The target was handed to the proxy as a name: no socket of ours.
        assert_eq!(resolution.target.mode, ResolutionMode::ForwardedUnresolved);
        assert_eq!(resolution.target.dialed, None);
        assert_eq!(resolution.target.local_addr, None);
        assert_eq!(resolution.target.answers, 0);
    }

    #[tokio::test]
    async fn first_hop_name_is_resolved_once_and_the_forwarded_target_is_not() {
        let (port, proxy) = socks5_proxy_noting_its_peer().await;
        let fake = CountingResolver::answering(vec![addr(&format!("127.0.0.1:{port}"))]);
        let executor =
            RouteExecutor::new(socks5_registry("proxy.test", port)).with_resolver(fake.clone());
        let route = RouteKind::SingleHop(HopSpec::new("socks", "proxy.test", port));
        let session = executor
            .connect(&route, ("upstream.internal", 443))
            .await
            .expect("the chain connects through the resolved first hop");
        let seen_as = proxy.await.expect("join");

        assert_eq!(
            fake.calls(),
            vec![("proxy.test".to_owned(), port)],
            "the first hop is looked up once; the target is the proxy's to resolve"
        );
        let first_hop = session.resolution().first_hop.as_ref().expect("first hop");
        assert_eq!(first_hop.mode, ResolutionMode::OsResolver);
        assert_eq!(first_hop.answers, 1);
        assert_eq!(first_hop.local_addr, Some(seen_as));
        assert_eq!(
            session.resolution().target.mode,
            ResolutionMode::ForwardedUnresolved
        );
    }

    #[tokio::test]
    async fn a_numeric_alias_as_first_hop_is_refused_before_any_lookup_or_byte() {
        let fake = CountingResolver::answering(vec![addr("127.0.0.1:9")]);
        let executor =
            RouteExecutor::new(socks5_registry("127.1", 1080)).with_resolver(fake.clone());
        let route = RouteKind::SingleHop(HopSpec::new("socks", "127.1", 1080));
        let err = executor
            .connect(&route, ("upstream.internal", 443))
            .await
            .expect_err("`127.1` is not a host this crate dials");
        assert_eq!(err.code(), "NETCORE_INVALID_TARGET");
        assert_eq!(fake.calls(), Vec::new());
    }

    #[tokio::test]
    async fn a_numeric_alias_target_is_refused_before_the_os_resolver_can_dial_it() {
        // `getaddrinfo` reads `2130706433`, `127.1` and `0x7f.1` as 127.0.0.1,
        // so a Direct dial of any of them used to reach this local listener
        // although no rule could ever have named it.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let executor = RouteExecutor::new(AdapterRegistry::new());
        for alias in ["2130706433", "127.1", "0x7f.1"] {
            match executor.connect(&RouteKind::Direct, (alias, port)).await {
                Ok(_) => panic!("`{alias}` reached the OS resolver and dialled the local listener"),
                Err(err) => assert_eq!(err.code(), "NETCORE_INVALID_TARGET", "{alias}: {err:?}"),
            }
        }
        drop(listener);
    }

    #[tokio::test(start_paused = true)]
    async fn resolver_busy_after_the_wait_and_literals_still_dial() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let fake = GatedResolver::new(Arc::clone(&gate), vec![addr("127.0.0.1:9")]);
        let executor = Arc::new(
            RouteExecutor::new(AdapterRegistry::new())
                .with_resolver(fake)
                .with_max_concurrent_lookups(2),
        );
        let dial = |host: &'static str| {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                executor
                    .connect(&RouteKind::Direct, (host, 443))
                    .await
                    .map(|_| ())
            })
        };
        let _stuck = [dial("stuck-0.test"), dial("stuck-1.test")];
        until("both lookup slots taken", || gate.entered() == 2).await;

        let busy = dial("fresh.test");
        settle().await;
        assert!(!busy.is_finished(), "a name waits for a slot first");
        tokio::time::advance(RESOLVER_WAIT + Duration::from_millis(4)).await;
        settle().await;
        assert!(busy.is_finished(), "a name waits at most the bounded wait");
        let err = busy.await.expect("join").expect_err("no slot");
        assert!(matches!(err, NetcoreError::ResolverBusy), "{err:?}");
        assert_eq!(err.code(), "NETCORE_RESOLVER_BUSY");

        // Literals never needed a slot. The real socket below needs real time.
        tokio::time::resume();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accept = tokio::spawn(async move { listener.accept().await });
        let session = executor
            .connect(&RouteKind::Direct, ("127.0.0.1", port))
            .await
            .expect("a literal dials while every lookup slot is taken");
        assert_eq!(session.resolution().target.mode, ResolutionMode::Literal);
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test(start_paused = true)]
    async fn dial_deadline_cuts_a_stuck_lookup_and_counts_it() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let executor = Arc::new(
            RouteExecutor::new(AdapterRegistry::new())
                .with_resolver(GatedResolver::new(
                    Arc::clone(&gate),
                    vec![addr("127.0.0.1:9")],
                ))
                .with_dial_deadline(Duration::from_secs(1)),
        );
        assert!(Duration::from_secs(1) < RESOLVE_TIMEOUT);
        let dial = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                executor
                    .connect(&RouteKind::Direct, ("stuck-deadline.test", 443))
                    .await
                    .map(|_| ())
            })
        };
        until("the lookup starting", || gate.entered() == 1).await;
        tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(4)).await;
        settle().await;
        let err = dial
            .await
            .expect("join")
            .expect_err("the dial deadline cuts it");
        assert!(
            matches!(&err, NetcoreError::Timeout(label, d)
                if label == "stuck-deadline.test:443" && *d == Duration::from_secs(1)),
            "{err:?}"
        );
        assert_eq!(
            executor.abandoned_lookups(),
            1,
            "the dial is gone, the OS call is not"
        );

        gate.release("stuck-deadline.test");
        until("the lookup returning", || executor.abandoned_lookups() == 0).await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_executor_sets_its_own_resolve_timeout() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let executor = Arc::new(
            RouteExecutor::new(AdapterRegistry::new())
                .with_resolver(GatedResolver::new(
                    Arc::clone(&gate),
                    vec![addr("127.0.0.1:9")],
                ))
                .with_resolve_timeout(Duration::from_millis(250)),
        );
        let dial = {
            let executor = Arc::clone(&executor);
            tokio::spawn(async move {
                executor
                    .connect(&RouteKind::Direct, ("stuck-own-timeout.test", 443))
                    .await
                    .map(|_| ())
            })
        };
        until("the lookup starting", || gate.entered() == 1).await;
        tokio::time::advance(Duration::from_millis(254)).await;
        settle().await;
        let err = dial
            .await
            .expect("join")
            .expect_err("the resolve timeout fires");
        assert!(
            matches!(&err, NetcoreError::Timeout(label, d)
                if label == "stuck-own-timeout.test:443" && *d == Duration::from_millis(250)),
            "{err:?}"
        );
    }
}
