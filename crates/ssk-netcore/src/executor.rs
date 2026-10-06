#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ssk_netadmin::adapter::{AdapterDescriptor, AdapterKind};
use ssk_netadmin::route::{HopSpec, RouteKind};
use tokio::sync::OnceCell;

use crate::dns::{self, RecordType};
use crate::error::NetcoreError;
use crate::probe::ProbeReport;
use crate::session::{BoxedTransport, EgressSession};
use crate::{direct, http_connect, socks5, tls};

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
    tls_config: OnceCell<Arc<rustls::ClientConfig>>,
}

impl RouteExecutor {
    #[must_use]
    pub fn new(registry: AdapterRegistry) -> Self {
        Self {
            registry,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            tls_config: OnceCell::new(),
        }
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
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
    /// with `NoRoute` before any socket is opened.
    pub async fn connect(
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
        let stream = direct::connect_tcp(target.0, target.1, self.connect_timeout).await?;
        Ok(EgressSession::new(
            Box::new(stream),
            vec![AdapterKind::Direct],
            (target.0.to_string(), target.1),
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
        let mut transport: BoxedTransport =
            Box::new(direct::connect_tcp(&first.address, first.port, self.connect_timeout).await?);

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
