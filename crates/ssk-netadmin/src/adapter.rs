#![forbid(unsafe_code)]

//! Data Plane Adapters — pluggable descriptors for SOCKS5, HTTP CONNECT,
//! TLS tunnel, Direct, and DNS override egress methods.
//!
//! Adapters are **descriptor-only**: they define *how* a connection should be
//! set up, not the networking implementation itself.  The actual transport is
//! the responsibility of the caller.  This keeps the library `no_std`-friendly
//! for the descriptor types and avoids pulling in async/tokio dependencies.

use serde::{Deserialize, Serialize};

/// High-level adapter kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterKind {
    Direct,
    Socks5,
    HttpConnect,
    TlsTunnel,
    DnsOverride,
}

/// A fully-resolved adapter descriptor ready for use by a transport layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterDescriptor {
    pub adapter_id: String,
    pub kind: AdapterKind,
    /// Proxy/relay address (empty for `Direct`).
    pub address: String,
    /// Proxy/relay port (0 for `Direct`).
    pub port: u16,
    /// Additional kind-specific metadata as key-value pairs.
    pub metadata: Vec<(String, String)>,
}

/// Trait implemented by all data-plane adapter types.
pub trait DataPlaneAdapter: Send + Sync {
    fn adapter_id(&self) -> &str;
    fn describe(&self) -> AdapterDescriptor;
}

// ---------------------------------------------------------------------------
// Concrete adapter implementations
// ---------------------------------------------------------------------------

/// Passes the connection directly to the destination without any proxy.
#[derive(Debug, Clone)]
pub struct DirectAdapter {
    pub id: String,
}

impl DirectAdapter {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}

impl DataPlaneAdapter for DirectAdapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_id: self.id.clone(),
            kind: AdapterKind::Direct,
            address: String::new(),
            port: 0,
            metadata: vec![],
        }
    }
}

/// Routes via a SOCKS5 proxy server.
#[derive(Debug, Clone)]
pub struct Socks5Adapter {
    pub id: String,
    pub proxy_host: String,
    pub proxy_port: u16,
    /// Optional `"user:pass"` authentication string.
    pub auth: Option<String>,
}

impl Socks5Adapter {
    pub fn new(id: impl Into<String>, proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            id: id.into(),
            proxy_host: proxy_host.into(),
            proxy_port,
            auth: None,
        }
    }

    #[must_use]
    pub fn with_auth(mut self, auth: impl Into<String>) -> Self {
        self.auth = Some(auth.into());
        self
    }
}

impl DataPlaneAdapter for Socks5Adapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> AdapterDescriptor {
        let mut metadata = vec![("version".into(), "5".into())];
        if let Some(a) = &self.auth {
            metadata.push(("auth".into(), a.clone()));
        }
        AdapterDescriptor {
            adapter_id: self.id.clone(),
            kind: AdapterKind::Socks5,
            address: self.proxy_host.clone(),
            port: self.proxy_port,
            metadata,
        }
    }
}

/// Routes via an HTTP CONNECT tunnel through a forward proxy.
#[derive(Debug, Clone)]
pub struct HttpConnectAdapter {
    pub id: String,
    pub proxy_host: String,
    pub proxy_port: u16,
    /// Optional `"******"` or `"Basic <b64>"` auth header value.
    pub auth_header: Option<String>,
}

impl HttpConnectAdapter {
    pub fn new(id: impl Into<String>, proxy_host: impl Into<String>, proxy_port: u16) -> Self {
        Self {
            id: id.into(),
            proxy_host: proxy_host.into(),
            proxy_port,
            auth_header: None,
        }
    }
}

impl DataPlaneAdapter for HttpConnectAdapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> AdapterDescriptor {
        let mut metadata = vec![("method".into(), "CONNECT".into())];
        if let Some(h) = &self.auth_header {
            metadata.push(("proxy-authorization".into(), h.clone()));
        }
        AdapterDescriptor {
            adapter_id: self.id.clone(),
            kind: AdapterKind::HttpConnect,
            address: self.proxy_host.clone(),
            port: self.proxy_port,
            metadata,
        }
    }
}

/// Wraps the connection in a TLS tunnel to a relay endpoint.
#[derive(Debug, Clone)]
pub struct TlsTunnelAdapter {
    pub id: String,
    pub relay_host: String,
    pub relay_port: u16,
    /// Expected TLS SNI / server name.
    pub sni: String,
    /// Whether mutual TLS is required.
    pub mtls: bool,
}

impl TlsTunnelAdapter {
    pub fn new(
        id: impl Into<String>,
        relay_host: impl Into<String>,
        relay_port: u16,
        sni: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            relay_host: relay_host.into(),
            relay_port,
            sni: sni.into(),
            mtls: false,
        }
    }

    #[must_use]
    pub fn with_mtls(mut self) -> Self {
        self.mtls = true;
        self
    }
}

impl DataPlaneAdapter for TlsTunnelAdapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_id: self.id.clone(),
            kind: AdapterKind::TlsTunnel,
            address: self.relay_host.clone(),
            port: self.relay_port,
            metadata: vec![
                ("sni".into(), self.sni.clone()),
                ("mtls".into(), self.mtls.to_string()),
            ],
        }
    }
}

/// Overrides DNS resolution for the destination to a specific resolver.
#[derive(Debug, Clone)]
pub struct DnsOverrideAdapter {
    pub id: String,
    /// The DNS resolver to use instead of the system default.
    pub resolver_host: String,
    pub resolver_port: u16,
    /// Whether to use DNS-over-TLS (DoT).
    pub dot: bool,
}

impl DnsOverrideAdapter {
    pub fn new(
        id: impl Into<String>,
        resolver_host: impl Into<String>,
        resolver_port: u16,
    ) -> Self {
        Self {
            id: id.into(),
            resolver_host: resolver_host.into(),
            resolver_port,
            dot: false,
        }
    }

    #[must_use]
    pub fn with_dot(mut self) -> Self {
        self.dot = true;
        self
    }
}

impl DataPlaneAdapter for DnsOverrideAdapter {
    fn adapter_id(&self) -> &str {
        &self.id
    }

    fn describe(&self) -> AdapterDescriptor {
        AdapterDescriptor {
            adapter_id: self.id.clone(),
            kind: AdapterKind::DnsOverride,
            address: self.resolver_host.clone(),
            port: self.resolver_port,
            metadata: vec![("dot".into(), self.dot.to_string())],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_adapter_descriptor() {
        let a = DirectAdapter::new("direct-default");
        let d = a.describe();
        assert_eq!(d.kind, AdapterKind::Direct);
        assert_eq!(d.port, 0);
    }

    #[test]
    fn socks5_adapter_descriptor() {
        let a = Socks5Adapter::new("socks5-exit", "proxy.example.com", 1080).with_auth("user:pass");
        let d = a.describe();
        assert_eq!(d.kind, AdapterKind::Socks5);
        assert_eq!(d.port, 1080);
        assert!(d.metadata.iter().any(|(k, _)| k == "auth"));
    }

    #[test]
    fn http_connect_adapter_descriptor() {
        let a = HttpConnectAdapter::new("http-proxy", "proxy.corp.com", 3128);
        let d = a.describe();
        assert_eq!(d.kind, AdapterKind::HttpConnect);
        assert!(d
            .metadata
            .iter()
            .any(|(k, v)| k == "method" && v == "CONNECT"));
    }

    #[test]
    fn tls_tunnel_adapter_with_mtls() {
        let a = TlsTunnelAdapter::new("tls-relay", "relay.example.com", 8443, "relay.example.com")
            .with_mtls();
        let d = a.describe();
        assert_eq!(d.kind, AdapterKind::TlsTunnel);
        assert!(d.metadata.iter().any(|(k, v)| k == "mtls" && v == "true"));
    }

    #[test]
    fn dns_override_adapter_dot() {
        let a = DnsOverrideAdapter::new("dns-dot", "1.1.1.1", 853).with_dot();
        let d = a.describe();
        assert_eq!(d.kind, AdapterKind::DnsOverride);
        assert!(d.metadata.iter().any(|(k, v)| k == "dot" && v == "true"));
    }
}
