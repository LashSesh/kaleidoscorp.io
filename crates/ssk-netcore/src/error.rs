#![forbid(unsafe_code)]

use std::time::Duration;

use ssk_netadmin::adapter::AdapterKind;
use thiserror::Error;

/// Every real-egress failure the executor can produce, typed so the daemon
/// and CLI can surface a fail-closed reason instead of a bare `false`.
///
/// This is the concrete "explicit failure reasons" half of the SSKΩ-7
/// contract (`docs/ARCHITECTURE_COMPLETION_SPEC.md` §3.2 "MockDataPlane ->
/// real RouteExecutor"): every variant below corresponds to a real, typed
/// cause a caller can act on, never a silent `None`/`false`.
#[derive(Debug, Error)]
pub enum NetcoreError {
    #[error("OpenVPN profile `{0}` is configured but broker integration is not available")]
    OpenVpnNotReady(String),
    #[error("connect to {0} timed out after {1:?}")]
    Timeout(String, Duration),
    #[error("connection to {0} refused: {1}")]
    ConnectionRefused(String, String),
    #[error("dns resolution of `{0}` via {1} failed: {2}")]
    DnsResolutionFailed(String, String, String),
    #[error("tls handshake with {0} failed: {1}")]
    TlsHandshakeFailed(String, String),
    #[error("proxy at {0} rejected the request: {1}")]
    ProxyRejected(String, String),
    #[error("no real executor implemented for adapter kind {0:?}")]
    Unsupported(AdapterKind),
    #[error("egress denied by policy: {0}")]
    PolicyDenied(String),
    #[error("no viable route: {0}")]
    NoRoute(String),
    #[error("adapter `{0}` referenced by the route is not registered")]
    UnknownAdapter(String),
    #[error("i/o error talking to {0}: {1}")]
    Io(String, std::io::Error),
    #[error("malformed protocol response from {0}: {1}")]
    ProtocolError(String, String),
    /// Refused locally before any byte reached a proxy. The message never
    /// echoes the offending target: it is client-influenced text and could
    /// carry line breaks into logs.
    #[error("invalid dial target: {0}")]
    InvalidTarget(String),
}

impl NetcoreError {
    /// Stable, machine-readable code (mirrors `ssk-daemon`'s `explain_code`
    /// convention) so a caller can `match` without string-comparing
    /// `Display` output.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::OpenVpnNotReady(_) => "OPENVPN_NOT_READY",
            Self::Timeout(..) => "NETCORE_TIMEOUT",
            Self::ConnectionRefused(..) => "NETCORE_CONNECTION_REFUSED",
            Self::DnsResolutionFailed(..) => "NETCORE_DNS_FAILED",
            Self::TlsHandshakeFailed(..) => "NETCORE_TLS_FAILED",
            Self::ProxyRejected(..) => "NETCORE_PROXY_REJECTED",
            Self::Unsupported(_) => "NETCORE_UNSUPPORTED_ADAPTER",
            Self::PolicyDenied(_) => "NETCORE_POLICY_DENIED",
            Self::NoRoute(_) => "NETCORE_NO_ROUTE",
            Self::UnknownAdapter(_) => "NETCORE_UNKNOWN_ADAPTER",
            Self::Io(..) => "NETCORE_IO_ERROR",
            Self::ProtocolError(..) => "NETCORE_PROTOCOL_ERROR",
            Self::InvalidTarget(_) => "NETCORE_INVALID_TARGET",
        }
    }
}
