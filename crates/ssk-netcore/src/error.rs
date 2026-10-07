#![forbid(unsafe_code)]

use std::time::Duration;

use ssk_netadmin::adapter::AdapterKind;
use thiserror::Error;

use crate::session::DialAttempts;

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
    /// No resolver slot was free within the bounded wait, or too many dials
    /// were already waiting for one. Nothing was looked up and no socket was
    /// opened; the caller may retry.
    #[error("name resolver busy: every lookup slot is in use")]
    ResolverBusy,
    /// The address guard refused at least one address a name resolved to, so
    /// no socket was opened for any of them (all or nothing: a mixed answer is
    /// what DNS rebinding looks like). `code` is the guard's static label of
    /// the first refusal. Neither the name nor an address is echoed.
    #[error("dial refused by the address guard ({code}): {refused} of {answers} answers")]
    AddressRefused {
        code: &'static str,
        /// How many of the answers the guard refused.
        refused: u8,
        /// How many distinct answers were checked; `0` for a literal.
        answers: u8,
    },
    /// Every address of the dial belongs to a family this executor does not
    /// use (see `RouteExecutor::with_address_families`). Nothing was dialled.
    #[error("no address of an enabled family to dial")]
    FamilyDisabled,
    /// A dial that started at least one connect and failed: the real error,
    /// and which addresses were tried. `code()` and `Display` are the real
    /// error's, so callers that only report the failure never see the wrapper.
    #[error("{source}")]
    DialFailed {
        source: Box<NetcoreError>,
        attempts: DialAttempts,
    },
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
            Self::ResolverBusy => "NETCORE_RESOLVER_BUSY",
            Self::AddressRefused { .. } => "NETCORE_ADDR_REFUSED",
            Self::FamilyDisabled => "NETCORE_FAMILY_DISABLED",
            Self::DialFailed { source, .. } => source.code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn the_dial_errors_have_stable_codes_and_a_wrapper_that_is_invisible() {
        let refused = NetcoreError::AddressRefused {
            code: "loopback",
            refused: 1,
            answers: 3,
        };
        assert_eq!(refused.code(), "NETCORE_ADDR_REFUSED");
        assert_eq!(
            NetcoreError::FamilyDisabled.code(),
            "NETCORE_FAMILY_DISABLED"
        );

        let wrapped = NetcoreError::DialFailed {
            source: Box::new(NetcoreError::Timeout(
                "svc.test:443".into(),
                Duration::from_secs(2),
            )),
            attempts: DialAttempts {
                answers: 2,
                attempted: vec![SocketAddr::from(([192, 0, 2, 1], 443))],
            },
        };
        assert_eq!(wrapped.code(), "NETCORE_TIMEOUT");
        assert_eq!(
            wrapped.to_string(),
            "connect to svc.test:443 timed out after 2s",
            "the wrapper changed what a caller prints"
        );
        // The wrapped error is reachable for a caller that wants it.
        assert!(std::error::Error::source(&wrapped).is_some());
    }
}
