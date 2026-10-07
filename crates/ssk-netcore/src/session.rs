#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};

use ssk_netadmin::AdapterKind;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::authority::unbracket;

/// A real transport: any concrete stream that can carry bytes to/from a real
/// peer. `Unpin` keeps every layer (`TcpStream`, `TlsStream<Box<dyn
/// Transport>>`, ...) boxable without `Pin`-projection ceremony.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Transport for T {}

/// A boxed, type-erased real transport, so a chain of heterogeneous adapters
/// (TCP -> SOCKS5 handshake -> TLS wrap -> ...) can be composed uniformly.
pub type BoxedTransport = Box<dyn Transport>;

/// How the daemon came by the address of one dial. A record of what happened,
/// not a promise about any path: it says nothing about which interface the
/// operating system chose or whether a third-party tunnel is involved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMode {
    /// The destination was an IP literal: no lookup happened.
    Literal,
    /// A host name, looked up exactly once by the OS resolver; the dial went
    /// to the answers themselves.
    OsResolver,
    /// A proxied route whose target is a host name: the daemon did no lookup,
    /// the upstream proxy resolves it.
    ForwardedUnresolved,
}

/// One dial as the executor saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialResolution {
    pub mode: ResolutionMode,
    /// The address the established socket is connected to; `None` when this
    /// process opened no socket for the party (a proxied target).
    pub dialed: Option<SocketAddr>,
    /// Every address a connect was started for, in start order.
    pub attempted: Vec<SocketAddr>,
    /// How many distinct addresses the resolver gave (after normalisation);
    /// `0` when nothing was looked up.
    pub answers: u8,
    /// The source address the OS gave the socket, read back from the socket
    /// after the connect. An observation: it adds no option and no bind.
    pub local_addr: Option<SocketAddr>,
}

impl DialResolution {
    /// The target of a proxied route: this process dials only the first hop,
    /// so the target has no socket of its own.
    pub(crate) fn forwarded(host: &str) -> Self {
        let mode = if unbracket(host).parse::<IpAddr>().is_ok() {
            ResolutionMode::Literal
        } else {
            ResolutionMode::ForwardedUnresolved
        };
        Self {
            mode,
            dialed: None,
            attempted: Vec::new(),
            answers: 0,
            local_addr: None,
        }
    }
}

/// The resolution facts of a whole session: the target, and for a proxy chain
/// also the first hop (the only socket this process opened).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResolution {
    pub target: DialResolution,
    pub first_hop: Option<DialResolution>,
}

/// A live egress connection produced by [`crate::RouteExecutor`]: the boxed
/// real transport plus a truthful record of every adapter it actually
/// traversed, in traversal order. This `chain` is the evidence a caller
/// presents to a user instead of a hardcoded `Protected`/`true` — it can only
/// ever list adapters a real handshake succeeded through.
pub struct EgressSession {
    transport: BoxedTransport,
    chain: Vec<AdapterKind>,
    target: (String, u16),
    resolution: SessionResolution,
}

impl std::fmt::Debug for EgressSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressSession")
            .field("chain", &self.chain)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl EgressSession {
    pub(crate) fn new(
        transport: BoxedTransport,
        chain: Vec<AdapterKind>,
        target: (String, u16),
        resolution: SessionResolution,
    ) -> Self {
        Self {
            transport,
            chain,
            target,
            resolution,
        }
    }

    /// Adapters actually traversed to establish this session, in order.
    #[must_use]
    pub fn chain(&self) -> &[AdapterKind] {
        &self.chain
    }

    /// The final destination this session carries traffic to.
    #[must_use]
    pub fn target(&self) -> &(String, u16) {
        &self.target
    }

    /// How the addresses of this session were obtained (see
    /// [`SessionResolution`]). Deliberately not part of the `Debug` output:
    /// the addresses are destination information.
    #[must_use]
    pub fn resolution(&self) -> &SessionResolution {
        &self.resolution
    }

    /// Mutable access to the underlying transport, for a caller that wants to
    /// exchange real application bytes over the established egress.
    pub fn transport_mut(&mut self) -> &mut BoxedTransport {
        &mut self.transport
    }

    /// Cleanly tears down the real transport (TCP FIN / TLS close-notify).
    /// This is the concrete mechanism behind a kill-switch: dropping a
    /// `RouteExecutor`-backed session actually closes the socket.
    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.transport.shutdown().await
    }
}
