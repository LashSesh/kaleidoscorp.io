#![forbid(unsafe_code)]

use ssk_netadmin::AdapterKind;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// A real transport: any concrete stream that can carry bytes to/from a real
/// peer. `Unpin` keeps every layer (`TcpStream`, `TlsStream<Box<dyn
/// Transport>>`, ...) boxable without `Pin`-projection ceremony.
pub trait Transport: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + ?Sized> Transport for T {}

/// A boxed, type-erased real transport, so a chain of heterogeneous adapters
/// (TCP -> SOCKS5 handshake -> TLS wrap -> ...) can be composed uniformly.
pub type BoxedTransport = Box<dyn Transport>;

/// A live egress connection produced by [`crate::RouteExecutor`]: the boxed
/// real transport plus a truthful record of every adapter it actually
/// traversed, in traversal order. This `chain` is the evidence a caller
/// presents to a user instead of a hardcoded `Protected`/`true` — it can only
/// ever list adapters a real handshake succeeded through.
pub struct EgressSession {
    transport: BoxedTransport,
    chain: Vec<AdapterKind>,
    target: (String, u16),
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
    ) -> Self {
        Self {
            transport,
            chain,
            target,
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
