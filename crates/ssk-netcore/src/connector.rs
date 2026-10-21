#![forbid(unsafe_code)]

//! The one place a socket is created for a dial.
//!
//! The executor never opens a socket itself: every dial, a literal, a pinned
//! answer of a name, the first hop of a chain, ends in
//! [`TcpConnector::connect`]. Its only parameter is the destination, so no
//! caller can ask for an interface or a source address through it, which is
//! what keeps a `Direct` dial under the operating system's routing table (CO-1
//! of `docs/M2_LOCAL_INGRESS_DESIGN.md`). It is also the seam that lets a test
//! script the outcome and timing of each address without a network.

use std::io;
use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::data_plane::BoxFuture;
use crate::session::BoxedTransport;

/// An established connection and what the dial may record about it.
pub struct Connected {
    pub transport: BoxedTransport,
    /// The source address the OS gave the socket, read back after the connect.
    /// An observation: reading it adds no option and no bind.
    pub local_addr: Option<SocketAddr>,
}

/// Opens one TCP connection to one address. Implementations must not look a
/// name up (an address is all there is to dial) and must not choose an
/// interface or a source address: the operating system decides both.
pub trait TcpConnector: Send + Sync + 'static {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>>;
}

/// The operating system's TCP stack, reached through tokio, and nothing else.
/// A static test pins `open` to exactly one call, so that this stays true.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsConnector;

impl OsConnector {
    /// The socket-creating call of every dial. Kept apart from the trait
    /// method so a test can look at the socket that production code made.
    pub(crate) async fn open(addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

impl TcpConnector for OsConnector {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>> {
        Box::pin(async move {
            let stream = Self::open(addr).await?;
            let local_addr = stream.local_addr().ok();
            Ok(Connected {
                transport: Box::new(stream),
                local_addr,
            })
        })
    }
}

/// A connector whose answers a test writes down in advance, so a dial can be
/// followed in paused time with no socket and no network.
#[cfg(test)]
pub(crate) mod fakes {
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::Duration;

    use tokio::time::{sleep, Instant};

    use super::*;

    /// What one address does when it is dialled.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum Script {
        /// Connects after this long.
        Connect(Duration),
        /// Fails with this kind after this long.
        Fail(Duration, io::ErrorKind),
        /// Never answers: a blackholed address.
        Hang,
        /// The connector itself is broken.
        Panic,
    }

    impl Script {
        pub(crate) const REFUSED: Script =
            Script::Fail(Duration::ZERO, io::ErrorKind::ConnectionRefused);
        pub(crate) const NOW: Script = Script::Connect(Duration::ZERO);
    }

    /// The source address every scripted connection reports.
    pub(crate) fn scripted_local_addr() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 99], 4000))
    }

    #[derive(Default)]
    struct State {
        started: Vec<(SocketAddr, Instant)>,
        live: usize,
        max_live: usize,
        dropped: Vec<SocketAddr>,
    }

    pub(crate) struct ScriptedConnector {
        scripts: HashMap<SocketAddr, Script>,
        otherwise: Script,
        state: Mutex<State>,
    }

    impl ScriptedConnector {
        /// Every address not scripted does `otherwise`.
        pub(crate) fn new(otherwise: Script) -> Self {
            Self {
                scripts: HashMap::new(),
                otherwise,
                state: Mutex::new(State::default()),
            }
        }

        pub(crate) fn script(mut self, addr: SocketAddr, script: Script) -> Self {
            self.scripts.insert(addr, script);
            self
        }

        fn state(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Every address a connect was started for, in start order.
        pub(crate) fn started(&self) -> Vec<SocketAddr> {
            self.state().started.iter().map(|(addr, _)| *addr).collect()
        }

        /// When each connect was started, relative to `origin`.
        pub(crate) fn started_after(&self, origin: Instant) -> Vec<(SocketAddr, Duration)> {
            self.state()
                .started
                .iter()
                .map(|(addr, at)| (*addr, at.duration_since(origin)))
                .collect()
        }

        /// Connects in flight now, that is started and neither finished nor
        /// dropped.
        pub(crate) fn live(&self) -> usize {
            self.state().live
        }

        /// The most connects that were ever in flight at once.
        pub(crate) fn max_live(&self) -> usize {
            self.state().max_live
        }

        /// Addresses whose connect future ended (finished or was dropped), in
        /// that order.
        pub(crate) fn ended(&self) -> Vec<SocketAddr> {
            self.state().dropped.clone()
        }

        fn begin(&self, addr: SocketAddr) -> Live<'_> {
            let mut state = self.state();
            state.started.push((addr, Instant::now()));
            state.live += 1;
            state.max_live = state.max_live.max(state.live);
            Live {
                connector: self,
                addr,
            }
        }

        fn connected() -> Connected {
            let (ours, _theirs) = tokio::io::duplex(8);
            Connected {
                transport: Box::new(ours),
                local_addr: Some(scripted_local_addr()),
            }
        }
    }

    /// Dropped when the connect future ends, however it ends.
    struct Live<'a> {
        connector: &'a ScriptedConnector,
        addr: SocketAddr,
    }

    impl Drop for Live<'_> {
        fn drop(&mut self) {
            let mut state = self.connector.state();
            state.live = state.live.saturating_sub(1);
            state.dropped.push(self.addr);
        }
    }

    impl TcpConnector for ScriptedConnector {
        fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>> {
            Box::pin(async move {
                let _live = self.begin(addr);
                match self.scripts.get(&addr).copied().unwrap_or(self.otherwise) {
                    Script::Connect(after) => {
                        pause(after).await;
                        Ok(Self::connected())
                    }
                    Script::Fail(after, kind) => {
                        pause(after).await;
                        Err(io::Error::new(kind, "scripted failure"))
                    }
                    Script::Hang => std::future::pending().await,
                    Script::Panic => panic!("a scripted connector bug"),
                }
            })
        }
    }

    /// `sleep(ZERO)` still yields once; an instant answer must not.
    async fn pause(after: Duration) {
        if !after.is_zero() {
            sleep(after).await;
        }
    }
}
