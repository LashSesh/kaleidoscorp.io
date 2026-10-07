// Doubles for the two seams of `ssk-netcore` that decide what a `Direct` dial
// touches, shared through `include!` by the ingress tests (unit tests in
// `crates/ssk-daemon/src/ingress/` and the integration tests of `ssk-daemon`).
//
// * `FakeResolver` is a `NameResolver`: it answers from a table, never asks the
//   operating system, and records every call, so a test can say "resolved
//   exactly once" and "never resolved".
// * `RecordingConnector` is a `TcpConnector`: it opens no socket. It records
//   every address a connect was started for and answers from a table (connect,
//   fail with an error kind, or hang), so a test can say "nothing was dialled".
//
// Everything is `#[allow(dead_code)]` because each including file uses only part
// of it.

#[allow(dead_code)]
pub mod net_fakes {
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use ssk_netcore::{BoxFuture, Connected, NameResolver, TcpConnector};

    fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The source address every scripted connection reports.
    pub fn scripted_local_addr() -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 99], 4000))
    }

    #[derive(Default)]
    pub struct FakeResolver {
        answers: Mutex<HashMap<String, io::Result<Vec<IpAddr>>>>,
        calls: Mutex<Vec<(String, u16)>>,
    }

    impl FakeResolver {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// `name` resolves to these addresses.
        #[must_use]
        pub fn answering(self, name: &str, addrs: &[&str]) -> Self {
            let parsed = addrs
                .iter()
                .map(|a| a.parse::<IpAddr>().expect("test address"))
                .collect();
            locked(&self.answers).insert(name.to_owned(), Ok(parsed));
            self
        }

        /// `name` fails with this error kind.
        #[must_use]
        pub fn failing(self, name: &str, kind: io::ErrorKind) -> Self {
            locked(&self.answers).insert(name.to_owned(), Err(io::Error::from(kind)));
            self
        }

        /// Every `(name, port)` a lookup was started for, in order.
        pub fn calls(&self) -> Vec<(String, u16)> {
            locked(&self.calls).clone()
        }
    }

    impl NameResolver for FakeResolver {
        fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            locked(&self.calls).push((name.to_owned(), port));
            match locked(&self.answers).get(name) {
                Some(Ok(addrs)) => Ok(addrs.iter().map(|ip| SocketAddr::new(*ip, port)).collect()),
                Some(Err(error)) => Err(io::Error::from(error.kind())),
                None => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        }
    }

    /// What a scripted address does when it is dialled.
    #[derive(Clone, Copy)]
    pub enum Outcome {
        Connect,
        Fail(io::ErrorKind),
    }

    pub struct RecordingConnector {
        scripts: Mutex<HashMap<SocketAddr, Outcome>>,
        started: Mutex<Vec<SocketAddr>>,
    }

    impl RecordingConnector {
        /// Every address connects unless scripted otherwise.
        #[must_use]
        pub fn new() -> Self {
            Self {
                scripts: Mutex::new(HashMap::new()),
                started: Mutex::new(Vec::new()),
            }
        }

        #[must_use]
        pub fn script(self, addr: &str, outcome: Outcome) -> Self {
            locked(&self.scripts).insert(addr.parse().expect("test address"), outcome);
            self
        }

        /// Every address a connect was started for, in start order.
        pub fn started(&self) -> Vec<SocketAddr> {
            locked(&self.started).clone()
        }
    }

    impl TcpConnector for RecordingConnector {
        fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, io::Result<Connected>> {
            locked(&self.started).push(addr);
            let outcome = locked(&self.scripts)
                .get(&addr)
                .copied()
                .unwrap_or(Outcome::Connect);
            Box::pin(async move {
                match outcome {
                    Outcome::Connect => {
                        let (ours, _theirs) = tokio::io::duplex(64);
                        Ok(Connected {
                            transport: Box::new(ours),
                            local_addr: Some(scripted_local_addr()),
                        })
                    }
                    Outcome::Fail(kind) => Err(io::Error::from(kind)),
                }
            })
        }
    }
}
