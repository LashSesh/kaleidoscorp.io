//! What differs between operating systems for the loopback listener (design
//! 6.6): how to bind it, how long to keep trying, which hardening controls exist
//! and who owns a connection.
//!
//! A control that is `false` is absent, not unknown: `hardening: required` refuses
//! to serve without the ones it needs (types.rs `Controls`). Linux has an
//! exclusive bind (a live listener cannot be bound twice) and a peer check (the
//! owner of a connection from the kernel's table, proved by a self-test in THIS
//! environment). The audit store claim is the ledger backend's, composed by the
//! host: [`IngressPlatform::controls`] says whether the platform CAN keep a private
//! store, the host also asks the opened store.

use std::io;
use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

#[cfg(not(unix))]
use super::peer::no_controls;
use super::peer::{MissingControl, PeerAuthorizer};
use super::types::Controls;

/// How a bind that finds the port busy is retried (design 6.9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindRetryPolicy {
    /// The waits before each attempt, the first usually zero.
    Schedule(&'static [Duration]),
    /// A window that doubles up to a cap, until the window has passed.
    Doubling {
        first: Duration,
        cap: Duration,
        window: Duration,
    },
}

/// The Unix schedule: 0, 250, 500, 1000, 2000, 4000 ms (at most 7.75 s). Linux needs
/// no retry for `TIME_WAIT` (the listener is bound with `SO_REUSEADDR`); this covers
/// a predecessor that is still closing its listener.
pub const UNIX_BIND_SCHEDULE: [Duration; 6] = [
    Duration::ZERO,
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_millis(1000),
    Duration::from_millis(2000),
    Duration::from_millis(4000),
];

pub trait IngressPlatform: Send + Sync {
    /// The controls this platform has. Does real self-tests, so it may block for
    /// a few milliseconds; the answer is computed once.
    fn controls(&self) -> Controls;
    /// Why a missing control is missing (`INGRESS_HARDENING_UNAVAILABLE` lists
    /// them).
    fn missing(&self) -> Vec<MissingControl>;
    /// Binds the listener. Must be called inside the tokio runtime.
    ///
    /// # Errors
    /// The OS error; `AddrInUse` and `AddrNotAvailable` are the ones the host
    /// retries.
    fn bind(&self, addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener>;
    fn bind_retry(&self) -> BindRetryPolicy;
    /// `None` when this platform cannot say who connected.
    fn peer_authorizer(&self) -> Option<Arc<dyn PeerAuthorizer>>;
}

/// The platform of this build.
#[must_use]
pub fn default_platform() -> Arc<dyn IngressPlatform> {
    #[cfg(unix)]
    {
        Arc::new(UnixPlatform::new())
    }
    #[cfg(not(unix))]
    {
        Arc::new(UnsupportedPlatform)
    }
}

/// Plain `std` bind, non-blocking, handed to tokio. On Unix `std` sets
/// `SO_REUSEADDR`: a rebind next to `TIME_WAIT` sockets succeeds, a second bind to a
/// live listener still fails with `AddrInUse` (measured, design 26).
#[cfg(unix)]
fn bind_loopback(addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener> {
    let listener = std::net::TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

#[cfg(unix)]
pub use unix::{IdMapping, UnixPlatform};

#[cfg(unix)]
mod unix {
    use std::sync::OnceLock;

    use super::*;
    use crate::ingress::peer::{
        selftest, PeerTableService, ProcTableSource, ServiceTuning, TableSource,
    };

    type Factory = Box<dyn Fn() -> Box<dyn TableSource> + Send + Sync>;

    /// What the user namespace of this process does to the user ids in the kernel's
    /// tables. The table shows a connection's owner TRANSLATED into the namespace
    /// of the reader, and an owner the namespace does not map is shown as the
    /// overflow uid. A daemon whose own uid is the overflow uid would therefore
    /// take every unmapped account for itself (design 6.10, review item (h)).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct IdMapping {
        /// `/proc/sys/kernel/overflowuid`.
        pub overflow_uid: u32,
        /// Every range of `/proc/self/uid_map` maps an id to itself.
        pub identity: bool,
    }

    /// The kernel's own default, used when the file cannot be read.
    const DEFAULT_OVERFLOW_UID: u32 = 65534;

    impl IdMapping {
        /// A process in the initial namespace.
        #[must_use]
        pub const fn initial() -> Self {
            Self {
                overflow_uid: DEFAULT_OVERFLOW_UID,
                identity: true,
            }
        }

        /// From the text of the two files; `None` is a file that could not be read.
        /// Whatever cannot be understood is read as the answer that refuses.
        #[must_use]
        pub fn from_texts(overflow: Option<&str>, uid_map: Option<&str>) -> Self {
            let overflow_uid = overflow
                .and_then(|text| text.trim().parse::<u32>().ok())
                .unwrap_or(DEFAULT_OVERFLOW_UID);
            let identity = uid_map.is_some_and(|text| {
                let mut ranges = 0_usize;
                for line in text.lines().filter(|line| !line.trim().is_empty()) {
                    let mut fields = line.split_ascii_whitespace().map(str::parse::<u64>);
                    match (fields.next(), fields.next(), fields.next(), fields.next()) {
                        (Some(Ok(inside)), Some(Ok(outside)), Some(Ok(_count)), None)
                            if inside == outside =>
                        {
                            ranges = ranges.saturating_add(1);
                        }
                        _ => return false,
                    }
                }
                ranges > 0
            });
            Self {
                overflow_uid,
                identity,
            }
        }

        /// Reads this process's own view.
        #[must_use]
        pub fn read() -> Self {
            let overflow = std::fs::read_to_string("/proc/sys/kernel/overflowuid").ok();
            let uid_map = std::fs::read_to_string("/proc/self/uid_map").ok();
            Self::from_texts(overflow.as_deref(), uid_map.as_deref())
        }

        /// `true` when "the table says my uid" does not mean "the daemon's user".
        #[must_use]
        pub fn is_ambiguous_for(&self, uid: u32) -> bool {
            uid == self.overflow_uid || !self.identity
        }
    }

    /// The Linux platform, and the other Unixes with less to offer: there the peer
    /// check is unsupported because the kernel's table is Linux's.
    pub struct UnixPlatform {
        uids: (u32, u32),
        tables: Option<Factory>,
        tuning: ServiceTuning,
        /// `None`: read the real one when the verdict is made.
        mapping: Option<IdMapping>,
        verdict: OnceLock<Verdict>,
    }

    struct Verdict {
        controls: Controls,
        missing: Vec<MissingControl>,
        authorizer: Option<Arc<dyn PeerAuthorizer>>,
    }

    impl UnixPlatform {
        #[must_use]
        pub fn new() -> Self {
            let tables: Option<Factory> = if cfg!(target_os = "linux") {
                Some(Box::new(|| Box::new(ProcTableSource::new())))
            } else {
                None
            };
            let mut platform = Self::with(
                (
                    rustix::process::getuid().as_raw(),
                    rustix::process::geteuid().as_raw(),
                ),
                tables,
                ServiceTuning::DEFAULT,
            );
            platform.mapping = None;
            platform
        }

        /// For tests: other identities, another table source.
        #[must_use]
        pub fn with(uids: (u32, u32), tables: Option<Factory>, tuning: ServiceTuning) -> Self {
            Self {
                uids,
                tables,
                tuning,
                // A test names the identities it wants; the namespace it runs in
                // is not one of them (`with_mapping` says otherwise).
                mapping: Some(IdMapping::initial()),
                verdict: OnceLock::new(),
            }
        }

        /// For tests: another view of the user namespace.
        #[must_use]
        pub fn with_mapping(mut self, mapping: IdMapping) -> Self {
            self.mapping = Some(mapping);
            self
        }

        fn verdict(&self) -> &Verdict {
            self.verdict.get_or_init(|| self.decide())
        }

        fn decide(&self) -> Verdict {
            let (uid, euid) = self.uids;
            let fail = |reason: MissingControl| Verdict {
                controls: Controls {
                    exclusive_bind: true,
                    peer_check: false,
                    private_audit_store: true,
                },
                missing: vec![reason],
                authorizer: None,
            };
            let Some(tables) = &self.tables else {
                return fail(MissingControl::PeerCheckUnsupported);
            };
            // "Same user" has one meaning for the daemon's sockets: `getuid()`, as
            // in the IPC check. The kernel's table shows the creator's EFFECTIVE
            // uid, so the two agree only if the daemon is not running setuid.
            if uid != euid {
                return fail(MissingControl::IdentityAmbiguous);
            }
            let mapping = self.mapping.clone().unwrap_or_else(IdMapping::read);
            if mapping.is_ambiguous_for(uid) {
                return fail(MissingControl::IdentityAmbiguous);
            }
            let mut source = tables();
            if selftest(&mut *source, uid).is_err() {
                return fail(MissingControl::PeerSelftestFailed);
            }
            match PeerTableService::start(tables(), uid, self.tuning) {
                Ok(service) => Verdict {
                    controls: Controls {
                        exclusive_bind: true,
                        peer_check: true,
                        private_audit_store: true,
                    },
                    missing: Vec::new(),
                    authorizer: Some(Arc::new(service)),
                },
                Err(_) => fail(MissingControl::PeerSelftestFailed),
            }
        }
    }

    impl Default for UnixPlatform {
        fn default() -> Self {
            Self::new()
        }
    }

    impl IngressPlatform for UnixPlatform {
        fn controls(&self) -> Controls {
            self.verdict().controls
        }

        fn missing(&self) -> Vec<MissingControl> {
            self.verdict().missing.clone()
        }

        fn bind(&self, addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener> {
            bind_loopback(addr)
        }

        fn bind_retry(&self) -> BindRetryPolicy {
            BindRetryPolicy::Schedule(&UNIX_BIND_SCHEDULE)
        }

        fn peer_authorizer(&self) -> Option<Arc<dyn PeerAuthorizer>> {
            self.verdict().authorizer.clone()
        }
    }
}

/// A target with no ingress backend yet: nothing binds and no control exists.
/// `C-WIN0` replaces it on Windows with the baseline bind.
#[cfg(not(unix))]
pub struct UnsupportedPlatform;

#[cfg(not(unix))]
impl IngressPlatform for UnsupportedPlatform {
    fn controls(&self) -> Controls {
        no_controls()
    }

    fn missing(&self) -> Vec<MissingControl> {
        vec![MissingControl::PeerCheckUnsupported]
    }

    fn bind(&self, _addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    fn bind_retry(&self) -> BindRetryPolicy {
        BindRetryPolicy::Schedule(&UNIX_BIND_SCHEDULE)
    }

    fn peer_authorizer(&self) -> Option<Arc<dyn PeerAuthorizer>> {
        None
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr, TcpStream};

    use crate::ingress::peer::{PeerQuery, PeerVerdict, RawTables, ServiceTuning, TableSource};

    fn own() -> (u32, u32) {
        (
            rustix::process::getuid().as_raw(),
            rustix::process::geteuid().as_raw(),
        )
    }

    struct Failing;

    impl TableSource for Failing {
        fn read(&mut self) -> io::Result<RawTables> {
            Err(io::Error::other("hidden"))
        }
    }

    fn platform_with(
        uids: (u32, u32),
        tables: Option<Box<dyn Fn() -> Box<dyn TableSource> + Send + Sync>>,
    ) -> UnixPlatform {
        UnixPlatform::with(uids, tables, ServiceTuning::DEFAULT)
    }

    #[test]
    fn the_unix_schedule_is_the_documented_one_and_sums_to_seven_and_three_quarter_seconds() {
        let platform = platform_with(own(), None);
        let BindRetryPolicy::Schedule(waits) = platform.bind_retry() else {
            panic!("a schedule");
        };
        assert_eq!(
            waits,
            [
                Duration::ZERO,
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
            ]
        );
        assert_eq!(waits.iter().sum::<Duration>(), Duration::from_millis(7750));
    }

    #[test]
    fn identity_ambiguous_disables_peer_check() {
        // A setuid launch: real and effective uid differ. The table would show
        // the effective one, the IPC check compares the real one.
        let platform = platform_with(
            (1000, 0),
            Some(Box::new(|| Box::new(Failing) as Box<dyn TableSource>)),
        );
        assert_eq!(
            platform.controls(),
            Controls {
                exclusive_bind: true,
                peer_check: false,
                private_audit_store: true
            }
        );
        assert_eq!(platform.missing(), [MissingControl::IdentityAmbiguous]);
        assert!(platform.peer_authorizer().is_none());
    }

    fn working_tables() -> Option<Box<dyn Fn() -> Box<dyn TableSource> + Send + Sync>> {
        Some(Box::new(|| Box::new(Failing) as Box<dyn TableSource>))
    }

    #[test]
    fn a_daemon_whose_uid_is_the_overflow_uid_cannot_tell_a_stranger_from_itself() {
        // The table shows every account the namespace does not map as the overflow
        // uid. A daemon running as that uid would call all of them "the same user".
        let platform = platform_with((65534, 65534), working_tables());
        assert!(!platform.controls().peer_check);
        assert_eq!(platform.missing(), [MissingControl::IdentityAmbiguous]);
        assert!(platform.peer_authorizer().is_none());
        // The kernel's overflow uid can be changed (`/proc/sys/kernel/overflowuid`).
        let platform = platform_with((1000, 1000), working_tables()).with_mapping(IdMapping {
            overflow_uid: 1000,
            identity: true,
        });
        assert_eq!(platform.missing(), [MissingControl::IdentityAmbiguous]);
    }

    #[test]
    fn a_namespace_that_maps_ids_is_ambiguous_for_every_uid() {
        let platform = platform_with((1000, 1000), working_tables()).with_mapping(IdMapping {
            overflow_uid: 65534,
            identity: false,
        });
        assert!(!platform.controls().peer_check);
        assert_eq!(platform.missing(), [MissingControl::IdentityAmbiguous]);
    }

    #[test]
    fn the_id_mapping_is_read_from_the_two_files_and_unreadable_means_refuse() {
        let initial = "         0          0 4294967295\n";
        let identity = IdMapping::from_texts(Some("65534\n"), Some(initial));
        assert_eq!(identity, IdMapping::initial());
        assert!(!identity.is_ambiguous_for(1000));
        assert!(identity.is_ambiguous_for(65534));
        // Several ranges, each onto itself.
        assert!(IdMapping::from_texts(None, Some("0 0 1000\n1000 1000 1\n")).identity);
        // One range that moves ids: a rootless container.
        assert!(!IdMapping::from_texts(None, Some("0 1000 1\n")).identity);
        assert!(!IdMapping::from_texts(None, Some("0 0 1\n1 100000 65536\n")).identity);
        // Nothing, garbage, a short or long line: refused, never assumed.
        for bad in [
            "",
            "\n",
            "garbage",
            "0 0\n",
            "0 0 1 1\n",
            "0 x 1\n",
            "-1 -1 1\n",
        ] {
            assert!(!IdMapping::from_texts(None, Some(bad)).identity, "{bad:?}");
        }
        assert!(!IdMapping::from_texts(None, None).identity, "unreadable");
        // The overflow uid: the file, else the kernel's default.
        assert_eq!(
            IdMapping::from_texts(Some("4242\n"), None).overflow_uid,
            4242
        );
        assert_eq!(IdMapping::from_texts(Some("x"), None).overflow_uid, 65534);
        assert_eq!(IdMapping::from_texts(None, None).overflow_uid, 65534);
        // Whatever the answer, an id that is not the overflow uid is fine if the
        // map is the identity.
        assert!(!IdMapping::initial().is_ambiguous_for(0));
    }

    #[test]
    fn a_platform_with_no_table_source_has_no_peer_check() {
        let platform = platform_with(own(), None);
        assert!(!platform.controls().peer_check);
        assert!(platform.controls().exclusive_bind);
        assert_eq!(platform.missing(), [MissingControl::PeerCheckUnsupported]);
        assert!(platform.peer_authorizer().is_none());
    }

    #[test]
    fn a_failing_self_test_disables_the_peer_check_with_its_reason() {
        let platform = platform_with(
            own(),
            Some(Box::new(|| Box::new(Failing) as Box<dyn TableSource>)),
        );
        assert!(!platform.controls().peer_check);
        assert_eq!(platform.missing(), [MissingControl::PeerSelftestFailed]);
        assert!(platform.peer_authorizer().is_none());
    }

    #[test]
    fn the_verdict_is_computed_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        let made = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&made);
        let platform = platform_with(
            own(),
            Some(Box::new(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::new(Failing) as Box<dyn TableSource>
            })),
        );
        for _ in 0..3 {
            let _ = platform.controls();
            let _ = platform.missing();
            let _ = platform.peer_authorizer();
        }
        assert_eq!(made.load(Ordering::SeqCst), 1, "one self-test, not three");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_default_platform_on_linux_has_all_its_controls_and_authorizes_a_real_client() {
        let platform = default_platform();
        assert_eq!(
            platform.controls(),
            Controls {
                exclusive_bind: true,
                peer_check: true,
                private_audit_store: true
            }
        );
        assert!(platform.missing().is_empty());
        let authorizer = platform.peer_authorizer().expect("an authorizer");
        let listener = platform
            .bind(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("binds");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (accepted, _) = listener.accept().await.expect("accept");
        let query = PeerQuery {
            client: client.local_addr().expect("client"),
            listener: accepted.local_addr().expect("listener"),
        };
        assert_eq!(authorizer.authorize(query).await, PeerVerdict::SameUser);
    }

    #[tokio::test]
    async fn second_bind_to_live_listener_fails_on_linux() {
        let platform = platform_with(own(), None);
        let first = platform
            .bind(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("binds");
        let SocketAddr::V4(addr) = first.local_addr().expect("addr") else {
            panic!("IPv4");
        };
        let second = platform.bind(addr);
        assert_eq!(
            second.err().map(|e| e.kind()),
            Some(io::ErrorKind::AddrInUse),
            "a live listener cannot be bound twice, SO_REUSEADDR or not"
        );
    }

    #[tokio::test]
    async fn a_rebind_next_to_time_wait_sockets_succeeds() {
        let platform = platform_with(own(), None);
        let first = platform
            .bind(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("binds");
        let SocketAddr::V4(addr) = first.local_addr().expect("addr") else {
            panic!("IPv4");
        };
        let client = TcpStream::connect(addr).expect("connect");
        let (accepted, _) = first.accept().await.expect("accept");
        // The side that closes first keeps the TIME_WAIT: close the accepted one first.
        drop(accepted);
        drop(client);
        drop(first);
        let again = platform.bind(addr);
        assert!(again.is_ok(), "{:?}", again.err());
    }

    #[tokio::test]
    async fn a_bind_that_is_refused_says_why() {
        let platform = platform_with(own(), None);
        // The address of another machine: not ours to bind.
        let result = platform.bind(std::net::SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 7),
            0,
        ));
        assert!(matches!(
            result.err().map(|e| e.kind()),
            Some(io::ErrorKind::AddrNotAvailable)
        ));
    }
}
