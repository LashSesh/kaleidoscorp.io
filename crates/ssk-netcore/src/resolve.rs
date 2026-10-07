#![forbid(unsafe_code)]

//! Name resolution for a `Direct` dial, and the bound on it.
//!
//! tokio's `TcpStream::connect((host, port))` runs `getaddrinfo` on the
//! runtime's blocking pool (512 threads by default) and cannot cancel it:
//! `timeout()` drops the future, the thread keeps running until the OS call
//! returns. Enough hung lookups (a dead DNS server, a client that opens many
//! cold names) would take every blocking thread and stall each other user of
//! the pool. So a name is never handed to tokio's dial; it goes through
//! [`BoundedResolver::resolve_once`], where the permit that limits concurrent
//! lookups lives inside the lookup thread and is returned only when the OS
//! call has really returned, whatever the callers' deadlines did.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};

use crate::authority::authority;
use crate::error::NetcoreError;

/// Lookups that may run at once, which is also the most blocking-pool threads
/// lookups can ever hold. Public because the ingress's descriptor budget is
/// derived from it (`ssk-daemon` `ingress/budget.rs`).
pub const MAX_CONCURRENT_LOOKUPS: usize = 16;
/// Dials that may wait for a free lookup slot; the next one fails at once.
pub(crate) const RESOLVER_WAITERS: usize = 32;
/// How long a dial waits for a slot before it fails with `ResolverBusy`. A
/// burst of fast lookups (the normal case) is absorbed; a client does not
/// retry a refusal, so failing the 17th name at once would lose it for good.
pub(crate) const RESOLVER_WAIT: Duration = Duration::from_millis(500);
/// Bound on one `resolve_once`, counted from the call: the wait is inside it.
pub(crate) const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// Distinct answers kept from one lookup.
pub(crate) const MAX_ANSWERS: usize = 32;

/// Label of the resolver in `DnsResolutionFailed`.
const RESOLVER_LABEL: &str = "os-resolver";

/// A blocking name lookup. The seam that lets tests count and script lookups
/// without touching the network.
pub trait NameResolver: Send + Sync + 'static {
    /// BLOCKING; called only from a thread that may block (never from an async
    /// task). `name` has already passed [`is_resolvable_name`].
    fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// The operating system's resolver (`getaddrinfo` through
/// `std::net::ToSocketAddrs`), answers in the order the OS gave them. It adds
/// no cache: a cache would be a second place that decides which address a name
/// means.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsResolver;

impl NameResolver for OsResolver {
    fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (name, port).to_socket_addrs().map(Iterator::collect)
    }
}

/// `true` when `name` may be handed to a resolver: a DNS name of ASCII labels
/// (letters, digits and inner hyphens, 1 to 63 bytes each), at most 253 bytes
/// (one trailing dot allowed and not counted), whose final label starts with a
/// letter.
///
/// The final-label rule is what keeps numeric aliases out: the OS resolver
/// dials `127.1`, `0x7f.0.0.1`, `010.0.0.1` and `2130706433` as IPv4
/// addresses, every such spelling ends in a label that starts with a digit, and
/// a real top-level label never does (punycode `xn--` starts with a letter).
/// An IP literal never passes either: IPv4 ends in a digit and IPv6 has `:`.
/// Defence in depth below the front end's canonicalisation, which already
/// produces only such names. The grammar is that of `ssk_config`'s `valid_host`
/// for names, which is what an activation destination and an adapter host are
/// checked with before they reach this crate, so nothing they accept is refused
/// here; `is_resolvable_name_agrees_with_the_shared_host_corpus` pins that.
#[must_use]
pub fn is_resolvable_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            (1..=63).contains(&bytes.len())
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        })
        && name
            .rsplit('.')
            .next()
            .is_some_and(|label| label.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// What a lookup answered, made fit to dial: `::ffff:a.b.c.d` becomes the IPv4
/// address, exact duplicates are dropped (the first occurrence stays), and at
/// most [`MAX_ANSWERS`] remain, in the resolver's order.
///
/// Only `to_ipv4_mapped` may unmap: `to_ipv4` would also turn `::1` into
/// `0.0.0.1`.
pub(crate) fn normalise_answers(answers: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for answer in answers {
        let answer = match answer {
            SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
                Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
                None => answer,
            },
            SocketAddr::V4(_) => answer,
        };
        if seen.insert(answer) {
            kept.push(answer);
            if kept.len() == MAX_ANSWERS {
                break;
            }
        }
    }
    kept
}

const LOOKUP_RUNNING: u8 = 0;
const LOOKUP_FINISHED: u8 = 1;
const LOOKUP_ABANDONED: u8 = 2;

/// One lookup thread, seen from both sides. A lookup whose caller stopped
/// waiting while the OS call is still running is "abandoned", and counted until
/// that call returns: its permit stays taken, so the count says how many of
/// the permits are pinned by calls that nobody waits for any more.
struct Lookup {
    state: AtomicU8,
    abandoned: Arc<AtomicUsize>,
}

impl Lookup {
    /// The caller leaves: its deadline passed or its future was dropped. When
    /// the lookup already finished (the normal case) this changes nothing.
    fn abandon(&self) {
        // Count first, then claim: the thread's decrement is only ever done
        // after it saw the claim, so the counter never underflows.
        self.abandoned.fetch_add(1, Ordering::AcqRel);
        if self
            .state
            .compare_exchange(
                LOOKUP_RUNNING,
                LOOKUP_ABANDONED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // The thread finished in between: nothing is outstanding.
            self.abandoned.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// The OS call has returned (or the thread is unwinding).
    fn finish(&self) {
        if self
            .state
            .compare_exchange(
                LOOKUP_RUNNING,
                LOOKUP_FINISHED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            // The caller had abandoned this lookup and counted it.
            self.abandoned.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Lives in the lookup thread. Dropping it, also while the thread unwinds from
/// a panicking resolver, first settles the abandoned count and only then
/// returns the permit, so a reader that sees the permit free also sees the
/// count settled.
struct LookupExit {
    lookup: Arc<Lookup>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for LookupExit {
    fn drop(&mut self) {
        self.lookup.finish();
    }
}

/// Held by the waiting side; leaving early abandons the lookup.
struct AbandonOnDrop(Arc<Lookup>);

impl Drop for AbandonOnDrop {
    fn drop(&mut self) {
        self.0.abandon();
    }
}

/// A [`NameResolver`] behind a permit bound, a bounded wait and a deadline.
pub(crate) struct BoundedResolver {
    inner: Arc<dyn NameResolver>,
    permits: Arc<Semaphore>,
    waiters: Arc<Semaphore>,
    timeout: Duration,
    abandoned: Arc<AtomicUsize>,
}

impl BoundedResolver {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(OsResolver),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_LOOKUPS)),
            waiters: Arc::new(Semaphore::new(RESOLVER_WAITERS)),
            timeout: RESOLVE_TIMEOUT,
            abandoned: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(crate) fn with_resolver(mut self, resolver: Arc<dyn NameResolver>) -> Self {
        self.inner = resolver;
        self
    }

    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replaces the permit pool, so it belongs to construction time: a lookup
    /// already running keeps the permit of the pool it started in. Clamped to
    /// what a semaphore can hold (and to at least one, so a mistaken zero does
    /// not turn every name into `ResolverBusy`).
    pub(crate) fn with_max_concurrent(mut self, lookups: usize) -> Self {
        self.permits = Arc::new(Semaphore::new(lookups.clamp(1, Semaphore::MAX_PERMITS)));
        self
    }

    /// Lookups whose caller stopped waiting while the OS call is still
    /// running: each still holds one permit.
    pub(crate) fn abandoned(&self) -> usize {
        self.abandoned.load(Ordering::Acquire)
    }

    /// Resolves `name` with ONE call to the resolver and never repeats it. The
    /// caller owns that rule: a failed connect, a second address or a retry
    /// must not come back here.
    ///
    /// `name` has passed [`is_resolvable_name`]. Failures: no slot within
    /// [`RESOLVER_WAIT`], or more than [`RESOLVER_WAITERS`] dials already
    /// waiting, is `ResolverBusy`; the deadline is `Timeout`; an OS error or an
    /// empty answer is `DnsResolutionFailed`.
    pub(crate) async fn resolve_once(
        &self,
        name: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, NetcoreError> {
        let started = Instant::now();
        // At most RESOLVER_WAITERS dials wait for a permit; the next one fails
        // at once, so the queue cannot grow without bound.
        let Ok(waiter) = Arc::clone(&self.waiters).try_acquire_owned() else {
            return Err(NetcoreError::ResolverBusy);
        };
        let permit = match timeout(RESOLVER_WAIT, Arc::clone(&self.permits).acquire_owned()).await {
            Ok(Ok(permit)) => permit,
            // The wait ran out, or the semaphore is closed (nothing closes it).
            Ok(Err(_)) | Err(_) => return Err(NetcoreError::ResolverBusy),
        };
        drop(waiter);

        let lookup = Arc::new(Lookup {
            state: AtomicU8::new(LOOKUP_RUNNING),
            abandoned: Arc::clone(&self.abandoned),
        });
        let (answer_tx, answer_rx) = oneshot::channel();
        let exit = LookupExit {
            lookup: Arc::clone(&lookup),
            _permit: permit,
        };
        let resolver = Arc::clone(&self.inner);
        let owned_name = name.to_owned();
        // The permit lives in the thread, not here: this call can give up (the
        // deadline, or its future dropped by an outer deadline) while
        // `getaddrinfo` runs on, and the permit must stay taken until it returns.
        // The handle is not kept: the answer travels through the channel.
        tokio::task::spawn_blocking(move || {
            let answer = resolver.resolve(&owned_name, port);
            drop(exit);
            let _ = answer_tx.send(answer);
        });
        let _abandon_if_we_leave = AbandonOnDrop(lookup);

        let remaining = self.timeout.saturating_sub(started.elapsed());
        match timeout(remaining, answer_rx).await {
            Ok(Ok(Ok(answers))) if !answers.is_empty() => Ok(answers),
            Ok(Ok(Ok(_))) => Err(dns_failed(name, "no addresses")),
            Ok(Ok(Err(err))) => Err(dns_failed(name, &err.to_string())),
            // The thread ended without an answer: the resolver panicked.
            Ok(Err(_)) => Err(dns_failed(name, "the lookup ended without an answer")),
            Err(_) => Err(NetcoreError::Timeout(authority(name, port), self.timeout)),
        }
    }
}

fn dns_failed(name: &str, reason: &str) -> NetcoreError {
    NetcoreError::DnsResolutionFailed(
        name.to_owned(),
        RESOLVER_LABEL.to_owned(),
        reason.to_owned(),
    )
}

/// Fakes and helpers shared by the tests of this crate that need a resolver.
/// None of them touches the network; only `os_resolver_resolves_localhost`
/// calls the real OS resolver.
#[cfg(test)]
pub(crate) mod fakes {
    use std::collections::HashSet;
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};

    use super::*;

    type Answer = Box<dyn Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync>;

    /// Answers every lookup from a closure and remembers each call.
    pub(crate) struct CountingResolver {
        calls: Mutex<Vec<(String, u16)>>,
        answer: Answer,
    }

    impl CountingResolver {
        pub(crate) fn new(
            answer: impl Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync + 'static,
        ) -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                answer: Box::new(answer),
            })
        }

        /// The same answers for every name.
        pub(crate) fn answering(addrs: Vec<SocketAddr>) -> Arc<Self> {
            Self::new(move |_, _| Ok(addrs.clone()))
        }

        /// Every `(name, port)` this resolver was asked, in call order.
        pub(crate) fn calls(&self) -> Vec<(String, u16)> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl NameResolver for CountingResolver {
        fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((name.to_owned(), port));
            (self.answer)(name, port)
        }
    }

    /// A real thread-blocking latch: a lookup of a name that starts with
    /// `stuck` parks inside [`Gate::hold`] until the test releases that name
    /// (or all of them), like a `getaddrinfo` that waits for a dead DNS server.
    pub(crate) struct Gate {
        state: Mutex<GateState>,
        changed: Condvar,
    }

    #[derive(Default)]
    struct GateState {
        entered: usize,
        released: HashSet<String>,
        all: bool,
    }

    /// A parked lookup gives up on its own after this long, so a test that
    /// fails before it can release the gate cannot hang the runtime's
    /// shutdown for ever.
    const HOLD_LIMIT: Duration = Duration::from_secs(30);

    impl Gate {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(GateState::default()),
                changed: Condvar::new(),
            })
        }

        fn lock(&self) -> MutexGuard<'_, GateState> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        fn hold(&self, name: &str) {
            let mut state = self.lock();
            state.entered += 1;
            self.changed.notify_all();
            let give_up = std::time::Instant::now() + HOLD_LIMIT;
            while !(state.all || state.released.contains(name)) {
                let left = give_up.saturating_duration_since(std::time::Instant::now());
                if left.is_zero() {
                    break;
                }
                state = self
                    .changed
                    .wait_timeout(state, left)
                    .unwrap_or_else(PoisonError::into_inner)
                    .0;
            }
        }

        /// How many lookups have reached the latch so far.
        pub(crate) fn entered(&self) -> usize {
            self.lock().entered
        }

        pub(crate) fn release(&self, name: &str) {
            self.lock().released.insert(name.to_owned());
            self.changed.notify_all();
        }

        pub(crate) fn release_all(&self) {
            self.lock().all = true;
            self.changed.notify_all();
        }
    }

    /// Opens the gate when the test ends, however it ends: a lookup thread
    /// still parked would otherwise keep the runtime from shutting down.
    pub(crate) struct ReleaseOnDrop(pub(crate) Arc<Gate>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release_all();
        }
    }

    /// Parks names that start with `stuck` at the gate; answers every other
    /// name at once.
    pub(crate) struct GatedResolver {
        gate: Arc<Gate>,
        answer: Vec<SocketAddr>,
    }

    impl GatedResolver {
        pub(crate) fn new(gate: Arc<Gate>, answer: Vec<SocketAddr>) -> Arc<Self> {
            Arc::new(Self { gate, answer })
        }
    }

    impl NameResolver for GatedResolver {
        fn resolve(&self, name: &str, _port: u16) -> io::Result<Vec<SocketAddr>> {
            if name.starts_with("stuck") {
                self.gate.hold(name);
            }
            Ok(self.answer.clone())
        }
    }

    pub(crate) fn addr(text: &str) -> SocketAddr {
        text.parse().expect("a socket address")
    }

    /// Lets every ready task run, and lets real threads run in between. A
    /// lookup needs the runtime to be polled before it reaches
    /// `spawn_blocking`, the tests run on one thread, and a lookup that is not
    /// held at the gate answers within microseconds: after this, "it has not
    /// finished" means it was really held back, not that its thread was slow
    /// to start. Passing code never depends on the pause; it only gives a
    /// wrongly unbounded lookup time to show itself.
    pub(crate) async fn settle() {
        for _ in 0..2 {
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits, in real time, for `condition`; the lookups run on real threads.
    pub(crate) async fn until(what: &str, condition: impl Fn() -> bool) {
        let started = std::time::Instant::now();
        while !condition() {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "timed out waiting for {what}"
            );
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub(crate) fn spawn_lookup(
        resolver: &Arc<BoundedResolver>,
        name: &str,
    ) -> tokio::task::JoinHandle<Result<Vec<SocketAddr>, NetcoreError>> {
        let resolver = Arc::clone(resolver);
        let name = name.to_owned();
        tokio::spawn(async move { resolver.resolve_once(&name, 443).await })
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::advance;

    use super::fakes::*;
    use super::*;

    const ANSWER: &str = "192.0.2.7:443";

    #[test]
    fn names_are_accepted_and_everything_else_is_refused() {
        for name in [
            "example.com",
            "a",
            "localhost",
            "my-host.example",
            "EXAMPLE.COM",
            "example.com.",
            "xn--p1ai",
            "1password.com",
            "10.0.0.1.nip.io",
        ] {
            assert!(is_resolvable_name(name), "{name:?} is a name");
        }
        for name in [
            "",
            ".",
            "..",
            "a..b",
            "example.com..",
            "-a.example",
            "a-.example",
            "a_b.example",
            "exa mple.com",
            "example.com\n",
            "a\0b.example",
            "example.com:443",
            "b\u{fc}cher.example",
            "[example.com]",
            // Addresses in every spelling, and the numeric aliases the OS
            // resolver dials as IPv4 addresses.
            "127.0.0.1",
            "::1",
            "[::1]",
            "::ffff:10.0.0.1",
            "fe80::1%eth0",
            "127.1",
            "0x7f.1",
            "0x7f000001",
            "010.0.0.1",
            "2130706433",
            "127.0.0.1.",
        ] {
            assert!(!is_resolvable_name(name), "{name:?} is not a name");
        }
    }

    #[test]
    fn name_length_limits_are_63_per_label_and_253_in_all() {
        let label63 = "a".repeat(63);
        let name253 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(61));
        assert_eq!(name253.len(), 253);
        assert!(is_resolvable_name(&format!("{label63}.example")));
        assert!(!is_resolvable_name(&format!("{}.example", "a".repeat(64))));
        assert!(is_resolvable_name(&name253));
        assert!(is_resolvable_name(&format!("{name253}.")));
        assert!(!is_resolvable_name(&format!("{name253}a")));
    }

    /// The name grammar is written down three times (ssk-config, ssk-netadmin
    /// and here, which cannot depend on either); one shared table keeps them
    /// from drifting apart.
    mod host_corpus {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/support/host_corpus.rs"
        ));

        use crate::resolve::is_resolvable_name;

        #[test]
        fn is_resolvable_name_agrees_with_the_shared_host_corpus() {
            let corpus = host_corpus();
            let mut disagreements = Vec::new();
            for case in &corpus {
                let expected = case.class == HostClass::Name;
                if is_resolvable_name(&case.host) != expected {
                    disagreements.push(format!("{:?} ({:?})", case.host, case.class));
                }
            }
            assert!(
                disagreements.is_empty(),
                "{} disagreement(s) with the shared host corpus: {disagreements:#?}",
                disagreements.len()
            );
            // The table must keep exercising both sides of the verdict.
            assert!(corpus.iter().any(|c| c.class == HostClass::Name));
            assert!(corpus.iter().any(|c| c.class == HostClass::NumericAlias));
        }
    }

    #[test]
    fn answers_are_unmapped_deduplicated_in_order_and_kept_apart_by_port() {
        let input = vec![
            addr("[::ffff:10.0.0.1]:80"),
            addr("10.0.0.1:80"),
            // `to_ipv4` would make this 0.0.0.1; only a mapped address unmaps.
            addr("[::1]:80"),
            addr("10.0.0.1:81"),
            addr("[2001:db8::1]:80"),
            addr("[2001:db8::1]:80"),
        ];
        assert_eq!(
            normalise_answers(input),
            vec![
                addr("10.0.0.1:80"),
                addr("[::1]:80"),
                addr("10.0.0.1:81"),
                addr("[2001:db8::1]:80"),
            ]
        );
    }

    #[test]
    fn at_most_32_distinct_answers_are_kept_and_duplicates_do_not_count() {
        let distinct = |n: u8| addr(&format!("192.0.2.{n}:80"));
        // 30 distinct, the same 30 again, then 10 more distinct: 40 distinct
        // in all, so a cap taken before the duplicates are dropped would keep
        // only 30 of them.
        let mut input: Vec<SocketAddr> = (1..=30).map(distinct).collect();
        input.extend((1..=30).map(distinct));
        input.extend((31..=40).map(distinct));
        let kept = normalise_answers(input);
        assert_eq!(kept.len(), MAX_ANSWERS);
        assert_eq!(kept, (1..=32).map(distinct).collect::<Vec<_>>());
    }

    #[test]
    fn the_bounds_are_the_ones_the_design_names() {
        // Sufficiency for a browsing workload is UNVERIFIED (design 6.10); what
        // is pinned here is that nobody changes a bound by accident.
        assert_eq!(MAX_CONCURRENT_LOOKUPS, 16);
        assert_eq!(RESOLVER_WAITERS, 32);
        assert_eq!(RESOLVER_WAIT, Duration::from_millis(500));
        assert_eq!(RESOLVE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(MAX_ANSWERS, 32);
    }

    #[test]
    fn the_lookup_limit_is_clamped_to_what_a_semaphore_can_hold() {
        let zero = BoundedResolver::new().with_max_concurrent(0);
        assert_eq!(zero.permits.available_permits(), 1);
        let huge = BoundedResolver::new().with_max_concurrent(usize::MAX);
        assert_eq!(huge.permits.available_permits(), Semaphore::MAX_PERMITS);
        let default = BoundedResolver::new();
        assert_eq!(default.permits.available_permits(), MAX_CONCURRENT_LOOKUPS);
        assert_eq!(default.waiters.available_permits(), RESOLVER_WAITERS);
    }

    #[test]
    fn os_resolver_resolves_localhost() {
        match OsResolver.resolve("localhost", 80) {
            Ok(answers) => {
                assert!(!answers.is_empty(), "`localhost` resolved to nothing");
                assert!(answers.iter().all(|answer| answer.port() == 80));
                assert!(
                    answers.iter().any(|answer| answer.ip().is_loopback()),
                    "`localhost` resolved to no loopback address: {answers:?}"
                );
            }
            Err(err) => eprintln!(
                "SKIPPED: this host cannot resolve `localhost` ({err}); the OS resolver was not exercised"
            ),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn failures_are_typed_and_the_deadline_names_its_duration() {
        let failing = BoundedResolver::new().with_resolver(CountingResolver::new(|_, _| {
            Err(io::Error::new(io::ErrorKind::NotFound, "no such host"))
        }));
        let err = failing.resolve_once("gone.test", 443).await.unwrap_err();
        assert_eq!(err.code(), "NETCORE_DNS_FAILED");
        assert!(
            matches!(&err, NetcoreError::DnsResolutionFailed(name, via, reason)
                if name == "gone.test" && via == "os-resolver" && reason.contains("no such host")),
            "{err:?}"
        );

        let empty = BoundedResolver::new().with_resolver(CountingResolver::answering(Vec::new()));
        let err = empty.resolve_once("empty.test", 443).await.unwrap_err();
        assert!(
            matches!(&err, NetcoreError::DnsResolutionFailed(_, _, reason) if reason == "no addresses"),
            "{err:?}"
        );

        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let slow = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)]))
                .with_timeout(Duration::from_millis(250)),
        );
        let lookup = spawn_lookup(&slow, "stuck-slow.test");
        until("the lookup starting", || gate.entered() == 1).await;
        advance(Duration::from_millis(248)).await;
        settle().await;
        assert!(!lookup.is_finished(), "the deadline fired early");
        advance(Duration::from_millis(4)).await;
        settle().await;
        assert!(lookup.is_finished(), "the deadline never fired");
        let err = lookup.await.expect("join").unwrap_err();
        assert_eq!(err.code(), "NETCORE_TIMEOUT");
        assert!(
            matches!(&err, NetcoreError::Timeout(label, d)
                if label == "stuck-slow.test:443" && *d == Duration::from_millis(250)),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_17th_name_waits_for_a_permit_and_succeeds_when_one_frees() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)])),
        );
        let _running: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS)
            .map(|i| spawn_lookup(&resolver, &format!("stuck-{i}.test")))
            .collect();
        until("every lookup slot taken", || {
            gate.entered() == MAX_CONCURRENT_LOOKUPS
        })
        .await;

        let seventeenth = spawn_lookup(&resolver, "late.test");
        settle().await;
        assert!(
            !seventeenth.is_finished(),
            "the 17th name must wait for a slot, not fail at once"
        );

        gate.release("stuck-0.test");
        until("the waiting name finishing", || seventeenth.is_finished()).await;
        let answers = seventeenth
            .await
            .expect("join")
            .expect("the 17th name resolves once a slot frees");
        assert_eq!(answers, vec![addr(ANSWER)]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_33rd_waiter_fails_at_once() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)])),
        );
        let _running: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS)
            .map(|i| spawn_lookup(&resolver, &format!("stuck-{i}.test")))
            .collect();
        until("every lookup slot taken", || {
            gate.entered() == MAX_CONCURRENT_LOOKUPS
        })
        .await;

        let waiting: Vec<_> = (0..RESOLVER_WAITERS)
            .map(|i| spawn_lookup(&resolver, &format!("wait-{i}.test")))
            .collect();
        settle().await;
        assert!(
            waiting.iter().all(|lookup| !lookup.is_finished()),
            "32 dials may wait for a slot"
        );

        let one_too_many = spawn_lookup(&resolver, "one-too-many.test");
        settle().await;
        assert!(
            one_too_many.is_finished(),
            "the 33rd waiter must fail at once, not queue behind the others"
        );
        let err = one_too_many.await.expect("join").unwrap_err();
        assert!(matches!(err, NetcoreError::ResolverBusy), "{err:?}");
        assert_eq!(err.code(), "NETCORE_RESOLVER_BUSY");
    }

    #[tokio::test(start_paused = true)]
    async fn sixteen_lookups_blocked_for_30s_then_a_17th_distinct_name_is_busy_after_the_wait() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)])),
        );
        let running: Vec<_> = (0..MAX_CONCURRENT_LOOKUPS)
            .map(|i| spawn_lookup(&resolver, &format!("stuck-{i}.test")))
            .collect();
        until("every lookup slot taken", || {
            gate.entered() == MAX_CONCURRENT_LOOKUPS
        })
        .await;

        advance(Duration::from_secs(30)).await;
        settle().await;
        for lookup in running {
            let err = lookup.await.expect("join").unwrap_err();
            assert!(
                matches!(&err, NetcoreError::Timeout(_, d) if *d == RESOLVE_TIMEOUT),
                "{err:?}"
            );
        }
        // Every caller is gone, every OS call is still running: all sixteen
        // slots stay taken, and they are counted.
        assert_eq!(resolver.abandoned(), MAX_CONCURRENT_LOOKUPS);
        assert_eq!(resolver.permits.available_permits(), 0);

        let seventeenth = spawn_lookup(&resolver, "fresh-name.test");
        settle().await;
        assert!(!seventeenth.is_finished(), "the wait has not run out yet");
        // The timer wheel rounds a deadline up to the next millisecond, so the
        // bounds sit a little either side of the 500 ms.
        advance(RESOLVER_WAIT - Duration::from_millis(2)).await;
        settle().await;
        assert!(
            !seventeenth.is_finished(),
            "it gave up before the wait ran out"
        );
        advance(Duration::from_millis(4)).await;
        settle().await;
        assert!(seventeenth.is_finished(), "it waited longer than the wait");
        let err = seventeenth.await.expect("join").unwrap_err();
        assert!(matches!(err, NetcoreError::ResolverBusy), "{err:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn resolver_permit_is_held_until_the_thread_returns() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)]))
                .with_max_concurrent(1),
        );
        let lookup = spawn_lookup(&resolver, "stuck-a.test");
        until("the lookup starting", || gate.entered() == 1).await;

        advance(RESOLVE_TIMEOUT + Duration::from_millis(2)).await;
        settle().await;
        let err = lookup.await.expect("join").unwrap_err();
        assert!(matches!(err, NetcoreError::Timeout(..)), "{err:?}");
        assert_eq!(
            resolver.permits.available_permits(),
            0,
            "the deadline fired but the OS call has not returned: its permit must stay taken"
        );
        assert_eq!(
            resolver.abandoned(),
            1,
            "a lookup nobody waits for is counted"
        );

        gate.release("stuck-a.test");
        until("the permit coming back", || {
            resolver.permits.available_permits() == 1
        })
        .await;
        assert_eq!(
            resolver.abandoned(),
            0,
            "the count is settled before the permit is returned"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_caller_that_is_dropped_leaves_its_lookup_counted_until_the_thread_returns() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)]))
                .with_max_concurrent(1),
        );
        let lookup = spawn_lookup(&resolver, "stuck-b.test");
        until("the lookup starting", || gate.entered() == 1).await;

        // What an outer deadline (the executor's dial deadline) does.
        lookup.abort();
        let _ = lookup.await;
        assert_eq!(resolver.abandoned(), 1);
        assert_eq!(resolver.permits.available_permits(), 0);

        gate.release("stuck-b.test");
        until("the permit coming back", || {
            resolver.permits.available_permits() == 1
        })
        .await;
        assert_eq!(resolver.abandoned(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_that_answers_in_time_is_never_counted_as_abandoned() {
        let resolver = Arc::new(
            BoundedResolver::new().with_resolver(CountingResolver::answering(vec![addr(ANSWER)])),
        );
        for _ in 0..3 {
            let answers = resolver
                .resolve_once("quick.test", 443)
                .await
                .expect("answer");
            assert_eq!(answers, vec![addr(ANSWER)]);
        }
        assert_eq!(resolver.abandoned(), 0);
        until("the permits coming back", || {
            resolver.permits.available_permits() == MAX_CONCURRENT_LOOKUPS
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_lookup_is_a_typed_failure_and_returns_its_permit() {
        let resolver = BoundedResolver::new()
            .with_resolver(CountingResolver::new(|_, _| panic!("a resolver bug")))
            .with_max_concurrent(1);
        let err = resolver.resolve_once("boom.test", 443).await.unwrap_err();
        assert!(
            matches!(&err, NetcoreError::DnsResolutionFailed(..)),
            "{err:?}"
        );
        until("the permit coming back", || {
            resolver.permits.available_permits() == 1
        })
        .await;
        assert_eq!(resolver.abandoned(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn the_wait_for_a_slot_counts_against_the_deadline() {
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        let resolver = Arc::new(
            BoundedResolver::new()
                .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)]))
                .with_max_concurrent(1),
        );
        let first = spawn_lookup(&resolver, "stuck-first.test");
        until("the first lookup starting", || gate.entered() == 1).await;
        let second = spawn_lookup(&resolver, "stuck-second.test");
        settle().await;

        // The second call has waited 300 ms for the slot when it gets it.
        advance(Duration::from_millis(300)).await;
        gate.release("stuck-first.test");
        until("the second lookup starting", || gate.entered() == 2).await;
        first
            .await
            .expect("join")
            .expect("the first lookup answers");

        // Its deadline is 5 s from the CALL, not from getting the slot: 4.7 s
        // later it is not due yet, a little after that it is.
        advance(Duration::from_millis(4_698)).await;
        settle().await;
        assert!(!second.is_finished(), "the deadline fired early");
        advance(Duration::from_millis(4)).await;
        settle().await;
        assert!(
            second.is_finished(),
            "the deadline restarted when the slot was granted"
        );
        let err = second.await.expect("join").unwrap_err();
        assert!(matches!(err, NetcoreError::Timeout(..)), "{err:?}");
    }

    #[test]
    fn stuck_lookups_do_not_exhaust_the_blocking_pool() {
        // Four blocking threads, two lookup slots, eight distinct names that
        // all hang: whatever the deadlines do, lookups may hold two threads,
        // and an ordinary `spawn_blocking` (the kill-switch poller, say) must
        // still run.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .max_blocking_threads(4)
            .build()
            .expect("runtime");
        let gate = Gate::new();
        let _open = ReleaseOnDrop(Arc::clone(&gate));
        runtime.block_on(async {
            let resolver = Arc::new(
                BoundedResolver::new()
                    .with_resolver(GatedResolver::new(Arc::clone(&gate), vec![addr(ANSWER)]))
                    .with_max_concurrent(2)
                    .with_timeout(Duration::from_millis(50)),
            );
            let lookups: Vec<_> = (0..8)
                .map(|i| spawn_lookup(&resolver, &format!("stuck-{i}.test")))
                .collect();
            until("two lookups running", || gate.entered() >= 2).await;
            // The two running lookups time out (and stay counted); the six that
            // never got a slot fail Busy once the wait runs out.
            advance(RESOLVER_WAIT + Duration::from_millis(100)).await;
            settle().await;
            for lookup in lookups {
                assert!(lookup.is_finished(), "a lookup is still waiting");
            }
            assert_eq!(
                gate.entered(),
                2,
                "no more than two lookups may hold a thread"
            );
            assert_eq!(resolver.abandoned(), 2);

            let (done_tx, done_rx) = std::sync::mpsc::channel();
            tokio::task::spawn_blocking(move || {
                let _ = done_tx.send(());
            });
            done_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("an ordinary blocking task never got a thread: lookups took the pool");
        });
    }
}
