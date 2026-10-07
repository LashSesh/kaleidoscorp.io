#![forbid(unsafe_code)]

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::{Id, JoinSet};
use tokio::time::{timeout, timeout_at, Instant};

use crate::authority::{authority, unbracket};
use crate::connector::{Connected, TcpConnector};
use crate::error::NetcoreError;
use crate::resolve::{is_resolvable_name, normalise_answers, BoundedResolver};
use crate::session::{BoxedTransport, DialAttempts, DialResolution, ResolutionMode};

/// Candidates one dial of a name starts at most.
pub(crate) const MAX_DIAL_CANDIDATES: usize = 8;
/// How long an attempt runs alone before the next candidate starts.
pub(crate) const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// Attempts beyond the first of a dial that may be in flight at once across ALL
/// dials of one executor: each is a descriptor, and the daemon's descriptor
/// budget counts exactly this many for them.
pub const DIAL_EXTRA_PERMITS: usize = 64;

/// Why an address is being dialled, which decides what the guard asks about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialPurpose {
    /// The destination of a `Direct` route.
    Target,
    /// The first hop of a proxy chain: the configured proxy's own address.
    FirstHop,
}

/// Which address families a dial may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamilies {
    /// IPv6 addresses are dropped before anything is dialled.
    Ipv4Only,
    /// Both families; an IPv6-only host is handled by the attempts that fail.
    Any,
}

impl AddressFamilies {
    fn allows(self, ip: IpAddr) -> bool {
        match self {
            Self::Ipv4Only => ip.is_ipv4(),
            Self::Any => true,
        }
    }
}

/// Why a guard refused an address: a static label (`loopback`, `private`,
/// `listener`, ...), never the address itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddrRefusal {
    pub code: &'static str,
}

/// Decides whether an address a name resolved to (or a first hop literal) may
/// be dialled. Called once per address, for every address of an answer, before
/// any socket exists.
pub trait DirectAddrGuard: Send + Sync {
    fn check(&self, purpose: DialPurpose, ip: IpAddr, port: u16) -> Result<(), AddrRefusal>;
}

/// What one dial needs from the executor, borrowed for the length of the dial.
pub(crate) struct Dialer<'a> {
    pub(crate) resolver: &'a BoundedResolver,
    pub(crate) connector: &'a Arc<dyn TcpConnector>,
    pub(crate) guard: Option<&'a Arc<dyn DirectAddrGuard>>,
    pub(crate) families: AddressFamilies,
    pub(crate) attempt_delay: Duration,
    pub(crate) extra_attempts: &'a Arc<Semaphore>,
    pub(crate) connect_timeout: Duration,
}

/// Opens a real TCP connection to `host:port` for a host that is either an IP
/// literal or a DNS name, and says how it got the address.
///
/// * An IP literal is dialled as it is: no resolver, and no guard unless it is
///   the first hop of a chain (the engine decided a `Target` literal before the
///   dial existed). Under [`AddressFamilies::Ipv4Only`] an IPv6 literal is
///   refused with `FamilyDisabled`.
/// * A name is looked up by the OS resolver exactly once, through the bounded
///   resolver (so a hung lookup cannot hold more than its permit), and never
///   asked again: not for the next address, not after a refusal. Then, in this
///   order: every answer goes through the guard, and one refused answer refuses
///   them all, before any socket exists (a mixed answer is what DNS rebinding
///   looks like); the family filter drops what is not allowed; the candidates
///   are ordered IPv4 first and alternating; and a short race over them under
///   one connect budget, [`race`], keeps the first that connects. The address
///   that was looked up is the address that is dialled ("pinned"). The sockets
///   come from the [`TcpConnector`] and are ordinary ones, with no bind and no
///   interface, so where they go is the operating system's decision.
/// * Anything else (a numeric alias such as `127.1`, text with whitespace or
///   control characters) is refused as `InvalidTarget` before any lookup.
///
/// Resolution time is not part of `connect_timeout`; the resolver has its own
/// deadline and the executor's dial deadline bounds both. A failure after a
/// connect of a name was started is [`NetcoreError::DialFailed`], which says
/// what was tried; one before that (a refusal, the filter, the resolver) is
/// returned as it is.
pub(crate) async fn connect_host(
    host: &str,
    port: u16,
    purpose: DialPurpose,
    dialer: &Dialer<'_>,
) -> Result<(BoxedTransport, DialResolution), NetcoreError> {
    let label = authority(host, port);
    let bare = unbracket(host);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return connect_literal(ip, port, &label, purpose, dialer).await;
    }
    if !is_resolvable_name(bare) {
        // The text is client-influenced and could carry line breaks into
        // logs, so it is not echoed.
        return Err(NetcoreError::InvalidTarget(
            "the host is neither an IP address nor a resolvable DNS name".into(),
        ));
    }
    let answers = normalise_answers(dialer.resolver.resolve_once(bare, port).await?);
    let answer_count = u8::try_from(answers.len()).unwrap_or(u8::MAX);
    if let Some(guard) = dialer.guard {
        guard_every_answer(guard.as_ref(), purpose, &answers, answer_count)?;
    }
    let candidates = pick_candidates(&answers, dialer.families)?;
    dial_candidates(&candidates, answer_count, &label, dialer).await
}

/// One connect to an IP literal under the connect budget, with no resolver.
async fn connect_literal(
    ip: IpAddr,
    port: u16,
    label: &str,
    purpose: DialPurpose,
    dialer: &Dialer<'_>,
) -> Result<(BoxedTransport, DialResolution), NetcoreError> {
    // Defence in depth below the engine's own refusal of the same thing.
    if !dialer.families.allows(ip) {
        return Err(NetcoreError::FamilyDisabled);
    }
    if purpose == DialPurpose::FirstHop {
        if let Some(guard) = dialer.guard {
            guard
                .check(purpose, ip, port)
                .map_err(|refusal| NetcoreError::AddressRefused {
                    code: refusal.code,
                    refused: 1,
                    answers: 0,
                })?;
        }
    }
    let addr = SocketAddr::new(ip, port);
    let connected = match timeout(dialer.connect_timeout, dialer.connector.connect(addr)).await {
        Ok(Ok(connected)) => connected,
        Ok(Err(err)) => return Err(io_failure(label, err)),
        Err(_) => {
            return Err(NetcoreError::Timeout(
                label.to_owned(),
                dialer.connect_timeout,
            ))
        }
    };
    let resolution = DialResolution {
        mode: ResolutionMode::Literal,
        dialed: Some(addr),
        attempted: vec![addr],
        answers: 0,
        local_addr: connected.local_addr,
    };
    Ok((connected.transport, resolution))
}

/// All or nothing. Every answer is checked, also after the first refusal, so
/// the error can say how many were refused; the label is the first refusal's.
fn guard_every_answer(
    guard: &dyn DirectAddrGuard,
    purpose: DialPurpose,
    answers: &[SocketAddr],
    answer_count: u8,
) -> Result<(), NetcoreError> {
    let mut first = None;
    let mut refused: u8 = 0;
    for answer in answers {
        if let Err(refusal) = guard.check(purpose, answer.ip(), answer.port()) {
            first.get_or_insert(refusal.code);
            refused = refused.saturating_add(1);
        }
    }
    match first {
        None => Ok(()),
        Some(code) => Err(NetcoreError::AddressRefused {
            code,
            refused,
            answers: answer_count,
        }),
    }
}

/// What to dial, and in which order. The family filter drops every IPv6 answer
/// under `ipv4_only`; what is left keeps the resolver's order inside a family,
/// starts with an IPv4 address and then alternates families, at most
/// [`MAX_DIAL_CANDIDATES`].
///
/// IPv4 first is on purpose and differs from RFC 8305 section 4, which starts
/// with the family of the first answer (IPv6 on a host with a global IPv6
/// address): an IPv6 path may bypass a third-party tunnel that does not cover
/// it. No family is dropped under `any`: a host without IPv6 is handled by the
/// attempts that fail.
fn pick_candidates(
    answers: &[SocketAddr],
    families: AddressFamilies,
) -> Result<Vec<SocketAddr>, NetcoreError> {
    let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) =
        answers.iter().copied().partition(SocketAddr::is_ipv4);
    let v6 = match families {
        AddressFamilies::Ipv4Only => Vec::new(),
        AddressFamilies::Any => v6,
    };
    if v4.is_empty() && v6.is_empty() && !answers.is_empty() {
        return Err(NetcoreError::FamilyDisabled);
    }
    let (mut v4, mut v6) = (v4.into_iter(), v6.into_iter());
    let mut candidates = Vec::with_capacity(MAX_DIAL_CANDIDATES);
    while candidates.len() < MAX_DIAL_CANDIDATES {
        let (next4, next6) = (v4.next(), v6.next());
        if next4.is_none() && next6.is_none() {
            break;
        }
        candidates.extend(next4);
        candidates.extend(next6);
    }
    candidates.truncate(MAX_DIAL_CANDIDATES);
    Ok(candidates)
}

fn io_failure(label: &str, err: io::Error) -> NetcoreError {
    if err.kind() == io::ErrorKind::ConnectionRefused {
        NetcoreError::ConnectionRefused(label.to_owned(), err.to_string())
    } else {
        NetcoreError::Io(label.to_owned(), err)
    }
}

/// Races `candidates` under ONE connect budget and keeps the first that
/// connects. The failure says what was started, for the ledger.
async fn dial_candidates(
    candidates: &[SocketAddr],
    answers: u8,
    label: &str,
    dialer: &Dialer<'_>,
) -> Result<(BoxedTransport, DialResolution), NetcoreError> {
    let mut attempted = Vec::with_capacity(candidates.len());
    let raced = timeout(
        dialer.connect_timeout,
        race(candidates, dialer, &mut attempted),
    )
    .await;
    let failure = match raced {
        Ok(Ok((connected, dialed))) => {
            let resolution = DialResolution {
                mode: ResolutionMode::OsResolver,
                dialed: Some(dialed),
                attempted,
                answers,
                local_addr: connected.local_addr,
            };
            return Ok((connected.transport, resolution));
        }
        Ok(Err(Failures {
            last: Some(err),
            every_refusal: true,
        })) => NetcoreError::ConnectionRefused(label.to_owned(), err.to_string()),
        Ok(Err(Failures {
            last: Some(err), ..
        })) => NetcoreError::Io(label.to_owned(), err),
        // No candidate was ever started. Unreachable while `resolve_once`
        // refuses an empty answer; typed anyway, so an empty list can never
        // look like a success.
        Ok(Err(Failures { last: None, .. })) => {
            return Err(NetcoreError::DnsResolutionFailed(
                label.to_owned(),
                "os-resolver".to_owned(),
                "no addresses".to_owned(),
            ));
        }
        Err(_) => NetcoreError::Timeout(label.to_owned(), dialer.connect_timeout),
    };
    if attempted.is_empty() {
        return Err(failure);
    }
    Err(NetcoreError::DialFailed {
        source: Box::new(failure),
        attempts: DialAttempts { answers, attempted },
    })
}

/// What the attempts that failed said.
struct Failures {
    /// The error of the attempt that failed last.
    last: Option<io::Error>,
    /// Whether every error so far was a refusal.
    every_refusal: bool,
}

impl Failures {
    fn record(&mut self, err: io::Error) {
        self.every_refusal &= err.kind() == io::ErrorKind::ConnectionRefused;
        self.last = Some(err);
    }
}

/// One attempt, as its task reports it.
struct Finished {
    addr: SocketAddr,
    outcome: io::Result<Connected>,
}

/// A running attempt, as the race remembers it.
struct Running {
    task: Id,
    index: usize,
    /// Whether it holds the dial's first slot rather than a pool permit.
    first_slot: bool,
}

/// Happy eyeballs without a second lookup.
///
/// The first attempt starts at once. The next starts at the earlier of
/// `attempt_delay` after the previous start and the moment the previous attempt
/// FAILED (an attempt that is not the newest failing changes nothing). The first
/// connect to be established wins and every other attempt is aborted, so its
/// socket is closed before this returns. A [`JoinSet`] owns the attempts: if
/// this future is dropped (the connect budget, the executor's dial deadline, a
/// gate change) they go with it.
///
/// Descriptor bound: a dial owns one slot for free (its tunnel's descriptor is
/// already counted by the daemon), and every further attempt in flight needs a
/// permit of the executor's shared pool, taken with `try_acquire`. No permit
/// free means the next attempt waits until an earlier one has failed and so
/// freed its slot, which a dial with nothing in flight always has.
async fn race(
    candidates: &[SocketAddr],
    dialer: &Dialer<'_>,
    attempted: &mut Vec<SocketAddr>,
) -> Result<(Connected, SocketAddr), Failures> {
    let mut attempts: JoinSet<Finished> = JoinSet::new();
    let mut running: Vec<Running> = Vec::new();
    let mut failures = Failures {
        last: None,
        every_refusal: true,
    };
    let mut next = 0;
    let mut newest = None;
    let mut first_slot_free = true;
    // A start is wanted now: at the beginning, when the stagger ran out, or
    // when the newest attempt failed.
    let mut start_due = true;
    let mut stagger_ends = Instant::now();
    loop {
        if start_due {
            if let Some(&addr) = candidates.get(next) {
                let permit = if first_slot_free {
                    Some(None)
                } else {
                    Arc::clone(dialer.extra_attempts)
                        .try_acquire_owned()
                        .ok()
                        .map(Some)
                };
                if let Some(permit) = permit {
                    let connector = Arc::clone(dialer.connector);
                    let first_slot = permit.is_none();
                    let handle = attempts.spawn(async move {
                        // Held until this attempt ends, however it ends: the
                        // socket and the permit go together.
                        let _permit = permit;
                        Finished {
                            addr,
                            outcome: connector.connect(addr).await,
                        }
                    });
                    running.push(Running {
                        task: handle.id(),
                        index: next,
                        first_slot,
                    });
                    attempted.push(addr);
                    first_slot_free &= !first_slot;
                    newest = Some(next);
                    next += 1;
                    start_due = false;
                    stagger_ends = Instant::now() + dialer.attempt_delay;
                }
                // No permit: stay due and wait for an attempt to fail.
            }
        }
        let stagger_pending = !start_due && next < candidates.len();
        let joined = if stagger_pending {
            match timeout_at(stagger_ends, attempts.join_next_with_id()).await {
                Ok(joined) => joined,
                Err(_) => {
                    start_due = true;
                    continue;
                }
            }
        } else {
            attempts.join_next_with_id().await
        };
        let Some(joined) = joined else {
            // Nothing is running, so the first slot is free by definition (also
            // if the bookkeeping were ever wrong: the next start cannot then
            // wait for a permit it would never get). With candidates left a
            // start is due; with none left the race is lost.
            first_slot_free = true;
            if next < candidates.len() {
                start_due = true;
                continue;
            }
            return Err(failures);
        };
        let (task, finished) = match joined {
            Ok((task, finished)) => (task, Some(finished)),
            // The attempt panicked (a broken connector): it is a failed
            // attempt, not a dial that waits for it for ever.
            Err(join_error) => (join_error.id(), None),
        };
        let ended = running
            .iter()
            .position(|attempt| attempt.task == task)
            .map(|at| running.swap_remove(at));
        if let Some(ended) = &ended {
            first_slot_free |= ended.first_slot;
        }
        match finished {
            Some(Finished {
                addr,
                outcome: Ok(connected),
            }) => {
                attempts.shutdown().await;
                return Ok((connected, addr));
            }
            Some(Finished {
                outcome: Err(err), ..
            }) => failures.record(err),
            None => failures.record(io::Error::other(
                "the connect attempt ended without an answer",
            )),
        }
        if ended.is_some_and(|ended| newest == Some(ended.index)) && next < candidates.len() {
            start_due = true;
        }
    }
}

/// A guard a test can script, that remembers every question it was asked.
#[cfg(test)]
pub(crate) mod fakes {
    use std::sync::{Mutex, PoisonError};

    use super::*;

    struct Rule {
        purpose: Option<DialPurpose>,
        ip: IpAddr,
        port: Option<u16>,
        code: &'static str,
    }

    /// Allows everything it has no rule for.
    #[derive(Default)]
    pub(crate) struct RecordingGuard {
        rules: Vec<Rule>,
        asked: Mutex<Vec<(DialPurpose, IpAddr, u16)>>,
    }

    impl RecordingGuard {
        /// Refuses `ip` for every purpose and port.
        pub(crate) fn refusing(self, ip: &str, code: &'static str) -> Self {
            self.refusing_where(None, ip, None, code)
        }

        /// Refuses `ip` for `purpose` (any when `None`) and `port` (any when
        /// `None`).
        pub(crate) fn refusing_where(
            mut self,
            purpose: Option<DialPurpose>,
            ip: &str,
            port: Option<u16>,
            code: &'static str,
        ) -> Self {
            self.rules.push(Rule {
                purpose,
                ip: ip.parse().expect("an IP address"),
                port,
                code,
            });
            self
        }

        /// Every question, in the order it was asked.
        pub(crate) fn asked(&self) -> Vec<(DialPurpose, IpAddr, u16)> {
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl DirectAddrGuard for RecordingGuard {
        fn check(&self, purpose: DialPurpose, ip: IpAddr, port: u16) -> Result<(), AddrRefusal> {
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((purpose, ip, port));
            self.rules
                .iter()
                .find(|rule| {
                    rule.ip == ip
                        && rule.purpose.is_none_or(|wanted| wanted == purpose)
                        && rule.port.is_none_or(|wanted| wanted == port)
                })
                .map_or(Ok(()), |rule| Err(AddrRefusal { code: rule.code }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::OsConnector;
    use crate::resolve::fakes::{addr, CountingResolver};
    use tokio::net::TcpListener;
    #[cfg(target_os = "linux")]
    use tokio::net::TcpStream;

    /// What `connect_host` borrows, owned, so a test can build the same
    /// `Dialer` an executor does. The dial reaches the real OS stack through
    /// `OsConnector` unless a test passes a connector of its own.
    struct Rig {
        resolver: BoundedResolver,
        connector: Arc<dyn TcpConnector>,
        guard: Option<Arc<dyn DirectAddrGuard>>,
        families: AddressFamilies,
        extra_attempts: Arc<Semaphore>,
        connect_timeout: Duration,
    }

    impl Rig {
        fn new(resolver: BoundedResolver, connector: Arc<dyn TcpConnector>) -> Self {
            Self {
                resolver,
                connector,
                guard: None,
                families: AddressFamilies::Any,
                extra_attempts: Arc::new(Semaphore::new(DIAL_EXTRA_PERMITS)),
                connect_timeout: DIAL_TIMEOUT,
            }
        }

        fn os(resolver: BoundedResolver) -> Self {
            Self::new(resolver, Arc::new(OsConnector))
        }

        fn timeout(mut self, connect_timeout: Duration) -> Self {
            self.connect_timeout = connect_timeout;
            self
        }

        fn dialer(&self) -> Dialer<'_> {
            Dialer {
                resolver: &self.resolver,
                connector: &self.connector,
                guard: self.guard.as_ref(),
                families: self.families,
                attempt_delay: ATTEMPT_DELAY,
                extra_attempts: &self.extra_attempts,
                connect_timeout: self.connect_timeout,
            }
        }

        async fn dial(
            &self,
            host: &str,
            port: u16,
        ) -> Result<(BoxedTransport, DialResolution), NetcoreError> {
            connect_host(host, port, DialPurpose::Target, &self.dialer()).await
        }
    }

    #[tokio::test]
    async fn connects_to_a_real_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });

        let rig = Rig::os(BoundedResolver::new()).timeout(Duration::from_secs(5));
        let (_stream, resolution) = rig
            .dial("127.0.0.1", addr.port())
            .await
            .expect("real tcp connect must succeed");
        assert_eq!(
            resolution.dialed.map(|dialed| dialed.port()),
            Some(addr.port())
        );
        let (_accepted, seen_as) = accept.await.expect("join").expect("accept");
        assert_eq!(
            resolution.local_addr,
            Some(seen_as),
            "the connection the listener accepted is the one the dial made"
        );
    }

    #[tokio::test]
    async fn refused_when_nothing_listens() {
        // Bind then drop immediately to obtain a port that is guaranteed
        // free at the moment we connect, without racing another test.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);

        let err = Rig::os(BoundedResolver::new())
            .timeout(Duration::from_secs(5))
            .dial("127.0.0.1", port)
            .await
            .err()
            .expect("connecting to a closed port must fail");
        assert!(matches!(err, NetcoreError::ConnectionRefused(..)));
    }

    #[tokio::test]
    async fn times_out_against_a_non_routable_address() {
        // 10.255.255.1 is within a private, non-routable-from-here block;
        // used only to exercise the timeout path deterministically without
        // a live external host. If the sandbox has no route to it at all,
        // the OS may return an immediate unreachable error instead of
        // timing out — either is an honest, typed failure, so accept both.
        let err = Rig::os(BoundedResolver::new())
            .timeout(Duration::from_millis(200))
            .dial("10.255.255.1", 9)
            .await
            .err()
            .expect("must not silently succeed");
        assert!(matches!(
            err,
            NetcoreError::Timeout(..) | NetcoreError::Io(..) | NetcoreError::ConnectionRefused(..)
        ));
    }

    /// What a test does when this host cannot bind `[::1]`: print why and let
    /// the caller skip, so IPv4-only machines can still run the suite. CI sets
    /// `SSK_REQUIRE_IPV6=1` (exactly) on a runner that must have IPv6, and a
    /// skip there would hide that the IPv6 dial was never exercised.
    fn ipv6_loopback_unavailable(require: Option<&str>, err: &std::io::Error) {
        assert!(
            require != Some("1"),
            "SSK_REQUIRE_IPV6=1 but this host cannot bind [::1] ({err}); the IPv6 dial cannot be exercised here"
        );
        eprintln!("SKIPPED: this host cannot bind [::1] ({err}); the IPv6 dial was not exercised");
    }

    /// `None` (with the reason printed) when this host has no IPv6 loopback,
    /// so the test skips instead of failing on IPv4-only runners.
    async fn bind_ipv6_loopback() -> Option<TcpListener> {
        match TcpListener::bind("[::1]:0").await {
            Ok(listener) => Some(listener),
            Err(err) => {
                ipv6_loopback_unavailable(std::env::var("SSK_REQUIRE_IPV6").ok().as_deref(), &err);
                None
            }
        }
    }

    #[test]
    #[should_panic(expected = "SSK_REQUIRE_IPV6=1")]
    fn a_missing_ipv6_loopback_fails_when_ci_requires_it() {
        let err = std::io::Error::from(std::io::ErrorKind::Unsupported);
        ipv6_loopback_unavailable(Some("1"), &err);
    }

    #[test]
    fn a_missing_ipv6_loopback_is_a_skip_unless_the_value_is_exactly_one() {
        // `0` is what the Windows leg sets; the others are near misses that must
        // not turn a skip into a failure by accident.
        let err = std::io::Error::from(std::io::ErrorKind::Unsupported);
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("true"),
            Some("11"),
            Some(" 1"),
        ] {
            ipv6_loopback_unavailable(value, &err);
        }
    }

    #[tokio::test]
    async fn connects_to_an_ipv6_literal_listener() {
        let Some(listener) = bind_ipv6_loopback().await else {
            return;
        };
        let port = listener.local_addr().expect("addr").port();
        let accept = tokio::spawn(async move {
            // Two dials below: bare and bracketed spelling of the same literal.
            for _ in 0..2 {
                listener.accept().await.expect("accept");
            }
        });
        let rig = Rig::os(BoundedResolver::new()).timeout(Duration::from_secs(5));
        for host in ["::1", "[::1]"] {
            let (_stream, resolution) = rig
                .dial(host, port)
                .await
                .unwrap_or_else(|err| panic!("dialing {host:?} must succeed: {err}"));
            assert!(resolution.dialed.is_some_and(|dialed| dialed.is_ipv6()));
        }
        accept.await.expect("join");
    }

    /// Far above how long any OS takes to answer a loopback connect; see the test.
    const RESOLVER_POOL_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

    #[test]
    fn ipv6_literal_dial_does_not_wait_for_the_resolver_pool() {
        // With the only blocking thread occupied, a dial that needs the
        // blocking resolver pool (`getaddrinfo`) cannot even start and burns
        // its WHOLE timeout. A literal needs no lookup, so it must reach the
        // socket layer at once. What the socket layer then says depends on
        // the host (connected, refused, or IPv6 unsupported); only "stuck
        // behind the resolver" is wrong, so that is all this asserts.
        //
        // The timeout is deliberately far above any socket-layer answer: Windows
        // reports a refused connect to a closed loopback port only after its SYN
        // retransmissions (about 2 s), so a short timeout would also fire for a
        // dial that is NOT stuck behind the resolver and the test could not tell
        // the two apart. Only a dial that really waits on the pool uses all of it.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .expect("runtime");
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        runtime.block_on(async {
            let hog = tokio::task::spawn_blocking(move || {
                let _ = started_tx.send(());
                let _ = release_rx.recv();
            });
            started_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("the blocking pool thread must start");
            // Concurrent, so a slow refusal costs the test one wait, not two.
            let rig = Rig::os(BoundedResolver::new()).timeout(RESOLVER_POOL_PROBE_TIMEOUT);
            let (bare, bracketed) = tokio::join!(rig.dial("::1", 9), rig.dial("[::1]", 9));
            for (host, result) in [("::1", bare), ("[::1]", bracketed)] {
                assert!(
                    !matches!(result, Err(NetcoreError::Timeout(..))),
                    "dialing the literal {host:?} waited on the resolver pool"
                );
            }
            let _ = release_tx.send(());
            hog.await.expect("join");
        });
    }

    /// An upper bound, far above any socket-layer answer: Windows reports a
    /// refused connect to a closed loopback port only after about 2 s, and the
    /// tests below dial several in turn under one budget. Only a dial that
    /// really hangs uses all of it.
    const DIAL_TIMEOUT: Duration = Duration::from_secs(20);

    /// A port that refuses: bound then dropped, so nothing listens on it.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    #[tokio::test]
    async fn resolver_called_exactly_once_per_dial_even_when_first_address_fails() {
        let closed = closed_port().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let first = addr(&format!("127.0.0.1:{closed}"));

        let fake = CountingResolver::answering(vec![first, open]);
        let rig = Rig::os(BoundedResolver::new().with_resolver(fake.clone()));
        let (_stream, resolution) = rig
            .dial("svc.test", 443)
            .await
            .expect("the second answer accepts");

        assert_eq!(
            fake.calls(),
            vec![("svc.test".to_owned(), 443)],
            "one lookup per dial, with the name and port of the dial"
        );
        assert_eq!(resolution.mode, ResolutionMode::OsResolver);
        assert_eq!(resolution.answers, 2);
        assert_eq!(resolution.dialed, Some(open));
        assert_eq!(resolution.attempted, vec![first, open]);
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn numeric_alias_never_reaches_the_resolver() {
        // Each of these is dialled by the OS resolver as an IPv4 address. The
        // fake would answer a loopback address that is listening, so a dial
        // that reached it would succeed: only the refusal keeps them out.
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let fake = CountingResolver::answering(vec![listener.local_addr().expect("addr")]);
        let rig = Rig::os(BoundedResolver::new().with_resolver(fake.clone()));
        for alias in [
            "2130706433",
            "127.1",
            "0x7f.1",
            "010.0.0.1",
            "0x7f000001",
            "127.0.0.1.",
            "1",
        ] {
            let err = rig
                .dial(alias, 80)
                .await
                .err()
                .expect("a numeric alias must be refused");
            assert_eq!(err.code(), "NETCORE_INVALID_TARGET", "{alias}: {err:?}");
            assert!(
                !err.to_string().contains(alias),
                "the target is echoed: {err}"
            );
        }
        assert_eq!(fake.calls(), Vec::new(), "the resolver was called");
    }

    #[tokio::test]
    async fn text_that_is_no_host_never_reaches_the_resolver() {
        let fake = CountingResolver::answering(vec![addr("127.0.0.1:9")]);
        let rig = Rig::os(BoundedResolver::new().with_resolver(fake.clone()));
        for text in [
            "",
            "bad host",
            "line\nbreak.test",
            "nul\0.test",
            "under_score.test",
            "[name.test]",
            "fe80::1%eth0",
            "a..b",
            "host.test:80",
        ] {
            let err = rig.dial(text, 80).await.err().expect("not a host");
            assert_eq!(err.code(), "NETCORE_INVALID_TARGET", "{text:?}: {err:?}");
        }
        assert_eq!(fake.calls(), Vec::new(), "the resolver was called");
    }

    #[tokio::test]
    async fn ipv6_and_ipv4_literals_never_call_the_resolver() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let fake = CountingResolver::answering(vec![addr("192.0.2.1:9")]);
        let rig = Rig::os(BoundedResolver::new().with_resolver(fake.clone()));

        let (_stream, resolution) = rig
            .dial("127.0.0.1", open.port())
            .await
            .expect("the IPv4 literal dials directly");
        assert_eq!(resolution.mode, ResolutionMode::Literal);
        assert_eq!(resolution.dialed, Some(open));
        assert_eq!(resolution.answers, 0);
        accept.await.expect("join").expect("accept");

        // The IPv6 spellings may well fail on a host without IPv6 or with
        // nothing listening (a timeout is as good as a refusal here); what they
        // must not do is ask the resolver.
        let closed = closed_port().await;
        for host in ["::1", "[::1]", "::ffff:127.0.0.1", "[::ffff:127.0.0.1]"] {
            let outcome = Rig::os(BoundedResolver::new().with_resolver(fake.clone()))
                .timeout(Duration::from_millis(500))
                .dial(host, closed)
                .await;
            if let Err(err) = &outcome {
                assert_ne!(err.code(), "NETCORE_INVALID_TARGET", "{host}: {err:?}");
                assert_ne!(err.code(), "NETCORE_DNS_FAILED", "{host}: {err:?}");
            }
        }
        assert_eq!(fake.calls(), Vec::new(), "a literal reached the resolver");
    }

    #[tokio::test]
    async fn mapped_and_duplicate_answers_are_dialed_once_as_ipv4() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let open = listener.local_addr().expect("addr");
        let accept = tokio::spawn(async move { listener.accept().await });
        let mapped = addr(&format!("[::ffff:127.0.0.1]:{}", open.port()));

        let rig = Rig::os(
            BoundedResolver::new()
                .with_resolver(CountingResolver::answering(vec![mapped, open, mapped])),
        );
        let (_stream, resolution) = rig
            .dial("svc.test", 443)
            .await
            .expect("the unmapped IPv4 address accepts");
        assert_eq!(resolution.answers, 1, "three answers are one address");
        assert_eq!(resolution.attempted, vec![open], "dialled once, as IPv4");
        assert_eq!(resolution.dialed, Some(open));
        accept.await.expect("join").expect("accept");
    }

    #[tokio::test]
    async fn a_name_whose_every_answer_refuses_is_a_refusal_not_an_io_error() {
        let (one, two) = (closed_port().await, closed_port().await);
        let fake = CountingResolver::answering(vec![
            addr(&format!("127.0.0.1:{one}")),
            addr(&format!("127.0.0.1:{two}")),
        ]);
        let rig = Rig::os(BoundedResolver::new().with_resolver(fake.clone()));
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("nothing listens");
        // The dial of a name that started connects reports the real error
        // inside `DialFailed`, which says what was tried.
        assert!(
            matches!(&err, NetcoreError::DialFailed { source, .. }
                if matches!(&**source, NetcoreError::ConnectionRefused(label, _) if label == "svc.test:443")),
            "{err:?}"
        );
        assert_eq!(err.code(), "NETCORE_CONNECTION_REFUSED");
        assert_eq!(
            fake.calls().len(),
            1,
            "a refusal is not a reason to look up again"
        );
    }

    #[tokio::test]
    async fn connect_in_order_types_an_empty_list_instead_of_succeeding() {
        let rig = Rig::os(BoundedResolver::new());
        let err = dial_candidates(&[], 0, "svc.test:443", &rig.dialer())
            .await
            .err()
            .expect("no address to dial");
        assert_eq!(err.code(), "NETCORE_DNS_FAILED");
    }

    /// The device an upstream socket is bound to (`SO_BINDTODEVICE`), as the
    /// kernel reports it: `None` for a socket nobody bound.
    #[cfg(target_os = "linux")]
    fn bound_device(stream: &TcpStream) -> Option<Vec<u8>> {
        socket2::SockRef::from(stream)
            .device()
            .expect("SO_BINDTODEVICE can be read back")
    }

    /// The connector of the test below: it asks the real [`OsConnector`] for
    /// the socket, reads the device off it and hands it on unchanged, so what
    /// is read is the socket production code made.
    #[cfg(target_os = "linux")]
    struct DeviceSpy {
        devices: std::sync::Mutex<Vec<Option<Vec<u8>>>>,
    }

    #[cfg(target_os = "linux")]
    impl TcpConnector for DeviceSpy {
        fn connect<'a>(
            &'a self,
            addr: SocketAddr,
        ) -> crate::data_plane::BoxFuture<'a, io::Result<Connected>> {
            Box::pin(async move {
                let stream = OsConnector::open(addr).await?;
                self.devices
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(bound_device(&stream));
                let local_addr = stream.local_addr().ok();
                Ok(Connected {
                    transport: Box::new(stream),
                    local_addr,
                })
            })
        }
    }

    /// CO-1 (docs/M2_LOCAL_INGRESS_DESIGN.md 2.3, 24.2.1) read from real
    /// sockets: a Direct dial applies no interface binding, and its source
    /// address is the one the kernel gives a plain connection to the same
    /// listener. Both kinds of dial are read: the literal one and, behind a
    /// name, the pinned-address one. Since C-N4 both reach the socket through
    /// the connector, so the socket is read there, from the real OS connector.
    ///
    /// The listener is on the loopback alias 127.0.0.5 while the kernel picks
    /// 127.0.0.1 as the source, so the source differs from the destination and
    /// a dial that bound to the destination address would show.
    ///
    /// What this does and does not show. `device()` being `None` means no
    /// `SO_BINDTODEVICE` was applied. The source equality is consistent with
    /// an unbound socket but cannot tell it from an explicit `bind(127.0.0.1)`,
    /// which gives the same address, so it is not offered as proof that the OS
    /// chose the source. That nothing binds is the static scan of
    /// `ssk-daemon/tests/dial_path_binds_nothing.rs`; that the OS decides is
    /// the route-flip test (C-CO1b); what the Windows stack does is the manual
    /// run of ACCEPT-5.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn direct_dial_leaves_device_and_source_to_the_os() {
        let listener = TcpListener::bind("127.0.0.5:0")
            .await
            .expect("127.0.0.5 is a loopback address on Linux");
        let target = listener.local_addr().expect("addr");

        // Nothing of ours touches the control: its source is what the kernel
        // chooses for this destination.
        let control = std::net::TcpStream::connect(target).expect("control connect");
        let control_source = control.local_addr().expect("control source").ip();
        assert_ne!(
            control_source,
            target.ip(),
            "the kernel chose the destination as the source: the source check cannot see a bind to it"
        );

        let spy = Arc::new(DeviceSpy {
            devices: std::sync::Mutex::new(Vec::new()),
        });
        let rig = Rig::new(
            BoundedResolver::new().with_resolver(CountingResolver::answering(vec![target])),
            spy.clone(),
        );
        let devices = || {
            spy.devices
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        };

        let (_literal, resolution) = rig
            .dial("127.0.0.5", target.port())
            .await
            .expect("the literal dial");
        assert_eq!(
            resolution.mode,
            ResolutionMode::Literal,
            "not the literal path"
        );
        assert_eq!(devices(), vec![None], "the literal dial binds a device");
        assert_eq!(
            resolution.local_addr.map(|local| local.ip()),
            Some(control_source),
            "the literal dial's source is not the kernel's choice"
        );

        let (_named, resolution) = rig
            .dial("svc.test", target.port())
            .await
            .expect("the dial of a name");
        assert_eq!(
            resolution.mode,
            ResolutionMode::OsResolver,
            "not the name path"
        );
        assert_eq!(devices(), vec![None, None], "the name dial binds a device");
        assert_eq!(
            resolution.local_addr.map(|local| local.ip()),
            Some(control_source),
            "the name dial's source is not the kernel's choice"
        );
    }

    /// The device check above can fail: on a socket to which the test itself
    /// applies `SO_BINDTODEVICE`, the same reader reports the device. Without
    /// this, "no device" could be what a broken reader always says.
    ///
    /// Skips, saying why, where the kernel refuses the option for lack of
    /// permission (CAP_NET_RAW, on kernels that require it).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_device_check_has_teeth() {
        let listener = TcpListener::bind("127.0.0.5:0")
            .await
            .expect("127.0.0.5 is a loopback address on Linux");
        let target = listener.local_addr().expect("addr");

        let socket = tokio::net::TcpSocket::new_v4().expect("socket");
        if let Err(err) = socket.bind_device(Some(b"lo")) {
            assert_eq!(
                err.kind(),
                std::io::ErrorKind::PermissionDenied,
                "binding a socket to lo failed for a reason other than permission: {err}"
            );
            eprintln!(
                "SKIPPED: this process may not set SO_BINDTODEVICE ({err}); the device check was \
                 not shown to detect a bound socket"
            );
            return;
        }
        let stream = socket.connect(target).await.expect("the bound dial");
        assert_eq!(
            bound_device(&stream),
            Some(b"lo".to_vec()),
            "the device check does not see a device that was bound"
        );
    }

    // ---- C-N4: guard, family filter, candidate order, the race ------------

    use crate::connector::fakes::{scripted_local_addr, Script, ScriptedConnector};
    use crate::direct::fakes::RecordingGuard;
    use tokio::time::Instant;

    /// tokio timers have a granularity of 1 ms, and a few of them add up.
    const START_SLACK: Duration = Duration::from_millis(10);

    fn v4(n: u8) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, n], 443))
    }

    fn v6(n: u16) -> SocketAddr {
        SocketAddr::from(([0x2001, 0x0db8, 0, 0, 0, 0, 0, n], 443))
    }

    fn answering(answers: &[SocketAddr]) -> BoundedResolver {
        BoundedResolver::new().with_resolver(CountingResolver::answering(answers.to_vec()))
    }

    /// The addresses a connect was started for, and when (in ms after
    /// `origin`, within [`START_SLACK`]).
    fn assert_starts(
        connector: &ScriptedConnector,
        origin: Instant,
        expected: &[(SocketAddr, u64)],
    ) {
        let actual = connector.started_after(origin);
        assert_eq!(
            actual.iter().map(|(addr, _)| *addr).collect::<Vec<_>>(),
            expected.iter().map(|(addr, _)| *addr).collect::<Vec<_>>(),
            "the addresses a connect was started for, in order"
        );
        for ((addr, at), (_, ms)) in actual.iter().zip(expected) {
            let want = Duration::from_millis(*ms);
            assert!(
                *at >= want && *at <= want + START_SLACK,
                "{addr} was started at {at:?}, expected {want:?}"
            );
        }
    }

    #[test]
    fn the_dial_bounds_are_the_ones_the_design_names() {
        // Their sufficiency for a browsing workload is UNVERIFIED (design 6.10);
        // what is pinned is that nobody changes one by accident.
        assert_eq!(MAX_DIAL_CANDIDATES, 8);
        assert_eq!(ATTEMPT_DELAY, Duration::from_millis(250));
        assert_eq!(DIAL_EXTRA_PERMITS, 64);
    }

    #[test]
    fn candidates_start_with_ipv4_alternate_families_and_keep_each_familys_order() {
        use AddressFamilies::{Any, Ipv4Only};
        // The resolver's order is IPv6 first, as on a host with a global IPv6
        // address: the dial starts with IPv4 anyway.
        assert_eq!(
            pick_candidates(&[v6(1), v6(2), v4(1), v4(2), v4(3), v6(3)], Any).expect("candidates"),
            [v4(1), v6(1), v4(2), v6(2), v4(3), v6(3)]
        );
        // One family runs out, the other carries on in its own order.
        assert_eq!(
            pick_candidates(&[v6(1), v6(2), v4(1), v6(3), v6(4)], Any).expect("candidates"),
            [v4(1), v6(1), v6(2), v6(3), v6(4)]
        );
        // An IPv6-only answer is dialled under `any` (the attempts that fail
        // handle a host without IPv6, not a guess).
        assert_eq!(
            pick_candidates(&[v6(1), v6(2)], Any).expect("candidates"),
            [v6(1), v6(2)]
        );
        // At most 8, and the cap falls after the alternation.
        let many: Vec<_> = (1..=5u8).flat_map(|n| [v6(n.into()), v4(n)]).collect();
        assert_eq!(
            pick_candidates(&many, Any).expect("candidates"),
            [v4(1), v6(1), v4(2), v6(2), v4(3), v6(3), v4(4), v6(4)]
        );
        // `ipv4_only` keeps IPv4 in the OS's order, under the same cap.
        let ten: Vec<_> = (1..=10).map(v4).collect();
        assert_eq!(
            pick_candidates(&ten, Ipv4Only).expect("candidates"),
            ten[..MAX_DIAL_CANDIDATES]
        );
        assert_eq!(
            pick_candidates(&[v6(1), v4(1), v6(2)], Ipv4Only).expect("candidates"),
            [v4(1)]
        );
        assert!(matches!(
            pick_candidates(&[v6(1), v6(2)], Ipv4Only),
            Err(NetcoreError::FamilyDisabled)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn first_family_is_ipv4_then_alternates() {
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let rig = Rig::new(answering(&[v6(1), v4(1), v6(2), v4(2)]), connector.clone())
            .timeout(Duration::from_secs(2));
        let t0 = Instant::now();
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("every address hangs");
        assert_starts(
            &connector,
            t0,
            &[(v4(1), 0), (v6(1), 250), (v4(2), 500), (v6(2), 750)],
        );
        assert_eq!(err.code(), "NETCORE_TIMEOUT");
    }

    #[tokio::test(start_paused = true)]
    async fn at_most_eight_of_many_answers_are_ever_attempted() {
        // Twenty distinct answers, every one refused at once: the dial walks the
        // first eight and says so (the ledger's `attempted` holds at most 8).
        let answers: Vec<SocketAddr> = (1..=20).map(v4).collect();
        let connector = Arc::new(ScriptedConnector::new(Script::REFUSED));
        let rig = Rig::new(answering(&answers), connector.clone());
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("every address refuses");
        let NetcoreError::DialFailed { attempts, .. } = &err else {
            panic!("{err:?}");
        };
        assert_eq!(attempts.answers, 20);
        assert_eq!(attempts.attempted, answers[..MAX_DIAL_CANDIDATES]);
        assert_eq!(connector.started(), answers[..MAX_DIAL_CANDIDATES]);
    }

    #[tokio::test(start_paused = true)]
    async fn ipv4_only_drops_every_ipv6_candidate() {
        // Any IPv6 address that is dialled panics the connector.
        let connector = Arc::new(ScriptedConnector::new(Script::Panic).script(v4(1), Script::NOW));
        let mut rig = Rig::new(answering(&[v6(1), v4(1), v6(2)]), connector.clone());
        rig.families = AddressFamilies::Ipv4Only;
        let (_transport, resolution) = rig
            .dial("svc.test", 443)
            .await
            .expect("the IPv4 answer connects");
        assert_eq!(connector.started(), [v4(1)]);
        assert_eq!(resolution.attempted, [v4(1)]);
        assert_eq!(
            resolution.answers, 3,
            "the filter does not change how many answers the resolver gave"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn no_candidate_left_after_filtering_is_a_typed_failure() {
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let mut rig = Rig::new(answering(&[v6(1), v6(2)]), connector.clone());
        rig.families = AddressFamilies::Ipv4Only;
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("only IPv6 answers");
        assert!(matches!(err, NetcoreError::FamilyDisabled), "{err:?}");
        assert_eq!(err.code(), "NETCORE_FAMILY_DISABLED");
        assert_eq!(connector.started(), [], "a socket was opened");
    }

    #[tokio::test(start_paused = true)]
    async fn ipv6_literal_is_refused_with_family_disabled_under_ipv4_only() {
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let resolver = CountingResolver::answering(vec![v4(9)]);
        let mut rig = Rig::new(
            BoundedResolver::new().with_resolver(resolver.clone()),
            connector.clone(),
        );
        rig.families = AddressFamilies::Ipv4Only;
        for host in ["::1", "[::1]", "2001:db8::1", "[2001:db8::1]"] {
            let err = rig
                .dial(host, 443)
                .await
                .err()
                .expect("an IPv6 literal under ipv4_only");
            assert!(
                matches!(err, NetcoreError::FamilyDisabled),
                "{host}: {err:?}"
            );
        }
        assert_eq!(connector.started(), [], "a socket was opened");
        assert_eq!(
            resolver.calls(),
            Vec::new(),
            "a literal reached the resolver"
        );

        // An IPv4 literal is not affected, and `any` lets IPv6 through.
        let (_transport, resolution) = rig.dial("192.0.2.5", 443).await.expect("IPv4 literal");
        assert_eq!(resolution.dialed, Some(v4(5)));
        rig.families = AddressFamilies::Any;
        rig.dial("2001:db8::1", 443)
            .await
            .expect("IPv6 literal under any");
        assert_eq!(connector.started(), [v4(5), v6(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn second_attempt_starts_after_250ms() {
        let connector = Arc::new(ScriptedConnector::new(Script::Hang).script(v4(2), Script::NOW));
        let rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        let t0 = Instant::now();
        let (_transport, resolution) = rig
            .dial("svc.test", 443)
            .await
            .expect("the second candidate connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 250)]);
        assert_eq!(resolution.dialed, Some(v4(2)));
        assert_eq!(resolution.attempted, [v4(1), v4(2)]);
        assert_eq!(resolution.mode, ResolutionMode::OsResolver);
        assert!(
            t0.elapsed() < ATTEMPT_DELAY + START_SLACK,
            "the dial waited for something after the winner connected"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failed_attempt_starts_the_next_immediately() {
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(v4(1), Script::REFUSED)
                .script(v4(2), Script::Connect(Duration::from_millis(40))),
        );
        let rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        let t0 = Instant::now();
        rig.dial("svc.test", 443)
            .await
            .expect("the second candidate connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 0)]);
        assert!(
            t0.elapsed() < ATTEMPT_DELAY,
            "the dial waited out the stagger after a failure"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn only_the_newest_attempt_failing_starts_the_next_one_early() {
        // The design: the next attempt starts at the earlier of 250 ms after the
        // PREVIOUS start and the moment the PREVIOUS attempt failed. The first
        // attempt fails at 300 ms, while the second (started at 250 ms) runs:
        // the third still waits for its own 250 ms.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(
                    v4(1),
                    Script::Fail(Duration::from_millis(300), io::ErrorKind::ConnectionReset),
                )
                .script(v4(3), Script::NOW),
        );
        let rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone());
        let t0 = Instant::now();
        rig.dial("svc.test", 443).await.expect("the third connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 250), (v4(3), 500)]);
    }

    #[tokio::test(start_paused = true)]
    async fn the_newest_attempt_failing_starts_the_next_at_once_while_an_older_one_runs() {
        // The first attempt hangs for the whole dial. The second, started at
        // 250 ms, fails at 300 ms: the third does not wait for 500 ms.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(
                    v4(2),
                    Script::Fail(Duration::from_millis(50), io::ErrorKind::ConnectionReset),
                )
                .script(v4(3), Script::NOW),
        );
        let rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone());
        let t0 = Instant::now();
        rig.dial("svc.test", 443).await.expect("the third connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 250), (v4(3), 300)]);
    }

    #[tokio::test(start_paused = true)]
    async fn all_attempts_share_one_budget() {
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone())
            .timeout(Duration::from_secs(1));
        let t0 = Instant::now();
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("every address hangs");
        let elapsed = t0.elapsed();
        assert!(
            elapsed >= Duration::from_secs(1) && elapsed <= Duration::from_secs(1) + START_SLACK,
            "three attempts, one budget of 1 s: the dial took {elapsed:?}"
        );
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 250), (v4(3), 500)]);
        assert!(
            matches!(&err, NetcoreError::DialFailed { source, attempts }
                if matches!(&**source, NetcoreError::Timeout(label, d)
                        if label == "svc.test:443" && *d == Duration::from_secs(1))
                    && attempts.attempted == [v4(1), v4(2), v4(3)]),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_black_holed_first_candidate_does_not_consume_the_whole_connect_budget() {
        // The dial this replaces tried addresses one after another under one
        // budget, so a blackholed first address burned all of it.
        let connector = Arc::new(ScriptedConnector::new(Script::Hang).script(v4(2), Script::NOW));
        let rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone())
            .timeout(Duration::from_secs(10));
        let t0 = Instant::now();
        let (_transport, resolution) = rig
            .dial("svc.test", 443)
            .await
            .expect("the second address connects");
        assert_eq!(resolution.dialed, Some(v4(2)));
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "the dial took {:?} of a 10 s budget",
            t0.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn winner_aborts_the_losers() {
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(v4(2), Script::Connect(Duration::from_millis(100))),
        );
        let rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone());
        rig.dial("svc.test", 443)
            .await
            .expect("the second connects");
        // No waiting and no yielding: the losers are gone when the dial returns.
        assert_eq!(connector.live(), 0, "an attempt outlived the dial");
        let mut ended = connector.ended();
        ended.sort();
        assert_eq!(ended, [v4(1), v4(2)]);
        assert_eq!(
            connector.started(),
            [v4(1), v4(2)],
            "the third never started"
        );
        assert_eq!(
            rig.extra_attempts.available_permits(),
            DIAL_EXTRA_PERMITS,
            "a permit outlived the dial"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_answer_with_one_special_use_address_refuses_the_whole_flow_without_a_socket() {
        let public = v4(7);
        let loopback = addr("127.0.0.1:443");
        let private = addr("10.1.2.3:443");
        let guard = Arc::new(
            RecordingGuard::default()
                .refusing("127.0.0.1", "loopback")
                .refusing("10.1.2.3", "private"),
        );
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let mut rig = Rig::new(answering(&[public, loopback, private]), connector.clone());
        rig.guard = Some(guard.clone());

        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("one answer is special-use");
        // All or nothing, and the label is the FIRST refusal in answer order.
        assert!(
            matches!(
                err,
                NetcoreError::AddressRefused {
                    code: "loopback",
                    refused: 2,
                    answers: 3
                }
            ),
            "{err:?}"
        );
        assert_eq!(err.code(), "NETCORE_ADDR_REFUSED");
        assert_eq!(connector.started(), [], "a socket was opened");
        // Every address was asked about, even after the first refusal, and as a
        // target.
        assert_eq!(
            guard.asked(),
            [
                (DialPurpose::Target, public.ip(), 443),
                (DialPurpose::Target, loopback.ip(), 443),
                (DialPurpose::Target, private.ip(), 443),
            ]
        );
        // The error carries counts and a static label, never an address or the name.
        let text = err.to_string();
        for secret in ["127.0.0.1", "10.1.2.3", "192.0.2.7", "svc.test"] {
            assert!(!text.contains(secret), "the message names {secret}: {text}");
        }

        // The other order: the label follows the answer order.
        let mut rig = Rig::new(answering(&[private, public, loopback]), connector.clone());
        rig.guard = Some(guard);
        let err = rig.dial("svc.test", 443).await.err().expect("refused");
        assert!(
            matches!(
                err,
                NetcoreError::AddressRefused {
                    code: "private",
                    refused: 2,
                    answers: 3
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_name_whose_answers_are_all_allowed_is_dialled_after_the_guard_passed_every_one() {
        let guard = Arc::new(RecordingGuard::default().refusing("127.0.0.1", "loopback"));
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let mut rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        rig.guard = Some(guard.clone());
        rig.dial("svc.test", 443).await.expect("both are allowed");
        assert_eq!(guard.asked().len(), 2, "the guard saw every answer");
        assert_eq!(connector.started(), [v4(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn guard_runs_before_the_family_filter() {
        // Without the order, the filter would drop the IPv6 loopback answer
        // silently and the IPv4 one would be dialled: the mixed answer that
        // marks DNS rebinding would pass.
        let guard = Arc::new(RecordingGuard::default().refusing("::1", "loopback"));
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let loopback_v6 = addr("[::1]:443");
        let mut rig = Rig::new(answering(&[v4(7), loopback_v6]), connector.clone());
        rig.guard = Some(guard);
        rig.families = AddressFamilies::Ipv4Only;
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("the IPv6 answer is refused although the filter would drop it");
        assert!(
            matches!(
                err,
                NetcoreError::AddressRefused {
                    code: "loopback",
                    refused: 1,
                    answers: 2
                }
            ),
            "{err:?}"
        );
        assert_eq!(connector.started(), [], "a socket was opened");
    }

    #[tokio::test(start_paused = true)]
    async fn guard_is_not_consulted_for_target_literals() {
        let guard = Arc::new(RecordingGuard::default().refusing("127.0.0.1", "loopback"));
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let mut rig = Rig::new(answering(&[v4(1)]), connector.clone());
        rig.guard = Some(guard.clone());
        // The engine decided a literal target before the dial existed, so the
        // guard is not asked: this one is dialled although the guard refuses it.
        rig.dial("127.0.0.1", 443)
            .await
            .expect("a Target literal is not the guard's to refuse");
        assert_eq!(
            guard.asked(),
            [],
            "the guard was asked about a Target literal"
        );
        assert_eq!(connector.started(), [addr("127.0.0.1:443")]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_first_hop_literal_is_checked_by_the_guard_for_the_first_hop_purpose() {
        let guard = Arc::new(RecordingGuard::default().refusing_where(
            Some(DialPurpose::FirstHop),
            "127.0.0.1",
            Some(10800),
            "listener",
        ));
        let connector = Arc::new(ScriptedConnector::new(Script::NOW));
        let mut rig = Rig::new(answering(&[v4(1)]), connector.clone());
        rig.guard = Some(guard.clone());

        let err = connect_host("127.0.0.1", 10800, DialPurpose::FirstHop, &rig.dialer())
            .await
            .err()
            .expect("the listener is not a first hop");
        assert!(
            matches!(
                err,
                NetcoreError::AddressRefused {
                    code: "listener",
                    refused: 1,
                    answers: 0
                }
            ),
            "{err:?}"
        );
        assert_eq!(connector.started(), [], "a socket was opened");

        // Another loopback port is a legitimate local proxy.
        connect_host("127.0.0.1", 1080, DialPurpose::FirstHop, &rig.dialer())
            .await
            .expect("a local proxy is allowed");
        assert_eq!(
            guard.asked(),
            [
                (DialPurpose::FirstHop, addr("127.0.0.1:1").ip(), 10800),
                (DialPurpose::FirstHop, addr("127.0.0.1:1").ip(), 1080),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn attempted_addresses_are_recorded_on_success_and_on_failure() {
        // Three answers, one of them a duplicate: two distinct addresses.
        let answers = [v4(1), v4(2), v4(1)];

        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(v4(1), Script::REFUSED)
                .script(v4(2), Script::NOW),
        );
        let rig = Rig::new(answering(&answers), connector);
        let (_transport, resolution) = rig.dial("svc.test", 443).await.expect("connects");
        assert_eq!(resolution.answers, 2);
        assert_eq!(resolution.attempted, [v4(1), v4(2)]);
        assert_eq!(resolution.dialed, Some(v4(2)));
        assert_eq!(resolution.local_addr, Some(scripted_local_addr()));

        let connector = Arc::new(ScriptedConnector::new(Script::REFUSED));
        let rig = Rig::new(answering(&answers), connector);
        let err = rig.dial("svc.test", 443).await.err().expect("refused");
        let NetcoreError::DialFailed { source, attempts } = &err else {
            panic!("a dial that started connects reports what it tried: {err:?}");
        };
        assert!(
            matches!(&**source, NetcoreError::ConnectionRefused(label, _) if label == "svc.test:443")
        );
        assert_eq!(attempts.answers, 2);
        assert_eq!(attempts.attempted, [v4(1), v4(2)]);
        // The wrapper is invisible to a caller that only reports the failure.
        assert_eq!(err.code(), "NETCORE_CONNECTION_REFUSED");
        assert_eq!(err.to_string(), source.to_string());

        // A refusal mixed with another error is an I/O error with the last one.
        let connector = Arc::new(ScriptedConnector::new(Script::REFUSED).script(
            v4(2),
            Script::Fail(Duration::from_millis(5), io::ErrorKind::HostUnreachable),
        ));
        let rig = Rig::new(answering(&answers), connector);
        let err = rig.dial("svc.test", 443).await.err().expect("fails");
        assert_eq!(err.code(), "NETCORE_IO_ERROR");
        assert!(
            matches!(&err, NetcoreError::DialFailed { source, .. }
                if matches!(&**source, NetcoreError::Io(_, e) if e.kind() == io::ErrorKind::HostUnreachable)),
            "{err:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_literal_that_fails_is_reported_as_itself() {
        // The ledger knows a literal from its Pending record, and callers match
        // the plain variants of a literal dial (the first hop of a chain, say).
        let connector = Arc::new(ScriptedConnector::new(Script::REFUSED));
        let rig = Rig::new(answering(&[v4(1)]), connector);
        let err = rig.dial("192.0.2.5", 443).await.err().expect("refused");
        assert!(
            matches!(&err, NetcoreError::ConnectionRefused(label, _) if label == "192.0.2.5:443"),
            "{err:?}"
        );
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let rig = Rig::new(answering(&[v4(1)]), connector).timeout(Duration::from_secs(1));
        let err = rig
            .dial("[2001:db8::1]", 443)
            .await
            .err()
            .expect("times out");
        assert!(
            matches!(&err, NetcoreError::Timeout(label, d)
            if label == "[2001:db8::1]:443" && *d == Duration::from_secs(1)),
            "{err:?}"
        );
    }

    // ---- the descriptor pool ----------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn a_dial_with_nothing_in_flight_never_waits_for_a_permit() {
        // An empty pool means a sequential dial, not a dial that cannot start:
        // the first descriptor of a dial is not the pool's.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(
                    v4(1),
                    Script::Fail(Duration::from_millis(100), io::ErrorKind::ConnectionReset),
                )
                .script(v4(2), Script::NOW),
        );
        let mut rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        rig.extra_attempts = Arc::new(Semaphore::new(0));
        let t0 = Instant::now();
        rig.dial("svc.test", 443).await.expect("connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 100)]);
        assert_eq!(connector.max_live(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_that_finds_no_permit_waits_for_an_earlier_attempt_to_fail() {
        // The stagger fires at 250 ms and the pool is empty: the next attempt
        // starts only when the first has failed, at 1 s.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(
                    v4(1),
                    Script::Fail(Duration::from_secs(1), io::ErrorKind::ConnectionReset),
                )
                .script(v4(2), Script::NOW),
        );
        let mut rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        rig.extra_attempts = Arc::new(Semaphore::new(0));
        let t0 = Instant::now();
        rig.dial("svc.test", 443).await.expect("connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 1000)]);
        assert_eq!(connector.max_live(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_slot_of_a_failed_attempt_is_reused_while_a_permit_holder_runs() {
        // One permit. The first attempt holds the dial's own slot and fails at
        // 400 ms; the second holds the permit and hangs; the third is due at
        // 500 ms. The pool is empty, but the dial's slot is free again, so the
        // third starts without waiting for the second to fail.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(
                    v4(1),
                    Script::Fail(Duration::from_millis(400), io::ErrorKind::ConnectionReset),
                )
                .script(v4(3), Script::NOW),
        );
        let mut rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone());
        rig.extra_attempts = Arc::new(Semaphore::new(1));
        let t0 = Instant::now();
        rig.dial("svc.test", 443).await.expect("the third connects");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 250), (v4(3), 500)]);
        assert_eq!(connector.max_live(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dial_that_cannot_get_a_permit_ends_with_the_budget_not_with_a_hang() {
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let mut rig =
            Rig::new(answering(&[v4(1), v4(2)]), connector.clone()).timeout(Duration::from_secs(2));
        rig.extra_attempts = Arc::new(Semaphore::new(0));
        let err = rig.dial("svc.test", 443).await.err().expect("times out");
        assert!(
            matches!(&err, NetcoreError::DialFailed { source, attempts }
                if matches!(**source, NetcoreError::Timeout(..)) && attempts.attempted == [v4(1)]),
            "{err:?}"
        );
        assert_eq!(connector.started(), [v4(1)]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_connector_is_a_failed_attempt_not_a_stuck_dial() {
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(v4(1), Script::Panic)
                .script(v4(2), Script::NOW),
        );
        let mut rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        rig.extra_attempts = Arc::new(Semaphore::new(0));
        let t0 = Instant::now();
        rig.dial("svc.test", 443)
            .await
            .expect("the next candidate is tried");
        assert_starts(&connector, t0, &[(v4(1), 0), (v4(2), 0)]);

        let connector = Arc::new(ScriptedConnector::new(Script::Panic));
        let rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        let err = rig
            .dial("svc.test", 443)
            .await
            .err()
            .expect("every connector call panics");
        assert_eq!(err.code(), "NETCORE_IO_ERROR", "{err:?}");
        assert_eq!(connector.started(), [v4(1), v4(2)]);
    }

    #[tokio::test(start_paused = true)]
    async fn extra_permits_return_when_a_dial_ends_however_it_ends() {
        let pool = || Arc::new(Semaphore::new(2));
        let settle_pool = |rig: &Rig| {
            let extra = Arc::clone(&rig.extra_attempts);
            async move {
                crate::resolve::fakes::until("the permits coming back", || {
                    extra.available_permits() == 2
                })
                .await;
            }
        };

        // Won: the loser holds the permit until the dial has aborted it.
        let connector = Arc::new(
            ScriptedConnector::new(Script::Hang)
                .script(v4(2), Script::Connect(Duration::from_millis(10))),
        );
        let mut rig = Rig::new(answering(&[v4(1), v4(2)]), connector.clone());
        rig.extra_attempts = pool();
        rig.dial("svc.test", 443).await.expect("connects");
        assert_eq!(rig.extra_attempts.available_permits(), 2);

        // Timed out.
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let mut rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone())
            .timeout(Duration::from_secs(2));
        rig.extra_attempts = pool();
        rig.dial("svc.test", 443).await.err().expect("times out");
        settle_pool(&rig).await;
        assert_eq!(connector.live(), 0);

        // Dropped by an outer deadline (the executor's dial deadline, a gate
        // change): the attempts and their permits go with the future.
        let connector = Arc::new(ScriptedConnector::new(Script::Hang));
        let mut rig = Rig::new(answering(&[v4(1), v4(2), v4(3)]), connector.clone());
        rig.extra_attempts = pool();
        let outer = timeout(Duration::from_millis(600), rig.dial("svc.test", 443)).await;
        assert!(outer.is_err(), "the outer deadline did not fire");
        assert_eq!(connector.started().len(), 3);
        settle_pool(&rig).await;
        crate::resolve::fakes::until("the sockets closing", || connector.live() == 0).await;
    }
}
