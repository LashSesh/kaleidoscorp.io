//! The daemon's **read-only** view of the privileged kill-switch (roadmap P3).
//!
//! # The defect this module exists to remove
//!
//! `Supervisor::handle` used to answer every `get_status` with a literal
//! `kill_switch: false`. The comment above it was truthful *when it was
//! written* — there was no enforcement mechanism at all — but P1/P2/P3 built
//! one, and a hardcoded `false` next to a real, possibly-engaged kill-switch is
//! no longer "honestly false": it is a fabricated safe-looking value, the same
//! class of statement the release blocker register was opened about.
//!
//! # The layering decision, and where it was and was not followed
//!
//! The enforcement design's core rule is that **the daemon asks; it does not
//! observe**. That rule is followed here without exception:
//!
//! * nothing in this crate constructs a [`ssk_netd_helper::Broker`], holds a
//!   `ReceiptStore`, or names a `BoundaryEnforcer`/`EgressObserver`;
//! * nothing here knows what a firewall rule, a `netsh` invocation or a WFP
//!   filter is;
//! * the only thing the daemon does is open a client connection to the
//!   privileged broker, read the authoritative [`KillSwitchStatus`], and map it
//!   through one pure function ([`view_of`]).
//!
//! The design additionally preferred that the *production provider* live in
//! `ssk-winhost`, so that `ssk-daemon` would need **no new dependency edge at
//! all**. That was not achievable in this change's file scope
//! (`crates/ssk-daemon/**`): `ssk-winhost` exposes the pipe transport
//! (`NamedPipeClientTransport`) but does not re-export
//! `ssk_netd_helper::PrivilegedClient`, and adding such a re-export or an
//! adapter there was out of scope. So `ssk-daemon` grew a **client-only** edge
//! to `ssk-netd-helper`. It introduces no cycle (`ssk-netd-helper` depends on
//! `ssk-types`/`ssk-signature`/`ssk-boundary` and reaches nothing here), and it
//! is deliberately narrow — but it does mean `Broker` is *nameable* from an
//! unprivileged process, which the design wanted to keep impossible. Do not
//! construct one here; the correct fix is a `KillSwitchProvider`-shaped adapter
//! owned by `ssk-winhost`.
//!
//! # Three-valued, because two values cannot say "I don't know"
//!
//! `ssk_ipc::StatusDto::kill_switch` is a `bool`. `bool` has no room for "the
//! broker did not answer", and the old hardcoded `false` was exactly that
//! missing third value collapsed onto the reassuring side. `ssk-ipc` is outside
//! this change's file scope, so the DTO could not gain a third variant. The
//! compromise, stated so nobody has to infer it:
//!
//! * the **in-daemon** representation is honestly three-valued
//!   ([`KillSwitchView`]) and is never collapsed before a decision is made;
//! * on the wire, `kill_switch` is defined as
//!   [`KillSwitchView::is_confirmed_engaged`] — i.e. `false` now means
//!   **"not confirmed engaged"**, not "confirmed not engaged";
//! * and whenever the view is [`KillSwitchView::Unknown`] the daemon populates
//!   the DTO's existing `last_error` with a typed advisory
//!   ([`KILL_SWITCH_STATUS_UNKNOWN`]), so the third value still reaches the
//!   client instead of being silently rounded to "off".
//!
//! That advisory is the only honest channel the current wire type leaves. It is
//! the daemon defining the meaning of a field it does not own, and that is
//! recorded as a residual rather than hidden.
//!
//! # `view()` must not block
//!
//! A status read that blocks on a pipe connect is how `ssk status` hangs, and
//! `Supervisor::handle` calls [`KillSwitchProvider::view`] while holding the
//! supervisor's mutex inside an async task. So the trait's contract is
//! *non-blocking*: [`CachedBrokerView`] answers from a cache and does its I/O in
//! [`CachedBrokerView::refresh`], which the composition root drives from a
//! background thread. A cached answer older than the staleness bound is
//! `Unknown`, never the last good value — a stale "engaged" is a claim of
//! protection nobody re-established.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use ssk_boundary::KillSwitchState;
use ssk_ipc::IpcError;
use ssk_netd_helper::{KillSwitchStatus, Recovery};

/// The stable machine-readable code the daemon reports when it cannot
/// establish the kill-switch's state. A distinct code (not a generic failure)
/// because the operator action differs: this one means *"go find out whether
/// the privileged broker is running"*, not *"your command failed"*.
pub const KILL_SWITCH_STATUS_UNKNOWN: &str = "KILL_SWITCH_STATUS_UNKNOWN";

/// How long an authoritative answer stays usable before the daemon stops
/// repeating it. Deliberately short: the value is a security claim, and a claim
/// nobody has re-established is not evidence.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(15);

/// How often the composition root's background refresher should poll. Must be
/// comfortably below [`DEFAULT_MAX_AGE`] or every answer is stale by
/// construction.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// The daemon's read-only view of the privileged kill-switch.
///
/// Three-valued on purpose — see the module header. `Unknown` is **never**
/// rendered as "not engaged" inside this crate; the only place it is narrowed
/// is at the wire boundary, and there it is accompanied by an advisory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillSwitchView {
    /// The broker answered: egress is severed, and the OS enforcement backing
    /// that claim was positively observed.
    EngagedConfirmed,
    /// The broker answered coherently: the switch is not engaged.
    NotEngaged,
    /// The broker's own verdict was `Inconsistent`, OR it was unreachable, OR
    /// it answered something this daemon will not interpret, OR no provider is
    /// configured. Carries a fixed reason so it can be logged and explained.
    Unknown { reason: &'static str },
}

impl KillSwitchView {
    /// The reason an `Unknown` is unknown; `None` for a definite answer.
    #[must_use]
    pub fn reason(self) -> Option<&'static str> {
        match self {
            KillSwitchView::Unknown { reason } => Some(reason),
            KillSwitchView::EngagedConfirmed | KillSwitchView::NotEngaged => None,
        }
    }

    /// A short stable label for logs and tests.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            KillSwitchView::EngagedConfirmed => "engaged_confirmed",
            KillSwitchView::NotEngaged => "not_engaged",
            KillSwitchView::Unknown { .. } => "unknown",
        }
    }

    /// The value `ssk_ipc::StatusDto::kill_switch` carries.
    ///
    /// **`false` means "not confirmed engaged".** It does not mean "confirmed
    /// not engaged" — the wire type cannot distinguish those, which is why
    /// [`KillSwitchView::advisory`] exists and why a client that only reads
    /// this bool is reading a lossy projection.
    #[must_use]
    pub fn is_confirmed_engaged(self) -> bool {
        matches!(self, KillSwitchView::EngagedConfirmed)
    }

    /// The typed advisory that must accompany a lossy `false`.
    ///
    /// `Some` exactly when the view is [`KillSwitchView::Unknown`]. This is what
    /// stops the wire's `false` from being a lie: a client that reads
    /// `kill_switch == false` **and** `last_error == None` is entitled to
    /// believe egress is not severed; if the advisory is present it is not
    /// entitled to believe anything.
    #[must_use]
    pub fn advisory(self) -> Option<IpcError> {
        let reason = self.reason()?;
        Some(
            IpcError::new(
                "Boundary",
                KILL_SWITCH_STATUS_UNKNOWN,
                format!("the kill-switch state could not be established: {reason}"),
            )
            .with_next_step(
                "Treat `kill_switch: false` as UNKNOWN, not as off. Check that the privileged \
                 broker service is running and reachable, then re-read status.",
            )
            .retriable(),
        )
    }
}

/// Map the broker's authoritative status onto the daemon's view.
///
/// Pure, total, and the one thing in this module worth mutation-testing. Two
/// orderings matter and are load-bearing:
///
/// 1. `Recovery::Inconsistent` is checked **first**. An inconsistent broker has
///    already decided that its journal and the OS disagree; whatever
///    `logical_state` says in that case is not something to report as fact.
/// 2. `Engaged` is only ever reported as confirmed when the OS enforcement was
///    *positively observed present*. `Engaged` with an unanswerable probe is
///    `Unknown` — a severed-egress claim nobody could confirm.
#[must_use]
pub fn view_of(status: &KillSwitchStatus) -> KillSwitchView {
    if matches!(status.recovery, Recovery::Inconsistent) {
        return KillSwitchView::Unknown {
            reason: "the broker's journal and the observed OS enforcement disagree",
        };
    }
    match (status.logical_state, status.os_rule_present) {
        (KillSwitchState::Engaged, Some(true)) => KillSwitchView::EngagedConfirmed,
        (KillSwitchState::Engaged, Some(false)) => KillSwitchView::Unknown {
            reason: "the broker reports engaged while the OS enforcement was observed absent",
        },
        (KillSwitchState::Engaged, None) => KillSwitchView::Unknown {
            reason: "the broker reports engaged but the OS enforcement could not be observed",
        },
        // Defensive, and deliberately not `NotEngaged`: a rule observed present
        // under a not-engaged journal is a strand, and the broker having called
        // that coherent does not make it something to report as "off".
        (KillSwitchState::Armed | KillSwitchState::Released, Some(true)) => {
            KillSwitchView::Unknown {
                reason: "OS enforcement was observed present while the broker's journal says the \
                         switch is not engaged",
            }
        }
        (KillSwitchState::Armed | KillSwitchState::Released, None | Some(false)) => {
            KillSwitchView::NotEngaged
        }
    }
}

/// Where the daemon's view comes from. Injected at the composition root exactly
/// like `Box<dyn DataPlane>`.
///
/// # Contract
///
/// `view` **must not block and must not perform I/O.** It is called while the
/// supervisor's mutex is held, on an async task. An implementation that dials a
/// pipe here turns `ssk status` into something that can hang.
pub trait KillSwitchProvider: Send + Sync {
    fn view(&self) -> KillSwitchView;
}

/// So one provider can be shared between the supervisor (which reads it) and a
/// background poller (which fills it) without either owning the other.
impl<T: KillSwitchProvider + ?Sized> KillSwitchProvider for std::sync::Arc<T> {
    fn view(&self) -> KillSwitchView {
        (**self).view()
    }
}

/// A provider whose answer is filled from outside, by a poller the composition
/// root owns.
///
/// Split from [`KillSwitchProvider`] so the blocking half cannot be reached
/// from the supervisor's hot path by accident: `Supervisor` holds a
/// `Box<dyn KillSwitchProvider>` and therefore has no way to call
/// [`RefreshableKillSwitch::refresh_once`].
pub trait RefreshableKillSwitch: KillSwitchProvider {
    /// Perform one blocking round trip and store the result.
    fn refresh_once(&self);
}

/// The provider for a build with no privileged broker to ask: every answer is
/// `Unknown`, never `NotEngaged`.
///
/// Used off-Windows and on a Windows machine where the service is not
/// installed. It is *not* a mock standing in for a real answer — "no provider
/// configured" genuinely means the daemon cannot tell.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoProvider;

impl KillSwitchProvider for NoProvider {
    fn view(&self) -> KillSwitchView {
        KillSwitchView::Unknown {
            reason: "no privileged broker is configured for this build",
        }
    }
}

/// Why one attempt to read the broker's authoritative status did not produce
/// one.
///
/// Every variant maps to a fixed `&'static str` so [`KillSwitchView`] can stay
/// `Copy` and so the reason cannot accidentally carry a path, a SID, or a
/// remote-controlled string into a status response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BrokerLinkError {
    /// The endpoint could not be reached at all (not running, not installed,
    /// busy, or refused by the OS).
    #[error("the privileged broker could not be reached: {0}")]
    Unreachable(String),
    /// The endpoint answered but is not the broker, or not owned by the
    /// principal the client requires. **Not** the same as unreachable: this is
    /// the squatter case and deserves its own operator response.
    #[error("the endpoint is not a trustworthy privileged broker: {0}")]
    Untrusted(String),
    /// The broker was reached but the exchange failed (handshake refused,
    /// framing error, command rejected).
    #[error("the privileged broker refused or failed the status read: {0}")]
    Refused(String),
}

impl BrokerLinkError {
    /// The fixed reason this failure contributes to a
    /// [`KillSwitchView::Unknown`].
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            BrokerLinkError::Unreachable(_) => "the privileged broker could not be reached",
            BrokerLinkError::Untrusted(_) => {
                "the privileged endpoint is not owned by the expected principal"
            }
            BrokerLinkError::Refused(_) => "the privileged broker refused the status read",
        }
    }
}

/// One round trip to the privileged broker.
///
/// The I/O seam. Implementations open a connection, handshake, read status, and
/// close — the daemon holds no long-lived privileged connection, so it cannot
/// hold a lease and cannot keep a machine severed by existing.
pub trait BrokerStatusSource: Send + Sync {
    /// # Errors
    /// [`BrokerLinkError`] if no authoritative status could be obtained.
    fn status(&self) -> Result<KillSwitchStatus, BrokerLinkError>;
}

struct Sample {
    at: Instant,
    view: KillSwitchView,
}

/// A [`KillSwitchProvider`] that answers from a bounded-age cache filled by
/// [`CachedBrokerView::refresh`].
///
/// The split exists because `view()` is on the hot, mutex-held, async path and
/// `refresh()` is blocking I/O. The composition root drives `refresh()` from a
/// background thread.
pub struct CachedBrokerView<S: BrokerStatusSource> {
    source: S,
    max_age: Duration,
    cache: Mutex<Option<Sample>>,
}

impl<S: BrokerStatusSource> CachedBrokerView<S> {
    #[must_use]
    pub fn new(source: S) -> Self {
        Self::with_max_age(source, DEFAULT_MAX_AGE)
    }

    #[must_use]
    pub fn with_max_age(source: S, max_age: Duration) -> Self {
        CachedBrokerView {
            source,
            max_age,
            cache: Mutex::new(None),
        }
    }

    /// Ask the broker once and store the result. Returns what was stored.
    ///
    /// A failure stores a fresh `Unknown` rather than leaving the previous
    /// success in place. That ordering is the whole point: if the broker dies
    /// while the switch was engaged, continuing to serve the last good
    /// "engaged" for the rest of the staleness window would be a claim of
    /// protection that nothing is backing.
    pub fn refresh(&self) -> KillSwitchView {
        let view = match self.source.status() {
            Ok(status) => view_of(&status),
            Err(err) => KillSwitchView::Unknown {
                reason: err.reason(),
            },
        };
        self.store(view);
        view
    }

    fn store(&self, view: KillSwitchView) {
        let sample = Sample {
            at: Instant::now(),
            view,
        };
        match self.cache.lock() {
            Ok(mut guard) => *guard = Some(sample),
            // A poisoned cache means a previous holder panicked. Recovering the
            // guard is safe here (the invariant is "a timestamped view", and we
            // are about to overwrite it wholesale), and refusing to recover
            // would wedge the daemon into permanent `Unknown` for the lifetime
            // of the process.
            Err(poisoned) => *poisoned.into_inner() = Some(sample),
        }
    }
}

impl<S: BrokerStatusSource> RefreshableKillSwitch for CachedBrokerView<S> {
    fn refresh_once(&self) {
        let view = self.refresh();
        tracing::debug!(
            target: "ssk.boundary",
            kill_switch = view.as_str(),
            reason = view.reason().unwrap_or(""),
            "refreshed the privileged broker's kill-switch status"
        );
    }
}

impl<S: BrokerStatusSource> KillSwitchProvider for CachedBrokerView<S> {
    fn view(&self) -> KillSwitchView {
        let guard = match self.cache.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_ref() {
            None => KillSwitchView::Unknown {
                reason: "the privileged broker has not answered yet",
            },
            Some(sample) if sample.at.elapsed() > self.max_age => KillSwitchView::Unknown {
                reason: "the last authoritative broker answer is older than the staleness bound",
            },
            Some(sample) => sample.view,
        }
    }
}

/// The Windows production source: one connection to the LocalSystem-owned
/// privileged pipe per read.
///
/// Everything privileged is on the far side of the pipe. This side only:
/// dials `ssk_winhost::PRIVILEGED_PIPE_NAME`, requires the endpoint be owned by
/// `S-1-5-18` (`NamedPipeClientTransport::connect` performs that check *before*
/// the first frame — without it a squatter on the fixed name could answer a
/// forged `Engaged`), performs the versioned handshake with a
/// [`ssk_netd_helper::LeaseKind::Session`] claim, and reads status.
///
/// # Verification boundary
///
/// **This type has never successfully completed a round trip.** No privileged
/// broker service has been installed or started on any machine, so every path
/// through it below `connect` is unexecuted. What *is* exercised by tests is
/// everything above the seam: the error mapping, the caching, the staleness
/// bound and [`view_of`], driven against a real `ssk_netd_helper::Broker` over
/// an in-memory transport.
#[cfg(windows)]
pub struct PrivilegedPipeStatus {
    pipe_name: String,
}

#[cfg(windows)]
impl Default for PrivilegedPipeStatus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(windows)]
impl PrivilegedPipeStatus {
    #[must_use]
    pub fn new() -> Self {
        PrivilegedPipeStatus {
            pipe_name: ssk_winhost::PRIVILEGED_PIPE_NAME.to_owned(),
        }
    }

    /// Point at a non-default endpoint. Exists so an operator can drive a
    /// staging host; it does **not** relax the `S-1-5-18` owner requirement.
    #[must_use]
    pub fn at(pipe_name: impl Into<String>) -> Self {
        PrivilegedPipeStatus {
            pipe_name: pipe_name.into(),
        }
    }
}

/// Nonces from the OS CSPRNG.
///
/// The broker's anti-replay set makes these load-bearing: a predictable nonce is
/// one an attacker can burn ahead of a legitimate client, turning anti-replay
/// into denial of service. A CSPRNG failure is surfaced as an all-zero value
/// **only** after being logged — the alternative (panicking inside a status
/// read) would take the daemon down over a diagnostic.
#[cfg(windows)]
struct OsNonces;

#[cfg(windows)]
impl ssk_netd_helper::NonceSource for OsNonces {
    fn next(&mut self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        if let Err(err) = getrandom::fill(&mut buf) {
            tracing::error!(
                target: "ssk.boundary",
                %err,
                "the OS CSPRNG refused; this status read uses a non-random nonce and may be \
                 rejected as a replay"
            );
        }
        buf
    }
}

#[cfg(windows)]
impl BrokerStatusSource for PrivilegedPipeStatus {
    fn status(&self) -> Result<KillSwitchStatus, BrokerLinkError> {
        use ssk_netd_helper::client::{session_hello, PrivilegedClient};

        let transport = ssk_winhost::privileged::NamedPipeClientTransport::connect(
            &self.pipe_name,
            ssk_winhost::LOCAL_SYSTEM_SID,
        )
        .map_err(|err| {
            // `connect` folds both "nothing is listening" and "the listener is
            // owned by the wrong principal" into `io::Error`. They demand
            // different operator responses, so they are separated here on the
            // one signal available: the owner check reports `PermissionDenied`.
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                BrokerLinkError::Untrusted(err.to_string())
            } else {
                BrokerLinkError::Unreachable(err.to_string())
            }
        })?;

        let mut client = PrivilegedClient::connect(transport, OsNonces, session_hello())
            .map_err(|err| BrokerLinkError::Refused(err.to_string()))?;
        client
            .status()
            .map_err(|err| BrokerLinkError::Refused(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_boundary::{BoundaryScope, EnforcementReceipt};
    use ssk_types::Digest;

    fn status(
        logical_state: KillSwitchState,
        os_rule_present: Option<bool>,
        recovery: Recovery,
    ) -> KillSwitchStatus {
        let scope = BoundaryScope::all_egress();
        KillSwitchStatus {
            logical_state,
            receipt: matches!(logical_state, KillSwitchState::Engaged)
                .then(|| EnforcementReceipt::new(&scope, "flowing")),
            os_rule_present,
            audit_head: Digest::GENESIS,
            audit_len: 1,
            state_version: 1,
            recovery,
        }
    }

    #[test]
    fn engaged_and_positively_observed_is_the_only_confirmed_answer() {
        assert_eq!(
            view_of(&status(
                KillSwitchState::Engaged,
                Some(true),
                Recovery::Consistent
            )),
            KillSwitchView::EngagedConfirmed
        );
        assert_eq!(
            view_of(&status(
                KillSwitchState::Engaged,
                Some(true),
                Recovery::Reconciled
            )),
            KillSwitchView::EngagedConfirmed
        );
    }

    #[test]
    fn an_inconsistent_broker_is_unknown_whatever_its_journal_says() {
        for state in [
            KillSwitchState::Engaged,
            KillSwitchState::Armed,
            KillSwitchState::Released,
        ] {
            for observed in [Some(true), Some(false), None] {
                let v = view_of(&status(state, observed, Recovery::Inconsistent));
                assert!(
                    matches!(v, KillSwitchView::Unknown { .. }),
                    "an inconsistent broker must never yield a definite answer; \
                     {state:?}/{observed:?} produced {v:?}"
                );
            }
        }
    }

    #[test]
    fn engaged_but_unconfirmed_is_unknown_never_engaged_and_never_off() {
        for observed in [None, Some(false)] {
            let v = view_of(&status(
                KillSwitchState::Engaged,
                observed,
                Recovery::Consistent,
            ));
            assert!(
                matches!(v, KillSwitchView::Unknown { .. }),
                "an unconfirmed severed-egress claim must be Unknown; got {v:?}"
            );
            assert!(!v.is_confirmed_engaged());
            assert!(v.advisory().is_some());
        }
    }

    #[test]
    fn a_not_engaged_journal_with_a_rule_present_is_unknown_not_off() {
        for state in [KillSwitchState::Armed, KillSwitchState::Released] {
            let v = view_of(&status(state, Some(true), Recovery::Consistent));
            assert!(
                matches!(v, KillSwitchView::Unknown { .. }),
                "a strand must not be reported as 'off'; {state:?} produced {v:?}"
            );
        }
    }

    #[test]
    fn a_coherent_not_engaged_journal_is_not_engaged() {
        for state in [KillSwitchState::Armed, KillSwitchState::Released] {
            for observed in [None, Some(false)] {
                assert_eq!(
                    view_of(&status(state, observed, Recovery::Consistent)),
                    KillSwitchView::NotEngaged,
                    "{state:?}/{observed:?}"
                );
            }
        }
    }

    #[test]
    fn only_a_confirmed_engagement_sets_the_wire_bool_and_only_unknown_carries_an_advisory() {
        assert!(KillSwitchView::EngagedConfirmed.is_confirmed_engaged());
        assert!(KillSwitchView::EngagedConfirmed.advisory().is_none());

        assert!(!KillSwitchView::NotEngaged.is_confirmed_engaged());
        assert!(KillSwitchView::NotEngaged.advisory().is_none());

        let unknown = KillSwitchView::Unknown { reason: "because" };
        assert!(!unknown.is_confirmed_engaged());
        let advisory = unknown.advisory().expect("unknown must carry an advisory");
        assert_eq!(advisory.code, KILL_SWITCH_STATUS_UNKNOWN);
        assert!(advisory.retriable);
        assert!(
            advisory.message.contains("because"),
            "the advisory must say why: {}",
            advisory.message
        );
        assert!(!advisory.next_steps.is_empty());
    }

    #[test]
    fn no_provider_is_unknown_not_off() {
        let v = NoProvider.view();
        assert!(matches!(v, KillSwitchView::Unknown { .. }));
        assert!(!v.is_confirmed_engaged());
    }

    // ------------------------------------------------------------------
    // The cache. `BrokerStatusSource` is faked here on purpose: these tests
    // are about the caching contract, not about the broker. The broker-backed
    // ones live in `tests/kill_switch_status.rs` and drive a real `Broker`.
    // ------------------------------------------------------------------

    struct Scripted {
        answers: Mutex<Vec<Result<KillSwitchStatus, BrokerLinkError>>>,
        calls: std::sync::atomic::AtomicU32,
    }

    impl Scripted {
        fn new(answers: Vec<Result<KillSwitchStatus, BrokerLinkError>>) -> Self {
            Scripted {
                answers: Mutex::new(answers),
                calls: std::sync::atomic::AtomicU32::new(0),
            }
        }
        fn calls(&self) -> u32 {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl BrokerStatusSource for Scripted {
        fn status(&self) -> Result<KillSwitchStatus, BrokerLinkError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut answers = self.answers.lock().expect("script");
            if answers.is_empty() {
                return Err(BrokerLinkError::Unreachable("script exhausted".into()));
            }
            answers.remove(0)
        }
    }

    #[test]
    fn view_performs_no_io_and_an_unpolled_cache_is_unknown() {
        let source = Scripted::new(vec![Ok(status(
            KillSwitchState::Engaged,
            Some(true),
            Recovery::Consistent,
        ))]);
        let cached = CachedBrokerView::new(source);

        // Called many times; the source must not be touched once.
        for _ in 0..10 {
            assert!(matches!(cached.view(), KillSwitchView::Unknown { .. }));
        }
        assert_eq!(
            cached.source.calls(),
            0,
            "view() must never perform I/O: it runs under the supervisor mutex"
        );

        assert_eq!(cached.refresh(), KillSwitchView::EngagedConfirmed);
        assert_eq!(cached.view(), KillSwitchView::EngagedConfirmed);
        assert_eq!(cached.source.calls(), 1);
    }

    #[test]
    fn a_failed_refresh_replaces_a_good_answer_rather_than_letting_it_ride() {
        let cached = CachedBrokerView::new(Scripted::new(vec![
            Ok(status(
                KillSwitchState::Engaged,
                Some(true),
                Recovery::Consistent,
            )),
            Err(BrokerLinkError::Unreachable("service stopped".into())),
        ]));
        assert_eq!(cached.refresh(), KillSwitchView::EngagedConfirmed);
        let after = cached.refresh();
        assert!(
            matches!(after, KillSwitchView::Unknown { .. }),
            "a dead broker must not leave 'engaged' standing: got {after:?}"
        );
        assert_eq!(cached.view(), after);
    }

    #[test]
    fn an_answer_older_than_the_staleness_bound_is_unknown() {
        let cached = CachedBrokerView::with_max_age(
            Scripted::new(vec![Ok(status(
                KillSwitchState::Engaged,
                Some(true),
                Recovery::Consistent,
            ))]),
            Duration::from_millis(30),
        );
        assert_eq!(cached.refresh(), KillSwitchView::EngagedConfirmed);
        std::thread::sleep(Duration::from_millis(60));
        let v = cached.view();
        assert!(
            matches!(v, KillSwitchView::Unknown { .. }),
            "a stale claim of protection must expire; got {v:?}"
        );
        assert_eq!(
            cached.source.calls(),
            1,
            "expiry must not trigger I/O from view()"
        );
    }

    #[test]
    fn every_link_failure_maps_to_a_distinct_reason() {
        let reasons: Vec<&str> = [
            BrokerLinkError::Unreachable(String::new()),
            BrokerLinkError::Untrusted(String::new()),
            BrokerLinkError::Refused(String::new()),
        ]
        .iter()
        .map(BrokerLinkError::reason)
        .collect();
        let mut unique = reasons.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            reasons.len(),
            "an operator must be able to tell 'not running' from 'squatter' from 'refused'"
        );
    }

    #[test]
    fn the_default_refresh_interval_keeps_a_healthy_link_out_of_staleness() {
        assert!(
            DEFAULT_REFRESH_INTERVAL < DEFAULT_MAX_AGE,
            "a refresh interval at or above the staleness bound makes every answer Unknown"
        );
    }
}
