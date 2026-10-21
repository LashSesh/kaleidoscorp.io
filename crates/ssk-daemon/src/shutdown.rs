#![forbid(unsafe_code)]

//! One cancellation token, many sources.
//!
//! # No FFI is required for this, in either the console or the service case
//!
//! `tokio::signal::windows` already wraps `SetConsoleCtrlHandler` and exports
//! all five console events (`ctrl_c`, `ctrl_break`, `ctrl_close`,
//! `ctrl_logoff`, `ctrl_shutdown`); on Unix `tokio::signal::unix` covers
//! `SIGINT` **and `SIGTERM`** — the latter is unhandled today, so `docker stop`
//! and systemd currently hard-kill the daemon. Writing a bespoke
//! `SetConsoleCtrlHandler` binding in `ssk-winhost` would duplicate a vetted
//! implementation and add `unsafe` for nothing.
//!
//! When the daemon runs in session 0 with no console, `SetConsoleCtrlHandler`
//! registration still succeeds and simply never fires, so the console arm is
//! inert rather than broken. The live route there is
//! `SERVICE_CONTROL_STOP`/`PRESHUTDOWN`, which `windows-service` already owns:
//! the service host flips this same [`Shutdown`] via
//! [`Shutdown::trigger`]. That is the entire integration surface it needs.
//!
//! # Correctness must not depend on any of this running
//!
//! The OS can terminate the process before the token is ever flipped
//! (`CTRL_CLOSE_EVENT` grants roughly `HungAppTimeout` before the process is
//! killed; shutdown is governed by `WaitToKillServiceTimeout`). So graceful
//! shutdown is an *optimisation*, and every invariant it would otherwise
//! maintain is satisfied by construction instead:
//!
//! * the daemon lock is released by the kernel (see [`crate::lock`]);
//! * a Windows named pipe is a kernel object refcounted on handles, so process
//!   death frees the name — which is why the kill-and-restart cycles observed
//!   on Windows 11 rebound cleanly;
//! * the Unix socket is the one asymmetry: an `AF_UNIX` path *does* survive
//!   `SIGKILL`. `ssk_ipc::server::serve_unix` unlinks a leftover path before
//!   binding, which is safe only because the lock is taken first.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::lock::DaemonLock;

/// Why the daemon is stopping. Every variant corresponds to a real OS event or
/// a real internal failure; none is a placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    CtrlC,
    CtrlBreak,
    ConsoleClose,
    Logoff,
    SystemShutdown,
    SigTerm,
    ServiceStop,
    ServicePreshutdown,
    ServerError,
}

impl ShutdownReason {
    /// Stable identifier for logs and for any future SIEM contract.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ShutdownReason::CtrlC => "ctrl_c",
            ShutdownReason::CtrlBreak => "ctrl_break",
            ShutdownReason::ConsoleClose => "console_close",
            ShutdownReason::Logoff => "logoff",
            ShutdownReason::SystemShutdown => "system_shutdown",
            ShutdownReason::SigTerm => "sigterm",
            ShutdownReason::ServiceStop => "service_stop",
            ShutdownReason::ServicePreshutdown => "service_preshutdown",
            ShutdownReason::ServerError => "server_error",
        }
    }

    /// Whether the OS is about to kill us on a short timer, so the short
    /// [`ShutdownPlan`] applies: the time a graceful stop would use is not time
    /// we own.
    #[must_use]
    pub fn is_os_deadline(self) -> bool {
        matches!(
            self,
            ShutdownReason::ConsoleClose
                | ShutdownReason::Logoff
                | ShutdownReason::SystemShutdown
                | ShutdownReason::ServicePreshutdown
        )
    }
}

impl std::fmt::Display for ShutdownReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How long each phase of a stop may take, chosen by [`ShutdownPlan::for_reason`]
/// and the only source of these numbers (design 8.5).
///
/// The phases run in this order:
///
/// * P0 closes the gate to new work (the ingress; nothing in the legacy daemon);
/// * P1 ([`flows`](Self::flows)) lets in-flight flows end, then aborts them;
/// * P2 ([`audit`](Self::audit)) drains the ingress ledger's queue, syncs it and
///   joins its writer thread;
/// * P3 stops the IPC accept loop, which `serve`'s `select!` already did by the
///   time the plan is chosen;
/// * P4 ([`runtime_stop`](Self::runtime_stop)) drops every task still alive.
///   Its bound covers everything the stop does, what a task does while it is
///   dropped included, see the field.
///
/// P0 to P2 belong to the ingress host, which does not exist yet: the daemon
/// executes P3 and P4 only, and `total` is therefore an upper bound for it, not
/// what it takes (measured: a SIGTERM to a daemon with an activation dialling a
/// silent proxy ends it in a few milliseconds, `tests/daemon_shutdown.rs`). The
/// fields are here so that the host takes the whole plan and the numbers are
/// written down once.
///
/// # Budget arithmetic
///
/// * Graceful (`CtrlC`, `CtrlBreak`, `SigTerm`, `ServiceStop`, `ServerError`):
///   700 + 1200 + 1000 = 2900 ms.
/// * OS deadline (`ConsoleClose`, `Logoff`, `SystemShutdown`,
///   `ServicePreshutdown`): 0 + 600 + 200 = 800 ms.
///
/// What those are compared with is not in this repository. `CTRL_CLOSE_EVENT`
/// grants "roughly `HungAppTimeout`" and service shutdown is governed by
/// `WaitToKillServiceTimeout`; neither value is read, set or verified here and
/// nothing in this crate has run on Windows, so the 800 ms is chosen small
/// against any plausible value, not measured against one (UNVERIFIED on
/// Windows). It is also below the single 2 s `DRAIN_DEADLINE` this plan
/// replaces, which was handed to every reason, OS-deadline ones included, while
/// its comment said the OS would not wait for it. The graceful 2.9 s is above
/// that 2 s on purpose: Ctrl-C, SIGTERM and an operator's service stop are not
/// on an OS timer ([`ShutdownReason::is_os_deadline`]), and the supervisors that
/// send SIGTERM wait longer by default (`docker stop` 10 s, systemd
/// `TimeoutStopSec` 90 s; upstream defaults, not checked here). The log flush at
/// the end of `main` runs after the plan and is in neither total.
///
/// What P4's share has to be big enough for is the one thing the daemon does
/// with it today: the terminal `FailClosed` ledger record of an activation that
/// was mid-dial. That write verifies the whole ledger, then rewrites it through
/// a temp file, `fsync` and rename, so its time grows with the ledger and with a
/// slow or busy disk. It was timed only on a fast local disk with a ledger of
/// one entry before it (under 10 ms from SIGTERM to exit,
/// `tests/daemon_shutdown.rs`); against 1000 ms that is a wide margin, against
/// the 200 ms of the OS-deadline plan it is an assumption that nothing here has
/// measured on a large ledger, a slow disk or Windows. An accepted risk, not a
/// solved one: see [`runtime_stop`](Self::runtime_stop) for what a write that
/// does not fit leaves behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownPlan {
    /// P1: flows end by themselves, then `abort_all`.
    pub flows: Duration,
    /// P2: the audit queue drains, a last sync, the writer thread is joined.
    pub audit: Duration,
    /// P4: `Runtime::shutdown_timeout`, which waits for the runtime's blocking
    /// pool for at most this long. That one bound covers everything the stop
    /// does, drop-time work included: the multi-thread scheduler drops its tasks
    /// on its worker threads, and those are threads of the blocking pool
    /// (`tokio` 1.53.1, `runtime/scheduler/multi_thread/worker.rs`), so what
    /// a task does while it is dropped (an abandoned activation writing its
    /// terminal `FailClosed` ledger record) is waited for no longer than blocking
    /// work (name resolution, a ledger open) is.
    ///
    /// What is still running when the bound ends is not stopped. `run` returns,
    /// the process exits and ends it where it stands. For a ledger write that
    /// leaves the file as it was, whole (the new entry list goes to a temp file,
    /// is synced and renamed over it), without the record: the activation's
    /// `DispatchPending` then has no terminal record, the state the settlement
    /// exists to prevent. The lock is held through all of this
    /// ([`DaemonLock::hold_until_exit`]), so no second daemon appends in between;
    /// it does not make the record appear.
    pub runtime_stop: Duration,
}

impl ShutdownPlan {
    /// A stop nobody is timing: Ctrl-C, Ctrl-Break, SIGTERM, a service stop, or
    /// the IPC server ending.
    pub const GRACEFUL: Self = Self {
        flows: Duration::from_millis(700),
        audit: Duration::from_millis(1200),
        runtime_stop: Duration::from_millis(1000),
    };

    /// A stop the OS will cut short: console close, logoff, system shutdown,
    /// service pre-shutdown. Flows are aborted at once.
    pub const OS_DEADLINE: Self = Self {
        flows: Duration::ZERO,
        audit: Duration::from_millis(600),
        runtime_stop: Duration::from_millis(200),
    };

    /// The plan for a stop. Pure: the reason alone decides.
    #[must_use]
    pub fn for_reason(reason: ShutdownReason) -> Self {
        if reason.is_os_deadline() {
            Self::OS_DEADLINE
        } else {
            Self::GRACEFUL
        }
    }

    /// The sum of the phases: the longest a stop that follows the plan takes.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.flows
            .saturating_add(self.audit)
            .saturating_add(self.runtime_stop)
    }

    /// P4, then the lock: stop `runtime` within [`runtime_stop`](Self::runtime_stop)
    /// and keep `lock` until the process ends.
    ///
    /// The order is the point. `shutdown_timeout` drops every task, and a task
    /// dropped mid-dial still writes: `ActivationScope` gives an abandoned
    /// activation its terminal ledger record while it is dropped. Releasing the
    /// lock first let a second daemon start, and extend the same hash chain,
    /// while the old runtime was still writing to it. Work that outlives the
    /// bound, blocking work or a task's drop-time write alike, is leaked, not
    /// stopped (`Runtime::drop` would wait for it without end, which is why
    /// `shutdown_timeout` is used), so the lock is not released by dropping it
    /// after this call either: see [`DaemonLock::hold_until_exit`].
    ///
    /// The bound is also the limit of the guarantee. A drop-time write that
    /// finishes within it is on disk when this returns; one that does not is cut
    /// off by the process exit that follows, and its record is lost (see
    /// [`runtime_stop`](Self::runtime_stop)).
    pub fn stop_runtime_then_hold_lock(self, runtime: tokio::runtime::Runtime, lock: DaemonLock) {
        runtime.shutdown_timeout(self.runtime_stop);
        lock.hold_until_exit();
    }
}

/// The single cancellation token every shutdown source funnels into.
///
/// A `tokio::sync::watch` rather than `tokio_util::sync::CancellationToken`,
/// so no new dependency is required and the *reason* rides along with the
/// signal.
#[derive(Debug, Clone)]
pub struct Shutdown {
    tx: Arc<watch::Sender<Option<ShutdownReason>>>,
}

impl Shutdown {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(None);
        Self { tx: Arc::new(tx) }
    }

    /// Request shutdown. The **first** reason wins: a later source cannot
    /// relabel why the daemon is going down. Returns `true` if this call is
    /// the one that triggered it.
    pub fn trigger(&self, reason: ShutdownReason) -> bool {
        let mut fired = false;
        self.tx.send_if_modified(|slot| {
            if slot.is_none() {
                *slot = Some(reason);
                fired = true;
                true
            } else {
                false
            }
        });
        fired
    }

    /// The reason, if shutdown has been requested.
    #[must_use]
    pub fn reason(&self) -> Option<ShutdownReason> {
        *self.tx.borrow()
    }

    #[must_use]
    pub fn watcher(&self) -> ShutdownWatcher {
        ShutdownWatcher {
            rx: self.tx.subscribe(),
        }
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// A read side of the token. Held by the accept loop and by any task that
/// wants to stop when the daemon does.
#[derive(Debug, Clone)]
pub struct ShutdownWatcher {
    rx: watch::Receiver<Option<ShutdownReason>>,
}

impl ShutdownWatcher {
    /// Resolve when shutdown is requested, yielding the reason. Resolves
    /// immediately if it was already requested before this call.
    pub async fn wait(&mut self) -> ShutdownReason {
        loop {
            if let Some(reason) = *self.rx.borrow_and_update() {
                return reason;
            }
            if self.rx.changed().await.is_err() {
                // Every sender is gone, which can only mean the process is
                // tearing down anyway. Treat it as a stop rather than hanging.
                return ShutdownReason::ServerError;
            }
        }
    }

    #[must_use]
    pub fn triggered(&self) -> Option<ShutdownReason> {
        *self.rx.borrow()
    }
}

/// Await the first OS shutdown signal this platform can deliver.
///
/// # Errors
/// Propagates registration failure from the underlying signal handlers.
#[cfg(windows)]
pub async fn first_os_signal() -> std::io::Result<ShutdownReason> {
    use tokio::signal::windows;

    let mut ctrl_c = windows::ctrl_c()?;
    let mut ctrl_break = windows::ctrl_break()?;
    let mut ctrl_close = windows::ctrl_close()?;
    let mut ctrl_logoff = windows::ctrl_logoff()?;
    let mut ctrl_shutdown = windows::ctrl_shutdown()?;

    let reason = tokio::select! {
        _ = ctrl_c.recv() => ShutdownReason::CtrlC,
        _ = ctrl_break.recv() => ShutdownReason::CtrlBreak,
        _ = ctrl_close.recv() => ShutdownReason::ConsoleClose,
        _ = ctrl_logoff.recv() => ShutdownReason::Logoff,
        _ = ctrl_shutdown.recv() => ShutdownReason::SystemShutdown,
    };
    Ok(reason)
}

/// Await the first OS shutdown signal this platform can deliver.
///
/// # Errors
/// Propagates registration failure from the underlying signal handlers.
#[cfg(unix)]
pub async fn first_os_signal() -> std::io::Result<ShutdownReason> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    let reason = tokio::select! {
        _ = sigint.recv() => ShutdownReason::CtrlC,
        _ = sigterm.recv() => ShutdownReason::SigTerm,
    };
    Ok(reason)
}

/// Spawn the OS-signal listener. It triggers `shutdown` on the first event and
/// then exits; the token, not this task, is what the rest of the daemon reads.
pub fn spawn_os_signal_listener(shutdown: Shutdown) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        match first_os_signal().await {
            Ok(reason) => {
                if shutdown.trigger(reason) {
                    tracing::info!(
                        target: "ssk.lifecycle",
                        reason = reason.as_str(),
                        os_deadline = reason.is_os_deadline(),
                        "shutdown requested"
                    );
                }
            }
            Err(err) => {
                // Registration failing is not itself a reason to stop; it means
                // this daemon can only be stopped by a harder mechanism, and an
                // operator needs to know that rather than guess.
                tracing::error!(
                    target: "ssk.lifecycle",
                    %err,
                    "could not register OS shutdown signals; graceful stop is unavailable"
                );
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_token_is_not_triggered() {
        let shutdown = Shutdown::new();
        assert_eq!(shutdown.reason(), None);
        assert_eq!(shutdown.watcher().triggered(), None);
    }

    #[test]
    fn the_first_reason_wins() {
        let shutdown = Shutdown::new();
        assert!(shutdown.trigger(ShutdownReason::ConsoleClose));
        assert!(!shutdown.trigger(ShutdownReason::CtrlC));
        assert_eq!(shutdown.reason(), Some(ShutdownReason::ConsoleClose));
    }

    #[tokio::test]
    async fn a_watcher_created_before_the_trigger_observes_it() {
        let shutdown = Shutdown::new();
        let mut watcher = shutdown.watcher();
        let handle = tokio::spawn(async move { watcher.wait().await });
        // Give the waiter a chance to park before the trigger, so this
        // exercises the `changed()` path rather than the fast path.
        tokio::task::yield_now().await;
        shutdown.trigger(ShutdownReason::SigTerm);
        assert_eq!(handle.await.expect("join"), ShutdownReason::SigTerm);
    }

    #[tokio::test]
    async fn a_watcher_created_after_the_trigger_resolves_immediately() {
        let shutdown = Shutdown::new();
        shutdown.trigger(ShutdownReason::ServiceStop);
        let mut watcher = shutdown.watcher();
        let reason = tokio::time::timeout(std::time::Duration::from_secs(1), watcher.wait())
            .await
            .expect("a late watcher must not hang");
        assert_eq!(reason, ShutdownReason::ServiceStop);
    }

    #[tokio::test]
    async fn a_clone_of_the_token_triggers_the_same_shutdown() {
        // This is the shape the P3 service-control handler uses: it is handed a
        // clone and flips it from a completely separate callback.
        let shutdown = Shutdown::new();
        let from_service_handler = shutdown.clone();
        let mut watcher = shutdown.watcher();
        from_service_handler.trigger(ShutdownReason::ServicePreshutdown);
        assert_eq!(watcher.wait().await, ShutdownReason::ServicePreshutdown);
        assert_eq!(shutdown.reason(), Some(ShutdownReason::ServicePreshutdown));
    }

    #[test]
    fn every_reason_has_a_distinct_stable_identifier() {
        let all = [
            ShutdownReason::CtrlC,
            ShutdownReason::CtrlBreak,
            ShutdownReason::ConsoleClose,
            ShutdownReason::Logoff,
            ShutdownReason::SystemShutdown,
            ShutdownReason::SigTerm,
            ShutdownReason::ServiceStop,
            ShutdownReason::ServicePreshutdown,
            ShutdownReason::ServerError,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for reason in all {
            assert!(seen.insert(reason.as_str()), "duplicate id for {reason:?}");
            assert_eq!(reason.to_string(), reason.as_str());
        }
        assert_eq!(seen.len(), all.len());
    }

    #[test]
    fn the_os_deadline_reasons_are_exactly_the_ones_the_os_times_out() {
        assert!(ShutdownReason::ConsoleClose.is_os_deadline());
        assert!(ShutdownReason::Logoff.is_os_deadline());
        assert!(ShutdownReason::SystemShutdown.is_os_deadline());
        assert!(ShutdownReason::ServicePreshutdown.is_os_deadline());
        // Ctrl-C and an operator-issued service stop are not on a hard OS
        // timer in the same way, so the drain budget is genuinely ours.
        assert!(!ShutdownReason::CtrlC.is_os_deadline());
        assert!(!ShutdownReason::SigTerm.is_os_deadline());
        assert!(!ShutdownReason::ServiceStop.is_os_deadline());
    }

    const GRACEFUL_REASONS: [ShutdownReason; 5] = [
        ShutdownReason::CtrlC,
        ShutdownReason::CtrlBreak,
        ShutdownReason::SigTerm,
        ShutdownReason::ServiceStop,
        ShutdownReason::ServerError,
    ];
    const OS_DEADLINE_REASONS: [ShutdownReason; 4] = [
        ShutdownReason::ConsoleClose,
        ShutdownReason::Logoff,
        ShutdownReason::SystemShutdown,
        ShutdownReason::ServicePreshutdown,
    ];

    #[test]
    fn shutdown_plan_totals_fit_their_budgets_and_reasons_map_to_plans() {
        let ms = Duration::from_millis;
        // The table of design 8.5, one number per line: changing any of them is
        // a decision about the daemon's exit time and has to change this test.
        assert_eq!(ShutdownPlan::GRACEFUL.flows, ms(700));
        assert_eq!(ShutdownPlan::GRACEFUL.audit, ms(1200));
        assert_eq!(ShutdownPlan::GRACEFUL.runtime_stop, ms(1000));
        assert_eq!(ShutdownPlan::GRACEFUL.total(), ms(2900));
        assert_eq!(ShutdownPlan::OS_DEADLINE.flows, ms(0));
        assert_eq!(ShutdownPlan::OS_DEADLINE.audit, ms(600));
        assert_eq!(ShutdownPlan::OS_DEADLINE.runtime_stop, ms(200));
        assert_eq!(ShutdownPlan::OS_DEADLINE.total(), ms(800));

        // A stop the OS will cut short never gets more of any phase than a
        // graceful one, and the total stays under a second.
        let (os, graceful) = (ShutdownPlan::OS_DEADLINE, ShutdownPlan::GRACEFUL);
        assert!(os.flows <= graceful.flows);
        assert!(os.audit <= graceful.audit);
        assert!(os.runtime_stop <= graceful.runtime_stop);
        assert!(os.total() < Duration::from_secs(1));

        // Every reason, spelled out here rather than derived from
        // `is_os_deadline`, so that the mapping is checked against the intent
        // and not against itself. The match has no wildcard: a tenth reason does
        // not compile until it is placed.
        let mut seen = 0;
        for reason in GRACEFUL_REASONS.into_iter().chain(OS_DEADLINE_REASONS) {
            let expected = match reason {
                ShutdownReason::CtrlC
                | ShutdownReason::CtrlBreak
                | ShutdownReason::SigTerm
                | ShutdownReason::ServiceStop
                | ShutdownReason::ServerError => ShutdownPlan::GRACEFUL,
                ShutdownReason::ConsoleClose
                | ShutdownReason::Logoff
                | ShutdownReason::SystemShutdown
                | ShutdownReason::ServicePreshutdown => ShutdownPlan::OS_DEADLINE,
            };
            let listed_as_os = OS_DEADLINE_REASONS.contains(&reason);
            assert_eq!(
                expected == ShutdownPlan::OS_DEADLINE,
                listed_as_os,
                "{reason}"
            );
            assert_eq!(ShutdownPlan::for_reason(reason), expected, "{reason}");
            seen += 1;
        }
        assert_eq!(seen, 9, "the plan must be checked for all nine reasons");
    }

    #[test]
    fn the_total_of_a_plan_saturates_instead_of_panicking() {
        let plan = ShutdownPlan {
            flows: Duration::MAX,
            audit: Duration::MAX,
            runtime_stop: Duration::from_secs(1),
        };
        assert_eq!(plan.total(), Duration::MAX);
    }

    fn lock_info(dir: &std::path::Path) -> crate::lock::LockInfo {
        crate::lock::LockInfo::for_this_process(dir, "test-endpoint", "0.0.0")
    }

    fn multi_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("runtime")
    }

    /// Tries to take the daemon lock when it is dropped and records whether it
    /// was refused. A task holding one is dropped by the runtime during
    /// `shutdown_timeout`, which is the moment the old shutdown order had already
    /// given the lock up.
    struct TryLockOnDrop {
        path: std::path::PathBuf,
        info: crate::lock::LockInfo,
        refused: Arc<std::sync::Mutex<Option<bool>>>,
    }

    impl Drop for TryLockOnDrop {
        fn drop(&mut self) {
            let attempt = crate::lock::acquire(&self.path, &self.info, Duration::ZERO);
            if let Ok(mut slot) = self.refused.lock() {
                *slot = Some(attempt.is_err());
            }
        }
    }

    #[test]
    fn the_lock_is_still_held_while_the_runtime_drops_its_tasks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = lock_info(dir.path());
        let lock = crate::lock::acquire(&path, &info, Duration::ZERO).expect("acquire");
        let refused = Arc::new(std::sync::Mutex::new(None));

        let runtime = multi_thread_runtime();
        let guard = TryLockOnDrop {
            path: path.clone(),
            info,
            refused: Arc::clone(&refused),
        };
        // Parked for ever: only the runtime dropping it ends it, as with an
        // activation whose dial is silent.
        runtime.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        ShutdownPlan::GRACEFUL.stop_runtime_then_hold_lock(runtime, lock);

        let seen = *refused.lock().expect("slot");
        assert_eq!(
            seen,
            Some(true),
            "the runtime dropped a task after the daemon lock had been released \
             (None: the task was never dropped)"
        );
    }

    #[test]
    fn a_blocking_task_that_outlives_the_bound_neither_hangs_the_stop_nor_frees_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = lock_info(dir.path());
        let lock = crate::lock::acquire(&path, &info, Duration::ZERO).expect("acquire");

        let runtime = multi_thread_runtime();
        let (release, parked) = std::sync::mpsc::channel::<()>();
        let (started_tx, started) = std::sync::mpsc::channel::<()>();
        // The kind of work the design worries about (name resolution, a ledger
        // open): on the blocking pool, not stoppable, not finishing.
        runtime.spawn_blocking(move || {
            let _ = started_tx.send(());
            let _ = parked.recv();
        });
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("the blocking task must be running before the stop");

        let plan = ShutdownPlan {
            runtime_stop: Duration::from_millis(100),
            ..ShutdownPlan::GRACEFUL
        };
        let (done_tx, done) = std::sync::mpsc::channel::<()>();
        let stopper = std::thread::spawn(move || {
            plan.stop_runtime_then_hold_lock(runtime, lock);
            let _ = done_tx.send(());
        });
        let returned = done.recv_timeout(Duration::from_secs(3));
        // Let the blocking task go whatever happened, so a failing run does not
        // leave a thread (and, with `Runtime::drop`, a stuck stop) behind.
        let _ = release.send(());
        stopper.join().expect("stopper thread");
        returned.expect("the stop waited for a blocking task for longer than its bound");

        // The task outlived the bound, so the lock must outlive it too.
        let err = crate::lock::acquire(&path, &lock_info(dir.path()), Duration::ZERO)
            .expect_err("the lock was released although the runtime's work can still run");
        assert!(
            matches!(err.code(), "DAEMON_ALREADY_RUNNING" | "LOCK_CONTENDED"),
            "{err}"
        );
    }

    /// A task whose drop takes `work`, standing for what `ActivationScope` does
    /// when the runtime drops an abandoned activation: verify the ledger, rewrite
    /// it to a temp file, fsync, rename. `done` is set when that work has ended,
    /// and the channel wakes whoever waits for it.
    struct SlowDrop {
        work: Duration,
        done: Arc<std::sync::atomic::AtomicBool>,
        finished: std::sync::mpsc::Sender<()>,
    }

    impl Drop for SlowDrop {
        fn drop(&mut self) {
            std::thread::sleep(self.work);
            self.done.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = self.finished.send(());
        }
    }

    /// What `stop_a_runtime_whose_task_drops_slowly` saw.
    struct SlowDropStop {
        elapsed: Duration,
        /// Whether the task's drop had ended by the time the stop returned.
        done_at_return: bool,
        /// Whether a second acquisition of the daemon lock was refused afterwards.
        lock_refused: bool,
        /// The drop's own end, which the stop does not wait for past its bound.
        finished: std::sync::mpsc::Receiver<()>,
    }

    /// Stop a runtime under `plan`, as `run` does, while its one task takes
    /// `work` to drop. The drop runs on a worker thread, which is a thread of the
    /// runtime's blocking pool, and that pool is what `shutdown_timeout` waits on.
    fn stop_a_runtime_whose_task_drops_slowly(plan: ShutdownPlan, work: Duration) -> SlowDropStop {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = lock_info(dir.path());
        let lock = crate::lock::acquire(&path, &info, Duration::ZERO).expect("acquire");

        let runtime = multi_thread_runtime();
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (finished_tx, finished) = std::sync::mpsc::channel::<()>();
        let slow = SlowDrop {
            work,
            done: Arc::clone(&done),
            finished: finished_tx,
        };
        // Parked for ever, like an activation whose dial is silent: only the
        // runtime dropping it ends it.
        runtime.spawn(async move {
            let _slow = slow;
            std::future::pending::<()>().await;
        });

        let stopper = std::thread::spawn(move || {
            let began = std::time::Instant::now();
            plan.stop_runtime_then_hold_lock(runtime, lock);
            let elapsed = began.elapsed();
            // Read in the thread that stopped, at once: a later read would see a
            // drop that ended in the meantime.
            (elapsed, done.load(std::sync::atomic::Ordering::SeqCst))
        });
        let (elapsed, done_at_return) = stopper.join().expect("stopper thread");

        let lock_refused = matches!(
            crate::lock::acquire(&path, &lock_info(dir.path()), Duration::ZERO),
            Err(err) if matches!(err.code(), "DAEMON_ALREADY_RUNNING" | "LOCK_CONTENDED")
        );
        SlowDropStop {
            elapsed,
            done_at_return,
            lock_refused,
            finished,
        }
    }

    #[test]
    fn a_task_whose_drop_fits_the_stop_bound_has_finished_when_the_stop_returns() {
        // The case the compatibility paragraph relies on: the abandoned
        // activation's ledger record is on disk before the stop returns, so
        // before the process ends.
        let bound = Duration::from_secs(5);
        let plan = ShutdownPlan {
            runtime_stop: bound,
            ..ShutdownPlan::GRACEFUL
        };
        let stop = stop_a_runtime_whose_task_drops_slowly(plan, Duration::from_millis(50));
        assert!(
            stop.done_at_return,
            "the stop returned before a drop that fits its bound had finished"
        );
        // A generous bound is a ceiling, not a delay: the stop ends when the
        // runtime has.
        assert!(
            stop.elapsed < bound,
            "the stop waited out its bound ({:?}) with nothing left to wait for",
            stop.elapsed
        );
        assert!(
            stop.lock_refused,
            "the daemon lock was released by the stop"
        );
    }

    #[test]
    fn a_task_whose_drop_outlasts_the_stop_bound_is_still_running_when_the_stop_returns() {
        // Pins the outcome the documentation states, not one anybody wants: the
        // drop-time work of a task is inside the bound, and what is not finished
        // when the bound ends is cut off by the process ending, with nothing
        // stopping it before. The ledger record an abandoned activation writes
        // while dropped is lost that way, which is why the bound is a figure to
        // size against the slowest ledger write and not only against blocking
        // work.
        let work = Duration::from_millis(1500);
        let plan = ShutdownPlan {
            runtime_stop: Duration::from_millis(300),
            ..ShutdownPlan::GRACEFUL
        };
        let stop = stop_a_runtime_whose_task_drops_slowly(plan, work);
        assert!(
            !stop.done_at_return,
            "the stop waited for a drop that outlasts its bound"
        );
        assert!(
            stop.elapsed < work,
            "the stop took {:?}, as long as the drop it was to cut off",
            stop.elapsed
        );
        // The lock outlives the bound and the work it cannot stop.
        assert!(
            stop.lock_refused,
            "the daemon lock was released while a task's drop could still write"
        );
        // Cut off is not stopped: only the process ending ends it, so the work
        // goes on past the stop and the test has to wait for it to end its thread.
        stop.finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the slow drop never ended");
    }

    #[tokio::test]
    async fn registering_the_os_signal_listener_succeeds_on_this_platform() {
        // Falsifiable: if `tokio`'s console/POSIX handlers cannot be
        // registered here, graceful shutdown silently does not exist and this
        // goes red rather than the daemon shipping with an inert listener.
        let shutdown = Shutdown::new();
        let handle = spawn_os_signal_listener(shutdown.clone());
        // No signal is sent, so the listener must still be parked (registered
        // and waiting), not finished with a registration error.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "the signal listener exited early, which means registration failed"
        );
        assert_eq!(shutdown.reason(), None);
        handle.abort();
    }
}
