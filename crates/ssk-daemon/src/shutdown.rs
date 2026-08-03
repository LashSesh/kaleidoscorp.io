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

use tokio::sync::watch;

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

    /// Whether the OS is about to kill us on a short timer, so the drain
    /// budget must be treated as advisory rather than as time we actually own.
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
