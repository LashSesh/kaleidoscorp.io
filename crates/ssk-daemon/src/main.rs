#![forbid(unsafe_code)]

//! `sskd` — the Kaleidoscorp daemon.
//!
//! # Why there is no `std::process::exit` below `ssk_diag::init`
//!
//! `main` returns [`ExitCode`] and every failure path propagates one.
//! `std::process::exit` runs **no destructors**, which would discard the
//! non-blocking log worker's buffer. (The daemon lock is not released by a
//! destructor: it is held to the end of the process, see `run`.) The previous
//! `main` called it in three places.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use ssk_daemon::cli::Args;
use ssk_daemon::config_load::load_daemon_config;
use ssk_daemon::lock::{DaemonLock, LockInfo};
use ssk_daemon::paths::Layout;
use ssk_daemon::shutdown::{Shutdown, ShutdownPlan, ShutdownReason};
use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::Endpoint;
use ssk_netcore::{DataPlane, NetcoreDataPlane, RouteExecutor};

const BINARY: &str = "sskd";
const BUILD: &str = env!("CARGO_PKG_VERSION");

/// Usage error (bad arguments). Matches `ssk-cli`'s `ErrorClass::Usage`.
const EXIT_USAGE: u8 = 2;
/// Startup failure: unresolvable state dir, unusable state dir, lock held.
const EXIT_STARTUP: u8 = 1;
/// The IPC server exited with an error.
const EXIT_SERVER: u8 = 1;

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args_os().skip(1)) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if args.help {
        println!("{}", ssk_daemon::cli::USAGE);
        return ExitCode::SUCCESS;
    }

    // Resolved before any thread exists, because of the `set_var` below.
    let layout = match Layout::resolve() {
        Ok(layout) => layout,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    if args.print_lock_holder {
        return print_lock_holder(&layout);
    }

    if let Err(err) = std::fs::create_dir_all(layout.root()) {
        eprintln!(
            "failed to create state directory {}: {err}",
            layout.root().display()
        );
        return ExitCode::from(EXIT_STARTUP);
    }

    // Pin the resolved root for the rest of the process. `ssk_ipc::paths` is
    // the shared resolver, but it re-reads the environment on every call and
    // its default branch depends on variables that could be edited underneath
    // a long-lived daemon; the Windows pipe name is a digest over this exact
    // string, so it must not drift mid-run. Done here, single-threaded, before
    // the tokio runtime exists — mutating the environment once threads are
    // running is a race on Unix.
    std::env::set_var("SSK_STATE_DIR", layout.root());

    // `StderrPolicy::Always`: a daemon's stderr *is* a log, unlike `ssk`'s,
    // which is a user-facing surface the typed error contract already owns.
    let guard = ssk_diag::init(
        BINARY,
        Some(&layout.logs_dir()),
        ssk_diag::StderrPolicy::Always,
    );
    if let Some(err) = &guard.file_sink_error {
        tracing::error!(target: "ssk.lifecycle", error = %err, "no durable log sink; stderr only");
    }
    ssk_diag::install_panic_hook(BINARY, Some(layout.crash_dir()), BUILD);

    let code = run(&layout, &args);

    // Explicit, ordered, and last: flushes the non-blocking log worker.
    drop(guard);
    code
}

/// `--print-lock-holder`: read-only, takes no lock, starts nothing.
fn print_lock_holder(layout: &Layout) -> ExitCode {
    let path = layout.lock_path();
    match ssk_daemon::lock::read_holder(&path) {
        Some(info) => match serde_json::to_string_pretty(&info) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("could not render the lock record: {err}");
                ExitCode::from(EXIT_STARTUP)
            }
        },
        None => {
            eprintln!(
                "no readable sskd lock record at {} (which says nothing about liveness — the \
                 kernel handle is the lock, not the file)",
                path.display()
            );
            ExitCode::from(EXIT_STARTUP)
        }
    }
}

fn run(layout: &Layout, args: &Args) -> ExitCode {
    let endpoint = match ssk_daemon::paths::endpoint(layout) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            tracing::error!(target: "ssk.lifecycle", %err, "cannot determine an IPC endpoint");
            eprintln!("{err}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    let info = LockInfo::for_this_process(layout.root(), &endpoint.to_string(), BUILD);
    let lock = match ssk_daemon::lock::acquire(&layout.lock_path(), &info, args.lock_wait) {
        Ok(lock) => lock,
        Err(err) => {
            tracing::error!(target: "ssk.lifecycle", code = err.code(), %err, "refusing to start");
            eprintln!("{err}");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            tracing::error!(target: "ssk.lifecycle", %err, "could not start the async runtime");
            return ExitCode::from(EXIT_STARTUP);
        }
    };

    let (code, plan) = runtime.block_on(serve(layout, endpoint, &lock));

    // P4 of the shutdown plan, then the lock, in that order and with the lock
    // kept to the end of the process (`ShutdownPlan::stop_runtime_then_hold_lock`
    // says why). Dropping the lock here, as this did before, let a successor
    // start while the runtime was still dropping tasks that write to the ledger.
    plan.stop_runtime_then_hold_lock(runtime, lock);
    code
}

/// The kill-switch half of the composition root.
///
/// Returns the provider the supervisor reads and, when there is a real broker
/// to ask, the same object as something a poller can fill. Two properties are
/// deliberate:
///
/// * the two halves are the *same* cache, shared by `Arc`, so a client never
///   reads a different answer than the poller last stored;
/// * off-Windows — and on a Windows box with no privileged broker — the
///   provider is [`ssk_daemon::killswitch::NoProvider`], which answers
///   `Unknown`. It does **not** answer "not engaged". This daemon has no way to
///   know whether some other mechanism severed egress, and saying "off" would
///   be the fabricated-safe-value defect this seam replaced.
///
/// # Not verified
///
/// On Windows this constructs the real pipe client, but **no privileged broker
/// service has ever been installed or started**, so `refresh_once` has never
/// completed a round trip on any machine. Until it does, the honest production
/// answer is `Unknown` with reason "the privileged broker could not be reached"
/// — which is exactly what the code below produces, and is why that path is
/// worth having rather than short-circuiting to `NoProvider`.
fn build_kill_switch_view() -> (
    Box<dyn ssk_daemon::killswitch::KillSwitchProvider>,
    Option<Arc<dyn ssk_daemon::killswitch::RefreshableKillSwitch>>,
) {
    #[cfg(windows)]
    {
        let cached = Arc::new(ssk_daemon::killswitch::CachedBrokerView::new(
            ssk_daemon::killswitch::PrivilegedPipeStatus::new(),
        ));
        (Box::new(Arc::clone(&cached)), Some(cached))
    }
    #[cfg(not(windows))]
    {
        (Box::new(ssk_daemon::killswitch::NoProvider), None)
    }
}

/// Poll the privileged broker on an interval, off the async worker threads.
///
/// `spawn_blocking` is not decoration: the read dials a named pipe with an
/// OS-level connect retry and a read timeout, and doing that on a runtime worker
/// would stall unrelated IPC clients. Aborting the returned handle stops the
/// poller; the in-flight blocking call is not cancellable and is simply allowed
/// to finish and be discarded.
fn spawn_kill_switch_poller(
    refresher: Arc<dyn ssk_daemon::killswitch::RefreshableKillSwitch>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ssk_daemon::killswitch::DEFAULT_REFRESH_INTERVAL);
        // The first tick fires immediately, so the daemon has an authoritative
        // answer (or an honest failure to obtain one) without waiting a full
        // interval while reporting "not answered yet".
        loop {
            ticker.tick().await;
            let handle = Arc::clone(&refresher);
            if tokio::task::spawn_blocking(move || handle.refresh_once())
                .await
                .is_err()
            {
                // The blocking pool is gone (runtime shutting down) or the read
                // panicked. Either way stop polling rather than spinning; the
                // cached answer then ages out to `Unknown` on its own, which is
                // the correct thing for a poller that has stopped.
                tracing::warn!(
                    target: "ssk.boundary",
                    "the kill-switch poller stopped; status will report unknown once the last \
                     answer goes stale"
                );
                break;
            }
        }
    })
}

/// Serve until a shutdown source fires or the IPC server ends. Returns the exit
/// code and the shutdown plan; `run` carries out P4 and the lock hold, because
/// both need the runtime this future runs on to be gone.
async fn serve(layout: &Layout, endpoint: Endpoint, lock: &DaemonLock) -> (ExitCode, ShutdownPlan) {
    let config_path = std::env::var_os("SSK_CONFIG_PATH").map(PathBuf::from);
    let config = load_daemon_config(config_path.as_deref());
    match &config {
        Ok(loaded) => {
            tracing::info!(migrated_from = ?loaded.migrated_from, "config loaded");
        }
        Err(err) => {
            // Keep IPC available for diagnosis. The supervisor owns this
            // failure and refuses activation until a corrected restart.
            tracing::error!(%err, "config invalid; activation disabled, diagnostics available");
        }
    }

    // Compiled once. The executor's adapter registry comes from this very
    // compilation and the supervisor plans with it, so the planner and the
    // executor cannot disagree about what an adapter id means. A configuration
    // that failed to load compiles to the empty default, which the supervisor
    // never reads: it refuses activation first.
    let routing = Arc::new(ssk_daemon::routing::ConfiguredRouting::new(
        &config
            .as_ref()
            .map(|loaded| loaded.config.routing.clone())
            .unwrap_or_default(),
    ));
    let executor = Arc::new(RouteExecutor::new(routing.adapters.clone()));
    let data_plane: Arc<dyn DataPlane> = Arc::new(NetcoreDataPlane::new(executor));
    let (kill_switch, kill_switch_refresher) = build_kill_switch_view();
    let supervisor = Arc::new(Supervisor::from_parts(
        layout.audit_path(),
        routing,
        data_plane,
        kill_switch,
        config,
    ));

    // The kill-switch poller. It must exist for the supervisor's answer to be
    // anything but `Unknown`, and it must be a *separate* task because reading
    // the broker is blocking I/O that `Supervisor::handle` cannot do while
    // holding its mutex on an async worker.
    let kill_switch_poll = kill_switch_refresher.map(spawn_kill_switch_poller);

    let shutdown = Shutdown::new();
    let signals = ssk_daemon::shutdown::spawn_os_signal_listener(shutdown.clone());
    let mut watcher = shutdown.watcher();

    // One event, carrying the endpoint this build will actually bind — never a
    // Unix socket path on Windows. It says "starting", not "listening",
    // because the bind happens inside `ssk_ipc::server` and this process
    // cannot observe its success; claiming liveness here is what produced
    // `"sskd listening"` immediately followed by `"ipc server exited with
    // error"`. Emitting the confirmation *after* the bind requires an
    // `ssk-ipc` change and belongs with that crate.
    tracing::info!(
        target: "ssk.lifecycle",
        endpoint = %endpoint,
        state_dir = %layout.root().display(),
        lock = %lock.path().display(),
        pid = std::process::id(),
        build = BUILD,
        "sskd starting: binding the IPC endpoint"
    );

    let (serve_result, reason) = tokio::select! {
        // The server ending by itself is not a signal, so no OS timer is
        // running: the graceful plan, labelled as the server's own end.
        result = run_server(endpoint.clone(), Arc::clone(&supervisor)) => {
            (Some(result), ShutdownReason::ServerError)
        }
        reason = watcher.wait() => (None, reason),
    };
    let plan = ShutdownPlan::for_reason(reason);
    if serve_result.is_none() {
        tracing::info!(
            target: "ssk.lifecycle",
            reason = reason.as_str(),
            os_deadline = reason.is_os_deadline(),
            runtime_stop_ms = u64::try_from(plan.runtime_stop.as_millis()).unwrap_or(u64::MAX),
            "sskd stopping"
        );
    }
    signals.abort();
    if let Some(handle) = kill_switch_poll {
        handle.abort();
    }

    // Nothing is drained here. There is no ingress, so P1 and P2 have no work,
    // and P3 is done: `select!` dropped the accept loop, so no new connection is
    // served. Connection tasks that are already running go on until `run` stops
    // the runtime (P4); one that is mid-dial is then settled by
    // `ActivationScope`, with the lock still held, if that fits the P4 bound:
    // a settlement still writing when it ends is cut off by the process exit
    // (`ShutdownPlan::runtime_stop`).

    if let Endpoint::UnixSocket(path) = &endpoint {
        // A Windows named pipe is a refcounted kernel object and vanishes with
        // the process; an AF_UNIX path does not, so it is unlinked here on the
        // graceful path. The ungraceful path is covered by `serve_unix`'s
        // unlink-before-bind, which is safe only because the daemon lock is
        // taken first.
        let _ = std::fs::remove_file(path);
    }

    let code = match serve_result {
        None | Some(Ok(())) => ExitCode::SUCCESS,
        Some(Err(err)) => {
            tracing::error!(
                target: "ssk.lifecycle",
                %err,
                reason = ShutdownReason::ServerError.as_str(),
                "ipc server exited with error"
            );
            ExitCode::from(EXIT_SERVER)
        }
    };
    (code, plan)
}

#[cfg(unix)]
async fn run_server(
    endpoint: Endpoint,
    supervisor: Arc<Supervisor>,
) -> Result<(), ssk_ipc::IpcError> {
    match endpoint {
        Endpoint::UnixSocket(path) => ssk_ipc::server::serve_unix(path, supervisor).await,
        Endpoint::NamedPipe(name) => Err(ssk_ipc::IpcError::new(
            "Runtime",
            "IPC_BIND_FAILED",
            format!("this build has no named-pipe transport, but was asked to bind `{name}`"),
        )),
    }
}

/// Windows named-pipe transport — **the injection point for SEC-3's two
/// security controls.**
///
/// `ssk_ipc::server::serve_named_pipe` takes both as required arguments, so
/// "the Windows IPC surface is unauthenticated" is no longer a state this
/// binary can be built in. Neither can be supplied by this crate
/// (`#![forbid(unsafe_code)]`); both are Win32 FFI from `ssk-winhost`:
///
/// * [`ssk_winhost::WindowsPipeFactory::for_current_user`] creates every
///   instance through `create_with_security_attributes_raw` carrying the SDDL
///   `O:<owner>D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<owner>)S:(ML;;NW;;;ME)`. The
///   measured pre-P2 default DACL granted `FILE_GENERIC_READ` to `Everyone`
///   *and* `ANONYMOUS LOGON`; both ACEs are gone under this one.
/// * [`ssk_winhost::WindowsPeerAuthenticator::new`] impersonates each client
///   and reads its `TokenUser`, and `serve_named_pipe` calls it **before a
///   single frame byte is read**, hanging up on any peer whose SID is not this
///   process's own or cannot be determined at all.
///
/// Both are constructed here, once, at startup rather than per connection: a
/// process that cannot build its own DACL or read its own SID must refuse to
/// *start*, not accept connections and discover the problem later.
///
/// Two shortcuts were available and are deliberately not taken, because either
/// would leave this file reading as though the seam were satisfied: a factory
/// over the *safe* `ServerOptions::create` binds the default DACL (which is
/// SEC-3), and a permissive authenticator is a fail-open authentication stub.
#[cfg(windows)]
async fn run_server(
    endpoint: Endpoint,
    supervisor: Arc<Supervisor>,
) -> Result<(), ssk_ipc::IpcError> {
    let name = match endpoint {
        Endpoint::NamedPipe(name) => name,
        Endpoint::UnixSocket(path) => {
            return Err(ssk_ipc::IpcError::new(
                "Runtime",
                "IPC_BIND_FAILED",
                format!(
                    "this build has no Unix transport, but was asked to bind `{}`",
                    path.display()
                ),
            ))
        }
    };

    let pipes = ssk_winhost::WindowsPipeFactory::for_current_user().map_err(|err| {
        ssk_ipc::IpcError::new(
            "Runtime",
            "IPC_PIPE_SECURITY_UNAVAILABLE",
            format!("could not build the pipe's security descriptor: {err}"),
        )
        .with_next_step("Refusing to bind a pipe with the default DACL. Check the process token.")
    })?;
    let auth = ssk_winhost::WindowsPeerAuthenticator::new().map_err(|err| {
        ssk_ipc::IpcError::new(
            "Runtime",
            "IPC_PEER_SID_UNAVAILABLE",
            format!(
                "could not read this daemon's own SID, so no peer can be compared to it: {err}"
            ),
        )
        .with_next_step("Refusing to serve without a peer check. Check the process token.")
    })?;

    tracing::info!(
        target: "ssk.lifecycle",
        pipe = %name,
        sddl = pipes.sddl(),
        own_sid = auth.own_sid_str(),
        "binding the named pipe with an explicit DACL and a live peer-SID check"
    );

    ssk_ipc::server::serve_named_pipe(
        &name,
        supervisor,
        Arc::new(pipes),
        Arc::new(auth),
        ssk_ipc::ServeLimits::default(),
    )
    .await
}
