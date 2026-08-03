//! `ssk-svc` — the real Windows service host: the process
//! [`ssk_netd_helper::Broker`] lives in.
//!
//! [`WindowsServiceHelper`](ssk_winhost::WindowsServiceHelper) registers a
//! service whose executable is this binary. When the SCM starts it, it must
//! attach to the service dispatcher, report `Running`, and honor a `Stop`
//! control — otherwise `start` would time out.
//!
//! **P3 replaced the deliberate idle no-op.** The host now, in this exact order:
//!
//! 1. provisions `%ProgramData%\ScorpioSync\state` through
//!    [`ssk_winhost::state_dir::ensure_state_dir`] — create-or-verify, never
//!    `create_dir_all`, and a squatted directory is refused rather than
//!    repaired;
//! 2. opens the already-provisioned receipt store
//!    ([`ssk_netd_helper::FileReceiptStore::open_existing`], which performs no
//!    ACL work — conflating provisioning with opening is what locked the broker
//!    out of its own store before P1);
//! 3. loads the `(SID, verb)` allow-list, degrading to **read-only** with a
//!    stated reason rather than to deny-all;
//! 4. constructs the broker with
//!    [`ssk_netd_helper::Broker::recover_privileged`] — which takes an
//!    `AuthorizationPolicyTable` **by value with no default**, so
//!    `ActuationAuthority::SelfAsserted` is not expressible here;
//! 5. runs [`ssk_netd_helper::Broker::reconcile_startup`] with
//!    `EnforceJournal`, **before the pipe accepts anything**;
//! 6. only then starts the listeners and reports `Running`.
//!
//! ## Why the order in step 5/6 is not stylistic
//!
//! Reconciliation is several operations under the op-lock, not one. A client
//! that connected between them would read a status that is about to change and
//! could engage or release into a half-reconciled machine. The op-lock does not
//! protect against that; ordering does. `reconcile_startup`'s own doc comment
//! states the requirement, and this file is the only place that can honour it.
//!
//! The SCM's start timeout is respected without weakening that: the control
//! handler is registered and `StartPending` reported **first**, with a wait
//! hint, so the SCM sees a live, progressing service throughout. `Running` is
//! reported only once the machine's enforcement state has actually been
//! reconciled — reporting healthy before that would be reporting a state nobody
//! had checked.
//!
//! ## Verification boundary — read this before trusting anything above
//!
//! **Nothing in this file has ever been executed under the SCM, and nothing in
//! it has ever run as `LocalSystem`.** The development machine is the author's
//! primary workstation under a hard no-system-changes rule: no service was
//! installed, no firewall rule created, `%ProgramData%\ScorpioSync` was
//! deliberately not created, and nothing was elevated.
//!
//! What *is* executed by tests: every decision this file composes, each behind
//! an injected seam in the library — the allow-list parser, the tiered
//! observer, the pipe descriptor, the peer-token FFI, the transport, and the
//! accept loop (`crates/ssk-winhost/tests/privileged_pipe.rs` drives a real
//! broker through a real pipe end to end, unelevated). What is **not**: that
//! the SCM starts this, that `ensure_state_dir` succeeds as `LocalSystem`, that
//! a SYSTEM-created pipe carries `O:SY`, or that any of it ever touched the
//! Windows firewall. Those are operator legs — see
//! `docs/OPERATOR_VM_VALIDATION.md` and `RUNBOOK_WINDOWS.md`.
//!
//! # Diagnostics: what a service makes different
//!
//! P2's exit criterion is that *every* binary writes to a durable rotated log.
//! `ssk` and `sskd` do. Getting there for a service is not "call the same
//! function", because four things are not true of a service that are true of a
//! console app:
//!
//! * **There is no console.** The SCM starts this process in session 0 with no
//!   attached console, so a `tracing` layer on stderr is not a quieter sink, it
//!   is *no* sink. Hence [`ssk_diag::StderrPolicy::Never`] and the removal of
//!   both `eprintln!`s: the rotated file is the only real sink here.
//! * **`service_main` runs before the status handle exists.** Everything
//!   `run_service` can fail at — `register`, the first `set_service_status` —
//!   happens before there is any SCM-visible place to report it. That is why
//!   diagnostics are installed at the *top* of [`windows_svc::service_main`],
//!   ahead of `run_service`, rather than inside it.
//! * **The `WorkerGuard` must outlive the service loop.** `ssk_diag`'s docs
//!   spell this out: `tracing_appender::non_blocking` flushes on `Drop`, so a
//!   guard that dies before the idle loop loses every line the service ever
//!   wrote. The guard is bound in `service_main`, which *is* the service's
//!   lifetime, and dropped only after `run_service` returns.
//! * **`%LOCALAPPDATA%` is the wrong place.** A service runs as `LocalSystem`,
//!   whose `%LOCALAPPDATA%` is
//!   `%SystemRoot%\System32\config\systemprofile\AppData\Local` — a per-account
//!   profile directory that no operator looks in and that says "user data"
//!   about machine-wide state. See [`windows_svc::state_dir_for_diagnostics`]
//!   for what is used instead and why it is not a `create_dir_all`.
//!
//! # Windows Event Log: deliberately not implemented here
//!
//! The roadmap's P2 item reads "…add `panic::set_hook` writing a structured
//! crash record; Event Log output for `ssk-svc`". The crash record is done; the
//! Event Log is **not**, and this is a decision rather than an omission:
//!
//! * `ReportEventW` needs a **registered event source** — an
//!   `EventMessageFile` value under
//!   `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\<source>`
//!   pointing at a binary containing a compiled message table (`mc.exe`).
//!   Without it every event renders as *"The description for Event ID … cannot
//!   be found"*, which is worse than no Event Log entry because it looks like a
//!   broken product.
//! * That registry value is written at **install** time by whatever installs the
//!   service. This binary is installed by `WindowsServiceHelper`, and giving it
//!   an event-source registration is service-install work. P3 hosted the broker
//!   but did **not** take the install-time registry write with it — that is a
//!   privileged system mutation this machine will not perform, so it moves to
//!   P6 with the installer rather than being written blind.
//! * It cannot be exercised at all from the development machine: writing that
//!   key is a privileged system mutation, and the only thing that would validate
//!   the result is reading it back from a real installed service in Event
//!   Viewer.
//!
//! So it is deferred explicitly rather than implemented blind. **The
//! consequence is stated rather than hidden, and P3 made it worse:** if the file
//! sink itself cannot be opened, this process has no channel left at all and
//! starts silent — and it now has strictly more to say when that happens (a
//! refused state directory, an unusable allow-list, a failed reconciliation, a
//! control plane that could not be built). Every one of those is reported into
//! the rotated log and nowhere else. That is what the Event Log would cover.

#[cfg(not(windows))]
fn main() {
    // Off Windows this binary is not a service and has no SCM to attach to, so
    // there is no session-0 problem and no state directory worth provisioning —
    // stderr is a real console here. It still goes through `ssk-diag` rather
    // than `eprintln!`, so there is exactly one way an SSK binary emits.
    let _guard = ssk_diag::init("ssk-svc", None, ssk_diag::StderrPolicy::Always);
    tracing::warn!(
        target: "ssk.lifecycle",
        "ssk-svc is the Windows service host; it only runs when launched by the Windows Service \
         Control Manager on Windows. Nothing to do on this platform."
    );
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_svc::run()
}

#[cfg(windows)]
mod windows_svc {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use ssk_boundary::{BoundaryPolicy, BoundaryScope, BOUNDARY_CONTROL_USE};
    use ssk_netd_helper::recover::ReconcilePolicy;
    use ssk_netd_helper::{
        Broker, BrokerConfig, CapabilityToken, FileReceiptStore, ReconcileReport,
    };
    use ssk_signature::policy::{AuthorizationPolicyTable, Principal, PrivilegedUse};
    use ssk_signature::AuthorizationManifest;
    use ssk_types::SessionId;
    use ssk_winhost::privileged::{CsprngLeaseIds, PrivilegedPipeHost, PrivilegedPipeHostConfig};
    use ssk_winhost::state_dir::{ensure_state_dir, StateDirLayout};
    use ssk_winhost::{
        authz_file, privilege, AuthzLoad, TieredEgressObserver, WindowsEgressEnforcer,
    };
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    // The name the SCM uses to identify us. For a SERVICE_WIN32_OWN_PROCESS
    // service the SCM supplies the real registered name at launch; the string
    // handed to the dispatcher is not authoritative, so a stable placeholder is
    // fine here.
    const DISPATCH_NAME: &str = "SSKHost";

    /// Log filename prefix and the `binary` field of any crash record.
    const BINARY: &str = "ssk-svc";

    /// Build identity recorded in crash records. `ssk`'s richer
    /// `build::short()` (version + declared git SHA) lives in `ssk-cli` and is
    /// not reachable from here; making it shared needs the `build.rs` in
    /// `ssk-diag` that the roadmap still owes, so this is honestly the package
    /// version and nothing more.
    const BUILD: &str = env!("CARGO_PKG_VERSION");

    /// The component name the broker's actuation manifest speaks for, and the
    /// only principal granted [`PrivilegedUse::BoundaryControl`] in this host's
    /// policy table.
    ///
    /// It must appear in **both** places — `with_principal` on the manifest and
    /// `allow` in the table — or `authorize` returns `NoPrincipal` and every
    /// mutating verb is refused. Sharing one constant is what keeps them from
    /// drifting.
    const BROKER_PRINCIPAL: &str = "ssk-netd-helper";

    /// How many accept loops run.
    ///
    /// Each owns a thread and a current-thread tokio runtime and serves exactly
    /// one connection at a time, so this — not
    /// [`ssk_netd_helper::MAX_PRIV_CONNECTIONS`] — is the real concurrency
    /// bound. Stated plainly rather than left implied: with 4 listeners and a
    /// 16-slot [`ssk_netd_helper::ConnectionLimiter`], the limiter is **never
    /// reached**, so `HandshakeReject::AtCapacity` is unreachable in this
    /// deployment. The limiter remains as the process-wide bound a future
    /// multi-accept design would need; it is not load-bearing today.
    ///
    /// The cost of a small number is disclosed in `privileged.rs`: a peer that
    /// connects and then stalls occupies one listener until the read timeout
    /// fires. Four means one such peer costs a quarter of the control plane's
    /// availability for at most `PRIV_READ_TIMEOUT`.
    const LISTENER_THREADS: usize = 4;

    /// Wait hint reported to the SCM while the broker is being built and the
    /// journal reconciled. Generous because step 1 may spawn `icacls` twice per
    /// created directory level on a first start, and step 5 may spawn `netsh`.
    const START_WAIT_HINT: Duration = Duration::from_secs(30);

    /// Wait hint reported while listeners are being joined. Bounded by
    /// `ACCEPT_POLL` plus whatever connection each listener is mid-way through,
    /// itself bounded by the transport's read timeout.
    const STOP_WAIT_HINT: Duration = Duration::from_secs(30);

    /// Service-specific exit code for "the privileged control plane could not be
    /// built". Reported instead of `Running`, because a host that cannot serve
    /// the broker and says it is healthy is a fabricated green.
    const EXIT_NO_CONTROL_PLANE: u32 = 0x5353_4B01;

    define_windows_service!(ffi_service_main, service_main);

    /// The directory `ssk-svc` writes diagnostics under, or why it has none.
    ///
    /// **`%ProgramData%\ScorpioSync\state`, obtained through
    /// [`ensure_state_dir`] — never `create_dir_all`, never `%LOCALAPPDATA%`.**
    ///
    /// The choice of `%ProgramData%` over the `LocalSystem` profile is the easy
    /// half: machine-wide state belongs in a machine-wide directory that an
    /// operator can find and that survives a profile reset.
    ///
    /// The choice of `ensure_state_dir` over a bare `create_dir_all` is the
    /// half that matters. `C:\ProgramData` grants `BUILTIN\Users:(CI)(WD,AD,…)`
    /// (measured on this hardware, see `state_dir.rs`), so a `create_dir_all`
    /// here would produce a `ScorpioSync` tree carrying that inherited
    /// `Users:Write` ACE — and because `state_dir`'s audit refuses such a
    /// directory rather than repairing it, that one convenience call would
    /// **permanently break** the kill-switch receipt store that P3 has to open
    /// in this same directory. Provisioning it correctly is not optional
    /// politeness; it is the difference between a log file and a wrecked
    /// install.
    ///
    /// [`ensure_state_dir`] is create-or-verify: it needs elevation only on the
    /// *absent* branch, verifies and accepts an already-protected directory
    /// without it, and refuses a squatted one. A `LocalSystem` service is
    /// elevated, so the absent branch is expected to succeed under the SCM —
    /// but that has not been executed here, and if the elevation probe says
    /// otherwise the refusal is returned as the string below rather than
    /// papered over.
    ///
    /// Cost, stated: on first start this spawns `icacls` (twice per created
    /// level) before `Running` is reported. That is inside the SCM's start
    /// timeout by a wide margin on an empty tree, and it has not been measured
    /// on a real service.
    fn state_dir_for_diagnostics() -> Result<PathBuf, String> {
        let layout = StateDirLayout::default_program_data()
            .map_err(|refusal| format!("[{}] {refusal}", refusal.code()))?;
        ensure_state_dir(&layout, privilege::elevation())
            .map_err(|refusal| format!("[{}] {refusal}", refusal.code()))
    }

    /// Pure: turn the state-directory outcome into a diagnostics layout, plus
    /// the reason when there will be no durable log.
    ///
    /// Split out from [`state_dir_for_diagnostics`] precisely so both failure
    /// shapes are reachable from a unit test without touching `%ProgramData%`:
    /// a refusal, and the non-absolute path that must never become a log
    /// directory relative to whatever working directory the SCM happened to
    /// hand this process.
    fn diagnostics_layout(
        state_dir: Result<PathBuf, String>,
    ) -> (ssk_diag::Layout, Option<String>) {
        match state_dir {
            Ok(leaf) => {
                let layout = ssk_diag::Layout::from_state_dir(&leaf);
                if layout.root().is_none() {
                    let reason = format!(
                        "the resolved state directory `{}` is not absolute, so no log directory \
                         was derived from it",
                        leaf.display()
                    );
                    return (layout, Some(reason));
                }
                (layout, None)
            }
            Err(reason) => (ssk_diag::Layout::none(), Some(reason)),
        }
    }

    /// Entry point invoked by the SCM through the dispatcher.
    ///
    /// The [`ssk_diag::Guard`] is bound here and dropped at the end, so it spans
    /// the entire service lifetime — including the idle loop — which is the
    /// `WorkerGuard` requirement `ssk_diag`'s docs state.
    ///
    /// Moving this whole setup up into [`run`] would cover dispatcher-start
    /// failures too, and is still the wrong place: `run` is also reached when a
    /// human launches `ssk-svc.exe` by hand, and the first act here provisions a
    /// directory in `%ProgramData%`. Only the SCM reaches `service_main`, so
    /// only the SCM triggers that mutation.
    fn service_main(_arguments: Vec<OsString>) {
        // One provisioning call feeds both consumers: the diagnostics layout and
        // the broker's store. Calling `ensure_state_dir` twice would be two
        // chances for the audit to disagree with itself between them.
        let state_dir = state_dir_for_diagnostics();
        let store_dir = state_dir.as_ref().ok().cloned();
        let (paths, no_sink_reason) = diagnostics_layout(state_dir);
        // `StderrPolicy::Never`: session 0 has no console. The rotated file is
        // the only sink that exists here.
        let guard = ssk_diag::init(
            BINARY,
            paths.logs().as_deref(),
            ssk_diag::StderrPolicy::Never,
        );
        ssk_diag::install_panic_hook(BINARY, paths.crash(), BUILD);

        // Both branches fire only when there is no file sink, and
        // `StderrPolicy::Never` means there is no other layer either — so under
        // the SCM these two events land nowhere. That blind spot is exactly the
        // Event Log gap recorded in this file's header, and it is stated here
        // rather than hidden behind an emit that looks like reporting. They are
        // emitted anyway so the events already exist the moment a channel does.
        if let Some(reason) = &no_sink_reason {
            tracing::error!(
                target: "ssk.lifecycle",
                reason = %reason,
                "no diagnostics directory; ssk-svc is running without a durable log"
            );
        }
        if let Some(err) = &guard.file_sink_error {
            tracing::error!(
                target: "ssk.lifecycle",
                error = %err,
                "the durable log sink could not be opened; ssk-svc has no log sink at all"
            );
        }

        tracing::info!(
            target: "ssk.lifecycle",
            build = BUILD,
            pid = std::process::id(),
            durable_log = guard.has_durable_sink(),
            logs = paths.logs().as_deref().map_or_else(
                || "<none>".to_owned(),
                |dir| dir.display().to_string()
            ),
            "ssk-svc entered service_main"
        );

        if let Err(e) = run_service(store_dir.as_deref()) {
            // Replaces the `eprintln!` this file carried until now. There is no
            // console in session 0, so that line went nowhere; this one reaches
            // the rotated log, which is the whole point of the change.
            tracing::error!(
                target: "ssk.lifecycle",
                error = %e,
                "ssk-svc failed before or during the service loop"
            );
        }

        tracing::info!(target: "ssk.lifecycle", "ssk-svc leaving service_main");
        // Last, explicitly: flushes the non-blocking log worker. Anything after
        // this point is unlogged.
        drop(guard);
    }

    /// Everything the host needs to serve, built and reconciled.
    struct ControlPlane {
        broker: Arc<Broker>,
        host: Arc<PrivilegedPipeHost>,
        /// `Some(reason)` when the allow-list could not be used and every
        /// mutating verb will be refused.
        read_only: Option<String>,
        /// `Ok` carries what startup reconciliation actually did. An `Err` is
        /// **not** fatal — see [`build_control_plane`].
        reconcile: Result<ReconcileReport, String>,
    }

    /// Steps 2–6 of the header's list. Step 1 (`ensure_state_dir`) already ran,
    /// in [`service_main`], because the diagnostics sink needs it too.
    ///
    /// Returns `Err` only for the failures that make serving impossible: no
    /// state directory, no provisioned store, an unbuildable authorization
    /// table, a descriptor that will not convert, or a broker that cannot
    /// rehydrate its own journal. Each of those means the process cannot do the
    /// one job it exists for, and reporting `Running` anyway would be exactly
    /// the fabricated green the project's blocker register exists to prevent.
    ///
    /// A failed **reconciliation** is deliberately not in that set. It is
    /// carried in `reconcile` and logged at `error`, and the host serves anyway:
    /// if reconciliation failed, the machine's egress may well be severed, and
    /// refusing to start would leave an operator with no channel at all —
    /// neither to see it nor to release it. Serving is strictly better; claiming
    /// the reconciliation succeeded would not be.
    ///
    /// `reconcile` is a parameter rather than a constant for one reason, and it
    /// is a disclosure rather than a convenience: [`ReconcilePolicy::
    /// EnforceJournal`] drives a **real** `netsh advfirewall firewall delete
    /// rule` through the receipt-less sweep, and the machine this was written on
    /// is the author's primary workstation under a hard no-system-mutation rule.
    /// Production passes `EnforceJournal`; the unit test below passes
    /// [`ReconcilePolicy::ObserveOnly`], which is documented to attempt no OS
    /// effect at all. **The consequence is that the `EnforceJournal` path is
    /// composed here but has never been executed** — it is operator leg P3-6.
    fn build_control_plane(
        state_dir: Option<&Path>,
        reconcile: ReconcilePolicy,
    ) -> Result<ControlPlane, String> {
        let state_dir = state_dir.ok_or_else(|| {
            "no usable state directory; the store, the allow-list and the journal all live there"
                .to_owned()
        })?;

        // Step 2. `open_existing` performs no ACL work and never creates the
        // directory: a missing one means it was never provisioned, and silently
        // creating an unprotected one would be a downgrade nobody could see.
        let store = FileReceiptStore::open_existing(state_dir)
            .map_err(|e| format!("the receipt store could not be opened: {e}"))?;

        // Step 3. Degrades, never fails.
        let authz = authz_file::load(state_dir);
        let read_only = authz.reason().map(str::to_owned);
        let pipe_config = match &authz {
            AuthzLoad::Granted { client_sids, .. } => {
                let refs: Vec<&str> = client_sids.iter().map(String::as_str).collect();
                PrivilegedPipeHostConfig::for_allow_list(&refs)
                    .map_err(|e| format!("the pipe descriptor could not be built: {e}"))?
            }
            // Reachability without authority: the pipe admits INTERACTIVE so a
            // severed machine stays diagnosable, and the authorizer below
            // refuses every mutating verb with the reason.
            AuthzLoad::ReadOnly { .. } => PrivilegedPipeHostConfig::read_only_fallback(),
        };

        // Step 4.
        let principal = Principal::parse(BROKER_PRINCIPAL)
            .map_err(|e| format!("the broker principal is not well formed: {e}"))?;
        let scope = BoundaryScope::all_egress();
        let config = BrokerConfig {
            session_token: session_token(),
            actuation_auth: AuthorizationManifest::new(
                BROKER_PRINCIPAL,
                "system",
                "privileged Windows service host",
            )
            .with_allowed_uses([BOUNDARY_CONTROL_USE])
            .with_principal(principal.clone()),
            scope: scope.clone(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new(format!("ssk-svc-{}", std::process::id())),
        };
        let broker = Broker::recover_privileged(
            config,
            // By value, with no default. `ActuationAuthority::SelfAsserted` is
            // not reachable from this constructor, which is the point: a
            // LocalSystem host cannot ship a self-asserting broker.
            AuthorizationPolicyTable::deny_all().allow(principal, PrivilegedUse::BoundaryControl),
            Box::new(authz.authorizer()),
            Box::new(store),
            Box::new(WindowsEgressEnforcer::new()),
            Box::new(TieredEgressObserver::netsh_only(scope)),
        )
        .map_err(|e| format!("the broker could not be recovered: {e}"))?
        // The receipt-less sweep. Without it `reconcile_startup` cannot run the
        // startup sweep at all, and its report says so rather than reporting a
        // clean start it never established.
        .with_recoverer(Box::new(WindowsEgressEnforcer::new()));

        // Step 5. BEFORE the pipe exists — see this file's header.
        let reconcile = broker
            .reconcile_startup(reconcile)
            .map_err(|e| e.to_string());

        // Step 6.
        let host = PrivilegedPipeHost::new(pipe_config)
            .map_err(|e| format!("the privileged pipe host could not be built: {e}"))?;

        Ok(ControlPlane {
            broker: Arc::new(broker),
            host: Arc::new(host),
            read_only,
            reconcile,
        })
    }

    /// A fresh capability token for this process's session.
    ///
    /// From the OS CSPRNG. On a CSPRNG failure the token is left all-zero and
    /// the failure is logged at `error` — which is safe rather than alarming
    /// only because the token is **not** the authorization boundary: it
    /// authenticates a session, and every mutating verb is separately gated by
    /// a per-request `PeerAuthorizer` decision on the caller's SID. That is
    /// stated here so the choice is visible instead of looking like an
    /// oversight.
    fn session_token() -> CapabilityToken {
        let mut bytes = [0u8; 16];
        if let Err(e) = getrandom::fill(&mut bytes) {
            tracing::error!(
                target: "ssk.lifecycle",
                error = %e,
                "the OS CSPRNG refused; the session capability token is not random"
            );
        }
        CapabilityToken(bytes)
    }

    fn service_status(
        state: ServiceState,
        controls: ServiceControlAccept,
        exit_code: ServiceExitCode,
        checkpoint: u32,
        wait_hint: Duration,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: controls,
            exit_code,
            checkpoint,
            wait_hint,
            process_id: None,
        }
    }

    fn run_service(state_dir: Option<&Path>) -> windows_service::Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => {
                    tracing::info!(target: "ssk.lifecycle", control = "Stop", "SCM control received");
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                other => {
                    tracing::debug!(
                        target: "ssk.lifecycle",
                        control = ?other,
                        "SCM control not implemented by this host"
                    );
                    ServiceControlHandlerResult::NotImplemented
                }
            }
        };

        // For own-process services the registered name may be empty; the SCM
        // binds the handle to whichever service started this process.
        let status_handle = service_control_handler::register("", event_handler)?;

        // Registered first, and `StartPending` reported before any work, so the
        // SCM sees a live service for the whole of startup. This is what makes
        // "report Running promptly" and "reconcile before serving" compatible
        // rather than a trade-off.
        status_handle.set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            START_WAIT_HINT,
        ))?;

        let plane = match build_control_plane(state_dir, ReconcilePolicy::EnforceJournal) {
            Ok(plane) => plane,
            Err(reason) => {
                tracing::error!(
                    target: "ssk.lifecycle",
                    reason = %reason,
                    "the privileged control plane could not be built; refusing to report Running"
                );
                status_handle.set_service_status(service_status(
                    ServiceState::Stopped,
                    ServiceControlAccept::empty(),
                    ServiceExitCode::ServiceSpecific(EXIT_NO_CONTROL_PLANE),
                    0,
                    Duration::default(),
                ))?;
                return Ok(());
            }
        };

        match &plane.reconcile {
            Ok(report) => tracing::info!(
                target: "ssk.lifecycle",
                action = report.action.as_str(),
                verdict = ?report.verdict,
                logical_state = ?report.logical_state,
                observed = ?report.observed,
                leases_discarded = report.leases_discarded.len(),
                alarm = report.is_alarm(),
                "startup reconciliation complete"
            ),
            Err(e) => tracing::error!(
                target: "ssk.lifecycle",
                error = %e,
                "startup reconciliation FAILED; serving anyway so the machine stays diagnosable \
                 and releasable, but nothing here establishes that enforcement matches the journal"
            ),
        }
        if let Some(reason) = &plane.read_only {
            tracing::error!(
                target: "ssk.lifecycle",
                reason = %reason,
                "no usable allow-list; every mutating verb will be refused and the pipe carries \
                 the degraded descriptor. Status remains readable on purpose."
            );
        }
        tracing::info!(
            target: "ssk.lifecycle",
            pipe = plane.host.pipe_name(),
            sddl = plane.host.sddl(),
            listeners = LISTENER_THREADS,
            read_only = plane.read_only.is_some(),
            "privileged control pipe configured"
        );

        // Only now does anything become reachable.
        let mut listeners = Vec::with_capacity(LISTENER_THREADS);
        for index in 0..LISTENER_THREADS {
            let host = Arc::clone(&plane.host);
            let broker = Arc::clone(&plane.broker);
            let spawned = std::thread::Builder::new()
                .name(format!("ssk-priv-{index}"))
                .spawn(move || {
                    let mut lease_ids = CsprngLeaseIds::default();
                    match host.run_listener(&broker, &mut lease_ids) {
                        Ok(report) => tracing::info!(
                            target: "ssk.lifecycle",
                            listener = index,
                            served = report.served,
                            refused = report.refused,
                            unauthenticated = report.unauthenticated,
                            transport_failures = report.transport_failures,
                            "privileged listener stopped"
                        ),
                        Err(e) => tracing::error!(
                            target: "ssk.lifecycle",
                            listener = index,
                            error = %e,
                            "privileged listener failed"
                        ),
                    }
                });
            match spawned {
                Ok(handle) => listeners.push(handle),
                Err(e) => {
                    // A listener that cannot be spawned is not fatal as long as
                    // at least one is running; zero listeners is.
                    tracing::error!(
                        target: "ssk.lifecycle",
                        listener = index,
                        error = %e,
                        "could not spawn a privileged listener thread"
                    );
                }
            }
        }
        if listeners.is_empty() {
            tracing::error!(
                target: "ssk.lifecycle",
                "no privileged listener could be started; refusing to report Running"
            );
            status_handle.set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                ServiceExitCode::ServiceSpecific(EXIT_NO_CONTROL_PLANE),
                0,
                Duration::default(),
            ))?;
            return Ok(());
        }

        status_handle.set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP,
            ServiceExitCode::Win32(0),
            0,
            Duration::default(),
        ))?;
        tracing::info!(target: "ssk.lifecycle", state = "Running", "reported to the SCM");

        // Serve until the SCM asks us to stop.
        let _ = shutdown_rx.recv();

        status_handle.set_service_status(service_status(
            ServiceState::StopPending,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            1,
            STOP_WAIT_HINT,
        ))?;
        plane.host.stop_signal().stop();
        for handle in listeners {
            // Joining rather than detaching: a listener still inside
            // `serve_connection` holds the broker's op-lock across a durable
            // write, and exiting the process underneath it is how a half-written
            // journal happens. The wait is bounded by `ACCEPT_POLL` plus the
            // transport's read timeout.
            if handle.join().is_err() {
                tracing::error!(
                    target: "ssk.lifecycle",
                    "a privileged listener thread panicked; its connection slot is released by \
                     the RAII permit, but the panic itself is a defect worth investigating"
                );
            }
        }
        tracing::info!(
            target: "ssk.lifecycle",
            accepted = plane.host.accepted(),
            "every privileged listener has stopped"
        );

        status_handle.set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            ServiceExitCode::Win32(0),
            0,
            Duration::default(),
        ))?;
        tracing::info!(target: "ssk.lifecycle", state = "Stopped", "reported to the SCM");

        Ok(())
    }

    /// Attach to the SCM dispatcher; blocks until the service stops.
    ///
    /// Deliberately installs no diagnostics of its own: a failure here means
    /// `StartServiceCtrlDispatcher` refused, which is overwhelmingly the
    /// "somebody ran the .exe by hand" case — a context that *does* have a
    /// console, and where `main`'s `Result` already prints the error.
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        service_dispatcher::start(DISPATCH_NAME, ffi_service_main)?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        #[test]
        fn a_provisioned_state_directory_yields_log_and_crash_paths_under_it() {
            let leaf = std::env::temp_dir().join("ssk-svc-diag-probe");
            let (layout, reason) = diagnostics_layout(Ok(leaf.clone()));
            assert_eq!(reason, None);
            assert_eq!(layout.logs(), Some(leaf.join("logs")));
            assert_eq!(layout.crash(), Some(leaf.join("crash")));
        }

        #[test]
        fn a_refused_state_directory_yields_no_paths_and_keeps_the_reason() {
            let (layout, reason) =
                diagnostics_layout(Err("[STATE_DIR_UNSAFE] owned by a user".to_owned()));
            assert_eq!(layout.logs(), None);
            assert_eq!(layout.crash(), None);
            assert_eq!(
                reason.as_deref(),
                Some("[STATE_DIR_UNSAFE] owned by a user"),
                "the refusal must survive to the one place that can report it"
            );
        }

        #[test]
        fn a_relative_state_directory_is_refused_rather_than_used() {
            // A service inherits whatever working directory the SCM gives it
            // (`%SystemRoot%\System32`). Writing `logs\` relative to that is
            // never what was meant.
            let (layout, reason) = diagnostics_layout(Ok(PathBuf::from(r"ScorpioSync\state")));
            assert_eq!(layout.root(), None);
            assert_eq!(layout.logs(), None);
            assert!(
                reason.is_some_and(|r| r.contains("not absolute")),
                "the reason must name the actual problem"
            );
        }

        /// The location decision, pinned. If this ever starts resolving under a
        /// user profile, the service is writing machine state into
        /// `%SystemRoot%\System32\config\systemprofile` and nobody will find it.
        #[test]
        fn the_service_never_logs_under_a_user_profile_directory() {
            let Ok(program_data) = std::env::var("ProgramData") else {
                return; // Not a Windows-shaped environment; nothing to pin.
            };
            let leaf = ssk_winhost::state_dir::default_state_dir();
            assert!(
                leaf.starts_with(Path::new(&program_data)),
                "expected the ProgramData state directory, got {}",
                leaf.display()
            );
            let (layout, _) = diagnostics_layout(Ok(leaf));
            let logs = layout.logs().expect("an absolute leaf yields a logs dir");
            let logs = logs.to_string_lossy().to_ascii_lowercase();
            assert!(!logs.contains("appdata"), "{logs}");
            assert!(!logs.contains("systemprofile"), "{logs}");
        }

        /// Without a state directory there is no store, no allow-list and no
        /// journal. The host must refuse rather than come up empty and report
        /// healthy.
        #[test]
        fn no_state_directory_means_no_control_plane() {
            let Err(reason) = build_control_plane(None, ReconcilePolicy::ObserveOnly) else {
                panic!("a host with no state directory must refuse to serve")
            };
            assert!(reason.contains("state directory"), "{reason}");
        }

        /// A directory that was never provisioned as a store is a refusal too:
        /// `open_existing` deliberately does not create one, because silently
        /// creating an unprotected store is a downgrade nobody can see.
        #[test]
        fn an_unprovisioned_store_directory_means_no_control_plane() {
            let dir = std::env::temp_dir().join(format!(
                "ssk-svc-missing-store-{}-{}",
                std::process::id(),
                BUILD
            ));
            // Deliberately not created.
            let Err(reason) = build_control_plane(Some(&dir), ReconcilePolicy::ObserveOnly) else {
                panic!("an unprovisioned store directory must refuse to serve")
            };
            assert!(reason.contains("receipt store"), "{reason}");
        }

        /// The full composition root, against a scratch directory: the broker is
        /// recovered, reconciliation runs *before* the host is built, and the
        /// missing allow-list degrades to read-only rather than to deny-all.
        ///
        /// This exercises the real `WindowsEgressEnforcer` and the real
        /// `TieredEgressObserver`, which on this unelevated machine means netsh
        /// is genuinely spawned and genuinely cannot conclude anything — the
        /// `Indeterminate` path, which is the one that must not read as "not
        /// severed".
        #[test]
        fn a_scratch_state_directory_yields_a_read_only_control_plane() {
            let dir = std::env::temp_dir().join(format!(
                "ssk-svc-control-plane-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("scratch dir");
            // `ObserveOnly`, not `EnforceJournal`: the enforcing policy runs
            // the receipt-less sweep, which spawns a real
            // `netsh advfirewall firewall delete rule`. This test must not
            // attempt an OS mutation, and `ObserveOnly` is contractually
            // side-effect free. What that costs is stated on
            // `build_control_plane`: the enforcing path is unexercised here.
            let Ok(plane) = build_control_plane(Some(&dir), ReconcilePolicy::ObserveOnly) else {
                panic!("a provisioned store directory is enough to build a control plane")
            };

            let reason = plane
                .read_only
                .as_deref()
                .expect("no allow-list was written, so the broker must be read-only");
            assert!(
                reason.contains(ssk_winhost::AUTHZ_FILE_NAME),
                "the refusal must name the file an operator has to create: {reason}"
            );
            // The degraded pipe must still admit someone, or a severed machine
            // is not diagnosable.
            assert!(
                plane.host.sddl().contains(";;;IU)"),
                "{}",
                plane.host.sddl()
            );
            // And the broker really is peer-authorizing, i.e. it was built by
            // `recover_privileged` and not by the in-process constructor.
            assert!(plane.broker.is_peer_authorizing());

            let _ = std::fs::remove_dir_all(&dir);
        }

        /// The two places the broker principal has to appear must be the same
        /// string, or `authorize` returns `NoPrincipal` and every mutating verb
        /// is refused at runtime with a message that does not point here.
        #[test]
        fn the_broker_principal_is_well_formed_and_grantable() {
            let principal = Principal::parse(BROKER_PRINCIPAL).expect("well formed");
            let table = AuthorizationPolicyTable::deny_all()
                .allow(principal.clone(), PrivilegedUse::BoundaryControl);
            let manifest = AuthorizationManifest::new(
                BROKER_PRINCIPAL,
                "system",
                "privileged Windows service host",
            )
            .with_allowed_uses([BOUNDARY_CONTROL_USE])
            .with_principal(principal);
            manifest
                .authorize(PrivilegedUse::BoundaryControl.as_str(), &table)
                .expect("the manifest this host builds must satisfy the table this host builds");
        }

        /// The session token is drawn from the OS CSPRNG. Two draws differing is
        /// a weak assertion on its own; it is here because an all-zero token
        /// would mean the CSPRNG silently failed, and the failure branch is
        /// deliberately non-fatal.
        #[test]
        fn the_session_token_is_not_a_constant() {
            let a = session_token();
            let b = session_token();
            assert_ne!(a.0, [0u8; 16], "an all-zero token means the CSPRNG failed");
            assert_ne!(a.0, b.0);
        }
    }
}
