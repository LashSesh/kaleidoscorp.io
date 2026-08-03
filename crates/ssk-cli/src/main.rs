#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use serde::Serialize;
use ssk_boundary::{BoundaryProbe, BoundaryScope, EnforcementReceipt, KillSwitchState, Presence};
use ssk_capture::{CaptureMode, CaptureScope, SystemTrafficField, TrafficSource, TrafficWindow};
use ssk_crown::EmissionDecision;
use ssk_faultscan::{run_playbook, ChaosFaultKind};
use ssk_gates::GateVector;
use ssk_interop::{Blake3KeyedVerifier, CompatibilityPolicy, ConformanceSuite};
use ssk_locator::StaticLocatorPool;
use ssk_mpk::Graph;
use ssk_netadmin::{
    audit::{AuditLedger, AuditOutcome},
    flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel},
    policy::{MatchCriteria, PolicyAction, PolicyEngine, PolicyRule},
    route::{AdapterRegistryEntry, RouteOrchestrator},
    session::SessionLedger,
};
use ssk_netd_helper::{
    ClientError, ClientHello, HandshakeReject, KillSwitchStatus, LeaseId, LeaseKind, NonceSource,
    PrivilegedClient, Recovery, RejectReason,
};
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, DeterminismContext, Runtime, RuntimeEvent, RuntimeMetrics};
use ssk_service_host::{
    HostManifest, InstallReceipt, PrivilegedHelper, ServiceError, ServiceHealth, ServiceState,
};
use ssk_system::{SystemInputs, SystemPipeline};
use ssk_tensor::{FileLedgerBackend, LedgerBackend, MemoryBackend};
use ssk_types::{digest_of, GateId, GateOutcomeKind, HashAlg, LocatorId, ReplayVerdict};
// `Verification` is gone from this import: it described the outcome of an
// enforcement *this process performed*, and this process performs none. The
// equivalent judgement now comes from the service's own `KillSwitchStatus` via
// `broker_verdict`, and an unconfirmed engage is refused there for the same
// reason it was refused here — a claim of protection must never be stronger
// than its evidence.
use ssk_winhost::firewall::{rule_name_for_scope, Ownership, PriorState};
use ssk_winhost::state_dir::{
    ensure_state_dir, verify_state_dir, StateDirLayout, StateDirRefusal, StateDirStatus,
};
use ssk_winhost::{
    EgressMechanism, WindowsConnectionSource, WindowsFirewallEnforcer, WindowsServiceHelper,
};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Build identity for `ssk --version` / `ssk version`.
///
/// # What this is, and what it is not
///
/// The design (roadmap P2 §7) calls for **one `build.rs`**, in the shared
/// `ssk-diag` crate, running `git rev-parse` / `git status --porcelain` /
/// `git log -1 --format=%cI`. That is not what this module is: `ssk-diag` now
/// exists and owns the subscriber, the durable sink, the panic hook and the
/// entropy probe, but it carries **no `build.rs`** — so the git identity here is
/// still *supplied by the build environment* through `option_env!` rather than
/// *derived* by the build. Moving this module into `ssk-diag` unchanged would
/// only relocate the gap; the derivation is the owed work, not the location.
///
/// # One premise of that design does not hold on this toolchain — measured
///
/// The design rejects `option_env!` as "unsound", on the grounds that cargo
/// does not track environment variables read by `env!`/`option_env!` without a
/// build script's `rerun-if-env-changed`, so a changed SHA would not force a
/// rebuild and the binary would keep reporting the previous commit.
///
/// **That was checked here and is false for cargo shipped with rustc 1.95.**
/// `SSK_BUILD_SHA`, `SSK_BUILD_DIRTY` and `SSK_COMMIT_DATE` all appear as
/// env-dependencies in this binary's fingerprint
/// (`target/debug/.fingerprint/ssk-cli-*/dep-bin-ssk`), and an A/B run with no
/// source change confirmed the behaviour: with the variable set, `ssk -V`
/// printed `ssk 0.1.0+gdeadbeef1234`; after unsetting it and rebuilding, `ssk
/// 0.1.0`. cargo rebuilt on the environment change both times. So staleness is
/// **not** the residual risk here.
///
/// # What genuinely is still missing
///
/// The identity is *declared*, not *derived*: nothing in this build runs
/// `git`, so an environment that supplies a wrong SHA is believed, and an
/// environment that supplies none reports `unknown`. That is why every output
/// carries an explicit `provenance` field instead of printing a bare SHA and
/// letting a reader infer it was verified. The `build.rs` the design specifies
/// is still owed; it closes the derivation gap (and adds the rustc version and
/// target triple), not a staleness gap.
///
/// # Determinism
///
/// No wall-clock build timestamp is embedded, on purpose. `Cargo.toml`'s
/// `[profile.release] codegen-units = 1` justifies itself with "byte-identical
/// rebuilds from the same lockfile and toolchain are a requirement, not a
/// nicety" (P6 checksums, SBOM, Authenticode). A build date would break that
/// while the comment kept claiming it. `SSK_COMMIT_DATE` — the HEAD commit
/// date, deterministic per commit — is used when a packager supplies it.
mod build {
    /// The package version. Short `--version` output is `ssk <VERSION>`.
    pub const VERSION: &str = env!("CARGO_PKG_VERSION");

    /// Git commit, when a CI job or packager declared one. Never fabricated:
    /// absent means the string `unknown`, which is honest, where a made-up SHA
    /// is not. Reading it with `option_env!` registers it as a cargo
    /// env-dependency, so changing it does force a rebuild (measured — see the
    /// module docs).
    pub const GIT_SHA: Option<&str> = option_env!("SSK_BUILD_SHA");

    /// Whether the working tree was dirty at build time, as declared. Best
    /// effort by construction — working-tree dirtiness cannot be made a
    /// reliable cargo rerun trigger even *with* a build script — so it is
    /// labelled as declared rather than presented as authoritative.
    pub const GIT_DIRTY: Option<&str> = option_env!("SSK_BUILD_DIRTY");

    /// ISO-8601 date of the HEAD commit, as declared. Deterministic per commit.
    pub const COMMIT_DATE: Option<&str> = option_env!("SSK_COMMIT_DATE");

    /// `declared` when the build environment supplied the git identity,
    /// `unknown` otherwise. A consumer must not treat `declared` as
    /// *verified*: nothing in this build runs `git`, so the value is believed,
    /// not checked. See the module docs.
    #[must_use]
    pub fn provenance() -> &'static str {
        if GIT_SHA.is_some() {
            "declared"
        } else {
            "unknown"
        }
    }

    /// The build profile this binary was compiled with. Derived from
    /// `debug_assertions`, which is a property of the compiled artifact rather
    /// than of the environment it runs in.
    #[must_use]
    pub fn profile() -> &'static str {
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    }

    /// Short identity used by `ssk -V`, log records and crash records:
    /// `0.1.0`, or `0.1.0+g<sha>` when a git identity was declared.
    #[must_use]
    pub fn short() -> &'static str {
        static SHORT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| match GIT_SHA {
            Some(sha) if !sha.is_empty() => format!("{VERSION}+g{sha}"),
            _ => VERSION.to_owned(),
        });
        SHORT.as_str()
    }

    /// Multi-line `--version` output. Computed once; clap's `long_version`
    /// requires a `&'static str`, and the value is a build constant, so a
    /// `LazyLock` is the whole of the machinery needed.
    #[must_use]
    pub fn long_version() -> &'static str {
        static LONG: std::sync::LazyLock<String> = std::sync::LazyLock::new(render_long_version);
        LONG.as_str()
    }

    /// Note the leading line is the bare version: clap renders
    /// `{bin name} {long_version}`, so prefixing "ssk " here would print
    /// `ssk ssk 0.1.0`.
    fn render_long_version() -> String {
        let mut out = format!("{VERSION}\n");
        out.push_str(&format!("git-sha:    {}\n", GIT_SHA.unwrap_or("unknown")));
        out.push_str(&format!(
            "git-dirty:  {} (declared at build time, best effort)\n",
            GIT_DIRTY.unwrap_or("unknown")
        ));
        out.push_str(&format!(
            "commit-date: {}\n",
            COMMIT_DATE.unwrap_or("unknown")
        ));
        out.push_str(&format!("profile:    {}\n", profile()));
        out.push_str(&format!(
            "target:     {}-{}\n",
            std::env::consts::ARCH,
            std::env::consts::OS
        ));
        out.push_str(&format!("provenance: {}\n", provenance()));
        out.push_str(
            "note:       git provenance is supplied by the build environment \
             (SSK_BUILD_SHA) and believed, not derived by this build, so `declared` is \
             not `verified`.",
        );
        out
    }
}

#[derive(Parser)]
#[command(name = "ssk")]
#[command(about = "ScorpioSync-Kaleidoscorp Omega runtime CLI")]
#[command(version = build::short(), long_version = build::long_version())]
struct Cli {
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        valid_fixture: bool,
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        seeded: bool,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
    },
    ReplayVerify {
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        valid_fixture: bool,
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        seeded: bool,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
    },
    /// Drive the full decision-core pipeline (BCIK crossing → tensor
    /// materialization → fiber execution → concave focus) to a real
    /// 3-variant `RunOutcome`.
    Connect {
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        valid_fixture: bool,
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        seeded: bool,
        #[arg(long, default_value_t = 0)]
        epoch: u64,
    },
    VerifyLedger {
        #[arg(long)]
        path: String,
    },
    Doctor {
        #[arg(long)]
        ledger_path: Option<String>,
    },
    Explain {
        target: String,
    },
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Interoperability tools.
    Interop {
        #[command(subcommand)]
        command: InteropCommand,
    },
    /// Chaos & recovery drills.
    Chaos {
        #[command(subcommand)]
        command: ChaosCommand,
    },
    /// Network administration layer (Proxifier replacement).
    NetAdmin {
        #[command(subcommand)]
        command: NetAdminCommand,
    },
    /// Print this binary's build identity. `--json` emits it structured, so
    /// machine consumers never have to parse clap's `--version` prose.
    Version,
    /// Daemon-backed commands (talk to `sskd` over `ssk-ipc`).
    Status,
    /// Activate a profile via the daemon: establishes real, policy-decided,
    /// audited egress to `--dest`. Reaching `Protected` requires the daemon
    /// to really connect — there is no destination-less success path.
    Activate {
        #[arg(long)]
        profile: String,
        /// Real destination to protect, `host:port`. Required: with no
        /// destination there is nothing to protect, so the daemon fails
        /// closed rather than reporting a fabricated `Protected` status.
        #[arg(long)]
        dest: String,
    },
    /// Deactivate protection via the daemon.
    Deactivate {
        #[arg(long, default_value_t = false)]
        release_kill_switch: bool,
    },
    /// List profiles known to the daemon.
    ListProfiles,
    /// Run the SSCL Crown SystemPipeline (capture -> field-tensor ->
    /// transduction -> signature gate -> QLOGIC -> MetaResonance ->
    /// ServiceHost health -> CrownSupervisor) over a deterministic fixture and
    /// print the fail-closed verdict. This is the library stack
    /// (`ssk-system`) made runnable, not a new decision path.
    System {
        #[command(subcommand)]
        command: SystemCommand,
    },
    /// Real Windows 11 privileged actions (the "hands"): live flow capture, the
    /// firewall kill-switch, and the Windows service lifecycle. Admin-only at
    /// runtime; on a non-Windows build each action reports a typed "requires
    /// Windows" error instead of a silent success.
    #[command(name = "winhost")]
    WinHost {
        #[command(subcommand)]
        command: WinHostCommand,
    },
}

#[derive(Subcommand)]
enum WinHostCommand {
    /// Report whether this build carries the privileged Windows backends and
    /// what an operator must do to exercise them.
    Doctor,
    /// Enumerate real active TCP/UDP flows (IP Helper) as payload-neutral
    /// canonical surfaces.
    Capture,
    /// The firewall kill-switch: sever or restore all outbound egress.
    Killswitch {
        #[command(subcommand)]
        command: KillswitchCommand,
    },
    /// The Windows service lifecycle (Service Control Manager).
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

/// Every verb here is commanded over the privileged service's control pipe.
///
/// **This CLI actuates nothing.** It opens the pipe, verifies the endpoint is
/// owned by LocalSystem, handshakes, sends one envelope and renders the typed
/// answer. When the service is unreachable each verb fails with a typed error
/// naming it; there is deliberately no fallback that drives the firewall
/// directly.
///
/// `--scope` no longer selects anything privileged: the service owns exactly
/// one scope, fixed when it starts. It is kept because it still names the rule
/// the local advisory lines describe, and dropping a flag that every existing
/// script passes would break them for no gain. A mismatch against the scope the
/// service is actually holding is reported.
#[derive(Subcommand)]
enum KillswitchCommand {
    /// Ask the privileged service to sever all outbound egress, taking a
    /// durable claim that survives this process and a reboot.
    Engage {
        #[arg(long, default_value = "all-egress")]
        scope: String,
    },
    /// Ask the privileged service to drop a claim, restoring egress when it was
    /// the last one.
    Release {
        #[arg(long, default_value = "all-egress")]
        scope: String,
        /// The durable claim to drop, as printed by `engage`.
        ///
        /// Omit it to use the id this CLI remembered from its own `engage`. A
        /// claim id is not a credential: the service refuses one it is not
        /// holding, and dropping a claim is authorized against the caller's
        /// account regardless of which id is presented.
        #[arg(long)]
        lease: Option<String>,
    },
    /// Report the authoritative kill-switch state held by the privileged
    /// service.
    ///
    /// Read-only. Scripts should key on the `verdict` field. It exits 0
    /// whenever the service answered — including for the `inconsistent` alarm,
    /// because describing a broken machine is precisely what it is for — and
    /// non-zero only when there was no authoritative answer to report, which is
    /// itself the finding.
    Status {
        #[arg(long, default_value = "all-egress")]
        scope: String,
    },
    /// Explain how to recover a machine whose kill-switch cannot be released
    /// normally.
    ///
    /// **This no longer deletes anything.** Receipt-less recovery is the
    /// service's own startup reconciliation, which runs as LocalSystem before
    /// the control pipe accepts its first client; a CLI that deleted the rule
    /// itself would be exactly the unauthorized, unaudited privileged action
    /// this release removed. So this verb reports the authoritative state,
    /// derives the rule name from the scope, and names the two real recovery
    /// paths. It always exits non-zero, because it changed nothing.
    Recover {
        #[arg(long, default_value = "all-egress")]
        scope: String,
        /// Retained for command-line compatibility. It no longer confirms a
        /// deletion, because this verb no longer performs one.
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Register the SSK host as a Windows service pointing at the `ssk-svc`
    /// binary, and persist the rollback receipt.
    Install {
        /// Path to the `ssk-svc` service host executable. Defaults to `ssk-svc`
        /// (or `ssk-svc.exe`) beside the current binary.
        #[arg(long)]
        exe: Option<String>,
    },
    /// Start the installed service.
    Start,
    /// Stop the running service.
    Stop,
    /// Uninstall the service (only if a prior install created it).
    Uninstall,
}

#[derive(Subcommand)]
enum SystemCommand {
    /// Evaluate one fixture through the pipeline and print the verdict.
    Run {
        /// Which built-in fixture to capture: "clean" (no sensitive surface)
        /// or "sensitive" (carries an Authorization header, so the signature
        /// gate holds and no privileged effect auto-passes).
        #[arg(long, default_value = "clean")]
        fixture: String,
        /// Simulate the session kill-switch being engaged.
        #[arg(long, default_value_t = false)]
        engage_kill_switch: bool,
        /// Simulate this many open residue/boundary obligations.
        #[arg(long, default_value_t = 0)]
        open_obligations: usize,
        /// Simulate the privileged ServiceHost being unhealthy (degraded).
        #[arg(long, default_value_t = false)]
        host_unhealthy: bool,
    },
}

#[derive(Subcommand)]
enum InteropCommand {
    /// Run the cross-implementation conformance suite.
    Conformance {
        /// Run only the named profile.
        #[arg(long)]
        profile: Option<String>,
        /// Require attestation verification (uses test key).
        #[arg(long, default_value_t = false)]
        require_attestation: bool,
    },
}

#[derive(Subcommand)]
enum ChaosCommand {
    /// Execute a chaos/recovery drill.
    Drill {
        /// Fault kind to inject (signature-corruption, capability-withdrawal,
        /// ttl-expiry, attestation-failure).  Omit to run all standard faults.
        #[arg(long)]
        fault: Option<String>,
    },
}

#[derive(Subcommand)]
enum NetAdminCommand {
    /// Inspect and classify a flow through the policy engine.
    FlowInspect {
        #[arg(long)]
        app_id: String,
        #[arg(long)]
        dest_host: String,
        #[arg(long, default_value_t = 443)]
        dest_port: u16,
        /// Protocol: tcp, udp, tls, http, https, dns (default: https)
        #[arg(long, default_value = "https")]
        protocol: String,
        /// Risk level: low, medium, high, critical (default: medium)
        #[arg(long, default_value = "medium")]
        risk: String,
    },
    /// Show the route computed for a flow.
    RouteTrace {
        #[arg(long)]
        app_id: String,
        #[arg(long)]
        dest_host: String,
        #[arg(long, default_value_t = 443)]
        dest_port: u16,
        #[arg(long, default_value = "https")]
        protocol: String,
        #[arg(long, default_value = "medium")]
        risk: String,
    },
    /// Dump a summary of the in-memory audit ledger for a sample pipeline run.
    AuditDump,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Lint {
        #[arg(long)]
        path: PathBuf,
    },
    Schema,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum ErrorClass {
    Usage,
    Config,
    Runtime,
    Integrity,
    Replay,
    Permission,
    Doctor,
    Interop,
    Chaos,
    NetAdmin,
    /// The SSCL Crown SystemPipeline denied emission (`EmissionDecision::Deny`)
    /// — a fail-closed verdict, not a tool malfunction, but still a non-zero
    /// exit so the decision is observable in `$?`/scripts.
    System,
    /// A real Windows 11 privileged action (`ssk winhost ...`) failed — e.g.
    /// the backend is unavailable on this platform, or the OS refused the
    /// privileged operation (typically: not running as Administrator).
    WinHost,
}

impl ErrorClass {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::Config => 10,
            Self::Runtime => 12,
            Self::Integrity => 13,
            Self::Replay => 14,
            Self::Permission => 15,
            Self::Doctor => 16,
            Self::Interop => 17,
            Self::Chaos => 18,
            Self::NetAdmin => 19,
            Self::System => 20,
            Self::WinHost => 21,
        }
    }
}

#[derive(Debug)]
struct AppError {
    class: ErrorClass,
    message: String,
    machine_code: String,
    next_steps: Vec<String>,
}

impl AppError {
    fn new(
        class: ErrorClass,
        machine_code: impl Into<String>,
        message: impl Into<String>,
        next_steps: Vec<String>,
    ) -> Self {
        Self {
            class,
            message: message.into(),
            machine_code: machine_code.into(),
            next_steps,
        }
    }
}

/// Maps `ssk-ipc`'s string-based error class back onto this binary's
/// `ErrorClass` enum, so daemon-backed commands report through the exact
/// same machine-readable contract as every local command.
impl From<ssk_ipc::IpcError> for AppError {
    fn from(err: ssk_ipc::IpcError) -> Self {
        let class = match err.class.as_str() {
            "Usage" => ErrorClass::Usage,
            // `ssk-ipc` has emitted class "Validation" (e.g. `DEST_REQUIRED`)
            // on an already-shipping path, and with no arm here it fell through
            // to `Runtime` — exit 12 for what is a usage error. The daemon side
            // is being moved to "Usage"; the arm stays so a surviving or
            // reintroduced "Validation" cannot silently produce a wrong exit
            // code again.
            "Validation" => ErrorClass::Usage,
            "Config" => ErrorClass::Config,
            "Integrity" => ErrorClass::Integrity,
            "Replay" => ErrorClass::Replay,
            "Permission" => ErrorClass::Permission,
            "Doctor" => ErrorClass::Doctor,
            "Interop" => ErrorClass::Interop,
            "Chaos" => ErrorClass::Chaos,
            "NetAdmin" => ErrorClass::NetAdmin,
            _ => ErrorClass::Runtime,
        };
        AppError::new(class, err.code, err.message, err.next_steps)
    }
}

/// Connect to `sskd`, issue one request, and return its response.
///
/// # What this replaces
///
/// There used to be two of these: a `#[cfg(unix)]` real client, and a
/// `#[cfg(not(unix))]` stub returning `DAEMON_UNIX_ONLY` (exit 12). On Windows
/// the stub fired **while `sskd` was listening on its named pipe beside it** —
/// the server half had been written and the client half never was, so the
/// entire control plane (`status` / `activate` / `deactivate` /
/// `list-profiles`) was dead on the product's target platform. `ssk-ipc` now
/// exposes one [`ssk_ipc::DaemonClient`] over both transports, so there is one
/// call path here too and the only platform split left is naming the endpoint.
///
/// # The error contract is preserved exactly
///
/// The stub reported class `Runtime` → exit **12**. Every failure this function
/// can now produce is also class `Runtime` → exit 12: `IPC_CONNECT_FAILED`
/// (nothing is listening — the daemon-absent case, and it says so and is marked
/// retriable), `IPC_CONNECT_BUSY`, `IPC_RUNTIME_INIT_FAILED`, and
/// `IPC_PEER_SID_UNAVAILABLE`. There is no path on which a missing daemon
/// yields success or a zero exit.
///
/// Spins up a lightweight current-thread Tokio runtime for the single call
/// rather than making the whole `ssk` binary async — `run` / `replay-verify` /
/// `doctor` / etc. stay fully synchronous and local.
fn call_daemon(req: ssk_ipc::Request) -> Result<ssk_ipc::Response, AppError> {
    call_daemon_at(&daemon_endpoint()?, req)
}

/// The transport half of [`call_daemon`], with the endpoint injected so the
/// daemon-absent error contract is testable without mutating `SSK_STATE_DIR`
/// (which would race every other test in this binary).
fn call_daemon_at(
    endpoint: &ssk_ipc::Endpoint,
    req: ssk_ipc::Request,
) -> Result<ssk_ipc::Response, AppError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            AppError::new(
                ErrorClass::Runtime,
                "IPC_RUNTIME_INIT_FAILED",
                e.to_string(),
                vec![],
            )
        })?;
    tracing::debug!(target: "ssk.lifecycle", endpoint = %endpoint, "calling the daemon");
    rt.block_on(async {
        let mut client = ssk_ipc::DaemonClient::connect(endpoint)
            .await
            .map_err(AppError::from)?;
        client.call(req).await.map_err(AppError::from)
    })
}

/// The daemon endpoint for this platform: the state-directory-scoped Unix
/// socket.
#[cfg(unix)]
fn daemon_endpoint() -> Result<ssk_ipc::Endpoint, AppError> {
    Ok(ssk_ipc::paths::default_endpoint())
}

/// The daemon endpoint for this platform: the named pipe whose name is a digest
/// over `(scheme, version, user SID, state directory)`.
///
/// Both halves must derive the identical name from identical inputs — there is
/// no discovery step and no shared file. If the SID cannot be obtained the
/// function **refuses to name a pipe** rather than falling back to an unscoped
/// one: an unscoped name is the pre-P2 fixed global name, which is what made a
/// second daemon die with `ERROR_ACCESS_DENIED` and what let any user's client
/// address any other user's daemon.
#[cfg(windows)]
fn daemon_endpoint() -> Result<ssk_ipc::Endpoint, AppError> {
    let sid = current_user_sid()?;
    Ok(ssk_ipc::paths::default_endpoint(&sid))
}

/// This process's user SID, in `S-1-…` string form, from
/// `ssk_winhost::current_user_sid` — `OpenProcessToken` +
/// `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW`.
///
/// The FFI lives in `ssk-winhost` because that is the one crate exempt from the
/// workspace's `unsafe_code = "forbid"`; `ssk-cli` is `#![forbid(unsafe_code)]`
/// and only consumes the answer. It must be the *same* implementation the
/// daemon uses, because the pipe name is a digest over this string: two
/// spellings of one SID are two different pipes, and the client and daemon
/// would silently never meet.
///
/// Fails closed: no SID, no pipe name, no call. The alternative — an unscoped
/// name — is the pre-P2 fixed global pipe, which is what let any user's client
/// address any other user's daemon.
#[cfg(windows)]
fn current_user_sid() -> Result<String, AppError> {
    ssk_winhost::current_user_sid().map_err(|e| {
        AppError::new(
            ErrorClass::Runtime,
            "IPC_PEER_SID_UNAVAILABLE",
            format!(
                "could not determine this process's user SID, so the daemon's pipe name cannot \
                 be derived: {e}"
            ),
            vec![
                "The pipe name is scoped by the caller's SID; deriving an unscoped name instead \
                 would address another user's daemon, so this refuses rather than guessing."
                    .into(),
            ],
        )
    })
}

#[derive(Serialize)]
struct ErrorOutput<'a> {
    status: &'a str,
    class: ErrorClass,
    machine_code: &'a str,
    message: &'a str,
    exit_code: u8,
    next_steps: &'a [String],
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    name: &'static str,
    ok: bool,
    detail: String,
    next_step: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct ExplainOutput {
    target: String,
    category: String,
    summary: String,
    details: Vec<String>,
}

/// # No `std::process::exit`, anywhere below `ssk_diag::init`
///
/// `tracing_appender::non_blocking` buffers in a worker thread and flushes when
/// [`ssk_diag::Guard`] drops. `process::exit` runs no destructors, so a single
/// such call would silently discard the durable log. This binary contains none,
/// and this function returns [`ExitCode`] so it never needs one. (`clap` does
/// call `process::exit` for `--help`/`--version`, which is why `Cli::parse()`
/// runs **before** the guard exists: those paths have nothing to flush.)
///
/// # Why `StderrPolicy::WhenLogEnvSet` and not the daemon's `Always`
///
/// `sskd`'s stderr *is* a log. A CLI's stderr is a user-facing surface that the
/// error contract (`ErrorOutput`) already owns, so the human layer is installed
/// only when `SSK_LOG` is set. Measured, not assumed: with a stderr layer on by
/// default, `ssk status` against an absent daemon printed a `WARN
/// ssk.lifecycle: ssk command failed` line immediately above the typed error
/// that says the same thing, and `ssk system run --fixture sensitive` printed
/// two `ERROR` events above `EMISSION_DENIED`. Nothing is lost: the durable JSON
/// sink receives everything the global filter admits, and the one case that must
/// not go dark — the sink itself failing to open — is printed directly below.
fn main() -> ExitCode {
    let cli = Cli::parse();

    // `Layout::from_state_dir`, not a resolver inside `ssk-diag`: the state
    // directory is `ssk-ipc`'s to resolve, and `ssk-diag` deliberately has no
    // workspace dependencies so that `ssk-winhost` (which hosts `ssk-svc`) can
    // link it without a cycle. A relative state dir yields no sink paths at all
    // — see `ssk_diag::Layout`.
    let layout = ssk_diag::Layout::from_state_dir(&ssk_ipc::paths::state_dir());
    let guard = ssk_diag::init(
        "ssk",
        layout.logs().as_deref(),
        ssk_diag::StderrPolicy::WhenLogEnvSet,
    );
    ssk_diag::install_panic_hook("ssk", layout.crash(), build::short());
    if let Some(err) = &guard.file_sink_error {
        // Printed directly, because with `SSK_LOG` unset there is no stderr
        // layer to carry it and the file sink is precisely what failed. stderr,
        // never stdout: `ssk --json` owns stdout as a machine contract.
        eprintln!("warning: this run is not being logged durably: {err}");
    }
    tracing::debug!(
        target: "ssk.lifecycle",
        build = %build::short(),
        durable_log = guard.has_durable_sink(),
        "ssk starting"
    );

    let code = match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::warn!(
                target: "ssk.lifecycle",
                code = %err.machine_code,
                class = ?err.class,
                "ssk command failed"
            );
            emit_error(&err, cli.json);
            ExitCode::from(err.class.exit_code())
        }
    };

    drop(guard); // flushes the non-blocking writer
    code
}

fn run(cli: &Cli) -> Result<(), AppError> {
    match &cli.command {
        Command::Run {
            valid_fixture,
            seeded,
            epoch,
        } => run_once_command(*valid_fixture, *seeded, *epoch, cli),
        Command::ReplayVerify {
            valid_fixture,
            seeded,
            epoch,
        } => replay_verify_command(*valid_fixture, *seeded, *epoch, cli),
        Command::Connect {
            valid_fixture,
            seeded,
            epoch,
        } => connect_command(*valid_fixture, *seeded, *epoch, cli),
        Command::VerifyLedger { path } => verify_ledger_command(path, cli.json),
        Command::Doctor { ledger_path } => doctor_command(ledger_path.as_deref(), cli),
        Command::Explain { target } => explain_command(target, cli.json),
        Command::Config { command } => config_command(command, cli.json),
        Command::Interop { command } => interop_command(command, cli.json),
        Command::Chaos { command } => chaos_command(command, cli.json),
        Command::NetAdmin { command } => net_admin_command(command, cli.json),
        Command::Status => status_command(cli.json),
        Command::Activate { profile, dest } => activate_command(profile, dest, cli.json),
        Command::Deactivate {
            release_kill_switch,
        } => deactivate_command(*release_kill_switch, cli.json),
        Command::Version => version_command(cli.json),
        Command::ListProfiles => list_profiles_command(cli.json),
        Command::System { command } => system_command(command, cli.json),
        Command::WinHost { command } => winhost_command(command, cli.json),
    }
}

/// Machine-readable build identity. `provenance` is reported alongside the SHA
/// so a consumer can tell "the build environment declared this" from "a build
/// script derived and verified it" — see [`build`] for why only the latter is
/// sound and why this binary can currently only do the former.
fn version_command(json: bool) -> Result<(), AppError> {
    if json {
        let value = serde_json::json!({
            "status": "ok",
            "name": "ssk",
            "version": build::VERSION,
            "build": build::short(),
            "git_sha": build::GIT_SHA,
            "git_dirty": build::GIT_DIRTY,
            "commit_date": build::COMMIT_DATE,
            "provenance": build::provenance(),
            "provenance_means":
                "`declared` = supplied by the build environment via SSK_BUILD_SHA and believed, \
                 not verified: nothing in this build runs `git`. `unknown` = no git identity was \
                 supplied. (Changing SSK_BUILD_SHA does force a rebuild — it is a tracked cargo \
                 env-dependency — so a declared value is at least not stale.)",
            "profile": build::profile(),
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "next_steps": []
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                e.to_string(),
                vec![]
            ))?
        );
    } else {
        // clap supplies the binary name in front of `long_version`; this
        // subcommand prints the same body, so it supplies it itself.
        println!("ssk {}", build::long_version());
    }
    Ok(())
}

fn status_command(json: bool) -> Result<(), AppError> {
    match call_daemon(ssk_ipc::Request::GetStatus)? {
        ssk_ipc::Response::Status(status) => print_status(&status, json),
        ssk_ipc::Response::Err(err) => Err(AppError::from(err)),
        other => Err(unexpected_response(&other)),
    }
}

/// Parses a `host:port` destination. Splits on the last `:` so a bracketed
/// IPv6 literal like `[::1]:443` still yields `::1` (brackets stripped) —
/// full IPv6 zone-id support is not attempted here.
fn parse_dest(dest: &str) -> Result<(String, u16), AppError> {
    let (host, port) = dest.rsplit_once(':').ok_or_else(|| {
        AppError::new(
            ErrorClass::Usage,
            "INVALID_DEST",
            format!("`{dest}` is not a valid host:port destination"),
            vec!["Pass --dest in the form host:port, e.g. --dest 93.184.216.34:443".into()],
        )
    })?;
    let port: u16 = port.parse().map_err(|_| {
        AppError::new(
            ErrorClass::Usage,
            "INVALID_DEST",
            format!("`{port}` is not a valid port number"),
            vec![],
        )
    })?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host.to_string(), port))
}

fn activate_command(profile: &str, dest: &str, json: bool) -> Result<(), AppError> {
    let (dest_host, dest_port) = parse_dest(dest)?;
    match call_daemon(ssk_ipc::Request::ActivateProfile(
        ssk_ipc::ActivateProfileRequest {
            profile_id: profile.to_string(),
            dest_host: Some(dest_host),
            dest_port: Some(dest_port),
        },
    ))? {
        ssk_ipc::Response::Status(status) => print_status(&status, json),
        ssk_ipc::Response::Err(err) => Err(AppError::from(err)),
        other => Err(unexpected_response(&other)),
    }
}

fn deactivate_command(release_kill_switch: bool, json: bool) -> Result<(), AppError> {
    match call_daemon(ssk_ipc::Request::Deactivate(ssk_ipc::DeactivateRequest {
        release_kill_switch,
    }))? {
        ssk_ipc::Response::Status(status) => print_status(&status, json),
        ssk_ipc::Response::Err(err) => Err(AppError::from(err)),
        other => Err(unexpected_response(&other)),
    }
}

fn list_profiles_command(json: bool) -> Result<(), AppError> {
    match call_daemon(ssk_ipc::Request::ListProfiles)? {
        ssk_ipc::Response::Profiles(profiles) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "profiles": profiles,
                        "next_steps": []
                    }))
                    .map_err(|e| AppError::new(
                        ErrorClass::Runtime,
                        "JSON_OUTPUT_FAILED",
                        e.to_string(),
                        vec![]
                    ))?
                );
            } else {
                for p in &profiles {
                    println!("{} ({})", p.id, p.name);
                }
            }
            Ok(())
        }
        ssk_ipc::Response::Err(err) => Err(AppError::from(err)),
        other => Err(unexpected_response(&other)),
    }
}

/// A deterministic in-process fixture for `ssk system run`. This CLI has no OS-
/// level capture privilege (and needs none to demonstrate the pipeline): it
/// yields the same shape of synthetic-but-realistic windows the `ssk-system`
/// test doubles (`CleanSource`/`DriftingSource`) use — a clean GET, plus (when
/// `sensitive`) a second POST carrying an `Authorization` header.
struct CliFixtureSource {
    sensitive: bool,
}

impl TrafficSource for CliFixtureSource {
    fn source_id(&self) -> String {
        "ssk-cli-fixture".to_owned()
    }

    fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
        let mut clean = TrafficWindow::http("http");
        clean.method = Some("GET".to_owned());
        clean.url = Some("https://example.local/health".to_owned());
        clean.status = Some(200);
        clean.response_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        clean.payload = b"{}".to_vec();

        if !self.sensitive {
            return vec![clean];
        }

        let mut sensitive = TrafficWindow::http("http");
        sensitive.method = Some("POST".to_owned());
        sensitive.url = Some("https://example.local/login".to_owned());
        sensitive.status = Some(401);
        sensitive.request_headers = vec![("Authorization".to_owned(), "Bearer secret".to_owned())];
        sensitive.response_headers =
            vec![("Content-Type".to_owned(), "application/json".to_owned())];
        sensitive.payload = b"{\"user\":\"x\"}".to_vec();

        vec![clean, sensitive]
    }
}

fn system_command(command: &SystemCommand, json: bool) -> Result<(), AppError> {
    let SystemCommand::Run {
        fixture,
        engage_kill_switch,
        open_obligations,
        host_unhealthy,
    } = command;

    let sensitive = match fixture.as_str() {
        "clean" => false,
        "sensitive" => true,
        other => {
            return Err(AppError::new(
                ErrorClass::Usage,
                "INVALID_FIXTURE",
                format!("`{other}` is not a known fixture"),
                vec!["Pass --fixture clean or --fixture sensitive.".into()],
            ))
        }
    };

    let source = CliFixtureSource { sensitive };
    let scope = CaptureScope::new("local", ["lo0"]);
    let traffic = SystemTrafficField::capture(&source, &scope, CaptureMode::PassiveLocal);

    let windows = [Graph::from_edges(3, &[(0, 1), (1, 2)]).map_err(|e| {
        AppError::new(
            ErrorClass::Runtime,
            "MPK_WINDOW_BUILD_FAILED",
            e.to_string(),
            vec![],
        )
    })?];

    let inputs = SystemInputs {
        traffic: &traffic,
        windows: &windows,
        host_health: if *host_unhealthy {
            ServiceHealth::Degraded
        } else {
            ServiceHealth::Healthy
        },
        kill_switch: if *engage_kill_switch {
            KillSwitchState::Engaged
        } else {
            KillSwitchState::Armed
        },
        open_obligations: *open_obligations,
        // No IMDF wavefront/replay evidence is wired into this fixture path yet
        // (docs/WINDOWS_PRODUCT_ROADMAP.md P5: `ssk system run --live`). Per
        // ssk-system's own SystemInputs doc comment, a caller with no real
        // evidence must pass `false` so A3/A8 conservatively hold rather than
        // silently assuming consistency.
        parallax_consistent: false,
        replay_equal: false,
        // No persisted per-host signature baseline is wired into this fixture
        // path yet (docs/WINDOWS_PRODUCT_ROADMAP.md P5: `ssk system
        // baseline-init` / `ssk system run --live`). Per
        // `SystemInputs::signature_baseline`'s own doc comment, a caller with
        // no real baseline must pass `None` so the signature gate
        // conservatively holds rather than fabricating one from the
        // observation it is about to gate.
        signature_baseline: None,
    };

    let mut pipeline = SystemPipeline::new();
    let verdict = pipeline.evaluate(&inputs);
    let ledger_ok = pipeline.verify_ledger();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "decision": verdict.decision.as_str(),
                "reasons": verdict.reasons,
                "signature_gate": verdict.signature_gate,
                "qlogic_gate": verdict.qlogic_gate,
                "resonance_action": verdict.resonance_action,
                "host_downgraded": verdict.host_downgraded,
                "field_digest": verdict.field_digest.to_hex(),
                "crown_head": pipeline.crown_head().to_hex(),
                "ledger_ok": ledger_ok,
            }))
            .map_err(|e| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                e.to_string(),
                vec![]
            ))?
        );
    } else {
        println!("decision: {}", verdict.decision.as_str());
        println!("reasons: {:?}", verdict.reasons);
        println!("signature_gate: {:?}", verdict.signature_gate);
        println!("qlogic_gate: {:?}", verdict.qlogic_gate);
        println!("resonance_action: {:?}", verdict.resonance_action);
        println!("host_downgraded: {}", verdict.host_downgraded);
        println!("field_digest: {}", verdict.field_digest.to_hex());
        println!("crown_head: {}", pipeline.crown_head().to_hex());
        println!("ledger_ok: {ledger_ok}");
    }

    if verdict.decision == EmissionDecision::Deny {
        return Err(AppError::new(
            ErrorClass::System,
            "EMISSION_DENIED",
            "the SystemPipeline denied emission (fail-closed)",
            vec!["Inspect the printed `reasons` for the contributing gate(s).".into()],
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `ssk winhost ...` — the real Windows 11 privileged backends (ssk-winhost),
// bound here behind the same BoundaryEnforcer / BoundaryProbe / TrafficSource /
// PrivilegedHelper traits the pure crates use. Each privileged action is
// reversible and its rollback receipt is persisted so a later `release` /
// `uninstall` (a fresh process) can undo exactly what it did. On a non-Windows
// build every action reports a typed WinHost error, never a silent success.
//
// # SEC-1 at the call site (P1)
//
// Every rollback receipt this binary reads is untrusted input, and there are two
// kinds: the kill-switch receipt and the service install receipt. Both start at
// `winhost_receipt_store_gate` — gate 0, the container — because both live in
// the same directory and neither one's digest is keyed.
//
// For the *kill-switch* receipt, gate 0 is then followed by three byte-level
// checks. Before a receipt may influence a privileged action it must survive, in
// order:
//
//   1. `EnforcementReceipt::verify_against(&scope)` — the receipt is for *this*
//      scope, and its digest matches its own contents. The digest is UNKEYED, so
//      this detects corruption, truncation and naive tampering, and does **not**
//      detect forgery. It is not the control that closes SEC-1.
//   2. `PriorState::parse` — the envelope is `v2`, was written by the netsh
//      actuator, carries a known ownership token, and names a rule that passes
//      the `SSK-KillSwitch-` grammar. **This is the SEC-1 stop.** It is what
//      makes `prior_state = "...;rule=all"` unrepresentable — that value would
//      otherwise have reached `netsh advfirewall firewall delete rule name=all`,
//      which deletes every rule in the profile.
//   3. `rule_name_for_scope(&scope)` — the name carried by the receipt must
//      equal the name re-derived from the scope. After this the receipt's rule
//      name contributes *nothing* to the privileged action: the blast radius is
//      exactly one rule, ours, for this scope.
//
// `BoundaryEnforcer::release_scoped` re-checks 2 and 3 inside the enforcer. The
// duplication is deliberate — the CLI gate is what produces the actionable
// operator error, and neither layer relies on the other remembering to check.
//
// The *service install* receipt has a smaller grammar — no rule name, no
// envelope — so after gate 0 it gets `winhost_verify_install_receipt` and that
// is all there is: `prior_state` in range, `host_id` re-derived from this
// build's manifest, `receipt_id` recomputed. What that leaves standing is
// stated at that function, and it is the reason gate 0 carries this path.
//
// Receipts live in `%ProgramData%\ScorpioSync\state`, never `%TEMP%`. The
// pre-P1 `%TEMP%\ssk-winhost` location is never read for content; a migration
// that "helpfully" imported from a user-writable directory would re-open SEC-1
// verbatim. It is only *counted*, so `doctor` and the no-receipt error can tell
// an operator that stale files are sitting there.
// ---------------------------------------------------------------------------

fn winhost_json_err(e: serde_json::Error) -> AppError {
    AppError::new(
        ErrorClass::Runtime,
        "JSON_OUTPUT_FAILED",
        e.to_string(),
        vec![],
    )
}

/// Build a `WinHost`-class error.
///
/// `next_steps` is a required argument, not a constant. Before P1 this
/// constructor appended *"Live effects require Windows 11 and an elevated
/// (Administrator) shell."* to **every** winhost failure — including failures
/// where elevation was demonstrably not the cause. The de-DE netsh parse break
/// emitted exactly that hint (roadmap §1.4: "The emitted next-step is
/// misleading — elevation is not the problem") and sent the audit down the
/// wrong path. Each call site now states only what the typed error it just
/// handled actually supports.
fn winhost_err(
    machine_code: &str,
    message: impl Into<String>,
    next_steps: Vec<String>,
) -> AppError {
    AppError::new(ErrorClass::WinHost, machine_code, message, next_steps)
}

// `killswitch_next_steps` — next steps derived from a typed `BoundaryError` —
// was deleted here, together with its two tests. It had exactly one consumer
// shape: a `BoundaryError` returned by `WindowsFirewallEnforcer::engage_report`
// / `release_scoped` / `recover` called *from this process*. P3 removed every
// one of those call sites, so this binary can no longer obtain a
// `BoundaryError` at all — the enforcer runs inside the service and its typed
// failures reach here as `ClientError::Failed(String)`.
//
// The two properties its tests pinned did not go with it. They are asserted
// against the function that replaced it, `broker_command_err`:
// `a_service_side_failure_points_at_the_services_message_not_at_elevation` and
// `an_unverified_engage_says_the_claim_survived`.

/// Next steps derived from a **typed** [`ServiceError`].
///
/// `ServiceError::Helper` carries the platform layer's message as a string, so
/// this cannot narrow further — and it deliberately does not guess. The SEC-2
/// image-path refusal arrives through that variant, and elevation does not fix
/// it, which is exactly why the elevation hint is stated as a conditional and
/// placed after the backend's own message rather than asserted first.
fn service_next_steps(err: &ServiceError) -> Vec<String> {
    match err {
        ServiceError::Helper(_) => vec![
            "The privileged helper's message above is authoritative — it names the precondition \
             that failed (for example a refused image path, which elevation does not fix)."
                .into(),
            "Service registration and lifecycle also require an elevated (Administrator) shell; \
             check that only if the message above does not name another cause."
                .into(),
        ],
        ServiceError::Unauthorized => {
            vec!["The caller is not authorized for service control.".into()]
        }
        ServiceError::InvalidTransition(_) => vec![
            "The lifecycle state machine refused this transition; the message above names the \
             states involved."
                .into(),
        ],
        ServiceError::NotHandshaked => {
            vec!["Complete the capability handshake before starting the host.".into()]
        }
        ServiceError::CapabilityDenied(_) => vec![
            "The host manifest does not provide the requested capability; an authorized request \
             for a capability the host cannot provide is denied, not narrowed."
                .into(),
        ],
    }
}

/// Where kill-switch and service rollback receipts live:
/// `%ProgramData%\ScorpioSync\state`.
///
/// Delegates to `ssk-winhost`, which in turn delegates to
/// `ssk_netd_helper::store::default_state_dir()`. The path used to be re-spelled
/// here because `ssk-cli` does not depend on the broker crate; it no longer has
/// to be, because `ssk-winhost` — which `ssk-cli` already depends on — now owns
/// the state-directory primitive and re-exports the one definition. `ssk-cli`
/// still does not depend on `ssk-netd-helper`: the broker is the privileged
/// layer P3 will host as SYSTEM, and the unprivileged CLI depending on it
/// directly would invert that.
fn winhost_store_dir() -> PathBuf {
    ssk_winhost::state_dir::default_state_dir()
}

/// The layout the state directory gate operates on: `…\ScorpioSync` and
/// `…\ScorpioSync\state` are ours to create and lock down; everything above them
/// belongs to Windows and is audited but never modified.
fn winhost_store_layout() -> Result<StateDirLayout, AppError> {
    StateDirLayout::default_program_data().map_err(|refusal| winhost_state_dir_err(&refusal))
}

/// Turn a typed [`StateDirRefusal`] into this binary's error contract. The
/// machine code comes from the refusal itself — notably `NOT_ELEVATED`, which is
/// the same code `ssk_netd_helper::HelperError` emits for the same precondition.
fn winhost_state_dir_err(refusal: &StateDirRefusal) -> AppError {
    let mut next_steps = Vec::new();
    if refusal.is_squat() {
        next_steps.push(
            "This directory is under another principal's control, so nothing in it can be \
             trusted. It is deliberately NOT repaired: re-applying the ACL does not revoke a \
             handle an attacker already holds, and any file already there was written by them."
                .to_owned(),
        );
        if let Some(path) = refusal.path() {
            next_steps.push(format!(
                "From an elevated shell, inspect it before doing anything else: \
                 `icacls \"{path}\"`. If its contents are not yours, remove the directory (it \
                 may be evidence — capture it first), then re-run this command elevated."
            ));
        }
    }
    if refusal.code() == "NOT_ELEVATED" {
        next_steps.push(
            "The state directory does not exist yet, and creating it correctly means taking \
             ownership for BUILTIN\\Administrators and breaking inheritance — both of which \
             require an elevated (Administrator) shell. Creating it unelevated would leave a \
             directory that inherits %ProgramData%'s `Users:Write`, which is exactly the hole \
             this refusal exists to prevent."
                .to_owned(),
        );
    }
    if refusal.code() == "STATE_DIR_UNVERIFIABLE" {
        next_steps.push(
            "The ACL could not be read, so the directory cannot be shown to be safe. This gate \
             fails closed rather than assuming it is."
                .to_owned(),
        );
    }
    AppError::new(
        ErrorClass::WinHost,
        refusal.code(),
        refusal.to_string(),
        next_steps,
    )
}

/// The store directory, **created and locked down** if absent, **verified** if
/// present, and **refused** if some other principal already controls it.
///
/// Only the *writing* paths call this; `release` / `status` / `recover` must
/// never create it, so that a missing directory reads as "nothing was ever
/// engaged" rather than being papered over. Those paths call
/// [`winhost_store_dir_verified`] instead, which verifies without creating.
///
/// This replaced a bare `create_dir_all`. That call was honest about being
/// incomplete but it was still the hole: `C:\ProgramData` grants `BUILTIN\Users`
/// write with `ContainerInherit` (measured on this hardware), so the directory
/// it produced was writable by any unprivileged process on the box, and the P1
/// lockdown that would have fixed that had no caller on this path.
fn winhost_store_dir_created() -> Result<PathBuf, AppError> {
    let layout = winhost_store_layout()?;
    ensure_state_dir(&layout, ssk_winhost::privilege::elevation())
        .map_err(|refusal| winhost_state_dir_err(&refusal))
}

/// Read-only: refuse if the state directory exists but is not protected.
///
/// [`StateDirStatus::Absent`] is **not** an error here — it is the normal
/// first-run state, and the caller decides what an absent store means for its
/// verb. Anything else that cannot be shown to be safe is a refusal.
fn winhost_store_dir_verified() -> Result<StateDirStatus, AppError> {
    let layout = winhost_store_layout()?;
    verify_state_dir(&layout).map_err(|refusal| winhost_state_dir_err(&refusal))
}

/// The pre-P1 receipt directory, `%TEMP%\ssk-winhost`.
///
/// **Never read for content.** Importing a receipt from a user-writable
/// directory is the SEC-1 hole itself; the only thing this location is used for
/// is telling an operator that stale files remain.
fn winhost_legacy_temp_dir() -> PathBuf {
    std::env::temp_dir().join("ssk-winhost")
}

fn winhost_legacy_receipt_count() -> usize {
    std::fs::read_dir(winhost_legacy_temp_dir())
        .map(|entries| entries.flatten().filter(|e| e.path().is_file()).count())
        .unwrap_or(0)
}

/// The kill-switch receipt path for a scope, keyed on the scope's *content
/// digest* — the same digest that determines the firewall rule name — not on a
/// lossy sanitization of the label. This guarantees distinct scopes never
/// collide onto the same receipt file (which would let one engage silently
/// clobber another's rollback receipt). Pure: it performs no IO.
fn winhost_killswitch_receipt_path(scope: &BoundaryScope) -> Result<PathBuf, AppError> {
    let digest = digest_of(scope, HashAlg::Blake3).map_err(|e| {
        AppError::new(
            ErrorClass::Runtime,
            "WINHOST_STATE_DIGEST",
            e.to_string(),
            vec![],
        )
    })?;
    Ok(winhost_store_dir().join(format!("killswitch-{}.json", digest.to_hex())))
}

/// The single spelling of the service install receipt's file name.
///
/// The writer (`install`) and the reader (`uninstall`) deliberately do **not**
/// share a path function: `install` needs [`winhost_store_dir_created`] (which
/// provisions and ACLs the directory before the privileged effect), while
/// `uninstall` needs the non-provisioning [`winhost_service_receipt_path`] —
/// an uninstall must never create the store it is about to read from.
///
/// What they DO share is [`winhost_service_receipt_path_in`]: both call sites
/// pass their own directory to that one function, so the file name cannot drift
/// between writer and reader by construction rather than by convention. If it
/// could, uninstall would silently fail to find what install wrote and skip the
/// rollback.
///
/// That the two directories also agree is a separate invariant, pinned in
/// `ssk-winhost`: `state_dir.rs`'s `layout.leaf() == default_state_dir()`, plus
/// `ensure_state_dir` returning the leaf.
const SERVICE_RECEIPT_FILE: &str = "service-install.json";

/// The one expression that turns a store directory into the service receipt's
/// path. Both call sites go through this; they differ only in **which** store
/// directory they hand it (see [`SERVICE_RECEIPT_FILE`]), which is the part
/// that legitimately differs between a provisioning writer and a
/// non-provisioning reader.
fn winhost_service_receipt_path_in(dir: &std::path::Path) -> PathBuf {
    dir.join(SERVICE_RECEIPT_FILE)
}

fn winhost_service_receipt_path() -> PathBuf {
    winhost_service_receipt_path_in(&winhost_store_dir())
}

/// **Gate 0**, shared by every persisted receipt this binary reads: the
/// *container*, not the bytes.
///
/// If the directory a receipt lives in is owned by, or writable by, a
/// non-administrative principal, then a receipt found in it was planted by
/// whoever controls that directory, and the byte-level checks are the wrong
/// question — every receipt digest in this binary is unkeyed, so whoever can
/// write the file can also recompute the digest over whatever they put in it.
/// This is the same reasoning that moved receipts out of `%TEMP%`: a
/// user-writable directory anywhere is the SEC-1 hole, `%ProgramData%` included,
/// because `C:\ProgramData` grants `BUILTIN\Users` write with `ContainerInherit`
/// to every child it creates.
///
/// [`StateDirStatus::Absent`] is **not** a failure here — it means there is no
/// receipt either, so the caller's own read reports that in the caller's own
/// words rather than this function inventing a second phrasing for it.
///
/// This exists as one function on purpose. It used to be inline in the
/// kill-switch loader only, and the service-uninstall path claimed to use "the
/// same gate" in a comment while performing a bare `fs::read`. A shared function
/// is the only version of that claim that cannot be false.
///
/// # Errors
/// The typed state-directory refusal, already mapped to this binary's error
/// contract by [`winhost_state_dir_err`] (machine code and next steps included).
fn winhost_receipt_store_gate() -> Result<(), AppError> {
    winhost_store_dir_verified().map(|_| ())
}

/// What came back from the one function allowed to read persisted receipt bytes.
enum ReceiptBytes {
    /// The store could not be vouched for. **The file was not read.**
    StoreUnsafe(AppError),
    /// No receipt file exists for this path.
    Missing,
    /// The file exists but could not be read.
    Unreadable(std::io::Error),
    /// The store passed the gate and these are the (still untrusted) bytes.
    Read(Vec<u8>),
}

/// The single choke point for reading a persisted receipt.
///
/// The store gate runs *inside* this function, so receipt bytes only exist on
/// the far side of it. That is deliberate and is the fix for a real defect: the
/// service-uninstall path once read its receipt with a bare `fs::read` under a
/// comment claiming it was gated, and a mutation test later showed that
/// deleting a gate *call* from a caller left the whole suite green. A caller
/// cannot forget a gate it never invokes.
///
/// Callers map the variants onto their own machine codes; they do not get to
/// choose whether the gate runs.
fn winhost_read_receipt_bytes(path: &Path) -> ReceiptBytes {
    winhost_read_receipt_bytes_with(path, winhost_receipt_store_gate)
}

/// [`winhost_read_receipt_bytes`] with the gate injected, so a test can prove
/// the gate really precedes the read rather than merely sitting near it.
fn winhost_read_receipt_bytes_with(
    path: &Path,
    gate: impl FnOnce() -> Result<(), AppError>,
) -> ReceiptBytes {
    if let Err(e) = gate() {
        return ReceiptBytes::StoreUnsafe(e);
    }
    match std::fs::read(path) {
        Ok(bytes) => ReceiptBytes::Read(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ReceiptBytes::Missing,
        Err(e) => ReceiptBytes::Unreadable(e),
    }
}

/// Result of loading a persisted kill-switch receipt through the full gate
/// described in this module's header.
enum LoadedReceipt {
    /// No receipt file exists for this scope.
    Missing,
    /// A receipt file exists but must not influence any privileged action.
    Invalid { code: &'static str, detail: String },
    /// The receipt passed integrity, envelope-grammar and scope re-derivation.
    Valid {
        receipt: EnforcementReceipt,
        prior: PriorState,
    },
}

/// Load and fully validate the receipt for `scope`. This is the only function
/// in this binary that turns receipt bytes into something a privileged action
/// may act on.
///
/// Gate 0 is [`winhost_receipt_store_gate`] — the container, not the bytes.
fn winhost_load_killswitch_receipt(scope: &BoundaryScope, path: &Path) -> LoadedReceipt {
    // Gate 0 runs inside the reader; see `winhost_read_receipt_bytes`.
    let bytes = match winhost_read_receipt_bytes(path) {
        ReceiptBytes::StoreUnsafe(e) => {
            return LoadedReceipt::Invalid {
                code: "KILLSWITCH_STORE_UNSAFE",
                detail: format!(
                    "refusing to read {}: the state directory cannot be trusted — {}",
                    path.display(),
                    e.message
                ),
            }
        }
        ReceiptBytes::Missing => return LoadedReceipt::Missing,
        ReceiptBytes::Unreadable(e) => {
            return LoadedReceipt::Invalid {
                code: "KILLSWITCH_RECEIPT_UNREADABLE",
                detail: format!("cannot read the receipt at {}: {e}", path.display()),
            }
        }
        ReceiptBytes::Read(bytes) => bytes,
    };
    let receipt: EnforcementReceipt = match serde_json::from_slice(&bytes) {
        Ok(receipt) => receipt,
        Err(e) => {
            return LoadedReceipt::Invalid {
                code: "KILLSWITCH_RECEIPT_INVALID",
                detail: format!(
                    "{} is not a decodable enforcement receipt: {e}",
                    path.display()
                ),
            }
        }
    };

    // 1. Integrity + scope binding. Unkeyed: catches corruption, truncation and
    //    naive tampering, NOT forgery. Checks 2 and 3 are what bound forgery.
    if let Err(e) = receipt.verify_against(scope) {
        return LoadedReceipt::Invalid {
            code: "KILLSWITCH_RECEIPT_INVALID",
            detail: format!(
                "the receipt at {} failed its integrity check: {e}",
                path.display()
            ),
        };
    }

    // 2. The envelope grammar — the SEC-1 stop. A rule name that is not
    //    `SSK-KillSwitch-[label-]<16 lowercase hex>` cannot get past this.
    let prior = match PriorState::parse(&receipt.prior_state) {
        Ok(prior) => prior,
        Err(e) => {
            return LoadedReceipt::Invalid {
                code: "KILLSWITCH_RECEIPT_REJECTED",
                detail: format!("refusing to act on the receipt at {}: {e}", path.display()),
            }
        }
    };

    // 3. Scope re-derivation. After this the receipt's rule name contributes
    //    nothing at all to the privileged action.
    match rule_name_for_scope(scope) {
        Ok(expected) if expected == prior.rule_name => LoadedReceipt::Valid { receipt, prior },
        Ok(expected) => LoadedReceipt::Invalid {
            code: "KILLSWITCH_RECEIPT_REJECTED",
            detail: format!(
                "the receipt at {} names rule {} but scope {:?} derives {}; refusing to act on it",
                path.display(),
                prior.rule_name,
                scope.label,
                expected
            ),
        },
        Err(e) => LoadedReceipt::Invalid {
            code: "KILLSWITCH_RECEIPT_REJECTED",
            detail: format!(
                "cannot re-derive the rule name for scope {:?}: {e}",
                scope.label
            ),
        },
    }
}

/// Next steps for "there is no usable **pre-broker** receipt for this scope".
///
/// If the *store* is what is wrong, that comes first: no receipt-level advice is
/// actionable while the directory the receipts live in is under someone else's
/// control.
///
/// These steps describe the advisory, local view only. They no longer offer a
/// CLI `recover` that deletes the rule, because there is no longer one: this
/// process performs no privileged action, and `recover` explains the
/// service-side path instead of taking it.
fn winhost_no_receipt_next_steps(scope_label: &str) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    if let Err(store_err) = winhost_store_dir_verified() {
        steps.extend(store_err.next_steps);
    }
    steps.extend([
        format!(
            "`ssk winhost killswitch status --scope {scope_label}` reports the AUTHORITATIVE \
             state held by the privileged service; it is read-only and needs no elevation."
        ),
        format!(
            "If a rule is present that the service does not account for, `ssk winhost killswitch \
             recover --scope {scope_label}` prints the derived rule name and the two recovery \
             paths. It deletes nothing itself."
        ),
    ]);
    let stale = winhost_legacy_receipt_count();
    if stale > 0 {
        steps.push(format!(
            "{stale} file(s) remain in the pre-P1 receipt directory {}. They are deliberately NOT \
             imported — reading a receipt out of a user-writable directory is the SEC-1 hole this \
             release closed. Delete them.",
            winhost_legacy_temp_dir().display()
        ));
    }
    steps
}

/// Resolve `netsh.exe` the way `ssk_winhost::firewall` does: absolute, under
/// `%SystemRoot%\System32`, never through a `PATH` search. Duplicated because
/// that resolver is private to its crate; used only as a read-only `doctor`
/// probe, never to spawn anything.
fn winhost_netsh_path() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(root) = std::env::var_os("SystemRoot") {
        candidates.push(PathBuf::from(root).join("System32").join("netsh.exe"));
    }
    candidates.push(PathBuf::from(r"C:\Windows\System32\netsh.exe"));
    candidates.into_iter().find(|c| c.is_file())
}

/// The deterministic host manifest the service subcommands share, so `install`,
/// `start`, `stop`, and `uninstall` all derive the same content-addressed host
/// id (and therefore the same Windows service name).
fn winhost_manifest() -> HostManifest {
    HostManifest::new(
        "ssk-host",
        env!("CARGO_PKG_VERSION"),
        "windows",
        ["system_capture", "egress_teardown"],
    )
}

fn winhost_default_svc_path() -> Result<PathBuf, AppError> {
    let current = std::env::current_exe()
        .map_err(|e| AppError::new(ErrorClass::Runtime, "CURRENT_EXE", e.to_string(), vec![]))?;
    let dir = current.parent().unwrap_or_else(|| Path::new("."));
    let name = if cfg!(windows) {
        "ssk-svc.exe"
    } else {
        "ssk-svc"
    };
    Ok(dir.join(name))
}

// ---------------------------------------------------------------------------
// The privileged broker client (roadmap P3)
// ---------------------------------------------------------------------------
//
// Before P3 this file constructed `WindowsFirewallEnforcer::new` at five
// sites and called `engage_report` / `release_scoped` / `release_reporting` /
// `recover` on it. Every one of those spawned `netsh advfirewall firewall
// add|delete rule` **from the unprivileged CLI process**, which meant the
// broker's peer-authorization gate, nonce rejection, op-lock, version gate and
// hash-chained audit were all bypassed on the path users actually take. They
// were on no path at all: `ssk_netd_helper::Broker` was constructed in three
// test files and nowhere else.
//
// After P3 this binary performs **no privileged action**. It opens the
// SYSTEM-owned control pipe, completes a versioned handshake, sends one
// envelope, and renders the typed answer. Exactly two things are still asked of
// a Windows firewall backend, and both are reads:
//
//   * `EgressMechanism` — which mechanism this build selected, printed by
//     `doctor`. No process is spawned.
//   * `BoundaryProbe::observe` — `netsh advfirewall firewall show rule`,
//     measured on Windows 11 de-DE to need no elevation, reached only through
//     `winhost_local_advisory_observation`, and used only for the *advisory*
//     line that says whether a rule is visible on a machine whose broker is
//     unreachable.
//
// Two tests hold that line: one asserts no mutating enforcer verb appears
// anywhere in this file, the other counts the enforcer's construction sites and
// fails on a third.
//
// # There is deliberately no fallback
//
// If the broker cannot be reached, every mutating verb fails with a typed
// error naming the service. It does not "helpfully" fall back to driving netsh
// directly. A fallback would re-open, in one branch, everything this phase
// exists to close: an unauthenticated caller, no allow-list, no audit chain, no
// lease bookkeeping, and a receipt written by an unprivileged process into a
// directory the broker treats as authoritative.
//
// # SEC-1 and receipts
//
// **Kill-switch receipts moved behind the broker entirely.** The broker owns
// `killswitch.cbor` in `%ProgramData%\ScorpioSync\state`, writes it as SYSTEM,
// and serves the held `EnforcementReceipt` inside `KillSwitchStatus` over the
// authenticated pipe. This binary no longer reads a receipt to drive any
// action, because it drives no action.
//
// The P1 receipt reader (`winhost_load_killswitch_receipt` and its three gates)
// is kept and still runs, on one path only: `status` and `doctor` report
// whether a **pre-broker `killswitch-<digest>.json`** is sitting in the state
// directory, because a machine upgraded from P1 can be severed by a rule the
// broker's journal knows nothing about. That is a migration finding, never a
// decision input — and it is still read through the full gate, so a planted
// file cannot influence even the sentence that describes it.

/// The transport the privileged client speaks over.
///
/// On Windows this is `ssk-winhost`'s named-pipe client, which verifies that
/// the endpoint is owned by `S-1-5-18` **before the first frame is written**.
/// That check is what makes a fixed, well-known pipe name safe to use: a
/// squatter that starts before the service can otherwise complete a handshake
/// and answer a forged `Ok(Status)` claiming `Engaged` while egress flows.
#[cfg(windows)]
type BrokerTransport = ssk_winhost::NamedPipeClientTransport;

/// Off-Windows there is no privileged control plane to speak to, so this type
/// exists only to give [`BrokerClient`] a concrete parameter. It is never
/// constructed: [`broker_open`] returns a typed refusal first. Its methods are
/// still real refusals rather than `unimplemented!()`, because a panic in a
/// binary that promises a machine-readable error contract is a contract break.
#[cfg(not(windows))]
struct UnreachableTransport;

#[cfg(not(windows))]
impl ssk_netd_helper::FrameTransport for UnreachableTransport {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ssk_netd_helper::TransportError> {
        Err(ssk_netd_helper::TransportError::Closed)
    }
    fn write_all(&mut self, _bytes: &[u8]) -> Result<(), ssk_netd_helper::TransportError> {
        Err(ssk_netd_helper::TransportError::Closed)
    }
    fn flush(&mut self) -> Result<(), ssk_netd_helper::TransportError> {
        Err(ssk_netd_helper::TransportError::Closed)
    }
}

#[cfg(not(windows))]
type BrokerTransport = UnreachableTransport;

/// A connected, handshaken privileged client.
type BrokerClient = PrivilegedClient<BrokerTransport, CsprngNonces>;

/// The endpoint this binary would speak to, named so `doctor` can print it
/// whether or not the platform has one.
#[must_use]
fn privileged_endpoint_name() -> &'static str {
    #[cfg(windows)]
    {
        ssk_winhost::PRIVILEGED_PIPE_NAME
    }
    #[cfg(not(windows))]
    {
        "(none — this build carries no Windows privileged control plane)"
    }
}

/// Per-command anti-replay nonces and idempotency keys, seeded from the OS
/// CSPRNG.
///
/// `ssk_netd_helper::NonceSource` has no error channel on `next`, so the
/// failure story has to be decided here rather than deferred. It is:
///
/// * **Construction fails closed.** [`CsprngNonces::new`] draws a seed and
///   returns a typed error if the OS CSPRNG refuses, so a client is never built
///   on top of a random source that has already failed once.
/// * **A later refusal degrades to the seed, never to a constant.** If
///   `getrandom` fails mid-session the seed drawn at construction is used
///   instead — a value the OS CSPRNG did produce and an attacker does not know.
/// * **Distinctness never depends on the CSPRNG having worked.** The counter is
///   mixed into the low half unconditionally, so a repeated nonce (which the
///   broker rejects as a replay, denying service to the legitimate caller) is
///   not reachable even if every draw after the first fails.
///
/// This is the same shape as `ssk_winhost::CsprngLeaseIds`, deliberately: two
/// different fallbacks for the same failure in one product is how one of them
/// ends up being the wrong one.
struct CsprngNonces {
    seed: [u8; 16],
    counter: u64,
}

impl CsprngNonces {
    fn new() -> Result<Self, AppError> {
        let mut seed = [0u8; 16];
        getrandom::fill(&mut seed).map_err(|e| {
            winhost_err(
                "KILLSWITCH_CSPRNG_UNAVAILABLE",
                format!("the OS CSPRNG refused to seed the privileged client's nonce source: {e}"),
                vec![
                    "Anti-replay nonces must be unpredictable, so this refuses rather than \
                     sending a guessable one. A predictable nonce can be burned ahead of a \
                     legitimate client, which turns anti-replay into denial of service."
                        .into(),
                    "`ssk doctor` runs the same entropy probe and reports the provider by name."
                        .into(),
                ],
            )
        })?;
        Ok(CsprngNonces { seed, counter: 0 })
    }
}

impl NonceSource for CsprngNonces {
    fn next(&mut self) -> [u8; 16] {
        self.counter += 1;
        let mut out = [0u8; 16];
        if getrandom::fill(&mut out).is_err() {
            tracing::error!(
                target: "ssk.winhost.broker",
                "the OS CSPRNG refused mid-session; deriving this nonce from the seed drawn at \
                 construction"
            );
            out = self.seed;
        }
        let tail = u64::from_be_bytes(out[8..].try_into().unwrap_or([0u8; 8])) ^ self.counter;
        out[8..].copy_from_slice(&tail.to_be_bytes());
        out
    }
}

/// Open the privileged control pipe and complete the handshake.
///
/// # Errors
/// A [`ErrorClass::WinHost`] error (exit 21) for every failure, so the
/// kill-switch error contract is unchanged: a broker-absent machine gets
/// `KILLSWITCH_BROKER_UNREACHABLE` and never a success.
#[cfg(windows)]
fn broker_open(hello: ClientHello) -> Result<BrokerClient, AppError> {
    let nonces = CsprngNonces::new()?;
    let transport = ssk_winhost::NamedPipeClientTransport::connect(
        ssk_winhost::PRIVILEGED_PIPE_NAME,
        ssk_winhost::LOCAL_SYSTEM_SID,
    )
    .map_err(|e| broker_transport_err(&e))?;
    tracing::debug!(
        target: "ssk.winhost.broker",
        endpoint = ssk_winhost::PRIVILEGED_PIPE_NAME,
        "privileged endpoint accepted; its owner is S-1-5-18"
    );
    PrivilegedClient::connect(transport, nonces, hello)
        .map_err(|e| broker_command_err("KILLSWITCH_BROKER_HANDSHAKE_REFUSED", &e))
}

/// Off-Windows there is no privileged broker and no named pipe. Refuse in the
/// same typed shape rather than pretending the machine is un-severed.
///
/// # Errors
/// Always.
#[cfg(not(windows))]
fn broker_open(hello: ClientHello) -> Result<BrokerClient, AppError> {
    let _ = hello;
    // Seeded here too, in the same order as the Windows path: the nonce source
    // has one construction contract on every target, and a client that cannot
    // draw an unpredictable nonce is refused before anything else is
    // considered. It also keeps `CsprngNonces::new` on a non-test call path on
    // targets that have no pipe, rather than needing a lint exemption to
    // silence it.
    let _nonces = CsprngNonces::new()?;
    Err(winhost_err(
        "KILLSWITCH_BROKER_UNSUPPORTED",
        format!(
            "this build targets {} and carries no Windows privileged control plane, so the \
             kill-switch cannot be commanded from here",
            std::env::consts::OS
        ),
        vec![
            "The kill-switch is actuated by a LocalSystem Windows service over a named pipe. \
             Run this on Windows 11 with the service installed."
                .into(),
            "Nothing was actuated. This command does NOT fall back to driving a firewall itself \
             on any platform."
                .into(),
        ],
    ))
}

/// Map a connect-time [`std::io::Error`] onto the kill-switch error contract.
///
/// The three cases are told apart by *evidence*, not by string matching on the
/// message:
///
/// * `NotFound` — nothing is listening. This is the common real-world case (the
///   service is not installed, or is stopped) and it must be immediately
///   actionable, not a bare OS errno.
/// * `PermissionDenied` **with no OS errno** — the only producer of that shape
///   is `ssk_winhost::require_pipe_owner` refusing an endpoint whose owner is
///   not `S-1-5-18`. That is a squatted pipe, and it is the loudest error here.
/// * `PermissionDenied` **with an OS errno** — the kernel's access check on the
///   pipe DACL refused this caller.
#[cfg(windows)]
fn broker_transport_err(e: &std::io::Error) -> AppError {
    match e.kind() {
        std::io::ErrorKind::NotFound => winhost_err(
            "KILLSWITCH_BROKER_UNREACHABLE",
            format!(
                "the privileged kill-switch service is not running: nothing is listening on {}",
                ssk_winhost::PRIVILEGED_PIPE_NAME
            ),
            broker_absent_next_steps(),
        ),
        std::io::ErrorKind::PermissionDenied if e.raw_os_error().is_none() => winhost_err(
            "KILLSWITCH_BROKER_NOT_SYSTEM_OWNED",
            format!(
                "REFUSING TO TALK TO {}: it is not owned by {}. Something other than the \
                 LocalSystem service is holding that name, and it can answer with a forged \
                 status. Nothing was sent to it. ({e})",
                ssk_winhost::PRIVILEGED_PIPE_NAME,
                ssk_winhost::LOCAL_SYSTEM_SID
            ),
            vec![
                "Do not trust any kill-switch state reported while this persists — a squatter \
                 can claim `engaged` while egress flows."
                    .into(),
                "The endpoint name is fixed and well known, so an unprivileged process that \
                 starts before the service can claim it. Find and stop it, then restart the \
                 service."
                    .into(),
                "`ssk winhost service stop` then `ssk winhost service start`, from an elevated \
                 shell, re-binds the name with FILE_FLAG_FIRST_PIPE_INSTANCE."
                    .into(),
            ],
        ),
        std::io::ErrorKind::PermissionDenied => winhost_err(
            "KILLSWITCH_BROKER_ACCESS_DENIED",
            format!(
                "the OS refused this process access to {}: {e}",
                ssk_winhost::PRIVILEGED_PIPE_NAME
            ),
            vec![
                "The pipe's DACL names the accounts allowed to open it at all. This is the \
                 kernel's access check, which happens before any of the broker's own \
                 authorization."
                    .into(),
                "An administrator can add this account to the service's allow-list \
                 (`authz.json` in the service's state directory); the pipe is rebuilt from it \
                 when the service restarts."
                    .into(),
            ],
        ),
        _ => winhost_err(
            "KILLSWITCH_BROKER_UNREACHABLE",
            format!(
                "cannot reach the privileged kill-switch service on {}: {e}",
                ssk_winhost::PRIVILEGED_PIPE_NAME
            ),
            broker_absent_next_steps(),
        ),
    }
}

/// What to tell an operator whose machine has no reachable broker.
///
/// Deliberately concrete. The pre-P3 code answered every winhost failure with
/// "run as Administrator", which was wrong often enough that P1 deleted the
/// blanket hint; the same discipline applies here — none of these steps blames
/// elevation, because an unelevated `ssk` talking to a running service is the
/// normal case.
///
/// `#[cfg(windows)]` because every step names a Windows service. Off-Windows
/// there is no endpoint to be absent from, and `broker_open` refuses with its
/// own guidance rather than pointing at `sc start`.
#[cfg(windows)]
fn broker_absent_next_steps() -> Vec<String> {
    vec![
        "Install it: `ssk winhost service install` from an elevated (Administrator) shell."
            .to_owned(),
        "If it is installed, start it: `ssk winhost service start` (elevated), or `sc start \
         ScorpioSync`."
            .to_owned(),
        "`ssk winhost doctor` reports whether the service is reachable and what this build can \
         and cannot establish about it."
            .to_owned(),
        "Nothing was actuated. This command does NOT fall back to driving the firewall itself: \
         doing so would bypass the authorization, audit and lease bookkeeping the service exists \
         to provide."
            .to_owned(),
    ]
}

/// Map a [`ClientError`] onto the kill-switch error contract.
///
/// `failed_code` is the caller's own code for "the OS effect was attempted and
/// failed" — `KILLSWITCH_ENGAGE_FAILED` / `KILLSWITCH_RELEASE_FAILED`, the exact
/// codes the pre-P3 CLI emitted for the same condition. Everything else maps to
/// a P3-specific code, because it describes a condition that could not exist
/// before: there was no peer, no session and no version to be wrong about.
fn broker_command_err(failed_code: &'static str, e: &ClientError) -> AppError {
    match e {
        ClientError::Failed(message) => winhost_err(
            failed_code,
            format!("the privileged service attempted the change and it failed: {message}"),
            vec![
                "The service's own message above is authoritative — act on what it names.".into(),
                "The service reports its state unchanged on this path; `ssk winhost killswitch \
                 status` re-reads the authoritative status."
                    .into(),
            ],
        ),
        ClientError::Rejected(RejectReason::PeerUnauthorized { code, detail }) => winhost_err(
            "KILLSWITCH_PEER_UNAUTHORIZED",
            format!("this account is not permitted to drive the kill-switch ({code}): {detail}"),
            vec![
                "The service authorizes each verb against the SID of the calling process. \
                 Reading status is open to any caller the pipe admitted; engaging and releasing \
                 require an explicit grant."
                    .into(),
                "An administrator grants it by adding this account's SID to `authz.json` in the \
                 service's state directory, then restarting the service."
                    .into(),
                "`whoami /user` prints the SID to add.".into(),
            ],
        ),
        ClientError::Rejected(RejectReason::Unauthorized) => winhost_err(
            "KILLSWITCH_BROKER_UNAUTHORIZED",
            "the privileged service is not itself authorized to actuate the boundary; the \
             caller is not the problem"
                .to_owned(),
            vec![
                "This is a deployment fault, not a permissions one: the service was composed \
                 without a grant for its own boundary-control verb."
                    .into(),
                "Reinstall the service; if it persists, the installed build is not one that can \
                 drive the kill-switch at all."
                    .into(),
            ],
        ),
        ClientError::Rejected(RejectReason::StaleVersion { expected, actual }) => winhost_err(
            "KILLSWITCH_CONCURRENT_CHANGE",
            format!(
                "someone else changed the kill-switch while this command was in flight \
                 (expected state version {expected}, the service is at {actual}); nothing was \
                 applied"
            ),
            vec![
                "The client already refreshed and retried once. A second loss means another \
                 holder is actively driving the switch."
                    .into(),
                "`ssk winhost killswitch status` shows the authoritative state; re-run the \
                 command if it is still what you want."
                    .into(),
            ],
        ),
        ClientError::Rejected(RejectReason::ReplayedNonce) => winhost_err(
            "KILLSWITCH_COMMAND_REJECTED",
            "the privileged service rejected this command's nonce as already seen".to_owned(),
            vec![
                "Nothing was applied. A fresh nonce is drawn per command, so this means the \
                 session's anti-replay set already contains it."
                    .into(),
                "Re-run the command; it opens a new session with a new nonce.".into(),
            ],
        ),
        ClientError::Rejected(reason) => winhost_err(
            "KILLSWITCH_COMMAND_REJECTED",
            format!("the privileged service refused this command before executing it: {reason:?}"),
            vec![
                "Nothing was applied — refusals happen before any OS effect.".into(),
                "`ssk winhost killswitch status` reports the authoritative state.".into(),
            ],
        ),
        ClientError::Refused(reason) => winhost_err(
            "KILLSWITCH_BROKER_HANDSHAKE_REFUSED",
            format!("the privileged service refused the connection: {reason}"),
            broker_handshake_next_steps(reason),
        ),
        ClientError::Protocol(detail) => winhost_err(
            "KILLSWITCH_BROKER_PROTOCOL_VIOLATION",
            format!(
                "the endpoint answered with something this protocol does not allow at that \
                 point: {detail}"
            ),
            vec![
                "Nothing was applied. An endpoint that does not speak this protocol is not \
                 treated as a broker, whatever it claims."
                    .into(),
                "This is what a squatted pipe looks like after it passes the owner check, or \
                 what a badly mismatched build looks like. Compare `ssk version` with the \
                 installed service binary."
                    .into(),
            ],
        ),
        ClientError::Frame(frame) => winhost_err(
            "KILLSWITCH_BROKER_TRANSPORT_FAILED",
            format!(
                "the connection to the privileged service failed ({}): {frame}",
                frame.code()
            ),
            vec![
                "Whether the command took effect is NOT established by this error — the reply \
                 was lost, not the request."
                    .into(),
                "`ssk winhost killswitch status` reports the authoritative state; read it before \
                 retrying."
                    .into(),
            ],
        ),
        // `ClientError` is `#[non_exhaustive]`. A variant this build does not
        // know is not evidence that nothing happened, so it fails into the
        // loudest generic branch rather than a reassuring one.
        other => winhost_err(
            "KILLSWITCH_COMMAND_REJECTED",
            format!("the privileged client reported an unrecognized failure: {other}"),
            vec![
                "This build does not recognize the failure it just received; do not assume the \
                 command did or did not take effect."
                    .into(),
                "`ssk winhost killswitch status` reports the authoritative state.".into(),
            ],
        ),
    }
}

/// Next steps derived from a **typed** [`HandshakeReject`] — never from prose.
fn broker_handshake_next_steps(reason: &HandshakeReject) -> Vec<String> {
    let mut steps = match reason {
        HandshakeReject::LeaseUnavailable(detail) => vec![
            format!(
                "The claim named on the command line is not one the service is holding: {detail}"
            ),
            "Only a durable (pinned) claim can be adopted, and only while it is still held. \
             `ssk winhost killswitch status` shows whether the switch is engaged at all."
                .to_owned(),
            "If the switch is engaged and no claim id is known, the service's own startup \
             reconciliation is the recovery path — stop and start the service."
                .to_owned(),
        ],
        HandshakeReject::AtCapacity => vec![
            "The service is serving its maximum number of concurrent control connections. \
             Nothing was applied; retry."
                .to_owned(),
        ],
        other => vec![format!(
            "The service stated the reason above verbatim ({}); nothing was applied.",
            other.code()
        )],
    };
    steps.push(
        "Nothing was actuated, and this command does not fall back to driving the firewall \
         itself."
            .to_owned(),
    );
    steps
}

// ---------------------------------------------------------------------------
// The pinned-claim hint
// ---------------------------------------------------------------------------
//
// `engage` from a command line takes a **pinned** claim: an operator who types
// it means "stay severed", including across a reboot, which is exactly what
// `LeaseKind::Pinned` is. The consequence is that the claim outlives the
// process, and the protocol identifies a claim by an id the *server* mints and
// returns in the handshake. A later `release` in a fresh process therefore has
// to name that id — and `KillSwitchStatus` does not carry the claim set, so
// there is no way to ask for it back.
//
// Without something remembering the id, `ssk winhost killswitch engage`
// followed by closing the terminal would leave a machine severed that this CLI
// can no longer un-sever. That is the "a user cannot un-sever their own
// machine" failure the whole authorization design was shaped to avoid, so it is
// not acceptable to leave it to the operator to copy a hex string.
//
// So `engage` writes the id to a per-user hint file and `release` reads it,
// with `--lease` overriding both.
//
// # The hint file is not a receipt, and it is not a credential
//
// It is user-writable by construction (it lives under `%LOCALAPPDATA%`), and
// that is fine, because it carries no authority whatsoever:
//
//  * it names no rule, no path, no principal and no scope — the whole file is
//    32 hex characters, parsed by a total function that accepts nothing else;
//  * the service refuses any id that is not **currently held** and **pinned**,
//    so a planted value yields a typed handshake refusal, not an action;
//  * dropping a claim is still authorized per request against the caller's SID,
//    so presenting an id is not permission to release.
//
// That is the whole SEC-1 argument: the file cannot influence a privileged
// decision because the only thing it can do is *fail*. It is deliberately NOT
// stored beside the broker's receipts — an unprivileged process must not write
// into the directory the service treats as authoritative.

/// Parse a lease id: exactly 32 lowercase hex characters, nothing else.
///
/// Total, and strict on purpose. `LeaseId::to_hex` is what produced the string,
/// so accepting uppercase, whitespace, `0x`, or a truncated id would mean
/// accepting something this product never emits.
fn parse_lease_id(text: &str) -> Result<LeaseId, String> {
    if text.len() != 32 {
        return Err(format!(
            "a claim id is exactly 32 hexadecimal characters; this one is {}",
            text.len()
        ));
    }
    let mut raw = [0u8; 16];
    for (i, byte) in raw.iter_mut().enumerate() {
        let pair = text
            .get(i * 2..i * 2 + 2)
            .ok_or_else(|| "a claim id is exactly 32 ASCII hexadecimal characters".to_owned())?;
        if !pair
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(format!(
                "`{pair}` is not lowercase hexadecimal; a claim id is exactly what `engage` \
                 printed"
            ));
        }
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|e| format!("`{pair}` is not a hexadecimal byte: {e}"))?;
    }
    Ok(LeaseId(raw))
}

/// Where the hint for a scope lives, given the per-user directory it belongs in.
///
/// Keyed on the scope's *content digest*, the same digest that determines the
/// firewall rule name, for the same reason the receipt path was: two distinct
/// scopes must never collide onto one file.
fn lease_hint_path_in(dir: &Path, scope: &BoundaryScope) -> Result<PathBuf, AppError> {
    let digest = digest_of(scope, HashAlg::Blake3).map_err(|e| {
        AppError::new(
            ErrorClass::Runtime,
            "WINHOST_STATE_DIGEST",
            e.to_string(),
            vec![],
        )
    })?;
    Ok(dir.join(format!("killswitch-claim-{}.hint", digest.to_hex())))
}

/// The per-user directory the hint lives in, or `None` when this platform or
/// this environment does not offer one.
///
/// `None` is a degradation, never a failure: the product still works, `release`
/// just needs `--lease` explicitly. Falling back to the working directory or to
/// `%TEMP%` was rejected — the first litters wherever the user happened to be,
/// and the second is auto-cleaned, which is precisely the defect that made the
/// pre-P1 receipt scheme lose rollback state.
fn lease_hint_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("SSK_CLAIM_HINT_DIR") {
        return Some(PathBuf::from(dir));
    }
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("ScorpioSync"))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state"))
            })
            .map(|d| d.join("scorpiosync"))
    }
}

/// Read the remembered claim id for a scope, if there is one this build will
/// act on.
///
/// Every failure — no directory, no file, unreadable, unparsable — is `None`.
/// There is nothing to report: the hint is an optimization over typing
/// `--lease`, and an unusable one simply is not used.
fn read_lease_hint(scope: &BoundaryScope) -> Option<LeaseId> {
    let dir = lease_hint_dir()?;
    let path = lease_hint_path_in(&dir, scope).ok()?;
    let text = std::fs::read_to_string(path).ok()?;
    parse_lease_id(text.trim()).ok()
}

/// Remember the claim id `engage` was granted. Best effort by design.
///
/// A failure here is **not** an error the way a lost rollback receipt was: the
/// claim exists in the service's durable store either way, and the only cost of
/// losing the hint is that `release` needs `--lease`. So this reports the
/// failure to the operator (who can then write the id down) and does not undo
/// the engagement.
fn write_lease_hint(scope: &BoundaryScope, lease: LeaseId) -> Result<PathBuf, String> {
    let dir = lease_hint_dir()
        .ok_or_else(|| "this environment names no per-user state directory".to_owned())?;
    let path = lease_hint_path_in(&dir, scope).map_err(|e| e.message)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    std::fs::write(&path, lease.to_hex())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// Forget the remembered claim id. Best effort; a stale hint is harmless
/// because the service refuses an id it is not holding.
fn clear_lease_hint(scope: &BoundaryScope) {
    if let Some(dir) = lease_hint_dir() {
        if let Ok(path) = lease_hint_path_in(&dir, scope) {
            let _ = std::fs::remove_file(path);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering the authoritative status
// ---------------------------------------------------------------------------

/// A stable token for a [`Recovery`] verdict.
///
/// `Inconsistent` is the fail-closed alarm: the journal and the observed OS
/// rule disagree, **or** the journal says engaged and the probe could not
/// answer. It is never softened into one of the clean states.
fn recovery_token(recovery: Recovery) -> &'static str {
    match recovery {
        Recovery::Consistent => "consistent",
        Recovery::Reconciled => "reconciled",
        Recovery::Inconsistent => "inconsistent",
    }
}

/// The single verdict token every kill-switch command renders, derived only
/// from the authoritative status.
///
/// Pure, so the whole table is testable with no service and no firewall. The
/// pre-P3 verdict was a cross product of a local receipt file and a local
/// probe; this one is a cross product of the service's journal and the
/// service's observation, which is the same shape one layer up and one
/// principal over.
fn broker_verdict(status: &KillSwitchStatus) -> (&'static str, String) {
    match (
        status.logical_state,
        status.os_rule_present,
        status.recovery,
    ) {
        (_, _, Recovery::Inconsistent) => (
            "inconsistent",
            "the service's journal and what it observes of the OS firewall disagree, or it \
             believes egress is severed and could not confirm it. This is an alarm, not a state."
                .to_owned(),
        ),
        (KillSwitchState::Engaged, Some(true), _) => (
            "engaged",
            "egress is severed and the service confirmed its rule is present".to_owned(),
        ),
        (KillSwitchState::Engaged, _, _) => (
            "engaged_unconfirmed",
            "the service's journal says egress is severed but it could not confirm the rule; \
             this is NOT evidence that egress is flowing"
                .to_owned(),
        ),
        (state, Some(true), _) => (
            "not_engaged_rule_present",
            format!(
                "the service's journal says {} yet a rule is observed present — something other \
                 than this service is severing egress",
                state.as_str()
            ),
        ),
        (state, _, _) => (
            "not_engaged",
            format!(
                "the service's journal says {} and it observes nothing severing egress for this \
                 scope",
                state.as_str()
            ),
        ),
    }
}

/// The machine-readable authoritative block.
///
/// The receipt is rendered because it is *evidence*, and it is safe to render
/// precisely because of where it came from: over the authenticated pipe from
/// the SYSTEM-owned service, not out of a file this process could have written.
/// Nothing in this binary acts on it.
fn broker_status_json(status: &KillSwitchStatus) -> serde_json::Value {
    let (verdict, verdict_detail) = broker_verdict(status);
    serde_json::json!({
        "authoritative": true,
        "logical_state": status.logical_state.as_str(),
        "os_rule_present": status.os_rule_present,
        "os_rule_present_means":
            "null means the service's probe could not determine presence. It is NEVER read as \
             absence: an unobservable rule is not a removed one",
        "recovery": recovery_token(status.recovery),
        "alarm": status.is_alarm(),
        "state_version": status.state_version,
        "audit_head": status.audit_head.to_hex(),
        "audit_len": status.audit_len,
        "receipt": status.receipt.as_ref().map(|r| serde_json::json!({
            "receipt_id": r.receipt_id.to_hex(),
            "scope_label": r.scope_label,
        })),
        "verdict": verdict,
        "verdict_detail": verdict_detail
    })
}

/// The human-readable authoritative block.
fn print_broker_status(status: &KillSwitchStatus) {
    let (verdict, verdict_detail) = broker_verdict(status);
    println!("source: the privileged service (authoritative)");
    println!("logical_state: {}", status.logical_state.as_str());
    println!(
        "os_rule_present: {}",
        match status.os_rule_present {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown (the service's probe could not answer; not read as absent)",
        }
    );
    println!("recovery: {}", recovery_token(status.recovery));
    println!(
        "state_version: {} (audit entries: {}, head {})",
        status.state_version,
        status.audit_len,
        status.audit_head.to_hex()
    );
    if let Some(receipt) = &status.receipt {
        println!(
            "held receipt: {} for scope '{}'",
            receipt.receipt_id.to_hex(),
            receipt.scope_label
        );
    }
    println!("verdict: {verdict} — {verdict_detail}");
    if status.is_alarm() {
        println!(
            "ALARM: the service raised `Inconsistent`. Do not read any state above as \
             established protection."
        );
    }
}

/// How much a release actually established: `(journal_released,
/// removal_confirmed)`.
///
/// See the call site in [`winhost_killswitch_release`] for why these are two
/// values and not one, and why `engage` is allowed to be stricter than
/// `release` on the currently shipped mechanism.
fn release_outcome(status: &KillSwitchStatus) -> (bool, bool) {
    let journal_released = broker_verdict(status).0 == "not_engaged";
    (
        journal_released,
        journal_released && status.os_rule_present == Some(false),
    )
}

/// Warn when the scope on the command line is not the scope the service is
/// actually holding.
///
/// The service is configured with **one** scope at its composition root, and
/// `KillSwitchStatus` carries the scope label only inside the held receipt — so
/// this can be established while engaged and cannot be while not. Saying so is
/// the honest option; silently accepting `--scope` as if it selected something
/// is not.
fn scope_mismatch_note(status: &KillSwitchStatus, requested: &str) -> Option<String> {
    let receipt = status.receipt.as_ref()?;
    if receipt.scope_label == requested {
        return None;
    }
    Some(format!(
        "`--scope {requested}` does not name what the service is holding: its receipt is for \
         scope '{}'. The service owns exactly one scope, fixed when it starts, so `--scope` \
         selects nothing here — it is carried only so the local advisory lines below describe \
         the rule name you asked about.",
        receipt.scope_label
    ))
}

/// The one remaining call into a Windows firewall backend, and it is a read.
///
/// `netsh advfirewall firewall show rule` was measured on Windows 11 de-DE to
/// need no elevation, and `classify_show` decides on the exit code alone and
/// never on the localized text. It is used **only** to produce an advisory line
/// when the authoritative source is unavailable.
///
/// Its one honest capability is positive detection: `classify_show` cannot
/// return `Absent`, so a clean machine reports `indeterminate`, not "nothing is
/// severed". That asymmetry is exactly the useful direction — the case that
/// matters when the broker is gone is a rule that is still *there*.
fn winhost_local_advisory_observation(scope: &BoundaryScope) -> ssk_boundary::BoundaryObservation {
    WindowsFirewallEnforcer::new().observe(scope)
}

fn winhost_command(command: &WinHostCommand, json: bool) -> Result<(), AppError> {
    match command {
        WinHostCommand::Doctor => winhost_doctor(json),
        WinHostCommand::Capture => winhost_capture(json),
        WinHostCommand::Killswitch { command } => match command {
            KillswitchCommand::Engage { scope } => winhost_killswitch_engage(scope, json),
            KillswitchCommand::Release { scope, lease } => {
                winhost_killswitch_release(scope, lease.as_deref(), json)
            }
            KillswitchCommand::Status { scope } => winhost_killswitch_status(scope, json),
            KillswitchCommand::Recover { scope, yes } => {
                winhost_killswitch_recover(scope, *yes, json)
            }
        },
        WinHostCommand::Service { command } => match command {
            ServiceCommand::Install { exe } => winhost_service_install(exe.as_deref(), json),
            ServiceCommand::Start => winhost_service_lifecycle(WinHostServiceOp::Start, json),
            ServiceCommand::Stop => winhost_service_lifecycle(WinHostServiceOp::Stop, json),
            ServiceCommand::Uninstall => winhost_service_uninstall(json),
        },
    }
}

/// Report what this build carries **and what has actually been checked here**.
///
/// Pre-P1 this printed a hardcoded `"status": "ok"` next to a
/// `platform_supported` that is nothing but `cfg!(windows)`, so on a Windows box
/// where the kill-switch could not engage at all (the de-DE netsh break) it
/// still reported green. Two things changed:
///
/// * `platform_supported` is kept, and is still exactly "this build contains the
///   Windows backends" — but it no longer stands alone. `verdict` says what was
///   established, `checks` lists the probes that were actually *executed*, and
///   `cannot_verify_here` enumerates, by name, what this process is structurally
///   unable to establish.
/// * Only checks that ran are listed. A probe that cannot be performed on this
///   target is not reported as passing; it is reported as unverifiable.
///
/// Every check is read-only. `doctor` must never add or delete a firewall rule,
/// so it cannot — and does not claim to — prove that an engage would succeed.
fn winhost_doctor(json: bool) -> Result<(), AppError> {
    let supported = ssk_winhost::platform_supported();
    let os = std::env::consts::OS;
    let mechanism = WindowsFirewallEnforcer::new().mechanism();

    // Broker reachability and the authoritative kill-switch state, reported
    // exactly the way `elevated` is: as an OBSERVATION, not as a pass/fail
    // check. A stock machine with no service installed is not a broken
    // machine — it is a machine on which the kill-switch is unavailable, which
    // is what `doctor` is for saying. Turning it into a failing check would
    // make an unelevated diagnostic exit non-zero on every box that has not
    // been installed yet, which is the same defect P1 removed when it stopped
    // `platform_supported` from standing in for a verdict.
    //
    // It is cheap: a broker-absent connect returns `ERROR_FILE_NOT_FOUND`
    // immediately (only `ERROR_PIPE_BUSY` is retried), so `doctor` cannot hang
    // on the common case.
    let broker = broker_open(ClientHello::new(LeaseKind::Session)).and_then(|mut c| {
        c.status()
            .map_err(|e| broker_command_err("KILLSWITCH_STATUS_FAILED", &e))
    });
    let store_dir = winhost_store_dir();
    let store_exists = store_dir.is_dir();
    let stale_temp_receipts = winhost_legacy_receipt_count();

    // Read-only, and deliberately NOT a pass/fail `check`: an unelevated
    // diagnostic must exit 0. `doctor` reports what it observed; it does not
    // turn "you are not an administrator right now" into a failure.
    let elevated = ssk_winhost::privilege::is_elevated();
    let store_verdict = winhost_store_dir_verified();
    let store_protection = match &store_verdict {
        Ok(StateDirStatus::Absent) => {
            "absent (it is created and locked down by the first elevated engage/install)".to_owned()
        }
        Ok(StateDirStatus::Protected) => {
            "present; owner and DACL verified administrative-only".to_owned()
        }
        Err(e) => format!("REFUSED ({}): {}", e.machine_code, e.message),
    };

    // Checks are only pushed when they were genuinely executed on this target.
    let mut checks: Vec<DoctorCheck> = Vec::new();

    // The receipt store's provenance gate ran, so its result is a check — not
    // a string in a report nobody's exit code depends on.
    //
    // This was the remaining dishonesty after P1. A refusal means the store is
    // under another principal's control, which makes engage/release
    // unavailable: `winhost_read_receipt_bytes` gates every receipt read on
    // this same verification, so release *will* fail. Reporting that in a
    // `receipt_store.protection` string while `verdict` stayed
    // `backends_present_unverified` and the command exited 0 is the exact
    // shape of the defect P1 removed from `platform_supported`.
    checks.push(DoctorCheck {
        name: "receipt_store_provenance",
        ok: store_verdict.is_ok(),
        detail: store_protection.clone(),
        next_step: match &store_verdict {
            Ok(_) => "None.".into(),
            Err(e) => e.next_steps.first().cloned().unwrap_or_else(|| {
                "Inspect the receipt store from an elevated shell before using the kill-switch."
                    .to_owned()
            }),
        },
    });
    if supported {
        let mechanism_implemented = mechanism == EgressMechanism::NetshInterim;
        checks.push(DoctorCheck {
            name: "egress_mechanism_implemented",
            ok: mechanism_implemented,
            detail: format!("selected egress mechanism: {}", mechanism.as_str()),
            next_step: if mechanism_implemented {
                "None.".into()
            } else {
                "The selected mechanism has no implementation in this build; the kill-switch \
                 cannot engage."
                    .into()
            },
        });

        let netsh = winhost_netsh_path();
        checks.push(DoctorCheck {
            name: "netsh_resolvable",
            ok: netsh.is_some(),
            detail: match &netsh {
                Some(p) => format!("found {}", p.display()),
                None => "netsh.exe not found under %SystemRoot%\\System32 (a PATH search is \
                         deliberately not attempted)"
                    .to_owned(),
            },
            next_step: if netsh.is_some() {
                "None.".into()
            } else {
                "The kill-switch cannot run at all without netsh.exe at an absolute System32 \
                 path."
                    .into()
            },
        });
    }

    let failed: Vec<&'static str> = checks
        .iter()
        .filter(|c| !c.ok)
        .map(|c| c.name)
        .collect::<Vec<_>>();
    // A failed check outranks `unsupported`: an off-Windows build whose receipt
    // store is squatted is degraded, and saying only "unsupported" would hide
    // the finding behind a platform fact.
    let verdict = if !failed.is_empty() {
        "degraded"
    } else if supported {
        "backends_present_unverified"
    } else {
        "unsupported"
    };

    // Stated by name, so nobody can read the green above as more than it is.
    let mut cannot_verify_here: Vec<String> = vec![
        "engage/release: proving the kill-switch functions requires adding and removing a real \
         firewall rule, which a diagnostic must not do. No engage -> release cycle has been \
         observed on any machine in any locale (roadmap §5.1)."
            .to_owned(),
        "netsh authorization: `elevated` above is this process's TokenElevation, which is a \
         preflight, not an access check. An elevated shell can still be refused by the OS."
            .to_owned(),
    ];
    if elevated.is_none() {
        cannot_verify_here.push(
            "elevation: the TokenElevation probe could not answer on this target, so every \
             state-directory provisioning call will fail closed with NOT_ELEVATED regardless of \
             the real token."
                .to_owned(),
        );
    }
    if !supported {
        cannot_verify_here.push(format!(
            "every Windows backend: this build targets {os}, so the privileged seams are inert \
             stubs and nothing about a real Windows host can be established from here."
        ));
    }
    if let Err(err) = &broker {
        cannot_verify_here.push(format!(
            "kill-switch state: the privileged service did not answer ({}), so NOTHING above is \
             a statement about whether egress is severed. This process cannot determine that on \
             its own — its local probe can report a rule present but can never report one \
             absent.",
            err.machine_code
        ));
    }

    // The one line an operator actually needs out of the block above.
    let broker_summary = match &broker {
        Ok(status) => {
            let (verdict, detail) = broker_verdict(status);
            format!("reachable; authoritative verdict `{verdict}` — {detail}")
        }
        Err(err) => format!("NOT reachable ({}): {}", err.machine_code, err.message),
    };

    if json {
        let value = serde_json::json!({
            // Derived, never hardcoded. It used to be the literal "ok" printed
            // on stdout *even when the function was about to return an error*
            // — so a consumer reading stdout got `status: ok` in the same
            // document as `verdict: degraded` and a populated `failed_checks`.
            // One document must not contradict itself.
            "status": if failed.is_empty() { "ok" } else { "error" },
            "verdict": verdict,
            "platform_supported": supported,
            "platform_supported_means":
                "this BUILD carries the Windows backends; it is not a statement that the \
                 kill-switch can engage on this box",
            "os": os,
            "egress_mechanism": mechanism.as_str(),
            "elevated": elevated,
            "elevated_means":
                "this process's TokenElevation. `null` means the probe could not answer, which \
                 fails closed exactly like false",
            "checks": checks,
            "failed_checks": failed,
            "cannot_verify_here": cannot_verify_here,
            // Reported, deliberately not a `check`: see the comment where
            // `broker` is computed. An uninstalled service is a fact about the
            // machine, not a diagnostic failure.
            "privileged_broker": match &broker {
                Ok(status) => {
                    let mut v = broker_status_json(status);
                    if let Some(map) = v.as_object_mut() {
                        map.insert("reachable".to_owned(), serde_json::Value::Bool(true));
                        map.insert(
                            "endpoint".to_owned(),
                            serde_json::Value::String(privileged_endpoint_name().to_owned()),
                        );
                    }
                    v
                }
                Err(err) => serde_json::json!({
                    "reachable": false,
                    "authoritative": false,
                    "endpoint": privileged_endpoint_name(),
                    "machine_code": err.machine_code,
                    "detail": err.message,
                    "next_steps": err.next_steps
                }),
            },
            "privileged_broker_means":
                "the LocalSystem service that owns the kill-switch. `ssk` performs no privileged \
                 action itself: with the service unreachable, engage/release/recover all fail \
                 with a typed error and nothing is actuated",
            "receipt_store": {
                "path": store_dir.display().to_string(),
                "exists": store_exists,
                "protection": store_protection,
                "legacy_temp_dir": winhost_legacy_temp_dir().display().to_string(),
                "legacy_temp_files": stale_temp_receipts,
                "legacy_temp_files_are_imported": false
            },
            "backends": {
                "firewall_killswitch": "netsh advfirewall (Administrator)",
                "capture": "IP Helper GetExtendedTcpTable/GetExtendedUdpTable",
                "service": "Service Control Manager (windows-service)"
            },
            "requires": "Windows 11 + Administrator for live effects"
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        println!("verdict: {verdict}");
        println!("platform_supported: {supported} (this build carries the Windows backends)");
        println!("os: {os}");
        println!("egress_mechanism: {}", mechanism.as_str());
        for check in &checks {
            println!(
                "check {}: {} — {}",
                check.name,
                if check.ok { "ok" } else { "FAILED" },
                check.detail
            );
        }
        println!(
            "elevated: {}",
            match elevated {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown (fails closed like 'no')",
            }
        );
        println!("privileged_broker: {}", privileged_endpoint_name());
        println!("privileged_broker status: {broker_summary}");
        match &broker {
            Ok(status) => print_broker_status(status),
            Err(err) => {
                for step in &err.next_steps {
                    println!("  next: {step}");
                }
            }
        }
        println!(
            "receipt_store: {} (exists: {store_exists})",
            store_dir.display()
        );
        println!("receipt_store protection: {store_protection}");
        if stale_temp_receipts > 0 {
            println!(
                "warning: {stale_temp_receipts} stale file(s) in the pre-P1 receipt directory {}; \
                 they are never imported — delete them",
                winhost_legacy_temp_dir().display()
            );
        }
        println!("NOT verified here:");
        for item in &cannot_verify_here {
            println!("  - {item}");
        }
        if !supported {
            println!(
                "note: this build has no Windows backends; run on Windows 11 to exercise them"
            );
        }
    }

    if failed.is_empty() {
        Ok(())
    } else {
        Err(winhost_err(
            "WINHOST_DOCTOR_FAILED",
            format!(
                "the Windows backends are compiled in but {} prerequisite check(s) failed: {}",
                failed.len(),
                failed.join(", ")
            ),
            checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| format!("{}: {}", c.name, c.next_step))
                .collect(),
        ))
    }
}

fn winhost_capture(json: bool) -> Result<(), AppError> {
    let source = WindowsConnectionSource::new();
    let scope = CaptureScope::new("winhost", ["local"]);
    let field = SystemTrafficField::capture(&source, &scope, CaptureMode::PassiveLocal);

    if json {
        let flows: Vec<_> = field
            .surfaces
            .iter()
            .map(|s| {
                serde_json::json!({
                    "protocol": s.protocol,
                    "url": s.url,
                    "status": s.status
                })
            })
            .collect();
        let value = serde_json::json!({
            "status": "ok",
            "supported": ssk_winhost::platform_supported(),
            "flow_count": field.surfaces.len(),
            "flows": flows
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        println!("flows captured: {}", field.surfaces.len());
        for s in &field.surfaces {
            println!(
                "  {} {} status={:?}",
                s.protocol,
                s.url.as_deref().unwrap_or("-"),
                s.status
            );
        }
        if !ssk_winhost::platform_supported() {
            println!("note: no Windows backend on this build; 0 flows is expected off-Windows");
        }
    }
    Ok(())
}

fn winhost_scope_rule_name(scope: &BoundaryScope) -> Result<String, AppError> {
    rule_name_for_scope(scope)
        .map(|name| name.to_string())
        .map_err(|e| {
            winhost_err(
                "KILLSWITCH_SCOPE_INVALID",
                e.to_string(),
                vec!["Choose a scope label this build can content-address.".into()],
            )
        })
}

/// Ask the privileged service to sever egress.
///
/// # What used to be here
///
/// Roughly 180 lines that constructed `WindowsFirewallEnforcer::new`, probed
/// the rule, gated on a local receipt file, provisioned the state directory,
/// spawned `netsh advfirewall firewall add rule`, persisted a rollback receipt,
/// and ran a compensating release when that write failed. Every one of those
/// concerns now belongs to the service, and all of them are things an
/// unprivileged process had no business doing:
///
/// * the "already engaged" gate is the service's, and it is exact — it holds
///   the journal and the claim set, where this process could only ever compare
///   a file against a probe that cannot report absence;
/// * the state directory is provisioned and locked down by LocalSystem;
/// * the rollback receipt is written by the same process that made the change,
///   under its op-lock, so the window in which a rule exists with no receipt —
///   the `KILLSWITCH_STRANDED` path — is gone rather than compensated;
/// * the change is authorized against this caller's SID, refused if the nonce
///   replays, serialized against every other caller, and appended to a
///   hash-chained journal.
///
/// # The claim is pinned
///
/// An operator typing `engage` means "stay severed", including across a reboot.
/// That is [`ssk_netd_helper::LeaseKind::Pinned`]. The cost is that the claim
/// outlives this process and has to be named to be dropped, which is what the
/// hint file exists for.
fn winhost_killswitch_engage(scope_label: &str, json: bool) -> Result<(), AppError> {
    let scope = BoundaryScope::new(scope_label, ["*"]);
    let rule_name = winhost_scope_rule_name(&scope)?;

    let mut client = broker_open(ClientHello::new(LeaseKind::Pinned))?;
    let lease = client.lease();
    let status = client
        .engage()
        .map_err(|e| broker_command_err("KILLSWITCH_ENGAGE_FAILED", &e))?;

    // Remembering the claim id is best effort and is deliberately not allowed
    // to fail the command: the engagement is already durable in the service's
    // own store, and undoing a successful severance because a convenience file
    // could not be written would be the wrong direction for a kill-switch.
    let hint = write_lease_hint(&scope, lease);
    let mismatch = scope_mismatch_note(&status, scope_label);
    let (verdict, _) = broker_verdict(&status);

    if json {
        let value = serde_json::json!({
            "status": "ok",
            "action": "killswitch-engage",
            "scope": scope_label,
            "rule_name": rule_name,
            "claim": lease.to_hex(),
            "claim_kind": LeaseKind::Pinned.as_str(),
            "claim_hint_path": hint.as_ref().ok().map(|p| p.display().to_string()),
            "claim_hint_error": hint.as_ref().err(),
            "scope_mismatch": mismatch,
            "broker": broker_status_json(&status)
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        if let Some(note) = &mismatch {
            println!("note: {note}");
        }
        print_broker_status(&status);
        println!(
            "claim: {} (pinned — it survives this process)",
            lease.to_hex()
        );
        match &hint {
            Ok(path) => println!(
                "release with: ssk winhost killswitch release --scope {scope_label}   (claim id \
                 remembered in {})",
                path.display()
            ),
            Err(why) => {
                println!(
                    "warning: the claim id could not be remembered ({why}); WRITE IT DOWN — \
                     without it `release` cannot name this claim."
                );
                println!(
                    "release with: ssk winhost killswitch release --scope {scope_label} --lease {}",
                    lease.to_hex()
                );
            }
        }
    }

    // A verdict of `engaged` is the only one that means protection. Anything
    // else — including the service accepting the command and then failing to
    // observe its own rule — is reported as a failure, because a claim of
    // protection must never be stronger than its evidence. This is the same
    // rule the pre-P3 `Verification::Unconfirmed` branch enforced, moved to the
    // authoritative source.
    if verdict == "engaged" {
        Ok(())
    } else {
        Err(engage_unverified_err(scope_label, lease, verdict))
    }
}

/// The error for "the service accepted the engage, and its own verdict is not
/// `engaged`".
///
/// Extracted so the property that matters is pinned by a test rather than by
/// reading: an unverified engage must say **the claim was taken and the
/// engagement is releasable**. The pre-P3 equivalent
/// (`BoundaryError::EnforcementUnverified` reaching `killswitch_next_steps`)
/// carried the same obligation about the persisted receipt; the layer moved,
/// the obligation did not. Getting this wrong strands an operator who reads a
/// failure and concludes nothing happened.
fn engage_unverified_err(scope_label: &str, lease: LeaseId, verdict: &str) -> AppError {
    winhost_err(
        "KILLSWITCH_ENGAGE_UNVERIFIED",
        format!(
            "the privileged service accepted the engage for scope '{scope_label}' but its \
             authoritative verdict is `{verdict}`, so this is not reported as protection"
        ),
        vec![
            format!(
                "The claim WAS taken ({}) and the change is in the service's journal — the \
                 engagement is releasable.",
                lease.to_hex()
            ),
            format!(
                "`ssk winhost killswitch status --scope {scope_label}` re-reads the \
                 authoritative status."
            ),
            format!("Undo it with `ssk winhost killswitch release --scope {scope_label}`."),
        ],
    )
}

/// Ask the privileged service to drop a claim.
///
/// Which claim, and why it has to be named:
///
/// * `--lease <id>` names it explicitly;
/// * otherwise the id this CLI remembered from its own `engage` is used;
/// * with neither, the connection's own (fresh) claim is dropped, which is
///   correct and idempotent but will not restore egress if a durable claim from
///   another session is still held. That case is detected from the returned
///   status and reported as a failure with the exact next step, never as a
///   success.
///
/// The pre-P3 implementation loaded a local receipt, ran it through the three
/// SEC-1 gates and handed it to `release_scoped`. There is no receipt to load
/// any more: the service holds it, and it re-derives the rule name from its own
/// scope, so nothing this process could write influences what gets deleted.
fn winhost_killswitch_release(
    scope_label: &str,
    lease_arg: Option<&str>,
    json: bool,
) -> Result<(), AppError> {
    let scope = BoundaryScope::new(scope_label, ["*"]);

    let (adopt, claim_source) = match lease_arg {
        Some(text) => {
            let id = parse_lease_id(text.trim()).map_err(|why| {
                AppError::new(
                    ErrorClass::Usage,
                    "KILLSWITCH_CLAIM_ID_INVALID",
                    format!("`--lease {text}` is not a claim id: {why}"),
                    vec![
                        "A claim id is the 32-character value `engage` printed. Nothing else is \
                         accepted, so a mistyped id fails here rather than being sent."
                            .into(),
                    ],
                )
            })?;
            (Some(id), "command line")
        }
        None => match read_lease_hint(&scope) {
            Some(id) => (Some(id), "remembered from this CLI's own engage"),
            None => (None, "none — this connection's own claim"),
        },
    };

    let hello = match adopt {
        Some(id) => ClientHello::adopting(id),
        None => ClientHello::new(LeaseKind::Session),
    };
    let mut client = broker_open(hello)?;
    let lease = client.lease();
    let status = client
        .release()
        .map_err(|e| broker_command_err("KILLSWITCH_RELEASE_FAILED", &e))?;

    let (_, verdict_detail) = broker_verdict(&status);
    // Two different claims, kept apart on purpose.
    //
    // `journal_released` is what the service's own journal says: nothing is
    // severed by it any more. `removal_confirmed` additionally requires that
    // the service *observed* the rule gone.
    //
    // The asymmetry with `engage` is not an oversight. Positive detection works
    // on the shipped netsh mechanism, so `engage` demands `Some(true)` and
    // refuses anything weaker. Negative detection does not: `classify_show`
    // cannot return `Absent`, so `Some(false)` is currently unreachable and
    // demanding it here would make every release on every machine report
    // failure. So this reports success on the journal and says, in the same
    // breath, that removal was not confirmed. It becomes a real confirmation
    // the moment a negative-capable probe (WFP, or the `Get-NetFirewallRule`
    // cold path) is wired into the service's observer — with no change here.
    let (journal_released, removal_confirmed) = release_outcome(&status);
    if journal_released {
        // Only once the service says nothing is severed any more. A stale hint
        // is harmless — the service refuses an id it is not holding — but a
        // hint deleted while the claim is still live would cost the operator
        // the only copy of the id.
        clear_lease_hint(&scope);
    }
    let mismatch = scope_mismatch_note(&status, scope_label);

    if json {
        let value = serde_json::json!({
            "status": "ok",
            "action": "killswitch-release",
            "scope": scope_label,
            "claim": lease.to_hex(),
            "claim_source": claim_source,
            "journal_released": journal_released,
            "removal_confirmed": removal_confirmed,
            "removal_confirmed_means":
                "the service positively OBSERVED its rule gone. False with `journal_released` \
                 true means its journal no longer severs egress but its probe could not confirm \
                 the rule's removal — which is the normal result on the netsh mechanism, because \
                 that probe cannot report absence at all",
            "scope_mismatch": mismatch,
            "broker": broker_status_json(&status)
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        if let Some(note) = &mismatch {
            println!("note: {note}");
        }
        println!("claim dropped: {} ({claim_source})", lease.to_hex());
        print_broker_status(&status);
        if journal_released && !removal_confirmed {
            println!(
                "note: the service no longer severs egress for this scope, but it did not \
                 positively observe the rule gone. Do not read this as a confirmed removal."
            );
        }
    }

    if journal_released {
        return Ok(());
    }

    // The service accepted the release and the machine is still severed. That
    // is the "a durable claim taken elsewhere is still held" case, and it must
    // not read as success: the operator asked for egress back and did not get
    // it.
    Err(winhost_err(
        "KILLSWITCH_STILL_ENGAGED",
        format!(
            "the claim {} was dropped, but egress is still severed for scope '{scope_label}': \
             {verdict_detail}",
            lease.to_hex()
        ),
        vec![
            "A durable claim taken by another session is still held. Dropping one claim only \
             restores egress when it was the last."
                .to_owned(),
            format!(
                "Re-run naming that claim: `ssk winhost killswitch release --scope {scope_label} \
                 --lease <id>` — the id is what `engage` printed."
            ),
            format!(
                "If no id is known, `ssk winhost killswitch recover --scope {scope_label}` \
                 explains the service-side recovery path; it deletes nothing itself."
            ),
        ],
    ))
}

/// Describe an observation without ever branching on its evidence text.
fn winhost_presence_token(presence: &Presence) -> (&'static str, String) {
    match presence {
        Presence::Present => ("present", String::new()),
        Presence::Absent => ("absent", String::new()),
        Presence::Indeterminate { detail } => ("indeterminate", detail.clone()),
        // `Presence` is `#[non_exhaustive]`; an unknown variant is not evidence
        // of absence, so it fails closed onto the indeterminate branch.
        other => (
            "indeterminate",
            format!("unrecognized presence variant: {other:?}"),
        ),
    }
}

/// The **advisory, pre-broker** verdict: the cross-product of (a
/// `killswitch-<digest>.json` left by the pre-broker release) x (what a
/// read-only local probe observes).
///
/// Pure, so the whole table is testable without touching a firewall: this is
/// what makes an inconsistent machine *describable* instead of being silently
/// reported as one of the two clean states.
///
/// # It is no longer the answer to "is egress severed?"
///
/// That answer is [`broker_verdict`], computed from the status the privileged
/// service serves. This one is reached on exactly one path —
/// [`winhost_killswitch_status`] when the service did not answer — where it is
/// the most this process can honestly say on its own, and is labelled
/// non-authoritative everywhere it is rendered. Its next steps therefore never
/// offer a privileged action; this binary has none left to offer.
fn killswitch_verdict(
    loaded: &LoadedReceipt,
    presence: &Presence,
    scope_label: &str,
) -> (&'static str, String, Vec<String>) {
    match (loaded, presence) {
        (LoadedReceipt::Valid { prior, .. }, Presence::Present) => {
            if prior.ownership == Ownership::Preexisting {
                (
                    "engaged_not_ours",
                    "the rule is present and the pre-broker receipt records that it pre-existed \
                     that engagement, so a faithful rollback would have left it in place"
                        .to_owned(),
                    vec![format!(
                        "`ssk winhost killswitch recover --scope {scope_label}` prints the \
                         derived rule name and what can remove it. It deletes nothing itself."
                    )],
                )
            } else {
                (
                    "engaged",
                    "the rule is present and a valid pre-broker rollback receipt is held for it"
                        .to_owned(),
                    vec![format!(
                        "The privileged service is the only thing that can remove it. Start it, \
                         then `ssk winhost killswitch status --scope {scope_label}`."
                    )],
                )
            }
        }
        (LoadedReceipt::Valid { .. }, Presence::Absent) => (
            "inconsistent",
            "a valid pre-broker rollback receipt is held but the rule was positively observed \
             ABSENT — it was removed by something other than this tool"
                .to_owned(),
            vec![format!(
                "Nothing is severed by that receipt for scope '{scope_label}'; it is a stale \
                 pre-broker artifact and can be deleted."
            )],
        ),
        (LoadedReceipt::Valid { .. }, _) => (
            "engaged_unconfirmed",
            "a valid rollback receipt is held but the rule's presence could not be observed; \
             this is NOT evidence that egress is flowing"
                .to_owned(),
            vec![
                "The probe could not answer — see observation_detail. Nothing here should be \
                 read as restored egress."
                    .into(),
            ],
        ),
        (LoadedReceipt::Missing, Presence::Present) => (
            "engaged_receipt_lost",
            "the rule is present but there is no rollback receipt for it".to_owned(),
            winhost_no_receipt_next_steps(scope_label),
        ),
        (LoadedReceipt::Missing, Presence::Absent) => (
            "armed",
            "no rule and no pre-broker receipt: nothing is severed by this scope".to_owned(),
            vec![format!(
                "Sever egress with `ssk winhost killswitch engage --scope {scope_label}`, which \
                 asks the privileged service to do it."
            )],
        ),
        (LoadedReceipt::Missing, _) => (
            "unknown",
            "no receipt, and the rule's presence could not be observed".to_owned(),
            vec![
                "The probe could not answer — see observation_detail. This is not the same as \
                 'nothing is severed'."
                    .into(),
            ],
        ),
        (LoadedReceipt::Invalid { detail, .. }, Presence::Present) => (
            "receipt_rejected_and_engaged",
            format!(
                "the rule is present AND the stored receipt was refused, so it cannot be used to \
                 roll back: {detail}"
            ),
            winhost_no_receipt_next_steps(scope_label),
        ),
        (LoadedReceipt::Invalid { detail, .. }, _) => (
            "receipt_rejected",
            format!("the stored receipt was refused: {detail}"),
            winhost_no_receipt_next_steps(scope_label),
        ),
    }
}

/// What a pre-broker `killswitch-<digest>.json` in the state directory means
/// now, if one is there.
///
/// **This is a migration finding, not a decision input.** Kill-switch receipts
/// moved behind the service entirely: it writes its own journal and receipt as
/// LocalSystem and serves the held receipt inside `KillSwitchStatus`. Nothing
/// in this binary acts on the file below. It is reported because a machine
/// upgraded from the pre-broker release can be severed by a rule the service's
/// journal knows nothing about, and an operator staring at `not_engaged` while
/// their network is down deserves to be told that.
///
/// It is still read through the full P1 gate — store provenance, then
/// `verify_against`, then `PriorState::parse`, then the re-derived rule name —
/// so a planted file cannot influence even the sentence that describes it.
fn winhost_legacy_receipt_note(scope: &BoundaryScope, path: &Path) -> Option<String> {
    match winhost_load_killswitch_receipt(scope, path) {
        LoadedReceipt::Missing => None,
        LoadedReceipt::Valid { receipt, prior } => Some(format!(
            "a pre-broker rollback receipt is still on disk at {} (id {}, rule {}). The service \
             does not know about it. If egress is severed and the service says otherwise, that \
             rule is the likely cause.",
            path.display(),
            receipt.receipt_id.to_hex(),
            prior.rule_name
        )),
        LoadedReceipt::Invalid { code, detail } => Some(format!(
            "a pre-broker rollback receipt at {} was REFUSED by the integrity gate ({code}): \
             {detail}. It is left in place as evidence and is not acted on.",
            path.display()
        )),
    }
}

/// Report the authoritative kill-switch state.
///
/// # Exit code
///
/// 0 whenever the service answered — including for the `inconsistent` alarm,
/// because a diagnostic that refuses to run on a broken machine is useless
/// exactly when it is needed, and scripts key on `verdict`.
///
/// Non-zero when there was **no** authoritative answer, because then there is
/// no verdict to report and saying so quietly would be the "silent success"
/// this phase exists to prevent. Everything the machine can still say is
/// printed first, on stdout, in the same single document — the advisory
/// observation, the derived rule name, and any pre-broker receipt — so the
/// error is an addition to the information, not a replacement for it.
fn winhost_killswitch_status(scope_label: &str, json: bool) -> Result<(), AppError> {
    let scope = BoundaryScope::new(scope_label, ["*"]);
    let path = winhost_killswitch_receipt_path(&scope)?;
    let rule_name = winhost_scope_rule_name(&scope)?;

    let broker = broker_open(ClientHello::new(LeaseKind::Session)).and_then(|mut c| {
        c.status()
            .map_err(|e| broker_command_err("KILLSWITCH_STATUS_FAILED", &e))
    });

    match broker {
        Ok(status) => {
            let mismatch = scope_mismatch_note(&status, scope_label);
            let legacy = winhost_legacy_receipt_note(&scope, &path);
            if json {
                let value = serde_json::json!({
                    "status": "ok",
                    "action": "killswitch-status",
                    "scope": scope_label,
                    "rule_name": rule_name,
                    "scope_mismatch": mismatch,
                    "legacy_receipt_note": legacy,
                    "broker": broker_status_json(&status)
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
                );
            } else {
                println!("scope: {scope_label}");
                println!("rule: {rule_name}");
                if let Some(note) = &mismatch {
                    println!("note: {note}");
                }
                print_broker_status(&status);
                if let Some(note) = &legacy {
                    println!("migration: {note}");
                }
            }
            Ok(())
        }
        Err(err) => {
            // No authoritative answer. Print everything this process can still
            // establish on its own — all of it read-only, none of it a claim
            // about protection — and then fail with the reason.
            let observation = winhost_local_advisory_observation(&scope);
            let (observed, observed_detail) = winhost_presence_token(&observation.presence);
            let loaded = winhost_load_killswitch_receipt(&scope, &path);
            let legacy = winhost_legacy_receipt_note(&scope, &path);
            // The pre-broker cross product is exactly what "the most this
            // process can say on its own" is, so it is reported here — and
            // nowhere else, and never without the `authoritative: false` label
            // that sits beside it.
            let (advisory_verdict, advisory_detail, advisory_steps) =
                killswitch_verdict(&loaded, &observation.presence, scope_label);
            if json {
                let value = serde_json::json!({
                    // Matches the error emitted on stderr. One run must not
                    // report `ok` on stdout and `error` on stderr.
                    "status": "error",
                    "action": "killswitch-status",
                    "scope": scope_label,
                    "rule_name": rule_name,
                    "broker": {
                        "authoritative": false,
                        "reachable": false,
                        "machine_code": err.machine_code,
                        "detail": err.message
                    },
                    "local_advisory": {
                        "authoritative": false,
                        "means":
                            "a read-only `netsh advfirewall firewall show rule` by this \
                             unprivileged process. It can report `present`; it can NOT report \
                             `absent`, so `indeterminate` never means `nothing is severed`",
                        "observed": observed,
                        "observation_detail": observed_detail,
                        "observation_evidence": observation.evidence,
                        "mechanism": observation.mechanism,
                        "verdict": advisory_verdict,
                        "verdict_detail": advisory_detail,
                        "next_steps": advisory_steps
                    },
                    "legacy_receipt_note": legacy,
                    "verdict": "broker_unreachable"
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
                );
            } else {
                println!("scope: {scope_label}");
                println!("rule: {rule_name}");
                println!("source: NONE — the privileged service did not answer");
                println!("verdict: broker_unreachable — there is no authoritative state to report");
                println!(
                    "local advisory (read-only, NOT authoritative): observed {observed}{}",
                    if observed_detail.is_empty() {
                        String::new()
                    } else {
                        format!(" — {observed_detail}")
                    }
                );
                if observed == "present" {
                    println!(
                        "WARNING: a rule named {rule_name} is present on this machine while no \
                         service is answering for it. Egress for this scope is severed and \
                         nothing here can release it."
                    );
                } else {
                    println!(
                        "note: this probe cannot report absence, so `{observed}` is not evidence \
                         that egress is flowing."
                    );
                }
                println!(
                    "local advisory verdict (NOT authoritative): {advisory_verdict} — \
                     {advisory_detail}"
                );
                for step in &advisory_steps {
                    println!("next: {step}");
                }
                if let Some(note) = &legacy {
                    println!("migration: {note}");
                }
            }
            Err(err)
        }
    }
}

/// Explain how to recover, and change nothing.
///
/// # This verb no longer deletes a firewall rule
///
/// It used to: it derived the rule name from the scope and ran `netsh
/// advfirewall firewall delete rule` with no receipt involved. That was the
/// right shape for a receipt-less recovery and the wrong process to do it in.
/// Receipt-less recovery is now the service's startup reconciliation, which
/// runs as LocalSystem, under the op-lock, before the control pipe accepts its
/// first client, and appends to the hash-chained journal. Reintroducing a CLI
/// path that deletes the rule would be a second, unauthorized, unaudited
/// actuator for the one thing this phase moved behind an authorization gate —
/// and it would be reachable exactly when the gate is unreachable, which is the
/// worst possible time.
///
/// So this reports the authoritative state if there is one, prints the rule
/// name (a pure function of the scope — no firewall is touched to compute it),
/// and names the two real recovery paths. `--yes` is accepted and ignored.
///
/// # Errors
///
/// Always. A command that changed nothing must not exit 0: that is precisely
/// the silent success this contract forbids.
fn winhost_killswitch_recover(scope_label: &str, yes: bool, json: bool) -> Result<(), AppError> {
    let _ = yes;
    let scope = BoundaryScope::new(scope_label, ["*"]);
    let path = winhost_killswitch_receipt_path(&scope)?;
    let rule_name = winhost_scope_rule_name(&scope)?;

    let broker = broker_open(ClientHello::new(LeaseKind::Session)).and_then(|mut c| {
        c.status()
            .map_err(|e| broker_command_err("KILLSWITCH_STATUS_FAILED", &e))
    });
    let observation = winhost_local_advisory_observation(&scope);
    let (observed, observed_detail) = winhost_presence_token(&observation.presence);
    let legacy = winhost_legacy_receipt_note(&scope, &path);

    let mut next_steps: Vec<String> = vec![
        "Nothing was changed by this command. Recovery is the service's own startup \
         reconciliation; a CLI that deleted the rule itself would be an unauthorized, unaudited \
         second actuator for the thing this release put behind an authorization gate."
            .to_owned(),
    ];
    match &broker {
        Ok(status) => {
            next_steps.push(
                "The service is reachable, so start with a normal release: `ssk winhost \
                 killswitch release --lease <id>`, naming the claim `engage` printed."
                    .to_owned(),
            );
            next_steps.push(
                "If no claim id is known, restart the service (`ssk winhost service stop` then \
                 `start`, elevated). Its startup reconciliation discards every claim that cannot \
                 survive a restart and then makes the OS match the journal."
                    .to_owned(),
            );
            if status.is_alarm() {
                next_steps.push(
                    "The service is currently raising the `inconsistent` alarm — its journal and \
                     what it observes disagree. A restart is what reconciles that."
                        .to_owned(),
                );
            }
        }
        Err(err) => {
            next_steps.push(format!(
                "The service did not answer ({}), so there is no service-side recovery to \
                 trigger. Install or start it first — see `ssk winhost doctor`.",
                err.machine_code
            ));
        }
    }
    if observed == "present" {
        next_steps.push(format!(
            "A rule named {rule_name} IS present on this machine right now. If no service can be \
             made to answer, an administrator can remove exactly that rule by hand: `netsh \
             advfirewall firewall delete rule name={rule_name}` from an elevated shell. The name \
             is derived from the scope and is never read from a file, so only that one rule can \
             be named."
        ));
    } else {
        next_steps.push(format!(
            "This process could not observe a rule named {rule_name} — but its probe cannot \
             report absence, so that is not evidence there is none."
        ));
    }
    if let Some(note) = &legacy {
        next_steps.push(note.clone());
    }

    if json {
        let value = serde_json::json!({
            "status": "error",
            "action": "killswitch-recover",
            "scope": scope_label,
            "rule_name": rule_name,
            "deleted_anything": false,
            "broker": match &broker {
                Ok(status) => broker_status_json(status),
                Err(err) => serde_json::json!({
                    "authoritative": false,
                    "reachable": false,
                    "machine_code": err.machine_code,
                    "detail": err.message
                }),
            },
            "local_advisory": {
                "authoritative": false,
                "observed": observed,
                "observation_detail": observed_detail,
                "observation_evidence": observation.evidence
            },
            "legacy_receipt_note": legacy,
            "next_steps": next_steps
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        println!("scope: {scope_label}");
        println!("rule: {rule_name}");
        match &broker {
            Ok(status) => print_broker_status(status),
            Err(err) => println!(
                "source: NONE — the privileged service did not answer ({})",
                err.machine_code
            ),
        }
        println!("local advisory (read-only, NOT authoritative): observed {observed}");
        if !observed_detail.is_empty() {
            println!("observation: {observed_detail}");
        }
    }

    Err(winhost_err(
        "KILLSWITCH_RECOVER_UNAVAILABLE",
        format!(
            "`recover` no longer deletes a firewall rule: receipt-less recovery belongs to the \
             privileged service, which performs it under its own authorization and audit at \
             startup. Nothing was changed for scope '{scope_label}'"
        ),
        next_steps,
    ))
}

/// Recompute an install receipt's own digest and bind it to *this* build's
/// deterministic host id.
///
/// The pre-P1 uninstall path read this receipt out of user-writable `%TEMP%`
/// and derived the SCM service name from `receipt.host_id` verbatim, so a
/// planted receipt chose which `SSKHost_*` service got deleted. Re-deriving the
/// host id from the manifest removes that input entirely; the digest
/// recomputation additionally catches corruption and naive tampering.
///
/// What this does **not** do, stated so no caller assumes otherwise: the digest
/// is unkeyed, so this is not authentication. `prior_state` is the one field
/// still carrying information into the privileged decision, and an attacker who
/// can write the receipt file can set it and recompute `receipt_id` freely.
/// [`winhost_receipt_store_gate`] is what makes that write access the hard part,
/// and it must run before these bytes are read — it is not optional hardening on
/// top of this check, it is the check this one cannot perform.
fn winhost_verify_install_receipt(
    receipt: &InstallReceipt,
    manifest: &HostManifest,
) -> Result<ServiceState, String> {
    let prior = if receipt.prior_state == ServiceState::Installed.as_str() {
        ServiceState::Installed
    } else if receipt.prior_state == ServiceState::Uninstalled.as_str() {
        ServiceState::Uninstalled
    } else {
        return Err(format!(
            "receipt prior_state {:?} is not a state an install can roll back to",
            receipt.prior_state
        ));
    };
    if receipt.host_id != manifest.host_id {
        return Err(format!(
            "receipt is for host {}, but this build's host id is {}",
            receipt.host_id.to_hex(),
            manifest.host_id.to_hex()
        ));
    }
    let expected = InstallReceipt::new(receipt.host_id, prior);
    if expected.receipt_id != receipt.receipt_id {
        return Err(format!(
            "receipt_id does not match its own contents (expected {}, found {})",
            expected.receipt_id.to_hex(),
            receipt.receipt_id.to_hex()
        ));
    }
    Ok(prior)
}

fn winhost_service_install(exe: Option<&str>, json: bool) -> Result<(), AppError> {
    let manifest = winhost_manifest();
    let exe_path = match exe {
        Some(p) => PathBuf::from(p),
        None => winhost_default_svc_path()?,
    };

    // Prepare the durable receipt path BEFORE the privileged effect, so a
    // state-dir failure cannot leave a created service with no receipt.
    let path = winhost_service_receipt_path_in(&winhost_store_dir_created()?);

    // Refuse to overwrite an existing install receipt. Re-running install would
    // otherwise find the service already present, record prior_state=Installed,
    // and downgrade the authoritative "we created it" receipt — after which
    // uninstall would skip deleting a service this tool actually created,
    // orphaning it. The first receipt is authoritative about the pre-SSK state.
    if path.exists() {
        return Err(winhost_err(
            "SERVICE_ALREADY_TRACKED",
            format!(
                "an install receipt already exists at {}; run `ssk winhost service uninstall` first",
                path.display()
            ),
            vec![
                "Uninstall first, or remove the stale receipt if you are certain no SSK service \
                 is registered."
                    .into(),
            ],
        ));
    }

    let helper = WindowsServiceHelper::new(&exe_path);
    let receipt = helper.install(&manifest).map_err(|e| {
        winhost_err(
            "SERVICE_INSTALL_FAILED",
            e.to_string(),
            service_next_steps(&e),
        )
    })?;

    // Persist the receipt. If this fails after a fresh create, compensate by
    // uninstalling the just-created service rather than leaking an orphaned,
    // untracked privileged service (the receipt records prior_state ==
    // Uninstalled, so uninstall will actually delete it).
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(winhost_json_err)?;
    if let Err(e) = std::fs::write(&path, bytes) {
        if receipt.prior_state == ServiceState::Uninstalled.as_str() {
            let _ = helper.uninstall(&receipt);
        }
        return Err(AppError::new(
            ErrorClass::Runtime,
            "WINHOST_STATE_WRITE",
            format!("failed to persist install receipt (created service rolled back): {e}"),
            vec![],
        ));
    }

    if json {
        let value = serde_json::json!({
            "status": "ok",
            "action": "service-install",
            "host_id": manifest.host_id.to_hex(),
            "exe": exe_path.display().to_string(),
            "receipt_id": receipt.receipt_id.to_hex(),
            "receipt_path": path.display().to_string()
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        println!("service installed for host {}", manifest.host_id.to_hex());
        println!("exe: {}", exe_path.display());
        println!(
            "receipt: {} -> {}",
            receipt.receipt_id.to_hex(),
            path.display()
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum WinHostServiceOp {
    Start,
    Stop,
}

fn winhost_service_lifecycle(op: WinHostServiceOp, json: bool) -> Result<(), AppError> {
    let manifest = winhost_manifest();
    let helper = WindowsServiceHelper::new(winhost_default_svc_path()?);
    let (verb, code) = match op {
        WinHostServiceOp::Start => ("start", "SERVICE_START_FAILED"),
        WinHostServiceOp::Stop => ("stop", "SERVICE_STOP_FAILED"),
    };
    match op {
        WinHostServiceOp::Start => helper.start(&manifest.host_id, &manifest.provided),
        WinHostServiceOp::Stop => helper.stop(&manifest.host_id),
    }
    .map_err(|e| winhost_err(code, e.to_string(), service_next_steps(&e)))?;

    if json {
        let value = serde_json::json!({
            "status": "ok",
            "action": format!("service-{verb}"),
            "host_id": manifest.host_id.to_hex()
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else {
        println!("service {verb} for host {}", manifest.host_id.to_hex());
    }
    Ok(())
}

/// Roll back an install, driven by the persisted install receipt.
///
/// The receipt is untrusted input on the way in, and it decides two privileged
/// things: *which* `SSKHost_*` service is deleted, and *whether* anything is
/// deleted at all. It therefore shares gate 0 with the kill-switch receipt —
/// literally the same function, not an equivalent one — and then gets the byte
/// checks its own smaller grammar supports. Two stages here, against the
/// kill-switch receipt's four; the difference is in stage 1, not stage 0:
///
/// 0. [`winhost_receipt_store_gate`] — the container. Without it the byte-level
///    checks below are decorative: [`InstallReceipt`]'s digest is unkeyed, so
///    anyone who can write into the store can flip `prior_state` and rehash. A
///    flip to `installed` makes uninstall silently leave our service registered
///    (`WindowsServiceHelper::uninstall` returns `Ok` without touching the SCM);
///    a flip to `uninstalled` makes it delete a service this tool never created.
///    Both are reachable with nothing but write access to the directory.
/// 1. [`winhost_verify_install_receipt`] — the bytes: `prior_state` must be one
///    of the two states an install can roll back to, `host_id` must equal the
///    host id re-derived from *this* build's manifest, and `receipt_id` must
///    equal the digest recomputed over those two fields. That is the entirety of
///    this receipt's grammar (see [`ssk_service_host::InstallReceipt`]); unlike
///    the kill-switch envelope there is no rule name to re-derive, because the
///    service name is derived from the manifest's host id and never from the
///    receipt.
fn winhost_service_uninstall(json: bool) -> Result<(), AppError> {
    let manifest = winhost_manifest();
    let path = winhost_service_receipt_path();

    // Gate 0 runs inside the reader; see `winhost_read_receipt_bytes`. `Absent`
    // passes: it means there is no receipt, reported below as SERVICE_NO_RECEIPT.
    let no_receipt = |detail: String| {
        winhost_err(
            "SERVICE_NO_RECEIPT",
            detail,
            vec![
                "`uninstall` only removes a service a matching `install` created; without that \
                 receipt there is nothing this tool is entitled to delete."
                    .into(),
                format!(
                    "The pre-P1 receipt location was {}; it is deliberately not read.",
                    winhost_legacy_temp_dir().display()
                ),
            ],
        )
    };

    let bytes = match winhost_read_receipt_bytes(&path) {
        ReceiptBytes::StoreUnsafe(e) => {
            return Err(AppError::new(
                ErrorClass::WinHost,
                "SERVICE_STORE_UNSAFE",
                format!(
                    "refusing to read {}: the state directory cannot be trusted — {}",
                    path.display(),
                    e.message
                ),
                e.next_steps,
            ))
        }
        ReceiptBytes::Missing => {
            return Err(no_receipt(format!(
                "no install receipt at {}",
                path.display()
            )))
        }
        ReceiptBytes::Unreadable(e) => {
            return Err(no_receipt(format!(
                "no install receipt at {}: {e}",
                path.display()
            )))
        }
        ReceiptBytes::Read(bytes) => bytes,
    };

    let receipt: InstallReceipt = serde_json::from_slice(&bytes).map_err(|e| {
        winhost_err(
            "SERVICE_RECEIPT_INVALID",
            format!("{} is not a decodable install receipt: {e}", path.display()),
            vec![
                "The receipt drives which service gets deleted, so an undecodable one is refused \
                 rather than guessed at."
                    .into(),
            ],
        )
    })?;
    // Gate 1: the bytes. Everything this receipt's grammar supports — see this
    // function's own doc comment for what that is and, just as importantly,
    // what it is not.
    let prior = winhost_verify_install_receipt(&receipt, &manifest).map_err(|detail| {
        winhost_err(
            "SERVICE_RECEIPT_REJECTED",
            format!(
                "refusing to act on the install receipt at {}: {detail}",
                path.display()
            ),
            vec![
                "The receipt determines which `SSKHost_*` service is deleted, so it must match \
                 this build's own host id and its own digest."
                    .into(),
            ],
        )
    })?;

    let helper = WindowsServiceHelper::new(winhost_default_svc_path()?);
    helper.uninstall(&receipt).map_err(|e| {
        winhost_err(
            "SERVICE_UNINSTALL_FAILED",
            e.to_string(),
            service_next_steps(&e),
        )
    })?;
    let _ = std::fs::remove_file(&path);

    // `WindowsServiceHelper::uninstall` is an exact rollback: a receipt whose
    // prior_state is `installed` means install found the service already there,
    // so nothing is deleted. Say which of the two happened.
    let deleted = prior == ServiceState::Uninstalled;
    if json {
        let value = serde_json::json!({
            "status": "ok",
            "action": "service-uninstall",
            "host_id": receipt.host_id.to_hex(),
            "prior_state": receipt.prior_state,
            "service_deleted": deleted
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(winhost_json_err)?
        );
    } else if deleted {
        println!("service uninstalled for host {}", receipt.host_id.to_hex());
    } else {
        println!(
            "no service was deleted for host {}: the receipt records that it already existed \
             before this tool installed anything, so an exact rollback leaves it in place",
            receipt.host_id.to_hex()
        );
    }
    Ok(())
}

fn print_status(status: &ssk_ipc::StatusDto, json: bool) -> Result<(), AppError> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "state": status,
                "next_steps": []
            }))
            .map_err(|e| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                e.to_string(),
                vec![]
            ))?
        );
    } else {
        println!(
            "state={:?} active_profile={}",
            status.state,
            status.active_profile.as_deref().unwrap_or("<none>")
        );
    }
    Ok(())
}

fn unexpected_response(resp: &ssk_ipc::Response) -> AppError {
    AppError::new(
        ErrorClass::Runtime,
        "IPC_UNEXPECTED_RESPONSE",
        format!("unexpected daemon response: {resp:?}"),
        vec![],
    )
}

fn run_once_command(
    valid_fixture: bool,
    seeded: bool,
    epoch: u64,
    cli: &Cli,
) -> Result<(), AppError> {
    let loaded = load_config(cli.config.as_deref())?;
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let pool = default_pool();
    let determinism = DeterminismContext { seeded, epoch };

    let (outcome, manifest) = runtime
        .run_once_with_context(sample_intent(valid_fixture), &pool, &determinism)
        .map_err(|err| {
            AppError::new(
                ErrorClass::Runtime,
                "RUNTIME_RUN_FAILED",
                format!("runtime execution failed: {err}"),
                vec![
                    "Run `ssk doctor` and inspect locator/policy checks.".into(),
                    "Retry with `--json` for machine-readable diagnostics.".into(),
                ],
            )
        })?;

    let event = runtime.runtime_event(&outcome, &manifest, &determinism);
    let mut metrics = load_metrics(&loaded.config.runtime.metrics_path)?;
    metrics.record_run(outcome.gate_report.outcome);
    persist_metrics(&loaded.config.runtime.metrics_path, &metrics)?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "outcome": outcome,
                "event": event,
                "metrics": metrics,
                "next_steps": [
                    "Use `ssk replay-verify` to verify determinism.",
                    "Use `ssk verify-ledger --path <ledger.json>` when using file ledger backend."
                ]
            }))
            .map_err(|err| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                err.to_string(),
                vec![]
            ))?
        );
    } else {
        print_human_run_summary(&event, &metrics);
    }

    Ok(())
}

fn connect_command(
    valid_fixture: bool,
    seeded: bool,
    epoch: u64,
    cli: &Cli,
) -> Result<(), AppError> {
    let mut tensor = ssk_tensor::StitchTensor::open(Box::new(ssk_tensor::GenericMemoryBackend::<
        ssk_types::StitchTensorEntry,
    >::new()))
    .map_err(|_| {
        AppError::new(
            ErrorClass::Runtime,
            "TENSOR_OPEN_FAILED",
            "could not open stitch tensor",
            vec!["Check storage backend availability.".into()],
        )
    })?;
    let determinism = DeterminismContext { seeded, epoch };
    let outcome = ssk_runtime::run_to_outcome(
        &sample_intent(valid_fixture),
        &default_pool(),
        &determinism,
        &GateVector::with_all_default(),
        &mut tensor,
        &ssk_runtime::LocalFiberExecutor,
        ssk_types::EpochId(epoch),
    )
    .map_err(|err| {
        AppError::new(
            ErrorClass::Runtime,
            "RUNTIME_CONNECT_FAILED",
            format!("connect pipeline failed: {err}"),
            vec!["Run `ssk doctor` and inspect locator/policy checks.".into()],
        )
    })?;

    let (kind, stitches, residues) = match &outcome {
        ssk_runtime::RunOutcome::Pass { stitches, .. } => ("pass", stitches.len(), 0),
        ssk_runtime::RunOutcome::HoldRefine { residues } => ("hold_refine", 0, residues.len()),
        ssk_runtime::RunOutcome::DissolveRejectQuarantine { residues, .. } => {
            ("dissolve_reject_quarantine", 0, residues.len())
        }
    };

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "outcome_kind": kind,
                "materialized_stitches": stitches,
                "residues": residues,
                "tensor_head": tensor.head().to_hex(),
                "next_steps": [
                    "A `pass` materialized the stitch into the tensor.",
                    "A `dissolve_*` outcome is fail-closed: no tensor mutation, residues recorded."
                ]
            }))
            .map_err(|err| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                err.to_string(),
                vec![]
            ))?
        );
    } else {
        println!("connect: outcome={kind} materialized={stitches} residues={residues}");
        println!("tensor head: {}", tensor.head().to_hex());
    }

    Ok(())
}

fn replay_verify_command(
    valid_fixture: bool,
    seeded: bool,
    epoch: u64,
    cli: &Cli,
) -> Result<(), AppError> {
    let loaded = load_config(cli.config.as_deref())?;
    let tensor = MemoryBackend::new();
    let runtime = Runtime {
        gate_vector: GateVector::with_all_default(),
        tensor: &tensor,
    };
    let pool = default_pool();
    let determinism = DeterminismContext { seeded, epoch };

    let (actual, manifest) = runtime
        .run_once_with_context(sample_intent(valid_fixture), &pool, &determinism)
        .map_err(|err| {
            AppError::new(
                ErrorClass::Runtime,
                "RUNTIME_REPLAY_SOURCE_FAILED",
                err.to_string(),
                vec!["Retry run with a valid fixture and strict config.".into()],
            )
        })?;

    // The engine re-executes the pipeline from the original intent and
    // diffs the result against the manifest itself — it is not handed two
    // pre-computed outcomes to compare.
    let engine = DeterministicReplayEngine;
    let verdict = engine
        .replay(
            &manifest,
            sample_intent(valid_fixture),
            &pool,
            &determinism,
            &runtime.gate_vector,
        )
        .map_err(|err| {
            AppError::new(
                ErrorClass::Runtime,
                "RUNTIME_REPLAY_REEXEC_FAILED",
                err.to_string(),
                vec!["Inspect run setup and replay inputs.".into()],
            )
        })?;

    let mut metrics = load_metrics(&loaded.config.runtime.metrics_path)?;
    let event = runtime.runtime_event(&actual, &manifest, &determinism);

    match verdict {
        ReplayVerdict::Deterministic => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "verdict": "deterministic",
                        "event": event,
                        "metrics": metrics,
                        "next_steps": [
                            "Persist outputs and replay manifests for audit artifacts.",
                            "Run `ssk doctor` if environment drift is suspected."
                        ]
                    }))
                    .map_err(|err| AppError::new(
                        ErrorClass::Runtime,
                        "JSON_OUTPUT_FAILED",
                        err.to_string(),
                        vec![]
                    ))?
                );
            } else {
                println!(
                    "Replay deterministic for run={} replay={}.",
                    event.run_id, event.replay_id
                );
            }
        }
        ReplayVerdict::Divergent { first_diff, detail } => {
            metrics.record_replay_drift();
            persist_metrics(&loaded.config.runtime.metrics_path, &metrics)?;
            return Err(AppError::new(
                ErrorClass::Replay,
                "REPLAY_DIVERGENCE",
                format!("divergent at {first_diff:?}: {detail}"),
                vec![
                    "Check deterministic seed/epoch and interop handshake assumptions.".into(),
                    "Review `docs/RUNBOOK.md` replay drift recovery section.".into(),
                ],
            ));
        }
    }

    persist_metrics(&loaded.config.runtime.metrics_path, &metrics)?;
    Ok(())
}

fn verify_ledger_command(path: &str, json: bool) -> Result<(), AppError> {
    let ledger = FileLedgerBackend::new(path);
    ledger.verify().map_err(|err| {
        AppError::new(
            ErrorClass::Integrity,
            "LEDGER_VERIFY_FAILED",
            format!("ledger verification failed: {err}"),
            vec![
                "Compare ledger head with replay manifest trace head.".into(),
                "Follow ledger mismatch flow in docs/RUNBOOK.md.".into(),
            ],
        )
    })?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": "ok",
                "ledger": path,
                "message": "ledger-ok"
            }))
            .map_err(|err| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                err.to_string(),
                vec![]
            ))?
        );
    } else {
        println!("ledger-ok");
    }

    Ok(())
}

fn doctor_command(ledger_path: Option<&str>, cli: &Cli) -> Result<(), AppError> {
    let mut checks = vec![
        check_system_clock(),
        check_entropy(),
        check_paths(),
        check_permissions(),
    ];

    match load_config(cli.config.as_deref()) {
        Ok(loaded) => checks.push(DoctorCheck {
            name: "config",
            ok: true,
            detail: format!(
                "config v{} loaded{}",
                loaded.config.version,
                loaded
                    .migrated_from
                    .map(|v| format!(" (migrated from v{v})"))
                    .unwrap_or_default()
            ),
            next_step: "Run `ssk config lint --path <config>` before deployment.".into(),
        }),
        Err(err) => checks.push(DoctorCheck {
            name: "config",
            ok: false,
            detail: err.message,
            next_step: "Fix config and rerun `ssk doctor` (fail-closed startup is enforced)."
                .into(),
        }),
    }

    if let Some(path) = ledger_path {
        let check = match FileLedgerBackend::new(path).verify() {
            Ok(()) => DoctorCheck {
                name: "ledger",
                ok: true,
                detail: "ledger hash-chain verified".into(),
                next_step: "Keep periodic `verify-ledger` checks in operations scripts.".into(),
            },
            Err(err) => DoctorCheck {
                name: "ledger",
                ok: false,
                detail: format!("ledger verify failed: {err}"),
                next_step: "Follow `docs/RUNBOOK.md` ledger mismatch recovery steps.".into(),
            },
        };
        checks.push(check);
    }

    let report = DoctorReport { checks };
    let healthy = report.checks.iter().all(|c| c.ok);

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "status": if healthy {"ok"} else {"error"},
                "report": report,
                "next_steps": ["Fix failing checks before production runs."]
            }))
            .map_err(|err| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                err.to_string(),
                vec![]
            ))?
        );
    } else {
        for check in &report.checks {
            let marker = if check.ok { "[ok]" } else { "[!!]" };
            println!("{marker} {}: {}", check.name, check.detail);
            if !check.ok {
                println!("    next: {}", check.next_step);
            }
        }
    }

    if healthy {
        Ok(())
    } else {
        Err(AppError::new(
            ErrorClass::Doctor,
            "DOCTOR_CHECK_FAILED",
            "one or more doctor checks failed",
            vec!["Resolve failed checks and rerun doctor.".into()],
        ))
    }
}

fn explain_command(target: &str, json: bool) -> Result<(), AppError> {
    let output = explain_target(target).ok_or_else(|| {
        AppError::new(
            ErrorClass::Usage,
            "EXPLAIN_UNKNOWN_TARGET",
            format!("unknown explain target: {target}"),
            vec!["Use a gate name (e.g. `Core`) or error class (`config`, `replay`).".into()],
        )
    })?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).map_err(|err| AppError::new(
                ErrorClass::Runtime,
                "JSON_OUTPUT_FAILED",
                err.to_string(),
                vec![]
            ))?
        );
    } else {
        println!("{} [{}]", output.target, output.category);
        println!("{}", output.summary);
        for detail in output.details {
            println!("- {detail}");
        }
    }
    Ok(())
}

fn config_command(command: &ConfigCommand, json: bool) -> Result<(), AppError> {
    match command {
        ConfigCommand::Lint { path } => {
            let content = std::fs::read_to_string(path).map_err(|err| {
                AppError::new(
                    ErrorClass::Config,
                    "CONFIG_READ_FAILED",
                    format!("cannot read config {}: {err}", path.display()),
                    vec!["Verify path and permissions.".into()],
                )
            })?;
            let report = ssk_config::lint(&content, config_format_from_path(path)?);

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|err| {
                        AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            err.to_string(),
                            vec![],
                        )
                    })?
                );
            } else if report.ok {
                if let Some(from) = report.migrated_from {
                    println!("config-ok (migrated from v{from} to v2)");
                } else {
                    println!("config-ok");
                }
            } else {
                println!("config-invalid");
                for error in report.errors {
                    println!("- {error}");
                }
            }

            if report.ok {
                Ok(())
            } else {
                Err(AppError::new(
                    ErrorClass::Config,
                    "CONFIG_LINT_FAILED",
                    "config lint failed",
                    vec!["Fix lint errors and rerun `ssk config lint`.".into()],
                ))
            }
        }
        ConfigCommand::Schema => {
            let schema = ssk_config::AppConfig::schema_json();
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schema).map_err(|err| {
                        AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            err.to_string(),
                            vec![],
                        )
                    })?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&schema).map_err(|err| {
                        AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            err.to_string(),
                            vec![],
                        )
                    })?
                );
            }
            Ok(())
        }
    }
}

fn emit_error(err: &AppError, json: bool) {
    if json {
        let output = ErrorOutput {
            status: "error",
            class: err.class,
            machine_code: &err.machine_code,
            message: &err.message,
            exit_code: err.class.exit_code(),
            next_steps: &err.next_steps,
        };
        if let Ok(text) = serde_json::to_string_pretty(&output) {
            eprintln!("{text}");
            return;
        }
    }

    eprintln!(
        "error({:?}/{}): {}",
        err.class,
        err.class.exit_code(),
        err.message
    );
    for step in &err.next_steps {
        eprintln!("next: {step}");
    }
}

fn load_config(path: Option<&Path>) -> Result<ssk_config::LoadedConfig, AppError> {
    if let Some(path) = path {
        let content = std::fs::read_to_string(path).map_err(|err| {
            AppError::new(
                ErrorClass::Config,
                "CONFIG_READ_FAILED",
                format!("cannot read config {}: {err}", path.display()),
                vec!["Check file path and permissions.".into()],
            )
        })?;

        let loaded = match config_format_from_path(path)? {
            ssk_config::ConfigFormat::Yaml => {
                ssk_config::AppConfig::parse_with_migration_yaml(&content)
            }
            ssk_config::ConfigFormat::Toml => {
                ssk_config::AppConfig::parse_with_migration_toml(&content)
            }
        }
        .map_err(|err| {
            AppError::new(
                ErrorClass::Config,
                "CONFIG_VALIDATION_FAILED",
                err.to_string(),
                vec![
                    "Run `ssk config lint --path <file>` for details.".into(),
                    "Keep strict_mode and fail_closed enabled.".into(),
                ],
            )
        })?;

        return Ok(loaded);
    }

    Ok(ssk_config::LoadedConfig {
        config: ssk_config::AppConfig::default(),
        migrated_from: None,
    })
}

fn config_format_from_path(path: &Path) -> Result<ssk_config::ConfigFormat, AppError> {
    match path.extension().and_then(|s| s.to_str()) {
        Some("yaml") | Some("yml") => Ok(ssk_config::ConfigFormat::Yaml),
        Some("toml") => Ok(ssk_config::ConfigFormat::Toml),
        _ => Err(AppError::new(
            ErrorClass::Usage,
            "CONFIG_UNKNOWN_FORMAT",
            format!("unsupported config extension for {}", path.display()),
            vec!["Use .yaml/.yml or .toml config files.".into()],
        )),
    }
}

fn load_metrics(path: &str) -> Result<RuntimeMetrics, AppError> {
    let metrics_path = PathBuf::from(path);
    if !metrics_path.exists() {
        return Ok(RuntimeMetrics::default());
    }

    let bytes = std::fs::read(&metrics_path).map_err(|err| {
        AppError::new(
            ErrorClass::Permission,
            "METRICS_READ_FAILED",
            format!("cannot read metrics {}: {err}", metrics_path.display()),
            vec!["Fix metrics file permissions or remove corrupted file.".into()],
        )
    })?;
    if bytes.is_empty() {
        return Ok(RuntimeMetrics::default());
    }

    serde_json::from_slice(&bytes).map_err(|err| {
        AppError::new(
            ErrorClass::Runtime,
            "METRICS_DECODE_FAILED",
            format!("cannot decode metrics: {err}"),
            vec!["Delete or fix the metrics file then rerun command.".into()],
        )
    })
}

fn persist_metrics(path: &str, metrics: &RuntimeMetrics) -> Result<(), AppError> {
    let metrics_path = PathBuf::from(path);
    if let Some(parent) = metrics_path.parent() {
        std::fs::create_dir_all(parent).map_err(|err| {
            AppError::new(
                ErrorClass::Permission,
                "METRICS_DIR_CREATE_FAILED",
                format!(
                    "cannot create metrics directory {}: {err}",
                    parent.display()
                ),
                vec!["Check write permissions on metrics directory.".into()],
            )
        })?;
    }

    let payload = serde_json::to_vec_pretty(metrics).map_err(|err| {
        AppError::new(
            ErrorClass::Runtime,
            "METRICS_ENCODE_FAILED",
            err.to_string(),
            vec![],
        )
    })?;
    std::fs::write(&metrics_path, payload).map_err(|err| {
        AppError::new(
            ErrorClass::Permission,
            "METRICS_WRITE_FAILED",
            format!("cannot write metrics {}: {err}", metrics_path.display()),
            vec!["Check write permissions on metrics path.".into()],
        )
    })
}

fn print_human_run_summary(event: &RuntimeEvent, metrics: &RuntimeMetrics) {
    println!(
        "run={} replay={} outcome={:?} residues={} traces={}",
        event.run_id, event.replay_id, event.gate_outcome, event.residues, event.trace_count
    );
    println!(
        "metrics: runs={} gate_failures={} replay_drifts={}",
        metrics.run_count, metrics.gate_failures, metrics.replay_drifts
    );
    println!("next: run `ssk replay-verify` for deterministic verification");
}

fn check_system_clock() -> DoctorCheck {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => value,
        Err(err) => {
            return DoctorCheck {
                name: "clock",
                ok: false,
                detail: format!("clock before unix epoch: {err}"),
                next_step: "Correct system clock and timezone before running runtime commands."
                    .into(),
            }
        }
    };

    let plausible = now.as_secs() > 1_577_836_800 && now.as_secs() < 4_102_444_800;
    let start = Instant::now();
    std::thread::sleep(Duration::from_millis(1));
    let monotonic = start.elapsed() >= Duration::from_millis(1);

    DoctorCheck {
        name: "clock",
        ok: plausible && monotonic,
        detail: format!("unix={} monotonic={monotonic}", now.as_secs()),
        next_step: "Fix clock sync (NTP) and rerun doctor if this check fails.".into(),
    }
}

/// The OS-CSPRNG check. See [`ssk_diag::entropy`] for what it asserts, what it
/// refuses to claim, and why the previous `/dev/urandom` implementation made
/// `ssk doctor` exit 16 on every Windows machine.
///
/// `DoctorCheck::next_step` is a `String` for every check in this report, so the
/// probe's `None` — "nothing to do" — is rendered with this surface's own
/// wording rather than pushing an `Option` into the JSON contract.
fn check_entropy() -> DoctorCheck {
    let probe = ssk_diag::entropy::probe();
    DoctorCheck {
        name: "entropy",
        ok: probe.ok,
        detail: probe.detail,
        next_step: probe
            .next_step
            .unwrap_or_else(|| "No action required.".to_owned()),
    }
}

/// Report the **resolved state directory**, not the current working directory.
///
/// The old check reported `cwd` and passed whenever that directory existed —
/// which is always. It therefore said nothing. What actually matters to every
/// other component is where state lands, and on Windows the daemon's pipe name
/// is a digest *over that directory*, so a client and a daemon that resolve it
/// differently never meet.
///
/// Fails closed on a non-absolute result. That is the CWD-relative `.ssk`
/// default the roadmap ordered off the CWD (and, on a machine with neither
/// `%LOCALAPPDATA%` nor `$HOME`, `ssk-ipc`'s surviving fallback to it): a
/// relative state directory means every invocation from a different directory
/// gets different state.
fn check_paths() -> DoctorCheck {
    check_paths_in(&ssk_ipc::paths::state_dir())
}

fn check_paths_in(dir: &Path) -> DoctorCheck {
    let absolute = dir.is_absolute();
    let source = if std::env::var_os("SSK_STATE_DIR").is_some() {
        "SSK_STATE_DIR"
    } else {
        "platform default"
    };
    DoctorCheck {
        name: "paths",
        ok: absolute,
        detail: format!("state_dir={} (from {source})", dir.display()),
        next_step: "Set SSK_STATE_DIR to an absolute path, or ensure %LOCALAPPDATA% (Windows) / \
                    $XDG_STATE_HOME or $HOME (Unix) is set: a relative state directory makes \
                    state depend on the directory `ssk` happened to be run from."
            .into(),
    }
}

/// Write-probe the **resolved state directory**, not `./.ssk`.
///
/// The old check did `create_dir_all(".ssk")` in the current working directory
/// — so running `ssk doctor` anywhere, including inside a source tree,
/// created a stray `.ssk`. Measured on this machine before the change. It also
/// probed a directory nothing else uses.
fn check_permissions() -> DoctorCheck {
    check_permissions_in(&ssk_ipc::paths::state_dir())
}

fn check_permissions_in(dir: &Path) -> DoctorCheck {
    if !dir.is_absolute() {
        // `check_paths` already reports this as the failure it is; do not
        // compound it by creating a directory in the CWD to prove a point.
        return DoctorCheck {
            name: "permissions",
            ok: false,
            detail: format!(
                "refused to write-probe the non-absolute state directory {}",
                dir.display()
            ),
            next_step: "Resolve the `paths` check first; a relative state directory is not \
                        probed, because probing it would create one."
                .into(),
        };
    }

    let check_file = dir.join("doctor-permission-check.tmp");
    let result = std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::write(&check_file, b"ok"))
        .and_then(|()| std::fs::remove_file(&check_file));

    DoctorCheck {
        name: "permissions",
        ok: result.is_ok(),
        detail: match &result {
            Ok(()) => format!("create+write+delete verified in {}", dir.display()),
            Err(err) => format!("write check failed in {}: {err}", dir.display()),
        },
        next_step: "Grant write permissions on the state directory (config/metrics/runtime \
                    output all land there)."
            .into(),
    }
}

fn explain_target(target: &str) -> Option<ExplainOutput> {
    let normalized = target.trim().to_ascii_lowercase();

    let gate = match normalized.as_str() {
        "core" => Some(GateId::Core),
        "mirror" => Some(GateId::Mirror),
        "locator" => Some(GateId::Locator),
        "bcik" => Some(GateId::Bcik),
        "hypercube" => Some(GateId::Hypercube),
        "capability" => Some(GateId::Capability),
        "fiber" => Some(GateId::Fiber),
        "privacy" => Some(GateId::Privacy),
        "boundary" => Some(GateId::Boundary),
        "focus" => Some(GateId::Focus),
        "replay" => Some(GateId::Replay),
        "dissolution" => Some(GateId::Dissolution),
        _ => None,
    };

    if let Some(gate) = gate {
        return Some(ExplainOutput {
            target: gate_name(gate).into(),
            category: "gate".into(),
            summary: format!(
                "Gate `{}` enforces fail-closed progression.",
                gate_name(gate)
            ),
            details: vec![
                "Any non-pass verdict blocks stitch persistence.".into(),
                "Residues from this gate are replay-visible and auditable.".into(),
                "Use `ssk --json run ...` for machine-readable gate diagnostics.".into(),
            ],
        });
    }

    let error = match normalized.as_str() {
        "config" => Some((
            "Configuration validation failed before runtime start.",
            vec![
                "Fail-closed policy and strict runtime mode are mandatory.".into(),
                "Run `ssk config lint --path <file>` for concrete validation errors.".into(),
            ],
        )),
        "interop" => Some((
            "Interop negotiation failed due to version/capability mismatch.",
            vec![
                "Check protocol semver compatibility matrix.".into(),
                "Ensure required capabilities are advertised by both peers.".into(),
            ],
        )),
        "replay" => Some((
            "Replay verification detected deterministic drift.",
            vec![
                "Compare run/replay IDs and scheduler context fields.".into(),
                "Use runbook replay drift flow to isolate root cause.".into(),
            ],
        )),
        "integrity" | "ledger" => Some((
            "Ledger hash-chain verification failed.",
            vec![
                "Stop writes and preserve current ledger artifact.".into(),
                "Rebuild expected chain using replay manifests and recover from backup.".into(),
            ],
        )),
        _ => None,
    };

    error.map(|(summary, details)| ExplainOutput {
        target: normalized,
        category: "error".into(),
        summary: summary.into(),
        details,
    })
}

const fn gate_name(gate: GateId) -> &'static str {
    match gate {
        GateId::Core => "Core",
        GateId::Mirror => "Mirror",
        GateId::Locator => "Locator",
        GateId::Bcik => "Bcik",
        GateId::Hypercube => "Hypercube",
        GateId::Capability => "Capability",
        GateId::Fiber => "Fiber",
        GateId::Privacy => "Privacy",
        GateId::Boundary => "Boundary",
        GateId::Focus => "Focus",
        GateId::Replay => "Replay",
        GateId::Dissolution => "Dissolution",
    }
}

// ---------------------------------------------------------------------------
// Interop conformance command
// ---------------------------------------------------------------------------

fn interop_command(command: &InteropCommand, json: bool) -> Result<(), AppError> {
    match command {
        InteropCommand::Conformance {
            profile,
            require_attestation,
        } => {
            let policy = CompatibilityPolicy {
                require_attestation: *require_attestation,
                ..CompatibilityPolicy::default()
            };

            // This is a protocol conformance self-test against golden vectors,
            // not a peer-trust decision — the fixed reference key is
            // deliberately used here (see `insecure-test-keys` on ssk-interop
            // in Cargo.toml). Never use `new_test_key()` to verify an actual
            // peer's attestation.
            let verifier = Blake3KeyedVerifier::new_test_key();
            let verifier_ref: Option<&dyn ssk_interop::AttestationVerifier> =
                if *require_attestation {
                    Some(&verifier)
                } else {
                    None
                };

            let suite = ConformanceSuite::default();

            // Filter to a specific profile if requested.
            let profiles_to_run: Vec<_> = if let Some(name) = profile {
                suite.profiles.iter().filter(|p| p.name == *name).collect()
            } else {
                suite.profiles.iter().collect()
            };

            if profiles_to_run.is_empty() {
                return Err(AppError::new(
                    ErrorClass::Interop,
                    "CONFORMANCE_PROFILE_NOT_FOUND",
                    format!(
                        "no conformance profile named '{}'",
                        profile.as_deref().unwrap_or("<all>")
                    ),
                    vec!["Run `ssk interop conformance` without --profile to list all.".into()],
                ));
            }

            let results: Vec<_> = profiles_to_run
                .iter()
                .map(|p| {
                    let outcome = policy.evaluate(&p.request, verifier_ref);
                    let accepted = outcome.is_ok();
                    let passed = accepted == p.expected_accept;
                    serde_json::json!({
                        "name": p.name,
                        "description": p.description,
                        "expected_accept": p.expected_accept,
                        "actual_accept": accepted,
                        "passed": passed,
                    })
                })
                .collect();

            let all_passed = results
                .iter()
                .all(|r| r["passed"].as_bool().unwrap_or(false));

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": if all_passed { "ok" } else { "error" },
                        "all_passed": all_passed,
                        "results": results,
                        "next_steps": [
                            "Review failing profiles and update policy or peer capabilities.",
                            "Consult docs/INTEROP_SPEC.md for compatibility requirements."
                        ]
                    }))
                    .map_err(|e| AppError::new(
                        ErrorClass::Runtime,
                        "JSON_OUTPUT_FAILED",
                        e.to_string(),
                        vec![]
                    ))?
                );
            } else {
                for r in &results {
                    let marker = if r["passed"].as_bool().unwrap_or(false) {
                        "[ok]"
                    } else {
                        "[!!]"
                    };
                    println!(
                        "{marker} {}: expected_accept={} actual_accept={}",
                        r["name"], r["expected_accept"], r["actual_accept"]
                    );
                }
                if all_passed {
                    println!("conformance: all profiles passed");
                } else {
                    println!("conformance: one or more profiles FAILED");
                }
            }

            if all_passed {
                Ok(())
            } else {
                Err(AppError::new(
                    ErrorClass::Interop,
                    "CONFORMANCE_FAILED",
                    "conformance suite: one or more profiles failed",
                    vec![
                        "Fix peer capability or version configuration.".into(),
                        "See docs/INTEROP_SPEC.md for the compatibility matrix.".into(),
                    ],
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chaos drill command
// ---------------------------------------------------------------------------

fn chaos_command(command: &ChaosCommand, json: bool) -> Result<(), AppError> {
    match command {
        ChaosCommand::Drill { fault } => {
            let clean_intent = sample_intent(true);

            // Stub runner: mimics the gate heuristic used in faultscan tests.
            let run_intent =
                |intent: ssk_types::ConnectionIntent| -> (GateOutcomeKind, Vec<ssk_types::BoundaryResidue>) {
                    if !intent.core.signature.is_present()
                        || intent.capability.is_none()
                        || intent.ttl_epoch == 0
                    {
                        let residue = ssk_types::BoundaryResidue::new(
                            ssk_types::ResidueId::new("chaos-fault"),
                            ssk_types::ResidueKind::Identity,
                            ssk_types::GateId::Core,
                            "chaos-injected fault detected",
                            ssk_types::Severity::High,
                            ssk_types::TraceId::new("chaos-fault-trace"),
                            true,
                        );
                        (GateOutcomeKind::Reject, vec![residue])
                    } else {
                        (GateOutcomeKind::Pass, vec![])
                    }
                };

            if let Some(fault_str) = fault {
                let fault_kind = parse_fault_kind(fault_str)?;
                let report = ssk_faultscan::run_drill(clean_intent, fault_kind, &run_intent);
                let passed = report.passed();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": if passed { "ok" } else { "error" },
                            "drill": report,
                            "next_steps": [
                                "Investigate failing drill: check gate logic for the fault kind.",
                                "Consult docs/RUNBOOK.md for incident recovery procedures."
                            ]
                        }))
                        .map_err(|e| AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            e.to_string(),
                            vec![]
                        ))?
                    );
                } else {
                    let marker = if passed { "[ok]" } else { "[!!]" };
                    println!(
                        "{marker} drill {:?}: detected={} recovered={}",
                        report.fault, report.fault_detected, report.recovery_succeeded
                    );
                }
                if passed {
                    Ok(())
                } else {
                    Err(AppError::new(
                        ErrorClass::Chaos,
                        "CHAOS_DRILL_FAILED",
                        format!("chaos drill {:?} failed", fault_kind),
                        vec![
                            "Review gate logic for the injected fault type.".into(),
                            "Follow incident recovery procedures in docs/RUNBOOK.md.".into(),
                        ],
                    ))
                }
            } else {
                // Run full playbook.
                let playbook = run_playbook(clean_intent, &run_intent);
                let all_passed = playbook.all_passed();
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": if all_passed { "ok" } else { "error" },
                            "playbook": playbook,
                            "next_steps": [
                                "Resolve failing drills before production deployment.",
                                "Consult docs/RUNBOOK.md for chaos/recovery guidance."
                            ]
                        }))
                        .map_err(|e| AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            e.to_string(),
                            vec![]
                        ))?
                    );
                } else {
                    for drill in &playbook.drills {
                        let marker = if drill.passed() { "[ok]" } else { "[!!]" };
                        println!(
                            "{marker} {:?}: detected={} recovered={}",
                            drill.fault, drill.fault_detected, drill.recovery_succeeded
                        );
                    }
                    if all_passed {
                        println!(
                            "chaos playbook: all drills passed ({}/{})",
                            playbook.passed, playbook.total
                        );
                    } else {
                        println!("chaos playbook: {} drills FAILED", playbook.failed);
                    }
                }
                if all_passed {
                    Ok(())
                } else {
                    Err(AppError::new(
                        ErrorClass::Chaos,
                        "CHAOS_PLAYBOOK_FAILED",
                        "chaos playbook: one or more drills failed",
                        vec!["Resolve failing drills before production deployment.".into()],
                    ))
                }
            }
        }
    }
}

fn parse_fault_kind(s: &str) -> Result<ChaosFaultKind, AppError> {
    match s {
        "signature-corruption" => Ok(ChaosFaultKind::SignatureCorruption),
        "capability-withdrawal" => Ok(ChaosFaultKind::CapabilityWithdrawal),
        "ttl-expiry" => Ok(ChaosFaultKind::TtlExpiry),
        "replay-drift" => Ok(ChaosFaultKind::ReplayDrift),
        "attestation-failure" => Ok(ChaosFaultKind::AttestationFailure),
        "locator-untrust" => Ok(ChaosFaultKind::LocatorUntrust),
        _ => Err(AppError::new(
            ErrorClass::Usage,
            "CHAOS_UNKNOWN_FAULT",
            format!("unknown fault kind: {s}"),
            vec![
                "Valid faults: signature-corruption, capability-withdrawal, ttl-expiry, \
                 replay-drift, attestation-failure, locator-untrust"
                    .into(),
            ],
        )),
    }
}

// ---------------------------------------------------------------------------
// Net-admin commands
// ---------------------------------------------------------------------------

fn net_admin_command(command: &NetAdminCommand, json: bool) -> Result<(), AppError> {
    match command {
        NetAdminCommand::FlowInspect {
            app_id,
            dest_host,
            dest_port,
            protocol,
            risk,
        }
        | NetAdminCommand::RouteTrace {
            app_id,
            dest_host,
            dest_port,
            protocol,
            risk,
        } => {
            let proto = parse_protocol(protocol)?;
            let risk_level = parse_risk(risk)?;
            let flow = FlowRecord::new(
                format!("flow-cli-{app_id}"),
                0,
                FlowDescriptor::new(app_id, dest_host, *dest_port, proto, risk_level),
            );
            let engine = default_policy_engine();
            let orc = default_route_orchestrator();

            let decision = engine.evaluate(&flow).map_err(|e| {
                AppError::new(
                    ErrorClass::NetAdmin,
                    "NETADMIN_POLICY_EVAL_FAILED",
                    e.to_string(),
                    vec!["Check netadmin policy configuration.".into()],
                )
            })?;

            let is_route_cmd = matches!(command, NetAdminCommand::RouteTrace { .. });

            if is_route_cmd {
                let candidate = orc.plan(&flow, &decision).map_err(|e| {
                    AppError::new(
                        ErrorClass::NetAdmin,
                        "NETADMIN_ROUTE_PLAN_FAILED",
                        e.to_string(),
                        vec!["Register required adapters or fix policy.".into()],
                    )
                })?;

                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "flow_id": flow.flow_id,
                            "policy_decision": decision,
                            "route_candidate": candidate,
                            "next_steps": [
                                "Use the route_kind to configure your transport layer.",
                                "If attestation is required, bind a signed token before dispatch."
                            ]
                        }))
                        .map_err(|e| AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            e.to_string(),
                            vec![]
                        ))?
                    );
                } else {
                    println!(
                        "flow={} action={:?} route={:?} requires_attestation={}",
                        flow.flow_id,
                        decision.action,
                        candidate.route,
                        candidate.requires_attestation
                    );
                }
            } else {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "status": "ok",
                            "flow": flow,
                            "decision": decision,
                            "next_steps": [
                                "Use `ssk net-admin route-trace` to inspect the computed route.",
                                "Adjust policy rules if the decision is unexpected."
                            ]
                        }))
                        .map_err(|e| AppError::new(
                            ErrorClass::Runtime,
                            "JSON_OUTPUT_FAILED",
                            e.to_string(),
                            vec![]
                        ))?
                    );
                } else {
                    println!(
                        "flow={} matched_rule={} action={:?}",
                        flow.flow_id,
                        decision.matched_rule.as_deref().unwrap_or("<fail-closed>"),
                        decision.action
                    );
                }
            }

            Ok(())
        }

        NetAdminCommand::AuditDump => {
            // Run a sample two-flow pipeline and dump the audit ledger.
            let engine = default_policy_engine();
            let orc = default_route_orchestrator();
            let mut session = SessionLedger::new();
            let mut audit = AuditLedger::new();

            let flows = [
                FlowRecord::new(
                    "audit-demo-f1",
                    1,
                    FlowDescriptor::new(
                        "demo-app",
                        "db.internal",
                        5432,
                        ProtocolKind::Tcp,
                        RiskLevel::Low,
                    ),
                ),
                FlowRecord::new(
                    "audit-demo-f2",
                    2,
                    FlowDescriptor::new(
                        "demo-app",
                        "risky.external.com",
                        443,
                        ProtocolKind::Https,
                        RiskLevel::High,
                    ),
                ),
            ];

            for (i, flow) in flows.iter().enumerate() {
                let decision = engine.evaluate(flow).map_err(|e| {
                    AppError::new(
                        ErrorClass::NetAdmin,
                        "NETADMIN_AUDIT_DEMO_FAILED",
                        e.to_string(),
                        vec![],
                    )
                })?;
                let candidate = orc.plan(flow, &decision).map_err(|e| {
                    AppError::new(
                        ErrorClass::NetAdmin,
                        "NETADMIN_AUDIT_DEMO_FAILED",
                        e.to_string(),
                        vec![],
                    )
                })?;

                let outcome = if candidate.is_denied() {
                    AuditOutcome::Denied
                } else {
                    AuditOutcome::Dispatched
                };

                let sd = session
                    .record(
                        format!("sd-{i}"),
                        &flow.flow_id,
                        decision.clone(),
                        candidate.clone(),
                        None,
                    )
                    .map_err(|e| {
                        AppError::new(
                            ErrorClass::NetAdmin,
                            "NETADMIN_SESSION_RECORD_FAILED",
                            e.to_string(),
                            vec![],
                        )
                    })?;

                audit
                    .record(
                        format!("ae-{i}"),
                        &flow.flow_id,
                        Some(sd.decision_id.clone()),
                        None,
                        &candidate.route,
                        outcome,
                        flow.intake_epoch,
                    )
                    .map_err(|e| {
                        AppError::new(
                            ErrorClass::NetAdmin,
                            "NETADMIN_AUDIT_RECORD_FAILED",
                            e.to_string(),
                            vec![],
                        )
                    })?;
            }

            audit.verify().map_err(|e| {
                AppError::new(
                    ErrorClass::Integrity,
                    "NETADMIN_AUDIT_VERIFY_FAILED",
                    e.to_string(),
                    vec!["Audit chain broken; do not trust forensic records.".into()],
                )
            })?;

            let entries = audit.entries().map_err(|e| {
                AppError::new(
                    ErrorClass::NetAdmin,
                    "NETADMIN_AUDIT_READ_FAILED",
                    e.to_string(),
                    vec![],
                )
            })?;

            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "status": "ok",
                        "entries": entries.iter().map(|e| serde_json::json!({
                            "entry_id": e.entry_id,
                            "flow_id": e.flow_id,
                            "outcome": e.outcome,
                            "route_kind_summary": e.route_kind_summary,
                            "epoch": e.epoch,
                            "entry_hash": e.entry_hash,
                        })).collect::<Vec<_>>(),
                        "next_steps": ["Preserve audit ledger for incident forensics."]
                    }))
                    .map_err(|e| AppError::new(
                        ErrorClass::Runtime,
                        "JSON_OUTPUT_FAILED",
                        e.to_string(),
                        vec![]
                    ))?
                );
            } else {
                println!("audit-ledger verified ({} entries):", entries.len());
                for e in &entries {
                    println!(
                        "  {} flow={} outcome={:?} route={}",
                        e.entry_id, e.flow_id, e.outcome, e.route_kind_summary
                    );
                }
            }

            Ok(())
        }
    }
}

fn parse_protocol(s: &str) -> Result<ProtocolKind, AppError> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Ok(ProtocolKind::Tcp),
        "udp" => Ok(ProtocolKind::Udp),
        "tls" => Ok(ProtocolKind::Tls),
        "http" => Ok(ProtocolKind::Http),
        "https" => Ok(ProtocolKind::Https),
        "dns" => Ok(ProtocolKind::Dns),
        _ => Err(AppError::new(
            ErrorClass::Usage,
            "NETADMIN_UNKNOWN_PROTOCOL",
            format!("unknown protocol: {s}"),
            vec!["Valid protocols: tcp, udp, tls, http, https, dns".into()],
        )),
    }
}

fn parse_risk(s: &str) -> Result<RiskLevel, AppError> {
    match s.to_ascii_lowercase().as_str() {
        "low" => Ok(RiskLevel::Low),
        "medium" => Ok(RiskLevel::Medium),
        "high" => Ok(RiskLevel::High),
        "critical" => Ok(RiskLevel::Critical),
        _ => Err(AppError::new(
            ErrorClass::Usage,
            "NETADMIN_UNKNOWN_RISK",
            format!("unknown risk level: {s}"),
            vec!["Valid risk levels: low, medium, high, critical".into()],
        )),
    }
}

fn default_policy_engine() -> PolicyEngine {
    PolicyEngine::new(vec![
        PolicyRule {
            rule_id: "allow-internal".into(),
            description: "allow internal low-risk traffic".into(),
            priority: 10,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: Some(".internal".into()),
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        },
        PolicyRule {
            rule_id: "proxy-high-risk".into(),
            description: "route high-risk external traffic via socks5".into(),
            priority: 20,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: Some(RiskLevel::High),
                max_risk: None,
            },
            action: PolicyAction::Redirect {
                adapter_id: "socks5-exit".into(),
            },
        },
        PolicyRule {
            rule_id: "allow-low-risk-direct".into(),
            description: "default profile: allow low-risk traffic direct".into(),
            priority: 30,
            criteria: MatchCriteria {
                app_prefix: None,
                dest_suffix: None,
                protocol: None,
                min_risk: None,
                max_risk: Some(RiskLevel::Low),
            },
            action: PolicyAction::Allow,
        },
    ])
}

fn default_route_orchestrator() -> RouteOrchestrator {
    use ssk_netadmin::route::HopSpec;
    RouteOrchestrator::new(vec![AdapterRegistryEntry {
        adapter_id: "socks5-exit".into(),
        default_hop: HopSpec::new("socks5-exit", "proxy.corp.com", 1080),
    }])
}

fn default_pool() -> StaticLocatorPool {
    StaticLocatorPool::new(vec![ssk_types::LocatorFacet {
        id: LocatorId::new("local"),
        kind: ssk_types::LocatorKind::LocalOverlay,
        endpoint: ssk_types::EndpointRef::new("local-endpoint"),
        route: ssk_types::RouteClass::Direct,
        transport: ssk_types::TransportClass::Tcp,
        epoch: ssk_types::EpochId(0),
        ttl: ssk_types::Ttl(100),
        trust: ssk_types::TrustClass::Owned,
        cost: ssk_types::CostClass::Free,
        risk: ssk_types::RiskClass::Low,
        health: ssk_types::HealthStatus::Live,
        trace: ssk_types::TraceId::new("trace-local"),
        trusted: true,
        risk_score: 10,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- P2: the Windows control plane ------------------------------------

    /// The endpoint must name the transport this platform actually has. On
    /// Windows that is a named pipe — the pre-P2 code computed a Unix socket
    /// path here and then reported `DAEMON_UNIX_ONLY`.
    #[test]
    fn the_daemon_endpoint_names_this_platforms_transport() {
        let endpoint = daemon_endpoint().expect("an endpoint must be derivable on this host");
        match &endpoint {
            #[cfg(windows)]
            ssk_ipc::Endpoint::NamedPipe(name) => {
                assert!(
                    name.starts_with(r"\\.\pipe\kaleidoscorp-sskd-"),
                    "unexpected pipe name: {name}"
                );
                assert_ne!(
                    name, r"\\.\pipe\kaleidoscorp-sskd",
                    "the fixed global pre-P2 name is what stopped two daemons coexisting"
                );
            }
            #[cfg(unix)]
            ssk_ipc::Endpoint::UnixSocket(path) => {
                assert!(path.ends_with("sskd.sock"), "unexpected socket: {path:?}");
            }
            other => panic!("wrong transport for this platform: {other:?}"),
        }
    }

    /// The regression that matters: an absent daemon must be a *retriable
    /// runtime* error naming the daemon, never the `DAEMON_UNIX_ONLY` platform
    /// refusal that used to fire on Windows while `sskd` was listening.
    #[test]
    fn a_missing_daemon_is_a_retriable_runtime_error_not_a_platform_refusal() {
        #[cfg(windows)]
        let endpoint = ssk_ipc::Endpoint::NamedPipe(format!(
            r"\\.\pipe\ssk-cli-absent-{}",
            std::process::id()
        ));
        #[cfg(unix)]
        let endpoint = ssk_ipc::Endpoint::UnixSocket(
            std::env::temp_dir().join(format!("ssk-cli-absent-{}.sock", std::process::id())),
        );

        let err = call_daemon_at(&endpoint, ssk_ipc::Request::GetStatus)
            .expect_err("no daemon is listening on a per-pid scratch endpoint");

        assert_ne!(
            err.machine_code, "DAEMON_UNIX_ONLY",
            "the platform-refusal stub must be gone: the named-pipe client exists now"
        );
        assert_eq!(err.machine_code, "IPC_CONNECT_FAILED");
        // Exit code contract preserved: the stub was Runtime/12 too, so no
        // script that keyed on 12 changes behaviour.
        assert_eq!(err.class.exit_code(), 12);
        assert!(
            err.message.contains("absent") || !err.next_steps.is_empty(),
            "a daemon-absent failure must be actionable: {err:?}"
        );
    }

    /// `Validation` used to fall through to `Runtime` (exit 12) for what is a
    /// usage error (exit 2).
    #[test]
    fn ipc_error_classes_map_to_the_documented_exit_codes() {
        let cases = [
            ("Usage", 2u8),
            ("Validation", 2),
            ("Config", 10),
            ("Permission", 15),
            ("Doctor", 16),
            ("SomethingUnmapped", 12),
        ];
        for (class, code) in cases {
            let err = AppError::from(ssk_ipc::IpcError::new(class, "X", "m"));
            assert_eq!(err.class.exit_code(), code, "class {class}");
        }
    }

    // --- P2: build identity ------------------------------------------------

    #[test]
    fn the_version_string_is_the_package_version() {
        assert_eq!(build::VERSION, env!("CARGO_PKG_VERSION"));
        assert!(build::short().starts_with(build::VERSION));
    }

    /// The long form must label its provenance rather than printing a bare SHA
    /// and implying it was derived and verified.
    #[test]
    fn the_long_version_labels_its_provenance_and_embeds_no_build_clock() {
        let long = build::long_version();
        // clap renders `{bin} {long_version}`, so this must NOT repeat "ssk".
        assert!(long.starts_with(build::VERSION), "{long}");
        assert!(!long.starts_with("ssk "), "{long}");
        assert!(long.contains("provenance:"), "{long}");
        assert!(long.contains(build::provenance()), "{long}");
        assert!(long.contains("profile:"), "{long}");
        // Determinism: no wall-clock build date, per `[profile.release]`'s
        // byte-identical-rebuild requirement.
        assert!(
            !long.contains("build-date"),
            "a wall-clock build date would break reproducible builds: {long}"
        );
    }

    #[test]
    fn provenance_is_unknown_unless_a_sha_was_declared() {
        assert_eq!(
            build::provenance(),
            if build::GIT_SHA.is_some() {
                "declared"
            } else {
                "unknown"
            }
        );
    }

    // --- P2: doctor --------------------------------------------------------

    #[test]
    fn the_entropy_check_is_green_on_this_machine_and_never_names_urandom() {
        let check = check_entropy();
        assert!(check.ok, "{}", check.detail);
        assert!(!check.detail.contains("/dev/urandom"), "{}", check.detail);
        assert!(!check.detail.contains("dev/urandom"), "{}", check.detail);
    }

    /// The whole point of `ssk_diag::entropy`'s injected seam: the check must
    /// still be able to say no. Without this the green above is unfalsifiable.
    #[test]
    fn the_entropy_check_still_fails_closed_on_a_stubbed_provider() {
        let mut stub = |buf: &mut [u8]| {
            buf.fill(0);
            Ok(())
        };
        assert!(!ssk_diag::entropy::probe_with(&mut stub).ok);
    }

    /// The `Option<String>` → `String` adaptation this surface performs: a green
    /// check must still carry a next step, because every other check in the
    /// report does and the JSON contract has no null there.
    #[test]
    fn a_green_entropy_check_still_carries_a_next_step_string() {
        let check = check_entropy();
        assert!(check.ok, "{}", check.detail);
        assert_eq!(check.next_step, "No action required.");
    }

    #[test]
    fn the_paths_check_refuses_a_cwd_relative_state_directory() {
        assert!(!check_paths_in(Path::new(".ssk")).ok);
        assert!(check_paths_in(&std::env::temp_dir()).ok);
    }

    /// The measured defect: `ssk doctor` used to `create_dir_all(".ssk")` in
    /// whatever directory it was invoked from, including a source tree.
    #[test]
    fn the_permissions_check_never_creates_a_directory_in_the_cwd() {
        let before = Path::new(".ssk").exists();
        let check = check_permissions_in(Path::new(".ssk"));
        assert!(!check.ok, "a relative state directory must fail closed");
        assert_eq!(
            Path::new(".ssk").exists(),
            before,
            "the permission probe must not have created `.ssk`"
        );
    }

    #[test]
    fn the_permissions_check_probes_the_directory_it_is_given() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("state");
        let check = check_permissions_in(&target);
        assert!(check.ok, "{}", check.detail);
        assert!(check.detail.contains("state"), "{}", check.detail);
        assert!(
            !target.join("doctor-permission-check.tmp").exists(),
            "the probe file must be removed again"
        );
    }

    #[test]
    fn explain_gate_has_deterministic_shape() {
        let output = explain_target("core").expect("core explanation exists");
        let json = serde_json::to_string_pretty(&output).expect("json output");
        assert!(json.contains("\"category\": \"gate\""));
        assert!(json.contains("Core"));
    }

    #[test]
    fn explain_error_has_machine_readable_fields() {
        let output = explain_target("config").expect("config explanation exists");
        assert_eq!(output.category, "error");
        assert!(!output.details.is_empty());
    }

    // The kill-switch receipt path is keyed on the scope content digest, so
    // distinct scopes never collide onto one receipt file (finding #3), and the
    // same scope always resolves to the same file (engage/release must agree).
    #[test]
    fn killswitch_receipt_path_is_scope_digest_keyed() {
        let a = BoundaryScope::new("all-egress", ["*"]);
        let b = BoundaryScope::new("tenant-7", ["*"]);
        let a2 = BoundaryScope::new("all-egress", ["*"]);
        let pa = winhost_killswitch_receipt_path(&a).expect("path a");
        let pb = winhost_killswitch_receipt_path(&b).expect("path b");
        let pa2 = winhost_killswitch_receipt_path(&a2).expect("path a2");
        assert_ne!(pa, pb, "distinct scopes must not share a receipt file");
        assert_eq!(
            pa, pa2,
            "the same scope must resolve to the same receipt file"
        );
        assert!(pa
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("killswitch-") && n.ends_with(".json")));
    }

    // -----------------------------------------------------------------------
    // SEC-1 at the call site.
    //
    // Every receipt below is a *perfect* forgery by the digest's own standard:
    // `EnforcementReceipt::new` recomputes `receipt_id` over the attacker's
    // chosen `prior_state`, so `verify_against` passes. That is deliberate —
    // these tests exercise the controls that actually bound SEC-1 (the envelope
    // grammar and scope re-derivation), not the unkeyed hash.
    //
    // No test here reaches a firewall: `winhost_load_killswitch_receipt` is
    // pure apart from reading the file it is handed, and every file is written
    // into a `tempfile::tempdir()`.
    // -----------------------------------------------------------------------

    fn scope(label: &str) -> BoundaryScope {
        BoundaryScope::new(label, ["*"])
    }

    /// Write `receipt` to a scratch file and run it through the full gate.
    fn load_planted(scope: &BoundaryScope, receipt: &EnforcementReceipt) -> LoadedReceipt {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("planted.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(receipt).expect("serialize receipt"),
        )
        .expect("write planted receipt");
        winhost_load_killswitch_receipt(scope, &path)
    }

    fn rejection_code(loaded: &LoadedReceipt) -> &'static str {
        match loaded {
            LoadedReceipt::Invalid { code, .. } => code,
            LoadedReceipt::Missing => panic!("expected a rejection, got Missing"),
            LoadedReceipt::Valid { .. } => panic!("expected a rejection, got Valid"),
        }
    }

    /// The canonical receipt this build writes for a scope.
    fn honest_receipt(scope: &BoundaryScope) -> EnforcementReceipt {
        let prior = PriorState {
            ownership: Ownership::Unknown,
            rule_name: rule_name_for_scope(scope).expect("derive rule name"),
        };
        EnforcementReceipt::new(scope, prior.encode())
    }

    #[test]
    fn an_honest_receipt_passes_the_full_gate() {
        let s = scope("all-egress");
        match load_planted(&s, &honest_receipt(&s)) {
            LoadedReceipt::Valid { prior, .. } => {
                assert_eq!(
                    prior.rule_name,
                    rule_name_for_scope(&s).expect("derive rule name")
                );
                assert_eq!(prior.ownership, Ownership::Unknown);
            }
            other => panic!("expected Valid, got {:?}", rejection_code(&other)),
        }
    }

    #[test]
    fn a_missing_receipt_is_missing_not_invalid() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(
            winhost_load_killswitch_receipt(&scope("all-egress"), &dir.path().join("absent.json")),
            LoadedReceipt::Missing
        ));
    }

    // The catastrophic case: pre-P1 this reached `build_delete_args` and became
    // `netsh advfirewall firewall delete rule name=all`, which deletes EVERY
    // rule in the profile.
    #[test]
    fn a_forged_receipt_naming_all_rules_is_rejected() {
        let s = scope("all-egress");
        let forged = EnforcementReceipt::new(&s, "v2;mech=netsh;own=unknown;rule=all");
        assert!(
            forged.verify_against(&s).is_ok(),
            "the digest is unkeyed, so a forgery MUST still pass integrity — that is why the \
             envelope grammar is the real control"
        );
        assert_eq!(
            rejection_code(&load_planted(&s, &forged)),
            "KILLSWITCH_RECEIPT_REJECTED"
        );
    }

    #[test]
    fn a_forged_receipt_naming_a_real_windows_rule_is_rejected() {
        let s = scope("all-egress");
        for name in [
            "Windows Firewall Remote Management",
            "",
            "SSK-KillSwitch-",
            "SSK-KillSwitch-ABCDEF0123456789",
            "SSK-KillSwitch-x-0011223344556677 --extra",
        ] {
            let forged =
                EnforcementReceipt::new(&s, format!("v2;mech=netsh;own=unknown;rule={name}"));
            assert_eq!(
                rejection_code(&load_planted(&s, &forged)),
                "KILLSWITCH_RECEIPT_REJECTED",
                "rule name {name:?} must not survive the gate"
            );
        }
    }

    // The `;rule=` injection the pre-P1 `split_once` parser admitted.
    #[test]
    fn a_second_rule_field_is_rejected() {
        let s = scope("all-egress");
        let good = rule_name_for_scope(&s).expect("derive rule name");
        let forged = EnforcementReceipt::new(
            &s,
            format!("v2;mech=netsh;own=unknown;rule={good};rule=evil"),
        );
        assert_eq!(
            rejection_code(&load_planted(&s, &forged)),
            "KILLSWITCH_RECEIPT_REJECTED"
        );
    }

    // A grammatically perfect rule name for a DIFFERENT scope. Scope
    // re-derivation is what reduces the blast radius from "any rule matching
    // our grammar" to "exactly the one rule this scope maps to".
    #[test]
    fn a_receipt_naming_another_scopes_rule_is_rejected() {
        let mine = scope("all-egress");
        let theirs = scope("tenant-7");
        let other_rule = rule_name_for_scope(&theirs).expect("derive rule name");
        let forged = EnforcementReceipt::new(
            &mine,
            format!("v2;mech=netsh;own=unknown;rule={other_rule}"),
        );
        assert_eq!(
            rejection_code(&load_planted(&mine, &forged)),
            "KILLSWITCH_RECEIPT_REJECTED"
        );
    }

    #[test]
    fn a_receipt_for_another_scope_is_rejected_on_integrity() {
        let mine = scope("all-egress");
        let theirs = scope("tenant-7");
        assert_eq!(
            rejection_code(&load_planted(&mine, &honest_receipt(&theirs))),
            "KILLSWITCH_RECEIPT_INVALID"
        );
    }

    #[test]
    fn a_tampered_receipt_is_rejected_on_integrity() {
        let s = scope("all-egress");
        let mut tampered = honest_receipt(&s);
        // Edit prior_state without rehashing — the case recomputation catches.
        tampered.prior_state =
            "v2;mech=netsh;own=preexisting;rule=SSK-KillSwitch-0011223344556677".to_owned();
        assert_eq!(
            rejection_code(&load_planted(&s, &tampered)),
            "KILLSWITCH_RECEIPT_INVALID"
        );
    }

    // Residual risk 4 of the design: stale pre-P1 receipts must be refused, not
    // migrated. A migration that "helpfully" read the old form would re-open
    // SEC-1 verbatim.
    #[test]
    fn a_pre_p1_v1_receipt_is_refused_not_imported() {
        let s = scope("all-egress");
        let good = rule_name_for_scope(&s).expect("derive rule name");
        let v1 = EnforcementReceipt::new(&s, format!("flowing;rule={good}"));
        assert_eq!(
            rejection_code(&load_planted(&s, &v1)),
            "KILLSWITCH_RECEIPT_REJECTED"
        );
    }

    #[test]
    fn a_receipt_from_a_foreign_mechanism_is_rejected() {
        let s = scope("all-egress");
        let good = rule_name_for_scope(&s).expect("derive rule name");
        let foreign = EnforcementReceipt::new(&s, format!("v2;mech=wfp;own=unknown;rule={good}"));
        assert_eq!(
            rejection_code(&load_planted(&s, &foreign)),
            "KILLSWITCH_RECEIPT_REJECTED"
        );
    }

    #[test]
    fn undecodable_bytes_are_rejected_not_treated_as_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("garbage.json");
        std::fs::write(&path, b"not json at all").expect("write garbage");
        assert_eq!(
            rejection_code(&winhost_load_killswitch_receipt(
                &scope("all-egress"),
                &path
            )),
            "KILLSWITCH_RECEIPT_INVALID"
        );
    }

    // -----------------------------------------------------------------------
    // Receipt storage location
    // -----------------------------------------------------------------------

    #[test]
    fn receipts_never_live_in_the_user_writable_temp_dir() {
        let temp = std::env::temp_dir();
        let killswitch =
            winhost_killswitch_receipt_path(&scope("all-egress")).expect("receipt path");
        assert!(
            !killswitch.starts_with(&temp),
            "kill-switch receipts must not live under {} (SEC-1)",
            temp.display()
        );
        assert!(
            !winhost_service_receipt_path().starts_with(&temp),
            "service install receipts must not live under {} (same class of hole)",
            temp.display()
        );
        assert!(killswitch.starts_with(winhost_store_dir()));
    }

    #[test]
    fn the_store_dir_is_program_data_on_windows() {
        let dir = winhost_store_dir();
        if std::env::var_os("ProgramData").is_some() {
            assert!(dir.ends_with(Path::new("ScorpioSync").join("state")));
        } else {
            assert_eq!(dir, PathBuf::from("/var/lib/scorpiosync/state"));
        }
    }

    #[test]
    fn the_store_dir_is_the_one_definition_winhost_owns() {
        // It used to be re-spelled here, with a comment saying the two "must
        // stay in sync". They cannot drift now.
        assert_eq!(
            winhost_store_dir(),
            ssk_winhost::state_dir::default_state_dir()
        );
        let layout = winhost_store_layout().expect("the default layout must be constructible");
        assert_eq!(layout.leaf(), winhost_store_dir());
        assert_eq!(
            layout.owned().len(),
            2,
            "both ScorpioSync and state are provisioned, not just the leaf"
        );
    }

    // -----------------------------------------------------------------------
    // State-directory refusals reach the operator as typed errors
    // -----------------------------------------------------------------------

    #[test]
    fn a_squat_refusal_says_it_will_not_be_repaired_and_names_the_directory() {
        let refusal = StateDirRefusal::OwnerNotAdministrative {
            path: r"C:\ProgramData\ScorpioSync".to_owned(),
            owner: "S-1-5-21-1-2-3-1001".to_owned(),
        };
        assert!(refusal.is_squat());
        let err = winhost_state_dir_err(&refusal);
        assert_eq!(err.machine_code, "STATE_DIR_UNSAFE");
        assert!(matches!(err.class, ErrorClass::WinHost));
        assert!(
            err.next_steps.iter().any(|s| s.contains("NOT repaired")),
            "an operator must be told the tool deliberately does not fix this: {:?}",
            err.next_steps
        );
        assert!(
            err.next_steps
                .iter()
                .any(|s| s.contains(r"C:\ProgramData\ScorpioSync")),
            "the refusal must name the directory to inspect: {:?}",
            err.next_steps
        );
    }

    #[test]
    fn an_unverifiable_state_dir_is_reported_as_fail_closed_not_as_a_squat() {
        let refusal = StateDirRefusal::ProbeFailed {
            path: r"C:\ProgramData\ScorpioSync".to_owned(),
            reason: "access denied reading the security descriptor".to_owned(),
        };
        assert!(!refusal.is_squat());
        let err = winhost_state_dir_err(&refusal);
        assert_eq!(err.machine_code, "STATE_DIR_UNVERIFIABLE");
        assert!(err.next_steps.iter().any(|s| s.contains("fails closed")));
    }

    /// The elevation refusal must carry the *same* machine code the privileged
    /// broker uses, and must say that nothing was created — otherwise an
    /// operator cannot tell it apart from a partial provisioning.
    #[test]
    fn a_not_elevated_refusal_uses_the_brokers_machine_code() {
        let refusal = StateDirRefusal::NotElevated {
            operation: ssk_winhost::state_dir::PROVISION_OPERATION,
            observed: ssk_winhost::Elevation::NotElevated,
        };
        let err = winhost_state_dir_err(&refusal);
        assert_eq!(err.machine_code, "NOT_ELEVATED");
        assert!(
            err.message.contains("nothing was created"),
            "{}",
            err.message
        );
        assert!(!refusal.is_squat());
        assert!(err
            .next_steps
            .iter()
            .any(|s| s.contains("Administrator") && s.contains("Users:Write")));
    }

    /// `Unknown` must be refused exactly like `NotElevated`: an elevation probe
    /// that cannot answer is not permission.
    #[test]
    fn an_unknown_elevation_is_refused_exactly_like_not_elevated() {
        for observed in [
            ssk_winhost::Elevation::NotElevated,
            ssk_winhost::Elevation::Unknown,
        ] {
            assert!(!observed.permits_system_mutation());
            let err = winhost_state_dir_err(&StateDirRefusal::NotElevated {
                operation: ssk_winhost::state_dir::PROVISION_OPERATION,
                observed,
            });
            assert_eq!(err.machine_code, "NOT_ELEVATED");
        }
    }

    #[test]
    fn deriving_a_receipt_path_creates_nothing() {
        // The read-only verbs must never conjure an unprotected state
        // directory; only the writing paths call `winhost_store_dir_created`.
        let dir = winhost_store_dir();
        let existed = dir.exists();
        let _ = winhost_killswitch_receipt_path(&scope("all-egress")).expect("receipt path");
        let _ = winhost_service_receipt_path();
        assert_eq!(existed, dir.exists(), "path derivation must not touch disk");
    }

    // -----------------------------------------------------------------------
    // Diagnostics honesty (the misleading next-step defect)
    // -----------------------------------------------------------------------

    /// The exact blanket string `winhost_err` used to append to *every* winhost
    /// failure. It is what made the de-DE netsh break look like an elevation
    /// problem (roadmap §1.4).
    const PRE_P1_BLANKET_HINT: &str =
        "Live effects require Windows 11 and an elevated (Administrator) shell.";

    #[test]
    fn winhost_err_appends_no_blanket_elevation_hint() {
        let err = winhost_err("SOME_CODE", "some message", vec![]);
        assert!(
            err.next_steps.is_empty(),
            "the constructor must add nothing of its own; got {:?}",
            err.next_steps
        );
    }

    // The successor of `a_backend_failure_points_at_the_backend_message_not_at_elevation`.
    // The layer moved (the enforcer's typed `BoundaryError` is now produced
    // inside the service and arrives here as `ClientError::Failed`), the
    // property did not: the operator is pointed at the message the privileged
    // layer actually produced, and elevation is never asserted as the cause.
    #[test]
    fn a_service_side_failure_points_at_the_services_message_not_at_elevation() {
        let err = broker_command_err(
            "KILLSWITCH_ENGAGE_FAILED",
            &ClientError::Failed(
                "netsh exited Some(1); the exit code does not distinguish absent from failed"
                    .into(),
            ),
        );
        assert_eq!(err.machine_code, "KILLSWITCH_ENGAGE_FAILED");
        assert_eq!(err.class.exit_code(), 21);
        assert!(
            err.message.contains("netsh exited Some(1)"),
            "the service's own message must be carried through verbatim, got {:?}",
            err.message
        );
        assert!(!err.next_steps.is_empty());
        assert!(
            err.next_steps[0].contains("authoritative"),
            "the first next-step must defer to the typed message, got {:?}",
            err.next_steps[0]
        );
        assert!(
            err.next_steps.iter().all(|s| s != PRE_P1_BLANKET_HINT),
            "the pre-P1 blanket hint must not reappear"
        );
        assert!(
            !err.next_steps.iter().any(|s| s.contains("Administrator")),
            "a service-side enforcement failure says nothing about this shell's elevation; got \
             {:?}",
            err.next_steps
        );
    }

    // The successor of `an_unverified_engage_says_the_receipt_survived`. The
    // obligation is unchanged and is the one that matters: an operator reading
    // a *failure* must be told the engagement happened and can be undone, or
    // they will conclude nothing did and leave the machine severed.
    #[test]
    fn an_unverified_engage_says_the_claim_survived() {
        let err = engage_unverified_err("all-egress", LeaseId([0xab; 16]), "engaged_unconfirmed");
        assert_eq!(err.machine_code, "KILLSWITCH_ENGAGE_UNVERIFIED");
        assert_eq!(err.class.exit_code(), 21);
        assert!(
            err.next_steps[0].contains("WAS taken"),
            "got {:?}",
            err.next_steps[0]
        );
        assert!(err.next_steps.iter().any(|s| s.contains("releasable")));
        assert!(
            err.next_steps
                .iter()
                .any(|s| s.contains(&LeaseId([0xab; 16]).to_hex())),
            "the claim id must be printed, because release needs to name it: {:?}",
            err.next_steps
        );
        assert!(err
            .next_steps
            .iter()
            .any(|s| s.contains("killswitch release")));
    }

    #[test]
    fn a_service_helper_failure_does_not_assert_elevation_first() {
        let steps = service_next_steps(&ServiceError::Helper(
            "refusing to register a LocalSystem service for image path ...".into(),
        ));
        assert!(steps[0].contains("authoritative"));
        assert!(steps.iter().all(|s| s != PRE_P1_BLANKET_HINT));
        assert!(
            steps[1].contains("only if"),
            "the elevation hint must stay conditional, got {:?}",
            steps[1]
        );
    }

    // -----------------------------------------------------------------------
    // The status verdict table
    // -----------------------------------------------------------------------

    fn indeterminate() -> Presence {
        Presence::Indeterminate {
            detail: "netsh show exited Some(1)".into(),
        }
    }

    fn valid_with(ownership: Ownership) -> LoadedReceipt {
        let s = scope("all-egress");
        LoadedReceipt::Valid {
            receipt: honest_receipt(&s),
            prior: PriorState {
                ownership,
                rule_name: rule_name_for_scope(&s).expect("derive rule name"),
            },
        }
    }

    fn rejected() -> LoadedReceipt {
        LoadedReceipt::Invalid {
            code: "KILLSWITCH_RECEIPT_REJECTED",
            detail: "planted".into(),
        }
    }

    #[test]
    fn the_verdict_table_covers_the_receipt_times_presence_cross_product() {
        let cases: Vec<(LoadedReceipt, Presence, &str)> = vec![
            (valid_with(Ownership::Unknown), Presence::Present, "engaged"),
            (
                valid_with(Ownership::Preexisting),
                Presence::Present,
                "engaged_not_ours",
            ),
            (
                valid_with(Ownership::Unknown),
                Presence::Absent,
                "inconsistent",
            ),
            (
                valid_with(Ownership::Unknown),
                indeterminate(),
                "engaged_unconfirmed",
            ),
            (
                LoadedReceipt::Missing,
                Presence::Present,
                "engaged_receipt_lost",
            ),
            (LoadedReceipt::Missing, Presence::Absent, "armed"),
            (LoadedReceipt::Missing, indeterminate(), "unknown"),
            (
                rejected(),
                Presence::Present,
                "receipt_rejected_and_engaged",
            ),
            (rejected(), indeterminate(), "receipt_rejected"),
        ];
        for (loaded, presence, expected) in cases {
            let (verdict, detail, _) = killswitch_verdict(&loaded, &presence, "all-egress");
            assert_eq!(verdict, expected, "detail was: {detail}");
            assert!(!detail.is_empty(), "{expected} must explain itself");
        }
    }

    // An unobservable rule is never reported as an absent one: that collapse is
    // how a kill-switch comes to claim restored egress it never restored.
    #[test]
    fn an_unobservable_rule_is_not_reported_as_absent() {
        assert_eq!(winhost_presence_token(&Presence::Absent).0, "absent");
        assert_eq!(winhost_presence_token(&Presence::Present).0, "present");
        let (token, detail) = winhost_presence_token(&indeterminate());
        assert_eq!(token, "indeterminate");
        assert!(!detail.is_empty());

        let (verdict, _, _) =
            killswitch_verdict(&LoadedReceipt::Missing, &indeterminate(), "all-egress");
        assert_ne!(
            verdict, "armed",
            "an indeterminate probe must not read as 'nothing is severed'"
        );
    }

    // -----------------------------------------------------------------------
    // Service install receipt
    // -----------------------------------------------------------------------

    #[test]
    fn an_install_receipt_for_another_host_is_rejected() {
        let manifest = winhost_manifest();
        let other = HostManifest::new("other-host", "9.9.9", "windows", ["x"]);
        let receipt = InstallReceipt::new(other.host_id, ServiceState::Uninstalled);
        let err = winhost_verify_install_receipt(&receipt, &manifest)
            .expect_err("a receipt for another host must be refused");
        assert!(err.contains("but this build's host id is"), "{err}");
    }

    #[test]
    fn a_tampered_install_receipt_is_rejected() {
        let manifest = winhost_manifest();
        let mut receipt = InstallReceipt::new(manifest.host_id, ServiceState::Uninstalled);
        // Flip "we created it" to "it already existed" without rehashing: this
        // would otherwise turn a real deletion into a silent no-op.
        receipt.prior_state = ServiceState::Installed.as_str().to_owned();
        let err = winhost_verify_install_receipt(&receipt, &manifest)
            .expect_err("a rehashless edit must be refused");
        assert!(err.contains("receipt_id does not match"), "{err}");
    }

    #[test]
    fn an_install_receipt_with_an_unknown_prior_state_is_rejected() {
        let manifest = winhost_manifest();
        let mut receipt = InstallReceipt::new(manifest.host_id, ServiceState::Uninstalled);
        receipt.prior_state = "running".to_owned();
        assert!(winhost_verify_install_receipt(&receipt, &manifest).is_err());
    }

    #[test]
    fn an_honest_install_receipt_round_trips_both_prior_states() {
        let manifest = winhost_manifest();
        for state in [ServiceState::Uninstalled, ServiceState::Installed] {
            let receipt = InstallReceipt::new(manifest.host_id, state);
            assert_eq!(
                winhost_verify_install_receipt(&receipt, &manifest).expect("honest receipt"),
                state
            );
        }
    }

    /// Why gate 0 is not optional hardening on the uninstall path.
    ///
    /// `a_tampered_install_receipt_is_rejected` covers the *rehashless* edit.
    /// This covers the edit an attacker would actually make: flip `prior_state`
    /// **and** recompute `receipt_id`. `host_id` is not free — it is re-derived
    /// from this build's manifest — but everything else about that receipt is
    /// well formed, so the byte-level check accepts it, exactly as it should:
    /// the digest is unkeyed and there is nothing left for it to catch.
    ///
    /// The assertion here is therefore not "this is rejected" — it is that both
    /// flips are accepted, i.e. that the byte checks cannot be the control, and
    /// [`winhost_receipt_store_gate`] running first is what denies the write in
    /// the first place. Pinning this stops the check being mistaken for a
    /// forgery defence again.
    #[test]
    fn a_rehashed_prior_state_flip_passes_the_byte_checks_so_gate_zero_is_the_control() {
        let manifest = winhost_manifest();
        for flipped in [ServiceState::Installed, ServiceState::Uninstalled] {
            // What a store-write attacker produces: consistent, self-hashed,
            // bound to this host — and chosen by them.
            let forged = InstallReceipt::new(manifest.host_id, flipped);
            assert_eq!(
                winhost_verify_install_receipt(&forged, &manifest)
                    .expect("a well-formed receipt passes the byte checks by construction"),
                flipped,
                "the unkeyed digest cannot distinguish a forged prior_state from an honest one"
            );
        }
    }

    /// The file `winhost_service_uninstall` reads must sit inside the directory
    /// gate 0 verifies. If it ever moved out from under the layout leaf, that
    /// gate would still run, still pass, and protect nothing — which is the
    /// shape of the bug being fixed, one level up.
    #[test]
    fn the_install_receipt_lives_inside_the_directory_gate_zero_verifies() {
        let layout = winhost_store_layout().expect("the default layout must be constructible");
        assert_eq!(
            winhost_service_receipt_path().parent(),
            Some(layout.leaf()),
            "the install receipt must live in the verified leaf, not merely near it"
        );
        let killswitch =
            winhost_killswitch_receipt_path(&scope("all-egress")).expect("receipt path");
        assert_eq!(
            killswitch.parent(),
            Some(layout.leaf()),
            "both receipt kinds are covered by the one gate"
        );
    }

    /// The store gate must run **before** the read, not merely near it.
    ///
    /// This is the test the earlier passes lacked: a mutation that deleted the
    /// gate call from `winhost_service_uninstall` left the entire suite green,
    /// because on this machine the real store is `Absent`, so the real gate
    /// passes and no assertion could tell the difference. Injecting a *failing*
    /// gate is what gives the property teeth — and pointing it at a file that
    /// genuinely exists is what proves the read did not happen anyway.
    #[test]
    fn the_store_gate_precedes_the_read_and_the_file_is_not_touched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("receipt.json");
        std::fs::write(&path, br#"{"would":"be readable"}"#).expect("write");
        assert!(
            path.exists(),
            "the fixture must exist for this to prove anything"
        );

        let refusal = || {
            Err(AppError::new(
                ErrorClass::WinHost,
                "STATE_DIR_UNSAFE",
                "injected refusal".to_owned(),
                vec![],
            ))
        };

        match winhost_read_receipt_bytes_with(&path, refusal) {
            ReceiptBytes::StoreUnsafe(e) => assert_eq!(e.machine_code, "STATE_DIR_UNSAFE"),
            ReceiptBytes::Read(_) => panic!(
                "the gate was bypassed: readable bytes were returned from a store that refused"
            ),
            _ => panic!("expected StoreUnsafe from a refusing gate"),
        }

        // Control: the same path with a passing gate must reach the bytes, so
        // the assertion above cannot pass for the wrong reason (e.g. an
        // unreadable fixture).
        match winhost_read_receipt_bytes_with(&path, || Ok(())) {
            ReceiptBytes::Read(bytes) => assert_eq!(bytes, br#"{"would":"be readable"}"#),
            _ => panic!("a passing gate must reach the bytes"),
        }
    }

    /// `install` and `uninstall` must address the same file, or uninstall
    /// silently finds nothing and skips the rollback.
    ///
    /// This asserts the property that can actually drift. The file name cannot:
    /// both call sites go through [`winhost_service_receipt_path_in`], so
    /// asserting *that* would be a tautology. What can drift is the directory —
    /// `install` uses the provisioning [`winhost_store_dir_created`], `uninstall`
    /// the plain [`winhost_store_dir`]. So drive the shared constructor with both
    /// store dirs the binary knows and require identical results.
    ///
    /// `winhost_store_dir_created()` is not callable here (it provisions, and
    /// would need elevation), so its leaf-return contract is pinned on the
    /// `ssk-winhost` side instead — see `SERVICE_RECEIPT_FILE`'s doc.
    #[test]
    fn install_and_uninstall_address_the_same_receipt_file() {
        let layout = winhost_store_layout().expect("layout");

        // The reader's path, and the writer's path with the directory its
        // provisioning call is contracted to return.
        let reader = winhost_service_receipt_path();
        let writer = winhost_service_receipt_path_in(layout.leaf());

        assert_eq!(
            reader, writer,
            "install and uninstall must resolve to one file; if this fails, an \
             uninstall will not find the receipt install wrote and will skip \
             the service rollback"
        );
    }

    // -----------------------------------------------------------------------
    // P3: the CLI drives the privileged service and actuates nothing itself
    // -----------------------------------------------------------------------

    /// Build an authoritative status without a service, a pipe or a firewall.
    fn status_of(
        state: KillSwitchState,
        os_rule_present: Option<bool>,
        recovery: Recovery,
    ) -> KillSwitchStatus {
        KillSwitchStatus {
            logical_state: state,
            receipt: None,
            os_rule_present,
            audit_head: ssk_types::Digest::GENESIS,
            audit_len: 0,
            state_version: 7,
            recovery,
        }
    }

    /// **The anti-fallback guard.**
    ///
    /// P3's requirement is not "the happy path goes through the service", it is
    /// "there is no other path". A single surviving direct enforcer call in an
    /// error branch would reintroduce an unauthenticated, unaudited actuator
    /// reachable exactly when the authorization gate is unreachable — and no
    /// behavioural test would notice, because that branch is only taken on a
    /// machine where the service is down.
    ///
    /// So this asserts it structurally, over this file's own source. The needles
    /// are assembled with `concat!` so that the test's own text does not satisfy
    /// the search it performs.
    #[test]
    fn the_cli_contains_no_call_that_actuates_the_firewall() {
        let source = include_str!("main.rs");
        for needle in [
            concat!("engage", "_report("),
            concat!("release", "_scoped("),
            concat!("release", "_reporting("),
            concat!(".eng", "age(&scope"),
            concat!("enforcer", ".recover("),
        ] {
            assert!(
                !source.contains(needle),
                "`{needle}` is back in ssk-cli. Every privileged boundary effect belongs to the \
                 LocalSystem service; a CLI-side actuator bypasses peer authorization, the \
                 op-lock, the version gate and the hash-chained audit."
            );
        }
    }

    /// The complement of the guard above: the one Windows firewall backend this
    /// binary may still construct, and the only two things it may ask of it.
    ///
    /// Both are reads. `mechanism()` names the selected mechanism, and
    /// `observe()` runs `netsh advfirewall firewall show rule`, measured to
    /// need no elevation. If a third construction site appears, this fails and
    /// whoever added it has to justify it here.
    #[test]
    fn the_only_surviving_firewall_backend_uses_are_two_reads() {
        let source = include_str!("main.rs");
        let sites = source
            .matches(concat!("WindowsFirewall", "Enforcer::new()"))
            .count();
        assert_eq!(
            sites, 2,
            "expected exactly two constructions — `doctor`'s `mechanism()` and \
             `winhost_local_advisory_observation`'s `observe()`, both reads. Found {sites}. A \
             third site is a privileged action this binary must not perform; prose must spell \
             the type without `::new()` so this stays a count of call sites."
        );
    }

    /// The service's `Broker` is never constructed here. `ssk-cli` depends on
    /// `ssk-netd-helper` for its *client* surface only; constructing a broker
    /// in an unprivileged process would put the privileged security core inside
    /// the thing it exists to keep out.
    #[test]
    fn the_cli_never_constructs_a_broker() {
        let source = include_str!("main.rs");
        for needle in [
            concat!("Bro", "ker::recover"),
            concat!("Bro", "ker::recover_privileged"),
        ] {
            assert!(
                !source.contains(needle),
                "`{needle}` appeared in ssk-cli; the broker is hosted by the LocalSystem service"
            );
        }
    }

    // --- the claim id -------------------------------------------------------

    #[test]
    fn a_claim_id_round_trips_through_exactly_what_engage_prints() {
        let id = LeaseId([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ]);
        assert_eq!(parse_lease_id(&id.to_hex()).expect("round trip"), id);
    }

    #[test]
    fn a_claim_id_parser_accepts_nothing_but_32_lowercase_hex_characters() {
        let good = LeaseId([0x5a; 16]).to_hex();
        for bad in [
            String::new(),
            "0".repeat(31),
            "0".repeat(33),
            good.to_uppercase(),
            format!("0x{}", &good[2..]),
            format!("{} ", &good[..31]),
            "z".repeat(32),
        ] {
            assert!(
                parse_lease_id(&bad).is_err(),
                "`{bad}` must not parse as a claim id"
            );
        }
        assert!(parse_lease_id(&good).is_ok());
    }

    /// A hint path is derived, never guessed, and deriving it touches no disk.
    #[test]
    fn a_claim_hint_path_is_scope_digest_keyed_and_creates_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mine = lease_hint_path_in(dir.path(), &scope("all-egress")).expect("path");
        let theirs = lease_hint_path_in(dir.path(), &scope("other-scope")).expect("path");
        assert_ne!(
            mine, theirs,
            "two scopes must never share a hint file; one would silently overwrite the other's \
             claim id"
        );
        assert!(mine.starts_with(dir.path()));
        assert!(!mine.exists(), "deriving a path must not create it");
        assert_eq!(
            std::fs::read_dir(dir.path())
                .expect("read dir")
                .flatten()
                .count(),
            0
        );
    }

    /// A planted hint cannot do anything but fail: it carries a claim id and
    /// nothing else, and this build refuses everything that is not one.
    #[test]
    fn a_planted_claim_hint_is_refused_by_the_parser_not_acted_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = lease_hint_path_in(dir.path(), &scope("all-egress")).expect("path");
        for planted in [
            "name=all",
            "../../../../windows/system32",
            "S-1-5-18",
            "SSK-KillSwitch-allegress-1f8609f29d697ab0",
        ] {
            std::fs::write(&path, planted).expect("plant");
            assert!(
                parse_lease_id(std::fs::read_to_string(&path).expect("read").trim()).is_err(),
                "`{planted}` must not parse as a claim id"
            );
        }
    }

    // --- the authoritative verdict -----------------------------------------

    /// The whole (journal x observation x recovery) cross product, decided
    /// without a service and without a firewall.
    #[test]
    fn the_authoritative_verdict_covers_the_cross_product() {
        let cases: Vec<(KillSwitchStatus, &str)> = vec![
            (
                status_of(KillSwitchState::Engaged, Some(true), Recovery::Consistent),
                "engaged",
            ),
            (
                status_of(KillSwitchState::Engaged, Some(true), Recovery::Reconciled),
                "engaged",
            ),
            (
                status_of(KillSwitchState::Engaged, None, Recovery::Consistent),
                "engaged_unconfirmed",
            ),
            (
                status_of(KillSwitchState::Engaged, None, Recovery::Inconsistent),
                "inconsistent",
            ),
            (
                status_of(
                    KillSwitchState::Engaged,
                    Some(false),
                    Recovery::Inconsistent,
                ),
                "inconsistent",
            ),
            (
                status_of(KillSwitchState::Armed, None, Recovery::Consistent),
                "not_engaged",
            ),
            (
                status_of(KillSwitchState::Released, None, Recovery::Consistent),
                "not_engaged",
            ),
            (
                status_of(KillSwitchState::Armed, Some(true), Recovery::Consistent),
                "not_engaged_rule_present",
            ),
            (
                status_of(KillSwitchState::Armed, Some(true), Recovery::Inconsistent),
                "inconsistent",
            ),
        ];
        for (status, expected) in cases {
            let (verdict, detail) = broker_verdict(&status);
            assert_eq!(verdict, expected, "detail was: {detail}");
            assert!(!detail.is_empty(), "{expected} must explain itself");
        }
    }

    /// The single most important asymmetry: an engagement the service cannot
    /// confirm is never reported as protection, and is never reported as
    /// restored egress either.
    #[test]
    fn an_unconfirmable_engagement_is_neither_protection_nor_restored_egress() {
        let (verdict, detail) = broker_verdict(&status_of(
            KillSwitchState::Engaged,
            None,
            Recovery::Consistent,
        ));
        assert_ne!(verdict, "engaged", "an unconfirmed rule is not protection");
        assert_ne!(verdict, "not_engaged", "and it is not restored egress");
        assert!(detail.contains("NOT evidence that egress is flowing"));
    }

    /// `Inconsistent` outranks every clean state. The service raises it when
    /// its journal and its observation disagree, or when it believes egress is
    /// severed and could not confirm it; softening that into `engaged` or
    /// `not_engaged` is how an alarm becomes invisible.
    #[test]
    fn the_inconsistent_alarm_outranks_every_clean_state() {
        for state in [
            KillSwitchState::Armed,
            KillSwitchState::Engaged,
            KillSwitchState::Released,
        ] {
            for observed in [None, Some(true), Some(false)] {
                let status = status_of(state, observed, Recovery::Inconsistent);
                assert!(status.is_alarm());
                assert_eq!(
                    broker_verdict(&status).0,
                    "inconsistent",
                    "{state:?}/{observed:?} must not soften the alarm"
                );
            }
        }
    }

    #[test]
    fn an_unknown_observation_is_rendered_as_null_never_as_false() {
        let json = broker_status_json(&status_of(
            KillSwitchState::Armed,
            None,
            Recovery::Consistent,
        ));
        assert_eq!(json["authoritative"], serde_json::json!(true));
        assert!(
            json["os_rule_present"].is_null(),
            "`cannot determine` must stay null; rendering it as `false` is how a machine that \
             might be severed reports as flowing"
        );
        assert_eq!(json["state_version"], serde_json::json!(7));
        assert_eq!(json["recovery"], serde_json::json!("consistent"));
    }

    /// A release is only a *success* when the service's journal no longer
    /// severs egress, and only a *confirmed removal* when the service also
    /// observed the rule gone. Collapsing the two would either report an
    /// unconfirmed removal as proven (the direction that gets a user shot) or
    /// fail every release on the netsh mechanism, which cannot report absence.
    #[test]
    fn a_release_reports_the_journal_and_the_observation_separately() {
        // The normal netsh result: journal released, removal unconfirmed.
        assert_eq!(
            release_outcome(&status_of(
                KillSwitchState::Released,
                None,
                Recovery::Consistent
            )),
            (true, false)
        );
        // What a negative-capable probe would give.
        assert_eq!(
            release_outcome(&status_of(
                KillSwitchState::Released,
                Some(false),
                Recovery::Consistent
            )),
            (true, true)
        );
        // Still engaged: neither.
        assert_eq!(
            release_outcome(&status_of(
                KillSwitchState::Engaged,
                Some(true),
                Recovery::Consistent
            )),
            (false, false)
        );
        // Released journal but a rule still observed present, and the alarm:
        // both refuse to report a release at all.
        assert_eq!(
            release_outcome(&status_of(
                KillSwitchState::Released,
                Some(true),
                Recovery::Consistent
            )),
            (false, false)
        );
        assert_eq!(
            release_outcome(&status_of(
                KillSwitchState::Released,
                Some(false),
                Recovery::Inconsistent
            )),
            (false, false)
        );
    }

    #[test]
    fn recovery_tokens_are_stable_and_distinct() {
        let tokens = [
            recovery_token(Recovery::Consistent),
            recovery_token(Recovery::Reconciled),
            recovery_token(Recovery::Inconsistent),
        ];
        assert_eq!(tokens, ["consistent", "reconciled", "inconsistent"]);
    }

    // --- the scope note -----------------------------------------------------

    #[test]
    fn a_scope_that_is_not_the_services_scope_is_reported_not_silently_accepted() {
        let mut status = status_of(KillSwitchState::Engaged, Some(true), Recovery::Consistent);
        status.receipt = Some(honest_receipt(&scope("all-egress")));
        assert!(scope_mismatch_note(&status, "all-egress").is_none());
        let note = scope_mismatch_note(&status, "something-else").expect("a mismatch is reported");
        assert!(note.contains("all-egress"), "{note}");
        assert!(note.contains("something-else"), "{note}");
        // Not established while nothing is engaged: the status carries the
        // scope label only inside the held receipt. Saying nothing is the
        // honest answer, and it is what happens.
        assert!(scope_mismatch_note(
            &status_of(KillSwitchState::Armed, None, Recovery::Consistent),
            "something-else"
        )
        .is_none());
    }

    // --- the error contract -------------------------------------------------

    /// Every kill-switch failure keeps class `WinHost` -> exit 21, exactly as
    /// before P3, and every one of them carries at least one next step.
    #[test]
    fn every_broker_failure_keeps_the_pre_p3_exit_code_and_is_actionable() {
        let errors = vec![
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Failed("boom".into()),
            ),
            broker_command_err(
                "KILLSWITCH_RELEASE_FAILED",
                &ClientError::Rejected(RejectReason::PeerUnauthorized {
                    code: "PEER_NOT_GRANTED".into(),
                    detail: "S-1-5-21-1 holds no grant for release_kill_switch".into(),
                }),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Rejected(RejectReason::Unauthorized),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Rejected(RejectReason::StaleVersion {
                    expected: 1,
                    actual: 4,
                }),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Rejected(RejectReason::ReplayedNonce),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Rejected(RejectReason::BadToken),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Refused(HandshakeReject::AtCapacity),
            ),
            broker_command_err(
                "KILLSWITCH_RELEASE_FAILED",
                &ClientError::Refused(HandshakeReject::LeaseUnavailable("no claim".into())),
            ),
            broker_command_err(
                "KILLSWITCH_ENGAGE_FAILED",
                &ClientError::Protocol("second hello".into()),
            ),
        ];
        for err in &errors {
            assert_eq!(
                err.class.exit_code(),
                21,
                "{} changed the kill-switch exit code",
                err.machine_code
            );
            assert!(
                !err.next_steps.is_empty(),
                "{} must be actionable",
                err.machine_code
            );
            assert!(!err.message.is_empty());
        }
    }

    /// The two conditions that must never be conflated, because they tell an
    /// operator to fix different things: *this caller* is not on the
    /// allow-list, versus *the service itself* was deployed without a grant.
    #[test]
    fn a_refused_caller_and_an_unauthorized_service_are_different_errors() {
        let caller = broker_command_err(
            "KILLSWITCH_ENGAGE_FAILED",
            &ClientError::Rejected(RejectReason::PeerUnauthorized {
                code: "PEER_NOT_GRANTED".into(),
                detail: "no grant".into(),
            }),
        );
        let service = broker_command_err(
            "KILLSWITCH_ENGAGE_FAILED",
            &ClientError::Rejected(RejectReason::Unauthorized),
        );
        assert_eq!(caller.machine_code, "KILLSWITCH_PEER_UNAUTHORIZED");
        assert_eq!(service.machine_code, "KILLSWITCH_BROKER_UNAUTHORIZED");
        assert_ne!(caller.machine_code, service.machine_code);
        assert!(caller.next_steps.iter().any(|s| s.contains("authz.json")));
        assert!(service
            .next_steps
            .iter()
            .any(|s| s.contains("deployment fault")));
    }

    /// A lost reply must never be rendered as "nothing happened". The request
    /// was delivered; only the answer was not.
    #[test]
    fn a_lost_reply_does_not_claim_the_command_had_no_effect() {
        let err = broker_command_err(
            "KILLSWITCH_ENGAGE_FAILED",
            &ClientError::Frame(ssk_netd_helper::FrameError::Transport(
                ssk_netd_helper::TransportError::Closed,
            )),
        );
        assert_eq!(err.machine_code, "KILLSWITCH_BROKER_TRANSPORT_FAILED");
        assert!(
            err.next_steps[0].contains("NOT established"),
            "got {:?}",
            err.next_steps[0]
        );
        assert!(!err
            .next_steps
            .iter()
            .any(|s| s.contains("Nothing was actuated")));
    }

    /// The broker-absent guidance is the message a stock machine actually
    /// prints, and it has one job beyond naming the fix: saying out loud that
    /// no fallback happened.
    #[cfg(windows)]
    #[test]
    fn the_broker_absent_guidance_names_the_fix_and_denies_a_fallback() {
        let steps = broker_absent_next_steps();
        assert!(steps.iter().any(|s| s.contains("service install")));
        assert!(steps.iter().any(|s| s.contains("service start")));
        assert!(steps.iter().any(|s| s.contains("doctor")));
        let disclaimer = steps
            .iter()
            .find(|s| s.contains("Nothing was actuated"))
            .expect("the no-fallback statement must be present");
        assert!(disclaimer.contains("does NOT fall back"), "{disclaimer}");
    }

    /// No kill-switch failure may tell the operator to reach for netsh unless a
    /// rule was actually *observed present* — which only `recover` can
    /// establish, and which it does before saying so.
    #[test]
    fn no_broker_failure_hands_the_operator_a_raw_firewall_command() {
        let errs = [
            broker_command_err("KILLSWITCH_ENGAGE_FAILED", &ClientError::Failed("x".into())),
            broker_command_err(
                "KILLSWITCH_RELEASE_FAILED",
                &ClientError::Rejected(RejectReason::BadToken),
            ),
        ];
        for err in &errs {
            for step in &err.next_steps {
                assert!(
                    !step.contains("netsh advfirewall firewall delete"),
                    "{}: a generic failure must not suggest hand-deleting a rule that may not \
                     exist; got {step:?}",
                    err.machine_code
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_three_connect_failures_are_told_apart_by_evidence_not_by_text() {
        let absent = broker_transport_err(&std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(absent.machine_code, "KILLSWITCH_BROKER_UNREACHABLE");
        assert!(absent.message.contains("not running"));

        // What `require_pipe_owner` produces: a synthesized PermissionDenied
        // with no OS errno.
        let squatted = broker_transport_err(&std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing the privileged endpoint: owner is S-1-5-21-1, expected S-1-5-18",
        ));
        assert_eq!(squatted.machine_code, "KILLSWITCH_BROKER_NOT_SYSTEM_OWNED");
        assert!(
            squatted.message.contains("Nothing was sent to it"),
            "a squatted endpoint must state that no frame was written: {}",
            squatted.message
        );

        // What the kernel's access check produces: ERROR_ACCESS_DENIED.
        let denied = broker_transport_err(&std::io::Error::from_raw_os_error(5));
        assert_eq!(denied.machine_code, "KILLSWITCH_BROKER_ACCESS_DENIED");

        for err in [&absent, &squatted, &denied] {
            assert_eq!(err.class.exit_code(), 21);
            assert!(!err.next_steps.is_empty());
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn off_windows_the_kill_switch_refuses_rather_than_reporting_a_clean_machine() {
        let err = broker_open(ClientHello::new(LeaseKind::Session))
            .err()
            .expect("there is no privileged control plane off Windows");
        assert_eq!(err.machine_code, "KILLSWITCH_BROKER_UNSUPPORTED");
        assert_eq!(err.class.exit_code(), 21);
        assert!(err
            .next_steps
            .iter()
            .any(|s| s.contains("does NOT fall back")));
    }

    #[test]
    fn the_endpoint_is_named_on_every_platform_so_doctor_can_print_it() {
        let name = privileged_endpoint_name();
        assert!(!name.is_empty());
        #[cfg(windows)]
        assert_eq!(name, ssk_winhost::PRIVILEGED_PIPE_NAME);
    }

    // --- nonces -------------------------------------------------------------

    /// A repeated nonce is rejected by the service as a replay, which denies
    /// service to the legitimate caller. Distinctness must therefore not depend
    /// on any single CSPRNG draw succeeding — the counter is mixed in
    /// unconditionally.
    #[test]
    fn nonces_are_distinct_even_if_every_draw_after_the_seed_failed() {
        let mut source = CsprngNonces {
            seed: [0x42; 16],
            counter: 0,
        };
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            assert!(
                seen.insert(source.next()),
                "a repeated nonce is rejected by the service as a replay"
            );
        }
        // The same again with the CSPRNG's contribution held constant, which is
        // exactly the degraded path: only the counter distinguishes them.
        let mut degraded = CsprngNonces {
            seed: [0x42; 16],
            counter: 0,
        };
        let mut manual = std::collections::BTreeSet::new();
        for i in 1..=256u64 {
            let mut out = degraded.seed;
            let tail = u64::from_be_bytes(out[8..].try_into().expect("8 bytes")) ^ i;
            out[8..].copy_from_slice(&tail.to_be_bytes());
            assert!(
                manual.insert(out),
                "the degraded derivation must not repeat"
            );
        }
        let _ = degraded.next();
    }

    #[test]
    fn the_nonce_source_seeds_from_this_machines_csprng() {
        let mut a = CsprngNonces::new().expect("the OS CSPRNG must seed the nonce source");
        let mut b = CsprngNonces::new().expect("seed");
        assert_ne!(
            a.next(),
            b.next(),
            "two independently seeded sources drawing their first nonce must not collide"
        );
    }

    // --- the advisory path --------------------------------------------------

    /// The advisory verdict is reachable only when there is no authoritative
    /// answer, and it never claims to be one. This pins the labelling that goes
    /// with it, because the whole risk of keeping a local probe is that someone
    /// reads it as the answer.
    #[test]
    fn the_local_advisory_never_presents_itself_as_authoritative() {
        let (verdict, detail, steps) = killswitch_verdict(
            &LoadedReceipt::Missing,
            &Presence::Indeterminate {
                detail: "netsh show exited Some(1)".into(),
            },
            "all-egress",
        );
        assert_eq!(verdict, "unknown");
        assert!(!detail.is_empty());
        // The advisory must not offer a privileged action, because this binary
        // has none to offer.
        for step in &steps {
            assert!(
                !step.contains("killswitch recover --scope all-egress --yes"),
                "the advisory must not offer the deleted `recover --yes` path: {step}"
            );
        }
    }

    /// A pre-broker receipt is reported as a migration finding and nothing
    /// more — and a refused one is reported as refused rather than being
    /// silently skipped.
    #[test]
    fn a_pre_broker_receipt_is_reported_but_never_acted_on() {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = scope("all-egress");
        let path = dir.path().join("killswitch-legacy.json");

        assert!(
            winhost_legacy_receipt_note(&s, &path).is_none(),
            "no file, nothing to say"
        );

        std::fs::write(&path, b"not json at all").expect("plant");
        let note = winhost_legacy_receipt_note(&s, &path);
        // On a machine whose state directory gate refuses (or where the gate
        // passes), the note is either the refusal or `None` if gate 0 stopped
        // the read. Either way it must never claim the receipt is usable.
        if let Some(note) = note {
            assert!(
                note.contains("REFUSED") || note.contains("pre-broker"),
                "got {note}"
            );
            assert!(
                !note.contains("release"),
                "a migration note must not point at a verb that would act on it: {note}"
            );
        }
    }
}
