#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use serde::Serialize;
use ssk_faultscan::{run_playbook, ChaosFaultKind};
use ssk_gates::GateVector;
use ssk_interop::{Blake3KeyedVerifier, CompatibilityPolicy, ConformanceSuite};
use ssk_locator::StaticLocatorPool;
use ssk_netadmin::{
    audit::{AuditLedger, AuditOutcome},
    flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel},
    policy::{MatchCriteria, PolicyAction, PolicyEngine, PolicyRule},
    route::{AdapterRegistryEntry, RouteOrchestrator},
    session::SessionLedger,
};
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, DeterminismContext, Runtime, RuntimeEvent, RuntimeMetrics};
use ssk_tensor::{FileLedgerBackend, LedgerBackend, MemoryBackend};
use ssk_types::{GateId, GateOutcomeKind, LocatorId, ReplayVerdict};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(name = "ssk")]
#[command(about = "ScorpioSync-Kaleidoscorp Omega runtime CLI")]
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

/// Connect to `sskd` over its Unix socket, issue one request, and return its
/// response. Spins up a lightweight current-thread Tokio runtime for the
/// single call rather than making the whole `ssk` binary async — `run` /
/// `replay-verify` / `doctor` / etc. stay fully synchronous and local.
fn call_daemon(req: ssk_ipc::Request) -> Result<ssk_ipc::Response, AppError> {
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
    rt.block_on(async {
        let mut client = ssk_ipc::client::UnixClient::connect(ssk_ipc::paths::socket_path())
            .await
            .map_err(AppError::from)?;
        client.call(req).await.map_err(AppError::from)
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            emit_error(&err, cli.json);
            ExitCode::from(err.class.exit_code())
        }
    }
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
        Command::ListProfiles => list_profiles_command(cli.json),
    }
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

fn check_entropy() -> DoctorCheck {
    let mut buf = [0_u8; 8];
    let result = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut buf))
        .map(|_| !buf.iter().all(|b| *b == 0));

    match result {
        Ok(true) => DoctorCheck {
            name: "entropy",
            ok: true,
            detail: "entropy source /dev/urandom readable".into(),
            next_step: "No action required.".into(),
        },
        _ => DoctorCheck {
            name: "entropy",
            ok: false,
            detail: "failed to sample /dev/urandom".into(),
            next_step: "Ensure OS entropy source is available before production workloads.".into(),
        },
    }
}

fn check_paths() -> DoctorCheck {
    match std::env::current_dir() {
        Ok(dir) => DoctorCheck {
            name: "paths",
            ok: dir.exists(),
            detail: format!("cwd={}", dir.display()),
            next_step: "Run from a valid workspace directory with expected files.".into(),
        },
        Err(err) => DoctorCheck {
            name: "paths",
            ok: false,
            detail: err.to_string(),
            next_step: "Fix working directory path resolution and rerun.".into(),
        },
    }
}

fn check_permissions() -> DoctorCheck {
    let dir = PathBuf::from(".ssk");
    let check_file = dir.join("doctor-permission-check.tmp");
    let ok = std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(&check_file, b"ok"))
        .and_then(|_| std::fs::remove_file(&check_file))
        .is_ok();

    DoctorCheck {
        name: "permissions",
        ok,
        detail: format!("write check in {}", dir.display()),
        next_step: "Grant write permissions for config/metrics/runtime output paths.".into(),
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
}
