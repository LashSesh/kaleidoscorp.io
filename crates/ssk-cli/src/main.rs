#![forbid(unsafe_code)]

use clap::{Parser, Subcommand};
use serde::Serialize;
use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, DeterminismContext, Runtime, RuntimeEvent, RuntimeMetrics};
use ssk_tensor::{FileLedgerBackend, LedgerBackend, MemoryBackend};
use ssk_types::{GateId, Locator, LocatorId, LocatorType, ReplayVerdict};
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
        Command::VerifyLedger { path } => verify_ledger_command(path, cli.json),
        Command::Doctor { ledger_path } => doctor_command(ledger_path.as_deref(), cli),
        Command::Explain { target } => explain_command(target, cli.json),
        Command::Config { command } => config_command(command, cli.json),
    }
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
    let (expected, _) = runtime
        .run_once_with_context(sample_intent(valid_fixture), &pool, &determinism)
        .map_err(|err| {
            AppError::new(
                ErrorClass::Runtime,
                "RUNTIME_REPLAY_EXPECTED_FAILED",
                err.to_string(),
                vec!["Inspect run setup and replay inputs.".into()],
            )
        })?;

    let engine = DeterministicReplayEngine;
    let verdict = engine.replay(&manifest, &actual, &expected);

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

fn default_pool() -> LocatorPool {
    LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
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
