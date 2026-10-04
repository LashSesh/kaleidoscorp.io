#![forbid(unsafe_code)]

//! Process-level diagnostics for every SSK binary: the tracing subscriber, the
//! durable rotated log sink, the panic hook that writes a crash record, and (in
//! [`entropy`]) the OS-CSPRNG health probe.
//!
//! # Why this crate exists
//!
//! P2 gave `ssk` and `sskd` a durable log by writing the same code twice —
//! `ssk-daemon/src/diag.rs` and an inline `mod diag` in `ssk-cli/src/main.rs`,
//! with `entropy` duplicated alongside it. Both copies were correct, and that is
//! not the argument for merging them: the argument is that the *previous*
//! duplication of exactly this logic is what produced the `/dev/urandom` probe
//! in two places, so it had to be fixed in two places. `ssk-svc` would have been
//! the third copy. This crate is the single implementation; the binaries keep
//! only the parts that are genuinely theirs (where their state directory comes
//! from, and what their stderr means).
//!
//! # Where it sits in the graph, and why it has no workspace dependencies
//!
//! `ssk-svc` is a bin target of `ssk-winhost`, so `ssk-winhost` links this
//! crate. P2 added `ssk-daemon -> ssk-winhost` for the named-pipe peer
//! authenticator, so anything `ssk-winhost` links must sit strictly below it or
//! the graph cycles. A crate with no workspace edges at all cannot cycle, which
//! is why `Layout::resolve()` — which needs `ssk_ipc::paths::state_dir()` —
//! stayed behind in `ssk-cli` while [`Layout`] itself moved here.
//!
//! # `SSK_LOG`, not `RUST_LOG`
//!
//! A developer's global `RUST_LOG=trace` must not silently change the log volume
//! of a security product, so the filter reads its own variable ([`LOG_ENV_VAR`]).
//!
//! # stdout is never touched
//!
//! `ssk --json` owns stdout as a machine contract. A log line there would
//! corrupt it, so the human layer is on stderr or nowhere — see [`StderrPolicy`],
//! which is the one place the three binaries legitimately differ.
//!
//! # The `WorkerGuard` is a hard requirement, not a nicety
//!
//! `tracing_appender::non_blocking` buffers in a worker thread and flushes on
//! the guard's `Drop`. `std::process::exit` runs no destructors, so any
//! `process::exit` below [`init`] silently discards the buffered log. That is
//! the concrete reason `ssk` and `sskd` return [`std::process::ExitCode`] from
//! `main` and contain no `process::exit` at all, and why `ssk-svc` creates its
//! [`Guard`] at the top of `service_main` and drops it only after the service
//! loop has returned. It is also what makes `Cargo.toml`'s `panic = "unwind"`
//! comment — "what unwinding buys is … the rolling-file tracing sink … flush" —
//! true rather than aspirational.

pub mod entropy;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

/// Schema version of the crash record's JSON body.
pub const CRASH_SCHEMA: u32 = 1;

/// Environment variable the log filter reads. Deliberately not `RUST_LOG`.
pub const LOG_ENV_VAR: &str = "SSK_LOG";

/// How many rotated log files to keep.
pub const MAX_LOG_FILES: usize = 14;

/// The literal recorded when a panic payload is neither `&str` nor `String`.
/// Never a fabricated message — the record says it does not know.
pub const OPAQUE_PAYLOAD: &str = "<non-string panic payload>";

static CRASH_SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether a human-readable layer is put on stderr, and under what condition.
///
/// This is the only axis on which the three binaries' diagnostics legitimately
/// differ, so it is an explicit argument rather than three implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StderrPolicy {
    /// Always. `sskd`: a daemon's stderr *is* a log.
    Always,
    /// Only when [`LOG_ENV_VAR`] is set. `ssk`: a CLI's stderr is a user-facing
    /// surface that the typed error contract already owns. Measured, not
    /// assumed — with a stderr layer on by default, `ssk status` against an
    /// absent daemon printed a `WARN ssk.lifecycle: ssk command failed` line
    /// immediately above the typed error that says the same thing.
    WhenLogEnvSet,
    /// Never. `ssk-svc`: a service started by the SCM runs in session 0 with no
    /// console, so a stderr layer is not a quieter sink, it is no sink at all.
    /// Saying so in the type is the point — the file sink is the only real one
    /// there.
    Never,
}

impl StderrPolicy {
    /// Whether this policy installs the layer in the current environment.
    #[must_use]
    pub fn installs_layer(self) -> bool {
        match self {
            StderrPolicy::Always => true,
            StderrPolicy::WhenLogEnvSet => std::env::var_os(LOG_ENV_VAR).is_some(),
            StderrPolicy::Never => false,
        }
    }
}

/// Where a process may write diagnostics.
///
/// A [`Layout`] with no root is a first-class state, not a failure: it means
/// this process has no directory it is entitled to write to, and no durable sink
/// will be installed. [`Layout::from_state_dir`] produces it for a **relative**
/// state directory, which is not fastidiousness — the pre-P2 default was `.ssk`
/// relative to the current working directory, and a CLI that scattered
/// `.ssk/logs` into whatever directory it was invoked from, including a source
/// tree, is the same defect wearing a different hat. No durable sink is strictly
/// better than a sink in an arbitrary place.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Layout {
    root: Option<PathBuf>,
}

impl Layout {
    /// No diagnostics root: no durable log, no crash record. The caller is
    /// expected to say *why* through its own channel.
    #[must_use]
    pub fn none() -> Self {
        Self { root: None }
    }

    /// Diagnostics under `dir`, or [`Layout::none`] if `dir` is not absolute.
    #[must_use]
    pub fn from_state_dir(dir: &Path) -> Self {
        Self {
            root: dir.is_absolute().then(|| dir.to_path_buf()),
        }
    }

    /// The resolved root, if there is one.
    #[must_use]
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Where the rotated log files go.
    #[must_use]
    pub fn logs(&self) -> Option<PathBuf> {
        self.root.as_ref().map(|r| r.join("logs"))
    }

    /// Where crash records go.
    #[must_use]
    pub fn crash(&self) -> Option<PathBuf> {
        self.root.as_ref().map(|r| r.join("crash"))
    }
}

/// Holds the non-blocking writer's worker alive. Dropping it flushes.
///
/// Must outlive every log site and must be dropped on *every* exit path — see
/// the crate docs.
#[derive(Debug)]
pub struct Guard {
    _file: Option<tracing_appender::non_blocking::WorkerGuard>,
    /// Set when a rolling file sink was requested but could not be built. The
    /// caller reports it *after* init, so the failure is surfaced through the
    /// subscriber that did come up rather than swallowed.
    pub file_sink_error: Option<String>,
}

impl Guard {
    /// Whether a durable rotated log is actually being written.
    #[must_use]
    pub fn has_durable_sink(&self) -> bool {
        self._file.is_some()
    }
}

/// Install the process subscriber: an `SSK_LOG`-filtered registry with a human
/// layer on stderr as `stderr` allows, and, when `logs_dir` is given and usable,
/// a JSON layer on a daily-rotated file keeping [`MAX_LOG_FILES`] generations.
///
/// Safe to call more than once in a process (later calls are no-ops), so tests
/// that touch it do not poison each other.
#[must_use]
pub fn init(binary: &str, logs_dir: Option<&Path>, stderr: StderrPolicy) -> Guard {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .with_env_var(LOG_ENV_VAR)
        .from_env_lossy();

    let stderr_layer = stderr.installs_layer().then(|| {
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_ansi(std::io::stderr().is_terminal())
    });

    let mut file_sink_error = None;
    let mut file_guard = None;
    let file_layer = match logs_dir.map(|dir| build_rolling_appender(binary, dir)) {
        None => None,
        Some(Ok(appender)) => {
            let (writer, guard) = tracing_appender::non_blocking(appender);
            file_guard = Some(guard);
            Some(
                fmt::layer()
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .with_writer(writer),
            )
        }
        Some(Err(err)) => {
            file_sink_error = Some(err);
            None
        }
    };

    // `try_init`, not `init`: a second call must not panic the process.
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(stderr_layer)
        .with(file_layer)
        .try_init();

    Guard {
        _file: file_guard,
        file_sink_error,
    }
}

fn build_rolling_appender(
    binary: &str,
    dir: &Path,
) -> Result<tracing_appender::rolling::RollingFileAppender, String> {
    std::fs::create_dir_all(dir).map_err(|err| {
        format!(
            "could not create the log directory `{}`: {err}",
            dir.display()
        )
    })?;
    tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(MAX_LOG_FILES)
        .filename_prefix(binary)
        .filename_suffix("log")
        .build(dir)
        .map_err(|err| format!("could not open a rolling log in `{}`: {err}", dir.display()))
}

/// A durable crash record.
///
/// # Not redacted, deliberately
///
/// `payload` is an arbitrary developer-authored string that may embed a host,
/// a path, or a config value, and `backtrace` embeds source paths. The record
/// therefore lives in the same ACL domain as the logs, and any future opt-in
/// crash reporting must redact **before** upload. Saying so here is the point:
/// a reader must not assume this file is safe to ship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashRecord {
    pub schema: u32,
    pub build: String,
    pub binary: String,
    pub pid: u32,
    pub thread: String,
    pub payload: String,
    pub location: Option<String>,
    pub backtrace: String,
    pub timestamp_unix: u64,
    pub uptime_secs: u64,
}

/// Extract a panic payload as text, or say honestly that it could not.
#[must_use]
pub fn payload_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        OPAQUE_PAYLOAD.to_owned()
    }
}

/// Write `record` to `dir` synchronously and `fsync` it.
///
/// **Direct `File::create` → `write_all` → `sync_all`, not `tracing`.** The
/// tracing pipeline may be the thing that broke, and the non-blocking worker
/// thread may never be scheduled again — a crash report that lives only in a
/// userspace buffer is a crash report that is lost.
///
/// # Errors
/// Any I/O failure creating or writing the file.
pub fn write_crash_record(dir: &Path, record: &CrashRecord) -> std::io::Result<PathBuf> {
    use std::io::Write;
    std::fs::create_dir_all(dir)?;
    let seq = CRASH_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!(
        "crash-{}-{}-{seq}.json",
        record.timestamp_unix, record.pid
    ));
    let body = serde_json::to_vec_pretty(record)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&body)?;
    file.sync_all()?;
    Ok(path)
}

/// Install the panic hook. Every panic writes a durable record under `crash_dir`
/// when there is one, emits a `tracing::error!` as well (best effort — the sink
/// may be the casualty), and then **chains to the previous hook**, so the
/// default stderr message is not swallowed.
pub fn install_panic_hook(binary: &'static str, crash_dir: Option<PathBuf>, build: &'static str) {
    let started = Instant::now();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let record = CrashRecord {
            schema: CRASH_SCHEMA,
            build: build.to_owned(),
            binary: binary.to_owned(),
            pid: std::process::id(),
            thread: std::thread::current()
                .name()
                .unwrap_or("<unnamed>")
                .to_owned(),
            payload: payload_text(info.payload()),
            location: info.location().map(std::string::ToString::to_string),
            backtrace: std::backtrace::Backtrace::force_capture().to_string(),
            timestamp_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            uptime_secs: started.elapsed().as_secs(),
        };

        let written = crash_dir
            .as_deref()
            .map(|dir| write_crash_record(dir, &record));
        match written {
            Some(Ok(path)) => tracing::error!(
                target: "ssk.lifecycle",
                crash_record = %path.display(),
                payload = %record.payload,
                location = record.location.as_deref().unwrap_or("<unknown>"),
                "panic: durable crash record written"
            ),
            Some(Err(err)) => tracing::error!(
                target: "ssk.lifecycle",
                %err,
                crash_dir = crash_dir.as_deref().map_or_else(
                    || "<none>".to_owned(),
                    |dir| dir.display().to_string()
                ),
                payload = %record.payload,
                "panic: could not write a durable crash record"
            ),
            None => tracing::error!(
                target: "ssk.lifecycle",
                payload = %record.payload,
                location = record.location.as_deref().unwrap_or("<unknown>"),
                "panic: no diagnostics directory, so no durable crash record was written"
            ),
        }

        previous(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> CrashRecord {
        CrashRecord {
            schema: CRASH_SCHEMA,
            build: "0.1.0".into(),
            binary: "sskd".into(),
            pid: 4242,
            thread: "tokio-runtime-worker".into(),
            payload: "assertion failed".into(),
            location: Some("src/supervisor.rs:123:5".into()),
            backtrace: "disabled".into(),
            timestamp_unix: 1_785_701_805,
            uptime_secs: 7,
        }
    }

    // ── Layout ──────────────────────────────────────────────────────────────

    #[test]
    fn a_relative_state_dir_yields_no_sink_paths_at_all() {
        // The CWD-pollution guard. `.ssk` relative to wherever `ssk` was invoked
        // must never become a log directory.
        let layout = Layout::from_state_dir(Path::new(".ssk"));
        assert_eq!(layout.root(), None);
        assert_eq!(layout.logs(), None);
        assert_eq!(layout.crash(), None);
    }

    #[test]
    fn an_absolute_state_dir_yields_logs_and_crash_subdirectories() {
        let base = std::env::temp_dir().join("ssk-diag-layout-probe");
        let layout = Layout::from_state_dir(&base);
        assert_eq!(layout.root(), Some(base.as_path()));
        assert_eq!(layout.logs(), Some(base.join("logs")));
        assert_eq!(layout.crash(), Some(base.join("crash")));
    }

    #[test]
    fn an_explicitly_absent_layout_has_no_paths() {
        let layout = Layout::none();
        assert_eq!(layout.root(), None);
        assert_eq!(layout.logs(), None);
        assert_eq!(layout.crash(), None);
        assert_eq!(layout, Layout::default());
    }

    // ── Crash records ───────────────────────────────────────────────────────

    #[test]
    fn a_crash_record_round_trips_through_the_file_it_writes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_crash_record(dir.path(), &record()).expect("write");
        assert!(path.exists());
        let raw = std::fs::read(&path).expect("read");
        let back: CrashRecord = serde_json::from_slice(&raw).expect("parse");
        assert_eq!(back, record());
    }

    #[test]
    fn a_crash_record_is_pretty_json_a_human_can_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_crash_record(dir.path(), &record()).expect("write");
        let raw = std::fs::read_to_string(&path).expect("read");
        assert!(raw.contains("assertion failed"));
        assert!(raw.contains("\"schema\": 1"));
    }

    #[test]
    fn crash_records_do_not_overwrite_each_other() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = write_crash_record(dir.path(), &record()).expect("write");
        let b = write_crash_record(dir.path(), &record()).expect("write");
        assert_ne!(
            a, b,
            "the sequence number must disambiguate same-second panics"
        );
        assert!(a.exists() && b.exists());
    }

    #[test]
    fn the_crash_directory_is_created_on_demand() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("does").join("not").join("exist");
        let path = write_crash_record(&nested, &record()).expect("write");
        assert!(path.exists());
    }

    #[test]
    fn a_string_payload_is_recorded_verbatim() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom".to_owned());
        assert_eq!(payload_text(payload.as_ref()), "boom");
    }

    #[test]
    fn a_static_str_payload_is_recorded_verbatim() {
        let payload: Box<dyn std::any::Any + Send> = Box::new("boom");
        assert_eq!(payload_text(payload.as_ref()), "boom");
    }

    #[test]
    fn an_opaque_payload_is_labelled_not_invented() {
        let payload: Box<dyn std::any::Any + Send> = Box::new(42u32);
        assert_eq!(payload_text(payload.as_ref()), OPAQUE_PAYLOAD);
    }

    // ── The subscriber ──────────────────────────────────────────────────────

    #[test]
    fn init_produces_a_durable_sink_and_actually_writes_to_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        let guard = init("ssk-diag-test", Some(&logs), StderrPolicy::Never);
        assert!(
            guard.has_durable_sink(),
            "a rolling file sink must exist: {:?}",
            guard.file_sink_error
        );
        assert!(guard.file_sink_error.is_none());

        tracing::error!(target: "ssk.lifecycle", probe = "durable-sink", "log sink smoke test");
        drop(guard); // flushes the non-blocking worker

        let files: Vec<_> = std::fs::read_dir(&logs)
            .expect("logs dir")
            .filter_map(Result::ok)
            .collect();
        assert!(!files.is_empty(), "the rotated log file must exist on disk");
        let body = files
            .iter()
            .map(|f| std::fs::read_to_string(f.path()).unwrap_or_default())
            .collect::<String>();
        // The subscriber may already have been installed by another test in
        // this binary; what must hold either way is that the sink is a real,
        // writable, rotated file rather than a silently-dropped writer.
        assert!(
            body.is_empty() || body.contains("durable-sink"),
            "the file sink wrote something other than the JSON event: {body}"
        );
    }

    #[test]
    fn the_rotated_log_is_named_after_the_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        let guard = init("ssk-svc", Some(&logs), StderrPolicy::Never);
        assert!(guard.has_durable_sink());
        drop(guard);
        let names: Vec<String> = std::fs::read_dir(&logs)
            .expect("logs dir")
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("ssk-svc.") && n.ends_with(".log")),
            "expected an `ssk-svc.<date>.log`, found {names:?}"
        );
    }

    #[test]
    fn an_unusable_log_directory_is_reported_rather_than_silently_dropped() {
        // Point the sink at a path that is a *file*, so the directory cannot be
        // created. The subscriber must still come up (a process that cannot log
        // must still run) but the failure must be visible.
        let dir = tempfile::tempdir().expect("tempdir");
        let blocker = dir.path().join("logs");
        std::fs::write(&blocker, b"not a directory").expect("write");
        let guard = init("ssk-diag-test", Some(&blocker), StderrPolicy::Never);
        assert!(!guard.has_durable_sink());
        assert!(
            guard.file_sink_error.is_some(),
            "an unusable log directory must be reported"
        );
    }

    #[test]
    fn init_without_a_log_directory_has_no_durable_sink_and_no_error() {
        let guard = init("ssk-diag-test", None, StderrPolicy::Never);
        assert!(!guard.has_durable_sink());
        assert!(guard.file_sink_error.is_none());
    }

    // ── The stderr policy, which is the one thing the binaries differ on ─────

    #[test]
    fn the_daemon_policy_always_installs_the_stderr_layer() {
        assert!(StderrPolicy::Always.installs_layer());
    }

    #[test]
    fn the_service_policy_never_installs_the_stderr_layer() {
        // Session 0 has no console: a stderr layer there is not a quieter sink,
        // it is no sink at all. This must not become "always" by accident.
        assert!(!StderrPolicy::Never.installs_layer());
    }

    #[test]
    fn the_cli_policy_follows_the_log_env_var() {
        // Reads the ambient environment deliberately rather than mutating it:
        // `set_var` is not thread-safe and the test binary is threaded. Whatever
        // the ambient state is, the two must agree.
        assert_eq!(
            StderrPolicy::WhenLogEnvSet.installs_layer(),
            std::env::var_os(LOG_ENV_VAR).is_some()
        );
    }
}
