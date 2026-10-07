//! Real-`sskd` shutdown regressions (Unix): SIGTERM arrives while an activation
//! is dialling a proxy that accepted the connection and never answers.
//!
//! The activation's future is a connection task of the daemon's runtime, so the
//! only thing that ever ends it before its own 20 s deadline is the runtime
//! being torn down. That makes it the one in-flight piece of work whose
//! last act (the terminal ledger record of `ActivationScope`) happens during
//! shutdown, and so the thing that shows whether the daemon lock is given up
//! before or after the runtime has stopped.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

#[cfg(unix)]
use std::process::{Child, Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use ssk_ipc::{ActivateProfileRequest, DaemonClient, Request, Response};
#[cfg(unix)]
use ssk_netadmin::audit::AuditOutcome;
#[cfg(unix)]
use tokio::net::TcpListener;

/// Kills and reaps the daemon when a test ends or panics, so a failed
/// assertion never leaves an `sskd` holding a state directory.
#[cfg(unix)]
struct Reaper(Child);

#[cfg(unix)]
impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A real `sskd` with an activation in flight against a silent proxy.
#[cfg(unix)]
struct SilentDaemon {
    child: Reaper,
    state: tempfile::TempDir,
    activation: Option<tokio::task::JoinHandle<Result<Response, ssk_ipc::IpcError>>>,
    // The proxy's end of the dial, kept open: the daemon must see silence, not a
    // reset, or the dial would end on its own.
    _held: tokio::net::TcpStream,
}

#[cfg(unix)]
impl SilentDaemon {
    fn audit_path(&self) -> std::path::PathBuf {
        self.state.path().join("audit.json")
    }

    fn lock_path(&self) -> std::path::PathBuf {
        self.state.path().join("sskd.lock")
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.state.path().join("sskd.err")).unwrap_or_default()
    }

    /// `kill -TERM`, the way `docker stop` and systemd stop a daemon. The
    /// `kill` binary rather than a signal crate: this crate has no signal
    /// dependency and `unsafe` is forbidden here.
    fn sigterm(&self) {
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.0.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -TERM failed: {status}");
    }
}

/// Start `sskd`, send it an `ActivateProfile` for a destination routed through
/// a proxy that accepts and then says nothing, and return once that dial is
/// really in flight. The ledger then holds the activation's `DispatchPending`
/// and nothing else.
#[cfg(unix)]
async fn start_with_a_silent_activation() -> SilentDaemon {
    use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter, RoutingRule};

    let state = tempfile::tempdir().expect("state directory");
    let proxy = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
    let port = proxy.local_addr().expect("address").port();
    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((socket, _)) = proxy.accept().await {
            if accepted_tx.send(socket).is_err() {
                break;
            }
        }
    });

    let mut loaded = loopback_config();
    loaded.config.routing.profiles[0].rules.push(RoutingRule {
        id: "silent".into(),
        priority: 20,
        destination: Some("service.corp.invalid".into()),
        domain_suffix: None,
        port: Some(8443),
        action: RoutingAction::Adapter {
            adapter_id: "silent-proxy".into(),
        },
        require_attestation: false,
    });
    loaded.config.routing.adapters.push(RoutingAdapter {
        id: "silent-proxy".into(),
        transport: AdapterTransport::Socks5 {
            host: "127.0.0.1".into(),
            port,
        },
    });
    // JSON is YAML; the loader chooses its parser by the file extension.
    let config = state.path().join("silent-test.yaml");
    std::fs::write(
        &config,
        serde_json::to_string_pretty(&loaded.config).expect("config"),
    )
    .expect("write config");

    let mut child = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sskd"))
            .env("SSK_STATE_DIR", state.path())
            .env("SSK_CONFIG_PATH", &config)
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(state.path().join("sskd.err")).expect("stderr"),
            ))
            .spawn()
            .expect("spawn sskd"),
    );
    let socket = state.path().join("sskd.sock");
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut client = loop {
        if let Ok(client) = DaemonClient::connect_path(&socket).await {
            break client;
        }
        assert!(
            child.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "sskd did not start: {}",
            std::fs::read_to_string(state.path().join("sskd.err")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let activation = tokio::spawn(async move {
        client
            .call(Request::ActivateProfile(ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("service.corp.invalid".into()),
                dest_port: Some(8443),
            }))
            .await
    });
    let held = match tokio::time::timeout(Duration::from_secs(10), accepted.recv()).await {
        Ok(Some(held)) => held,
        _ => panic!(
            "the activation never dialled the silent proxy: {}",
            std::fs::read_to_string(state.path().join("sskd.err")).unwrap_or_default()
        ),
    };
    SilentDaemon {
        child,
        state,
        activation: Some(activation),
        _held: held,
    }
}

/// The outcomes in the ledger, oldest first.
#[cfg(unix)]
fn ledger_outcomes(audit: &std::path::Path) -> Vec<AuditOutcome> {
    ssk_netadmin::audit::AuditLedger::persisted(audit)
        .entries()
        .expect("the ledger must stay readable")
        .into_iter()
        .map(|entry| entry.outcome)
        .collect()
}

/// A successor daemon asks for the lock the moment it is free and then looks at
/// the ledger it would extend. The ledger is one hash chain and the lock is what
/// keeps a second writer away from it, so everything the old process writes must
/// be on disk before the lock can be taken.
///
/// Before the shutdown plan the daemon dropped the lock and only then dropped
/// its runtime, and dropping the runtime is what drops the connection task that
/// holds the in-flight activation: its terminal `FailClosed` record was written
/// by a process that no longer held the lock.
#[cfg(unix)]
#[tokio::test]
async fn the_lock_is_not_released_before_the_runtime_has_settled_its_work() {
    use rustix::fs::{flock, FlockOperation};

    let daemon = start_with_a_silent_activation().await;
    assert_eq!(
        ledger_outcomes(&daemon.audit_path()),
        [AuditOutcome::DispatchPending],
        "the activation must be in flight before the signal"
    );

    // The successor spins on `flock` with no sleep, so it notices a release
    // within microseconds, and reads the ledger on the same thread. If the old
    // process had given the lock up first, settling the activation (a temp file,
    // an fsync and a rename) would still be ahead of it and the read would miss
    // the record. Once the lock is only released by the process ending, nothing
    // is ahead of it and the read cannot miss: this passes by construction, and
    // fails against the old order on every run seen (12 of 12).
    let lock_path = daemon.lock_path();
    let audit_path = daemon.audit_path();
    let successor = std::thread::spawn(move || {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .expect("open the lock file");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if flock(&file, FlockOperation::NonBlockingLockExclusive).is_ok() {
                let seen = ledger_outcomes(&audit_path);
                return Some((seen, file));
            }
            std::hint::spin_loop();
        }
        None
    });

    daemon.sigterm();
    let (seen, _lock) = successor
        .join()
        .expect("the successor thread")
        .unwrap_or_else(|| panic!("the lock was never released: {}", daemon.log()));
    assert_eq!(
        seen,
        [AuditOutcome::DispatchPending, AuditOutcome::FailClosed],
        "a successor took the daemon lock while the old runtime still had the in-flight \
         activation to settle; the old process wrote after it had given the lock up\n{}",
        daemon.log()
    );
}

/// The budget a SIGTERM may take to end the daemon, whatever it is doing: the
/// graceful plan's worst case.
#[cfg(unix)]
fn exit_budget() -> Duration {
    ssk_daemon::shutdown::ShutdownPlan::for_reason(ssk_daemon::shutdown::ShutdownReason::SigTerm)
        .total()
}

/// A SIGTERM during a dial that nothing else would end for 20 s must still end
/// the daemon promptly, with the in-flight activation given its terminal ledger
/// record and no half-written state behind.
#[cfg(unix)]
#[tokio::test]
async fn sigterm_during_a_silent_activation_settles_the_ledger_and_exits_within_budget() {
    let mut daemon = start_with_a_silent_activation().await;
    assert_eq!(
        ledger_outcomes(&daemon.audit_path()),
        [AuditOutcome::DispatchPending]
    );

    let budget = exit_budget();
    let signalled = Instant::now();
    daemon.sigterm();
    let status = loop {
        if let Some(status) = daemon.child.0.try_wait().expect("child status") {
            break status;
        }
        assert!(
            signalled.elapsed() < budget + Duration::from_secs(5),
            "sskd was still running {:?} after SIGTERM, far past its {budget:?} budget:\n{}",
            signalled.elapsed(),
            daemon.log()
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    let elapsed = signalled.elapsed();
    println!("sskd exited {elapsed:?} after SIGTERM (budget {budget:?})");
    assert!(
        elapsed <= budget,
        "sskd took {elapsed:?} to exit after SIGTERM; the plan allows {budget:?}"
    );
    assert!(status.success(), "a graceful stop exits 0, got {status}");

    // The activation's terminal record is the one the daemon owes the ledger
    // for a dial it abandoned; the chain stays valid.
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(daemon.audit_path());
    ledger.verify().expect("the chain must verify after a stop");
    assert_eq!(
        ledger_outcomes(&daemon.audit_path()),
        [AuditOutcome::DispatchPending, AuditOutcome::FailClosed]
    );
    assert!(
        !daemon.state.path().join("sskd.sock").exists(),
        "a graceful stop unlinks the IPC socket"
    );

    // The requester is gone with the daemon: its connection ends without a
    // status that could be mistaken for a protected session.
    let answer = tokio::time::timeout(
        Duration::from_secs(5),
        daemon.activation.take().expect("activation"),
    )
    .await
    .expect("the client's call must end with the daemon")
    .expect("client task");
    assert!(
        answer.is_err(),
        "the abandoned activation was answered: {answer:?}"
    );
}
