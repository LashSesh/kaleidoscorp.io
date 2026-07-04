#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use ssk_daemon::config_load::load_daemon_config;
use ssk_daemon::mock_dataplane::AlwaysUpMockDataPlane;
use ssk_daemon::supervisor::Supervisor;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    tracing_subscriber::fmt::init();

    let dir = ssk_ipc::paths::state_dir();
    if let Err(err) = std::fs::create_dir_all(&dir) {
        eprintln!("failed to create state directory {}: {err}", dir.display());
        std::process::exit(1);
    }

    // Simple single-writer lock: refuses to start a second instance against
    // the same state directory (Section F.1/F.2).
    let lock_path = dir.join("sskd.lock");
    let _lock = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(err) => {
            eprintln!(
                "failed to acquire daemon lock at {} (is sskd already running?): {err}",
                lock_path.display()
            );
            std::process::exit(1);
        }
    };

    let config_path = std::env::var_os("SSK_CONFIG_PATH").map(PathBuf::from);
    match load_daemon_config(config_path.as_deref()) {
        Ok(loaded) => {
            tracing::info!(migrated_from = ?loaded.migrated_from, "config loaded");
        }
        Err(err) => {
            // Fail-closed: still start (so a client can connect and
            // diagnose), but the daemon never engages protection with an
            // invalid config. Wiring this into a live `config_invalid` state
            // is Phase 5 work once the supervisor owns config, not just audit.
            tracing::error!(%err, "config invalid; starting with defaults, protection unavailable");
        }
    }

    let audit_path = dir.join("audit.json");
    let supervisor = Arc::new(Supervisor::new(audit_path, Box::new(AlwaysUpMockDataPlane)));

    let socket = ssk_ipc::paths::socket_path();
    tracing::info!(socket = %socket.display(), "sskd listening");

    let serve_result = run_server(socket, supervisor).await;

    let _ = std::fs::remove_file(&lock_path);
    if let Err(err) = serve_result {
        tracing::error!(%err, "ipc server exited with error");
        std::process::exit(1);
    }
}

#[cfg(unix)]
async fn run_server(socket: PathBuf, supervisor: Arc<Supervisor>) -> Result<(), ssk_ipc::IpcError> {
    tokio::select! {
        result = ssk_ipc::server::serve_unix(socket, supervisor) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
            Ok(())
        }
    }
}

/// Windows named-pipe path — written against tokio's documented API but not
/// compiled/tested in this sandboxed Linux environment (see
/// `ssk-ipc::server`'s module docs for the same caveat).
#[cfg(windows)]
async fn run_server(
    _socket: PathBuf,
    supervisor: Arc<Supervisor>,
) -> Result<(), ssk_ipc::IpcError> {
    tokio::select! {
        result = ssk_ipc::server::serve_named_pipe(ssk_ipc::paths::named_pipe_name(), supervisor) => result,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
            Ok(())
        }
    }
}
