//! Desktop port against the actual unprivileged daemon. No activation command,
//! broker, system service, VPN or routing changes.
include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use ssk_desktop_client::{DesktopClient, ReadError};
use ssk_ipc::Endpoint;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
async fn desktop_reads_real_daemon_then_fails_when_that_daemon_stops() {
    let dir = tempfile::tempdir().unwrap();
    let config = write_loopback_config(dir.path());
    let mut command = Command::new(env!("CARGO_BIN_EXE_sskd"));
    command
        .env("SSK_STATE_DIR", dir.path())
        .env("SSK_CONFIG_PATH", config)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(dir.path().join("sskd.err")).unwrap(),
        ));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut daemon = Daemon(command.spawn().unwrap());
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(
        &ssk_winhost::current_user_sid().unwrap(),
        dir.path(),
    ));
    #[cfg(unix)]
    let endpoint = Endpoint::UnixSocket(dir.path().join("sskd.sock"));
    let client = DesktopClient::new(endpoint);
    let deadline = Instant::now() + Duration::from_secs(30);
    let view = loop {
        match client.read_snapshot().await {
            Ok(view) => break view,
            Err(error) => assert!(matches!(
                error,
                ReadError::Unavailable | ReadError::Deadline
            )),
        }
        assert!(
            daemon.0.try_wait().unwrap().is_none() && Instant::now() < deadline,
            "daemon failed: {}",
            std::fs::read_to_string(dir.path().join("sskd.err")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let value = serde_json::to_value(view).unwrap();
    assert_eq!(value["schema_version"], 2);
    assert_eq!(value["panel_state"], "degraded");
    assert_eq!(value["daemon"]["reported_state"], "inactive");
    assert_eq!(value["daemon"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["daemon"]["active_profile"].is_null());
    assert!(value.get("kill_switch").is_none());
    assert!(value.get("audit").is_none());
    assert!(value.get("connections").is_none());
    drop(daemon);
    assert_eq!(client.read_snapshot().await, Err(ReadError::Unavailable));
}
