//! Actual bundled WebView -> Tauri capability -> desktop client -> Windows pipe.
//! The peer is a clearly synthetic test daemon; it never changes system state.
#![cfg(windows)]
use ssk_ipc::{DaemonState, Request, Response, StatusDto};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tokio::net::windows::named_pipe::ServerOptions;

struct Desktop(Child);
impl Drop for Desktop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires an interactive Windows session and installed WebView2"]
async fn bundled_webview_requests_status_through_the_real_native_command() {
    let directory = tempfile::tempdir().unwrap();
    let sid = ssk_winhost::current_user_sid().unwrap();
    let name = ssk_ipc::paths::named_pipe_name(&sid, directory.path());
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(name)
        .unwrap();
    let error_log = directory.path().join("desktop.err");
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssk-desktop"));
    command
        .env("SSK_STATE_DIR", directory.path())
        .env("LOCALAPPDATA", directory.path())
        .env("APPDATA", directory.path())
        .stdout(Stdio::null())
        .stderr(Stdio::from(std::fs::File::create(&error_log).unwrap()));
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console window
    let mut desktop = Desktop(command.spawn().unwrap());
    let observation = tokio::time::timeout(Duration::from_secs(45), async {
        server.connect().await.unwrap();
        let request: Request =
            ssk_ipc::framing::read_frame(&mut server, ssk_ipc::framing::MAX_REQUEST_FRAME_LEN)
                .await
                .unwrap();
        assert!(
            matches!(request, Request::GetStatus),
            "UI must only read status"
        );
        let response = Response::Status(StatusDto {
            state: DaemonState::Inactive,
            active_profile: None,
            adapters: vec![],
            dns_protected: false,
            kill_switch: false,
            audit_head: None,
            version: "desktop-smoke-peer".into(),
            last_error: None,
        });
        ssk_ipc::framing::write_frame(&mut server, &response)
            .await
            .unwrap();
        let mut unexpected = [0];
        let end = tokio::io::AsyncReadExt::read(&mut server, &mut unexpected).await;
        assert!(
            !matches!(end, Ok(n) if n > 0),
            "no further request on the one-read connection"
        );
    })
    .await;
    assert!(
        observation.is_ok(),
        "WebView did not reach status port; process: {:?}, stderr: {}",
        desktop.0.try_wait().unwrap(),
        std::fs::read_to_string(&error_log).unwrap_or_default()
    );
    assert!(
        desktop.0.try_wait().unwrap().is_none(),
        "desktop exited unexpectedly"
    );
    // Drop terminates only the child created here; no user processes are
    // searched or killed. WebView cleanup belongs to the host/runtime.
}
