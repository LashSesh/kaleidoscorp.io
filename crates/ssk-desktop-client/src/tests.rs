use super::*;
use ssk_ipc::{AdapterHealthSummaryDto, IpcError};

fn status(state: DaemonState) -> StatusDto {
    StatusDto {
        state,
        active_profile: Some("office".into()),
        adapters: vec![],
        dns_protected: true,
        kill_switch: true,
        audit_head: Some("claimed-head".into()),
        version: "0.1.0".into(),
        last_error: None,
        ..Default::default()
    }
}

#[test]
fn reported_states_never_promote_daemon_claims_to_protection() {
    for (state, expected) in [
        (DaemonState::Inactive, "inactive"),
        (DaemonState::Activating, "activating"),
        (DaemonState::Active, "active"),
        (DaemonState::Protected, "protected"),
        (DaemonState::Degraded, "degraded"),
        (DaemonState::FailClosed, "fail_closed"),
        (DaemonState::ConfigInvalid, "config_invalid"),
        (DaemonState::RecoveryMode, "recovery_mode"),
    ] {
        let view = project_response(Response::Status(status(state))).unwrap();
        let value = serde_json::to_value(view).unwrap();
        assert_eq!(value["panel_state"], "degraded");
        assert_eq!(value["daemon"]["reported_state"], expected);
        assert_eq!(value["daemon"]["active_profile"], "office");
        assert!(value.get("kill_switch").is_none());
        assert!(value.get("audit").is_none());
        assert!(value.get("connections").is_none());
    }
}

/// The v2 contract projects only the fields it knows (design 11.3). A daemon
/// that announces protocol 1 and answers an ingress block is read exactly as
/// one that does not, and nothing of the block reaches the webview until the
/// v3 contract replaces this one.
#[test]
fn a_daemon_that_reports_an_ingress_block_is_read_as_before() {
    let plain = status(DaemonState::Inactive);
    let mut announcing = status(DaemonState::Inactive);
    announcing.protocol = ssk_ipc::IPC_PROTOCOL_VERSION;
    announcing.ingress = Some(ssk_ipc::IngressStatusDto {
        state: "armed".into(),
        coverage: "proxy_clients_only".into(),
        armed_profile: Some("office".into()),
        ..Default::default()
    });
    let plain = serde_json::to_value(project_status(plain).unwrap()).unwrap();
    let announcing = serde_json::to_value(project_status(announcing).unwrap()).unwrap();
    assert_eq!(plain, announcing);
    let text = announcing.to_string();
    for word in ["ingress", "proxy_clients_only", "armed", "protocol"] {
        assert!(
            !text.contains(word),
            "`{word}` reached the v2 snapshot: {text}"
        );
    }
}

#[test]
fn invalid_display_data_is_rejected_and_private_errors_are_not_forwarded() {
    for invalid in [
        "".into(),
        "x".repeat(257),
        "é".repeat(129),
        "bad\nversion".into(),
    ] {
        let mut data = status(DaemonState::Inactive);
        data.version = invalid;
        assert_eq!(project_status(data), Err(ReadError::InvalidResponse));
    }
    let mut data = status(DaemonState::Inactive);
    data.active_profile = Some("bad\u{009f}".into());
    assert_eq!(project_status(data), Err(ReadError::InvalidResponse));
    let mut data = status(DaemonState::Inactive);
    data.adapters = vec![
        AdapterHealthSummaryDto {
            id: "a".into(),
            health: "ok".into()
        };
        257
    ];
    assert_eq!(project_status(data), Err(ReadError::InvalidResponse));
    let mut data = status(DaemonState::Inactive);
    data.last_error = Some(IpcError::new(
        "Runtime",
        "SAFE_CODE",
        "private file path or secret",
    ));
    let value = serde_json::to_string(&project_status(data).unwrap()).unwrap();
    assert!(value.contains("SAFE_CODE"));
    assert!(!value.contains("private file"));
    assert_eq!(
        project_response(Response::Err(IpcError::new("x", "private", "secret"))),
        Err(ReadError::Unavailable)
    );
    assert_eq!(
        project_response(Response::Ack),
        Err(ReadError::InvalidResponse)
    );
    assert_eq!(
        serde_json::to_string(&ReadError::Unavailable).unwrap(),
        "\"unavailable\""
    );
}

#[test]
fn relative_state_directory_is_never_an_endpoint() {
    assert!(matches!(
        endpoint_for_directory(Path::new(".ssk")),
        Err(ReadError::EndpointUnavailable)
    ));
}

#[tokio::test(start_paused = true)]
async fn an_unresponsive_read_has_a_fixed_deadline() {
    let start = tokio::time::Instant::now();
    assert_eq!(
        bounded_read(std::future::pending()).await,
        Err(ReadError::Deadline)
    );
    assert_eq!(start.elapsed(), READ_DEADLINE);
}

// These tests deliberately use a non-authenticating test peer. The desktop
// summary is not a server identity attestation. Production daemon ACLs are
// exercised separately by the real-daemon integration test.
#[cfg(windows)]
mod pipe {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    fn peer() -> (DesktopClient, NamedPipeServer) {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let name = format!(
            r"\\.\pipe\ssk-desktop-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .unwrap();
        (DesktopClient::new(Endpoint::NamedPipe(name)), server)
    }

    async fn receive_status_request(server: &mut NamedPipeServer) {
        server.connect().await.unwrap();
        let request: Request =
            ssk_ipc::framing::read_frame(server, ssk_ipc::framing::MAX_REQUEST_FRAME_LEN)
                .await
                .unwrap();
        assert!(matches!(request, Request::GetStatus));
    }

    #[tokio::test]
    async fn real_pipe_reads_only_status_and_rejects_wrong_responses() {
        for (response, error) in [
            (Response::Status(status(DaemonState::Protected)), None),
            (Response::Ack, Some(ReadError::InvalidResponse)),
        ] {
            let (client, mut server) = peer();
            let task = tokio::spawn(async move {
                receive_status_request(&mut server).await;
                ssk_ipc::framing::write_frame(&mut server, &response)
                    .await
                    .unwrap();
                // Keep the pipe alive until the client has consumed the frame.
                let mut byte = [0];
                let _ = tokio::io::AsyncReadExt::read(&mut server, &mut byte).await;
            });
            let result = client.read_snapshot().await;
            assert_eq!(result.as_ref().err().copied(), error);
            if let Ok(view) = result {
                assert_eq!(view.panel_state, DesktopPanelState::Degraded);
            }
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancellation_and_timeout_close_connection_and_release_single_read_slot() {
        for cancel in [true, false] {
            let (client, mut server) = peer();
            let client = Arc::new(client);
            let reader = Arc::clone(&client);
            let task = tokio::spawn(async move { reader.read_snapshot().await });
            receive_status_request(&mut server).await;
            assert_eq!(client.read_snapshot().await, Err(ReadError::Busy));
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert_eq!(task.await.unwrap(), Err(ReadError::Deadline));
            }
            let mut byte = [0];
            let eof = tokio::time::timeout(
                Duration::from_secs(1),
                tokio::io::AsyncReadExt::read(&mut server, &mut byte),
            )
            .await
            .unwrap();
            assert!(!matches!(eof, Ok(n) if n > 0));
            drop(server);
            assert_eq!(client.read_snapshot().await, Err(ReadError::Unavailable));
        }
    }
}
