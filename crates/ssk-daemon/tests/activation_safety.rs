//! Real-daemon regressions for configuration and audit failures. All network
//! effects are confined to loopback; no privileged broker or OS mutation.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_ipc::{
    ActivateProfileRequest, DaemonClient, DaemonState, DeactivateRequest, Endpoint, Request,
    Response,
};
use tokio::net::TcpListener;

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn start(state_dir: &Path, config: Option<&Path>) -> (Daemon, DaemonClient) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sskd"));
    command
        .env("SSK_STATE_DIR", state_dir)
        .env_remove("SSK_CONFIG_PATH")
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            std::fs::File::create(state_dir.join("sskd.err")).expect("stderr"),
        ));
    let config_path = config
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| write_loopback_config(state_dir));
    command.env("SSK_CONFIG_PATH", config_path);
    let mut daemon = Daemon(command.spawn().expect("spawn daemon"));
    #[cfg(windows)]
    let endpoint = Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(
        &ssk_winhost::current_user_sid().expect("SID"),
        state_dir,
    ));
    #[cfg(unix)]
    let endpoint = Endpoint::UnixSocket(state_dir.join("sskd.sock"));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(client) = DaemonClient::connect(&endpoint).await {
            return (daemon, client);
        }
        assert!(
            daemon.0.try_wait().expect("child status").is_none() && Instant::now() < deadline,
            "daemon did not start: {}",
            std::fs::read_to_string(state_dir.join("sskd.err")).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn activate(listener: &TcpListener) -> Request {
    Request::ActivateProfile(ActivateProfileRequest {
        profile_id: "default".into(),
        dest_host: Some("127.0.0.1".into()),
        dest_port: Some(listener.local_addr().expect("address").port()),
    })
}

async fn assert_no_connection(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err(),
        "refused activation must not attempt a connection"
    );
}

fn write_config(directory: &Path, config: &ssk_config::AppConfig) -> std::path::PathBuf {
    let path = directory.join("routing.yaml");
    std::fs::write(&path, serde_yaml::to_string(config).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn default_denial_and_required_attestation_never_reach_the_data_plane() {
    for requires_attestation in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let config = if requires_attestation {
            let mut config = loopback_config().config;
            config.routing.profiles[0].rules[0].require_attestation = true;
            config
        } else {
            ssk_config::AppConfig::default()
        };
        let path = write_config(dir.path(), &config);
        let (_daemon, mut client) = start(dir.path(), Some(&path)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let response = client.call(activate(&listener)).await.unwrap();
        match response {
            Response::Err(error) => assert_eq!(
                error.code,
                if requires_attestation {
                    "ATTESTATION_REQUIRED"
                } else {
                    "FAIL_CLOSED"
                }
            ),
            other => panic!("unadmitted flow was accepted: {other:?}"),
        }
        assert_no_connection(&listener).await;
        let ledger = ssk_netadmin::audit::AuditLedger::persisted(dir.path().join("audit.json"));
        ledger.verify().unwrap();
        let entries = ledger.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].outcome,
            ssk_netadmin::audit::AuditOutcome::Denied
        );
    }
}

#[tokio::test]
async fn configured_openvpn_is_visible_but_fails_explicitly_without_direct_fallback() {
    use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter};
    let dir = tempfile::tempdir().unwrap();
    let mut config = loopback_config().config;
    config.routing.adapters.push(RoutingAdapter {
        id: "corporate-vpn".into(),
        transport: AdapterTransport::OpenVpn {
            profile_id: "company-managed".into(),
        },
    });
    config.routing.profiles[0].rules[0].action = RoutingAction::Adapter {
        adapter_id: "corporate-vpn".into(),
    };
    let path = write_config(dir.path(), &config);
    let (_daemon, mut client) = start(dir.path(), Some(&path)).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let response = client.call(activate(&listener)).await.unwrap();
    match response {
        Response::Status(status) => {
            assert_eq!(status.state, DaemonState::FailClosed);
            assert_eq!(status.last_error.unwrap().code, "OPENVPN_NOT_READY");
            assert!(status.active_profile.is_none());
            assert!(status.adapters.is_empty());
        }
        other => panic!("unexpected VPN activation: {other:?}"),
    }
    assert_no_connection(&listener).await;
    let response = client
        .call(Request::TraceRoute(ssk_ipc::RouteTraceRequest {
            app_id: None,
            dest_host: "127.0.0.1".into(),
            dest_port: 443,
            protocol: "tcp".into(),
            risk: "low".into(),
        }))
        .await
        .unwrap();
    match response {
        Response::RouteTrace(trace) => {
            assert_eq!(trace.hops, ["corporate-vpn"]);
            assert!(
                matches!(trace.route, ssk_netadmin::RouteKind::OpenVpn { profile_id, .. } if profile_id == "company-managed")
            );
        }
        other => panic!("VPN plan was hidden: {other:?}"),
    }
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(dir.path().join("audit.json"));
    ledger.verify().unwrap();
    let entries = ledger.entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        entries[1].outcome,
        ssk_netadmin::audit::AuditOutcome::FailClosed
    );
    assert!(entries[1].route_kind_summary.contains("corporate-vpn"));
}

#[tokio::test]
async fn custom_profile_uses_configured_socks5_endpoint_and_forwards_exact_destination() {
    use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let handshake = tokio::spawn(async move {
        let (mut socket, _) = proxy.accept().await.unwrap();
        let mut greeting = [0; 2];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting[0], 5);
        let mut methods = vec![0; greeting[1] as usize];
        socket.read_exact(&mut methods).await.unwrap();
        assert!(methods.contains(&0));
        socket.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 5];
        socket.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &[5, 1, 0, 3]);
        let mut destination = vec![0; header[4] as usize];
        socket.read_exact(&mut destination).await.unwrap();
        assert_eq!(destination, b"service.corp.invalid");
        let mut dest_port = [0; 2];
        socket.read_exact(&mut dest_port).await.unwrap();
        assert_eq!(u16::from_be_bytes(dest_port), 8443);
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        socket
    });
    let mut config = loopback_config().config;
    config.routing.default_profile = "corporate".into();
    let profile = &mut config.routing.profiles[0];
    profile.id = "corporate".into();
    profile.name = "Corporate proxy".into();
    profile.rules[0].destination = Some("service.corp.invalid".into());
    profile.rules[0].port = Some(8443);
    profile.rules[0].action = RoutingAction::Adapter {
        adapter_id: "corp-proxy".into(),
    };
    config.routing.adapters.push(RoutingAdapter {
        id: "corp-proxy".into(),
        transport: AdapterTransport::Socks5 {
            host: "127.0.0.1".into(),
            port,
        },
    });
    let path = write_config(dir.path(), &config);
    let (_daemon, mut client) = start(dir.path(), Some(&path)).await;
    match client.call(Request::ListProfiles).await.unwrap() {
        Response::Profiles(profiles) => {
            assert_eq!(profiles.len(), 1);
            assert_eq!(profiles[0].id, "corporate");
        }
        other => panic!("configured profiles absent: {other:?}"),
    }
    // The obsolete built-in profile must not survive in a custom configuration.
    match client
        .call(Request::ActivateProfile(ActivateProfileRequest {
            profile_id: "default".into(),
            dest_host: Some("service.corp.invalid".into()),
            dest_port: Some(8443),
        }))
        .await
        .unwrap()
    {
        Response::Err(error) => assert_eq!(error.code, "UNKNOWN_PROFILE"),
        other => panic!("unconfigured default accepted: {other:?}"),
    }
    let response = client
        .call(Request::ActivateProfile(ActivateProfileRequest {
            profile_id: "corporate".into(),
            dest_host: Some("service.corp.invalid".into()),
            dest_port: Some(8443),
        }))
        .await
        .unwrap();
    let mut socket = tokio::time::timeout(Duration::from_secs(3), handshake)
        .await
        .unwrap()
        .unwrap();
    match response {
        Response::Status(status) => {
            assert_eq!(status.state, DaemonState::Protected);
            assert_eq!(status.active_profile.as_deref(), Some("corporate"));
            assert_eq!(status.adapters[0].id, "Socks5");
        }
        other => panic!("configured proxy dispatch failed: {other:?}"),
    }
    // Changing only the port must deny, and close the previously active session.
    match client
        .call(Request::ActivateProfile(ActivateProfileRequest {
            profile_id: "corporate".into(),
            dest_host: Some("service.corp.invalid".into()),
            dest_port: Some(443),
        }))
        .await
        .unwrap()
    {
        Response::Err(error) => assert_eq!(error.code, "FAIL_CLOSED"),
        other => panic!("port restriction ignored: {other:?}"),
    }
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0)) || closed.is_err());
}

#[tokio::test]
async fn invalid_or_missing_config_blocks_dispatch_but_keeps_diagnostics_available() {
    for content in [Some("[invalid"), Some("version = 999"), None] {
        let dir = tempfile::tempdir().expect("state directory");
        let path = dir.path().join("config.toml");
        if let Some(content) = content {
            std::fs::write(&path, content).expect("invalid config");
        }
        let (_daemon, mut client) = start(dir.path(), Some(&path)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        match client.call(activate(&listener)).await.expect("activate") {
            Response::Err(err) => {
                assert_eq!(err.code, "CONFIG_INVALID");
                assert_eq!(err.class, "Config");
            }
            other => panic!("invalid config permitted activation: {other:?}"),
        }
        assert_no_connection(&listener).await;
        for request in [
            Request::GetStatus,
            Request::Deactivate(DeactivateRequest {
                release_kill_switch: true,
            }),
            Request::GetStatus,
        ] {
            match client.call(request).await.expect("diagnostics") {
                Response::Status(status) => {
                    assert_eq!(status.state, DaemonState::ConfigInvalid);
                    assert_eq!(
                        status.last_error.expect("config error").code,
                        "CONFIG_INVALID"
                    );
                    assert!(status.active_profile.is_none());
                }
                other => panic!("diagnostics unavailable: {other:?}"),
            }
        }
        match client.call(Request::RunDoctor).await.expect("doctor") {
            Response::Doctor(report) => assert!(report
                .checks
                .iter()
                .any(|check| check.name == "config" && !check.ok)),
            other => panic!("doctor unavailable: {other:?}"),
        }
        assert!(!dir.path().join("audit.json").exists());
    }
}

#[tokio::test]
async fn unavailable_audit_blocks_dispatch_and_reports_the_cause() {
    for malformed_file in [false, true] {
        let dir = tempfile::tempdir().expect("state directory");
        let path = dir.path().join("audit.json");
        if malformed_file {
            std::fs::write(&path, b"not JSON").expect("malformed ledger");
        } else {
            std::fs::create_dir(&path).expect("unusable ledger path");
        }
        let (_daemon, mut client) = start(dir.path(), None).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        match client.call(activate(&listener)).await.expect("activate") {
            Response::Err(err) => assert_eq!(err.class, "Integrity"),
            other => panic!("unavailable audit permitted activation: {other:?}"),
        }
        assert_no_connection(&listener).await;
        match client.call(Request::GetStatus).await.expect("status") {
            Response::Status(status) => {
                assert_eq!(status.state, DaemonState::FailClosed);
                assert_eq!(status.last_error.expect("audit error").class, "Integrity");
                assert!(status.active_profile.is_none());
                assert!(status.adapters.is_empty());
                assert!(!status.dns_protected);
            }
            other => panic!("status unavailable: {other:?}"),
        }
    }
}

#[tokio::test]
async fn valid_config_records_pending_and_result_and_preserves_ids_across_restart() {
    let dir = tempfile::tempdir().expect("state directory");
    let config = dir.path().join("config.yaml");
    std::fs::write(
        &config,
        serde_yaml::to_string(&loopback_config().config).unwrap(),
    )
    .unwrap();
    for completed in [2, 4] {
        let (daemon, mut client) = start(dir.path(), Some(&config)).await;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let status = match client.call(activate(&listener)).await.expect("activate") {
            Response::Status(status) => status,
            other => panic!("valid activation refused: {other:?}"),
        };
        assert_eq!(status.state, DaemonState::Protected);
        let (_connection, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("real connection")
            .expect("accept");
        let ledger = ssk_netadmin::audit::AuditLedger::persisted(dir.path().join("audit.json"));
        ledger.verify().expect("durable valid chain");
        let entries = ledger.entries().expect("entries");
        assert_eq!(entries.len(), completed);
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.entry_id, format!("activate-{index}"));
            assert_eq!(
                entry.outcome,
                if index % 2 == 0 {
                    ssk_netadmin::audit::AuditOutcome::DispatchPending
                } else {
                    ssk_netadmin::audit::AuditOutcome::Dispatched
                }
            );
        }
        assert_eq!(
            status.audit_head.as_deref(),
            Some(entries.last().unwrap().entry_hash.as_str())
        );
        drop(client);
        drop(daemon);
    }
}

#[tokio::test]
async fn a_corrupted_existing_chain_is_not_extended_and_never_dispatches() {
    let dir = tempfile::tempdir().expect("state directory");
    let path = dir.path().join("audit.json");
    let mut ledger = ssk_netadmin::audit::AuditLedger::persisted(&path);
    ledger
        .record(
            "historic",
            "flow",
            None,
            None,
            &ssk_netadmin::RouteKind::Direct,
            ssk_netadmin::audit::AuditOutcome::Dispatched,
            1,
        )
        .expect("seed");
    let mut entries = ledger.entries().unwrap();
    entries[0].entry_hash = "tampered".into();
    let damaged = serde_json::to_vec(&entries).unwrap();
    std::fs::write(&path, &damaged).unwrap();
    let (_daemon, mut client) = start(dir.path(), None).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    match client.call(activate(&listener)).await.expect("activate") {
        Response::Err(error) => assert_eq!(error.code, "AUDIT_CHAIN_BROKEN"),
        other => panic!("corrupted ledger admitted a connection: {other:?}"),
    }
    assert_no_connection(&listener).await;
    assert_eq!(std::fs::read(&path).unwrap(), damaged);
}

/// The data plane still establishes a real TCP connection. Only the timing of
/// a storage failure is injected, immediately before the result is committed.
struct AuditFailsAfterConnect {
    real: ssk_netcore::NetcoreDataPlane,
    path: std::path::PathBuf,
}

impl ssk_netcore::DataPlane for AuditFailsAfterConnect {
    fn probe_route<'a>(
        &'a self,
        route: &'a ssk_netadmin::RouteKind,
        target: (&'a str, u16),
    ) -> ssk_netcore::BoxFuture<'a, ssk_netcore::ProbeReport> {
        self.real.probe_route(route, target)
    }

    fn connect_route<'a>(
        &'a self,
        admission: ssk_netadmin::admission::AdmissionToken,
    ) -> ssk_netcore::BoxFuture<'a, Result<ssk_netcore::EgressSession, ssk_netcore::NetcoreError>>
    {
        Box::pin(async move {
            let ledger = ssk_netadmin::audit::AuditLedger::persisted(&self.path);
            let pending = ledger
                .entries()
                .expect("intent must be durable before dispatch");
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending[0].outcome,
                ssk_netadmin::audit::AuditOutcome::DispatchPending
            );
            let session = self.real.connect_route(admission).await?;
            std::fs::rename(&self.path, self.path.with_extension("before-failure.json")).unwrap();
            std::fs::create_dir(&self.path).unwrap();
            Ok(session)
        })
    }
}

#[tokio::test]
async fn audit_failure_after_connect_closes_the_socket_without_a_protected_event() {
    use ssk_ipc::CommandHandler;
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().expect("state directory");
    let path = dir.path().join("audit.json");
    let data_plane = AuditFailsAfterConnect {
        real: ssk_netcore::NetcoreDataPlane::new(std::sync::Arc::new(
            ssk_netcore::RouteExecutor::new(ssk_netcore::AdapterRegistry::new()),
        )),
        path: path.clone(),
    };
    let supervisor = ssk_daemon::supervisor::Supervisor::new(
        path,
        Box::new(data_plane),
        Box::new(ssk_daemon::killswitch::NoProvider),
        Ok(loopback_config()),
    );
    #[cfg(windows)]
    let peer = ssk_ipc::PeerIdentity::Sid("test".into());
    #[cfg(unix)]
    let peer = ssk_ipc::PeerIdentity::Uid(0);
    let mut events = supervisor.subscribe_events().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    match supervisor.handle(activate(&listener), &peer).await {
        Response::Err(error) => assert_eq!(error.class, "Integrity"),
        other => panic!("audit failure reported success: {other:?}"),
    }
    let (mut connection, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("must have really connected")
        .expect("accept");
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(2), connection.read(&mut byte))
        .await
        .expect("unaudited connection must be closed");
    assert!(
        matches!(read, Ok(0))
            || matches!(read, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionReset)
    );
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(
                event,
                ssk_ipc::Event::StateChanged {
                    to: DaemonState::Protected,
                    ..
                }
            ),
            "Protected must not be emitted before the durable result"
        );
    }
    assert_eq!(supervisor.current_state().await, DaemonState::FailClosed);
}

/// A proxy that accepts the TCP connection and then never speaks can only be
/// ended by a deadline. The daemon must own one of its own: the mutex is held
/// across the dial, so an unbounded dial is an unbounded status/deactivate
/// outage, and a deadline that lives only in the executor is not the daemon's
/// to promise.
#[tokio::test]
async fn silent_proxy_ends_fail_closed_at_the_activation_deadline_and_status_answers() {
    use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter};
    use ssk_ipc::CommandHandler;
    use ssk_netadmin::audit::AuditOutcome;
    use tokio::io::AsyncReadExt;

    let dir = tempfile::tempdir().expect("state directory");
    let path = dir.path().join("audit.json");
    let proxy = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
    let port = proxy.local_addr().expect("address").port();
    // Accepted sockets are handed to the test and kept open: the peer must see
    // silence, not a reset, or the dial would end on its own.
    let (accepted_tx, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((socket, _)) = proxy.accept().await {
            if accepted_tx.send(socket).is_err() {
                break;
            }
        }
    });

    let mut loaded = loopback_config();
    let rule = &mut loaded.config.routing.profiles[0].rules[0];
    rule.destination = Some("service.corp.invalid".into());
    rule.port = Some(8443);
    rule.action = RoutingAction::Adapter {
        adapter_id: "silent-proxy".into(),
    };
    loaded.config.routing.adapters.push(RoutingAdapter {
        id: "silent-proxy".into(),
        transport: AdapterTransport::Socks5 {
            host: "127.0.0.1".into(),
            port,
        },
    });
    let registry = ssk_daemon::routing::ConfiguredRouting::new(&loaded.config.routing).adapters;
    // The executor keeps its own, longer, dial deadline: only the daemon's
    // bound can fire inside this test.
    let data_plane = ssk_netcore::NetcoreDataPlane::new(std::sync::Arc::new(
        ssk_netcore::RouteExecutor::new(registry),
    ));
    let supervisor = ssk_daemon::supervisor::Supervisor::new(
        path.clone(),
        Box::new(data_plane),
        Box::new(ssk_daemon::killswitch::NoProvider),
        Ok(loaded),
    )
    .with_activation_deadline(Duration::from_millis(300));
    #[cfg(windows)]
    let peer = ssk_ipc::PeerIdentity::Sid("test".into());
    #[cfg(unix)]
    let peer = ssk_ipc::PeerIdentity::Uid(0);
    let mut events = supervisor.subscribe_events().await;

    let request = Request::ActivateProfile(ActivateProfileRequest {
        profile_id: "default".into(),
        dest_host: Some("service.corp.invalid".into()),
        dest_port: Some(8443),
    });
    let response = tokio::time::timeout(Duration::from_secs(5), supervisor.handle(request, &peer))
        .await
        .expect("a silent upstream must not hold the activation past the daemon's own deadline");
    match response {
        Response::Status(status) => {
            assert_eq!(status.state, DaemonState::FailClosed);
            let error = status.last_error.expect("the failure must be reported");
            assert_eq!(error.code, "ACTIVATION_CONNECT_TIMEOUT");
            assert!(!error.retriable, "the daemon never retries a dial itself");
            assert!(status.active_profile.is_none());
            assert!(status.adapters.is_empty());
            assert!(!status.dns_protected);
        }
        other => panic!("a stalled dial was not reported as a fail-closed status: {other:?}"),
    }
    assert_eq!(supervisor.current_state().await, DaemonState::FailClosed);

    // The dial really reached the silent proxy exactly once, and expiry closed
    // that socket instead of leaving a half-built tunnel behind.
    let mut connection = accepted.try_recv().expect("the proxy was dialed");
    assert!(
        accepted.try_recv().is_err(),
        "an expired dial must not be retried"
    );
    // The client's SOCKS5 greeting is already in flight; it is the only thing
    // the proxy may ever see before EOF.
    let mut buffer = [0; 16];
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match connection.read(&mut buffer).await {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) => return error.kind() == std::io::ErrorKind::ConnectionReset,
            }
        }
    })
    .await
    .expect("an expired dial must be closed");
    assert!(closed);

    // The durable result is the same one every other failed dial writes.
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(&path);
    ledger.verify().expect("durable valid chain");
    let entries = ledger.entries().expect("entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].outcome, AuditOutcome::DispatchPending);
    assert_eq!(entries[1].outcome, AuditOutcome::FailClosed);

    // Neither Protected nor a stuck Activating was ever the last word.
    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let ssk_ipc::Event::StateChanged { to, .. } = event {
            states.push(to);
        }
    }
    assert_eq!(states, [DaemonState::Activating, DaemonState::FailClosed]);

    match tokio::time::timeout(
        Duration::from_secs(1),
        supervisor.handle(Request::GetStatus, &peer),
    )
    .await
    .expect("status must answer after the dial expired")
    {
        Response::Status(status) => {
            assert_eq!(status.state, DaemonState::FailClosed);
            assert_eq!(
                status.last_error.expect("failure stays visible").code,
                "ACTIVATION_CONNECT_TIMEOUT"
            );
            assert_eq!(
                status.audit_head.as_deref(),
                Some(entries[1].entry_hash.as_str())
            );
        }
        other => panic!("status unavailable: {other:?}"),
    }
}
