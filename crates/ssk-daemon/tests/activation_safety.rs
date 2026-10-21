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
            profile_id: None,
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

/// A kill-switch answer the test can change while an activation is in flight,
/// to prove the status overlay reads the provider when it answers rather than
/// when the activation started.
struct SwitchableKillSwitch(
    std::sync::Arc<std::sync::Mutex<ssk_daemon::killswitch::KillSwitchView>>,
);

impl ssk_daemon::killswitch::KillSwitchProvider for SwitchableKillSwitch {
    fn view(&self) -> ssk_daemon::killswitch::KillSwitchView {
        *self.0.lock().expect("kill-switch view")
    }
}

/// A supervisor whose `silent-proxy` adapter accepts the TCP connection and
/// never answers, with a deliberately long activation deadline: only the
/// test, not the daemon's own bound, ends a dial here. The loopback `Direct`
/// rule stays available so a test can establish a real session first.
struct SilentDial {
    supervisor: std::sync::Arc<ssk_daemon::supervisor::Supervisor>,
    view: std::sync::Arc<std::sync::Mutex<ssk_daemon::killswitch::KillSwitchView>>,
    accepted: tokio::sync::mpsc::UnboundedReceiver<tokio::net::TcpStream>,
    state: tempfile::TempDir,
}

async fn silent_dial() -> SilentDial {
    use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter, RoutingRule};
    let state = tempfile::tempdir().expect("state directory");
    let proxy = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
    let port = proxy.local_addr().expect("address").port();
    // Accepted sockets are handed to the test and kept open: the peer must
    // see silence, not a reset, or the dial would end on its own.
    let (accepted_tx, accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((socket, _)) = proxy.accept().await {
            if accepted_tx.send(socket).is_err() {
                break;
            }
        }
    });

    let mut loaded = loopback_config();
    let profile = &mut loaded.config.routing.profiles[0];
    profile.rules.push(RoutingRule {
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
    let registry = ssk_daemon::routing::ConfiguredRouting::new(&loaded.config.routing).adapters;
    let data_plane = ssk_netcore::NetcoreDataPlane::new(std::sync::Arc::new(
        ssk_netcore::RouteExecutor::new(registry),
    ));
    let view = std::sync::Arc::new(std::sync::Mutex::new(
        ssk_daemon::killswitch::KillSwitchView::NotEngaged,
    ));
    let supervisor = ssk_daemon::supervisor::Supervisor::new(
        state.path().join("audit.json"),
        Box::new(data_plane),
        Box::new(SwitchableKillSwitch(std::sync::Arc::clone(&view))),
        Ok(loaded),
    )
    .with_activation_deadline(Duration::from_secs(60));
    SilentDial {
        supervisor: std::sync::Arc::new(supervisor),
        view,
        accepted,
        state,
    }
}

fn test_peer() -> ssk_ipc::PeerIdentity {
    #[cfg(windows)]
    {
        ssk_ipc::PeerIdentity::Sid("test".into())
    }
    #[cfg(unix)]
    {
        ssk_ipc::PeerIdentity::Uid(0)
    }
}

fn silent_activation() -> Request {
    Request::ActivateProfile(ActivateProfileRequest {
        profile_id: "default".into(),
        dest_host: Some("service.corp.invalid".into()),
        dest_port: Some(8443),
    })
}

/// Ask for status the way the desktop client does: it gives up after 2 s, so
/// an answer that needs more than 1 s here is an answer the client never sees.
async fn status_within_a_second(
    supervisor: &ssk_daemon::supervisor::Supervisor,
) -> ssk_ipc::StatusDto {
    use ssk_ipc::CommandHandler;
    match tokio::time::timeout(
        Duration::from_secs(1),
        supervisor.handle(Request::GetStatus, &test_peer()),
    )
    .await
    .expect("GetStatus must answer while an activation dial is silent")
    {
        Response::Status(status) => status,
        other => panic!("GetStatus did not answer with a status: {other:?}"),
    }
}

/// Start the silent activation and wait until it really holds the supervisor
/// mutex across its dial: the proxy has accepted the TCP connection, which the
/// executor only does from inside `connect_route`.
async fn start_silent_activation(
    dial: &mut SilentDial,
) -> (tokio::task::JoinHandle<Response>, tokio::net::TcpStream) {
    use ssk_ipc::CommandHandler;
    let supervisor = std::sync::Arc::clone(&dial.supervisor);
    let activation =
        tokio::spawn(async move { supervisor.handle(silent_activation(), &test_peer()).await });
    let held = tokio::time::timeout(Duration::from_secs(5), dial.accepted.recv())
        .await
        .expect("the activation must dial the silent proxy")
        .expect("proxy accept loop");
    (activation, held)
}

/// Closing the silent proxy's socket ends the dial at once (EOF or reset in
/// the SOCKS5 handshake), so a test does not wait out the long deadline.
async fn end_the_dial(activation: tokio::task::JoinHandle<Response>, held: tokio::net::TcpStream) {
    drop(held);
    match tokio::time::timeout(Duration::from_secs(5), activation)
        .await
        .expect("closing the proxy socket must end the dial")
        .expect("activation task")
    {
        Response::Status(status) => assert_eq!(status.state, DaemonState::FailClosed),
        other => panic!("a failed dial was not reported as a fail-closed status: {other:?}"),
    }
}

/// The supervisor mutex is held across the activation dial, so before this a
/// proxy that accepted and then stayed silent kept `GetStatus` waiting for the
/// whole dial: the desktop client, which gives up after 2 s, saw no status at
/// all. The answer given instead must not repeat anything the daemon cannot
/// stand behind: the session a previous activation held is gone the moment a
/// new activation clears it, so no `Protected`, profile, adapter or DNS claim
/// may survive into the answer.
#[tokio::test]
async fn status_answers_while_activation_dial_is_silent() {
    use ssk_ipc::CommandHandler;
    let mut dial = silent_dial().await;

    // A real held session first, so a status served from a cache of the last
    // answer would still say Protected with a profile, an adapter and DNS.
    let target = TcpListener::bind("127.0.0.1:0").await.expect("target");
    let target_port = target.local_addr().expect("address").port();
    let accept = tokio::spawn(async move { target.accept().await });
    match dial
        .supervisor
        .handle(
            Request::ActivateProfile(ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(target_port),
            }),
            &test_peer(),
        )
        .await
    {
        Response::Status(status) => {
            assert_eq!(status.state, DaemonState::Protected);
            assert_eq!(status.active_profile.as_deref(), Some("default"));
            assert!(status.dns_protected);
            assert_eq!(status.adapters.len(), 1);
        }
        other => panic!("the first activation did not reach Protected: {other:?}"),
    }
    let _accepted_target = accept.await.expect("join").expect("accept");

    let (activation, held) = start_silent_activation(&mut dial).await;
    let started = Instant::now();
    let status = status_within_a_second(&dial.supervisor).await;
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "GetStatus took {:?} behind a silent dial",
        started.elapsed()
    );
    assert_eq!(status.state, DaemonState::Activating);
    assert!(
        status.active_profile.is_none(),
        "no profile is active while the new session does not exist yet"
    );
    assert!(
        status.adapters.is_empty(),
        "no adapter has been traversed yet"
    );
    assert!(
        !status.dns_protected,
        "no DNS protection is established during the dial"
    );
    assert!(
        status.last_error.is_none(),
        "a confirmed kill-switch answer and no error of this run: {:?}",
        status.last_error
    );
    assert!(!status.kill_switch);
    assert!(
        status.audit_head.is_none(),
        "the ledger is only readable under the lock: no head is claimed"
    );

    end_the_dial(activation, held).await;
    // The overlay does not outlive the activation.
    let after = status_within_a_second(&dial.supervisor).await;
    assert_eq!(after.state, DaemonState::FailClosed);
    assert!(after.last_error.is_some(), "the failed dial stays visible");
    assert!(after.audit_head.is_some());
}

/// `Activating` was transitioned to and emitted as an event, but a client
/// polling status could not read it while an activation ran: the state exists
/// only while the mutex is held, and status needed the mutex. It must be
/// observable by polling, repeatedly, and the parts of the answer that do not
/// need the mutex (the kill-switch view) must be read when the answer is given.
#[tokio::test]
async fn activating_is_observable() {
    use ssk_daemon::killswitch::{KillSwitchView, KILL_SWITCH_STATUS_UNKNOWN};
    let mut dial = silent_dial().await;
    let (activation, held) = start_silent_activation(&mut dial).await;

    // Polled more than once, and concurrently: each poll answers by itself.
    let (first, second) = tokio::join!(
        status_within_a_second(&dial.supervisor),
        status_within_a_second(&dial.supervisor)
    );
    assert_eq!(first.state, DaemonState::Activating);
    assert_eq!(second.state, DaemonState::Activating);
    assert!(!first.kill_switch && first.last_error.is_none());

    // The provider is read per answer, not captured when the activation began.
    *dial.view.lock().expect("kill-switch view") = KillSwitchView::EngagedConfirmed;
    let engaged = status_within_a_second(&dial.supervisor).await;
    assert_eq!(engaged.state, DaemonState::Activating);
    assert!(engaged.kill_switch);
    assert!(engaged.last_error.is_none());

    // An unknown kill switch stays visible, never rounded to a clean `false`.
    *dial.view.lock().expect("kill-switch view") = KillSwitchView::Unknown {
        reason: "the privileged broker could not be reached",
    };
    let unknown = status_within_a_second(&dial.supervisor).await;
    assert_eq!(unknown.state, DaemonState::Activating);
    assert!(!unknown.kill_switch);
    assert_eq!(
        unknown.last_error.expect("unknown must be marked").code,
        KILL_SWITCH_STATUS_UNKNOWN
    );

    *dial.view.lock().expect("kill-switch view") = KillSwitchView::NotEngaged;
    end_the_dial(activation, held).await;
    let settled = status_within_a_second(&dial.supervisor).await;
    assert_eq!(
        settled.state,
        DaemonState::FailClosed,
        "Activating must not be the last word once the dial has ended"
    );
}

/// Subscribing only needs the event bus, but it used to be read out of the
/// state machine behind the supervisor mutex, so a silent dial kept every new
/// subscriber waiting for the whole dial. The bus is a clone of the sender the
/// state machine publishes on, held outside the mutex: a subscriber that joins
/// mid-dial is live at once, and it hears what the dial's end publishes.
#[tokio::test]
async fn subscribe_events_does_not_wait_for_a_dial() {
    let mut dial = silent_dial().await;
    let (activation, held) = start_silent_activation(&mut dial).await;

    let mut events =
        tokio::time::timeout(Duration::from_secs(1), dial.supervisor.subscribe_events())
            .await
            .expect("subscribe_events must not wait behind a silent dial");

    end_the_dial(activation, held).await;

    // `Activating` was published before this subscriber existed; what the
    // dial's end publishes, through the state machine's own sender, reaches it.
    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let ssk_ipc::Event::StateChanged { to, .. } = event {
            states.push(to);
        }
    }
    assert_eq!(states, [DaemonState::FailClosed]);
}

/// The `ActivateProfile` future is dropped while it holds the mutex across its
/// dial: the task serving a client that went away is aborted, the runtime is
/// shutting down, or a caller's own timeout fired. Nothing after the dial's
/// `await` runs then, so the `Activating` state stayed for ever with no session
/// behind it and nothing that resets it, and the ledger kept a lone
/// `DispatchPending` that never got its result.
#[tokio::test]
async fn a_cancelled_activation_settles_fail_closed_and_records_it() {
    use ssk_netadmin::audit::AuditOutcome;
    use tokio::io::AsyncReadExt;

    let mut dial = silent_dial().await;
    let mut events = dial.supervisor.subscribe_events().await;
    let (activation, mut held) = start_silent_activation(&mut dial).await;

    activation.abort();
    assert!(activation.await.expect_err("aborted").is_cancelled());

    let status = status_within_a_second(&dial.supervisor).await;
    assert_eq!(
        status.state,
        DaemonState::FailClosed,
        "a cancelled activation must not leave Activating (or Protected) behind"
    );
    let error = status
        .last_error
        .expect("the interruption must be reported");
    assert_eq!(error.code, "ACTIVATION_CANCELLED");
    assert!(status.active_profile.is_none());
    assert!(status.adapters.is_empty());
    assert!(!status.dns_protected);

    // The dial was dropped with the future: the half-built tunnel is closed
    // and the proxy only ever saw the client's greeting before EOF.
    let mut buffer = [0; 16];
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match held.read(&mut buffer).await {
                Ok(0) => return true,
                Ok(_) => {}
                Err(error) => return error.kind() == std::io::ErrorKind::ConnectionReset,
            }
        }
    })
    .await
    .expect("a cancelled dial must be closed");
    assert!(closed);

    // The same durable pair every other failed dial leaves, for the same flow.
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(dial.state.path().join("audit.json"));
    ledger.verify().expect("durable valid chain");
    let entries = ledger.entries().expect("entries");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].outcome, AuditOutcome::DispatchPending);
    assert_eq!(entries[1].outcome, AuditOutcome::FailClosed);
    assert_eq!(entries[0].flow_id, entries[1].flow_id);
    assert_eq!(
        status.audit_head.as_deref(),
        Some(entries[1].entry_hash.as_str())
    );

    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        if let ssk_ipc::Event::StateChanged { to, .. } = event {
            states.push(to);
        }
    }
    assert_eq!(states, [DaemonState::Activating, DaemonState::FailClosed]);
}

/// The data plane is real up to the moment it is asked to dial: the handler
/// panics while it holds `Inner` and the dial is pending. `Inner` sits behind
/// an async mutex that does not poison, so the next request gets the state the
/// panic left.
struct PanicsMidDial(ssk_netcore::NetcoreDataPlane);

impl ssk_netcore::DataPlane for PanicsMidDial {
    fn probe_route<'a>(
        &'a self,
        route: &'a ssk_netadmin::RouteKind,
        target: (&'a str, u16),
    ) -> ssk_netcore::BoxFuture<'a, ssk_netcore::ProbeReport> {
        self.0.probe_route(route, target)
    }

    fn connect_route<'a>(
        &'a self,
        _admission: ssk_netadmin::admission::AdmissionToken,
    ) -> ssk_netcore::BoxFuture<'a, Result<ssk_netcore::EgressSession, ssk_netcore::NetcoreError>>
    {
        Box::pin(async move { panic!("injected: the data plane failed mid-dial") })
    }
}

#[tokio::test]
async fn a_panicking_activation_settles_fail_closed() {
    use ssk_ipc::CommandHandler;

    let dir = tempfile::tempdir().expect("state directory");
    let path = dir.path().join("audit.json");
    let data_plane = PanicsMidDial(ssk_netcore::NetcoreDataPlane::new(std::sync::Arc::new(
        ssk_netcore::RouteExecutor::new(ssk_netcore::AdapterRegistry::new()),
    )));
    let supervisor = std::sync::Arc::new(ssk_daemon::supervisor::Supervisor::new(
        path.clone(),
        Box::new(data_plane),
        Box::new(ssk_daemon::killswitch::NoProvider),
        Ok(loopback_config()),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");

    // Spawned, as the IPC server spawns a task per connection: the panic ends
    // that task and nothing else.
    let activation = {
        let supervisor = std::sync::Arc::clone(&supervisor);
        let request = activate(&listener);
        tokio::spawn(async move { supervisor.handle(request, &test_peer()).await })
    };
    let panic = tokio::time::timeout(Duration::from_secs(5), activation)
        .await
        .expect("the panicking activation must end")
        .expect_err("the handler panicked");
    assert!(panic.is_panic());

    let status = status_within_a_second(&supervisor).await;
    assert_eq!(
        status.state,
        DaemonState::FailClosed,
        "a panicking activation must not leave Activating (or Protected) behind"
    );
    assert_eq!(
        status
            .last_error
            .expect("the failure must be reported")
            .code,
        "ACTIVATION_CANCELLED"
    );
    assert!(status.active_profile.is_none());
    assert!(status.adapters.is_empty());
    assert!(!status.dns_protected);
    assert_no_connection(&listener).await;

    // The intent is still on record and the chain was not damaged by the
    // unwinding.
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(&path);
    ledger.verify().expect("durable valid chain");
    let entries = ledger.entries().expect("entries");
    assert_eq!(
        entries[0].outcome,
        ssk_netadmin::audit::AuditOutcome::DispatchPending
    );
}

// ---------------------------------------------------------------------------
// Control-plane liveness during an activation dial, over the real Unix
// transport. The supervisor mutex is held across the dial, and the IPC server
// serves at most 16 connections at once (`ServeLimits::default`): a request
// that queues behind the dial keeps its connection, so enough of them leave a
// status read with no connection to arrive on, whatever the status handler
// itself does. These tests drive the same `serve_unix_with_limits` loop `sskd`
// runs, with one client connection per request as separate `ssk` invocations
// would use.
// ---------------------------------------------------------------------------

/// The supervisor of a [`SilentDial`], served on a Unix socket.
#[cfg(unix)]
struct Served {
    socket: std::path::PathBuf,
    _directory: tempfile::TempDir,
    server: tokio::task::JoinHandle<Result<(), ssk_ipc::IpcError>>,
}

#[cfg(unix)]
impl Drop for Served {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[cfg(unix)]
impl Served {
    async fn connect(&self) -> DaemonClient {
        DaemonClient::connect_path(&self.socket)
            .await
            .expect("connect to the served supervisor")
    }
}

#[cfg(unix)]
async fn serve(supervisor: std::sync::Arc<ssk_daemon::supervisor::Supervisor>) -> Served {
    let directory = tempfile::tempdir().expect("socket directory");
    let socket = directory.path().join("sskd.sock");
    let handler: std::sync::Arc<dyn ssk_ipc::CommandHandler> = supervisor;
    let server = tokio::spawn(ssk_ipc::server::serve_unix_with_limits(
        socket.clone(),
        handler,
        ssk_ipc::ServeLimits::default(),
    ));
    // Readiness is a connection, as in `start`: the socket file appears at bind,
    // before the accept loop runs.
    let deadline = Instant::now() + Duration::from_secs(5);
    while DaemonClient::connect_path(&socket).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "the served supervisor never accepted a connection"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Served {
        socket,
        _directory: directory,
        server,
    }
}

/// One request on its own connection, answered within `bound`; `None` when it
/// was not. The connection is closed afterwards, as the CLI does.
#[cfg(unix)]
async fn call_within(served: &Served, request: Request, bound: Duration) -> Option<Response> {
    let mut client = served.connect().await;
    tokio::time::timeout(bound, client.call(request))
        .await
        .ok()
        .map(|answer| answer.expect("the daemon answered with a transport error"))
}

/// [`start_silent_activation`], with the activation sent over the transport.
#[cfg(unix)]
async fn start_served_silent_activation(
    served: &Served,
    dial: &mut SilentDial,
) -> (tokio::task::JoinHandle<Response>, tokio::net::TcpStream) {
    let mut client = served.connect().await;
    let activation =
        tokio::spawn(async move { client.call(silent_activation()).await.expect("answer") });
    let held = tokio::time::timeout(Duration::from_secs(5), dial.accepted.recv())
        .await
        .expect("the activation must dial the silent proxy")
        .expect("proxy accept loop");
    (activation, held)
}

#[cfg(unix)]
fn deactivate_released() -> Request {
    Request::Deactivate(DeactivateRequest {
        release_kill_switch: true,
    })
}

#[cfg(unix)]
fn trace_request() -> Request {
    Request::TraceRoute(ssk_ipc::RouteTraceRequest {
        app_id: None,
        dest_host: "127.0.0.1".into(),
        dest_port: 443,
        protocol: "tcp".into(),
        risk: "low".into(),
        profile_id: None,
    })
}

/// Every request that is not a mutator used to queue behind the dial for as long
/// as it lasted (20 s in production). A request is now either answered from
/// what the daemon holds outside the mutex, or refused at once with the
/// retriable `DAEMON_BUSY`.
#[cfg(unix)]
#[tokio::test]
async fn read_handlers_answer_or_say_busy_while_activation_dials() {
    let mut dial = silent_dial().await;
    let served = serve(std::sync::Arc::clone(&dial.supervisor)).await;
    let (activation, held) = start_served_silent_activation(&served, &mut dial).await;

    // All at once, as a GUI refresh and a doctor run would arrive.
    let requests = [
        ("ListProfiles", Request::ListProfiles),
        ("RunDoctor", Request::RunDoctor),
        ("TraceRoute", trace_request()),
        ("GetAuditEntries", Request::GetAuditEntries { limit: 10 }),
        ("VerifyAuditChain", Request::VerifyAuditChain),
    ];
    let mut pending = Vec::new();
    for (name, request) in requests {
        let mut client = served.connect().await;
        pending.push((
            name,
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(1), client.call(request))
                    .await
                    .ok()
                    .map(|answer| answer.expect("transport error"))
            }),
        ));
    }
    let mut answers = Vec::new();
    for (name, task) in pending {
        answers.push((name, task.await.expect("request task")));
    }
    let blocked: Vec<_> = answers
        .iter()
        .filter(|(_, answer)| answer.is_none())
        .map(|(name, _)| *name)
        .collect();
    assert!(
        blocked.is_empty(),
        "not answered within 1 s of a silent dial (queued behind it): {blocked:?}"
    );

    for (name, answer) in answers {
        match (name, answer.expect("answered")) {
            ("ListProfiles", Response::Profiles(profiles)) => {
                assert!(profiles.iter().any(|profile| profile.id == "default"));
            }
            ("RunDoctor", Response::Doctor(report)) => {
                let config = report
                    .checks
                    .iter()
                    .find(|check| check.name == "config")
                    .expect("the doctor still reports the configuration");
                assert!(config.ok, "{}", config.detail);
            }
            ("TraceRoute" | "GetAuditEntries" | "VerifyAuditChain", Response::Err(error)) => {
                assert_eq!(error.code, "DAEMON_BUSY", "{name}");
                assert_eq!(error.class, "Runtime", "{name}");
                assert!(error.retriable, "{name}: a busy answer is retriable");
                assert!(!error.next_steps.is_empty(), "{name}: say what to do");
            }
            (name, other) => panic!("{name} answered with the wrong shape: {other:?}"),
        }
    }

    // Busy is a statement about the dial, not a state of the daemon.
    end_the_dial(activation, held).await;
    match call_within(&served, trace_request(), Duration::from_secs(1)).await {
        Some(Response::RouteTrace(trace)) => {
            assert!(matches!(trace.route, ssk_netadmin::RouteKind::Direct));
        }
        other => panic!("TraceRoute must answer once the dial has ended: {other:?}"),
    }
    match call_within(
        &served,
        Request::GetAuditEntries { limit: 10 },
        Duration::from_secs(1),
    )
    .await
    {
        Some(Response::AuditEntries(entries)) => assert_eq!(entries.len(), 2),
        other => panic!("GetAuditEntries must answer once the dial has ended: {other:?}"),
    }
    match call_within(&served, Request::VerifyAuditChain, Duration::from_secs(1)).await {
        Some(Response::AuditVerify(verdict)) => assert!(verdict.ok),
        other => panic!("VerifyAuditChain must answer once the dial has ended: {other:?}"),
    }
}

/// The measured defect: one activation and 15 requests that queue behind it use
/// all 16 connections, and a 17th client asking `GetStatus` was served 0.6 ms
/// after the dial ended and not before. Mutators are what can still queue, so
/// they are what the gate counts: the second waits for its turn, the others are
/// refused at once and give their connections back.
#[cfg(unix)]
#[tokio::test]
async fn status_is_served_while_mutators_queue_on_ipc() {
    let mut dial = silent_dial().await;
    let served = serve(std::sync::Arc::clone(&dial.supervisor)).await;
    let (activation, held) = start_served_silent_activation(&served, &mut dial).await;

    // 15 more: with the activation's own connection that is the whole of
    // `ServeLimits::default().max_connections`. Each one is a client that sends
    // one request, reads the answer and goes away.
    let mut waiting = Vec::new();
    for _ in 0..15 {
        let mut client = served.connect().await;
        waiting.push(tokio::spawn(async move {
            client.call(deactivate_released()).await.expect("answer")
        }));
    }
    // Long enough for every one of them to be connected and inside its handler.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let started = Instant::now();
    match call_within(&served, Request::GetStatus, Duration::from_secs(1)).await {
        Some(Response::Status(status)) => assert_eq!(status.state, DaemonState::Activating),
        Some(other) => panic!("GetStatus did not answer with a status: {other:?}"),
        None => panic!(
            "the 17th client was not served within 1 s: the connections were all held by \
             requests queued behind the dial"
        ),
    }
    assert!(started.elapsed() < Duration::from_secs(1));

    end_the_dial(activation, held).await;
    let mut busy = 0;
    let mut deactivated = 0;
    for task in waiting {
        match tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("a queued Deactivate ends with the dial")
            .expect("request task")
        {
            Response::Err(error) if error.code == "DAEMON_BUSY" => busy += 1,
            Response::Status(status) if status.state == DaemonState::Inactive => deactivated += 1,
            other => panic!("unexpected answer to a Deactivate behind a dial: {other:?}"),
        }
    }
    assert_eq!(
        (busy, deactivated),
        (14, 1),
        "the activation and one Deactivate are the two mutators; the other 14 are refused"
    );
}

/// The status that is built around a dial is a different literal from the idle
/// one. It says which protocol the daemon speaks and carries the proxy's block
/// all the same, so that a client does not take a daemon that is busy dialing for
/// one that predates the proxy (`ingress: None`, protocol 0).
#[cfg(unix)]
#[tokio::test]
async fn a_status_read_during_a_silent_activation_carries_protocol_and_the_ingress_block() {
    let mut dial = silent_dial().await;
    let served = serve(std::sync::Arc::clone(&dial.supervisor)).await;
    let (activation, held) = start_served_silent_activation(&served, &mut dial).await;

    match call_within(&served, Request::GetStatus, Duration::from_secs(1)).await {
        Some(Response::Status(status)) => {
            assert_eq!(status.state, DaemonState::Activating);
            assert_eq!(status.protocol, ssk_ipc::IPC_PROTOCOL_VERSION);
            let ingress = status
                .ingress
                .expect("a daemon of protocol 1 never answers `ingress: None`");
            assert_eq!(ingress.state, "disabled");
            assert_eq!(ingress.coverage, "none");
        }
        Some(other) => panic!("GetStatus did not answer with a status: {other:?}"),
        None => panic!("GetStatus was not served within 1 s of the dial starting"),
    }

    end_the_dial(activation, held).await;
}

/// The gate holds two: the activation that is dialing and one request behind
/// it. A third mutating request, of either kind, is refused at once, changes
/// nothing and writes nothing, and the gate is whole again afterwards.
#[cfg(unix)]
#[tokio::test]
async fn third_mutating_request_is_refused_daemon_busy() {
    use ssk_netadmin::audit::AuditOutcome;

    let mut dial = silent_dial().await;
    let mut events = dial.supervisor.subscribe_events().await;
    let served = serve(std::sync::Arc::clone(&dial.supervisor)).await;
    let (activation, held) = start_served_silent_activation(&served, &mut dial).await;

    let queued = {
        let mut client = served.connect().await;
        tokio::spawn(async move { client.call(deactivate_released()).await.expect("answer") })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!queued.is_finished(), "the second mutator waits its turn");

    for (name, request) in [
        ("ActivateProfile", silent_activation()),
        ("Deactivate", deactivate_released()),
    ] {
        match call_within(&served, request, Duration::from_secs(1)).await {
            Some(Response::Err(error)) => {
                assert_eq!(error.code, "DAEMON_BUSY", "{name}");
                assert_eq!(error.class, "Runtime", "{name}");
                assert!(error.retriable, "{name}: a busy answer is retriable");
            }
            Some(other) => panic!("a third {name} must be refused, got: {other:?}"),
            None => panic!("a third {name} queued behind two mutators instead of being refused"),
        }
    }
    // Refusing them neither moved the daemon nor disturbed the dial.
    match call_within(&served, Request::GetStatus, Duration::from_secs(1)).await {
        Some(Response::Status(status)) => assert_eq!(status.state, DaemonState::Activating),
        other => panic!("status must still answer around the dial: {other:?}"),
    }

    end_the_dial(activation, held).await;
    match tokio::time::timeout(Duration::from_secs(5), queued)
        .await
        .expect("the queued Deactivate ends with the dial")
        .expect("request task")
    {
        Response::Status(status) => assert_eq!(status.state, DaemonState::Inactive),
        other => panic!("the queued Deactivate must run after the activation: {other:?}"),
    }

    // The two mutators' own transitions and nothing from the refused ones: no
    // second activation started, no warning was raised for them.
    let mut states = Vec::new();
    while let Ok(event) = events.try_recv() {
        match event {
            ssk_ipc::Event::StateChanged { to, .. } => states.push(to),
            ssk_ipc::Event::Warning { code, .. } => panic!("a refusal raised a warning: {code}"),
            _ => {}
        }
    }
    assert_eq!(
        states,
        [
            DaemonState::Activating,
            DaemonState::FailClosed,
            DaemonState::Inactive
        ]
    );
    let ledger = ssk_netadmin::audit::AuditLedger::persisted(dial.state.path().join("audit.json"));
    ledger.verify().expect("durable valid chain");
    let entries = ledger.entries().expect("entries");
    assert_eq!(entries.len(), 2, "a refused activation writes no intent");
    assert_eq!(entries[0].outcome, AuditOutcome::DispatchPending);
    assert_eq!(entries[1].outcome, AuditOutcome::FailClosed);

    // Both permits came back: two more mutators can be in flight.
    match call_within(&served, deactivate_released(), Duration::from_secs(1)).await {
        Some(Response::Status(status)) => assert_eq!(status.state, DaemonState::Inactive),
        other => panic!("the gate must be free again: {other:?}"),
    }
}

/// `Deactivate` is the one handler that keeps queueing behind a dial, by
/// design: the mutex is FIFO, so a `Deactivate` sent after an `ActivateProfile`
/// runs after it and its result stands. An activation that finished after a
/// `Deactivate` had been answered would undo it.
#[cfg(unix)]
#[tokio::test]
async fn deactivate_waits_its_turn_behind_an_activation() {
    let mut dial = silent_dial().await;
    let served = serve(std::sync::Arc::clone(&dial.supervisor)).await;
    let (activation, held) = start_served_silent_activation(&served, &mut dial).await;

    let deactivate = {
        let mut client = served.connect().await;
        tokio::spawn(async move { client.call(deactivate_released()).await.expect("answer") })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !deactivate.is_finished(),
        "a Deactivate sent after an activation must not overtake it"
    );
    match call_within(&served, Request::GetStatus, Duration::from_secs(1)).await {
        Some(Response::Status(status)) => assert_eq!(status.state, DaemonState::Activating),
        other => panic!("status must answer around the dial: {other:?}"),
    }

    end_the_dial(activation, held).await;
    match tokio::time::timeout(Duration::from_secs(5), deactivate)
        .await
        .expect("the Deactivate runs once the activation is over")
        .expect("request task")
    {
        Response::Status(status) => assert_eq!(status.state, DaemonState::Inactive),
        other => panic!("unexpected answer to the Deactivate: {other:?}"),
    }
    match call_within(&served, Request::GetStatus, Duration::from_secs(1)).await {
        Some(Response::Status(status)) => assert_eq!(
            status.state,
            DaemonState::Inactive,
            "the activation's failure must not have been written over the Deactivate"
        ),
        other => panic!("status unavailable: {other:?}"),
    }
}
