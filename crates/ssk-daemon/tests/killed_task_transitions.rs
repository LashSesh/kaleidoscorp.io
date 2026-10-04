//! Literal Phase 2 acceptance criterion: "a killed daemon task transitions to
//! degraded/fail_closed and emits an event." Exercises the real
//! `Supervisor::spawn_supervised` watchdog mechanism (`src/supervisor.rs`) —
//! not a simulated call to `record_task_failure` directly.

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::sync::Arc;
use std::time::Duration;

use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{CommandHandler, DaemonState, Event, PeerIdentity};
use ssk_netcore::{AdapterRegistry, NetcoreDataPlane, RouteExecutor};
use tokio::net::TcpListener;

fn supervisor() -> (Arc<Supervisor>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.json");
    let data_plane = Box::new(NetcoreDataPlane::new(Arc::new(RouteExecutor::new(
        AdapterRegistry::new(),
    ))));
    // Kill-switch state is irrelevant to task-death transitions; `NoProvider`
    // reports `Unknown`, which is what a process with no broker actually knows.
    (
        Arc::new(Supervisor::new(
            audit_path,
            data_plane,
            Box::new(ssk_daemon::killswitch::NoProvider),
            Ok(loopback_config()),
        )),
        dir,
    )
}

async fn wait_for_state_changed_to(
    events: &mut tokio::sync::broadcast::Receiver<Event>,
    target: DaemonState,
) -> bool {
    for _ in 0..50 {
        match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
            Ok(Ok(Event::StateChanged { to, .. })) if to == target => return true,
            _ => {}
        }
    }
    false
}

#[tokio::test]
async fn killed_task_transitions_to_fail_closed_when_inactive() {
    let (sup, _dir) = supervisor();
    let mut events = sup.subscribe_events().await;

    let abort_handle = sup.spawn_supervised("test-worker", async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    // Simulate a crash/kill of the supervised task from outside — the
    // supervisor did not call this itself, exactly like a real panic/abort.
    abort_handle.abort();

    assert!(
        wait_for_state_changed_to(&mut events, DaemonState::FailClosed).await,
        "expected a StateChanged event to FailClosed after the task was killed"
    );
    assert_eq!(sup.current_state().await, DaemonState::FailClosed);
}

#[tokio::test]
async fn killed_task_transitions_to_degraded_when_a_profile_is_active() {
    let (sup, _dir) = supervisor();

    // Bring the daemon to Protected with a real, active egress first.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accept = tokio::spawn(async move { listener.accept().await });
    // `SessionToken` is gone; the handler now receives the identity the
    // transport verified.
    #[cfg(unix)]
    let peer = PeerIdentity::Uid(0);
    #[cfg(not(unix))]
    let peer = PeerIdentity::Sid("S-1-5-21-0-0-0-1000".into());
    sup.handle(
        ssk_ipc::Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
            profile_id: "default".into(),
            dest_host: Some("127.0.0.1".into()),
            dest_port: Some(addr.port()),
        }),
        &peer,
    )
    .await;
    assert_eq!(sup.current_state().await, DaemonState::Protected);
    accept.await.expect("join").expect("accept");

    let mut events = sup.subscribe_events().await;
    let abort_handle = sup.spawn_supervised("test-worker", async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });
    abort_handle.abort();

    assert!(
        wait_for_state_changed_to(&mut events, DaemonState::Degraded).await,
        "expected a StateChanged event to Degraded after the task was killed with an active profile"
    );
    assert_eq!(sup.current_state().await, DaemonState::Degraded);
}
