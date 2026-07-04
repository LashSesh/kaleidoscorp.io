//! Literal Phase 2 acceptance criterion: "a killed daemon task transitions to
//! degraded/fail_closed and emits an event." Exercises the real
//! `Supervisor::spawn_supervised` watchdog mechanism (`src/supervisor.rs`) —
//! not a simulated call to `record_task_failure` directly.

use std::sync::Arc;
use std::time::Duration;

use ssk_daemon::mock_dataplane::AlwaysUpMockDataPlane;
use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{CommandHandler, DaemonState, Event};

fn supervisor() -> (Arc<Supervisor>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.json");
    (
        Arc::new(Supervisor::new(audit_path, Box::new(AlwaysUpMockDataPlane))),
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

    // Bring the daemon to Protected with an active profile first.
    let token = ssk_ipc::SessionToken::generate();
    sup.handle(
        ssk_ipc::Request::ActivateProfile(ssk_ipc::ActivateProfileRequest {
            profile_id: "default".into(),
        }),
        &token,
    )
    .await;
    assert_eq!(sup.current_state().await, DaemonState::Protected);

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
