//! Literal Phase 2 acceptance criterion: "event backpressure yields Lagged."
//! Exercises this through the Supervisor's real event bus while it services
//! genuine `ActivateProfile`/`Deactivate` requests — complementing (not
//! duplicating) `ssk-daemon`'s lower-level `state::tests` unit test, which
//! exercises the same guarantee directly on `StateMachine`.

use ssk_daemon::mock_dataplane::AlwaysUpMockDataPlane;
use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{ActivateProfileRequest, CommandHandler, DeactivateRequest, Request, SessionToken};

#[tokio::test]
async fn lagging_subscriber_observes_lagged_during_real_activity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.json");
    let sup = Supervisor::new(audit_path, Box::new(AlwaysUpMockDataPlane));

    let mut events = sup.subscribe_events().await;
    let token = SessionToken::generate();

    // Drive enough real state transitions to overflow the bounded broadcast
    // channel while `events` never reads, forcing a genuine `Lagged`.
    for _ in 0..200u32 {
        sup.handle(
            Request::ActivateProfile(ActivateProfileRequest {
                profile_id: "default".into(),
            }),
            &token,
        )
        .await;
        sup.handle(
            Request::Deactivate(DeactivateRequest {
                release_kill_switch: false,
            }),
            &token,
        )
        .await;
    }

    let err = events
        .recv()
        .await
        .expect_err("subscriber must have lagged behind real daemon activity");
    assert!(matches!(
        err,
        tokio::sync::broadcast::error::RecvError::Lagged(_)
    ));
}
