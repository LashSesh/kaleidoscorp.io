//! Literal Phase 2 acceptance criterion: "event backpressure yields Lagged."
//! Exercises this through the Supervisor's real event bus while it services
//! genuine `ActivateProfile`/`Deactivate` requests — complementing (not
//! duplicating) `ssk-daemon`'s lower-level `state::tests` unit test, which
//! exercises the same guarantee directly on `StateMachine`.

use std::sync::Arc;

use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{ActivateProfileRequest, CommandHandler, DeactivateRequest, Request, SessionToken};
use ssk_netcore::{AdapterRegistry, NetcoreDataPlane, RouteExecutor};
use tokio::net::TcpListener;

#[tokio::test]
async fn lagging_subscriber_observes_lagged_during_real_activity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.json");
    let data_plane = Box::new(NetcoreDataPlane::new(Arc::new(RouteExecutor::new(
        AdapterRegistry::new(),
    ))));
    let sup = Supervisor::new(audit_path, data_plane);

    // A real, reachable local listener each `ActivateProfile` really
    // connects to (and each `Deactivate` really tears back down).
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let accept_all = tokio::spawn(async move {
        loop {
            if listener.accept().await.is_err() {
                break;
            }
        }
    });

    let mut events = sup.subscribe_events().await;
    let token = SessionToken::generate();

    // Drive enough real state transitions to overflow the bounded broadcast
    // channel while `events` never reads, forcing a genuine `Lagged`.
    for _ in 0..200u32 {
        sup.handle(
            Request::ActivateProfile(ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(addr.port()),
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
    accept_all.abort();

    let err = events
        .recv()
        .await
        .expect_err("subscriber must have lagged behind real daemon activity");
    assert!(matches!(
        err,
        tokio::sync::broadcast::error::RecvError::Lagged(_)
    ));
}
