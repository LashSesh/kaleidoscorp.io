//! Literal Phase 2 acceptance criterion: "event backpressure yields Lagged."
//! Exercises this through the Supervisor's real event bus while it services
//! genuine `ActivateProfile`/`Deactivate` requests — complementing (not
//! duplicating) `ssk-daemon`'s lower-level `state::tests` unit test, which
//! exercises the same guarantee directly on `StateMachine`.

use std::sync::Arc;

use ssk_daemon::supervisor::Supervisor;
use ssk_ipc::{ActivateProfileRequest, CommandHandler, DeactivateRequest, PeerIdentity, Request};

/// The identity a transport would have verified. `SessionToken` is gone: it
/// was a value the server minted, never transmitted and never compared, so it
/// authenticated nothing. `PeerIdentity` is what the transport's
/// authentication step actually produces.
fn test_peer() -> PeerIdentity {
    #[cfg(unix)]
    {
        PeerIdentity::Uid(0)
    }
    #[cfg(not(unix))]
    {
        PeerIdentity::Sid("S-1-5-21-0-0-0-1000".into())
    }
}
use ssk_netcore::{AdapterRegistry, NetcoreDataPlane, RouteExecutor};
use tokio::net::TcpListener;

#[tokio::test]
async fn lagging_subscriber_observes_lagged_during_real_activity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_path = dir.path().join("audit.json");
    let data_plane = Box::new(NetcoreDataPlane::new(Arc::new(RouteExecutor::new(
        AdapterRegistry::new(),
    ))));
    // This file is about event backpressure, not the kill-switch. `NoProvider`
    // answers `Unknown` — the truth for a process with no privileged broker to
    // ask — rather than a convenient `false`.
    let sup = Supervisor::new(
        audit_path,
        data_plane,
        Box::new(ssk_daemon::killswitch::NoProvider),
    );

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
    let peer = test_peer();

    // Drive enough real state transitions to overflow the bounded broadcast
    // channel while `events` never reads, forcing a genuine `Lagged`.
    for _ in 0..200u32 {
        sup.handle(
            Request::ActivateProfile(ActivateProfileRequest {
                profile_id: "default".into(),
                dest_host: Some("127.0.0.1".into()),
                dest_port: Some(addr.port()),
            }),
            &peer,
        )
        .await;
        sup.handle(
            Request::Deactivate(DeactivateRequest {
                release_kill_switch: false,
            }),
            &peer,
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
