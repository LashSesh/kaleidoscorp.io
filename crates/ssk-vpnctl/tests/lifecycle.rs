use ssk_vpnctl::{
    Command, CredentialKind, Event, Failure, ManagementPassword, Session, Stage, Timeouts, VpnState,
};
use std::time::Duration;

fn at(seconds: u64) -> Duration {
    Duration::from_secs(seconds)
}
fn password() -> ManagementPassword {
    ManagementPassword::new(b"test-only-management-secret".to_vec()).unwrap()
}
fn new() -> Session {
    Session::new(password(), 123, Timeouts::default(), at(0)).unwrap()
}
fn command(actual: Option<Command>, expected: &str) {
    assert_eq!(actual.unwrap().into_bytes().as_slice(), expected.as_bytes());
}
fn held_session() -> Session {
    let mut session = new();
    command(
        session.on_event(Event::PasswordPrompt, at(0)).unwrap(),
        "test-only-management-secret\n",
    );
    command(
        session.on_event(Event::Authenticated, at(0)).unwrap(),
        "pid\n",
    );
    session
        .on_event(
            Event::Hold {
                retry_after_secs: 1,
            },
            at(0),
        )
        .unwrap();
    command(
        session.on_event(Event::Pid(123), at(0)).unwrap(),
        "state on\n",
    );
    assert!(session
        .on_event(Event::StateSubscribed, at(0))
        .unwrap()
        .is_none());
    assert_eq!(session.snapshot().stage, Stage::WaitingForHold);
    session
}
fn connected_session() -> Session {
    let mut session = held_session();
    command(session.tick(at(1)).unwrap(), "hold release\n");
    session.on_event(Event::HoldReleased, at(1)).unwrap();
    session
        .on_event(Event::State(VpnState::Connecting), at(1))
        .unwrap();
    session
        .on_event(Event::State(VpnState::Connected), at(1))
        .unwrap();
    assert_eq!(session.snapshot().stage, Stage::ConnectedUnverified);
    session
}

#[test]
fn holds_are_released_only_after_authentication_pid_and_subscription() {
    let mut session = held_session();
    assert!(session.tick(Duration::from_millis(999)).unwrap().is_none());
    command(session.tick(at(1)).unwrap(), "hold release\n");
    // An async CONNECTED may precede the release reply, but cannot complete setup.
    session
        .on_event(Event::State(VpnState::Connected), at(1))
        .unwrap();
    assert_eq!(session.snapshot().stage, Stage::Connecting);
    session.on_event(Event::HoldReleased, at(1)).unwrap();
    assert_eq!(session.snapshot().stage, Stage::ConnectedUnverified);
}

#[test]
fn spoofed_or_unsolicited_replies_never_advance_setup() {
    for event in [
        Event::Authenticated,
        Event::Pid(123),
        Event::StateSubscribed,
        Event::State(VpnState::Connected),
        Event::HoldReleased,
    ] {
        let mut session = new();
        assert_eq!(
            session.on_event(event, at(0)).unwrap_err(),
            Failure::UnexpectedResponse
        );
        assert_eq!(session.snapshot().stage, Stage::Failed);
    }
    let mut session = new();
    session.on_event(Event::PasswordPrompt, at(0)).unwrap();
    session.on_event(Event::Authenticated, at(0)).unwrap();
    assert_eq!(
        session.on_event(Event::Pid(999), at(0)).unwrap_err(),
        Failure::ProcessMismatch
    );
}

#[test]
fn fatal_authentication_credential_and_eof_failures_are_terminal() {
    for (event, expected) in [
        (Event::Fatal, Failure::Fatal),
        (
            Event::AuthenticationRejected,
            Failure::ManagementAuthentication,
        ),
        (Event::VpnAuthenticationFailed, Failure::VpnAuthentication),
        (
            Event::CredentialsRequired(CredentialKind::Auth),
            Failure::CredentialsRequired(CredentialKind::Auth),
        ),
        (Event::CommandRejected, Failure::CommandRejected),
        (Event::State(VpnState::Exiting), Failure::UnexpectedExit),
    ] {
        let mut session = connected_session();
        assert_eq!(session.on_event(event, at(2)).unwrap_err(), expected);
        assert_eq!(session.snapshot().reported_state, None);
        assert_eq!(
            session
                .on_event(Event::State(VpnState::Connected), at(2))
                .unwrap_err(),
            expected
        );
        assert_eq!(session.snapshot().stage, Stage::Failed);
    }
    let mut session = connected_session();
    assert_eq!(session.eof(at(2)).unwrap_err(), Failure::Disconnected);
}

#[test]
fn command_timeout_is_absolute_even_under_informational_flood() {
    let mut session = new();
    session.on_event(Event::PasswordPrompt, at(0)).unwrap();
    for millis in 1..3000 {
        session
            .on_event(Event::Ignored, Duration::from_millis(millis))
            .unwrap();
    }
    assert_eq!(
        session.on_event(Event::Authenticated, at(3)).unwrap_err(),
        Failure::CommandTimeout
    );
}

#[test]
fn startup_has_a_deadline_even_if_the_peer_keeps_progressing() {
    let mut session = held_session();
    session.tick(at(1)).unwrap();
    session.on_event(Event::HoldReleased, at(1)).unwrap();
    for second in 2..30 {
        let request = session
            .on_event(Event::State(VpnState::Authenticating), at(second))
            .unwrap();
        if request.is_some() {
            session.on_event(Event::Pid(123), at(second)).unwrap();
        }
    }
    assert_eq!(session.tick(at(30)).unwrap_err(), Failure::StartupTimeout);
}

#[test]
fn reconnect_and_heartbeat_never_reuse_a_connected_report_as_health() {
    let mut session = connected_session();
    session
        .on_event(Event::State(VpnState::Reconnecting), at(2))
        .unwrap();
    assert_eq!(session.snapshot().stage, Stage::Reconnecting);
    for second in 3..32 {
        let request = session
            .on_event(Event::State(VpnState::Connecting), at(second))
            .unwrap();
        if request.is_some() {
            command(request, "pid\n");
            session.on_event(Event::Pid(123), at(second)).unwrap();
        }
    }
    assert_eq!(
        session
            .on_event(Event::State(VpnState::Connected), at(32))
            .unwrap_err(),
        Failure::ReconnectTimeout
    );

    let mut session = connected_session();
    command(session.tick(at(5)).unwrap(), "pid\n");
    session.on_event(Event::Ignored, at(7)).unwrap();
    assert_eq!(session.tick(at(8)).unwrap_err(), Failure::CommandTimeout);
    assert_eq!(session.snapshot().stage, Stage::Failed);
}

#[test]
fn reconnect_hold_respects_backoff_and_requires_a_new_release_ack() {
    let mut session = connected_session();
    assert!(session
        .on_event(
            Event::Hold {
                retry_after_secs: 1
            },
            at(2)
        )
        .unwrap()
        .is_none());
    assert_eq!(session.snapshot().stage, Stage::Reconnecting);
    command(session.tick(at(3)).unwrap(), "hold release\n");
    session
        .on_event(Event::State(VpnState::Connected), at(3))
        .unwrap();
    assert_eq!(session.snapshot().stage, Stage::Connecting);
    session.on_event(Event::HoldReleased, at(3)).unwrap();
    assert_eq!(session.snapshot().stage, Stage::ConnectedUnverified);
    session
        .on_event(
            Event::Hold {
                retry_after_secs: 1,
            },
            at(4),
        )
        .unwrap();
    assert_eq!(
        session
            .on_event(Event::State(VpnState::Connected), at(4))
            .unwrap_err(),
        Failure::UnexpectedResponse
    );
}

#[test]
fn stop_is_serialized_after_pending_reply_and_eof_is_not_process_exit_proof() {
    let mut session = connected_session();
    session.tick(at(5)).unwrap(); // PID heartbeat is pending.
    assert!(session.request_stop(at(5)).unwrap().is_none());
    assert_eq!(session.snapshot().stage, Stage::Stopping);
    command(
        session.on_event(Event::Pid(123), at(6)).unwrap(),
        "signal SIGTERM\n",
    );
    session
        .on_event(Event::TerminationAcknowledged, at(6))
        .unwrap();
    session
        .on_event(Event::State(VpnState::Connected), at(6))
        .unwrap();
    assert_eq!(session.snapshot().stage, Stage::Stopping);
    assert_eq!(session.eof(at(6)).unwrap().stage, Stage::ManagementClosed);

    let mut session = connected_session();
    session.request_stop(at(2)).unwrap();
    session
        .on_event(Event::TerminationAcknowledged, at(2))
        .unwrap();
    assert_eq!(session.tick(at(7)).unwrap_err(), Failure::StopTimeout);
    let mut session = new();
    assert_eq!(
        session.request_stop(at(0)).unwrap_err(),
        Failure::StopBeforeAuthentication
    );
}

#[test]
fn backwards_clock_invalid_limits_and_command_injection_are_rejected() {
    let mut session = connected_session();
    assert_eq!(session.tick(at(0)).unwrap_err(), Failure::ClockRegression);
    assert!(Session::new(password(), 0, Timeouts::default(), at(0)).is_err());
    assert!(Session::new(
        password(),
        123,
        Timeouts {
            command: Duration::ZERO,
            ..Timeouts::default()
        },
        at(0)
    )
    .is_err());
    for invalid in [
        "short",
        "a-long-secret\nsignal SIGTERM",
        "a-long-secret\rpid",
        "a-long-secret\0bad",
    ] {
        assert!(ManagementPassword::new(invalid.as_bytes().to_vec()).is_err());
    }
    let secret = password();
    assert!(!format!("{secret:?}").contains("test-only-management-secret"));
    let mut session = new();
    let auth = session
        .on_event(Event::PasswordPrompt, at(0))
        .unwrap()
        .unwrap();
    assert!(!format!("{auth:?}").contains("test-only-management-secret"));
}

fn prepared_session() -> Session {
    let mut s = Session::new_held(password(), 123, Timeouts::default(), at(0)).unwrap();
    command(
        s.on_event(Event::PasswordPrompt, at(0)).unwrap(),
        "test-only-management-secret\n",
    );
    command(s.on_event(Event::Authenticated, at(0)).unwrap(), "pid\n");
    s.on_event(
        Event::Hold {
            retry_after_secs: 0,
        },
        at(0),
    )
    .unwrap();
    command(s.on_event(Event::Pid(123), at(0)).unwrap(), "state on\n");
    assert!(s.on_event(Event::StateSubscribed, at(0)).unwrap().is_none());
    assert_eq!(s.snapshot().stage, Stage::PreparedHeld);
    s
}
#[test]
fn prepared_mode_never_releases_hold_and_keeps_heartbeating_past_startup_deadline() {
    let mut s = prepared_session();
    for second in (5..=120).step_by(5) {
        command(s.tick(at(second)).unwrap(), "pid\n");
        assert!(s.on_event(Event::Pid(123), at(second)).unwrap().is_none());
        assert_eq!(s.snapshot().stage, Stage::PreparedHeld);
    }
    command(s.request_stop(at(121)).unwrap(), "signal SIGTERM\n");
    s.on_event(Event::TerminationAcknowledged, at(121)).unwrap();
    assert_eq!(s.eof(at(121)).unwrap().stage, Stage::ManagementClosed);
}
#[test]
fn prepared_mode_still_enforces_heartbeat_and_rejects_a_connected_claim() {
    let mut s = prepared_session();
    s.tick(at(5)).unwrap();
    assert_eq!(s.tick(at(8)).unwrap_err(), Failure::CommandTimeout);
    let mut s = prepared_session();
    assert_eq!(
        s.on_event(Event::State(VpnState::Connected), at(0))
            .unwrap_err(),
        Failure::UnexpectedResponse
    );
}
#[test]
fn held_mode_cannot_skip_startup_timeout_without_confirmed_hold() {
    let mut s = Session::new_held(password(), 123, Timeouts::default(), at(0)).unwrap();
    s.on_event(Event::PasswordPrompt, at(0)).unwrap();
    s.on_event(Event::Authenticated, at(0)).unwrap();
    s.on_event(Event::Pid(123), at(0)).unwrap();
    s.on_event(Event::StateSubscribed, at(0)).unwrap();
    assert_eq!(s.tick(at(30)).unwrap_err(), Failure::StartupTimeout);
}
