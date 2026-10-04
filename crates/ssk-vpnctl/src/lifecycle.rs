use crate::{CredentialKind, Event, ProtocolError, VpnState};
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    #[error("invalid OpenVPN management configuration")]
    Configuration,
    #[error("OpenVPN management protocol: {0}")]
    Protocol(ProtocolError),
    #[error("unexpected OpenVPN management response")]
    UnexpectedResponse,
    #[error("OpenVPN management authentication failed")]
    ManagementAuthentication,
    #[error("OpenVPN management PID differs from the owned process")]
    ProcessMismatch,
    #[error("OpenVPN requested credentials; credential custody is not implemented ({0:?})")]
    CredentialsRequired(CredentialKind),
    #[error("OpenVPN VPN authentication failed")]
    VpnAuthentication,
    #[error("OpenVPN reported a fatal error")]
    Fatal,
    #[error("OpenVPN rejected a management command")]
    CommandRejected,
    #[error("OpenVPN management command timed out")]
    CommandTimeout,
    #[error("OpenVPN startup timed out")]
    StartupTimeout,
    #[error("OpenVPN reconnection timed out")]
    ReconnectTimeout,
    #[error("OpenVPN shutdown is unconfirmed; the owner must terminate and reap the process")]
    StopTimeout,
    #[error("OpenVPN cannot be stopped through an unauthenticated management channel")]
    StopBeforeAuthentication,
    #[error("OpenVPN management connection was lost")]
    Disconnected,
    #[error("OpenVPN exited unexpectedly")]
    UnexpectedExit,
    #[error("OpenVPN management I/O failed ({0:?})")]
    Io(std::io::ErrorKind),
    #[error("monotonic clock moved backwards")]
    ClockRegression,
    #[error("OpenVPN management session is closed")]
    Closed,
}

/// Supplied by the future process owner, generated independently for every
/// launch. Shape validation does not establish entropy or authenticate the peer.
pub struct ManagementPassword(Zeroizing<Vec<u8>>);

impl ManagementPassword {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Failure> {
        let bytes = Zeroizing::new(bytes);
        if !(16..=64).contains(&bytes.len()) || !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(Failure::Configuration);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ManagementPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ManagementPassword([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Authentication,
    Pid,
    Subscribe,
    ReleaseHold,
    Terminate,
}

/// One owned command, minted only by the lifecycle. No arbitrary command API.
pub struct Command {
    kind: Pending,
    password: Option<ManagementPassword>,
}

impl Command {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.kind {
            Pending::Authentication => "authenticate",
            Pending::Pid => "pid",
            Pending::Subscribe => "state on",
            Pending::ReleaseHold => "hold release",
            Pending::Terminate => "signal SIGTERM",
        }
    }

    /// Secrets remain in an owned zeroizing buffer through transport write.
    #[must_use]
    pub fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        if let Some(password) = self.password.take() {
            // Reserve the newline before copying: reallocating a secret Vec
            // would leave the old allocation outside Zeroizing's ownership.
            let mut bytes = Zeroizing::new(Vec::with_capacity(password.0.len() + 1));
            bytes.extend_from_slice(&password.0);
            bytes.push(b'\n');
            bytes
        } else {
            Zeroizing::new(format!("{}\n", self.name()).into_bytes())
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Command").field(&self.name()).finish()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    pub startup: Duration,
    pub command: Duration,
    pub reconnect: Duration,
    pub heartbeat: Duration,
    pub stop: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            startup: Duration::from_secs(30),
            command: Duration::from_secs(3),
            reconnect: Duration::from_secs(30),
            heartbeat: Duration::from_secs(5),
            stop: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Starting,
    Authenticating,
    WaitingForHold,
    /// Authenticated and held; this mode has no hold-release operation.
    PreparedHeld,
    Connecting,
    Reconnecting,
    /// A management report only. Not an interface, route or traffic guarantee.
    ConnectedUnverified,
    Stopping,
    /// EOF following a stop request. Process exit still needs OS confirmation.
    ManagementClosed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub stage: Stage,
    pub reported_state: Option<VpnState>,
    pub failure: Option<Failure>,
    /// Local monotonic observation time, never the peer's Unix timestamp.
    pub observed_at: Duration,
}

/// A fresh held-process session; terminal failures cannot be reset or revived.
/// Call tick on a monotonic timer even if the peer stops producing data.
pub struct Session {
    password: Option<ManagementPassword>,
    expected_pid: u32,
    timeouts: Timeouts,
    started_at: Duration,
    now: Duration,
    authenticated: bool,
    pid_verified: bool,
    subscribed: bool,
    release_sent: bool,
    release_acked: bool,
    pending: Option<(Pending, Duration)>,
    hold_until: Option<Duration>,
    reported: Option<VpnState>,
    ever_connected: bool,
    reconnect_since: Option<Duration>,
    last_pid_ack: Duration,
    stop_since: Option<Duration>,
    terminate_sent: bool,
    closed: bool,
    failure: Option<Failure>,
    keep_held: bool,
}

impl Session {
    pub fn new(
        password: ManagementPassword,
        expected_pid: u32,
        timeouts: Timeouts,
        now: Duration,
    ) -> Result<Self, Failure> {
        if expected_pid == 0
            || [
                timeouts.startup,
                timeouts.command,
                timeouts.reconnect,
                timeouts.heartbeat,
                timeouts.stop,
            ]
            .iter()
            .any(|t| t.is_zero() || *t > Duration::from_secs(300))
        {
            return Err(Failure::Configuration);
        }
        Ok(Self {
            password: Some(password),
            expected_pid,
            timeouts,
            started_at: now,
            now,
            authenticated: false,
            pid_verified: false,
            subscribed: false,
            release_sent: false,
            release_acked: false,
            pending: None,
            hold_until: None,
            reported: None,
            ever_connected: false,
            reconnect_since: None,
            last_pid_ack: now,
            stop_since: None,
            terminate_sent: false,
            closed: false,
            failure: None,
            keep_held: false,
        })
    }

    /// Prepares management only. There is deliberately no API to release this
    /// session's hold; network activation needs a separate enforcement design.
    pub fn new_held(
        password: ManagementPassword,
        expected_pid: u32,
        timeouts: Timeouts,
        now: Duration,
    ) -> Result<Self, Failure> {
        let mut session = Self::new(password, expected_pid, timeouts, now)?;
        session.keep_held = true;
        Ok(session)
    }

    fn prepared_held(&self) -> bool {
        self.keep_held
            && self.authenticated
            && self.pid_verified
            && self.subscribed
            && self.hold_until.is_some()
    }

    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let stage = if self.failure.is_some() {
            Stage::Failed
        } else if self.closed {
            Stage::ManagementClosed
        } else if self.stop_since.is_some() {
            Stage::Stopping
        } else if !self.authenticated {
            Stage::Authenticating
        } else if !self.subscribed {
            Stage::Starting
        } else if self.reconnect_since.is_some() {
            Stage::Reconnecting
        } else if self.prepared_held() {
            Stage::PreparedHeld
        } else if !self.release_sent {
            Stage::WaitingForHold
        } else if self.release_acked && self.reported == Some(VpnState::Connected) {
            Stage::ConnectedUnverified
        } else {
            Stage::Connecting
        };
        Snapshot {
            stage,
            reported_state: self.reported,
            failure: self.failure,
            observed_at: self.now,
        }
    }

    pub fn fail(&mut self, failure: Failure) -> Failure {
        let first = *self.failure.get_or_insert(failure);
        self.password = None;
        self.pending = None;
        self.reported = None;
        first
    }

    fn advance(&mut self, now: Duration) -> Result<(), Failure> {
        if let Some(failure) = self.failure {
            return Err(failure);
        }
        if self.closed {
            return Err(Failure::Closed);
        }
        if now < self.now {
            return Err(self.fail(Failure::ClockRegression));
        }
        self.now = now;
        let failure = if let Some(stop) = self.stop_since {
            (now - stop >= self.timeouts.stop).then_some(Failure::StopTimeout)
        } else if !self.ever_connected
            && !self.prepared_held()
            && now - self.started_at >= self.timeouts.startup
        {
            Some(Failure::StartupTimeout)
        } else if self
            .reconnect_since
            .is_some_and(|since| now - since >= self.timeouts.reconnect)
        {
            Some(Failure::ReconnectTimeout)
        } else {
            None
        };
        if let Some(failure) = failure {
            return Err(self.fail(failure));
        }
        if self
            .pending
            .is_some_and(|(_, sent)| now - sent >= self.timeouts.command)
        {
            return Err(self.fail(Failure::CommandTimeout));
        }
        Ok(())
    }

    fn issue(&mut self, kind: Pending) -> Command {
        self.pending = Some((kind, self.now));
        let password = if kind == Pending::Authentication {
            self.password.take()
        } else {
            None
        };
        Command { kind, password }
    }

    fn drive(&mut self) -> Option<Command> {
        if self.pending.is_some() || !self.authenticated {
            return None;
        }
        if self.stop_since.is_some() {
            if self.terminate_sent {
                return None;
            }
            self.terminate_sent = true;
            return Some(self.issue(Pending::Terminate));
        }
        if !self.pid_verified {
            return Some(self.issue(Pending::Pid));
        }
        if !self.subscribed {
            return Some(self.issue(Pending::Subscribe));
        }
        if !self.keep_held && self.hold_until.is_some_and(|due| self.now >= due) {
            self.hold_until = None;
            self.release_sent = true;
            self.release_acked = false;
            return Some(self.issue(Pending::ReleaseHold));
        }
        if (self.release_sent || self.prepared_held())
            && self.now - self.last_pid_ack >= self.timeouts.heartbeat
        {
            return Some(self.issue(Pending::Pid));
        }
        None
    }

    pub fn tick(&mut self, now: Duration) -> Result<Option<Command>, Failure> {
        self.advance(now)?;
        Ok(self.drive())
    }

    pub(crate) fn io_budget(
        &mut self,
        now: Duration,
        maximum: Duration,
    ) -> Result<Duration, Failure> {
        self.advance(now)?;
        let mut budget = maximum;
        if let Some((_, since)) = self.pending {
            budget = budget.min(self.timeouts.command - (now - since));
        }
        if let Some(since) = self.stop_since {
            budget = budget.min(self.timeouts.stop - (now - since));
        } else if !self.ever_connected && !self.prepared_held() {
            budget = budget.min(self.timeouts.startup - (now - self.started_at));
        } else if let Some(since) = self.reconnect_since {
            budget = budget.min(self.timeouts.reconnect - (now - since));
        }
        Ok(budget)
    }

    pub fn on_event(&mut self, event: Event, now: Duration) -> Result<Option<Command>, Failure> {
        self.advance(now)?;
        let pending = self.pending.map(|(kind, _)| kind);
        match event {
            Event::Ignored => {}
            Event::PasswordPrompt
                if !self.authenticated && pending.is_none() && self.password.is_some() =>
            {
                return Ok(Some(self.issue(Pending::Authentication)));
            }
            Event::Authenticated if pending == Some(Pending::Authentication) => {
                self.authenticated = true;
                self.pending = None;
            }
            Event::Pid(pid) if pending == Some(Pending::Pid) => {
                if pid != self.expected_pid {
                    return Err(self.fail(Failure::ProcessMismatch));
                }
                self.pid_verified = true;
                self.last_pid_ack = now;
                self.pending = None;
            }
            Event::StateSubscribed if pending == Some(Pending::Subscribe) => {
                self.subscribed = true;
                self.pending = None;
            }
            Event::HoldReleased if pending == Some(Pending::ReleaseHold) => {
                self.release_acked = true;
                self.pending = None;
            }
            Event::TerminationAcknowledged if pending == Some(Pending::Terminate) => {
                self.pending = None;
            }
            Event::AuthenticationRejected => {
                return Err(self.fail(Failure::ManagementAuthentication))
            }
            Event::CommandRejected => return Err(self.fail(Failure::CommandRejected)),
            Event::Fatal => return Err(self.fail(Failure::Fatal)),
            Event::CredentialsRequired(kind) => {
                return Err(self.fail(Failure::CredentialsRequired(kind)))
            }
            Event::VpnAuthenticationFailed => return Err(self.fail(Failure::VpnAuthentication)),
            Event::Hold { retry_after_secs } if self.authenticated => {
                if retry_after_secs > 300 {
                    return Err(self.fail(Failure::Protocol(ProtocolError::Malformed)));
                }
                if self.stop_since.is_none() {
                    self.reported = None;
                    self.release_acked = false;
                    if self.ever_connected {
                        self.reconnect_since.get_or_insert(now);
                    }
                    self.hold_until.get_or_insert(
                        now.saturating_add(Duration::from_secs(u64::from(retry_after_secs))),
                    );
                }
            }
            Event::State(state) if self.subscribed && self.release_sent => {
                if self.stop_since.is_none() {
                    if state == VpnState::Connected && self.hold_until.is_some() {
                        return Err(self.fail(Failure::UnexpectedResponse));
                    }
                    if state == VpnState::Exiting {
                        return Err(self.fail(Failure::UnexpectedExit));
                    }
                    self.reported = Some(state);
                    if state == VpnState::Connected {
                        self.ever_connected = true;
                        self.reconnect_since = None;
                    } else if self.ever_connected {
                        self.reconnect_since.get_or_insert(now);
                    }
                }
            }
            _ => return Err(self.fail(Failure::UnexpectedResponse)),
        }
        Ok(self.drive())
    }

    pub fn request_stop(&mut self, now: Duration) -> Result<Option<Command>, Failure> {
        self.advance(now)?;
        if !self.authenticated {
            return Err(self.fail(Failure::StopBeforeAuthentication));
        }
        self.stop_since.get_or_insert(now);
        self.reported = None;
        Ok(self.drive())
    }

    pub fn eof(&mut self, now: Duration) -> Result<Snapshot, Failure> {
        self.advance(now)?;
        // EOF is an orderly management close only after actually sending SIGTERM.
        if !self.terminate_sent {
            return Err(self.fail(Failure::Disconnected));
        }
        self.pending = None;
        self.reported = None;
        self.closed = true;
        Ok(self.snapshot())
    }
}
