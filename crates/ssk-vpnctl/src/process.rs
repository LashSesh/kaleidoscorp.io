use crate::{Client, Failure, ManagementPassword, ManagementTransport, Snapshot, Stage, Timeouts};
use std::{
    io,
    time::{Duration, Instant},
};

/// Owned OS child, never a PID reopened later. Calls must be nonblocking.
/// terminate must address the entire owned execution container. The platform
/// implementation must also contain the child if its owner crashes (a Windows
/// kill-on-close job), since Rust Drop alone cannot handle process termination.
pub trait ChildProcess {
    fn id(&self) -> u32;
    fn try_wait(&mut self) -> io::Result<Option<u32>>;
    fn terminate(&mut self) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStage {
    Managing,
    Stopping,
    Terminating,
    Exited,
    TerminationUnconfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessFailure {
    Management(Failure),
    UnexpectedExit,
    ExitTimeout,
    ProcessIo(io::ErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSnapshot {
    pub stage: ProcessStage,
    pub management: Option<Snapshot>,
    pub failure: Option<ProcessFailure>,
    pub termination_error: Option<io::ErrorKind>,
    /// Present only after the owned process handle confirms exit.
    pub exit_code: Option<u32>,
}

struct Owned<P: ChildProcess>(P);
impl<P: ChildProcess> Drop for Owned<P> {
    fn drop(&mut self) {
        let _ = self.0.terminate();
    }
}

/// Couples continuous management polling to OS process ownership. Never grants
/// network admission. Call poll on a dedicated worker; snapshots are historical.
/// Drop requests termination; explicit polling is needed to confirm/reap exit.
pub struct ManagedProcess<P: ChildProcess, T: ManagementTransport> {
    process: Owned<P>,
    client: Option<Client<T>>,
    snapshot: ProcessSnapshot,
    started: Instant,
    deadline: Option<Duration>,
    grace: Duration,
    stop_timeout: Duration,
}

impl<P: ChildProcess, T: ManagementTransport> ManagedProcess<P, T> {
    /// Caller must establish transport/owned-process identity before this call.
    /// On any constructor failure, termination is requested and transport closed.
    /// OS crash containment remains the ChildProcess implementation's duty.
    pub fn new(
        process: P,
        transport: T,
        password: ManagementPassword,
        timeouts: Timeouts,
        exit_grace: Duration,
    ) -> Result<Self, Failure> {
        Self::build(process, transport, password, timeouts, exit_grace, false)
    }

    /// Management preparation only; this process can never release its hold.
    pub fn new_held(
        process: P,
        transport: T,
        password: ManagementPassword,
        timeouts: Timeouts,
        exit_grace: Duration,
    ) -> Result<Self, Failure> {
        Self::build(process, transport, password, timeouts, exit_grace, true)
    }

    fn build(
        process: P,
        mut transport: T,
        password: ManagementPassword,
        timeouts: Timeouts,
        exit_grace: Duration,
        keep_held: bool,
    ) -> Result<Self, Failure> {
        let process = Owned(process);
        if exit_grace.is_zero() || exit_grace > Duration::from_secs(30) {
            transport.close();
            return Err(Failure::Configuration);
        }
        let client = if keep_held {
            Client::new_held(transport, password, process.0.id(), timeouts)?
        } else {
            Client::new(transport, password, process.0.id(), timeouts)?
        };
        Ok(Self {
            process,
            client: Some(client),
            snapshot: ProcessSnapshot {
                stage: ProcessStage::Managing,
                management: None,
                failure: None,
                termination_error: None,
                exit_code: None,
            },
            started: Instant::now(),
            deadline: None,
            grace: exit_grace,
            stop_timeout: timeouts.stop,
        })
    }

    pub fn last_snapshot(&self) -> ProcessSnapshot {
        self.snapshot
    }

    fn terminate(&mut self, cause: Option<ProcessFailure>, now: Duration) {
        if self.snapshot.failure.is_none() {
            self.snapshot.failure = cause;
        }
        self.client.take(); // close first; never release a hold after failure
        if !matches!(
            self.snapshot.stage,
            ProcessStage::Terminating | ProcessStage::TerminationUnconfirmed | ProcessStage::Exited
        ) {
            if let Err(error) = self.process.0.terminate() {
                self.snapshot.termination_error = Some(error.kind());
            }
            self.snapshot.stage = ProcessStage::Terminating;
            self.deadline = Some(now + self.grace);
        }
    }

    pub fn request_stop(&mut self) {
        if self.snapshot.stage != ProcessStage::Managing {
            return;
        }
        self.snapshot.stage = ProcessStage::Stopping;
        let now = self.started.elapsed();
        self.deadline = Some(now + self.stop_timeout);
        if let Some(client) = self.client.as_mut() {
            if let Err(error) = client.request_stop() {
                self.terminate(Some(ProcessFailure::Management(error)), now);
            }
        }
    }

    /// Abandon management immediately and request OS-container termination.
    /// Continue polling to distinguish confirmed exit from a termination timeout.
    pub fn abort(&mut self) {
        self.terminate(None, self.started.elapsed());
    }

    pub fn poll(&mut self) -> ProcessSnapshot {
        self.poll_at(self.started.elapsed())
    }

    fn poll_at(&mut self, now: Duration) -> ProcessSnapshot {
        if self.snapshot.stage == ProcessStage::Exited {
            return self.snapshot;
        }
        match self.process.0.try_wait() {
            Ok(Some(code)) => {
                if self.snapshot.stage == ProcessStage::Managing && self.snapshot.failure.is_none()
                {
                    self.snapshot.failure = Some(ProcessFailure::UnexpectedExit);
                }
                // End the execution container even if the root exited itself.
                if let Err(error) = self.process.0.terminate() {
                    self.snapshot.termination_error = Some(error.kind());
                }
                self.client.take();
                self.snapshot.stage = ProcessStage::Exited;
                self.snapshot.exit_code = Some(code);
                return self.snapshot;
            }
            Err(error) => self.terminate(Some(ProcessFailure::ProcessIo(error.kind())), now),
            Ok(None) => {}
        }
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            match self.snapshot.stage {
                ProcessStage::Stopping => self.terminate(Some(ProcessFailure::ExitTimeout), now),
                ProcessStage::Terminating => {
                    self.snapshot.stage = ProcessStage::TerminationUnconfirmed
                }
                _ => {}
            }
        }
        if let Some(client) = self.client.as_mut() {
            let result = client.poll();
            self.snapshot.management = Some(client.last_snapshot());
            match result {
                Err(error) => self.terminate(Some(ProcessFailure::Management(error)), now),
                Ok(state) if state.stage == Stage::ManagementClosed => {
                    // EOF is NOT process exit. Keep the stop deadline running.
                    self.client.take();
                }
                Ok(_) => {}
            }
        }
        self.snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    #[derive(Default)]
    struct State {
        exit: Option<u32>,
        kills: usize,
        closed: bool,
        wait_error: bool,
        kill_error: bool,
        replies: VecDeque<Vec<u8>>,
    }
    struct Child(Rc<RefCell<State>>, u32);
    impl ChildProcess for Child {
        fn id(&self) -> u32 {
            self.1
        }
        fn try_wait(&mut self) -> io::Result<Option<u32>> {
            let s = self.0.borrow();
            if s.wait_error {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(s.exit)
            }
        }
        fn terminate(&mut self) -> io::Result<()> {
            let mut s = self.0.borrow_mut();
            s.kills += 1;
            if s.kill_error {
                Err(io::ErrorKind::PermissionDenied.into())
            } else {
                Ok(())
            }
        }
    }
    struct Transport(Rc<RefCell<State>>);
    impl ManagementTransport for Transport {
        fn read(&mut self, bytes: &mut [u8], _: Duration) -> io::Result<usize> {
            match self.0.borrow_mut().replies.pop_front() {
                Some(reply) => {
                    bytes[..reply.len()].copy_from_slice(&reply);
                    Ok(reply.len())
                }
                None => Err(io::ErrorKind::TimedOut.into()),
            }
        }
        fn write_all(&mut self, _: &[u8], _: Duration) -> io::Result<()> {
            Ok(())
        }
        fn close(&mut self) {
            self.0.borrow_mut().closed = true;
        }
    }
    fn password() -> ManagementPassword {
        ManagementPassword::new(b"fixture-password-only".to_vec()).unwrap()
    }
    fn setup() -> (ManagedProcess<Child, Transport>, Rc<RefCell<State>>) {
        let s = Rc::new(RefCell::new(State::default()));
        let p = ManagedProcess::new(
            Child(s.clone(), 42),
            Transport(s.clone()),
            password(),
            Timeouts::default(),
            Duration::from_secs(1),
        )
        .unwrap();
        (p, s)
    }
    #[test]
    fn constructor_failures_close_transport_and_terminate_child() {
        for (pid, grace) in [(0, Duration::from_secs(1)), (42, Duration::ZERO)] {
            let s = Rc::new(RefCell::new(State::default()));
            assert!(ManagedProcess::new(
                Child(s.clone(), pid),
                Transport(s.clone()),
                password(),
                Timeouts::default(),
                grace
            )
            .is_err());
            assert!(s.borrow().closed);
            assert_eq!(s.borrow().kills, 1);
        }
    }
    #[test]
    fn protocol_failure_terminates_and_cannot_revive() {
        let (mut p, s) = setup();
        s.borrow_mut()
            .replies
            .push_back(b">FATAL:fixture\n".to_vec());
        let status = p.poll_at(Duration::ZERO);
        assert_eq!(status.stage, ProcessStage::Terminating);
        assert_eq!(
            status.failure,
            Some(ProcessFailure::Management(Failure::Fatal))
        );
        assert!(s.borrow().closed);
        assert_eq!(s.borrow().kills, 1);
        s.borrow_mut()
            .replies
            .push_back(b">STATE:1,CONNECTED,SUCCESS,10.0.0.2\n".to_vec());
        assert_eq!(
            p.poll_at(Duration::from_secs(1)).stage,
            ProcessStage::TerminationUnconfirmed
        );
        assert_eq!(p.last_snapshot().exit_code, None);
        // A late, real OS confirmation is still accepted, without losing cause.
        s.borrow_mut().exit = Some(1);
        assert_eq!(p.poll().stage, ProcessStage::Exited);
        assert_eq!(p.last_snapshot().failure, status.failure);
    }
    #[test]
    fn os_exit_is_checked_before_management_traffic() {
        let (mut p, s) = setup();
        s.borrow_mut().exit = Some(0);
        assert_eq!(p.poll().failure, Some(ProcessFailure::UnexpectedExit));
        assert_eq!(p.last_snapshot().exit_code, Some(0));
        assert!(s.borrow().closed);
    }
    #[test]
    fn wait_and_termination_failures_are_not_reported_as_exit() {
        let (mut p, s) = setup();
        s.borrow_mut().wait_error = true;
        s.borrow_mut().kill_error = true;
        let state = p.poll_at(Duration::ZERO);
        assert_eq!(
            state.failure,
            Some(ProcessFailure::ProcessIo(io::ErrorKind::PermissionDenied))
        );
        assert_eq!(
            state.termination_error,
            Some(io::ErrorKind::PermissionDenied)
        );
        assert_eq!(
            p.poll_at(Duration::from_secs(1)).stage,
            ProcessStage::TerminationUnconfirmed
        );
        assert_eq!(p.last_snapshot().exit_code, None);
        assert_eq!(s.borrow().kills, 1); // failures do not restart deadlines
    }
    #[test]
    fn drop_terminates_without_waiting() {
        let (p, s) = setup();
        drop(p);
        assert!(s.borrow().closed);
        assert_eq!(s.borrow().kills, 1);
    }
    #[test]
    fn stop_before_authentication_terminates_instead_of_releasing_hold() {
        let (mut p, s) = setup();
        p.request_stop();
        assert_eq!(p.last_snapshot().stage, ProcessStage::Terminating);
        assert_eq!(s.borrow().kills, 1);
        assert!(s.borrow().closed);
    }
    #[test]
    fn graceful_management_eof_still_requires_os_exit_or_forced_timeout() {
        let (mut p, s) = setup();
        for reply in [
            "ENTER PASSWORD:",
            "SUCCESS: password is correct\n",
            "SUCCESS: pid=42\n",
            "SUCCESS: real-time state notification set to ON\n>HOLD:Waiting for hold release:0\n",
            "SUCCESS: hold release succeeded\n>STATE:1,CONNECTED,SUCCESS,10.0.0.2\n",
        ] {
            s.borrow_mut().replies.push_back(reply.as_bytes().to_vec());
            p.poll();
        }
        assert_eq!(
            p.last_snapshot().management.unwrap().stage,
            Stage::ConnectedUnverified
        );
        p.request_stop();
        s.borrow_mut()
            .replies
            .push_back(b"SUCCESS: signal SIGTERM thrown\n".to_vec());
        p.poll();
        s.borrow_mut().replies.push_back(vec![]);
        p.poll();
        assert_eq!(p.last_snapshot().stage, ProcessStage::Stopping);
        assert_eq!(p.last_snapshot().exit_code, None);
        assert_eq!(s.borrow().kills, 0);
        assert_eq!(
            p.poll_at(Duration::from_secs(6)).stage,
            ProcessStage::Terminating
        );
        assert_eq!(p.last_snapshot().failure, Some(ProcessFailure::ExitTimeout));
        assert_eq!(s.borrow().kills, 1);
    }
}
