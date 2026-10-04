use crate::{Decoder, Failure, ManagementPassword, Session, Snapshot, Stage, Timeouts};
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const POLL_QUANTUM: Duration = Duration::from_millis(100);

/// Implementations must enforce the supplied time budget, including partial
/// writes, and return TimedOut/WouldBlock for an idle read. close must not block.
pub trait ManagementTransport {
    fn read(&mut self, bytes: &mut [u8], timeout: Duration) -> io::Result<usize>;
    fn write_all(&mut self, bytes: &[u8], timeout: Duration) -> io::Result<()>;
    fn close(&mut self);
}

/// Uses an already connected local socket. The future broker must establish
/// endpoint/process ownership BEFORE constructing this transport. Loopback and
/// a reported PID do not authenticate an OpenVPN server.
pub struct TcpTransport(TcpStream);

impl TcpTransport {
    pub fn from_loopback_stream(stream: TcpStream) -> io::Result<Self> {
        if !stream.peer_addr()?.ip().is_loopback() || !stream.local_addr()?.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "OpenVPN management requires loopback",
            ));
        }
        stream.set_nonblocking(false)?;
        stream.set_nodelay(true)?;
        Ok(Self(stream))
    }
}

impl ManagementTransport for TcpTransport {
    fn read(&mut self, bytes: &mut [u8], timeout: Duration) -> io::Result<usize> {
        self.0.set_read_timeout(Some(timeout))?;
        self.0.read(bytes)
    }

    fn write_all(&mut self, mut bytes: &[u8], timeout: Duration) -> io::Result<()> {
        let start = Instant::now();
        while !bytes.is_empty() {
            let remaining = timeout
                .checked_sub(start.elapsed())
                .filter(|t| !t.is_zero())
                .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
            self.0.set_write_timeout(Some(remaining))?;
            match self.0.write(bytes) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => bytes = &bytes[n..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn close(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

/// Synchronous, bounded polling client for a dedicated broker worker. Failure
/// closes the management transport immediately. The owner must additionally
/// terminate/reap its child and retain network enforcement on failure or Drop.
pub struct Client<T: ManagementTransport> {
    transport: Option<T>,
    decoder: Decoder,
    session: Session,
    started: Instant,
}

impl<T: ManagementTransport> Client<T> {
    pub fn new(
        transport: T,
        password: ManagementPassword,
        expected_pid: u32,
        timeouts: Timeouts,
    ) -> Result<Self, Failure> {
        Self::from_session(
            transport,
            Session::new(password, expected_pid, timeouts, Duration::ZERO),
        )
    }

    pub fn new_held(
        transport: T,
        password: ManagementPassword,
        expected_pid: u32,
        timeouts: Timeouts,
    ) -> Result<Self, Failure> {
        Self::from_session(
            transport,
            Session::new_held(password, expected_pid, timeouts, Duration::ZERO),
        )
    }

    fn from_session(mut transport: T, session: Result<Session, Failure>) -> Result<Self, Failure> {
        let session = match session {
            Ok(session) => session,
            Err(error) => {
                transport.close();
                return Err(error);
            }
        };
        Ok(Self {
            transport: Some(transport),
            decoder: Decoder::default(),
            session,
            started: Instant::now(),
        })
    }

    /// Historical observation only. Call poll continuously to refresh liveness;
    /// this snapshot is not an egress permit, even when ConnectedUnverified.
    #[must_use]
    pub fn last_snapshot(&self) -> Snapshot {
        self.session.snapshot()
    }

    fn close(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.close();
        }
    }

    fn failed(&mut self, error: Failure) -> Failure {
        let error = self.session.fail(error);
        // A timeout can occur halfway through a sensitive peer message. Do not
        // retain that partial buffer while the owner keeps the failed snapshot.
        let _ = self.decoder.finish();
        self.close();
        error
    }

    fn send(&mut self, command: Option<crate::Command>) -> Result<(), Failure> {
        if let Some(command) = command {
            let timeout = self
                .session
                .io_budget(self.started.elapsed(), POLL_QUANTUM)
                .map_err(|error| self.failed(error))?;
            let bytes = command.into_bytes();
            let result = self
                .transport
                .as_mut()
                .ok_or(Failure::Closed)?
                .write_all(&bytes, timeout);
            result.map_err(|error| self.failed(Failure::Io(error.kind())))?;
        }
        Ok(())
    }

    /// Processes at most 1024 bytes per poll, with a 100ms I/O quantum further
    /// bounded by command/start/reconnect/stop deadlines. Ignored-event floods
    /// cannot postpone deadlines or create unbounded queues.
    pub fn poll(&mut self) -> Result<Snapshot, Failure> {
        if self.transport.is_none() {
            let snapshot = self.last_snapshot();
            return if snapshot.stage == Stage::ManagementClosed {
                Ok(snapshot)
            } else {
                Err(snapshot.failure.unwrap_or(Failure::Closed))
            };
        }
        let command = self
            .session
            .tick(self.started.elapsed())
            .map_err(|error| self.failed(error))?;
        self.send(command)?;
        let timeout = self
            .session
            .io_budget(self.started.elapsed(), POLL_QUANTUM)
            .map_err(|error| self.failed(error))?;
        let mut bytes = Zeroizing::new([0u8; 1024]);
        let read = self
            .transport
            .as_mut()
            .ok_or(Failure::Closed)?
            .read(&mut bytes[..], timeout);
        match read {
            Ok(0) => {
                self.decoder
                    .finish()
                    .map_err(|error| self.failed(Failure::Protocol(error)))?;
                let snapshot = self
                    .session
                    .eof(self.started.elapsed())
                    .map_err(|error| self.failed(error))?;
                self.close();
                return Ok(snapshot);
            }
            Ok(n) if n <= bytes.len() => {
                for byte in &bytes[..n] {
                    if let Some(event) = self
                        .decoder
                        .push(*byte)
                        .map_err(|error| self.failed(Failure::Protocol(error)))?
                    {
                        let command = self
                            .session
                            .on_event(event, self.started.elapsed())
                            .map_err(|error| self.failed(error))?;
                        self.send(command)?;
                    }
                }
            }
            Ok(_) => return Err(self.failed(Failure::Io(io::ErrorKind::InvalidData))),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => return Err(self.failed(Failure::Io(error.kind()))),
        }
        let command = self
            .session
            .tick(self.started.elapsed())
            .map_err(|error| self.failed(error))?;
        self.send(command)?;
        Ok(self.last_snapshot())
    }

    /// Requests graceful stop; poll until management EOF or failure. Neither a
    /// signal acknowledgement nor management EOF proves that the process exited.
    pub fn request_stop(&mut self) -> Result<(), Failure> {
        let command = self
            .session
            .request_stop(self.started.elapsed())
            .map_err(|error| self.failed(error))?;
        self.send(command)
    }
}

impl<T: ManagementTransport> Drop for Client<T> {
    fn drop(&mut self) {
        self.close();
    }
}
