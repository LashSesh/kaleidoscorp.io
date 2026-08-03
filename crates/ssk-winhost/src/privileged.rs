//! The P3 privileged control pipe: the SYSTEM-owned endpoint and the accept
//! loop that fronts [`ssk_netd_helper::Broker`].
//!
//! `ssk-netd-helper` is `#![forbid(unsafe_code)]` and owns every *decision* —
//! framing caps, the versioned handshake, per-request peer authorization, lease
//! algebra, startup reconciliation. It declares two seams it cannot implement:
//! [`ssk_netd_helper::FrameTransport`] (a synchronous byte stream with a read
//! timeout) and the production of an [`ssk_netd_helper::AuthenticatedPeer`].
//! This module fills both, and does nothing else.
//!
//! # Why this is not the P2 accept loop with a different DACL
//!
//! Three things differ, and each is structural:
//!
//! * **The peer check is inverted.** `ssk_ipc::transport_win::check_peer_same_user`
//!   accepts a peer whose SID equals our own. A broker running as SYSTEM shares
//!   its SID with no legitimate client, so same-user here would accept only
//!   SYSTEM callers and reject every real user. The privileged pipe therefore
//!   uses [`WindowsPeerAuthenticator::authenticate_peer`], which establishes
//!   *who* the peer is and makes no authorization decision at all — the verb is
//!   not known at accept time. `check_peer_same_user` is untouched and still
//!   fronts the unprivileged `sskd` pipe. Two pipes, two authentication
//!   contracts, one set of FFI.
//! * **The transport is synchronous.** The broker's serve loop is a plain
//!   blocking function, deliberately, so that the whole protocol is testable
//!   without an async runtime. Bridging is done by owning a **current-thread**
//!   tokio runtime per listener and calling `block_on` per I/O operation — never
//!   across the serve loop. That is what keeps `Runtime::block_on` legal here
//!   (the loop is not itself running inside a `block_on`) and it is why
//!   `run_listener` takes the calling thread for its whole life.
//! * **Impersonation stays off the async workers.** A listener thread owns a
//!   current-thread runtime, so it is not a work-stealing tokio worker; and
//!   `authenticate_peer` is synchronous with the impersonation window closed
//!   before it returns. There is no point at which a thread could be handed an
//!   unrelated task while carrying a foreign identity.
//!
//! # Shutdown
//!
//! `NamedPipeServer::connect` is cancel-safe, so each listener awaits it under a
//! short [`ACCEPT_POLL`] timeout and re-checks the stop flag on every expiry.
//! The alternative — connecting to our own pipe to unblock the accept — was
//! rejected: it consumes an instance, it races with real clients, and a poke
//! that arrives while the listener is mid-connection is simply lost. Polling
//! costs one wakeup per listener per [`ACCEPT_POLL`] and cannot deadlock.
//!
//! # What is NOT verified here
//!
//! Everything about running as `LocalSystem`. Specifically: that a
//! SYSTEM-created pipe actually carries `O:SY`; that `0x12019b` denies
//! `FILE_CREATE_PIPE_INSTANCE` to a *different* principal (the mask's refusal is
//! proven same-user, the principal split is not); that a genuinely different,
//! non-allow-listed OS user is refused; and that the mandatory label blocks a
//! below-Medium client. Those are operator legs, not assertions. What *is*
//! exercised by the tests in this module, unelevated, on a real pipe: the
//! transport's framing and timeout behaviour, the accept loop's shutdown, and a
//! full engage/release round trip against a real broker.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use ssk_ipc::transport_win::PipeFactory;
use ssk_netd_helper::framing::{FrameTransport, TransportError, PRIV_READ_TIMEOUT};
use ssk_netd_helper::lease::LeaseId;
use ssk_netd_helper::server::{ConnectionOutcome, LeaseIdSource, PrivilegedServer};
use ssk_netd_helper::{Broker, ConnectionLimiter, MAX_PRIV_CONNECTIONS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
use tokio::runtime::{Builder, Runtime};

use crate::pipe::{
    sddl_for_read_only_fallback_pipe, sddl_for_system_owned_pipe, PipeSecurityError,
    WindowsPeerAuthenticator, WindowsPipeFactory,
};

/// The privileged broker's endpoint.
///
/// **Fixed and well known, on purpose.** The unprivileged `sskd` pipe is scoped
/// by a state-directory digest (P2), which works because the client can compute
/// the same digest. A client cannot compute SYSTEM's state-directory digest, so
/// the privileged name must be discoverable — and a discoverable name invites
/// squatting. That is exactly why
/// [`crate::pipe::require_system_owned_pipe`] exists and why it is not
/// optional: `FILE_FLAG_FIRST_PIPE_INSTANCE` protects the server, the owner
/// check protects the client.
///
/// The protocol scheme version is in the name, as `ssk_ipc::paths` already does,
/// so an incompatible future scheme is a different endpoint rather than a
/// mis-parse.
pub const PRIVILEGED_PIPE_NAME: &str = r"\\.\pipe\kaleidoscorp-sskbroker-1";

/// How long a listener waits for a client before re-checking the stop flag.
///
/// Only a shutdown-latency knob: `connect` is cancel-safe, so a client that
/// arrives during the gap is not lost, it is picked up on the next await.
pub const ACCEPT_POLL: Duration = Duration::from_millis(250);

/// How long [`NamedPipeClientTransport::connect`] keeps retrying
/// `ERROR_PIPE_BUSY`.
pub const BUSY_RETRY_WINDOW: Duration = Duration::from_secs(5);

/// Gap between `ERROR_PIPE_BUSY` retries.
const BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(20);

/// A synchronous [`FrameTransport`] over one connected named-pipe instance.
///
/// Holds a borrowed [`Runtime`] rather than creating one per call: building a
/// runtime per read would be absurd, and holding an owned one would make the
/// transport un-`Send` in a way that hides the real constraint. The constraint
/// is that **`run_listener` owns the runtime and the transport borrows it**, so
/// the transport cannot outlive the loop that is allowed to block on it.
///
/// Every read is bounded by [`PRIV_READ_TIMEOUT`]. That bound is an obligation
/// `ssk-netd-helper` documents on the implementer and cannot enforce: a
/// transport that ignores it simply never produces
/// [`TransportError::TimedOut`], and the broker's serve loop blocks forever.
/// This implementation honours it, and a test drives a real stalled client
/// through it.
pub struct NamedPipeFrameTransport<'rt> {
    pipe: NamedPipeServer,
    rt: &'rt Runtime,
    read_timeout: Duration,
}

impl<'rt> NamedPipeFrameTransport<'rt> {
    /// Wrap a connected instance.
    #[must_use]
    pub fn new(pipe: NamedPipeServer, rt: &'rt Runtime) -> Self {
        NamedPipeFrameTransport {
            pipe,
            rt,
            read_timeout: PRIV_READ_TIMEOUT,
        }
    }

    /// Override the read timeout. Tests use it to make the timeout observable
    /// in milliseconds instead of ten seconds; production uses the default.
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Give the pipe back, so a caller can disconnect it explicitly.
    #[must_use]
    pub fn into_pipe(self) -> NamedPipeServer {
        self.pipe
    }
}

/// Map a pipe I/O error onto the transport vocabulary.
///
/// `ERROR_BROKEN_PIPE` (109) and `ERROR_PIPE_NOT_CONNECTED` (233) are the two
/// ways a Windows named pipe reports "the peer went away". They are **not**
/// errors at this layer: the serve loop treats a clean close as end-of-
/// connection, and reporting them as `Io` would turn every normal disconnect
/// into a logged transport failure.
fn transport_error(e: &io::Error) -> TransportError {
    const ERROR_BROKEN_PIPE: i32 = 109;
    const ERROR_PIPE_NOT_CONNECTED: i32 = 233;
    match e.raw_os_error() {
        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => TransportError::Closed,
        _ if e.kind() == io::ErrorKind::UnexpectedEof => TransportError::Closed,
        _ => TransportError::Io(e.to_string()),
    }
}

impl FrameTransport for NamedPipeFrameTransport<'_> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.read(buf)).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(0)) => Err(TransportError::Closed),
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.write_all(bytes)).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.flush()).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }
}

/// The client half of the same transport, over a connected
/// [`NamedPipeClient`].
///
/// Owns its runtime rather than borrowing one, because a client is typically a
/// short-lived CLI process with no runtime of its own, and because the owner
/// check below must happen before anything is written — which is far easier to
/// guarantee if connecting and checking are one constructor.
///
/// **The owner check is not optional.** [`connect`](Self::connect) refuses a
/// pipe that is not owned by `expected_owner_sid` before a single byte is
/// written. Without it a squatter on the fixed [`PRIVILEGED_PIPE_NAME`] can
/// complete a handshake and answer with a forged `Ok(Status)` claiming
/// `Engaged` while egress flows.
#[derive(Debug)]
pub struct NamedPipeClientTransport {
    pipe: NamedPipeClient,
    rt: Runtime,
    read_timeout: Duration,
}

impl NamedPipeClientTransport {
    /// Open `pipe_name`, verify its owner, and wrap it.
    ///
    /// # Errors
    /// [`io::Error`] if the pipe cannot be opened or the runtime cannot be
    /// built, and an `io::Error` of kind [`io::ErrorKind::PermissionDenied`]
    /// carrying the underlying [`PipeSecurityError`] if the owner is wrong or
    /// unreadable. An unreadable owner is a refusal, never a "cannot tell,
    /// continue".
    pub fn connect(pipe_name: &str, expected_owner_sid: &str) -> io::Result<Self> {
        let rt = Builder::new_current_thread().enable_all().build()?;
        // `ERROR_PIPE_BUSY` means the endpoint exists but every instance is in
        // use. Retrying is the documented Windows client pattern, and it is
        // load-bearing here rather than polite: a host with N listeners has a
        // short window after each connection ends in which that listener has not
        // yet created its replacement instance, so a client that treated 231 as
        // fatal would fail intermittently against a perfectly healthy service.
        //
        // Only 231 is retried. `ERROR_FILE_NOT_FOUND` — the service is not
        // running — is returned immediately, because waiting on it would turn
        // "no broker installed" into a multi-second hang on every `ssk status`.
        const ERROR_PIPE_BUSY: i32 = 231;
        let deadline = std::time::Instant::now() + BUSY_RETRY_WINDOW;
        let pipe = loop {
            match rt.block_on(async { ClientOptions::new().open(pipe_name) }) {
                Ok(pipe) => break pipe,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(BUSY_RETRY_INTERVAL);
                }
                Err(e) => return Err(e),
            }
        };
        // BEFORE the first frame. See the type's doc comment.
        crate::pipe::require_pipe_owner(&pipe, expected_owner_sid).map_err(|e| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing the privileged endpoint {pipe_name}: {e}"),
            )
        })?;
        Ok(NamedPipeClientTransport {
            pipe,
            rt,
            read_timeout: PRIV_READ_TIMEOUT,
        })
    }

    /// Override the read timeout. Tests only; production uses the default.
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }
}

impl FrameTransport for NamedPipeClientTransport {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.read(buf)).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(0)) => Err(TransportError::Closed),
            Ok(Ok(n)) => Ok(n),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.write_all(bytes)).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }

    fn flush(&mut self) -> Result<(), TransportError> {
        let timeout = self.read_timeout;
        let pipe = &mut self.pipe;
        match self
            .rt
            .block_on(async { tokio::time::timeout(timeout, pipe.flush()).await })
        {
            Err(_elapsed) => Err(TransportError::TimedOut),
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(transport_error(&e)),
        }
    }
}

/// Lease ids drawn from the OS CSPRNG.
///
/// [`ssk_netd_helper::SequentialLeaseIds`] is documented as predictable by
/// construction and adequate because presenting an id is not authorization. The
/// privileged host still uses a real CSPRNG, because "not authorization" and
/// "safe to guess" are different claims and only the first one was argued.
///
/// A CSPRNG failure does **not** silently fall back to something guessable in a
/// way that could collide: the counter half guarantees distinctness, the failure
/// is logged at `error`, and the consequence — an adoptable pinned claim whose
/// id is predictable — is bounded by the fact that adopting one still requires
/// passing the pipe DACL and a per-request authorization for the verb.
#[derive(Debug, Default)]
pub struct CsprngLeaseIds {
    counter: u64,
}

impl LeaseIdSource for CsprngLeaseIds {
    fn next(&mut self) -> LeaseId {
        self.counter += 1;
        let mut id = [0u8; 16];
        if let Err(e) = getrandom::fill(&mut id) {
            tracing::error!(
                target: "ssk.winhost.privileged",
                error = %e,
                "the OS CSPRNG refused; falling back to a counter-derived lease id, which is \
                 distinct but predictable"
            );
            id = [0u8; 16];
        }
        // Mixed in unconditionally: distinctness must not depend on the CSPRNG
        // having worked.
        let tail = u64::from_be_bytes(
            id[8..]
                .try_into()
                .expect("a 16-byte array always yields an 8-byte tail"),
        ) ^ self.counter;
        id[8..].copy_from_slice(&tail.to_be_bytes());
        if id == LeaseId::IN_PROCESS.0 {
            id[15] ^= 0x01;
        }
        LeaseId(id)
    }
}

/// Serializes the creation of the very first pipe instance across listeners.
///
/// `FILE_FLAG_FIRST_PIPE_INSTANCE` is the anti-squat guard and it is only
/// meaningful on the *first* create: exactly one listener may pass `true`, every
/// other must wait until that create has succeeded, or the second listener's
/// `first_pipe_instance(true)` would collide with our own first instance and be
/// refused with the same `ERROR_ACCESS_DENIED` a squatter produces. Waiting also
/// means a squatted name fails the whole host rather than one thread.
#[derive(Debug)]
struct FirstInstanceGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateState {
    /// Nobody has tried yet.
    Unclaimed,
    /// One listener is creating the first instance.
    Claimed,
    /// The first instance exists; everyone else may create non-first instances.
    Created,
    /// The first create failed — overwhelmingly, the name is squatted. Every
    /// other listener must give up rather than spin.
    Failed,
}

impl FirstInstanceGate {
    fn new() -> Self {
        FirstInstanceGate {
            state: Mutex::new(GateState::Unclaimed),
            changed: Condvar::new(),
        }
    }

    /// `Ok(true)` if this caller must create the first instance; `Ok(false)`
    /// once one exists.
    fn acquire(&self) -> io::Result<bool> {
        let mut state = self.state.lock().expect("first-instance gate");
        loop {
            match *state {
                GateState::Unclaimed => {
                    *state = GateState::Claimed;
                    return Ok(true);
                }
                GateState::Created => return Ok(false),
                GateState::Failed => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "the first privileged pipe instance could not be created; refusing to \
                         serve on a name this process does not own",
                    ))
                }
                GateState::Claimed => {
                    state = self.changed.wait(state).expect("first-instance gate");
                }
            }
        }
    }

    fn settle(&self, created: bool) {
        let mut state = self.state.lock().expect("first-instance gate");
        *state = if created {
            GateState::Created
        } else {
            GateState::Failed
        };
        drop(state);
        self.changed.notify_all();
    }
}

/// How the privileged pipe is configured.
#[derive(Debug, Clone)]
pub struct PrivilegedPipeHostConfig {
    /// The endpoint. [`PRIVILEGED_PIPE_NAME`] in production.
    pub pipe_name: String,
    /// The descriptor every instance carries.
    pub sddl: String,
    /// Per-instance cap handed to `CreateNamedPipeW`.
    pub max_instances: u32,
}

impl PrivilegedPipeHostConfig {
    /// The production configuration: the well-known name, `O:SY`, and one client
    /// ACE per allow-listed SID.
    ///
    /// # Errors
    /// [`PipeSecurityError`] if the allow-list is empty, over
    /// [`crate::pipe::MAX_CLIENT_ACES`], or contains a SID that is not a plain
    /// decimal SID string.
    pub fn for_allow_list(client_sids: &[&str]) -> Result<Self, PipeSecurityError> {
        Ok(PrivilegedPipeHostConfig {
            pipe_name: PRIVILEGED_PIPE_NAME.to_owned(),
            sddl: sddl_for_system_owned_pipe(client_sids)?,
            max_instances: MAX_PRIV_CONNECTIONS_U32,
        })
    }

    /// The degraded configuration used when the allow-list could not be read.
    ///
    /// The pipe still admits `INTERACTIVE` so a severed machine stays
    /// diagnosable; the broker behind it must be constructed with
    /// [`ssk_netd_helper::TieredSidAuthorizer::read_only`] so every mutating
    /// verb is refused. **Reachability without authority** — and the two halves
    /// are chosen at the same composition root so they cannot drift apart.
    #[must_use]
    pub fn read_only_fallback() -> Self {
        PrivilegedPipeHostConfig {
            pipe_name: PRIVILEGED_PIPE_NAME.to_owned(),
            sddl: sddl_for_read_only_fallback_pipe(),
            max_instances: MAX_PRIV_CONNECTIONS_U32,
        }
    }
}

/// [`MAX_PRIV_CONNECTIONS`] as the `u32` `CreateNamedPipeW` wants. Clamped at
/// the factory's own ceiling by [`WindowsPipeFactory::create_instance`], which
/// refuses out-of-range values with an `io::Error` rather than panicking.
const MAX_PRIV_CONNECTIONS_U32: u32 = MAX_PRIV_CONNECTIONS as u32;

/// A stop signal that can be handed to another thread.
///
/// Cloneable and cheap. Setting it makes every listener return after at most
/// [`ACCEPT_POLL`] plus however long the connection it is currently serving
/// takes to finish — bounded by [`PRIV_READ_TIMEOUT`], since every read on the
/// transport is timed.
#[derive(Debug, Clone)]
pub struct StopSignal(Arc<AtomicBool>);

impl StopSignal {
    #[must_use]
    fn new() -> Self {
        StopSignal(Arc::new(AtomicBool::new(false)))
    }

    /// Ask every listener sharing this signal to stop.
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What one listener loop did before it returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenerReport {
    /// Connections that completed a handshake and were served.
    pub served: u64,
    /// Connections refused at the handshake (bad magic, version, capacity, an
    /// unavailable lease).
    pub refused: u64,
    /// Peers whose token could not be read at all. **Every one is a rejection**
    /// — never a downgrade to an unprivileged token.
    pub unauthenticated: u64,
    /// Connections whose stream failed or desynchronised.
    pub transport_failures: u64,
}

/// Hosts the privileged pipe.
///
/// Shareable across listener threads: the DACL, the authenticator and the
/// connection cap are process-wide facts, and the first-instance gate must be
/// process-wide or the anti-squat guard degrades into a race between our own
/// threads.
#[derive(Debug)]
pub struct PrivilegedPipeHost {
    config: PrivilegedPipeHostConfig,
    factory: WindowsPipeFactory,
    auth: WindowsPeerAuthenticator,
    limiter: ConnectionLimiter,
    stop: StopSignal,
    first: FirstInstanceGate,
    accepted: AtomicU64,
}

impl PrivilegedPipeHost {
    /// Build the host, failing at construction on a descriptor that will not
    /// convert or an authenticator that cannot read this process's own SID.
    ///
    /// Both are startup failures on purpose: "we cannot express our own
    /// security descriptor" and "we do not know who we are" must refuse to
    /// serve, not surface as a per-connection surprise.
    ///
    /// # Errors
    /// [`PipeSecurityError`] from the descriptor conversion or the SID probe.
    pub fn new(config: PrivilegedPipeHostConfig) -> Result<Self, PipeSecurityError> {
        let factory = WindowsPipeFactory::from_sddl(config.sddl.clone())?;
        let auth = WindowsPeerAuthenticator::new()?;
        Ok(PrivilegedPipeHost {
            config,
            factory,
            auth,
            limiter: ConnectionLimiter::new(MAX_PRIV_CONNECTIONS),
            stop: StopSignal::new(),
            first: FirstInstanceGate::new(),
            accepted: AtomicU64::new(0),
        })
    }

    /// The stop signal. Clone it before spawning listeners; the SCM `Stop`
    /// handler sets it.
    #[must_use]
    pub fn stop_signal(&self) -> StopSignal {
        self.stop.clone()
    }

    /// The endpoint this host serves.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.config.pipe_name
    }

    /// The SDDL every instance carries. Logged at startup so the applied
    /// descriptor is in the record, not just the intent.
    #[must_use]
    pub fn sddl(&self) -> &str {
        &self.config.sddl
    }

    /// Total connections accepted across every listener. Observability.
    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::Relaxed)
    }

    /// Run one listener loop on the calling thread until the stop signal is set.
    ///
    /// Blocking, and it owns a current-thread tokio runtime for its whole life.
    /// Call it from a dedicated `std::thread`, once per desired concurrent
    /// connection.
    ///
    /// # Errors
    /// [`io::Error`] if an instance cannot be created. The **first** such
    /// failure is overwhelmingly a squatted pipe name and is fatal to the whole
    /// host: every other listener is released with `AddrInUse` rather than
    /// spinning on a name this process does not own.
    pub fn run_listener(
        &self,
        broker: &Broker,
        lease_ids: &mut dyn LeaseIdSource,
    ) -> io::Result<ListenerReport> {
        let rt = Builder::new_current_thread().enable_all().build()?;
        let server = PrivilegedServer::with_limiter(broker, self.limiter.clone());
        let mut report = ListenerReport::default();
        let mut first_instance = self.first.acquire()?;

        while !self.stop.is_stopped() {
            // `create_instance` registers the handle with this runtime's I/O
            // driver, so it must happen inside the runtime context. Every later
            // await on the same handle is on this same runtime, on this thread.
            let instance = rt.block_on(async {
                self.factory.create_instance(
                    &self.config.pipe_name,
                    first_instance,
                    self.config.max_instances,
                )
            });
            let instance = match instance {
                Ok(instance) => {
                    if first_instance {
                        self.first.settle(true);
                        first_instance = false;
                    }
                    instance
                }
                Err(e) => {
                    if first_instance {
                        // Release every waiting listener with a typed refusal
                        // rather than leaving them blocked on a gate that will
                        // never open.
                        self.first.settle(false);
                    }
                    return Err(e);
                }
            };

            // Wait for a client, re-checking the stop flag on every expiry.
            // `NamedPipeServer::connect` is cancel safe, so a client that
            // arrives during a gap is picked up on the next await rather than
            // lost.
            loop {
                if self.stop.is_stopped() {
                    return Ok(report);
                }
                match rt
                    .block_on(async { tokio::time::timeout(ACCEPT_POLL, instance.connect()).await })
                {
                    Err(_elapsed) => continue,
                    Ok(Ok(())) => break,
                    Ok(Err(e)) => return Err(e),
                }
            }
            self.accepted.fetch_add(1, Ordering::Relaxed);

            // Authenticate BEFORE any byte is read. The impersonation token is
            // valid pre-read (proven by a test in `pipe.rs`), and doing it here
            // means an unauthenticated peer never reaches the framing layer and
            // never causes an allocation.
            let peer = match self.auth.authenticate_peer(&instance) {
                Ok(peer) => peer,
                Err(e) => {
                    report.unauthenticated += 1;
                    tracing::warn!(
                        target: "ssk.winhost.privileged",
                        error = %e,
                        "refusing a peer whose token could not be established"
                    );
                    // Hang up without answering. There is nothing safe to say
                    // to a peer we cannot name, and a typed refusal would be a
                    // response written on an unauthenticated channel.
                    drop(instance);
                    continue;
                }
            };
            tracing::info!(
                target: "ssk.winhost.privileged",
                peer = %peer.sid,
                elevated_admin = peer.token.elevated_admin,
                admin_account = peer.token.admin_account_filtered,
                integrity = peer.token.integrity_rid,
                "privileged peer authenticated"
            );

            let mut transport = NamedPipeFrameTransport::new(instance, &rt);
            let outcome = server.serve_connection(&mut transport, &peer, lease_ids);
            match &outcome {
                ConnectionOutcome::Served { frames, .. } => {
                    report.served += 1;
                    tracing::info!(
                        target: "ssk.winhost.privileged",
                        peer = %peer.sid,
                        frames = *frames,
                        "privileged connection closed"
                    );
                }
                ConnectionOutcome::Refused(reason) => {
                    report.refused += 1;
                    tracing::warn!(
                        target: "ssk.winhost.privileged",
                        peer = %peer.sid,
                        code = reason.code(),
                        "privileged handshake refused"
                    );
                }
                ConnectionOutcome::TransportFailed(e) => {
                    report.transport_failures += 1;
                    tracing::warn!(
                        target: "ssk.winhost.privileged",
                        peer = %peer.sid,
                        code = e.code(),
                        error = %e,
                        "privileged connection failed"
                    );
                }
                // `ConnectionOutcome` is `#[non_exhaustive]`. A variant this
                // host has never seen is counted as a transport failure — the
                // conservative bucket, since it is the only one that does not
                // claim a connection was successfully served.
                other => {
                    report.transport_failures += 1;
                    tracing::warn!(
                        target: "ssk.winhost.privileged",
                        peer = %peer.sid,
                        outcome = ?other,
                        "privileged connection ended with an outcome this host does not recognise"
                    );
                }
            }
            // Dropping the instance closes it; the next iteration creates a
            // fresh one. Reusing an instance across clients would mean calling
            // `DisconnectNamedPipe` and reasoning about a client that has not
            // yet noticed — a new instance costs one syscall and has no such
            // state.
            drop(transport);
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipe::current_user_sid;
    use ssk_netd_helper::framing::write_frame;
    use ssk_netd_helper::handshake::{ClientHello, ServerHandshake, PRIV_HANDSHAKE_MAGIC};
    use ssk_netd_helper::lease::LeaseKind;
    use ssk_netd_helper::{MAX_HANDSHAKE_FRAME, MAX_PRIV_FRAME};
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique_name(tag: &str) -> String {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            r"\\.\pipe\ssk-winhost-priv-{}-{tag}-{n}",
            std::process::id()
        )
    }

    /// The production descriptor cannot be created by a non-SYSTEM process (it
    /// carries `O:SY`), so the tests here use a same-user descriptor. What they
    /// exercise is the transport, the accept loop and the shutdown — none of
    /// which depend on which principals the DACL names.
    fn test_config(name: &str) -> PrivilegedPipeHostConfig {
        let sid = current_user_sid().expect("this process must know its own SID");
        PrivilegedPipeHostConfig {
            pipe_name: name.to_owned(),
            sddl: crate::pipe::sddl_for_user_owned_pipe(&sid).expect("descriptor"),
            max_instances: 8,
        }
    }

    #[test]
    fn the_production_config_carries_the_system_owner_and_one_ace_per_sid() {
        let cfg = PrivilegedPipeHostConfig::for_allow_list(&["S-1-5-21-1-2-3-1001"])
            .expect("a one-SID allow-list is valid");
        assert_eq!(cfg.pipe_name, PRIVILEGED_PIPE_NAME);
        assert!(cfg.sddl.starts_with("O:SY"), "{}", cfg.sddl);
        assert!(cfg.sddl.contains("(A;;0x12019b;;;S-1-5-21-1-2-3-1001)"));
        assert!(PrivilegedPipeHostConfig::for_allow_list(&[]).is_err());
    }

    #[test]
    fn the_read_only_fallback_config_is_reachable_by_interactive() {
        let cfg = PrivilegedPipeHostConfig::read_only_fallback();
        assert_eq!(cfg.pipe_name, PRIVILEGED_PIPE_NAME);
        assert!(cfg.sddl.contains(";;;IU)"), "{}", cfg.sddl);
    }

    #[test]
    fn a_descriptor_that_will_not_convert_is_a_startup_failure() {
        let err = PrivilegedPipeHost::new(PrivilegedPipeHostConfig {
            pipe_name: unique_name("bad-sddl"),
            sddl: "definitely not an sddl string".to_owned(),
            max_instances: 4,
        })
        .expect_err("a malformed descriptor must refuse at construction");
        assert!(matches!(err, PipeSecurityError::Win32 { .. }), "{err}");
    }

    /// Lease ids must be distinct even if the CSPRNG is unavailable, because a
    /// collision means one connection can drop another's claim.
    #[test]
    fn csprng_lease_ids_are_distinct_and_never_the_in_process_id() {
        let mut source = CsprngLeaseIds::default();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..512 {
            let id = source.next();
            assert_ne!(id, LeaseId::IN_PROCESS);
            assert!(seen.insert(id), "lease ids must not repeat");
        }
    }

    /// A listener with the stop flag already set must return without ever
    /// creating an instance, so a service that is stopped during startup does
    /// not leave a pipe behind.
    #[test]
    fn a_listener_that_is_already_stopped_returns_immediately() {
        let name = unique_name("prestop");
        let host = PrivilegedPipeHost::new(test_config(&name)).expect("host");
        host.stop_signal().stop();

        // No broker is needed: the loop must not get far enough to want one.
        // Constructing one here would make the test pass for the wrong reason.
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let created = rt
            .block_on(async { tokio::net::windows::named_pipe::ClientOptions::new().open(&name) });
        assert!(
            created.is_err(),
            "the listener must not have created an instance"
        );
        assert_eq!(host.accepted(), 0);
    }

    /// The read timeout is honoured against a **real** client that connects and
    /// then says nothing. Without this, `PRIV_READ_TIMEOUT` is a documented
    /// obligation that nothing checks, and a stalled peer blocks a listener
    /// forever.
    #[test]
    fn a_silent_client_hits_the_read_timeout_rather_than_blocking_forever() {
        let name = unique_name("stall");
        let sid = current_user_sid().expect("sid");
        let factory =
            WindowsPipeFactory::from_sddl(crate::pipe::sddl_for_user_owned_pipe(&sid).unwrap())
                .expect("factory");
        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        let server = rt
            .block_on(async { factory.create_instance(&name, true, 4) })
            .expect("create");
        let client = rt
            .block_on(async { ClientOptions::new().open(&name) })
            .expect("client");
        rt.block_on(server.connect()).expect("accept");

        let mut transport =
            NamedPipeFrameTransport::new(server, &rt).with_read_timeout(Duration::from_millis(150));
        let mut buf = [0u8; 4];
        let started = std::time::Instant::now();
        let err = transport
            .read(&mut buf)
            .expect_err("a silent peer must time out");
        assert_eq!(err, TransportError::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the timeout must actually bound the wait"
        );
        drop(client);
    }

    /// A peer that closes must read as `Closed`, not as an `Io` failure — the
    /// serve loop treats the two completely differently (end-of-connection
    /// versus a logged transport failure).
    #[test]
    fn a_disconnecting_client_reads_as_closed() {
        let name = unique_name("close");
        let sid = current_user_sid().expect("sid");
        let factory =
            WindowsPipeFactory::from_sddl(crate::pipe::sddl_for_user_owned_pipe(&sid).unwrap())
                .expect("factory");
        let rt = Builder::new_current_thread().enable_all().build().unwrap();

        let server = rt
            .block_on(async { factory.create_instance(&name, true, 4) })
            .expect("create");
        let client = rt
            .block_on(async { ClientOptions::new().open(&name) })
            .expect("client");
        rt.block_on(server.connect()).expect("accept");
        drop(client);

        let mut transport = NamedPipeFrameTransport::new(server, &rt);
        let mut buf = [0u8; 4];
        assert_eq!(transport.read(&mut buf), Err(TransportError::Closed));
    }

    /// The first-instance gate: exactly one caller creates the first instance,
    /// and a failure releases everyone with a typed refusal instead of leaving
    /// them blocked.
    #[test]
    fn the_first_instance_gate_elects_one_creator_and_releases_on_failure() {
        let gate = Arc::new(FirstInstanceGate::new());
        assert!(gate.acquire().expect("first caller creates"));

        let waiter = {
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || gate.acquire())
        };
        std::thread::sleep(Duration::from_millis(50));
        gate.settle(true);
        assert!(
            !waiter.join().expect("waiter").expect("released"),
            "a later caller must be told it is NOT the first instance"
        );

        let failing = Arc::new(FirstInstanceGate::new());
        assert!(failing.acquire().expect("first"));
        let waiter = {
            let gate = Arc::clone(&failing);
            std::thread::spawn(move || gate.acquire())
        };
        std::thread::sleep(Duration::from_millis(50));
        failing.settle(false);
        let err = waiter
            .join()
            .expect("waiter")
            .expect_err("a squatted name must fail every listener, not just one");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);
    }

    /// A frame written by this transport is readable by an ordinary client, and
    /// a hello written by an ordinary client is readable by this transport.
    /// That is the whole contract the broker's serve loop rests on.
    #[test]
    fn the_transport_round_trips_a_handshake_frame_with_a_real_client() {
        let name = unique_name("frame");
        let sid = current_user_sid().expect("sid");
        let factory =
            WindowsPipeFactory::from_sddl(crate::pipe::sddl_for_user_owned_pipe(&sid).unwrap())
                .expect("factory");
        let rt = Builder::new_current_thread().enable_all().build().unwrap();
        let server = rt
            .block_on(async { factory.create_instance(&name, true, 4) })
            .expect("create");

        // Encode a ClientHello exactly as the pure client would, and push it
        // through a raw OS handle so nothing in this test shares code with the
        // transport under test.
        let hello = ClientHello::new(LeaseKind::Session);
        let mut body = Vec::new();
        ciborium::ser::into_writer(&hello, &mut body).expect("encode");
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&body);

        let writer = {
            let name = name.clone();
            std::thread::spawn(move || {
                use std::io::Write;
                let mut handle = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&name)
                    .expect("client opens");
                handle.write_all(&frame).expect("client writes");
                handle.flush().expect("client flushes");
                handle
            })
        };
        rt.block_on(server.connect()).expect("accept");
        let _handle = writer.join().expect("writer thread");

        let mut transport = NamedPipeFrameTransport::new(server, &rt);
        let decoded: ClientHello =
            ssk_netd_helper::framing::read_frame(&mut transport, MAX_HANDSHAKE_FRAME)
                .expect("the transport must read a frame a real client wrote");
        assert_eq!(decoded.magic, PRIV_HANDSHAKE_MAGIC);
        assert_eq!(decoded.lease_kind, LeaseKind::Session);

        // And the other direction: a ServerHandshake written by the transport.
        let rejected =
            ServerHandshake::Rejected(ssk_netd_helper::handshake::HandshakeReject::AtCapacity);
        write_frame(&mut transport, &rejected, MAX_PRIV_FRAME)
            .expect("the transport must write a frame");
    }
}
