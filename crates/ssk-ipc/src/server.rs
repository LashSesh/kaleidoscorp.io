#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::auth::PeerIdentity;
use crate::dto::{
    ActivateProfileRequest, AuditEntryDto, DeactivateRequest, DoctorReportDto, ExplainRequest,
    ExplainResponse, FlowInspectionDto, FlowSummaryDto, ProfileSummaryDto, RouteTraceDto,
    RouteTraceRequest, StatusDto, SubscribeEventsRequest, VerifyAuditChainResponse,
};
use crate::error::IpcError;
use crate::state::Event;

/// Section-J commands 1-4 and 15-22 (Phase 2 scope). `run` / `replay-verify` /
/// `doctor` (as local CLI commands) and the remaining Section-J commands
/// (adapter/chain CRUD, config import/export) are out of scope until their
/// respective phases (3, 5) ship real backing state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    GetStatus,
    ActivateProfile(ActivateProfileRequest),
    Deactivate(DeactivateRequest),
    ListProfiles,
    InspectFlow { flow_id: String },
    TraceRoute(RouteTraceRequest),
    ListRecentFlows { limit: usize },
    GetAuditEntries { limit: usize },
    VerifyAuditChain,
    RunDoctor,
    ExplainError(ExplainRequest),
    SubscribeEvents(SubscribeEventsRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Status(StatusDto),
    Profiles(Vec<ProfileSummaryDto>),
    FlowInspection(FlowInspectionDto),
    RouteTrace(RouteTraceDto),
    RecentFlows(Vec<FlowSummaryDto>),
    AuditEntries(Vec<AuditEntryDto>),
    AuditVerify(VerifyAuditChainResponse),
    Doctor(DoctorReportDto),
    Explain(ExplainResponse),
    Event(Event),
    Ack,
    Err(IpcError),
}

/// Upper bound the transport clamps `limit`-bearing requests to before the
/// handler sees them.
///
/// `Request::ListRecentFlows { limit }` and `Request::GetAuditEntries { limit }`
/// carry an attacker-controlled `usize` that feeds a `Vec` allocation on the
/// handler side. The peer is authenticated by the time this applies, so it is
/// defence in depth rather than the boundary — but an authenticated peer is
/// still not entitled to name an allocation size, and the response cap
/// ([`crate::framing::MAX_RESPONSE_FRAME_LEN`]) would otherwise be reached only
/// *after* the allocation had already happened.
pub const MAX_LIST_LIMIT: usize = 1000;

/// Bounds a served connection. Every field is explicit — there is no ambient
/// default a call site can forget it inherited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeLimits {
    /// Maximum concurrent connections. On Windows it is passed to
    /// [`PipeFactory::create_instance`](crate::transport_win::PipeFactory::create_instance)
    /// as `max_instances`, which implementations map to `CreateNamedPipeW`'s
    /// `nMaxInstances` so the OS itself refuses the overflow connection; it is
    /// *also* enforced by a semaphore around the accept loop, so the loop
    /// cannot spawn unbounded tasks even if the OS-level cap changes.
    pub max_connections: u32,
    /// Cap on one inbound request frame.
    pub max_request_frame_len: u32,
    /// How long a connected peer may stay silent before its first frame.
    /// Drops connected-but-silent clients that would otherwise hold an
    /// instance open forever.
    pub first_frame_timeout: Duration,
    /// How long an established connection may stay idle between frames.
    pub idle_timeout: Duration,
}

impl Default for ServeLimits {
    fn default() -> Self {
        Self {
            max_connections: 16,
            max_request_frame_len: crate::framing::MAX_REQUEST_FRAME_LEN,
            first_frame_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(300),
        }
    }
}

/// Clamp the attacker-controlled `limit` fields. Returns the request either
/// unchanged or with `limit` reduced to [`MAX_LIST_LIMIT`].
#[must_use]
pub fn clamp_request_limits(req: Request) -> Request {
    match req {
        Request::ListRecentFlows { limit } => Request::ListRecentFlows {
            limit: limit.min(MAX_LIST_LIMIT),
        },
        Request::GetAuditEntries { limit } => Request::GetAuditEntries {
            limit: limit.min(MAX_LIST_LIMIT),
        },
        other => other,
    }
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Implemented by the daemon's supervisor to answer IPC requests. Kept as a
/// trait — rather than a concrete daemon type — so `ssk-ipc` never depends on
/// `ssk-daemon` (the architecture's dependency-layering rule: data-plane and
/// service crates depend on control-plane crates, never the reverse; `ssk-ipc`
/// is a control/wire crate that `ssk-daemon` depends on).
///
/// `peer` is the identity the transport *verified*, replacing the former
/// `&SessionToken` — a value the server minted, never transmitted and never
/// compared (see [`crate::auth`] for why transmitting it would have been
/// vacuous). A handler can now audit and authorize on who actually called.
pub trait CommandHandler: Send + Sync {
    fn handle<'a>(&'a self, req: Request, peer: &'a PeerIdentity) -> BoxFuture<'a, Response>;
}

/// Whether a connection is still subject to an idle timeout.
///
/// `SubscribeEvents` is exempt: it is a long-lived server-push stream and a
/// blanket idle timeout would kill a live UI. Today the handler answers a
/// subscribe with a single `Response`, so the exemption changes no observable
/// behaviour yet; it is here so that adding server push is additive rather
/// than a timeout regression discovered in production.
fn next_timeout(subscribed: bool, limits: &ServeLimits) -> Option<Duration> {
    if subscribed {
        None
    } else {
        Some(limits.idle_timeout)
    }
}

#[cfg(unix)]
mod unix_transport {
    use super::{clamp_request_limits, next_timeout, CommandHandler, Request, ServeLimits};
    use crate::auth::unix::check_peer_same_user;
    use crate::error::IpcError;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    /// Bind a Unix domain socket at `socket_path` and serve `handler` forever
    /// with [`ServeLimits::default`].
    pub async fn serve_unix(
        socket_path: impl AsRef<std::path::Path>,
        handler: Arc<dyn CommandHandler>,
    ) -> Result<(), IpcError> {
        serve_unix_with_limits(socket_path, handler, ServeLimits::default()).await
    }

    /// Bind a Unix domain socket at `socket_path` and serve `handler` forever.
    /// Removes a stale socket file left over from an unclean previous exit
    /// and creates the parent directory if needed.
    pub async fn serve_unix_with_limits(
        socket_path: impl AsRef<std::path::Path>,
        handler: Arc<dyn CommandHandler>,
        limits: ServeLimits,
    ) -> Result<(), IpcError> {
        let path = socket_path.as_ref();
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| IpcError::new("Runtime", "IPC_BIND_FAILED", e.to_string()))?;
        }
        let listener = tokio::net::UnixListener::bind(path)
            .map_err(|e| IpcError::new("Runtime", "IPC_BIND_FAILED", e.to_string()))?;
        let permits = Arc::new(Semaphore::new(limits.max_connections as usize));

        loop {
            let (stream, _addr) = listener
                .accept()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;
            let permit = Arc::clone(&permits)
                .acquire_owned()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) = handle_connection(stream, handler, limits).await {
                    tracing::warn!(code = %err.code, message = %err.message, "ipc connection ended with error");
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: tokio::net::UnixStream,
        handler: Arc<dyn CommandHandler>,
        limits: ServeLimits,
    ) -> Result<(), IpcError> {
        let peer = check_peer_same_user(&stream)?;
        let mut subscribed = false;
        let mut timeout = Some(limits.first_frame_timeout);
        loop {
            let read =
                crate::framing::read_frame::<Request, _>(&mut stream, limits.max_request_frame_len);
            let req = match super::read_with_timeout(read, timeout).await? {
                Some(req) => req,
                None => return Ok(()), // peer closed or sent a malformed frame
            };
            if matches!(req, Request::SubscribeEvents(_)) {
                subscribed = true;
            }
            let resp = handler.handle(clamp_request_limits(req), &peer).await;
            crate::framing::write_frame(&mut stream, &resp).await?;
            timeout = next_timeout(subscribed, &limits);
        }
    }
}

#[cfg(unix)]
pub use unix_transport::{serve_unix, serve_unix_with_limits};

/// Await `read`, applying `timeout` when one is set.
///
/// Three outcomes, kept distinct on purpose:
/// * `Ok(Some(req))` — a frame arrived.
/// * `Ok(None)` — the connection ended at the I/O layer (`IPC_IO_FAILED`).
///   That is how every well-behaved client disconnects, so it is not logged.
/// * `Err(_)` — the peer stayed silent past the timeout, or sent a frame this
///   server refused (`IPC_FRAME_TOO_LARGE`) or could not decode
///   (`IPC_DECODE_FAILED`). Those are peer *misbehaviour*, not a disconnect,
///   and the caller logs them. Collapsing them into the disconnect case —
///   as `read_frame(...).ok()` used to — is how an instance-exhaustion or
///   malformed-frame probe leaves no trace at all.
async fn read_with_timeout<F>(
    read: F,
    timeout: Option<Duration>,
) -> Result<Option<Request>, IpcError>
where
    F: Future<Output = Result<Request, IpcError>>,
{
    let outcome = match timeout {
        None => read.await,
        Some(limit) => match tokio::time::timeout(limit, read).await {
            Ok(result) => result,
            Err(_) => {
                return Err(IpcError::new(
                    "Runtime",
                    "IPC_READ_TIMEOUT",
                    format!("peer sent no frame within {limit:?}"),
                ))
            }
        },
    };
    match outcome {
        Ok(req) => Ok(Some(req)),
        // A closed or reset pipe/socket is an ordinary end of conversation.
        Err(err) if err.code == "IPC_IO_FAILED" => Ok(None),
        Err(err) => Err(err),
    }
}

/// Windows named-pipe transport.
///
/// **This server path works.** It was compiled and driven end-to-end on
/// Windows 11 (2026-08-02): `sskd.exe` bound its pipe and a hand-written .NET
/// client spoke this CBOR framing against it and received a valid 116-byte
/// `Response::Status` DTO back.
///
/// What that exercise also demonstrated was the defect this module now closes:
/// the client was an unrelated, unelevated process with zero credentials, and
/// `handle_connection` performed **no peer check at all** where its Unix twin
/// called `check_peer_same_user`. The pipe was additionally created with no
/// `SECURITY_ATTRIBUTES`, so the measured default DACL granted
/// `FILE_GENERIC_READ` to `Everyone` and `ANONYMOUS LOGON`.
///
/// Both halves are now required arguments rather than optional hardening:
/// [`serve_named_pipe`] cannot be called without a
/// [`PipeFactory`](crate::transport_win::PipeFactory) (which carries the DACL)
/// and a [`PeerAuthenticator`](crate::transport_win::PeerAuthenticator) (which
/// establishes the peer's SID). Both are implemented in `ssk-winhost`.
#[cfg(windows)]
mod windows_transport {
    use super::{clamp_request_limits, next_timeout, CommandHandler, Request, ServeLimits};
    use crate::auth::PeerIdentity;
    use crate::error::IpcError;
    use crate::transport_win::{check_peer_same_user, PeerAuthenticator, PipeFactory};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::net::windows::named_pipe::NamedPipeServer;
    use tokio::sync::Semaphore;

    /// All pipe instances are in use. Not fatal: back off and retry.
    const ERROR_PIPE_BUSY: i32 = 231;
    /// With `FILE_FLAG_FIRST_PIPE_INSTANCE`, someone else already owns this
    /// name. Fatal: refuse to start rather than serve beside a squatter.
    const ERROR_ACCESS_DENIED: i32 = 5;

    const CREATE_RETRY_MIN: Duration = Duration::from_millis(5);
    const CREATE_RETRY_MAX: Duration = Duration::from_millis(250);

    /// Serve `handler` on `pipe_name` forever.
    ///
    /// `pipes` creates each instance with the daemon's DACL; `auth` establishes
    /// the peer SID of each connection. Neither is optional — that is what
    /// makes "the Windows IPC surface is unauthenticated" a state this binary
    /// can no longer be built in.
    pub async fn serve_named_pipe(
        pipe_name: &str,
        handler: Arc<dyn CommandHandler>,
        pipes: Arc<dyn PipeFactory>,
        auth: Arc<dyn PeerAuthenticator>,
        limits: ServeLimits,
    ) -> Result<(), IpcError> {
        let permits = Arc::new(Semaphore::new(limits.max_connections as usize));
        // `first_instance` is true exactly once, for the first instance. It is
        // the anti-squat guard: if another process already owns this name our
        // create fails with ERROR_ACCESS_DENIED and we refuse to start.
        let mut listening =
            create_instance(&*pipes, pipe_name, true, limits.max_connections).await?;

        loop {
            // Take a serving slot *before* waiting for a client, so the loop
            // never holds a connected peer it has no capacity to serve.
            let permit = Arc::clone(&permits)
                .acquire_owned()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;

            listening
                .connect()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;
            let connected = listening;

            let spawn_handler = Arc::clone(&handler);
            let spawn_auth = Arc::clone(&auth);
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) =
                    handle_connection(connected, spawn_handler, spawn_auth, limits).await
                {
                    tracing::warn!(code = %err.code, message = %err.message, "ipc connection ended with error");
                }
            });

            // Only now create the replacement listener. At the instance cap
            // this blocks retrying ERROR_PIPE_BUSY, which is safe precisely
            // because the handler is already spawned.
            //
            // Creating it *before* the spawn — as an earlier revision of this
            // loop did, to shrink the window in which no instance is listening
            // — deadlocks at the cap. Measured on Windows 11 with
            // `max_connections = 2`: the second client connected, the loop
            // blocked retrying the third instance, and that client's first
            // request went unanswered for **30 s** — until the *first*
            // client's idle timeout expired and freed an instance. The window
            // this ordering reopens is a `tokio::spawn` wide, and a client
            // that lands in it gets ERROR_PIPE_BUSY, which
            // `DaemonClient::connect` already retries.
            listening = create_instance(&*pipes, pipe_name, false, limits.max_connections).await?;
        }
    }

    /// Create one instance, retrying while every instance is in use.
    ///
    /// `ERROR_PIPE_BUSY` is the expected consequence of the connection cap:
    /// once `max_connections` instances exist the OS refuses the next one, and
    /// the accept loop must wait rather than return `Err` and kill the server.
    async fn create_instance(
        pipes: &dyn PipeFactory,
        pipe_name: &str,
        first_instance: bool,
        max_instances: u32,
    ) -> Result<NamedPipeServer, IpcError> {
        let mut backoff = CREATE_RETRY_MIN;
        loop {
            match pipes.create_instance(pipe_name, first_instance, max_instances) {
                Ok(server) => return Ok(server),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(CREATE_RETRY_MAX);
                }
                Err(e) if first_instance && e.raw_os_error() == Some(ERROR_ACCESS_DENIED) => {
                    return Err(IpcError::new(
                        "Permission",
                        "IPC_PIPE_NAME_TAKEN",
                        format!("another process already owns {pipe_name}: {e}"),
                    )
                    .with_next_step(
                        "Another daemon — or a squatter — holds this pipe name. \
                         Stop the other instance, or run with a different SSK_STATE_DIR.",
                    ));
                }
                Err(e) => {
                    return Err(IpcError::new("Runtime", "IPC_BIND_FAILED", e.to_string()));
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: NamedPipeServer,
        handler: Arc<dyn CommandHandler>,
        auth: Arc<dyn PeerAuthenticator>,
        limits: ServeLimits,
    ) -> Result<(), IpcError> {
        // Authenticate before a single frame byte is read or allocated.
        // Impersonation is valid pre-read (measured against a client that
        // wrote zero bytes), so there is no reason to let an unauthenticated
        // peer reach the framing layer at all.
        let sid = check_peer_same_user(&*auth, &stream)?;
        let peer = PeerIdentity::Sid(sid.0);

        let mut subscribed = false;
        let mut timeout = Some(limits.first_frame_timeout);
        loop {
            let read =
                crate::framing::read_frame::<Request, _>(&mut stream, limits.max_request_frame_len);
            let req = match super::read_with_timeout(read, timeout).await? {
                Some(req) => req,
                None => return Ok(()),
            };
            if matches!(req, Request::SubscribeEvents(_)) {
                subscribed = true;
            }
            let resp = handler.handle(clamp_request_limits(req), &peer).await;
            crate::framing::write_frame(&mut stream, &resp).await?;
            timeout = next_timeout(subscribed, &limits);
        }
    }
}

#[cfg(windows)]
pub use windows_transport::serve_named_pipe;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_limits_are_clamped() {
        let clamped = clamp_request_limits(Request::ListRecentFlows { limit: usize::MAX });
        match clamped {
            Request::ListRecentFlows { limit } => assert_eq!(limit, MAX_LIST_LIMIT),
            other => panic!("wrong variant: {other:?}"),
        }
        let clamped = clamp_request_limits(Request::GetAuditEntries { limit: usize::MAX });
        match clamped {
            Request::GetAuditEntries { limit } => assert_eq!(limit, MAX_LIST_LIMIT),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn list_limits_below_the_cap_pass_through() {
        let clamped = clamp_request_limits(Request::ListRecentFlows { limit: 7 });
        match clamped {
            Request::ListRecentFlows { limit } => assert_eq!(limit, 7),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn subscribe_exempts_a_connection_from_the_idle_timeout() {
        let limits = ServeLimits::default();
        assert_eq!(next_timeout(false, &limits), Some(limits.idle_timeout));
        assert_eq!(next_timeout(true, &limits), None);
    }

    #[test]
    fn default_limits_are_the_documented_ones() {
        let limits = ServeLimits::default();
        assert_eq!(limits.max_connections, 16);
        assert_eq!(
            limits.max_request_frame_len,
            crate::framing::MAX_REQUEST_FRAME_LEN
        );
        assert_eq!(limits.first_frame_timeout, Duration::from_secs(5));
        assert_eq!(limits.idle_timeout, Duration::from_secs(300));
    }

    /// A refused or undecodable frame must be distinguishable from a normal
    /// disconnect, so the accept loop's `tracing::warn!` actually fires on it.
    #[tokio::test]
    async fn misbehaving_peer_is_surfaced_not_swallowed() {
        use tokio::io::AsyncWriteExt;

        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&(crate::framing::MAX_REQUEST_FRAME_LEN + 1).to_be_bytes())
            .await
            .expect("write oversized length prefix");
        let read = crate::framing::read_frame::<Request, _>(
            &mut server,
            crate::framing::MAX_REQUEST_FRAME_LEN,
        );
        let err = read_with_timeout(read, Some(Duration::from_secs(5)))
            .await
            .expect_err("an over-cap frame is misbehaviour, not a disconnect");
        assert_eq!(err.code, "IPC_FRAME_TOO_LARGE");

        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&2u32.to_be_bytes())
            .await
            .expect("write length prefix");
        client
            .write_all(&[0xff, 0xff])
            .await
            .expect("write undecodable body");
        let read = crate::framing::read_frame::<Request, _>(
            &mut server,
            crate::framing::MAX_REQUEST_FRAME_LEN,
        );
        let err = read_with_timeout(read, Some(Duration::from_secs(5)))
            .await
            .expect_err("an undecodable frame is misbehaviour, not a disconnect");
        assert_eq!(err.code, "IPC_DECODE_FAILED");
    }

    #[tokio::test]
    async fn silent_peer_hits_the_read_timeout() {
        let (_client, mut server) = tokio::io::duplex(64);
        let read = crate::framing::read_frame::<Request, _>(
            &mut server,
            crate::framing::MAX_REQUEST_FRAME_LEN,
        );
        let err = read_with_timeout(read, Some(Duration::from_millis(50)))
            .await
            .expect_err("a silent peer must time out");
        assert_eq!(err.code, "IPC_READ_TIMEOUT");
    }

    #[tokio::test]
    async fn closed_peer_is_not_an_error() {
        let (client, mut server) = tokio::io::duplex(64);
        drop(client);
        let read = crate::framing::read_frame::<Request, _>(
            &mut server,
            crate::framing::MAX_REQUEST_FRAME_LEN,
        );
        let outcome = read_with_timeout(read, Some(Duration::from_secs(5)))
            .await
            .expect("a closed peer is a normal disconnect");
        assert!(outcome.is_none());
    }
}
