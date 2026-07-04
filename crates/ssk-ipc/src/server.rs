#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::auth::SessionToken;
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

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Implemented by the daemon's supervisor to answer IPC requests. Kept as a
/// trait — rather than a concrete daemon type — so `ssk-ipc` never depends on
/// `ssk-daemon` (the architecture's dependency-layering rule: data-plane and
/// service crates depend on control-plane crates, never the reverse; `ssk-ipc`
/// is a control/wire crate that `ssk-daemon` depends on).
pub trait CommandHandler: Send + Sync {
    fn handle<'a>(&'a self, req: Request, token: &'a SessionToken) -> BoxFuture<'a, Response>;
}

#[cfg(unix)]
mod unix_transport {
    use super::{CommandHandler, Request};
    use crate::auth::{unix::check_peer_same_user, SessionToken};
    use crate::error::IpcError;
    use std::sync::Arc;

    /// Bind a Unix domain socket at `socket_path` and serve `handler` forever.
    /// Removes a stale socket file left over from an unclean previous exit
    /// and creates the parent directory if needed.
    pub async fn serve_unix(
        socket_path: impl AsRef<std::path::Path>,
        handler: Arc<dyn CommandHandler>,
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

        loop {
            let (stream, _addr) = listener
                .accept()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                if let Err(err) = handle_connection(stream, handler).await {
                    tracing::warn!(code = %err.code, message = %err.message, "ipc connection ended with error");
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: tokio::net::UnixStream,
        handler: Arc<dyn CommandHandler>,
    ) -> Result<(), IpcError> {
        check_peer_same_user(&stream)?;
        let token = SessionToken::generate();
        loop {
            let req: Request = match crate::framing::read_frame(&mut stream).await {
                Ok(req) => req,
                Err(_) => return Ok(()), // peer closed or sent a malformed frame
            };
            let resp = handler.handle(req, &token).await;
            crate::framing::write_frame(&mut stream, &resp).await?;
        }
    }
}

#[cfg(unix)]
pub use unix_transport::serve_unix;

/// Windows named-pipe transport. Written against tokio's documented
/// `windows::named_pipe` API; this sandboxed Linux environment has no Windows
/// toolchain, so this path has **not** been compiled or tested here — treat
/// it as unverified until a Windows CI job or manual run confirms it builds.
/// Client-SID verification is a documented gap (see `auth::windows`).
#[cfg(windows)]
mod windows_transport {
    use super::{CommandHandler, Request};
    use crate::auth::SessionToken;
    use crate::error::IpcError;
    use std::sync::Arc;
    use tokio::net::windows::named_pipe::ServerOptions;

    pub async fn serve_named_pipe(
        pipe_name: &str,
        handler: Arc<dyn CommandHandler>,
    ) -> Result<(), IpcError> {
        let mut first = true;
        loop {
            let mut server = ServerOptions::new()
                .first_pipe_instance(first)
                .create(pipe_name)
                .map_err(|e| IpcError::new("Runtime", "IPC_BIND_FAILED", e.to_string()))?;
            first = false;
            server
                .connect()
                .await
                .map_err(|e| IpcError::new("Runtime", "IPC_ACCEPT_FAILED", e.to_string()))?;
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                if let Err(err) = handle_connection(server, handler).await {
                    tracing::warn!(code = %err.code, message = %err.message, "ipc connection ended with error");
                }
            });
        }
    }

    async fn handle_connection(
        mut stream: tokio::net::windows::named_pipe::NamedPipeServer,
        handler: Arc<dyn CommandHandler>,
    ) -> Result<(), IpcError> {
        let token = SessionToken::generate();
        loop {
            let req: Request = match crate::framing::read_frame(&mut stream).await {
                Ok(req) => req,
                Err(_) => return Ok(()),
            };
            let resp = handler.handle(req, &token).await;
            crate::framing::write_frame(&mut stream, &resp).await?;
        }
    }
}

#[cfg(windows)]
pub use windows_transport::serve_named_pipe;
