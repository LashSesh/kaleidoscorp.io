#![forbid(unsafe_code)]
//! Read-only desktop port. No UI, daemon startup, broker or mutation commands.
use serde::Serialize;
use ssk_ipc::{DaemonClient, DaemonState, Endpoint, Request, Response, StatusDto};
use ssk_ui_contract::{
    DaemonViewDto, DesktopPanelState, DesktopSchemaVersion, DesktopSnapshotV2, ReportedDaemonState,
};
use std::{path::Path, time::Duration};
use tokio::sync::Semaphore;

const READ_DEADLINE: Duration = Duration::from_secs(2);
const MAX_TEXT: usize = 256;
const MAX_ADAPTERS: usize = 256;

/// Stable public failure codes. Never expose raw IPC messages, paths or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadError {
    EndpointUnavailable,
    Unavailable,
    Deadline,
    Busy,
    InvalidResponse,
}
impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReadError {}

/// Resolve the same per-user endpoint as the CLI. No fallback to a relative
/// working directory or caller-supplied browser path is allowed.
pub fn local_endpoint() -> Result<Endpoint, ReadError> {
    endpoint_for_directory(&ssk_ipc::paths::state_dir())
}

fn endpoint_for_directory(directory: &Path) -> Result<Endpoint, ReadError> {
    if !directory.is_absolute() {
        return Err(ReadError::EndpointUnavailable);
    }
    #[cfg(windows)]
    {
        let sid = ssk_winhost::current_user_sid().map_err(|_| ReadError::EndpointUnavailable)?;
        Ok(Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(
            &sid, directory,
        )))
    }
    #[cfg(not(windows))]
    {
        Ok(Endpoint::UnixSocket(directory.join("sskd.sock")))
    }
}

pub struct DesktopClient {
    endpoint: Endpoint,
    reads: Semaphore,
}
impl DesktopClient {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            reads: Semaphore::new(1),
        }
    }

    /// One in-flight request, bounded connect+response time, fresh connection.
    /// Cancelling/dropping this future closes its connection and releases the slot.
    pub async fn read_snapshot(&self) -> Result<DesktopSnapshotV2, ReadError> {
        let _slot = self.reads.try_acquire().map_err(|_| ReadError::Busy)?;
        bounded_read(async {
            let mut client = DaemonClient::connect(&self.endpoint)
                .await
                .map_err(|_| ReadError::Unavailable)?;
            let response = client
                .call(Request::GetStatus)
                .await
                .map_err(|_| ReadError::Unavailable)?;
            project_response(response)
        })
        .await
    }
}

async fn bounded_read<F: std::future::Future<Output = Result<DesktopSnapshotV2, ReadError>>>(
    read: F,
) -> Result<DesktopSnapshotV2, ReadError> {
    tokio::time::timeout(READ_DEADLINE, read)
        .await
        .map_err(|_| ReadError::Deadline)?
}

fn text_allowed(value: &str) -> bool {
    value.len() <= MAX_TEXT && !value.chars().any(char::is_control)
}

fn project_response(response: Response) -> Result<DesktopSnapshotV2, ReadError> {
    match response {
        Response::Status(status) => project_status(status),
        Response::Err(_) => Err(ReadError::Unavailable),
        _ => Err(ReadError::InvalidResponse),
    }
}

fn project_status(status: StatusDto) -> Result<DesktopSnapshotV2, ReadError> {
    let last_error_code = status.last_error.map(|e| e.code);
    if !text_allowed(&status.version)
        || status.version.is_empty()
        || status
            .active_profile
            .as_deref()
            .is_some_and(|s| !text_allowed(s))
        || last_error_code.as_deref().is_some_and(|s| !text_allowed(s))
        || status.adapters.len() > MAX_ADAPTERS
    {
        return Err(ReadError::InvalidResponse);
    }
    let reported_state = match status.state {
        DaemonState::Inactive => ReportedDaemonState::Inactive,
        DaemonState::Activating => ReportedDaemonState::Activating,
        DaemonState::Active => ReportedDaemonState::Active,
        DaemonState::Protected => ReportedDaemonState::Protected,
        DaemonState::Degraded => ReportedDaemonState::Degraded,
        DaemonState::FailClosed => ReportedDaemonState::FailClosed,
        DaemonState::ConfigInvalid => ReportedDaemonState::ConfigInvalid,
        DaemonState::RecoveryMode => ReportedDaemonState::RecoveryMode,
    };
    // StatusDto's booleans and audit head do not prove OS protection or chain
    // integrity. Do not invent the missing detailed v1 security views.
    Ok(DesktopSnapshotV2 {
        schema_version: DesktopSchemaVersion,
        panel_state: DesktopPanelState::Degraded,
        daemon: DaemonViewDto {
            reported_state,
            version: status.version,
            active_profile: status.active_profile,
            adapter_count: status.adapters.len() as u32,
            last_error_code,
        },
    })
}

#[cfg(test)]
mod tests;
