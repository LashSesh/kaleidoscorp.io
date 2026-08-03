#![forbid(unsafe_code)]

//! The daemon client — **one** call path on both platforms.
//!
//! `ssk-cli` previously had a `#[cfg(unix)]` client and a `#[cfg(not(unix))]`
//! stub that returned `DAEMON_UNIX_ONLY` (exit 12), so `ssk status` failed on
//! Windows while `sskd` sat listening on its pipe beside it. There is now a
//! single [`DaemonClient`] with a single [`connect`](DaemonClient::connect) /
//! [`call`](DaemonClient::call) pair; only the private stream type behind it
//! differs by platform, and only the [`Endpoint`] construction differs at the
//! composition root.
//!
//! The wire protocol is identical in both directions and on both platforms:
//! the same length-prefixed canonical CBOR the server already speaks
//! ([`crate::framing`]).

use std::time::Duration;

use crate::error::IpcError;
use crate::paths::Endpoint;
use crate::server::{Request, Response};

/// How long [`DaemonClient::connect`] keeps retrying a busy Windows pipe
/// before giving up. Every instance being momentarily in use is normal under
/// concurrency, not a failure; a server that is not running fails immediately
/// with a different error and never reaches this path.
const CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(2);
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(20);

#[cfg(unix)]
type Stream = tokio::net::UnixStream;

#[cfg(windows)]
type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// A connected client. Issues requests sequentially, matching the daemon's
/// per-connection request/response loop.
pub struct DaemonClient {
    stream: Stream,
}

impl DaemonClient {
    /// Connect to the daemon at `endpoint`.
    ///
    /// An `Endpoint` variant that does not match the running platform is a
    /// typed error, not a panic and not a silent fallback — both variants are
    /// constructible everywhere so cross-platform code compiles, and this is
    /// where the mismatch is caught.
    pub async fn connect(endpoint: &Endpoint) -> Result<Self, IpcError> {
        match endpoint {
            Endpoint::UnixSocket(path) => Self::connect_unix(path).await,
            Endpoint::NamedPipe(name) => Self::connect_named_pipe(name).await,
        }
    }

    /// Send one request and read the single response to it.
    pub async fn call(&mut self, req: Request) -> Result<Response, IpcError> {
        crate::framing::write_frame(&mut self.stream, &req).await?;
        self.recv().await
    }

    /// Read one further response without sending a request.
    ///
    /// Used by a subscriber after `Request::SubscribeEvents`: that connection
    /// is exempt from the server's idle timeout (see
    /// `server::next_timeout`), so it may sit waiting for pushed frames.
    pub async fn recv(&mut self) -> Result<Response, IpcError> {
        crate::framing::read_frame(&mut self.stream, crate::framing::MAX_RESPONSE_FRAME_LEN).await
    }

    #[cfg(unix)]
    async fn connect_unix(path: &std::path::Path) -> Result<Self, IpcError> {
        let stream = tokio::net::UnixStream::connect(path).await.map_err(|e| {
            IpcError::new("Runtime", "IPC_CONNECT_FAILED", e.to_string())
                .with_next_step("Is `sskd` running? Start the daemon and retry.")
                .retriable()
        })?;
        Ok(Self { stream })
    }

    #[cfg(not(unix))]
    #[allow(clippy::unused_async)]
    async fn connect_unix(path: &std::path::Path) -> Result<Self, IpcError> {
        Err(IpcError::new(
            "Runtime",
            "IPC_ENDPOINT_UNSUPPORTED",
            format!(
                "{} is a Unix domain socket path; this build has no Unix transport",
                path.display()
            ),
        ))
    }

    /// Open the named pipe.
    ///
    /// `ClientOptions::new()` is left with its default `security_qos_flags`
    /// (`SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT`). **Do not clear or
    /// override it.** That default is exactly what lets the server's
    /// `ImpersonateNamedPipeClient` check read our SID; a client that opens
    /// with `SECURITY_ANONYMOUS`, or with no SQOS flags at all, is rejected by
    /// the server on purpose. It is also the flag that stops a rogue *server*
    /// from impersonating us onward to other objects.
    #[cfg(windows)]
    async fn connect_named_pipe(name: &str) -> Result<Self, IpcError> {
        use tokio::net::windows::named_pipe::ClientOptions;

        /// All server instances are momentarily in use.
        const ERROR_PIPE_BUSY: i32 = 231;

        let deadline = std::time::Instant::now() + CONNECT_RETRY_BUDGET;
        loop {
            match ClientOptions::new().open(name) {
                Ok(stream) => return Ok(Self { stream }),
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                    if std::time::Instant::now() >= deadline {
                        return Err(IpcError::new(
                            "Runtime",
                            "IPC_CONNECT_BUSY",
                            format!(
                                "every instance of {name} was in use for {CONNECT_RETRY_BUDGET:?}"
                            ),
                        )
                        .with_next_step("The daemon is at its connection cap. Retry shortly.")
                        .retriable());
                    }
                    tokio::time::sleep(CONNECT_RETRY_INTERVAL).await;
                }
                Err(e) => {
                    return Err(IpcError::new(
                        "Runtime",
                        "IPC_CONNECT_FAILED",
                        format!("{name}: {e}"),
                    )
                    .with_next_step("Is `sskd` running? Start the daemon and retry.")
                    .retriable());
                }
            }
        }
    }

    #[cfg(not(windows))]
    #[allow(clippy::unused_async)]
    async fn connect_named_pipe(name: &str) -> Result<Self, IpcError> {
        Err(IpcError::new(
            "Runtime",
            "IPC_ENDPOINT_UNSUPPORTED",
            format!("{name} is a Windows named pipe; this build has no named-pipe transport"),
        ))
    }
}

/// Unix domain socket client, kept as the name existing callers and tests use.
///
/// It is now an alias for the cross-platform [`DaemonClient`] rather than a
/// separate type, so there is exactly one framing implementation and one
/// request/response loop to keep correct.
///
/// **Migration:** `UnixClient::connect(path)` no longer compiles, because
/// `DaemonClient::connect` takes an [`Endpoint`]. Call
/// [`DaemonClient::connect_path`] with the same argument, or
/// `DaemonClient::connect(&paths::default_endpoint())`. The break is
/// deliberate and mechanical: a silently-accepted path would have reintroduced
/// the two-call-path split this type exists to remove.
#[cfg(unix)]
pub type UnixClient = DaemonClient;

#[cfg(unix)]
impl DaemonClient {
    /// Connect to a Unix domain socket by path — the direct replacement for
    /// the old `UnixClient::connect`.
    pub async fn connect_path(socket_path: impl AsRef<std::path::Path>) -> Result<Self, IpcError> {
        Self::connect(&Endpoint::UnixSocket(socket_path.as_ref().to_path_buf())).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wrong-platform endpoint variant must produce a typed error rather
    /// than a panic — the property that lets cross-platform callers hold an
    /// `Endpoint` without cfg-splitting their own code.
    #[tokio::test]
    async fn wrong_platform_endpoint_is_a_typed_error() {
        #[cfg(windows)]
        let endpoint = Endpoint::UnixSocket(std::path::PathBuf::from("/tmp/nope.sock"));
        #[cfg(unix)]
        let endpoint = Endpoint::NamedPipe(r"\\.\pipe\nope".to_owned());

        let err = DaemonClient::connect(&endpoint)
            .await
            .err()
            .expect("wrong-platform endpoint must fail");
        assert_eq!(err.code, "IPC_ENDPOINT_UNSUPPORTED");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn connecting_to_an_absent_pipe_fails_fast_and_retriably() {
        let name = format!(
            r"\\.\pipe\ssk-ipc-absent-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        );
        let started = std::time::Instant::now();
        let err = DaemonClient::connect(&Endpoint::NamedPipe(name))
            .await
            .err()
            .expect("no server is listening");
        assert_eq!(err.code, "IPC_CONNECT_FAILED");
        assert!(err.retriable);
        assert!(
            started.elapsed() < CONNECT_RETRY_BUDGET,
            "a missing pipe must not consume the busy-retry budget"
        );
    }
}
