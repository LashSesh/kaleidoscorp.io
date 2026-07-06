#![forbid(unsafe_code)]

#[cfg(unix)]
use crate::error::IpcError;
#[cfg(unix)]
use crate::server::{Request, Response};

/// Unix domain socket client. Connects once and issues requests sequentially
/// (matches the daemon's per-connection request/response loop in
/// `server::serve_unix`).
#[cfg(unix)]
pub struct UnixClient {
    stream: tokio::net::UnixStream,
}

#[cfg(unix)]
impl UnixClient {
    pub async fn connect(socket_path: impl AsRef<std::path::Path>) -> Result<Self, IpcError> {
        let stream = tokio::net::UnixStream::connect(socket_path.as_ref())
            .await
            .map_err(|e| {
                IpcError::new("Runtime", "IPC_CONNECT_FAILED", e.to_string())
                    .with_next_step("Is `sskd` running? Start the daemon and retry.")
                    .retriable()
            })?;
        Ok(Self { stream })
    }

    pub async fn call(&mut self, req: Request) -> Result<Response, IpcError> {
        crate::framing::write_frame(&mut self.stream, &req).await?;
        crate::framing::read_frame(&mut self.stream).await
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::auth::SessionToken;
    use crate::server::{serve_unix, BoxFuture, CommandHandler};
    use std::sync::Arc;

    struct EchoHandler;
    impl CommandHandler for EchoHandler {
        fn handle<'a>(&'a self, req: Request, _token: &'a SessionToken) -> BoxFuture<'a, Response> {
            Box::pin(async move {
                match req {
                    Request::GetStatus => Response::Ack,
                    _ => Response::Ack,
                }
            })
        }
    }

    #[tokio::test]
    async fn connect_and_call_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("test.sock");
        let handler: Arc<dyn CommandHandler> = Arc::new(EchoHandler);

        let socket_for_server = socket.clone();
        tokio::spawn(async move {
            let _ = serve_unix(socket_for_server, handler).await;
        });

        // Give the server a moment to bind before connecting.
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mut client = UnixClient::connect(&socket).await.expect("connect");
        let resp = client.call(Request::GetStatus).await.expect("call");
        assert!(matches!(resp, Response::Ack));
    }
}
