#![forbid(unsafe_code)]

//! Length-prefixed canonical CBOR framing: `[u32 big-endian length][ciborium
//! body]`. Reuses `ciborium` (already a workspace dependency, the same
//! encoder `ssk-interop`/`ssk-types` use for canonical encoding) instead of
//! adding a new serialization crate.
//!
//! # Frame caps are a parameter, not a constant
//!
//! [`read_frame`] takes `max_len` explicitly so no call site can silently
//! inherit a cap that was chosen for the other direction. The two caps a
//! caller should reach for are [`MAX_REQUEST_FRAME_LEN`] (client → server) and
//! [`MAX_RESPONSE_FRAME_LEN`] (server → client); they are deliberately
//! asymmetric, because a request is a small enum variant while a response can
//! be a list.
//!
//! The previous single 16 MiB constant was *enforced* (the roadmap's claim of
//! an "unbounded pre-auth allocation" was imprecise), but 16 MiB is absurd for
//! a control protocol, and the body was allocated in one `vec![0u8; len]` up
//! front — so a peer that declared a large length and then stalled cost the
//! server the full declared size. The body is now read incrementally in
//! [`READ_CHUNK_LEN`] pieces, so a lying prefix costs what was actually sent.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::IpcError;

/// Cap on a client → server request frame: 64 KiB.
///
/// Follows the precedent already set by `ssk_netd_helper::protocol`'s
/// `MAX_PRIV_FRAME`, whose own doc calls the old 16 MiB IPC cap "generic".
/// Every `Request` variant is a small enum; the largest realistic one carries
/// two short strings.
pub const MAX_REQUEST_FRAME_LEN: u32 = 64 * 1024;

/// Cap on a server → client response frame: 1 MiB. Larger than the request cap
/// because responses genuinely can be lists (`ListRecentFlows`,
/// `GetAuditEntries`), bounded in turn by [`crate::server::MAX_LIST_LIMIT`].
pub const MAX_RESPONSE_FRAME_LEN: u32 = 1024 * 1024;

/// Granularity of the incremental body read. A peer that declares a large
/// length and then stalls makes the server hold at most this much more than it
/// has actually delivered.
pub const READ_CHUNK_LEN: usize = 64 * 1024;

/// Encode `value` and write it as one length-prefixed frame.
pub async fn write_frame<T, W>(stream: &mut W, value: &T) -> Result<(), IpcError>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let mut body = Vec::new();
    ciborium::ser::into_writer(value, &mut body)
        .map_err(|e| IpcError::new("Runtime", "IPC_ENCODE_FAILED", e.to_string()))?;
    let len = u32::try_from(body.len())
        .map_err(|_| IpcError::new("Runtime", "IPC_FRAME_TOO_LARGE", "frame exceeds u32 length"))?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| IpcError::new("Runtime", "IPC_IO_FAILED", e.to_string()).retriable())?;
    stream
        .write_all(&body)
        .await
        .map_err(|e| IpcError::new("Runtime", "IPC_IO_FAILED", e.to_string()).retriable())?;
    Ok(())
}

/// Read one length-prefixed frame written by [`write_frame`], refusing any
/// declared body longer than `max_len` before a single body byte is read or
/// allocated.
pub async fn read_frame<T, R>(stream: &mut R, max_len: u32) -> Result<T, IpcError>
where
    T: DeserializeOwned,
    R: AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    stream
        .read_exact(&mut len_bytes)
        .await
        .map_err(|e| IpcError::new("Runtime", "IPC_IO_FAILED", e.to_string()).retriable())?;
    let len = u32::from_be_bytes(len_bytes);
    if len > max_len {
        return Err(IpcError::new(
            "Runtime",
            "IPC_FRAME_TOO_LARGE",
            format!("frame length {len} exceeds max {max_len}"),
        ));
    }
    let body = read_body(stream, len as usize).await?;
    ciborium::de::from_reader(&body[..])
        .map_err(|e| IpcError::new("Runtime", "IPC_DECODE_FAILED", e.to_string()))
}

/// Read exactly `len` bytes, growing the buffer as bytes actually arrive
/// rather than reserving `len` up front. The scratch chunk is capped at
/// [`READ_CHUNK_LEN`], so the peak cost of a peer that declares `len` and then
/// stalls is `bytes_actually_sent + READ_CHUNK_LEN`, not `len`.
async fn read_body<R>(stream: &mut R, len: usize) -> Result<Vec<u8>, IpcError>
where
    R: AsyncRead + Unpin,
{
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut body: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK_LEN.min(len)];
    while body.len() < len {
        let want = (len - body.len()).min(chunk.len());
        let read = stream
            .read(&mut chunk[..want])
            .await
            .map_err(|e| IpcError::new("Runtime", "IPC_IO_FAILED", e.to_string()).retriable())?;
        if read == 0 {
            return Err(IpcError::new(
                "Runtime",
                "IPC_IO_FAILED",
                format!(
                    "peer closed after {} of {len} declared body bytes",
                    body.len()
                ),
            ));
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Ping {
        seq: u32,
        message: String,
    }

    #[tokio::test]
    async fn write_then_read_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let value = Ping {
            seq: 7,
            message: "hello".into(),
        };
        write_frame(&mut client, &value).await.expect("write");
        let decoded: Ping = read_frame(&mut server, MAX_REQUEST_FRAME_LEN)
            .await
            .expect("read");
        assert_eq!(decoded, value);
    }

    #[tokio::test]
    async fn read_rejects_oversized_frame_length() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&(MAX_REQUEST_FRAME_LEN + 1).to_be_bytes())
            .await
            .expect("write length prefix");
        let result: Result<Ping, IpcError> = read_frame(&mut server, MAX_REQUEST_FRAME_LEN).await;
        let err = result.expect_err("oversized length must be refused");
        assert_eq!(err.code, "IPC_FRAME_TOO_LARGE");
    }

    /// The cap is a parameter, so the *same* frame is accepted under the
    /// response cap and refused under the request cap. This is what makes the
    /// asymmetry real rather than decorative.
    #[tokio::test]
    async fn request_cap_is_tighter_than_response_cap() {
        const { assert!(MAX_REQUEST_FRAME_LEN < MAX_RESPONSE_FRAME_LEN) };
        let len = MAX_REQUEST_FRAME_LEN + 1;

        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&len.to_be_bytes())
            .await
            .expect("write length prefix");
        let refused: Result<Ping, IpcError> = read_frame(&mut server, MAX_REQUEST_FRAME_LEN).await;
        assert_eq!(
            refused.expect_err("over request cap").code,
            "IPC_FRAME_TOO_LARGE"
        );

        // Under the response cap the length passes the check and the read
        // proceeds to the body, where the truncated stream is what fails.
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&len.to_be_bytes())
            .await
            .expect("write length prefix");
        drop(client);
        let accepted: Result<Ping, IpcError> =
            read_frame(&mut server, MAX_RESPONSE_FRAME_LEN).await;
        assert_eq!(accepted.expect_err("truncated body").code, "IPC_IO_FAILED");
    }

    /// A peer that declares a body and then closes must not leave `read_frame`
    /// blocked or hand back a short buffer as if it were complete.
    #[tokio::test]
    async fn lying_length_prefix_fails_on_short_body() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client
            .write_all(&1_000_000u32.to_be_bytes())
            .await
            .expect("write length prefix");
        client.write_all(&[0u8; 4]).await.expect("write short body");
        drop(client);
        let result: Result<Ping, IpcError> = read_frame(&mut server, MAX_RESPONSE_FRAME_LEN).await;
        let err = result.expect_err("short body must fail");
        assert_eq!(err.code, "IPC_IO_FAILED");
        assert!(
            err.message.contains("4 of 1000000"),
            "error should report how much actually arrived, got: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn zero_length_body_decodes_as_cbor_error_not_hang() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&0u32.to_be_bytes())
            .await
            .expect("write length prefix");
        let result: Result<Ping, IpcError> = read_frame(&mut server, MAX_REQUEST_FRAME_LEN).await;
        assert_eq!(result.expect_err("empty body").code, "IPC_DECODE_FAILED");
    }
}
