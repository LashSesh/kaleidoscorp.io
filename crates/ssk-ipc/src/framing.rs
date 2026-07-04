#![forbid(unsafe_code)]

//! Length-prefixed canonical CBOR framing: `[u32 big-endian length][ciborium
//! body]`. Reuses `ciborium` (already a workspace dependency, the same
//! encoder `ssk-interop`/`ssk-types` use for canonical encoding) instead of
//! adding a new serialization crate.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::IpcError;

/// Hard cap on a single frame's body size, to bound memory use against a
/// malformed or hostile peer before authentication has even completed.
const MAX_FRAME_LEN: u32 = 16 * 1024 * 1024;

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

/// Read one length-prefixed frame written by [`write_frame`].
pub async fn read_frame<T, R>(stream: &mut R) -> Result<T, IpcError>
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
    if len > MAX_FRAME_LEN {
        return Err(IpcError::new(
            "Runtime",
            "IPC_FRAME_TOO_LARGE",
            format!("frame length {len} exceeds max {MAX_FRAME_LEN}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| IpcError::new("Runtime", "IPC_IO_FAILED", e.to_string()).retriable())?;
    ciborium::de::from_reader(&body[..])
        .map_err(|e| IpcError::new("Runtime", "IPC_DECODE_FAILED", e.to_string()))
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
        let decoded: Ping = read_frame(&mut server).await.expect("read");
        assert_eq!(decoded, value);
    }

    #[tokio::test]
    async fn read_rejects_oversized_frame_length() {
        let (mut client, mut server) = tokio::io::duplex(64);
        client
            .write_all(&(MAX_FRAME_LEN + 1).to_be_bytes())
            .await
            .expect("write length prefix");
        let result: Result<Ping, IpcError> = read_frame(&mut server).await;
        assert!(result.is_err());
    }
}
