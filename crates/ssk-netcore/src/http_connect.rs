#![forbid(unsafe_code)]

//! Real HTTP CONNECT tunnel handshake (RFC 9110 §9.3.6) run over an
//! already-connected real transport.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::NetcoreError;

/// Response headers larger than this are treated as a protocol violation
/// (or a proxy trying to exhaust memory) rather than read indefinitely.
const MAX_HEADER_BYTES: usize = 8192;

/// Sends a real `CONNECT host:port HTTP/1.1` request and reads the real
/// status line + headers, failing closed unless the proxy answered with a
/// 2xx status. Returns the same stream positioned at the start of the
/// tunneled byte stream.
pub(crate) async fn handshake_connect<S>(
    mut stream: S,
    target_host: &str,
    target_port: u16,
    auth_header: Option<&str>,
    proxy_label: &str,
) -> Result<S, NetcoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io_err = |e: std::io::Error| NetcoreError::Io(proxy_label.to_string(), e);

    let mut request = format!(
        "CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n"
    );
    if let Some(header_value) = auth_header {
        request.push_str("Proxy-Authorization: ");
        request.push_str(header_value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.map_err(io_err)?;
    stream.flush().await.map_err(io_err)?;

    let head = read_headers(&mut stream, proxy_label).await?;
    let status_line = head.lines().next().ok_or_else(|| {
        NetcoreError::ProtocolError(proxy_label.to_string(), "empty proxy response".into())
    })?;
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| {
            NetcoreError::ProtocolError(
                proxy_label.to_string(),
                format!("malformed HTTP status line: {status_line:?}"),
            )
        })?;

    if !(200..300).contains(&status_code) {
        return Err(NetcoreError::ProxyRejected(
            proxy_label.to_string(),
            format!("proxy responded {status_code} to CONNECT: {status_line}"),
        ));
    }

    Ok(stream)
}

/// Reads bytes one at a time until the `\r\n\r\n` header terminator, bounded
/// by [`MAX_HEADER_BYTES`]. HTTP CONNECT responses are small and this runs
/// once per session establishment, so the per-byte read cost is negligible
/// against a real handshake's round-trip latency.
async fn read_headers<S>(stream: &mut S, proxy_label: &str) -> Result<String, NetcoreError>
where
    S: AsyncRead + Unpin,
{
    let io_err = |e: std::io::Error| NetcoreError::Io(proxy_label.to_string(), e);
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.map_err(io_err)?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(NetcoreError::ProtocolError(
                proxy_label.to_string(),
                format!("proxy response headers exceeded {MAX_HEADER_BYTES} bytes"),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    async fn spawn_fake_http_proxy(status_line: &'static str) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                sock.read_exact(&mut byte).await.expect("read request");
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let response = format!("{status_line}\r\n\r\n");
            sock.write_all(response.as_bytes())
                .await
                .expect("write response");
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        addr
    }

    #[tokio::test]
    async fn successful_connect_through_real_http_connect_wire_protocol() {
        let addr = spawn_fake_http_proxy("HTTP/1.1 200 Connection Established").await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let tunneled = handshake_connect(stream, "example.internal", 443, None, "test-proxy")
            .await
            .expect("2xx response must be accepted");
        drop(tunneled);
    }

    #[tokio::test]
    async fn non_2xx_is_a_typed_rejection_not_a_silent_success() {
        let addr = spawn_fake_http_proxy("HTTP/1.1 407 Proxy Authentication Required").await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = handshake_connect(stream, "example.internal", 443, None, "test-proxy")
            .await
            .expect_err("407 must surface as an error, never as an opened tunnel");
        assert!(matches!(err, NetcoreError::ProxyRejected(..)));
    }
}
