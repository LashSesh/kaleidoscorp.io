#![forbid(unsafe_code)]

//! Real SOCKS5 client handshake (RFC 1928 negotiation/request, RFC 1929
//! username/password auth) run over an already-connected real transport.
//! This performs the genuine wire protocol against a real proxy — it does
//! not simulate acceptance.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::NetcoreError;

const SOCKS5_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const RSV: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERPASS: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// Runs the real SOCKS5 CONNECT handshake over `stream` (already connected
/// to the proxy) asking it to relay to `target_host:target_port`. Returns
/// the same stream, positioned exactly at the start of the tunneled byte
/// stream, on success.
pub(crate) async fn handshake_connect<S>(
    mut stream: S,
    target_host: &str,
    target_port: u16,
    auth: Option<(&str, &str)>,
    proxy_label: &str,
) -> Result<S, NetcoreError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let io_err = |e: std::io::Error| NetcoreError::Io(proxy_label.to_string(), e);

    let methods: &[u8] = if auth.is_some() {
        &[METHOD_NO_AUTH, METHOD_USERPASS]
    } else {
        &[METHOD_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(SOCKS5_VERSION);
    greeting.push(u8::try_from(methods.len()).expect("method list is a small fixed constant"));
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await.map_err(io_err)?;
    stream.flush().await.map_err(io_err)?;

    let mut method_resp = [0u8; 2];
    stream.read_exact(&mut method_resp).await.map_err(io_err)?;
    if method_resp[0] != SOCKS5_VERSION {
        return Err(NetcoreError::ProtocolError(
            proxy_label.to_string(),
            format!(
                "unexpected SOCKS version {} in method reply",
                method_resp[0]
            ),
        ));
    }
    match method_resp[1] {
        METHOD_NO_AUTH => {}
        METHOD_USERPASS => {
            let (user, pass) = auth.ok_or_else(|| {
                NetcoreError::ProxyRejected(
                    proxy_label.to_string(),
                    "proxy selected username/password auth but none was configured".into(),
                )
            })?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(NetcoreError::ProtocolError(
                    proxy_label.to_string(),
                    "username/password must each be <= 255 bytes for RFC 1929 auth".into(),
                ));
            }
            let mut auth_req = Vec::with_capacity(3 + user.len() + pass.len());
            auth_req.push(0x01); // sub-negotiation version
            auth_req.push(u8::try_from(user.len()).expect("checked above"));
            auth_req.extend_from_slice(user.as_bytes());
            auth_req.push(u8::try_from(pass.len()).expect("checked above"));
            auth_req.extend_from_slice(pass.as_bytes());
            stream.write_all(&auth_req).await.map_err(io_err)?;
            stream.flush().await.map_err(io_err)?;

            let mut auth_resp = [0u8; 2];
            stream.read_exact(&mut auth_resp).await.map_err(io_err)?;
            if auth_resp[1] != 0x00 {
                return Err(NetcoreError::ProxyRejected(
                    proxy_label.to_string(),
                    "SOCKS5 username/password authentication failed".into(),
                ));
            }
        }
        METHOD_NO_ACCEPTABLE => {
            return Err(NetcoreError::ProxyRejected(
                proxy_label.to_string(),
                "proxy rejected every offered authentication method".into(),
            ))
        }
        other => {
            return Err(NetcoreError::ProtocolError(
                proxy_label.to_string(),
                format!("proxy selected unsupported auth method 0x{other:02x}"),
            ))
        }
    }

    let mut req = vec![SOCKS5_VERSION, CMD_CONNECT, RSV];
    encode_address(&mut req, target_host, proxy_label)?;
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req).await.map_err(io_err)?;
    stream.flush().await.map_err(io_err)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.map_err(io_err)?;
    if head[0] != SOCKS5_VERSION {
        return Err(NetcoreError::ProtocolError(
            proxy_label.to_string(),
            "malformed SOCKS5 reply version".into(),
        ));
    }
    if head[1] != 0x00 {
        return Err(NetcoreError::ProxyRejected(
            proxy_label.to_string(),
            reply_code_reason(head[1]),
        ));
    }
    // Consume the bound-address field so the stream is left exactly at the
    // start of the tunneled bytes, regardless of which ATYP the proxy used.
    match head[3] {
        ATYP_IPV4 => {
            let mut rest = [0u8; 4 + 2];
            stream.read_exact(&mut rest).await.map_err(io_err)?;
        }
        ATYP_IPV6 => {
            let mut rest = [0u8; 16 + 2];
            stream.read_exact(&mut rest).await.map_err(io_err)?;
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(io_err)?;
            let mut rest = vec![0u8; usize::from(len[0]) + 2];
            stream.read_exact(&mut rest).await.map_err(io_err)?;
        }
        other => {
            return Err(NetcoreError::ProtocolError(
                proxy_label.to_string(),
                format!("unknown address type 0x{other:02x} in SOCKS5 reply"),
            ))
        }
    }

    Ok(stream)
}

fn encode_address(out: &mut Vec<u8>, host: &str, proxy_label: &str) -> Result<(), NetcoreError> {
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        out.push(ATYP_IPV4);
        out.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        out.push(ATYP_IPV6);
        out.extend_from_slice(&ip.octets());
    } else {
        if host.len() > 255 {
            return Err(NetcoreError::ProtocolError(
                proxy_label.to_string(),
                "target hostname exceeds the 255-byte SOCKS5 domain-name limit".into(),
            ));
        }
        out.push(ATYP_DOMAIN);
        out.push(u8::try_from(host.len()).expect("checked above"));
        out.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

fn reply_code_reason(code: u8) -> String {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused by the ultimate destination",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unrecognized SOCKS5 reply code",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};

    /// A minimal, real SOCKS5 server speaking the actual wire protocol
    /// (not a mock of our client's expectations): it reads the real
    /// greeting/request bytes our client sends and replies exactly as
    /// RFC 1928 specifies, so this test exercises the genuine parser.
    async fn spawn_fake_socks5_server(succeed: bool, require_auth: bool) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut greeting = [0u8; 2];
            sock.read_exact(&mut greeting).await.expect("greeting");
            let nmethods = greeting[1] as usize;
            let mut methods = vec![0u8; nmethods];
            sock.read_exact(&mut methods).await.expect("methods");

            if require_auth {
                sock.write_all(&[SOCKS5_VERSION, METHOD_USERPASS])
                    .await
                    .expect("method reply");
                let mut sub_version = [0u8; 1];
                sock.read_exact(&mut sub_version)
                    .await
                    .expect("sub version");
                let mut ulen = [0u8; 1];
                sock.read_exact(&mut ulen).await.expect("ulen");
                let mut user = vec![0u8; ulen[0] as usize];
                sock.read_exact(&mut user).await.expect("user");
                let mut plen = [0u8; 1];
                sock.read_exact(&mut plen).await.expect("plen");
                let mut pass = vec![0u8; plen[0] as usize];
                sock.read_exact(&mut pass).await.expect("pass");
                sock.write_all(&[0x01, 0x00]).await.expect("auth ok");
            } else {
                sock.write_all(&[SOCKS5_VERSION, METHOD_NO_AUTH])
                    .await
                    .expect("method reply");
            }

            let mut req_head = [0u8; 4];
            sock.read_exact(&mut req_head).await.expect("req head");
            match req_head[3] {
                ATYP_DOMAIN => {
                    let mut len = [0u8; 1];
                    sock.read_exact(&mut len).await.expect("domain len");
                    let mut domain = vec![0u8; len[0] as usize];
                    sock.read_exact(&mut domain).await.expect("domain");
                    let mut port = [0u8; 2];
                    sock.read_exact(&mut port).await.expect("port");
                }
                ATYP_IPV4 => {
                    let mut rest = [0u8; 4 + 2];
                    sock.read_exact(&mut rest).await.expect("v4 addr+port");
                }
                other => panic!("unexpected ATYP {other} from client"),
            }

            if succeed {
                // BND.ADDR = 0.0.0.0:0, ATYP = IPV4
                sock.write_all(&[SOCKS5_VERSION, 0x00, RSV, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("success reply");
            } else {
                sock.write_all(&[SOCKS5_VERSION, 0x05, RSV, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("failure reply");
            }
            // Keep the socket open briefly so the client can finish reading.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        addr
    }

    #[tokio::test]
    async fn successful_connect_through_real_socks5_wire_protocol() {
        let addr = spawn_fake_socks5_server(true, false).await;
        let stream = TcpStream::connect(addr)
            .await
            .expect("connect to fake proxy");
        let tunneled = handshake_connect(stream, "example.internal", 443, None, "test-proxy")
            .await
            .expect("handshake must succeed against a compliant server");
        drop(tunneled);
    }

    #[tokio::test]
    async fn proxy_rejection_is_a_typed_error_not_a_silent_success() {
        let addr = spawn_fake_socks5_server(false, false).await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = handshake_connect(stream, "example.internal", 443, None, "test-proxy")
            .await
            .expect_err("a SOCKS5 failure reply must surface as an error");
        assert!(matches!(err, NetcoreError::ProxyRejected(..)));
    }

    #[tokio::test]
    async fn username_password_auth_round_trips_for_real() {
        let addr = spawn_fake_socks5_server(true, true).await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let tunneled = handshake_connect(
            stream,
            "example.internal",
            443,
            Some(("user", "pass")),
            "test-proxy",
        )
        .await
        .expect("auth handshake must succeed");
        drop(tunneled);
    }

    #[tokio::test]
    async fn missing_auth_when_required_is_rejected_before_any_credentials_are_sent() {
        let addr = spawn_fake_socks5_server(true, true).await;
        let stream = TcpStream::connect(addr).await.expect("connect");
        let err = handshake_connect(stream, "example.internal", 443, None, "test-proxy")
            .await
            .expect_err("client must fail closed when it has no credentials to offer");
        assert!(matches!(err, NetcoreError::ProxyRejected(..)));
    }
}
