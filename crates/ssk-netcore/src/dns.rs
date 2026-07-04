#![forbid(unsafe_code)]

//! Real DNS resolution (RFC 1035 message format) against a caller-specified
//! resolver — the real counterpart to `ssk-netadmin::DnsOverrideAdapter`,
//! which today only stores a resolver host/port as inert data. Sends a real
//! UDP query, falls back to TCP on a truncated (`TC`) response, and decodes
//! the real reply including name-compression pointers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::error::NetcoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    Aaaa,
}

impl RecordType {
    fn qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(1);

fn next_query_id() -> u16 {
    NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed)
}

/// Resolves `query_name` against `resolver_host:resolver_port` for real,
/// over UDP with a TCP retry on truncation. Returns every address of the
/// requested `record` type the resolver returned.
pub(crate) async fn resolve(
    resolver_host: &str,
    resolver_port: u16,
    query_name: &str,
    record: RecordType,
    query_timeout: Duration,
) -> Result<Vec<IpAddr>, NetcoreError> {
    let resolver_label = format!("{resolver_host}:{resolver_port}");
    let id = next_query_id();
    let query = encode_query(id, query_name, record)?;

    let bind_addr = if resolver_host.parse::<Ipv6Addr>().is_ok() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;
    socket
        .connect(&resolver_label)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;
    socket
        .send(&query)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;

    let mut buf = [0u8; 4096];
    let n = match timeout(query_timeout, socket.recv(&mut buf)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => return Err(NetcoreError::Io(resolver_label, e)),
        Err(_) => {
            return Err(NetcoreError::Timeout(resolver_label, query_timeout));
        }
    };

    let response = &buf[..n];
    if is_truncated(response, &resolver_label)? {
        return resolve_tcp(resolver_host, resolver_port, &query, id, query_timeout).await;
    }
    decode_response(response, id, &resolver_label)
}

async fn resolve_tcp(
    resolver_host: &str,
    resolver_port: u16,
    udp_query: &[u8],
    id: u16,
    query_timeout: Duration,
) -> Result<Vec<IpAddr>, NetcoreError> {
    let resolver_label = format!("{resolver_host}:{resolver_port}");
    let mut stream = timeout(
        query_timeout,
        TcpStream::connect((resolver_host, resolver_port)),
    )
    .await
    .map_err(|_| NetcoreError::Timeout(resolver_label.clone(), query_timeout))?
    .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;

    // RFC 1035 §4.2.2: TCP messages are prefixed with a two-byte length.
    let len = u16::try_from(udp_query.len()).map_err(|_| {
        NetcoreError::ProtocolError(
            resolver_label.clone(),
            "query too large for TCP framing".into(),
        )
    })?;
    let mut framed = Vec::with_capacity(2 + udp_query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(udp_query);
    stream
        .write_all(&framed)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| NetcoreError::Io(resolver_label.clone(), e))?;

    decode_response(&resp, id, &resolver_label)
}

fn is_truncated(msg: &[u8], resolver_label: &str) -> Result<bool, NetcoreError> {
    if msg.len() < 12 {
        return Err(NetcoreError::ProtocolError(
            resolver_label.to_string(),
            "DNS response shorter than a header".into(),
        ));
    }
    Ok(msg[2] & 0x02 != 0)
}

fn encode_query(id: u16, name: &str, record: RecordType) -> Result<Vec<u8>, NetcoreError> {
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD=1, standard query
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut msg, name)?;
    msg.extend_from_slice(&record.qtype().to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Ok(msg)
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), NetcoreError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return Ok(());
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(NetcoreError::ProtocolError(
                "dns-encode".into(),
                format!("invalid DNS label in `{name}`: each label must be 1-63 bytes"),
            ));
        }
        out.push(u8::try_from(label.len()).expect("checked above"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Reads a (possibly compressed, RFC 1035 §4.1.4) name starting at `offset`
/// and returns `(name, bytes_consumed_at_offset)`. `bytes_consumed_at_offset`
/// is the number of bytes the *original* read cursor should advance by,
/// which is always correct even when the name follows a compression
/// pointer elsewhere in the message.
fn read_name(msg: &[u8], offset: usize) -> Result<(String, usize), NetcoreError> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut consumed_at_start: Option<usize> = None;
    let mut jumps = 0;

    loop {
        let len_byte = *msg
            .get(cursor)
            .ok_or_else(|| protocol_err("name extends past end of message"))?;

        if len_byte & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit offset from the start of the message.
            let next = *msg
                .get(cursor + 1)
                .ok_or_else(|| protocol_err("truncated compression pointer"))?;
            let pointer = (usize::from(len_byte & 0x3F) << 8) | usize::from(next);
            if consumed_at_start.is_none() {
                consumed_at_start = Some(cursor + 2 - offset);
            }
            jumps += 1;
            if jumps > 32 {
                return Err(protocol_err("too many DNS compression pointer jumps"));
            }
            cursor = pointer;
            continue;
        }

        if len_byte == 0 {
            if consumed_at_start.is_none() {
                consumed_at_start = Some(cursor + 1 - offset);
            }
            break;
        }

        let label_len = usize::from(len_byte);
        let start = cursor + 1;
        let end = start + label_len;
        let label = msg
            .get(start..end)
            .ok_or_else(|| protocol_err("label extends past end of message"))?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor = end;
    }

    Ok((labels.join("."), consumed_at_start.unwrap_or(0)))
}

fn protocol_err(msg: &str) -> NetcoreError {
    NetcoreError::ProtocolError("dns-decode".into(), msg.to_string())
}

fn decode_response(
    msg: &[u8],
    expected_id: u16,
    resolver_label: &str,
) -> Result<Vec<IpAddr>, NetcoreError> {
    if msg.len() < 12 {
        return Err(NetcoreError::ProtocolError(
            resolver_label.to_string(),
            "DNS response shorter than a header".into(),
        ));
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    if id != expected_id {
        return Err(NetcoreError::ProtocolError(
            resolver_label.to_string(),
            format!("DNS response id {id} does not match query id {expected_id} (possible spoof/mismatch)"),
        ));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = flags & 0x8000 != 0;
    if !is_response {
        return Err(NetcoreError::ProtocolError(
            resolver_label.to_string(),
            "QR bit not set: message is not a response".into(),
        ));
    }
    let rcode = flags & 0x000F;
    if rcode != 0 {
        return Err(NetcoreError::DnsResolutionFailed(
            "query".to_string(),
            resolver_label.to_string(),
            rcode_reason(rcode),
        ));
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let ancount = u16::from_be_bytes([msg[6], msg[7]]) as usize;

    let mut offset = 12;
    for _ in 0..qdcount {
        let (_, consumed) = read_name(msg, offset)?;
        offset += consumed + 4; // + QTYPE(2) + QCLASS(2)
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        let (_, consumed) = read_name(msg, offset)?;
        offset += consumed;
        let rr_head = msg
            .get(offset..offset + 10)
            .ok_or_else(|| protocol_err("truncated resource record header"))?;
        let rtype = u16::from_be_bytes([rr_head[0], rr_head[1]]);
        let rdlength = u16::from_be_bytes([rr_head[8], rr_head[9]]) as usize;
        offset += 10;
        let rdata = msg
            .get(offset..offset + rdlength)
            .ok_or_else(|| protocol_err("resource record data extends past end of message"))?;
        match rtype {
            1 if rdata.len() == 4 => {
                addrs.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            28 if rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => { /* CNAME/other record types: skip, we only surface A/AAAA */ }
        }
        offset += rdlength;
    }

    Ok(addrs)
}

fn rcode_reason(rcode: u16) -> String {
    match rcode {
        1 => "format error",
        2 => "server failure",
        3 => "name error (NXDOMAIN)",
        4 => "not implemented",
        5 => "refused",
        _ => "unrecognized rcode",
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket as TestUdpSocket;

    /// Builds a real DNS response byte-for-byte, using a **compressed**
    /// name pointer for the answer's owner name (the common real-world
    /// case), to genuinely exercise the decompression path rather than
    /// only the trivial uncompressed one.
    fn build_fake_a_response(id: u16, query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&id.to_be_bytes());
        resp.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1, RCODE=0
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes());
        resp.extend_from_slice(&0u16.to_be_bytes());
        // Echo the question section verbatim (name + qtype + qclass).
        resp.extend_from_slice(&query[12..]);
        // Answer: pointer to offset 12 (the question's name).
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
        resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
        resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&ip.octets());
        resp
    }

    async fn spawn_fake_dns_server(ip: Ipv4Addr) -> std::net::SocketAddr {
        let socket = TestUdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, peer) = socket.recv_from(&mut buf).await.expect("recv");
            let id = u16::from_be_bytes([buf[0], buf[1]]);
            let response = build_fake_a_response(id, &buf[..n], ip);
            socket.send_to(&response, peer).await.expect("send");
        });
        addr
    }

    #[tokio::test]
    async fn resolves_a_record_via_real_udp_wire_protocol_with_name_compression() {
        let ip = Ipv4Addr::new(203, 0, 113, 42);
        let addr = spawn_fake_dns_server(ip).await;
        let result = resolve(
            "127.0.0.1",
            addr.port(),
            "example.internal",
            RecordType::A,
            Duration::from_secs(5),
        )
        .await
        .expect("resolution must succeed against a compliant fake resolver");
        assert_eq!(result, vec![IpAddr::V4(ip)]);
    }

    #[test]
    fn encode_query_rejects_overlong_labels() {
        let overlong = "a".repeat(64);
        let err = encode_query(1, &overlong, RecordType::A).expect_err("must reject");
        assert!(matches!(err, NetcoreError::ProtocolError(..)));
    }

    #[test]
    fn decode_response_rejects_mismatched_query_id() {
        let query = encode_query(42, "example.internal", RecordType::A).expect("encode");
        let resp = build_fake_a_response(999, &query, Ipv4Addr::new(1, 2, 3, 4));
        let err = decode_response(&resp, 42, "resolver").expect_err("id mismatch must be rejected");
        assert!(matches!(err, NetcoreError::ProtocolError(..)));
    }

    #[test]
    fn decode_response_surfaces_nxdomain_as_a_typed_error() {
        let mut resp = Vec::new();
        resp.extend_from_slice(&7u16.to_be_bytes());
        resp.extend_from_slice(&0x8183u16.to_be_bytes()); // QR=1, RCODE=3 (NXDOMAIN)
        resp.extend_from_slice(&[0u8; 8]);
        let err = decode_response(&resp, 7, "resolver")
            .expect_err("NXDOMAIN must surface, not silently return no addresses");
        assert!(matches!(err, NetcoreError::DnsResolutionFailed(..)));
    }
}
