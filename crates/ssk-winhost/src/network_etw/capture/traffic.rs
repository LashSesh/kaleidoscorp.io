//! Fixed loopback-only application workload. No ETW, DNS or external destination.
//! Counters describe this workload's application operations, not ETW/wire bytes.
use serde::Serialize;
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

pub const MESSAGES_PER_CASE: u32 = 8;
pub const MESSAGE_BYTES: usize = 128;
const IO_TIMEOUT: Duration = Duration::from_millis(250);
const BUDGET: Duration = Duration::from_secs(3);

#[derive(Debug, Serialize)]
pub struct CaseReport {
    case: &'static str,
    status: &'static str,
    round_trips_completed: u32,
    verified_received_application_bytes: u32,
    error_kind: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrafficReport {
    schema_version: u32,
    source: &'static str,
    status: &'static str,
    process_id: u32,
    messages_per_case: u32,
    message_bytes: usize,
    cases: Vec<CaseReport>,
    etw_coverage_verified: bool,
    enforcement_active: bool,
}

fn check_time(started: Instant) -> io::Result<()> {
    if started.elapsed() >= BUDGET {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

fn message(ordinal: u32) -> [u8; MESSAGE_BYTES] {
    let mut data = [0x53u8; MESSAGE_BYTES];
    data[..4].copy_from_slice(&ordinal.to_le_bytes());
    data
}

fn equal(actual: &[u8], expected: &[u8]) -> io::Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}

fn tcp(ip: IpAddr, started: Instant, completed: &mut u32) -> io::Result<()> {
    let listener = TcpListener::bind(SocketAddr::new(ip, 0))?;
    listener.set_nonblocking(true)?;
    let mut client = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
    let (mut server, peer) = loop {
        check_time(started)?;
        match listener.accept() {
            Ok(pair) => break pair,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    };
    if peer != client.local_addr()? {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Accepted sockets may inherit the listener's nonblocking mode on some OSes.
    server.set_nonblocking(false)?;
    for socket in [&client, &server] {
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
        socket.set_nodelay(true)?;
    }
    for ordinal in 0..MESSAGES_PER_CASE {
        check_time(started)?;
        let payload = message(ordinal);
        let mut data = [0; MESSAGE_BYTES];
        client.write_all(&payload)?;
        server.read_exact(&mut data)?;
        equal(&data, &payload)?;
        server.write_all(&data)?;
        client.read_exact(&mut data)?;
        equal(&data, &payload)?;
        *completed += 1;
    }
    check_time(started)
}

fn udp(ip: IpAddr, started: Instant, completed: &mut u32) -> io::Result<()> {
    let server = UdpSocket::bind(SocketAddr::new(ip, 0))?;
    let client = UdpSocket::bind(SocketAddr::new(ip, 0))?;
    server.connect(client.local_addr()?)?;
    client.connect(server.local_addr()?)?;
    for socket in [&client, &server] {
        socket.set_read_timeout(Some(IO_TIMEOUT))?;
        socket.set_write_timeout(Some(IO_TIMEOUT))?;
    }
    for ordinal in 0..MESSAGES_PER_CASE {
        check_time(started)?;
        let payload = message(ordinal);
        // The extra byte detects an oversized datagram instead of truncating
        // it into an apparently valid 128-byte reply.
        let mut data = [0; MESSAGE_BYTES + 1];
        if client.send(&payload)? != MESSAGE_BYTES {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let count = server.recv(&mut data)?;
        equal(&data[..count], &payload)?;
        if server.send(&data[..count])? != MESSAGE_BYTES {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let count = client.recv(&mut data)?;
        equal(&data[..count], &payload)?;
        *completed += 1;
    }
    check_time(started)
}

/// Four fixed cases, eight request/reply exchanges each, on ephemeral loopback
/// ports. Missing IPv6 or any error remains an unavailable case, never a skip.
pub fn run() -> TrafficReport {
    let started = Instant::now();
    let mut cases = Vec::with_capacity(4);
    for (case, ip, is_tcp) in [
        ("tcp_ipv4", IpAddr::V4(Ipv4Addr::LOCALHOST), true),
        ("udp_ipv4", IpAddr::V4(Ipv4Addr::LOCALHOST), false),
        ("tcp_ipv6", IpAddr::V6(Ipv6Addr::LOCALHOST), true),
        ("udp_ipv6", IpAddr::V6(Ipv6Addr::LOCALHOST), false),
    ] {
        let mut completed = 0;
        let result = check_time(started).and_then(|()| {
            if is_tcp {
                tcp(ip, started, &mut completed)
            } else {
                udp(ip, started, &mut completed)
            }
        });
        cases.push(CaseReport {
            case,
            status: if result.is_ok() {
                "completed"
            } else {
                "unavailable"
            },
            round_trips_completed: completed,
            verified_received_application_bytes: completed * 2 * MESSAGE_BYTES as u32,
            error_kind: result.err().map(|e| format!("{:?}", e.kind())),
        });
    }
    TrafficReport {
        schema_version: 1,
        source: "local_loopback_workload",
        status: if cases.iter().all(|c| c.status == "completed") {
            "completed"
        } else {
            "unavailable"
        },
        process_id: std::process::id(),
        messages_per_case: MESSAGES_PER_CASE,
        message_bytes: MESSAGE_BYTES,
        cases,
        etw_coverage_verified: false,
        enforcement_active: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_is_ordinal_bound_and_length_is_not_truncated() {
        assert!(equal(&message(0), &message(1)).is_err());
        assert!(equal(&message(0)[..127], &message(0)).is_err());
        assert!(equal(&message(7), &message(7)).is_ok());
    }
    #[test]
    fn expired_workload_budget_is_a_failure() {
        assert_eq!(
            check_time(Instant::now() - BUDGET).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}
