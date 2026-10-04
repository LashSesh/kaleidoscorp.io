//! Reserved reverse-management endpoint and kernel TCP peer ownership check.
//! Deliberately IPv4 loopback even for IPv6 VPN profiles. No bytes are read or
//! written until the accepted socket is matched to the still-owned child.
use crate::{
    connections::{parse_tcp_table, FlowRow},
    vpn_process::JobChild,
};
use ssk_vpnctl::ChildProcess;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    os::windows::io::AsRawSocket,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_CONNECTIONS},
    Networking::WinSock::{
        setsockopt, WSAGetLastError, AF_INET, SOCKET_ERROR, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
    },
};

pub(crate) fn reserve() -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    let enabled = 1i32;
    // SAFETY: live socket, initialized i32 option value, exact byte size. Set
    // exclusivity BEFORE bind; a second listener cannot share/squat this port.
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    socket.listen(4)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

pub(crate) fn verify(stream: &TcpStream, child: &mut JobChild) -> io::Result<bool> {
    if child.try_wait()?.is_some() {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    let rows = query()?;
    let matched = owned_peer(&rows, local, peer, child.id());
    // Retaining the process HANDLE prevents PID-based control confusion. Check
    // liveness again after the OS table observation, before exposing any secret.
    if child.try_wait()?.is_some() {
        return Err(io::ErrorKind::BrokenPipe.into());
    }
    Ok(matched)
}

fn owned_peer(rows: &[FlowRow], local: SocketAddr, peer: SocketAddr, pid: u32) -> bool {
    let (SocketAddr::V4(local), SocketAddr::V4(peer)) = (local, peer) else {
        return false;
    };
    if *local.ip() != Ipv4Addr::LOCALHOST || *peer.ip() != Ipv4Addr::LOCALHOST || pid == 0 {
        return false;
    }
    let matching: Vec<_> = rows
        .iter()
        .filter(|r| {
            r.protocol == "tcp"
                && r.local_addr == *peer.ip()
                && r.local_port == peer.port()
                && r.remote_addr == *local.ip()
                && r.remote_port == local.port()
        })
        .collect();
    matching.len() == 1 && matching[0].state == 5 && matching[0].pid == pid
}

fn query() -> io::Result<Vec<FlowRow>> {
    const MAX: u32 = 4 * 1024 * 1024;
    let mut size = 0;
    // SAFETY: documented sizing call, writable size; IPv4 OWNER_PID ABI.
    let result = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            0,
        )
    };
    if result != NO_ERROR && result != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    for _ in 0..3 {
        if !(4..=MAX).contains(&size) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // DWORD-aligned storage, not an unaligned Vec<u8> cast to a table.
        let mut storage = vec![0u32; (size as usize).div_ceil(4)];
        let available = storage.len() * 4;
        // SAFETY: initialized, correctly aligned buffer of at least size bytes.
        let result = unsafe {
            GetExtendedTcpTable(
                storage.as_mut_ptr().cast(),
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_CONNECTIONS,
                0,
            )
        };
        if result == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if result != NO_ERROR {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        if size < 4 || size as usize > available {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: every byte is initialized; the returned length was checked.
        let bytes =
            unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), size as usize) };
        let count = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| io::ErrorKind::InvalidData)?,
        ) as usize;
        if count > (bytes.len() - 4) / 24 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        return Ok(parse_tcp_table(bytes));
    }
    Err(io::ErrorKind::TimedOut.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_reverse_tuple_pid_and_established_state_are_required() {
        let local = "127.0.0.1:10000".parse().unwrap();
        let peer = "127.0.0.1:10001".parse().unwrap();
        let row = FlowRow {
            protocol: "tcp",
            local_addr: Ipv4Addr::LOCALHOST,
            local_port: 10001,
            remote_addr: Ipv4Addr::LOCALHOST,
            remote_port: 10000,
            state: 5,
            pid: 42,
        };
        assert!(owned_peer(std::slice::from_ref(&row), local, peer, 42));
        assert!(!owned_peer(std::slice::from_ref(&row), local, peer, 43));
        assert!(!owned_peer(std::slice::from_ref(&row), peer, local, 42));
        assert!(!owned_peer(&[row.clone(), row.clone()], local, peer, 42));
        let mut bad = row;
        bad.state = 2;
        assert!(!owned_peer(&[bad], local, peer, 42));
    }
    #[test]
    fn reserved_listener_cannot_be_rebound_and_current_process_is_observed() {
        let listener = reserve().unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(TcpListener::bind(addr).is_err());
        let _peer = TcpStream::connect(addr).unwrap();
        let (stream, _) = listener.accept().unwrap();
        assert!(owned_peer(
            &query().unwrap(),
            stream.local_addr().unwrap(),
            stream.peer_addr().unwrap(),
            std::process::id()
        ));
        assert!(!owned_peer(
            &query().unwrap(),
            stream.local_addr().unwrap(),
            stream.peer_addr().unwrap(),
            u32::MAX
        ));
    }
}
