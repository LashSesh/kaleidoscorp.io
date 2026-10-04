use super::*;
use std::{
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, ERROR_INSUFFICIENT_BUFFER, FILETIME, NO_ERROR, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::Threading::{
        GetProcessTimes, OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE,
    },
};

struct ProcessSource {
    process: OwnedHandle,
    pid: u32,
    started: Instant,
}

impl SnapshotSource for ProcessSource {
    fn creation_time(&mut self) -> Result<u64, SnapshotError> {
        let mut times = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 4];
        // SAFETY: owned query-only process handle; disjoint initialized outputs.
        if unsafe {
            GetProcessTimes(
                self.process.as_raw_handle(),
                &mut times[0],
                &mut times[1],
                &mut times[2],
                &mut times[3],
            )
        } == 0
        {
            return Err(SnapshotError::ProcessQuery {
                code: unsafe { GetLastError() },
            });
        }
        Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
    }

    fn require_alive(&mut self) -> Result<(), SnapshotError> {
        // SAFETY: owned handle with SYNCHRONIZE; zero timeout does not block.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(SnapshotError::ProcessExited),
            _ => Err(SnapshotError::ProcessQuery {
                code: unsafe { GetLastError() },
            }),
        }
    }

    fn read_table(&mut self, kind: TableKind) -> Result<Vec<EndpointRow>, SnapshotError> {
        let af = match kind {
            TableKind::TcpV4 | TableKind::UdpV4 => AF_INET,
            _ => AF_INET6,
        };
        let bytes = bounded_query(
            |words, size| {
                let buffer = if words.is_empty() {
                    std::ptr::null_mut()
                } else {
                    words.as_mut_ptr().cast()
                };
                // SAFETY: 4-byte aligned initialized buffer with *size bytes of
                // writable storage, or null on the initial sizing call; fixed table
                // classes, valid family and reserved=0. Synchronous, no retention.
                let code = unsafe {
                    match kind {
                        TableKind::TcpV4 | TableKind::TcpV6 => GetExtendedTcpTable(
                            buffer,
                            size,
                            0,
                            u32::from(af),
                            TCP_TABLE_OWNER_PID_ALL,
                            0,
                        ),
                        TableKind::UdpV4 | TableKind::UdpV6 => GetExtendedUdpTable(
                            buffer,
                            size,
                            0,
                            u32::from(af),
                            UDP_TABLE_OWNER_PID,
                            0,
                        ),
                    }
                };
                match code {
                    NO_ERROR => QueryReply::Success,
                    ERROR_INSUFFICIENT_BUFFER => QueryReply::Resize,
                    code => QueryReply::Failure(code),
                }
            },
            || self.elapsed_micros() >= MAX_CAPTURE_MICROS,
        )?;
        parse_table(kind, &bytes, self.pid)
    }

    fn elapsed_micros(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

pub(super) fn capture(pid: u32) -> Result<ProcessNetworkSnapshot, SnapshotError> {
    let started = Instant::now();
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|_| SnapshotError::EntropyUnavailable)?;
    let capture_id: String = random.iter().map(|b| format!("{b:02x}")).collect();
    // SAFETY: read-only rights, no inheritance and nonzero PID. No privilege
    // adjustment or fallback to a different process if this query fails.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return Err(SnapshotError::ProcessOpen {
            code: unsafe { GetLastError() },
        });
    }
    // SAFETY: successful OpenProcess transfers unique ownership; RAII closes
    // on every success/error path. No terminate/write/duplication rights.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut source = ProcessSource {
        process,
        pid,
        started,
    };
    capture_from(&mut source, pid, capture_id)
}
