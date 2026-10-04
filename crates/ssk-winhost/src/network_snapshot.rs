//! Read-only, bounded IP Helper diagnostics for ONE process incarnation.
//!
//! A process handle is opened before querying tables and checked for termination
//! before and after them. These are sequential endpoint snapshots, never a
//! complete connection history, byte counter, packet attribution or admission.
//! This module deliberately has no conversion to `ssk-netanalysis::Observation`.

use serde::Serialize;
use std::net::SocketAddr;
#[cfg(any(windows, test))]
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV6};

pub const MAX_TABLE_BYTES: usize = 1_048_576;
pub const MAX_TABLE_ROWS: usize = 16_384;
pub const MAX_MATCHING_ROWS: usize = 1024;
pub const MAX_QUERY_CALLS: usize = 4;
pub const MAX_CAPTURE_MICROS: u64 = 2_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    TcpV4,
    TcpV6,
    UdpV4,
    UdpV6,
}

#[cfg(any(windows, test))]
impl TableKind {
    fn row_size(self) -> usize {
        match self {
            Self::TcpV4 => 24,
            Self::TcpV6 => 56,
            Self::UdpV4 => 12,
            Self::UdpV6 => 28,
        }
    }

    fn pid_offset(self) -> usize {
        self.row_size() - 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotError {
    InvalidPid,
    UnsupportedPlatform,
    EntropyUnavailable,
    ProcessOpen { code: u32 },
    ProcessQuery { code: u32 },
    ProcessExited,
    InvalidProcessTime,
    TimeBudgetExceeded,
    TableQuery { code: u32 },
    TableTooLarge,
    TableRowLimit,
    MatchingRowLimit,
    UnstableTable,
    MalformedTable,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network snapshot unavailable: {self:?}")
    }
}
impl std::error::Error for SnapshotError {}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct EndpointRow {
    pub local: SocketAddr,
    /// Absent for UDP and TCP LISTEN: IP Helper does not supply a peer there.
    pub remote: Option<SocketAddr>,
    /// Raw MIB_TCP_STATE, NOT an HTTP status or an attempt outcome.
    pub tcp_state: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum TableOutcome {
    Observed { rows: Vec<EndpointRow> },
    Unavailable { reason: SnapshotError },
}

#[derive(Debug, Serialize)]
pub struct TableSnapshot {
    pub table: TableKind,
    pub started_after_micros: u64,
    pub ended_after_micros: u64,
    pub outcome: TableOutcome,
}

/// Historical diagnostic report, not deserializable into internal evidence.
/// No application identity, executable signature, SID or traffic history claim.
#[derive(Debug, Serialize)]
pub struct ProcessNetworkSnapshot {
    schema_version: u32,
    source: &'static str,
    capture_id: String,
    pid: u32,
    // A decimal string preserves exact FILETIME in JSON clients using f64.
    process_created_at_filetime_100ns: String,
    process_binding: &'static str,
    elapsed_micros: u64,
    all_tables_read: bool,
    connection_history_complete: bool,
    attempt_outcomes_available: bool,
    byte_counts_available: bool,
    event_loss_observable: bool,
    baseline_compatible: bool,
    enforcement_active: bool,
    tables: [TableSnapshot; 4],
}

impl ProcessNetworkSnapshot {
    pub fn tables(&self) -> &[TableSnapshot; 4] {
        &self.tables
    }

    pub fn all_tables_read(&self) -> bool {
        self.all_tables_read
    }
}

#[cfg(any(windows, test))]
fn le32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("validated row"))
}

#[cfg(any(windows, test))]
fn port(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

#[cfg(any(windows, test))]
fn v4(bytes: &[u8], addr: usize, port_offset: usize) -> SocketAddr {
    let ip = Ipv4Addr::new(
        bytes[addr],
        bytes[addr + 1],
        bytes[addr + 2],
        bytes[addr + 3],
    );
    SocketAddr::from((ip, port(bytes, port_offset)))
}

#[cfg(any(windows, test))]
fn v6(bytes: &[u8], addr: usize, scope: usize, port_offset: usize) -> SocketAddr {
    let ip: [u8; 16] = bytes[addr..addr + 16].try_into().expect("validated row");
    // Both TCP6/UDP6 OWNER_PID document dw*ScopeId in network byte order.
    let scope_id = u32::from_be_bytes(bytes[scope..scope + 4].try_into().expect("validated row"));
    SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::from(ip),
        port(bytes, port_offset),
        0,
        scope_id,
    ))
}

/// Parses the complete bounded table before publishing matching rows. A short
/// buffer or exceeded budget never becomes a successful empty/partial table.
#[cfg(any(windows, test))]
fn parse_table(kind: TableKind, bytes: &[u8], pid: u32) -> Result<Vec<EndpointRow>, SnapshotError> {
    if pid == 0 {
        return Err(SnapshotError::InvalidPid);
    }
    if bytes.len() > MAX_TABLE_BYTES {
        return Err(SnapshotError::TableTooLarge);
    }
    if bytes.len() < 4 {
        return Err(SnapshotError::MalformedTable);
    }
    let count = le32(bytes, 0) as usize;
    if count > MAX_TABLE_ROWS {
        return Err(SnapshotError::TableRowLimit);
    }
    let required = 4 + count * kind.row_size(); // bounded <= 917,508
    if bytes.len() < required {
        return Err(SnapshotError::MalformedTable);
    }
    let mut rows = Vec::new();
    for row in bytes[4..required].chunks_exact(kind.row_size()) {
        if le32(row, kind.pid_offset()) != pid {
            continue;
        }
        if rows.len() == MAX_MATCHING_ROWS {
            return Err(SnapshotError::MatchingRowLimit);
        }
        let (local, remote, state) = match kind {
            TableKind::TcpV4 => (v4(row, 4, 8), Some(v4(row, 12, 16)), Some(le32(row, 0))),
            TableKind::TcpV6 => (
                v6(row, 0, 16, 20),
                Some(v6(row, 24, 40, 44)),
                Some(le32(row, 48)),
            ),
            TableKind::UdpV4 => (v4(row, 0, 4), None, None),
            TableKind::UdpV6 => (v6(row, 0, 16, 20), None, None),
        };
        // Future/unknown TCP states are preserved as raw diagnostics. LISTEN's
        // undefined remote fields must not acquire endpoint semantics.
        rows.push(EndpointRow {
            local,
            remote: if state == Some(2) { None } else { remote },
            tcp_state: state,
        });
    }
    Ok(rows)
}

#[cfg(any(windows, test))]
enum QueryReply {
    Success,
    Resize,
    Failure(u32),
}

// u32 storage provides the alignment required by the OWNER_PID table layouts.
// At most four calls, including sizing; at most one MiB plus its parsing copy.
#[cfg(any(windows, test))]
fn bounded_query(
    mut call: impl FnMut(&mut [u32], &mut u32) -> QueryReply,
    mut expired: impl FnMut() -> bool,
) -> Result<Vec<u8>, SnapshotError> {
    let mut words = Vec::<u32>::new();
    for attempt in 0..MAX_QUERY_CALLS {
        if expired() {
            return Err(SnapshotError::TimeBudgetExceeded);
        }
        let mut size = (words.len() * 4) as u32;
        let reply = call(&mut words, &mut size);
        if expired() {
            return Err(SnapshotError::TimeBudgetExceeded);
        }
        match reply {
            QueryReply::Failure(code) => return Err(SnapshotError::TableQuery { code }),
            QueryReply::Resize => {
                if size as usize > MAX_TABLE_BYTES {
                    return Err(SnapshotError::TableTooLarge);
                }
                if size < 4 {
                    return Err(SnapshotError::MalformedTable);
                }
                if attempt + 1 == MAX_QUERY_CALLS {
                    return Err(SnapshotError::UnstableTable);
                }
                // Fresh exact-sized storage avoids Vec's geometric growth
                // retaining capacity above the byte budget after a retry.
                words = vec![0; (size as usize).div_ceil(4)];
            }
            QueryReply::Success => {
                if size < 4 || size as usize > words.len() * 4 {
                    return Err(SnapshotError::MalformedTable);
                }
                return Ok(words
                    .iter()
                    .flat_map(|word| word.to_ne_bytes())
                    .take(size as usize)
                    .collect());
            }
        }
    }
    unreachable!("final retry returns an error")
}

// The test seam is private: external callers cannot manufacture an OS source.
#[cfg(any(windows, test))]
trait SnapshotSource {
    fn creation_time(&mut self) -> Result<u64, SnapshotError>;
    fn require_alive(&mut self) -> Result<(), SnapshotError>;
    fn read_table(&mut self, kind: TableKind) -> Result<Vec<EndpointRow>, SnapshotError>;
    fn elapsed_micros(&self) -> u64;
}

#[cfg(any(windows, test))]
fn capture_from(
    source: &mut impl SnapshotSource,
    pid: u32,
    capture_id: String,
) -> Result<ProcessNetworkSnapshot, SnapshotError> {
    if pid == 0 {
        return Err(SnapshotError::InvalidPid);
    }
    source.require_alive()?;
    let created = source.creation_time()?;
    if created == 0 {
        return Err(SnapshotError::InvalidProcessTime);
    }
    let tables = [
        TableKind::TcpV4,
        TableKind::TcpV6,
        TableKind::UdpV4,
        TableKind::UdpV6,
    ]
    .map(|table| {
        let started = source.elapsed_micros();
        let result = if started >= MAX_CAPTURE_MICROS {
            Err(SnapshotError::TimeBudgetExceeded)
        } else {
            source.read_table(table)
        };
        TableSnapshot {
            table,
            started_after_micros: started,
            ended_after_micros: source.elapsed_micros(),
            outcome: match result {
                Ok(rows) => TableOutcome::Observed { rows },
                Err(reason) => TableOutcome::Unavailable { reason },
            },
        }
    });
    // An exited or inaccessible process invalidates ALL rows, even if a table
    // call succeeded. Never reopen by PID after collection.
    source.require_alive()?;
    let elapsed_micros = source.elapsed_micros();
    if elapsed_micros >= MAX_CAPTURE_MICROS {
        return Err(SnapshotError::TimeBudgetExceeded);
    }
    Ok(ProcessNetworkSnapshot {
        schema_version: 1,
        source: "windows_ip_helper_owner_pid_snapshot_v1",
        capture_id,
        pid,
        process_created_at_filetime_100ns: created.to_string(),
        process_binding: "same_handle_alive_before_and_after_tables",
        elapsed_micros,
        all_tables_read: tables
            .iter()
            .all(|t| matches!(t.outcome, TableOutcome::Observed { .. })),
        connection_history_complete: false,
        attempt_outcomes_available: false,
        byte_counts_available: false,
        event_loss_observable: false,
        baseline_compatible: false,
        enforcement_active: false,
        tables,
    })
}

/// Collects sequential TCP/UDP v4/v6 diagnostics for the process resolved at
/// call time. Read-only query/synchronize rights; no debug privilege elevation.
/// The time budget is checked between synchronous OS calls, not preemption.
pub fn snapshot_process(pid: u32) -> Result<ProcessNetworkSnapshot, SnapshotError> {
    if pid == 0 {
        return Err(SnapshotError::InvalidPid);
    }
    #[cfg(windows)]
    {
        windows::capture(pid)
    }
    #[cfg(not(windows))]
    {
        Err(SnapshotError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;
