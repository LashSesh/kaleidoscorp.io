//! Traffic capture (connections seam): a real [`ssk_capture::TrafficSource`].
//!
//! Driverless, connection/flow-level capture via the Windows IP Helper API. We
//! enumerate active TCP and UDP endpoints together with their owning PID using
//! `GetExtendedTcpTable` / `GetExtendedUdpTable` with the OWNER_PID table
//! classes. This is **not** packet capture: no driver, no raw sockets — each row
//! is an observed "flow" (a live/listening endpoint pair).
//!
//! Design split (the reason this is testable off-Windows):
//! * the raw FFI layer (`#[cfg(windows)] mod sys`) is thin — it only performs
//!   the two-call size/data pattern and hands back an owned `Vec<u8>` of raw
//!   table bytes;
//! * all correctness-bearing LOGIC is pure and platform-neutral
//!   ([`parse_tcp_table`], [`parse_udp_table`], [`flow_to_traffic_window`]),
//!   unit-tested on any host.
//!
//! ## Deeper tier (documented, not yet built)
//! Packet-level capture (payload sizes, timing, direction) needs a driver
//! (WinDivert) or WFP datagram inspection. This IP-Helper tier is the honest
//! driverless first step: it observes *who is talking to whom*, not the bytes.
//! IPv4 is enumerated here; IPv6 (`AF_INET6` + the `*6ROW_OWNER_PID` structs)
//! is a mechanical extension needing its own pure parser (16-byte addresses).

use std::net::Ipv4Addr;

use ssk_capture::{CaptureScope, TrafficSource, TrafficWindow};

/// A single observed connection/flow parsed out of an IP Helper OWNER_PID table.
/// Platform-neutral so it can be unit-tested off-Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    pub protocol: &'static str,
    pub local_addr: Ipv4Addr,
    pub local_port: u16,
    pub remote_addr: Ipv4Addr,
    pub remote_port: u16,
    /// TCP connection state (MIB_TCP_STATE); 0 for UDP (connectionless).
    pub state: u32,
    pub pid: u32,
}

// ---------------------------------------------------------------------------
// Raw table layout constants (stable ABI of the IP Helper MIB structs).
// ---------------------------------------------------------------------------

/// sizeof(MIB_TCPROW_OWNER_PID): 6 x DWORD.
const TCP_ROW_SIZE: usize = 24;
/// sizeof(MIB_UDPROW_OWNER_PID): 3 x DWORD.
const UDP_ROW_SIZE: usize = 12;
/// Both tables begin with `DWORD dwNumEntries`; the row array follows with no
/// padding (4-byte aligned).
const NUM_ENTRIES_SIZE: usize = 4;

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
}

/// `dwLocalAddr`/`dwRemoteAddr` are `in_addr` in network byte order: the four
/// bytes in memory are the dotted-quad octets in order.
fn read_ipv4(bytes: &[u8], off: usize) -> Ipv4Addr {
    Ipv4Addr::new(bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3])
}

/// `dwLocalPort`/`dwRemotePort` store the port in the low WORD in *network byte
/// order* (big-endian). The first two bytes of the DWORD are the port.
fn read_port_be(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([bytes[off], bytes[off + 1]])
}

/// PURE parser for a `MIB_TCPTABLE_OWNER_PID` byte image.
///
/// Layout: `DWORD dwNumEntries;` then `dwNumEntries` repetitions of
/// `MIB_TCPROW_OWNER_PID { dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr,
/// dwRemotePort, dwOwningPid }`. Truncated/short buffers are tolerated: only
/// fully-present rows are returned.
#[must_use]
pub fn parse_tcp_table(bytes: &[u8]) -> Vec<FlowRow> {
    if bytes.len() < NUM_ENTRIES_SIZE {
        return Vec::new();
    }
    let num = read_u32_le(bytes, 0) as usize;
    let mut out = Vec::new();
    for i in 0..num {
        let base = NUM_ENTRIES_SIZE + i * TCP_ROW_SIZE;
        if base + TCP_ROW_SIZE > bytes.len() {
            break;
        }
        out.push(FlowRow {
            protocol: "tcp",
            state: read_u32_le(bytes, base),
            local_addr: read_ipv4(bytes, base + 4),
            local_port: read_port_be(bytes, base + 8),
            remote_addr: read_ipv4(bytes, base + 12),
            remote_port: read_port_be(bytes, base + 16),
            pid: read_u32_le(bytes, base + 20),
        });
    }
    out
}

/// PURE parser for a `MIB_UDPTABLE_OWNER_PID` byte image.
///
/// Layout: `DWORD dwNumEntries;` then `dwNumEntries` repetitions of
/// `MIB_UDPROW_OWNER_PID { dwLocalAddr, dwLocalPort, dwOwningPid }`. UDP is
/// connectionless: no remote endpoint and no state.
#[must_use]
pub fn parse_udp_table(bytes: &[u8]) -> Vec<FlowRow> {
    if bytes.len() < NUM_ENTRIES_SIZE {
        return Vec::new();
    }
    let num = read_u32_le(bytes, 0) as usize;
    let mut out = Vec::new();
    for i in 0..num {
        let base = NUM_ENTRIES_SIZE + i * UDP_ROW_SIZE;
        if base + UDP_ROW_SIZE > bytes.len() {
            break;
        }
        out.push(FlowRow {
            protocol: "udp",
            state: 0,
            local_addr: read_ipv4(bytes, base),
            local_port: read_port_be(bytes, base + 4),
            remote_addr: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            pid: read_u32_le(bytes, base + 8),
        });
    }
    out
}

/// MIB_TCP_STATE ESTABLISHED.
const MIB_TCP_STATE_ESTAB: u32 = 5;

/// Map a TCP state code to a coarse HTTP-like status. ESTABLISHED reads as 200
/// (live/OK); everything else surfaces the raw state code so downstream can
/// still distinguish LISTEN / TIME_WAIT / etc.
fn tcp_state_to_status(state: u32) -> Option<i64> {
    match state {
        MIB_TCP_STATE_ESTAB => Some(200),
        s => Some(i64::from(s)),
    }
}

/// PURE mapping from a parsed [`FlowRow`] to the workspace [`TrafficWindow`].
///
/// `url` is `<proto>://<remote_ip>:<remote_port>` for TCP (the meaningful
/// observable — who we are talking to), or the local endpoint for UDP. Byte-
/// level fields (headers, payload, timing) are unknown at flow granularity and
/// left empty / `-1` (the crate's unknown sentinel), never fabricated.
#[must_use]
pub fn flow_to_traffic_window(flow: &FlowRow) -> TrafficWindow {
    let (host_ip, host_port, status) = if flow.protocol == "udp" {
        (flow.local_addr, flow.local_port, None)
    } else {
        (
            flow.remote_addr,
            flow.remote_port,
            tcp_state_to_status(flow.state),
        )
    };

    let mut window = TrafficWindow::http(flow.protocol);
    window.url = Some(format!("{}://{host_ip}:{host_port}", flow.protocol));
    window.status = status;
    window
}

// ---------------------------------------------------------------------------
// Thin Windows FFI layer. Everything below is #[cfg(windows)] and delegates all
// interpretation to the pure parsers above.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod sys {
    use super::{parse_tcp_table, parse_udp_table, FlowRow};
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    /// Errors from the raw IP Helper calls.
    #[derive(Debug)]
    pub enum CaptureError {
        /// A `GetExtended*Table` call returned a non-success Win32 code.
        Win32(u32),
    }

    impl std::fmt::Display for CaptureError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                CaptureError::Win32(code) => write!(f, "IP Helper call failed (Win32 {code})"),
            }
        }
    }
    impl std::error::Error for CaptureError {}

    /// Run the IP Helper two-call (size, then data) pattern and return the raw
    /// table bytes. Retries on `ERROR_INSUFFICIENT_BUFFER` because the table can
    /// grow between the two calls.
    unsafe fn query_table(is_tcp: bool, class: i32) -> Result<Vec<u8>, CaptureError> {
        let mut size: u32 = 0;
        let call = |buf: *mut c_void, sz: *mut u32| -> u32 {
            if is_tcp {
                GetExtendedTcpTable(buf, sz, 0, AF_INET as u32, class, 0)
            } else {
                GetExtendedUdpTable(buf, sz, 0, AF_INET as u32, class, 0)
            }
        };

        let ret = call(ptr::null_mut(), &mut size);
        if ret != NO_ERROR && ret != ERROR_INSUFFICIENT_BUFFER {
            return Err(CaptureError::Win32(ret));
        }

        loop {
            if size == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; size as usize];
            match call(buf.as_mut_ptr().cast::<c_void>(), &mut size) {
                r if r == NO_ERROR => {
                    buf.truncate(size as usize);
                    return Ok(buf);
                }
                r if r == ERROR_INSUFFICIENT_BUFFER => continue,
                r => return Err(CaptureError::Win32(r)),
            }
        }
    }

    /// Enumerate active IPv4 TCP flows with owning PID.
    pub fn capture_tcp_flows() -> Result<Vec<FlowRow>, CaptureError> {
        let bytes = unsafe { query_table(true, TCP_TABLE_OWNER_PID_ALL)? };
        Ok(parse_tcp_table(&bytes))
    }

    /// Enumerate active IPv4 UDP endpoints with owning PID.
    pub fn capture_udp_flows() -> Result<Vec<FlowRow>, CaptureError> {
        let bytes = unsafe { query_table(false, UDP_TABLE_OWNER_PID)? };
        Ok(parse_udp_table(&bytes))
    }
}

/// Capture every observable IPv4 flow (TCP + UDP) on the current platform.
/// Real IP Helper enumeration on Windows; an empty list on other targets (the
/// crate is inert off-Windows — callers gate on [`crate::platform_supported`]).
fn platform_capture_flows() -> Vec<FlowRow> {
    #[cfg(windows)]
    {
        let mut flows = sys::capture_tcp_flows().unwrap_or_default();
        flows.extend(sys::capture_udp_flows().unwrap_or_default());
        flows
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// The real TrafficSource
// ---------------------------------------------------------------------------

/// A real [`TrafficSource`] backed by the Windows IP Helper API: each active
/// TCP/UDP flow becomes a [`TrafficWindow`]. Payload-neutral by construction (no
/// bytes are read — only endpoint metadata), which matches the capture crate's
/// canonicalization contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsConnectionSource;

impl WindowsConnectionSource {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl TrafficSource for WindowsConnectionSource {
    fn source_id(&self) -> String {
        "windows-iphelper".to_owned()
    }

    fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
        let flows = platform_capture_flows();
        tracing::info!(
            target: "ssk.winhost.capture",
            event = "flows_captured",
            count = flows.len(),
            supported = cfg!(windows),
        );
        flows.iter().map(flow_to_traffic_window).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_row(state: u32, la: [u8; 4], lp: u16, ra: [u8; 4], rp: u16, pid: u32) -> Vec<u8> {
        let mut r = Vec::with_capacity(TCP_ROW_SIZE);
        r.extend_from_slice(&state.to_le_bytes());
        r.extend_from_slice(&la);
        r.extend_from_slice(&lp.to_be_bytes());
        r.extend_from_slice(&[0, 0]);
        r.extend_from_slice(&ra);
        r.extend_from_slice(&rp.to_be_bytes());
        r.extend_from_slice(&[0, 0]);
        r.extend_from_slice(&pid.to_le_bytes());
        assert_eq!(r.len(), TCP_ROW_SIZE);
        r
    }

    fn udp_row(la: [u8; 4], lp: u16, pid: u32) -> Vec<u8> {
        let mut r = Vec::with_capacity(UDP_ROW_SIZE);
        r.extend_from_slice(&la);
        r.extend_from_slice(&lp.to_be_bytes());
        r.extend_from_slice(&[0, 0]);
        r.extend_from_slice(&pid.to_le_bytes());
        assert_eq!(r.len(), UDP_ROW_SIZE);
        r
    }

    #[test]
    fn parses_two_tcp_rows() {
        let mut buf = 2u32.to_le_bytes().to_vec();
        buf.extend(tcp_row(
            5,
            [127, 0, 0, 1],
            49512,
            [93, 184, 216, 34],
            443,
            4321,
        ));
        buf.extend(tcp_row(2, [0, 0, 0, 0], 135, [0, 0, 0, 0], 0, 900));

        let rows = parse_tcp_table(&buf);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].local_addr, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(rows[0].local_port, 49512);
        assert_eq!(rows[0].remote_addr, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(rows[0].remote_port, 443);
        assert_eq!(rows[0].pid, 4321);
        assert_eq!(rows[1].local_port, 135);
        assert_eq!(rows[1].pid, 900);
    }

    #[test]
    fn parses_udp_row() {
        let mut buf = 1u32.to_le_bytes().to_vec();
        buf.extend(udp_row([0, 0, 0, 0], 53, 1200));
        let rows = parse_udp_table(&buf);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].protocol, "udp");
        assert_eq!(rows[0].local_port, 53);
        assert_eq!(rows[0].remote_port, 0);
        assert_eq!(rows[0].pid, 1200);
    }

    #[test]
    fn truncated_buffer_yields_only_full_rows() {
        // Claims 2 rows but supplies 1.
        let mut buf = 2u32.to_le_bytes().to_vec();
        buf.extend(tcp_row(5, [10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 7));
        let rows = parse_tcp_table(&buf);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].local_port, 1000);
    }

    #[test]
    fn empty_and_short_buffers() {
        assert!(parse_tcp_table(&[]).is_empty());
        assert!(parse_tcp_table(&[0, 0]).is_empty());
        assert_eq!(parse_tcp_table(&0u32.to_le_bytes()).len(), 0);
    }

    #[test]
    fn tcp_flow_to_traffic_window() {
        let flow = FlowRow {
            protocol: "tcp",
            local_addr: Ipv4Addr::new(127, 0, 0, 1),
            local_port: 49512,
            remote_addr: Ipv4Addr::new(93, 184, 216, 34),
            remote_port: 443,
            state: 5,
            pid: 4321,
        };
        let tw = flow_to_traffic_window(&flow);
        assert_eq!(tw.protocol, "tcp");
        assert_eq!(tw.url.as_deref(), Some("tcp://93.184.216.34:443"));
        assert_eq!(tw.status, Some(200));
        assert_eq!(tw.method, None);
        assert!(tw.request_headers.is_empty());
        // timing/payload are honestly unknown at flow granularity.
        assert_eq!(tw.duration_ms, -1);
        assert!(tw.payload.is_empty());
    }

    #[test]
    fn listen_state_status_is_raw_code() {
        let flow = FlowRow {
            protocol: "tcp",
            local_addr: Ipv4Addr::UNSPECIFIED,
            local_port: 135,
            remote_addr: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            state: 2,
            pid: 900,
        };
        let tw = flow_to_traffic_window(&flow);
        assert_eq!(tw.status, Some(2));
        assert_eq!(tw.url.as_deref(), Some("tcp://0.0.0.0:0"));
    }

    #[test]
    fn udp_flow_to_traffic_window() {
        let flow = FlowRow {
            protocol: "udp",
            local_addr: Ipv4Addr::new(0, 0, 0, 0),
            local_port: 53,
            remote_addr: Ipv4Addr::UNSPECIFIED,
            remote_port: 0,
            state: 0,
            pid: 1200,
        };
        let tw = flow_to_traffic_window(&flow);
        assert_eq!(tw.protocol, "udp");
        assert_eq!(tw.url.as_deref(), Some("udp://0.0.0.0:53"));
        assert_eq!(tw.status, None);
    }

    #[test]
    fn source_is_payload_neutral_and_off_windows_yields_no_flows() {
        let source = WindowsConnectionSource::new();
        assert_eq!(source.source_id(), "windows-iphelper");
        let scope = CaptureScope::new("local", ["lo0"]);
        let windows = source.windows(&scope);
        // On the non-Windows build box there are no flows; on Windows this would
        // enumerate real endpoints. Either way, no window ever carries a payload.
        assert!(windows.iter().all(|w| w.payload.is_empty()));
        #[cfg(not(windows))]
        assert!(windows.is_empty());
    }
}
