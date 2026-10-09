//! Who connected to the loopback port (design 6.6): the pure part, `/proc/net/tcp`
//! and `/proc/net/tcp6` parsing and the decision on the rows found.
//!
//! The Linux owner of a connection is the `uid` column of the CLIENT's row of
//! the kernel's TCP table: the row with `local == client` and
//! `rem == listener`. The accepted (server-side) socket has the mirror row
//! (`local == listener`); it belongs to this daemon and is never used. No PID is
//! derived and `/proc/<pid>/fd` is never scanned, so there is no PID or inode
//! reuse race on Linux; the only race is the lifetime of the row, and it fails
//! closed: anything that is not exactly one clear row is `Unknown`, and
//! `Unknown` means refuse.
//!
//! The parsing and the decision read no file and no socket. The service that
//! does ([`PeerTableService`]: one thread, one table read per batch of requests, a
//! bound on how often the table is read) and the self-test of the peer check are
//! at the end of this file.

use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ssk_netcore::BoxFuture;
use tokio::sync::oneshot;

use super::types::Controls;

/// What the authorizer answers. `Unknown` always means refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerVerdict {
    SameUser,
    DifferentUser,
    Unknown,
}

/// The two ends of an accepted connection, as the daemon saw them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerQuery {
    /// The peer's address (`peer_addr()` of the accepted socket).
    pub client: SocketAddr,
    /// The listener's address (`local_addr()` of the accepted socket).
    pub listener: SocketAddr,
}

/// A kernel table is read at most this large; a bigger one is not parsed.
pub const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

/// TCP states of the kernel's table (`include/net/tcp_states.h`) a client row may
/// be in: a connected client, and a client that has half-closed its side while
/// the request is still being read. `08 CLOSE_WAIT` appears only on the accepted
/// socket's row, never on the client's.
const STATE_ESTABLISHED: u8 = 0x01;
const STATE_FIN_WAIT1: u8 = 0x04;
const STATE_FIN_WAIT2: u8 = 0x05;

/// One row of `/proc/net/tcp` or `/proc/net/tcp6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Row {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// The two tables as text. `tcp6` is `None` when the file does not exist (IPv6
/// disabled): that is an empty table, not an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawTables {
    pub tcp: String,
    pub tcp6: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// The first line is not the header this parser knows: the column layout it
    /// relies on cannot be trusted.
    UnexpectedHeader,
    /// The table is larger than [`MAX_TABLE_BYTES`].
    TooLarge,
    /// The listener is not an IPv4 address: the ingress binds IPv4 loopback only.
    UnsupportedListener,
}

/// The rows of both tables whose remote end is the listener, and what was left
/// out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    pub rows: Vec<Row>,
    /// Data lines that do not have the expected shape. A table where this is
    /// not zero is not trusted by the self-test.
    pub malformed: usize,
}

/// The remote endpoint a row must show to be a client row, spelled as the
/// kernel prints it, so that most lines are skipped by a string comparison and
/// only the interesting ones are parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFilter {
    tcp: String,
    tcp6_mapped: String,
}

impl RemoteFilter {
    /// For a listener on an IPv4 address. `None` for anything else.
    #[must_use]
    pub fn for_listener(listener: SocketAddr) -> Option<Self> {
        let SocketAddr::V4(listener) = listener else {
            return None;
        };
        let word = u32::from_ne_bytes(listener.ip().octets());
        let port = listener.port();
        Some(Self {
            tcp: format!("{word:08X}:{port:04X}"),
            // ::ffff:a.b.c.d is the words 0, 0, 0xFFFF0000 (as bytes 00 00 FF FF),
            // then the IPv4 word.
            tcp6_mapped: format!(
                "00000000{:08X}{:08X}{word:08X}:{port:04X}",
                0_u32,
                u32::from_ne_bytes([0, 0, 0xff, 0xff])
            ),
        })
    }
}

/// `true` when `text` is exactly `len` ASCII hex digits (no sign, no prefix).
fn hex_exact(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_u32(text: &str) -> Option<u32> {
    if !hex_exact(text, 8) {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

fn hex_u16(text: &str) -> Option<u16> {
    if !hex_exact(text, 4) {
        return None;
    }
    u16::from_str_radix(text, 16).ok()
}

/// `0100007F:1F90`: the host-order word of the network-order bytes, then the
/// port. `to_ne_bytes` undoes the kernel's `%08X` of a native word on either
/// endianness.
fn parse_endpoint_v4(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    let [a, b, c, d] = hex_u32(address)?.to_ne_bytes();
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        hex_u16(port)?,
    ))
}

/// `0000000000000000FFFF00000100007F:1F90`: four such words.
fn parse_endpoint_v6(text: &str) -> Option<SocketAddr> {
    let (address, port) = text.split_once(':')?;
    if !hex_exact(address, 32) {
        return None;
    }
    let mut bytes = [0_u8; 16];
    for (digits, out) in address
        .as_bytes()
        .chunks_exact(8)
        .zip(bytes.chunks_exact_mut(4))
    {
        let digits = std::str::from_utf8(digits).ok()?;
        out.copy_from_slice(&hex_u32(digits)?.to_ne_bytes());
    }
    Some(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::from(bytes)),
        hex_u16(port)?,
    ))
}

/// The header line of each table, as the kernel prints it, reduced to its words.
/// The two tables do NOT agree: `tcp` says `rem_address` and `tcp6` says
/// `remote_address` (`net/ipv4/tcp_ipv4.c` and `net/ipv6/tcp_ipv6.c`). The data
/// lines are read by absolute position, so the header must be exactly the layout
/// those positions assume; anything else is refused, not guessed at.
const HEADER_V4: [&str; 12] = [
    "sl",
    "local_address",
    "rem_address",
    "st",
    "tx_queue",
    "rx_queue",
    "tr",
    "tm->when",
    "retrnsmt",
    "uid",
    "timeout",
    "inode",
];
const HEADER_V6: [&str; 12] = [
    "sl",
    "local_address",
    "remote_address",
    "st",
    "tx_queue",
    "rx_queue",
    "tr",
    "tm->when",
    "retrnsmt",
    "uid",
    "timeout",
    "inode",
];

fn header_is_known(line: &str, ipv6: bool) -> bool {
    let expected: &[&str; 12] = if ipv6 { &HEADER_V6 } else { &HEADER_V4 };
    // The kernel writes ASCII; `split_whitespace` would also split on U+0085 and
    // other Unicode spaces, which a forged table could use.
    line.split_ascii_whitespace().eq(expected.iter().copied())
}

fn parse_row(line: &str, ipv6: bool) -> Option<Row> {
    // `sl: local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`
    let mut fields = line.split_ascii_whitespace();
    let _slot = fields.next()?;
    let local = fields.next()?;
    let remote = fields.next()?;
    let state = fields.next()?;
    let _queues = fields.next()?;
    let _timer = fields.next()?;
    let _retransmits = fields.next()?;
    let uid = fields.next()?;
    let _timeout = fields.next()?;
    let inode = fields.next()?;
    let endpoint = if ipv6 {
        parse_endpoint_v6
    } else {
        parse_endpoint_v4
    };
    if !hex_exact(state, 2) {
        return None;
    }
    Some(Row {
        local: endpoint(local)?,
        remote: endpoint(remote)?,
        state: u8::from_str_radix(state, 16).ok()?,
        uid: decimal(uid)?,
        inode: decimal(inode)?,
    })
}

fn decimal<T: std::str::FromStr>(text: &str) -> Option<T> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn parse_table(
    text: &str,
    ipv6: bool,
    filter: Option<&str>,
    into: &mut Table,
) -> Result<(), ParseError> {
    if text.len() > MAX_TABLE_BYTES {
        return Err(ParseError::TooLarge);
    }
    let mut lines = text.lines();
    if !lines
        .next()
        .is_some_and(|header| header_is_known(header, ipv6))
    {
        return Err(ParseError::UnexpectedHeader);
    }
    for line in lines.filter(|line| !line.trim().is_empty()) {
        if let Some(wanted) = filter {
            // The remote endpoint is the third whitespace-separated field.
            let remote = line.split_ascii_whitespace().nth(2);
            if remote.is_some_and(|remote| !remote.eq_ignore_ascii_case(wanted)) {
                continue;
            }
        }
        match parse_row(line, ipv6) {
            Some(row) => into.rows.push(row),
            None => into.malformed = into.malformed.saturating_add(1),
        }
    }
    Ok(())
}

/// Rows of `/proc/net/tcp` (IPv4). `remote`, when given, is the kernel's
/// spelling of the remote endpoint that a row must show.
pub fn parse_proc_net_tcp(text: &str, remote: Option<&str>) -> Result<Table, ParseError> {
    let mut table = Table::default();
    parse_table(text, false, remote, &mut table)?;
    Ok(table)
}

/// Rows of `/proc/net/tcp6`, IPv4-mapped addresses included.
pub fn parse_proc_net_tcp6(text: &str, remote: Option<&str>) -> Result<Table, ParseError> {
    let mut table = Table::default();
    parse_table(text, true, remote, &mut table)?;
    Ok(table)
}

/// Both tables, reduced to the rows whose remote end is `listener`.
pub fn parse_tables(raw: &RawTables, listener: SocketAddr) -> Result<Table, ParseError> {
    let filter = RemoteFilter::for_listener(listener).ok_or(ParseError::UnsupportedListener)?;
    let mut table = Table::default();
    parse_table(&raw.tcp, false, Some(&filter.tcp), &mut table)?;
    if let Some(text) = &raw.tcp6 {
        parse_table(text, true, Some(&filter.tcp6_mapped), &mut table)?;
    }
    Ok(table)
}

/// IPv4-mapped IPv6 is the same endpoint as its IPv4 form; only the strict
/// `::ffff:a.b.c.d` range is unmapped.
fn normalise(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

/// What the rows say about one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowDecision {
    /// A verdict; `Unknown` included.
    Verdict(PeerVerdict),
    /// No row for this connection (yet): read the table once more before giving
    /// up. `/proc/net/tcp` is not an atomic snapshot.
    Miss,
}

/// The decision of 6.6:
///
/// * the client row is the one with `local == client` and `remote == listener`
///   (addresses normalised); a row with the two reversed is the accepted
///   socket's and is never used;
/// * only states 01, 04 and 05 count; a row in any other state (TIME_WAIT, ...)
///   is not a connected client;
/// * identical duplicates collapse (the table may repeat a row under churn); two
///   different `(state, uid, inode)` are ambiguous, `Unknown`;
/// * `inode == 0` is an orphan (the client closed completely; its uid column is
///   not an owner), `Unknown`;
/// * a clear row is `SameUser` when its uid is `own_uid`, else `DifferentUser`.
#[must_use]
pub fn decide_row(rows: &[Row], query: &PeerQuery, own_uid: u32) -> RowDecision {
    let client = normalise(query.client);
    let listener = normalise(query.listener);
    // At most one distinct clear row is ever kept: the second one ends the scan,
    // so a table of forged rows cannot make this take longer than one pass.
    let mut clear: Option<(u8, u32, u64)> = None;
    let mut other_state = false;
    for row in rows {
        if normalise(row.local) != client || normalise(row.remote) != listener {
            continue;
        }
        if !matches!(
            row.state,
            STATE_ESTABLISHED | STATE_FIN_WAIT1 | STATE_FIN_WAIT2
        ) {
            other_state = true;
            continue;
        }
        let key = (row.state, row.uid, row.inode);
        match clear {
            None => clear = Some(key),
            Some(first) if first == key => {}
            Some(_) => return RowDecision::Verdict(PeerVerdict::Unknown),
        }
    }
    match clear {
        None if other_state => RowDecision::Verdict(PeerVerdict::Unknown),
        None => RowDecision::Miss,
        Some((_, _, 0)) => RowDecision::Verdict(PeerVerdict::Unknown),
        Some((_, uid, _)) if uid == own_uid => RowDecision::Verdict(PeerVerdict::SameUser),
        Some(_) => RowDecision::Verdict(PeerVerdict::DifferentUser),
    }
}

/// Why a control is missing: the closed set of reasons `controls()` reports and
/// `INGRESS_HARDENING_UNAVAILABLE` lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingControl {
    /// "Same user" would be ambiguous: `getuid() != geteuid()`, or the user
    /// namespace maps ids (an unmapped account would show as the overflow uid).
    IdentityAmbiguous,
    /// The self-test against a temporary loopback connection failed.
    PeerSelftestFailed,
    /// No peer authorizer exists on this platform.
    PeerCheckUnsupported,
}

impl MissingControl {
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::IdentityAmbiguous => "IDENTITY_AMBIGUOUS",
            Self::PeerSelftestFailed => "PEER_SELFTEST_FAILED",
            Self::PeerCheckUnsupported => "PEER_CHECK_UNSUPPORTED",
        }
    }
}

/// What a platform with no peer check reports.
#[must_use]
pub const fn no_controls() -> Controls {
    Controls {
        exclusive_bind: false,
        peer_check: false,
        private_audit_store: false,
    }
}

// ---------------------------------------------------------------------------
// The service (C-G7b)
// ---------------------------------------------------------------------------

/// Answers who owns a connection. Async on purpose: it must never block a
/// runtime worker AND never occupy a blocking-pool slot of the runtime.
pub trait PeerAuthorizer: Send + Sync {
    fn authorize<'a>(&'a self, query: PeerQuery) -> BoxFuture<'a, PeerVerdict>;
}

/// Where the raw tables come from. Linux reads `/proc/net/tcp*`
/// ([`ProcTableSource`]); the Windows source of `C-WIN2` calls
/// `GetExtendedTcpTable`; tests inject a counting fake.
pub trait TableSource: Send + 'static {
    /// One snapshot of both tables. Blocking.
    ///
    /// # Errors
    /// Whatever the source could not read; the service answers `Unknown`.
    fn read(&mut self) -> io::Result<RawTables>;
}

impl TableSource for Box<dyn TableSource> {
    fn read(&mut self) -> io::Result<RawTables> {
        (**self).read()
    }
}

/// `/proc/net/tcp` and, when it exists, `/proc/net/tcp6`.
#[derive(Debug, Clone)]
pub struct ProcTableSource {
    tcp: PathBuf,
    tcp6: PathBuf,
}

impl ProcTableSource {
    #[must_use]
    pub fn new() -> Self {
        Self::at("/proc/net/tcp", "/proc/net/tcp6")
    }

    /// Other paths, for tests.
    #[must_use]
    pub fn at(tcp: impl Into<PathBuf>, tcp6: impl Into<PathBuf>) -> Self {
        Self {
            tcp: tcp.into(),
            tcp6: tcp6.into(),
        }
    }
}

impl Default for ProcTableSource {
    fn default() -> Self {
        Self::new()
    }
}

/// At most one byte more than the cap is read, so a table larger than the cap
/// is seen as such by the parser and is never held whole.
fn read_capped(path: &Path) -> io::Result<String> {
    let limit = u64::try_from(MAX_TABLE_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut text = String::new();
    std::fs::File::open(path)?
        .take(limit)
        .read_to_string(&mut text)?;
    Ok(text)
}

impl TableSource for ProcTableSource {
    fn read(&mut self) -> io::Result<RawTables> {
        let tcp = read_capped(&self.tcp)?;
        // IPv6 disabled: the file is not there, which is an empty table.
        let tcp6 = match read_capped(&self.tcp6) {
            Ok(text) => Some(text),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        Ok(RawTables { tcp, tcp6 })
    }
}

/// How the service paces itself. The defaults are the design's numbers; tests
/// shrink them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceTuning {
    /// How long a caller waits for its verdict before it is `Unknown`.
    pub timeout: Duration,
    /// Requests that may wait for the thread; one more is `Unknown` at once.
    pub queue: usize,
    /// Requests served from one snapshot.
    pub batch: usize,
    /// The next snapshot starts no earlier than `max(min_interval, 2 x the
    /// duration of the last one)` after the last one ENDED, so a read of `d` is
    /// followed by a rest of at least `2d`: at most a third of one core however
    /// fast connections arrive.
    pub min_interval: Duration,
    /// The wait before the one re-read of a miss.
    pub reread_after: Duration,
}

impl ServiceTuning {
    pub const DEFAULT: Self = Self {
        timeout: Duration::from_millis(500),
        queue: 256,
        batch: 256,
        min_interval: Duration::from_millis(20),
        reread_after: Duration::from_millis(5),
    };
}

impl Default for ServiceTuning {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What the service counted, for the doctor and the tests.
#[derive(Debug, Default)]
pub struct ServiceCounters {
    snapshots: AtomicU64,
    rereads: AtomicU64,
    queue_full: AtomicU64,
    timeouts: AtomicU64,
    source_errors: AtomicU64,
    abandoned: AtomicU64,
}

/// A copy of [`ServiceCounters`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ServiceStats {
    /// Table reads, the re-reads excluded.
    pub snapshots: u64,
    pub rereads: u64,
    /// Requests refused because the queue was full.
    pub queue_full: u64,
    pub timeouts: u64,
    /// Reads that failed (every request of the batch was `Unknown`).
    pub source_errors: u64,
    /// Requests whose caller had given up before the thread got to them.
    pub abandoned: u64,
}

impl ServiceCounters {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn stats(&self) -> ServiceStats {
        ServiceStats {
            snapshots: self.snapshots.load(Ordering::Relaxed),
            rereads: self.rereads.load(Ordering::Relaxed),
            queue_full: self.queue_full.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            source_errors: self.source_errors.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
        }
    }
}

struct Request {
    query: PeerQuery,
    reply: oneshot::Sender<PeerVerdict>,
}

/// One dedicated thread (not a slot of the runtime's blocking pool) that reads
/// the kernel's table for every request that queued meanwhile, once.
///
/// Every request was enqueued after its connection was accepted, so a snapshot
/// started afterwards already holds that connection's row: there is no cache and
/// no staleness window. Dropping the service ends the thread.
pub struct PeerTableService {
    tx: SyncSender<Request>,
    timeout: Duration,
    counters: Arc<ServiceCounters>,
}

impl PeerTableService {
    /// Starts the thread. `own_uid` is the identity "same user" means.
    ///
    /// # Errors
    /// The thread could not be started.
    pub fn start(
        source: impl TableSource,
        own_uid: u32,
        tuning: ServiceTuning,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(tuning.queue);
        let counters = Arc::new(ServiceCounters::default());
        let worker = Worker {
            source: Box::new(source),
            rx,
            own_uid,
            tuning,
            counters: Arc::clone(&counters),
        };
        std::thread::Builder::new()
            .name("ssk-ingress-peer".to_owned())
            .spawn(move || worker.run())?;
        Ok(Self {
            tx,
            timeout: tuning.timeout,
            counters,
        })
    }

    #[must_use]
    pub fn stats(&self) -> ServiceStats {
        self.counters.stats()
    }
}

impl PeerAuthorizer for PeerTableService {
    fn authorize<'a>(&'a self, query: PeerQuery) -> BoxFuture<'a, PeerVerdict> {
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            match self.tx.try_send(Request { query, reply }) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    ServiceCounters::bump(&self.counters.queue_full);
                    return PeerVerdict::Unknown;
                }
                // The thread is gone: nobody can say.
                Err(TrySendError::Disconnected(_)) => return PeerVerdict::Unknown,
            }
            match tokio::time::timeout(self.timeout, answer).await {
                Ok(Ok(verdict)) => verdict,
                Ok(Err(_)) => PeerVerdict::Unknown,
                Err(_) => {
                    ServiceCounters::bump(&self.counters.timeouts);
                    PeerVerdict::Unknown
                }
            }
        })
    }
}

struct Worker {
    source: Box<dyn TableSource>,
    rx: Receiver<Request>,
    own_uid: u32,
    tuning: ServiceTuning,
    counters: Arc<ServiceCounters>,
}

impl Worker {
    fn run(mut self) {
        let mut next_allowed: Option<Instant> = None;
        while let Ok(first) = self.rx.recv() {
            // The duty cycle: wait for the interval, then take everything that
            // queued meanwhile into the same snapshot.
            if let Some(at) = next_allowed {
                if let Some(wait) = at.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
            }
            let mut batch = vec![first];
            while batch.len() < self.tuning.batch {
                match self.rx.try_recv() {
                    Ok(request) => batch.push(request),
                    Err(_) => break,
                }
            }
            let started = Instant::now();
            self.serve(batch);
            let took = started.elapsed();
            // Measured from the END of the snapshot: a rest of twice its duration
            // makes the busy fraction at most one in three.
            next_allowed =
                Instant::now().checked_add(self.tuning.min_interval.max(took.saturating_mul(2)));
        }
    }

    /// One snapshot for the batch, and one shared re-read for what it missed.
    fn serve(&mut self, batch: Vec<Request>) {
        let live: Vec<Request> = batch
            .into_iter()
            .filter(|request| {
                let gone = request.reply.is_closed();
                if gone {
                    ServiceCounters::bump(&self.counters.abandoned);
                }
                !gone
            })
            .collect();
        if live.is_empty() {
            return;
        }
        ServiceCounters::bump(&self.counters.snapshots);
        let missed = self.answer(live);
        if missed.is_empty() {
            return;
        }
        // `/proc/net/tcp` is not an atomic snapshot: a row can be skipped. Once
        // more, for every miss of the batch together, then `Unknown`.
        std::thread::sleep(self.tuning.reread_after);
        ServiceCounters::bump(&self.counters.rereads);
        for request in self.answer(missed) {
            let _ = request.reply.send(PeerVerdict::Unknown);
        }
    }

    /// Reads the tables once and answers every request it can. Returns the
    /// requests whose connection has no row.
    fn answer(&mut self, requests: Vec<Request>) -> Vec<Request> {
        let raw = match self.source.read() {
            Ok(raw) => raw,
            Err(_) => {
                ServiceCounters::bump(&self.counters.source_errors);
                for request in requests {
                    let _ = request.reply.send(PeerVerdict::Unknown);
                }
                return Vec::new();
            }
        };
        // One parse per listener (in practice one).
        let mut tables: HashMap<SocketAddr, Result<Table, ParseError>> = HashMap::new();
        let mut missed = Vec::new();
        for request in requests {
            let table = tables
                .entry(request.query.listener)
                .or_insert_with(|| parse_tables(&raw, request.query.listener));
            let decision = match table {
                Ok(table) => decide_row(&table.rows, &request.query, self.own_uid),
                Err(_) => RowDecision::Verdict(PeerVerdict::Unknown),
            };
            match decision {
                RowDecision::Verdict(verdict) => {
                    let _ = request.reply.send(verdict);
                }
                RowDecision::Miss => missed.push(request),
            }
        }
        missed
    }
}

/// The self-test of the peer check: this environment's table carries the owner of
/// a real loopback connection. A temporary listener on `127.0.0.1:0`, a client, the
/// accepted socket, then the real lookup of the client's address; it must find
/// exactly one `ESTABLISHED` row, owned by `own_uid`, with an inode. Anything
/// else (a hidden `/proc`, a container without the table, a changed layout) is
/// `PEER_SELFTEST_FAILED`: the file existing proves nothing.
///
/// # Errors
/// [`MissingControl::PeerSelftestFailed`].
pub fn selftest(source: &mut dyn TableSource, own_uid: u32) -> Result<(), MissingControl> {
    let failed = || MissingControl::PeerSelftestFailed;
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| failed())?;
    let listen_addr = listener.local_addr().map_err(|_| failed())?;
    let client = std::net::TcpStream::connect(listen_addr).map_err(|_| failed())?;
    // Keeps the accepted socket (and so its row) alive for the lookup.
    let (_accepted, _) = listener.accept().map_err(|_| failed())?;
    let client_addr = client.local_addr().map_err(|_| failed())?;
    let raw = source.read().map_err(|_| failed())?;
    let table = parse_tables(&raw, listen_addr).map_err(|_| failed())?;
    if table.malformed != 0 {
        return Err(MissingControl::PeerSelftestFailed);
    }
    let query = PeerQuery {
        client: client_addr,
        listener: listen_addr,
    };
    let established = table.rows.iter().any(|row| {
        normalise(row.local) == normalise(client_addr)
            && normalise(row.remote) == normalise(listen_addr)
            && row.state == STATE_ESTABLISHED
    });
    match decide_row(&table.rows, &query, own_uid) {
        RowDecision::Verdict(PeerVerdict::SameUser) if established => Ok(()),
        _ => Err(MissingControl::PeerSelftestFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
    /// The header of `/proc/net/tcp6`, as `net/ipv6/tcp_ipv6.c` prints it: the
    /// third column is `remote_address`, not `rem_address`.
    const HEADER6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    /// Lines as this sandbox's kernel printed them (see the comments for what
    /// each is).
    const REAL_TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:AAA5 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 3222 2 000000003205eb87 100 0 0 10 0
   4: 0100007F:931D 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 104051 1 00000000f37e1a45 100 0 0 10 0
   5: 0100007F:D656 0100007F:931D 01 00000000:00000000 00:00000000 00000000     0        0 104052 2 00000000343c1b12 20 0 0 10 -1
   6: 0100007F:D45C 0100007F:AAA5 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000006e35d46
   7: 020200C0:D4A6 A5429522:01BB 01 00000000:00000000 02:0000001B 00000000     0        0 3308 2 00000000ed80eb5d 24 4 30 213 -1
  13: 0100007F:931D 0100007F:D656 01 00000000:00000000 00:00000000 00000000     0        0 104053 1 0000000070169279 20 0 0 10 -1
";

    fn sa(text: &str) -> SocketAddr {
        text.parse().expect("socket address")
    }

    fn row(local: &str, remote: &str, state: u8, uid: u32, inode: u64) -> Row {
        Row {
            local: sa(local),
            remote: sa(remote),
            state,
            uid,
            inode,
        }
    }

    fn query(client: &str, listener: &str) -> PeerQuery {
        PeerQuery {
            client: sa(client),
            listener: sa(listener),
        }
    }

    const CLIENT: &str = "127.0.0.1:54870"; // 0xD656
    const LISTENER: &str = "127.0.0.1:37661"; // 0x931D

    // -- parsing ------------------------------------------------------------

    #[test]
    fn real_kernel_lines_decode_to_the_documented_endpoints() {
        let table = parse_proc_net_tcp(REAL_TCP, None).expect("parses");
        assert_eq!(table.malformed, 0);
        assert_eq!(table.rows.len(), 6);
        // The client's row and the accepted socket's mirror row.
        assert_eq!(table.rows[2], row(CLIENT, LISTENER, 0x01, 0, 104_052));
        assert_eq!(table.rows[5], row(LISTENER, CLIENT, 0x01, 0, 104_053));
        // A listener, a TIME_WAIT row with the short form, and a remote address.
        assert_eq!(table.rows[1].state, 0x0a);
        assert_eq!(table.rows[3].state, 0x06);
        assert_eq!(table.rows[4].local, sa("192.0.2.2:54438"));
        assert_eq!(table.rows[4].remote, sa("34.149.66.165:443"));
    }

    #[test]
    fn the_ipv4_word_is_decoded_through_the_native_byte_order() {
        // The kernel prints the host-order word of the network-order bytes, so
        // the same address reads differently on little- and big-endian machines
        // and the decoder has to go through the native order to be right on both.
        let word = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            parse_endpoint_v4(&format!("{word:08X}:1F90")),
            Some(sa("127.0.0.1:8080"))
        );
        assert_eq!(
            parse_endpoint_v4(&format!("{word:08x}:1f90")),
            Some(sa("127.0.0.1:8080"))
        );
        if cfg!(target_endian = "little") {
            assert_eq!(
                parse_endpoint_v4("0100007F:1F90"),
                Some(sa("127.0.0.1:8080"))
            );
            assert_eq!(
                parse_endpoint_v4("020200C0:D4A6"),
                Some(sa("192.0.2.2:54438"))
            );
        }
    }

    #[test]
    fn parse_proc_net_tcp6_golden_lines() {
        // Native IPv6, a dual-stack client in the mapped form (derived from the
        // kernel's formatting rule: the words 0, 0, 0xFFFF0000 and the IPv4 word),
        // and the same on the listener side.
        let mapped_client = format!(
            "00000000{:08X}{:08X}{:08X}",
            0,
            u32::from_ne_bytes([0, 0, 0xff, 0xff]),
            u32::from_ne_bytes([127, 0, 0, 1])
        );
        let native = format!(
            "{:08X}{:08X}{:08X}{:08X}",
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]),
            0,
            0,
            u32::from_ne_bytes([0, 0, 0, 1])
        );
        let loopback6 = format!(
            "{:08X}{:08X}{:08X}{:08X}",
            0,
            0,
            0,
            u32::from_ne_bytes([0, 0, 0, 1])
        );
        let text = format!(
            "{HEADER6}\n\
             0: {mapped_client}:D656 {mapped_client}:931D 01 00000000:00000000 00:00000000 00000000  1000        0 555 1 0000000000000000 100 0 0 10 0\n\
             1: {native}:0050 {loopback6}:01BB 04 00000000:00000000 00:00000000 00000000  0        0 777 1 0000000000000000 100 0 0 10 0\n"
        );
        let table = parse_proc_net_tcp6(&text, None).expect("parses");
        assert_eq!(table.malformed, 0);
        assert_eq!(table.rows.len(), 2);
        assert_eq!(
            table.rows[0],
            Row {
                local: sa("[::ffff:127.0.0.1]:54870"),
                remote: sa("[::ffff:127.0.0.1]:37661"),
                state: 1,
                uid: 1000,
                inode: 555
            }
        );
        assert_eq!(table.rows[1].local, sa("[2001:db8::1]:80"));
        assert_eq!(table.rows[1].remote, sa("[::1]:443"));
        assert_eq!(table.rows[1].state, 4);
    }

    #[test]
    fn the_header_must_be_the_known_layout() {
        assert!(header_is_known(HEADER, false));
        assert!(header_is_known(HEADER6, true));
        // The two tables are not interchangeable: tcp says rem_address and tcp6
        // says remote_address, and a parser that accepted the wrong one for a
        // table would reject (or misread) every real file.
        assert!(!header_is_known(HEADER, true));
        assert!(!header_is_known(HEADER6, false));
        for bad in [
            "",
            "garbage",
            "sl local_address rem_address st uid",
            // Same words, wrong order: the positions would mean something else.
            "sl rem_address local_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   timeout inode uid",
            // A header that merely contains the words in order, with others between.
            "sl local_address rem_address st extra tx_queue rx_queue tr tm->when retrnsmt uid timeout inode",
            "sl local_address rem_address st uid foo bar baz inode",
        ] {
            assert!(!header_is_known(bad, false), "{bad:?}");
            assert_eq!(
                parse_proc_net_tcp(&format!("{bad}\n   0: 0100007F:1F90 0100007F:0050 01 0:0 0:0 0 0 0 1"), None),
                Err(ParseError::UnexpectedHeader),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse_proc_net_tcp("", None),
            Err(ParseError::UnexpectedHeader)
        );
        assert_eq!(
            parse_proc_net_tcp6(&format!("{HEADER}\n"), None),
            Err(ParseError::UnexpectedHeader),
            "the tcp header is not the tcp6 header"
        );
        assert_eq!(
            parse_proc_net_tcp(&format!("{HEADER6}\n"), None),
            Err(ParseError::UnexpectedHeader)
        );
    }

    #[test]
    fn every_edit_of_the_header_is_refused_for_both_tables() {
        for (header, ipv6) in [(HEADER, false), (HEADER6, true)] {
            let words: Vec<&str> = header.split_ascii_whitespace().collect();
            for at in 0..words.len() {
                // A word missing.
                let mut dropped = words.clone();
                dropped.remove(at);
                assert!(
                    !header_is_known(&dropped.join(" "), ipv6),
                    "missing {}",
                    words[at]
                );
                // A word altered.
                let mut altered = words.clone();
                let changed = format!("{}x", words[at]);
                altered[at] = &changed;
                assert!(
                    !header_is_known(&altered.join(" "), ipv6),
                    "altered {}",
                    words[at]
                );
                // A word added.
                let mut added = words.clone();
                added.insert(at, "extra");
                assert!(
                    !header_is_known(&added.join(" "), ipv6),
                    "added before {}",
                    words[at]
                );
                // Two neighbours swapped.
                if let Some(next) = words.get(at + 1) {
                    let mut swapped = words.clone();
                    swapped[at] = next;
                    swapped[at + 1] = words[at];
                    assert!(
                        !header_is_known(&swapped.join(" "), ipv6),
                        "swapped {}",
                        words[at]
                    );
                }
            }
            // Case matters, and so does a Unicode space where the kernel writes ASCII.
            assert!(!header_is_known(&header.to_uppercase(), ipv6));
            assert!(!header_is_known(&header.replacen(' ', "\u{85}", 3), ipv6));
            // Any amount of ASCII white space between the words is fine.
            assert!(header_is_known(&words.join("\t \t"), ipv6));
        }
    }

    #[test]
    fn a_header_alone_is_an_empty_table() {
        let table = parse_proc_net_tcp(&format!("{HEADER}\n"), None).expect("parses");
        assert_eq!(table, Table::default());
    }

    #[test]
    fn malformed_data_lines_are_counted_and_never_become_rows() {
        let good = "   5: 0100007F:D656 0100007F:931D 01 00000000:00000000 00:00000000 00000000     0        0 104052 2 00000000343c1b12 20 0 0 10 -1";
        let bad_lines = [
            "",                                                               // blank: ignored, not counted
            "   9: 0100007F:D656",                                            // truncated
            "   9: 0100007F:D656 0100007F:931D 1 0:0 0:0 0 0 0 5",            // one-digit state
            "   9: 0100007F:D656 0100007F:931D 0G 0:0 0:0 0 0 0 5",           // not hex
            "   9: +100007F:D656 0100007F:931D 01 0:0 0:0 0 0 0 5", // a sign in the address
            "   9: 0100007F:D656 0100007F:931D 01 0:0 0:0 0 -1 0 5", // negative uid
            "   9: 0100007F:D656 0100007F:931D 01 0:0 0:0 0 +5 0 5", // a plus sign: `parse` takes it
            "   9: 0100007F:D656 0100007F:931D 01 0:0 0:0 0 5 0 +7", // ... for the inode too
            "   9: 0100007F:D656 0100007F:931D 01 0:0 0:0 0 0 0 x",  // inode not a number
            "   9: 0100007F:D656 0100007F:931D 01 0:0 0:0 0 99999999999 0 5", // uid overflows u32
            "   9: 0100007F:D6 0100007F:931D 01 0:0 0:0 0 0 0 5",    // short port
            "   9: 0100007F D656 0100007F:931D 01 0:0 0:0 0 0 0 5",  // no colon
        ];
        let text = format!("{HEADER}\n{good}\n{}\n", bad_lines.join("\n"));
        let table = parse_proc_net_tcp(&text, None).expect("parses");
        assert_eq!(table.rows.len(), 1);
        assert_eq!(
            table.malformed,
            bad_lines.len() - 1,
            "every non-blank bad line"
        );
    }

    #[test]
    fn only_ascii_white_space_separates_the_fields() {
        // U+0085 (NEL) and the other Unicode spaces are white space to
        // `split_whitespace`; a forged table could use them to shift fields. The
        // kernel writes ASCII, so anything else is a malformed line.
        let good = "   5: 0100007F:D656 0100007F:931D 01 00000000:00000000 00:00000000 00000000     0        0 104052 2 00000000343c1b12 20 0 0 10 -1";
        let nel = good.replacen(' ', "\u{85}", 40);
        let table =
            parse_proc_net_tcp(&format!("{HEADER}\n{good}\n{nel}\n"), None).expect("parses");
        assert_eq!(
            table.rows.len(),
            1,
            "only the ASCII-separated line is a row"
        );
        assert_eq!(table.malformed, 1);
        // The same for the remote-endpoint filter, which looks at the third field.
        let word = u32::from_ne_bytes([127, 0, 0, 1]);
        let forged = format!("   5: {word:08X}:D656\u{a0}{word:08X}:931D 01 0:0 0:0 0 0 0 1");
        let raw = RawTables {
            tcp: format!("{HEADER}\n{forged}\n"),
            tcp6: None,
        };
        let table = parse_tables(&raw, sa(LISTENER)).expect("parses");
        assert!(
            table.rows.is_empty(),
            "the filter did not see a remote endpoint"
        );
        // The filter skipped the line without parsing it; with Unicode white space
        // it would have let it through to the row parser, which counts it as
        // malformed.
        assert_eq!(table.malformed, 0, "skipped by the filter, not counted");
    }

    #[test]
    fn the_remote_filter_skips_other_lines_without_parsing_them() {
        let listener = sa(LISTENER);
        let raw = RawTables {
            tcp: REAL_TCP.to_owned(),
            tcp6: None,
        };
        let table = parse_tables(&raw, listener).expect("parses");
        // Only the client's own row has the listener as its remote end.
        assert_eq!(table.rows, vec![row(CLIENT, LISTENER, 0x01, 0, 104_052)]);
        assert_eq!(table.malformed, 0);

        // A line the filter skips is not counted as malformed even if it is.
        let raw = RawTables {
            tcp: format!("{REAL_TCP}  99: 0100007F:D656 DEADBEEF:0000 garbage\n"),
            tcp6: None,
        };
        assert_eq!(parse_tables(&raw, listener).expect("parses").malformed, 0);
    }

    #[test]
    fn the_filter_spelling_matches_what_the_kernel_prints() {
        let filter = RemoteFilter::for_listener(sa(LISTENER)).expect("ipv4");
        let word = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(filter.tcp, format!("{word:08X}:931D"));
        // The same endpoint in the dual-stack table.
        let mapped = parse_endpoint_v6(&filter.tcp6_mapped).expect("an endpoint");
        assert_eq!(mapped, sa("[::ffff:127.0.0.1]:37661"));
        assert_eq!(RemoteFilter::for_listener(sa("[::1]:80")), None);
        assert_eq!(
            parse_tables(&RawTables::default(), sa("[::1]:80")),
            Err(ParseError::UnsupportedListener)
        );
    }

    #[test]
    fn missing_tcp6_file_is_an_empty_table() {
        let raw = RawTables {
            tcp: REAL_TCP.to_owned(),
            tcp6: None,
        };
        let table = parse_tables(&raw, sa(LISTENER)).expect("a missing tcp6 is not an error");
        assert_eq!(table.rows.len(), 1);
        // And an empty tcp6 with only its header changes nothing.
        let raw = RawTables {
            tcp: REAL_TCP.to_owned(),
            tcp6: Some(format!("{HEADER6}\n")),
        };
        assert_eq!(
            parse_tables(&raw, sa(LISTENER)).expect("parses").rows.len(),
            1
        );
        // A tcp6 that is present but unreadable as a table is an error, not an
        // empty table: refusing is the safe answer.
        let raw = RawTables {
            tcp: REAL_TCP.to_owned(),
            tcp6: Some("not a table".to_owned()),
        };
        assert_eq!(
            parse_tables(&raw, sa(LISTENER)),
            Err(ParseError::UnexpectedHeader)
        );
    }

    #[test]
    fn a_populated_tcp6_table_goes_through_parse_tables() {
        // A dual-stack client of 127.0.0.1:37661 shows up in tcp6 in the mapped
        // form; native IPv6 rows and rows for other listeners are left out. This is
        // the path a machine with IPv6 takes on every request.
        let word = u32::from_ne_bytes([127, 0, 0, 1]);
        let mapped = |port: &str| {
            format!(
                "0000000000000000{:08X}{word:08X}:{port}",
                u32::from_ne_bytes([0, 0, 0xff, 0xff])
            )
        };
        let line = |n: u32, local: &str, remote: &str, state: &str, uid: u32, inode: u32| {
            format!("{n}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  {uid}        0 {inode} 1 0000000000000000 100 0 0 10 0")
        };
        let text = format!(
            "{HEADER6}\n{}\n{}\n{}\n",
            line(0, &mapped("D656"), &mapped("931D"), "01", 1000, 555),
            line(1, &mapped("931D"), &mapped("D656"), "01", 1000, 556),
            line(2, &mapped("D657"), &mapped("2710"), "01", 1000, 557),
        );
        let raw = RawTables {
            tcp: format!("{HEADER}\n"),
            tcp6: Some(text),
        };
        let table = parse_tables(&raw, sa(LISTENER)).expect("a real-shaped tcp6 parses");
        assert_eq!(table.malformed, 0);
        assert_eq!(
            table.rows,
            vec![Row {
                local: sa("[::ffff:127.0.0.1]:54870"),
                remote: sa("[::ffff:127.0.0.1]:37661"),
                state: 1,
                uid: 1000,
                inode: 555,
            }]
        );
        assert_eq!(
            decide_row(&table.rows, &query(CLIENT, LISTENER), 1000),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
    }

    #[test]
    fn a_listener_port_below_0x1000_is_spelled_with_four_digits() {
        // The kernel prints ports as %04X, so 1080 is 0438 and a filter that
        // printed 438 would match no row at all (which refuses every client of a
        // listener on a low port, silently).
        let listener = sa("127.0.0.1:1080");
        let filter = RemoteFilter::for_listener(listener).expect("ipv4");
        assert!(filter.tcp.ends_with(":0438"), "{}", filter.tcp);
        assert!(
            filter.tcp6_mapped.ends_with(":0438"),
            "{}",
            filter.tcp6_mapped
        );
        let word = u32::from_ne_bytes([127, 0, 0, 1]);
        let raw = RawTables {
            tcp: format!(
                "{HEADER}\n   1: {word:08X}:D656 {word:08X}:0438 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0000000000000000 100 0 0 10 0\n"
            ),
            tcp6: None,
        };
        let table = parse_tables(&raw, listener).expect("parses");
        assert_eq!(table.rows.len(), 1);
        assert_eq!(table.rows[0].remote, listener);
        // And port 0x0001 and the highest ports.
        for port in [1_u16, 15, 255, 4095, 4096, 65535] {
            let filter =
                RemoteFilter::for_listener(sa(&format!("127.0.0.1:{port}"))).expect("ipv4");
            assert!(
                filter.tcp.ends_with(&format!(":{port:04X}")),
                "{port}: {}",
                filter.tcp
            );
        }
    }

    #[test]
    fn a_table_over_the_cap_is_not_parsed() {
        let big = format!("{HEADER}\n{}", " ".repeat(MAX_TABLE_BYTES));
        assert_eq!(parse_proc_net_tcp(&big, None), Err(ParseError::TooLarge));
        // Exactly at the cap is read; one byte more is not.
        let header = format!("{HEADER}\n");
        let at_cap = format!("{header}{}", " ".repeat(MAX_TABLE_BYTES - header.len()));
        assert_eq!(at_cap.len(), MAX_TABLE_BYTES);
        assert!(parse_proc_net_tcp(&at_cap, None).is_ok());
        let over = format!("{at_cap} ");
        assert_eq!(parse_proc_net_tcp(&over, None), Err(ParseError::TooLarge));
    }

    // -- decisions ----------------------------------------------------------

    const ME: u32 = 1000;

    fn decide(rows: &[Row]) -> RowDecision {
        decide_row(rows, &query(CLIENT, LISTENER), ME)
    }

    #[test]
    fn a_clear_client_row_decides_by_uid() {
        assert_eq!(
            decide(&[row(CLIENT, LISTENER, 0x01, ME, 42)]),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        assert_eq!(
            decide(&[row(CLIENT, LISTENER, 0x01, ME + 1, 42)]),
            RowDecision::Verdict(PeerVerdict::DifferentUser)
        );
        assert_eq!(
            decide(&[row(CLIENT, LISTENER, 0x01, 0, 42)]),
            RowDecision::Verdict(PeerVerdict::DifferentUser),
            "root is another user unless the daemon is root"
        );
    }

    #[test]
    fn client_row_states_are_exactly_01_04_05() {
        for state in 0_u8..=0x0f {
            let decision = decide(&[row(CLIENT, LISTENER, state, ME, 42)]);
            match state {
                0x01 | 0x04 | 0x05 => {
                    assert_eq!(
                        decision,
                        RowDecision::Verdict(PeerVerdict::SameUser),
                        "{state:02X}"
                    );
                }
                // Another state is a row that exists and is not a connected client.
                _ => {
                    assert_eq!(
                        decision,
                        RowDecision::Verdict(PeerVerdict::Unknown),
                        "{state:02X}"
                    );
                }
            }
        }
    }

    #[test]
    fn server_side_row_is_never_used() {
        // Only the accepted socket's mirror row is present: it is owned by this
        // daemon, and it must neither authorise nor refuse the client.
        let mirror = row(LISTENER, CLIENT, 0x01, ME, 43);
        assert_eq!(decide(&[mirror]), RowDecision::Miss);
        // And next to the real one it changes nothing, whoever it says owns it.
        let client_row = row(CLIENT, LISTENER, 0x01, ME + 7, 42);
        assert_eq!(
            decide(&[mirror, client_row]),
            RowDecision::Verdict(PeerVerdict::DifferentUser)
        );
    }

    #[test]
    fn inode_zero_is_unknown() {
        // An orphan: the client closed completely and the kernel keeps the row
        // (state 05, inode 0); its uid column is not an owner.
        for state in [0x01, 0x04, 0x05] {
            assert_eq!(
                decide(&[row(CLIENT, LISTENER, state, ME, 0)]),
                RowDecision::Verdict(PeerVerdict::Unknown)
            );
        }
    }

    #[test]
    fn identical_duplicate_rows_collapse_conflicting_rows_are_unknown() {
        let a = row(CLIENT, LISTENER, 0x01, ME, 42);
        assert_eq!(
            decide(&[a, a, a]),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        for other in [
            row(CLIENT, LISTENER, 0x01, ME, 43),
            row(CLIENT, LISTENER, 0x01, ME + 1, 42),
            row(CLIENT, LISTENER, 0x05, ME, 42),
        ] {
            assert_eq!(
                decide(&[a, other]),
                RowDecision::Verdict(PeerVerdict::Unknown)
            );
            assert_eq!(
                decide(&[other, a]),
                RowDecision::Verdict(PeerVerdict::Unknown)
            );
        }
    }

    #[test]
    fn no_row_is_a_miss_and_unrelated_rows_do_not_count() {
        assert_eq!(decide(&[]), RowDecision::Miss);
        let rows = [
            row("127.0.0.1:1111", LISTENER, 0x01, ME, 1), // another client
            row(CLIENT, "127.0.0.1:2222", 0x01, ME, 2),   // another listener
            row("127.0.0.2:54870", LISTENER, 0x01, ME, 3), // another client address
            row(CLIENT, "127.0.0.2:37661", 0x01, ME, 4),
        ];
        assert_eq!(decide(&rows), RowDecision::Miss);
    }

    #[test]
    fn a_time_wait_row_does_not_hide_the_live_row_or_replace_it() {
        let live = row(CLIENT, LISTENER, 0x01, ME, 42);
        let old = row(CLIENT, LISTENER, 0x06, 0, 0);
        assert_eq!(
            decide(&[old, live]),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        assert_eq!(
            decide(&[live, old]),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        assert_eq!(decide(&[old]), RowDecision::Verdict(PeerVerdict::Unknown));
    }

    #[test]
    fn the_mapped_spelling_is_the_same_endpoint() {
        // A dual-stack client shows up in tcp6 as ::ffff:127.0.0.1.
        let mapped = row(
            "[::ffff:127.0.0.1]:54870",
            "[::ffff:127.0.0.1]:37661",
            0x01,
            ME,
            42,
        );
        assert_eq!(
            decide(&[mapped]),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        // The accepted socket's own addresses may arrive mapped, too.
        let q = PeerQuery {
            client: sa("[::ffff:127.0.0.1]:54870"),
            listener: sa("[::ffff:127.0.0.1]:37661"),
        };
        let plain = row(CLIENT, LISTENER, 0x01, ME, 42);
        assert_eq!(
            decide_row(&[plain], &q, ME),
            RowDecision::Verdict(PeerVerdict::SameUser)
        );
        // Only the strict mapped range is folded: a different IPv6 address is
        // not made equal to an IPv4 one.
        let lookalike = row(
            "[::127.0.0.1]:54870",
            "[::ffff:127.0.0.1]:37661",
            0x01,
            ME,
            42,
        );
        assert_eq!(decide(&[lookalike]), RowDecision::Miss);
    }

    #[test]
    fn missing_controls_have_stable_codes() {
        assert_eq!(
            MissingControl::IdentityAmbiguous.code(),
            "IDENTITY_AMBIGUOUS"
        );
        assert_eq!(
            MissingControl::PeerSelftestFailed.code(),
            "PEER_SELFTEST_FAILED"
        );
        assert_eq!(
            MissingControl::PeerCheckUnsupported.code(),
            "PEER_CHECK_UNSUPPORTED"
        );
        assert_eq!(no_controls(), Controls::default());
    }

    // -- the real kernel ----------------------------------------------------

    /// The parser against the file the kernel really writes: a loopback
    /// connection made here must be found, with this process's uid and a
    /// non-zero inode. Skips (and says so) where the table is not readable.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_parser_finds_a_real_loopback_connection_in_the_real_table() {
        use std::net::{TcpListener, TcpStream};
        use std::os::unix::fs::MetadataExt;

        let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") else {
            eprintln!("skipped: /proc/net/tcp is not readable here");
            return;
        };
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let listen_addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(listen_addr).expect("connect");
        let client_addr = client.local_addr().expect("addr");
        let (_accepted, _) = listener.accept().expect("accept");
        // The table was read before the connection: read again.
        let tcp_now = std::fs::read_to_string("/proc/net/tcp").unwrap_or(tcp);
        let raw = RawTables {
            tcp: tcp_now,
            tcp6: std::fs::read_to_string("/proc/net/tcp6").ok(),
        };
        let table = parse_tables(&raw, listen_addr).expect("the real table parses");
        assert_eq!(
            table.malformed, 0,
            "every line of the real table is understood"
        );
        let own_uid = std::fs::metadata("/proc/self").expect("self").uid();
        let decision = decide_row(
            &table.rows,
            &PeerQuery {
                client: client_addr,
                listener: listen_addr,
            },
            own_uid,
        );
        assert_eq!(decision, RowDecision::Verdict(PeerVerdict::SameUser));
        // And against a different idea of who we are, the same row is another user's.
        let other = decide_row(
            &table.rows,
            &PeerQuery {
                client: client_addr,
                listener: listen_addr,
            },
            own_uid.wrapping_add(1),
        );
        assert_eq!(other, RowDecision::Verdict(PeerVerdict::DifferentUser));
    }

    // -- the service (C-G7b) --------------------------------------------------------------------

    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    use crate::ingress::types::lock_unpoisoned;

    const OWN: u32 = 1000;

    /// The text of a `/proc/net/tcp` that holds the client rows of `clients` (ports on
    /// 127.0.0.1) connected to `listener`, each owned by `uid`.
    fn table_text(listener: SocketAddr, clients: &[u16], uid: u32) -> String {
        let SocketAddr::V4(listener) = listener else {
            panic!("an IPv4 listener");
        };
        let word = |ip: Ipv4Addr| u32::from_ne_bytes(ip.octets());
        let mut text = String::from(HEADER);
        text.push('\n');
        for (n, port) in clients.iter().enumerate() {
            text.push_str(&format!(
                "  {n}: {:08X}:{:04X} {:08X}:{:04X} 01 00000000:00000000 00:00000000 00000000 {uid:5}        0 {} 1 0000000000000000 20 0 0 10 -1\n",
                word(Ipv4Addr::LOCALHOST),
                port,
                word(*listener.ip()),
                listener.port(),
                10_000 + n
            ));
        }
        text
    }

    fn raw(text: String) -> RawTables {
        RawTables {
            tcp: text,
            tcp6: None,
        }
    }

    /// A source that counts its reads and hands out whatever `make` builds.
    #[derive(Clone)]
    struct Counting {
        reads: Arc<AtomicUsize>,
        make: Arc<dyn Fn(usize) -> io::Result<RawTables> + Send + Sync>,
        delay: Duration,
    }

    impl Counting {
        fn new(make: impl Fn(usize) -> io::Result<RawTables> + Send + Sync + 'static) -> Self {
            Self {
                reads: Arc::new(AtomicUsize::new(0)),
                make: Arc::new(make),
                delay: Duration::ZERO,
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl TableSource for Counting {
        fn read(&mut self) -> io::Result<RawTables> {
            let n = self.reads.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            (self.make)(n)
        }
    }

    fn listener() -> SocketAddr {
        sa("127.0.0.1:10800")
    }

    fn client_query(port: u16) -> PeerQuery {
        PeerQuery {
            client: sa(&format!("127.0.0.1:{port}")),
            listener: listener(),
        }
    }

    fn service(source: impl TableSource, tuning: ServiceTuning) -> PeerTableService {
        PeerTableService::start(source, OWN, tuning).expect("starts")
    }

    #[tokio::test]
    async fn a_connection_with_a_row_gets_its_owner_s_verdict() {
        let source = Counting::new(|_| Ok(raw(table_text(listener(), &[40001], OWN))));
        let svc = service(source.clone(), ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::SameUser
        );
        let other = Counting::new(|_| Ok(raw(table_text(listener(), &[40001], 4242))));
        let svc = service(other, ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::DifferentUser
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_service_batches_concurrent_requests() {
        let ports: Vec<u16> = (40_000..40_100).collect();
        let text = table_text(listener(), &ports, OWN);
        let mut source = Counting::new(move |_| Ok(raw(text.clone())));
        // A slow first read, so that the others queue behind it.
        source.delay = Duration::from_millis(60);
        let svc = Arc::new(service(source.clone(), ServiceTuning::DEFAULT));
        let mut tasks = Vec::new();
        for port in ports {
            let svc = Arc::clone(&svc);
            tasks.push(tokio::spawn(async move {
                svc.authorize(client_query(port)).await
            }));
        }
        for task in tasks {
            assert_eq!(task.await.expect("joined"), PeerVerdict::SameUser);
        }
        // One read for the first request, one for the rest that queued behind it.
        assert!(
            source.reads() <= 2,
            "{} reads for 100 requests",
            source.reads()
        );
        assert_eq!(svc.stats().rereads, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn snapshot_rate_is_bounded_under_flood() {
        let text = table_text(listener(), &[40001], OWN);
        let source = Counting::new(move |_| Ok(raw(text.clone())));
        let svc = Arc::new(service(source.clone(), ServiceTuning::DEFAULT));
        let began = Instant::now();
        let mut tasks = Vec::new();
        // Eight callers asking one after the other for 400 ms.
        for _ in 0..8 {
            let svc = Arc::clone(&svc);
            tasks.push(tokio::spawn(async move {
                let mut answered = 0_u32;
                while began.elapsed() < Duration::from_millis(400) {
                    assert_eq!(
                        svc.authorize(client_query(40001)).await,
                        PeerVerdict::SameUser
                    );
                    answered += 1;
                }
                answered
            }));
        }
        let mut total = 0;
        for task in tasks {
            total += task.await.expect("joined");
        }
        let elapsed = began.elapsed();
        // One read at most per 20 ms, plus the first.
        let allowed = usize::try_from(elapsed.as_millis() / 20).expect("fits") + 2;
        assert!(
            source.reads() <= allowed,
            "{} reads in {elapsed:?}",
            source.reads()
        );
        assert!(total > 20, "{total} answers: the flood was served");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_miss_is_read_again_once_and_shared_by_every_miss_of_the_batch() {
        // Read 0 is slow and only knows the blocker, so that the three requests
        // below queue behind it and are served as one batch. Read 1 does not know
        // them yet; read 2, the shared re-read, does.
        let blocker = table_text(listener(), &[40000], OWN);
        let without = table_text(listener(), &[], OWN);
        let with = table_text(listener(), &[40001, 40002, 40003], OWN);
        let source = Counting::new(move |n| {
            Ok(raw(match n {
                0 => {
                    std::thread::sleep(Duration::from_millis(80));
                    blocker.clone()
                }
                1 => without.clone(),
                _ => with.clone(),
            }))
        });
        let svc = Arc::new(service(source.clone(), ServiceTuning::DEFAULT));
        let first = {
            let svc = Arc::clone(&svc);
            tokio::spawn(async move { svc.authorize(client_query(40000)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (a, b, c) = tokio::join!(
            svc.authorize(client_query(40001)),
            svc.authorize(client_query(40002)),
            svc.authorize(client_query(40003))
        );
        assert_eq!(first.await.expect("joined"), PeerVerdict::SameUser);
        assert_eq!([a, b, c], [PeerVerdict::SameUser; 3]);
        assert_eq!(
            source.reads(),
            3,
            "the blocker, the batch, one shared re-read"
        );
        assert_eq!((svc.stats().snapshots, svc.stats().rereads), (2, 1));
    }

    #[tokio::test]
    async fn a_connection_that_never_gets_a_row_is_unknown_after_exactly_one_reread() {
        let source = Counting::new(|_| Ok(raw(table_text(listener(), &[], OWN))));
        let svc = service(source.clone(), ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        assert_eq!(source.reads(), 2);
    }

    #[tokio::test]
    async fn a_source_that_fails_makes_every_request_unknown() {
        let source = Counting::new(|_| Err(io::Error::other("no table")));
        let svc = service(source.clone(), ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        assert_eq!(svc.stats().source_errors, 1);
        assert_eq!(source.reads(), 1, "an error is not a miss: no re-read");
    }

    #[tokio::test]
    async fn a_table_over_the_cap_is_unknown() {
        let big = "x".repeat(MAX_TABLE_BYTES + 1);
        let source = Counting::new(move |_| Ok(raw(big.clone())));
        let svc = service(source.clone(), ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        assert_eq!(source.reads(), 1, "a table that cannot be read is no miss");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_source_is_unknown_at_the_timeout_and_a_full_queue_at_once() {
        let mut source = Counting::new(|_| Ok(raw(table_text(listener(), &[40001], OWN))));
        source.delay = Duration::from_millis(400);
        let tuning = ServiceTuning {
            timeout: Duration::from_millis(100),
            queue: 2,
            ..ServiceTuning::DEFAULT
        };
        let svc = Arc::new(service(source, tuning));
        // The first is taken by the thread and keeps it busy; two more fill the queue.
        let busy = {
            let svc = Arc::clone(&svc);
            tokio::spawn(async move { svc.authorize(client_query(40001)).await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        let queued: Vec<_> = (0..2)
            .map(|_| {
                let svc = Arc::clone(&svc);
                tokio::spawn(async move { svc.authorize(client_query(40001)).await })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let began = Instant::now();
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        assert!(
            began.elapsed() < Duration::from_millis(60),
            "refused at once"
        );
        assert_eq!(svc.stats().queue_full, 1);
        assert_eq!(
            busy.await.expect("joined"),
            PeerVerdict::Unknown,
            "timed out"
        );
        for task in queued {
            assert_eq!(task.await.expect("joined"), PeerVerdict::Unknown);
        }
        assert!(svc.stats().timeouts >= 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_caller_that_gave_up_is_not_served() {
        let mut source = Counting::new(|_| Ok(raw(table_text(listener(), &[40001], OWN))));
        source.delay = Duration::from_millis(150);
        let tuning = ServiceTuning {
            timeout: Duration::from_millis(40),
            ..ServiceTuning::DEFAULT
        };
        let svc = service(source.clone(), tuning);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        // Queued behind the slow read and abandoned before the thread looks at it.
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(svc.stats().abandoned, 1);
        assert_eq!(source.reads(), 1, "the abandoned request cost no read");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_listeners_in_one_batch_are_each_filtered_for_their_own() {
        let other: SocketAddr = sa("127.0.0.1:10801");
        let mut text = table_text(listener(), &[40001], OWN);
        let second = table_text(other, &[40002], 4242);
        text.push_str(second.split_once('\n').map_or("", |(_, rest)| rest));
        let mut source = Counting::new(move |_| Ok(raw(text.clone())));
        // A slow first read, so that the two requests below queue behind it and are
        // served together.
        source.delay = Duration::from_millis(80);
        let svc = Arc::new(service(source.clone(), ServiceTuning::DEFAULT));
        let blocker = {
            let svc = Arc::clone(&svc);
            tokio::spawn(async move { svc.authorize(client_query(40001)).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let (a, b) = tokio::join!(
            svc.authorize(client_query(40001)),
            svc.authorize(PeerQuery {
                client: sa("127.0.0.1:40002"),
                listener: other
            })
        );
        assert_eq!(blocker.await.expect("joined"), PeerVerdict::SameUser);
        assert_eq!((a, b), (PeerVerdict::SameUser, PeerVerdict::DifferentUser));
        assert_eq!(source.reads(), 2, "the two shared one read");
    }

    /// A source that notes when each read began.
    fn timed(delay: Duration, rows: String) -> (Counting, Arc<Mutex<Vec<Instant>>>) {
        let starts: Arc<Mutex<Vec<Instant>>> = Arc::default();
        let log = Arc::clone(&starts);
        let mut source = Counting::new(move |_| {
            lock_unpoisoned(&log).push(Instant::now());
            Ok(raw(rows.clone()))
        });
        source.delay = delay;
        (source, starts)
    }

    #[test]
    fn the_defaults_are_the_documented_pacing() {
        let tuning = ServiceTuning::default();
        assert_eq!(tuning, ServiceTuning::DEFAULT);
        assert_eq!(tuning.timeout, Duration::from_millis(500));
        assert_eq!((tuning.queue, tuning.batch), (256, 256));
        assert_eq!(tuning.min_interval, Duration::from_millis(20));
        assert_eq!(tuning.reread_after, Duration::from_millis(5));
    }

    #[tokio::test]
    async fn the_next_snapshot_rests_twice_as_long_as_the_last_one_took() {
        let (source, starts) = timed(
            Duration::from_millis(60),
            table_text(listener(), &[40001], OWN),
        );
        let tuning = ServiceTuning {
            min_interval: Duration::from_millis(1),
            ..ServiceTuning::DEFAULT
        };
        let svc = service(source, tuning);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::SameUser
        );
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::SameUser
        );
        let starts = lock_unpoisoned(&starts).clone();
        assert_eq!(starts.len(), 2);
        let gap = starts[1].duration_since(starts[0]);
        // 60 ms of reading and then a rest of 2 x 60 ms: a third of the time at most.
        assert!(
            gap >= Duration::from_millis(175),
            "{gap:?}: 60 ms + 2 x 60 ms"
        );
    }

    #[tokio::test]
    async fn the_interval_has_a_floor_however_fast_the_table_is_read() {
        let (source, starts) = timed(Duration::ZERO, table_text(listener(), &[40001], OWN));
        let tuning = ServiceTuning {
            min_interval: Duration::from_millis(50),
            ..ServiceTuning::DEFAULT
        };
        let svc = service(source, tuning);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::SameUser
        );
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::SameUser
        );
        let starts = lock_unpoisoned(&starts).clone();
        let gap = starts[1].duration_since(starts[0]);
        assert!(gap >= Duration::from_millis(48), "{gap:?}");
    }

    #[tokio::test]
    async fn a_miss_is_read_again_only_after_the_wait() {
        let (source, starts) = timed(Duration::ZERO, table_text(listener(), &[], OWN));
        let tuning = ServiceTuning {
            reread_after: Duration::from_millis(80),
            ..ServiceTuning::DEFAULT
        };
        let svc = service(source, tuning);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        let starts = lock_unpoisoned(&starts).clone();
        assert_eq!(starts.len(), 2);
        let gap = starts[1].duration_since(starts[0]);
        assert!(gap >= Duration::from_millis(75), "{gap:?}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_batch_never_holds_more_requests_than_its_cap() {
        let ports: Vec<u16> = (40_000..40_005).collect();
        let (mut source, _) = timed(Duration::ZERO, table_text(listener(), &ports, OWN));
        // The first read is slow, so that all five are queued behind it.
        source.delay = Duration::from_millis(80);
        // The service rests twice as long as it read between snapshots (80 + 160 +
        // 80 + 160 + 80 ms here), which is longer than a caller's default wait.
        let tuning = ServiceTuning {
            batch: 2,
            min_interval: Duration::from_millis(1),
            timeout: Duration::from_secs(10),
            ..ServiceTuning::DEFAULT
        };
        let svc = Arc::new(service(source.clone(), tuning));
        let tasks: Vec<_> = ports
            .iter()
            .map(|port| {
                let svc = Arc::clone(&svc);
                let port = *port;
                tokio::spawn(async move { svc.authorize(client_query(port)).await })
            })
            .collect();
        for task in tasks {
            assert_eq!(task.await.expect("joined"), PeerVerdict::SameUser);
        }
        // 1 + 2 + 2: five requests in batches of at most two.
        assert!(source.reads() >= 3, "{} reads", source.reads());
    }

    #[tokio::test]
    async fn a_source_that_panics_leaves_every_caller_unknown_and_the_service_refusing() {
        struct Panicking;
        impl TableSource for Panicking {
            fn read(&mut self) -> io::Result<RawTables> {
                panic!("the table source was told to panic");
            }
        }
        let svc = service(Panicking, ServiceTuning::DEFAULT);
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        // The thread is gone; nobody is let in on a guess.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let began = Instant::now();
        assert_eq!(
            svc.authorize(client_query(40001)).await,
            PeerVerdict::Unknown
        );
        assert!(
            began.elapsed() < Duration::from_millis(100),
            "refused at once"
        );
    }

    #[test]
    fn dropping_the_service_ends_its_thread() {
        let source = Counting::new(|_| Ok(raw(String::new())));
        let reads = Arc::clone(&source.reads);
        let svc = service(source, ServiceTuning::DEFAULT);
        drop(svc);
        std::thread::sleep(Duration::from_millis(50));
        // The thread held the only other reference to the counter's owner; once it
        // ended, ours is the last.
        assert_eq!(Arc::strong_count(&reads), 1);
    }

    // -- the real table ---------------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::io::Write as _;
        use std::net::{Shutdown, TcpListener, TcpStream};

        fn own_uid() -> u32 {
            rustix::process::getuid().as_raw()
        }

        fn connected() -> (TcpListener, TcpStream, TcpStream, PeerQuery) {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            let listen_addr = listener.local_addr().expect("addr");
            let client = TcpStream::connect(listen_addr).expect("connect");
            let (accepted, _) = listener.accept().expect("accept");
            let query = PeerQuery {
                client: client.local_addr().expect("client addr"),
                listener: accepted.local_addr().expect("listener addr"),
            };
            (listener, client, accepted, query)
        }

        #[tokio::test]
        async fn a_real_loopback_client_is_the_same_user() {
            let svc =
                PeerTableService::start(ProcTableSource::new(), own_uid(), ServiceTuning::DEFAULT)
                    .expect("starts");
            let (_listener, client, _accepted, query) = connected();
            assert_eq!(svc.authorize(query).await, PeerVerdict::SameUser);
            // A client that has written its request and half-closed is still served.
            let mut client = client;
            client.write_all(b"hello").expect("write");
            client.shutdown(Shutdown::Write).expect("shutdown");
            assert_eq!(svc.authorize(query).await, PeerVerdict::SameUser);
        }

        #[tokio::test]
        async fn a_client_that_has_gone_is_never_the_same_user() {
            let svc =
                PeerTableService::start(ProcTableSource::new(), own_uid(), ServiceTuning::DEFAULT)
                    .expect("starts");
            let (_listener, client, _accepted, query) = connected();
            drop(client);
            // An orphan row (inode 0), a row in another state, or no row at all.
            assert_eq!(svc.authorize(query).await, PeerVerdict::Unknown);
        }

        #[tokio::test]
        async fn the_other_users_connection_is_a_different_user() {
            // Only root can run a helper as another uid.
            if rustix::process::geteuid().as_raw() != 0 {
                eprintln!("skipped: not root");
                return;
            }
            use std::os::unix::process::CommandExt as _;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
            let port = listener.local_addr().expect("addr").port();
            let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}; read -t 5 -u 3 _");
            let mut helper = match std::process::Command::new("bash")
                .arg("-c")
                .arg(script)
                .uid(65534)
                .spawn()
            {
                Ok(child) => child,
                Err(error) => {
                    eprintln!("skipped: cannot run a helper as uid 65534: {error}");
                    return;
                }
            };
            let accepted = listener.accept().map(|(stream, _)| stream);
            let Ok(accepted) = accepted else {
                helper.kill().ok();
                eprintln!("skipped: the helper did not connect");
                return;
            };
            let query = PeerQuery {
                client: accepted.peer_addr().expect("peer"),
                listener: accepted.local_addr().expect("local"),
            };
            let svc =
                PeerTableService::start(ProcTableSource::new(), own_uid(), ServiceTuning::DEFAULT)
                    .expect("starts");
            let verdict = svc.authorize(query).await;
            helper.kill().ok();
            helper.wait().ok();
            assert_eq!(verdict, PeerVerdict::DifferentUser);
        }

        #[test]
        fn the_self_test_passes_on_this_machine() {
            let mut source = ProcTableSource::new();
            assert_eq!(selftest(&mut source, own_uid()), Ok(()));
        }

        #[test]
        fn the_self_test_wants_an_established_row_not_just_a_clear_one() {
            // State 05 is a row the lookup accepts (a half-closed client), but the
            // self-test's connection is open: any other state means the table is not
            // telling the truth about it.
            struct HalfClosed;
            impl TableSource for HalfClosed {
                fn read(&mut self) -> io::Result<RawTables> {
                    let mut real = ProcTableSource::new().read()?;
                    real.tcp = real.tcp.replace(" 01 ", " 05 ");
                    Ok(real)
                }
            }
            assert_eq!(
                selftest(&mut HalfClosed, own_uid()),
                Err(MissingControl::PeerSelftestFailed)
            );
        }

        #[test]
        fn the_self_test_fails_when_the_table_does_not_carry_the_owner() {
            // Another identity than the one that made the connection.
            let mut source = ProcTableSource::new();
            assert_eq!(
                selftest(&mut source, own_uid().wrapping_add(1)),
                Err(MissingControl::PeerSelftestFailed)
            );
            // A table that does not exist.
            let mut missing = ProcTableSource::at("/nonexistent/tcp", "/nonexistent/tcp6");
            assert_eq!(
                selftest(&mut missing, own_uid()),
                Err(MissingControl::PeerSelftestFailed)
            );
            // A table in a layout this parser does not know is not trusted.
            struct OtherLayout;
            impl TableSource for OtherLayout {
                fn read(&mut self) -> io::Result<RawTables> {
                    let mut real = ProcTableSource::new().read()?;
                    real.tcp = real.tcp.replacen("rem_address", "elsewhere", 1);
                    Ok(real)
                }
            }
            assert_eq!(
                selftest(&mut OtherLayout, own_uid()),
                Err(MissingControl::PeerSelftestFailed)
            );
            // Neither is one with a line of the connection's own shape that does not
            // parse: every ESTABLISHED line is repeated with a state that is not hex.
            struct Garbled;
            impl TableSource for Garbled {
                fn read(&mut self) -> io::Result<RawTables> {
                    let mut real = ProcTableSource::new().read()?;
                    let extra: String = real
                        .tcp
                        .lines()
                        .skip(1)
                        .filter(|line| line.contains(" 01 "))
                        .map(|line| format!("{}\n", line.replace(" 01 ", " 0Z ")))
                        .collect();
                    real.tcp.push_str(&extra);
                    Ok(real)
                }
            }
            assert_eq!(
                selftest(&mut Garbled, own_uid()),
                Err(MissingControl::PeerSelftestFailed)
            );
        }
    }

    #[test]
    fn the_proc_source_reads_both_files_and_treats_a_missing_tcp6_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tcp = dir.path().join("tcp");
        std::fs::write(&tcp, HEADER).expect("write");
        let mut source = ProcTableSource::at(&tcp, dir.path().join("absent6"));
        let raw = source.read().expect("reads");
        assert_eq!(raw.tcp, HEADER);
        assert_eq!(raw.tcp6, None);
        let tcp6 = dir.path().join("tcp6");
        std::fs::write(&tcp6, HEADER6).expect("write");
        let mut both = ProcTableSource::at(&tcp, &tcp6);
        assert_eq!(both.read().expect("reads").tcp6.as_deref(), Some(HEADER6));
        // A tcp6 that is there and cannot be read is an error, not an empty table.
        let unreadable = dir.path().join("dir6");
        std::fs::create_dir(&unreadable).expect("mkdir");
        let mut bad6 = ProcTableSource::at(&tcp, &unreadable);
        assert!(bad6.read().is_err());
        // A missing IPv4 table is an error, not an empty one.
        let mut none = ProcTableSource::at(dir.path().join("absent"), &tcp6);
        assert!(none.read().is_err());
    }

    #[test]
    fn a_table_over_the_cap_is_read_to_one_byte_past_it_and_no_further() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tcp = dir.path().join("tcp");
        let file = std::fs::File::create(&tcp).expect("create");
        file.set_len(u64::try_from(MAX_TABLE_BYTES).expect("fits") * 2)
            .expect("sparse");
        // A sparse file of NULs is valid UTF-8; the cap stops the read.
        let mut source = ProcTableSource::at(&tcp, dir.path().join("absent6"));
        let raw = source.read().expect("reads");
        assert_eq!(raw.tcp.len(), MAX_TABLE_BYTES + 1);
        assert_eq!(
            parse_tables(&raw, sa("127.0.0.1:10800")).err(),
            Some(ParseError::TooLarge)
        );
    }
}
