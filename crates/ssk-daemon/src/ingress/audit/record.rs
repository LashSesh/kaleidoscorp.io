//! The format of the ingress flow ledger (design 6.4.2, 6.4.3): the records, one
//! line per record, the hash chain, and the bounded reader.
//!
//! One record per line: `<64-hex entry_hash> <body_json>` and a line feed.
//! `entry_hash = blake3(prev_hash_hex ++ body_json_bytes)` over the stored bytes;
//! the first record of a chain has the literal `genesis` as its previous hash.
//! The body is compact `serde_json` output, which contains no raw line feed even
//! when a string field does (a line feed is written as the two characters
//! backslash and `n`), so a string cannot smuggle a second record into a line.
//!
//! What the ledger says is what Kaleidoscorp decided and did. It never asserts a
//! property of the network path. Integrity is PREFIX integrity only: deleting the
//! newest records, or truncating at a record boundary, verifies; the status
//! publishes `(entries, head)` so an operator can keep an out-of-band
//! checkpoint.
//!
//! Only validated values reach a record (design R-L1): every string of a record
//! must be printable ASCII of bounded length, and a host or an address must be in
//! the canonical alphabet of `target::canonicalize`. A value that is not is
//! refused at encode time and never written.

use std::collections::BTreeMap;
use std::io::{self, BufRead};

use serde::{Deserialize, Serialize};

use crate::ingress::types::{
    AddrRef, ConfigFingerprint, DestRef, DestinationLogging, Observation, Resolution,
    ResultOutcome, RuleTable, Unresolved,
};

/// The version of this format. A ledger whose `Started` record carries a larger
/// number is not read and nothing is appended to it.
pub const LEDGER_FORMAT: u32 = 1;

/// The previous hash of the first record of a chain.
pub const GENESIS: &str = "genesis";

/// The longest body a record may have. The writer refuses a larger one
/// (`RecordTooLarge`, which never trips the gate).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// A hash is 64 lowercase hex characters, then one space, then the body.
const HASH_HEX_LEN: usize = 64;
const HEADER_LEN: usize = 65;

/// The longest line a reader accepts, line feed not counted: header plus the
/// largest body. A longer one is corrupt, so a tampered file cannot make a
/// verifier allocate without bound.
pub const MAX_LINE_BYTES: usize = HEADER_LEN + MAX_RECORD_BYTES;

/// The longest string any field of a record may hold. Hosts are at most 253
/// characters and the rest are short codes; this is the ceiling for all of them.
const MAX_STRING_CHARS: usize = 512;

/// One line of the ledger. `seq` is authoritative; `ts_ms` is an untrusted wall
/// clock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowAuditRecord {
    pub seq: u64,
    pub ts_ms: u64,
    /// `ingress:b<seq of the governing Started>:<n>`; empty for records that do
    /// not belong to a flow.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow_id: String,
    #[serde(flatten)]
    pub event: FlowAuditEvent,
}

/// A key that was refused repeatedly, as a `Summary` names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepeatCount {
    pub profile: String,
    pub host: String,
    pub port: u16,
    pub reason: String,
    pub rule: Option<String>,
    pub count: u64,
}

/// What happened. The tag is the `event` field of the line.
///
/// Closed vocabularies inside (`cause`, `reason`, `reason_code`, `error_code`,
/// `refusal`, `route`) are strings in the record and enums where they are
/// produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FlowAuditEvent {
    /// The first record of every daemon boot and of every re-open after a trip.
    /// `unresolved_before` is computed while the chain is verified at open and
    /// can be recomputed by any verifier.
    Started {
        daemon_version: String,
        ledger_format: u32,
        config: ConfigFingerprint,
        destination_logging: DestinationLogging,
        dest_key_id: Option<String>,
        unresolved_before: Unresolved,
    },
    /// Written before `Started` when a torn tail was truncated or the ledger was
    /// re-opened after a trip.
    Recovered {
        truncated_tail_bytes: u64,
        unresolved: Unresolved,
        after_trip: Option<String>,
    },
    Armed {
        profile: String,
        /// `operator` or `config_autostart`.
        cause: String,
        /// `cli`, `desktop`, `config` or `unknown`.
        client: String,
        /// `uid:<n>`, `sid:<sid>`, `config` or `unknown`.
        requested_by: String,
        epoch: u64,
        profile_digest: String,
        rules: RuleTable,
        observations: Vec<Observation>,
    },
    Disarmed {
        cause: String,
        epoch: u64,
    },
    /// Best effort and bounded; cannot exist for an audit write failure.
    Tripped {
        reason: String,
        epoch: u64,
    },
    /// Refused, nothing dialled. `dest` is always `Plain`: a refusal is evidence.
    Denied {
        peer: String,
        peer_verified: bool,
        dest: DestRef,
        target_provenance: String,
        /// `ipv4`, `ipv6` or `name`.
        target_kind: String,
        profile: String,
        matched_rule: Option<String>,
        reason_code: String,
        route: Option<String>,
        coalesced: bool,
    },
    /// The proxy authorised the destination under the named rule and a dial is
    /// about to start. Durable before the dial.
    Pending {
        peer: String,
        peer_verified: bool,
        dest: DestRef,
        target_provenance: String,
        target_kind: String,
        resolution: Resolution,
        profile: String,
        matched_rule: Option<String>,
        route: String,
        planned_adapters: Vec<String>,
    },
    /// Durable before the success reply and before any application byte.
    Result {
        outcome: ResultOutcome,
        error_code: Option<String>,
        /// The static label of an address refusal, never an address.
        refusal: Option<String>,
        chain_kinds: Vec<String>,
        dialed: Option<AddrRef>,
        /// At most eight, in start order.
        attempted: Vec<AddrRef>,
        answers: Option<u8>,
        observations: Vec<Observation>,
    },
    Closed {
        bytes_up: u64,
        bytes_down: u64,
        duration_ms: u64,
        reason: String,
    },
    Summary {
        window_ms: u64,
        pre_admission_rejects: BTreeMap<String, u64>,
        denials_suppressed: BTreeMap<String, u64>,
        denials_over_quota: BTreeMap<String, u64>,
        /// The most repeated keys, at most sixteen.
        denials_repeated: Vec<RepeatCount>,
        other_keys: u64,
    },
    Continue {
        prev_segment_head: String,
        prev_seq: u64,
        pruned_before_seq: Option<u64>,
        prune_deferred: u32,
        refusals_unrecorded: u64,
    },
}

impl FlowAuditEvent {
    /// The value of the `event` field, for counters and tests.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Started { .. } => "started",
            Self::Recovered { .. } => "recovered",
            Self::Armed { .. } => "armed",
            Self::Disarmed { .. } => "disarmed",
            Self::Tripped { .. } => "tripped",
            Self::Denied { .. } => "denied",
            Self::Pending { .. } => "pending",
            Self::Result { .. } => "result",
            Self::Closed { .. } => "closed",
            Self::Summary { .. } => "summary",
            Self::Continue { .. } => "continue",
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// The body is larger than [`MAX_RECORD_BYTES`].
    RecordTooLarge,
    /// A field holds a value that may not be written; the string names the field
    /// by its kind, never by its content.
    InvalidField(&'static str),
    /// Serialising failed (not reachable for these types).
    Serialize,
}

/// A record ready to be appended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedLine {
    /// The entry hash of this record: the previous hash of the next one.
    pub hash: String,
    /// `<hash> <body>` and the line feed.
    pub bytes: Vec<u8>,
}

/// `blake3(prev ++ body)` as 64 lowercase hex characters.
#[must_use]
pub fn chain_hash(prev: &str, body: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev.as_bytes());
    hasher.update(body);
    hasher.finalize().to_hex().to_string()
}

fn printable(text: &str) -> bool {
    text.chars().count() <= MAX_STRING_CHARS && text.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Every string of the record must be printable ASCII of bounded length, so that
/// no control character, bidirectional control or look-alike ever reaches the
/// file, whatever produced the value.
fn all_strings_printable(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => printable(text),
        serde_json::Value::Array(items) => items.iter().all(all_strings_printable),
        serde_json::Value::Object(map) => map
            .iter()
            .all(|(key, value)| printable(key) && all_strings_printable(value)),
        _ => true,
    }
}

fn host_alphabet(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b':')
}

fn plain_host_ok(host: &str) -> bool {
    !host.is_empty() && host.len() <= 253 && host.bytes().all(host_alphabet)
}

/// A resolved address in its one spelling: what `IpAddr` prints, and never the
/// mapped IPv6 form (the dial unmaps it first).
fn plain_ip_ok(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok_and(|parsed| {
        parsed.to_string() == ip
            && !matches!(parsed, std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
    })
}

fn hex_ok(text: &str, len: usize) -> bool {
    text.len() == len
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn dest_ok(dest: &DestRef) -> bool {
    match dest {
        DestRef::Plain { host, .. } => plain_host_ok(host),
        DestRef::Hashed { kid, token, .. } => hex_ok(kid, 16) && hex_ok(token, 32),
    }
}

fn addr_ok(addr: &AddrRef) -> bool {
    match addr {
        AddrRef::Plain { ip, .. } => plain_ip_ok(ip),
        AddrRef::Hashed { kid, token, .. } => hex_ok(kid, 16) && hex_ok(token, 32),
    }
}

/// The checks that need to know what a field is.
fn fields_ok(event: &FlowAuditEvent) -> Result<(), EncodeError> {
    let bad = |what: &'static str| Err(EncodeError::InvalidField(what));
    match event {
        FlowAuditEvent::Denied { dest, .. } => {
            // A refusal is written in the clear, whatever the setting.
            if !matches!(dest, DestRef::Plain { .. }) {
                return bad("denied destination must be plain");
            }
            if !dest_ok(dest) {
                return bad("destination");
            }
        }
        FlowAuditEvent::Pending { dest, .. } if !dest_ok(dest) => {
            return bad("destination");
        }
        FlowAuditEvent::Result {
            dialed, attempted, ..
        } => {
            if !dialed.iter().chain(attempted.iter()).all(addr_ok) {
                return bad("address");
            }
            if attempted.len() > 8 {
                return bad("too many attempted addresses");
            }
        }
        FlowAuditEvent::Summary {
            denials_repeated, ..
        } => {
            if denials_repeated.len() > 16 {
                return bad("too many repeated keys");
            }
            if !denials_repeated.iter().all(|r| plain_host_ok(&r.host)) {
                return bad("repeated host");
            }
        }
        _ => {}
    }
    Ok(())
}

/// Turns a record into the line that follows `prev_hash` in the chain.
pub fn encode_line(prev_hash: &str, record: &FlowAuditRecord) -> Result<EncodedLine, EncodeError> {
    let value = serde_json::to_value(record).map_err(|_| EncodeError::Serialize)?;
    if !all_strings_printable(&value) {
        return Err(EncodeError::InvalidField("string"));
    }
    fields_ok(&record.event)?;
    if !flow_id_ok(&record.flow_id) {
        return Err(EncodeError::InvalidField("flow id"));
    }
    let body = serde_json::to_vec(record).map_err(|_| EncodeError::Serialize)?;
    if body.len() > MAX_RECORD_BYTES {
        return Err(EncodeError::RecordTooLarge);
    }
    let hash = chain_hash(prev_hash, &body);
    let mut bytes = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()).saturating_add(1));
    bytes.extend_from_slice(hash.as_bytes());
    bytes.push(b' ');
    bytes.extend_from_slice(&body);
    bytes.push(b'\n');
    Ok(EncodedLine { hash, bytes })
}

fn flow_id_ok(flow_id: &str) -> bool {
    flow_id.is_empty()
        || flow_id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b':' | b'-' | b'_' | b'.')
        })
}

// ---------------------------------------------------------------------------
// Decoding and the chain
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The line is not `<64 hex> <body>`.
    Malformed,
    /// The body is not a record this build knows.
    UnknownRecord,
    /// The recomputed hash differs from the stored one: the line, or an earlier
    /// one, was changed, removed or reordered.
    HashMismatch,
    /// `seq` is not the one that follows the previous record.
    SeqGap { expected: u64, found: u64 },
    /// `seq` cannot be followed: the counter is exhausted.
    SeqExhausted,
    /// The `Started` record was written by a newer format. Nothing may be
    /// appended to this ledger.
    UnsupportedFormat { found: u32 },
    /// A `Started` record that claims format 0.
    InvalidFormat,
}

/// A line that parsed and whose hash was recomputed from the stored bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLine {
    pub hash: String,
    pub record: FlowAuditRecord,
}

fn lower_hex64(bytes: &[u8]) -> bool {
    bytes.len() == HASH_HEX_LEN
        && bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// Parses one line (line feed removed) and checks its hash against `prev_hash`.
pub fn decode_line(prev_hash: &str, line: &[u8]) -> Result<DecodedLine, ChainError> {
    let (hash, rest) = line
        .split_at_checked(HASH_HEX_LEN)
        .ok_or(ChainError::Malformed)?;
    let (space, body) = rest.split_at_checked(1).ok_or(ChainError::Malformed)?;
    // A record is a JSON object and the writer emits nothing before it: a body
    // that does not start with `{` is not a line of this ledger.
    if !lower_hex64(hash)
        || space != b" "
        || body.len() > MAX_RECORD_BYTES
        || body.first() != Some(&b'{')
    {
        return Err(ChainError::Malformed);
    }
    let hash = std::str::from_utf8(hash).map_err(|_| ChainError::Malformed)?;
    // The hash is over the stored bytes, so a body that is not exactly what was
    // hashed is a mismatch before it is a parse question.
    if chain_hash(prev_hash, body) != hash {
        return Err(ChainError::HashMismatch);
    }
    let record: FlowAuditRecord =
        serde_json::from_slice(body).map_err(|_| ChainError::UnknownRecord)?;
    Ok(DecodedLine {
        hash: hash.to_owned(),
        record,
    })
}

/// What the next line's `seq` must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// Not prescribed: the first line of a segment says where the segment starts.
    Any,
    Seq(u64),
    /// The last representable `seq` was accepted; nothing can follow.
    End,
}

/// Where a verification stands: the hash the next line must follow and the
/// `seq` it must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    prev_hash: String,
    expect: Expect,
}

impl Chain {
    /// A new chain: the first line follows `genesis`, and its `seq` is not
    /// prescribed (a segment says where it starts in its name).
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            prev_hash: GENESIS.to_owned(),
            expect: Expect::Any,
        }
    }

    /// The first line must carry `first_seq`.
    #[must_use]
    pub fn genesis_at(first_seq: u64) -> Self {
        Self {
            prev_hash: GENESIS.to_owned(),
            expect: Expect::Seq(first_seq),
        }
    }

    /// Continues a chain whose last record had hash `head` and sequence number
    /// `last_seq`.
    #[must_use]
    pub fn resume(head: String, last_seq: u64) -> Self {
        Self {
            prev_hash: head,
            expect: last_seq.checked_add(1).map_or(Expect::End, Expect::Seq),
        }
    }

    /// The hash the next line must follow.
    #[must_use]
    pub fn head(&self) -> &str {
        &self.prev_hash
    }

    /// The sequence number the next line must carry, when one is prescribed.
    #[must_use]
    pub fn next_seq(&self) -> Option<u64> {
        match self.expect {
            Expect::Seq(seq) => Some(seq),
            Expect::Any | Expect::End => None,
        }
    }

    /// `true` once the last representable sequence number has been accepted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.expect == Expect::End
    }

    /// Verifies the next line and moves past it. On an error the chain is
    /// unchanged.
    pub fn accept(&mut self, line: &[u8]) -> Result<FlowAuditRecord, ChainError> {
        let decoded = decode_line(&self.prev_hash, line)?;
        match self.expect {
            Expect::End => return Err(ChainError::SeqExhausted),
            Expect::Seq(expected) if decoded.record.seq != expected => {
                return Err(ChainError::SeqGap {
                    expected,
                    found: decoded.record.seq,
                });
            }
            Expect::Seq(_) | Expect::Any => {}
        }
        if let FlowAuditEvent::Started { ledger_format, .. } = &decoded.record.event {
            match *ledger_format {
                0 => return Err(ChainError::InvalidFormat),
                found if found > LEDGER_FORMAT => {
                    return Err(ChainError::UnsupportedFormat { found });
                }
                _ => {}
            }
        }
        // The last representable sequence number is accepted as a record; the
        // chain cannot go past it, and the writer treats that as a trip.
        self.expect = decoded
            .record
            .seq
            .checked_add(1)
            .map_or(Expect::End, Expect::Seq);
        self.prev_hash = decoded.hash;
        Ok(decoded.record)
    }
}

// ---------------------------------------------------------------------------
// The bounded reader
// ---------------------------------------------------------------------------

/// What one call to [`read_line_bounded`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineRead {
    /// End of input with nothing pending.
    Eof,
    /// A complete line (without its line feed) is in the buffer.
    Line,
    /// Input ended in the middle of a line: the torn tail of a crashed write.
    /// The bytes are in the buffer.
    TornTail,
    /// The line is longer than [`MAX_LINE_BYTES`]. The stream position is
    /// undefined afterwards; the file is corrupt.
    TooLong,
}

/// Reads one line into `line` without ever holding more than
/// [`MAX_LINE_BYTES`] of it.
pub fn read_line_bounded<R: BufRead + ?Sized>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<LineRead> {
    line.clear();
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if line.is_empty() {
                LineRead::Eof
            } else {
                LineRead::TornTail
            });
        }
        let newline = chunk.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(chunk.len());
        if line.len().saturating_add(take) > MAX_LINE_BYTES {
            return Ok(LineRead::TooLong);
        }
        line.extend_from_slice(chunk.get(..take).unwrap_or_default());
        match newline {
            Some(_) => {
                reader.consume(take.saturating_add(1));
                return Ok(LineRead::Line);
            }
            None => reader.consume(take),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::types::HostKind;
    use proptest::prelude::*;
    use ssk_config::fingerprint::RuleRow;
    use std::io::Cursor;

    // -- samples ------------------------------------------------------------

    fn fingerprint() -> ConfigFingerprint {
        ConfigFingerprint {
            version: 1,
            config: "a".repeat(64),
            routing: "b".repeat(64),
            ingress: "c".repeat(64),
        }
    }

    fn plain_dest(host: &str) -> DestRef {
        DestRef::Plain {
            host: host.into(),
            port: 443,
        }
    }

    fn hashed_dest() -> DestRef {
        DestRef::Hashed {
            kid: "0123456789abcdef".into(),
            kind: HostKind::Name,
            token: "00112233445566778899aabbccddeeff".into(),
            port: 443,
        }
    }

    fn obs(kind: &str, value: &str) -> Observation {
        Observation::new(kind, value).expect("a closed kind")
    }

    /// One record of every kind, with every optional part present once and absent
    /// once, and the largest numbers.
    fn every_variant() -> Vec<FlowAuditEvent> {
        vec![
            FlowAuditEvent::Started {
                daemon_version: "0.1.0".into(),
                ledger_format: LEDGER_FORMAT,
                config: fingerprint(),
                destination_logging: DestinationLogging::Hashed,
                dest_key_id: Some("0123456789abcdef".into()),
                unresolved_before: Unresolved {
                    pending: u64::MAX,
                    open_tunnels: 3,
                },
            },
            FlowAuditEvent::Started {
                daemon_version: "0.1.0".into(),
                ledger_format: LEDGER_FORMAT,
                config: fingerprint(),
                destination_logging: DestinationLogging::Plain,
                dest_key_id: None,
                unresolved_before: Unresolved::default(),
            },
            FlowAuditEvent::Recovered {
                truncated_tail_bytes: 17,
                unresolved: Unresolved {
                    pending: 1,
                    open_tunnels: 0,
                },
                after_trip: Some("audit_write_failed".into()),
            },
            FlowAuditEvent::Recovered {
                truncated_tail_bytes: 0,
                unresolved: Unresolved::default(),
                after_trip: None,
            },
            FlowAuditEvent::Armed {
                profile: "work".into(),
                cause: "operator".into(),
                client: "desktop".into(),
                requested_by: "uid:1000".into(),
                epoch: u64::MAX,
                profile_digest: "d".repeat(64),
                rules: RuleTable {
                    total: 2,
                    truncated: false,
                    rules: vec![
                        RuleRow {
                            id: "rule-1".into(),
                            priority: 10,
                            action: "deny".into(),
                            attestation: false,
                            exact_destination: true,
                            suffix: false,
                            port: Some(443),
                        },
                        RuleRow {
                            id: "rule-2".into(),
                            priority: u32::MAX,
                            action: "adapter:exit".into(),
                            attestation: true,
                            exact_destination: false,
                            suffix: true,
                            port: None,
                        },
                    ],
                },
                observations: vec![
                    obs("os_route_if", "Ethernet 2"),
                    obs("egress_local", "192.0.2.7"),
                ],
            },
            FlowAuditEvent::Disarmed {
                cause: "arm_superseded".into(),
                epoch: 7,
            },
            FlowAuditEvent::Tripped {
                reason: "listener_died".into(),
                epoch: 8,
            },
            FlowAuditEvent::Denied {
                peer: "uid:1000".into(),
                peer_verified: true,
                dest: plain_dest("blocked.example"),
                target_provenance: "client_supplied_name".into(),
                target_kind: "name".into(),
                profile: "work".into(),
                matched_rule: Some("rule-1".into()),
                reason_code: "RULE_DENY".into(),
                route: None,
                coalesced: true,
            },
            FlowAuditEvent::Denied {
                peer: "unverified".into(),
                peer_verified: false,
                dest: plain_dest("2001:db8::1"),
                target_provenance: "client_supplied_literal".into(),
                target_kind: "ipv6".into(),
                profile: "work".into(),
                matched_rule: None,
                reason_code: "SPECIAL_USE_NEEDS_EXACT_RULE".into(),
                route: Some("deny".into()),
                coalesced: false,
            },
            FlowAuditEvent::Pending {
                peer: "uid:1000".into(),
                peer_verified: true,
                dest: hashed_dest(),
                target_provenance: "client_supplied_name".into(),
                target_kind: "name".into(),
                resolution: Resolution::LocalPinned,
                profile: "work".into(),
                matched_rule: Some("rule-2".into()),
                route: "direct".into(),
                planned_adapters: vec!["exit".into(), "second".into()],
            },
            FlowAuditEvent::Pending {
                peer: "uid:1000".into(),
                peer_verified: true,
                dest: plain_dest("93.184.216.34"),
                target_provenance: "client_supplied_literal".into(),
                target_kind: "ipv4".into(),
                resolution: Resolution::Literal,
                profile: "work".into(),
                matched_rule: None,
                route: "direct".into(),
                planned_adapters: Vec::new(),
            },
            FlowAuditEvent::Result {
                outcome: ResultOutcome::Connected,
                error_code: None,
                refusal: None,
                chain_kinds: vec!["socks5".into(), "tls_tunnel".into()],
                dialed: Some(AddrRef::Plain {
                    ip: "93.184.216.34".into(),
                    port: 443,
                }),
                attempted: vec![
                    AddrRef::Plain {
                        ip: "2606:4700::1".into(),
                        port: 443,
                    },
                    AddrRef::Hashed {
                        kid: "0123456789abcdef".into(),
                        kind: HostKind::Ipv4,
                        token: "00112233445566778899aabbccddeeff".into(),
                        port: 443,
                    },
                ],
                answers: Some(2),
                observations: vec![obs("egress_local", "192.0.2.7")],
            },
            FlowAuditEvent::Result {
                outcome: ResultOutcome::Failed,
                error_code: Some("NETCORE_ADDR_REFUSED".into()),
                refusal: Some("private".into()),
                chain_kinds: Vec::new(),
                dialed: None,
                attempted: Vec::new(),
                answers: None,
                observations: Vec::new(),
            },
            FlowAuditEvent::Closed {
                bytes_up: u64::MAX,
                bytes_down: 0,
                duration_ms: 123_456,
                reason: "idle_timeout".into(),
            },
            FlowAuditEvent::Summary {
                window_ms: 300_000,
                pre_admission_rejects: [("refused_peer".to_owned(), 4)].into(),
                denials_suppressed: [
                    ("RULE_DENY".to_owned(), 9),
                    ("SPECIAL_USE_NEEDS_EXACT_RULE".to_owned(), 2),
                ]
                .into(),
                denials_over_quota: BTreeMap::new(),
                denials_repeated: vec![RepeatCount {
                    profile: "work".into(),
                    host: "ads.example".into(),
                    port: 443,
                    reason: "RULE_DENY".into(),
                    rule: Some("rule-1".into()),
                    count: 9,
                }],
                other_keys: 2,
            },
            FlowAuditEvent::Continue {
                prev_segment_head: "e".repeat(64),
                prev_seq: 104_856,
                pruned_before_seq: Some(1),
                prune_deferred: 0,
                refusals_unrecorded: 5,
            },
            FlowAuditEvent::Continue {
                prev_segment_head: "e".repeat(64),
                prev_seq: 1,
                pruned_before_seq: None,
                prune_deferred: u32::MAX,
                refusals_unrecorded: 0,
            },
        ]
    }

    fn record(seq: u64, event: FlowAuditEvent) -> FlowAuditRecord {
        FlowAuditRecord {
            seq,
            ts_ms: 1_700_000_000_000,
            flow_id: "ingress:b1:5".into(),
            event,
        }
    }

    fn started(seq: u64, format: u32) -> FlowAuditRecord {
        FlowAuditRecord {
            seq,
            ts_ms: 0,
            flow_id: String::new(),
            event: FlowAuditEvent::Started {
                daemon_version: "0.1.0".into(),
                ledger_format: format,
                config: fingerprint(),
                destination_logging: DestinationLogging::Plain,
                dest_key_id: None,
                unresolved_before: Unresolved::default(),
            },
        }
    }

    /// A chain of records as the bytes of a file.
    fn file_of(records: &[FlowAuditRecord]) -> Vec<u8> {
        let mut prev = GENESIS.to_owned();
        let mut out = Vec::new();
        for record in records {
            let line = encode_line(&prev, record).expect("encodes");
            out.extend_from_slice(&line.bytes);
            prev = line.hash;
        }
        out
    }

    fn lines(file: &[u8]) -> Vec<Vec<u8>> {
        file.split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect()
    }

    // -- round trips ----------------------------------------------------------

    #[test]
    fn flatten_round_trip_for_every_event_variant() {
        let mut kinds = std::collections::BTreeSet::new();
        for (n, event) in every_variant().into_iter().enumerate() {
            let record = record(u64::try_from(n).expect("small") + 1, event);
            let line = encode_line(GENESIS, &record).expect("encodes");
            let body = line
                .bytes
                .get(HEADER_LEN..line.bytes.len() - 1)
                .expect("body");
            // The body is the record and nothing else, in the documented shape.
            let value: serde_json::Value = serde_json::from_slice(body).expect("json");
            assert_eq!(value["event"], record.event.kind());
            assert_eq!(value["seq"], record.seq);
            let decoded = decode_line(GENESIS, line.bytes.strip_suffix(b"\n").expect("newline"))
                .expect("decodes");
            assert_eq!(decoded.record, record, "variant {n}");
            assert_eq!(decoded.hash, line.hash);
            kinds.insert(record.event.kind());
        }
        assert_eq!(
            kinds.len(),
            11,
            "every kind of record is covered: {kinds:?}"
        );
    }

    #[test]
    fn the_line_is_hash_space_body_newline_and_nothing_else() {
        let line = encode_line(GENESIS, &started(1, LEDGER_FORMAT)).expect("encodes");
        let (hash, rest) = line.bytes.split_at(64);
        assert!(lower_hex64(hash));
        assert_eq!(rest.first(), Some(&b' '));
        assert_eq!(line.bytes.last(), Some(&b'\n'));
        assert_eq!(line.bytes.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(hash, line.hash.as_bytes());
        // The hash is blake3 over the previous hash and the stored body.
        let body = &line.bytes[65..line.bytes.len() - 1];
        let mut expected = blake3::Hasher::new();
        expected.update(b"genesis");
        expected.update(body);
        assert_eq!(line.hash, expected.finalize().to_hex().to_string());
    }

    #[test]
    fn the_body_is_compact_and_keeps_the_documented_field_order() {
        let line = encode_line(
            GENESIS,
            &record(
                9,
                FlowAuditEvent::Disarmed {
                    cause: "operator".into(),
                    epoch: 3,
                },
            ),
        )
        .expect("encodes");
        let body = std::str::from_utf8(&line.bytes[65..line.bytes.len() - 1]).expect("utf-8");
        assert_eq!(
            body,
            r#"{"seq":9,"ts_ms":1700000000000,"flow_id":"ingress:b1:5","event":"disarmed","cause":"operator","epoch":3}"#
        );
        // A record without a flow carries no flow_id at all.
        let line = encode_line(GENESIS, &started(1, 1)).expect("encodes");
        assert!(!std::str::from_utf8(&line.bytes)
            .expect("utf-8")
            .contains("flow_id"));
    }

    #[test]
    fn golden_started_line() {
        // Pins the persisted shape of the first record of every boot: the field
        // names, their order, and the hash. A change here is a format change.
        let line = encode_line(GENESIS, &started(1, 1)).expect("encodes");
        let body = std::str::from_utf8(&line.bytes[65..line.bytes.len() - 1]).expect("utf-8");
        let expected_body = format!(
            r#"{{"seq":1,"ts_ms":0,"event":"started","daemon_version":"0.1.0","ledger_format":1,"config":{{"version":1,"config":"{a}","routing":"{b}","ingress":"{c}"}},"destination_logging":"plain","dest_key_id":null,"unresolved_before":{{"pending":0,"open_tunnels":0}}}}"#,
            a = "a".repeat(64),
            b = "b".repeat(64),
            c = "c".repeat(64),
        );
        assert_eq!(body, expected_body);
        assert_eq!(line.hash, chain_hash(GENESIS, expected_body.as_bytes()));
    }

    // -- the hash chain -------------------------------------------------------

    #[test]
    fn a_chain_of_every_variant_verifies_and_reproduces_its_head() {
        let records: Vec<_> = every_variant()
            .into_iter()
            .enumerate()
            .map(|(n, event)| record(u64::try_from(n).expect("small") + 1, event))
            .collect();
        let file = file_of(&records);
        let mut chain = Chain::genesis_at(1);
        let mut read = Vec::new();
        for line in lines(&file) {
            read.push(chain.accept(&line).expect("verifies"));
        }
        assert_eq!(read, records);
        assert_eq!(
            chain.next_seq(),
            Some(u64::try_from(records.len()).expect("small") + 1)
        );
        // Resuming at the head continues the same chain.
        let mut resumed = Chain::resume(
            chain.head().to_owned(),
            u64::try_from(records.len()).expect("small"),
        );
        let next = record(
            u64::try_from(records.len()).expect("small") + 1,
            FlowAuditEvent::Disarmed {
                cause: "operator".into(),
                epoch: 1,
            },
        );
        let line = encode_line(chain.head(), &next).expect("encodes");
        assert_eq!(
            resumed.accept(line.bytes.strip_suffix(b"\n").expect("newline")),
            Ok(next)
        );
    }

    #[test]
    fn tamper_table() {
        let records = vec![
            started(1, 1),
            record(
                2,
                FlowAuditEvent::Disarmed {
                    cause: "operator".into(),
                    epoch: 1,
                },
            ),
            record(
                3,
                FlowAuditEvent::Tripped {
                    reason: "listener_died".into(),
                    epoch: 2,
                },
            ),
            record(
                4,
                FlowAuditEvent::Disarmed {
                    cause: "shutdown".into(),
                    epoch: 3,
                },
            ),
        ];
        let file = file_of(&records);
        let good = lines(&file);
        let verify = |lines: &[Vec<u8>]| -> Result<usize, (usize, ChainError)> {
            let mut chain = Chain::genesis_at(1);
            for (n, line) in lines.iter().enumerate() {
                chain.accept(line).map_err(|e| (n, e))?;
            }
            Ok(lines.len())
        };
        assert_eq!(verify(&good), Ok(4));

        // A byte of a body changed.
        let mut edited = good.clone();
        let at = edited[1].len() - 3;
        edited[1][at] ^= 0x01;
        assert_eq!(verify(&edited), Err((1, ChainError::HashMismatch)));

        // A record removed from the middle: the next one no longer links.
        let mut removed = good.clone();
        removed.remove(1);
        assert!(matches!(
            verify(&removed),
            Err((1, ChainError::HashMismatch))
        ));

        // Two records swapped.
        let mut swapped = good.clone();
        swapped.swap(1, 2);
        assert!(matches!(
            verify(&swapped),
            Err((1, ChainError::HashMismatch))
        ));

        // A record repeated.
        let mut repeated = good.clone();
        repeated.insert(2, good[1].clone());
        assert!(matches!(
            verify(&repeated),
            Err((2, ChainError::HashMismatch))
        ));

        // The first record replaced by another that is valid on its own.
        let mut replaced = good.clone();
        replaced[0] = lines(&file_of(&[started(1, 1), started(2, 1)]))[1].clone();
        assert!(verify(&replaced).is_err());

        // A forged record appended with a hash that does not follow the head.
        let mut forged = good.clone();
        let line = encode_line(
            "genesis",
            &record(
                5,
                FlowAuditEvent::Disarmed {
                    cause: "operator".into(),
                    epoch: 4,
                },
            ),
        )
        .expect("encodes");
        forged.push(line.bytes.strip_suffix(b"\n").expect("newline").to_vec());
        assert_eq!(verify(&forged), Err((4, ChainError::HashMismatch)));

        // A forged record with a correct hash for the wrong sequence number.
        let mut head = Chain::genesis_at(1);
        for line in &good {
            head.accept(line).expect("verifies");
        }
        let skip = encode_line(
            head.head(),
            &record(
                9,
                FlowAuditEvent::Disarmed {
                    cause: "operator".into(),
                    epoch: 4,
                },
            ),
        )
        .expect("encodes");
        let mut gap = head.clone();
        assert_eq!(
            gap.accept(skip.bytes.strip_suffix(b"\n").expect("newline")),
            Err(ChainError::SeqGap {
                expected: 5,
                found: 9
            })
        );
        assert_eq!(gap, head, "an error leaves the chain where it was");

        // The hash itself replaced by another valid-looking one.
        let mut rehashed = good.clone();
        rehashed[2][..64].copy_from_slice("0".repeat(64).as_bytes());
        assert_eq!(verify(&rehashed), Err((2, ChainError::HashMismatch)));

        // Prefix integrity only, and said so: dropping the newest records verifies.
        assert_eq!(verify(&good[..2]), Ok(2));
        assert_eq!(verify(&good[..1]), Ok(1));
        assert_eq!(verify(&[]), Ok(0));
    }

    #[test]
    fn a_line_that_is_not_hash_space_body_is_malformed() {
        let line = encode_line(GENESIS, &started(1, 1)).expect("encodes");
        let good = line.bytes.strip_suffix(b"\n").expect("newline").to_vec();
        let mut chain = Chain::genesis();
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("short", good[..60].to_vec()),
            ("no body", good[..65].to_vec()),
            ("tab for the space", {
                let mut l = good.clone();
                l[64] = b'\t';
                l
            }),
            ("upper-case hash", {
                let mut l = good.clone();
                l[0] = l[0].to_ascii_uppercase();
                if l[0] == good[0] {
                    l[0] = b'A';
                }
                l
            }),
            ("non-hex hash", {
                let mut l = good.clone();
                l[10] = b'g';
                l
            }),
            ("two spaces", {
                let mut l = good[..64].to_vec();
                l.extend_from_slice(b"  ");
                l.extend_from_slice(&good[65..]);
                l
            }),
        ];
        for (name, bytes) in cases {
            assert_eq!(chain.accept(&bytes), Err(ChainError::Malformed), "{name}");
        }
        // A body that is JSON for something else, with a correct hash, is an
        // unknown record and not a crash.
        let body = br#"{"seq":1,"ts_ms":0,"event":"from_the_future","x":1}"#;
        let mut forged = chain_hash(GENESIS, body).into_bytes();
        forged.push(b' ');
        forged.extend_from_slice(body);
        assert_eq!(chain.accept(&forged), Err(ChainError::UnknownRecord));
        let body = b"{not json at all";
        let mut forged = chain_hash(GENESIS, body).into_bytes();
        forged.push(b' ');
        forged.extend_from_slice(body);
        assert_eq!(chain.accept(&forged), Err(ChainError::UnknownRecord));
    }

    #[test]
    fn unsupported_ledger_format_is_refused() {
        // A ledger written by a newer build says so in its Started record, and a
        // verifier of this build refuses it instead of reading it as format 1.
        let newer = encode_line(GENESIS, &started(1, LEDGER_FORMAT + 1)).expect("encodes");
        let mut chain = Chain::genesis();
        assert_eq!(
            chain.accept(newer.bytes.strip_suffix(b"\n").expect("newline")),
            Err(ChainError::UnsupportedFormat {
                found: LEDGER_FORMAT + 1
            })
        );
        assert_eq!(chain, Chain::genesis(), "nothing was accepted");
        let huge = encode_line(GENESIS, &started(1, u32::MAX)).expect("encodes");
        assert_eq!(
            Chain::genesis().accept(huge.bytes.strip_suffix(b"\n").expect("newline")),
            Err(ChainError::UnsupportedFormat { found: u32::MAX })
        );
        let zero = encode_line(GENESIS, &started(1, 0)).expect("encodes");
        assert_eq!(
            Chain::genesis().accept(zero.bytes.strip_suffix(b"\n").expect("newline")),
            Err(ChainError::InvalidFormat)
        );
        // The current format is accepted, including in the middle of a chain.
        let ok = file_of(&[started(1, 1), started(2, 1)]);
        let mut chain = Chain::genesis_at(1);
        for line in lines(&ok) {
            chain.accept(&line).expect("verifies");
        }
    }

    #[test]
    fn the_format_version_is_one() {
        // A change of this number is a change of the persisted format and needs a
        // paragraph in docs/COMPATIBILITY_MATRIX.md; this is the test that fails.
        assert_eq!(LEDGER_FORMAT, 1);
        assert_eq!(GENESIS, "genesis");
        assert_eq!(MAX_RECORD_BYTES, 64 * 1024);
        assert_eq!(MAX_LINE_BYTES, 64 + 1 + 64 * 1024);
    }

    #[test]
    fn a_newer_format_is_refused_wherever_its_started_record_sits() {
        // Every boot and every re-open writes a Started record, so one can appear
        // in the middle of a chain: a verifier that looked only at the first line
        // would read a ledger that a newer build continued as if it were its own.
        let file = file_of(&[started(1, 1), started(2, 1), started(3, LEDGER_FORMAT + 1)]);
        let all = lines(&file);
        let mut chain = Chain::genesis_at(1);
        assert!(chain.accept(&all[0]).is_ok());
        assert!(chain.accept(&all[1]).is_ok());
        assert_eq!(
            chain.accept(&all[2]),
            Err(ChainError::UnsupportedFormat {
                found: LEDGER_FORMAT + 1
            })
        );
        // Also when the chain started at some other sequence number.
        let file = file_of(&[started(50, 0)]);
        assert_eq!(
            Chain::genesis_at(50).accept(&lines(&file)[0]),
            Err(ChainError::InvalidFormat)
        );
    }

    #[test]
    fn the_last_sequence_number_is_a_record_and_the_end_of_the_chain() {
        let last = record(
            u64::MAX,
            FlowAuditEvent::Disarmed {
                cause: "shutdown".into(),
                epoch: 1,
            },
        );
        let line = encode_line("a".repeat(64).as_str(), &last).expect("encodes");
        let mut chain = Chain::resume("a".repeat(64), u64::MAX - 1);
        assert_eq!(
            chain.accept(line.bytes.strip_suffix(b"\n").expect("newline")),
            Ok(last)
        );
        assert_eq!(chain.next_seq(), None, "nothing can follow");
        assert_eq!(Chain::resume("a".repeat(64), u64::MAX).next_seq(), None);
    }

    // -- what may be written --------------------------------------------------

    #[test]
    fn ledger_line_has_exactly_one_newline_for_any_string() {
        // Strings with line feeds, U+2028 and every control character cannot be
        // written at all; the ones that can are single-line by construction.
        for hostile in [
            "a\nb",
            "a\r\nb",
            "x\u{2028}y",
            "x\u{2029}y",
            "a\0b",
            "tab\there",
            "\u{7f}",
            "\u{202e}rtl",
            "caf\u{e9}",
            "emoji \u{1f600}",
        ] {
            let record = record(
                1,
                FlowAuditEvent::Disarmed {
                    cause: hostile.into(),
                    epoch: 1,
                },
            );
            assert_eq!(
                encode_line(GENESIS, &record),
                Err(EncodeError::InvalidField("string")),
                "{hostile:?}"
            );
            let mut as_flow = started(1, 1);
            as_flow.flow_id = hostile.into();
            assert!(
                encode_line(GENESIS, &as_flow).is_err(),
                "{hostile:?} as a flow id"
            );
        }
        // The serializer itself never emits a raw line feed, which is what makes
        // a refusal here defence in depth and not the only line of defence.
        let body = serde_json::to_vec(&record(
            1,
            FlowAuditEvent::Disarmed {
                cause: "a\nb\u{2028}c".into(),
                epoch: 1,
            },
        ))
        .expect("json");
        assert!(!body.contains(&b'\n'));
    }

    #[test]
    fn a_string_longer_than_the_ceiling_is_refused() {
        let disarmed = |cause: String| record(1, FlowAuditEvent::Disarmed { cause, epoch: 1 });
        assert!(encode_line(GENESIS, &disarmed("a".repeat(MAX_STRING_CHARS))).is_ok());
        assert_eq!(
            encode_line(GENESIS, &disarmed("a".repeat(MAX_STRING_CHARS + 1))),
            Err(EncodeError::InvalidField("string"))
        );
        // Keys of the maps of a summary are strings too.
        let summary = |key: String| {
            record(
                1,
                FlowAuditEvent::Summary {
                    window_ms: 1,
                    pre_admission_rejects: [(key, 1)].into(),
                    denials_suppressed: BTreeMap::new(),
                    denials_over_quota: BTreeMap::new(),
                    denials_repeated: Vec::new(),
                    other_keys: 0,
                },
            )
        };
        assert!(encode_line(GENESIS, &summary("refused_peer".into())).is_ok());
        assert_eq!(
            encode_line(GENESIS, &summary("bad\nkey".into())),
            Err(EncodeError::InvalidField("string"))
        );
    }

    #[test]
    fn only_canonical_hosts_and_addresses_reach_a_record() {
        let pending = |dest: DestRef| {
            record(
                1,
                FlowAuditEvent::Pending {
                    peer: "uid:1".into(),
                    peer_verified: true,
                    dest,
                    target_provenance: "client_supplied_name".into(),
                    target_kind: "name".into(),
                    resolution: Resolution::ProxyResolved,
                    profile: "work".into(),
                    matched_rule: None,
                    route: "direct".into(),
                    planned_adapters: Vec::new(),
                },
            )
        };
        assert!(encode_line(GENESIS, &pending(plain_dest("example.com"))).is_ok());
        assert!(encode_line(GENESIS, &pending(plain_dest("2001:db8::1"))).is_ok());
        for host in [
            "",
            "Example.com",
            "exa mple.com",
            "a_b.example",
            "a/b",
            "a%b",
            "a@b",
            "[::1]",
            "caf\u{e9}.example",
            &"a".repeat(254),
        ] {
            // Non-ASCII text is refused by the general string rule before the
            // host rule is asked; either way nothing is written.
            let expected = if host.is_ascii() {
                "destination"
            } else {
                "string"
            };
            assert_eq!(
                encode_line(GENESIS, &pending(plain_dest(host))),
                Err(EncodeError::InvalidField(expected)),
                "{host:?}"
            );
        }
        // A hashed destination must really be a key id and a token.
        for (kid, token) in [
            ("short", "00112233445566778899aabbccddeeff"),
            ("0123456789abcdef", "tooshort"),
            ("0123456789ABCDEF", "00112233445566778899aabbccddeeff"),
            ("0123456789abcdef", "00112233445566778899aabbccddeefg"),
        ] {
            let dest = DestRef::Hashed {
                kid: kid.into(),
                kind: HostKind::Name,
                token: token.into(),
                port: 1,
            };
            assert!(
                encode_line(GENESIS, &pending(dest)).is_err(),
                "{kid} {token}"
            );
        }
    }

    #[test]
    fn a_denial_is_always_written_in_the_clear() {
        let denied = |dest: DestRef| {
            record(
                1,
                FlowAuditEvent::Denied {
                    peer: "uid:1".into(),
                    peer_verified: true,
                    dest,
                    target_provenance: "client_supplied_name".into(),
                    target_kind: "name".into(),
                    profile: "work".into(),
                    matched_rule: None,
                    reason_code: "RULE_DENY".into(),
                    route: None,
                    coalesced: false,
                },
            )
        };
        assert!(encode_line(GENESIS, &denied(plain_dest("example.com"))).is_ok());
        assert_eq!(
            encode_line(GENESIS, &denied(hashed_dest())),
            Err(EncodeError::InvalidField(
                "denied destination must be plain"
            ))
        );
    }

    #[test]
    fn a_denied_destination_is_validated_like_any_other() {
        let denied = |host: &str| {
            record(
                1,
                FlowAuditEvent::Denied {
                    peer: "uid:1".into(),
                    peer_verified: true,
                    dest: plain_dest(host),
                    target_provenance: "client_supplied_name".into(),
                    target_kind: "name".into(),
                    profile: "work".into(),
                    matched_rule: None,
                    reason_code: "RULE_DENY".into(),
                    route: None,
                    coalesced: false,
                },
            )
        };
        for host in ["Bad Host", "UPPER.example", "a_b", "", "a/b"] {
            assert_eq!(
                encode_line(GENESIS, &denied(host)),
                Err(EncodeError::InvalidField("destination")),
                "{host:?}"
            );
        }
    }

    #[test]
    fn a_flow_id_has_the_shape_of_a_flow_id() {
        for ok in ["", "ingress:b1:5", "ingress:b12345:678"] {
            let mut r = started(1, 1);
            r.flow_id = ok.into();
            assert!(encode_line(GENESIS, &r).is_ok(), "{ok:?}");
        }
        for bad in [
            "Ingress:b1:5",
            "ingress/b1/5",
            "ingress b1 5",
            "ingress:b1:5;",
            "INGRESS",
            "a\"b",
            "a,b",
        ] {
            let mut r = started(1, 1);
            r.flow_id = bad.into();
            assert_eq!(
                encode_line(GENESIS, &r),
                Err(EncodeError::InvalidField("flow id")),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn result_addresses_are_canonical_and_bounded() {
        let result = |dialed: Option<AddrRef>, attempted: Vec<AddrRef>| {
            record(
                1,
                FlowAuditEvent::Result {
                    outcome: ResultOutcome::Failed,
                    error_code: None,
                    refusal: None,
                    chain_kinds: Vec::new(),
                    dialed,
                    attempted,
                    answers: None,
                    observations: Vec::new(),
                },
            )
        };
        let plain = |ip: &str| AddrRef::Plain {
            ip: ip.into(),
            port: 1,
        };
        assert!(encode_line(
            GENESIS,
            &result(Some(plain("93.184.216.34")), vec![plain("2606:4700::1")])
        )
        .is_ok());
        for bad in [
            "",
            "example.com",
            "93.184.216.034",
            "2606:4700:0:0:0:0:0:1",
            "::FFFF:1.2.3.4",
            "::ffff:1.2.3.4",
            "1.2.3.4 ",
            "1.2.3",
        ] {
            assert!(
                encode_line(GENESIS, &result(Some(plain(bad)), Vec::new())).is_err(),
                "{bad:?}"
            );
            assert!(
                encode_line(GENESIS, &result(None, vec![plain(bad)])).is_err(),
                "{bad:?} attempted"
            );
        }
        let nine: Vec<AddrRef> = (0..9).map(|n| plain(&format!("93.184.216.{n}"))).collect();
        assert_eq!(
            encode_line(GENESIS, &result(None, nine.clone())),
            Err(EncodeError::InvalidField("too many attempted addresses"))
        );
        assert!(encode_line(GENESIS, &result(None, nine[..8].to_vec())).is_ok());
    }

    #[test]
    fn a_summary_names_at_most_sixteen_keys() {
        let key = |n: u32| RepeatCount {
            profile: "work".into(),
            host: format!("h{n}.example"),
            port: 443,
            reason: "RULE_DENY".into(),
            rule: None,
            count: 2,
        };
        let summary = |keys: Vec<RepeatCount>| {
            record(
                1,
                FlowAuditEvent::Summary {
                    window_ms: 1,
                    pre_admission_rejects: BTreeMap::new(),
                    denials_suppressed: BTreeMap::new(),
                    denials_over_quota: BTreeMap::new(),
                    denials_repeated: keys,
                    other_keys: 0,
                },
            )
        };
        assert!(encode_line(GENESIS, &summary((0..16).map(key).collect())).is_ok());
        assert_eq!(
            encode_line(GENESIS, &summary((0..17).map(key).collect())),
            Err(EncodeError::InvalidField("too many repeated keys"))
        );
        let mut bad = key(1);
        bad.host = "Not Canonical".into();
        assert_eq!(
            encode_line(GENESIS, &summary(vec![bad])),
            Err(EncodeError::InvalidField("repeated host"))
        );
    }

    #[test]
    fn the_largest_record_is_written_and_one_byte_more_is_refused() {
        // A record whose body is exactly MAX_RECORD_BYTES: rows are added until the
        // next would not fit, then the id of the last row is padded to the byte.
        let build = |rows: usize, pad: usize| {
            record(
                1,
                FlowAuditEvent::Armed {
                    profile: "p".into(),
                    cause: "operator".into(),
                    client: "cli".into(),
                    requested_by: "uid:1".into(),
                    epoch: 1,
                    profile_digest: "d".repeat(64),
                    rules: RuleTable {
                        total: 1,
                        truncated: false,
                        rules: (0..rows)
                            .map(|n| RuleRow {
                                id: if n + 1 == rows {
                                    format!("r{n}{}", "x".repeat(pad))
                                } else {
                                    format!("r{n}")
                                },
                                priority: 1,
                                action: "deny".into(),
                                attestation: false,
                                exact_destination: false,
                                suffix: false,
                                port: None,
                            })
                            .collect(),
                    },
                    observations: Vec::new(),
                },
            )
        };
        let size =
            |rows: usize, pad: usize| serde_json::to_vec(&build(rows, pad)).expect("json").len();
        let mut rows = 1;
        while size(rows + 1, 0) <= MAX_RECORD_BYTES {
            rows += 1;
        }
        let pad = MAX_RECORD_BYTES - size(rows, 0);
        assert!(pad < MAX_STRING_CHARS, "the padding fits a string: {pad}");
        assert_eq!(size(rows, pad), MAX_RECORD_BYTES, "exactly at the limit");

        let at_limit = encode_line(GENESIS, &build(rows, pad)).expect("exactly the limit fits");
        assert_eq!(
            at_limit.bytes.len(),
            MAX_LINE_BYTES + 1,
            "header, body and the line feed"
        );
        // The reader accepts the longest line the writer can produce ...
        let mut reader = Cursor::new(at_limit.bytes.clone());
        let mut line = Vec::new();
        assert_eq!(
            read_line_bounded(&mut reader, &mut line).expect("reads"),
            LineRead::Line
        );
        assert_eq!(Chain::genesis_at(1).accept(&line).map(|r| r.seq), Ok(1));
        // ... and one byte more is refused by the writer.
        assert_eq!(
            encode_line(GENESIS, &build(rows, pad + 1)),
            Err(EncodeError::RecordTooLarge)
        );
        // A line forged to be one byte longer than the limit is refused by the
        // decoder, even with a correct hash.
        let mut forged_body = serde_json::to_vec(&build(rows, pad)).expect("json");
        forged_body.insert(1, b' ');
        assert_eq!(forged_body.len(), MAX_RECORD_BYTES + 1);
        let mut forged = chain_hash(GENESIS, &forged_body).into_bytes();
        forged.push(b' ');
        forged.extend_from_slice(&forged_body);
        assert_eq!(Chain::genesis().accept(&forged), Err(ChainError::Malformed));
    }

    // -- the bounded reader ---------------------------------------------------

    fn read_all(input: &[u8], chunk: usize) -> Vec<(LineRead, Vec<u8>)> {
        // `chunk` bytes at a time, so lines span buffer refills.
        let mut reader =
            std::io::BufReader::with_capacity(chunk.max(1), Cursor::new(input.to_vec()));
        let mut out = Vec::new();
        let mut line = Vec::new();
        loop {
            let kind = read_line_bounded(&mut reader, &mut line).expect("reads");
            out.push((kind, line.clone()));
            if matches!(kind, LineRead::Eof | LineRead::TooLong | LineRead::TornTail) {
                return out;
            }
        }
    }

    #[test]
    fn the_reader_splits_on_line_feeds_only_whatever_the_buffer_size() {
        let input = b"one\ntwo words\n\nfour\xe2\x80\xa8with separator\n";
        for chunk in [1, 2, 3, 7, 64, 4096] {
            let got = read_all(input, chunk);
            let lines: Vec<&[u8]> = got
                .iter()
                .filter(|(k, _)| *k == LineRead::Line)
                .map(|(_, l)| l.as_slice())
                .collect();
            assert_eq!(
                lines,
                vec![
                    &b"one"[..],
                    b"two words",
                    b"",
                    "four\u{2028}with separator".as_bytes()
                ],
                "chunk {chunk}"
            );
            assert_eq!(
                got.last().map(|(k, _)| *k),
                Some(LineRead::Eof),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_torn_tail_is_reported_and_not_mistaken_for_a_line() {
        for chunk in [1, 5, 4096] {
            let got = read_all(b"complete\npartial with no newline", chunk);
            assert_eq!(got[0], (LineRead::Line, b"complete".to_vec()));
            assert_eq!(
                got[1],
                (LineRead::TornTail, b"partial with no newline".to_vec())
            );
        }
        assert_eq!(read_all(b"", 8), vec![(LineRead::Eof, Vec::new())]);
        assert_eq!(read_all(b"\n", 8)[0], (LineRead::Line, Vec::new()));
    }

    #[test]
    fn a_line_longer_than_the_cap_is_too_long_and_never_buffered_whole() {
        for chunk in [1, 100, 8192, 1 << 20] {
            // Exactly the cap is a line; one more is not.
            let mut at_cap = vec![b'x'; MAX_LINE_BYTES];
            at_cap.push(b'\n');
            let got = read_all(&at_cap, chunk);
            assert_eq!(got[0].0, LineRead::Line, "chunk {chunk}");
            assert_eq!(got[0].1.len(), MAX_LINE_BYTES);

            let mut over = vec![b'x'; MAX_LINE_BYTES + 1];
            over.push(b'\n');
            let got = read_all(&over, chunk);
            assert_eq!(got[0].0, LineRead::TooLong, "chunk {chunk}");
            assert!(
                got[0].1.len() <= MAX_LINE_BYTES,
                "the buffer never exceeded the cap"
            );

            // The same without a line feed at all (a file of one endless line).
            let endless = vec![b'y'; MAX_LINE_BYTES * 2];
            let got = read_all(&endless, chunk);
            assert_eq!(got[0].0, LineRead::TooLong);
            assert!(got[0].1.len() <= MAX_LINE_BYTES);
        }
    }

    #[test]
    fn a_whole_file_reads_back_through_the_reader_and_the_chain() {
        let records: Vec<_> = every_variant()
            .into_iter()
            .enumerate()
            .map(|(n, event)| record(u64::try_from(n).expect("small") + 1, event))
            .collect();
        let file = file_of(&records);
        let mut reader = std::io::BufReader::with_capacity(7, Cursor::new(file));
        let mut chain = Chain::genesis_at(1);
        let mut line = Vec::new();
        let mut seen = Vec::new();
        while read_line_bounded(&mut reader, &mut line).expect("reads") == LineRead::Line {
            seen.push(chain.accept(&line).expect("verifies"));
        }
        assert_eq!(seen, records);
    }

    // -- properties -----------------------------------------------------------

    fn printable_string() -> impl Strategy<Value = String> {
        "[ -~]{0,40}"
    }

    proptest! {
        /// Whatever printable text the free-form fields hold, the line is one
        /// line, verifies, and decodes to the same record.
        #[test]
        fn any_printable_text_round_trips_as_one_line(
            cause in printable_string(),
            peer in printable_string(),
            reason in printable_string(),
            flow in "[a-z0-9:._-]{0,24}",
            epoch in any::<u64>(),
            bytes in any::<u64>(),
        ) {
            for event in [
                FlowAuditEvent::Disarmed { cause: cause.clone(), epoch },
                FlowAuditEvent::Tripped { reason: reason.clone(), epoch },
                FlowAuditEvent::Closed { bytes_up: bytes, bytes_down: epoch, duration_ms: 1, reason: reason.clone() },
                FlowAuditEvent::Armed {
                    profile: peer.clone(), cause: cause.clone(), client: "cli".into(), requested_by: peer.clone(),
                    epoch, profile_digest: "d".repeat(64),
                    rules: RuleTable { total: 0, truncated: false, rules: Vec::new() }, observations: Vec::new(),
                },
            ] {
                let mut record = record(epoch, event);
                record.flow_id = flow.clone();
                let line = encode_line(GENESIS, &record).expect("printable text encodes");
                prop_assert_eq!(line.bytes.iter().filter(|b| **b == b'\n').count(), 1);
                prop_assert_eq!(line.bytes.last(), Some(&b'\n'));
                let decoded = decode_line(GENESIS, &line.bytes[..line.bytes.len() - 1]).expect("decodes");
                prop_assert_eq!(decoded.record, record);
            }
        }

        /// Any string that holds a character outside printable ASCII is refused.
        #[test]
        fn any_other_character_is_refused(
            prefix in "[ -~]{0,10}",
            odd in prop::char::range('\u{0}', '\u{10ffff}').prop_filter("not printable ASCII", |c| !(' '..='~').contains(c)),
            suffix in "[ -~]{0,10}",
        ) {
            let record = record(1, FlowAuditEvent::Disarmed { cause: format!("{prefix}{odd}{suffix}"), epoch: 1 });
            prop_assert_eq!(encode_line(GENESIS, &record), Err(EncodeError::InvalidField("string")));
        }

        /// The decoder never panics and never accepts what it was not given.
        #[test]
        fn the_decoder_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = Chain::genesis().accept(&bytes);
        }

        /// A line with one byte changed anywhere never verifies as the same
        /// record: it is rejected or, in the one case where the change leaves
        /// the stored bytes alone, equal.
        #[test]
        fn one_changed_byte_is_never_accepted(index in 0_usize..2000, delta in 1_u8..=255) {
            let line = encode_line(GENESIS, &record(3, FlowAuditEvent::Disarmed { cause: "operator".into(), epoch: 9 })).expect("encodes");
            let mut stored = line.bytes[..line.bytes.len() - 1].to_vec();
            let at = index % stored.len();
            stored[at] = stored[at].wrapping_add(delta);
            prop_assert!(decode_line(GENESIS, &stored).is_err());
        }
    }
}
