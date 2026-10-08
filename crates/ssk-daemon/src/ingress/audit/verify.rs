//! Reading the flow ledger back (design 6.4.8, "Open and recovery" and
//! "`verify_dir(dir, mode)`").
//!
//! One function reads every retained segment of a ledger directory and proves the
//! chain: dense sequence numbers, hashes, and the `Continue` record that starts
//! every segment but the first and links it to its predecessor (`prev_seq`,
//! `prev_segment_head`). On the way it counts what an auditor wants to know: how
//! many entries and bytes are retained, how old the oldest is, and which flows
//! are still open (`Unresolved`).
//!
//! Two modes:
//!
//! * [`VerifyMode::Open`] is strict and is the daemon's, under the single-writer
//!   lock. A newest segment that ends inside a line is reported as a torn tail for
//!   the opener to cut, and any other irregularity is `Corrupt`.
//! * [`VerifyMode::Reader`] is for concurrent readers (the doctor, a status
//!   query). It tolerates a partial last line of the newest segment (an append in
//!   progress), reads each file only up to the length it had when it was opened,
//!   and treats a vanished OLDEST segment as a concurrent prune: it lists again
//!   and starts from the new oldest segment, at most three times.
//!
//! The chain of the oldest retained segment is anchored in its own `Continue`
//! record (or at `genesis` for segment 1). That is the prefix integrity the
//! design states: a ledger from which the oldest records were removed still
//! verifies, and so does one that ends earlier than it did; the status publishes
//! `(entries, head)` so that an operator can keep a checkpoint.

use std::collections::HashSet;

use super::fs::{LedgerStore, StoreError};
use super::record::{
    read_line_bounded, Chain, ChainError, FlowAuditEvent, FlowAuditRecord, LineRead,
};
use crate::ingress::types::{ResultOutcome, Unresolved};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyMode {
    Open,
    Reader,
}

/// Why a ledger is not a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorruptKind {
    /// The line is not `<64 hex> <body>`.
    Malformed,
    /// The body is not a record this build knows.
    UnknownRecord,
    /// A hash does not follow from the previous one.
    Hash,
    /// A sequence number is not the one that follows.
    SeqGap,
    /// A line longer than the format allows.
    TooLong,
    /// A segment other than the newest ends inside a line.
    TornInClosedSegment,
    /// A segment other than the first does not start with a `Continue`.
    AnchorMissing,
    /// A `Continue` does not link to the segment before it.
    ContinueLinkage,
    /// The first record of a segment is not the one its name says.
    NameMismatch,
    /// A segment other than the newest has no record.
    EmptySegment,
    /// A segment listed has vanished (and was not the oldest, or this is not a
    /// reader).
    MissingSegment,
    /// `ledger_format` 0, or records after the last sequence number.
    InvalidFormat,
}

impl CorruptKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed_line",
            Self::UnknownRecord => "unknown_record",
            Self::Hash => "hash_mismatch",
            Self::SeqGap => "sequence_gap",
            Self::TooLong => "line_too_long",
            Self::TornInClosedSegment => "torn_closed_segment",
            Self::AnchorMissing => "anchor_missing",
            Self::ContinueLinkage => "continue_linkage",
            Self::NameMismatch => "segment_name_mismatch",
            Self::EmptySegment => "empty_segment",
            Self::MissingSegment => "missing_segment",
            Self::InvalidFormat => "invalid_format",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The chain does not hold. `segment` is the first sequence number of the
    /// segment (its name), `line` the 1-based line in it (0 when no line is meant).
    Corrupt {
        segment: u64,
        line: u64,
        kind: CorruptKind,
    },
    /// The ledger was written by a newer format: read nothing more, write nothing.
    UnsupportedFormat { found: u32 },
    /// The store refused or failed.
    Store(StoreError),
    /// Reading failed.
    Io(&'static str),
    /// Reader mode: the oldest segment kept vanishing under a pruning writer.
    Inconclusive,
}

/// What one segment held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentSummary {
    pub first_seq: u64,
    /// `None` for a segment with no complete line.
    pub last_seq: Option<u64>,
    pub records: u64,
    /// Bytes of complete lines.
    pub bytes: u64,
}

/// Where the newest segment ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    /// Every byte is a complete line.
    Clean,
    /// The segment ends inside a line: a write that was never acknowledged.
    Torn {
        /// The length up to the last complete line.
        valid_len: u64,
        /// The bytes after it.
        torn_bytes: u64,
    },
}

/// Bytes of the newest segment by record class, for the refusal quota.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClassBytes {
    pub denied: u64,
    pub summary: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Ascending by `first_seq`.
    pub segments: Vec<SegmentSummary>,
    /// The hash the next line must follow: `genesis` for an empty ledger.
    pub head: String,
    /// The last sequence number, `None` for an empty ledger.
    pub last_seq: Option<u64>,
    /// Records in all retained segments.
    pub entries: u64,
    /// Bytes of complete lines in all retained segments.
    pub bytes: u64,
    /// The untrusted wall clock of the oldest retained record.
    pub oldest_ts_ms: Option<u64>,
    pub unresolved: Unresolved,
    pub tail: Tail,
    pub newest_class_bytes: ClassBytes,
    /// Names in the directory that are not segments (the doctor shows the count).
    pub ignored: usize,
}

impl Verified {
    fn empty(ignored: usize) -> Self {
        Self {
            segments: Vec::new(),
            head: super::record::GENESIS.to_owned(),
            last_seq: None,
            entries: 0,
            bytes: 0,
            oldest_ts_ms: None,
            unresolved: Unresolved::default(),
            tail: Tail::Clean,
            newest_class_bytes: ClassBytes::default(),
            ignored,
        }
    }

    /// Entries that were pruned before the oldest retained one: the sequence is
    /// dense from 1, so this is the first retained number minus one.
    #[must_use]
    pub fn pruned_entries(&self) -> u64 {
        self.segments
            .first()
            .map_or(0, |segment| segment.first_seq.saturating_sub(1))
    }
}

/// Flows that are open, bounded: ids beyond the bound are only counted, which can
/// only over-report (an upper bound, as the design says of every unresolved flow).
const OPEN_FLOWS_MAX: usize = 262_144;

struct OpenFlows {
    max: usize,
    pending: HashSet<String>,
    tunnels: HashSet<String>,
    /// Pendings and tunnels that did not fit in the sets: never resolved.
    pending_overflow: u64,
    tunnel_overflow: u64,
}

impl OpenFlows {
    fn new(max: usize) -> Self {
        Self {
            max,
            pending: HashSet::new(),
            tunnels: HashSet::new(),
            pending_overflow: 0,
            tunnel_overflow: 0,
        }
    }

    fn see(&mut self, record: &FlowAuditRecord) {
        if record.flow_id.is_empty() {
            return;
        }
        match &record.event {
            FlowAuditEvent::Pending { .. } => {
                if self.pending.len() < self.max {
                    self.pending.insert(record.flow_id.clone());
                } else {
                    self.pending_overflow = self.pending_overflow.saturating_add(1);
                }
            }
            FlowAuditEvent::Result { outcome, .. } => {
                self.pending.remove(&record.flow_id);
                if *outcome == ResultOutcome::Connected {
                    if self.tunnels.len() < self.max {
                        self.tunnels.insert(record.flow_id.clone());
                    } else {
                        self.tunnel_overflow = self.tunnel_overflow.saturating_add(1);
                    }
                }
            }
            FlowAuditEvent::Closed { .. } => {
                self.tunnels.remove(&record.flow_id);
            }
            _ => {}
        }
    }

    fn unresolved(&self) -> Unresolved {
        Unresolved {
            pending: u64::try_from(self.pending.len())
                .unwrap_or(u64::MAX)
                .saturating_add(self.pending_overflow),
            open_tunnels: u64::try_from(self.tunnels.len())
                .unwrap_or(u64::MAX)
                .saturating_add(self.tunnel_overflow),
        }
    }
}

fn corrupt(segment: u64, line: u64, kind: CorruptKind) -> VerifyError {
    VerifyError::Corrupt {
        segment,
        line,
        kind,
    }
}

fn chain_error(segment: u64, line: u64, error: &ChainError) -> VerifyError {
    let kind = match error {
        ChainError::Malformed => CorruptKind::Malformed,
        ChainError::UnknownRecord => CorruptKind::UnknownRecord,
        ChainError::HashMismatch => CorruptKind::Hash,
        ChainError::SeqGap { .. } => CorruptKind::SeqGap,
        ChainError::SeqExhausted | ChainError::InvalidFormat => CorruptKind::InvalidFormat,
        ChainError::UnsupportedFormat { found } => {
            return VerifyError::UnsupportedFormat { found: *found };
        }
    };
    corrupt(segment, line, kind)
}

/// The anchor a segment's first line claims, read before the line is verified: the
/// hash and sequence number of the record before it. Only for the OLDEST retained
/// segment, whose predecessor is not there to be checked against.
pub(super) fn peek_anchor(line: &[u8]) -> Option<(String, u64)> {
    // After the 64 hex digits and the space; like `decode_line`, only an object.
    let body = line.get(65..).filter(|body| body.first() == Some(&b'{'))?;
    let record: FlowAuditRecord = serde_json::from_slice(body).ok()?;
    match record.event {
        FlowAuditEvent::Continue {
            prev_segment_head,
            prev_seq,
            ..
        } => Some((prev_segment_head, prev_seq)),
        _ => None,
    }
}

/// How many times a reader starts over after the oldest segment vanished.
const READER_RESTARTS: usize = 3;

/// Reads and proves the whole ledger.
///
/// # Errors
/// [`VerifyError`].
pub fn verify_dir(store: &dyn LedgerStore, mode: VerifyMode) -> Result<Verified, VerifyError> {
    // Only a reader's listing can go stale (the strict mode reports a vanished
    // segment as damage), so only a reader ever gets `Vanished` and starts over.
    for _ in 0..=READER_RESTARTS {
        match verify_once(store, mode) {
            Err(Outcome::Vanished) => {}
            Err(Outcome::Failed(error)) => return Err(error),
            Ok(verified) => return Ok(verified),
        }
    }
    Err(VerifyError::Inconclusive)
}

enum Outcome {
    /// The oldest listed segment was removed while a reader looked.
    Vanished,
    Failed(VerifyError),
}

impl From<VerifyError> for Outcome {
    fn from(error: VerifyError) -> Self {
        Self::Failed(error)
    }
}

#[allow(clippy::too_many_lines)]
fn verify_once(store: &dyn LedgerStore, mode: VerifyMode) -> Result<Verified, Outcome> {
    let listing = store
        .segments()
        .map_err(|error| Outcome::Failed(VerifyError::Store(error)))?;
    if listing.first_seqs.is_empty() {
        return Ok(Verified::empty(listing.ignored));
    }
    let newest = listing.first_seqs.len().saturating_sub(1);
    let mut verified = Verified::empty(listing.ignored);
    let mut open = OpenFlows::new(OPEN_FLOWS_MAX);
    let mut chain: Option<Chain> = None;
    let mut line = Vec::new();

    for (index, first_seq) in listing.first_seqs.iter().copied().enumerate() {
        let reader = match store.open_reader(first_seq) {
            Ok(reader) => reader,
            // A reader races the writer's prune, which removes the OLDEST segments
            // first: whatever vanished, the listing is stale. Start over; if the
            // segment is really missing from the middle the new listing lacks it and
            // the chain proves it.
            Err(StoreError::Io("AUDIT_NOT_FOUND")) if mode == VerifyMode::Reader => {
                return Err(Outcome::Vanished);
            }
            Err(StoreError::Io("AUDIT_NOT_FOUND")) => {
                return Err(corrupt(first_seq, 0, CorruptKind::MissingSegment).into());
            }
            Err(error) => return Err(Outcome::Failed(VerifyError::Store(error))),
        };
        let mut reader = reader.reader;
        let mut summary = SegmentSummary {
            first_seq,
            last_seq: None,
            records: 0,
            bytes: 0,
        };
        let mut class = ClassBytes::default();
        let mut line_no: u64 = 0;
        let mut torn: Option<u64> = None;
        loop {
            let read = read_line_bounded(&mut *reader, &mut line)
                .map_err(|_| Outcome::Failed(VerifyError::Io("AUDIT_READ")))?;
            match read {
                LineRead::Eof => break,
                LineRead::TooLong => {
                    return Err(corrupt(
                        first_seq,
                        line_no.saturating_add(1),
                        CorruptKind::TooLong,
                    )
                    .into());
                }
                LineRead::TornTail => {
                    torn = Some(u64::try_from(line.len()).unwrap_or(u64::MAX));
                    break;
                }
                LineRead::Line => {}
            }
            line_no = line_no.saturating_add(1);

            // The chain the line must continue. The oldest retained segment starts
            // it: segment 1 at `genesis`, any other at the `Continue` that anchors it
            // (whose claim about the record before it cannot be checked, that record
            // being gone). Every later segment continues the chain that is there.
            let prior = if summary.records == 0 {
                chain
                    .as_ref()
                    .map(|c| (c.head().to_owned(), verified.last_seq))
            } else {
                None
            };
            if chain.is_none() {
                chain = Some(if first_seq == 1 {
                    Chain::genesis_at(1)
                } else {
                    let (head, prev_seq) = peek_anchor(&line).ok_or_else(|| {
                        Outcome::Failed(corrupt(first_seq, line_no, CorruptKind::AnchorMissing))
                    })?;
                    Chain::resume(head, prev_seq)
                });
            }
            let current = chain
                .as_mut()
                .ok_or(Outcome::Failed(VerifyError::Io("AUDIT_VERIFY")))?;
            let record = current
                .accept(&line)
                .map_err(|error| Outcome::Failed(chain_error(first_seq, line_no, &error)))?;
            if summary.records == 0 {
                if record.seq != first_seq {
                    return Err(corrupt(first_seq, line_no, CorruptKind::NameMismatch).into());
                }
                if first_seq != 1 {
                    // Every segment but the first starts with the record that links
                    // it to the one before.
                    let FlowAuditEvent::Continue {
                        prev_segment_head,
                        prev_seq,
                        ..
                    } = &record.event
                    else {
                        return Err(corrupt(first_seq, line_no, CorruptKind::AnchorMissing).into());
                    };
                    // The oldest retained segment has no predecessor to check (`prior`
                    // is `None`): its `Continue` is the anchor, and the chain was
                    // resumed from it, so its numbers already agree with the name.
                    let linked = prior.as_ref().is_none_or(|(head, last)| {
                        prev_segment_head == head && *last == Some(*prev_seq)
                    });
                    if !linked {
                        return Err(
                            corrupt(first_seq, line_no, CorruptKind::ContinueLinkage).into()
                        );
                    }
                }
                if verified.oldest_ts_ms.is_none() {
                    verified.oldest_ts_ms = Some(record.ts_ms);
                }
            }
            let length = u64::try_from(line.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            summary.records = summary.records.saturating_add(1);
            summary.bytes = summary.bytes.saturating_add(length);
            summary.last_seq = Some(record.seq);
            match &record.event {
                FlowAuditEvent::Denied { .. } => class.denied = class.denied.saturating_add(length),
                FlowAuditEvent::Summary { .. } => {
                    class.summary = class.summary.saturating_add(length);
                }
                _ => {}
            }
            open.see(&record);
            verified.last_seq = Some(record.seq);
        }

        if index == newest {
            verified.newest_class_bytes = class;
            verified.tail = match torn {
                Some(torn_bytes) => Tail::Torn {
                    valid_len: summary.bytes,
                    torn_bytes,
                },
                None => Tail::Clean,
            };
        } else if torn.is_some() {
            return Err(corrupt(
                first_seq,
                line_no.saturating_add(1),
                CorruptKind::TornInClosedSegment,
            )
            .into());
        } else if summary.records == 0 {
            return Err(corrupt(first_seq, 0, CorruptKind::EmptySegment).into());
        }
        verified.entries = verified.entries.saturating_add(summary.records);
        verified.bytes = verified.bytes.saturating_add(summary.bytes);
        verified.segments.push(summary);
    }
    verified.head = chain.as_ref().map_or_else(
        || super::record::GENESIS.to_owned(),
        |c| c.head().to_owned(),
    );
    verified.unresolved = open.unresolved();
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::Mutex;

    use crate::ingress::audit::fs::{ActiveSegment, SegmentReader, Segments, StoreError as Se};
    use crate::ingress::audit::record::{encode_line, GENESIS, LEDGER_FORMAT};
    use crate::ingress::types::{
        lock_unpoisoned, ConfigFingerprint, DestRef, DestinationLogging, Resolution,
    };

    // -- an in-memory store and a builder of well-formed ledgers ------------------------------

    #[derive(Default)]
    struct MemStore {
        segments: Mutex<BTreeMap<u64, Vec<u8>>>,
        /// Segments that disappear when they are first opened.
        vanish: Mutex<Vec<u64>>,
        ignored: usize,
    }

    impl MemStore {
        fn put(&self, first_seq: u64, bytes: Vec<u8>) {
            lock_unpoisoned(&self.segments).insert(first_seq, bytes);
        }
    }

    impl LedgerStore for MemStore {
        fn created(&self) -> bool {
            false
        }

        fn segments(&self) -> Result<Segments, Se> {
            Ok(Segments {
                first_seqs: lock_unpoisoned(&self.segments).keys().copied().collect(),
                ignored: self.ignored,
            })
        }

        fn open_reader(&self, first_seq: u64) -> Result<SegmentReader, Se> {
            {
                let mut vanish = lock_unpoisoned(&self.vanish);
                if let Some(at) = vanish.iter().position(|seq| *seq == first_seq) {
                    vanish.remove(at);
                    lock_unpoisoned(&self.segments).remove(&first_seq);
                }
            }
            let segments = lock_unpoisoned(&self.segments);
            let bytes = segments
                .get(&first_seq)
                .cloned()
                .ok_or(Se::Io("AUDIT_NOT_FOUND"))?;
            Ok(SegmentReader {
                len: u64::try_from(bytes.len()).expect("fits"),
                reader: Box::new(Cursor::new(bytes)),
            })
        }

        fn open_active(&self, _first_seq: u64) -> Result<Box<dyn ActiveSegment>, Se> {
            Err(Se::Unsupported)
        }

        fn create_segment(&self, _first_seq: u64) -> Result<Box<dyn ActiveSegment>, Se> {
            Err(Se::Unsupported)
        }

        fn remove_segment(&self, _first_seq: u64) -> std::io::Result<()> {
            Err(std::io::Error::other("unused"))
        }

        fn sync_dir(&self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn fingerprint() -> ConfigFingerprint {
        ConfigFingerprint {
            version: 1,
            config: "a".repeat(64),
            routing: "b".repeat(64),
            ingress: "c".repeat(64),
        }
    }

    fn started(format: u32) -> FlowAuditEvent {
        FlowAuditEvent::Started {
            daemon_version: "0.0.0".into(),
            ledger_format: format,
            config: fingerprint(),
            destination_logging: DestinationLogging::Plain,
            dest_key_id: None,
            unresolved_before: Unresolved::default(),
        }
    }

    fn pending() -> FlowAuditEvent {
        FlowAuditEvent::Pending {
            peer: "uid:1".into(),
            peer_verified: true,
            dest: DestRef::Plain {
                host: "example.com".into(),
                port: 443,
            },
            target_provenance: "client_supplied_name".into(),
            target_kind: "name".into(),
            resolution: Resolution::LocalPinned,
            profile: "main".into(),
            matched_rule: None,
            route: "Direct".into(),
            planned_adapters: Vec::new(),
        }
    }

    fn result(outcome: ResultOutcome) -> FlowAuditEvent {
        FlowAuditEvent::Result {
            outcome,
            error_code: None,
            refusal: None,
            chain_kinds: Vec::new(),
            dialed: None,
            attempted: Vec::new(),
            answers: None,
            observations: Vec::new(),
        }
    }

    fn closed_event() -> FlowAuditEvent {
        FlowAuditEvent::Closed {
            bytes_up: 1,
            bytes_down: 2,
            duration_ms: 3,
            reason: "eof".into(),
        }
    }

    fn denied() -> FlowAuditEvent {
        FlowAuditEvent::Denied {
            peer: "uid:1".into(),
            peer_verified: true,
            dest: DestRef::Plain {
                host: "blocked.example".into(),
                port: 25,
            },
            target_provenance: "client_supplied_name".into(),
            target_kind: "name".into(),
            profile: "main".into(),
            matched_rule: None,
            reason_code: "POLICY_DENY".into(),
            route: None,
            coalesced: false,
        }
    }

    fn summary() -> FlowAuditEvent {
        FlowAuditEvent::Summary {
            window_ms: 1,
            pre_admission_rejects: BTreeMap::new(),
            denials_suppressed: BTreeMap::new(),
            denials_over_quota: BTreeMap::new(),
            denials_repeated: Vec::new(),
            other_keys: 0,
        }
    }

    /// Writes a well-formed ledger the way the writer will: one chain across
    /// segments, each segment after the first beginning with a `Continue`.
    struct Builder {
        store: MemStore,
        head: String,
        next_seq: u64,
        active: u64,
    }

    impl Builder {
        fn new() -> Self {
            Self {
                store: MemStore::default(),
                head: GENESIS.to_owned(),
                next_seq: 1,
                active: 1,
            }
        }

        fn line(&mut self, flow: &str, event: FlowAuditEvent) -> Vec<u8> {
            let record = FlowAuditRecord {
                seq: self.next_seq,
                ts_ms: 1_000 + self.next_seq,
                flow_id: flow.to_owned(),
                event,
            };
            let encoded = encode_line(&self.head, &record).expect("encodes");
            self.head = encoded.hash;
            self.next_seq += 1;
            encoded.bytes
        }

        fn add(&mut self, flow: &str, event: FlowAuditEvent) -> &mut Self {
            let bytes = self.line(flow, event);
            let active = self.active;
            lock_unpoisoned(&self.store.segments)
                .entry(active)
                .or_default()
                .extend_from_slice(&bytes);
            self
        }

        /// Starts the next segment with its `Continue`.
        fn rotate(&mut self) -> &mut Self {
            self.rotate_with(None, None)
        }

        fn rotate_with(&mut self, head: Option<String>, prev_seq: Option<u64>) -> &mut Self {
            let continue_event = FlowAuditEvent::Continue {
                prev_segment_head: head.unwrap_or_else(|| self.head.clone()),
                prev_seq: prev_seq.unwrap_or(self.next_seq - 1),
                pruned_before_seq: None,
                prune_deferred: 0,
                refusals_unrecorded: 0,
            };
            self.active = self.next_seq;
            self.add("", continue_event)
        }

        fn remove(&mut self, first_seq: u64) -> &mut Self {
            lock_unpoisoned(&self.store.segments).remove(&first_seq);
            self
        }

        fn bytes_of(&self, first_seq: u64) -> Vec<u8> {
            lock_unpoisoned(&self.store.segments)
                .get(&first_seq)
                .cloned()
                .expect("segment")
        }

        fn verify(&self, mode: VerifyMode) -> Result<Verified, VerifyError> {
            verify_dir(&self.store, mode)
        }
    }

    fn three_segments() -> Builder {
        let mut b = Builder::new();
        b.add("", started(1));
        b.add("f1", pending())
            .add("f1", result(ResultOutcome::Failed));
        b.rotate();
        b.add("f2", pending())
            .add("f2", result(ResultOutcome::Failed));
        b.rotate();
        b.add("f3", pending())
            .add("f3", result(ResultOutcome::Failed));
        b
    }

    // -- the happy paths ---------------------------------------------------------------------------

    #[test]
    fn an_empty_directory_is_an_empty_ledger() {
        let store = MemStore {
            ignored: 3,
            ..MemStore::default()
        };
        let v = verify_dir(&store, VerifyMode::Open).expect("verifies");
        assert_eq!(v, Verified::empty(3));
        assert_eq!(v.head, "genesis");
        assert_eq!(v.last_seq, None);
        assert_eq!(v.pruned_entries(), 0);
    }

    #[test]
    fn one_segment_is_counted_and_its_head_is_the_last_hash() {
        let mut b = Builder::new();
        b.add("", started(1)).add("f1", pending());
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(v.entries, 2);
        assert_eq!(v.last_seq, Some(2));
        assert_eq!(v.head, b.head);
        assert_eq!(v.bytes, u64::try_from(b.bytes_of(1).len()).expect("fits"));
        assert_eq!(v.oldest_ts_ms, Some(1_001));
        assert_eq!(v.tail, Tail::Clean);
        assert_eq!(
            v.segments,
            [SegmentSummary {
                first_seq: 1,
                last_seq: Some(2),
                records: 2,
                bytes: v.bytes
            }]
        );
        assert_eq!(v.pruned_entries(), 0);
    }

    #[test]
    fn a_chain_across_segments_verifies_and_adds_up() {
        let b = three_segments();
        let v = b.verify(VerifyMode::Open).expect("verifies");
        // started, f1 x2, continue, f2 x2, continue, f3 x2.
        assert_eq!(v.entries, 9);
        assert_eq!(v.last_seq, Some(9));
        assert_eq!(v.head, b.head);
        let firsts: Vec<u64> = v.segments.iter().map(|s| s.first_seq).collect();
        assert_eq!(firsts, [1, 4, 7]);
        let records: Vec<u64> = v.segments.iter().map(|s| s.records).collect();
        assert_eq!(records, [3, 3, 3]);
        assert_eq!(
            v.bytes,
            v.segments.iter().map(|s| s.bytes).sum::<u64>(),
            "the totals are the sums"
        );
        assert_eq!(b.verify(VerifyMode::Reader).expect("reader"), v);
    }

    #[test]
    fn a_ledger_whose_oldest_segments_were_pruned_still_verifies_from_its_anchor() {
        let mut b = three_segments();
        b.remove(1);
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(v.entries, 6);
        assert_eq!(v.pruned_entries(), 3, "seq is dense from 1");
        assert_eq!(v.segments.first().map(|s| s.first_seq), Some(4));
        // The oldest retained record is the anchoring Continue.
        assert_eq!(v.oldest_ts_ms, Some(1_004));
        b.remove(4);
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!((v.entries, v.pruned_entries()), (3, 6));
        assert_eq!(v.head, b.head);
    }

    #[test]
    fn the_newest_segment_may_be_empty_and_the_chain_stays_where_it_was() {
        let b = three_segments();
        let head = b.head.clone();
        b.store.put(10, Vec::new());
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(v.head, head);
        assert_eq!(v.last_seq, Some(9));
        assert_eq!(
            v.segments.last().map(|s| (s.first_seq, s.records)),
            Some((10, 0))
        );
        assert_eq!(v.tail, Tail::Clean);
    }

    #[test]
    fn class_bytes_are_the_lengths_of_the_denied_and_summary_lines_of_the_newest_segment() {
        let mut b = Builder::new();
        b.add("", started(1));
        b.add("", denied())
            .add("", denied())
            .add("", summary())
            .add("f", pending());
        let lens: Vec<usize> = b
            .bytes_of(1)
            .split_inclusive(|byte| *byte == b'\n')
            .map(<[u8]>::len)
            .collect();
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(
            v.newest_class_bytes,
            ClassBytes {
                denied: u64::try_from(lens[1] + lens[2]).expect("fits"),
                summary: u64::try_from(lens[3]).expect("fits"),
            }
        );
        // Only the newest segment counts.
        b.rotate();
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(v.newest_class_bytes, ClassBytes::default());
    }

    // -- what is wrong ---------------------------------------------------------------------------------

    fn kind_of(result: Result<Verified, VerifyError>) -> (u64, u64, CorruptKind) {
        match result {
            Err(VerifyError::Corrupt {
                segment,
                line,
                kind,
            }) => (segment, line, kind),
            other => panic!("not corrupt: {other:?}"),
        }
    }

    #[test]
    fn a_changed_byte_names_the_segment_and_the_line() {
        let b = three_segments();
        let mut bytes = b.bytes_of(4);
        // Inside the body of the second line of the second segment.
        let second = bytes.iter().position(|c| *c == b'\n').expect("line") + 1;
        let at = second + 90;
        bytes[at] = if bytes[at] == b'x' { b'y' } else { b'x' };
        b.store.put(4, bytes);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (4, 2, CorruptKind::Hash)
        );
    }

    #[test]
    fn a_missing_middle_segment_is_corruption_at_the_segment_after_it() {
        let mut b = three_segments();
        b.remove(4);
        // The first line of the segment after the gap does not follow the hash
        // before it; the gap in the numbers is the same fact.
        let (segment, line, kind) = kind_of(b.verify(VerifyMode::Open));
        assert_eq!((segment, line), (7, 1));
        assert!(
            matches!(kind, CorruptKind::Hash | CorruptKind::SeqGap),
            "{kind:?}"
        );
    }

    #[test]
    fn a_removed_line_inside_a_segment_is_caught() {
        let b = three_segments();
        let bytes = b.bytes_of(4);
        let mut lines: Vec<&[u8]> = bytes.split_inclusive(|c| *c == b'\n').collect();
        lines.remove(1);
        b.store.put(4, lines.concat());
        let (segment, line, kind) = kind_of(b.verify(VerifyMode::Open));
        assert_eq!((segment, line), (4, 2));
        assert!(
            matches!(kind, CorruptKind::Hash | CorruptKind::SeqGap),
            "{kind:?}"
        );
    }

    #[test]
    fn a_continue_that_lies_about_the_record_before_it_is_refused() {
        // The hash chain is intact; only the claim inside the record is false.
        for (head, prev_seq) in [(Some("f".repeat(64)), None), (None, Some(1_u64))] {
            let mut b = Builder::new();
            b.add("", started(1)).add("f1", pending());
            b.rotate_with(head, prev_seq);
            assert_eq!(
                kind_of(b.verify(VerifyMode::Open)),
                (3, 1, CorruptKind::ContinueLinkage)
            );
        }
    }

    #[test]
    fn a_segment_that_does_not_begin_with_a_continue_is_refused() {
        let mut b = Builder::new();
        b.add("", started(1)).add("f1", pending());
        b.active = 3;
        b.add("f2", pending());
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (3, 1, CorruptKind::AnchorMissing)
        );
        // And the oldest one, whose predecessor is gone, needs an anchor as well.
        let mut b = Builder::new();
        b.add("", started(1)).add("f1", pending());
        b.active = 3;
        b.add("f2", pending());
        b.remove(1);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (3, 1, CorruptKind::AnchorMissing)
        );
    }

    #[test]
    fn a_segment_whose_name_is_not_its_first_sequence_number_is_refused() {
        let mut b = three_segments();
        let bytes = b.bytes_of(7);
        b.remove(7);
        b.store.put(8, bytes);
        let (segment, _, kind) = kind_of(b.verify(VerifyMode::Open));
        assert_eq!(segment, 8);
        assert!(matches!(
            kind,
            CorruptKind::SeqGap | CorruptKind::NameMismatch
        ));
        // The oldest segment, anchored by its own Continue, is checked against its name.
        let mut b = three_segments();
        b.remove(1);
        let bytes = b.bytes_of(4);
        b.remove(4);
        b.store.put(5, bytes);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (5, 1, CorruptKind::NameMismatch)
        );
    }

    #[test]
    fn a_closed_segment_without_records_or_ending_in_a_line_is_refused() {
        let b = three_segments();
        b.store.put(4, Vec::new());
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (4, 0, CorruptKind::EmptySegment)
        );
        let b = three_segments();
        let mut bytes = b.bytes_of(4);
        bytes.extend_from_slice(b"0123");
        b.store.put(4, bytes);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (4, 4, CorruptKind::TornInClosedSegment)
        );
    }

    #[test]
    fn a_line_longer_than_the_format_allows_is_refused_without_being_held() {
        let b = three_segments();
        let mut bytes = b.bytes_of(7);
        bytes.extend(std::iter::repeat_n(
            b'a',
            super::super::record::MAX_LINE_BYTES + 10,
        ));
        b.store.put(7, bytes);
        // Three lines are there; the long one is the fourth.
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (7, 4, CorruptKind::TooLong)
        );
    }

    #[test]
    fn a_ledger_written_by_a_newer_format_is_refused_wherever_it_starts() {
        let mut b = Builder::new();
        b.add("", started(LEDGER_FORMAT + 1));
        assert_eq!(
            b.verify(VerifyMode::Open),
            Err(VerifyError::UnsupportedFormat {
                found: LEDGER_FORMAT + 1
            })
        );
        let mut b = Builder::new();
        b.add("", started(1)).add("f", pending());
        b.rotate();
        b.add("", started(LEDGER_FORMAT + 1));
        assert_eq!(
            b.verify(VerifyMode::Reader),
            Err(VerifyError::UnsupportedFormat {
                found: LEDGER_FORMAT + 1
            })
        );
        let mut b = Builder::new();
        b.add("", started(0));
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (1, 1, CorruptKind::InvalidFormat)
        );
    }

    // -- the end of the newest segment -----------------------------------------------------------------

    #[test]
    fn a_torn_tail_on_the_newest_segment_is_reported_with_where_to_cut() {
        let b = three_segments();
        let clean = b.bytes_of(7);
        let mut bytes = clean.clone();
        bytes.extend_from_slice(b"0123456789abcdef");
        b.store.put(7, bytes);
        for mode in [VerifyMode::Open, VerifyMode::Reader] {
            let v = b.verify(mode).expect("a torn tail is not corruption");
            assert_eq!(
                v.tail,
                Tail::Torn {
                    valid_len: u64::try_from(clean.len()).expect("fits"),
                    torn_bytes: 16
                },
                "{mode:?}"
            );
            assert_eq!(v.entries, 9, "the torn bytes are not an entry");
            assert_eq!(v.head, b.head);
        }
    }

    #[test]
    fn a_newest_segment_with_only_a_partial_first_line_has_no_records_and_a_torn_tail() {
        let b = three_segments();
        b.store.put(10, b"0123456789".to_vec());
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(
            v.tail,
            Tail::Torn {
                valid_len: 0,
                torn_bytes: 10
            }
        );
        assert_eq!(v.segments.last().map(|s| s.records), Some(0));
        assert_eq!(v.head, b.head);
    }

    // -- unresolved flows -----------------------------------------------------------------------------------

    #[test]
    fn unresolved_flows_are_counted_across_all_the_segments() {
        let mut b = Builder::new();
        b.add("", started(1));
        b.add("a", pending()); // never resolved
        b.add("b", pending())
            .add("b", result(ResultOutcome::Connected)); // tunnel open
        b.add("c", pending())
            .add("c", result(ResultOutcome::Failed)); // done
        b.rotate();
        b.add("d", pending())
            .add("d", result(ResultOutcome::Connected));
        b.add("d", closed_event()); // done
        b.add("e", pending())
            .add("e", result(ResultOutcome::NotDialed)); // done
        b.add("", started(1)); // a later boot does not resolve anything
        b.add("f", pending());
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(
            v.unresolved,
            Unresolved {
                pending: 2,
                open_tunnels: 1
            }
        );
        // A tunnel's Result moved it out of pending and into tunnels: not both.
        b.add("b", closed_event());
        let v = b.verify(VerifyMode::Open).expect("verifies");
        assert_eq!(v.unresolved.open_tunnels, 0);
    }

    #[test]
    fn flows_beyond_the_bound_are_only_counted_and_never_resolved() {
        let mut open = OpenFlows::new(2);
        let record = |flow: &str, event: FlowAuditEvent| FlowAuditRecord {
            seq: 1,
            ts_ms: 0,
            flow_id: flow.to_owned(),
            event,
        };
        for flow in ["a", "b", "c", "d"] {
            open.see(&record(flow, pending()));
        }
        // Two fit; two over-report.
        assert_eq!(open.unresolved().pending, 4);
        open.see(&record("a", result(ResultOutcome::Failed)));
        assert_eq!(open.unresolved().pending, 3);
        // "c" did not fit: its Result cannot be matched, and it stays counted.
        open.see(&record("c", result(ResultOutcome::Failed)));
        assert_eq!(open.unresolved().pending, 3);
        // Records without a flow are ignored.
        open.see(&record("", pending()));
        assert_eq!(open.unresolved().pending, 3);
    }

    // -- a reader and a writer that prunes -----------------------------------------------------------------

    #[test]
    fn a_reader_starts_over_from_the_new_oldest_segment_when_the_oldest_vanishes() {
        let b = three_segments();
        lock_unpoisoned(&b.store.vanish).push(1);
        let v = b.verify(VerifyMode::Reader).expect("restarts and verifies");
        assert_eq!(v.segments.first().map(|s| s.first_seq), Some(4));
        assert_eq!(v.entries, 6);
        assert_eq!(v.head, b.head);
        // The strict mode has no concurrent pruner: a vanished segment is damage.
        let b = three_segments();
        lock_unpoisoned(&b.store.vanish).push(1);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (1, 0, CorruptKind::MissingSegment)
        );
    }

    #[test]
    fn a_reader_that_loses_a_middle_segment_starts_over_and_the_chain_proves_the_hole() {
        let b = three_segments();
        lock_unpoisoned(&b.store.vanish).push(4);
        // The listing was stale; the new one has a hole in it, which is damage.
        let (segment, _, kind) = kind_of(b.verify(VerifyMode::Reader));
        assert_eq!(segment, 7);
        assert!(
            matches!(kind, CorruptKind::Hash | CorruptKind::SeqGap),
            "{kind:?}"
        );
    }

    #[test]
    fn a_reader_that_loses_the_two_oldest_segments_at_once_starts_over() {
        // Pruning removes the oldest first, and can have removed two by the time the
        // reader opens the second.
        let b = three_segments();
        lock_unpoisoned(&b.store.vanish).push(1);
        lock_unpoisoned(&b.store.vanish).push(4);
        let v = b
            .verify(VerifyMode::Reader)
            .expect("verifies after starting over");
        assert_eq!(v.segments.first().map(|s| s.first_seq), Some(7));
        assert_eq!(v.pruned_entries(), 6);
    }

    #[test]
    fn a_reader_gives_up_after_three_restarts() {
        let mut b = Builder::new();
        b.add("", started(1));
        for _ in 0..6 {
            b.rotate();
            b.add("f", pending());
        }
        // Every time a reader looks, the oldest segment is gone.
        let firsts: Vec<u64> = lock_unpoisoned(&b.store.segments).keys().copied().collect();
        // The first look and three restarts: four vanishings are one too many.
        lock_unpoisoned(&b.store.vanish).extend(firsts.iter().take(4));
        assert_eq!(b.verify(VerifyMode::Reader), Err(VerifyError::Inconclusive));
        // With one fewer, the fourth attempt succeeds.
        let mut b = Builder::new();
        b.add("", started(1));
        for _ in 0..6 {
            b.rotate();
            b.add("f", pending());
        }
        let firsts: Vec<u64> = lock_unpoisoned(&b.store.segments).keys().copied().collect();
        lock_unpoisoned(&b.store.vanish).extend(firsts.iter().take(3));
        assert!(b.verify(VerifyMode::Reader).is_ok());
    }

    #[test]
    fn the_store_refusing_is_reported_as_the_stores_error() {
        struct Refusing;
        impl LedgerStore for Refusing {
            fn created(&self) -> bool {
                false
            }
            fn segments(&self) -> Result<Segments, Se> {
                Err(Se::Io("AUDIT_PERMISSION_DENIED"))
            }
            fn open_reader(&self, _: u64) -> Result<SegmentReader, Se> {
                Err(Se::Unsupported)
            }
            fn open_active(&self, _: u64) -> Result<Box<dyn ActiveSegment>, Se> {
                Err(Se::Unsupported)
            }
            fn create_segment(&self, _: u64) -> Result<Box<dyn ActiveSegment>, Se> {
                Err(Se::Unsupported)
            }
            fn remove_segment(&self, _: u64) -> std::io::Result<()> {
                Ok(())
            }
            fn sync_dir(&self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            verify_dir(&Refusing, VerifyMode::Open),
            Err(VerifyError::Store(Se::Io("AUDIT_PERMISSION_DENIED")))
        );
        let b = three_segments();
        let copy = std::sync::Arc::new(MemStore::default());
        for (first_seq, bytes) in lock_unpoisoned(&b.store.segments).iter() {
            copy.put(*first_seq, bytes.clone());
        }
        // A segment that is there but refused (a planted symlink) is the store's finding.
        struct Planted(std::sync::Arc<MemStore>);
        impl LedgerStore for Planted {
            fn created(&self) -> bool {
                false
            }
            fn segments(&self) -> Result<Segments, Se> {
                self.0.segments()
            }
            fn open_reader(&self, first_seq: u64) -> Result<SegmentReader, Se> {
                if first_seq == 4 {
                    Err(Se::FileUnsafe(
                        crate::ingress::audit::fs::UnsafeReason::NotRegularFile,
                    ))
                } else {
                    self.0.open_reader(first_seq)
                }
            }
            fn open_active(&self, _: u64) -> Result<Box<dyn ActiveSegment>, Se> {
                Err(Se::Unsupported)
            }
            fn create_segment(&self, _: u64) -> Result<Box<dyn ActiveSegment>, Se> {
                Err(Se::Unsupported)
            }
            fn remove_segment(&self, _: u64) -> std::io::Result<()> {
                Ok(())
            }
            fn sync_dir(&self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            verify_dir(&Planted(copy), VerifyMode::Open),
            Err(VerifyError::Store(Se::FileUnsafe(
                crate::ingress::audit::fs::UnsafeReason::NotRegularFile
            )))
        );
    }

    #[test]
    fn corrupt_kinds_have_stable_words() {
        let all = [
            (CorruptKind::Malformed, "malformed_line"),
            (CorruptKind::UnknownRecord, "unknown_record"),
            (CorruptKind::Hash, "hash_mismatch"),
            (CorruptKind::SeqGap, "sequence_gap"),
            (CorruptKind::TooLong, "line_too_long"),
            (CorruptKind::TornInClosedSegment, "torn_closed_segment"),
            (CorruptKind::AnchorMissing, "anchor_missing"),
            (CorruptKind::ContinueLinkage, "continue_linkage"),
            (CorruptKind::NameMismatch, "segment_name_mismatch"),
            (CorruptKind::EmptySegment, "empty_segment"),
            (CorruptKind::MissingSegment, "missing_segment"),
            (CorruptKind::InvalidFormat, "invalid_format"),
        ];
        for (kind, word) in all {
            assert_eq!(kind.as_str(), word);
        }
    }

    #[test]
    fn tunnels_beyond_the_bound_are_only_counted_and_a_closed_is_not_a_result() {
        let record = |flow: &str, event: FlowAuditEvent| FlowAuditRecord {
            seq: 1,
            ts_ms: 0,
            flow_id: flow.to_owned(),
            event,
        };
        let mut open = OpenFlows::new(2);
        for flow in ["a", "b", "c", "d"] {
            open.see(&record(flow, result(ResultOutcome::Connected)));
        }
        // Two fit; two over-report.
        assert_eq!(open.unresolved().open_tunnels, 4);
        open.see(&record("a", closed_event()));
        assert_eq!(open.unresolved().open_tunnels, 3);
        // "c" did not fit: its Closed cannot be matched, and it stays counted.
        open.see(&record("c", closed_event()));
        assert_eq!(open.unresolved().open_tunnels, 3);
        // Only a Result resolves a Pending.
        let mut open = OpenFlows::new(2);
        open.see(&record("p", pending()));
        open.see(&record("p", closed_event()));
        assert_eq!(open.unresolved().pending, 1);
    }

    #[test]
    fn a_gap_in_the_numbers_behind_an_intact_hash_chain_is_a_sequence_gap() {
        let mut b = Builder::new();
        b.add("", started(1)).add("f", pending());
        // A writer that skipped a number and hashed on: the chain holds, the count does not.
        b.next_seq += 1;
        b.add("f", result(ResultOutcome::Failed));
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (1, 3, CorruptKind::SeqGap)
        );
    }

    #[test]
    fn a_line_with_a_good_hash_and_a_body_this_build_does_not_know_is_an_unknown_record() {
        let b = Builder::new();
        let mut bytes = Vec::new();
        let body = br#"{"seq":1,"ts_ms":1,"event":"mystery"}"#;
        bytes.extend_from_slice(super::super::record::chain_hash(GENESIS, body).as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(body);
        bytes.push(b'\n');
        b.store.put(1, bytes);
        assert_eq!(
            kind_of(b.verify(VerifyMode::Open)),
            (1, 1, CorruptKind::UnknownRecord)
        );
    }

    #[test]
    fn the_anchor_is_read_from_a_continue_line_and_from_nothing_else() {
        let mut b = Builder::new();
        b.add("", started(1)).add("f1", pending());
        let started_line = b.bytes_of(1);
        let started_line = started_line.split(|c| *c == b'\n').next().expect("line");
        assert_eq!(peek_anchor(started_line), None);
        b.rotate();
        let second = b.bytes_of(3);
        let continue_line = second.split(|c| *c == b'\n').next().expect("line");
        let (head, prev_seq) = peek_anchor(continue_line).expect("a continue");
        assert_eq!((head.len(), prev_seq), (64, 2));
        assert_eq!(peek_anchor(b""), None);
        assert_eq!(peek_anchor(&[b'a'; 65]), None);
        // The body starts right after the hash and the space, and with an object.
        let mut shifted = continue_line.to_vec();
        shifted.insert(64, b' ');
        assert_eq!(peek_anchor(&shifted), None);
    }
}
