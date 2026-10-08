//! Opening the flow ledger of a daemon (design 6.4.8, "Open and recovery").
//!
//! [`open_dir`] is blocking and runs inside `spawn_blocking`, never on a runtime
//! worker, under the single-writer lock (a [`LockProof`] is the evidence the caller
//! holds it). It opens the store (any refusal is `UnsafeStore` and the ingress is
//! unavailable with no port bound), proves the chain with [`verify_dir`] in its
//! strict mode, repairs only what a crash of this very daemon can have left, and
//! hands the result to the writer, which appends `Recovered` (when something was
//! cut or a trip preceded) and `Started`.
//!
//! What a crash can leave, and what is done about it:
//!
//! * the newest segment ends inside a line: an append that was never acknowledged
//!   (replies follow the sync). The tail is cut (`set_len`, then `sync_all`) and
//!   `Recovered` says how many bytes;
//! * the newest segment has no complete line: a crash between creating it (R2) and
//!   making its first record durable (R4). With a predecessor it is unlinked (and
//!   the directory made durable) and the predecessor is the active segment again;
//!   alone and named for 1 it is a fresh chain;
//! * more segments than the retention allows (a crash between R5 and R7): the next
//!   rotation prunes down;
//! * a pruned segment that reappears (a crash before the directory was durable): it
//!   is still a valid, anchored prefix, and is pruned again.
//!
//! Anything else is `Corrupt`, and nothing is repaired: the operator moves the
//! directory aside. (That includes a tail damaged by a power loss in a way that
//! leaves line feeds behind: cutting every invalid trailing line would also cut
//! acknowledged records behind a damaged one.)
//!
//! Whichever segment ends up active, the writer makes its size and its directory
//! entry durable before the first receipt exists: a segment found here may be the
//! product of a rotation that died before its directory entry was forced.

use super::fs::{ActiveSegment, LedgerFs, LedgerStore, StoreError};
use super::segments::SegmentInfo;
use super::store_io::StoreIo;
use super::verify::{verify_dir, CorruptKind, Tail, Verified, VerifyError, VerifyMode};
use super::writer::{AuditOpenCfg, AuditOpenError, FlowAuditWriter, Replayed, TripFn};
use crate::ingress::audit::dest::DestSealer;
use crate::lock::LockProof;

fn verify_error(error: VerifyError) -> AuditOpenError {
    match error {
        VerifyError::Corrupt {
            segment,
            line,
            kind,
        } => AuditOpenError::Corrupt {
            segment,
            line,
            kind,
        },
        VerifyError::UnsupportedFormat { found } => AuditOpenError::UnsupportedFormat { found },
        VerifyError::Store(error) => AuditOpenError::UnsafeStore(error),
        VerifyError::Io(code) => AuditOpenError::Io(code),
        // Only a reader can be inconclusive; the strict mode has no concurrent pruner.
        VerifyError::Inconclusive => AuditOpenError::Io("AUDIT_VERIFY_INCONCLUSIVE"),
    }
}

fn store_error(error: StoreError) -> AuditOpenError {
    match error {
        StoreError::Io(code) => AuditOpenError::Io(code),
        other => AuditOpenError::UnsafeStore(other),
    }
}

fn io_error(error: &std::io::Error) -> AuditOpenError {
    AuditOpenError::Io(super::fs::io_code(error))
}

/// Opens the ledger in the directory `fs` names: verifies it, repairs what a crash
/// leaves, and starts the writer.
///
/// `after_trip` is the reason of the trip that preceded this open, when this is a
/// re-open after one; it goes into `Recovered`.
///
/// # Errors
/// [`AuditOpenError`]; nothing is appended then.
pub fn open_dir(
    _lock: LockProof,
    fs: &dyn LedgerFs,
    cfg: &AuditOpenCfg,
    sealer: DestSealer,
    after_trip: Option<String>,
    on_trip: TripFn,
) -> Result<FlowAuditWriter, AuditOpenError> {
    let store = fs.open_store().map_err(AuditOpenError::UnsafeStore)?;
    let (replayed, active) = recover(&*store, after_trip)?;
    FlowAuditWriter::open_with(StoreIo::new(store, active), replayed, cfg, sealer, on_trip)
}

/// Proves the chain and brings the newest segment to a state that can be appended
/// to. Returns what the writer needs to continue and the segment to append to.
fn recover(
    store: &dyn LedgerStore,
    after_trip: Option<String>,
) -> Result<(Replayed, Box<dyn ActiveSegment>), AuditOpenError> {
    let mut verified = verify_dir(store, VerifyMode::Open).map_err(verify_error)?;
    let mut truncated_tail_bytes = 0;

    // A newest segment with no complete line and a predecessor: unlink it.
    if let Some(last) = verified.segments.last().filter(|s| s.records == 0) {
        if verified.segments.len() > 1 {
            truncated_tail_bytes = torn_bytes(&verified);
            store
                .remove_segment(last.first_seq)
                .map_err(|e| io_error(&e))?;
            store.sync_dir().map_err(|e| io_error(&e))?;
            verified = verify_dir(store, VerifyMode::Open).map_err(verify_error)?;
        }
    }

    let active: Box<dyn ActiveSegment> = match verified.segments.last() {
        None => {
            // No ledger yet: the first segment, created exclusively.
            store.create_segment(1).map_err(store_error)?
        }
        Some(last) if last.records == 0 => {
            if last.first_seq != 1 {
                // A lone segment that is not the first, with nothing in it: its
                // predecessors are gone and nothing anchors it.
                return Err(AuditOpenError::Corrupt {
                    segment: last.first_seq,
                    line: 0,
                    kind: CorruptKind::AnchorMissing,
                });
            }
            // Never acknowledged anything: a fresh chain. Cut what is there.
            truncated_tail_bytes = torn_bytes(&verified);
            let mut active = store.open_active(last.first_seq).map_err(store_error)?;
            active.truncate(0).map_err(|e| io_error(&e))?;
            active.sync_all().map_err(|e| io_error(&e))?;
            active
        }
        Some(last) => {
            let mut active = store.open_active(last.first_seq).map_err(store_error)?;
            if let Tail::Torn {
                valid_len,
                torn_bytes,
            } = verified.tail
            {
                // An append that was never acknowledged.
                active.truncate(valid_len).map_err(|e| io_error(&e))?;
                active.sync_all().map_err(|e| io_error(&e))?;
                truncated_tail_bytes = torn_bytes;
            }
            active
        }
    };

    let mut segments: Vec<SegmentInfo> = verified.segments.iter().map(SegmentInfo::from).collect();
    if segments.is_empty() {
        segments.push(SegmentInfo {
            first_seq: 1,
            records: 0,
            bytes: 0,
            first_ts_ms: 0,
        });
    }
    let replayed = Replayed {
        head: verified.head,
        last_seq: verified.last_seq,
        segments,
        class_bytes: verified.newest_class_bytes,
        unresolved: verified.unresolved,
        truncated_tail_bytes,
        after_trip,
    };
    Ok((replayed, active))
}

/// The bytes after the last complete line of the newest segment.
fn torn_bytes(verified: &Verified) -> u64 {
    match verified.tail {
        Tail::Torn { torn_bytes, .. } => torn_bytes,
        Tail::Clean => 0,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ssk_netadmin::{
        FlowDescriptor, FlowRecord, PolicyAction, PolicyDecision, ProtocolKind, RiskLevel,
        RouteOrchestrator,
    };

    use crate::ingress::audit::fs::{segment_name, UnsafeReason, LEDGER_DIR};
    use crate::ingress::audit::fs_unix::UnixLedgerFs;
    use crate::ingress::audit::input::{DeniedEvent, PendingInput};
    use crate::ingress::audit::record::{decode_line, FlowAuditEvent, FlowAuditRecord};
    use crate::ingress::audit::writer::{system_clock, Waits, SUMMARY_FLOOR};
    use crate::ingress::target::{canonicalize, Provenance, RawTarget, TargetKind};
    use crate::ingress::types::{
        lock_unpoisoned, DestinationLogging, IngressCfgView, Resolution, TripReason,
    };

    type Trips = Arc<Mutex<Vec<TripReason>>>;

    struct Dir {
        root: tempfile::TempDir,
    }

    impl Dir {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            Self { root }
        }

        fn fs(&self) -> UnixLedgerFs {
            UnixLedgerFs::new(self.root.path().to_path_buf())
        }

        fn ledger(&self) -> std::path::PathBuf {
            self.root.path().join(LEDGER_DIR)
        }

        fn segment(&self, first_seq: u64) -> std::path::PathBuf {
            self.ledger().join(segment_name(first_seq))
        }

        fn segment_seqs(&self) -> Vec<u64> {
            let mut seqs: Vec<u64> = std::fs::read_dir(self.ledger())
                .expect("list")
                .filter_map(|e| {
                    crate::ingress::audit::fs::parse_segment_name(
                        e.expect("entry").file_name().to_str().expect("name"),
                    )
                })
                .collect();
            seqs.sort_unstable();
            seqs
        }

        fn verify(&self) -> crate::ingress::audit::verify::Verified {
            let store = self.fs().open_store().expect("store");
            verify_dir(&*store, VerifyMode::Open).expect("the ledger verifies")
        }

        /// Every record of every retained segment, in order.
        fn records(&self) -> Vec<FlowAuditRecord> {
            let mut out = Vec::new();
            for first_seq in self.segment_seqs() {
                let bytes = std::fs::read(self.segment(first_seq)).expect("read");
                for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                    // The hash is not re-proved here (`verify` does that); the line is parsed.
                    let record: FlowAuditRecord =
                        serde_json::from_slice(line.get(65..).expect("a line")).expect("a record");
                    out.push(record);
                }
            }
            out
        }

        fn kinds(&self) -> Vec<&'static str> {
            self.records().iter().map(|r| r.event.kind()).collect()
        }
    }

    fn cfg(segment_bytes: u64, retain: u32) -> AuditOpenCfg {
        AuditOpenCfg {
            segment_bytes,
            retain_segments: retain,
            denied_share_percent: 100,
            summary_share_percent: 5,
            destination_logging: DestinationLogging::Plain,
            fingerprint: IngressCfgView::for_tests().fingerprint,
            daemon_version: "0.0.0-test".to_owned(),
            queue_cap: 256,
            summary_floor: SUMMARY_FLOOR,
            clock: system_clock(),
        }
    }

    fn open(
        dir: &Dir,
        segment_bytes: u64,
        retain: u32,
    ) -> Result<(FlowAuditWriter, Trips), AuditOpenError> {
        open_after(dir, segment_bytes, retain, None)
    }

    fn open_after(
        dir: &Dir,
        segment_bytes: u64,
        retain: u32,
        after_trip: Option<String>,
    ) -> Result<(FlowAuditWriter, Trips), AuditOpenError> {
        let seen: Trips = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let on_trip: TripFn = Arc::new(move |reason| lock_unpoisoned(&sink).push(reason));
        open_dir(
            LockProof::for_tests(),
            &dir.fs(),
            &cfg(segment_bytes, retain),
            DestSealer::Plain,
            after_trip,
            on_trip,
        )
        .map(|writer| (writer, seen))
    }

    const LONG: Waits = Waits {
        queue_wait: Duration::from_secs(20),
        sync_wait: Duration::from_secs(20),
    };

    async fn deny(writer: &FlowAuditWriter) {
        let target =
            canonicalize(RawTarget::Name(b"blocked.example".to_vec(), 25)).expect("target");
        writer
            .append_denied(
                DeniedEvent {
                    peer: "uid:1000",
                    peer_verified: true,
                    target: &target,
                    profile: "main",
                    matched_rule: None,
                    reason_code: "POLICY_DENY",
                    route: None,
                    coalesced: false,
                },
                LONG,
            )
            .await
            .expect("answered");
    }

    fn token(host: &str, port: u16) -> ssk_netadmin::admission::AdmissionToken {
        let flow = FlowRecord::new(
            "flow",
            0,
            FlowDescriptor::new("app", host, port, ProtocolKind::Tcp, RiskLevel::Low),
        );
        let decision = PolicyDecision {
            flow_id: flow.flow_id.clone(),
            matched_rule: None,
            action: PolicyAction::Allow,
            rationale: String::new(),
        };
        RouteOrchestrator::default()
            .admit(&flow, &decision)
            .expect("admitted")
    }

    async fn pend(writer: &FlowAuditWriter) -> crate::ingress::audit::writer::PendingReceipt {
        let token = token("example.com", 443);
        let flow = writer.next_flow_id();
        writer
            .append_pending(
                PendingInput {
                    token: &token,
                    flow_id: &flow,
                    profile: "main",
                    matched_rule: None,
                    peer: "uid:1000",
                    peer_verified: true,
                    target_kind: TargetKind::Name,
                    provenance: Provenance::ClientSuppliedName,
                    resolution: Resolution::LocalPinned,
                    planned_adapters: &[],
                },
                LONG,
            )
            .await
            .expect("pending")
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777
    }

    // -- a fresh directory and a reopened one ----------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_fresh_directory_gets_its_first_segment_and_a_started_record() {
        let dir = Dir::new();
        let (writer, seen) = open(&dir, 1 << 20, 4).expect("opens");
        assert_eq!(dir.segment_seqs(), [1]);
        assert_eq!(mode_of(&dir.segment(1)), 0o600);
        assert_eq!(mode_of(&dir.ledger()), 0o700);
        assert_eq!(dir.kinds(), ["started"]);
        let status = writer.status();
        assert_eq!(
            (status.entries, status.segments, status.pruned_entries),
            (1, 1, 0)
        );
        assert_eq!(writer.boot_seq(), 1);
        writer.close(Duration::from_secs(10)).await;
        assert!(lock_unpoisoned(&seen).is_empty());
        let v = dir.verify();
        assert_eq!(v.entries, 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reopened_directory_continues_the_chain_and_counts_what_was_left_open() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        deny(&writer).await;
        // A flow whose Pending has no Result when the process dies: the receipt is
        // forgotten, as a crash forgets it.
        let lost = pend(&writer).await;
        std::mem::forget(lost);
        writer.close(Duration::from_secs(10)).await;
        let before = dir.verify();
        assert_eq!(before.last_seq, Some(3));

        let (again, _) = open(&dir, 1 << 20, 4).expect("reopens");
        assert_eq!(again.boot_seq(), 4);
        assert_eq!(again.next_flow_id(), "ingress:b4:1");
        again.close(Duration::from_secs(10)).await;
        let records = dir.records();
        match &records.last().expect("started").event {
            FlowAuditEvent::Started {
                unresolved_before, ..
            } => assert_eq!(unresolved_before.pending, 1),
            other => panic!("not Started: {other:?}"),
        }
        let v = dir.verify();
        assert_eq!(v.last_seq, Some(4));
        assert_eq!(v.unresolved.pending, 1);
        assert_eq!(dir.kinds(), ["started", "denied", "pending", "started"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reopen_after_a_trip_says_so() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        writer.close(Duration::from_secs(10)).await;
        let (again, _) =
            open_after(&dir, 1 << 20, 4, Some("audit_stalled".to_owned())).expect("reopens");
        again.close(Duration::from_secs(10)).await;
        assert_eq!(dir.kinds(), ["started", "recovered", "started"]);
        match &dir.records()[1].event {
            FlowAuditEvent::Recovered {
                truncated_tail_bytes,
                after_trip,
                ..
            } => {
                assert_eq!(*truncated_tail_bytes, 0);
                assert_eq!(after_trip.as_deref(), Some("audit_stalled"));
            }
            other => panic!("not Recovered: {other:?}"),
        }
    }

    // -- the end of a crashed process ----------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_torn_tail_is_cut_and_recorded() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        deny(&writer).await;
        writer.close(Duration::from_secs(10)).await;
        let clean = std::fs::read(dir.segment(1)).expect("read");
        // A write that did not finish: half a line, never acknowledged.
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.segment(1))
            .expect("open");
        file.write_all(b"0123456789abcdef0123456789abcdef0123")
            .expect("write");
        drop(file);

        let (again, _) = open(&dir, 1 << 20, 4).expect("reopens");
        again.close(Duration::from_secs(10)).await;
        let after = std::fs::read(dir.segment(1)).expect("read");
        assert!(
            after.starts_with(&clean),
            "the acknowledged lines are untouched"
        );
        assert!(!String::from_utf8_lossy(&after).contains("0123456789abcdef0123456789abcdef0123"));
        assert_eq!(dir.kinds(), ["started", "denied", "recovered", "started"]);
        match &dir.records()[2].event {
            FlowAuditEvent::Recovered {
                truncated_tail_bytes,
                after_trip,
                ..
            } => {
                assert_eq!(*truncated_tail_bytes, 36);
                assert_eq!(*after_trip, None);
            }
            other => panic!("not Recovered: {other:?}"),
        }
        dir.verify();
    }

    /// Fills the ledger until it has rotated, then returns the writer's directory
    /// with the writer closed.
    async fn rotated(dir: &Dir, retain: u32) {
        let (writer, _) = open(dir, 1_200, retain).expect("opens");
        for _ in 0..12 {
            deny(&writer).await;
        }
        writer.close(Duration::from_secs(10)).await;
        assert!(dir.segment_seqs().len() >= 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_empty_newest_segment_is_unlinked_and_its_predecessor_is_active_again() {
        for leftover in [&b""[..], b"0123456789"] {
            let dir = Dir::new();
            rotated(&dir, 8).await;
            let seqs = dir.segment_seqs();
            let last = *seqs.last().expect("segment");
            let next = last + 1_000;
            let records_before = dir.records().len();
            // A crash after creating the next segment, before its first record was durable.
            std::fs::write(dir.segment(next), leftover).expect("write");
            std::fs::set_permissions(dir.segment(next), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");

            let (writer, _) = open(&dir, 1_200, 8).expect("reopens");
            assert!(!dir.segment(next).exists(), "the leftover is gone");
            assert!(dir.segment_seqs().contains(&last) || last < dir.segment_seqs()[0]);
            deny(&writer).await;
            writer.close(Duration::from_secs(10)).await;
            let v = dir.verify();
            assert!(usize::try_from(v.entries).expect("fits") >= records_before + 2);
            let recovered = dir.kinds().contains(&"recovered");
            assert_eq!(
                recovered,
                !leftover.is_empty(),
                "a Recovered only when bytes were cut"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lone_first_segment_with_only_a_partial_line_is_a_fresh_chain() {
        let dir = Dir::new();
        // The directory and the first segment exist; the first record never became durable.
        {
            let store = dir.fs().open_store().expect("store");
            let mut segment = store.create_segment(1).expect("creates");
            segment.append(b"01234567").expect("append");
        }
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        writer.close(Duration::from_secs(10)).await;
        assert_eq!(dir.kinds(), ["recovered", "started"]);
        assert_eq!(dir.records().first().map(|r| r.seq), Some(1));
        match &dir.records()[0].event {
            FlowAuditEvent::Recovered {
                truncated_tail_bytes,
                ..
            } => assert_eq!(*truncated_tail_bytes, 8),
            other => panic!("not Recovered: {other:?}"),
        }
        dir.verify();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lone_segment_that_is_not_the_first_and_is_empty_is_corrupt() {
        let dir = Dir::new();
        {
            let store = dir.fs().open_store().expect("store");
            drop(store.create_segment(77).expect("creates"));
        }
        let result = open(&dir, 1 << 20, 4);
        assert_eq!(
            result.err(),
            Some(AuditOpenError::Corrupt {
                segment: 77,
                line: 0,
                kind: CorruptKind::AnchorMissing
            })
        );
    }

    // -- what is refused ------------------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_changed_byte_is_corruption_and_nothing_is_appended() {
        let dir = Dir::new();
        rotated(&dir, 8).await;
        let seqs = dir.segment_seqs();
        let victim = seqs[1];
        let mut bytes = std::fs::read(dir.segment(victim)).expect("read");
        let at = bytes.len() / 2;
        bytes[at] = if bytes[at] == b'x' { b'y' } else { b'x' };
        std::fs::write(dir.segment(victim), &bytes).expect("write");
        let before: Vec<Vec<u8>> = seqs
            .iter()
            .map(|s| std::fs::read(dir.segment(*s)).expect("read"))
            .collect();
        let result = open(&dir, 1_200, 8);
        match result {
            Err(AuditOpenError::Corrupt { segment, .. }) => assert_eq!(segment, victim),
            other => panic!("not corrupt: {:?}", other.err()),
        }
        let after: Vec<Vec<u8>> = seqs
            .iter()
            .map(|s| std::fs::read(dir.segment(*s)).expect("read"))
            .collect();
        assert_eq!(before, after, "never repaired");
        assert_eq!(dir.segment_seqs(), seqs);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_ledger_of_a_newer_format_is_not_read_or_appended_to() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        writer.close(Duration::from_secs(10)).await;
        // Rewrite the Started record as a newer format, with a chain that is intact.
        let line = std::fs::read(dir.segment(1)).expect("read");
        let line = line.split(|b| *b == b'\n').next().expect("line");
        let decoded = decode_line("genesis", line).expect("decodes");
        let FlowAuditEvent::Started {
            daemon_version,
            config,
            destination_logging,
            dest_key_id,
            unresolved_before,
            ..
        } = decoded.record.event
        else {
            panic!("started");
        };
        let newer = FlowAuditRecord {
            seq: 1,
            ts_ms: decoded.record.ts_ms,
            flow_id: String::new(),
            event: FlowAuditEvent::Started {
                daemon_version,
                ledger_format: 2,
                config,
                destination_logging,
                dest_key_id,
                unresolved_before,
            },
        };
        let encoded =
            crate::ingress::audit::record::encode_line("genesis", &newer).expect("encodes");
        std::fs::write(dir.segment(1), &encoded.bytes).expect("write");
        let result = open(&dir, 1 << 20, 4);
        assert_eq!(
            result.err(),
            Some(AuditOpenError::UnsupportedFormat { found: 2 })
        );
        assert_eq!(std::fs::read(dir.segment(1)).expect("read"), encoded.bytes);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unsafe_store_is_refused_before_anything_is_read() {
        // A group-writable state root.
        let dir = Dir::new();
        std::fs::set_permissions(dir.root.path(), std::fs::Permissions::from_mode(0o775))
            .expect("chmod");
        assert_eq!(
            open(&dir, 1 << 20, 4).err(),
            Some(AuditOpenError::UnsafeStore(StoreError::RootUnsafe(
                UnsafeReason::GroupOrOtherWritable
            )))
        );
        assert!(!dir.ledger().exists());
        // A group-readable segment in an otherwise good directory.
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1 << 20, 4).expect("opens");
        writer.close(Duration::from_secs(10)).await;
        std::fs::set_permissions(dir.segment(1), std::fs::Permissions::from_mode(0o644))
            .expect("chmod");
        assert_eq!(
            open(&dir, 1 << 20, 4).err(),
            Some(AuditOpenError::UnsafeStore(StoreError::FileUnsafe(
                UnsafeReason::GroupOrOtherAccess
            )))
        );
    }

    // -- crash windows of a rotation -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn more_segments_than_the_retention_are_pruned_by_the_next_rotation() {
        let dir = Dir::new();
        // Written with a retention of eight, reopened with one of three: the state a
        // crash between making the new segment durable and unlinking the old ones leaves.
        rotated(&dir, 8).await;
        assert!(dir.segment_seqs().len() > 3);
        let (writer, _) = open(&dir, 1_200, 3).expect("reopens");
        for _ in 0..12 {
            deny(&writer).await;
        }
        writer.close(Duration::from_secs(10)).await;
        assert_eq!(dir.segment_seqs().len(), 3);
        dir.verify();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_pruned_segment_that_reappears_is_a_valid_prefix_and_goes_again() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1_200, 3).expect("opens");
        // Run until the first prune happened.
        let mut saved: Option<(u64, Vec<u8>)> = None;
        for _ in 0..60 {
            let before = dir.segment_seqs();
            if let Some(oldest) = before.first() {
                saved = Some((*oldest, std::fs::read(dir.segment(*oldest)).expect("read")));
            }
            deny(&writer).await;
            if dir.segment_seqs().first() != before.first() {
                break;
            }
        }
        writer.close(Duration::from_secs(10)).await;
        let (gone, bytes) = saved.expect("a segment was pruned");
        assert!(!dir.segment(gone).exists());
        // The unlink was not durable: the file is back.
        std::fs::write(dir.segment(gone), &bytes).expect("restore");
        std::fs::set_permissions(dir.segment(gone), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
        let v = dir.verify();
        assert_eq!(v.segments.first().map(|s| s.first_seq), Some(gone));
        let (writer, _) = open(&dir, 1_200, 3).expect("reopens");
        for _ in 0..20 {
            deny(&writer).await;
        }
        writer.close(Duration::from_secs(10)).await;
        assert!(!dir.segment(gone).exists(), "pruned again");
        assert_eq!(dir.segment_seqs().len(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_refusal_quota_survives_a_restart() {
        let dir = Dir::new();
        // 30 kB segments; refusals may use 20 percent of one: about 15 denials.
        let mut config = cfg(30_000, 4);
        config.denied_share_percent = 20;
        let open_quota = |dir: &Dir, config: &AuditOpenCfg| {
            let on_trip: TripFn = Arc::new(|_| {});
            open_dir(
                LockProof::for_tests(),
                &dir.fs(),
                config,
                DestSealer::Plain,
                None,
                on_trip,
            )
            .expect("opens")
        };
        let writer = open_quota(&dir, &config);
        let mut recorded_first = 0_u64;
        for _ in 0..40 {
            if deny_outcome(&writer).await == "recorded" {
                recorded_first += 1;
            }
        }
        writer.close(Duration::from_secs(10)).await;
        assert!(recorded_first > 0 && recorded_first < 40);
        // The share was used before the restart: it is still used after it.
        let writer = open_quota(&dir, &config);
        assert_eq!(deny_outcome(&writer).await, "over_quota");
        writer.close(Duration::from_secs(10)).await;
    }

    async fn deny_outcome(writer: &FlowAuditWriter) -> &'static str {
        use crate::ingress::audit::writer::DeniedOutcome;
        let target =
            canonicalize(RawTarget::Name(b"blocked.example".to_vec(), 25)).expect("target");
        match writer
            .append_denied(
                DeniedEvent {
                    peer: "uid:1000",
                    peer_verified: true,
                    target: &target,
                    profile: "main",
                    matched_rule: None,
                    reason_code: "POLICY_DENY",
                    route: None,
                    coalesced: false,
                },
                LONG,
            )
            .await
            .expect("answered")
        {
            DeniedOutcome::Recorded(_) => "recorded",
            DeniedOutcome::OverQuota => "over_quota",
        }
    }

    // -- a reader while the writer works -------------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reader_verifies_the_ledger_while_it_is_written_and_pruned() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1_500, 3).expect("opens");
        let fs = dir.fs();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let (mut ok, mut inconclusive) = (0_u64, 0_u64);
                while !stop.load(std::sync::atomic::Ordering::Acquire) {
                    let store = fs.open_store().expect("store");
                    match verify_dir(&*store, VerifyMode::Reader) {
                        Ok(_) => ok += 1,
                        Err(VerifyError::Inconclusive) => inconclusive += 1,
                        Err(other) => panic!("a reader must never see damage: {other:?}"),
                    }
                }
                (ok, inconclusive)
            })
        };
        for _ in 0..400 {
            deny(&writer).await;
        }
        stop.store(true, std::sync::atomic::Ordering::Release);
        let (ok, inconclusive) = reader.join().expect("reader");
        assert!(ok > 0, "{ok} {inconclusive}");
        writer.close(Duration::from_secs(10)).await;
        dir.verify();
        assert!(writer_rotated(&dir));
    }

    fn writer_rotated(dir: &Dir) -> bool {
        dir.segment_seqs().first().is_some_and(|first| *first > 1)
    }

    // -- the pieces of recovery, with the store watched -----------------------------------------------

    type Log = Arc<Mutex<Vec<String>>>;

    /// A store that does what the real one does and notes the operations whose order
    /// is the point of recovery.
    struct Spy {
        inner: Box<dyn LedgerStore>,
        log: Log,
    }

    struct SpyActive {
        inner: Box<dyn ActiveSegment>,
        log: Log,
        first_seq: u64,
    }

    fn note(log: &Log, what: String) {
        lock_unpoisoned(log).push(what);
    }

    impl ActiveSegment for SpyActive {
        fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            self.inner.append(bytes)
        }
        fn sync_data(&mut self) -> std::io::Result<()> {
            self.inner.sync_data()
        }
        fn sync_all(&mut self) -> std::io::Result<()> {
            note(&self.log, format!("sync_all {}", self.first_seq));
            self.inner.sync_all()
        }
        fn stat(&self) -> std::io::Result<crate::ingress::audit::fs::ActiveStat> {
            self.inner.stat()
        }
        fn truncate(&mut self, len: u64) -> std::io::Result<()> {
            note(&self.log, format!("truncate {} {len}", self.first_seq));
            self.inner.truncate(len)
        }
    }

    impl Spy {
        fn watch(&self, active: Box<dyn ActiveSegment>, first_seq: u64) -> Box<dyn ActiveSegment> {
            Box::new(SpyActive {
                inner: active,
                log: Arc::clone(&self.log),
                first_seq,
            })
        }
    }

    impl LedgerStore for Spy {
        fn created(&self) -> bool {
            self.inner.created()
        }
        fn segments(&self) -> Result<crate::ingress::audit::fs::Segments, StoreError> {
            self.inner.segments()
        }
        fn open_reader(
            &self,
            first_seq: u64,
        ) -> Result<crate::ingress::audit::fs::SegmentReader, StoreError> {
            self.inner.open_reader(first_seq)
        }
        fn open_active(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
            note(&self.log, format!("open_active {first_seq}"));
            Ok(self.watch(self.inner.open_active(first_seq)?, first_seq))
        }
        fn create_segment(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
            note(&self.log, format!("create {first_seq}"));
            Ok(self.watch(self.inner.create_segment(first_seq)?, first_seq))
        }
        fn remove_segment(&self, first_seq: u64) -> std::io::Result<()> {
            note(&self.log, format!("remove {first_seq}"));
            self.inner.remove_segment(first_seq)
        }
        fn sync_dir(&self) -> std::io::Result<()> {
            note(&self.log, "sync_dir".to_owned());
            self.inner.sync_dir()
        }
    }

    fn spied(dir: &Dir) -> (Spy, Log) {
        let log: Log = Arc::default();
        let spy = Spy {
            inner: dir.fs().open_store().expect("store"),
            log: Arc::clone(&log),
        };
        (spy, log)
    }

    fn steps(log: &Log) -> Vec<String> {
        lock_unpoisoned(log).clone()
    }

    /// A directory with one real segment (the first record of a fresh daemon).
    async fn one_segment(dir: &Dir) {
        let (writer, _) = open(dir, 1 << 20, 4).expect("opens");
        writer.close(Duration::from_secs(10)).await;
        assert_eq!(dir.segment_seqs(), [1]);
    }

    #[test]
    fn a_fresh_directory_is_created_with_its_first_segment() {
        let dir = Dir::new();
        let (spy, log) = spied(&dir);
        let (replayed, _active) = recover(&spy, None).expect("recovers");
        assert_eq!(steps(&log), ["create 1"]);
        assert_eq!(replayed.truncated_tail_bytes, 0);
        assert_eq!(replayed.last_seq, None);
        assert_eq!(replayed.head, "genesis");
        assert_eq!(
            replayed.segments,
            [SegmentInfo {
                first_seq: 1,
                records: 0,
                bytes: 0,
                first_ts_ms: 0
            }]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_segment_that_never_held_a_record_is_unlinked_and_the_directory_made_durable() {
        // One real segment and a leftover of a rotation that did not get as far as its
        // first record: exactly two segments.
        for (leftover, cut) in [(&b""[..], 0_u64), (b"0123456789", 10)] {
            let dir = Dir::new();
            one_segment(&dir).await;
            std::fs::write(dir.segment(1_000), leftover).expect("write");
            std::fs::set_permissions(dir.segment(1_000), std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            let (spy, log) = spied(&dir);
            let (replayed, _active) = recover(&spy, None).expect("recovers");
            assert_eq!(steps(&log), ["remove 1000", "sync_dir", "open_active 1"]);
            assert_eq!(replayed.truncated_tail_bytes, cut);
            assert_eq!(dir.segment_seqs(), [1]);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_torn_tail_is_cut_and_made_durable_before_anything_is_appended() {
        let dir = Dir::new();
        one_segment(&dir).await;
        let valid = std::fs::metadata(dir.segment(1)).expect("stat").len();
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.segment(1))
            .expect("open");
        file.write_all(b"0123456789abc").expect("write");
        drop(file);
        let (spy, log) = spied(&dir);
        let (replayed, _active) = recover(&spy, None).expect("recovers");
        assert_eq!(
            steps(&log),
            [
                "open_active 1".to_owned(),
                format!("truncate 1 {valid}"),
                "sync_all 1".to_owned()
            ]
        );
        assert_eq!(replayed.truncated_tail_bytes, 13);
        assert_eq!(
            replayed.segments.last().map(|s| s.bytes),
            Some(valid),
            "the book holds what is left"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lone_first_segment_without_a_record_is_cut_to_nothing_and_made_durable() {
        let dir = Dir::new();
        {
            let store = dir.fs().open_store().expect("store");
            let mut segment = store.create_segment(1).expect("creates");
            segment.append(b"01234567").expect("append");
        }
        let (spy, log) = spied(&dir);
        let (replayed, _active) = recover(&spy, None).expect("recovers");
        assert_eq!(steps(&log), ["open_active 1", "truncate 1 0", "sync_all 1"]);
        assert_eq!(replayed.truncated_tail_bytes, 8);
        assert_eq!(replayed.last_seq, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_trip_that_preceded_an_open_is_carried_to_the_writer() {
        let dir = Dir::new();
        one_segment(&dir).await;
        let (spy, _log) = spied(&dir);
        let (replayed, _active) = recover(&spy, Some("WRITE_FAULT".to_owned())).expect("recovers");
        assert_eq!(replayed.after_trip.as_deref(), Some("WRITE_FAULT"));
    }

    #[test]
    fn a_verification_that_gave_up_is_an_io_error_of_its_own() {
        assert_eq!(
            verify_error(VerifyError::Inconclusive),
            AuditOpenError::Io("AUDIT_VERIFY_INCONCLUSIVE")
        );
        assert_eq!(
            verify_error(VerifyError::Io("AUDIT_READ")),
            AuditOpenError::Io("AUDIT_READ")
        );
        assert_eq!(
            verify_error(VerifyError::Store(StoreError::Unsupported)),
            AuditOpenError::UnsafeStore(StoreError::Unsupported)
        );
    }

    #[test]
    fn a_store_error_keeps_its_io_code_and_everything_else_is_an_unsafe_store() {
        assert_eq!(
            store_error(StoreError::Io("AUDIT_DISK_FULL")),
            AuditOpenError::Io("AUDIT_DISK_FULL")
        );
        assert_eq!(
            store_error(StoreError::Unsupported),
            AuditOpenError::UnsafeStore(StoreError::Unsupported)
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn status_after_a_reopen_counts_what_the_directory_retains() {
        let dir = Dir::new();
        let (writer, _) = open(&dir, 1_200, 3).expect("opens");
        for _ in 0..30 {
            deny(&writer).await;
        }
        writer.close(Duration::from_secs(10)).await;
        assert_eq!(dir.segment_seqs().len(), 3, "pruned down to the retention");

        let (again, _) = open(&dir, 1_200, 3).expect("reopens");
        let status = again.status();
        let on_disk = dir.verify();
        assert_eq!(status.entries, on_disk.entries);
        assert_eq!(status.bytes, on_disk.bytes);
        assert_eq!(status.pruned_entries, on_disk.pruned_entries());
        assert_eq!(status.oldest_ts_ms, on_disk.oldest_ts_ms);
        assert!(status.oldest_ts_ms.is_some());
        assert_eq!(
            usize::try_from(status.segments).expect("fits"),
            dir.segment_seqs().len()
        );
        assert_eq!(status.head, on_disk.head);
        again.close(Duration::from_secs(10)).await;
    }
}
