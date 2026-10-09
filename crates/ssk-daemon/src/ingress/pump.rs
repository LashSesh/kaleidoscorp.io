//! The byte pump of an admitted flow (design 6.8): client socket on one side, the
//! upstream transport on the other, until one of five things ends it.
//!
//! * **Counted.** Both ends are wrapped so the byte counts live in atomics owned
//!   by the caller ([`ByteCounts`]): they survive an error, an idle timeout and a
//!   cancellation that drops this future, which is what lets the `Closed` record
//!   report what really moved. `up` is what was written to the upstream, `down`
//!   what was written to the client: counted by the proxy on its two sockets, not
//!   confirmed by the destination.
//! * **Bounded.** `copy_bidirectional_with_sizes` with 16 KiB per direction, so a
//!   tunnel costs about 32 KiB however much data a peer pushes and however slowly
//!   the other side reads.
//! * **Cancelled by the gate.** Any change of the gate since the flow was
//!   admitted (a disarm, a re-arm, a trip, shutdown) ends the pump at once and
//!   before another byte moves; a gate whose sender is gone counts as changed.
//!   Cancellation returns, the caller drops both sockets: an abrupt close, the
//!   repository's fail-closed convention.
//! * **Idle.** No byte in either direction for `idle` ends the pump. A
//!   half-closed tunnel is idle like any other.
//! * **Proof.** A [`ResultProof`] is required: no application byte moves before
//!   the `Result` record of the flow is durable.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;
use tokio::time::Instant;

use super::types::{Gate, ResultProof};

/// Per direction.
pub const COPY_BUFFER: usize = 16 * 1024;

/// How a pump ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PumpEnd {
    /// Both directions reached EOF and were shut down in turn.
    Eof,
    /// Nothing moved for the idle timeout.
    IdleTimeout,
    /// The gate changed (or its sender went away).
    GateClosed,
    /// The client socket failed.
    ClientError,
    /// The upstream transport failed.
    UpstreamError,
}

impl PumpEnd {
    /// The word `Closed.reason` carries.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Eof => "eof",
            Self::IdleTimeout => "idle_timeout",
            Self::GateClosed => "gate_closed",
            Self::ClientError => "client_error",
            Self::UpstreamError => "upstream_error",
        }
    }
}

/// Bytes written in each direction. Owned by the flow, shared with the pump, read
/// after the pump ended or was dropped.
#[derive(Debug, Default)]
pub struct ByteCounts {
    up: AtomicU64,
    down: AtomicU64,
}

impl ByteCounts {
    /// Counts that already hold a value, for tests of what reads them.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_counts(up: u64, down: u64) -> Self {
        Self {
            up: AtomicU64::new(up),
            down: AtomicU64::new(down),
        }
    }

    /// Bytes written to the upstream (client to destination).
    #[must_use]
    pub fn up(&self) -> u64 {
        self.up.load(Ordering::Relaxed)
    }

    /// Bytes written to the client (destination to client).
    #[must_use]
    pub fn down(&self) -> u64 {
        self.down.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Client,
    Upstream,
}

const FAILED_NONE: u8 = 0;
const FAILED_CLIENT: u8 = 1;
const FAILED_UPSTREAM: u8 = 2;

/// What the two wrappers share.
struct Shared<'a> {
    counts: &'a ByteCounts,
    base: Instant,
    /// Milliseconds after `base` of the latest byte in either direction.
    activity_ms: AtomicU64,
    /// Which end reported the first I/O error.
    failed: AtomicU8,
}

impl Shared<'_> {
    fn touch(&self) {
        let elapsed = Instant::now().saturating_duration_since(self.base);
        let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.activity_ms.fetch_max(ms, Ordering::Relaxed);
    }

    fn fail(&self, end: End) {
        let code = match end {
            End::Client => FAILED_CLIENT,
            End::Upstream => FAILED_UPSTREAM,
        };
        let _ =
            self.failed
                .compare_exchange(FAILED_NONE, code, Ordering::Relaxed, Ordering::Relaxed);
    }

    fn wrote(&self, end: End, bytes: usize) {
        let n = u64::try_from(bytes).unwrap_or(u64::MAX);
        let counter = match end {
            End::Client => &self.counts.down,
            End::Upstream => &self.counts.up,
        };
        counter.fetch_add(n, Ordering::Relaxed);
        self.touch();
    }

    /// When the idle timeout fires if nothing else moves.
    fn idle_deadline(&self, idle: Duration) -> Instant {
        let last = Duration::from_millis(self.activity_ms.load(Ordering::Relaxed));
        self.base
            .checked_add(last)
            .and_then(|at| at.checked_add(idle))
            .unwrap_or_else(|| {
                // An absurd timeout is "never": a year from now.
                Instant::now()
                    .checked_add(Duration::from_secs(365 * 24 * 3600))
                    .unwrap_or_else(Instant::now)
            })
    }

    fn failed_end(&self) -> PumpEnd {
        match self.failed.load(Ordering::Relaxed) {
            FAILED_UPSTREAM => PumpEnd::UpstreamError,
            _ => PumpEnd::ClientError,
        }
    }
}

/// One end of the tunnel, counting what is written to it and noting the first
/// error it reports.
struct Counted<'a, 'b, T> {
    inner: &'a mut T,
    shared: &'a Shared<'b>,
    end: End,
}

impl<T: AsyncRead + Unpin> AsyncRead for Counted<'_, '_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut *self.inner).poll_read(cx, buf);
        match &poll {
            Poll::Ready(Ok(())) if buf.filled().len() > before => self.shared.touch(),
            Poll::Ready(Err(_)) => self.shared.fail(self.end),
            _ => {}
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<'_, '_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut *self.inner).poll_write(cx, data);
        match &poll {
            Poll::Ready(Ok(n)) => self.shared.wrote(self.end, *n),
            Poll::Ready(Err(_)) => self.shared.fail(self.end),
            Poll::Pending => {}
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.inner).poll_flush(cx);
        if let Poll::Ready(Err(_)) = &poll {
            self.shared.fail(self.end);
        }
        poll
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut *self.inner).poll_shutdown(cx);
        if let Poll::Ready(Err(_)) = &poll {
            self.shared.fail(self.end);
        }
        poll
    }
}

/// `true` while the gate is still the one the flow was admitted under.
pub(crate) fn gate_unchanged(gate: &watch::Receiver<Gate>, epoch: u64) -> bool {
    gate.borrow().epoch == epoch
}

/// Completes when the gate has changed or its sender is gone. Cancel-safe.
pub(crate) async fn gate_changed(gate: &mut watch::Receiver<Gate>, epoch: u64) {
    loop {
        if !gate_unchanged(gate, epoch) {
            return;
        }
        if gate.changed().await.is_err() {
            return;
        }
    }
}

/// Moves bytes both ways until [`PumpEnd`]. `epoch` is the gate epoch the flow
/// was admitted under.
pub async fn pump<C, U, P>(
    client: &mut C,
    upstream: &mut U,
    _proof: &P,
    idle: Duration,
    gate: &mut watch::Receiver<Gate>,
    epoch: u64,
    counts: &ByteCounts,
) -> PumpEnd
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
    P: ResultProof,
{
    let shared = Shared {
        counts,
        base: Instant::now(),
        activity_ms: AtomicU64::new(0),
        failed: AtomicU8::new(FAILED_NONE),
    };
    let mut client_end = Counted {
        inner: client,
        shared: &shared,
        end: End::Client,
    };
    let mut upstream_end = Counted {
        inner: upstream,
        shared: &shared,
        end: End::Upstream,
    };
    let copy =
        copy_bidirectional_with_sizes(&mut client_end, &mut upstream_end, COPY_BUFFER, COPY_BUFFER);
    tokio::pin!(copy);
    // `biased`: the gate is polled first, so a flow whose gate has already moved
    // on returns before the copy is polled once and moves no byte.
    loop {
        let deadline = shared.idle_deadline(idle);
        tokio::select! {
            biased;
            () = gate_changed(gate, epoch) => return PumpEnd::GateClosed,
            finished = &mut copy => {
                return match finished {
                    Ok(_) => PumpEnd::Eof,
                    Err(_) => shared.failed_end(),
                };
            }
            () = tokio::time::sleep_until(deadline) => {
                // Something may have moved while the sleep was pending; only a
                // deadline that is still current ends the flow.
                if Instant::now() >= shared.idle_deadline(idle) {
                    return PumpEnd::IdleTimeout;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::types::{sealed, GateMode};
    use std::sync::Arc;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};

    struct Proof;
    impl sealed::Sealed for Proof {}
    impl ResultProof for Proof {}

    const EPOCH: u64 = 7;

    fn armed(epoch: u64) -> Gate {
        Gate {
            epoch,
            mode: GateMode::Armed {
                profile: Arc::from("work"),
            },
        }
    }

    struct Rig {
        /// The test's end of the client socket.
        client: DuplexStream,
        /// The test's end of the upstream transport.
        far: DuplexStream,
        /// What the pump is given.
        pump_client: DuplexStream,
        pump_upstream: DuplexStream,
        gate_tx: watch::Sender<Gate>,
        gate_rx: watch::Receiver<Gate>,
        counts: Arc<ByteCounts>,
    }

    fn rig(buffer: usize) -> Rig {
        rig_with(buffer, buffer)
    }

    fn rig_with(client_buffer: usize, upstream_buffer: usize) -> Rig {
        let (client, pump_client) = duplex(client_buffer);
        let (far, pump_upstream) = duplex(upstream_buffer);
        let (gate_tx, gate_rx) = watch::channel(armed(EPOCH));
        Rig {
            client,
            far,
            pump_client,
            pump_upstream,
            gate_tx,
            gate_rx,
            counts: Arc::new(ByteCounts::default()),
        }
    }

    async fn run_pump(
        mut pump_client: DuplexStream,
        mut pump_upstream: DuplexStream,
        mut gate_rx: watch::Receiver<Gate>,
        counts: Arc<ByteCounts>,
        idle: Duration,
    ) -> PumpEnd {
        pump(
            &mut pump_client,
            &mut pump_upstream,
            &Proof,
            idle,
            &mut gate_rx,
            EPOCH,
            &counts,
        )
        .await
    }

    fn spawn_pump(rig: Rig, idle: Duration) -> PumpHandle {
        let counts = Arc::clone(&rig.counts);
        let task = tokio::spawn(run_pump(
            rig.pump_client,
            rig.pump_upstream,
            rig.gate_rx,
            Arc::clone(&counts),
            idle,
        ));
        PumpHandle {
            client: rig.client,
            far: rig.far,
            gate_tx: rig.gate_tx,
            counts,
            task,
        }
    }

    struct PumpHandle {
        client: DuplexStream,
        far: DuplexStream,
        gate_tx: watch::Sender<Gate>,
        counts: Arc<ByteCounts>,
        task: tokio::task::JoinHandle<PumpEnd>,
    }

    const LONG: Duration = Duration::from_secs(3600);

    #[tokio::test(start_paused = true)]
    async fn counts_bytes_both_directions() {
        let mut h = spawn_pump(rig(64 * 1024), LONG);
        h.client.write_all(&[1; 1000]).await.expect("write");
        let mut up = vec![0_u8; 1000];
        h.far.read_exact(&mut up).await.expect("read");
        assert_eq!(up, vec![1; 1000]);
        h.far.write_all(&[2; 2500]).await.expect("write");
        let mut down = vec![0_u8; 2500];
        h.client.read_exact(&mut down).await.expect("read");
        assert_eq!(down, vec![2; 2500]);

        assert_eq!((h.counts.up(), h.counts.down()), (1000, 2500));
        drop(h.client);
        drop(h.far);
        assert_eq!(h.task.await.expect("join"), PumpEnd::Eof);
        assert_eq!((h.counts.up(), h.counts.down()), (1000, 2500));
    }

    #[tokio::test(start_paused = true)]
    async fn a_megabyte_each_way_arrives_intact_and_is_counted() {
        let h = spawn_pump(rig(8 * 1024), LONG);
        let up: Vec<u8> = (0..1_000_000_u32)
            .map(|n| u8::try_from(n % 251).expect("byte"))
            .collect();
        let down: Vec<u8> = (0..1_000_000_u32)
            .map(|n| u8::try_from(n % 241).expect("byte"))
            .collect();
        let (mut client_read, mut client_write) = tokio::io::split(h.client);
        let (mut far_read, mut far_write) = tokio::io::split(h.far);
        let (up_c, down_c) = (up.clone(), down.clone());
        let writer_up = tokio::spawn(async move {
            client_write.write_all(&up_c).await.expect("write");
            client_write.shutdown().await.expect("shutdown");
        });
        let writer_down = tokio::spawn(async move {
            far_write.write_all(&down_c).await.expect("write");
            far_write.shutdown().await.expect("shutdown");
        });
        let mut got_up = Vec::new();
        far_read.read_to_end(&mut got_up).await.expect("read");
        let mut got_down = Vec::new();
        client_read.read_to_end(&mut got_down).await.expect("read");
        writer_up.await.expect("join");
        writer_down.await.expect("join");
        assert_eq!(got_up, up);
        assert_eq!(got_down, down);
        assert_eq!(h.task.await.expect("join"), PumpEnd::Eof);
        assert_eq!((h.counts.up(), h.counts.down()), (1_000_000, 1_000_000));
    }

    #[tokio::test(start_paused = true)]
    async fn half_close_is_propagated_each_way() {
        // The client finishes sending first; the destination still answers.
        let mut h = spawn_pump(rig(4096), LONG);
        h.client.write_all(b"ping").await.expect("write");
        h.client.shutdown().await.expect("half close");
        let mut request = Vec::new();
        h.far
            .read_to_end(&mut request)
            .await
            .expect("EOF reaches the upstream");
        assert_eq!(request, b"ping");
        h.far
            .write_all(b"pong")
            .await
            .expect("the other direction is still open");
        h.far.shutdown().await.expect("half close");
        let mut reply = Vec::new();
        h.client
            .read_to_end(&mut reply)
            .await
            .expect("EOF reaches the client");
        assert_eq!(reply, b"pong");
        assert_eq!(h.task.await.expect("join"), PumpEnd::Eof);
        assert_eq!((h.counts.up(), h.counts.down()), (4, 4));

        // And the other way round: the destination finishes first.
        let mut h = spawn_pump(rig(4096), LONG);
        h.far.write_all(b"banner").await.expect("write");
        h.far.shutdown().await.expect("half close");
        let mut banner = Vec::new();
        h.client
            .read_to_end(&mut banner)
            .await
            .expect("EOF reaches the client");
        assert_eq!(banner, b"banner");
        h.client
            .write_all(b"ok")
            .await
            .expect("the other direction is still open");
        h.client.shutdown().await.expect("half close");
        let mut ack = Vec::new();
        h.far
            .read_to_end(&mut ack)
            .await
            .expect("EOF reaches the upstream");
        assert_eq!(ack, b"ok");
        assert_eq!(h.task.await.expect("join"), PumpEnd::Eof);
        assert_eq!((h.counts.up(), h.counts.down()), (2, 6));
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_cancels_and_keeps_counts() {
        let idle = Duration::from_secs(30);
        let started = Instant::now();
        let mut h = spawn_pump(rig(4096), idle);
        h.client.write_all(b"0123456789").await.expect("write");
        let mut got = [0_u8; 10];
        h.far.read_exact(&mut got).await.expect("read");
        assert_eq!(h.task.await.expect("join"), PumpEnd::IdleTimeout);
        let waited = Instant::now().saturating_duration_since(started);
        assert!(
            waited >= idle && waited < idle + Duration::from_secs(1),
            "ended after {waited:?}"
        );
        assert_eq!(
            (h.counts.up(), h.counts.down()),
            (10, 0),
            "counts survive the cancel"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn traffic_in_either_direction_keeps_the_tunnel_alive() {
        let idle = Duration::from_secs(30);
        let mut h = spawn_pump(rig(4096), idle);
        // Every 20 s, alternating directions, for 100 s: never 30 s of silence.
        for round in 0..5_u8 {
            tokio::time::sleep(Duration::from_secs(20)).await;
            assert!(!h.task.is_finished(), "alive at round {round}");
            let mut one = [0_u8; 1];
            if round % 2 == 0 {
                h.client.write_all(&[round]).await.expect("write");
                h.far.read_exact(&mut one).await.expect("read");
            } else {
                h.far.write_all(&[round]).await.expect("write");
                h.client.read_exact(&mut one).await.expect("read");
            }
            assert_eq!(one, [round]);
        }
        let silent_since = Instant::now();
        assert_eq!(h.task.await.expect("join"), PumpEnd::IdleTimeout);
        let silence = Instant::now().saturating_duration_since(silent_since);
        assert!(
            (Duration::from_secs(29)..=Duration::from_secs(31)).contains(&silence),
            "30 s after the last byte, got {silence:?}"
        );
        assert_eq!((h.counts.up(), h.counts.down()), (3, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn gate_change_cancels_immediately() {
        let mut h = spawn_pump(rig(4096), LONG);
        h.client.write_all(b"before").await.expect("write");
        let mut got = [0_u8; 6];
        h.far.read_exact(&mut got).await.expect("read");

        // A re-arm (even to the same profile) is a new epoch.
        h.gate_tx.send(armed(EPOCH + 1)).expect("receiver alive");
        assert_eq!(h.task.await.expect("join"), PumpEnd::GateClosed);
        assert_eq!((h.counts.up(), h.counts.down()), (6, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn every_kind_of_gate_change_ends_the_pump() {
        for mode in [
            GateMode::Disarmed,
            GateMode::Tripped(super::super::types::TripReason::ListenerDied),
            GateMode::Closing,
            GateMode::Armed {
                profile: Arc::from("other"),
            },
        ] {
            let h = spawn_pump(rig(4096), LONG);
            h.gate_tx
                .send(Gate {
                    epoch: EPOCH + 1,
                    mode,
                })
                .expect("receiver alive");
            assert_eq!(h.task.await.expect("join"), PumpEnd::GateClosed);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_gate_that_changed_before_the_pump_moves_no_byte() {
        // `select!` without `biased` picks its first branch at random, so one
        // round proves nothing about the order: run many.
        for round in 0..64 {
            let mut r = rig(4096);
            // Data is waiting on both sockets, and the gate has moved on.
            r.client.write_all(b"queued up").await.expect("write");
            r.far.write_all(b"queued down").await.expect("write");
            r.gate_tx.send(armed(EPOCH + 1)).expect("receiver alive");
            let h = spawn_pump(r, LONG);
            assert_eq!(
                h.task.await.expect("join"),
                PumpEnd::GateClosed,
                "round {round}"
            );
            assert_eq!((h.counts.up(), h.counts.down()), (0, 0), "round {round}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_gate_whose_sender_is_gone_cancels() {
        let h = spawn_pump(rig(4096), LONG);
        drop(h.gate_tx);
        assert_eq!(h.task.await.expect("join"), PumpEnd::GateClosed);
    }

    #[tokio::test(start_paused = true)]
    async fn backpressure_bounds_memory() {
        // The destination never reads. A client that keeps writing must be
        // stopped by the pump after one copy buffer, not buffered without limit.
        // The client socket has a large kernel buffer on purpose (256 KiB): what
        // the pump may take out of it in one go is the copy buffer, 16 KiB, and
        // that number is spelled out here and not read from the constant.
        const CLIENT_BUFFER: usize = 256 * 1024;
        const UPSTREAM_BUFFER: usize = 4096;
        let mut h = spawn_pump(rig_with(CLIENT_BUFFER, UPSTREAM_BUFFER), LONG);
        let chunk = [0xaa_u8; 4096];
        let mut written = 0_usize;
        loop {
            let attempt =
                tokio::time::timeout(Duration::from_secs(1), h.client.write(&chunk)).await;
            match attempt {
                Ok(Ok(n)) => written += n,
                Ok(Err(error)) => panic!("write failed: {error}"),
                Err(_) => break,
            }
            assert!(written < 100_000_000, "unbounded: {written} bytes accepted");
        }
        // The client buffer, one 16 KiB copy buffer, the upstream buffer.
        assert!(
            written <= CLIENT_BUFFER + 16 * 1024 + UPSTREAM_BUFFER + 4096,
            "accepted {written} bytes"
        );
        assert!(
            written >= CLIENT_BUFFER,
            "at least the client buffer: {written}"
        );
        // Only what reached the upstream is counted as delivered.
        assert!(h.counts.up() <= u64::try_from(written).expect("fits"));
        // Reading it out lets the rest flow again.
        let mut sink = vec![0_u8; 1 << 16];
        let target: usize = h.counts.up().try_into().expect("fits");
        let mut read = 0_usize;
        while read < target {
            read += h.far.read(&mut sink).await.expect("read");
        }
        h.task.abort();
    }

    // -- error attribution --------------------------------------------------

    /// A stream that fails once `limit` bytes have gone through it.
    struct Faulty<S> {
        inner: S,
        fail_reads_after: Option<usize>,
        fail_writes_after: Option<usize>,
        read: usize,
        written: usize,
    }

    impl<S> Faulty<S> {
        fn new(
            inner: S,
            fail_reads_after: Option<usize>,
            fail_writes_after: Option<usize>,
        ) -> Self {
            Self {
                inner,
                fail_reads_after,
                fail_writes_after,
                read: 0,
                written: 0,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Faulty<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self
                .fail_reads_after
                .is_some_and(|limit| self.read >= limit)
            {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)));
            }
            let before = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if let Poll::Ready(Ok(())) = &poll {
                self.read += buf.filled().len() - before;
            }
            poll
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Faulty<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self
                .fail_writes_after
                .is_some_and(|limit| self.written >= limit)
            {
                return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
            }
            let poll = Pin::new(&mut self.inner).poll_write(cx, data);
            if let Poll::Ready(Ok(n)) = &poll {
                self.written += *n;
            }
            poll
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// `(fail reads after, fail writes after)` for one end.
    type Fault = (Option<usize>, Option<usize>);

    struct Case {
        name: &'static str,
        client: Fault,
        upstream: Fault,
        /// Sent by the client in two rounds; the second only after the first
        /// has reached the destination.
        client_sends: [&'static [u8]; 2],
        far_sends: &'static [u8],
        expected: PumpEnd,
        counts: (u64, u64),
    }

    #[tokio::test(start_paused = true)]
    async fn errors_are_attributed_to_the_end_that_failed() {
        let cases = [
            Case {
                name: "client read fails at once",
                client: (Some(0), None),
                upstream: (None, None),
                client_sends: [b"", b""],
                far_sends: b"",
                expected: PumpEnd::ClientError,
                counts: (0, 0),
            },
            Case {
                name: "client write fails (nothing is counted that was not written)",
                client: (None, Some(0)),
                upstream: (None, None),
                client_sends: [b"", b""],
                far_sends: b"to the client",
                expected: PumpEnd::ClientError,
                counts: (0, 0),
            },
            Case {
                name: "upstream read fails at once",
                client: (None, None),
                upstream: (Some(0), None),
                client_sends: [b"", b""],
                far_sends: b"",
                expected: PumpEnd::UpstreamError,
                counts: (0, 0),
            },
            Case {
                name: "upstream write fails",
                client: (None, None),
                upstream: (None, Some(0)),
                client_sends: [b"to the upstream", b""],
                far_sends: b"",
                expected: PumpEnd::UpstreamError,
                counts: (0, 0),
            },
            Case {
                name: "upstream write fails after ten bytes went through",
                client: (None, None),
                upstream: (None, Some(10)),
                client_sends: [b"0123456789", b"more"],
                far_sends: b"",
                expected: PumpEnd::UpstreamError,
                counts: (10, 0),
            },
            Case {
                name: "client read fails after eight bytes went through",
                client: (Some(8), None),
                upstream: (None, None),
                client_sends: [b"01234567", b"more"],
                far_sends: b"",
                expected: PumpEnd::ClientError,
                counts: (8, 0),
            },
        ];
        for case in cases {
            let (mut client, pump_client) = duplex(4096);
            let (mut far, pump_upstream) = duplex(4096);
            let (_gate_tx, mut gate_rx) = watch::channel(armed(EPOCH));
            let counts = Arc::new(ByteCounts::default());
            let task = {
                let counts = Arc::clone(&counts);
                let mut c = Faulty::new(pump_client, case.client.0, case.client.1);
                let mut u = Faulty::new(pump_upstream, case.upstream.0, case.upstream.1);
                tokio::spawn(async move {
                    pump(&mut c, &mut u, &Proof, LONG, &mut gate_rx, EPOCH, &counts).await
                })
            };
            let first = case.client_sends[0];
            if !first.is_empty() {
                let _ = client.write_all(first).await;
                if case.upstream.1 != Some(0) {
                    let mut got = vec![0_u8; first.len()];
                    far.read_exact(&mut got)
                        .await
                        .expect("the first round arrives");
                }
            }
            let second = case.client_sends[1];
            if !second.is_empty() {
                // The pump may have ended already; a closed socket is not the
                // thing under test.
                let _ = client.write_all(second).await;
            }
            if !case.far_sends.is_empty() {
                let _ = far.write_all(case.far_sends).await;
            }
            let end = tokio::time::timeout(Duration::from_secs(60), task)
                .await
                .unwrap_or_else(|_| panic!("{}: the pump did not end", case.name))
                .expect("join");
            assert_eq!(end, case.expected, "{}", case.name);
            assert_eq!((counts.up(), counts.down()), case.counts, "{}", case.name);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_end_reasons_are_the_closed_words_and_free_of_forbidden_ones() {
        let all = [
            (PumpEnd::Eof, "eof"),
            (PumpEnd::IdleTimeout, "idle_timeout"),
            (PumpEnd::GateClosed, "gate_closed"),
            (PumpEnd::ClientError, "client_error"),
            (PumpEnd::UpstreamError, "upstream_error"),
        ];
        for (end, word) in all {
            assert_eq!(end.reason(), word);
            assert_eq!(crate::ingress::types::contains_forbidden_word(word), None);
        }
    }
}
