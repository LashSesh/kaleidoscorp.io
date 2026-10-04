#![cfg(windows)]
//! Real Windows named-pipe round trips: a live `serve_named_pipe` driven by
//! the live `DaemonClient`, over the real CBOR framing, on real pipes.
//!
//! Every test uses a unique pipe name (`unique_pipe_name`) so the whole file
//! runs in parallel — which is itself a regression test for the defect that
//! motivated `paths::named_pipe_name`: with the old fixed global name, a second
//! instance died with `ERROR_ACCESS_DENIED` and parallel tests were impossible.
//!
//! # What the fakes here do and do not stand in for
//!
//! `TestPipes` creates instances with plain `ServerOptions`, i.e. with the
//! **default DACL**. It is not the product's factory — the product's carries
//! the SDDL and lives in `ssk-winhost`, which is the only crate allowed the
//! `unsafe` that `create_with_security_attributes_raw` requires. What these
//! tests cover is the transport: the accept loop, the instance lifecycle, the
//! caps, the timeouts, and the fact that the authentication *decision* is on
//! the path and closes the connection when it says no.
//!
//! `TestAuth` likewise stands in for `ssk-winhost`'s impersonation-based
//! authenticator. Driving the real FFI — including the two measured fail-open
//! traps, a client opened `SECURITY_ANONYMOUS` and a client opened with no SQOS
//! flags — belongs to `ssk-winhost`'s own tests, because that is where the code
//! under test lives. Rejecting a *genuinely different OS user* is not testable
//! unelevated on a single-user box at all; see `docs/OPERATOR_VM_VALIDATION.md`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssk_ipc::client::DaemonClient;
use ssk_ipc::error::IpcError;
use ssk_ipc::paths::Endpoint;
use ssk_ipc::server::{
    serve_named_pipe, BoxFuture, CommandHandler, Request, Response, ServeLimits,
};
use ssk_ipc::transport_win::{PeerAuthenticator, PipeFactory, Sid};
use ssk_ipc::PeerIdentity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

const SELF_SID: &str = "S-1-5-21-90000-90001-90002-1001";
const OTHER_SID: &str = "S-1-5-21-90000-90001-90002-1002";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_pipe_name(tag: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\ssk-ipc-it-{tag}-{}-{n}", std::process::id())
}

/// Instance factory with the default DACL. Test-only — see the module doc.
struct TestPipes;

impl PipeFactory for TestPipes {
    fn create_instance(
        &self,
        pipe_name: &str,
        first_instance: bool,
        max_instances: u32,
    ) -> std::io::Result<NamedPipeServer> {
        ServerOptions::new()
            .first_pipe_instance(first_instance)
            .max_instances(max_instances as usize)
            .create(pipe_name)
    }
}

/// Peer authenticator whose answers are fixed by the test.
struct TestAuth {
    own: Sid,
    peer: Result<Sid, IpcError>,
}

impl TestAuth {
    fn accepting() -> Arc<dyn PeerAuthenticator> {
        Arc::new(Self {
            own: Sid(SELF_SID.to_owned()),
            peer: Ok(Sid(SELF_SID.to_owned())),
        })
    }

    fn rejecting() -> Arc<dyn PeerAuthenticator> {
        Arc::new(Self {
            own: Sid(SELF_SID.to_owned()),
            peer: Ok(Sid(OTHER_SID.to_owned())),
        })
    }

    /// The measured fail-open trap in trait form: the FFI could not determine
    /// the peer. That must be a rejection, never an "unknown, continue".
    fn undeterminable() -> Arc<dyn PeerAuthenticator> {
        Arc::new(Self {
            own: Sid(SELF_SID.to_owned()),
            peer: Err(IpcError::new(
                "Permission",
                "IPC_PEER_SID_FAILED",
                "OpenThreadToken failed: 1347 ERROR_BAD_IMPERSONATION_LEVEL",
            )),
        })
    }
}

impl PeerAuthenticator for TestAuth {
    fn own_sid(&self) -> Result<Sid, IpcError> {
        Ok(self.own.clone())
    }
    fn peer_sid(&self, _server: &NamedPipeServer) -> Result<Sid, IpcError> {
        self.peer.clone()
    }
}

/// Records what the transport handed it, so tests can assert the handler now
/// receives a *verified peer identity* where it used to receive a server-minted
/// `SessionToken` it never read.
#[derive(Default)]
struct RecordingHandler {
    seen: Mutex<Vec<(Request, PeerIdentity)>>,
}

impl RecordingHandler {
    fn seen(&self) -> Vec<(Request, PeerIdentity)> {
        self.seen.lock().expect("handler mutex").clone()
    }
}

impl CommandHandler for RecordingHandler {
    fn handle<'a>(&'a self, req: Request, peer: &'a PeerIdentity) -> BoxFuture<'a, Response> {
        let record = (req.clone(), peer.clone());
        Box::pin(async move {
            self.seen.lock().expect("handler mutex").push(record);
            match req {
                Request::ListProfiles => Response::Profiles(Vec::new()),
                _ => Response::Ack,
            }
        })
    }
}

/// Start a server on a fresh pipe name. Returns the endpoint, the handler (for
/// assertions) and the server task's join handle.
fn spawn_server(
    tag: &str,
    auth: Arc<dyn PeerAuthenticator>,
    limits: ServeLimits,
) -> (
    Endpoint,
    Arc<RecordingHandler>,
    tokio::task::JoinHandle<Result<(), IpcError>>,
) {
    let name = unique_pipe_name(tag);
    let handler = Arc::new(RecordingHandler::default());
    let handler_for_server: Arc<dyn CommandHandler> = handler.clone();
    let server_name = name.clone();
    let task = tokio::spawn(async move {
        serve_named_pipe(
            &server_name,
            handler_for_server,
            Arc::new(TestPipes),
            auth,
            limits,
        )
        .await
    });
    (Endpoint::NamedPipe(name), handler, task)
}

/// Connect, tolerating the window before the server's first instance exists
/// (a pipe that does not exist yet yields `IPC_CONNECT_FAILED`, which the
/// client deliberately does *not* retry — only `ERROR_PIPE_BUSY` is retried).
async fn connect(endpoint: &Endpoint) -> DaemonClient {
    for _ in 0..200 {
        match DaemonClient::connect(endpoint).await {
            Ok(client) => return client,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    }
    panic!("server never became connectable at {endpoint}");
}

/// Open a raw client (no framing helpers) so a test can send a deliberately
/// malformed frame. Retries `ERROR_PIPE_BUSY`, which is the normal transient
/// state between the accept loop taking a connection and creating the next
/// listening instance.
async fn open_raw(name: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..200 {
        match ClientOptions::new().open(name) {
            Ok(client) => return client,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("raw open of {name} failed: {e}"),
        }
    }
    panic!("raw open of {name} stayed busy");
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_and_server_round_trip_over_a_real_pipe() {
    let (endpoint, handler, _task) =
        spawn_server("round-trip", TestAuth::accepting(), ServeLimits::default());
    let mut client = connect(&endpoint).await;

    let resp = client.call(Request::GetStatus).await.expect("GetStatus");
    assert!(matches!(resp, Response::Ack), "unexpected: {resp:?}");

    let resp = client
        .call(Request::ListProfiles)
        .await
        .expect("ListProfiles");
    match resp {
        Response::Profiles(p) => assert!(p.is_empty()),
        other => panic!("unexpected: {other:?}"),
    }

    let seen = handler.seen();
    assert_eq!(seen.len(), 2, "both requests must reach the handler");
    for (_, peer) in &seen {
        assert_eq!(
            peer,
            &PeerIdentity::Sid(SELF_SID.to_owned()),
            "the handler must receive the verified peer SID"
        );
    }
}

/// Several clients at once, each on its own pipe instance. This is the
/// multi-instance path that the old fixed pipe name made untestable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_clients_each_get_an_instance() {
    let (endpoint, handler, _task) =
        spawn_server("concurrent", TestAuth::accepting(), ServeLimits::default());

    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(connect(&endpoint).await);
    }
    for client in &mut clients {
        let resp = client.call(Request::GetStatus).await.expect("GetStatus");
        assert!(matches!(resp, Response::Ack));
    }
    assert_eq!(handler.seen().len(), 8);
}

/// Two servers with different state dirs must coexist. Derived names make this
/// possible; the fixed global name made it `ERROR_ACCESS_DENIED`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_with_different_names_coexist() {
    let (endpoint_a, handler_a, _a) =
        spawn_server("coexist-a", TestAuth::accepting(), ServeLimits::default());
    let (endpoint_b, handler_b, _b) =
        spawn_server("coexist-b", TestAuth::accepting(), ServeLimits::default());
    assert_ne!(endpoint_a, endpoint_b);

    let mut a = connect(&endpoint_a).await;
    let mut b = connect(&endpoint_b).await;
    assert!(matches!(
        a.call(Request::GetStatus).await.expect("a"),
        Response::Ack
    ));
    assert!(matches!(
        b.call(Request::GetStatus).await.expect("b"),
        Response::Ack
    ));
    assert_eq!(handler_a.seen().len(), 1);
    assert_eq!(handler_b.seen().len(), 1);
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

/// A peer whose SID does not match the daemon's is dropped before the handler
/// sees anything. This is the control `server.rs` previously did not have at
/// all on Windows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_peer_is_rejected_before_the_handler_runs() {
    let (endpoint, handler, _task) =
        spawn_server("foreign", TestAuth::rejecting(), ServeLimits::default());
    let mut client = connect(&endpoint).await;

    let outcome = client.call(Request::GetStatus).await;
    assert!(
        outcome.is_err(),
        "a rejected peer must not get a response: {outcome:?}"
    );
    assert!(
        handler.seen().is_empty(),
        "a rejected peer must not reach the handler"
    );
}

/// "Could not determine the peer" is a rejection, never an unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn undeterminable_peer_is_rejected_before_the_handler_runs() {
    let (endpoint, handler, _task) = spawn_server(
        "undeterminable",
        TestAuth::undeterminable(),
        ServeLimits::default(),
    );
    let mut client = connect(&endpoint).await;

    assert!(client.call(Request::GetStatus).await.is_err());
    assert!(handler.seen().is_empty());
}

/// The rejection happens *before any frame is read*, so a peer that never
/// speaks still never reaches the framing layer. Asserted by rejecting a
/// connection on which the client wrote zero bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejection_happens_pre_read() {
    let (endpoint, handler, _task) = spawn_server(
        "pre-read",
        TestAuth::rejecting(),
        ServeLimits {
            // Far longer than this test runs: if the disconnect below were the
            // timeout rather than the auth check, this test would hang.
            first_frame_timeout: Duration::from_secs(3600),
            ..ServeLimits::default()
        },
    );
    let mut client = connect(&endpoint).await;

    // Never send a request; just wait for the server to hang up.
    let closed = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("server must close a rejected connection without waiting for a frame");
    assert!(closed.is_err(), "expected a closed pipe, got {closed:?}");
    assert!(handler.seen().is_empty());
}

// ---------------------------------------------------------------------------
// Anti-squat
// ---------------------------------------------------------------------------

/// `FILE_FLAG_FIRST_PIPE_INSTANCE` is the anti-squat guard and is deliberately
/// kept. If someone already owns the name, the daemon refuses to start rather
/// than serving beside them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_to_start_when_the_name_is_already_owned() {
    let name = unique_pipe_name("squat");
    let _squatter = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .expect("squatter binds first");

    let handler: Arc<dyn CommandHandler> = Arc::new(RecordingHandler::default());
    let err = serve_named_pipe(
        &name,
        handler,
        Arc::new(TestPipes),
        TestAuth::accepting(),
        ServeLimits::default(),
    )
    .await
    .expect_err("must refuse to start on an owned name");
    assert_eq!(err.code, "IPC_PIPE_NAME_TAKEN");
    assert_eq!(err.class, "Permission");
    assert!(!err.next_steps.is_empty());
}

// ---------------------------------------------------------------------------
// Wire hardening
// ---------------------------------------------------------------------------

/// A connected-but-silent peer is dropped, so it cannot hold an instance open
/// forever. Measured against a real client that connects and says nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_client_is_dropped_after_the_first_frame_timeout() {
    let (endpoint, _handler, _task) = spawn_server(
        "silent",
        TestAuth::accepting(),
        ServeLimits {
            first_frame_timeout: Duration::from_millis(200),
            ..ServeLimits::default()
        },
    );
    let mut client = connect(&endpoint).await;

    let started = std::time::Instant::now();
    let closed = tokio::time::timeout(Duration::from_secs(5), client.recv())
        .await
        .expect("the server must hang up, not stall");
    assert!(closed.is_err(), "expected a closed pipe, got {closed:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(150),
        "must not close before the configured timeout"
    );
}

/// An *established* connection gets the longer idle timeout, not the short
/// first-frame one — a client that asks, waits, then asks again must survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn established_connection_survives_past_the_first_frame_timeout() {
    let (endpoint, _handler, _task) = spawn_server(
        "idle",
        TestAuth::accepting(),
        ServeLimits {
            first_frame_timeout: Duration::from_millis(150),
            idle_timeout: Duration::from_secs(30),
            ..ServeLimits::default()
        },
    );
    let mut client = connect(&endpoint).await;

    assert!(matches!(
        client.call(Request::GetStatus).await.expect("first call"),
        Response::Ack
    ));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(matches!(
        client.call(Request::GetStatus).await.expect("second call"),
        Response::Ack
    ));
}

/// A hostile length prefix over the request cap is refused at the framing
/// layer and the connection is dropped — the server never allocates the
/// declared size.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_request_frame_is_refused() {
    let limits = ServeLimits::default();
    let (endpoint, handler, _task) = spawn_server("oversize", TestAuth::accepting(), limits);
    // Wait for the server, then drive it with a raw client so we can lie.
    let _warm = connect(&endpoint).await;
    let Endpoint::NamedPipe(name) = &endpoint else {
        unreachable!("named pipe endpoint")
    };

    let mut raw = open_raw(name).await;
    let declared = limits.max_request_frame_len + 1;
    raw.write_all(&declared.to_be_bytes())
        .await
        .expect("write length prefix");
    // Deliberately send no body at all. If the server had pre-allocated the
    // declared length this would already have cost it 64 KiB+.
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .expect("server must hang up, not stall");
    match read {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("server answered an oversized frame with {n} bytes"),
    }
    assert!(
        handler.seen().is_empty(),
        "an oversized frame must never reach the handler"
    );
}

/// A declared body that never arrives costs the server the bytes actually
/// sent, not the declared length, and still ends in a refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lying_length_prefix_within_the_cap_is_refused() {
    let (endpoint, handler, _task) = spawn_server(
        "lying",
        TestAuth::accepting(),
        ServeLimits {
            first_frame_timeout: Duration::from_millis(300),
            ..ServeLimits::default()
        },
    );
    let _warm = connect(&endpoint).await;
    let Endpoint::NamedPipe(name) = &endpoint else {
        unreachable!("named pipe endpoint")
    };

    let mut raw = open_raw(name).await;
    raw.write_all(&60_000u32.to_be_bytes())
        .await
        .expect("write length prefix");
    raw.write_all(&[0u8; 4]).await.expect("write short body");

    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
        .await
        .expect("server must hang up, not stall");
    match read {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("server answered a truncated frame with {n} bytes"),
    }
    assert!(handler.seen().is_empty());
}

/// The connection cap is real: with `max_connections = 2`, a third client is
/// refused with the retriable busy error, and service resumes once a slot frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_cap_refuses_the_overflow_client_and_recovers() {
    let (endpoint, _handler, _task) = spawn_server(
        "cap",
        TestAuth::accepting(),
        ServeLimits {
            max_connections: 2,
            idle_timeout: Duration::from_secs(30),
            first_frame_timeout: Duration::from_secs(30),
            ..ServeLimits::default()
        },
    );

    let mut a = connect(&endpoint).await;
    assert!(matches!(
        a.call(Request::GetStatus).await.expect("a"),
        Response::Ack
    ));
    // The client that *takes the last slot* is the regression guard for an
    // accept-loop ordering defect measured on this machine: creating the next
    // pipe instance before spawning the handler deadlocks at the cap, and this
    // request went unanswered for 30 s (until the first client's idle timeout
    // freed an instance). It must be answered promptly instead.
    let mut b = connect(&endpoint).await;
    let started = std::time::Instant::now();
    assert!(matches!(
        b.call(Request::GetStatus).await.expect("b"),
        Response::Ack
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the client holding the last slot must be served immediately, took {:?}",
        started.elapsed()
    );

    let err = DaemonClient::connect(&endpoint)
        .await
        .err()
        .expect("the third client must be refused at the cap");
    assert_eq!(err.code, "IPC_CONNECT_BUSY");
    assert!(err.retriable);

    // Free a slot; the accept loop's ERROR_PIPE_BUSY retry must then succeed.
    drop(a);
    let mut c = connect(&endpoint).await;
    assert!(matches!(
        c.call(Request::GetStatus).await.expect("c"),
        Response::Ack
    ));
}

/// `limit` is attacker-controlled and feeds a `Vec` allocation on the handler
/// side, so the transport clamps it before the handler ever sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attacker_controlled_limits_are_clamped_before_the_handler() {
    let (endpoint, handler, _task) =
        spawn_server("clamp", TestAuth::accepting(), ServeLimits::default());
    let mut client = connect(&endpoint).await;

    client
        .call(Request::ListRecentFlows { limit: usize::MAX })
        .await
        .expect("call");
    client
        .call(Request::GetAuditEntries { limit: usize::MAX })
        .await
        .expect("call");

    let seen = handler.seen();
    assert_eq!(seen.len(), 2);
    match &seen[0].0 {
        Request::ListRecentFlows { limit } => assert_eq!(*limit, ssk_ipc::MAX_LIST_LIMIT),
        other => panic!("unexpected: {other:?}"),
    }
    match &seen[1].0 {
        Request::GetAuditEntries { limit } => assert_eq!(*limit, ssk_ipc::MAX_LIST_LIMIT),
        other => panic!("unexpected: {other:?}"),
    }
}
