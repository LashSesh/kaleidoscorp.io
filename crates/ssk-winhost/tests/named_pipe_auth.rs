#![cfg(windows)]

//! The composition proof for P2's Windows control plane.
//!
//! `ssk-ipc`'s own suite drives `serve_named_pipe` against *fake* trait
//! objects: a `PipeFactory` that creates instances with the default DACL and a
//! `PeerAuthenticator` that returns whatever SID the test wants. That proves
//! the decision logic and nothing about the syscalls. This file is the other
//! half — the **real** `WindowsPipeFactory` and `WindowsPeerAuthenticator` from
//! this crate, plugged into the real `serve_named_pipe`, driven by the real
//! `DaemonClient`, over a real named pipe.
//!
//! It is the only place in the workspace where the whole Windows transport is
//! exercised end to end, so it is what turns "the daemon has an authenticated
//! pipe" from a claim into an observation.
//!
//! Runs unelevated. Every pipe name is unique to this process and this test, so
//! the file is parallel-safe and leaves nothing behind.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ssk_ipc::server::{
    serve_named_pipe, BoxFuture, CommandHandler, Request, Response, ServeLimits,
};
use ssk_ipc::{DaemonClient, Endpoint, PeerIdentity};
use ssk_winhost::{current_user_sid, WindowsPeerAuthenticator, WindowsPipeFactory};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ClientOptions;

/// `SECURITY_ANONYMOUS`. tokio always ORs `SECURITY_SQOS_PRESENT`, so 0 gives
/// exactly the hostile `SQOS_PRESENT | SECURITY_ANONYMOUS` shape.
const SECURITY_ANONYMOUS: u32 = 0;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_pipe_name(tag: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(r"\\.\pipe\ssk-winhost-it-{}-{tag}-{n}", std::process::id())
}

/// Answers `Ack` and records the [`PeerIdentity`] the transport handed it —
/// which is the thing under test: the handler must see what the peer check
/// *proved*, not a value the server invented.
#[derive(Default)]
struct RecordingHandler {
    seen: Mutex<Vec<PeerIdentity>>,
}

impl CommandHandler for RecordingHandler {
    fn handle<'a>(&'a self, _req: Request, peer: &'a PeerIdentity) -> BoxFuture<'a, Response> {
        self.seen.lock().expect("handler mutex").push(peer.clone());
        Box::pin(async { Response::Ack })
    }
}

fn limits() -> ServeLimits {
    ServeLimits {
        max_connections: 4,
        // Short, so a test that expects a drop does not wait 5 s for it.
        first_frame_timeout: Duration::from_secs(2),
        ..ServeLimits::default()
    }
}

/// Start the real server on `name`, returning the handler so the test can read
/// back what it observed.
fn spawn_server(name: &str) -> Arc<RecordingHandler> {
    let handler = Arc::new(RecordingHandler::default());
    let pipes = Arc::new(WindowsPipeFactory::for_current_user().expect("P2 pipe factory"));
    let auth = Arc::new(WindowsPeerAuthenticator::new().expect("peer authenticator"));
    let owned = name.to_owned();
    let served = Arc::clone(&handler);
    tokio::spawn(async move {
        // The loop only ever returns on error; the test drops the runtime.
        let _ = serve_named_pipe(&owned, served, pipes, auth, limits()).await;
    });
    handler
}

/// Retry until the first instance exists. `serve_named_pipe` binds
/// asynchronously, so a client that races the spawn sees `ERROR_FILE_NOT_FOUND`
/// once — `DaemonClient::connect` retries `ERROR_PIPE_BUSY` but not this.
async fn connect_with_retry(name: &str) -> DaemonClient {
    let endpoint = Endpoint::NamedPipe(name.to_owned());
    for _ in 0..200 {
        if let Ok(client) = DaemonClient::connect(&endpoint).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server never became reachable on {name}");
}

/// THE composition proof: real DACL'd pipe, real impersonation check, real
/// client, real CBOR framing, and the handler sees the verified SID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_same_user_client_round_trips_through_the_real_transport() {
    let name = unique_pipe_name("roundtrip");
    let handler = spawn_server(&name);

    let mut client = connect_with_retry(&name).await;
    let resp = client
        .call(Request::GetStatus)
        .await
        .expect("a same-user request must round-trip");
    assert!(
        matches!(resp, Response::Ack),
        "unexpected response: {resp:?}"
    );

    let seen = handler.seen.lock().expect("handler mutex").clone();
    assert_eq!(seen.len(), 1, "handler must have been called exactly once");
    assert_eq!(
        seen[0],
        PeerIdentity::Sid(current_user_sid().expect("sid")),
        "the handler must receive the SID the transport verified"
    );
}

/// Several concurrent same-user clients, to show the accept loop keeps creating
/// authenticated instances rather than authenticating only the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_user_clients_are_all_authenticated() {
    let name = unique_pipe_name("concurrent");
    let handler = spawn_server(&name);
    // Make sure the first instance is up before fanning out.
    let mut first = connect_with_retry(&name).await;
    assert!(matches!(
        first.call(Request::GetStatus).await.expect("first call"),
        Response::Ack
    ));

    let mut tasks = Vec::new();
    for _ in 0..3 {
        let n = name.clone();
        tasks.push(tokio::spawn(async move {
            let mut c = connect_with_retry(&n).await;
            matches!(
                c.call(Request::ListProfiles).await.expect("call"),
                Response::Ack
            )
        }));
    }
    for t in tasks {
        assert!(t.await.expect("join"), "every client must be served");
    }

    let seen = handler.seen.lock().expect("handler mutex").clone();
    assert_eq!(seen.len(), 4);
    let expected = PeerIdentity::Sid(current_user_sid().expect("sid"));
    assert!(
        seen.iter().all(|p| *p == expected),
        "every served request must carry the verified SID: {seen:?}"
    );
}

/// The rejection, observed from the *client's* side of the wire rather than
/// from a return value inside the process.
///
/// A `SECURITY_ANONYMOUS` client is the fail-open trap: the kernel lets the
/// server impersonate it, and only `OpenThreadToken` says no. Through the full
/// serve loop the consequence must be that the connection is dropped without a
/// single byte of response — and, critically, that the handler is never
/// invoked, i.e. no request is executed for an unauthenticated peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anonymous_client_is_dropped_without_reaching_the_handler() {
    let name = unique_pipe_name("anon-drop");
    let handler = spawn_server(&name);
    // Wait for the pipe to exist by connecting once, legitimately.
    drop(connect_with_retry(&name).await);

    // Retry `ERROR_PIPE_BUSY` (231): the accept loop replaces an instance only
    // after spawning the previous connection's handler, so there is a brief
    // window with no free instance. `DaemonClient::connect` retries this for
    // real clients; a hand-rolled hostile client has to do it itself.
    let mut hostile = loop {
        match ClientOptions::new()
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(&name)
        {
            Ok(stream) => break stream,
            Err(e) if e.raw_os_error() == Some(231) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(e) => panic!("an anonymous client must still be able to open the pipe: {e}"),
        }
    };

    // The server authenticates before reading, so it hangs up immediately.
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(10), hostile.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => {}
        Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("an anonymous peer received {n} bytes; it must receive none"),
        Err(_) => panic!("the server neither answered nor hung up on an anonymous peer"),
    }

    assert!(
        handler.seen.lock().expect("handler mutex").is_empty(),
        "no request may reach the handler on an unauthenticated connection"
    );
}

/// Two daemons with different pipe names coexist. Before P2 the name was a
/// fixed global string and the second instance died with
/// `ERROR_ACCESS_DENIED`; with the real factory and per-state-dir names they
/// must both serve.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_daemons_with_distinct_names_coexist() {
    let a = unique_pipe_name("coexist-a");
    let b = unique_pipe_name("coexist-b");
    let ha = spawn_server(&a);
    let hb = spawn_server(&b);

    let mut ca = connect_with_retry(&a).await;
    let mut cb = connect_with_retry(&b).await;
    assert!(matches!(
        ca.call(Request::GetStatus).await.expect("a"),
        Response::Ack
    ));
    assert!(matches!(
        cb.call(Request::GetStatus).await.expect("b"),
        Response::Ack
    ));
    assert_eq!(ha.seen.lock().expect("a mutex").len(), 1);
    assert_eq!(hb.seen.lock().expect("b mutex").len(), 1);
}
