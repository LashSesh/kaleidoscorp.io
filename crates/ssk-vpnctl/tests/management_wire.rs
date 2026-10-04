//! Real loopback TCP with an independent scripted management peer. No OpenVPN
//! executable, privilege, interface, firewall or route changes are involved.
use ssk_vpnctl::{
    Client, CredentialKind, Failure, ManagementPassword, ManagementTransport, ProtocolError, Stage,
    TcpTransport, Timeouts, MAX_LINE_BYTES,
};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

const SECRET: &str = "fixture-management-password-not-a-real-secret";
const CONNECTED: &[u8] =
    b">STATE:1724000000,CONNECTED,SUCCESS,10.8.0.2,192.0.2.1,1194,192.0.2.2,49100\r\n";

fn read_command(peer: &mut BufReader<TcpStream>) -> String {
    let mut line = String::new();
    peer.read_line(&mut line).unwrap();
    assert!(!line.is_empty(), "client closed before expected command");
    line
}

fn reply(peer: &mut BufReader<TcpStream>, bytes: &[u8]) {
    peer.get_mut().write_all(bytes).unwrap();
}

fn peer_setup(stream: TcpStream) -> BufReader<TcpStream> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.set_nodelay(true).unwrap();
    BufReader::new(stream)
}

fn authenticate(peer: &mut BufReader<TcpStream>) {
    // Deliberately fragmented, with NO newline; a read_line-based client hangs.
    for part in [b"ENTER ".as_slice(), b"PASS", b"WORD:"] {
        reply(peer, part);
    }
    assert_eq!(read_command(peer), format!("{SECRET}\n"));
    reply(peer, b"SUCCESS: password is correct\r\n>INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n>HOLD:Waiting for hold release:0\r\n");
}

fn startup(peer: &mut BufReader<TcpStream>) {
    authenticate(peer);
    assert_eq!(read_command(peer), "pid\n");
    reply(
        peer,
        b">LOG:1724000000,I,interleaved startup log\r\nSUCCESS: pid=123\r\n",
    );
    assert_eq!(read_command(peer), "state on\n");
    reply(peer, b"SUCCESS: real-time state notification set to ON\r\n");
    assert_eq!(read_command(peer), "hold release\n");
    reply(
        peer,
        b"SUCCESS: hold release succeeded\r\n>STATE:1724000000,CONNECTING,,,,,,\r\n",
    );
    reply(peer, CONNECTED);
}

fn connect(listener: &TcpListener, timeouts: Timeouts) -> Client<TcpTransport> {
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    Client::new(
        TcpTransport::from_loopback_stream(stream).unwrap(),
        ManagementPassword::new(SECRET.as_bytes().to_vec()).unwrap(),
        123,
        timeouts,
    )
    .unwrap()
}

fn until(client: &mut Client<TcpTransport>, wanted: Stage) {
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let snapshot = client.poll().expect("management step");
        if snapshot.stage == wanted {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "did not reach {wanted:?}; got {snapshot:?}"
        );
    }
}

fn assert_closed(peer: &mut BufReader<TcpStream>) {
    let mut byte = [0];
    match peer.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ) => {}
        result => panic!("management transport stayed open or sent unexpected data: {result:?}"),
    }
}

#[test]
fn real_wire_startup_heartbeat_reconnect_and_graceful_management_close() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = connect(
        &listener,
        Timeouts {
            heartbeat: Duration::from_millis(250),
            ..Timeouts::default()
        },
    );
    let (resume_tx, resume_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut peer = peer_setup(listener.accept().unwrap().0);
        startup(&mut peer);
        assert_eq!(read_command(&mut peer), "pid\n");
        reply(
            &mut peer,
            b">STATE:1724000001,RECONNECTING,ping-restart,,,,,\r\nSUCCESS: pid=123\r\n",
        );
        resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        reply(&mut peer, CONNECTED);
        loop {
            let command = read_command(&mut peer);
            if command == "pid\n" {
                reply(&mut peer, b"SUCCESS: pid=123\r\n");
                continue;
            }
            assert_eq!(command, "signal SIGTERM\n");
            reply(
                &mut peer,
                b"SUCCESS: signal SIGTERM thrown\r\n>STATE:1724000002,EXITING,SIGTERM,,,,,\r\n",
            );
            break;
        }
    });
    until(&mut client, Stage::ConnectedUnverified);
    until(&mut client, Stage::Reconnecting);
    resume_tx.send(()).unwrap();
    until(&mut client, Stage::ConnectedUnverified);
    client.request_stop().unwrap();
    assert_eq!(client.last_snapshot().stage, Stage::Stopping);
    until(&mut client, Stage::ManagementClosed);
    assert_eq!(client.poll().unwrap().stage, Stage::ManagementClosed);
    server.join().unwrap();
}

#[test]
fn wire_failures_close_transport_and_never_accept_a_later_connected_message() {
    let scenarios = vec![
        (
            b">FATAL:do-not-log-this-secret\r\n".to_vec(),
            Failure::Fatal,
        ),
        (
            b">PASSWORD:Need 'Auth' username/password\r\n".to_vec(),
            Failure::CredentialsRequired(CredentialKind::Auth),
        ),
        (
            b">PASSWORD:Verification Failed: 'secret'\r\n".to_vec(),
            Failure::VpnAuthentication,
        ),
        (
            b">STATE:broken,CONNECTED,SUCCESS,10.8.0.2\r\n".to_vec(),
            Failure::Protocol(ProtocolError::Malformed),
        ),
        (
            vec![b'x'; MAX_LINE_BYTES + 1],
            Failure::Protocol(ProtocolError::TooLong),
        ),
        (
            b">STATE:1,EXITING,process-died,,,,,\r\n".to_vec(),
            Failure::UnexpectedExit,
        ),
    ];
    for (mut bytes, expected) in scenarios {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = connect(&listener, Timeouts::default());
        let server = thread::spawn(move || {
            let mut peer = peer_setup(listener.accept().unwrap().0);
            startup(&mut peer);
            bytes.extend_from_slice(CONNECTED);
            // Closure may race a fragmented write, so a reset here is allowed.
            let _ = peer.get_mut().write_all(&bytes);
            assert_closed(&mut peer);
        });
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match client.poll() {
                Err(error) => {
                    assert_eq!(error, expected);
                    break;
                }
                Ok(_) => assert!(Instant::now() < deadline),
            }
        }
        assert_eq!(client.last_snapshot().stage, Stage::Failed);
        assert_eq!(client.last_snapshot().reported_state, None);
        assert_eq!(client.poll().unwrap_err(), expected);
        server.join().unwrap();
    }
}

#[test]
fn rejected_password_and_wrong_pid_never_release_hold() {
    for wrong_pid in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = connect(&listener, Timeouts::default());
        let server = thread::spawn(move || {
            let mut peer = peer_setup(listener.accept().unwrap().0);
            if wrong_pid {
                authenticate(&mut peer);
                assert_eq!(read_command(&mut peer), "pid\n");
                reply(&mut peer, b"SUCCESS: pid=999\r\n");
            } else {
                reply(&mut peer, b"ENTER PASSWORD:");
                read_command(&mut peer);
                reply(&mut peer, b"ERROR: bad password\r\n");
            }
            assert_closed(&mut peer);
        });
        let expected = if wrong_pid {
            Failure::ProcessMismatch
        } else {
            Failure::ManagementAuthentication
        };
        loop {
            if let Err(error) = client.poll() {
                assert_eq!(error, expected);
                break;
            }
        }
        server.join().unwrap();
    }
}

#[test]
fn silent_peer_and_truncated_eof_are_bounded_failures() {
    for partial in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = connect(
            &listener,
            Timeouts {
                startup: Duration::from_millis(250),
                ..Timeouts::default()
            },
        );
        let server = thread::spawn(move || {
            let mut peer = peer_setup(listener.accept().unwrap().0);
            if partial {
                reply(&mut peer, b"ENTER PASS");
            } else {
                assert_closed(&mut peer);
            }
        });
        let start = Instant::now();
        loop {
            if let Err(error) = client.poll() {
                assert_eq!(
                    error,
                    if partial {
                        Failure::Protocol(ProtocolError::Truncated)
                    } else {
                        Failure::StartupTimeout
                    }
                );
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(3));
        }
        server.join().unwrap();
    }
}

#[test]
fn unexpected_eof_and_client_drop_close_the_management_connection() {
    for drop_client in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = connect(&listener, Timeouts::default());
        let (go_tx, go_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut peer = peer_setup(listener.accept().unwrap().0);
            startup(&mut peer);
            go_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            if drop_client {
                assert_closed(&mut peer);
            }
        });
        until(&mut client, Stage::ConnectedUnverified);
        go_tx.send(()).unwrap();
        if drop_client {
            drop(client);
        } else {
            assert_eq!(client.poll().unwrap_err(), Failure::Disconnected);
        }
        server.join().unwrap();
    }
}

#[test]
fn partial_write_error_is_terminal_and_closes_an_injected_transport() {
    struct BrokenWriter(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl ManagementTransport for BrokenWriter {
        fn read(&mut self, bytes: &mut [u8], _timeout: Duration) -> io::Result<usize> {
            bytes[..15].copy_from_slice(b"ENTER PASSWORD:");
            Ok(15)
        }
        fn write_all(&mut self, _bytes: &[u8], _timeout: Duration) -> io::Result<()> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn close(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut client = Client::new(
        BrokenWriter(closed.clone()),
        ManagementPassword::new(SECRET.as_bytes().to_vec()).unwrap(),
        123,
        Timeouts::default(),
    )
    .unwrap();
    assert_eq!(
        client.poll().unwrap_err(),
        Failure::Io(io::ErrorKind::BrokenPipe)
    );
    assert!(closed.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(client.last_snapshot().stage, Stage::Failed);
}
