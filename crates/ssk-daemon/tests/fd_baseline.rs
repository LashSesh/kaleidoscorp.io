//! The descriptor reserve of the ingress budget (design 7.3, `FD_RESERVE`), checked
//! against the real `sskd`.
//!
//! The ingress must not be able to use the descriptors that the IPC server and
//! the daemon itself need, because an IPC `accept()` that fails 60 times in a
//! row ends the daemon. `budget::FD_RESERVE` is the figure set aside for them.
//! It is the one number of the budget that is a measurement and not a bound by
//! construction, so it is re-measured here instead of being trusted: an idle
//! `sskd` holds about 12 descriptors, with `ServeLimits::default().max_connections`
//! (16) clients connected it holds about 28, and a 17th connection that has been
//! accepted and waits for a permit makes 29. If a change to the daemon (a second
//! log file, a new socket, a larger IPC limit) moves that, the reserve has to
//! move with it and this test is where it shows.
//!
//! Linux only: the count is `/proc/<pid>/fd`.

#![cfg(target_os = "linux")]

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/support/routing_config.rs"
));

use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use ssk_daemon::ingress::budget::FD_RESERVE;

/// Kills and reaps the daemon when the test ends or panics.
struct Reaper(Child);

impl Drop for Reaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn open_descriptors(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("read the daemon's descriptor table")
        .count()
}

#[test]
fn ipc_reserve_covers_measured_baseline() {
    let state = tempfile::tempdir().expect("state directory");
    let stderr = std::fs::File::create(state.path().join("sskd.err")).expect("stderr capture");
    let child = Reaper(
        Command::new(env!("CARGO_BIN_EXE_sskd"))
            .env("SSK_STATE_DIR", state.path())
            .env("SSK_CONFIG_PATH", write_loopback_config(state.path()))
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .expect("spawn sskd"),
    );
    let pid = child.0.id();
    let socket = state.path().join("sskd.sock");

    // Ready is a connection that is accepted, not a file that exists.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if UnixStream::connect(&socket).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "sskd never accepted a connection"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    // Idle: wait until the count stops moving (the probe connection above closes).
    let mut idle = open_descriptors(pid);
    let settle = Instant::now() + Duration::from_secs(5);
    loop {
        std::thread::sleep(Duration::from_millis(100));
        let now = open_descriptors(pid);
        if now == idle || Instant::now() > settle {
            idle = now;
            break;
        }
        idle = now;
    }
    assert!(
        (3..=20).contains(&idle),
        "an idle sskd holds about 12 descriptors, not {idle}"
    );

    // 40 clients that connect and stay silent: 16 hold a permit and the 17th has
    // been accepted and waits for one, so the daemon is at its saturated worst.
    // (A silent connection is dropped after 5 s, so sample quickly.)
    let held: Vec<UnixStream> = (0..40)
        .filter_map(|_| UnixStream::connect(&socket).ok())
        .collect();
    assert_eq!(held.len(), 40, "all 40 clients must have connected");

    let saturated = idle + 16;
    let mut peak = 0;
    let until = Instant::now() + Duration::from_secs(4);
    while Instant::now() < until {
        peak = peak.max(open_descriptors(pid));
        if peak > saturated {
            // The 17th accepted connection: nothing more can be added.
            std::thread::sleep(Duration::from_millis(300));
            peak = peak.max(open_descriptors(pid));
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    drop(held);
    eprintln!("sskd descriptors: idle {idle}, saturated peak {peak}");

    assert!(
        peak >= saturated,
        "the daemon never reached its saturated state (idle {idle}, peak {peak}): the measurement proves nothing"
    );
    let reserve = usize::try_from(FD_RESERVE).expect("fits");
    assert!(
        peak <= 32,
        "a saturated IPC server holds {peak} descriptors (idle {idle}); the design measured 29"
    );
    assert!(
        peak * 2 <= reserve + 2,
        "FD_RESERVE ({reserve}) must keep a margin of about 2x over the measured {peak}"
    );
}
