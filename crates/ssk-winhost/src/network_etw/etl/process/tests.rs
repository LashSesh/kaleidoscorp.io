use super::*;
use std::io::Write;
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
};

#[test]
fn diagnostic_child_fixture() {
    let Ok(role) = std::fs::read_to_string("etl-test-role") else {
        return;
    };
    require_containment().unwrap();
    std::fs::write("etl-test-pid", std::process::id().to_string()).unwrap();
    if role == "overflow" {
        let mut stdout = std::io::stdout().lock();
        loop {
            if stdout.write_all(&[b'x'; 4096]).is_err() {
                return;
            }
        }
    }
    if role == "crash" {
        std::process::exit(23);
    }
    if role == "success" {
        print!("worker-finished");
        return;
    }
    thread::sleep(Duration::from_secs(30));
}

fn run_fixture(role: &str, deadline: Duration) -> (io::Result<Vec<u8>>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("etl-test-role"), role).unwrap();
    let args: Vec<OsString> = [
        "--exact",
        "network_etw::etl::process::tests::diagnostic_child_fixture",
        "--nocapture",
    ]
    .into_iter()
    .map(Into::into)
    .collect();
    let result = supervise(
        &std::env::current_exe().unwrap(),
        &args,
        dir.path(),
        deadline,
    );
    (result, dir)
}

#[test]
fn hanging_worker_is_killed_and_parent_returns_within_deadline() {
    let start = Instant::now();
    let (result, dir) = run_fixture("hang", Duration::from_secs(2));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(6));
    let pid: u32 = std::fs::read_to_string(dir.path().join("etl-test-pid"))
        .unwrap()
        .parse()
        .unwrap();
    // Observation only; the owned job (not this PID) performs termination.
    let observer = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if !observer.is_null() {
        assert_eq!(
            unsafe { WaitForSingleObject(observer, 3000) },
            WAIT_OBJECT_0
        );
        unsafe {
            CloseHandle(observer);
        }
    }
}

#[test]
fn overflowing_and_crashing_workers_are_rejected() {
    for role in ["overflow", "crash"] {
        let (result, _dir) = run_fixture(role, Duration::from_secs(5));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}

#[test]
fn output_is_drained_after_normal_exit() {
    let (result, _dir) = run_fixture("success", Duration::from_secs(5));
    assert!(String::from_utf8(result.unwrap())
        .unwrap()
        .contains("worker-finished"));
}

#[test]
fn input_pin_prevents_write_and_delete_and_rejects_large_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.etl");
    std::fs::write(&path, b"fixture").unwrap();
    let (_, pin) = pin_file(&path).unwrap();
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(std::fs::remove_file(&path).is_err());
    drop(pin);
    File::create(&path)
        .unwrap()
        .set_len(MAX_FILE_BYTES + 1)
        .unwrap();
    assert!(pin_file(&path).is_err());
    for path in [
        r"\\server\share\input.etl",
        r"\\.\pipe\test",
        r"C:\test.etl:hidden",
    ] {
        assert!(pin_file(Path::new(path)).is_err());
    }
}
