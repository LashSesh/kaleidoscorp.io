use super::*;
use std::{
    fs,
    os::windows::{
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    process::{Command, Stdio},
    thread,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::WAIT_OBJECT_0,
    System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
};

const WORKER_TEST: &str = "network_etw::capture::supervisor::tests::fault_worker";
const PARENT_TEST: &str = "network_etw::capture::supervisor::tests::parent_fixture";

fn args(name: &str) -> Vec<OsString> {
    ["--exact", name, "--nocapture"]
        .map(OsString::from)
        .to_vec()
}

#[test]
fn fault_worker() {
    let Ok(kind) = fs::read_to_string("capture-test-fault") else {
        return;
    };
    worker_process::require_containment().unwrap();
    windows::fault_capture(&std::env::current_dir().unwrap(), &kind).unwrap();
}

#[test]
fn parent_fixture() {
    if !Path::new("capture-test-parent").exists() {
        return;
    }
    let _ = worker_process::run(
        &std::env::current_exe().unwrap(),
        &args(WORKER_TEST),
        &std::env::current_dir().unwrap(),
        Duration::from_secs(30),
        MAX_MESSAGE_BYTES,
    );
}

fn native_failure(kind: &str) -> (tempfile::TempDir, RunFailure) {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("capture-test-fault"), kind).unwrap();
    let result = worker_process::run(
        &std::env::current_exe().unwrap(),
        &args(WORKER_TEST),
        dir.path(),
        Duration::from_secs(2),
        MAX_MESSAGE_BYTES,
    );
    match result {
        Err(failure) => (dir, failure),
        Ok(_) => panic!("fault worker unexpectedly succeeded"),
    }
}

fn observed_process(pid: u32) -> OwnedHandle {
    let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!handle.is_null());
    unsafe { OwnedHandle::from_raw_handle(handle) }
}

#[test]
fn hanging_real_private_capture_is_killed_and_never_accepted() {
    let start = Instant::now();
    let (dir, failure) = native_failure("hang");
    assert!(start.elapsed() < Duration::from_secs(6));
    assert!(
        dir.path().join("worker-ready").exists(),
        "worker never reached an active private session"
    );
    assert!(matches!(failure.cause, Cause::Deadline));
    assert!(failure.process.termination_requested);
    assert_eq!(failure.process.termination_call_succeeded, Some(true));
    assert!(failure.process.exit_observed);
    assert!(finish(dir.path(), Err(failure)).is_err());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("supervision.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "unavailable");
    assert_eq!(report["session_cleanup_verified"], false);
    assert!(!dir.path().join("closure.json").exists());
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("recording.etl"))
        .is_ok());
}

#[test]
fn abrupt_controller_exit_and_overflow_remain_failures() {
    for kind in ["crash", "overflow"] {
        let (dir, failure) = native_failure(kind);
        assert!(dir.path().join("worker-ready").exists());
        assert!(failure.process.exit_observed);
        if kind == "crash" {
            assert!(matches!(failure.cause, Cause::WorkerExit));
            assert_eq!(failure.process.exit_code, Some(23));
            assert!(!failure.process.termination_requested);
        } else {
            assert!(matches!(failure.cause, Cause::OutputLimit));
        }
        assert!(finish(dir.path(), Err(failure)).is_err());
        assert!(!dir.path().join("closure.json").exists());
    }
}

#[test]
fn invalid_completion_after_a_real_private_session_cannot_create_success() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("capture-test-fault"), "malformed").unwrap();
    let result = worker_process::run(
        &std::env::current_exe().unwrap(),
        &args(WORKER_TEST),
        dir.path(),
        DEADLINE,
        MAX_MESSAGE_BYTES,
    );
    assert!(result.is_ok());
    assert!(finish(dir.path(), result).is_err());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("supervision.json")).unwrap()).unwrap();
    assert_eq!(report["failure"]["kind"], "protocol");
    assert_eq!(report["process"]["exit_observed"], true);
    assert_eq!(report["worker_completion_accepted"], false);
}

struct Parent(std::process::Child);
impl Drop for Parent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn abrupt_parent_death_closes_its_job_and_ends_the_active_private_worker() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("capture-test-parent"), "parent").unwrap();
    fs::write(dir.path().join("capture-test-fault"), "hang").unwrap();
    let mut parent = Parent(
        Command::new(std::env::current_exe().unwrap())
            .args(args(PARENT_TEST))
            .current_dir(dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(dir.path().join("worker-ready")) {
            if let Ok(pid) = text.parse::<u32>() {
                break pid;
            }
        }
        assert!(
            Instant::now() < deadline,
            "private worker did not become ready"
        );
        assert!(parent.0.try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(10));
    };
    // PID is read-only observation. Termination targets our owned parent handle;
    // the worker is killed by job closure, never by a PID supplied in a file.
    let observer = observed_process(pid);
    parent.0.kill().unwrap();
    parent.0.wait().unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(observer.as_raw_handle(), 3000) },
        WAIT_OBJECT_0
    );
    assert!(!dir.path().join("closure.json").exists());
    assert!(!dir.path().join("supervision.json").exists());
}

#[test]
fn completion_protocol_rejects_authority_fields_counts_and_duplicate_keys() {
    for text in [
        r#"{"schema_version":1,"events_submitted":8,"session_cleanup_verified":true}"#,
        r#"{"schema_version":1,"events_submitted":9}"#,
        r#"{"schema_version":2,"events_submitted":8}"#,
        r#"{"schema_version":1,"events_submitted":8,"events_submitted":8}"#,
    ] {
        assert!(parse(text.as_bytes()).is_err());
    }
    assert!(parse(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
}

#[test]
fn valid_message_without_artifacts_is_not_a_completed_fixture() {
    let dir = tempfile::tempdir().unwrap();
    let result = Completion {
        bytes: br#"{"schema_version":1,"events_submitted":8}"#.to_vec(),
        process: ProcessEvidence {
            started: true,
            exit_observed: true,
            exit_code: Some(0),
            ..Default::default()
        },
    };
    assert!(finish(dir.path(), Ok(result)).is_err());
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.path().join("supervision.json")).unwrap()).unwrap();
    assert_eq!(report["failure"]["kind"], "artifacts");
}
