#![cfg(windows)]
//! Real harmless child processes. No VPN, service, firewall or routing calls.
use ssk_vpnctl::ChildProcess;
use ssk_winhost::vpn_process::JobChild;
use std::{
    ffi::OsString,
    fs, io,
    os::windows::process::CommandExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, WAIT_OBJECT_0},
    System::Threading::{OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE},
};

fn args() -> Vec<OsString> {
    ["--exact", "child_fixture", "--nocapture"]
        .into_iter()
        .map(Into::into)
        .collect()
}
fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "fixture did not start: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}
fn wait_exit(child: &mut JobChild) -> u32 {
    let start = Instant::now();
    loop {
        if let Some(code) = child.try_wait().unwrap() {
            return code;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "child did not exit"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
// Helper is also a normal test; absent a fixture marker it immediately returns.
#[test]
fn child_fixture() {
    let cwd = std::env::current_dir().unwrap();
    let Ok(role) = fs::read_to_string(cwd.join("fixture-role")) else {
        return;
    };
    if role == "owner" {
        let dir = cwd.join("child");
        let child = JobChild::spawn(&std::env::current_exe().unwrap(), &args(), &dir).unwrap();
        fs::write(cwd.join("child-pid"), child.id().to_string()).unwrap();
        thread::sleep(Duration::from_secs(30));
        drop(child);
    } else if role == "spawn" {
        let result = Command::new(std::env::current_exe().unwrap())
            .arg("--list")
            .creation_flags(0x08000000)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match result {
            Err(_) => fs::write(cwd.join("descendant-refused"), b"ok").unwrap(),
            Ok(mut child) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("descendant escaped process limit");
            }
        }
    } else {
        fs::write(
            cwd.join("arguments"),
            serde_json::to_vec(&std::env::args().collect::<Vec<_>>()).unwrap(),
        )
        .unwrap();
        fs::write(cwd.join("ready"), b"ok").unwrap();
        thread::sleep(Duration::from_secs(30));
    }
}

#[test]
fn kill_and_exit_confirmation_use_the_owned_handle() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("fixture-role"), "wait").unwrap();
    let mut child =
        JobChild::spawn(&std::env::current_exe().unwrap(), &args(), dir.path()).unwrap();
    wait_for(&dir.path().join("ready"));
    assert_eq!(child.try_wait().unwrap(), None);
    child.terminate().unwrap();
    assert_eq!(wait_exit(&mut child), 1);
    assert_eq!(child.try_wait().unwrap(), Some(1));
}

#[test]
fn closing_last_job_handle_terminates_the_child() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("fixture-role"), "wait").unwrap();
    let child = JobChild::spawn(&std::env::current_exe().unwrap(), &args(), dir.path()).unwrap();
    wait_for(&dir.path().join("ready"));
    // A separate wait-only handle is observation, never a job handle or owner.
    let observer = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, child.id()) };
    assert!(!observer.is_null(), "{}", io::Error::last_os_error());
    drop(child);
    let result = unsafe { WaitForSingleObject(observer, 10000) };
    unsafe {
        CloseHandle(observer);
    }
    assert_eq!(result, WAIT_OBJECT_0);
}

#[test]
fn abrupt_owner_death_still_terminates_child_without_rust_drop() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("fixture-role"), "owner").unwrap();
    fs::create_dir(dir.path().join("child")).unwrap();
    fs::write(dir.path().join("child/fixture-role"), "wait").unwrap();
    let mut owner = Command::new(std::env::current_exe().unwrap())
        .args(args())
        .current_dir(dir.path())
        .creation_flags(0x08000000)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Guard also kills the owner if a fixture assertion panics.
    struct Owner<'a>(&'a mut std::process::Child);
    impl Drop for Owner<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let guard = Owner(&mut owner);
    wait_for(&dir.path().join("child/ready"));
    wait_for(&dir.path().join("child-pid"));
    let pid: u32 = fs::read_to_string(dir.path().join("child-pid"))
        .unwrap()
        .parse()
        .unwrap();
    let observer = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    assert!(!observer.is_null(), "{}", io::Error::last_os_error());
    guard.0.kill().unwrap();
    guard.0.wait().unwrap();
    let result = unsafe { WaitForSingleObject(observer, 10000) };
    unsafe {
        CloseHandle(observer);
    }
    assert_eq!(result, WAIT_OBJECT_0);
}

#[test]
fn descendant_creation_is_refused_by_the_job() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("fixture-role"), "spawn").unwrap();
    let mut child =
        JobChild::spawn(&std::env::current_exe().unwrap(), &args(), dir.path()).unwrap();
    assert_eq!(wait_exit(&mut child), 0);
    assert!(dir.path().join("descendant-refused").exists());
}

#[test]
fn arguments_with_quotes_spaces_unicode_and_trailing_slashes_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("fixture-role"), "wait").unwrap();
    let tricky = "space ü \\\"quoted\\\" tail\\";
    let mut arguments = args();
    arguments.extend([OsString::from("--skip"), OsString::from(tricky)]);
    let mut child =
        JobChild::spawn(&std::env::current_exe().unwrap(), &arguments, dir.path()).unwrap();
    wait_for(&dir.path().join("ready"));
    let observed: Vec<String> =
        serde_json::from_slice(&fs::read(dir.path().join("arguments")).unwrap()).unwrap();
    assert_eq!(observed.last().unwrap(), tricky);
    child.terminate().unwrap();
    wait_exit(&mut child);
}

#[test]
fn invalid_launch_inputs_fail_before_a_child_exists() {
    let dir = tempfile::tempdir().unwrap();
    assert!(JobChild::spawn(Path::new("relative.exe"), &[], dir.path()).is_err());
    assert!(JobChild::spawn(
        &std::env::current_exe().unwrap(),
        &[OsString::from("bad\0arg")],
        dir.path()
    )
    .is_err());
    assert!(JobChild::spawn(&dir.path().join("absent.exe"), &[], dir.path()).is_err());
}
