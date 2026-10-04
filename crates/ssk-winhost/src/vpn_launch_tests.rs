use super::*;
use crate::{
    service::{acl, AceEntry, PathSecurity, ProbeError},
    state_dir::StateDirLayout,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use ssk_vpnctl::ProfileId;
use std::{fs, os::windows::process::CommandExt, path::PathBuf, process::Command, sync::OnceLock};

struct TrustedFixtureAcl;
impl PathSecurityProbe for TrustedFixtureAcl {
    fn inspect(&self, _: &Path) -> Result<PathSecurity, ProbeError> {
        Ok(PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.into(),
            aces: Some(vec![AceEntry::allow(
                acl::SID_LOCAL_SYSTEM,
                acl::GENERIC_ALL,
            )]),
            is_reparse_point: false,
        })
    }
}
fn binary() -> PathBuf {
    static COMPILED: OnceLock<tempfile::TempDir> = OnceLock::new();
    let temp = COMPILED.get_or_init(|| {
        let temp = tempfile::tempdir().unwrap();
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let result = Command::new(rustc)
            .args(["--edition=2021", "-C", "debuginfo=0"])
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/vpn_management_child.rs"),
            )
            .arg("-o")
            .arg(temp.path().join("openvpn.exe"))
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "fixture build failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        temp
    });
    temp.path().join("openvpn.exe")
}
#[derive(Clone)]
struct Fixture {
    _temp: std::sync::Arc<tempfile::TempDir>,
    bundle: PathBuf,
    store: PathBuf,
    manifest: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let bundle = temp.path().join("bundle");
        let store = temp.path().join("profiles");
        fs::create_dir(&bundle).unwrap();
        fs::create_dir(&store).unwrap();
        fs::copy(binary(), bundle.join("openvpn.exe")).unwrap();
        let digest = format!(
            "{:x}",
            Sha256::digest(fs::read(bundle.join("openvpn.exe")).unwrap())
        );
        let manifest = serde_json::to_vec(&json!({"schema":1,"protocol":"openvpn-2.6","directory":bundle,"files":[{"name":"openvpn.exe","sha256":digest}]})).unwrap();
        Self {
            _temp: std::sync::Arc::new(temp),
            bundle,
            store,
            manifest,
        }
    }
    fn store(&self, probe: &dyn PathSecurityProbe) -> ProfileStore {
        ProfileStore::open_layout(StateDirLayout::new(&self.store, 1).unwrap(), probe).unwrap()
    }
    fn profile(mode: &str) -> Profile {
        let mut doc: Value = serde_json::from_slice(include_bytes!(
            "../../ssk-vpnctl/tests/fixtures/profile.json"
        ))
        .unwrap();
        doc["server_name"] = json!(mode);
        Profile::parse(&serde_json::to_vec(&doc).unwrap()).unwrap()
    }
    fn prepare(&self, mode: &str) -> Result<PreparedVpn, LaunchError> {
        let install = Installation::open_with(&self.manifest, &TrustedFixtureAcl).unwrap();
        let timeouts = Timeouts {
            startup: Duration::from_secs(3),
            command: Duration::from_millis(500),
            heartbeat: Duration::from_millis(100),
            stop: Duration::from_millis(250),
            ..Timeouts::default()
        };
        PreparedVpn::prepare_with(
            self.store(&TrustedFixtureAcl),
            install,
            Self::profile(mode),
            &TrustedFixtureAcl,
            timeouts,
        )
    }
}

#[test]
fn real_child_prepares_held_heartbeats_and_stops_with_verified_exit() {
    let f = Fixture::new();
    let mut vpn = f.prepare("normal").unwrap();
    assert_eq!(
        vpn.last_snapshot().management.unwrap().stage,
        Stage::PreparedHeld
    );
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 2);
    let until = Instant::now() + Duration::from_millis(350);
    while Instant::now() < until {
        assert_eq!(vpn.poll().management.unwrap().stage, Stage::PreparedHeld);
    }
    vpn.request_stop();
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        if vpn.poll().stage == ProcessStage::Exited {
            break;
        }
        assert!(Instant::now() < until);
    }
    assert_eq!(vpn.last_snapshot().exit_code, Some(0));
    drop(vpn);
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn post_spawn_failures_terminate_child_and_remove_launch_secrets() {
    for mode in ["wrong-pid", "reject-auth", "exit-early", "never-connect"] {
        let f = Fixture::new();
        let error = match f.prepare(mode) {
            Ok(_) => panic!("unexpected prepared state for {mode}"),
            Err(error) => error,
        };
        assert_eq!(error.process_exit_confirmed, Some(true), "{mode}: {error}");
        assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0, "{mode}");
        assert!(!format!("{error}").contains("RklYVFVSR"));
    }
}

#[test]
fn successful_management_stop_without_process_exit_escalates_to_os_termination() {
    let f = Fixture::new();
    let mut vpn = f.prepare("ignore-stop").unwrap();
    vpn.request_stop();
    let until = Instant::now() + Duration::from_secs(4);
    while vpn.poll().stage != ProcessStage::Exited {
        assert!(Instant::now() < until);
    }
    assert_ne!(vpn.last_snapshot().exit_code, Some(0));
    assert!(vpn.last_snapshot().failure.is_some());
    drop(vpn);
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn pinned_images_and_ephemeral_secrets_are_locked_and_passwords_are_fresh() {
    let f = Fixture::new();
    let mut first = f.prepare("normal").unwrap();
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(f.bundle.join("openvpn.exe"))
        .is_err());
    assert!(fs::remove_file(f.bundle.join("openvpn.exe")).is_err());
    let paths: Vec<_> = fs::read_dir(&f.store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let secret = paths
        .iter()
        .find(|p| p.extension().unwrap() == "pw")
        .unwrap();
    let first_secret = Zeroizing::new(fs::read(secret).unwrap());
    assert_eq!(first_secret.len(), 65);
    assert!(fs::OpenOptions::new().write(true).open(secret).is_err());
    assert!(first.abort_and_confirm());
    drop(first);
    let mut second = f.prepare("normal").unwrap();
    let secret = fs::read_dir(&f.store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().unwrap() == "pw")
        .unwrap();
    let second_secret = Zeroizing::new(fs::read(secret).unwrap());
    assert!(
        first_secret != second_secret,
        "per-launch passwords must differ"
    );
    assert!(second.abort_and_confirm());
    drop(second);
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn extra_missing_modified_and_hardlinked_bundle_files_are_refused() {
    let f = Fixture::new();
    fs::write(f.bundle.join("injected.dll"), b"unapproved").unwrap();
    assert!(matches!(
        Installation::open_with(&f.manifest, &TrustedFixtureAcl),
        Err(InstallationError::Contents)
    ));
    fs::remove_file(f.bundle.join("injected.dll")).unwrap();
    fs::hard_link(
        f.bundle.join("openvpn.exe"),
        f._temp.path().join("alias.exe"),
    )
    .unwrap();
    assert!(matches!(
        Installation::open_with(&f.manifest, &TrustedFixtureAcl),
        Err(InstallationError::Contents)
    ));
    fs::remove_file(f._temp.path().join("alias.exe")).unwrap();
    fs::write(f.bundle.join("openvpn.exe"), b"changed").unwrap();
    assert!(matches!(
        Installation::open_with(&f.manifest, &TrustedFixtureAcl),
        Err(InstallationError::Digest)
    ));
    fs::remove_file(f.bundle.join("openvpn.exe")).unwrap();
    assert!(Installation::open_with(&f.manifest, &TrustedFixtureAcl).is_err());
}

#[test]
fn manifest_refuses_unknown_duplicate_unsafe_and_unpinned_input() {
    let f = Fixture::new();
    let doc: Value = serde_json::from_slice(&f.manifest).unwrap();
    for (field, value) in [
        ("schema", json!(2)),
        ("protocol", json!("openvpn-2.7")),
        ("directory", json!("relative")),
        ("unknown", json!(true)),
        ("files", json!([])),
    ] {
        let mut d = doc.clone();
        d[field] = value;
        assert!(
            Installation::open_with(&serde_json::to_vec(&d).unwrap(), &TrustedFixtureAcl).is_err()
        );
    }
    for name in ["../evil.dll", "x.dll:stream", "OPENVPN.EXE", "other.exe"] {
        let mut d = doc.clone();
        d["files"][0]["name"] = json!(name);
        assert!(
            Installation::open_with(&serde_json::to_vec(&d).unwrap(), &TrustedFixtureAcl).is_err()
        );
    }
    let mut d = doc.clone();
    let entry = d["files"][0].clone();
    d["files"].as_array_mut().unwrap().push(entry);
    assert!(matches!(
        Installation::open_with(&serde_json::to_vec(&d).unwrap(), &TrustedFixtureAcl),
        Err(InstallationError::Manifest)
    ));
    let mut duplicate = b"{\"schema\":1,".to_vec();
    duplicate.extend_from_slice(&f.manifest[1..]);
    assert!(matches!(
        Installation::open_with(&duplicate, &TrustedFixtureAcl),
        Err(InstallationError::Manifest)
    ));
    let mut d = doc;
    d["files"][0]["sha256"] = json!("00");
    assert!(matches!(
        Installation::open_with(&serde_json::to_vec(&d).unwrap(), &TrustedFixtureAcl),
        Err(InstallationError::Manifest)
    ));
}

#[test]
fn writable_bundle_and_nonconfidential_run_file_are_refused_before_secret_write() {
    struct BadAcl;
    impl PathSecurityProbe for BadAcl {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            let mut security = TrustedFixtureAcl.inspect(path)?;
            security
                .aces
                .as_mut()
                .unwrap()
                .push(AceEntry::allow("S-1-1-0", acl::GENERIC_WRITE));
            Ok(security)
        }
    }
    let f = Fixture::new();
    assert!(matches!(
        Installation::open_with(&f.manifest, &BadAcl),
        Err(InstallationError::Permissions)
    ));
    struct LeakyFiles;
    impl PathSecurityProbe for LeakyFiles {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            let mut security = TrustedFixtureAcl.inspect(path)?;
            if path.extension().is_some() {
                security
                    .aces
                    .as_mut()
                    .unwrap()
                    .push(AceEntry::allow("S-1-1-0", 1));
            }
            Ok(security)
        }
    }
    let store = f.store(&TrustedFixtureAcl);
    let result = store.launch_files(
        &Fixture::profile("normal"),
        b"fixture-secret-only",
        12000,
        &LeakyFiles,
    );
    assert!(matches!(result, Err(ProfileStoreError::UnsafeFile)));
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn connected_claim_while_held_fails_even_if_it_arrives_after_preparation_returns() {
    let f = Fixture::new();
    match f.prepare("false-connected") {
        Err(error) => assert_eq!(error.process_exit_confirmed, Some(true)),
        Ok(mut vpn) => {
            let deadline = Instant::now() + Duration::from_secs(3);
            while vpn.poll().stage != ProcessStage::Exited {
                assert!(Instant::now() < deadline);
            }
            assert!(vpn.last_snapshot().failure.is_some());
        }
    }
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn a_foreign_process_connection_receives_no_password_or_protocol_bytes() {
    use std::{io::Read, net::TcpStream};
    let f = Fixture::new();
    let listener = vpn_endpoint::reserve().unwrap();
    let addr = listener.local_addr().unwrap();
    let files = f
        .store(&TrustedFixtureAcl)
        .launch_files(
            &Fixture::profile("never-connect"),
            b"fixture-password-not-for-sending",
            addr.port(),
            &TrustedFixtureAcl,
        )
        .unwrap();
    let args = [
        OsString::from("--config"),
        files.config().as_os_str().to_owned(),
    ];
    let mut child = JobChild::spawn_with_environment(
        &f.bundle.join("openvpn.exe"),
        &args,
        &f.bundle,
        &environment(&f.bundle).unwrap(),
    )
    .unwrap();
    let mut peer = TcpStream::connect(addr).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let (stream, _) = listener.accept().unwrap();
    assert!(!vpn_endpoint::verify(&stream, &mut child).unwrap());
    drop(stream);
    assert_eq!(peer.read(&mut [0u8; 128]).unwrap(), 0);
    assert!(terminate_child(&mut child));
}

#[test]
fn every_declared_dll_is_hashed_not_just_the_executable() {
    let f = Fixture::new();
    fs::write(f.bundle.join("provider.dll"), b"fixture provider").unwrap();
    let mut doc: Value = serde_json::from_slice(&f.manifest).unwrap();
    let entry = json!({"name":"provider.dll", "sha256":format!("{:x}", Sha256::digest(b"fixture provider"))});
    doc["files"].as_array_mut().unwrap().push(entry);
    let manifest = serde_json::to_vec(&doc).unwrap();
    let package = Installation::open_with(&manifest, &TrustedFixtureAcl).unwrap();
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(f.bundle.join("provider.dll"))
        .is_err());
    drop(package);
    fs::write(f.bundle.join("provider.dll"), b"replaced provider").unwrap();
    assert!(matches!(
        Installation::open_with(&manifest, &TrustedFixtureAcl),
        Err(InstallationError::Digest)
    ));
}

struct BrokerFixtureBackend {
    fixture: Fixture,
    mode: &'static str,
}
impl ssk_netd_helper::vpn::Backend for BrokerFixtureBackend {
    fn prepare(
        &mut self,
        id: &ProfileId,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(ssk_netd_helper::vpn::ProcessIdentity) -> bool,
    ) -> Result<Box<dyn ssk_netd_helper::vpn::LiveSession>, ssk_netd_helper::vpn::PrepareError>
    {
        assert_eq!(id.as_str(), "company-managed");
        let f = &self.fixture;
        let install = Installation::open_with(&f.manifest, &TrustedFixtureAcl).unwrap();
        let timeouts = Timeouts {
            startup: Duration::from_secs(3),
            command: Duration::from_millis(500),
            heartbeat: Duration::from_millis(100),
            stop: Duration::from_millis(250),
            ..Timeouts::default()
        };
        PreparedVpn::prepare_with_cancel(
            f.store(&TrustedFixtureAcl),
            install,
            &Fixture::profile(self.mode),
            &TrustedFixtureAcl,
            timeouts,
            cancelled,
            on_created,
        )
        .map(|p| Box::new(p) as Box<dyn ssk_netd_helper::vpn::LiveSession>)
        .map_err(|e| ssk_netd_helper::vpn::PrepareError {
            exit_confirmed: e.process_exit_confirmed,
            cancelled: matches!(e.reason, LaunchFailure::Cancelled),
        })
    }
    fn recover(
        &mut self,
        identity: ssk_netd_helper::vpn::ProcessIdentity,
        cancelled: &AtomicBool,
    ) -> Result<ssk_netd_helper::vpn::RecoveryEvidence, ssk_netd_helper::vpn::RecoveryFailure> {
        crate::vpn_service::recover_with(
            &self.fixture.store(&TrustedFixtureAcl),
            identity,
            cancelled,
            &TrustedFixtureAcl,
        )
    }
}

fn fixture_broker(
    mode: &'static str,
) -> (
    ssk_netd_helper::vpn::Service,
    PathBuf,
    std::sync::Arc<tempfile::TempDir>,
) {
    use ssk_netd_helper::{vpn, CapabilityToken};
    let f = Fixture::new();
    let path = f.store.clone();
    let keep = f._temp.clone();
    let store = crate::vpn_journal::SegmentedJournal::open_fixture(
        f.store(&TrustedFixtureAcl),
        Box::new(TrustedFixtureAcl),
    )
    .unwrap();
    let policy = vpn::Policy::parse(br#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"company-managed","verbs":["status","prepare","stop","recover"]}]}"#).unwrap();
    let service = vpn::Service::start(
        policy,
        CapabilityToken([7; 16]),
        Box::new(store),
        BrokerFixtureBackend { fixture: f, mode },
    )
    .unwrap();
    (service, path, keep)
}
fn fixture_request(
    verb: ssk_netd_helper::vpn::Verb,
    revision: u64,
    n: u8,
) -> ssk_netd_helper::vpn::Request {
    use ssk_netd_helper::{vpn, CapabilityToken, IdempotencyKey, Nonce};
    vpn::Request {
        session_token: CapabilityToken([7; 16]),
        nonce: Nonce([n; 16]),
        idempotency_key: IdempotencyKey([n; 16]),
        expected_revision: revision,
        command: vpn::Command {
            verb,
            profile: "company-managed".into(),
        },
    }
}
fn fixture_peer() -> ssk_netd_helper::AuthenticatedPeer {
    use ssk_netd_helper::{AuthenticatedPeer, PeerIdentity, PeerToken};
    AuthenticatedPeer::new(
        PeerIdentity::parse_sid("S-1-5-18").unwrap(),
        PeerToken::unprivileged(),
    )
}
fn fixture_status(b: &ssk_netd_helper::vpn::Broker) -> ssk_netd_helper::vpn::Status {
    use ssk_netd_helper::vpn;
    match b.handle(&fixture_peer(), fixture_request(vpn::Verb::Status, 0, 0)) {
        vpn::Response::Status(s) => s,
        other => panic!("{other:?}"),
    }
}
fn fixture_wait(
    b: &ssk_netd_helper::vpn::Broker,
    phase: ssk_netd_helper::vpn::Phase,
) -> ssk_netd_helper::vpn::Status {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let s = fixture_status(b);
        if s.phase == phase {
            return s;
        }
        assert!(Instant::now() < deadline, "{s:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn broker_worker_drives_real_held_child_with_locked_durable_intent_and_stop() {
    use ssk_netd_helper::vpn::{
        self,
        journal::{Kind, Store},
    };
    let (mut service, path, keep) = fixture_broker("normal");
    let b = service.broker();
    assert!(matches!(
        b.handle(&fixture_peer(), fixture_request(vpn::Verb::Prepare, 1, 1)),
        vpn::Response::Accepted(_)
    ));
    let held = fixture_wait(&b, vpn::Phase::PreparedHeld);
    assert!(fs::OpenOptions::new()
        .write(true)
        .open(path.join("openvpn-control.journal"))
        .is_err());
    assert!(fs::read_dir(&path).unwrap().any(|e| e
        .unwrap()
        .path()
        .extension()
        .is_some_and(|e| e == "pw")));
    assert!(matches!(
        b.handle(
            &fixture_peer(),
            fixture_request(vpn::Verb::Stop, held.revision, 2)
        ),
        vpn::Response::Accepted(_)
    ));
    assert_eq!(
        fixture_wait(&b, vpn::Phase::Idle).exit_confirmed,
        Some(true)
    );
    // Read from a separate read-only handle while the broker owns the writer.
    let file = fs::File::open(path.join("openvpn-control.journal")).unwrap();
    let records = crate::vpn_service::FileJournal { file }.load().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| r.event.kind == Kind::Intent)
            .count(),
        2
    );
    assert!(records
        .iter()
        .any(|r| r.event.status.phase == vpn::Phase::PreparedHeld));
    assert_eq!(
        fs::read_dir(&path).unwrap().count(),
        1,
        "only the durable journal remains"
    );
    assert_eq!(service.shutdown().phase, vpn::Phase::Shutdown);
    drop(b);
    drop(service);
    drop(keep);
}

#[test]
fn service_shutdown_cancels_real_child_during_management_startup_and_removes_secrets() {
    use ssk_netd_helper::vpn;
    let (mut service, path, keep) = fixture_broker("never-connect");
    let b = service.broker();
    b.handle(&fixture_peer(), fixture_request(vpn::Verb::Prepare, 1, 1));
    let deadline = Instant::now() + Duration::from_secs(3);
    while fs::read_dir(&path).unwrap().count() < 3 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    // Let the contained fixture enter its wait loop; all startup phases accept cancellation.
    thread::sleep(Duration::from_millis(100));
    service.request_shutdown();
    let stopped = service.shutdown();
    assert_eq!(stopped.phase, vpn::Phase::Shutdown);
    assert_eq!(stopped.exit_confirmed, Some(true));
    assert_eq!(fs::read_dir(&path).unwrap().count(), 1);
    drop(b);
    drop(service);
    drop(keep);
}

#[test]
fn control_artifact_locks_and_hardlink_refusal_apply_before_journal_writes() {
    let f = Fixture::new();
    let store = f.store(&TrustedFixtureAcl);
    let file = store.control_file_with(true, &TrustedFixtureAcl).unwrap();
    let path = f.store.join("openvpn-control.journal");
    assert!(store.control_file_with(true, &TrustedFixtureAcl).is_err());
    assert!(fs::remove_file(&path).is_err());
    drop(file);
    fs::hard_link(&path, f.store.join("other.journal")).unwrap();
    assert!(matches!(
        store.control_file_with(true, &TrustedFixtureAcl),
        Err(ProfileStoreError::UnsafeFile)
    ));
    assert_eq!(fs::metadata(path).unwrap().len(), 0);
}

#[test]
fn suspended_child_cannot_execute_before_resume_and_identity_queries_never_kill() {
    use ssk_netd_helper::vpn::{RecoveryEvidence, RecoveryFailure};
    let f = Fixture::new();
    let files = f
        .store(&TrustedFixtureAcl)
        .launch_files(
            &Fixture::profile("execution-marker"),
            &[b'a'; 64],
            12345,
            &TrustedFixtureAcl,
        )
        .unwrap();
    let marker = files.config().with_extension("executed");
    let mut child = JobChild::spawn_suspended(
        &f.bundle.join("openvpn.exe"),
        &["--config".into(), files.config().as_os_str().to_owned()],
        &f.bundle,
        &environment(&f.bundle).unwrap(),
    )
    .unwrap();
    let identity = child.identity(files.launch_id).unwrap();
    assert!(identity.valid());
    thread::sleep(Duration::from_millis(100));
    assert!(!marker.exists());
    assert_eq!(
        crate::vpn_process::observe_exit(identity),
        Err(RecoveryFailure::ProcessAlive)
    );
    let mut reused = identity;
    reused.created_at += 1; // deterministic stand-in for a PID with a different birth time
    assert_eq!(
        crate::vpn_process::observe_exit(reused),
        Ok(RecoveryEvidence::PidReused)
    );
    assert_eq!(
        child.try_wait().unwrap(),
        None,
        "query must never kill the PID occupant"
    );
    child.resume().unwrap();
    assert!(child.resume().is_err());
    let deadline = Instant::now() + Duration::from_secs(3);
    while !marker.exists() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(terminate_child(&mut child));
    assert_eq!(
        crate::vpn_process::observe_exit(identity),
        Ok(RecoveryEvidence::ProcessExited)
    );
    drop(child);
    assert!(matches!(
        crate::vpn_process::observe_exit(identity),
        Ok(RecoveryEvidence::PidAbsent
            | RecoveryEvidence::ProcessExited
            | RecoveryEvidence::PidReused)
    ));
    let mut invalid = identity;
    invalid.pid = 0;
    assert_eq!(
        crate::vpn_process::observe_exit(invalid),
        Err(RecoveryFailure::MissingIdentity)
    );
}

#[test]
fn refusing_identity_audit_terminates_suspended_child_without_execution() {
    let f = Fixture::new();
    let install = Installation::open_with(&f.manifest, &TrustedFixtureAcl).unwrap();
    let mut observed = None;
    let result = PreparedVpn::prepare_with_cancel(
        f.store(&TrustedFixtureAcl),
        install,
        &Fixture::profile("execution-marker"),
        &TrustedFixtureAcl,
        Timeouts::default(),
        &AtomicBool::new(false),
        &mut |identity| {
            observed = Some(identity);
            thread::sleep(Duration::from_millis(100));
            false
        },
    );
    let error = result.err().expect("audit denial must fail");
    assert!(matches!(error.reason, LaunchFailure::IdentityAudit));
    assert_eq!(error.process_exit_confirmed, Some(true));
    assert!(observed.is_some());
    assert_eq!(
        fs::read_dir(&f.store).unwrap().count(),
        0,
        "no child execution marker or secrets may remain"
    );
}

#[test]
fn cancellation_after_identity_audit_still_prevents_execution() {
    let f = Fixture::new();
    let install = Installation::open_with(&f.manifest, &TrustedFixtureAcl).unwrap();
    let cancelled = AtomicBool::new(false);
    let result = PreparedVpn::prepare_with_cancel(
        f.store(&TrustedFixtureAcl),
        install,
        &Fixture::profile("execution-marker"),
        &TrustedFixtureAcl,
        Timeouts::default(),
        &cancelled,
        &mut |_| {
            cancelled.store(true, Ordering::Release);
            true
        },
    );
    let error = result.err().expect("cancellation must fail");
    assert!(matches!(error.reason, LaunchFailure::Cancelled));
    assert_eq!(error.process_exit_confirmed, Some(true));
    assert_eq!(fs::read_dir(&f.store).unwrap().count(), 0);
}

#[test]
fn recovery_cleanup_is_exact_rejects_hardlinks_and_retries_partial_cleanup() {
    let f = Fixture::new();
    let store = f.store(&TrustedFixtureAcl);
    let id = [0x12; 16];
    let stem = format!("run-{}", "12".repeat(16));
    let pw = f.store.join(format!("{stem}.pw"));
    let config = f.store.join(format!("{stem}.ovpn"));
    let other = f.store.join("other-private-file");
    fs::write(&pw, b"fixture secret").unwrap();
    fs::write(&config, b"fixture configuration").unwrap();
    fs::write(&other, b"preserve").unwrap();
    let alias = f.store.join("alias");
    fs::hard_link(&config, &alias).unwrap();
    assert!(matches!(
        store.cleanup_run(id, &TrustedFixtureAcl),
        Err(ProfileStoreError::UnsafeFile)
    ));
    assert!(!pw.exists());
    assert!(config.exists());
    assert_eq!(fs::read(&alias).unwrap(), b"fixture configuration");
    fs::remove_file(alias).unwrap();
    store.cleanup_run(id, &TrustedFixtureAcl).unwrap();
    store.cleanup_run(id, &TrustedFixtureAcl).unwrap(); // already absent is safe
    assert!(!config.exists());
    assert_eq!(fs::read(other).unwrap(), b"preserve");
    assert!(store.cleanup_run([0; 16], &TrustedFixtureAcl).is_err());
}

#[test]
fn recovery_cleanup_refuses_unsafe_permissions_and_reparse_metadata() {
    struct UnsafeFile(bool);
    impl PathSecurityProbe for UnsafeFile {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            let mut security = TrustedFixtureAcl.inspect(path)?;
            if path.extension().is_some() {
                if self.0 {
                    security.is_reparse_point = true;
                } else {
                    security
                        .aces
                        .as_mut()
                        .unwrap()
                        .push(AceEntry::allow("S-1-1-0", 1));
                }
            }
            Ok(security)
        }
    }
    let f = Fixture::new();
    let path = f.store.join(format!("run-{}.pw", "34".repeat(16)));
    fs::write(&path, b"retain for investigation").unwrap();
    for reparse in [false, true] {
        assert!(f
            .store(&TrustedFixtureAcl)
            .cleanup_run([0x34; 16], &UnsafeFile(reparse))
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"retain for investigation");
    }
}

#[test]
fn broker_recovers_real_process_identity_from_a_crash_prefix_and_removes_only_its_files() {
    use ssk_netd_helper::{vpn, CapabilityToken};
    let f = Fixture::new();
    let start_service = |fixture: Fixture| {
        let store = crate::vpn_journal::SegmentedJournal::open_fixture(
            fixture.store(&TrustedFixtureAcl),
            Box::new(TrustedFixtureAcl),
        )
        .unwrap();
        let policy = vpn::Policy::parse(br#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"company-managed","verbs":["status","prepare","stop","recover"]}]}"#).unwrap();
        vpn::Service::start(
            policy,
            CapabilityToken([7; 16]),
            Box::new(store),
            BrokerFixtureBackend {
                fixture,
                mode: "normal",
            },
        )
        .unwrap()
    };
    let mut service = start_service(f.clone());
    let broker = service.broker();
    broker.handle(&fixture_peer(), fixture_request(vpn::Verb::Prepare, 1, 1));
    let held = fixture_wait(&broker, vpn::Phase::PreparedHeld);
    let identity = held.process_identity.unwrap();
    let journal_path = f.store.join("openvpn-control.journal");
    let crash_prefix = fs::read(&journal_path).unwrap();
    let artifacts: Vec<_> = fs::read_dir(&f.store)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "pw" || e == "ovpn"))
        .map(|p| {
            let bytes = fs::read(&p).unwrap();
            (p, bytes)
        })
        .collect();
    assert_eq!(artifacts.len(), 2);
    assert_eq!(
        crate::vpn_service::recover_with(
            &f.store(&TrustedFixtureAcl),
            identity,
            &AtomicBool::new(false),
            &TrustedFixtureAcl
        ),
        Err(vpn::RecoveryFailure::ProcessAlive)
    );
    assert!(artifacts.iter().all(|(p, _)| p.exists()));
    assert_eq!(service.shutdown().exit_confirmed, Some(true));
    drop(broker);
    drop(service);
    // Restore a durable interrupted prefix only inside this temporary fixture.
    // Real owner death/kill-on-close is separately covered in tests/vpn_job.rs.
    fs::write(&journal_path, crash_prefix).unwrap();
    for (path, bytes) in &artifacts {
        fs::write(path, bytes).unwrap();
    }
    fs::write(f.store.join("unrelated"), b"keep").unwrap();
    let mut restarted = start_service(f.clone());
    let broker = restarted.broker();
    let dirty = fixture_status(&broker);
    assert_eq!(dirty.phase, vpn::Phase::RecoveryRequired);
    assert_eq!(dirty.process_identity, Some(identity));
    assert!(matches!(
        broker.handle(
            &fixture_peer(),
            fixture_request(vpn::Verb::Recover, dirty.revision, 2)
        ),
        vpn::Response::Accepted(_)
    ));
    let recovered = fixture_wait(&broker, vpn::Phase::Idle);
    assert_eq!(recovered.exit_confirmed, Some(true));
    assert!(recovered.recovery_evidence.is_some());
    assert!(artifacts.iter().all(|(p, _)| !p.exists()));
    assert_eq!(fs::read(f.store.join("unrelated")).unwrap(), b"keep");
    assert!(fs::metadata(&journal_path).unwrap().len() > 0);
    assert!(matches!(
        broker.handle(
            &fixture_peer(),
            fixture_request(vpn::Verb::Prepare, recovered.revision, 3)
        ),
        vpn::Response::Accepted(_)
    ));
    let next = fixture_wait(&broker, vpn::Phase::PreparedHeld);
    assert_ne!(next.process_identity.unwrap().launch_id, identity.launch_id);
    restarted.shutdown();
}
