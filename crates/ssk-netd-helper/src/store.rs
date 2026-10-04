//! The durable, ACL-protected state store (SPEC_TAURI_GUI.md §3): replaces the
//! `%TEMP%` receipt store with an atomically-written snapshot in ProgramData.
//!
//! The snapshot holds everything needed to recover the authoritative kill-switch
//! state after a crash: the logical state, the held rollback receipt, the
//! monotone version, and the hash-chained audit journal. It is written whole,
//! atomically (temp file + fsync + rename), under the broker's operation lock —
//! so a crash mid-write never yields a torn snapshot, and a single writer never
//! races itself.
//!
//! # Provisioning is not opening (the P1 split)
//!
//! Before P1 a single `open()` both created the directory **and** ran `icacls`
//! against it. That conflation is what made 8 tests fail: every test that just
//! wanted a temp dir ran a production ACL lockdown, and the resulting DACL
//! (SYSTEM + `BUILTIN\Administrators` only) revokes a UAC-filtered process's own
//! access to the directory it just created — the very next `File::create`
//! returns `os error 5` (roadmap §5.2, reproduced by controlled experiment).
//!
//! The two operations are now separate and differently privileged:
//!
//! * [`FileReceiptStore::provision`] — install-time, **requires
//!   [`Elevation::Elevated`]**, takes ownership and applies the DACL.
//! * [`FileReceiptStore::open_existing`] — run-time, does **no** ACL work at
//!   all, and refuses a directory that does not already exist.
//!
//! The DACL is not weakened to make anything pass. It still grants only
//! `*S-1-5-18` (SYSTEM) and `*S-1-5-32-544` (`BUILTIN\Administrators`), and
//! [`lockdown_args`] is guarded by a test asserting that no user-scoped
//! principal ever appears in it.
//!
//! # Who calls this, and what it is *not* sufficient for
//!
//! [`FileReceiptStore::provision`] / [`FileReceiptStore::provision_with`] are
//! **create-and-lock-down**. They do not — and, being
//! `#![forbid(unsafe_code)]`, cannot — read back a Windows DACL, so on their own
//! they will happily lock down a directory an attacker created first. Rewriting
//! the DACL of a directory someone else already owns does not evict them: a
//! handle opened before the change keeps the access it was granted at open time.
//!
//! The **verification** half therefore lives in `ssk_winhost::state_dir`, the
//! crate that owns the `GetNamedSecurityInfoW` FFI, and it is the only
//! production caller of [`FileReceiptStore::provision`],
//! [`FileReceiptStore::provision_with`], [`default_provision_chain`] and
//! [`default_state_dir`]. It probes the directory first and calls in here only
//! for the *absent* case; a present-but-unsafe directory is refused, never
//! repaired. Callers that want the ProgramData store must use
//! `ssk_winhost::state_dir::ensure_state_dir`, not these functions directly.
//!
//! [`FileReceiptStore::open_existing`] is the constructor a privileged host
//! passes to [`crate::Broker::recover_privileged`]. Whether such a host exists
//! is a fact about `ssk-winhost`'s `ssk-svc` binary, not about this crate, and
//! this comment deliberately does not assert it — the reachability claim that
//! used to live here ("no production caller") was a statement about another
//! crate that this one cannot verify and that would silently go stale.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use ssk_boundary::{BoundaryAuditEntry, EnforcementReceipt, KillSwitchState};

use crate::error::HelperError;
use crate::lease::Lease;

const SNAPSHOT_FILE: &str = "killswitch.cbor";

/// The snapshot format version.
///
/// **1 → 2 at P3**, when [`PersistedState::leases`] was added. A version-1
/// snapshot is therefore rejected with [`HelperError::CorruptState`] rather than
/// read as leaseless: a leaseless read of a v1 `Engaged` snapshot would make the
/// startup reconciler see an engaged switch with no holder and release egress on
/// a machine an operator had deliberately severed.
const SNAPSHOT_SCHEMA: u32 = 2;

/// The full persisted snapshot of the kill-switch security state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedState {
    /// Schema version so a future format change is detected, not mis-decoded.
    pub schema_version: u32,
    pub logical_state: KillSwitchState,
    pub receipt: Option<EnforcementReceipt>,
    pub state_version: u64,
    /// The hash-chained kill-switch audit journal (verified on rehydrate).
    pub journal: Vec<BoundaryAuditEntry>,
    /// The live claims on the kill-switch (P3 refcounting, see
    /// [`crate::lease`]).
    ///
    /// `#[serde(default)]` so that a version-1 snapshot — which has no such
    /// field — reaches the schema-version check and is refused with
    /// *"unknown schema version 1"*, instead of failing earlier as
    /// *"missing field `leases`"*. Both fail closed; only one tells an operator
    /// what actually happened.
    #[serde(default)]
    pub leases: Vec<Lease>,
}

impl PersistedState {
    #[must_use]
    pub fn new(
        logical_state: KillSwitchState,
        receipt: Option<EnforcementReceipt>,
        state_version: u64,
        journal: Vec<BoundaryAuditEntry>,
        leases: Vec<Lease>,
    ) -> Self {
        PersistedState {
            schema_version: SNAPSHOT_SCHEMA,
            logical_state,
            receipt,
            state_version,
            journal,
            leases,
        }
    }

    /// The schema version this build writes.
    #[must_use]
    pub fn schema() -> u32 {
        SNAPSHOT_SCHEMA
    }
}

/// The durable store seam. The broker persists through this; tests inject an
/// in-memory or temp-dir implementation.
pub trait ReceiptStore: Send {
    /// Atomically persist the snapshot (whole-file, crash-safe).
    ///
    /// # Errors
    /// [`HelperError::Store`] on any IO failure.
    fn save(&self, state: &PersistedState) -> Result<(), HelperError>;

    /// Load the persisted snapshot, or `None` if the store is empty (first run).
    ///
    /// # Errors
    /// [`HelperError::Store`] on IO failure; [`HelperError::CorruptState`] if a
    /// present snapshot cannot be decoded.
    fn load(&self) -> Result<Option<PersistedState>, HelperError>;
}

/// The default ProgramData-based state directory
/// (`%ProgramData%\ScorpioSync\state`), or a conventional path off-Windows.
#[must_use]
pub fn default_state_dir() -> PathBuf {
    if let Some(program_data) = std::env::var_os("ProgramData") {
        PathBuf::from(program_data)
            .join("ScorpioSync")
            .join("state")
    } else {
        PathBuf::from("/var/lib/scorpiosync/state")
    }
}

/// The directories that make up the default store layout, **outermost first**.
///
/// Both must be locked down, not just the leaf: `C:\ProgramData` grants
/// `BUILTIN\Users:(CI)(WD,AD,...)` and `CREATOR OWNER:(OI)(CI)(IO)(F)`
/// (measured on Windows 11 de-DE, 2026-08-02), so an *unprivileged* process can
/// create `ScorpioSync` first and become its owner. An owner retains implicit
/// `WRITE_DAC`, so locking only `ScorpioSync\state` would leave a squatter able
/// to re-open the parent.
#[must_use]
pub fn default_provision_chain() -> Vec<PathBuf> {
    let leaf = default_state_dir();
    match leaf.parent() {
        Some(parent) => vec![parent.to_path_buf(), leaf],
        None => vec![leaf],
    }
}

/// Whether the current process is elevated, as a **value supplied by the
/// composition root** rather than something this crate probes for itself.
///
/// `ssk-netd-helper` is `#![forbid(unsafe_code)]` and must stay that way. The
/// only reliable Windows elevation check is
/// `GetTokenInformation(.., TokenElevation, ..)`, which is FFI and belongs in
/// `ssk-winhost` (the one crate exempt from the workspace's `unsafe_code`
/// forbid). Parsing `whoami /groups` was rejected instead of adopted: its
/// attribute column is localized (on the de-DE test box the deny-only flag
/// reads `"Gruppen, die nur zum Ablehnen verwendet wird"`), which is the same
/// class of defect as the English-literal netsh bug P1 exists to kill; and
/// `S-1-5-32-544` is *present* in an unelevated filtered token, so SID presence
/// alone is not elevation.
///
/// A capability-as-value also beats a capability-as-trait here: a trait method
/// can be called at the wrong moment or stubbed to always-true, whereas a value
/// has to be produced once, at the composition root, and passed to the call
/// site that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Elevation {
    Elevated,
    NotElevated,
    /// The probe could not answer. Treated **identically to
    /// [`Elevation::NotElevated`]** — fail closed.
    Unknown,
}

impl Elevation {
    /// Map a probe result (`ssk_winhost::privilege::is_elevated()`-shaped) to
    /// this enum. `None` becomes [`Elevation::Unknown`], not `Elevated`.
    #[must_use]
    pub fn from_probe(probe: Option<bool>) -> Self {
        match probe {
            Some(true) => Elevation::Elevated,
            Some(false) => Elevation::NotElevated,
            None => Elevation::Unknown,
        }
    }

    /// Only [`Elevation::Elevated`] permits a system-mutating operation.
    #[must_use]
    pub fn permits_system_mutation(self) -> bool {
        matches!(self, Elevation::Elevated)
    }
}

/// The seam through which the ACL tool is invoked, so the DACL path is
/// exercised **deliberately** in tests instead of incidentally by every test
/// that wanted a temp directory. Mirrors the `NetshRunner` seam in
/// `ssk-winhost::firewall` on purpose — same shape, same reason.
pub trait AclRunner {
    /// Run the ACL tool with `args`; return its process exit code.
    ///
    /// # Errors
    /// A diagnostic string if the tool could not be spawned at all.
    fn run(&self, args: &[String]) -> Result<i32, String>;
}

/// SID of `NT AUTHORITY\SYSTEM`. Used instead of the name `SYSTEM`, which is
/// localized (`NT-AUTORITÄT\SYSTEM` on the de-DE test box) — the pre-P1 code
/// passed the literal `SYSTEM` and carried that latent locale dependency.
const SID_SYSTEM: &str = "*S-1-5-18";
/// SID of `BUILTIN\Administrators`.
const SID_ADMINISTRATORS: &str = "*S-1-5-32-544";

/// `icacls <dir> /setowner *S-1-5-32-544 /T` — pure, no IO.
///
/// Issued **before** [`lockdown_args`]. Rewriting only the DACL of a directory
/// an attacker already owns is not sufficient: the owner keeps implicit
/// `READ_CONTROL | WRITE_DAC` and can put their ACEs back. `/T` covers a
/// subtree the squatter may have planted underneath.
#[must_use]
pub fn setowner_args(dir: &Path) -> Vec<String> {
    vec![
        dir.display().to_string(),
        "/setowner".to_owned(),
        SID_ADMINISTRATORS.to_owned(),
        "/T".to_owned(),
    ]
}

/// `icacls <dir> /inheritance:r /grant:r <SYSTEM> /grant:r <Administrators> /T`
/// — pure, no IO.
///
/// Grants **only** SYSTEM and `BUILTIN\Administrators`. It deliberately does
/// *not* grant the running principal: under UAC the running principal of an
/// elevated engage is the user's own SID, which — unlike `S-1-5-32-544` — is
/// fully enabled in every *unelevated* process that user runs. Granting it
/// would let any unprivileged process owned by that user rewrite
/// `killswitch.cbor`, which is precisely the `%TEMP%` hole (SEC-1) this move to
/// ProgramData exists to close. That would make the 8 broker tests pass by
/// making the store insecure.
#[must_use]
pub fn lockdown_args(dir: &Path) -> Vec<String> {
    vec![
        dir.display().to_string(),
        "/inheritance:r".to_owned(),
        "/grant:r".to_owned(),
        format!("{SID_SYSTEM}:(OI)(CI)F"),
        "/grant:r".to_owned(),
        format!("{SID_ADMINISTRATORS}:(OI)(CI)F"),
        "/T".to_owned(),
    ]
}

/// A crash-safe, ACL-protected file store.
#[derive(Debug)]
pub struct FileReceiptStore {
    dir: PathBuf,
}

impl FileReceiptStore {
    /// Use an **already-provisioned** store. Performs no ACL work whatsoever
    /// and never creates the directory: a missing directory means the store was
    /// never provisioned, and silently creating an unprotected one would be a
    /// downgrade the caller could not see.
    ///
    /// This is the run-time constructor — the broker's, and the tests'.
    ///
    /// # Errors
    /// [`HelperError::Store`] if `dir` does not exist or is not a directory.
    pub fn open_existing(dir: impl Into<PathBuf>) -> Result<Self, HelperError> {
        let dir = dir.into();
        if !dir.is_dir() {
            return Err(HelperError::Store(format!(
                "store directory {} does not exist (provision it first)",
                dir.display()
            )));
        }
        Ok(FileReceiptStore { dir })
    }

    /// Create `dir` and lock it down. **Requires [`Elevation::Elevated`].**
    ///
    /// Install-time / service-start only. On a non-Windows target the ACL step
    /// is a documented no-op (there are no Windows ACLs to apply); the
    /// elevation gate and the ordering still run, so the logic is identical and
    /// fully covered on both platforms.
    ///
    /// **Not safe to call on a directory that may already exist** — see this
    /// module's header. `ssk_winhost::state_dir::ensure_state_dir` is the
    /// supported entry point; it establishes absence (and the safety of every
    /// ancestor) before calling this, and re-reads the DACL afterwards.
    ///
    /// # Errors
    /// [`HelperError::NotElevated`] if `elevation` is not
    /// [`Elevation::Elevated`]; [`HelperError::Store`] if the directory cannot
    /// be created or the ACL tool fails.
    pub fn provision(dir: impl Into<PathBuf>, elevation: Elevation) -> Result<Self, HelperError> {
        Self::provision_with(dir, elevation, &default_acl_runner())
    }

    /// [`FileReceiptStore::provision`] with the ACL tool injected — the DACL
    /// path under test.
    ///
    /// Order is load-bearing: create → `/setowner` → `/grant:r`. Any non-zero
    /// exit from either step fails closed and yields **no store handle**, so a
    /// caller cannot end up writing receipts into a directory whose ACL was
    /// never asserted.
    ///
    /// # Errors
    /// As [`FileReceiptStore::provision`].
    pub fn provision_with(
        dir: impl Into<PathBuf>,
        elevation: Elevation,
        acl: &dyn AclRunner,
    ) -> Result<Self, HelperError> {
        let dir = dir.into();
        if !elevation.permits_system_mutation() {
            // Checked *before* anything is created or any tool is spawned.
            return Err(HelperError::NotElevated {
                operation: "provisioning the ProgramData state store",
                observed: elevation,
            });
        }
        fs::create_dir_all(&dir)
            .map_err(|e| HelperError::Store(format!("create_dir_all {}: {e}", dir.display())))?;
        run_acl_step(acl, &setowner_args(&dir), "setowner", &dir)?;
        run_acl_step(acl, &lockdown_args(&dir), "lockdown", &dir)?;
        Ok(FileReceiptStore { dir })
    }

    // `provision_default_with` used to live here: it walked
    // `default_provision_chain()` calling `provision_with` on each level. It was
    // deleted rather than kept, because it is precisely the create-and-trust
    // shape this module's header now warns against — it created every level
    // without ever establishing that the level was absent, so a squatted
    // `ScorpioSync` would have been adopted and re-ACL'd. Its replacement is
    // `ssk_winhost::state_dir::ensure_state_dir`, which drives
    // `default_provision_chain()` itself and probes before it creates. Keeping a
    // weaker second entry point alongside the correct one is how the correct one
    // stops being used.

    /// The directory this store reads and writes.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn snapshot_path(&self) -> PathBuf {
        self.dir.join(SNAPSHOT_FILE)
    }
}

fn run_acl_step(
    acl: &dyn AclRunner,
    args: &[String],
    step: &str,
    dir: &Path,
) -> Result<(), HelperError> {
    let code = acl
        .run(args)
        .map_err(|e| HelperError::Store(format!("acl {step} spawn for {}: {e}", dir.display())))?;
    if code != 0 {
        return Err(HelperError::Store(format!(
            "acl {step} failed for {} (exit {code})",
            dir.display()
        )));
    }
    Ok(())
}

impl ReceiptStore for FileReceiptStore {
    fn save(&self, state: &PersistedState) -> Result<(), HelperError> {
        let final_path = self.snapshot_path();
        let tmp_path = self.dir.join(format!("{SNAPSHOT_FILE}.tmp"));

        let mut body = Vec::new();
        ciborium::ser::into_writer(state, &mut body)
            .map_err(|e| HelperError::Store(format!("encode: {e}")))?;

        // Write to a temp file in the same dir, flush + fsync, then atomically
        // rename over the final path.
        {
            let mut f = fs::File::create(&tmp_path)
                .map_err(|e| HelperError::Store(format!("create tmp: {e}")))?;
            f.write_all(&body)
                .map_err(|e| HelperError::Store(format!("write tmp: {e}")))?;
            f.sync_all()
                .map_err(|e| HelperError::Store(format!("fsync tmp: {e}")))?;
        }
        atomic_replace(&tmp_path, &final_path)?;
        Ok(())
    }

    fn load(&self) -> Result<Option<PersistedState>, HelperError> {
        let path = self.snapshot_path();
        match fs::read(&path) {
            Ok(bytes) => {
                let state: PersistedState = ciborium::de::from_reader(&bytes[..])
                    .map_err(|e| HelperError::CorruptState(format!("decode: {e}")))?;
                if state.schema_version != SNAPSHOT_SCHEMA {
                    return Err(HelperError::CorruptState(format!(
                        "unknown schema version {}",
                        state.schema_version
                    )));
                }
                Ok(Some(state))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(HelperError::Store(format!("read {}: {e}", path.display()))),
        }
    }
}

/// Atomically replace `final_path` with `tmp_path`. On Unix `rename` replaces
/// atomically. On Windows `rename` fails if the destination exists, so we fall
/// back to remove-then-rename (a small non-atomic window). The fully-atomic
/// Windows path (`MoveFileEx(MOVEFILE_REPLACE_EXISTING)` / `ReplaceFileW`) is an
/// FFI call and belongs in the unsafe-isolated `ssk-winhost` crate — tracked as
/// a Windows-hardening follow-up; this crate stays `#![forbid(unsafe_code)]`.
fn atomic_replace(tmp_path: &Path, final_path: &Path) -> Result<(), HelperError> {
    match fs::rename(tmp_path, final_path) {
        Ok(()) => Ok(()),
        Err(_) if final_path.exists() => {
            fs::remove_file(final_path)
                .map_err(|e| HelperError::Store(format!("replace-remove: {e}")))?;
            fs::rename(tmp_path, final_path)
                .map_err(|e| HelperError::Store(format!("replace-rename: {e}")))
        }
        Err(e) => Err(HelperError::Store(format!("rename: {e}"))),
    }
}

/// Runs the real `icacls.exe`.
///
/// The image is resolved from `%SystemRoot%\System32\` and **never through
/// `PATH`**. `provision` runs elevated by requirement, so a `PATH` entry an
/// attacker controls would otherwise be a direct elevated-code-execution path
/// that bypasses every control this module implements.
#[cfg(windows)]
struct SystemAclRunner;

#[cfg(windows)]
impl AclRunner for SystemAclRunner {
    fn run(&self, args: &[String]) -> Result<i32, String> {
        let system_root = std::env::var_os("SystemRoot")
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        let exe = PathBuf::from(system_root)
            .join("System32")
            .join("icacls.exe");
        let status = std::process::Command::new(&exe)
            .args(args)
            .status()
            .map_err(|e| format!("{}: {e}", exe.display()))?;
        // A terminated-by-signal process has no code; treat it as failure.
        Ok(status.code().unwrap_or(-1))
    }
}

#[cfg(windows)]
fn default_acl_runner() -> SystemAclRunner {
    SystemAclRunner
}

/// There are no Windows ACLs off-Windows. This runner asserts nothing and says
/// so by returning success without doing anything — the deployment target for
/// the ACL'd store is Windows, and POSIX permissions on the injected directory
/// govern elsewhere (SPEC §3). It is **not** a stand-in for the real lockdown:
/// `provision` on a non-Windows host produces an unprotected directory, exactly
/// as `assert_restrictive_dacl` did before P1.
#[cfg(not(windows))]
struct NoOpAclRunner;

#[cfg(not(windows))]
impl AclRunner for NoOpAclRunner {
    fn run(&self, _args: &[String]) -> Result<i32, String> {
        Ok(0)
    }
}

#[cfg(not(windows))]
fn default_acl_runner() -> NoOpAclRunner {
    NoOpAclRunner
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    /// Records every argv it is handed and returns a scripted exit code.
    struct ScriptedAcl {
        calls: RefCell<Vec<Vec<String>>>,
        code: i32,
    }

    impl ScriptedAcl {
        fn ok() -> Self {
            ScriptedAcl {
                calls: RefCell::new(Vec::new()),
                code: 0,
            }
        }
        fn failing(code: i32) -> Self {
            ScriptedAcl {
                calls: RefCell::new(Vec::new()),
                code,
            }
        }
        fn count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl AclRunner for ScriptedAcl {
        fn run(&self, args: &[String]) -> Result<i32, String> {
            self.calls.borrow_mut().push(args.to_vec());
            Ok(self.code)
        }
    }

    // ── The DACL argv, asserted deliberately ────────────────────────────────
    #[test]
    fn lockdown_argv_grants_only_system_and_administrators() {
        let args = lockdown_args(Path::new("D:/store"));
        assert_eq!(args[0], "D:/store");
        assert!(args.contains(&"/inheritance:r".to_owned()));
        assert!(args.contains(&"*S-1-5-18:(OI)(CI)F".to_owned()));
        assert!(args.contains(&"*S-1-5-32-544:(OI)(CI)F".to_owned()));
        assert_eq!(
            args.iter().filter(|a| *a == "/grant:r").count(),
            2,
            "exactly two principals are granted"
        );
    }

    /// The regression guard against "fixing" the 8 failing tests by granting
    /// the running principal. Any of these appearing in the lockdown argv would
    /// hand write access to an unelevated process owned by the same user.
    #[test]
    fn lockdown_argv_grants_no_user_scoped_principal() {
        let joined = lockdown_args(Path::new("D:/store")).join(" ");
        for forbidden in [
            "%USERNAME%",
            "*S-1-5-11",     // Authenticated Users
            "*S-1-1-0",      // Everyone
            "*S-1-5-32-545", // BUILTIN\Users
            "*S-1-5-32-546", // BUILTIN\Guests
            "*S-1-3-0",      // CREATOR OWNER
            "(F)",           // an un-scoped full-control grant
        ] {
            assert!(
                !joined.contains(forbidden),
                "lockdown argv must never contain {forbidden}: {joined}"
            );
        }
        // And no environment-variable expansion of any kind.
        assert!(!joined.contains('%'));
    }

    #[test]
    fn setowner_argv_takes_ownership_for_administrators_recursively() {
        let args = setowner_args(Path::new("D:/store"));
        assert_eq!(
            args,
            vec![
                "D:/store".to_owned(),
                "/setowner".to_owned(),
                "*S-1-5-32-544".to_owned(),
                "/T".to_owned(),
            ]
        );
    }

    #[test]
    fn provision_issues_setowner_before_lockdown() {
        let dir = tempfile::tempdir().unwrap();
        let acl = ScriptedAcl::ok();
        FileReceiptStore::provision_with(dir.path(), Elevation::Elevated, &acl).unwrap();
        let calls = acl.calls.borrow();
        assert_eq!(calls.len(), 2, "exactly two ACL steps");
        assert_eq!(calls[0], setowner_args(dir.path()));
        assert_eq!(calls[1], lockdown_args(dir.path()));
    }

    #[test]
    fn a_failing_acl_step_fails_closed_with_no_store_handle() {
        let dir = tempfile::tempdir().unwrap();
        let acl = ScriptedAcl::failing(5);
        let err = FileReceiptStore::provision_with(dir.path(), Elevation::Elevated, &acl)
            .expect_err("a non-zero icacls exit must not yield a store");
        assert!(matches!(err, HelperError::Store(_)), "{err:?}");
        assert_eq!(acl.count(), 1, "it stopped at the failing step");
    }

    #[test]
    fn provision_refuses_unelevated_without_touching_anything() {
        for observed in [Elevation::NotElevated, Elevation::Unknown] {
            let dir = tempfile::tempdir().unwrap();
            let target = dir.path().join("state");
            let acl = ScriptedAcl::ok();
            let err = FileReceiptStore::provision_with(&target, observed, &acl).unwrap_err();
            assert_eq!(
                err,
                HelperError::NotElevated {
                    operation: "provisioning the ProgramData state store",
                    observed,
                },
                "Unknown must fail closed exactly like NotElevated"
            );
            assert_eq!(err.code(), "NOT_ELEVATED");
            assert_eq!(acl.count(), 0, "no ACL tool was spawned");
            assert!(!target.exists(), "no directory was created");
        }
    }

    #[test]
    fn elevation_from_probe_fails_closed_on_none() {
        assert_eq!(Elevation::from_probe(Some(true)), Elevation::Elevated);
        assert_eq!(Elevation::from_probe(Some(false)), Elevation::NotElevated);
        assert_eq!(Elevation::from_probe(None), Elevation::Unknown);
        assert!(!Elevation::Unknown.permits_system_mutation());
        assert!(!Elevation::NotElevated.permits_system_mutation());
        assert!(Elevation::Elevated.permits_system_mutation());
    }

    // ── open_existing: no ACL work, full round-trip ─────────────────────────
    #[test]
    fn open_existing_does_no_acl_work_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileReceiptStore::open_existing(dir.path()).unwrap();
        assert!(store.load().unwrap().is_none(), "empty store");
        let state = PersistedState::new(
            KillSwitchState::Armed,
            None,
            7,
            Vec::new(),
            vec![Lease {
                id: crate::lease::LeaseId([4u8; 16]),
                kind: crate::lease::LeaseKind::Pinned,
                holder: "S-1-5-21-1-2-3-1001".to_owned(),
                taken_at_version: 6,
            }],
        );
        store.save(&state).unwrap();
        assert_eq!(
            FileReceiptStore::open_existing(dir.path())
                .unwrap()
                .load()
                .unwrap(),
            Some(state),
            "the claim set is part of the durable snapshot, not in-memory only"
        );
    }

    /// A snapshot written by a pre-P3 build has no `leases` field and therefore
    /// no record of who is holding the switch engaged. Reading it as leaseless
    /// would let the startup reconciler conclude "engaged with no holder" and
    /// release egress on a machine an operator deliberately severed. It must be
    /// refused, with a message that names the version.
    #[test]
    fn a_version_1_snapshot_is_refused_rather_than_read_as_leaseless() {
        #[derive(serde::Serialize)]
        struct V1 {
            schema_version: u32,
            logical_state: KillSwitchState,
            receipt: Option<EnforcementReceipt>,
            state_version: u64,
            journal: Vec<BoundaryAuditEntry>,
        }
        let dir = tempfile::tempdir().unwrap();
        let mut body = Vec::new();
        ciborium::ser::into_writer(
            &V1 {
                schema_version: 1,
                logical_state: KillSwitchState::Armed,
                receipt: None,
                state_version: 3,
                journal: Vec::new(),
            },
            &mut body,
        )
        .unwrap();
        fs::write(dir.path().join(SNAPSHOT_FILE), &body).unwrap();

        let err = FileReceiptStore::open_existing(dir.path())
            .unwrap()
            .load()
            .expect_err("a v1 snapshot must not decode");
        assert!(
            matches!(err, HelperError::CorruptState(ref m) if m.contains("schema version 1")),
            "{err:?}"
        );
    }

    #[test]
    fn this_build_writes_schema_2() {
        assert_eq!(PersistedState::schema(), 2);
        assert_eq!(
            PersistedState::new(KillSwitchState::Armed, None, 0, Vec::new(), Vec::new())
                .schema_version,
            2
        );
    }

    #[test]
    fn open_existing_refuses_an_unprovisioned_directory() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-provisioned");
        let err = FileReceiptStore::open_existing(&missing).unwrap_err();
        assert!(matches!(err, HelperError::Store(_)), "{err:?}");
        assert!(!missing.exists(), "it must not create the directory");
    }

    #[test]
    fn the_default_provision_chain_covers_the_parent_not_just_the_leaf() {
        let chain = default_provision_chain();
        assert_eq!(chain.len(), 2, "parent + leaf");
        assert_eq!(chain[1], default_state_dir());
        assert_eq!(chain[1].parent(), Some(chain[0].as_path()));
    }
}
