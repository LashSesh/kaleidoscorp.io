//! The privileged state directory (`%ProgramData%\ScorpioSync\state`):
//! **create-or-verify, never create-and-trust**.
//!
//! This is the primitive that puts the P1 store lockdown on the path the product
//! actually takes. Before it, `ssk-cli` created the receipt directory with a bare
//! `create_dir_all` and the hardened
//! [`ssk_netd_helper::store::FileReceiptStore::provision`] had no caller outside
//! its own module — the DACL code was correct and never ran.
//!
//! ## Why a *verify* step, and why a squat is a refusal rather than a repair
//!
//! Measured on Windows 11 de-DE (2026-08-02, read-only `icacls`):
//! `C:\ProgramData` grants `BUILTIN\Benutzer:(CI)(WD,AD,WEA,WA)` — write, with
//! `ContainerInherit` — and `ERSTELLER-BESITZER:(OI)(CI)(IO)(F)`. An
//! unprivileged process can therefore create the whole `ScorpioSync\state`
//! chain, become `CREATOR OWNER` with full control, and plant receipts. An owner
//! also holds implicit `WRITE_DAC`, so it can restore its own ACEs afterwards.
//!
//! Consequently a directory that is merely *present* is not a directory that is
//! *safe*, and provisioning has to distinguish three cases:
//!
//! * **absent** — create it (atomically, non-recursively, so the create itself
//!   is the claim), take ownership for `BUILTIN\Administrators`, break
//!   inheritance, grant only `*S-1-5-18` and `*S-1-5-32-544`, then **re-read the
//!   ACL and verify it took**;
//! * **present, administratively owned, no non-administrative principal holding
//!   a dangerous right** — accept;
//! * **present but owned by, or writable by, a non-administrative principal** —
//!   **refuse**, with a typed error.
//!
//! Presence and safety are not the only two questions: **provenance** is the
//! third. `fs::create_dir` returns before the two `icacls` spawns have run, and
//! until they do the new `ScorpioSync` still carries the inherited
//! `Users:(CI)(WD,AD,WEA,WA)` — long enough for an unprivileged process to
//! create `ScorpioSync\state` inside it. The parent's `/T` then scrubs that
//! raced child clean, so by the time it is probed its ACL is indistinguishable
//! from one this code produced. Provisioning therefore remembers which levels it
//! created, and refuses a level that is *present* under a level it just created
//! — see [`ensure_impl`].
//!
//! The third case is deliberately *not* repaired. Re-ACLing a directory an
//! attacker pre-created does not evict them: a handle opened before the DACL
//! change keeps the access it was granted at open time, so a planted receipt
//! file can still be rewritten through that handle after the lockdown "succeeds"
//! — and any file already sitting there was written by that attacker. Silently
//! proceeding would produce a directory that *looks* hardened while still being
//! attacker-influenced, which is strictly worse than refusing: it converts a
//! visible failure into an invisible one. Removing the squatted tree is an
//! operator decision (it may be evidence), not something a CLI should do behind
//! the operator's back.
//!
//! Everything here **fails closed**: if the ACL state cannot be determined —
//! the probe errors, the path form is one this crate will not reason about, the
//! post-lockdown re-read disagrees — the answer is a refusal, never an
//! optimistic accept.
//!
//! ## What is reused rather than rebuilt
//!
//! * the DACL reader is P1/SEC-2's [`crate::service::Win32PathSecurityProbe`]
//!   (`GetNamedSecurityInfoW`), injected through [`PathSecurityProbe`];
//! * the administrative-principal allowlist is
//!   [`crate::service::is_administrative_sid`];
//! * the `icacls` argv, the ordering (`/setowner` **before** `/grant:r`) and the
//!   elevation gate are [`ssk_netd_helper::store`]'s, unchanged — this module
//!   adds the verification layer in front of them and gives them their first
//!   production caller.
//!
//! ## Ancestors are audited, never provisioned
//!
//! `C:\` and `C:\ProgramData` belong to Windows; this code must not touch their
//! ACLs. They are still audited, because a non-administrative principal holding
//! `FILE_DELETE_CHILD`/`DELETE`/`WRITE_DAC`/`WRITE_OWNER` over `ProgramData`
//! could delete `ScorpioSync` and recreate it as a squat. That is exactly
//! [`ComponentKind::Ancestor`]'s policy from SEC-2, so it is reused verbatim —
//! including its deliberate tolerance of `Users:(RX)` and the `(AD)` ACE on
//! `C:\`, which are present on every stock Windows 11 install and are not
//! re-point primitives.

use std::fs;
use std::path::{Path, PathBuf};

use ssk_netd_helper::store::{AclRunner, Elevation, FileReceiptStore};

#[cfg(not(windows))]
use crate::service::ImagePathRefusal;
use crate::service::{
    audit_component, describe_rights, is_administrative_sid, ComponentKind, PathSecurity,
    PathSecurityProbe, ProbeError,
};

/// The operation name carried by [`StateDirRefusal::NotElevated`]. Kept
/// identical to the string `ssk_netd_helper::store` uses so the two layers
/// report the same precondition, not two differently-worded ones.
pub const PROVISION_OPERATION: &str = "provisioning the ProgramData state store";

/// The access-mask bits that disqualify a non-administrative principal from
/// appearing in the state directory's DACL.
///
/// Identical to [`ComponentKind::Directory`]'s mask: this directory holds the
/// rollback receipts that drive an elevated `netsh delete rule`, so *adding* a
/// file to it is as dangerous as deleting one — planting a receipt is the whole
/// attack. Read and traverse rights are not included; a correctly provisioned
/// directory has no non-administrative ACE at all, so this only decides how a
/// wrong one is described.
pub const STATE_DIR_DANGEROUS_MASK: u32 = ComponentKind::Directory.dangerous_mask();

/// Why a state directory was refused. Every variant is a *refusal to proceed*;
/// none of them is recoverable by retrying.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateDirRefusal {
    /// The path is not an absolute, drive-rooted path with no `.`/`..`.
    PathForm { path: String, detail: String },
    /// The requested layout does not decompose into ancestors + owned levels.
    LayoutInvalid { detail: String },
    /// The directory is absent and creating it is a system mutation, which this
    /// process cannot be shown to be entitled to perform. Nothing was created.
    NotElevated {
        operation: &'static str,
        observed: Elevation,
    },
    /// The security of a component could not be read. Fail closed.
    ProbeFailed { path: String, reason: String },
    /// The path exists but is not a directory.
    NotADirectory { path: String },
    /// A component is a symlink or directory junction, i.e. re-pointable.
    ReparsePoint { path: String },
    /// The directory is owned by a non-administrative principal, which therefore
    /// holds implicit `WRITE_DAC` over it. **This is the squat case.**
    OwnerNotAdministrative { path: String, owner: String },
    /// The directory has a NULL DACL — unrestricted access for everyone.
    NullDacl { path: String },
    /// The directory grants a non-administrative principal a dangerous right.
    /// **This is the inherited-`Users:Write` case.**
    WritableByNonAdmin {
        path: String,
        principal: String,
        rights: String,
    },
    /// The DACL contains an ACE type this walker does not evaluate.
    UnsupportedAce { path: String, ace_type: u8 },
    /// An ancestor Windows owns (`C:\`, `%ProgramData%`) is itself unsafe.
    AncestorUnsafe { path: String, detail: String },
    /// A level of the owned chain exists that this invocation did not create,
    /// although it must have. Two shapes reach this:
    ///
    /// * `fs::create_dir` returned `AlreadyExists` — something appeared between
    ///   the probe that said "absent" and the create;
    /// * a level is *present* inside a level this invocation just created, which
    ///   was empty when `fs::create_dir` returned, so another process put it
    ///   there during the `icacls` window.
    ///
    /// The second shape can carry a perfectly clean ACL, because the parent's
    /// `icacls … /T` scrubs it — see [`ensure_impl`]. Both are treated as a
    /// squat, because that is what they are: a directory another principal
    /// created.
    RacedDuringCreate { path: String },
    /// The directory could not be created.
    CreateFailed { path: String, reason: String },
    /// Ownership or the DACL could not be applied.
    LockdownFailed { path: String, reason: String },
    /// The lockdown reported success but re-reading the ACL does not show a
    /// protected directory. Fail closed rather than trust the exit code.
    LockdownNotObserved { path: String, detail: String },
}

impl StateDirRefusal {
    /// A stable machine-readable code for the CLI/IPC surface.
    ///
    /// `NOT_ELEVATED` is intentionally the same string
    /// [`ssk_netd_helper::HelperError::code`] emits, so an operator sees one
    /// code for one precondition regardless of which layer refused.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            StateDirRefusal::PathForm { .. } | StateDirRefusal::LayoutInvalid { .. } => {
                "STATE_DIR_PATH_INVALID"
            }
            StateDirRefusal::NotElevated { .. } => "NOT_ELEVATED",
            StateDirRefusal::ProbeFailed { .. } => "STATE_DIR_UNVERIFIABLE",
            StateDirRefusal::NotADirectory { .. }
            | StateDirRefusal::ReparsePoint { .. }
            | StateDirRefusal::OwnerNotAdministrative { .. }
            | StateDirRefusal::NullDacl { .. }
            | StateDirRefusal::WritableByNonAdmin { .. }
            | StateDirRefusal::UnsupportedAce { .. }
            | StateDirRefusal::RacedDuringCreate { .. } => "STATE_DIR_UNSAFE",
            StateDirRefusal::AncestorUnsafe { .. } => "STATE_DIR_ANCESTOR_UNSAFE",
            StateDirRefusal::CreateFailed { .. }
            | StateDirRefusal::LockdownFailed { .. }
            | StateDirRefusal::LockdownNotObserved { .. } => "STATE_DIR_PROVISION_FAILED",
        }
    }

    /// True when the refusal says *another principal already controls this
    /// directory* — the case an operator must resolve by hand, because this
    /// code will not repair it (see the module header).
    #[must_use]
    pub fn is_squat(&self) -> bool {
        matches!(
            self,
            StateDirRefusal::NotADirectory { .. }
                | StateDirRefusal::ReparsePoint { .. }
                | StateDirRefusal::OwnerNotAdministrative { .. }
                | StateDirRefusal::NullDacl { .. }
                | StateDirRefusal::WritableByNonAdmin { .. }
                | StateDirRefusal::RacedDuringCreate { .. }
        )
    }

    /// The directory this refusal is about, when it names one.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        match self {
            StateDirRefusal::PathForm { path, .. }
            | StateDirRefusal::ProbeFailed { path, .. }
            | StateDirRefusal::NotADirectory { path }
            | StateDirRefusal::ReparsePoint { path }
            | StateDirRefusal::OwnerNotAdministrative { path, .. }
            | StateDirRefusal::NullDacl { path }
            | StateDirRefusal::WritableByNonAdmin { path, .. }
            | StateDirRefusal::UnsupportedAce { path, .. }
            | StateDirRefusal::AncestorUnsafe { path, .. }
            | StateDirRefusal::RacedDuringCreate { path }
            | StateDirRefusal::CreateFailed { path, .. }
            | StateDirRefusal::LockdownFailed { path, .. }
            | StateDirRefusal::LockdownNotObserved { path, .. } => Some(path),
            StateDirRefusal::LayoutInvalid { .. } | StateDirRefusal::NotElevated { .. } => None,
        }
    }
}

impl std::fmt::Display for StateDirRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateDirRefusal::PathForm { path, detail } => {
                write!(f, "'{path}' is not a usable state directory path: {detail}")
            }
            StateDirRefusal::LayoutInvalid { detail } => {
                write!(f, "invalid state directory layout: {detail}")
            }
            StateDirRefusal::NotElevated {
                operation,
                observed,
            } => write!(
                f,
                "{operation} requires an elevated (Administrator) process (observed: \
                 {observed:?}); nothing was created"
            ),
            StateDirRefusal::ProbeFailed { path, reason } => write!(
                f,
                "the security of '{path}' could not be read ({reason}), so it cannot be shown to \
                 be safe"
            ),
            StateDirRefusal::NotADirectory { path } => {
                write!(f, "'{path}' exists but is not a directory")
            }
            StateDirRefusal::ReparsePoint { path } => write!(
                f,
                "'{path}' is a symlink or directory junction, so it can be re-pointed at \
                 attacker-controlled content after this check"
            ),
            StateDirRefusal::OwnerNotAdministrative { path, owner } => write!(
                f,
                "'{path}' already exists and is owned by {owner}, which is not SYSTEM, \
                 Administrators or TrustedInstaller; an owner holds implicit WRITE_DAC, so this \
                 directory is under another principal's control and its contents cannot be trusted"
            ),
            StateDirRefusal::NullDacl { path } => write!(
                f,
                "'{path}' has a NULL DACL, which grants everyone full control"
            ),
            StateDirRefusal::WritableByNonAdmin {
                path,
                principal,
                rights,
            } => write!(
                f,
                "'{path}' grants {principal} the rights {rights}; {principal} is not an \
                 administrative principal, so any process running as it could plant or rewrite a \
                 rollback receipt"
            ),
            StateDirRefusal::UnsupportedAce { path, ace_type } => write!(
                f,
                "'{path}' has an ACE of type {ace_type}, whose semantics this check does not \
                 evaluate"
            ),
            StateDirRefusal::AncestorUnsafe { path, detail } => write!(
                f,
                "the ancestor directory '{path}' is not safe to build a privileged state \
                 directory under: {detail}"
            ),
            StateDirRefusal::RacedDuringCreate { path } => write!(
                f,
                "'{path}' did not exist a moment ago and does now, but this process did not \
                 create it; some other process did, so it is not this process's directory and \
                 will not be adopted — however its ACL now reads"
            ),
            StateDirRefusal::CreateFailed { path, reason } => {
                write!(f, "cannot create '{path}': {reason}")
            }
            StateDirRefusal::LockdownFailed { path, reason } => {
                write!(f, "cannot lock down '{path}': {reason}")
            }
            StateDirRefusal::LockdownNotObserved { path, detail } => write!(
                f,
                "'{path}' was created and locked down, but re-reading its ACL does not show a \
                 protected directory ({detail}); refusing to use it"
            ),
        }
    }
}

impl std::error::Error for StateDirRefusal {}

/// What a read-only verification found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateDirStatus {
    /// The directory does not exist. For a *reading* verb this is not an error —
    /// it means nothing was ever persisted — and for a *writing* verb it is the
    /// signal to provision.
    Absent,
    /// The directory exists, is administratively owned, and grants no
    /// non-administrative principal a dangerous right.
    Protected,
}

/// The directory chain a state directory implies, split into the part this
/// product creates and owns and the pre-existing OS directories above it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDirLayout {
    owned: Vec<PathBuf>,
    ancestors: Vec<PathBuf>,
}

impl StateDirLayout {
    /// Decompose `leaf` into `owned_levels` trailing directories this product
    /// creates, plus the ancestors above them.
    ///
    /// Both parts are ordered **outermost first**, because provisioning must
    /// lock the parent before the child: an attacker owning
    /// `…\ScorpioSync` can delete and recreate `…\ScorpioSync\state` no matter
    /// how tightly the leaf itself is ACL'd.
    ///
    /// # Errors
    /// [`StateDirRefusal::PathForm`] for a path shape this crate will not reason
    /// about (relative, `.`/`..`, UNC, `\\?\`, `\\.\`), or
    /// [`StateDirRefusal::LayoutInvalid`] if `owned_levels` does not leave at
    /// least one ancestor.
    pub fn new(leaf: &Path, owned_levels: usize) -> Result<Self, StateDirRefusal> {
        // On Windows the exact path grammar SEC-2 enforces applies here too, so
        // the two gates cannot diverge. Off-Windows `std::path` uses POSIX
        // rules and that grammar would reject every valid path, so the check
        // narrows to "absolute".
        #[cfg(windows)]
        crate::service::reject_unsupported_path_form(leaf).map_err(|refusal| {
            StateDirRefusal::PathForm {
                path: leaf.display().to_string(),
                detail: refusal.to_string(),
            }
        })?;
        #[cfg(not(windows))]
        if !leaf.is_absolute() {
            return Err(StateDirRefusal::PathForm {
                path: leaf.display().to_string(),
                detail: ImagePathRefusal::NotAbsolute.to_string(),
            });
        }

        let mut chain: Vec<PathBuf> = leaf.ancestors().map(Path::to_path_buf).collect();
        chain.reverse(); // outermost (volume root) first
        if owned_levels == 0 || owned_levels >= chain.len() {
            return Err(StateDirRefusal::LayoutInvalid {
                detail: format!(
                    "{} owned level(s) requested for '{}', which decomposes into {} component(s); \
                     at least one ancestor must remain unowned",
                    owned_levels,
                    leaf.display(),
                    chain.len()
                ),
            });
        }
        let split = chain.len() - owned_levels;
        let owned = chain.split_off(split);
        Ok(StateDirLayout {
            owned,
            ancestors: chain,
        })
    }

    /// The default layout: `%ProgramData%\ScorpioSync\state`, owning both
    /// `ScorpioSync` and `state`.
    ///
    /// Derived from [`ssk_netd_helper::store::default_provision_chain`] rather
    /// than re-spelled here, so the CLI, the broker and this gate cannot drift
    /// onto different directories.
    ///
    /// # Errors
    /// As [`StateDirLayout::new`].
    pub fn default_program_data() -> Result<Self, StateDirRefusal> {
        let chain = ssk_netd_helper::store::default_provision_chain();
        let owned_levels = chain.len();
        let leaf = chain
            .last()
            .ok_or_else(|| StateDirRefusal::LayoutInvalid {
                detail: "the default provision chain is empty".to_owned(),
            })?
            .clone();
        Self::new(&leaf, owned_levels)
    }

    /// The state directory itself.
    #[must_use]
    pub fn leaf(&self) -> &Path {
        // `new` rejects an empty owned list, so this cannot be empty.
        self.owned
            .last()
            .map_or_else(|| Path::new(""), PathBuf::as_path)
    }

    /// Directories this product creates and locks down, outermost first.
    #[must_use]
    pub fn owned(&self) -> &[PathBuf] {
        &self.owned
    }

    /// Pre-existing OS directories above them, outermost first. Audited, never
    /// modified.
    #[must_use]
    pub fn ancestors(&self) -> &[PathBuf] {
        &self.ancestors
    }
}

/// Audit one directory this product owns, against an already-probed security
/// descriptor.
///
/// Stricter than [`audit_component`] in exactly one way, and the difference is
/// load-bearing: **inherit-only ACEs are not skipped.** For a service *image*
/// directory an `INHERIT_ONLY` ACE grants nothing on the directory itself, so
/// SEC-2 ignores it. Here the objects that matter are the receipt *files* inside
/// the directory, and an inherit-only ACE is precisely what decides their DACL —
/// `C:\ProgramData`'s `CREATOR OWNER:(OI)(CI)(IO)(F)` is exactly that shape.
/// Ignoring it would let a directory pass while every file created in it is
/// attacker-writable.
///
/// A consequence worth stating: this refuses OS directories that are perfectly
/// safe in their own context. `%SystemRoot%\System32` carries the same
/// `CREATOR OWNER:(OI)(CI)(IO)(F)` ACE (measured on this box) and is refused by
/// this predicate, correctly — only administrators can create files there, so
/// the placeholder can only ever materialise as an administrator, but nothing in
/// a DACL walk can establish that. It costs nothing: `icacls /inheritance:r`
/// strips every inherited ACE, so a directory this module provisioned has
/// exactly two ACEs and no `CREATOR OWNER` at all. The predicate is applied only
/// to directories this product owns, never to OS directories — those go through
/// [`ComponentKind::Ancestor`], which does skip inherit-only ACEs.
///
/// # Errors
/// The specific [`StateDirRefusal`] that disqualified the directory.
pub fn audit_owned_directory(path: &Path, security: &PathSecurity) -> Result<(), StateDirRefusal> {
    let name = path.display().to_string();

    if security.is_reparse_point {
        return Err(StateDirRefusal::ReparsePoint { path: name });
    }
    if !is_administrative_sid(&security.owner_sid) {
        return Err(StateDirRefusal::OwnerNotAdministrative {
            path: name,
            owner: security.owner_sid.clone(),
        });
    }
    let Some(aces) = security.aces.as_ref() else {
        return Err(StateDirRefusal::NullDacl { path: name });
    };

    for ace in aces {
        match ace.ace_type {
            // Denies can only subtract access; ignoring them can only make this
            // gate stricter, never more permissive.
            crate::service::acl::ACCESS_DENIED_ACE_TYPE => continue,
            crate::service::acl::ACCESS_ALLOWED_ACE_TYPE => {}
            other => {
                return Err(StateDirRefusal::UnsupportedAce {
                    path: name,
                    ace_type: other,
                })
            }
        }
        if is_administrative_sid(&ace.sid) {
            continue;
        }
        let granted = ace.mask & STATE_DIR_DANGEROUS_MASK;
        if granted != 0 {
            return Err(StateDirRefusal::WritableByNonAdmin {
                path: name.clone(),
                principal: ace.sid.clone(),
                rights: describe_rights(granted),
            });
        }
    }
    Ok(())
}

/// How the `icacls` step is performed. The default arm is the real
/// `%SystemRoot%\System32\icacls.exe` on Windows (and a documented no-op
/// elsewhere); the injected arm is what the tests drive.
enum AclStep<'a> {
    /// Only reachable on Windows: off-Windows there is no DACL to read back, so
    /// [`ensure_state_dir`] does not run the create-or-verify machine at all and
    /// this variant would be dead code rather than an inert one.
    #[cfg(windows)]
    Default,
    Injected(&'a dyn AclRunner),
}

impl AclStep<'_> {
    /// Take ownership and apply the DACL, through
    /// [`ssk_netd_helper::store::FileReceiptStore`] — the P1 code, unchanged.
    /// The returned store handle is discarded: this module provisions the
    /// directory, it does not own the snapshot format.
    fn lock_down(&self, dir: &Path, elevation: Elevation) -> Result<(), StateDirRefusal> {
        let outcome = match self {
            #[cfg(windows)]
            AclStep::Default => FileReceiptStore::provision(dir, elevation).map(|_| ()),
            AclStep::Injected(acl) => {
                FileReceiptStore::provision_with(dir, elevation, *acl).map(|_| ())
            }
        };
        outcome.map_err(|e| StateDirRefusal::LockdownFailed {
            path: dir.display().to_string(),
            reason: e.to_string(),
        })
    }
}

fn probe_failed(path: &Path, err: &ProbeError) -> StateDirRefusal {
    StateDirRefusal::ProbeFailed {
        path: path.display().to_string(),
        reason: err.to_string(),
    }
}

/// Audit the ancestors Windows owns. They are never created and never modified.
fn audit_ancestors(
    layout: &StateDirLayout,
    probe: &dyn PathSecurityProbe,
) -> Result<(), StateDirRefusal> {
    for ancestor in layout.ancestors() {
        let security = probe
            .inspect(ancestor)
            .map_err(|e| probe_failed(ancestor, &e))?;
        audit_component(ComponentKind::Ancestor, ancestor, &security).map_err(|refusal| {
            StateDirRefusal::AncestorUnsafe {
                path: ancestor.display().to_string(),
                detail: refusal.to_string(),
            }
        })?;
    }
    Ok(())
}

/// Read-only: report whether the state directory is absent or protected, and
/// refuse if it is present but unsafe.
///
/// Creates nothing, changes nothing, needs no elevation. This is what the
/// **reading** verbs (`release`, `status`, `recover`) must call before they
/// treat anything in the directory as input: a receipt loaded out of a squatted
/// directory is the SEC-1 hole with a different path.
///
/// [`StateDirStatus::Absent`] is returned only when the leaf is absent *and*
/// every present component above it passed. An unreadable component is a
/// refusal, not an "absent".
///
/// # Errors
/// The first [`StateDirRefusal`] encountered, ancestors first, then the owned
/// chain outermost-first.
pub fn verify_state_dir_with(
    layout: &StateDirLayout,
    probe: &dyn PathSecurityProbe,
) -> Result<StateDirStatus, StateDirRefusal> {
    audit_ancestors(layout, probe)?;
    let mut status = StateDirStatus::Protected;
    for dir in layout.owned() {
        match probe.inspect(dir) {
            Ok(security) => {
                if status == StateDirStatus::Absent {
                    // A child exists under a parent that does not. Not
                    // reachable through a normal filesystem, so refuse rather
                    // than invent an interpretation.
                    return Err(StateDirRefusal::ProbeFailed {
                        path: dir.display().to_string(),
                        reason: "it exists although its parent does not".to_owned(),
                    });
                }
                if !dir.is_dir() {
                    return Err(StateDirRefusal::NotADirectory {
                        path: dir.display().to_string(),
                    });
                }
                audit_owned_directory(dir, &security)?;
            }
            Err(ProbeError::NotFound) => status = StateDirStatus::Absent,
            Err(e) => return Err(probe_failed(dir, &e)),
        }
    }
    Ok(status)
}

/// Create-or-verify the state directory, with the ACL tool and the security
/// probe injected.
///
/// Returns the leaf directory on success. Three cases, handled explicitly:
///
/// * present and safe → accepted, no mutation, **no elevation required** (so an
///   unelevated read-only verb can still use an already-provisioned store);
/// * absent → refused with [`StateDirRefusal::NotElevated`] unless `elevation`
///   is [`Elevation::Elevated`], and otherwise created, owned by
///   `BUILTIN\Administrators`, inheritance broken, granted only SYSTEM +
///   Administrators, and then **re-read and re-audited**;
/// * present and unsafe → refused. Never repaired — see the module header.
///
/// The elevation gate is checked **before** anything is created, so a
/// non-elevated invocation cannot leave a weakly-ACL'd directory behind for a
/// later elevated run to accept. That closes the obvious downgrade: without it,
/// step one of an attack is "run the unprivileged CLI once".
///
/// A level found *present* inside a level **this invocation just created** is
/// refused as [`StateDirRefusal::RacedDuringCreate`] — see [`ensure_impl`] for
/// why an ACL check cannot decide that case.
///
/// # Errors
/// The first [`StateDirRefusal`] encountered.
pub fn ensure_state_dir_with(
    layout: &StateDirLayout,
    elevation: Elevation,
    probe: &dyn PathSecurityProbe,
    acl: &dyn AclRunner,
) -> Result<PathBuf, StateDirRefusal> {
    ensure_impl(layout, elevation, probe, &AclStep::Injected(acl))
}

/// # Provenance, not just ACLs
///
/// The ACL audit alone cannot carry this gate, because there is a window in
/// which a raced directory ends up with a *passing* ACL. `fs::create_dir`
/// returns as soon as `…\ScorpioSync` exists, but the two `icacls` spawns that
/// take ownership and break inheritance have not run yet — until they finish,
/// the new directory still carries `%ProgramData%`'s inherited
/// `Users:(CI)(WD,AD,WEA,WA)`, so an unprivileged process spinning on the path
/// can create `…\ScorpioSync\state` inside it. Both `icacls` steps are issued
/// with `/T`, so the parent's lockdown then walks into that raced child and
/// scrubs it: administratively owned, inheritance broken, no non-administrative
/// ACE. Probing it afterwards is indistinguishable from probing one we created.
///
/// So this function tracks which levels it created, and treats *presence* under
/// a level it just created as the refusal. A directory we created was empty at
/// the instant `fs::create_dir` returned; anything inside it came from another
/// process. "We created it" and "it appeared and we cleaned it" are different
/// facts, and only the first one is a directory this process may adopt.
///
/// The consequence of the raced case was already bounded — the squatter cannot
/// keep write access through the `/T`, so the worst outcome is the
/// denial-of-rollback the module header documents — but adopting a directory
/// another principal created is exactly what this module exists to refuse.
fn ensure_impl(
    layout: &StateDirLayout,
    elevation: Elevation,
    probe: &dyn PathSecurityProbe,
    acl: &AclStep<'_>,
) -> Result<PathBuf, StateDirRefusal> {
    audit_ancestors(layout, probe)?;

    // The levels *this* invocation created, in order. `layout.owned()` is
    // outermost-first and strictly nested, so a present level whose parent is
    // in here appeared inside a directory that was empty moments ago.
    let mut created_here: Vec<&Path> = Vec::new();

    for dir in layout.owned() {
        match probe.inspect(dir) {
            Ok(security) => {
                if dir
                    .parent()
                    .is_some_and(|parent| created_here.contains(&parent))
                {
                    return Err(StateDirRefusal::RacedDuringCreate {
                        path: dir.display().to_string(),
                    });
                }
                if !dir.is_dir() {
                    return Err(StateDirRefusal::NotADirectory {
                        path: dir.display().to_string(),
                    });
                }
                audit_owned_directory(dir, &security)?;
            }
            Err(ProbeError::NotFound) => {
                // Checked before a single byte of state is touched.
                if !elevation.permits_system_mutation() {
                    return Err(StateDirRefusal::NotElevated {
                        operation: PROVISION_OPERATION,
                        observed: elevation,
                    });
                }
                create_and_lock_down(dir, elevation, probe, acl)?;
                created_here.push(dir.as_path());
            }
            Err(e) => return Err(probe_failed(dir, &e)),
        }
    }
    Ok(layout.leaf().to_path_buf())
}

/// Create `dir` as an atomic claim, lock it down, then verify the lockdown.
///
/// `create_dir` (not `create_dir_all`) is deliberate: it fails with
/// `AlreadyExists` if anything got there first, which turns the probe→create
/// TOCTOU window into a typed refusal instead of a silent adoption of someone
/// else's directory.
fn create_and_lock_down(
    dir: &Path,
    elevation: Elevation,
    probe: &dyn PathSecurityProbe,
    acl: &AclStep<'_>,
) -> Result<(), StateDirRefusal> {
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(StateDirRefusal::RacedDuringCreate {
                path: dir.display().to_string(),
            })
        }
        Err(e) => {
            return Err(StateDirRefusal::CreateFailed {
                path: dir.display().to_string(),
                reason: e.to_string(),
            })
        }
    }

    acl.lock_down(dir, elevation)?;

    // Do not trust icacls' exit code: re-read what the OS now reports. A
    // lockdown that "succeeded" but left the inherited `Users:Write` ACE in
    // place must not yield a usable directory.
    let security = probe.inspect(dir).map_err(|e| probe_failed(dir, &e))?;
    audit_owned_directory(dir, &security).map_err(|refusal| StateDirRefusal::LockdownNotObserved {
        path: dir.display().to_string(),
        detail: refusal.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Production entry points
// ---------------------------------------------------------------------------

/// The state directory path, `%ProgramData%\ScorpioSync\state`.
///
/// Delegates to [`ssk_netd_helper::store::default_state_dir`] so there is one
/// definition of this path in the workspace, not a copy per caller.
#[must_use]
pub fn default_state_dir() -> PathBuf {
    ssk_netd_helper::store::default_state_dir()
}

/// [`ensure_state_dir_with`] against the real Windows DACL reader and the real
/// `%SystemRoot%\System32\icacls.exe`.
///
/// # Errors
/// As [`ensure_state_dir_with`].
#[cfg(windows)]
pub fn ensure_state_dir(
    layout: &StateDirLayout,
    elevation: Elevation,
) -> Result<PathBuf, StateDirRefusal> {
    ensure_impl(
        layout,
        elevation,
        &crate::service::Win32PathSecurityProbe,
        &AclStep::Default,
    )
}

/// There are no Windows ACLs on this target, so there is nothing to verify and
/// nothing to lock down: this creates the directory and **claims no
/// protection**, exactly as `ssk-netd-helper`'s non-Windows path documents. The
/// elevation gate is not applied either — it exists to stop a weak *Windows*
/// DACL being established, and off-Windows POSIX permissions on the parent
/// govern instead.
///
/// # Errors
/// [`StateDirRefusal::CreateFailed`] if the directory cannot be created.
#[cfg(not(windows))]
pub fn ensure_state_dir(
    layout: &StateDirLayout,
    _elevation: Elevation,
) -> Result<PathBuf, StateDirRefusal> {
    let leaf = layout.leaf();
    fs::create_dir_all(leaf).map_err(|e| StateDirRefusal::CreateFailed {
        path: leaf.display().to_string(),
        reason: e.to_string(),
    })?;
    Ok(leaf.to_path_buf())
}

/// [`verify_state_dir_with`] against the real Windows DACL reader. Read-only.
///
/// # Errors
/// As [`verify_state_dir_with`].
#[cfg(windows)]
pub fn verify_state_dir(layout: &StateDirLayout) -> Result<StateDirStatus, StateDirRefusal> {
    verify_state_dir_with(layout, &crate::service::Win32PathSecurityProbe)
}

/// There are no Windows ACLs on this target, so verification can only report
/// presence. It never claims [`StateDirStatus::Protected`] on the strength of an
/// ACL it did not read — it reports presence, and the caller's own docs say what
/// that is worth off-Windows.
///
/// # Errors
/// Never on this target; the signature matches the Windows one so callers are
/// identical.
#[cfg(not(windows))]
pub fn verify_state_dir(layout: &StateDirLayout) -> Result<StateDirStatus, StateDirRefusal> {
    if layout.leaf().is_dir() {
        Ok(StateDirStatus::Protected)
    } else {
        Ok(StateDirStatus::Absent)
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;
    use crate::service::{acl, AceEntry};

    // ── Test doubles ────────────────────────────────────────────────────────

    /// A probe scripted per path, so the inheritance situations measured on the
    /// real box can be modelled without touching `C:\ProgramData`.
    #[derive(Default)]
    struct FakeProbe {
        answers: RefCell<BTreeMap<PathBuf, Result<PathSecurity, ProbeError>>>,
        /// Paths whose answer flips to `Ok(protected)` after a lockdown runs.
        relock: RefCell<BTreeMap<PathBuf, PathSecurity>>,
        seen: RefCell<Vec<PathBuf>>,
    }

    impl FakeProbe {
        fn set(&self, path: &Path, answer: Result<PathSecurity, ProbeError>) {
            self.answers.borrow_mut().insert(path.to_path_buf(), answer);
        }
        /// After the first `NotFound`, subsequent probes of `path` return
        /// `security` — modelling "the directory now exists".
        fn set_after_create(&self, path: &Path, security: PathSecurity) {
            self.relock
                .borrow_mut()
                .insert(path.to_path_buf(), security);
        }
        fn seen(&self) -> Vec<PathBuf> {
            self.seen.borrow().clone()
        }
    }

    impl PathSecurityProbe for FakeProbe {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            self.seen.borrow_mut().push(path.to_path_buf());
            if let Some(answer) = self.answers.borrow().get(path) {
                // A scripted NotFound is consumed once if a post-create answer
                // was registered, so create → re-probe sees the new state.
                if matches!(answer, Err(ProbeError::NotFound)) {
                    if let Some(after) = self.relock.borrow().get(path) {
                        if path.is_dir() {
                            return Ok(after.clone());
                        }
                    }
                }
                return answer.clone();
            }
            Err(ProbeError::NotFound)
        }
    }

    /// Records every argv and returns a scripted exit code.
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

    /// An ACL runner that loses the race it is spawned into.
    ///
    /// Models the real window precisely: `fs::create_dir(…\ScorpioSync)` has
    /// returned, the `icacls` spawns are in flight, and while they are the new
    /// directory still carries `%ProgramData%`'s inherited
    /// `Users:(CI)(WD,AD,WEA,WA)`. So an unprivileged process creates
    /// `…\ScorpioSync\state` inside it *during* the first step, and the parent's
    /// `/T` then scrubs that child's ACL clean — which is why the test scripts
    /// the probe to report it as `protected()`.
    struct RacingAcl {
        squat: PathBuf,
        calls: RefCell<Vec<Vec<String>>>,
    }

    impl RacingAcl {
        fn creating(squat: &Path) -> Self {
            RacingAcl {
                squat: squat.to_path_buf(),
                calls: RefCell::new(Vec::new()),
            }
        }
        fn count(&self) -> usize {
            self.calls.borrow().len()
        }
    }

    impl AclRunner for RacingAcl {
        fn run(&self, args: &[String]) -> Result<i32, String> {
            self.calls.borrow_mut().push(args.to_vec());
            // The squatter wins the window. Idempotent: it only has to succeed
            // once, and after that `AlreadyExists` is the expected outcome.
            let _ = fs::create_dir(&self.squat);
            Ok(0)
        }
    }

    // ── Security-descriptor fixtures, mirroring the measured real ones ──────

    fn protected() -> PathSecurity {
        PathSecurity {
            owner_sid: acl::SID_BUILTIN_ADMINISTRATORS.to_owned(),
            aces: Some(vec![
                AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL),
                AceEntry::allow(acl::SID_BUILTIN_ADMINISTRATORS, acl::GENERIC_ALL),
            ]),
            is_reparse_point: false,
        }
    }

    /// `C:\ProgramData` as measured on this machine, 2026-08-02:
    /// SYSTEM:(OI)(CI)F, Administrators:(OI)(CI)F, CREATOR OWNER:(OI)(CI)(IO)F,
    /// Users:(OI)(CI)(RX), Users:(CI)(WD,AD,WEA,WA).
    fn program_data_as_measured() -> PathSecurity {
        const CREATOR_OWNER: &str = "S-1-3-0";
        const USERS: &str = "S-1-5-32-545";
        const READ_EXECUTE: u32 = 0x0012_00A9;
        const WD_AD_WEA_WA: u32 = 0x0000_0002 | 0x0000_0004 | 0x0000_0010 | 0x0000_0100;
        PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.to_owned(),
            aces: Some(vec![
                AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL),
                AceEntry::allow(acl::SID_BUILTIN_ADMINISTRATORS, acl::GENERIC_ALL),
                AceEntry {
                    ace_type: acl::ACCESS_ALLOWED_ACE_TYPE,
                    flags: acl::INHERIT_ONLY_ACE,
                    mask: acl::GENERIC_ALL,
                    sid: CREATOR_OWNER.to_owned(),
                },
                AceEntry::allow(USERS, READ_EXECUTE),
                AceEntry::allow(USERS, WD_AD_WEA_WA),
            ]),
            is_reparse_point: false,
        }
    }

    /// What a squatted `ScorpioSync` looks like: created by an unprivileged
    /// user, who is therefore its owner.
    fn owned_by_a_user() -> PathSecurity {
        PathSecurity {
            owner_sid: "S-1-5-21-1111111111-2222222222-3333333333-1001".to_owned(),
            aces: Some(vec![AceEntry::allow(
                "S-1-5-21-1111111111-2222222222-3333333333-1001",
                acl::GENERIC_ALL,
            )]),
            is_reparse_point: false,
        }
    }

    /// Correct owner, but the inherited `Users:Write` ACE from ProgramData
    /// survived — the no-squat-needed case.
    fn inherited_users_write() -> PathSecurity {
        const USERS: &str = "S-1-5-32-545";
        PathSecurity {
            owner_sid: acl::SID_BUILTIN_ADMINISTRATORS.to_owned(),
            aces: Some(vec![
                AceEntry::allow(acl::SID_LOCAL_SYSTEM, acl::GENERIC_ALL),
                AceEntry::allow(acl::SID_BUILTIN_ADMINISTRATORS, acl::GENERIC_ALL),
                AceEntry::allow(USERS, acl::FILE_ADD_FILE),
            ]),
            is_reparse_point: false,
        }
    }

    /// Correct owner and no ACE that applies to the directory itself, but every
    /// file created inside inherits full control for a user. SEC-2's walker
    /// skips this; ours must not.
    fn inherit_only_user_full_control() -> PathSecurity {
        const USERS: &str = "S-1-5-32-545";
        PathSecurity {
            owner_sid: acl::SID_BUILTIN_ADMINISTRATORS.to_owned(),
            aces: Some(vec![
                AceEntry::allow(acl::SID_BUILTIN_ADMINISTRATORS, acl::GENERIC_ALL),
                AceEntry {
                    ace_type: acl::ACCESS_ALLOWED_ACE_TYPE,
                    flags: acl::INHERIT_ONLY_ACE,
                    mask: acl::GENERIC_ALL,
                    sid: USERS.to_owned(),
                },
            ]),
            is_reparse_point: false,
        }
    }

    fn null_dacl() -> PathSecurity {
        PathSecurity {
            owner_sid: acl::SID_BUILTIN_ADMINISTRATORS.to_owned(),
            aces: None,
            is_reparse_point: false,
        }
    }

    // A scratch layout under the system temp dir. `ProgramData` is deliberately
    // NOT touched by any test in this file.
    fn scratch_layout(root: &Path) -> (StateDirLayout, PathBuf, PathBuf) {
        let parent = root.join("ScorpioSync");
        let leaf = parent.join("state");
        let layout = StateDirLayout::new(&leaf, 2).expect("scratch layout");
        (layout, parent, leaf)
    }

    // ── Layout ──────────────────────────────────────────────────────────────

    #[test]
    fn the_layout_splits_owned_from_ancestors_outermost_first() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        assert_eq!(layout.owned().to_vec(), vec![parent.clone(), leaf.clone()]);
        assert_eq!(layout.leaf(), leaf.as_path());
        assert!(!layout.ancestors().is_empty());
        assert_eq!(
            layout.ancestors().last().map(PathBuf::as_path),
            parent.parent(),
            "the innermost ancestor is the owned chain's parent"
        );
        // Outermost first: each entry is a prefix of the next.
        let all: Vec<&Path> = layout
            .ancestors()
            .iter()
            .chain(layout.owned().iter())
            .map(PathBuf::as_path)
            .collect();
        for pair in all.windows(2) {
            assert!(
                pair[1].starts_with(pair[0]),
                "{pair:?} is not outermost-first"
            );
        }
    }

    #[test]
    fn a_layout_that_owns_everything_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("ScorpioSync").join("state");
        let depth = leaf.ancestors().count();
        for levels in [0usize, depth, depth + 1] {
            let err = StateDirLayout::new(&leaf, levels).unwrap_err();
            assert_eq!(err.code(), "STATE_DIR_PATH_INVALID", "{err}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_forms_this_crate_will_not_reason_about_are_refused() {
        // `\\?\C:\...` (`Prefix::VerbatimDisk`) is deliberately absent: SEC-2's
        // grammar accepts it as drive-rooted, and this gate reuses that grammar
        // verbatim so the two cannot diverge. `\\?\<name>` (`Prefix::Verbatim`)
        // and `\\.\<device>` are the forms that are refused.
        for bad in [
            r"ScorpioSync\state",
            r"C:\ProgramData\..\Users\Public\state",
            r"\\server\share\state",
            r"\\.\PIPE\state",
            r"C:ProgramData\state",
        ] {
            let err = StateDirLayout::new(Path::new(bad), 2)
                .expect_err(bad)
                .code();
            assert_eq!(err, "STATE_DIR_PATH_INVALID", "{bad}");
        }
    }

    // ── The predicate, against the measured ACLs ────────────────────────────

    #[test]
    fn a_correctly_locked_down_directory_is_accepted() {
        assert!(audit_owned_directory(Path::new("D:/state"), &protected()).is_ok());
    }

    #[test]
    fn a_directory_owned_by_a_user_is_refused_as_a_squat() {
        let err = audit_owned_directory(Path::new("D:/state"), &owned_by_a_user()).unwrap_err();
        assert!(matches!(
            err,
            StateDirRefusal::OwnerNotAdministrative { .. }
        ));
        assert!(err.is_squat());
        assert_eq!(err.code(), "STATE_DIR_UNSAFE");
    }

    #[test]
    fn an_inherited_users_write_ace_is_refused_even_with_the_right_owner() {
        let err =
            audit_owned_directory(Path::new("D:/state"), &inherited_users_write()).unwrap_err();
        match err {
            StateDirRefusal::WritableByNonAdmin {
                ref principal,
                ref rights,
                ..
            } => {
                assert_eq!(principal, "S-1-5-32-545");
                assert!(rights.contains("FILE_ADD_FILE"), "{rights}");
            }
            other => panic!("expected WritableByNonAdmin, got {other:?}"),
        }
        assert!(err.is_squat());
    }

    /// The difference from SEC-2's `audit_component`, asserted directly: an
    /// inherit-only ACE grants nothing on the directory but everything on the
    /// receipts inside it, so this walker must refuse where SEC-2's accepts.
    #[test]
    fn an_inherit_only_grant_to_a_user_is_refused_here_but_not_by_the_sec2_walker() {
        let security = inherit_only_user_full_control();
        assert!(
            audit_component(ComponentKind::Directory, Path::new("D:/state"), &security).is_ok(),
            "precondition: SEC-2's walker skips INHERIT_ONLY ACEs"
        );
        let err = audit_owned_directory(Path::new("D:/state"), &security).unwrap_err();
        assert!(
            matches!(err, StateDirRefusal::WritableByNonAdmin { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_null_dacl_is_refused() {
        let err = audit_owned_directory(Path::new("D:/state"), &null_dacl()).unwrap_err();
        assert!(matches!(err, StateDirRefusal::NullDacl { .. }));
        assert!(err.is_squat());
    }

    #[test]
    fn a_reparse_point_is_refused() {
        let mut security = protected();
        security.is_reparse_point = true;
        let err = audit_owned_directory(Path::new("D:/state"), &security).unwrap_err();
        assert!(matches!(err, StateDirRefusal::ReparsePoint { .. }));
    }

    #[test]
    fn an_ace_type_this_walker_does_not_evaluate_is_refused() {
        let mut security = protected();
        security.aces = Some(vec![AceEntry {
            ace_type: 0x09, // ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            flags: 0,
            mask: acl::GENERIC_ALL,
            sid: String::new(),
        }]);
        let err = audit_owned_directory(Path::new("D:/state"), &security).unwrap_err();
        assert!(matches!(
            err,
            StateDirRefusal::UnsupportedAce { ace_type: 0x09, .. }
        ));
    }

    #[test]
    fn a_deny_ace_for_a_user_does_not_disqualify_a_directory() {
        let mut security = protected();
        if let Some(aces) = security.aces.as_mut() {
            aces.push(AceEntry {
                ace_type: acl::ACCESS_DENIED_ACE_TYPE,
                flags: 0,
                mask: acl::GENERIC_ALL,
                sid: "S-1-5-32-545".to_owned(),
            });
        }
        assert!(audit_owned_directory(Path::new("D:/state"), &security).is_ok());
    }

    /// The real `C:\ProgramData` DACL must pass the *ancestor* policy — if it
    /// did not, every invocation on a stock Windows 11 box would refuse and the
    /// kill-switch would be unusable. This pins that, using the ACL measured on
    /// this hardware, without reading ProgramData at runtime.
    #[test]
    fn the_measured_program_data_acl_passes_the_ancestor_policy() {
        assert!(
            audit_component(
                ComponentKind::Ancestor,
                Path::new("C:/ProgramData"),
                &program_data_as_measured(),
            )
            .is_ok(),
            "the measured ProgramData ACL must not refuse the ancestor walk"
        );
    }

    /// ...and must NOT pass the owned policy. That asymmetry is the entire
    /// reason this module exists: `ProgramData` is safe to build under and
    /// unsafe to store receipts in.
    #[test]
    fn the_measured_program_data_acl_fails_the_owned_policy() {
        let err = audit_owned_directory(Path::new("C:/ProgramData"), &program_data_as_measured())
            .unwrap_err();
        assert!(
            matches!(err, StateDirRefusal::WritableByNonAdmin { .. }),
            "{err:?}"
        );
    }

    // ── verify: read-only, creates nothing ──────────────────────────────────

    #[test]
    fn verify_reports_absent_without_creating_anything() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        assert_eq!(
            verify_state_dir_with(&layout, &probe).unwrap(),
            StateDirStatus::Absent
        );
        assert!(
            !parent.exists() && !leaf.exists(),
            "verify must create nothing"
        );
    }

    #[test]
    fn verify_refuses_a_squatted_parent_and_never_looks_at_the_leaf() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        fs::create_dir_all(&leaf).unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(owned_by_a_user()));
        probe.set(&leaf, Ok(protected()));

        let err = verify_state_dir_with(&layout, &probe).unwrap_err();
        assert!(matches!(
            err,
            StateDirRefusal::OwnerNotAdministrative { .. }
        ));
        assert!(
            !probe.seen().contains(&leaf),
            "an unsafe parent must short-circuit before the leaf is trusted"
        );
    }

    #[test]
    fn verify_fails_closed_when_the_acl_cannot_be_read() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::Denied));
        let err = verify_state_dir_with(&layout, &probe).unwrap_err();
        assert_eq!(err.code(), "STATE_DIR_UNVERIFIABLE", "{err}");
        assert!(!err.is_squat());
    }

    #[test]
    fn verify_refuses_an_unsafe_ancestor() {
        let root = tempfile::tempdir().unwrap();
        let (layout, _parent, _leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for (i, a) in layout.ancestors().iter().enumerate() {
            if i == 0 {
                probe.set(a, Ok(owned_by_a_user()));
            } else {
                probe.set(a, Ok(program_data_as_measured()));
            }
        }
        let err = verify_state_dir_with(&layout, &probe).unwrap_err();
        assert_eq!(err.code(), "STATE_DIR_ANCESTOR_UNSAFE", "{err}");
    }

    #[test]
    fn verify_accepts_a_correctly_provisioned_chain() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        fs::create_dir_all(&leaf).unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(protected()));
        probe.set(&leaf, Ok(protected()));
        assert_eq!(
            verify_state_dir_with(&layout, &probe).unwrap(),
            StateDirStatus::Protected
        );
    }

    // ── ensure: the three cases ─────────────────────────────────────────────

    #[test]
    fn an_absent_directory_is_created_owned_and_locked_down_in_that_order() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));
        probe.set(&leaf, Err(ProbeError::NotFound));
        probe.set_after_create(&parent, protected());
        probe.set_after_create(&leaf, protected());

        let acl = ScriptedAcl::ok();
        let got = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap();
        assert_eq!(got, leaf);
        assert!(parent.is_dir() && leaf.is_dir());

        let calls = acl.calls.borrow();
        assert_eq!(calls.len(), 4, "setowner+lockdown for each of two levels");
        // Parent before leaf, and /setowner before /grant:r within each level.
        assert_eq!(calls[0], ssk_netd_helper::store::setowner_args(&parent));
        assert_eq!(calls[1], ssk_netd_helper::store::lockdown_args(&parent));
        assert_eq!(calls[2], ssk_netd_helper::store::setowner_args(&leaf));
        assert_eq!(calls[3], ssk_netd_helper::store::lockdown_args(&leaf));
    }

    #[test]
    fn an_unelevated_caller_cannot_create_the_directory_at_all() {
        for observed in [Elevation::NotElevated, Elevation::Unknown] {
            let root = tempfile::tempdir().unwrap();
            let (layout, parent, leaf) = scratch_layout(root.path());
            let probe = FakeProbe::default();
            for a in layout.ancestors() {
                probe.set(a, Ok(program_data_as_measured()));
            }
            probe.set(&parent, Err(ProbeError::NotFound));

            let acl = ScriptedAcl::ok();
            let err = ensure_state_dir_with(&layout, observed, &probe, &acl).unwrap_err();
            assert_eq!(
                err,
                StateDirRefusal::NotElevated {
                    operation: PROVISION_OPERATION,
                    observed,
                },
                "Unknown must fail closed exactly like NotElevated"
            );
            assert_eq!(err.code(), "NOT_ELEVATED");
            assert_eq!(acl.count(), 0, "no ACL tool was spawned");
            assert!(
                !parent.exists() && !leaf.exists(),
                "a non-elevated run must not leave a weakly-ACL'd directory behind"
            );
        }
    }

    #[test]
    fn an_already_protected_directory_is_accepted_without_elevation_or_mutation() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        fs::create_dir_all(&leaf).unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(protected()));
        probe.set(&leaf, Ok(protected()));

        let acl = ScriptedAcl::ok();
        let got = ensure_state_dir_with(&layout, Elevation::NotElevated, &probe, &acl).unwrap();
        assert_eq!(got, leaf);
        assert_eq!(acl.count(), 0, "an accepted directory is never re-ACL'd");
    }

    /// The whole point: a pre-existing directory with a planted file is a
    /// refusal, and the planted file is left exactly where it is.
    #[test]
    fn a_squatted_directory_with_a_planted_file_is_refused_and_not_repaired() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        fs::create_dir_all(&leaf).unwrap();
        let planted = leaf.join("killswitch-deadbeef.json");
        fs::write(&planted, b"{}").unwrap();

        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(protected()));
        probe.set(&leaf, Ok(owned_by_a_user()));

        let acl = ScriptedAcl::ok();
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert!(err.is_squat(), "{err:?}");
        assert_eq!(
            acl.count(),
            0,
            "a squat must never be silently re-ACL'd: an attacker's open handle survives it"
        );
        assert!(planted.is_file(), "evidence must be left in place");
    }

    #[test]
    fn a_directory_that_is_actually_a_file_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        fs::write(&parent, b"not a directory").unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(protected()));
        let acl = ScriptedAcl::ok();
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert!(
            matches!(err, StateDirRefusal::NotADirectory { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_failing_acl_step_yields_no_usable_directory() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));
        probe.set_after_create(&parent, protected());

        let acl = ScriptedAcl::failing(5);
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert_eq!(err.code(), "STATE_DIR_PROVISION_FAILED", "{err}");
        assert!(
            matches!(err, StateDirRefusal::LockdownFailed { .. }),
            "{err:?}"
        );
        assert_eq!(acl.count(), 1, "it stopped at the failing step");
    }

    /// icacls exiting 0 is not evidence. If the re-read still shows the
    /// inherited `Users:Write` ACE, the directory is refused.
    #[test]
    fn a_lockdown_that_did_not_take_is_refused_despite_a_zero_exit() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));
        probe.set_after_create(&parent, inherited_users_write());

        let acl = ScriptedAcl::ok();
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert!(
            matches!(err, StateDirRefusal::LockdownNotObserved { .. }),
            "{err:?}"
        );
        assert_eq!(err.code(), "STATE_DIR_PROVISION_FAILED");
    }

    /// The probe→create TOCTOU: the directory appears between the two. It must
    /// be refused, not adopted.
    #[test]
    fn a_directory_that_appears_between_the_probe_and_the_create_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        // Model the race: the probe is scripted NotFound while the directory
        // already exists on disk, so `create_dir` hits AlreadyExists.
        fs::create_dir_all(&parent).unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));

        let acl = ScriptedAcl::ok();
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert!(
            matches!(err, StateDirRefusal::RacedDuringCreate { .. }),
            "{err:?}"
        );
        assert!(err.is_squat());
        assert_eq!(acl.count(), 0, "nothing was ACL'd");
    }

    /// The create→lockdown race, which no ACL check can catch.
    ///
    /// The leaf appears inside the parent while the parent's `icacls` steps are
    /// still running, and the parent's `/T` then scrubs it — so the probe sees a
    /// *protected* leaf, exactly as it would for one we created. Only the fact
    /// that we did not create it separates the two, and that is what must be
    /// refused. Before this gate the raced leaf was silently adopted.
    #[test]
    fn a_level_that_appears_inside_a_level_we_just_created_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));
        probe.set_after_create(&parent, protected());
        // Scrubbed by the parent's `/T`: it passes `audit_owned_directory`.
        probe.set(&leaf, Ok(protected()));

        let acl = RacingAcl::creating(&leaf);
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();

        assert!(
            leaf.is_dir(),
            "precondition: the racing runner really created the leaf on disk"
        );
        assert!(
            audit_owned_directory(&leaf, &protected()).is_ok(),
            "precondition: the raced leaf's ACL is clean, so only provenance can refuse it"
        );
        assert!(
            matches!(err, StateDirRefusal::RacedDuringCreate { .. }),
            "{err:?}"
        );
        let leaf_str = leaf.display().to_string();
        assert_eq!(
            err.path(),
            Some(leaf_str.as_str()),
            "the refusal must name the raced level, not its parent"
        );
        assert!(err.is_squat());
        assert_eq!(err.code(), "STATE_DIR_UNSAFE");
        assert_eq!(
            acl.count(),
            2,
            "the parent was locked down; the raced leaf must never be ACL'd as ours"
        );
    }

    /// The counterpart, so the gate above is provenance and not "a present leaf
    /// under a fresh parent is always refused": when *we* create both levels the
    /// chain is accepted, and the leaf carries an identical descriptor.
    #[test]
    fn a_leaf_this_invocation_created_itself_is_accepted() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::NotFound));
        probe.set(&leaf, Err(ProbeError::NotFound));
        probe.set_after_create(&parent, protected());
        probe.set_after_create(&leaf, protected());

        let acl = ScriptedAcl::ok();
        assert_eq!(
            ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap(),
            leaf
        );
    }

    /// Provenance is required only where it can be established. A chain that was
    /// already there in full is accepted on its ACLs alone — this invocation
    /// created nothing, so it has no claim to make about who did.
    #[test]
    fn a_pre_existing_chain_is_not_treated_as_a_race() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, leaf) = scratch_layout(root.path());
        fs::create_dir_all(&leaf).unwrap();
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Ok(protected()));
        probe.set(&leaf, Ok(protected()));

        let acl = ScriptedAcl::ok();
        assert_eq!(
            ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap(),
            leaf
        );
        assert_eq!(acl.count(), 0);
    }

    #[test]
    fn an_unreadable_directory_is_refused_rather_than_assumed_absent() {
        let root = tempfile::tempdir().unwrap();
        let (layout, parent, _leaf) = scratch_layout(root.path());
        let probe = FakeProbe::default();
        for a in layout.ancestors() {
            probe.set(a, Ok(program_data_as_measured()));
        }
        probe.set(&parent, Err(ProbeError::Win32(1314)));
        let acl = ScriptedAcl::ok();
        let err = ensure_state_dir_with(&layout, Elevation::Elevated, &probe, &acl).unwrap_err();
        assert_eq!(err.code(), "STATE_DIR_UNVERIFIABLE", "{err}");
        assert_eq!(acl.count(), 0);
        assert!(!parent.exists(), "nothing was created");
    }

    // ── Cross-checks against the reused P1 code ─────────────────────────────

    /// [`PROVISION_OPERATION`] and [`StateDirRefusal::code`] both claim, in
    /// comments, to match what `ssk-netd-helper` emits for the same
    /// precondition. Both are copied string literals, so pin them: an operator
    /// must see one code and one operation name for one precondition, whichever
    /// layer refused. Driven through the broker's real API rather than compared
    /// against a re-spelled constant.
    #[test]
    fn the_elevation_refusal_matches_the_brokers_word_for_word() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("state");
        let acl = ScriptedAcl::ok();
        let broker = FileReceiptStore::provision_with(&dir, Elevation::NotElevated, &acl)
            .expect_err("an unelevated provision must be refused by the broker too");

        assert_eq!(broker.code(), "NOT_ELEVATED");
        assert_eq!(
            StateDirRefusal::NotElevated {
                operation: PROVISION_OPERATION,
                observed: Elevation::NotElevated,
            }
            .code(),
            broker.code(),
            "one precondition must not surface as two machine codes"
        );
        assert!(
            broker.to_string().starts_with(PROVISION_OPERATION),
            "PROVISION_OPERATION must be the broker's own operation name, got {broker}"
        );
        assert_eq!(acl.count(), 0, "nothing was spawned");
        assert!(!dir.exists(), "nothing was created");
    }

    #[test]
    fn the_lockdown_argv_still_grants_no_user_scoped_principal() {
        let joined = ssk_netd_helper::store::lockdown_args(Path::new("D:/state")).join(" ");
        for forbidden in [
            "%USERNAME%",
            "*S-1-5-11",     // Authenticated Users
            "*S-1-1-0",      // Everyone
            "*S-1-5-32-545", // BUILTIN\Users
            "*S-1-3-0",      // CREATOR OWNER
        ] {
            assert!(
                !joined.contains(forbidden),
                "the argv this module invokes must never contain {forbidden}: {joined}"
            );
        }
    }

    /// The principals the lockdown grants must be exactly the principals the
    /// audit accepts. If they ever diverge, provisioning would produce a
    /// directory its own verifier refuses — a permanent, silent outage.
    #[test]
    fn every_principal_the_lockdown_grants_is_one_the_audit_accepts() {
        for arg in ssk_netd_helper::store::lockdown_args(Path::new("D:/state")) {
            if let Some(rest) = arg.strip_prefix('*') {
                let sid = rest.split(':').next().unwrap_or_default();
                assert!(
                    is_administrative_sid(sid),
                    "lockdown grants {sid}, which audit_owned_directory would refuse"
                );
            }
        }
        let setowner = ssk_netd_helper::store::setowner_args(Path::new("D:/state"));
        let owner = setowner
            .iter()
            .find_map(|a| a.strip_prefix('*'))
            .expect("setowner names a SID");
        assert!(
            is_administrative_sid(owner),
            "setowner sets {owner}, which audit_owned_directory would refuse"
        );
    }

    // ── The REAL DACL reader, against real directories (unelevated) ─────────

    /// The predicate driven by `GetNamedSecurityInfoW`, not by a fixture. A
    /// directory an unprivileged process just created is owned by that user and
    /// must be refused.
    ///
    /// Scope of what this establishes, stated exactly: it exercises
    /// [`audit_owned_directory`] against a real security descriptor, in a scratch
    /// directory, without elevation and without touching `%ProgramData%`. It is
    /// **not** an end-to-end run. The CLI verbs are not involved, and this
    /// predicate has never been reached against a real
    /// `%ProgramData%\ScorpioSync` on the development machine, because that
    /// directory has deliberately never been allowed to exist there. Every
    /// state-directory refusal observed live through the CLI so far came from a
    /// gate that sits *in front* of this one — the ancestor walk
    /// ([`ComponentKind::Ancestor`], reused from SEC-2 and older than this
    /// module) and the elevation gate. Do not cite this test, or any CLI run, as
    /// evidence that the owned-directory predicate has fired in production.
    #[cfg(windows)]
    #[test]
    fn the_real_probe_refuses_a_directory_this_unprivileged_process_created() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("ScorpioSync");
        fs::create_dir(&dir).unwrap();

        let probe = crate::service::Win32PathSecurityProbe;
        let security = probe.inspect(&dir).expect("the real probe must read it");
        let err = audit_owned_directory(&dir, &security).expect_err(
            "a directory created by an unelevated process is owned by that user and must be \
             refused",
        );
        assert!(err.is_squat(), "{err}");
    }

    /// The user's own profile directory, read through the real descriptor. On
    /// this hardware it is *owned* by an administrative principal but grants the
    /// user `FILE_DELETE_CHILD|DELETE|WRITE_DAC|WRITE_OWNER` — so the refusal
    /// arrives through the DACL arm rather than the owner arm. The assertion is
    /// deliberately on `is_squat()` rather than on a specific variant: which arm
    /// fires is a property of the machine, that it is refused is the property of
    /// the policy.
    #[cfg(windows)]
    #[test]
    fn the_real_probe_refuses_the_user_profile_directory() {
        let Some(profile) = std::env::var_os("USERPROFILE") else {
            return;
        };
        let profile = PathBuf::from(profile);
        let probe = crate::service::Win32PathSecurityProbe;
        let security = probe
            .inspect(&profile)
            .expect("the real probe must read it");
        let err = audit_owned_directory(&profile, &security)
            .expect_err("the user profile is user-controlled and must be refused");
        assert!(err.is_squat(), "{err}");
    }

    /// Fail-closed on a path that does not exist: the real probe reports
    /// `NotFound`, which the orchestrator turns into "provision it", never into
    /// "accept it".
    #[cfg(windows)]
    #[test]
    fn the_real_probe_reports_not_found_rather_than_an_empty_descriptor() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("never-created");
        let probe = crate::service::Win32PathSecurityProbe;
        assert_eq!(probe.inspect(&missing), Err(ProbeError::NotFound));
    }

    #[test]
    fn the_default_layout_is_the_helpers_provision_chain() {
        let layout = StateDirLayout::default_program_data();
        let chain = ssk_netd_helper::store::default_provision_chain();
        match layout {
            Ok(layout) => {
                assert_eq!(layout.owned(), chain.as_slice());
                assert_eq!(layout.leaf(), default_state_dir());
            }
            // Off-Windows without `ProgramData` the default leaf is
            // `/var/lib/scorpiosync/state`, which is absolute and must parse.
            Err(e) => panic!("the default layout must be constructible: {e}"),
        }
    }
}
