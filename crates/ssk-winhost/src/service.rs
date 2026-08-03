//! Windows service lifecycle (service seam): a real
//! [`ssk_service_host::PrivilegedHelper`].
//!
//! Drives the Service Control Manager (SCM) through the `windows-service` crate.
//! The pure, platform-neutral logic (service-name derivation, Win32 error
//! classification, prior-state → rollback mapping) is factored out and
//! unit-tested on any host; the raw SCM layer is thin and `#[cfg(windows)]`.
//!
//! ## Exact rollback
//! `install` reports whether it *created* the service or found it *already
//! present*; that prior state rides in the [`ssk_service_host::InstallReceipt`].
//! `uninstall` honors it: a service we created is deleted; a service that
//! already existed is left in place (we never destroy what we did not create).
//!
//! ## Image-path safety gate (SEC-2)
//! The service is created with `account_name: None`, i.e. **LocalSystem**. Any
//! principal that can replace the image file — or plant a DLL beside it — then
//! obtains SYSTEM on the next service start. [`verify_image_path_protected`]
//! runs *before* `CreateServiceW` and refuses the install unless the image file,
//! its directory and **every** ancestor directory are owned by, and writable
//! only by, administrative principals. It fails **closed**: if the check cannot
//! be performed at all, the install is refused.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ssk_service_host::{
    HostManifest, InstallReceipt, PrivilegedHelper, ServiceError, ServiceState,
};
use ssk_types::Digest;

// ============================================================================
// Pure, platform-neutral layer (compiled everywhere — unit-tested on Linux)
// ============================================================================

/// Per `CreateServiceW`, a service name is limited to 256 characters.
pub const MAX_SERVICE_NAME_LEN: usize = 256;

/// Derive a deterministic, SCM-valid service name from a host id hex string:
/// `SSKHost_<first 16 hex chars, uppercased>`. A valid Windows service name must
/// not contain `/`, `\`, or spaces; keeping to `[0-9A-F_]` guarantees that.
#[must_use]
pub fn service_name_for(host_id_hex: &str) -> String {
    const PREFIX: &str = "SSKHost_";
    let cleaned: String = host_id_hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    format!("{PREFIX}{cleaned}")
}

/// True if `name` is a syntactically valid Windows service name.
#[must_use]
pub fn is_valid_service_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SERVICE_NAME_LEN
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains(' ')
}

/// Selected Win32 system error codes relevant to SCM lifecycle operations.
pub mod win32 {
    pub const ERROR_ACCESS_DENIED: i32 = 5;
    pub const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    pub const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
    pub const ERROR_SERVICE_EXISTS: i32 = 1073;
    pub const ERROR_SERVICE_ALREADY_RUNNING: i32 = 1056;
    pub const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;
    pub const ERROR_SERVICE_REQUEST_TIMEOUT: i32 = 1053;
}

/// Typed lifecycle error — classification is pure and testable off-Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinServiceError {
    /// Caller lacks Administrator rights (SCM returned ACCESS_DENIED).
    AccessDenied,
    /// The service does not exist.
    NotFound,
    /// A create was attempted but the service already exists.
    AlreadyExists,
    /// The service is marked for deletion; a fresh create must wait until the
    /// last open handle to the old instance is closed.
    MarkedForDeletion,
    /// The service was already in the requested run state.
    AlreadyInState,
    /// Waited for a state transition that did not complete in time.
    Timeout,
    /// This build target has no privileged SCM backend (non-Windows).
    Unsupported,
    /// **SEC-2.** The requested image path is not protected against
    /// modification by non-administrative principals, so registering it as a
    /// LocalSystem service would hand SYSTEM to whoever can rewrite it. The
    /// install is refused before any SCM call. Also produced when the check
    /// itself cannot be completed — this gate fails closed.
    UnsafeImagePath {
        path: String,
        refusal: ImagePathRefusal,
    },
    /// Any other Win32 failure, preserving the raw OS error code (if any).
    Winapi { code: Option<i32>, message: String },
    /// Non-winapi failure from the wrapper (e.g. an argument had a nul byte).
    Other(String),
}

impl std::fmt::Display for WinServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WinServiceError::AccessDenied => write!(f, "access denied (Administrator required)"),
            WinServiceError::NotFound => write!(f, "service does not exist"),
            WinServiceError::AlreadyExists => write!(f, "service already exists"),
            WinServiceError::MarkedForDeletion => write!(f, "service is marked for deletion"),
            WinServiceError::AlreadyInState => write!(f, "service already in requested state"),
            WinServiceError::Timeout => write!(f, "timed out waiting for state transition"),
            WinServiceError::Unsupported => {
                write!(
                    f,
                    "service lifecycle requires Windows (this build has no SCM backend)"
                )
            }
            WinServiceError::UnsafeImagePath { path, refusal } => {
                write!(
                    f,
                    "refusing to register a LocalSystem service for image path '{path}': \
                     {refusal}. A LocalSystem service runs as SYSTEM, so any principal that \
                     can replace that file — or plant a DLL next to it — gains SYSTEM on the \
                     next service start. Fix: from an elevated prompt, copy the service binary \
                     into a directory writable only by Administrators/SYSTEM (create one under \
                     %ProgramFiles%, e.g. \"C:\\Program Files\\ScorpioSync\\\") and pass that \
                     absolute path to --exe. Never install from the build tree, %TEMP%, \
                     %ProgramData%, a user profile, a newly created folder at the drive root, \
                     or a network share."
                )
            }
            WinServiceError::Winapi { code, message } => {
                write!(f, "winapi error {code:?}: {message}")
            }
            WinServiceError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for WinServiceError {}

/// Map a raw Win32 error code to a typed [`WinServiceError`]. Pure and testable.
#[must_use]
pub fn classify_os_error(code: Option<i32>, message: &str) -> WinServiceError {
    match code {
        Some(win32::ERROR_ACCESS_DENIED) => WinServiceError::AccessDenied,
        Some(win32::ERROR_SERVICE_DOES_NOT_EXIST) => WinServiceError::NotFound,
        Some(win32::ERROR_SERVICE_EXISTS) => WinServiceError::AlreadyExists,
        Some(win32::ERROR_SERVICE_MARKED_FOR_DELETE) => WinServiceError::MarkedForDeletion,
        Some(win32::ERROR_SERVICE_ALREADY_RUNNING | win32::ERROR_SERVICE_NOT_ACTIVE) => {
            WinServiceError::AlreadyInState
        }
        Some(win32::ERROR_SERVICE_REQUEST_TIMEOUT) => WinServiceError::Timeout,
        other => WinServiceError::Winapi {
            code: other,
            message: message.to_owned(),
        },
    }
}

/// Prior state observed by `install` before it acted, so uninstall is reversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorState {
    /// The service did not exist; `install` created it. Uninstall deletes it.
    CreatedFresh,
    /// The service already existed; `install` left it. Uninstall leaves it.
    AlreadyExisted,
}

impl PriorState {
    /// The [`ServiceState`] to record in the boundary's rollback receipt.
    /// `CreatedFresh` -> prior was `Uninstalled`; `AlreadyExisted` -> `Installed`.
    #[must_use]
    pub fn as_prior_service_state(self) -> ServiceState {
        match self {
            PriorState::CreatedFresh => ServiceState::Uninstalled,
            PriorState::AlreadyExisted => ServiceState::Installed,
        }
    }
}

// ============================================================================
// SEC-2 — image-path safety gate
//
// Pure policy over an injected security probe. The policy (which principals
// count as administrative, which access-mask bits are dangerous where, how the
// ancestor chain is walked, what happens when the probe fails) is ordinary Rust
// and is unit-tested on every host. Only [`acl_sys::Win32PathSecurityProbe`] —
// the thing that actually reads a Windows DACL — is `#[cfg(windows)]`.
//
// ## What this gate actually proves, and what it does not
//
// **Proves:** for the image file, its directory, and every ancestor directory
// up to the volume root — the owner is `LocalSystem`, `BUILTIN\Administrators`
// or `NT SERVICE\TrustedInstaller`, and no *effective* `ACCESS_ALLOWED` ACE
// grants a non-administrative principal a right that would let it replace the
// image or plant a DLL beside it.
//
// **Residual gaps — documented, not hidden:**
//
// 1. **No Authenticode / signature check.** A binary that lives in a protected
//    directory is still whatever an administrator put there. Signature
//    verification is P6 work (`docs/WINDOWS_PRODUCT_ROADMAP.md` §P6).
// 2. **TOCTOU.** The DACL is read at install time. It can be changed
//    afterwards — but only by a principal this check has just established is
//    administrative, and an administrator can register a service directly
//    anyway, so this does not widen the attacker set.
// 3. **This is a DACL walk, not `AccessCheck`.** Group nesting is not resolved:
//    a custom group SID whose only members are administrators is treated as
//    non-administrative, and so are domain groups such as Domain Admins
//    (`S-1-5-21-…-512`). That direction is a *refusal*, never an acceptance.
// 4. **`ACCESS_DENIED` ACEs are ignored.** Denies can only subtract access, so
//    ignoring them can only make the gate stricter than reality.
// 5. **Any ACE type other than allow/deny is a refusal.** Callback/conditional
//    and object ACEs carry semantics this walker does not evaluate, so it
//    refuses rather than guess. On a normal filesystem DACL they do not occur.
// 6. **Reparse points.** Any component that is a symlink or a directory
//    junction is refused, because the SCM resolves the *literal* path at start
//    time and a re-pointable link is a swap primitive. Reparse tags that Rust's
//    `FileType::is_symlink` does not report (cloud placeholders, `AppExecLink`)
//    are not detected.
// 7. **The owner check is deliberately strict.** An object's owner holds
//    implicit `WRITE_DAC`, and a user account SID is *enabled* even in a
//    UAC-filtered token — so a directory owned by an administrator's own user
//    account (rather than by the `Administrators` group) is refused. That is
//    correct: an unelevated process of that user could rewrite the DACL.
// 8. **A protected-directory *name* check is not used as a gate.** "Is it under
//    Program Files" is a weak proxy — `%ProgramData%` subtrees inherit
//    `Users:(WD,AD)` and a folder created at `C:\` inherits
//    `Authenticated Users:(M)`, both of which are user-writable despite living
//    on a system volume. The real DACL walk subsumes it; `%ProgramFiles%`
//    survives only as guidance in the error message.
// ============================================================================

/// Windows ACL constants used by the image-path gate.
///
/// Restated locally rather than pulled from `windows-sys`: the crate's
/// `windows-sys` feature set covers `Win32_Foundation` / IP Helper / WinSock
/// only, and these are stable, documented values.
pub mod acl {
    /// `ACCESS_ALLOWED_ACE_TYPE`.
    pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    /// `ACCESS_DENIED_ACE_TYPE`.
    pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    /// `INHERIT_ONLY_ACE` — the ACE does not apply to the object itself.
    pub const INHERIT_ONLY_ACE: u8 = 0x08;

    /// `FILE_ADD_FILE` on a directory (== `FILE_WRITE_DATA` on a file).
    pub const FILE_ADD_FILE: u32 = 0x0000_0002;
    /// `FILE_ADD_SUBDIRECTORY` on a directory (== `FILE_APPEND_DATA` on a file).
    pub const FILE_ADD_SUBDIRECTORY: u32 = 0x0000_0004;
    /// `FILE_DELETE_CHILD` — delete an entry regardless of the entry's own DACL.
    pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    /// Standard `DELETE`.
    pub const DELETE: u32 = 0x0001_0000;
    /// Standard `WRITE_DAC` — rewrite the object's DACL.
    pub const WRITE_DAC: u32 = 0x0004_0000;
    /// Standard `WRITE_OWNER` — take ownership, then rewrite the DACL.
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    /// `GENERIC_ALL`.
    pub const GENERIC_ALL: u32 = 0x1000_0000;
    /// `GENERIC_WRITE`. For files this maps to `FILE_GENERIC_WRITE`, which does
    /// **not** include `FILE_DELETE_CHILD`, `DELETE` or `WRITE_DAC`.
    pub const GENERIC_WRITE: u32 = 0x4000_0000;

    /// `NT AUTHORITY\SYSTEM`.
    pub const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
    /// `BUILTIN\Administrators`.
    pub const SID_BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";
    /// `NT SERVICE\TrustedInstaller` — owner of `C:\`, `C:\Windows` and
    /// `C:\Program Files` on a stock Windows 11 install.
    pub const SID_TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
}

/// Which role a path plays in the image-path chain. The dangerous access-mask
/// set differs by role, and the difference is load-bearing — see
/// [`ComponentKind::dangerous_mask`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentKind {
    /// The service image file itself.
    Image,
    /// The directory directly containing the image file.
    Directory,
    /// Any directory above that, up to and including the volume root.
    Ancestor,
}

impl ComponentKind {
    /// The access-mask bits that make this component a replace-the-binary (or
    /// plant-a-DLL) primitive when granted to a non-administrative principal.
    ///
    /// The split matters. `C:\` on a stock Windows 11 grants
    /// `Authenticated Users:(AD)` — `FILE_ADD_SUBDIRECTORY` — directly on the
    /// root. That lets anyone create a *new* folder at `C:\`; it does **not**
    /// let them delete, rename or re-point `C:\Program Files`, which needs
    /// `FILE_DELETE_CHILD` / `DELETE` / `WRITE_DAC` / `WRITE_OWNER`. Treating
    /// add-file/add-subdirectory as dangerous on an *ancestor* would therefore
    /// refuse every path on the system volume, including the correct one.
    ///
    /// On the image file and its own directory the bar is higher: creating a
    /// file next to a service binary is DLL planting, which is an EoP on its
    /// own, so add-file/add-subdirectory *are* dangerous there.
    #[must_use]
    pub const fn dangerous_mask(self) -> u32 {
        // Rights that let a principal destroy or re-point an existing entry,
        // wherever it appears in the chain.
        const STRUCTURAL: u32 = acl::FILE_DELETE_CHILD
            | acl::DELETE
            | acl::WRITE_DAC
            | acl::WRITE_OWNER
            | acl::GENERIC_ALL;
        match self {
            ComponentKind::Image | ComponentKind::Directory => {
                STRUCTURAL | acl::FILE_ADD_FILE | acl::FILE_ADD_SUBDIRECTORY | acl::GENERIC_WRITE
            }
            ComponentKind::Ancestor => STRUCTURAL,
        }
    }
}

/// One access-control entry, reduced to what the policy needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceEntry {
    /// `AceHeader.AceType`.
    pub ace_type: u8,
    /// `AceHeader.AceFlags`.
    pub flags: u8,
    /// The `ACCESS_MASK`.
    pub mask: u32,
    /// The trustee SID in S-R-I-S string form. Empty for ACE types whose SID
    /// offset this walker does not decode (those are refused on type alone).
    pub sid: String,
}

impl AceEntry {
    /// An `ACCESS_ALLOWED` ACE with no inheritance flags.
    #[must_use]
    pub fn allow(sid: &str, mask: u32) -> Self {
        Self {
            ace_type: acl::ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask,
            sid: sid.to_owned(),
        }
    }
}

/// The security of one filesystem object, as observed by a
/// [`PathSecurityProbe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSecurity {
    /// Owner SID in string form.
    pub owner_sid: String,
    /// `None` means the object has a **NULL DACL** — everyone has full control.
    /// `Some(vec![])` means an empty DACL, which denies everyone.
    pub aces: Option<Vec<AceEntry>>,
    /// Whether the object is a symlink or a directory junction.
    pub is_reparse_point: bool,
}

/// Why a security probe could not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// The path does not exist.
    NotFound,
    /// The caller may not read this object's security descriptor.
    Denied,
    /// A Win32 call failed with this code.
    Win32(u32),
    /// The security descriptor was malformed or unreadable in a way the walker
    /// refuses to interpret.
    Invalid(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::NotFound => write!(f, "path does not exist"),
            ProbeError::Denied => write!(f, "access denied reading the security descriptor"),
            ProbeError::Win32(code) => write!(f, "Win32 error {code}"),
            ProbeError::Invalid(m) => write!(f, "unreadable security descriptor: {m}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Reads the owner and DACL of a filesystem object. Injected so the policy is
/// testable without touching a real ACL.
pub trait PathSecurityProbe {
    /// Read `path`'s owner SID, DACL and reparse-point status.
    fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError>;
}

/// Why an image path was refused for a LocalSystem service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePathRefusal {
    /// Not an absolute, drive-rooted path (relative paths, and any path with a
    /// `.` or `..` component, are refused — the SCM resolves the literal string
    /// against a working directory this process does not control).
    NotAbsolute,
    /// A UNC path. The image would be fetched from a remote host that this
    /// machine's ACLs say nothing about.
    UncPath,
    /// A path form this gate will not reason about (`\\?\<name>`, `\\.\<dev>`).
    UnsupportedPathForm,
    /// A component is a symlink or directory junction, i.e. re-pointable.
    ReparsePoint { component: String },
    /// The security of a component could not be read. Fail closed.
    ProbeFailed { component: String, reason: String },
    /// A component is owned by a non-administrative principal, which therefore
    /// holds implicit `WRITE_DAC` over it.
    OwnerNotAdministrative { component: String, owner: String },
    /// A component has a NULL DACL — unrestricted access for everyone.
    NullDacl { component: String },
    /// A component grants a non-administrative principal a dangerous right.
    WritableByNonAdmin {
        component: String,
        principal: String,
        rights: String,
    },
    /// A component's DACL contains an ACE type this walker does not evaluate.
    UnsupportedAce { component: String, ace_type: u8 },
}

impl std::fmt::Display for ImagePathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImagePathRefusal::NotAbsolute => write!(
                f,
                "the path is not absolute (an absolute drive-rooted path with no '.' or '..' \
                 component is required)"
            ),
            ImagePathRefusal::UncPath => write!(
                f,
                "the path is a UNC network path, whose contents this machine does not control"
            ),
            ImagePathRefusal::UnsupportedPathForm => write!(
                f,
                "the path uses a form this check will not reason about (\\\\?\\ or \\\\.\\)"
            ),
            ImagePathRefusal::ReparsePoint { component } => write!(
                f,
                "'{component}' is a symlink or directory junction, so it can be re-pointed at \
                 attacker-controlled content after this check"
            ),
            ImagePathRefusal::ProbeFailed { component, reason } => write!(
                f,
                "the security of '{component}' could not be read ({reason}), so the path cannot \
                 be shown to be safe"
            ),
            ImagePathRefusal::OwnerNotAdministrative { component, owner } => write!(
                f,
                "'{component}' is owned by {owner}, which is not SYSTEM, Administrators or \
                 TrustedInstaller; an owner holds implicit WRITE_DAC and can grant itself \
                 full control"
            ),
            ImagePathRefusal::NullDacl { component } => write!(
                f,
                "'{component}' has a NULL DACL, which grants everyone full control"
            ),
            ImagePathRefusal::WritableByNonAdmin {
                component,
                principal,
                rights,
            } => write!(
                f,
                "'{component}' grants {principal} the rights {rights}, and {principal} is not an \
                 administrative principal"
            ),
            ImagePathRefusal::UnsupportedAce {
                component,
                ace_type,
            } => write!(
                f,
                "'{component}' has an ACE of type {ace_type}, whose semantics this check does not \
                 evaluate"
            ),
        }
    }
}

impl std::error::Error for ImagePathRefusal {}

/// True if `sid` names a principal that is already administrative, so granting
/// it write access over the service image adds no privilege.
///
/// Deliberately a short, exact allowlist. Anything else — including
/// `BUILTIN\Users`, `Authenticated Users`, `Everyone`, package SIDs, a
/// specific user account (even an administrator's own account, whose SID is
/// enabled in a UAC-filtered token) and domain groups such as Domain Admins —
/// is treated as non-administrative. That is the fail-closed direction.
#[must_use]
pub fn is_administrative_sid(sid: &str) -> bool {
    matches!(
        sid,
        acl::SID_LOCAL_SYSTEM | acl::SID_BUILTIN_ADMINISTRATORS | acl::SID_TRUSTED_INSTALLER
    )
}

/// Render a dangerous access mask as the names an operator can look up.
#[must_use]
pub fn describe_rights(mask: u32) -> String {
    let named = [
        (acl::FILE_ADD_FILE, "FILE_ADD_FILE/FILE_WRITE_DATA"),
        (
            acl::FILE_ADD_SUBDIRECTORY,
            "FILE_ADD_SUBDIRECTORY/FILE_APPEND_DATA",
        ),
        (acl::FILE_DELETE_CHILD, "FILE_DELETE_CHILD"),
        (acl::DELETE, "DELETE"),
        (acl::WRITE_DAC, "WRITE_DAC"),
        (acl::WRITE_OWNER, "WRITE_OWNER"),
        (acl::GENERIC_ALL, "GENERIC_ALL"),
        (acl::GENERIC_WRITE, "GENERIC_WRITE"),
    ];
    let parts: Vec<&str> = named
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if parts.is_empty() {
        format!("0x{mask:08X}")
    } else {
        parts.join("|")
    }
}

/// Reject the Windows path forms this crate will not reason about, before any
/// filesystem or ACL access happens.
///
/// Accepts only an absolute, drive-rooted path with no `.` or `..` component.
/// Shared by the SEC-2 image-path gate ([`image_path_chain`]) and the state
/// directory gate ([`crate::state_dir`]) so both refuse exactly the same set of
/// path shapes — a divergence between them would be a hole in whichever is
/// laxer.
///
/// # Errors
/// [`ImagePathRefusal::NotAbsolute`], [`ImagePathRefusal::UncPath`] or
/// [`ImagePathRefusal::UnsupportedPathForm`].
///
/// # Platform note
/// This parses *Windows* path syntax via [`std::path::Component`]. Compiled on
/// a non-Windows host, `std::path` uses POSIX rules, so a Windows-shaped string
/// has no `Prefix` component and is refused as `NotAbsolute`; callers that run
/// off-Windows gate this behind `#[cfg(windows)]`.
pub fn reject_unsupported_path_form(path: &Path) -> Result<(), ImagePathRefusal> {
    use std::path::{Component, Prefix};

    let mut drive_rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(_) | Prefix::VerbatimDisk(_) => drive_rooted = true,
                Prefix::UNC(..) | Prefix::VerbatimUNC(..) => return Err(ImagePathRefusal::UncPath),
                Prefix::Verbatim(_) | Prefix::DeviceNS(_) => {
                    return Err(ImagePathRefusal::UnsupportedPathForm)
                }
            },
            // `.` / `..` would be resolved by the OS against state we do not
            // control, so they defeat the point of checking the chain.
            Component::CurDir | Component::ParentDir => return Err(ImagePathRefusal::NotAbsolute),
            Component::RootDir | Component::Normal(_) => {}
        }
    }

    // `is_absolute()` also demands the RootDir component, so `C:relative` is
    // caught here rather than silently accepted as drive-rooted.
    if !drive_rooted || !path.is_absolute() {
        return Err(ImagePathRefusal::NotAbsolute);
    }
    Ok(())
}

/// Decompose an image path into the chain that must be checked: the image file,
/// its directory, then every ancestor directory up to the volume root.
///
/// Rejects anything whose Windows meaning this gate will not reason about
/// before any filesystem or ACL access happens.
///
/// # Errors
/// [`ImagePathRefusal::NotAbsolute`], [`ImagePathRefusal::UncPath`] or
/// [`ImagePathRefusal::UnsupportedPathForm`].
///
/// # Platform note
/// This parses *Windows* path syntax via [`std::path::Component`]. Compiled on
/// a non-Windows host, `std::path` uses POSIX rules, so a Windows-shaped string
/// has no `Prefix` component and is refused as `NotAbsolute`. The tests that
/// exercise concrete Windows paths are therefore `#[cfg(windows)]`.
pub fn image_path_chain(exe: &Path) -> Result<Vec<(PathBuf, ComponentKind)>, ImagePathRefusal> {
    reject_unsupported_path_form(exe)?;
    if exe.file_name().is_none() {
        return Err(ImagePathRefusal::NotAbsolute);
    }

    Ok(exe
        .ancestors()
        .enumerate()
        .map(|(i, p)| {
            let kind = match i {
                0 => ComponentKind::Image,
                1 => ComponentKind::Directory,
                _ => ComponentKind::Ancestor,
            };
            (p.to_path_buf(), kind)
        })
        .collect())
}

/// Audit one already-probed component against the policy.
///
/// # Errors
/// The specific [`ImagePathRefusal`] that disqualified the component.
pub fn audit_component(
    kind: ComponentKind,
    component: &Path,
    security: &PathSecurity,
) -> Result<(), ImagePathRefusal> {
    let name = component.display().to_string();

    if security.is_reparse_point {
        return Err(ImagePathRefusal::ReparsePoint { component: name });
    }

    if !is_administrative_sid(&security.owner_sid) {
        return Err(ImagePathRefusal::OwnerNotAdministrative {
            component: name,
            owner: security.owner_sid.clone(),
        });
    }

    let Some(aces) = security.aces.as_ref() else {
        return Err(ImagePathRefusal::NullDacl { component: name });
    };

    for ace in aces {
        match ace.ace_type {
            // Denies can only subtract access; ignoring them can only make this
            // gate stricter, never more permissive.
            acl::ACCESS_DENIED_ACE_TYPE => continue,
            acl::ACCESS_ALLOWED_ACE_TYPE => {}
            other => {
                return Err(ImagePathRefusal::UnsupportedAce {
                    component: name,
                    ace_type: other,
                })
            }
        }

        // An inherit-only ACE does not apply to this object at all.
        if ace.flags & acl::INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if is_administrative_sid(&ace.sid) {
            continue;
        }

        let granted = ace.mask & kind.dangerous_mask();
        if granted != 0 {
            return Err(ImagePathRefusal::WritableByNonAdmin {
                component: name,
                principal: ace.sid.clone(),
                rights: describe_rights(granted),
            });
        }
    }

    Ok(())
}

/// The SEC-2 gate: refuse an image path that a non-administrative principal
/// could replace, or whose safety cannot be established.
///
/// Runs before any SCM call, so a refusal has no side effect at all.
///
/// # Errors
/// The first [`ImagePathRefusal`] encountered, walking image → directory →
/// ancestors. A probe failure is itself a refusal: this gate fails **closed**.
pub fn verify_image_path_protected(
    exe: &Path,
    probe: &dyn PathSecurityProbe,
) -> Result<(), ImagePathRefusal> {
    for (component, kind) in image_path_chain(exe)? {
        let security = probe
            .inspect(&component)
            .map_err(|e| ImagePathRefusal::ProbeFailed {
                component: component.display().to_string(),
                reason: e.to_string(),
            })?;
        audit_component(kind, &component, &security)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The real Windows DACL probe. This is the only part of the gate that is
// `#[cfg(windows)]`, and the only part that is `unsafe`.
//
// The Win32 declarations are made locally rather than via `windows-sys`: this
// crate's `windows-sys` feature set covers `Win32_Foundation`, IP Helper and
// WinSock only, and the security APIs are in feature sets it does not enable.
// `advapi32` / `kernel32` are always present on the MSVC link line.
// ---------------------------------------------------------------------------

/// The real Windows DACL probe (`GetNamedSecurityInfoW` + a reparse-point
/// check). Re-exported so the state-directory gate in [`crate::state_dir`] can
/// reuse *this* reader rather than growing a second, differently-wrong one.
#[cfg(windows)]
pub use acl_sys::Win32PathSecurityProbe;

#[cfg(windows)]
mod acl_sys {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr;

    use super::{acl, AceEntry, PathSecurity, PathSecurityProbe, ProbeError};

    /// `SE_OBJECT_TYPE::SE_FILE_OBJECT`.
    const SE_FILE_OBJECT: i32 = 1;
    const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;

    const ERROR_SUCCESS: u32 = 0;
    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    const ERROR_ACCESS_DENIED: u32 = 5;

    /// The documented `ACL` header. Only `AceCount` is read.
    ///
    /// Both this and [`AceHeader`] are read through a raw pointer into the
    /// descriptor `GetNamedSecurityInfoW` allocated. That is sound because the
    /// ACL contract guarantees DWORD alignment for the ACL and for every ACE
    /// `GetAce` hands back, and both structs are less strictly aligned than
    /// that.
    #[repr(C)]
    struct AclHeader {
        acl_revision: u8,
        sbz1: u8,
        acl_size: u16,
        ace_count: u16,
        sbz2: u16,
    }

    /// The documented `ACE_HEADER`.
    #[repr(C)]
    struct AceHeader {
        ace_type: u8,
        ace_flags: u8,
        ace_size: u16,
    }

    /// In `ACCESS_ALLOWED_ACE` / `ACCESS_DENIED_ACE` the layout is
    /// `ACE_HEADER` (4 bytes), `ACCESS_MASK` (4 bytes), then `SidStart`.
    const ACE_MASK_OFFSET: usize = 4;
    const ACE_SID_OFFSET: usize = 8;

    // Parameter names are the SDK's own, so a reader can match them against the
    // MSDN signature; rustc does not apply `non_snake_case` to foreign items.
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn GetNamedSecurityInfoW(
            pObjectName: *const u16,
            ObjectType: i32,
            SecurityInfo: u32,
            ppsidOwner: *mut *mut c_void,
            ppsidGroup: *mut *mut c_void,
            ppDacl: *mut *mut c_void,
            ppSacl: *mut *mut c_void,
            ppSecurityDescriptor: *mut *mut c_void,
        ) -> u32;
        fn GetAce(pAcl: *const c_void, dwAceIndex: u32, pAce: *mut *mut c_void) -> i32;
        fn ConvertSidToStringSidW(Sid: *const c_void, StringSid: *mut *mut u16) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(hMem: *mut c_void) -> *mut c_void;
    }

    /// Owns a `LocalAlloc`'d block so every early return frees it.
    struct LocalMem(*mut c_void);

    impl Drop for LocalMem {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    /// Convert a SID to its `S-1-…` string form.
    ///
    /// # Safety
    /// `sid` must be null, or point to a valid SID that outlives this call.
    /// The returned `String` is an owned copy; nothing borrows from `sid`.
    unsafe fn sid_to_string(sid: *const c_void) -> Option<String> {
        if sid.is_null() {
            return None;
        }
        let mut raw: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut raw) == 0 || raw.is_null() {
            return None;
        }
        let owned = LocalMem(raw.cast());
        let mut len = 0usize;
        while *raw.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        drop(owned);
        Some(s)
    }

    /// Read `path`'s owner SID and DACL.
    ///
    /// # Safety
    /// Calls Win32 directly and walks the returned security descriptor through
    /// raw pointers. It has no preconditions on `path`: an interior NUL (which
    /// would silently truncate the wide string handed to Win32) is rejected
    /// here, as the first thing the function does.
    unsafe fn read_security(path: &Path) -> Result<(String, Option<Vec<AceEntry>>), ProbeError> {
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err(ProbeError::Invalid(
                "path contains an interior NUL".to_owned(),
            ));
        }
        wide.push(0);

        let mut owner: *mut c_void = ptr::null_mut();
        let mut dacl: *mut c_void = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();

        let rc = GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        );
        if rc != ERROR_SUCCESS {
            return Err(match rc {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ProbeError::NotFound,
                ERROR_ACCESS_DENIED => ProbeError::Denied,
                other => ProbeError::Win32(other),
            });
        }
        // Frees the whole self-relative descriptor, including `owner`/`dacl`.
        let _descriptor = LocalMem(descriptor);

        let owner_sid = sid_to_string(owner)
            .ok_or_else(|| ProbeError::Invalid("owner SID is absent or unreadable".to_owned()))?;

        // A NULL DACL is not an empty DACL: it grants everyone full control.
        if dacl.is_null() {
            return Ok((owner_sid, None));
        }

        let ace_count = u32::from((*dacl.cast::<AclHeader>()).ace_count);
        let mut aces = Vec::with_capacity(ace_count as usize);
        for index in 0..ace_count {
            let mut ace: *mut c_void = ptr::null_mut();
            if GetAce(dacl, index, &mut ace) == 0 || ace.is_null() {
                return Err(ProbeError::Invalid(format!(
                    "GetAce failed for ACE #{index}"
                )));
            }
            let header = &*ace.cast::<AceHeader>();
            let ace_type = header.ace_type;
            let flags = header.ace_flags;
            let mask = ace
                .cast::<u8>()
                .add(ACE_MASK_OFFSET)
                .cast::<u32>()
                .read_unaligned();

            // Only allow/deny ACEs have their SID at a fixed offset. Every other
            // type is refused on type alone by `audit_component`, so leaving the
            // SID empty here cannot make the gate more permissive.
            let sid = if ace_type == acl::ACCESS_ALLOWED_ACE_TYPE {
                sid_to_string(ace.cast::<u8>().add(ACE_SID_OFFSET).cast::<c_void>()).ok_or_else(
                    || ProbeError::Invalid(format!("ACE #{index} has an unreadable trustee SID")),
                )?
            } else {
                String::new()
            };

            aces.push(AceEntry {
                ace_type,
                flags,
                mask,
                sid,
            });
        }

        Ok((owner_sid, Some(aces)))
    }

    /// The real probe: `GetNamedSecurityInfoW` plus a reparse-point check.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Win32PathSecurityProbe;

    impl PathSecurityProbe for Win32PathSecurityProbe {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            // `symlink_metadata` does not traverse the final link, so a symlink
            // or junction is reported as itself.
            let meta = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProbeError::NotFound,
                std::io::ErrorKind::PermissionDenied => ProbeError::Denied,
                _ => ProbeError::Invalid(e.to_string()),
            })?;
            let is_reparse_point = meta.file_type().is_symlink();
            let (owner_sid, aces) = unsafe { read_security(path)? };
            Ok(PathSecurity {
                owner_sid,
                aces,
                is_reparse_point,
            })
        }
    }
}

// ============================================================================
// Windows-only SCM layer (thin) — absent on non-Windows targets
// ============================================================================

#[cfg(windows)]
mod imp {
    use super::{classify_os_error, PriorState, WinServiceError};
    use std::ffi::OsString;
    use std::path::Path;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use windows_service::service::{
        Service, ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    fn map_err(e: windows_service::Error) -> WinServiceError {
        match e {
            windows_service::Error::Winapi(io_err) => {
                classify_os_error(io_err.raw_os_error(), &io_err.to_string())
            }
            other => WinServiceError::Other(other.to_string()),
        }
    }

    fn open_manager(access: ServiceManagerAccess) -> Result<ServiceManager, WinServiceError> {
        ServiceManager::local_computer(None::<&str>, access).map_err(map_err)
    }

    /// Create the service (own-process, demand-start). If it already exists,
    /// report [`PriorState::AlreadyExisted`] instead of erroring, so uninstall
    /// can be exact. Surfaces "marked for deletion" as a typed error.
    pub fn install(
        service_name: &str,
        display_name: &str,
        exe_path: &Path,
    ) -> Result<PriorState, WinServiceError> {
        let manager =
            open_manager(ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;

        match manager.open_service(service_name, ServiceAccess::QUERY_STATUS) {
            Ok(_existing) => return Ok(PriorState::AlreadyExisted),
            Err(e) => match map_err(e) {
                WinServiceError::NotFound => {}
                other => return Err(other),
            },
        }

        let info = ServiceInfo {
            name: OsString::from(service_name),
            display_name: OsString::from(display_name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path.to_path_buf(),
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };

        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::DELETE;

        match manager.create_service(&info, access) {
            Ok(_svc) => Ok(PriorState::CreatedFresh),
            Err(e) => match map_err(e) {
                // Raced with another creator between probe and create.
                WinServiceError::AlreadyExists => Ok(PriorState::AlreadyExisted),
                other => Err(other),
            },
        }
    }

    pub fn start(service_name: &str) -> Result<(), WinServiceError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                service_name,
                ServiceAccess::QUERY_STATUS | ServiceAccess::START,
            )
            .map_err(map_err)?;

        let no_args: &[&std::ffi::OsStr] = &[];
        match service.start(no_args) {
            Ok(()) => {}
            Err(e) => match map_err(e) {
                WinServiceError::AlreadyInState => return Ok(()),
                other => return Err(other),
            },
        }
        wait_for_state(&service, ServiceState::Running, Duration::from_secs(30))
    }

    pub fn stop(service_name: &str) -> Result<(), WinServiceError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                service_name,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
            )
            .map_err(map_err)?;

        match service.stop() {
            Ok(_status) => {}
            Err(e) => match map_err(e) {
                WinServiceError::AlreadyInState => return Ok(()),
                other => return Err(other),
            },
        }
        wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30))
    }

    /// Delete (uninstall) the service. SCM only *marks* it for deletion; the
    /// record is removed once the last open handle closes. We best-effort stop
    /// it first so deletion completes promptly, then mark for deletion.
    pub fn uninstall(service_name: &str) -> Result<(), WinServiceError> {
        let manager = open_manager(ServiceManagerAccess::CONNECT)?;
        let service = manager
            .open_service(
                service_name,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(map_err)?;

        // Best-effort stop; ignore already-stopped / stop failures — they must
        // not block marking for deletion.
        if let Ok(status) = service.query_status() {
            let running = status.current_state != ServiceState::Stopped
                && status.current_state != ServiceState::StopPending;
            if running && service.stop().is_ok() {
                let _ = wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(15));
            }
        }

        match service.delete() {
            Ok(()) => Ok(()),
            // Already marked by a prior call — idempotent success shape.
            Err(e) => match map_err(e) {
                WinServiceError::MarkedForDeletion => Ok(()),
                other => Err(other),
            },
        }
        // Handle drops here; SCM completes removal when the last handle closes.
    }

    fn wait_for_state(
        service: &Service,
        target: ServiceState,
        timeout: Duration,
    ) -> Result<(), WinServiceError> {
        let deadline = Instant::now() + timeout;
        loop {
            let status = service.query_status().map_err(map_err)?;
            if status.current_state == target {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(WinServiceError::Timeout);
            }
            sleep(Duration::from_millis(250));
        }
    }
}

// Platform shims: real SCM on Windows; `Unsupported` on other targets.

fn platform_install(name: &str, display: &str, exe: &Path) -> Result<PriorState, WinServiceError> {
    #[cfg(windows)]
    {
        // SEC-2. This runs before the SCM is even opened, so a refusal has no
        // side effect. It gates the *already exists* branch too: this call is
        // what binds an install receipt to that service, and we will not vouch
        // for a service whose image any user can rewrite.
        verify_image_path_protected(exe, &acl_sys::Win32PathSecurityProbe).map_err(|refusal| {
            WinServiceError::UnsafeImagePath {
                path: exe.display().to_string(),
                refusal,
            }
        })?;
        imp::install(name, display, exe)
    }
    #[cfg(not(windows))]
    {
        let _ = (name, display, exe);
        Err(WinServiceError::Unsupported)
    }
}

fn platform_start(name: &str) -> Result<(), WinServiceError> {
    #[cfg(windows)]
    {
        imp::start(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(WinServiceError::Unsupported)
    }
}

fn platform_stop(name: &str) -> Result<(), WinServiceError> {
    #[cfg(windows)]
    {
        imp::stop(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(WinServiceError::Unsupported)
    }
}

fn platform_uninstall(name: &str) -> Result<(), WinServiceError> {
    #[cfg(windows)]
    {
        imp::uninstall(name)
    }
    #[cfg(not(windows))]
    {
        let _ = name;
        Err(WinServiceError::Unsupported)
    }
}

// ============================================================================
// The real PrivilegedHelper
// ============================================================================

/// A real [`PrivilegedHelper`] backed by the Windows Service Control Manager.
///
/// It registers the service pointing at `exe_path` — the path to the installed
/// `ssk-svc` service host binary. The service name is derived from the host
/// manifest's content id, so it is stable and unique per host.
#[derive(Debug, Clone)]
pub struct WindowsServiceHelper {
    exe_path: PathBuf,
}

impl WindowsServiceHelper {
    /// Bind the helper to the path of the `ssk-svc` service host executable that
    /// the SCM will launch.
    #[must_use]
    pub fn new(exe_path: impl Into<PathBuf>) -> Self {
        Self {
            exe_path: exe_path.into(),
        }
    }

    fn helper_err(e: WinServiceError) -> ServiceError {
        ServiceError::Helper(e.to_string())
    }
}

impl PrivilegedHelper for WindowsServiceHelper {
    fn install(&self, manifest: &HostManifest) -> Result<InstallReceipt, ServiceError> {
        let name = service_name_for(&manifest.host_id.to_hex());
        let prior =
            platform_install(&name, &manifest.name, &self.exe_path).map_err(Self::helper_err)?;

        tracing::info!(
            target: "ssk.winhost.service",
            event = "service_installed",
            service = %name,
            host = %manifest.host_id.to_hex(),
            prior = ?prior,
        );

        Ok(InstallReceipt::new(
            manifest.host_id,
            prior.as_prior_service_state(),
        ))
    }

    fn start(&self, host_id: &Digest, granted: &BTreeSet<String>) -> Result<(), ServiceError> {
        let name = service_name_for(&host_id.to_hex());
        platform_start(&name).map_err(Self::helper_err)?;
        tracing::info!(
            target: "ssk.winhost.service",
            event = "service_started",
            service = %name,
            granted = granted.len(),
        );
        Ok(())
    }

    fn stop(&self, host_id: &Digest) -> Result<(), ServiceError> {
        let name = service_name_for(&host_id.to_hex());
        platform_stop(&name).map_err(Self::helper_err)?;
        tracing::info!(target: "ssk.winhost.service", event = "service_stopped", service = %name);
        Ok(())
    }

    fn uninstall(&self, receipt: &InstallReceipt) -> Result<(), ServiceError> {
        let name = service_name_for(&receipt.host_id.to_hex());

        // Exact rollback: if install found the service already present
        // (prior_state == "installed"), we never created it, so a reversible
        // uninstall must leave it in place.
        if receipt.prior_state == ServiceState::Installed.as_str() {
            tracing::info!(
                target: "ssk.winhost.service",
                event = "service_uninstall_skipped_preexisting",
                service = %name,
            );
            return Ok(());
        }

        platform_uninstall(&name).map_err(Self::helper_err)?;
        tracing::info!(target: "ssk.winhost.service", event = "service_uninstalled", service = %name);
        Ok(())
    }
}

// ============================================================================
// Unit tests for the pure layer (run on any host, incl. Linux)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_derivation_basic() {
        let n = service_name_for("deadbeefcafef00d0011223344556677");
        assert_eq!(n, "SSKHost_DEADBEEFCAFEF00D");
        assert!(is_valid_service_name(&n));
    }

    #[test]
    fn name_takes_first_16_hex_only() {
        let n = service_name_for("00112233445566778899");
        assert_eq!(n, "SSKHost_0011223344556677");
        assert_eq!(n.len(), "SSKHost_".len() + 16);
    }

    #[test]
    fn name_filters_non_hex_and_uppercases() {
        let n = service_name_for("dead-beef-cafe-f00d-0011-2233-4455");
        assert_eq!(n, "SSKHost_DEADBEEFCAFEF00D");
        assert!(is_valid_service_name(&n));
    }

    #[test]
    fn name_is_within_length_bound() {
        let n = service_name_for(&"f".repeat(1000));
        assert!(n.len() <= MAX_SERVICE_NAME_LEN);
        assert_eq!(n.len(), "SSKHost_".len() + 16);
    }

    #[test]
    fn invalid_names_rejected() {
        assert!(!is_valid_service_name(""));
        assert!(!is_valid_service_name("has space"));
        assert!(!is_valid_service_name("has\\backslash"));
        assert!(!is_valid_service_name("has/slash"));
        assert!(!is_valid_service_name(
            &"x".repeat(MAX_SERVICE_NAME_LEN + 1)
        ));
    }

    #[test]
    fn classify_maps_known_codes() {
        assert_eq!(
            classify_os_error(Some(win32::ERROR_ACCESS_DENIED), "x"),
            WinServiceError::AccessDenied
        );
        assert_eq!(
            classify_os_error(Some(win32::ERROR_SERVICE_DOES_NOT_EXIST), "x"),
            WinServiceError::NotFound
        );
        assert_eq!(
            classify_os_error(Some(win32::ERROR_SERVICE_EXISTS), "x"),
            WinServiceError::AlreadyExists
        );
        assert_eq!(
            classify_os_error(Some(win32::ERROR_SERVICE_MARKED_FOR_DELETE), "x"),
            WinServiceError::MarkedForDeletion
        );
        assert_eq!(
            classify_os_error(Some(win32::ERROR_SERVICE_ALREADY_RUNNING), "x"),
            WinServiceError::AlreadyInState
        );
    }

    #[test]
    fn classify_unknown_code_preserved() {
        match classify_os_error(Some(999_999), "boom") {
            WinServiceError::Winapi { code, message } => {
                assert_eq!(code, Some(999_999));
                assert_eq!(message, "boom");
            }
            other => panic!("expected Winapi variant, got {other:?}"),
        }
    }

    #[test]
    fn prior_state_maps_to_rollback_service_state() {
        assert_eq!(
            PriorState::CreatedFresh.as_prior_service_state(),
            ServiceState::Uninstalled
        );
        assert_eq!(
            PriorState::AlreadyExisted.as_prior_service_state(),
            ServiceState::Installed
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn helper_is_unsupported_off_windows() {
        let helper = WindowsServiceHelper::new("C:/does/not/matter/ssk-svc.exe");
        let manifest = HostManifest::new("ssk-host", "0.1.0", "windows", ["system_capture"]);
        match helper.install(&manifest) {
            Err(ServiceError::Helper(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected Helper error off-Windows, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SEC-2 — image-path safety gate
    // ------------------------------------------------------------------

    /// A user account SID from this machine's shape; not administrative.
    const SID_A_USER: &str = "S-1-5-21-3707581644-2641971034-3119889655-1001";
    const SID_USERS: &str = "S-1-5-32-545";
    const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
    const SID_EVERYONE: &str = "S-1-1-0";

    /// `Modify` as Explorer grants it: read/write/execute + DELETE.
    const RIGHTS_MODIFY: u32 = 0x0013_01BF;
    /// `ReadAndExecute, Synchronize`.
    const RIGHTS_READ_EXECUTE: u32 = 0x0012_00A9;

    /// A probe answering from a fixed table; anything not in the table is
    /// [`ProbeError::NotFound`].
    struct FakeProbe(std::collections::BTreeMap<PathBuf, PathSecurity>);

    impl FakeProbe {
        fn new(entries: Vec<(&str, PathSecurity)>) -> Self {
            Self(
                entries
                    .into_iter()
                    .map(|(p, s)| (PathBuf::from(p), s))
                    .collect(),
            )
        }
    }

    impl PathSecurityProbe for FakeProbe {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            self.0.get(path).cloned().ok_or(ProbeError::NotFound)
        }
    }

    /// A probe that must never be consulted — proves a refusal happened purely
    /// from the path, before any filesystem or ACL access.
    struct NeverProbe;

    impl PathSecurityProbe for NeverProbe {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            panic!("probe must not be consulted for {}", path.display());
        }
    }

    fn protected(aces: Vec<AceEntry>) -> PathSecurity {
        PathSecurity {
            owner_sid: acl::SID_TRUSTED_INSTALLER.to_owned(),
            aces: Some(aces),
            is_reparse_point: false,
        }
    }

    /// The ACE set a stock protected system directory carries.
    fn system_dir_aces() -> Vec<AceEntry> {
        vec![
            AceEntry::allow(acl::SID_LOCAL_SYSTEM, RIGHTS_MODIFY),
            AceEntry::allow(acl::SID_BUILTIN_ADMINISTRATORS, RIGHTS_MODIFY),
            AceEntry::allow(acl::SID_TRUSTED_INSTALLER, acl::GENERIC_ALL),
            AceEntry::allow(SID_USERS, RIGHTS_READ_EXECUTE),
        ]
    }

    #[test]
    fn administrative_sid_allowlist_is_exact() {
        assert!(is_administrative_sid(acl::SID_LOCAL_SYSTEM));
        assert!(is_administrative_sid(acl::SID_BUILTIN_ADMINISTRATORS));
        assert!(is_administrative_sid(acl::SID_TRUSTED_INSTALLER));

        assert!(!is_administrative_sid(SID_USERS));
        assert!(!is_administrative_sid(SID_AUTHENTICATED_USERS));
        assert!(!is_administrative_sid(SID_EVERYONE));
        assert!(!is_administrative_sid(SID_A_USER));
        // Domain Admins. Genuinely administrative in AD terms, but this gate
        // does not resolve group nesting, so it refuses. Fail-closed, and the
        // module docs say so.
        assert!(!is_administrative_sid(
            "S-1-5-21-3707581644-2641971034-3119889655-512"
        ));
        // The built-in Administrator *account*: its SID is enabled even in a
        // UAC-filtered token, so it must not be allowlisted.
        assert!(!is_administrative_sid(
            "S-1-5-21-3707581644-2641971034-3119889655-500"
        ));
        assert!(!is_administrative_sid(""));
    }

    #[test]
    fn add_file_is_dangerous_on_the_leaf_but_not_on_an_ancestor() {
        // This asymmetry is why `C:\` (which grants Authenticated Users
        // FILE_ADD_SUBDIRECTORY outright) does not disqualify every path on the
        // system volume, while a directory in which anyone can drop a DLL next
        // to the service binary does.
        for bit in [acl::FILE_ADD_FILE, acl::FILE_ADD_SUBDIRECTORY] {
            assert_ne!(bit & ComponentKind::Image.dangerous_mask(), 0);
            assert_ne!(bit & ComponentKind::Directory.dangerous_mask(), 0);
            assert_eq!(bit & ComponentKind::Ancestor.dangerous_mask(), 0);
        }
    }

    #[test]
    fn structural_rights_are_dangerous_everywhere() {
        for bit in [
            acl::FILE_DELETE_CHILD,
            acl::DELETE,
            acl::WRITE_DAC,
            acl::WRITE_OWNER,
            acl::GENERIC_ALL,
        ] {
            for kind in [
                ComponentKind::Image,
                ComponentKind::Directory,
                ComponentKind::Ancestor,
            ] {
                assert_ne!(bit & kind.dangerous_mask(), 0, "{bit:#x} on {kind:?}");
            }
        }
    }

    #[test]
    fn read_and_execute_is_dangerous_nowhere() {
        for kind in [
            ComponentKind::Image,
            ComponentKind::Directory,
            ComponentKind::Ancestor,
        ] {
            assert_eq!(RIGHTS_READ_EXECUTE & kind.dangerous_mask(), 0, "{kind:?}");
        }
    }

    #[test]
    fn describe_rights_names_the_bits() {
        assert_eq!(
            describe_rights(acl::FILE_DELETE_CHILD | acl::WRITE_DAC),
            "FILE_DELETE_CHILD|WRITE_DAC"
        );
        assert_eq!(describe_rights(0x0000_0001), "0x00000001");
    }

    #[test]
    fn inherit_only_aces_do_not_apply_to_the_object_itself() {
        // `C:\` carries Authenticated Users:(OI)(CI)(IO)(M) — full Modify, but
        // inherit-only. It grants nothing on `C:\` itself.
        let mut ace = AceEntry::allow(SID_AUTHENTICATED_USERS, RIGHTS_MODIFY);
        ace.flags = acl::INHERIT_ONLY_ACE;
        let security = protected(vec![ace]);
        assert_eq!(
            audit_component(ComponentKind::Ancestor, Path::new("root"), &security),
            Ok(())
        );

        // The same ACE without the inherit-only flag is a refusal.
        let mut effective = AceEntry::allow(SID_AUTHENTICATED_USERS, RIGHTS_MODIFY);
        effective.flags = 0;
        let security = protected(vec![effective]);
        match audit_component(ComponentKind::Ancestor, Path::new("root"), &security) {
            Err(ImagePathRefusal::WritableByNonAdmin { principal, .. }) => {
                assert_eq!(principal, SID_AUTHENTICATED_USERS);
            }
            other => panic!("expected WritableByNonAdmin, got {other:?}"),
        }
    }

    #[test]
    fn deny_aces_are_ignored_and_unknown_ace_types_are_refused() {
        let deny = AceEntry {
            ace_type: acl::ACCESS_DENIED_ACE_TYPE,
            flags: 0,
            mask: acl::GENERIC_ALL,
            sid: SID_EVERYONE.to_owned(),
        };
        let security = protected(vec![deny]);
        assert_eq!(
            audit_component(ComponentKind::Directory, Path::new("d"), &security),
            Ok(())
        );

        // ACCESS_ALLOWED_CALLBACK_ACE_TYPE — conditional semantics this walker
        // does not evaluate. Refuse rather than guess.
        let callback = AceEntry {
            ace_type: 9,
            flags: 0,
            mask: acl::GENERIC_ALL,
            sid: String::new(),
        };
        let security = protected(vec![callback]);
        match audit_component(ComponentKind::Directory, Path::new("d"), &security) {
            Err(ImagePathRefusal::UnsupportedAce { ace_type, .. }) => assert_eq!(ace_type, 9),
            other => panic!("expected UnsupportedAce, got {other:?}"),
        }
    }

    #[test]
    fn null_dacl_is_refused_but_empty_dacl_is_accepted() {
        let null_dacl = PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.to_owned(),
            aces: None,
            is_reparse_point: false,
        };
        assert!(matches!(
            audit_component(ComponentKind::Directory, Path::new("d"), &null_dacl),
            Err(ImagePathRefusal::NullDacl { .. })
        ));

        // An empty DACL denies everyone — safe.
        let empty_dacl = protected(vec![]);
        assert_eq!(
            audit_component(ComponentKind::Directory, Path::new("d"), &empty_dacl),
            Ok(())
        );
    }

    #[test]
    fn a_non_administrative_owner_is_refused_even_with_a_clean_dacl() {
        let security = PathSecurity {
            owner_sid: SID_A_USER.to_owned(),
            aces: Some(system_dir_aces()),
            is_reparse_point: false,
        };
        match audit_component(ComponentKind::Directory, Path::new("d"), &security) {
            Err(ImagePathRefusal::OwnerNotAdministrative { owner, .. }) => {
                assert_eq!(owner, SID_A_USER);
            }
            other => panic!("expected OwnerNotAdministrative, got {other:?}"),
        }
    }

    #[test]
    fn a_reparse_point_component_is_refused() {
        let security = PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.to_owned(),
            aces: Some(system_dir_aces()),
            is_reparse_point: true,
        };
        assert!(matches!(
            audit_component(ComponentKind::Ancestor, Path::new("j"), &security),
            Err(ImagePathRefusal::ReparsePoint { .. })
        ));
    }

    // --- Windows path-syntax cases -------------------------------------
    // `std::path` parses Windows prefixes only on Windows, so these are
    // `#[cfg(windows)]` rather than silently asserting POSIX behaviour.

    #[cfg(windows)]
    #[test]
    fn a_relative_path_is_refused_before_any_probe() {
        // The exact string RUNBOOK_WINDOWS.md used to instruct.
        let refusal =
            verify_image_path_protected(Path::new(r".\target\release\ssk-svc.exe"), &NeverProbe)
                .unwrap_err();
        assert_eq!(refusal, ImagePathRefusal::NotAbsolute);
    }

    #[cfg(windows)]
    #[test]
    fn dot_dot_and_drive_relative_paths_are_refused() {
        for p in [
            r"C:\Program Files\SSK\..\..\Users\me\ssk-svc.exe",
            r"C:ssk-svc.exe",
            r"\ssk-svc.exe",
            r"C:\",
        ] {
            assert_eq!(
                verify_image_path_protected(Path::new(p), &NeverProbe).unwrap_err(),
                ImagePathRefusal::NotAbsolute,
                "{p}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_unc_path_is_refused_before_any_probe() {
        for p in [
            r"\\fileserver\deploy\ssk-svc.exe",
            r"\\?\UNC\fileserver\deploy\ssk-svc.exe",
        ] {
            assert_eq!(
                verify_image_path_protected(Path::new(p), &NeverProbe).unwrap_err(),
                ImagePathRefusal::UncPath,
                "{p}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn device_and_verbatim_non_disk_paths_are_refused() {
        assert_eq!(
            verify_image_path_protected(Path::new(r"\\.\PhysicalDrive0"), &NeverProbe).unwrap_err(),
            ImagePathRefusal::UnsupportedPathForm
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_whole_ancestor_chain_is_checked_not_just_the_leaf() {
        // Protected leaf and protected image, but a parent that Users can
        // delete children of — so the "protected" leaf can simply be swapped.
        let probe = FakeProbe::new(vec![
            (r"C:\", protected(system_dir_aces())),
            (
                r"C:\stage",
                protected(
                    [
                        system_dir_aces(),
                        vec![AceEntry::allow(SID_USERS, acl::FILE_DELETE_CHILD)],
                    ]
                    .concat(),
                ),
            ),
            (r"C:\stage\ssk", protected(system_dir_aces())),
            (r"C:\stage\ssk\ssk-svc.exe", protected(system_dir_aces())),
        ]);

        match verify_image_path_protected(Path::new(r"C:\stage\ssk\ssk-svc.exe"), &probe) {
            Err(ImagePathRefusal::WritableByNonAdmin {
                component,
                principal,
                rights,
            }) => {
                assert_eq!(component, r"C:\stage");
                assert_eq!(principal, SID_USERS);
                assert_eq!(rights, "FILE_DELETE_CHILD");
            }
            other => panic!("expected the parent to be named, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_fully_protected_chain_is_accepted() {
        let probe = FakeProbe::new(vec![
            // Models the real `C:\`: Authenticated Users may add a subdirectory
            // at the root, which is not a swap primitive for an existing child.
            (
                r"C:\",
                protected(
                    [
                        system_dir_aces(),
                        vec![AceEntry::allow(
                            SID_AUTHENTICATED_USERS,
                            acl::FILE_ADD_SUBDIRECTORY,
                        )],
                    ]
                    .concat(),
                ),
            ),
            (r"C:\Program Files", protected(system_dir_aces())),
            (
                r"C:\Program Files\ScorpioSync",
                protected(system_dir_aces()),
            ),
            (
                r"C:\Program Files\ScorpioSync\ssk-svc.exe",
                protected(system_dir_aces()),
            ),
        ]);

        assert_eq!(
            verify_image_path_protected(
                Path::new(r"C:\Program Files\ScorpioSync\ssk-svc.exe"),
                &probe
            ),
            Ok(())
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_same_add_file_grant_on_the_leaf_directory_is_refused() {
        // Exactly the ACE the previous test accepts on `C:\`, moved onto the
        // directory holding the binary: now it is DLL planting.
        let probe = FakeProbe::new(vec![
            (r"C:\", protected(system_dir_aces())),
            (r"C:\Program Files", protected(system_dir_aces())),
            (
                r"C:\Program Files\ScorpioSync",
                protected(
                    [
                        system_dir_aces(),
                        vec![AceEntry::allow(SID_AUTHENTICATED_USERS, acl::FILE_ADD_FILE)],
                    ]
                    .concat(),
                ),
            ),
            (
                r"C:\Program Files\ScorpioSync\ssk-svc.exe",
                protected(system_dir_aces()),
            ),
        ]);

        match verify_image_path_protected(
            Path::new(r"C:\Program Files\ScorpioSync\ssk-svc.exe"),
            &probe,
        ) {
            Err(ImagePathRefusal::WritableByNonAdmin { component, .. }) => {
                assert_eq!(component, r"C:\Program Files\ScorpioSync");
            }
            other => panic!("expected the leaf directory to be refused, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn image_path_chain_orders_image_then_directory_then_ancestors() {
        let chain = image_path_chain(Path::new(r"C:\Program Files\ScorpioSync\ssk-svc.exe"))
            .expect("well-formed path");
        let rendered: Vec<(String, ComponentKind)> = chain
            .into_iter()
            .map(|(p, k)| (p.display().to_string(), k))
            .collect();
        assert_eq!(
            rendered,
            vec![
                (
                    r"C:\Program Files\ScorpioSync\ssk-svc.exe".to_owned(),
                    ComponentKind::Image
                ),
                (
                    r"C:\Program Files\ScorpioSync".to_owned(),
                    ComponentKind::Directory
                ),
                (r"C:\Program Files".to_owned(), ComponentKind::Ancestor),
                (r"C:\".to_owned(), ComponentKind::Ancestor),
            ]
        );
    }

    // --- Against the real Windows DACLs of this machine -----------------

    /// A scratch directory under the system temp dir, removed on drop.
    #[cfg(windows)]
    struct ScratchDir(PathBuf);

    #[cfg(windows)]
    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let dir = std::env::temp_dir().join(format!(
                "ssk-winhost-sec2-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).expect("create scratch dir");
            Self(dir)
        }
    }

    #[cfg(windows)]
    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[cfg(windows)]
    #[test]
    fn real_probe_accepts_a_stock_protected_system_binary() {
        // `%SystemRoot%\System32\svchost.exe`: owner TrustedInstaller, Users
        // hold ReadAndExecute only, and every ancestor is likewise protected.
        // The whole chain is readable unelevated.
        let root = std::env::var("SystemRoot").expect("SystemRoot is set on Windows");
        let exe = PathBuf::from(root).join(r"System32\svchost.exe");
        assert!(exe.exists(), "{} must exist", exe.display());

        let result = verify_image_path_protected(&exe, &acl_sys::Win32PathSecurityProbe);
        assert_eq!(
            result,
            Ok(()),
            "a stock protected system binary must pass the gate"
        );
    }

    #[cfg(windows)]
    #[test]
    fn real_probe_refuses_a_user_writable_scratch_directory() {
        let scratch = ScratchDir::new("writable");
        let exe = scratch.0.join("ssk-svc.exe");
        std::fs::write(&exe, b"not really a binary").expect("write scratch exe");

        let refusal = verify_image_path_protected(&exe, &acl_sys::Win32PathSecurityProbe)
            .expect_err("a path under %TEMP% must never be accepted");

        // Which of the two fires depends on how the profile was provisioned:
        // a temp tree is normally *owned* by the user (implicit WRITE_DAC), and
        // always grants that user Modify. Both are the same finding — this
        // principal controls the image — and both are refusals.
        assert!(
            matches!(
                refusal,
                ImagePathRefusal::OwnerNotAdministrative { .. }
                    | ImagePathRefusal::WritableByNonAdmin { .. }
            ),
            "expected a user-control refusal, got {refusal}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn real_probe_fails_closed_on_a_nonexistent_path() {
        let root = std::env::var("SystemRoot").expect("SystemRoot is set on Windows");
        let missing = PathBuf::from(root).join(r"System32\ssk-svc-does-not-exist-9d3f1c7a.exe");
        assert!(!missing.exists());

        match verify_image_path_protected(&missing, &acl_sys::Win32PathSecurityProbe) {
            Err(ImagePathRefusal::ProbeFailed { component, reason }) => {
                assert_eq!(component, missing.display().to_string());
                assert!(reason.contains("does not exist"), "{reason}");
            }
            other => panic!("expected ProbeFailed, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn install_refuses_a_user_writable_image_without_touching_the_scm() {
        // End-to-end through the public helper. The gate runs before the SCM is
        // opened, so this cannot install, start or query anything.
        let scratch = ScratchDir::new("install");
        let exe = scratch.0.join("ssk-svc.exe");
        std::fs::write(&exe, b"not really a binary").expect("write scratch exe");

        let helper = WindowsServiceHelper::new(&exe);
        let manifest = HostManifest::new("ssk-host", "0.1.0", "windows", ["system_capture"]);
        match helper.install(&manifest) {
            Err(ServiceError::Helper(msg)) => {
                assert!(
                    msg.contains("refusing to register a LocalSystem service"),
                    "{msg}"
                );
                assert!(msg.contains("%ProgramFiles%"), "{msg}");
                // Must not be mistaken for "you forgot to elevate".
                assert!(!msg.contains("Administrator required"), "{msg}");
            }
            other => panic!("expected the SEC-2 refusal, got {other:?}"),
        }
    }

    #[test]
    fn uninstall_of_a_preexisting_service_is_a_no_op_not_a_deletion() {
        // A receipt whose prior_state is "installed" means install found it
        // already there; a reversible uninstall must NOT delete it. On any
        // platform this returns Ok without touching the SCM.
        let helper = WindowsServiceHelper::new("ssk-svc.exe");
        let host_id = HostManifest::new("h", "1", "windows", ["c"]).host_id;
        let receipt = InstallReceipt::new(host_id, ServiceState::Installed);
        assert!(helper.uninstall(&receipt).is_ok());
    }
}
