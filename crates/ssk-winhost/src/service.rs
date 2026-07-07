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

use std::collections::BTreeSet;
use std::path::PathBuf;

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

fn platform_install(
    name: &str,
    display: &str,
    exe: &PathBuf,
) -> Result<PriorState, WinServiceError> {
    #[cfg(windows)]
    {
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
