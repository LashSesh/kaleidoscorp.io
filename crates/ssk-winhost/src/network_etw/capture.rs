//! Capture preparation and private in-process acceptance only. A system logger
//! must not become executable until crash supervision and recovery are ready.
use serde::Serialize;
use std::{io, path::Path};

#[derive(Debug, Serialize)]
pub struct SystemCapturePlan {
    schema_version: u32,
    profile: &'static str,
    session_name: &'static str,
    scope: &'static str,
    log_file_mode: u32,
    enable_flags: u32,
    clock_type: u32,
    proposed_duration_ms: u32,
    proposed_max_file_mib: u32,
    system_capture_available: bool,
    private_capture_worker_supervised: bool,
    prerequisites: [&'static str; 3],
    enforcement_active: bool,
}

/// Read-only configuration plan. This is deliberately not a capture permit.
pub fn system_plan() -> SystemCapturePlan {
    SystemCapturePlan {
        schema_version: 2,
        profile: "process_network_v1",
        session_name: "ScorpioSync.NetworkAcceptance",
        scope: "system_process_tcp_udp",
        log_file_mode: super::session::SYSTEM_LOGGER | 1,
        enable_flags: super::session::PROCESS_NETWORK_FLAGS,
        clock_type: 1,
        proposed_duration_ms: 5000,
        proposed_max_file_mib: 16,
        system_capture_available: false,
        private_capture_worker_supervised: cfg!(windows),
        prerequisites: [
            "system_session_crash_recovery",
            "protected_output_and_recovery",
            "isolated_windows_acceptance",
        ],
        enforcement_active: false,
    }
}

#[derive(Debug, Serialize)]
pub struct PrivateFixtureReport {
    schema_version: u32,
    source: &'static str,
    status: &'static str,
    etl_file: &'static str,
    closure_file: &'static str,
    controller_file: &'static str,
    supervision_file: &'static str,
    events_submitted: u32,
    system_capture_available: bool,
    coverage_verified: bool,
    enforcement_active: bool,
}

/// Create a NEW directory containing a bounded, private synthetic trace.
/// No kernel/network provider is reachable from this function.
/// CLI-local protocol: only call from the ssk-netcapture executable.
pub fn private_fixture(directory: &Path) -> io::Result<PrivateFixtureReport> {
    #[cfg(windows)]
    {
        supervisor::fixture(directory)
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private ETL capture requires Windows",
        ))
    }
}

/// Hidden worker dispatch. Job containment is checked before filesystem access.
#[doc(hidden)]
pub fn private_worker(directory: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        super::worker_process::require_containment()?;
        let events_submitted = windows::fixture_prepared(directory)?;
        serde_json::to_writer(
            std::io::stdout().lock(),
            &supervisor::WorkerMessage {
                schema_version: 1,
                events_submitted,
            },
        )?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = directory;
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(any(windows, test))]
mod controller;
#[cfg(windows)]
mod supervisor;
pub mod traffic;
#[cfg(windows)]
mod windows;
