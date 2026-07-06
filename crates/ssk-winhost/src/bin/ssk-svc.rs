//! `ssk-svc` — the minimal real Windows service host that the SCM launches.
//!
//! [`WindowsServiceHelper`](ssk_winhost::WindowsServiceHelper) registers a
//! service whose executable is this binary. When the SCM starts it, it must
//! attach to the service dispatcher, report `Running`, and honor a `Stop`
//! control — otherwise `start` would time out. This is a deliberately minimal
//! host: it comes up, reports healthy, and idles until stopped. The actual SSK
//! decision work is driven through the library stack / `ssk` CLI; this binary
//! exists so the service lifecycle (task: PrivilegedHelper) is genuinely
//! exercisable end to end on a real Windows 11 machine.
//!
//! Verified to cross-compile for `x86_64-pc-windows-msvc`; on-machine behavior
//! (registering with the SCM, responding to `sc stop`) is an operator
//! validation step — see `RUNBOOK_WINDOWS.md`.

#[cfg(not(windows))]
fn main() {
    eprintln!(
        "ssk-svc is the Windows service host; it only runs when launched by the \
         Windows Service Control Manager on Windows. Nothing to do on this platform."
    );
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_svc::run()
}

#[cfg(windows)]
mod windows_svc {
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;

    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    // The name the SCM uses to identify us. For a SERVICE_WIN32_OWN_PROCESS
    // service the SCM supplies the real registered name at launch; the string
    // handed to the dispatcher is not authoritative, so a stable placeholder is
    // fine here.
    const DISPATCH_NAME: &str = "SSKHost";

    define_windows_service!(ffi_service_main, service_main);

    /// Entry point invoked by the SCM through the dispatcher.
    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            // Nowhere to log to before the status handle exists; surface to the
            // Windows error stream for `sc`/Event Viewer correlation.
            eprintln!("ssk-svc failed: {e}");
        }
    }

    fn run_service() -> windows_service::Result<()> {
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop => {
                    let _ = shutdown_tx.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        // For own-process services the registered name may be empty; the SCM
        // binds the handle to whichever service started this process.
        let status_handle = service_control_handler::register("", event_handler)?;

        let running = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        };
        status_handle.set_service_status(running)?;

        // Idle until the SCM asks us to stop.
        let _ = shutdown_rx.recv();

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        Ok(())
    }

    /// Attach to the SCM dispatcher; blocks until the service stops.
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        service_dispatcher::start(DISPATCH_NAME, ffi_service_main)?;
        Ok(())
    }
}
