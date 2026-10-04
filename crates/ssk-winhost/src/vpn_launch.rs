//! Composed, held OpenVPN startup without egress authority. The VPN broker
//! authorizes/audits before calling this from its dedicated service worker.
//! There is deliberately no method to release hold or turn this into activation.
pub use crate::vpn_installation::InstallationError;
use crate::{
    service::{PathSecurityProbe, Win32PathSecurityProbe},
    vpn_endpoint,
    vpn_installation::Installation,
    vpn_process::JobChild,
    vpn_profiles::{LaunchFiles, ProfileStore, ProfileStoreError},
};
use ssk_vpnctl::{
    ChildProcess, ManagedProcess, ManagementPassword, ProcessSnapshot, ProcessStage, Profile,
    Stage, TcpTransport, Timeouts,
};
use std::{
    ffi::OsString,
    io,
    os::windows::ffi::OsStrExt,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum LaunchFailure {
    Cancelled,
    IdentityAudit,
    Store(ProfileStoreError),
    Installation(InstallationError),
    Random,
    Io(io::ErrorKind),
    StartupTimeout,
    ChildExited,
    Management(ssk_vpnctl::Failure),
    ManagementExited,
}
#[derive(Debug)]
pub struct LaunchError {
    pub reason: LaunchFailure,
    /// None: no child was created. Some(false): termination requested, OS exit
    /// not confirmed within the cleanup deadline (job still closes on drop).
    pub process_exit_confirmed: Option<bool>,
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OpenVPN preparation failed: {:?}; exit confirmed: {:?}",
            self.reason, self.process_exit_confirmed
        )
    }
}
impl std::error::Error for LaunchError {}
fn early(reason: LaunchFailure) -> LaunchError {
    LaunchError {
        reason,
        process_exit_confirmed: None,
    }
}

/// Live, authenticated management session in HOLD. Continuous poll is mandatory.
/// Field order contains the process before removing files or releasing image locks.
pub struct PreparedVpn {
    process: ManagedProcess<JobChild, TcpTransport>,
    _files: LaunchFiles,
    _installation: Installation,
}
impl PreparedVpn {
    /// Only the authorized broker supplies a profile from its pinned snapshot
    /// and a durable identity callback. There is no unaudited public start path.
    pub(crate) fn prepare_tracked(
        profile: &Profile,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(ssk_netd_helper::vpn::ProcessIdentity) -> bool,
    ) -> Result<Self, LaunchError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(early(LaunchFailure::Cancelled));
        }
        let store = ProfileStore::open().map_err(|e| early(LaunchFailure::Store(e)))?;
        let manifest = store
            .installation_manifest()
            .map_err(|e| early(LaunchFailure::Store(e)))?;
        let installation =
            Installation::open(&manifest).map_err(|e| early(LaunchFailure::Installation(e)))?;
        Self::prepare_with_cancel(
            store,
            installation,
            profile,
            &Win32PathSecurityProbe,
            Timeouts::default(),
            cancelled,
            on_created,
        )
    }

    #[cfg(test)]
    fn prepare_with(
        store: ProfileStore,
        installation: Installation,
        profile: Profile,
        probe: &dyn PathSecurityProbe,
        timeouts: Timeouts,
    ) -> Result<Self, LaunchError> {
        Self::prepare_with_cancel(
            store,
            installation,
            &profile,
            probe,
            timeouts,
            &AtomicBool::new(false),
            &mut |_| true,
        )
    }

    fn prepare_with_cancel(
        store: ProfileStore,
        installation: Installation,
        profile: &Profile,
        probe: &dyn PathSecurityProbe,
        timeouts: Timeouts,
        cancelled: &AtomicBool,
        on_created: &mut dyn FnMut(ssk_netd_helper::vpn::ProcessIdentity) -> bool,
    ) -> Result<Self, LaunchError> {
        if cancelled.load(Ordering::Acquire) {
            return Err(early(LaunchFailure::Cancelled));
        }
        let listener = vpn_endpoint::reserve().map_err(|e| early(LaunchFailure::Io(e.kind())))?;
        let port = listener
            .local_addr()
            .map_err(|e| early(LaunchFailure::Io(e.kind())))?
            .port();
        let mut entropy = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *entropy).map_err(|_| early(LaunchFailure::Random))?;
        let mut secret = Zeroizing::new(Vec::with_capacity(64));
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in entropy.iter() {
            secret.push(HEX[(byte >> 4) as usize]);
            secret.push(HEX[(byte & 15) as usize]);
        }
        let files = store
            .launch_files(profile, &secret, port, probe)
            .map_err(|e| early(LaunchFailure::Store(e)))?;
        let password = ManagementPassword::new(secret.to_vec())
            .map_err(|e| early(LaunchFailure::Management(e)))?;
        drop(secret);
        drop(entropy);
        let args = [
            OsString::from("--config"),
            files.config().as_os_str().to_owned(),
        ];
        let env = environment(installation.directory())
            .map_err(|e| early(LaunchFailure::Io(e.kind())))?;
        if cancelled.load(Ordering::Acquire) {
            return Err(early(LaunchFailure::Cancelled));
        }
        let mut child = JobChild::spawn_suspended(
            &installation.executable(),
            &args,
            installation.directory(),
            &env,
        )
        .map_err(|e| early(LaunchFailure::Io(e.kind())))?;
        let release = (|| {
            let identity = child.identity(files.launch_id)?;
            if !on_created(identity) {
                return Err(LaunchFailure::IdentityAudit);
            }
            if cancelled.load(Ordering::Acquire) {
                return Err(LaunchFailure::Cancelled);
            }
            child.resume()?;
            Ok(())
        })();
        if let Err(reason) = release {
            return Err(LaunchError {
                reason,
                process_exit_confirmed: Some(terminate_child(&mut child)),
            });
        }
        let started = Instant::now();
        let stream = loop {
            let result = (|| {
                if cancelled.load(Ordering::Acquire) {
                    return Err(LaunchFailure::Cancelled);
                }
                if child.try_wait()?.is_some() {
                    return Err(LaunchFailure::ChildExited);
                }
                if started.elapsed() >= timeouts.startup {
                    return Err(LaunchFailure::StartupTimeout);
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        if vpn_endpoint::verify(&stream, &mut child)? {
                            Ok(Some(stream))
                        } else {
                            Ok(None)
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                    Err(error) => Err(LaunchFailure::Io(error.kind())),
                }
            })();
            match result {
                Ok(Some(stream)) => break stream,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(reason) => {
                    return Err(LaunchError {
                        reason,
                        process_exit_confirmed: Some(terminate_child(&mut child)),
                    })
                }
            }
        };
        drop(listener); // exactly one verified peer, never reconnect/reattach
        let transport = TcpTransport::from_loopback_stream(stream).map_err(|e| LaunchError {
            reason: LaunchFailure::Io(e.kind()),
            process_exit_confirmed: Some(terminate_child(&mut child)),
        })?;
        // From here the controller owns the child, transport and termination duty.
        let process =
            ManagedProcess::new_held(child, transport, password, timeouts, Duration::from_secs(2))
                .map_err(|e| LaunchError {
                    reason: LaunchFailure::Management(e),
                    process_exit_confirmed: Some(false),
                })?;
        let mut prepared = Self {
            process,
            _files: files,
            _installation: installation,
        };
        loop {
            let snapshot = prepared.poll();
            let reason = if cancelled.load(Ordering::Acquire) {
                Some(LaunchFailure::Cancelled)
            } else if started.elapsed() >= timeouts.startup {
                Some(LaunchFailure::StartupTimeout)
            } else if let Some(ssk_vpnctl::ProcessFailure::Management(error)) = snapshot.failure {
                Some(LaunchFailure::Management(error))
            } else if snapshot.stage != ProcessStage::Managing {
                Some(LaunchFailure::ManagementExited)
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(LaunchError {
                    reason,
                    process_exit_confirmed: Some(prepared.abort_and_confirm()),
                });
            }
            if snapshot
                .management
                .is_some_and(|s| s.stage == Stage::PreparedHeld)
            {
                return Ok(prepared);
            }
        }
    }

    pub fn poll(&mut self) -> ProcessSnapshot {
        self.process.poll()
    }
    pub fn last_snapshot(&self) -> ProcessSnapshot {
        self.process.last_snapshot()
    }
    pub fn request_stop(&mut self) {
        self.process.request_stop();
    }
    pub fn abort_and_confirm(&mut self) -> bool {
        self.process.abort();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.poll().stage == ProcessStage::Exited {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl From<io::Error> for LaunchFailure {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

fn terminate_child(child: &mut JobChild) -> bool {
    let _ = child.terminate();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn environment(directory: &Path) -> io::Result<Vec<u16>> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;
    let mut windows = vec![0u16; 32768];
    // SAFETY: allocated UTF-16 output buffer and its exact capacity.
    let count =
        unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    if count == 0 || count >= windows.len() {
        return Err(io::Error::last_os_error());
    }
    windows.truncate(count);
    let mut out = Vec::new();
    // Remove ambient OpenSSL configuration and pin its provider directory. The
    // selected distribution's remaining DLL-load behavior still needs VM validation.
    for (key, value) in [
        ("OPENSSL_CONF", "NUL".encode_utf16().collect::<Vec<_>>()),
        (
            "OPENSSL_MODULES",
            directory.as_os_str().encode_wide().collect(),
        ),
        ("SystemRoot", windows.clone()),
        ("WINDIR", windows),
    ] {
        out.extend(key.encode_utf16());
        out.push(b'=' as u16);
        out.extend(value);
        out.push(0);
    }
    out.push(0);
    Ok(out)
}

#[cfg(test)]
#[path = "vpn_launch_tests.rs"]
mod tests;
