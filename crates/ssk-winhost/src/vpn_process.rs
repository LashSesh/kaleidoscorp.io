//! Windows child containment used by held VPN preparation. Atomic job assignment
//! prevents uncontained execution; tracked launches stay suspended until audited.
use ssk_vpnctl::ChildProcess;
use std::{
    ffi::{OsStr, OsString},
    io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::{JobObjects::*, Threading::*},
};

/// One child in an unnamed, non-inheritable kill-on-close job. Atomic job
/// assignment at CreateProcess avoids an orphan window between spawn and assign.
/// ActiveProcessLimit=1 disallows descendants; no breakaway flags are enabled.
/// Owns process handles for its entire lifetime, so PID reuse is irrelevant.
pub struct JobChild {
    job: OwnedHandle,
    process: OwnedHandle,
    pid: u32,
    suspended_thread: Option<OwnedHandle>,
}

impl JobChild {
    /// Low-level same-token launch, no shell, hidden console, empty environment,
    /// no inherited handles. Requires Windows 10+ JOB_LIST support, fails closed
    /// if an enclosing job disallows nesting. The caller owns launch policy.
    pub fn spawn(executable: &Path, args: &[OsString], working_dir: &Path) -> io::Result<Self> {
        Self::spawn_with_environment(executable, args, working_dir, &[0u16, 0])
    }

    pub(crate) fn spawn_with_environment(
        executable: &Path,
        args: &[OsString],
        working_dir: &Path,
        environment: &[u16],
    ) -> io::Result<Self> {
        Self::spawn_inner(executable, args, working_dir, environment, false, None)
    }

    pub(crate) fn spawn_suspended(
        executable: &Path,
        args: &[OsString],
        working_dir: &Path,
        environment: &[u16],
    ) -> io::Result<Self> {
        Self::spawn_inner(executable, args, working_dir, environment, true, None)
    }

    /// Diagnostic worker only: inherit exactly stdout and a NUL handle, with a
    /// 256 MiB commit limit. VPN launches retain their original no-inheritance path.
    pub(crate) fn spawn_diagnostic(
        executable: &Path,
        args: &[OsString],
        working_dir: &Path,
        stdout: &OwnedHandle,
        null: &OwnedHandle,
    ) -> io::Result<Self> {
        Self::spawn_inner(
            executable,
            args,
            working_dir,
            &[0, 0],
            false,
            Some([stdout.as_raw_handle(), null.as_raw_handle()]),
        )
    }

    fn spawn_inner(
        executable: &Path,
        args: &[OsString],
        working_dir: &Path,
        environment: &[u16],
        suspended: bool,
        diagnostic_handles: Option<[HANDLE; 2]>,
    ) -> io::Result<Self> {
        if environment.len() < 2 || !environment.ends_with(&[0, 0]) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if !executable.is_absolute() || !working_dir.is_absolute() || args.len() > 64 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let application = wide(executable.as_os_str())?;
        let cwd = wide(working_dir.as_os_str())?;
        let mut command = Vec::new();
        quote(executable.as_os_str(), &mut command)?;
        for arg in args {
            command.push(b' ' as u16);
            quote(arg, &mut command)?;
        }
        if command.len() >= 32767 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        command.push(0);
        // SAFETY: unnamed job with default security, no inheritable attributes.
        let raw_job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw_job.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: unique ownership of a successful API result.
        let job = unsafe { OwnedHandle::from_raw_handle(raw_job) };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if diagnostic_handles.is_some() {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            limits.ProcessMemoryLimit = 256 * 1024 * 1024;
        }
        // SAFETY: live job and initialized struct with its exact size.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = Attributes::job_list(&raw_job, diagnostic_handles.as_ref())?;
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.pointer();
        if let Some([stdout, null]) = diagnostic_handles {
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdOutput = stdout;
            startup.StartupInfo.hStdInput = null;
            startup.StartupInfo.hStdError = null;
        }
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: every pointer references a live, correctly sized object;
        // command is writable/NUL terminated; application/cwd/environment are
        // bounded/NUL terminated. JOB_LIST attaches the job before execution.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                i32::from(diagnostic_handles.is_some()),
                CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | EXTENDED_STARTUPINFO_PRESENT
                    | if suspended { CREATE_SUSPENDED } else { 0 },
                environment.as_ptr().cast(),
                cwd.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both handles were returned by successful CreateProcessW and
        // are uniquely owned. The job closes on any subsequent unwinding path.
        let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
        let thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
        Ok(Self {
            job,
            process,
            pid: info.dwProcessId,
            suspended_thread: suspended.then_some(thread),
        })
    }
    pub(crate) fn identity(
        &self,
        launch_id: [u8; 16],
    ) -> io::Result<ssk_netd_helper::vpn::ProcessIdentity> {
        Ok(ssk_netd_helper::vpn::ProcessIdentity {
            pid: self.pid,
            created_at: creation_time(self.process.as_raw_handle())?,
            launch_id,
        })
    }

    pub(crate) fn resume(&mut self) -> io::Result<()> {
        let thread = self
            .suspended_thread
            .take()
            .ok_or(io::ErrorKind::InvalidInput)?;
        // SAFETY: owned primary thread created suspended; expected suspend count 1.
        // Any unexpected state is fatal and the caller terminates the owned job.
        if unsafe { ResumeThread(thread.as_raw_handle()) } != 1 {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }
}

fn creation_time(process: HANDLE) -> io::Result<u64> {
    let mut times: [FILETIME; 4] = unsafe { zeroed() };
    // SAFETY: live process with query rights and four disjoint writable FILETIMEs.
    if unsafe {
        GetProcessTimes(
            process,
            &mut times[0],
            &mut times[1],
            &mut times[2],
            &mut times[3],
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((u64::from(times[0].dwHighDateTime) << 32) | u64::from(times[0].dwLowDateTime))
}

/// This reopened handle can only query and wait. It has no termination, thread,
/// memory-write or job rights. PID reuse is evidence that the original ended;
/// it must never cause an action against the replacement process.
pub(crate) fn observe_exit(
    identity: ssk_netd_helper::vpn::ProcessIdentity,
) -> Result<ssk_netd_helper::vpn::RecoveryEvidence, ssk_netd_helper::vpn::RecoveryFailure> {
    use ssk_netd_helper::vpn::{RecoveryEvidence as Evidence, RecoveryFailure as Failure};
    if !identity.valid() {
        return Err(Failure::MissingIdentity);
    }
    // SAFETY: fixed read-only rights, no handle inheritance, validated nonzero PID.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            identity.pid,
        )
    };
    if raw.is_null() {
        return if io::Error::last_os_error().raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32)
        {
            Ok(Evidence::PidAbsent)
        } else {
            Err(Failure::ProcessQuery)
        };
    }
    // SAFETY: unique ownership of the successful OpenProcess result.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    let created = creation_time(process.as_raw_handle()).map_err(|_| Failure::ProcessQuery)?;
    if created != identity.created_at {
        return Ok(Evidence::PidReused);
    }
    // SAFETY: live owned process handle with SYNCHRONIZE; nonblocking wait.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(Evidence::ProcessExited),
        WAIT_TIMEOUT => Err(Failure::ProcessAlive),
        _ => Err(Failure::ProcessQuery),
    }
}

impl ChildProcess for JobChild {
    fn id(&self) -> u32 {
        self.pid
    }
    fn try_wait(&mut self) -> io::Result<Option<u32>> {
        // SAFETY: process handle owned by self; zero timeout never blocks.
        match unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                // SAFETY: live process handle and writable exit-code output.
                if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(code))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
    fn terminate(&mut self) -> io::Result<()> {
        // SAFETY: self owns this job and all its processes. Does not wait.
        if unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
// No custom Drop: closing the last job handle also works on abrupt owner exit.

struct Attributes {
    storage: Vec<usize>,
}
impl Attributes {
    fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
    }
    fn job_list(job: &HANDLE, handles: Option<&[HANDLE; 2]>) -> io::Result<Self> {
        let count = if handles.is_some() { 2 } else { 1 };
        let mut bytes = 0;
        // SAFETY: documented sizing call; first call is expected to fail.
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 64 * 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        let pointer = storage.as_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: allocation is pointer-aligned and at least the required size.
        if unsafe { InitializeProcThreadAttributeList(pointer, count, 0, &mut bytes) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self { storage };
        // SAFETY: the list is initialized; caller keeps job's HANDLE storage
        // alive through CreateProcess; exactly one handle is supplied.
        if unsafe {
            UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                (job as *const HANDLE).cast(),
                size_of::<HANDLE>(),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(handles) = handles {
            // SAFETY: two live inheritable handles; backing array lives through
            // CreateProcess. The explicit list excludes every other handle.
            if unsafe {
                UpdateProcThreadAttribute(
                    result.pointer(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr().cast(),
                    size_of::<[HANDLE; 2]>(),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(result)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: successful initialization is required to construct Self.
        unsafe {
            DeleteProcThreadAttributeList(self.pointer());
        }
    }
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut out: Vec<u16> = value.encode_wide().collect();
    if out.contains(&0) || out.len() >= 32767 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    out.push(0);
    Ok(out)
}

// Windows CRT quoting, operating on UTF-16 (no lossy path conversion). Every
// arg is quoted; backslashes before quotes and the closing quote are doubled.
fn quote(value: &OsStr, out: &mut Vec<u16>) -> io::Result<()> {
    let value = wide(value)?;
    out.push(b'"' as u16);
    let mut slashes = 0;
    for &unit in &value[..value.len() - 1] {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        let count = if unit == b'"' as u16 {
            slashes * 2 + 1
        } else {
            slashes
        };
        out.extend(std::iter::repeat_n(b'\\' as u16, count));
        slashes = 0;
        out.push(unit);
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    if out.len() >= 32767 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}
