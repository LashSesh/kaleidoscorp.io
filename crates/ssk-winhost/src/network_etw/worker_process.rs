//! Shared supervision for diagnostic child processes, never PID-based killing.
use crate::vpn_process::JobChild;
use serde::Serialize;
use ssk_vpnctl::ChildProcess;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, Read},
    mem::{size_of, zeroed},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{SetHandleInformation, ERROR_BROKEN_PIPE, HANDLE_FLAG_INHERIT},
    System::{
        JobObjects::*,
        Pipes::{CreatePipe, PeekNamedPipe},
    },
};

const CLEANUP_DEADLINE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Cause {
    Launch,
    Deadline,
    OutputLimit,
    Pipe,
    ProcessQuery,
    WorkerExit,
}

#[derive(Debug, Default, Serialize)]
pub(super) struct ProcessEvidence {
    pub started: bool,
    pub exit_observed: bool,
    pub exit_code: Option<u32>,
    pub termination_requested: bool,
    pub termination_call_succeeded: Option<bool>,
}

#[derive(Debug)]
pub(super) struct RunFailure {
    pub error: io::Error,
    pub cause: Cause,
    pub process: ProcessEvidence,
}

pub(super) struct Completion {
    pub bytes: Vec<u8>,
    pub process: ProcessEvidence,
}

pub(super) fn require_containment() -> io::Result<()> {
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    // NULL selects this process's immediate job, with exact output storage.
    if unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic worker requires containment",
        ));
    }
    let required = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    if limits.BasicLimitInformation.LimitFlags & required != required
        || limits.BasicLimitInformation.ActiveProcessLimit != 1
        || limits.ProcessMemoryLimit == 0
        || limits.ProcessMemoryLimit > 256 * 1024 * 1024
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "diagnostic worker requires containment",
        ));
    }
    Ok(())
}

fn inherited(handle: &OwnedHandle) -> io::Result<()> {
    if unsafe {
        SetHandleInformation(
            handle.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn launch(executable: &Path, args: &[OsString], cwd: &Path) -> io::Result<(JobChild, File)> {
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 4096) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe { OwnedHandle::from_raw_handle(read) };
    let write = unsafe { OwnedHandle::from_raw_handle(write) };
    inherited(&write)?;
    let null: OwnedHandle = OpenOptions::new()
        .read(true)
        .write(true)
        .open("NUL")?
        .into();
    inherited(&null)?;
    // Only stdout and NUL are inherited; atomic JOB_LIST attachment applies
    // before any child instruction. No job or process handle is inherited.
    let child = JobChild::spawn_diagnostic(executable, args, cwd, &write, &null)?;
    Ok((child, File::from(read)))
}

fn available(pipe: &File) -> io::Result<u32> {
    let mut bytes = 0;
    if unsafe {
        PeekNamedPipe(
            pipe.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut bytes,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_BROKEN_PIPE as i32) {
            return Err(error);
        }
    }
    Ok(bytes)
}

fn collect(
    child: &mut JobChild,
    pipe: &mut File,
    started: Instant,
    deadline: Duration,
    limit: usize,
) -> Result<Vec<u8>, (Cause, io::Error)> {
    let mut bytes = Vec::new();
    loop {
        if started.elapsed() >= deadline {
            return Err((
                Cause::Deadline,
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "diagnostic worker exceeded its time limit",
                ),
            ));
        }
        let count = available(pipe).map_err(|e| (Cause::Pipe, e))? as usize;
        if count > 0 {
            if count > limit.saturating_sub(bytes.len()) {
                return Err((
                    Cause::OutputLimit,
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "diagnostic worker exceeded its output limit",
                    ),
                ));
            }
            let mut buffer = [0u8; 4096];
            let n = pipe
                .read(&mut buffer[..count.min(4096)])
                .map_err(|e| (Cause::Pipe, e))?;
            if n == 0 {
                return Err((Cause::Pipe, io::ErrorKind::UnexpectedEof.into()));
            }
            bytes.extend_from_slice(&buffer[..n]);
            continue;
        }
        if let Some(code) = child.try_wait().map_err(|e| (Cause::ProcessQuery, e))? {
            // Drain the race between the previous peek and process exit.
            if available(pipe).map_err(|e| (Cause::Pipe, e))? != 0 {
                continue;
            }
            if code != 0 {
                return Err((
                    Cause::WorkerExit,
                    io::Error::new(io::ErrorKind::InvalidData, "diagnostic worker failed"),
                ));
            }
            return Ok(bytes);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn cleanup(child: &mut impl ChildProcess) -> ProcessEvidence {
    let mut evidence = ProcessEvidence {
        started: true,
        ..Default::default()
    };
    if let Ok(Some(code)) = child.try_wait() {
        evidence.exit_observed = true;
        evidence.exit_code = Some(code);
        return evidence;
    }
    evidence.termination_requested = true;
    evidence.termination_call_succeeded = Some(child.terminate().is_ok());
    let deadline = Instant::now() + CLEANUP_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(code)) => {
                evidence.exit_observed = true;
                evidence.exit_code = Some(code);
                break;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            _ => break,
        }
    }
    // The owning job still closes on return. Do not claim that this final
    // fallback was observed if the bounded wait above did not see process exit.
    evidence
}

pub(super) fn run(
    executable: &Path,
    args: &[OsString],
    cwd: &Path,
    deadline: Duration,
    limit: usize,
) -> Result<Completion, RunFailure> {
    let started = Instant::now();
    let (mut child, mut pipe) = launch(executable, args, cwd).map_err(|error| RunFailure {
        error,
        cause: Cause::Launch,
        process: ProcessEvidence::default(),
    })?;
    match collect(&mut child, &mut pipe, started, deadline, limit) {
        Ok(bytes) => Ok(Completion {
            bytes,
            process: ProcessEvidence {
                started: true,
                exit_observed: true,
                exit_code: Some(0),
                ..Default::default()
            },
        }),
        Err((cause, error)) => Err(RunFailure {
            error,
            cause,
            process: cleanup(&mut child),
        }),
    }
}

#[cfg(test)]
mod tests;
