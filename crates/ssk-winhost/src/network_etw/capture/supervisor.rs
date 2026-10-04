//! The parent owns the job. Child messages cannot assert cleanup or authority.
use super::super::worker_process::{self, Cause, Completion, ProcessEvidence, RunFailure};
use super::{windows, PrivateFixtureReport};
use serde::{Deserialize, Serialize};
use std::{ffi::OsString, io, path::Path, time::Duration};

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_MESSAGE_BYTES: usize = 4096;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerMessage {
    pub schema_version: u32,
    pub events_submitted: u32,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Failure {
    Worker { cause: Cause },
    Protocol,
    Artifacts,
}

#[derive(Serialize)]
struct Supervision {
    schema_version: u32,
    status: &'static str,
    failure: Option<Failure>,
    process: ProcessEvidence,
    worker_completion_accepted: bool,
    session_cleanup_verified: bool,
    system_capture_available: bool,
    enforcement_active: bool,
}

fn parse(bytes: &[u8]) -> io::Result<WorkerMessage> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let message: WorkerMessage =
        serde_json::from_slice(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
    if message.schema_version != 1 || message.events_submitted != super::controller::EVENT_COUNT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(message)
}

fn finish(
    directory: &Path,
    result: Result<Completion, RunFailure>,
) -> io::Result<PrivateFixtureReport> {
    let (process, failure, error) = match result {
        Err(f) => (
            f.process,
            Some(Failure::Worker { cause: f.cause }),
            Some(f.error),
        ),
        Ok(completion) => {
            if parse(&completion.bytes).is_err() {
                (
                    completion.process,
                    Some(Failure::Protocol),
                    Some(io::ErrorKind::InvalidData.into()),
                )
            } else if let Err(error) = windows::check_artifact_sizes(directory) {
                (completion.process, Some(Failure::Artifacts), Some(error))
            } else {
                (completion.process, None, None)
            }
        }
    };
    let accepted = failure.is_none();
    windows::write_new(
        &directory.join("supervision.json"),
        &serde_json::to_vec_pretty(&Supervision {
            schema_version: 1,
            status: if accepted {
                "worker_completed"
            } else {
                "unavailable"
            },
            failure,
            process,
            worker_completion_accepted: accepted,
            // Process exit, including forced exit, is NOT a verified ETW stop.
            session_cleanup_verified: false,
            system_capture_available: false,
            enforcement_active: false,
        })?,
    )?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(PrivateFixtureReport {
        schema_version: 2,
        source: "synthetic_private_in_process",
        status: "private_fixture_written",
        etl_file: "recording.etl",
        closure_file: "closure.json",
        controller_file: "controller.json",
        supervision_file: "supervision.json",
        events_submitted: super::controller::EVENT_COUNT,
        system_capture_available: false,
        coverage_verified: false,
        enforcement_active: false,
    })
}

pub(super) fn fixture(directory: &Path) -> io::Result<PrivateFixtureReport> {
    let executable = std::env::current_exe()?;
    let directory = windows::output_directory(directory)?;
    let args = [
        OsString::from("--private-capture-worker"),
        directory.clone().into_os_string(),
    ];
    let result = worker_process::run(
        &executable,
        &args,
        executable.parent().ok_or(io::ErrorKind::InvalidInput)?,
        DEADLINE,
        MAX_MESSAGE_BYTES,
    );
    finish(&directory, result)
}

#[cfg(test)]
mod tests;
