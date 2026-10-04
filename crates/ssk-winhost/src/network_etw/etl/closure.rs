//! Consistency checks for an UNTRUSTED controller sidecar, never an attestation.
//! No controller or provider-enabling API is called by this module.
#[cfg(any(windows, test))]
use super::super::session::{
    Properties, Snapshot, PROCESS_NETWORK_FLAGS as ENABLE_FLAGS, SYSTEM_LOGGER,
};
use super::EtlReport;
#[cfg(any(windows, test))]
use super::MAX_FILE_BYTES;
use serde::{Deserialize, Serialize};
#[cfg(any(windows, test))]
use {
    sha2::{Digest, Sha256},
    std::io::{self, Read},
};

#[cfg(any(windows, test))]
pub(super) const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Source {
    SyntheticFixture,
    UnverifiedControllerExport,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Profile {
    ProcessNetworkV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
pub(super) struct Receipt {
    schema_version: u32,
    source: Source,
    profile: Profile,
    file: FileBinding,
    intent: Intent,
    // These are declarations, not evidence of ownership or uninterrupted state.
    owns_session_from_start: Option<bool>,
    configuration_unchanged: Option<bool>,
    start_status: Option<u32>,
    query_after_start: Option<Snapshot>,
    stop: Option<Snapshot>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
struct FileBinding {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg(any(windows, test))]
struct Intent {
    session_guid: String,
    clock_type: u32,
    log_file_mode: u32,
    enable_flags: u32,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
enum Issue {
    FileBindingMismatch,
    UnsupportedProfileConfiguration,
    SessionOwnershipUndeclared,
    ConfigurationContinuityUndeclared,
    StartUnsuccessfulOrMissing,
    InitialQueryUnsuccessfulOrMissing,
    StopUnsuccessfulOrMissing,
    SessionConfigurationMismatch,
    LossReported,
    CounterRegression,
    NoBuffersWritten,
    EtlHeaderMismatch,
    EtlUnavailable,
}

#[derive(Debug, Serialize)]
pub struct ClosureReport {
    schema_version: u32,
    status: &'static str,
    source: Source,
    declared_profile: Profile,
    file_sha256: String,
    file_binding_matches: bool,
    issues: Vec<Issue>,
    controller_authenticity_verified: bool,
    provider_continuity_verified: bool,
    loss_completeness_verified: bool,
    coverage_verified: bool,
    baseline_compatible: bool,
    enforcement_active: bool,
}

/// Separate schema; the existing ETL report remains at version 2.
#[derive(Debug, Serialize)]
pub struct ClosureInspection {
    schema_version: u32,
    closure: ClosureReport,
    etl: EtlReport,
}

#[cfg(any(windows, test))]
pub(super) fn read(reader: impl Read) -> io::Result<Receipt> {
    let mut bytes = Vec::new();
    reader.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ETL closure exceeds 16 KiB",
        ));
    }
    // Do not echo arbitrary input, paths or serde field names in diagnostics.
    let receipt: Receipt = serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ETL closure schema"))?;
    if receipt.schema_version != 1
        || receipt.file.bytes == 0
        || receipt.file.bytes > MAX_FILE_BYTES
        || receipt.file.sha256.len() != 64
        || !receipt
            .file
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !valid_guid(&receipt.intent.session_guid)
        || [&receipt.query_after_start, &receipt.stop]
            .into_iter()
            .filter_map(|s| s.as_ref()?.properties.as_ref())
            .any(|p| !valid_guid(&p.session_guid))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ETL closure values",
        ));
    }
    Ok(receipt)
}

#[cfg(any(windows, test))]
fn valid_guid(guid: &str) -> bool {
    guid.len() == 36
        && guid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
        && guid
            .bytes()
            .any(|b| (b'1'..=b'9').contains(&b) || (b'a'..=b'f').contains(&b))
}

/// Hash the same pinned handle that remains held during native processing.
#[cfg(any(windows, test))]
pub(in crate::network_etw) fn fingerprint(
    reader: impl Read,
    expected_bytes: u64,
) -> io::Result<String> {
    if expected_bytes == 0 || expected_bytes > MAX_FILE_BYTES {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut reader = reader.take(expected_bytes + 1);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        hasher.update(&buffer[..n]);
    }
    if total != expected_bytes {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Only the private synthetic capture producer uses this constructor. It cannot
/// emit an authenticated source or a system-profile success.
#[cfg(windows)]
pub(in crate::network_etw) fn private_receipt(
    bytes: u64,
    sha256: String,
    guid: String,
    initial: Snapshot,
    stop: Snapshot,
) -> io::Result<Vec<u8>> {
    let receipt = Receipt {
        schema_version: 1,
        source: Source::SyntheticFixture,
        profile: Profile::ProcessNetworkV1,
        file: FileBinding { bytes, sha256 },
        intent: Intent {
            session_guid: guid,
            clock_type: 1,
            log_file_mode: super::super::session::PRIVATE_MODE,
            enable_flags: 0,
        },
        owns_session_from_start: Some(true),
        configuration_unchanged: Some(true),
        start_status: Some(0),
        query_after_start: Some(initial),
        stop: Some(stop),
    };
    serde_json::to_vec_pretty(&receipt).map_err(io::Error::other)
}

#[cfg(any(windows, test))]
fn properties(snapshot: &Option<Snapshot>) -> Option<&Properties> {
    snapshot
        .as_ref()
        .filter(|s| s.api_status == 0)?
        .properties
        .as_ref()
}

#[cfg(any(windows, test))]
pub(super) fn check(receipt: Receipt, sha256: String, etl: EtlReport) -> ClosureInspection {
    let mut issues = Vec::new();
    let binding = receipt.file.sha256 == sha256 && receipt.file.bytes == etl.source_file_bytes;
    if !binding {
        issues.push(Issue::FileBindingMismatch);
    }
    let intent = &receipt.intent;
    // Permit the documented sequential aliases 0 and 1, but no other mode bits.
    // QPC only in v1. The built-in kernel/global logger identities are excluded.
    if intent.enable_flags != ENABLE_FLAGS
        || intent.log_file_mode & !1 != SYSTEM_LOGGER
        || intent.clock_type != 1
        || [
            "9e814aad-3204-11d2-9a82-006008a86939",
            "e8908abc-aa84-11d2-9a93-00805f85d7c6",
        ]
        .contains(&intent.session_guid.as_str())
    {
        issues.push(Issue::UnsupportedProfileConfiguration);
    }
    if receipt.owns_session_from_start != Some(true) {
        issues.push(Issue::SessionOwnershipUndeclared);
    }
    if receipt.configuration_unchanged != Some(true) {
        issues.push(Issue::ConfigurationContinuityUndeclared);
    }
    if receipt.start_status != Some(0) {
        issues.push(Issue::StartUnsuccessfulOrMissing);
    }
    let initial = properties(&receipt.query_after_start);
    let stopped = properties(&receipt.stop);
    if initial.is_none() {
        issues.push(Issue::InitialQueryUnsuccessfulOrMissing);
    }
    // ERROR_MORE_DATA may stop the logger, but does not supply complete evidence.
    if stopped.is_none() {
        issues.push(Issue::StopUnsuccessfulOrMissing);
    }
    let snapshots = [initial, stopped];
    if snapshots.into_iter().flatten().any(|p| {
        p.session_guid != intent.session_guid
            || p.enable_flags != intent.enable_flags
            || p.log_file_mode & !1 != intent.log_file_mode & !1
    }) {
        issues.push(Issue::SessionConfigurationMismatch);
    }
    if snapshots
        .into_iter()
        .flatten()
        .any(|p| p.events_lost != 0 || p.log_buffers_lost != 0 || p.realtime_buffers_lost != 0)
    {
        issues.push(Issue::LossReported);
    }
    if let (Some(a), Some(b)) = (initial, stopped) {
        if b.events_lost < a.events_lost
            || b.log_buffers_lost < a.log_buffers_lost
            || b.realtime_buffers_lost < a.realtime_buffers_lost
            || b.buffers_written < a.buffers_written
        {
            issues.push(Issue::CounterRegression);
        }
    }
    if stopped.is_some_and(|p| p.buffers_written == 0) {
        issues.push(Issue::NoBuffersWritten);
    }
    if etl.observation.header.as_ref().is_none_or(|h| {
        h.log_file_mode & !1 != intent.log_file_mode & !1 || h.clock_type != intent.clock_type
    }) {
        issues.push(Issue::EtlHeaderMismatch);
    }
    if etl.status != "decoded_file" {
        issues.push(Issue::EtlUnavailable);
    }
    let closure = ClosureReport {
        schema_version: 1,
        status: if issues.is_empty() {
            "consistent_unverified"
        } else {
            "unavailable"
        },
        source: receipt.source,
        declared_profile: receipt.profile,
        file_sha256: sha256,
        file_binding_matches: binding,
        issues,
        controller_authenticity_verified: false,
        provider_continuity_verified: false,
        loss_completeness_verified: false,
        coverage_verified: false,
        baseline_compatible: false,
        enforcement_active: false,
    };
    ClosureInspection {
        schema_version: 1,
        closure,
        etl,
    }
}

#[cfg(test)]
mod tests;
