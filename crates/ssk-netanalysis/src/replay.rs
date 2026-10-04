//! Strict, bounded replay input. Reads observations; never interprets commands,
//! rule actions, paths to executables or model code from a fixture.

use crate::{
    Assessment, Baseline, BaselineConfig, ConfigError, Observation, Provenance, Scope,
    WindowAnalyzer, MAX_EVENTS,
};
use serde::{Deserialize, Serialize};
use std::io::Read;

pub const MAX_REPLAY_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayInput {
    pub schema_version: u32,
    pub baseline: BaselineConfig,
    pub scope: Scope,
    pub provenance: Provenance,
    pub start_ms: u64,
    pub first_sequence: u64,
    pub assess_at_ms: u64,
    pub lost_events: u64,
    pub observations: Vec<Observation>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay read failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("replay exceeds byte limit")]
    TooLarge,
    // Do not echo unknown-field names or input text into logs/errors.
    #[error("invalid replay JSON or schema fields")]
    Json,
    #[error("unsupported replay schema version")]
    Version,
    #[error("replay exceeds event limit")]
    TooManyEvents,
    #[error(transparent)]
    Configuration(#[from] ConfigError),
}

pub fn read_and_analyze(reader: impl Read) -> Result<Assessment, ReplayError> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_REPLAY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REPLAY_BYTES {
        return Err(ReplayError::TooLarge);
    }
    let input: ReplayInput = serde_json::from_slice(&bytes).map_err(|_| ReplayError::Json)?;
    analyze(input)
}

pub fn analyze(input: ReplayInput) -> Result<Assessment, ReplayError> {
    if input.schema_version != 1 {
        return Err(ReplayError::Version);
    }
    if input.observations.len() > MAX_EVENTS as usize {
        return Err(ReplayError::TooManyEvents);
    }
    let mut analyzer = WindowAnalyzer::new(
        Baseline::new(input.baseline)?,
        input.scope,
        input.provenance,
        input.start_ms,
        input.first_sequence,
    )?;
    analyzer.report_event_loss(input.lost_events);
    for event in &input.observations {
        if analyzer.observe(event).is_err() {
            // The first fault is sticky and reported as Unavailable; later
            // events cannot repair or sanitize this window.
            break;
        }
    }
    Ok(analyzer.assess(input.assess_at_ms))
}
