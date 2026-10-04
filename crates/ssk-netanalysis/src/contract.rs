use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const MAX_EVENTS: u32 = 4096;
pub const MAX_WINDOW_MS: u64 = 60_000;

/// Integer-only thresholds: neither NaN nor an uncalibrated probability is an
/// admissible configuration value. Rates use the entire completed window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineConfig {
    pub window_ms: u64,
    pub valid_for_ms: u64,
    pub max_events: u32,
    pub min_events: u32,
    pub max_attempts_per_second: u32,
    pub min_attempts_for_failure_rate: u32,
    /// 100 basis points = 1 percent. A threshold of 10,000 is valid.
    pub max_failed_basis_points: u16,
    pub max_sent_bytes_per_second: u64,
    pub min_sent_bytes_for_imbalance: u64,
    pub max_sent_to_received_ratio: u32,
}

impl Default for BaselineConfig {
    /// Demonstration values, not measured malware-detection thresholds.
    fn default() -> Self {
        Self {
            window_ms: 10_000,
            valid_for_ms: 5_000,
            max_events: MAX_EVENTS,
            min_events: 1,
            max_attempts_per_second: 20,
            min_attempts_for_failure_rate: 10,
            max_failed_basis_points: 5000,
            max_sent_bytes_per_second: 1_048_576,
            min_sent_bytes_for_imbalance: 1_048_576,
            max_sent_to_received_ratio: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid baseline field: {0}")]
    InvalidField(&'static str),
    #[error("invalid scope: bounded ASCII identifiers and nonzero endpoint port required")]
    InvalidScope,
    #[error("window time range overflows")]
    TimeOverflow,
}

/// Immutable validated parameters with a content-derived ID. The ID detects a
/// different baseline; it is neither a signature nor evidence of model quality.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub(crate) config: BaselineConfig,
    pub(crate) id: String,
}

impl Baseline {
    pub fn new(config: BaselineConfig) -> Result<Self, ConfigError> {
        let checks = [
            (
                (1000..=MAX_WINDOW_MS).contains(&config.window_ms),
                "window_ms",
            ),
            (
                (1..=MAX_WINDOW_MS).contains(&config.valid_for_ms),
                "valid_for_ms",
            ),
            ((1..=MAX_EVENTS).contains(&config.max_events), "max_events"),
            (
                (1..=config.max_events).contains(&config.min_events),
                "min_events",
            ),
            (
                config.max_attempts_per_second > 0,
                "max_attempts_per_second",
            ),
            (
                (1..=config.max_events).contains(&config.min_attempts_for_failure_rate),
                "min_attempts_for_failure_rate",
            ),
            (
                config.max_failed_basis_points <= 10_000,
                "max_failed_basis_points",
            ),
            (
                config.max_sent_bytes_per_second > 0,
                "max_sent_bytes_per_second",
            ),
            (
                config.min_sent_bytes_for_imbalance > 0,
                "min_sent_bytes_for_imbalance",
            ),
            (
                config.max_sent_to_received_ratio > 0,
                "max_sent_to_received_ratio",
            ),
        ];
        for (valid, field) in checks {
            if !valid {
                return Err(ConfigError::InvalidField(field));
            }
        }
        // Fixed-width little-endian encoding: independent of JSON whitespace
        // and field ordering. The domain/version changes with the algorithm.
        let mut hash = blake3::Hasher::new();
        hash.update(b"ssk-netanalysis/integer-baseline/v1\0");
        for value in [
            config.window_ms,
            config.valid_for_ms,
            u64::from(config.max_events),
            u64::from(config.min_events),
            u64::from(config.max_attempts_per_second),
            u64::from(config.min_attempts_for_failure_rate),
            u64::from(config.max_failed_basis_points),
            config.max_sent_bytes_per_second,
            config.min_sent_bytes_for_imbalance,
            u64::from(config.max_sent_to_received_ratio),
        ] {
            hash.update(&value.to_le_bytes());
        }
        Ok(Self {
            config,
            id: format!("integer-baseline-v1:{}", hash.finalize().to_hex()),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn config(&self) -> &BaselineConfig {
        &self.config
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

/// Caller-declared identity only. A source epoch must change when a producer
/// restarts, and the subject must distinguish process incarnations. No field
/// authenticates a PID, executable, hostname or user. Port/IP are exact, not DNS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub source_epoch: String,
    pub subject: String,
    pub endpoint: SocketAddr,
    pub transport: Transport,
}

impl Scope {
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        fn identifier(s: &str, max: usize) -> bool {
            !s.is_empty()
                && s.len() <= max
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
        }
        if !identifier(&self.source_epoch, 64)
            || !identifier(&self.subject, 128)
            || self.endpoint.port() == 0
        {
            return Err(ConfigError::InvalidScope);
        }
        Ok(())
    }
}

/// There is intentionally no `Verified`/`Trusted` variant that a JSON document
/// could self-assert. Synthetic and unverified evidence can be analyzed, but
/// neither is suitable to satisfy a mandatory live security check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    SyntheticReplay,
    UnverifiedObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Signal {
    /// One completed attempt, emitted once by the producer. Outstanding
    /// attempts and failure causes are outside this baseline's feature set.
    ConnectionAttempt { failed: bool },
    /// Deltas, not lifetime socket counters; both directions are relative to
    /// the declared subject. Retransmission/accounting semantics belong to the
    /// producer's feature schema and must be fixed before live integration.
    Transfer {
        sent_bytes: u64,
        received_bytes: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub scope: Scope,
    pub sequence: u64,
    pub at_ms: u64,
    pub signal: Signal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    #[error("observation scope mismatch")]
    ScopeMismatch,
    #[error("baseline mismatch")]
    BaselineMismatch,
    #[error("source reported event loss")]
    EventLoss,
    #[error("gap, duplicate or out-of-order sequence")]
    SequenceDiscontinuity,
    #[error("time moved backwards")]
    ClockRegression,
    #[error("observation outside the window")]
    OutsideWindow,
    #[error("event budget exhausted")]
    EventLimit,
    #[error("counter overflow")]
    CounterOverflow,
    #[error("observation window is incomplete")]
    IncompleteWindow,
    #[error("assessment has expired")]
    Expired,
    #[error("not enough observations")]
    InsufficientSamples,
}
