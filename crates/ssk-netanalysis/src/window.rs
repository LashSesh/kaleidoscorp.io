use crate::{Baseline, ConfigError, Observation, Provenance, Scope, Signal, UnavailableReason};
use serde::Serialize;

pub const FEATURE_SCHEMA: &str = "ssk-network-window-v1";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Metrics {
    pub accepted_events: u32,
    pub completed_attempts: u64,
    pub failed_attempts: u64,
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// Threshold crossings, not malware labels or probabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Finding {
    AttemptRateExceeded,
    FailureRatioExceeded,
    SentRateExceeded,
    SentReceivedImbalance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verdict {
    NoAnomalyObserved,
    Suspicious { findings: Vec<Finding> },
    Unavailable { reason: UnavailableReason },
}

impl Verdict {
    fn unavailable(reason: UnavailableReason) -> Self {
        Self::Unavailable { reason }
    }
}

/// An immutable, advisory snapshot. Deliberately not deserializable: a report
/// imported from JSON must not become an internally computed assessment.
/// No assessment is a verified identity or an admission capability.
///
/// ```compile_fail
/// use ssk_netanalysis::Assessment;
/// let assessment: Assessment = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    schema_version: u32,
    feature_schema: &'static str,
    baseline_id: String,
    baseline: crate::BaselineConfig,
    scope: Scope,
    provenance: Provenance,
    advisory_only: bool,
    identity_verified: bool,
    coverage_verified: bool,
    enforcement_active: bool,
    window_start_ms: u64,
    window_end_ms: u64,
    assessed_at_ms: u64,
    expires_at_ms: u64,
    metrics: Metrics,
    verdict: Verdict,
}

impl Assessment {
    /// Historical outcome at `assessed_at_ms`. Use `verdict_for` when comparing
    /// a stored snapshot with another scope, baseline or logical time.
    pub fn snapshot_verdict(&self) -> &Verdict {
        &self.verdict
    }

    pub fn metrics(&self) -> Metrics {
        self.metrics
    }

    pub fn baseline_id(&self) -> &str {
        &self.baseline_id
    }

    /// Recheck binding and freshness; this never grants a connection. Logical
    /// time must come from the same monotonic source epoch as the window.
    pub fn verdict_for(&self, scope: &Scope, baseline_id: &str, now_ms: u64) -> Verdict {
        if scope != &self.scope {
            return Verdict::unavailable(UnavailableReason::ScopeMismatch);
        }
        if baseline_id != self.baseline_id {
            return Verdict::unavailable(UnavailableReason::BaselineMismatch);
        }
        if now_ms < self.assessed_at_ms {
            return Verdict::unavailable(UnavailableReason::ClockRegression);
        }
        if now_ms >= self.expires_at_ms {
            return Verdict::unavailable(UnavailableReason::Expired);
        }
        self.verdict.clone()
    }
}

/// O(1) retained counters, at most `max_events` accepted observations per
/// window, no retained payloads or event list. First corruption/loss is sticky:
/// ignoring the returned error cannot turn a partial window into clean evidence.
pub struct WindowAnalyzer {
    baseline: Baseline,
    scope: Scope,
    provenance: Provenance,
    start_ms: u64,
    end_ms: u64,
    expires_at_ms: u64,
    next_sequence: u64,
    last_at_ms: u64,
    metrics: Metrics,
    fault: Option<UnavailableReason>,
}

impl WindowAnalyzer {
    pub fn new(
        baseline: Baseline,
        scope: Scope,
        provenance: Provenance,
        start_ms: u64,
        first_sequence: u64,
    ) -> Result<Self, ConfigError> {
        scope.validate()?;
        let end_ms = start_ms
            .checked_add(baseline.config.window_ms)
            .ok_or(ConfigError::TimeOverflow)?;
        let expires_at_ms = end_ms
            .checked_add(baseline.config.valid_for_ms)
            .ok_or(ConfigError::TimeOverflow)?;
        Ok(Self {
            baseline,
            scope,
            provenance,
            start_ms,
            end_ms,
            expires_at_ms,
            next_sequence: first_sequence,
            last_at_ms: start_ms,
            metrics: Metrics::default(),
            fault: None,
        })
    }

    pub fn observe(&mut self, event: &Observation) -> Result<(), UnavailableReason> {
        if let Some(reason) = self.fault {
            return Err(reason);
        }
        let result = self.accept(event);
        if let Err(reason) = result {
            self.fault = Some(reason);
        }
        result
    }

    fn accept(&mut self, event: &Observation) -> Result<(), UnavailableReason> {
        use UnavailableReason as U;
        if event.scope != self.scope {
            return Err(U::ScopeMismatch);
        }
        if event.sequence != self.next_sequence {
            return Err(U::SequenceDiscontinuity);
        }
        if event.at_ms < self.start_ms || event.at_ms >= self.end_ms {
            return Err(U::OutsideWindow);
        }
        if event.at_ms < self.last_at_ms {
            return Err(U::ClockRegression);
        }
        if self.metrics.accepted_events >= self.baseline.config.max_events {
            return Err(U::EventLimit);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(U::CounterOverflow)?;
        // Stage all arithmetic before committing, including both byte counters.
        let mut next = self.metrics;
        match event.signal {
            Signal::ConnectionAttempt { failed } => {
                next.completed_attempts = next
                    .completed_attempts
                    .checked_add(1)
                    .ok_or(U::CounterOverflow)?;
                next.failed_attempts = next
                    .failed_attempts
                    .checked_add(u64::from(failed))
                    .ok_or(U::CounterOverflow)?;
            }
            Signal::Transfer {
                sent_bytes,
                received_bytes,
            } => {
                next.sent_bytes = next
                    .sent_bytes
                    .checked_add(sent_bytes)
                    .ok_or(U::CounterOverflow)?;
                next.received_bytes = next
                    .received_bytes
                    .checked_add(received_bytes)
                    .ok_or(U::CounterOverflow)?;
            }
        }
        next.accepted_events += 1; // bounded by validated max_events <= 4096
        self.metrics = next;
        self.next_sequence = next_sequence;
        self.last_at_ms = event.at_ms;
        Ok(())
    }

    pub fn report_event_loss(&mut self, lost_events: u64) {
        if lost_events != 0 && self.fault.is_none() {
            self.fault = Some(UnavailableReason::EventLoss);
        }
    }

    /// Computes a snapshot. `now_ms >= end_ms` is a caller assertion of a
    /// completed observation window, not proof of complete OS capture.
    pub fn assess(&self, now_ms: u64) -> Assessment {
        let verdict = if let Some(reason) = self.fault {
            Verdict::unavailable(reason)
        } else if now_ms < self.last_at_ms {
            Verdict::unavailable(UnavailableReason::ClockRegression)
        } else if now_ms < self.end_ms {
            Verdict::unavailable(UnavailableReason::IncompleteWindow)
        } else if now_ms >= self.expires_at_ms {
            Verdict::unavailable(UnavailableReason::Expired)
        } else if self.metrics.accepted_events < self.baseline.config.min_events {
            Verdict::unavailable(UnavailableReason::InsufficientSamples)
        } else {
            self.evaluate_thresholds()
        };
        Assessment {
            schema_version: 1,
            feature_schema: FEATURE_SCHEMA,
            baseline_id: self.baseline.id.clone(),
            baseline: self.baseline.config.clone(),
            scope: self.scope.clone(),
            provenance: self.provenance,
            advisory_only: true,
            identity_verified: false,
            coverage_verified: false,
            enforcement_active: false,
            window_start_ms: self.start_ms,
            window_end_ms: self.end_ms,
            assessed_at_ms: now_ms,
            expires_at_ms: self.expires_at_ms,
            metrics: self.metrics,
            verdict,
        }
    }

    fn evaluate_thresholds(&self) -> Verdict {
        let c = &self.baseline.config;
        let m = self.metrics;
        let mut findings = Vec::with_capacity(4);
        // Cross multiplication in u128 avoids truncation, floating-point
        // ambiguity, division by zero and overflow of u64 byte counters.
        if u128::from(m.completed_attempts) * 1000
            > u128::from(c.max_attempts_per_second) * u128::from(c.window_ms)
        {
            findings.push(Finding::AttemptRateExceeded);
        }
        if m.completed_attempts >= u64::from(c.min_attempts_for_failure_rate)
            && u128::from(m.failed_attempts) * 10_000
                > u128::from(c.max_failed_basis_points) * u128::from(m.completed_attempts)
        {
            findings.push(Finding::FailureRatioExceeded);
        }
        if u128::from(m.sent_bytes) * 1000
            > u128::from(c.max_sent_bytes_per_second) * u128::from(c.window_ms)
        {
            findings.push(Finding::SentRateExceeded);
        }
        if m.sent_bytes >= c.min_sent_bytes_for_imbalance
            && u128::from(m.sent_bytes)
                > u128::from(c.max_sent_to_received_ratio) * u128::from(m.received_bytes)
        {
            findings.push(Finding::SentReceivedImbalance);
        }
        if findings.is_empty() {
            Verdict::NoAnomalyObserved
        } else {
            Verdict::Suspicious { findings }
        }
    }
}
