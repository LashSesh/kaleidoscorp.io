//! The authoritative `KillSwitchStatus` (SPEC_TAURI_GUI.md §4): a reconciliation
//! of the persisted journal, the held receipt, the observed OS rule, and the
//! recovery state — never a single flag.

use serde::{Deserialize, Serialize};
use ssk_boundary::{EnforcementReceipt, KillSwitchState};
use ssk_types::Digest;

/// The reconciliation verdict between the persisted journal and the OS reality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum Recovery {
    /// Journal and observed OS rule agree.
    Consistent,
    /// A crash was detected and the journal was replayed to a coherent state.
    Reconciled,
    /// Journal and OS rule disagree — a fail-closed, operator-visible alarm.
    Inconsistent,
}

/// The observer that reports whether the OS-level egress rule for a scope is
/// actually present. Distinct from [`ssk_boundary::BoundaryEnforcer`] (which
/// mutates); this only observes, so the broker can reconcile the persisted
/// journal against reality. `None` means "cannot determine" (e.g. the probe
/// itself failed) — treated fail-closed, never as "absent".
pub trait EgressObserver {
    fn rule_present(&self, scope_label: &str) -> Option<bool>;
}

/// The authoritative answer to "is egress severed right now, and can we prove
/// it?" — the broker's single source of truth (SPEC §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchStatus {
    /// The logical state from the persisted journal.
    pub logical_state: KillSwitchState,
    /// The held rollback receipt (present iff engaged).
    pub receipt: Option<EnforcementReceipt>,
    /// The enforcer-observed actual OS rule presence (`None` if unknown).
    pub os_rule_present: Option<bool>,
    /// The hash-chain head of the persisted journal.
    pub audit_head: Digest,
    /// The number of audited transitions so far.
    pub audit_len: u64,
    /// Monotone version, bumped by exactly 1 on every successful transition.
    pub state_version: u64,
    /// The reconciliation verdict.
    pub recovery: Recovery,
}

impl KillSwitchStatus {
    /// Compute the reconciliation verdict for a `(logical_state, observed rule)`
    /// pair. Unknown observation is fail-closed: an `Engaged` journal with an
    /// unknown rule is *not* asserted consistent.
    #[must_use]
    pub fn reconcile(
        logical_state: KillSwitchState,
        os_rule_present: Option<bool>,
        crashed: bool,
    ) -> Recovery {
        let expected_present = matches!(logical_state, KillSwitchState::Engaged);
        match os_rule_present {
            Some(actual) if actual == expected_present => {
                if crashed {
                    Recovery::Reconciled
                } else {
                    Recovery::Consistent
                }
            }
            // Disagreement, OR an unknown observation while we believe we are
            // engaged (a severed-egress claim we cannot confirm) — both are
            // fail-closed alarms.
            Some(_) => Recovery::Inconsistent,
            None if expected_present => Recovery::Inconsistent,
            None => {
                if crashed {
                    Recovery::Reconciled
                } else {
                    Recovery::Consistent
                }
            }
        }
    }

    /// Whether this status is a fail-closed alarm the GUI must surface in red.
    #[must_use]
    pub fn is_alarm(&self) -> bool {
        matches!(self.recovery, Recovery::Inconsistent)
    }
}
