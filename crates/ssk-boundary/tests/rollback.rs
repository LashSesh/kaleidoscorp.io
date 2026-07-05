//! Property-based confirmation that `KillSwitch` rollback exactly restores over
//! arbitrary operation sequences — not just the worked examples. This is the
//! regression class for the override_engage receipt-clobbering bug: the
//! in-crate `FakeEnforcer` ignores its receipt argument entirely and so cannot
//! detect a wrong or lost receipt. A `FaithfulEnforcer` that actually honors
//! `EnforcementReceipt::prior_state` is required to catch it.

use proptest::prelude::*;
use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, EnforcementReceipt, KillSwitch,
    KillSwitchState, BOUNDARY_CONTROL_USE, BOUNDARY_OVERRIDE_USE,
};
use ssk_signature::AuthorizationManifest;
use std::cell::Cell;

/// An enforcer that honors the receipt on release: it restores exactly the
/// `prior_state` the receipt carries, rather than a hardcoded value.
struct FaithfulEnforcer {
    severed: Cell<bool>,
}
impl FaithfulEnforcer {
    fn new() -> Self {
        FaithfulEnforcer {
            severed: Cell::new(false),
        }
    }
}
impl BoundaryEnforcer for FaithfulEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        let prior = if self.severed.get() {
            "severed"
        } else {
            "flowing"
        };
        let receipt = EnforcementReceipt::new(scope, prior);
        self.severed.set(true);
        Ok(receipt)
    }
    fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.severed.set(receipt.prior_state != "flowing");
        Ok(())
    }
}

fn control_auth() -> AuthorizationManifest {
    AuthorizationManifest::new("operator", "me", "session control")
        .with_allowed_uses([BOUNDARY_CONTROL_USE])
}

fn override_auth() -> AuthorizationManifest {
    AuthorizationManifest::new("operator", "me", "override control")
        .with_allowed_uses([BOUNDARY_CONTROL_USE, BOUNDARY_OVERRIDE_USE])
}

fn switch() -> KillSwitch {
    KillSwitch::arm(
        ssk_types::SessionId::new("sess-prop"),
        BoundaryScope::all_egress(),
        BoundaryPolicy::default(),
    )
}

// An operation stream: 0 = engage, 1 = release, 2 = override_engage.
fn ops_strategy() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(0u8..3, 0..12)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    // Over any sequence of engage/release/override_engage, the audit chain stays
    // verifiable and the enforcer's live "severed" bit always matches an oracle
    // maintained independently of the switch — i.e. release always restores the
    // TRUE pre-engagement state, never an intermediate state an overwritten
    // receipt would have captured.
    #[test]
    fn rollback_exactly_restores_over_arbitrary_sequences(ops in ops_strategy()) {
        let mut ks = switch();
        let enforcer = FaithfulEnforcer::new();
        // Oracle: the stack of "severed" bits captured at each successful
        // engagement (mirrors exactly what a correct receipt must preserve).
        let mut oracle_stack: Vec<bool> = Vec::new();
        let mut oracle_severed = false;

        for op in ops {
            match op {
                0 => {
                    let was_engaged = ks.state() == KillSwitchState::Engaged;
                    match ks.engage(&control_auth(), &enforcer) {
                        Ok(()) => {
                            prop_assert!(!was_engaged);
                            oracle_stack.push(oracle_severed);
                            oracle_severed = true;
                        }
                        Err(_) => prop_assert!(was_engaged),
                    }
                }
                1 => {
                    let was_engaged = ks.state() == KillSwitchState::Engaged;
                    match ks.release(&control_auth(), &enforcer) {
                        Ok(()) => {
                            prop_assert!(was_engaged);
                            oracle_severed = oracle_stack.pop().expect("engage pushed a state");
                        }
                        Err(_) => prop_assert!(!was_engaged),
                    }
                }
                _ => {
                    let was_engaged = ks.state() == KillSwitchState::Engaged;
                    ks.override_engage(&override_auth(), "prop", &enforcer).unwrap();
                    if !was_engaged {
                        oracle_stack.push(oracle_severed);
                        oracle_severed = true;
                    }
                    // If already engaged, override_engage is a no-op on the
                    // receipt/oracle — the original prior-state record survives.
                }
            }
            prop_assert_eq!(enforcer.severed.get(), oracle_severed);
            prop_assert!(ks.verify_audit());
        }
    }
}
