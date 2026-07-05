//! Property-based confirmation of `SystemPipeline`'s central promise: **no
//! input can promote a decision, only a fully clean stack emits**. The unit
//! tests in `src/lib.rs` cover worked examples; this suite drives every
//! control axis (kill-switch, open obligations, host health, parallax/replay
//! evidence, and whether the capture itself carries a sensitive surface)
//! through many random combinations and checks three invariants that must
//! hold for all of them, not just the examples: `Emit` implies every axis was
//! genuinely clear, worsening any single axis never lowers the decision, and
//! two independent pipelines given the same inputs replay to the same
//! decision and field digest.

use proptest::prelude::*;
use ssk_boundary::KillSwitchState;
use ssk_capture::{CaptureMode, CaptureScope, SystemTrafficField, TrafficSource, TrafficWindow};
use ssk_crown::EmissionDecision;
use ssk_mpk::Graph;
use ssk_service_host::ServiceHealth;
use ssk_system::{SystemInputs, SystemPipeline};

/// Yields a clean GET window, plus (when `sensitive`) a second POST carrying
/// an `Authorization` header — the same shape as the `CleanSource`/
/// `DriftingSource` doubles `ssk-system`'s own unit tests use.
struct FixtureSource {
    sensitive: bool,
}

impl TrafficSource for FixtureSource {
    fn source_id(&self) -> String {
        "prop-fixture".to_owned()
    }

    fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
        let mut clean = TrafficWindow::http("http");
        clean.method = Some("GET".to_owned());
        clean.url = Some("https://example.local/health".to_owned());
        clean.status = Some(200);
        clean.response_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        clean.payload = b"{}".to_vec();

        if !self.sensitive {
            return vec![clean];
        }

        let mut sensitive = TrafficWindow::http("http");
        sensitive.method = Some("POST".to_owned());
        sensitive.url = Some("https://example.local/login".to_owned());
        sensitive.status = Some(401);
        sensitive.request_headers = vec![("Authorization".to_owned(), "Bearer secret".to_owned())];
        sensitive.response_headers =
            vec![("Content-Type".to_owned(), "application/json".to_owned())];
        sensitive.payload = b"{\"user\":\"x\"}".to_vec();

        vec![clean, sensitive]
    }
}

fn field(sensitive: bool) -> SystemTrafficField {
    SystemTrafficField::capture(
        &FixtureSource { sensitive },
        &CaptureScope::new("local", ["lo0"]),
        CaptureMode::PassiveLocal,
    )
}

fn windows() -> Vec<Graph> {
    vec![Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap()]
}

fn decision_rank(d: EmissionDecision) -> u8 {
    match d {
        EmissionDecision::Emit => 0,
        EmissionDecision::Hold => 1,
        EmissionDecision::Deny => 2,
    }
}

fn health_strategy() -> impl Strategy<Value = ServiceHealth> {
    prop_oneof![
        Just(ServiceHealth::Healthy),
        Just(ServiceHealth::Degraded),
        Just(ServiceHealth::Down),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    // Regression class for the fail-open bugs already found in this stack
    // (hardcoded QLOGIC axes, the field-tensor authorization-only leak
    // detector): whatever combination of inputs is thrown at it, `Emit` may
    // only come out when every single axis was actually clear.
    #[test]
    fn emit_implies_every_axis_was_genuinely_clear(
        sensitive in any::<bool>(),
        kill_switch_engaged in any::<bool>(),
        open_obligations in 0usize..4,
        host_health in health_strategy(),
        parallax_consistent in any::<bool>(),
        replay_equal in any::<bool>(),
    ) {
        let traffic = field(sensitive);
        let ws = windows();
        let inputs = SystemInputs {
            traffic: &traffic,
            windows: &ws,
            host_health,
            kill_switch: if kill_switch_engaged {
                KillSwitchState::Engaged
            } else {
                KillSwitchState::Armed
            },
            open_obligations,
            parallax_consistent,
            replay_equal,
        };
        let mut pipeline = SystemPipeline::new();
        let verdict = pipeline.evaluate(&inputs);

        if verdict.decision == EmissionDecision::Emit {
            prop_assert!(!sensitive, "a sensitive capture must never be allowed to emit");
            prop_assert!(!kill_switch_engaged, "an engaged kill-switch must never emit");
            prop_assert_eq!(open_obligations, 0);
            prop_assert_eq!(host_health, ServiceHealth::Healthy);
            prop_assert!(parallax_consistent);
            prop_assert!(replay_equal);
        }
        prop_assert!(pipeline.verify_ledger());
    }

    // No subsystem may promote a decision: taking any one control axis to a
    // strictly worse value, holding everything else fixed, must never lower
    // the resulting decision's rank (Emit < Hold < Deny).
    #[test]
    fn worsening_any_single_axis_never_lowers_the_decision(
        sensitive in any::<bool>(),
        kill_switch_engaged in any::<bool>(),
        open_obligations in 0usize..4,
        host_health in health_strategy(),
        parallax_consistent in any::<bool>(),
        replay_equal in any::<bool>(),
    ) {
        let traffic = field(sensitive);
        let ws = windows();
        let base = SystemInputs {
            traffic: &traffic,
            windows: &ws,
            host_health,
            kill_switch: if kill_switch_engaged {
                KillSwitchState::Engaged
            } else {
                KillSwitchState::Armed
            },
            open_obligations,
            parallax_consistent,
            replay_equal,
        };
        let base_rank = decision_rank(SystemPipeline::new().evaluate(&base).decision);

        if !kill_switch_engaged {
            let worse = SystemInputs {
                kill_switch: KillSwitchState::Engaged,
                ..base
            };
            let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
            prop_assert!(worse_rank >= base_rank, "engaging the kill-switch must not lower the decision");
        }

        {
            let worse = SystemInputs {
                open_obligations: open_obligations + 1,
                ..base
            };
            let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
            prop_assert!(worse_rank >= base_rank, "an added open obligation must not lower the decision");
        }

        if host_health == ServiceHealth::Healthy {
            for worse_health in [ServiceHealth::Degraded, ServiceHealth::Down] {
                let worse = SystemInputs {
                    host_health: worse_health,
                    ..base
                };
                let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
                prop_assert!(worse_rank >= base_rank, "an un-emittable host must not lower the decision");
            }
        }

        if parallax_consistent {
            let worse = SystemInputs {
                parallax_consistent: false,
                ..base
            };
            let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
            prop_assert!(worse_rank >= base_rank, "losing parallax evidence must not lower the decision");
        }

        if replay_equal {
            let worse = SystemInputs {
                replay_equal: false,
                ..base
            };
            let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
            prop_assert!(worse_rank >= base_rank, "losing replay evidence must not lower the decision");
        }

        if !sensitive {
            let sensitive_traffic = field(true);
            let worse = SystemInputs {
                traffic: &sensitive_traffic,
                ..base
            };
            let worse_rank = decision_rank(SystemPipeline::new().evaluate(&worse).decision);
            prop_assert!(worse_rank >= base_rank, "a newly sensitive capture must not lower the decision");
        }
    }

    // The whole composition is a pure function of its inputs (given a fresh
    // pipeline): two independent pipelines fed the identical inputs must
    // agree on decision and field digest.
    #[test]
    fn replay_stability_across_independent_pipelines(
        sensitive in any::<bool>(),
        kill_switch_engaged in any::<bool>(),
        open_obligations in 0usize..4,
        host_health in health_strategy(),
        parallax_consistent in any::<bool>(),
        replay_equal in any::<bool>(),
    ) {
        let traffic = field(sensitive);
        let ws = windows();
        let inputs = SystemInputs {
            traffic: &traffic,
            windows: &ws,
            host_health,
            kill_switch: if kill_switch_engaged {
                KillSwitchState::Engaged
            } else {
                KillSwitchState::Armed
            },
            open_obligations,
            parallax_consistent,
            replay_equal,
        };

        let mut a = SystemPipeline::new();
        let va = a.evaluate(&inputs);
        let mut b = SystemPipeline::new();
        let vb = b.evaluate(&inputs);

        prop_assert_eq!(va.decision, vb.decision);
        prop_assert_eq!(va.field_digest, vb.field_digest);
        prop_assert_eq!(a.crown_head(), b.crown_head());
    }
}
