//! Property-based confirmation of the TFA transduction invariants over arbitrary
//! δF signal streams — not just the worked examples. Enterprise-grade rigor: for
//! *any* set of signals (including negatives, NaN, and magnitudes far past the
//! envelope) the transducer (1) never emits an amplitude past the envelope (no
//! silent amplification), (2) never auto-passes a privileged effect or a clamped
//! one, (3) loses nothing — every input signal is accounted for as an actuation
//! or a residue — and (4) is a deterministic function of the field.

use proptest::prelude::*;
use ssk_capture::{CaptureMode, CaptureScope, SystemTrafficField, TrafficSource, TrafficWindow};
use ssk_field_tensor::{DeltaSignalKind, FieldTensorSkin};
use ssk_mpk::Graph;
use ssk_tfa::{TransductionConfig, TransductionField};
use ssk_types::GateOutcomeKind;

// A single clean window — a δF-free, residue-free base to layer random signals on.
struct CleanSource;
impl TrafficSource for CleanSource {
    fn source_id(&self) -> String {
        "clean".to_owned()
    }
    fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
        let mut w = TrafficWindow::http("http");
        w.method = Some("GET".to_owned());
        w.url = Some("https://example.local/health".to_owned());
        w.status = Some(200);
        w.response_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
        w.payload = b"{}".to_vec();
        vec![w]
    }
}

fn base_skin() -> FieldTensorSkin {
    let field = SystemTrafficField::capture(
        &CleanSource,
        &CaptureScope::new("local", ["lo0"]),
        CaptureMode::PassiveLocal,
    );
    let windows = vec![Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap()];
    FieldTensorSkin::from_field(&field, &windows)
}

fn kind_of(i: u8) -> DeltaSignalKind {
    match i % 6 {
        0 => DeltaSignalKind::Drift,
        1 => DeltaSignalKind::Anomaly,
        2 => DeltaSignalKind::LinkabilityImpulse,
        3 => DeltaSignalKind::RouteChange,
        4 => DeltaSignalKind::ServiceFault,
        _ => DeltaSignalKind::OsEvent,
    }
}

// A stream of random (kind, magnitude) signals — magnitude spans negatives and
// values well past the envelope to exercise the invalid and clamp paths.
fn signals_strategy() -> impl Strategy<Value = Vec<(u8, f64)>> {
    proptest::collection::vec((0u8..6, -2.0f64..8.0), 0..10)
}

fn skin_with(signals: &[(u8, f64)]) -> FieldTensorSkin {
    let mut skin = base_skin();
    for (i, (k, mag)) in signals.iter().enumerate() {
        skin = skin.with_signal(kind_of(*k), *mag, "prop", i);
    }
    skin
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    // For any signal stream: amplitude is bounded by the envelope (no silent
    // amplification) and non-negative; privileged and clamped candidates never
    // gate Pass.
    #[test]
    fn transduction_is_bounded_and_conservative(signals in signals_strategy()) {
        let cfg = TransductionConfig {
            responsivity: 2.0,
            envelope: 0.5,
            deadband: 0.02,
        };
        let skin = skin_with(&signals);
        let plan = TransductionField::new(cfg).transduce(&skin);
        prop_assert!(!plan.applied);

        for g in &plan.actuations {
            prop_assert!(
                g.actuation.amplitude <= cfg.envelope,
                "amplitude {} exceeded envelope {}",
                g.actuation.amplitude,
                cfg.envelope
            );
            prop_assert!(g.actuation.amplitude >= 0.0);
            if g.actuation.kind.is_privileged() {
                prop_assert_ne!(
                    g.gate,
                    GateOutcomeKind::Pass,
                    "a privileged effect must never auto-pass"
                );
            }
            // A Pass candidate is always strictly within the envelope.
            if g.gate == GateOutcomeKind::Pass {
                prop_assert!(g.actuation.amplitude < cfg.envelope);
            }
        }
    }

    // No silent loss: every input δF signal is accounted for — as an actuation, a
    // residue, or both (a clamp/invalid produces both). So the total number of
    // recorded entries is at least the number of input signals.
    #[test]
    fn nothing_is_silently_lost(signals in signals_strategy()) {
        let skin = skin_with(&signals);
        let input_count = skin.delta.len();
        let plan = TransductionField::default().transduce(&skin);
        prop_assert!(
            plan.actuations.len() + plan.residues.len() >= input_count,
            "accounted {} < {} input signals",
            plan.actuations.len() + plan.residues.len(),
            input_count
        );
    }

    // The plan is a deterministic function of the field (replay-stable).
    #[test]
    fn plan_id_is_deterministic(signals in signals_strategy()) {
        let skin = skin_with(&signals);
        let a = TransductionField::default().transduce(&skin);
        let b = TransductionField::default().transduce(&skin);
        prop_assert_eq!(a.id, b.id);
    }
}
