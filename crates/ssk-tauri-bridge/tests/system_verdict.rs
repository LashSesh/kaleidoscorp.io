//! P1 fast-follow: the system-verdict view, verified against a REAL
//! `SystemPipeline::evaluate` run (SPEC_TAURI_GUI.md §10). No committed golden
//! with fabricated digests (review must-fix): the verdict is computed live and
//! asserted structurally + by decision, and the enum wire strings are pinned.

use ssk_boundary::KillSwitchState;
use ssk_capture::{CaptureMode, CaptureScope, SystemTrafficField, TrafficSource, TrafficWindow};
use ssk_mpk::Graph;
use ssk_service_host::ServiceHealth;
use ssk_system::{SystemInputs, SystemPipeline};

use ssk_tauri_bridge::dto::{DecisionDto, GateOutcomeDto, ResonanceActionDto};
use ssk_tauri_bridge::view::system_verdict_view;

/// A single clean HTTP window — the "everything passes" path.
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

fn field() -> SystemTrafficField {
    SystemTrafficField::capture(
        &CleanSource,
        &CaptureScope::new("local", ["lo0"]),
        CaptureMode::PassiveLocal,
    )
}

fn windows() -> Vec<Graph> {
    vec![
        Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap(),
        Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]).unwrap(),
    ]
}

fn inputs<'a>(
    traffic: &'a SystemTrafficField,
    ws: &'a [Graph],
    kill_switch: KillSwitchState,
) -> SystemInputs<'a> {
    SystemInputs {
        traffic,
        windows: ws,
        host_health: ServiceHealth::Healthy,
        kill_switch,
        open_obligations: 0,
        parallax_consistent: true,
        replay_equal: true,
    }
}

// A live clean run projects into a coherent DTO: 64-hex field digest, the
// reasons carried verbatim, and a serde round-trip under deny_unknown_fields.
#[test]
fn clean_run_projects_to_a_coherent_verdict_dto() {
    let traffic = field();
    let ws = windows();
    let verdict = SystemPipeline::new().evaluate(&inputs(&traffic, &ws, KillSwitchState::Armed));
    let dto = system_verdict_view(&verdict);

    assert_eq!(dto.decision, DecisionDto::Emit, "the clean path emits");
    assert!(!dto.host_downgraded, "a healthy host does not downgrade");
    assert_eq!(dto.field_digest_hex.len(), 64, "field digest is 64-hex");
    assert!(
        dto.field_digest_hex.chars().all(|c| c.is_ascii_hexdigit()),
        "field digest is lowercase hex"
    );
    assert_eq!(dto.reasons, verdict.reasons, "reasons carried verbatim");

    // The projection round-trips under deny_unknown_fields.
    let json = serde_json::to_string(&dto).unwrap();
    let back: ssk_tauri_bridge::dto::SystemVerdictViewDto = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dto);
}

// The kill-switch is a hard stop: an engaged switch forces the verdict to Deny,
// end-to-end through the real pipeline and into the DTO.
#[test]
fn an_engaged_kill_switch_forces_deny() {
    let traffic = field();
    let ws = windows();
    let verdict = SystemPipeline::new().evaluate(&inputs(&traffic, &ws, KillSwitchState::Engaged));
    let dto = system_verdict_view(&verdict);
    assert_eq!(
        dto.decision,
        DecisionDto::Deny,
        "an engaged kill switch denies emission"
    );
}

// The projected enum wire strings the frontend binds to are pinned.
#[test]
fn verdict_enum_wire_strings_are_pinned() {
    use serde_json::to_value;
    assert_eq!(to_value(DecisionDto::Emit).unwrap(), "emit");
    assert_eq!(to_value(DecisionDto::Deny).unwrap(), "deny");
    assert_eq!(to_value(GateOutcomeDto::Reject).unwrap(), "reject");
    assert_eq!(to_value(GateOutcomeDto::Quarantine).unwrap(), "quarantine");
    assert_eq!(
        to_value(ResonanceActionDto::Stabilize).unwrap(),
        "stabilize"
    );
    assert_eq!(to_value(ResonanceActionDto::Delay).unwrap(), "delay");
}
