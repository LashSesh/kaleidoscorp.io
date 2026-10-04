use ssk_ui_contract::DesktopSnapshotV2;
use ssk_ui_contract::PanelSnapshotV1;
use std::path::Path;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ui/desktop/fixtures")
            .join(format!("{name}.json")),
    )
    .unwrap()
}

#[test]
fn browser_scenarios_round_trip_through_the_rust_wire_contract() {
    for name in [
        "disconnected",
        "connecting",
        "ready",
        "engaged",
        "released",
        "inconsistent",
        "degraded",
    ] {
        let source: serde_json::Value = serde_json::from_str(&fixture(name)).unwrap();
        let typed: PanelSnapshotV1 = serde_json::from_value(source.clone()).unwrap();
        assert_eq!(serde_json::to_value(typed).unwrap(), source, "{name}");
    }
}

#[test]
fn incompatible_versions_and_unrecognized_authority_fields_are_rejected() {
    let original: serde_json::Value = serde_json::from_str(&fixture("engaged")).unwrap();
    for version in [
        serde_json::json!(0),
        serde_json::json!(2),
        serde_json::json!("1"),
    ] {
        let mut value = original.clone();
        value["schema_version"] = version;
        assert!(serde_json::from_value::<PanelSnapshotV1>(value).is_err());
    }
    let mut value = original.clone();
    value["enforcement_active"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PanelSnapshotV1>(value).is_err());
    let mut value = original.clone();
    value["kill_switch"]["execute"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PanelSnapshotV1>(value).is_err());
    let mut value = original;
    value["audit"]["integrity"]["trusted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PanelSnapshotV1>(value).is_err());
}

#[test]
fn absent_sections_remain_absent_and_unknown_states_are_rejected() {
    let minimal = r#"{"schema_version":1,"panel_state":"degraded"}"#;
    let snapshot: PanelSnapshotV1 = serde_json::from_str(minimal).unwrap();
    assert!(snapshot.kill_switch.is_none());
    assert!(snapshot.audit.is_none());
    assert!(snapshot.connections.is_none());
    assert!(
        serde_json::from_str::<PanelSnapshotV1>(&minimal.replace("degraded", "protected")).is_err()
    );
}

#[test]
fn desktop_v2_fixture_round_trips_and_cannot_carry_protection_authority() {
    let source: serde_json::Value = serde_json::from_str(&fixture("daemon-v2")).unwrap();
    let view: DesktopSnapshotV2 = serde_json::from_value(source.clone()).unwrap();
    assert_eq!(serde_json::to_value(view).unwrap(), source);
    for (field, value) in [
        ("schema_version", serde_json::json!(1)),
        ("panel_state", serde_json::json!("engaged")),
        ("kill_switch", serde_json::json!(null)),
        ("protection_confirmed", serde_json::json!(true)),
    ] {
        let mut bad = source.clone();
        bad[field] = value;
        assert!(serde_json::from_value::<DesktopSnapshotV2>(bad).is_err());
    }
    let mut bad = source;
    bad["daemon"]["enforcement_active"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DesktopSnapshotV2>(bad).is_err());
}
