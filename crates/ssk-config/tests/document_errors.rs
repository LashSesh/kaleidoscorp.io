//! A document that does not fit the schema is a problem with the document, not
//! with serialising anything. `parse_with_migration_*` is the only path the
//! daemon, `ssk` and `ssk config lint` use; it reads YAML or TOML into a JSON
//! value and deserialises that, so serde_json's error used to surface as
//! `json serialization error: ...`, also for YAML and TOML input.

use serde_json::{json, Value};
use ssk_config::{lint, AppConfig, ConfigError, ConfigFormat};

const LABEL: &str = "invalid configuration document: ";

fn current_document() -> Value {
    serde_json::to_value(AppConfig::default()).expect("the default config serialises")
}

fn yaml(value: &Value) -> String {
    serde_yaml::to_string(value).expect("a JSON value is valid YAML")
}

fn toml(value: &Value) -> String {
    toml::to_string(value).expect("the document has no null")
}

/// Every way a document can fail deserialisation, in the order the migration
/// code meets them: one case per `from_value` call site, one for the
/// YAML-to-JSON conversion, and the typos an operator makes.
struct Case {
    name: &'static str,
    yaml: String,
    toml: Option<String>,
    /// What the message must name so the operator can find the mistake.
    names: &'static str,
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();

    let mut typo = current_document();
    typo["rutime"] = json!({"strict_mode": true});
    cases.push(Case {
        name: "top-level typo in a current document",
        yaml: yaml(&typo),
        toml: Some(toml(&typo)),
        names: "unknown field `rutime`",
    });

    let mut missing = current_document();
    missing.as_object_mut().unwrap().remove("system");
    cases.push(Case {
        name: "required section missing from a current document",
        yaml: yaml(&missing),
        toml: Some(toml(&missing)),
        names: "missing field `system`",
    });

    let mut wrong_type = current_document();
    wrong_type["runtime"]["strict_mode"] = json!("yes");
    cases.push(Case {
        name: "wrong value type in a current document",
        yaml: yaml(&wrong_type),
        toml: Some(toml(&wrong_type)),
        names: "expected a boolean",
    });

    // The README's "minimum valid configuration" (measured at HEAD, design 5.6):
    // `fail_closed` is not a key of a version 2 document.
    let readme = "version: 2\nfail_closed: true\nruntime:\n  strict_mode: true\n";
    cases.push(Case {
        name: "the README minimal example, a version 2 document",
        yaml: readme.into(),
        toml: Some("version = 2\nfail_closed = true\n[runtime]\nstrict_mode = true\n".into()),
        names: "unknown field `fail_closed`",
    });

    let mut v3 = current_document();
    v3["version"] = 3.into();
    v3.as_object_mut().unwrap().remove("routing");
    v3.as_object_mut().unwrap().remove("core");
    cases.push(Case {
        name: "a version 3 document that lacks a section",
        yaml: yaml(&v3),
        toml: Some(toml(&v3)),
        names: "missing field `core`",
    });

    // Version 1 has no `version` key at all.
    cases.push(Case {
        name: "a version 1 document with an extra key",
        yaml: "name: p\nfail_closed: true\ngate_profile:\n  order: [Core]\n  fail_closed: true\nextra: 1\n"
            .into(),
        toml: Some(
            "name = \"p\"\nfail_closed = true\nextra = 1\n[gate_profile]\norder = [\"Core\"]\nfail_closed = true\n"
                .into(),
        ),
        names: "unknown field `extra`",
    });

    // serde_yaml reads a sequence key into a Mapping; turning that into a JSON
    // object is what fails. TOML cannot express such a key.
    cases.push(Case {
        name: "a YAML mapping key that is a sequence",
        yaml: "? [1, 2]\n: x\n".into(),
        toml: None,
        names: "key must be a string",
    });

    cases
}

#[test]
fn document_shape_errors_are_not_labelled_as_json_serialisation() {
    // Collect every failure, so one run shows which call sites are wrong.
    let mut problems = Vec::new();
    for case in cases() {
        let mut attempts: Vec<(&str, Result<_, ConfigError>)> =
            vec![("yaml", AppConfig::parse_with_migration_yaml(&case.yaml))];
        if let Some(text) = &case.toml {
            attempts.push(("toml", AppConfig::parse_with_migration_toml(text)));
        }
        for (format, result) in attempts {
            let context = format!("{} ({format})", case.name);
            let Err(err) = result else {
                problems.push(format!("{context}: accepted"));
                continue;
            };
            let message = err.to_string();
            if message.contains("json serialization error") {
                problems.push(format!(
                    "{context}: mislabelled as a serialisation failure: {message}"
                ));
            } else if !matches!(err, ConfigError::Document(_)) {
                problems.push(format!("{context}: not a document error: {err:?}"));
            } else if !message.starts_with(LABEL) {
                problems.push(format!("{context}: label is not `{LABEL}`: {message}"));
            } else if !message.contains(case.names) {
                problems.push(format!(
                    "{context}: the message does not name the mistake `{}`: {message}",
                    case.names
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// `lint` is what `ssk config lint` prints and what the daemon reports as
/// `ConfigInvalid`; it must carry the same label.
#[test]
fn lint_reports_the_document_label() {
    let mut typo = current_document();
    typo["rutime"] = json!({});
    for (format, text) in [
        (ConfigFormat::Yaml, yaml(&typo)),
        (ConfigFormat::Toml, toml(&typo)),
    ] {
        let report = lint(&text, format);
        assert!(!report.ok);
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(
            report.errors[0].starts_with(LABEL) && report.errors[0].contains("`rutime`"),
            "{report:?}"
        );
    }
}

/// `Document` is for documents that parsed as YAML or TOML and then did not fit.
/// Text that is not YAML or TOML, a version this build does not know and a
/// version that is not a number keep the labels they always had.
#[test]
fn the_other_failures_keep_their_own_labels() {
    assert!(matches!(
        AppConfig::parse_with_migration_yaml("a: [1, 2"),
        Err(ConfigError::Yaml(_))
    ));
    assert!(matches!(
        AppConfig::parse_with_migration_toml("a = [1, 2"),
        Err(ConfigError::Toml(_))
    ));

    let mut future = current_document();
    future["version"] = 999.into();
    assert!(matches!(
        AppConfig::parse_with_migration_yaml(&yaml(&future)),
        Err(ConfigError::UnsupportedVersion {
            found: 999,
            expected: _
        })
    ));

    let mut textual = current_document();
    textual["version"] = "4".into();
    assert!(matches!(
        AppConfig::parse_with_migration_yaml(&yaml(&textual)),
        Err(ConfigError::Structure(_))
    ));
    assert!(matches!(
        AppConfig::parse_with_migration_yaml("- just\n- a list\n"),
        Err(ConfigError::Structure(_))
    ));
}
