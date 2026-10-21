//! What `ssk config lint` says about the files it reads: the version it migrated
//! a file to is the current one (the message used to hard-code `v2`), and the
//! checked-in example configurations lint clean.

use std::path::Path;
use std::process::{Command, Output};

fn lint(path: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ssk"))
        .args(["config", "lint", "--path"])
        .arg(path)
        .output()
        .expect("ssk config lint must execute")
}

/// The default document as a file of version `version` wrote it. JSON is YAML.
fn write_old_file(directory: &Path, version: u32) -> std::path::PathBuf {
    let mut value = serde_json::to_value(ssk_config::AppConfig::default()).expect("default");
    let object = value.as_object_mut().expect("object");
    object.insert("version".into(), version.into());
    if version < 5 {
        object.remove("ingress");
    }
    if version < 4 {
        object.remove("routing");
    }
    let path = directory.join(format!("v{version}.yaml"));
    std::fs::write(&path, serde_json::to_string_pretty(&value).expect("json")).expect("write");
    path
}

#[test]
fn lint_names_the_current_version_it_migrated_to() {
    let temp = tempfile::tempdir().expect("tempdir");
    for from in [3, 4] {
        let output = lint(&write_old_file(temp.path(), from));
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(output.status.success(), "v{from}: {stdout}");
        assert_eq!(
            stdout.trim_end(),
            format!(
                "config-ok (migrated from v{from} to v{})",
                ssk_config::CURRENT_CONFIG_VERSION
            )
        );
    }
}

#[test]
fn lint_accepts_a_current_file_without_a_migration_note() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = lint(&write_old_file(
        temp.path(),
        ssk_config::CURRENT_CONFIG_VERSION,
    ));
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("utf8").trim_end(),
        "config-ok"
    );
}

#[test]
fn lint_accepts_every_checked_in_example_configuration() {
    let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/examples");
    for name in [
        "openvpn-routing.yaml",
        "ingress.example.yaml",
        "ingress-coexistence.yaml",
    ] {
        let output = lint(&examples.join(name));
        let stdout = String::from_utf8(output.stdout).expect("utf8");
        assert!(output.status.success(), "{name}: {stdout}");
        assert_eq!(stdout.trim_end(), "config-ok", "{name}");
    }
}
