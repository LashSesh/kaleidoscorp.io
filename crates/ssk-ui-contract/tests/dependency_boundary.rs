//! Guard the architectural boundary against an accidental host/runtime import.
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
};

#[test]
fn presentation_contract_has_no_other_workspace_dependency() {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--offline", "--locked", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "cargo metadata failed");
    let metadata: Value = serde_json::from_slice(&output.stdout).unwrap();
    let members: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    let root = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "ssk-ui-contract")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    let nodes: BTreeMap<_, _> = metadata["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["id"].as_str().unwrap(), n))
        .collect();
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        assert!(
            id == root || !members.contains(id),
            "contract imported workspace runtime: {id}"
        );
        for dependency in nodes[id]["deps"].as_array().unwrap() {
            if dependency["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
            {
                pending.push(dependency["pkg"].as_str().unwrap());
            }
        }
    }
}
