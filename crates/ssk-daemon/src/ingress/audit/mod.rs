// The flow ledger of the local ingress (design 6.4): a second, append-only,
// hash-chained file, because `audit.json` rewrites itself on every append and
// its cost grows with its length. `record` is the format; the writer, the file
// system layer and the segment handling follow in their own commits.
//
// Direction of dependencies: this module imports from `types`, `target`, `limits`
// and the crates below it, and from nothing that is built on top of it
// (`engine`, `flow`, `host`, `shared`): a test scans the sources.

pub mod dest;
pub mod fs;
#[cfg(unix)]
pub mod fs_unix;
#[cfg(windows)]
pub mod fs_win;
pub mod record;

/// The ledger is built from `types`, `target`, `limits` and the crates below; it
/// must not import the modules that are built on top of it. The writer (`C-A6`)
/// takes a plain input struct, not the engine's `Admitted`, for exactly this
/// reason, and this scan keeps it that way.
#[cfg(test)]
mod import_direction {
    use std::path::{Path, PathBuf};

    const UPWARD: [&str; 4] = ["engine", "flow", "host", "shared"];
    const ROOTS: [&str; 2] = ["ingress::", "super::super::"];

    fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read the audit directory") {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Every path in `source` that reaches an upward module, as written.
    fn upward_imports(source: &str) -> Vec<String> {
        let mut found = Vec::new();
        for root in ROOTS {
            for (at, _) in source.match_indices(root) {
                let rest = source.get(at + root.len()..).unwrap_or_default();
                if let Some(group) = rest.strip_prefix('{') {
                    // `ingress::{types, host}`: look at every word of the group.
                    let mut depth = 1_usize;
                    let end = group
                        .char_indices()
                        .find(|(_, c)| {
                            match c {
                                '{' => depth += 1,
                                '}' => depth -= 1,
                                _ => {}
                            }
                            depth == 0
                        })
                        .map_or(group.len(), |(i, _)| i);
                    let inside = group.get(..end).unwrap_or_default();
                    for word in inside.split(|c: char| !c.is_alphanumeric() && c != '_') {
                        if UPWARD.contains(&word) {
                            found.push(format!("{root}{{..{word}..}}"));
                        }
                    }
                } else {
                    let word: String = rest
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if UPWARD.contains(&word.as_str()) {
                        found.push(format!("{root}{word}"));
                    }
                }
            }
        }
        found
    }

    #[test]
    fn audit_module_has_no_upward_imports() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ingress/audit");
        let mut files = Vec::new();
        rust_files(&root, &mut files);
        assert!(!files.is_empty(), "the scan must see the audit tree");
        let mut offenders = Vec::new();
        for file in &files {
            let source = std::fs::read_to_string(file).expect("read a source file");
            // The direction is a property of the production code; the test modules
            // (this one holds fixtures that spell the forbidden paths) follow it
            // too but are not what the rule protects.
            let production = source.split("#[cfg(test)]").next().unwrap_or_default();
            for path in upward_imports(production) {
                offenders.push(format!("{}: {path}", file.display()));
            }
        }
        assert!(offenders.is_empty(), "{offenders:?}");
    }

    #[test]
    fn the_scan_finds_each_form_of_an_upward_import() {
        for source in [
            "use crate::ingress::engine::Admitted;",
            "use crate::ingress::flow;",
            "use crate::ingress::host::IngressHost;",
            "use crate::ingress::shared::IngressShared;",
            "use crate::ingress::{types, engine};",
            "use crate::ingress::{types::{Gate, GateMode}, shared::Gate};",
            "use super::super::engine::Admitted;",
            "use super::super::{limits, host};",
            "let x = crate::ingress::host::start();",
        ] {
            assert!(!upward_imports(source).is_empty(), "{source}");
        }
        for source in [
            "use crate::ingress::types::{Gate, GateMode};",
            "use crate::ingress::target::TargetKind;",
            "use crate::ingress::limits::DenialKey;",
            "use super::super::types::Tuning;",
            "use super::record::FlowAuditRecord;",
            // A local name that happens to be one of the words is not a module path.
            "let host = String::new(); let flow = 1;",
            "use crate::ingress::types::{lock_unpoisoned};",
        ] {
            assert!(
                upward_imports(source).is_empty(),
                "{source}: {:?}",
                upward_imports(source)
            );
        }
    }
}
