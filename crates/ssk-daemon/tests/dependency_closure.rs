//! ADR 0008's structural invariant, asserted mechanically: the shipping `sskd`
//! binary does not link the decision core.
//!
//! # Why this file exists
//!
//! Before ADR 0008, six decision-core crates -- `ssk-gates`, `ssk-imdf`,
//! `ssk-core`, `ssk-locator`, `ssk-bcik` and `ssk-focus`, 7,626 LOC between
//! them -- reached the shipping daemon binary through exactly ONE dependency
//! edge: `ssk-config`'s `HypercubeConfig.axes` reused `ssk_gates::pch::Axis`.
//! No decision logic among those crates ever executed in `sskd`; the only code
//! reached at runtime was that enum's derived `Deserialize`. Severing the edge
//! took the closure from 22 crates to 16.
//!
//! The failure mode this file guards is therefore not exotic. It is one `use`
//! statement, added for one type, by someone who has never read that ADR -- and
//! it is close to invisible in review, because the diff is a single import and
//! a single `Cargo.toml` line. It went unnoticed for months the first time.
//! Nothing about the severance makes the second time less likely; only a
//! mechanical check does.
//!
//! # What is real here and what is not
//!
//! Real: the resolved dependency graph, read from `cargo metadata` -- cargo's
//! own resolver output, not a re-implementation of it, and not a scan of the
//! `Cargo.toml` files (which would have to re-derive optional dependencies,
//! feature unification and `cfg()` target filtering to reach the same answer,
//! and would be wrong in exactly the cases that matter).
//!
//! Deliberately excluded: `dev-dependencies`. They do not link into the shipped
//! `sskd` binary, so a dev-dependency on a decision-core crate -- a daemon
//! integration test that cross-checks a decision against `ssk-runtime`, say --
//! does not violate ADR 0008 and must not fail this file. Only `kind: null`
//! (normal) and `kind: "build"` edges are walked. Measured when this file was
//! written, including dev edges would not have changed the answer; excluding
//! them is about what this guard MEANS, not about today's graph.
//!
//! Deliberately not restricted to one platform: `--filter-platform` is not
//! passed, so the closure is the union over every target. `ssk-winhost`
//! (`cfg(windows)`) and `rustix` (`cfg(unix)`) are both in the resolve output
//! whichever OS runs the test, which is what makes the assertions below give an
//! identical answer on the ubuntu and windows CI legs.
//!
//! # Where this runs
//!
//! Nowhere new. `.github/workflows/ci.yml`'s `build_test` job runs
//! `cargo test --workspace` on `ubuntu-latest` and `windows-latest`, and its
//! `windows_crate_gates` matrix runs `cargo test -p ssk-daemon`. Both pick this
//! file up with no change to the workflow. `cargo metadata` performs no network
//! access against an up-to-date `Cargo.lock`, and both jobs run a full
//! `cargo build` first, so the registry is already populated.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::process::Command;

use serde_json::Value;

/// The decision core. ADR 0008 decided these do not ship inside `sskd`.
///
/// Six of them were removed from the closure by that ADR. `ssk-runtime` and
/// `ssk-stitch` were never in it, and are listed because they are the rest of
/// the same subsystem: `ssk-runtime` owns `run_to_outcome`, the entry point the
/// ADR states the daemon does not call and will not, and `ssk-stitch` is the
/// crate that builds the composite the gate vector evaluates. A crate that is
/// out today is exactly the crate an unwitting edge drags back in tomorrow.
const DENIED_CORE: &[&str] = &[
    "ssk-bcik",
    "ssk-core",
    "ssk-focus",
    "ssk-gates",
    "ssk-imdf",
    "ssk-locator",
    "ssk-runtime",
    "ssk-stitch",
    // Offline analysis stays outside shipping authority until trusted ingress
    // and a reviewed, non-expanding policy integration exist.
    "ssk-netanalysis",
];

/// The workspace crates `sskd` links, including `ssk-daemon` itself -- the same
/// original 16 plus `ssk-vpnctl` for the Windows host's protected profile and
/// child-process boundary (ADR 0008's 2026-09-22 addendum).
///
/// This is an allow-list, and it is here because a deny-list alone rots: rename
/// `ssk-gates` and `DENIED_CORE` above silently stops matching, forever, with no
/// failing test to tell anyone. Any crate entering or leaving this set fails
/// `daemon_dependency_closure_is_the_set_adr_0008_recorded` below, whatever it
/// is called.
const EXPECTED_CLOSURE: &[&str] = &[
    "ssk-boundary",
    "ssk-capture",
    "ssk-config",
    "ssk-crypto",
    "ssk-daemon",
    "ssk-diag",
    "ssk-ipc",
    "ssk-netadmin",
    "ssk-netcore",
    "ssk-netd-helper",
    "ssk-privacy",
    "ssk-service-host",
    "ssk-signature",
    "ssk-tensor",
    "ssk-types",
    "ssk-vpnctl",
    "ssk-winhost",
];

/// The package whose closure is under test.
const ROOT: &str = "ssk-daemon";

// ---------------------------------------------------------------------------
// The measurement.
// ---------------------------------------------------------------------------

/// The workspace's resolved package graph, restricted to shipping edges.
struct Graph {
    /// Package id -> package name.
    names: BTreeMap<String, String>,
    /// Package id -> the ids it depends on over `normal` or `build` edges.
    edges: BTreeMap<String, Vec<String>>,
    /// The ids of this workspace's own members.
    members: BTreeSet<String>,
}

/// Reads the resolved graph from `cargo metadata`.
///
/// Every failure path here panics. It must: a guard that quietly returns when it
/// cannot take its measurement is a guard that reports success for the wrong
/// reason, which is the fail-open shape this workspace exists to remove.
fn load_graph() -> Graph {
    // `CARGO` is set by cargo both when compiling this test and when running it,
    // so this is the exact cargo that is driving the current build rather than
    // whatever `PATH` resolves to. Verified present in both positions.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    // `--no-deps` is deliberately NOT passed: it suppresses `resolve`, which is
    // the entire measurement. `--filter-platform` is deliberately not passed
    // either (see the module docs). The working directory is this crate's own
    // manifest directory; cargo walks up to the workspace root from there and
    // returns the whole workspace either way.
    let out = Command::new(&cargo)
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap_or_else(|e| panic!("could not run `{cargo} metadata`: {e}"));
    assert!(
        out.status.success(),
        "`{cargo} metadata` failed ({}):\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("could not parse `{cargo} metadata` output as JSON: {e}"));

    let mut names = BTreeMap::new();
    for pkg in meta["packages"]
        .as_array()
        .expect("`packages` array in cargo metadata")
    {
        let id = pkg["id"].as_str().expect("package id").to_owned();
        let name = pkg["name"].as_str().expect("package name").to_owned();
        names.insert(id, name);
    }

    let members: BTreeSet<String> = meta["workspace_members"]
        .as_array()
        .expect("`workspace_members` array in cargo metadata")
        .iter()
        .map(|id| id.as_str().expect("workspace member id").to_owned())
        .collect();

    let mut edges = BTreeMap::new();
    for node in meta["resolve"]["nodes"]
        .as_array()
        .expect("`resolve.nodes` in cargo metadata")
    {
        let id = node["id"].as_str().expect("resolve node id").to_owned();
        let mut deps = Vec::new();
        for dep in node["deps"].as_array().expect("resolve node deps") {
            // `dep_kinds` has been emitted by every cargo since 1.41; if it is
            // absent the walk below would silently see an empty graph, so this
            // fails loudly instead.
            let kinds = dep["dep_kinds"]
                .as_array()
                .expect("`dep_kinds` on every resolve dep (cargo >= 1.41)");
            // `kind: null` is a normal dependency; `"build"` is a build
            // dependency, which also becomes part of producing the binary.
            // `"dev"` is excluded -- see the module docs.
            let ships = kinds
                .iter()
                .any(|k| k["kind"].is_null() || k["kind"] == "build");
            if ships {
                deps.push(dep["pkg"].as_str().expect("dep pkg id").to_owned());
            }
        }
        edges.insert(id, deps);
    }

    Graph {
        names,
        edges,
        members,
    }
}

/// Breadth-first walk of `graph` from the workspace member named `root`.
///
/// Returns the ids reached (including `root`'s own) and, for each, the id it was
/// first reached from -- which is what lets a failure print the actual edge
/// chain instead of just a crate name. Breadth-first so that chain is the
/// shortest one.
fn closure_of(graph: &Graph, root: &str) -> (BTreeSet<String>, BTreeMap<String, String>) {
    let root_id = graph
        .members
        .iter()
        .find(|id| graph.names.get(*id).map(String::as_str) == Some(root))
        .unwrap_or_else(|| panic!("`{root}` is not a member of this workspace"))
        .clone();

    let mut reached = BTreeSet::from([root_id.clone()]);
    let mut came_from: BTreeMap<String, String> = BTreeMap::new();
    let mut queue = VecDeque::from([root_id]);
    while let Some(current) = queue.pop_front() {
        for next in graph.edges.get(&current).into_iter().flatten() {
            if reached.insert(next.clone()) {
                came_from.insert(next.clone(), current.clone());
                queue.push_back(next.clone());
            }
        }
    }
    (reached, came_from)
}

/// Wraps a comma-separated crate list so a 16-name failure message does not
/// print as one 175-column line.
fn wrap(names: &[&str], indent: &str, width: usize) -> String {
    let mut lines: Vec<String> = Vec::new();
    for name in names {
        match lines.last_mut() {
            Some(line) if line.len() + 2 + name.len() <= width => {
                line.push_str(", ");
                line.push_str(name);
            }
            _ => lines.push((*name).to_owned()),
        }
    }
    lines
        .iter()
        .map(|line| format!("{indent}{line}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Renders `ssk-daemon -> ssk-config -> ssk-gates` for a package in the closure.
fn edge_chain(graph: &Graph, came_from: &BTreeMap<String, String>, target: &str) -> String {
    let mut chain = vec![target.to_owned()];
    let mut current = target.to_owned();
    while let Some(parent) = came_from.get(&current) {
        chain.push(parent.clone());
        current = parent.clone();
    }
    chain.reverse();
    chain
        .iter()
        .map(|id| graph.names[id].as_str())
        .collect::<Vec<_>>()
        .join(" -> ")
}

/// The workspace-member names in `sskd`'s shipping closure, plus the walk's
/// predecessor map.
fn daemon_closure() -> (Graph, BTreeSet<String>, BTreeMap<String, String>) {
    let graph = load_graph();
    let (reached, came_from) = closure_of(&graph, ROOT);
    let internal = reached
        .iter()
        .filter(|id| graph.members.contains(*id))
        .map(|id| graph.names[id].clone())
        .collect();
    (graph, internal, came_from)
}

// ---------------------------------------------------------------------------
// The two assertions.
// ---------------------------------------------------------------------------

#[test]
fn decision_core_stays_out_of_the_daemon() {
    let (graph, closure, came_from) = daemon_closure();

    let violations: Vec<&str> = DENIED_CORE
        .iter()
        .copied()
        .filter(|name| closure.contains(*name))
        .collect();
    if violations.is_empty() {
        return;
    }

    let mut chains = String::new();
    for name in &violations {
        let id = graph
            .names
            .iter()
            .find(|(_, n)| n == name)
            .map(|(id, _)| id.clone())
            .expect("a crate in the closure has an id");
        chains.push_str(&format!("      {}\n", edge_chain(&graph, &came_from, &id)));
    }

    panic!(
        "\n\
         ssk-daemon's dependency closure has regained a decision-core crate.\n\
         \n\
         \x20   Forbidden, and now reachable from the shipping `sskd` binary:\n\
         \x20     {}\n\
         \n\
         \x20   Reached by:\n\
         {chains}\n\
         WHY THIS EDGE IS FORBIDDEN\n\
         \n\
         \x20 ADR 0008 -- docs/adr/0008-flow-path-owns-the-per-connection-decision.md\n\
         \x20 -- decided that ssk-netadmin's FlowDescriptor -> PolicyEngine::evaluate\n\
         \x20 -> RouteOrchestrator::plan -> RouteExecutor::connect spine is the\n\
         \x20 per-connection decision path, and the only one. sskd does not call\n\
         \x20 ssk_runtime::run_to_outcome and will not. The decision core is therefore\n\
         \x20 not part of the shipping daemon.\n\
         \n\
         \x20 Before that ADR, six of these crates -- 7,626 LOC -- were linked into\n\
         \x20 sskd by exactly ONE edge: ssk-config's HypercubeConfig.axes reused\n\
         \x20 ssk_gates::pch::Axis. No decision logic among them ever executed in the\n\
         \x20 daemon; the only code reached at runtime was that enum's derived\n\
         \x20 Deserialize. One import pulled in 7,626 lines of dead weight, and it went\n\
         \x20 unnoticed for months. This test exists because that mistake is cheap to\n\
         \x20 make, invisible in review, and undetectable without a mechanical check.\n\
         \n\
         WHAT TO DO NOW\n\
         \n\
         \x20 * If the edge is accidental -- the usual case, and the case above was --\n\
         \x20   remove it. A type that both the product path and the decision core\n\
         \x20   need belongs in ssk-types, which both already depend on. That is\n\
         \x20   precisely how ADR 0008 severed the Axis edge: the enum moved, no\n\
         \x20   behaviour changed, and six crates left the binary.\n\
         \n\
         \x20 * If the decision core is genuinely meant to return to the shipping\n\
         \x20   daemon, that is a deliberate architectural reversal, not a test to\n\
         \x20   edit. ADR 0008 leaves that question open on purpose and names the\n\
         \x20   three measurements it waits on. Amend the ADR first -- its\n\
         \x20   Consequences section states the 16-crate closure as a verified fact,\n\
         \x20   so that statement becomes false the moment you land this -- then\n\
         \x20   update DENIED_CORE and EXPECTED_CLOSURE in this file, in the same\n\
         \x20   commit as the manifest change, citing the amended ADR.\n\
         \n\
         \x20 Do not silence this test, and do not mark it #[ignore]. If it is wrong,\n\
         \x20 the ADR is what is wrong.\n",
        violations.join(", ")
    );
}

#[test]
fn daemon_dependency_closure_is_the_set_adr_0008_recorded() {
    let (_graph, closure, _came_from) = daemon_closure();

    let expected: BTreeSet<String> = EXPECTED_CLOSURE.iter().map(|s| (*s).to_owned()).collect();
    let added: Vec<&str> = closure
        .difference(&expected)
        .map(String::as_str)
        .collect::<Vec<_>>();
    let removed: Vec<&str> = expected
        .difference(&closure)
        .map(String::as_str)
        .collect::<Vec<_>>();
    if added.is_empty() && removed.is_empty() {
        return;
    }

    let render = |set: &[&str]| {
        if set.is_empty() {
            "(none)".to_owned()
        } else {
            set.join(", ")
        }
    };
    panic!(
        "\n\
         ssk-daemon's workspace-internal dependency closure changed.\n\
         \n\
         \x20   Added:   {}\n\
         \x20   Removed: {}\n\
         \n\
         \x20   Recorded ({} crates, ADR 0008 Consequences):\n\
         {}\n\
         \n\
         THIS IS A TRIPWIRE, NOT A PROHIBITION.\n\
         \n\
         \x20 Growing sskd's closure is allowed. Growing it by accident is not, and\n\
         \x20 the two are indistinguishable in a diff -- which is the whole reason\n\
         \x20 this list is pinned rather than merely documented. A deny-list of the\n\
         \x20 decision-core crates by name (DENIED_CORE, above) cannot do this job on\n\
         \x20 its own: rename one of them and it silently matches nothing forever.\n\
         \x20 This assertion is what survives a rename.\n\
         \n\
         BEFORE YOU EDIT EXPECTED_CLOSURE\n\
         \n\
         \x20 1. Check any ADDED crate against DENIED_CORE in this file, and against\n\
         \x20    its closure. If it is a decision-core crate, or a rename of one, or\n\
         \x20    pulls one in, stop and read decision_core_stays_out_of_the_daemon --\n\
         \x20    ADR 0008 forbids that edge and amending the ADR comes first.\n\
         \n\
         \x20 2. Confirm you meant to link the crate into the shipping sskd binary\n\
         \x20    rather than into a test. Dev-dependencies are excluded from this\n\
         \x20    closure by construction, so anything appearing here ships to users.\n\
         \n\
         \x20 3. A REMOVED crate is not automatically good news. ssk-netadmin leaving\n\
         \x20    this set would mean the daemon no longer reaches the per-connection\n\
         \x20    decision path ADR 0008 designates as its owner; ssk-winhost leaving\n\
         \x20    it would mean the Windows pipe DACL, the S-1-5-18 owner check and the\n\
         \x20    impersonation-based peer authentication are no longer injected.\n\
         \n\
         \x20 Then update EXPECTED_CLOSURE in the same commit as the manifest change.\n",
        render(&added),
        render(&removed),
        EXPECTED_CLOSURE.len(),
        wrap(EXPECTED_CLOSURE, "      ", 66)
    );
}
