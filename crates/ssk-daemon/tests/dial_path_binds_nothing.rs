//! CO-1 of docs/M2_LOCAL_INGRESS_DESIGN.md (2.3, 24.2.1): nothing in the dial
//! path binds an interface or a source address.
//!
//! # Why this file exists
//!
//! The owner-approved primary scenario is a laptop that also runs a third-party
//! VPN application. Kaleidoscorp's `Direct` egress must then follow the
//! operating system's routing table, and so go through that application's
//! adapter. It does exactly as long as the dial sockets carry no decision of
//! our own: a bound source address, an interface binding (`SO_BINDTODEVICE`,
//! `IP_UNICAST_IF`, `IPV6_UNICAST_IF`, `IP_BOUND_IF`) or a `bind` before the
//! `connect` each take the egress choice away from the routing table and would
//! send Direct traffic around the tunnel. The roadmap once planned such a call
//! for `direct::connect_tcp` (docs/P4_INGRESS_DESIGN.md, P4c); the design
//! withdraws it for this path.
//!
//! # What these tests prove, and what they do not
//!
//! They read source and the resolved dependency graph. They prove that the
//! code which dials, `ssk-netcore`'s `direct.rs` and the executor that calls
//! it, contains no call that could bind or steer a socket, and that no
//! dependency or `unsafe` could add one behind its back. They do NOT show what
//! the operating system then did with a socket: that is the route-flip test of
//! C-CO1b on Linux, and on Windows only the manual run of ACCEPT-5 (24.2).
//!
//! The behavioural half, the same claim read from a real socket, is
//! `direct_dial_leaves_device_and_source_to_the_os` in `ssk-netcore`'s
//! `direct.rs`.
//!
//! # Where this runs
//!
//! Nowhere new: like `dependency_closure.rs` it is part of the daemon's test
//! run on both legs of CI, and it reads only files and `cargo metadata`, so
//! both legs give one answer.
//!
//! The needles are assembled with `concat!`, as the design asks. For one of
//! them it is not optional: the repository-wide scan of
//! `check_resolve_via_has_no_caller` reads this file too.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Direct dependencies `ssk-netcore` may have over normal and build edges
/// (dev-dependencies do not link into `sskd`). The roots of `ssk-netcore` and
/// `ssk-daemon` are `forbid(unsafe_code)` (checked below), so a crate outside
/// this list is the only way to a `setsockopt`. Adding one needs a reason that
/// is about the dial path: C-H1 adds `socket2` for keepalive and extends this
/// list in the same commit.
const NETCORE_DIRECT_DEPENDENCIES: &[&str] = &[
    "rustls",
    "rustls-native-certs",
    "rustls-pki-types",
    "ssk-netadmin",
    "ssk-types",
    "thiserror",
    "tokio",
    "tokio-rustls",
    "tracing",
];

/// What must not appear in the non-test text of the dial path. Each is a way
/// to take the egress decision from the routing table. `bind` also catches
/// tokio's `TcpSocket::bind` and `UdpSocket::bind`.
const NEEDLES: &[&str] = &[
    concat!(".", "bind("),
    concat!("::", "bind("),
    concat!("bind", "_device"),
    concat!("SO_BIND", "TODEVICE"),
    concat!("IP_UNICAST", "_IF"),
    concat!("IPV6_UNICAST", "_IF"),
    concat!("IP_BOUND", "_IF"),
    concat!("set", "sockopt"),
    concat!("windows", "_sys"),
    concat!("libc", "::"),
];

/// The entry point of the `DnsOverride` resolver, the one place in the crate
/// that binds a wildcard UDP socket (`dns.rs`, which the needle scan skips
/// because of it). It is only unreachable from a dial while nothing calls it.
const RESOLVE_VIA_CALL: &str = concat!("resolve_", "via(");

/// Ingress files that must obey the same rule once they exist. Files that do
/// not exist yet are skipped; the listener, which has to `bind`, is not here.
const INGRESS_FILES: &[&str] = &["engine.rs", "flow.rs", "pump.rs"];

// ---------------------------------------------------------------------------
// Where things are.
// ---------------------------------------------------------------------------

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn crate_src(name: &str) -> PathBuf {
    workspace_root().join("crates").join(name).join("src")
}

fn netcore_src() -> PathBuf {
    crate_src("ssk-netcore")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()))
}

fn shown(path: &Path) -> String {
    path.strip_prefix(workspace_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Every `.rs` file below `dir`, sorted, without descending into a directory
/// whose name is in `skipped`.
fn rust_files(dir: &Path, skipped: &[&str]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let entries =
        fs::read_dir(dir).unwrap_or_else(|e| panic!("could not list {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !skipped.contains(&name) {
                found.extend(rust_files(&path, skipped));
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            found.push(path);
        }
    }
    found.sort();
    found
}

/// The `ssk-netcore` sources the needle scan covers: every file except
/// `dns.rs`, plus the ingress files that already exist. Never empty of the two
/// files that dial, so a moved directory cannot turn the scan into a no-op.
fn dial_path_files() -> Vec<PathBuf> {
    let src = netcore_src();
    let mut files: Vec<PathBuf> = rust_files(&src, &[])
        .into_iter()
        .filter(|path| path.file_name().is_some_and(|n| n != "dns.rs"))
        .collect();
    for required in ["direct.rs", "executor.rs"] {
        assert!(
            files.contains(&src.join(required)),
            "{} is not among the files this test scans; the dial path moved",
            shown(&src.join(required))
        );
    }
    let ingress = crate_src("ssk-daemon").join("ingress");
    for name in INGRESS_FILES {
        let path = ingress.join(name);
        if path.is_file() {
            files.push(path);
        }
    }
    files
}

// ---------------------------------------------------------------------------
// The scanner.
// ---------------------------------------------------------------------------

/// The text of `source` before its first column-0 `#[cfg(test)]`: the code
/// that ships. Unit tests and their fakes may bind and set options freely.
fn non_test_text(source: &str) -> &str {
    let mut offset = 0;
    for line in source.split_inclusive('\n') {
        if line.starts_with("#[cfg(test)]") {
            return &source[..offset];
        }
        offset += line.len();
    }
    source
}

/// Top-level items after the cut that are not themselves `#[cfg(test)]`.
///
/// Cutting at the first `#[cfg(test)]` would hide shipping code appended after
/// a test module, which is exactly where a new function lands when a file ends
/// with its tests. Source is rustfmt-formatted, so a top-level item starts in
/// column 0.
fn shipping_items_after_the_cut(source: &str) -> Vec<String> {
    const ITEM_STARTS: &[&str] = &[
        "pub ",
        "pub(",
        "fn ",
        "async fn ",
        "const ",
        "static ",
        "struct ",
        "enum ",
        "union ",
        "trait ",
        "impl",
        "mod ",
        "use ",
        "type ",
        "extern ",
        "unsafe ",
        "macro_rules!",
    ];
    let tail = &source[non_test_text(source).len()..];
    let mut test_only = false;
    let mut shipping = Vec::new();
    for line in tail.lines() {
        if line.starts_with("#[cfg(test)]") {
            test_only = true;
        } else if line.starts_with("#[") || line.starts_with("//") {
            // Another attribute or a comment between the attribute and its item.
        } else if ITEM_STARTS.iter().any(|start| line.starts_with(start)) {
            if !test_only {
                shipping.push(line.to_owned());
            }
            test_only = false;
        }
    }
    shipping
}

/// The needles that occur in `text`.
fn needle_hits(text: &str) -> Vec<&'static str> {
    NEEDLES
        .iter()
        .copied()
        .filter(|needle| text.contains(needle))
        .collect()
}

/// A scan that cannot fail proves nothing. This runs the scanner over small
/// sources whose answer is known, before it is trusted with the real files.
fn the_scan_can_fail() {
    for needle in NEEDLES {
        let source = format!("fn dial() {{ socket{needle}x }}\n");
        assert_eq!(
            needle_hits(non_test_text(&source)),
            vec![*needle],
            "the scan does not see {needle:?} in shipping code"
        );
    }
    assert_eq!(
        needle_hits("// a comment that says setsockopt\n"),
        vec![concat!("set", "sockopt")],
        "a needle in a comment is a hit: say it another way"
    );

    let after_tests = format!(
        "fn dial() {{}}\n#[cfg(test)]\nmod tests {{\n    fn t() {{ s{}x }}\n}}\n",
        NEEDLES[0]
    );
    assert!(
        needle_hits(non_test_text(&after_tests)).is_empty(),
        "test code is not shipping code"
    );
    assert!(shipping_items_after_the_cut(&after_tests).is_empty());

    let two_modules = "fn dial() {}\n#[cfg(test)]\npub(crate) mod fakes {\n}\n\n/// docs\n#[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n}\n";
    assert!(shipping_items_after_the_cut(two_modules).is_empty());

    let hidden = format!(
        "fn dial() {{}}\n#[cfg(test)]\nmod tests {{\n}}\n\npub fn sneaky() {{ s{}x }}\n",
        NEEDLES[0]
    );
    assert_eq!(
        shipping_items_after_the_cut(&hidden),
        vec![format!("pub fn sneaky() {{ s{}x }}", NEEDLES[0])],
        "shipping code after a test module is hidden from the scan"
    );
    assert_eq!(non_test_text("no tests here\n"), "no tests here\n");
}

// ---------------------------------------------------------------------------
// The dependency graph.
// ---------------------------------------------------------------------------

/// Package names of `ssk-netcore`'s direct dependencies over normal and build
/// edges, from `cargo metadata` (the method of `dependency_closure.rs`: cargo's
/// own resolver output, every target, no dev edges).
///
/// Every failure path panics: a guard that quietly returns when it cannot
/// measure reports success for the wrong reason.
fn netcore_direct_dependencies() -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
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

    let packages = meta["packages"].as_array().expect("`packages` in metadata");
    let name_of = |id: &str| -> String {
        packages
            .iter()
            .find(|pkg| pkg["id"] == id)
            .and_then(|pkg| pkg["name"].as_str())
            .unwrap_or_else(|| panic!("no package `{id}` in cargo metadata"))
            .to_owned()
    };
    let netcore = meta["workspace_members"]
        .as_array()
        .expect("`workspace_members` in metadata")
        .iter()
        .filter_map(Value::as_str)
        .find(|id| name_of(id) == "ssk-netcore")
        .expect("`ssk-netcore` is a workspace member");
    let node = meta["resolve"]["nodes"]
        .as_array()
        .expect("`resolve.nodes` in metadata")
        .iter()
        .find(|node| node["id"] == netcore)
        .expect("`ssk-netcore` is in the resolve graph");

    node["deps"]
        .as_array()
        .expect("resolve node deps")
        .iter()
        .filter(|dep| {
            dep["dep_kinds"]
                .as_array()
                .expect("`dep_kinds` on every resolve dep (cargo >= 1.41)")
                .iter()
                .any(|kind| kind["kind"].is_null() || kind["kind"] == "build")
        })
        .map(|dep| name_of(dep["pkg"].as_str().expect("dep pkg id")))
        .collect()
}

// ---------------------------------------------------------------------------
// The three checks of `dial_path_binds_nothing_static`.
// ---------------------------------------------------------------------------

/// (a) No dependency outside the list, and nothing that could call
/// `setsockopt` without one.
fn check_dependencies() {
    let direct = netcore_direct_dependencies();
    let extra: Vec<&String> = direct
        .iter()
        .filter(|name| !NETCORE_DIRECT_DEPENDENCIES.contains(&name.as_str()))
        .collect();
    assert!(
        extra.is_empty(),
        "ssk-netcore gained direct dependencies {extra:?}. A crate that can set socket options \
         would let the dial path bind an interface or a source address, which takes the egress \
         decision from the routing table (CO-1, docs/M2_LOCAL_INGRESS_DESIGN.md 2.3). If the \
         crate is needed, extend NETCORE_DIRECT_DEPENDENCIES in the same commit and say why it \
         cannot touch the dial path's addressing."
    );

    // The list only means something while nothing can reach `setsockopt`
    // through an `unsafe` declaration of its own.
    for root in [
        netcore_src().join("lib.rs"),
        crate_src("ssk-daemon").join("lib.rs"),
    ] {
        assert!(
            read(&root).starts_with("#![forbid(unsafe_code)]"),
            "{} no longer starts with #![forbid(unsafe_code)]; without it a socket option \
             needs no dependency",
            shown(&root)
        );
    }
}

/// (b) The non-test text of every dial-path file contains no needle, and the
/// cut that defines "non-test" hides no shipping code.
fn check_needles() {
    let mut violations = Vec::new();
    for path in dial_path_files() {
        let source = read(&path);
        for line in shipping_items_after_the_cut(&source) {
            violations.push(format!(
                "{}: shipping item after a #[cfg(test)] item (the scan cannot see it): {line}",
                shown(&path)
            ));
        }
        for needle in needle_hits(non_test_text(&source)) {
            violations.push(format!("{}: {needle}", shown(&path)));
        }
    }
    assert!(
        violations.is_empty(),
        "the dial path may not bind a socket or pick an interface or a source address \
         (CO-1, docs/M2_LOCAL_INGRESS_DESIGN.md 2.3): each of these takes the egress \
         decision from the operating system's routing table and would send Direct traffic \
         around a third-party VPN adapter.\n  {}",
        violations.join("\n  ")
    );
}

/// (c) Nothing calls the `DnsOverride` resolver, whose wildcard UDP bind is the
/// reason `dns.rs` is outside the needle scan. Every `.rs` file of the
/// repository is read; only the definition may match.
fn check_resolve_via_has_no_caller() {
    let mut hits = Vec::new();
    for path in rust_files(&workspace_root(), &["target", ".git", "node_modules"]) {
        for line in read(&path).lines() {
            if line.contains(RESOLVE_VIA_CALL) {
                hits.push((shown(&path), line.trim().to_owned()));
            }
        }
    }
    let defined_in = Path::new("crates")
        .join("ssk-netcore")
        .join("src")
        .join("executor.rs")
        .display()
        .to_string();
    assert!(
        hits.len() == 1 && hits[0].0 == defined_in && hits[0].1.contains("fn "),
        "`resolve_via` is the entry point of the DnsOverride resolver, which binds a wildcard UDP \
         socket in dns.rs (outside the needle scan). It may only be defined, not called: the \
         definition in {defined_in} is expected to be the single match, found {hits:?}"
    );
}

#[test]
fn dial_path_binds_nothing_static() {
    the_scan_can_fail();
    check_dependencies();
    check_needles();
    check_resolve_via_has_no_caller();
}

// ---------------------------------------------------------------------------
// One dial function.
// ---------------------------------------------------------------------------

/// The name a `fn` line declares, when `line` is a function declaration.
fn declared_fn(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let at = trimmed.find("fn ")?;
    let (qualifiers, rest) = trimmed.split_at(at);
    let qualifiers_only = qualifiers.split_whitespace().all(|word| {
        matches!(
            word,
            "pub" | "pub(crate)" | "pub(super)" | "async" | "const" | "unsafe"
        )
    });
    if !qualifiers_only {
        return None;
    }
    let name = &rest["fn ".len()..];
    let end = name
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(name.len());
    Some(&name[..end])
}

/// Every occurrence of `needle` in the code lines of `text` (full-line
/// comments excluded), with the function it sits in. A function's own
/// declaration is not a use of it.
fn occurrences(text: &str, needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let mut code = line;
        if let Some(name) = declared_fn(line) {
            name.clone_into(&mut current);
            // The declaration is not a use of itself; a body on the same line is.
            code = &line[line
                .find("fn ")
                .map_or(0, |at| at + "fn ".len() + name.len())..];
        }
        for _ in code.matches(needle) {
            found.push(current.clone());
        }
    }
    found
}

/// The declarations of a function called `name`.
fn declarations(text: &str, name: &str) -> usize {
    text.lines()
        .filter(|line| declared_fn(line) == Some(name))
        .count()
}

#[test]
fn first_hop_and_direct_share_one_dial_function() {
    let src = netcore_src();
    let executor = read(&src.join("executor.rs"));
    let executor = non_test_text(&executor);

    // The destination of a Direct route and the first hop of a chain are the
    // only two dials the executor makes. After C-N3 both go through the
    // function that takes a host that may be a name; the literal-only one is
    // reached through it.
    let mut calls = occurrences(executor, "connect_host(");
    calls.extend(occurrences(executor, "connect_tcp("));
    calls.sort();
    assert_eq!(
        calls,
        ["connect_chain", "connect_direct"],
        "the executor must dial exactly twice, from connect_direct and from the first hop of \
         connect_chain, through direct.rs; a third dial is a second way to open a socket that \
         this test and the CO-1 scan do not know"
    );

    // Nowhere else, and no second definition of either function.
    let mut defined = 0;
    let mut dials = Vec::new();
    for path in rust_files(&src, &[]) {
        let text = read(&path);
        let text = non_test_text(&text);
        defined += declarations(text, "connect_tcp") + declarations(text, "connect_host");
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        for (needle, callers) in [
            ("connect_tcp(", occurrences(text, "connect_tcp(")),
            ("connect_host(", occurrences(text, "connect_host(")),
        ] {
            for caller in callers {
                dials.push(format!("{file}: {caller} calls {needle}"));
            }
        }
    }
    assert_eq!(
        defined, 2,
        "connect_tcp and connect_host are each declared once, in direct.rs"
    );
    dials.sort();
    assert_eq!(
        dials,
        [
            "direct.rs: connect_host calls connect_tcp(",
            "executor.rs: connect_chain calls connect_host(",
            "executor.rs: connect_direct calls connect_host(",
        ],
        "both of the executor's dials must go through connect_host (connect_tcp alone would hand a \
         name to the OS resolver with no bound), and nothing else may call either function"
    );

    // The sockets themselves: the literal path and the pinned-address path of
    // direct.rs. `dns.rs` belongs to the DnsOverride resolver nothing calls.
    let mut sockets = Vec::new();
    for path in rust_files(&src, &[]) {
        let file = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if file == "dns.rs" {
            continue;
        }
        let text = read(&path);
        let text = non_test_text(&text);
        for needle in ["TcpStream::connect(", "TcpSocket"] {
            for caller in occurrences(text, needle) {
                sockets.push(format!("{file}: {caller} uses {needle}"));
            }
        }
    }
    sockets.sort();
    assert_eq!(
        sockets,
        [
            "direct.rs: connect_in_order uses TcpStream::connect(",
            "direct.rs: connect_tcp uses TcpStream::connect(",
        ],
        "a socket is created somewhere other than the two functions of direct.rs"
    );
}
