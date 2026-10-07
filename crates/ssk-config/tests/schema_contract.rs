//! What pins the exported schema.
//!
//! `AppConfig::schema_json` is written by hand: nothing generates it from the
//! types, and `schema_snapshot_stable` only looks for four substrings. Editors,
//! CI and operators read it as the description of what `sskd` accepts, so these
//! tests hold it against the parser itself, with a validator that understands
//! exactly the keywords the schema uses (a keyword it does not know fails the
//! test instead of being skipped).

use serde_json::{json, Value};
use ssk_config::ingress::{DestinationLogging, DirectAddressFamilies, IngressHardening};
use ssk_config::routing::{AdapterTransport, RoutingAction, RoutingAdapter, RoutingRule};
use ssk_config::{AppConfig, CURRENT_CONFIG_VERSION};
use std::collections::BTreeSet;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// A pattern matcher for the subset of regular expressions the schema uses.
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum Atom {
    Any,
    Literal(char),
    Class(Vec<(char, char)>),
}

impl Atom {
    fn accepts(&self, c: char) -> bool {
        match self {
            Atom::Any => true,
            Atom::Literal(literal) => *literal == c,
            Atom::Class(ranges) => ranges.iter().any(|(low, high)| (*low..=*high).contains(&c)),
        }
    }
}

struct Pattern {
    anchored_start: bool,
    anchored_end: bool,
    items: Vec<(Atom, usize, usize)>,
}

impl Pattern {
    /// Anchors, `.`, escaped punctuation, `[...]` with ranges, `+ * ? {n} {n,m}`.
    /// Anything else panics: a pattern this cannot read must not pass unchecked.
    fn compile(pattern: &str) -> Self {
        let chars: Vec<char> = pattern.chars().collect();
        let anchored_start = chars.first() == Some(&'^');
        let mut at = usize::from(anchored_start);
        let anchored_end = chars.len() > at && chars.last() == Some(&'$');
        let end = chars.len() - usize::from(anchored_end);
        let mut items = Vec::new();
        while at < end {
            let atom = match chars[at] {
                '.' => {
                    at += 1;
                    Atom::Any
                }
                '\\' => {
                    let escaped = *chars.get(at + 1).expect("dangling escape");
                    assert!(
                        !escaped.is_alphanumeric(),
                        "unsupported escape \\{escaped} in {pattern:?}"
                    );
                    at += 2;
                    Atom::Literal(escaped)
                }
                '[' => {
                    at += 1;
                    assert_ne!(chars[at], '^', "negated class in {pattern:?}");
                    let mut ranges = Vec::new();
                    while chars[at] != ']' {
                        let low = chars[at];
                        if chars[at + 1] == '-' && chars[at + 2] != ']' {
                            ranges.push((low, chars[at + 2]));
                            at += 3;
                        } else {
                            ranges.push((low, low));
                            at += 1;
                        }
                    }
                    at += 1;
                    Atom::Class(ranges)
                }
                c if "()|?*+{}^$".contains(c) => panic!("unsupported {c:?} in {pattern:?}"),
                c => {
                    at += 1;
                    Atom::Literal(c)
                }
            };
            let (min, max) = if at < end {
                match chars[at] {
                    '+' => {
                        at += 1;
                        (1, usize::MAX)
                    }
                    '*' => {
                        at += 1;
                        (0, usize::MAX)
                    }
                    '?' => {
                        at += 1;
                        (0, 1)
                    }
                    '{' => {
                        let close = at
                            + chars[at..end]
                                .iter()
                                .position(|c| *c == '}')
                                .expect("unclosed {");
                        let body: String = chars[at + 1..close].iter().collect();
                        at = close + 1;
                        match body.split_once(',') {
                            Some((low, high)) => (low.parse().unwrap(), high.parse().unwrap()),
                            None => (body.parse().unwrap(), body.parse().unwrap()),
                        }
                    }
                    _ => (1, 1),
                }
            } else {
                (1, 1)
            };
            items.push((atom, min, max));
        }
        Pattern {
            anchored_start,
            anchored_end,
            items,
        }
    }

    fn is_match(&self, text: &str) -> bool {
        let text: Vec<char> = text.chars().collect();
        let starts = if self.anchored_start {
            0..=0
        } else {
            0..=text.len()
        };
        starts
            .into_iter()
            .any(|start| Self::match_from(&self.items, &text[start..], self.anchored_end))
    }

    fn match_from(items: &[(Atom, usize, usize)], text: &[char], must_end: bool) -> bool {
        let Some(((atom, min, max), rest)) = items.split_first() else {
            return !must_end || text.is_empty();
        };
        let mut most = 0;
        while most < *max && most < text.len() && atom.accepts(text[most]) {
            most += 1;
        }
        (*min..=most)
            .rev()
            .any(|taken| Self::match_from(rest, &text[taken..], must_end))
    }
}

// ---------------------------------------------------------------------------
// A validator for the keywords `schema_json` and `routing::schema_json` use.
// ---------------------------------------------------------------------------

fn has_type(value: &Value, name: &str) -> bool {
    match name {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => value.is_i64() || value.is_u64(),
        other => panic!("unknown type {other:?}"),
    }
}

fn size(argument: &Value) -> usize {
    usize::try_from(argument.as_u64().expect("a size")).expect("a size that fits")
}

fn check(schema: &Value, value: &Value, at: &str, out: &mut Vec<String>) {
    let Some(keywords) = schema.as_object() else {
        out.push(format!("{at}: a schema node that is not an object"));
        return;
    };
    for (keyword, argument) in keywords {
        match keyword.as_str() {
            "$schema" | "$id" | "title" | "default" => {}
            "type" => {
                let name = argument.as_str().expect("a type name");
                if !has_type(value, name) {
                    out.push(format!("{at}: not of type {name}"));
                }
            }
            "const" => {
                if value != argument {
                    out.push(format!("{at}: not the constant {argument}"));
                }
            }
            "enum" => {
                if !argument.as_array().expect("members").contains(value) {
                    out.push(format!("{at}: not one of {argument}"));
                }
            }
            "required" => {
                if let Some(object) = value.as_object() {
                    for name in argument.as_array().expect("names") {
                        let name = name.as_str().expect("a name");
                        if !object.contains_key(name) {
                            out.push(format!("{at}: missing required `{name}`"));
                        }
                    }
                }
            }
            "properties" => {
                if let Some(object) = value.as_object() {
                    for (name, sub) in argument.as_object().expect("properties") {
                        if let Some(child) = object.get(name) {
                            check(sub, child, &format!("{at}/{name}"), out);
                        }
                    }
                }
            }
            "additionalProperties" => {
                assert_eq!(argument, &json!(false), "only `false` is understood");
                if let Some(object) = value.as_object() {
                    let known = keywords.get("properties").and_then(Value::as_object);
                    for name in object.keys() {
                        if !known.is_some_and(|known| known.contains_key(name)) {
                            out.push(format!("{at}: unexpected key `{name}`"));
                        }
                    }
                }
            }
            "items" => {
                if let Some(array) = value.as_array() {
                    for (index, element) in array.iter().enumerate() {
                        check(argument, element, &format!("{at}/{index}"), out);
                    }
                }
            }
            "minItems" => {
                if value.as_array().is_some_and(|a| a.len() < size(argument)) {
                    out.push(format!("{at}: fewer than {argument} items"));
                }
            }
            "maxItems" => {
                if value.as_array().is_some_and(|a| a.len() > size(argument)) {
                    out.push(format!("{at}: more than {argument} items"));
                }
            }
            "minLength" => {
                if value
                    .as_str()
                    .is_some_and(|s| s.chars().count() < size(argument))
                {
                    out.push(format!("{at}: shorter than {argument}"));
                }
            }
            "maxLength" => {
                if value
                    .as_str()
                    .is_some_and(|s| s.chars().count() > size(argument))
                {
                    out.push(format!("{at}: longer than {argument}"));
                }
            }
            "minimum" => {
                let limit = argument.as_f64().expect("a number");
                if value.as_f64().is_some_and(|n| n < limit) {
                    out.push(format!("{at}: below {argument}"));
                }
            }
            "maximum" => {
                let limit = argument.as_f64().expect("a number");
                if value.as_f64().is_some_and(|n| n > limit) {
                    out.push(format!("{at}: above {argument}"));
                }
            }
            "pattern" => {
                let pattern = Pattern::compile(argument.as_str().expect("a pattern"));
                if value.as_str().is_some_and(|s| !pattern.is_match(s)) {
                    out.push(format!("{at}: does not match {argument}"));
                }
            }
            "anyOf" | "oneOf" => {
                let passing = argument
                    .as_array()
                    .expect("alternatives")
                    .iter()
                    .filter(|sub| violations(sub, value).is_empty())
                    .count();
                if passing == 0 || (keyword == "oneOf" && passing > 1) {
                    out.push(format!(
                        "{at}: matches {passing} of the {keyword} alternatives"
                    ));
                }
            }
            other => out.push(format!("{at}: the test validator does not know `{other}`")),
        }
    }
}

fn violations(schema: &Value, value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    check(schema, value, "", &mut out);
    out
}

fn schema_accepts(value: &Value) -> bool {
    violations(&AppConfig::schema_json(), value).is_empty()
}

/// What the daemon does with a document that declares the current version.
fn parser_accepts(value: &Value) -> bool {
    serde_json::from_value::<AppConfig>(value.clone()).is_ok_and(|config| config.validate().is_ok())
}

// ---------------------------------------------------------------------------
// The documents the schema is held against.
// ---------------------------------------------------------------------------

fn default_document() -> Value {
    serde_json::to_value(AppConfig::default()).expect("the default config serialises")
}

/// The default configuration plus every routing shape: all four adapter
/// transports and all three rule actions, with and without the optional keys,
/// and an ingress section with every key off its default. The section stays
/// disabled: an enabled one is checked against the routing section (an IPv6
/// literal adapter needs `any`), which would make this document diverge from the
/// schema on a single edit of `direct_address_families` and hide what the
/// differential test is looking for.
fn rich_config() -> AppConfig {
    let adapter = |id: &str, transport| RoutingAdapter {
        id: id.into(),
        transport,
    };
    let rule = |id: &str,
                priority,
                destination: Option<&str>,
                domain_suffix: Option<&str>,
                port,
                action| {
        RoutingRule {
            id: id.into(),
            priority,
            destination: destination.map(Into::into),
            domain_suffix: domain_suffix.map(Into::into),
            port,
            action,
            require_attestation: port.is_some(),
        }
    };
    let via = |adapter_id: &str| RoutingAction::Adapter {
        adapter_id: adapter_id.into(),
    };
    let mut config = AppConfig::default();
    config.routing.adapters = vec![
        adapter(
            "socks",
            AdapterTransport::Socks5 {
                host: "127.0.0.1".into(),
                port: 1080,
            },
        ),
        adapter(
            "http",
            AdapterTransport::HttpConnect {
                host: "proxy.example.net".into(),
                port: 3128,
            },
        ),
        adapter(
            "tls",
            AdapterTransport::TlsTunnel {
                host: "2001:db8::1".into(),
                port: 8443,
            },
        ),
        adapter(
            "vpn",
            AdapterTransport::OpenVpn {
                profile_id: "company-managed".into(),
            },
        ),
    ];
    config.routing.profiles[0].rules = vec![
        rule(
            "to-socks",
            10,
            Some("example.com"),
            None,
            Some(443),
            via("socks"),
        ),
        rule("to-http", 20, None, Some("example.org"), None, via("http")),
        rule("to-tls", 30, None, None, None, via("tls")),
        rule("to-vpn", 40, None, None, None, via("vpn")),
        rule(
            "direct",
            50,
            Some("192.0.2.1"),
            None,
            Some(80),
            RoutingAction::Direct,
        ),
        rule(
            "blocked",
            60,
            None,
            Some("blocked.example"),
            None,
            RoutingAction::Deny,
        ),
    ];
    config.ingress.listen.address = "127.0.0.7".parse().expect("an address");
    config.ingress.listen.port = 41080;
    config.ingress.hardening = IngressHardening::BestEffort;
    config.ingress.arm_on_start = true;
    config.ingress.direct_address_families = DirectAddressFamilies::Any;
    config.ingress.limits.max_connections = 8;
    config.ingress.limits.accept_rate_per_s = 3;
    config.ingress.limits.handshake_timeout_ms = 300;
    config.ingress.limits.connect_timeout_ms = 400;
    config.ingress.limits.idle_timeout_ms = 500;
    config.ingress.audit.segment_mib = 16;
    config.ingress.audit.retain_segments = 4;
    config.ingress.audit.destination_logging = DestinationLogging::Hashed;
    config
        .validate()
        .expect("the rich configuration is a valid configuration");
    config
}

fn rich_document() -> Value {
    serde_json::to_value(rich_config()).expect("the rich config serialises")
}

// ---------------------------------------------------------------------------
// Tests of the validator itself: a validator that accepts everything would make
// every test below pass for nothing.
// ---------------------------------------------------------------------------

#[test]
fn the_test_validator_can_fail() {
    let version = Pattern::compile("^[0-9]+\\.[0-9]+\\.[0-9]+$");
    assert!(version.is_match("1.0.0") && version.is_match("10.20.300"));
    assert!(!version.is_match("1.0") && !version.is_match("1x0.0") && !version.is_match("v1.0.0"));
    // The pattern as it was written in lib.rs: two backslashes, i.e. a literal
    // backslash and then any character, which no version string contains.
    let doubled = Pattern::compile("^[0-9]+\\\\.[0-9]+\\\\.[0-9]+$");
    assert!(!doubled.is_match("1.0.0") && doubled.is_match("1\\x0\\y0"));
    let id = Pattern::compile("^[a-z0-9][a-z0-9._-]{0,63}$");
    assert!(id.is_match("a") && id.is_match(&"a".repeat(64)) && id.is_match("a._-9"));
    assert!(
        !id.is_match("")
            && !id.is_match(&"a".repeat(65))
            && !id.is_match("A")
            && !id.is_match("-a")
    );

    let schema = json!({
        "type": "object", "required": ["a"], "additionalProperties": false,
        "properties": {
            "a": {"type": "integer", "minimum": 1, "maximum": 3},
            "b": {"enum": ["x", "y"]},
            "c": {"const": true},
            "d": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 2},
            "e": {"anyOf": [{"type": "null"}, {"type": "string", "minLength": 2}]},
            "f": {"oneOf": [{"type": "number"}, {"type": "integer"}]},
            "g": {"type": "string", "pattern": "^a+$"},
            "h": {"type": "string", "maxLength": 2},
        }
    });
    let ok = |value: Value| violations(&schema, &value).is_empty();
    assert!(ok(json!({"a": 1})));
    assert!(ok(
        json!({"a": 3, "b": "y", "c": true, "d": ["s"], "e": null})
    ));
    assert!(ok(json!({"a": 2, "e": "ab", "g": "aaa", "h": "ab"})));
    for bad in [
        json!({}),
        json!([]),
        json!({"a": 0}),
        json!({"a": 4}),
        json!({"a": 1.5}),
        json!({"a": "1"}),
        json!({"a": 1, "b": "z"}),
        json!({"a": 1, "c": false}),
        json!({"a": 1, "d": []}),
        json!({"a": 1, "d": ["a", "b", "c"]}),
        json!({"a": 1, "d": [1]}),
        json!({"a": 1, "e": "a"}),
        json!({"a": 1, "e": 1}),
        json!({"a": 1, "f": 1}),
        json!({"a": 1, "g": "b"}),
        json!({"a": 1, "h": "abc"}),
        json!({"a": 1, "zz": 1}),
    ] {
        assert!(!ok(bad.clone()), "accepted {bad}");
    }
    assert!(
        violations(&json!({"uniqueItems": true}), &json!([]))[0].contains("does not know"),
        "an unknown keyword must be a violation, not a no-op"
    );
}

// ---------------------------------------------------------------------------
// The schema against what the serializer writes and the parser accepts.
// ---------------------------------------------------------------------------

#[test]
fn the_default_and_the_example_documents_validate_against_the_schema() {
    let example = |file: &str| -> Value {
        let text = std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/examples")
                .join(file),
        )
        .unwrap_or_else(|err| panic!("{file}: {err}"));
        serde_yaml::from_str(&text).unwrap_or_else(|err| panic!("{file} is not YAML: {err}"))
    };
    for (name, document) in [
        ("the default configuration", default_document()),
        ("the rich configuration", rich_document()),
        (
            "docs/examples/openvpn-routing.yaml",
            example("openvpn-routing.yaml"),
        ),
        (
            "docs/examples/ingress.example.yaml",
            example("ingress.example.yaml"),
        ),
        (
            "docs/examples/ingress-coexistence.yaml",
            example("ingress-coexistence.yaml"),
        ),
    ] {
        // The parser takes them, the schema must too.
        assert!(parser_accepts(&document), "{name}: the parser refuses it");
        let found = violations(&AppConfig::schema_json(), &document);
        assert!(
            found.is_empty(),
            "{name} does not satisfy the schema: {found:#?}"
        );
    }
}

/// Keys the serializer writes and the schema does not describe. A schema that
/// does not name a key says nothing about it; this list may only shrink, and a
/// stale entry fails the test below.
const UNDESCRIBED: &[&str] = &[
    "/policy/gate_profile/thresholds",
    "/policy/gate_profile/required_evidence",
];

/// The branch of an `anyOf`/`oneOf` that `value` satisfies, or the node itself.
fn branch<'a>(schema: &'a Value, value: &Value) -> &'a Value {
    for keyword in ["anyOf", "oneOf"] {
        if let Some(alternatives) = schema.get(keyword).and_then(Value::as_array) {
            if let Some(chosen) = alternatives
                .iter()
                .find(|sub| violations(sub, value).is_empty())
            {
                return branch(chosen, value);
            }
        }
    }
    schema
}

fn walk_keys(
    schema: &Value,
    value: &Value,
    pointer: &str,
    undescribed: &mut BTreeSet<String>,
    unwritten: &mut Vec<String>,
) {
    let schema = branch(schema, value);
    if let Some(object) = value.as_object() {
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("{pointer}: an object the schema has no properties for"));
        for (name, child) in object {
            match properties.get(name) {
                Some(sub) => walk_keys(
                    sub,
                    child,
                    &format!("{pointer}/{name}"),
                    undescribed,
                    unwritten,
                ),
                None => {
                    undescribed.insert(format!("{pointer}/{name}"));
                }
            }
        }
        for name in properties.keys().filter(|name| !object.contains_key(*name)) {
            unwritten.push(format!("{pointer}/{name}"));
        }
        for name in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|name| !properties.contains_key(*name))
        {
            unwritten.push(format!("{pointer}/{name} (required but not a property)"));
        }
    } else if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
        for (index, element) in array
            .iter()
            .enumerate()
            .filter(|(i, e)| *i == 0 || e.is_object())
        {
            walk_keys(
                items,
                element,
                &format!("{pointer}/{index}"),
                undescribed,
                unwritten,
            );
        }
    }
}

#[test]
fn schema_properties_equal_serialized_default_keys() {
    let schema = AppConfig::schema_json();
    for (name, document) in [("default", default_document()), ("rich", rich_document())] {
        let mut undescribed = BTreeSet::new();
        let mut unwritten = Vec::new();
        walk_keys(&schema, &document, "", &mut undescribed, &mut unwritten);
        // The index is part of the pointer only for arrays of objects.
        let undescribed: BTreeSet<String> = undescribed
            .into_iter()
            .map(|pointer| normalise(&pointer))
            .collect();
        let listed: BTreeSet<String> = UNDESCRIBED.iter().map(|p| (*p).to_string()).collect();
        assert_eq!(
            undescribed, listed,
            "{name}: keys the serializer writes that the schema does not describe \
             (left) against the allow-list (right); the list may only shrink"
        );
        assert!(
            unwritten.is_empty(),
            "{name}: the schema describes keys the serializer never writes: {unwritten:#?}"
        );
    }
}

/// `/routing/adapters/2/transport/host` -> `/routing/adapters/*/transport/host`.
fn normalise(pointer: &str) -> String {
    pointer
        .split('/')
        .map(|part| {
            if !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()) {
                "*"
            } else {
                part
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// One edit of one value of a valid document.
struct Probe {
    label: String,
    document: Value,
}

struct Prober<'a> {
    root: &'a Value,
    probes: Vec<Probe>,
}

impl Prober<'_> {
    fn with(&self, pointer: &str, change: impl FnOnce(&mut Value)) -> Value {
        let mut document = self.root.clone();
        change(
            document
                .pointer_mut(pointer)
                .unwrap_or_else(|| panic!("no value at {pointer:?}")),
        );
        document
    }

    fn replace(&mut self, pointer: &str, kind: &str, value: Value) {
        let document = self.with(pointer, |slot| *slot = value);
        self.probes.push(Probe {
            label: format!("{}: {kind}", normalise(pointer)),
            document,
        });
    }

    fn walk(&mut self, schema: &Value, value: &Value, pointer: &str) {
        let schema = branch(schema, value);
        self.value_probes(schema, value, pointer);
        if let (Some(properties), Some(object)) = (
            schema.get("properties").and_then(Value::as_object),
            value.as_object(),
        ) {
            for (name, sub) in properties {
                let Some(child) = object.get(name) else {
                    continue;
                };
                let child_pointer = format!("{pointer}/{name}");
                self.walk(sub, child, &child_pointer);
                let document = self.with(pointer, |slot| {
                    slot.as_object_mut().expect("an object").remove(name);
                });
                self.probes.push(Probe {
                    label: format!("{}: removed", normalise(&child_pointer)),
                    document,
                });
            }
            let document = self.with(pointer, |slot| {
                slot.as_object_mut()
                    .expect("an object")
                    .insert("zz_unknown".into(), json!(1));
            });
            self.probes.push(Probe {
                label: format!("{}: unknown key", normalise(pointer)),
                document,
            });
        }
        if let (Some(items), Some(array)) = (schema.get("items"), value.as_array()) {
            for (index, element) in array
                .iter()
                .enumerate()
                .filter(|(i, e)| *i == 0 || e.is_object())
            {
                self.walk(items, element, &format!("{pointer}/{index}"));
            }
        }
    }

    /// Edits of the value at `pointer` that the schema's own keywords call for,
    /// plus a value of every other JSON kind.
    fn value_probes(&mut self, schema: &Value, value: &Value, pointer: &str) {
        let number = |schema: &Value, keyword: &str, shift: i64| -> Option<Value> {
            let limit = schema.get(keyword)?;
            if schema.get("type") == Some(&json!("integer")) {
                Some(json!(limit.as_f64()? as i64 + shift))
            } else {
                Some(json!(limit.as_f64()? + shift as f64))
            }
        };
        let kind = |value: &Value| match value {
            Value::Null => 0,
            Value::Bool(_) => 1,
            Value::Number(_) => 2,
            Value::String(_) => 3,
            Value::Array(_) => 4,
            Value::Object(_) => 5,
        };
        for (name, other) in [
            ("null", Value::Null),
            ("boolean", json!(true)),
            ("number", json!(0)),
            ("string", json!("wrong-kind")),
            ("array", json!([])),
            ("object", json!({})),
        ] {
            if kind(&other) != kind(value) {
                self.replace(pointer, &format!("a {name}"), other);
            }
        }
        if schema.get("type") == Some(&json!("integer")) {
            self.replace(pointer, "a fraction", json!(0.5));
        }

        if let Some(constant) = schema.get("const") {
            let other = match constant {
                Value::Bool(b) => json!(!b),
                Value::Number(n) => json!(n.as_i64().expect("integer constant") + 1),
                Value::String(s) => json!(format!("{s}-other")),
                other => panic!("constant {other}"),
            };
            self.replace(pointer, "another constant", other);
        }
        if let Some(members) = schema.get("enum").and_then(Value::as_array) {
            for member in members {
                self.replace(pointer, &format!("enum member {member}"), member.clone());
            }
            self.replace(pointer, "enum non-member", json!("no-such-member"));
        }
        for (keyword, name, shift) in [
            ("minimum", "minimum", 0),
            ("minimum", "minimum-1", -1),
            ("maximum", "maximum", 0),
            ("maximum", "maximum+1", 1),
        ] {
            if let Some(edge) = number(schema, keyword, shift) {
                self.replace(pointer, name, edge);
            }
        }
        if let Some(min) = schema.get("minLength").map(size).filter(|min| *min > 0) {
            self.replace(pointer, "minLength-1", json!("a".repeat(min - 1)));
        }
        if let Some(max) = schema.get("maxLength").map(size) {
            self.replace(pointer, "maxLength+1", json!("a".repeat(max + 1)));
        }
        if let Some(array) = value.as_array() {
            if let Some(min) = schema.get("minItems").map(size).filter(|min| *min > 0) {
                self.replace(pointer, "minItems-1", json!(array[..min - 1]));
            }
            if let (Some(max), Some(last)) = (schema.get("maxItems").map(size), array.last()) {
                let mut longer = array.clone();
                longer.resize(max + 1, last.clone());
                self.replace(pointer, "maxItems+1", json!(longer));
            }
            if array.len() >= 2 && array.iter().all(Value::is_string) {
                let mut repeated = array.clone();
                let first = repeated[0].clone();
                repeated[array.len() - 1] = first;
                self.replace(pointer, "a repeated element", json!(repeated));
            }
        }
        if value.is_string() && schema.get("const").is_none() && schema.get("enum").is_none() {
            // A string no enumeration, grammar or pattern of the parser knows.
            self.replace(pointer, "free-form string", json!("\u{1F980}-free-form"));
        }
    }
}

/// Every difference between what the schema promises and what the parser does,
/// found by editing one value of a valid document at a time. "Schema looser"
/// means the schema accepts a document the parser refuses; "schema stricter"
/// means it refuses one the parser accepts. Each is a documented gap, not
/// intended behaviour, and a reason to fix the schema or the parser, whichever
/// the owner decides is wrong. The list may only shrink: an entry that stops
/// being true fails the test until it is deleted. The one addition since it was
/// written is the ledger product of the ingress section, a constraint across two
/// keys that no keyword of this schema can state.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[
    // The schema types the elements as strings; the parser reads an enum.
    (
        "/capabilities/allowed_witnesses/*: free-form string (schema looser)",
        "the parser accepts only the variants of ssk_crypto::WitnessKind",
    ),
    (
        "/hypertorus/phase_axes/*: free-form string (schema looser)",
        "the parser accepts only the variants of PhaseAxis",
    ),
    (
        "/locator_plane/allowed_types/*: free-form string (schema looser)",
        "the parser accepts only the variants of ssk_types::LocatorKind",
    ),
    (
        "/policy/gate_profile/order/*: free-form string (schema looser)",
        "the parser accepts only the variants of ssk_types::GateId",
    ),
    (
        "/projective_connection_hypercube/axes/*: free-form string (schema looser)",
        "the parser accepts only the variants of ssk_types::Axis",
    ),
    (
        "/interop/capabilities: a repeated element (schema looser)",
        "validate() refuses duplicates (DuplicateCapabilities); the schema has no uniqueItems",
    ),
    // The schema states a constraint the parser does not check.
    (
        "/interop/min_protocol: free-form string (schema stricter)",
        "the schema wants N.N.N; the parser only refuses a blank string",
    ),
    (
        "/policy/name: minLength-1 (schema stricter)",
        "nothing checks policy.name for emptiness",
    ),
    (
        "/runtime/metrics_path: minLength-1 (schema stricter)",
        "nothing checks runtime.metrics_path for emptiness",
    ),
    (
        "/system/name: minLength-1 (schema stricter)",
        "nothing checks system.name for emptiness",
    ),
    (
        "/projective_connection_hypercube/axes: maxItems+1 (schema stricter)",
        "the schema wants exactly 9 axes; HypercubeConfig::validate does not count them",
    ),
    (
        "/projective_connection_hypercube/axes: minItems-1 (schema stricter)",
        "the schema wants exactly 9 axes; HypercubeConfig::validate does not count them",
    ),
    // Host syntax is not in the schema (docs/COMPATIBILITY_MATRIX.md, "Host
    // grammar in routing configuration": "The JSON schema does not describe
    // host syntax").
    (
        "/routing/adapters/*/transport/host: free-form string (schema looser)",
        "the parser applies routing::valid_host",
    ),
    (
        "/routing/profiles/*/rules/*/destination: free-form string (schema looser)",
        "the parser applies routing::valid_host",
    ),
    (
        "/routing/profiles/*/rules/*/domain_suffix: free-form string (schema looser)",
        "the parser applies the DNS name grammar",
    ),
    // A constraint across two keys, which no keyword of this schema can state:
    // validate() refuses segment_mib x retain_segments over 1024 MiB, so either
    // key alone at its ceiling is refused while the other is at its default.
    (
        "/ingress/audit/retain_segments: maximum (schema looser)",
        "validate() refuses segment_mib x retain_segments over 1024 (5.3); a schema states no products",
    ),
    (
        "/ingress/audit/segment_mib: maximum (schema looser)",
        "validate() refuses segment_mib x retain_segments over 1024 (5.3); a schema states no products",
    ),
    // serde does not apply deny_unknown_fields to the unit variants of an
    // internally tagged enum.
    (
        "/routing/profiles/*/rules/*/action: unknown key (schema stricter)",
        "{\"kind\": \"direct\" or \"deny\", \"typo\": 1} loads; only the adapter variant refuses the extra key",
    ),
];

#[test]
fn the_schema_and_the_parser_agree_on_every_single_edit() {
    let schema = AppConfig::schema_json();
    // Probes of one kind differ only by an index or a branch of a `oneOf`; a
    // kind diverges when any of them does.
    let mut found = BTreeSet::new();
    for base in [default_document(), rich_document()] {
        // A base the schema already refuses would make every probe differ for
        // that one reason and bury it.
        let refused = violations(&schema, &base);
        assert!(
            refused.is_empty() && parser_accepts(&base),
            "the base document is not accepted by both: {refused:#?}"
        );
        let mut prober = Prober {
            root: &base,
            probes: Vec::new(),
        };
        prober.walk(&schema, &base, "");
        assert!(
            prober.probes.len() > 300,
            "the probe set shrank: {}",
            prober.probes.len()
        );
        for probe in prober.probes {
            match (
                schema_accepts(&probe.document),
                parser_accepts(&probe.document),
            ) {
                (true, false) => found.insert(format!("{} (schema looser)", probe.label)),
                (false, true) => found.insert(format!("{} (schema stricter)", probe.label)),
                _ => false,
            };
        }
    }
    let known: BTreeSet<String> = KNOWN_DIVERGENCES
        .iter()
        .map(|(label, _)| (*label).to_string())
        .collect();
    let undocumented: Vec<_> = found.difference(&known).collect();
    let stale: Vec<_> = known.difference(&found).collect();
    assert!(
        undocumented.is_empty() && stale.is_empty(),
        "the schema and the parser differ where nobody wrote it down:\n{}\n\n\
         documented but no longer true (delete the entry):\n{}",
        undocumented
            .iter()
            .map(|label| format!("  {label}"))
            .collect::<Vec<_>>()
            .join("\n"),
        stale
            .iter()
            .map(|label| format!("  {label}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}

#[test]
fn the_default_config_survives_json_value_yaml_and_toml_round_trips() {
    for (name, config) in [("default", AppConfig::default()), ("rich", rich_config())] {
        let value = serde_json::to_value(&config).expect("json value");
        let yaml = serde_yaml::to_string(&config).expect("yaml");
        let toml = toml::to_string(&config).expect("toml");
        assert_eq!(
            serde_json::from_value::<AppConfig>(value).expect("json value reads back"),
            config,
            "{name}: json value"
        );
        assert_eq!(
            AppConfig::from_yaml(&yaml).expect("yaml reads back"),
            config,
            "{name}: yaml"
        );
        assert_eq!(
            AppConfig::from_toml(&toml).expect("toml reads back"),
            config,
            "{name}: toml"
        );
        // And through the path the daemon and `ssk config lint` use.
        let from_yaml = AppConfig::parse_with_migration_yaml(&yaml).expect("yaml migrates");
        let from_toml = AppConfig::parse_with_migration_toml(&toml).expect("toml migrates");
        assert_eq!(
            (from_yaml.migrated_from, from_toml.migrated_from),
            (None, None)
        );
        assert_eq!(from_yaml.config, config, "{name}: yaml through migration");
        assert_eq!(from_toml.config, config, "{name}: toml through migration");
    }
}

// ---------------------------------------------------------------------------
// The golden schema file.
// ---------------------------------------------------------------------------

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
}

fn golden_name() -> String {
    format!("ssk-config-v{CURRENT_CONFIG_VERSION}.schema.json")
}

/// What `ssk config schema --json` prints: pretty JSON and a newline. Key order
/// is serde_json's sorted map; enabling `preserve_order` anywhere in the
/// workspace would change these bytes, and this test would say so.
fn rendered_schema() -> String {
    let mut text = serde_json::to_string_pretty(&AppConfig::schema_json()).expect("schema");
    text.push('\n');
    text
}

#[test]
fn schema_matches_the_golden_file() {
    let path = golden_dir().join(golden_name());
    let rendered = rendered_schema();
    if std::env::var_os("SSK_UPDATE_GOLDEN").is_some() {
        assert!(
            std::env::var_os("CI").is_none(),
            "SSK_UPDATE_GOLDEN rewrites the pinned schema; in CI it would turn this test \
             into a writer that cannot fail"
        );
        std::fs::create_dir_all(golden_dir()).expect("golden directory");
        std::fs::write(&path, &rendered).expect("write the golden file");
        return;
    }
    let pinned = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "no golden file {}: {err}\nrun with SSK_UPDATE_GOLDEN=1 to create it",
            path.display()
        )
    });
    // A checkout that converts line endings must not read as a schema change.
    let pinned = pinned.replace("\r\n", "\n");
    if pinned != rendered {
        let (line, (was, is)) = pinned
            .lines()
            .zip(rendered.lines())
            .enumerate()
            .find(|(_, (was, is))| was != is)
            .map_or((pinned.lines().count(), ("<end>", "<end>")), |(i, pair)| {
                (i, pair)
            });
        panic!(
            "the schema differs from {} at line {}:\n  pinned:  {was}\n  current: {is}\n\
             A schema change is a contract change: add a docs/COMPATIBILITY_MATRIX.md entry, \
             then regenerate with SSK_UPDATE_GOLDEN=1 cargo test -p ssk-config --test schema_contract",
            path.display(),
            line + 1
        );
    }
}

#[test]
fn the_golden_file_name_follows_the_current_version() {
    let mut names: Vec<String> = std::fs::read_dir(golden_dir())
        .expect("the golden directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.starts_with("ssk-config-v"))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [golden_name()],
        "exactly one golden schema, named for CURRENT_CONFIG_VERSION; rename it when the \
         version moves, never keep the old one beside the new"
    );
    let schema = AppConfig::schema_json();
    let id = schema["$id"].as_str().expect("$id");
    assert!(
        id.ends_with(&format!("/ssk-config-v{CURRENT_CONFIG_VERSION}.json")),
        "$id {id} does not name version {CURRENT_CONFIG_VERSION}"
    );
    assert_eq!(
        schema["properties"]["version"]["const"],
        json!(CURRENT_CONFIG_VERSION)
    );
    assert_eq!(AppConfig::default().version, CURRENT_CONFIG_VERSION);
}

// ---------------------------------------------------------------------------
// The ingress section of the schema (design 5.2, 5.6, 5.11).
// ---------------------------------------------------------------------------

/// Fragments no key of the ingress section may contain: a key with one of them
/// would imply that Kaleidoscorp starts, configures or authenticates a tunnel, or
/// chooses an interface or a source address, none of which it does (5.2).
const FORBIDDEN_KEY_FRAGMENTS: &[&str] = &[
    "vpn",
    "interface",
    "credential",
    "password",
    "secret",
    "token",
    "username",
    "source_address",
    "egress",
];

/// The property names of every object in a schema, at any depth, that contain a
/// forbidden fragment.
fn forbidden_key_names(schema: &Value, trail: &str, out: &mut Vec<String>) {
    match schema {
        Value::Object(node) => {
            for (keyword, child) in node {
                if keyword == "properties" {
                    for name in child.as_object().expect("properties").keys() {
                        if FORBIDDEN_KEY_FRAGMENTS
                            .iter()
                            .any(|fragment| name.to_ascii_lowercase().contains(fragment))
                        {
                            out.push(format!("{trail}/{name}"));
                        }
                    }
                }
                forbidden_key_names(child, &format!("{trail}/{keyword}"), out);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                forbidden_key_names(item, &format!("{trail}/{index}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn ingress_schema_has_no_credential_vpn_or_interface_keys() {
    let schema = AppConfig::schema_json();
    let ingress = &schema["properties"]["ingress"];
    assert!(
        ingress.is_object(),
        "the exported schema has no ingress section"
    );
    let mut found = Vec::new();
    forbidden_key_names(ingress, "/ingress", &mut found);
    assert!(
        found.is_empty(),
        "keys that imply control of a tunnel: {found:?}"
    );

    // The scan must be able to fail: planted keys, one per fragment, in nested
    // properties and behind an `anyOf`.
    let planted = json!({
        "type": "object",
        "properties": {
            "listen": {"type": "object", "properties": {
                "Egress_Interface": {"type": "string"},
                "source_address": {"type": "string"}
            }},
            "upstream": {"anyOf": [{"type": "object", "properties": {
                "vpn_profile": {}, "password": {}, "api_token": {}, "secret": {},
                "username": {}, "credential_ref": {}
            }}]}
        }
    });
    let mut found = Vec::new();
    forbidden_key_names(&planted, "", &mut found);
    assert_eq!(found.len(), 8, "{found:?}");
}

#[test]
fn the_new_section_and_the_top_level_deny_unknown_keys_in_the_schema() {
    fn objects<'a>(node: &'a Value, trail: &str, out: &mut Vec<(String, &'a Value)>) {
        match node {
            Value::Object(map) => {
                if map.get("type") == Some(&json!("object")) {
                    out.push((trail.to_string(), node));
                }
                for (keyword, child) in map {
                    objects(child, &format!("{trail}/{keyword}"), out);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    objects(item, &format!("{trail}/{index}"), out);
                }
            }
            _ => {}
        }
    }
    let schema = AppConfig::schema_json();
    assert_eq!(schema["additionalProperties"], json!(false));
    assert!(
        schema["required"]
            .as_array()
            .expect("required")
            .contains(&json!("ingress")),
        "a v5 document states its ingress stance explicitly"
    );
    let ingress = &schema["properties"]["ingress"];
    assert!(
        ingress.is_object(),
        "the exported schema has no ingress section"
    );
    let mut found = Vec::new();
    objects(ingress, "/ingress", &mut found);
    let paths: Vec<&str> = found.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/ingress",
            "/ingress/properties/audit",
            "/ingress/properties/limits",
            "/ingress/properties/listen"
        ],
        "the objects of the section; a new one needs its own additionalProperties: false"
    );
    for (path, node) in found {
        assert_eq!(
            node["additionalProperties"],
            json!(false),
            "{path} accepts unknown keys"
        );
        // Every field has a default, so a typo must be refused and nothing is required.
        assert!(node.get("required").is_none(), "{path} requires a key");
    }
}
