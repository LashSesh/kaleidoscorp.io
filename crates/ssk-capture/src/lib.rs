#![forbid(unsafe_code)]

//! # ssk-capture — the SSCL SystemTrafficField layer (SSCL-2)
//!
//! Observes traffic from a **pluggable local source** and canonicalizes each
//! window into a [`CanonicalTrafficSurface`] (SSCL 5): a **payload-neutral**
//! descriptor that keeps structure (method, status, header *names*, sizes,
//! timing, and a URL's scheme/host/port/path) and a replay-stable *digest* of
//! the payload — but never the payload bytes, header values, or a URL's query
//! string (redacted to a content-addressed marker by [`redact_url_query`]:
//! query strings routinely carry access tokens, session ids, and other
//! payload-equivalent secrets). Every surface carries [`Provenance`] (source,
//! mode, scope, sequence).
//!
//! These surfaces are the input the rest of the system consumes:
//! [`CanonicalTrafficSurface::to_surface_object`] yields an
//! `ssk_signature::SurfaceObject`, which `ssk-signature` turns into a spectrum
//! and `ssk-imdf` observes through the Mirror Dome.
//!
//! The crate is pure and deterministic. The concrete privileged capture that
//! reads real OS traffic binds a [`TrafficSource`] at the integration layer —
//! this seed implements [`CaptureMode::PassiveLocal`] over an injected source,
//! so the whole pipeline is testable and replay-stable.

use serde::{Deserialize, Serialize};
use ssk_signature::{signature_for, OrderedMap, SpectralSignature, SurfaceObject, Value};
use ssk_types::{digest_of, Digest, HashAlg};

/// How traffic is captured. The seed implements passive local observation; the
/// enum is the author's configurable capture-mode space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureMode {
    /// Passively observe traffic already flowing through local sources.
    PassiveLocal,
}

impl CaptureMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureMode::PassiveLocal => "passive_local",
        }
    }
}

/// Which local sources a capture covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureScope {
    pub label: String,
    pub sources: Vec<String>,
}

impl CaptureScope {
    #[must_use]
    pub fn new<I: IntoIterator<Item = S>, S: Into<String>>(
        label: impl Into<String>,
        sources: I,
    ) -> Self {
        CaptureScope {
            label: label.into(),
            sources: sources.into_iter().map(Into::into).collect(),
        }
    }
}

/// A raw observed traffic window, as a source yields it — carries the payload
/// and header values that canonicalization deliberately drops.
#[derive(Clone, Debug, PartialEq)]
pub struct TrafficWindow {
    pub protocol: String,
    pub method: Option<String>,
    pub url: Option<String>,
    pub request_headers: Vec<(String, String)>,
    pub response_headers: Vec<(String, String)>,
    pub status: Option<i64>,
    pub payload: Vec<u8>,
    pub duration_ms: i64,
    pub interarrival_ms: i64,
}

impl TrafficWindow {
    /// A minimal HTTP-shaped window.
    #[must_use]
    pub fn http(protocol: impl Into<String>) -> Self {
        TrafficWindow {
            protocol: protocol.into(),
            method: None,
            url: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            status: None,
            payload: Vec::new(),
            duration_ms: -1,
            interarrival_ms: -1,
        }
    }
}

/// A pluggable source of traffic windows. The concrete OS-level capture (which
/// needs privilege) implements this at the integration layer; tests inject fakes.
pub trait TrafficSource {
    /// A stable identifier for this source (recorded in provenance).
    fn source_id(&self) -> String;
    /// The windows this source observes within the scope.
    fn windows(&self, scope: &CaptureScope) -> Vec<TrafficWindow>;
}

/// Where a surface came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub source_id: String,
    pub capture_mode: CaptureMode,
    pub scope: String,
    pub sequence: u64,
}

/// A payload-neutral traffic surface (SSCL 5). Holds no payload bytes and no
/// header values — only structure, sizes, a payload digest, and provenance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalTrafficSurface {
    pub protocol: String,
    pub method: Option<String>,
    pub url: Option<String>,
    pub request_header_names: Vec<String>,
    pub response_header_names: Vec<String>,
    pub status: Option<i64>,
    pub payload_len: usize,
    pub payload_digest: Digest,
    pub duration_ms: i64,
    pub interarrival_ms: i64,
    pub provenance: Provenance,
}

/// Redacts a URL's query string to a short content-addressed marker, keeping
/// scheme/host/port/path intact. Query strings routinely carry access tokens,
/// session ids, and other payload-equivalent secrets — exactly the class of
/// value "payload-neutral" promises are stripped, but which (unlike header
/// *values*, already dropped, and the body, already digest-only) the raw URL
/// previously retained verbatim. Two different queries redact to different
/// markers (so drift/linkability signals over the URL shape are preserved);
/// the underlying secret is not recoverable from the marker.
fn redact_url_query(url: &str) -> String {
    let parsed = ssk_signature::urlparse(url);
    let mut out = String::new();
    if !parsed.scheme.is_empty() {
        out.push_str(&parsed.scheme);
        out.push_str("://");
    }
    out.push_str(&parsed.hostname);
    if let Some(port) = parsed.port {
        out.push(':');
        out.push_str(&port.to_string());
    }
    out.push_str(&parsed.path);
    if !parsed.query.is_empty() {
        let digest =
            digest_of(&parsed.query, HashAlg::Blake3).expect("query string is serializable");
        out.push_str("?q=");
        out.push_str(&digest.to_hex()[..16]);
    }
    out
}

impl CanonicalTrafficSurface {
    /// Canonicalize a raw window: drop the payload bytes, header values, and
    /// URL query string (see [`redact_url_query`]), keep the structure and a
    /// replay-stable payload digest.
    #[must_use]
    pub fn from_window(window: &TrafficWindow, provenance: Provenance) -> Self {
        let payload_digest =
            digest_of(&window.payload, HashAlg::Blake3).expect("payload bytes are serializable");
        CanonicalTrafficSurface {
            protocol: window.protocol.clone(),
            method: window.method.clone(),
            url: window.url.as_deref().map(redact_url_query),
            request_header_names: header_names(&window.request_headers),
            response_header_names: header_names(&window.response_headers),
            status: window.status,
            payload_len: window.payload.len(),
            payload_digest,
            duration_ms: window.duration_ms,
            interarrival_ms: window.interarrival_ms,
            provenance,
        }
    }

    /// Bridge to an `ssk_signature::SurfaceObject` — header *names* are preserved
    /// (so linkability detection still sees which sensitive headers were present)
    /// while their values and the body stay absent.
    #[must_use]
    pub fn to_surface_object(&self) -> SurfaceObject {
        let mut fields = OrderedMap::new();
        fields.insert("protocol", Value::Text(self.protocol.clone()));
        if let Some(m) = &self.method {
            fields.insert("method", Value::Text(m.clone()));
        }
        if let Some(u) = &self.url {
            fields.insert("url", Value::Text(u.clone()));
        }
        if let Some(s) = self.status {
            fields.insert("status", Value::Num(s as f64));
        }
        fields.insert("request_headers", header_shape(&self.request_header_names));
        fields.insert(
            "request_header_order",
            Value::Array(
                self.request_header_names
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        );
        fields.insert("headers", header_shape(&self.response_header_names));
        fields.insert(
            "response_header_order",
            Value::Array(
                self.response_header_names
                    .iter()
                    .cloned()
                    .map(Value::Text)
                    .collect(),
            ),
        );
        fields.insert("body_length", Value::Num(self.payload_len as f64));
        fields.insert("payload_digest", Value::Text(self.payload_digest.to_hex()));
        fields.insert("duration_ms", Value::Num(self.duration_ms as f64));

        let mut timing = OrderedMap::new();
        timing.insert("duration_ms", Value::Num(self.duration_ms as f64));
        if self.interarrival_ms >= 0 {
            timing.insert("interarrival_ms", Value::Num(self.interarrival_ms as f64));
        }

        let mut provenance = OrderedMap::new();
        provenance.insert(
            "source_name",
            Value::Text(self.provenance.source_id.clone()),
        );
        provenance.insert(
            "capture_mode",
            Value::Text(self.provenance.capture_mode.as_str().to_owned()),
        );
        provenance.insert("scope", Value::Text(self.provenance.scope.clone()));
        provenance.insert("sequence", Value::Num(self.provenance.sequence as f64));

        SurfaceObject::new("application/system-traffic-surface+http", fields)
            .with_declared_protocol_class(self.protocol.clone())
            .with_timing_model(timing)
            .with_provenance(provenance)
    }

    /// The surface's spectral signature (canonicalize → features → spectrum).
    #[must_use]
    pub fn signature(&self) -> SpectralSignature {
        signature_for(&self.to_surface_object())
    }
}

fn header_names(headers: &[(String, String)]) -> Vec<String> {
    headers.iter().map(|(k, _)| k.to_lowercase()).collect()
}

// A header "shape" object: names present, values absent (empty), so the
// signature layer can detect *which* headers appeared without their values.
fn header_shape(names: &[String]) -> Value {
    let mut m = OrderedMap::new();
    for name in names {
        m.insert(name.clone(), Value::Text(String::new()));
    }
    Value::Object(m)
}

/// The captured field: a sequence of payload-neutral surfaces from one source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemTrafficField {
    pub mode: CaptureMode,
    pub scope: CaptureScope,
    pub source_id: String,
    pub surfaces: Vec<CanonicalTrafficSurface>,
}

impl SystemTrafficField {
    /// Capture from a source under a scope and mode: pull windows, then extract
    /// each into a payload-neutral surface with provenance (WindowExtraction).
    #[must_use]
    pub fn capture(source: &dyn TrafficSource, scope: &CaptureScope, mode: CaptureMode) -> Self {
        let source_id = source.source_id();
        let surfaces = source
            .windows(scope)
            .iter()
            .enumerate()
            .map(|(index, window)| {
                CanonicalTrafficSurface::from_window(
                    window,
                    Provenance {
                        source_id: source_id.clone(),
                        capture_mode: mode,
                        scope: scope.label.clone(),
                        sequence: index as u64,
                    },
                )
            })
            .collect();
        SystemTrafficField {
            mode,
            scope: scope.clone(),
            source_id,
            surfaces,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.surfaces.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.surfaces.is_empty()
    }

    /// The spectra of every captured surface.
    #[must_use]
    pub fn signatures(&self) -> Vec<SpectralSignature> {
        self.surfaces
            .iter()
            .map(CanonicalTrafficSurface::signature)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_BODY: &str = "SUPERSECRETBODY-do-not-export";
    const SECRET_TOKEN: &str = "Bearer leak-me-not";

    struct FakeSource;
    impl TrafficSource for FakeSource {
        fn source_id(&self) -> String {
            "loopback-tap".to_owned()
        }
        fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
            let mut w = TrafficWindow::http("http");
            w.method = Some("GET".to_owned());
            w.url = Some("https://example.local/a".to_owned());
            w.status = Some(200);
            w.request_headers = vec![
                ("User-Agent".to_owned(), "demo/1.0".to_owned()),
                ("Authorization".to_owned(), SECRET_TOKEN.to_owned()),
            ];
            w.response_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
            w.payload = SECRET_BODY.as_bytes().to_vec();
            w.duration_ms = 25;
            w.interarrival_ms = 40;
            vec![w]
        }
    }

    fn field() -> SystemTrafficField {
        let scope = CaptureScope::new("local", ["lo0"]);
        SystemTrafficField::capture(&FakeSource, &scope, CaptureMode::PassiveLocal)
    }

    #[test]
    fn capture_produces_surfaces_with_provenance() {
        let f = field();
        assert_eq!(f.len(), 1);
        let s = &f.surfaces[0];
        assert_eq!(s.provenance.source_id, "loopback-tap");
        assert_eq!(s.provenance.capture_mode, CaptureMode::PassiveLocal);
        assert_eq!(s.provenance.scope, "local");
        assert_eq!(s.provenance.sequence, 0);
    }

    #[test]
    fn surface_is_payload_neutral() {
        let f = field();
        let s = &f.surfaces[0];
        // Structure is kept.
        assert_eq!(s.status, Some(200));
        assert_eq!(s.payload_len, SECRET_BODY.len());
        assert!(s.request_header_names.contains(&"authorization".to_owned()));
        // The raw payload and header values never appear anywhere in the surface
        // or the SurfaceObject / signature it produces.
        let json = serde_json::to_string(s).unwrap();
        assert!(!json.contains(SECRET_BODY));
        assert!(!json.contains(SECRET_TOKEN));
        let surface_json = format!("{:?}", s.to_surface_object());
        assert!(!surface_json.contains(SECRET_BODY));
        assert!(!surface_json.contains(SECRET_TOKEN));
        // But the payload is committed by digest for replay.
        assert_ne!(s.payload_digest, Digest::GENESIS);
    }

    // Regression: a URL query string is payload-equivalent (access tokens,
    // session ids, PII) and must not survive into the surface verbatim, even
    // though the raw URL was previously kept whole.
    #[test]
    fn url_query_string_is_redacted() {
        const SECRET_QUERY: &str = "access_token=SECRET123&ssn=555-00-1234";
        struct QueryLeakSource;
        impl TrafficSource for QueryLeakSource {
            fn source_id(&self) -> String {
                "tap".to_owned()
            }
            fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
                let mut w = TrafficWindow::http("http");
                w.method = Some("GET".to_owned());
                w.url = Some(format!("https://example.local/callback?{SECRET_QUERY}"));
                w.status = Some(200);
                vec![w]
            }
        }

        let f = SystemTrafficField::capture(
            &QueryLeakSource,
            &CaptureScope::new("local", ["lo0"]),
            CaptureMode::PassiveLocal,
        );
        let s = &f.surfaces[0];
        let url = s.url.as_deref().expect("url present");
        // Scheme/host/path are kept for structural signal...
        assert!(url.starts_with("https://example.local/callback"));
        // ...but the secret query string itself never appears anywhere.
        assert!(!url.contains(SECRET_QUERY));
        assert!(!url.contains("SECRET123"));
        assert!(!url.contains("555-00-1234"));
        let json = serde_json::to_string(s).unwrap();
        assert!(!json.contains("SECRET123"));
        assert!(!json.contains("555-00-1234"));
        let surface_json = format!("{:?}", s.to_surface_object());
        assert!(!surface_json.contains("SECRET123"));
        assert!(!surface_json.contains("555-00-1234"));

        // A different query redacts to a different marker (structure/drift
        // signal is preserved; it isn't just blanked to a constant).
        struct OtherQuerySource;
        impl TrafficSource for OtherQuerySource {
            fn source_id(&self) -> String {
                "tap".to_owned()
            }
            fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
                let mut w = TrafficWindow::http("http");
                w.method = Some("GET".to_owned());
                w.url = Some("https://example.local/callback?access_token=OTHER".to_owned());
                w.status = Some(200);
                vec![w]
            }
        }
        let f2 = SystemTrafficField::capture(
            &OtherQuerySource,
            &CaptureScope::new("local", ["lo0"]),
            CaptureMode::PassiveLocal,
        );
        assert_ne!(f.surfaces[0].url, f2.surfaces[0].url);
    }

    #[test]
    fn capture_is_replay_stable_and_feeds_a_signature() {
        let a = field();
        let b = field();
        // Deterministic: same source -> identical surfaces and signatures.
        assert_eq!(a.surfaces, b.surfaces);
        let sig_a = a.surfaces[0].signature();
        let sig_b = b.surfaces[0].signature();
        assert_eq!(sig_a.digest, sig_b.digest);
        // The signature detects the sensitive header by name (payload-neutrally).
        assert_eq!(
            sig_a.dimensions["linkability"]["has_authorization"],
            ssk_signature::FeatureValue::Num(1.0)
        );
    }
}
