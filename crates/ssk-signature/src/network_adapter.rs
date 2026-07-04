//! Authorized network observation adapter — Chameleon
//! `adapters/network_adapter`.
//!
//! Fetches an authorized HTTP endpoint and turns the response into a
//! [`SurfaceObject`], redacting sensitive headers and never exporting more than
//! a bounded body. The transport is a pluggable [`NetworkTransport`] — the
//! kernel's tests inject fakes. The concrete transport that drives real I/O
//! through `ssk-netcore` (TCP/SOCKS5/TLS/DNS) is bound at the async integration
//! layer (the daemon), deliberately *not* here: this crate stays pure, sync, and
//! deterministic so the whole signature pipeline is replay-stable.

use crate::object::SurfaceObject;
use crate::policy::AuthorizationManifest;
use crate::replay::KERNEL_VERSION;
use crate::value::{OrderedMap, Value};

/// Errors the network adapter can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetworkAdapterError {
    #[error("valid network observation authorization is required")]
    Authorization,
    #[error("scheme_not_allowed:{0}")]
    SchemeNotAllowed(String),
    #[error("method_not_allowed:{0}")]
    MethodNotAllowed(String),
    #[error("host_not_allowed:{0}")]
    HostNotAllowed(String),
    #[error("body_not_allowed_for_observation_method")]
    BodyNotAllowed,
    #[error("network request failed: {0}")]
    Transport(String),
}

/// A request for a network observation.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl NetworkRequest {
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        NetworkRequest {
            url: url.into(),
            method: "GET".to_owned(),
            headers: Vec::new(),
            body: None,
        }
    }

    #[must_use]
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }
}

/// A response from a network observation.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkResponse {
    pub url: String,
    pub method: String,
    pub status: i64,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub duration_ms: i64,
    pub truncated: bool,
}

/// Configuration bounding what the adapter will observe.
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkAdapterConfig {
    pub allowed_schemes: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub timeout_seconds: f64,
    pub max_body_bytes: usize,
    pub include_body: bool,
    pub user_agent: String,
    pub redacted_headers: Vec<String>,
}

impl Default for NetworkAdapterConfig {
    fn default() -> Self {
        let s = |xs: &[&str]| xs.iter().map(|x| (*x).to_owned()).collect();
        NetworkAdapterConfig {
            allowed_schemes: s(&["http", "https"]),
            allowed_methods: s(&["GET", "HEAD"]),
            allowed_hosts: Vec::new(),
            timeout_seconds: 10.0,
            max_body_bytes: 65536,
            include_body: false,
            user_agent: format!("ChameleonSignatureKernel/{KERNEL_VERSION}"),
            redacted_headers: s(&["authorization", "cookie", "set-cookie"]),
        }
    }
}

impl NetworkAdapterConfig {
    #[must_use]
    pub fn with_allowed_hosts<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        hosts: I,
    ) -> Self {
        self.allowed_hosts = hosts.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_include_body(mut self, on: bool) -> Self {
        self.include_body = on;
        self
    }
}

/// A pluggable transport. The concrete `ssk-netcore`-backed transport lives at
/// the async integration layer; tests inject fakes.
pub trait NetworkTransport {
    /// Perform the request.
    ///
    /// # Errors
    /// [`NetworkAdapterError::Transport`] on transport failure.
    fn send(
        &self,
        request: &NetworkRequest,
        config: &NetworkAdapterConfig,
    ) -> Result<NetworkResponse, NetworkAdapterError>;
}

/// Authorized HTTP observation adapter.
pub struct NetworkAdapter<'t> {
    authorization: AuthorizationManifest,
    config: NetworkAdapterConfig,
    transport: &'t dyn NetworkTransport,
}

impl<'t> NetworkAdapter<'t> {
    /// Build the adapter, requiring authorization valid for
    /// `network_observation` or `adapter_operation`.
    ///
    /// # Errors
    /// [`NetworkAdapterError::Authorization`] if the manifest is not valid.
    pub fn new(
        authorization: AuthorizationManifest,
        config: NetworkAdapterConfig,
        transport: &'t dyn NetworkTransport,
    ) -> Result<Self, NetworkAdapterError> {
        if !(authorization.is_valid_for("network_observation")
            || authorization.is_valid_for("adapter_operation"))
        {
            return Err(NetworkAdapterError::Authorization);
        }
        Ok(NetworkAdapter {
            authorization,
            config,
            transport,
        })
    }

    /// Fetch a request and convert the response into a surface.
    ///
    /// # Errors
    /// [`NetworkAdapterError`] on validation or transport failure.
    pub fn fetch(&self, request: &NetworkRequest) -> Result<SurfaceObject, NetworkAdapterError> {
        self.validate_request(request)?;
        let response = self.transport.send(request, &self.config)?;
        Ok(self.response_to_object(request, &response))
    }

    fn validate_request(&self, request: &NetworkRequest) -> Result<(), NetworkAdapterError> {
        let parsed = crate::url::urlparse(&request.url);
        let scheme = parsed.scheme.to_lowercase();
        if !self.config.allowed_schemes.iter().any(|s| s == &scheme) {
            return Err(NetworkAdapterError::SchemeNotAllowed(scheme));
        }
        let method = request.method.to_uppercase();
        if !self.config.allowed_methods.iter().any(|m| m == &method) {
            return Err(NetworkAdapterError::MethodNotAllowed(method));
        }
        if !self.config.allowed_hosts.is_empty() {
            let host = parsed.hostname.to_lowercase();
            let allowed = self
                .config
                .allowed_hosts
                .iter()
                .any(|h| h.to_lowercase() == host);
            if !allowed {
                return Err(NetworkAdapterError::HostNotAllowed(host));
            }
        }
        if request.body.is_some() && matches!(method.as_str(), "GET" | "HEAD") {
            return Err(NetworkAdapterError::BodyNotAllowed);
        }
        Ok(())
    }

    fn sanitize(&self, headers: &[(String, String)]) -> Vec<(String, String)> {
        let redacted: Vec<String> = self
            .config
            .redacted_headers
            .iter()
            .map(|h| h.to_lowercase())
            .collect();
        headers
            .iter()
            .map(|(k, v)| {
                if redacted.contains(&k.to_lowercase()) {
                    (k.clone(), "<redacted>".to_owned())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }

    fn response_to_object(
        &self,
        request: &NetworkRequest,
        response: &NetworkResponse,
    ) -> SurfaceObject {
        let request_headers = self.sanitize(&request.headers);
        let response_headers = self.sanitize(&response.headers);
        let to_obj = |hs: &[(String, String)]| {
            let mut m = OrderedMap::new();
            for (k, v) in hs {
                m.insert(k.clone(), Value::Text(v.clone()));
            }
            m
        };
        let order = |hs: &[(String, String)]| {
            Value::Array(hs.iter().map(|(k, _)| Value::Text(k.clone())).collect())
        };

        let mut fields = OrderedMap::new();
        fields.insert("protocol", Value::Text("http".to_owned()));
        fields.insert("method", Value::Text(response.method.clone()));
        fields.insert("url", Value::Text(response.url.clone()));
        fields.insert("status", Value::Num(response.status as f64));
        fields.insert("request_headers", Value::Object(to_obj(&request_headers)));
        fields.insert("request_header_order", order(&request_headers));
        fields.insert("headers", Value::Object(to_obj(&response_headers)));
        fields.insert("response_header_order", order(&response_headers));
        fields.insert("duration_ms", Value::Num(response.duration_ms as f64));
        fields.insert("body_length", Value::Num(response.body.len() as f64));
        fields.insert("body_truncated", Value::Bool(response.truncated));
        if self.config.include_body {
            fields.insert(
                "body",
                Value::Text(String::from_utf8_lossy(&response.body).into_owned()),
            );
        }

        let mut provenance = OrderedMap::new();
        provenance.insert(
            "source_name",
            Value::Text(self.authorization.source_name.clone()),
        );
        provenance.insert(
            "owner_or_controller",
            Value::Text(self.authorization.owner_or_controller.clone()),
        );
        if let Some(ev) = &self.authorization.evidence_ref {
            provenance.insert("authorization_evidence_ref", Value::Text(ev.clone()));
        }
        provenance.insert("adapter", Value::Text("network".to_owned()));

        let mut timing = OrderedMap::new();
        timing.insert("duration_ms", Value::Num(response.duration_ms as f64));

        SurfaceObject::new("application/network-observation+http", fields)
            .with_declared_protocol_class("http")
            .with_timing_model(timing)
            .with_provenance(provenance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport;
    impl NetworkTransport for FakeTransport {
        fn send(
            &self,
            request: &NetworkRequest,
            _config: &NetworkAdapterConfig,
        ) -> Result<NetworkResponse, NetworkAdapterError> {
            Ok(NetworkResponse {
                url: request.url.clone(),
                method: request.method.clone(),
                status: 200,
                headers: vec![
                    ("Content-Type".to_owned(), "application/json".to_owned()),
                    ("Set-Cookie".to_owned(), "secret".to_owned()),
                ],
                body: b"{\"ok\":true}".to_vec(),
                duration_ms: 12,
                truncated: false,
            })
        }
    }

    fn auth() -> AuthorizationManifest {
        AuthorizationManifest::new("owned-endpoint", "me", "self-owned service")
            .with_allowed_uses(["network_observation"])
    }

    // Chameleon test_network_adapter_converts_response_to_surface_object.
    #[test]
    fn converts_response_to_surface_object() {
        let transport = FakeTransport;
        let adapter = NetworkAdapter::new(
            auth(),
            NetworkAdapterConfig::default().with_allowed_hosts(["example.test"]),
            &transport,
        )
        .unwrap();
        let obj = adapter
            .fetch(&NetworkRequest::new("https://example.test/status"))
            .unwrap();
        assert_eq!(obj.declared_protocol_class, "http");
        assert_eq!(obj.fields.get("status"), Some(&Value::Num(200.0)));
        assert_eq!(obj.fields.get("body_length"), Some(&Value::Num(11.0)));
        assert_eq!(obj.fields.get("body_truncated"), Some(&Value::Bool(false)));
        let headers = obj.fields.get("headers").unwrap().as_object().unwrap();
        assert_eq!(
            headers.get("Set-Cookie"),
            Some(&Value::Text("<redacted>".to_owned()))
        );
        assert_eq!(obj.timing_model.get("duration_ms"), Some(&Value::Num(12.0)));
    }

    // Chameleon test_network_adapter_rejects_unconfigured_methods.
    #[test]
    fn rejects_unconfigured_methods() {
        let transport = FakeTransport;
        let adapter =
            NetworkAdapter::new(auth(), NetworkAdapterConfig::default(), &transport).unwrap();
        let err = adapter
            .fetch(&NetworkRequest::new("https://example.test/status").with_method("POST"))
            .unwrap_err();
        assert!(matches!(err, NetworkAdapterError::MethodNotAllowed(_)));
    }
}
