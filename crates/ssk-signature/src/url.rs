//! A minimal URL parser covering what the fingerprint layers read: scheme,
//! lowercased host, port, path depth, and query keys. Mirrors the subset of
//! Python `urllib.parse.urlparse` / `parse_qsl` the Chameleon kernel uses on
//! `http`/`https` observation surfaces — not a general RFC 3986 implementation,
//! and deliberately scoped to the surfaces the signature layer sees.

/// The parsed components the fingerprint layers consume.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedUrl {
    pub scheme: String,
    /// Lowercased host (Python `urlparse(...).hostname` is lowercased).
    pub hostname: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

impl ParsedUrl {
    /// Number of non-empty path segments.
    #[must_use]
    pub fn path_depth(&self) -> usize {
        self.path.split('/').filter(|s| !s.is_empty()).count()
    }

    /// Number of non-empty dot-separated host labels.
    #[must_use]
    pub fn host_label_count(&self) -> usize {
        self.hostname.split('.').filter(|s| !s.is_empty()).count()
    }

    /// `str(port)` when present, else the scheme-default class label — mirrors
    /// `str(parsed_url.port or ("default_https" if scheme=="https" else "default_http"))`.
    #[must_use]
    pub fn port_class(&self) -> String {
        match self.port {
            Some(p) if p != 0 => p.to_string(),
            _ => {
                if self.scheme == "https" {
                    "default_https".to_owned()
                } else {
                    "default_http".to_owned()
                }
            }
        }
    }

    /// Lowercased query keys (with duplicates, as `parse_qsl` yields), unsorted.
    #[must_use]
    pub fn query_keys(&self) -> Vec<String> {
        self.query
            .split('&')
            .filter(|seg| !seg.is_empty())
            .map(|seg| {
                let key = seg.split('=').next().unwrap_or("");
                key.to_lowercase()
            })
            .filter(|k| !k.is_empty())
            .collect()
    }
}

/// Parse a URL into the components the signature layer needs.
#[must_use]
pub fn urlparse(url: &str) -> ParsedUrl {
    if url.is_empty() {
        return ParsedUrl::default();
    }
    // Strip fragment.
    let url = url.split('#').next().unwrap_or(url);

    // Scheme.
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => (String::new(), url),
    };

    // Split authority from path+query. If there was no scheme/`//`, Python
    // treats the whole thing as a path; but the observation surfaces always
    // carry a scheme, so the authority branch is the meaningful one.
    let (authority, path_and_query) = match rest.find(['/', '?']) {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, ""),
    };

    // Path vs query.
    let (path, query) = match path_and_query.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (path_and_query.to_owned(), String::new()),
    };

    // Authority: strip userinfo, then split host:port.
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, hp)| hp);
    let (hostname, port) = split_host_port(host_port);

    ParsedUrl {
        scheme,
        hostname: hostname.to_lowercase(),
        port,
        path,
        query,
    }
}

fn split_host_port(host_port: &str) -> (String, Option<u16>) {
    // IPv6 literal: [::1]:8080
    if let Some(stripped) = host_port.strip_prefix('[') {
        if let Some((host, after)) = stripped.split_once(']') {
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (host.to_owned(), port);
        }
    }
    match host_port.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host.to_owned(), port.parse::<u16>().ok())
        }
        _ => (host_port.to_owned(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_url() {
        let p = urlparse("HTTPS://User@API.Example.COM:8443/v1/users?b=2&a=1&a=3");
        assert_eq!(p.scheme, "https");
        assert_eq!(p.hostname, "api.example.com");
        assert_eq!(p.port, Some(8443));
        assert_eq!(p.path, "/v1/users");
        assert_eq!(p.path_depth(), 2);
        assert_eq!(p.host_label_count(), 3);
        assert_eq!(p.port_class(), "8443");
        let mut keys = p.query_keys();
        keys.sort();
        assert_eq!(keys, vec!["a", "a", "b"]);
    }

    #[test]
    fn default_port_class_by_scheme() {
        assert_eq!(urlparse("https://h/").port_class(), "default_https");
        assert_eq!(urlparse("http://h/").port_class(), "default_http");
    }

    #[test]
    fn empty_url_is_all_empty() {
        let p = urlparse("");
        assert_eq!(p, ParsedUrl::default());
        assert_eq!(p.path_depth(), 0);
        assert_eq!(p.query_keys().len(), 0);
    }

    #[test]
    fn ipv6_host() {
        let p = urlparse("http://[::1]:9000/x");
        assert_eq!(p.hostname, "::1");
        assert_eq!(p.port, Some(9000));
    }
}
