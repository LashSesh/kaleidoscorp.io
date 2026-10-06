#![forbid(unsafe_code)]

//! `host:port` text for dial targets, shared by every hop type so an IPv6
//! literal is spelled one way (bracketed) wherever an authority is rendered.

/// Strips one pair of brackets from an IPv6 literal (`[::1]` -> `::1`).
/// Only text containing `:` is unwrapped: a hostname can never contain one,
/// so `[name]` is not an IPv6 literal and is left exactly as given.
pub(crate) fn unbracket(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .filter(|inner| inner.contains(':'))
        .unwrap_or(host)
}

/// `host:port`, with IPv6 literals bracketed (`[::1]:443`) so the port stays
/// unambiguous. Anything containing `:` is bracketed, not only text that
/// parses as an IPv6 address: left bare, `a:8080` plus port 443 would read as
/// a different host and port; bracketed, a proxy rejects it as malformed.
pub(crate) fn authority(host: &str, port: u16) -> String {
    let bare = unbracket(host);
    if bare.contains(':') {
        format!("[{bare}]:{port}")
    } else {
        format!("{bare}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unbracket_only_unwraps_ipv6_shaped_text() {
        assert_eq!(unbracket("[::1]"), "::1");
        assert_eq!(unbracket("::1"), "::1");
        assert_eq!(unbracket("[fe80::1%eth0]"), "fe80::1%eth0");
        assert_eq!(unbracket("[name]"), "[name]");
        assert_eq!(unbracket("[::1"), "[::1");
        assert_eq!(unbracket("::1]"), "::1]");
        assert_eq!(unbracket("example.internal"), "example.internal");
        assert_eq!(unbracket("192.0.2.1"), "192.0.2.1");
    }

    #[test]
    fn authority_brackets_ipv6_once_and_leaves_names_and_ipv4_alone() {
        assert_eq!(authority("::1", 443), "[::1]:443");
        assert_eq!(authority("[::1]", 443), "[::1]:443");
        assert_eq!(authority("2001:db8::7", 8443), "[2001:db8::7]:8443");
        assert_eq!(authority("example.internal", 443), "example.internal:443");
        assert_eq!(authority("192.0.2.1", 80), "192.0.2.1:80");
        assert_eq!(authority("a:8080", 443), "[a:8080]:443");
    }
}
