// One table of host spellings, shared through `include!` by every crate that
// reads a host: `ssk_config::routing::valid_host` and `RoutingConfig::validate`
// (`ssk-config/tests/host_grammar.rs`), and the policy engine's address-form
// test (`ssk-netadmin/tests/host_corpus.rs`), and the resolver's name check
// (`is_resolvable_name`, unit test in `ssk-netcore/src/resolve.rs`: exactly the
// `Name` class). The ingress target canonicaliser reads the same table once it
// exists. The three used to disagree: the config
// accepted `0.1` as a domain suffix and `127.1` as a destination while the
// policy engine already refused to match a suffix against either, so a rule
// could load and then never fire. A layer that disagrees with its column here
// is a bug in that layer, not in the table.
//
// Every item carries `#[allow(dead_code)]` because each including crate uses
// only the columns it asserts (as `routing_config.rs` does).

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostClass {
    /// A DNS name: valid labels, and a final label that starts with a letter
    /// (punycode `xn--` included).
    Name,
    /// An IP literal in a spelling `std::net::IpAddr` parses, and not
    /// IPv4-mapped.
    IpLiteral,
    /// An IPv4-mapped IPv6 literal: a second spelling of an IPv4 address.
    /// Policy compares two literals by parsed value, and `::ffff:10.0.0.1` is
    /// not equal to `10.0.0.1`, so a rule written this way never matches the
    /// plain IPv4 flow it was meant for (and a deny rule is bypassed).
    MappedIpv6,
    /// Passes the DNS label grammar, but the final label does not start with a
    /// letter: the OS resolver dials such a spelling as an IPv4 address
    /// (`inet_aton` forms: short, hex, octal, one integer) that `IpAddr`
    /// refuses to parse.
    NumericAlias,
    /// An address written in a form `IpAddr` refuses (brackets, a zone id).
    /// Never a DNS name; the policy engine still treats it as an address.
    AddressSpelling,
    /// Not a host: empty or doubled dots, underscore, non-ASCII, whitespace,
    /// control bytes, a port or path attached, an over-long label or name.
    Malformed,
}

#[allow(dead_code)]
impl HostClass {
    /// Every class, so a test can insist the table still exercises each one.
    const ALL: [Self; 6] = [
        Self::Name,
        Self::IpLiteral,
        Self::MappedIpv6,
        Self::NumericAlias,
        Self::AddressSpelling,
        Self::Malformed,
    ];

    /// `valid_host`, which is also the grammar of an adapter host.
    fn valid_host(self) -> bool {
        matches!(self, Self::Name | Self::IpLiteral | Self::MappedIpv6)
    }

    /// A rule `destination`: `valid_host`, minus the mapped spelling.
    fn valid_rule_destination(self) -> bool {
        matches!(self, Self::Name | Self::IpLiteral)
    }

    /// A rule `domain_suffix`: a DNS name, never an address of any kind.
    fn valid_domain_suffix(self) -> bool {
        matches!(self, Self::Name)
    }

    /// What the policy engine's address-form test must answer for a host the
    /// config grammar has a verdict on. `None` for `Malformed`: the engine
    /// compares text and never promised an answer for something that is not a
    /// host.
    fn address_form(self) -> Option<bool> {
        match self {
            Self::Name => Some(false),
            Self::IpLiteral | Self::MappedIpv6 | Self::NumericAlias | Self::AddressSpelling => {
                Some(true)
            }
            Self::Malformed => None,
        }
    }
}

#[allow(dead_code)]
struct HostCase {
    host: String,
    class: HostClass,
}

#[allow(dead_code)]
fn host_corpus() -> Vec<HostCase> {
    let mut cases = Vec::new();
    let mut add = |class: HostClass, hosts: &[&str]| {
        for host in hosts {
            cases.push(HostCase {
                host: (*host).to_string(),
                class,
            });
        }
    };
    add(
        HostClass::Name,
        &[
            "example.com",
            "api.corp.example",
            "a",
            "localhost",
            "my-host.example",
            "a-b.c-d.example",
            "example2",
            // Upper case and one trailing dot are valid spellings of a name.
            "EXAMPLE.COM",
            "Api.Corp.Example",
            "example.com.",
            "EXAMPLE.COM.",
            // Digits in a label other than the last one do not make an address.
            "10.corp.example",
            "0.1.example",
            "127.0.1.example",
            "10.0.0.1.nip.io",
            "1password.com",
            "my.1password.com",
            // Punycode is an A-label that starts with a letter.
            "xn--bcher-kva.example",
            "xn--p1ai",
            "xn--80ak6aa92e.xn--p1ai",
        ],
    );
    add(
        HostClass::IpLiteral,
        &[
            "127.0.0.1",
            "10.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "0:0:0:0:0:0:0:1",
            "2001:db8::1",
            "2001:DB8::A",
            "FE80::1",
        ],
    );
    add(
        HostClass::MappedIpv6,
        &[
            "::ffff:10.0.0.1",
            "::FFFF:10.0.0.1",
            "::ffff:a00:1",
            "0:0:0:0:0:ffff:10.0.0.1",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
        ],
    );
    add(
        HostClass::NumericAlias,
        &[
            // Short forms.
            "127.1",
            "127.0.1",
            "0.1",
            "1",
            "0",
            // Hex, octal and one-integer forms, which `getaddrinfo` dials.
            "0x7f.0.0.1",
            "0X7F.0.0.1",
            "0x7f.1",
            "010.0.0.1",
            "0177.0.0.1",
            "2130706433",
            "0x7f000001",
            "2852039166",
            // One trailing dot does not turn a dotted quad into a name.
            "127.0.0.1.",
            "127.1.",
            // Out of range or too many parts: still refused, one rule covers all.
            "256.256.256.256",
            "1.2.3.4.5",
            // A final label that merely starts with a digit.
            "intranet.3com",
        ],
    );
    add(
        HostClass::AddressSpelling,
        &[
            "[::1]",
            "[::ffff:10.0.0.1]",
            "[2001:db8::1]",
            "fe80::1%eth0",
            "[fe80::1%eth0]",
        ],
    );
    add(
        HostClass::Malformed,
        &[
            "",
            ".",
            "..",
            "a..b",
            ".example.com",
            "example.com..",
            "-a.example",
            "a-.example",
            "a_b.example",
            "_dmarc.example.com",
            "b\u{fc}cher.example",
            "\u{4f8b}\u{3048}.jp",
            "exa mple.com",
            " example.com",
            "example.com ",
            "example.com\n",
            "a\0b.example",
            "example.com:443",
            "1.2.3.4:80",
            "example.com/path",
            "http://example.com",
            "user@example.com",
            "*.example.com",
            "[example.com]",
            "::1.",
        ],
    );

    // Length limits: 63 bytes per label and 253 for the name, the trailing dot
    // not counted. Built, not written out, so the numbers are visible.
    let label63 = "a".repeat(63);
    let label64 = "a".repeat(64);
    let name253 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(61));
    let name254 = format!("{label63}.{label63}.{label63}.{}", "a".repeat(62));
    assert_eq!((name253.len(), name254.len()), (253, 254));
    let long: [(HostClass, String); 6] = [
        (HostClass::Name, format!("{label63}.example")),
        (HostClass::Name, name253.clone()),
        (HostClass::Name, format!("{name253}.")),
        (HostClass::Malformed, format!("{label64}.example")),
        (HostClass::Malformed, name254.clone()),
        (HostClass::Malformed, format!("{name254}.")),
    ];
    for (class, host) in long {
        cases.push(HostCase { host, class });
    }
    cases
}
