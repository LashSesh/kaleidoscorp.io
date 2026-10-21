//! Observing the operating system's path decision (design 6.12): something TRUE
//! for status to say about the path, without claiming anything about third-party
//! software.
//!
//! Everything here is read-only, sends no packet, and feeds status only; it never
//! influences a decision of the ingress (CO-8). What it reports is "the
//! interface the OS selects for a documentation address". The probe is a
//! documentation address, not a real destination: exclusion routes and
//! per-application steering can send a real destination elsewhere, so nothing
//! built on this may be called "the default route" or be read as the route of
//! any flow (design 10.6, item 9).
//!
//! The words of the never-claim list (design 10.6, item 3) do not appear in a
//! string literal of this file: an interface is described by what the OS calls
//! it, as quoted data, never by a guess about what it is. A source scan in
//! `ingress/mod.rs` keeps it so.
//!
//! The lookup is a best-route lookup of the probe, not "find the 0.0.0.0/0 row":
//! with split routes (two /1 routes through one interface and a /0 through
//! another with a lower metric) that row is not the one the OS uses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// RFC 5737 TEST-NET-1: never a real host.
pub const PROBE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// RFC 3849 documentation prefix.
pub const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
/// Same value as the kill-switch view's refresh interval.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Same value as the kill-switch view's maximum age.
pub const MAX_AGE: Duration = Duration::from_secs(15);
/// How long a replaced interface stays visible as the previous one.
pub const CHANGE_NOTICE_WINDOW: Duration = Duration::from_secs(600);
/// The longest alias that is kept.
pub const ALIAS_MAX_CHARS: usize = 64;
/// A route table larger than this is not parsed.
pub const MAX_TABLE_BYTES: usize = 4 * 1024 * 1024;

/// What one lookup found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteObservation {
    pub interface_index: Option<u32>,
    pub interface_alias: Option<String>,
    pub route_metric: u32,
}

impl RouteObservation {
    /// The part that says which interface it is: a change of it is a change of
    /// path; a change of the metric alone is not.
    fn identity(&self) -> (Option<u32>, Option<&str>) {
        (self.interface_index, self.interface_alias.as_deref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveError {
    /// This platform or address family has no observer.
    Unsupported,
    /// The table has no route for the probe.
    NoRoute,
    /// The lookup failed with this OS error code (0 when there is none).
    LookupFailed(u32),
    /// The table is not in the shape the parser knows.
    Malformed,
}

pub trait PathObserver: Send + Sync + 'static {
    /// Blocking lookup in the local routing table; sends no packet. Called from
    /// `spawn_blocking`, never under a lock.
    fn best_route(&self, probe: IpAddr) -> Result<RouteObservation, ObserveError>;
}

/// OS-supplied text is data: invisible and control characters dropped, length
/// bounded, never placed inside a sentence.
#[must_use]
pub fn sanitise_alias(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && !is_invisible(*c))
        .take(ALIAS_MAX_CHARS)
        .collect()
}

/// Characters that are not `is_control` but still change what a reader sees or
/// how a line breaks: bidirectional controls, zero-width characters, line and
/// paragraph separators, the byte order mark.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

// ---- Linux: /proc/net/route, IPv4 only ----

pub const RTF_UP: u16 = 0x0001;
pub const RTF_REJECT: u16 = 0x0200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow {
    pub iface: String,
    pub destination: Ipv4Addr,
    pub flags: u16,
    pub metric: u32,
    pub mask: Ipv4Addr,
}

/// The kernel prints the network-order word with `%08X`, so the text is the
/// host-order word and `to_ne_bytes` undoes it on either endianness.
fn hex_addr(field: &str) -> Option<Ipv4Addr> {
    if field.len() != 8 || !field.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Ipv4Addr::from(
        u32::from_str_radix(field, 16).ok()?.to_ne_bytes(),
    ))
}

fn parse_route_line(line: &str) -> Option<RouteRow> {
    // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
    let mut fields = line.split_whitespace();
    let iface = fields.next()?.to_owned();
    let destination = hex_addr(fields.next()?)?;
    let _gateway = fields.next()?;
    let flags = fields.next()?;
    let _refcnt = fields.next()?;
    let _use = fields.next()?;
    let metric = fields.next()?;
    let mask = hex_addr(fields.next()?)?;
    if flags.len() > 4 || !flags.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    if metric.is_empty() || !metric.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(RouteRow {
        iface,
        destination,
        flags: u16::from_str_radix(flags, 16).ok()?,
        metric: metric.parse().ok()?,
        mask,
    })
}

/// The rows of `/proc/net/route`. A table that does not look like one, or a line
/// that does not parse, is an error and not an empty answer: "no route" must
/// mean the table says so.
pub fn parse_proc_net_route(text: &str) -> Result<Vec<RouteRow>, ObserveError> {
    if text.len() > MAX_TABLE_BYTES {
        return Err(ObserveError::Malformed);
    }
    let mut lines = text.lines();
    let header = lines.next().ok_or(ObserveError::Malformed)?;
    let mut columns = header.split_whitespace();
    let known = columns.next() == Some("Iface")
        && columns.next() == Some("Destination")
        && columns.next() == Some("Gateway")
        && columns.next() == Some("Flags");
    if !known {
        return Err(ObserveError::Malformed);
    }
    lines
        .filter(|line| !line.trim().is_empty())
        .map(|line| parse_route_line(line).ok_or(ObserveError::Malformed))
        .collect()
}

/// The number of leading one bits of a contiguous mask; `None` for a mask with
/// holes, which is not a prefix.
fn prefix_len(mask: Ipv4Addr) -> Option<u32> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    (bits.checked_shl(ones).unwrap_or(0) == 0).then_some(ones)
}

/// Longest prefix wins, then the lowest metric. Rows that are down or rejecting
/// are ignored, and so is a row whose mask is not a prefix.
#[must_use]
pub fn best_route_v4(rows: &[RouteRow], dest: Ipv4Addr) -> Option<&RouteRow> {
    rows.iter()
        .filter(|row| row.flags & RTF_UP != 0 && row.flags & RTF_REJECT == 0)
        .filter_map(|row| {
            let mask = u32::from(row.mask);
            let covers = u32::from(dest) & mask == u32::from(row.destination) & mask;
            covers.then_some((prefix_len(row.mask)?, row))
        })
        .max_by(|(len_a, a), (len_b, b)| len_a.cmp(len_b).then(b.metric.cmp(&a.metric)))
        .map(|(_, row)| row)
}

/// What the route table text says about `dest`: the interface of the best route,
/// quoted through [`sanitise_alias`]. The Linux table has no interface index.
pub fn observe_v4(text: &str, dest: Ipv4Addr) -> Result<RouteObservation, ObserveError> {
    let rows = parse_proc_net_route(text)?;
    let best = best_route_v4(&rows, dest).ok_or(ObserveError::NoRoute)?;
    Ok(RouteObservation {
        interface_index: None,
        interface_alias: Some(sanitise_alias(&best.iface)),
        route_metric: best.metric,
    })
}

/// The Linux observer: `/proc/net/route`, IPv4 only. IPv6 is `Unsupported`: the
/// layout of `/proc/net/ipv6_route` was not available to check and no parser is
/// specified.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcNetRoute;

#[cfg(target_os = "linux")]
impl PathObserver for ProcNetRoute {
    fn best_route(&self, probe: IpAddr) -> Result<RouteObservation, ObserveError> {
        let IpAddr::V4(dest) = probe else {
            return Err(ObserveError::Unsupported);
        };
        let text = std::fs::read_to_string("/proc/net/route").map_err(|error| {
            ObserveError::LookupFailed(
                error
                    .raw_os_error()
                    .and_then(|code| u32::try_from(code).ok())
                    .unwrap_or(0),
            )
        })?;
        observe_v4(&text, dest)
    }
}

/// An observer for a platform that has none.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedObserver;

impl PathObserver for UnsupportedObserver {
    fn best_route(&self, _probe: IpAddr) -> Result<RouteObservation, ObserveError> {
        Err(ObserveError::Unsupported)
    }
}

/// The observer for this platform. Windows gets its own in `C-CO6w`.
#[must_use]
pub fn default_observer() -> Arc<dyn PathObserver> {
    #[cfg(target_os = "linux")]
    {
        Arc::new(ProcNetRoute)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(UnsupportedObserver)
    }
}

// ---- what the watcher keeps per address family ----

/// The words status uses for what the latest lookups said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewState {
    /// No lookup has finished yet.
    NotSampled,
    /// The last lookup succeeded and is at most [`MAX_AGE`] old.
    Observed,
    /// The last lookup succeeded, longer ago than [`MAX_AGE`].
    Stale,
    /// The last lookup failed; the last good observation, if any, is kept.
    Failed,
    /// The last lookup found no route for the probe.
    NoRoute,
    /// This platform or family has no observer.
    Unsupported,
}

impl ViewState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotSampled => "not_sampled",
            Self::Observed => "observed",
            Self::Stale => "stale",
            Self::Failed => "failed",
            Self::NoRoute => "no_route",
            Self::Unsupported => "unsupported",
        }
    }
}

/// The interface that was selected before the current one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousView {
    pub interface_index: Option<u32>,
    pub interface_alias: Option<String>,
    /// How long ago the current one replaced it.
    pub replaced_ago: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathView {
    pub state: ViewState,
    /// The last good observation, also while the last lookup failed.
    pub observation: Option<RouteObservation>,
    /// How old that observation is.
    pub age: Option<Duration>,
    /// How long this interface has been the selected one.
    pub selected_for: Option<Duration>,
    /// The interface it replaced, for [`CHANGE_NOTICE_WINDOW`] after the change.
    pub previous: Option<PreviousView>,
    /// How long ago the last lookup failed, when it did after the last success.
    pub failed_ago: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Sample {
    observation: RouteObservation,
    at: Instant,
    selected_since: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Replaced {
    interface_index: Option<u32>,
    interface_alias: Option<String>,
    at: Instant,
}

/// What the watcher remembers about one probe address.
///
/// `previous` changes only when two successful samples differ in interface; a
/// failed lookup never erases the last good observation and is shown as such
/// with its age. All time arithmetic is `saturating_duration_since`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathSlot {
    last_good: Option<Sample>,
    replaced: Option<Replaced>,
    last_failure: Option<(ObserveError, Instant)>,
}

impl PathSlot {
    /// Records the outcome of one lookup finished at `now`.
    pub fn record(&mut self, now: Instant, outcome: Result<RouteObservation, ObserveError>) {
        match outcome {
            Ok(observation) => {
                let selected_since = match &self.last_good {
                    Some(sample) if sample.observation.identity() == observation.identity() => {
                        sample.selected_since
                    }
                    Some(sample) => {
                        self.replaced = Some(Replaced {
                            interface_index: sample.observation.interface_index,
                            interface_alias: sample.observation.interface_alias.clone(),
                            at: now,
                        });
                        now
                    }
                    None => now,
                };
                self.last_good = Some(Sample {
                    observation,
                    at: now,
                    selected_since,
                });
                self.last_failure = None;
            }
            Err(error) => self.last_failure = Some((error, now)),
        }
    }

    /// What status shows at `now`.
    #[must_use]
    pub fn view(&self, now: Instant) -> PathView {
        let since = |at: Instant| now.saturating_duration_since(at);
        let age = self.last_good.as_ref().map(|sample| since(sample.at));
        let state = match (&self.last_failure, &self.last_good) {
            (Some((ObserveError::Unsupported, _)), _) => ViewState::Unsupported,
            (Some((ObserveError::NoRoute, _)), _) => ViewState::NoRoute,
            (Some(_), _) => ViewState::Failed,
            (None, Some(_)) if age.is_some_and(|age| age > MAX_AGE) => ViewState::Stale,
            (None, Some(_)) => ViewState::Observed,
            (None, None) => ViewState::NotSampled,
        };
        let previous = self
            .replaced
            .as_ref()
            .filter(|replaced| since(replaced.at) < CHANGE_NOTICE_WINDOW)
            .map(|replaced| PreviousView {
                interface_index: replaced.interface_index,
                interface_alias: replaced.interface_alias.clone(),
                replaced_ago: since(replaced.at),
            });
        PathView {
            state,
            observation: self
                .last_good
                .as_ref()
                .map(|sample| sample.observation.clone()),
            age,
            selected_for: self
                .last_good
                .as_ref()
                .map(|sample| since(sample.selected_since)),
            previous,
            failed_ago: self.last_failure.map(|(_, at)| since(at)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What this sandbox's kernel prints (padding included).
    const REAL: &str = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n\
        eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0                                                                               \n\
        eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0                                                                               \n";

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("address")
    }

    fn table(lines: &[&str]) -> String {
        let mut text = String::from(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        for line in lines {
            text.push_str(line);
            text.push('\n');
        }
        text
    }

    /// `iface dest/mask via flags metric` as a table line, computed through the
    /// native byte order so the test does not depend on the machine.
    fn line(iface: &str, dest: &str, mask: &str, flags: &str, metric: u32) -> String {
        let word = |a: &str| format!("{:08X}", u32::from_ne_bytes(ip(a).octets()));
        format!(
            "{iface}\t{}\t00000000\t{flags}\t0\t0\t{metric}\t{}\t0\t0\t0",
            word(dest),
            word(mask)
        )
    }

    // -- parsing ------------------------------------------------------------

    #[test]
    fn parse_proc_net_route_golden_lines() {
        let rows = parse_proc_net_route(REAL).expect("the real table parses");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].iface, "eth0");
        assert_eq!(rows[0].flags, 0x0003);
        assert_eq!(rows[0].metric, 0);
        if cfg!(target_endian = "little") {
            // 010200C0 is 192.0.2.1 on a little-endian machine.
            assert_eq!(rows[0].destination, ip("0.0.0.0"));
            assert_eq!(rows[1].destination, ip("192.0.2.0"));
            assert_eq!(rows[1].mask, ip("255.255.255.0"));
        }
        // The probe is covered by the on-link /24 and not by the default.
        assert_eq!(
            best_route_v4(&rows, PROBE_V4).map(|r| r.flags),
            Some(0x0001)
        );
    }

    #[test]
    fn the_word_is_decoded_through_the_native_byte_order() {
        let word = u32::from_ne_bytes([10, 1, 2, 3]);
        assert_eq!(hex_addr(&format!("{word:08X}")), Some(ip("10.1.2.3")));
        assert_eq!(hex_addr(&format!("{word:08x}")), Some(ip("10.1.2.3")));
        for bad in [
            "",
            "0",
            "0100007",
            "0100007F0",
            "0100007G",
            "+100007F",
            " 100007F",
        ] {
            assert_eq!(hex_addr(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn garbage_route_table_is_an_error_not_an_empty_answer() {
        for bad in [
            "",
            "garbage",
            "Iface Destination",
            "Destination Iface Gateway Flags",
            &table(&["eth0\t00000000"]),
            &table(&["eth0\tXXXXXXXX\t00000000\t0003\t0\t0\t0\t00000000\t0\t0\t0"]),
            &table(&["eth0\t00000000\t00000000\t0003\t0\t0\t-1\t00000000\t0\t0\t0"]),
            &table(&["eth0\t00000000\t00000000\t0003\t0\t0\t+1\t00000000\t0\t0\t0"]),
            &table(&["eth0\t00000000\t00000000\t00003\t0\t0\t0\t00000000\t0\t0\t0"]),
            &table(&["eth0\t00000000\t00000000\tZZ\t0\t0\t0\t00000000\t0\t0\t0"]),
            &table(&["eth0\t00000000\t00000000\t0003\t0\t0\t99999999999\t00000000\t0\t0\t0"]),
        ] {
            assert_eq!(
                parse_proc_net_route(bad),
                Err(ObserveError::Malformed),
                "{bad:?}"
            );
        }
        // A table with a header and no routes is a table: the lookup then says
        // "no route", which is what it means.
        assert_eq!(parse_proc_net_route(&table(&[])), Ok(Vec::new()));
        let big = format!("{}{}", table(&[]), " ".repeat(MAX_TABLE_BYTES));
        assert_eq!(parse_proc_net_route(&big), Err(ObserveError::Malformed));
    }

    // -- best route ---------------------------------------------------------

    #[test]
    fn longest_prefix_beats_a_lower_metric_default() {
        let text = table(&[
            &line("dev0", "0.0.0.0", "0.0.0.0", "0003", 1),
            &line("dev1", "198.51.100.0", "255.255.255.0", "0001", 600),
        ]);
        let rows = parse_proc_net_route(&text).expect("parses");
        let best = best_route_v4(&rows, ip("198.51.100.7")).expect("a route");
        assert_eq!(
            best.iface, "dev1",
            "the /24 wins although its metric is worse"
        );
        let other = best_route_v4(&rows, ip("203.0.113.9")).expect("a route");
        assert_eq!(other.iface, "dev0");
    }

    #[test]
    fn split_default_routes_are_resolved_by_the_best_route_not_the_zero_row() {
        // Two /1 routes through one interface and a /0 through another with a
        // lower metric: the /0 row is not what the OS uses.
        let text = table(&[
            &line("dev0", "0.0.0.0", "0.0.0.0", "0003", 5),
            &line("dev1", "0.0.0.0", "128.0.0.0", "0003", 50),
            &line("dev1", "128.0.0.0", "128.0.0.0", "0003", 50),
        ]);
        let rows = parse_proc_net_route(&text).expect("parses");
        for dest in ["8.8.8.8", "192.0.2.1", "200.1.1.1", "1.1.1.1"] {
            assert_eq!(
                best_route_v4(&rows, ip(dest)).expect("a route").iface,
                "dev1",
                "{dest}"
            );
        }
    }

    #[test]
    fn at_equal_prefix_the_lowest_metric_wins() {
        let text = table(&[
            &line("dev0", "0.0.0.0", "0.0.0.0", "0003", 600),
            &line("dev1", "0.0.0.0", "0.0.0.0", "0003", 100),
            &line("dev2", "0.0.0.0", "0.0.0.0", "0003", 300),
        ]);
        let rows = parse_proc_net_route(&text).expect("parses");
        assert_eq!(
            best_route_v4(&rows, ip("8.8.8.8")).expect("route").iface,
            "dev1"
        );
    }

    #[test]
    fn routes_that_are_down_or_rejecting_are_ignored() {
        let text = table(&[
            &line("dev0", "0.0.0.0", "0.0.0.0", "0003", 1),
            // /24 that is down (no RTF_UP) and a /24 that rejects (RTF_REJECT).
            &line("dev1", "192.0.2.0", "255.255.255.0", "0002", 1),
            &line("dev2", "192.0.2.0", "255.255.255.0", "0201", 1),
        ]);
        let rows = parse_proc_net_route(&text).expect("parses");
        assert_eq!(best_route_v4(&rows, PROBE_V4).expect("route").iface, "dev0");
        let only_down = table(&[&line("dev1", "0.0.0.0", "0.0.0.0", "0002", 1)]);
        let rows = parse_proc_net_route(&only_down).expect("parses");
        assert_eq!(best_route_v4(&rows, PROBE_V4), None);
    }

    #[test]
    fn a_mask_with_holes_is_not_a_prefix_and_never_matches() {
        let text = table(&[&line("dev0", "0.0.0.0", "255.0.255.0", "0003", 1)]);
        let rows = parse_proc_net_route(&text).expect("parses");
        assert_eq!(best_route_v4(&rows, ip("8.8.8.8")), None);
        assert_eq!(prefix_len(ip("255.0.255.0")), None);
        assert_eq!(prefix_len(ip("0.0.0.0")), Some(0));
        assert_eq!(prefix_len(ip("255.255.255.255")), Some(32));
        assert_eq!(prefix_len(ip("255.255.254.0")), Some(23));
        assert_eq!(prefix_len(ip("0.255.255.255")), None);
    }

    #[test]
    fn a_host_route_beats_everything_that_covers_it() {
        let text = table(&[
            &line("dev0", "0.0.0.0", "0.0.0.0", "0003", 1),
            &line("dev1", "192.0.2.0", "255.255.255.0", "0001", 1),
            &line("dev2", "192.0.2.1", "255.255.255.255", "0005", 900),
        ]);
        let rows = parse_proc_net_route(&text).expect("parses");
        assert_eq!(best_route_v4(&rows, PROBE_V4).expect("route").iface, "dev2");
        assert_eq!(
            best_route_v4(&rows, ip("192.0.2.2")).expect("route").iface,
            "dev1"
        );
    }

    // -- alias --------------------------------------------------------------

    #[test]
    fn alias_is_sanitised_and_bounded() {
        assert_eq!(sanitise_alias("Ethernet 2"), "Ethernet 2");
        assert_eq!(sanitise_alias("a\nb\tc\0d\u{7f}e"), "abcde");
        // Bidirectional controls, zero-width characters and separators.
        assert_eq!(
            sanitise_alias("a\u{202e}b\u{200b}c\u{2028}d\u{2029}e\u{feff}f\u{2066}g\u{061c}h"),
            "abcdefgh"
        );
        let long = "x".repeat(500);
        assert_eq!(sanitise_alias(&long).chars().count(), ALIAS_MAX_CHARS);
        // Counted in characters, not bytes, and never cut inside one.
        let wide = "\u{e9}".repeat(100);
        let kept = sanitise_alias(&wide);
        assert_eq!(kept.chars().count(), ALIAS_MAX_CHARS);
        assert!(kept.chars().all(|c| c == '\u{e9}'));
        assert_eq!(sanitise_alias(""), "");
        // Visible text is data and is left alone, whatever it says.
        assert_eq!(
            sanitise_alias("Some <b>quoted</b> name"),
            "Some <b>quoted</b> name"
        );
    }

    #[test]
    fn the_sanitiser_never_lets_a_control_or_invisible_character_through() {
        // The set is written out here, independently of `is_invisible`: the
        // Unicode controls and format characters that reorder or hide text.
        let hidden: Vec<char> = [0x061c_u32]
            .into_iter()
            .chain(0x200b..=0x200f)
            .chain(0x2028..=0x202e)
            .chain(0x2060..=0x2064)
            .chain(0x2066..=0x2069)
            .chain([0xfeff])
            .chain(0x00..=0x1f)
            .chain(0x7f..=0x9f)
            .filter_map(char::from_u32)
            .collect();
        for c in hidden {
            assert_eq!(
                sanitise_alias(&format!("a{c}b")),
                "ab",
                "U+{:04X}",
                u32::from(c)
            );
        }
        // Every printable ASCII character survives.
        let printable: String = (0x20_u8..0x7f).map(char::from).collect();
        for half in [&printable[..50], &printable[50..]] {
            assert_eq!(
                sanitise_alias(half),
                half,
                "kept whole, each half is under the cap"
            );
        }
        // And so does ordinary non-ASCII text.
        assert_eq!(
            sanitise_alias("Ethernet \u{e9} \u{4f8b}"),
            "Ethernet \u{e9} \u{4f8b}"
        );
    }

    // -- the watcher's slot -------------------------------------------------

    fn obs(alias: &str, metric: u32) -> RouteObservation {
        RouteObservation {
            interface_index: Some(7),
            interface_alias: Some(alias.to_owned()),
            route_metric: metric,
        }
    }

    #[test]
    fn a_fresh_slot_has_not_been_sampled() {
        let now = Instant::now();
        let view = PathSlot::default().view(now);
        assert_eq!(view.state, ViewState::NotSampled);
        assert_eq!(view.observation, None);
        assert_eq!(view.previous, None);
    }

    #[test]
    fn stale_observation_is_labelled_stale_after_15s() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        assert_eq!(slot.view(t0).state, ViewState::Observed);
        assert_eq!(
            slot.view(t0 + MAX_AGE).state,
            ViewState::Observed,
            "15 s exactly is still fresh"
        );
        let stale = slot.view(t0 + MAX_AGE + Duration::from_millis(1));
        assert_eq!(stale.state, ViewState::Stale);
        assert_eq!(
            stale.observation,
            Some(obs("dev0", 1)),
            "still shown, labelled"
        );
        assert_eq!(stale.age, Some(MAX_AGE + Duration::from_millis(1)));
    }

    #[test]
    fn failed_lookup_never_erases_the_last_observation() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        for (error, state) in [
            (ObserveError::LookupFailed(5), ViewState::Failed),
            (ObserveError::Malformed, ViewState::Failed),
            (ObserveError::NoRoute, ViewState::NoRoute),
            (ObserveError::Unsupported, ViewState::Unsupported),
        ] {
            slot.record(t0 + Duration::from_secs(5), Err(error));
            let view = slot.view(t0 + Duration::from_secs(7));
            assert_eq!(view.state, state, "{error:?}");
            assert_eq!(view.observation, Some(obs("dev0", 1)), "{error:?}");
            assert_eq!(view.failed_ago, Some(Duration::from_secs(2)));
            assert_eq!(view.age, Some(Duration::from_secs(7)));
        }
        // A later success clears the failure.
        slot.record(t0 + Duration::from_secs(10), Ok(obs("dev0", 1)));
        let view = slot.view(t0 + Duration::from_secs(11));
        assert_eq!(view.state, ViewState::Observed);
        assert_eq!(view.failed_ago, None);
    }

    #[test]
    fn a_slot_that_only_ever_failed_has_no_observation() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Err(ObserveError::NoRoute));
        let view = slot.view(t0 + Duration::from_secs(1));
        assert_eq!(
            (view.state, view.observation, view.age),
            (ViewState::NoRoute, None, None)
        );
    }

    #[test]
    fn route_change_records_previous_and_expires_after_the_notice_window() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        slot.record(t0 + Duration::from_secs(5), Ok(obs("dev0", 1)));
        assert_eq!(
            slot.view(t0 + Duration::from_secs(6)).previous,
            None,
            "same interface: no change"
        );

        // The interface changes.
        let change = t0 + Duration::from_secs(10);
        slot.record(change, Ok(obs("dev1", 1)));
        let view = slot.view(change + Duration::from_secs(1));
        assert_eq!(view.observation, Some(obs("dev1", 1)));
        assert_eq!(view.selected_for, Some(Duration::from_secs(1)));
        assert_eq!(
            view.previous,
            Some(PreviousView {
                interface_index: Some(7),
                interface_alias: Some("dev0".into()),
                replaced_ago: Duration::from_secs(1),
            })
        );

        // The notice lasts ten minutes and then goes; the current one stays.
        let inside = slot.view(change + CHANGE_NOTICE_WINDOW - Duration::from_millis(1));
        assert!(inside.previous.is_some());
        let outside = slot.view(change + CHANGE_NOTICE_WINDOW);
        assert_eq!(outside.previous, None);
        assert_eq!(outside.observation, Some(obs("dev1", 1)));
    }

    #[test]
    fn a_change_of_metric_alone_is_not_a_change_of_path() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        slot.record(t0 + Duration::from_secs(5), Ok(obs("dev0", 500)));
        let view = slot.view(t0 + Duration::from_secs(6));
        assert_eq!(view.previous, None);
        assert_eq!(
            view.selected_for,
            Some(Duration::from_secs(6)),
            "selected since the first sample"
        );
        assert_eq!(view.observation.map(|o| o.route_metric), Some(500));
    }

    #[test]
    fn a_failure_in_between_does_not_make_the_same_interface_look_new() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        slot.record(
            t0 + Duration::from_secs(5),
            Err(ObserveError::LookupFailed(1)),
        );
        slot.record(t0 + Duration::from_secs(10), Ok(obs("dev0", 1)));
        let view = slot.view(t0 + Duration::from_secs(11));
        assert_eq!(view.previous, None);
        assert_eq!(view.selected_for, Some(Duration::from_secs(11)));
    }

    #[test]
    fn the_index_is_part_of_the_identity() {
        let t0 = Instant::now();
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        let mut moved = obs("dev0", 1);
        moved.interface_index = Some(9);
        slot.record(t0 + Duration::from_secs(5), Ok(moved));
        assert!(slot.view(t0 + Duration::from_secs(6)).previous.is_some());
    }

    #[test]
    fn a_clock_that_runs_backwards_does_not_panic() {
        let t0 = Instant::now() + Duration::from_secs(100);
        let mut slot = PathSlot::default();
        slot.record(t0, Ok(obs("dev0", 1)));
        let view = slot.view(t0 - Duration::from_secs(50));
        assert_eq!(view.age, Some(Duration::ZERO));
    }

    #[test]
    fn view_words_are_the_closed_set() {
        let words = [
            (ViewState::NotSampled, "not_sampled"),
            (ViewState::Observed, "observed"),
            (ViewState::Stale, "stale"),
            (ViewState::Failed, "failed"),
            (ViewState::NoRoute, "no_route"),
            (ViewState::Unsupported, "unsupported"),
        ];
        for (state, word) in words {
            assert_eq!(state.as_str(), word);
            assert_eq!(crate::ingress::types::contains_forbidden_word(word), None);
        }
    }

    // -- the platform observers ---------------------------------------------

    #[test]
    fn the_unsupported_observer_says_so_for_both_families() {
        let observer = UnsupportedObserver;
        assert_eq!(
            observer.best_route(IpAddr::V4(PROBE_V4)),
            Err(ObserveError::Unsupported)
        );
        assert_eq!(
            observer.best_route(IpAddr::V6(PROBE_V6)),
            Err(ObserveError::Unsupported)
        );
    }

    #[test]
    fn the_probes_are_documentation_addresses() {
        use crate::ingress::target::{classify_ip, SpecialUse};
        assert_eq!(
            classify_ip(IpAddr::V4(PROBE_V4)),
            Some(SpecialUse::Documentation)
        );
        assert_eq!(
            classify_ip(IpAddr::V6(PROBE_V6)),
            Some(SpecialUse::Documentation)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_linux_observer_reads_the_real_table_and_does_not_do_ipv6() {
        let observer = ProcNetRoute;
        assert_eq!(
            observer.best_route(IpAddr::V6(PROBE_V6)),
            Err(ObserveError::Unsupported)
        );
        let Ok(text) = std::fs::read_to_string("/proc/net/route") else {
            eprintln!("skipped: /proc/net/route is not readable here");
            return;
        };
        let rows = parse_proc_net_route(&text).expect("the real table parses");
        match observer.best_route(IpAddr::V4(PROBE_V4)) {
            Ok(found) => {
                let best = best_route_v4(&rows, PROBE_V4).expect("the table has a route");
                assert_eq!(
                    found.interface_alias.as_deref(),
                    Some(sanitise_alias(&best.iface).as_str())
                );
                assert_eq!(found.route_metric, best.metric);
                assert_eq!(found.interface_index, None);
            }
            Err(error) => assert_eq!(error, ObserveError::NoRoute),
        }
    }

    #[test]
    fn the_default_observer_is_chosen_for_the_platform() {
        let observer = default_observer();
        let v6 = observer.best_route(IpAddr::V6(PROBE_V6));
        assert_eq!(
            v6,
            Err(ObserveError::Unsupported),
            "no IPv6 observer exists in M2"
        );
        #[cfg(target_os = "linux")]
        assert_ne!(
            observer.best_route(IpAddr::V4(PROBE_V4)),
            Err(ObserveError::Unsupported),
            "Linux has an IPv4 observer"
        );
    }

    #[test]
    fn the_constants_are_the_numbers_of_the_design() {
        assert_eq!(PROBE_V4, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(PROBE_V6, "2001:db8::1".parse::<Ipv6Addr>().expect("addr"));
        assert_eq!(POLL_INTERVAL, Duration::from_secs(5));
        assert_eq!(MAX_AGE, Duration::from_secs(15));
        assert_eq!(CHANGE_NOTICE_WINDOW, Duration::from_secs(600));
        assert_eq!(ALIAS_MAX_CHARS, 64);
        assert!(
            MAX_AGE > POLL_INTERVAL,
            "a sample every 5 s is fresh for 15 s"
        );
    }

    #[test]
    fn the_observation_quotes_the_interface_through_the_sanitiser() {
        let text = table(&[&line("dev\u{202e}0\u{7}", "0.0.0.0", "0.0.0.0", "0003", 42)]);
        let found = observe_v4(&text, PROBE_V4).expect("a route");
        assert_eq!(found.interface_alias.as_deref(), Some("dev0"));
        assert_eq!(found.route_metric, 42);
        assert_eq!(found.interface_index, None);
        assert_eq!(
            observe_v4(&table(&[]), PROBE_V4),
            Err(ObserveError::NoRoute)
        );
        assert_eq!(observe_v4("junk", PROBE_V4), Err(ObserveError::Malformed));
    }
}
