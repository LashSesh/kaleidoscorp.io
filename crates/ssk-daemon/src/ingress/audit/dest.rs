//! The destination key and the keyed token (design 6.4.10).
//!
//! `destination_logging: hashed` records a keyed token where `plain` records the
//! host name. A plain hash of a host name is not privacy (the input space is small
//! and public, and a per-ledger salt is read from the ledger), so the token is the
//! output of a keyed function under a per-installation secret that is not in the
//! ledger:
//!
//! ```text
//! key      32 random bytes, kept as 64 lowercase hex characters and 0x0A in
//!          <state_dir>/ingress-dest.key (mode 0600), created exclusively and made durable (D3)
//! kid      first 8 bytes of blake3::derive_key("ssk.ingress.dest.key-id.v1", key), as 16 hex characters
//! message  "ssk.ingress.dest.v1" 0x00 kind(1 byte) len(host) as u16 big-endian host
//! token    first 16 bytes of blake3::keyed_hash(key, message), as 32 hex characters
//! ```
//!
//! The port is not part of the token and stays in clear. `hashed` never degrades to
//! `plain`: whatever goes wrong with the key (it cannot be created, read or
//! validated, or the random source fails) is an error here, and the ingress is
//! unavailable with `INGRESS_AUDIT_KEY_UNAVAILABLE`.
//!
//! The token function and the key file are a persisted contract (COMPATIBILITY
//! matrix): a change to either makes every older token unverifiable.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::fs::{LedgerFs, StoreError, KEY_FILE_NAME};
use crate::ingress::target::{unmap_ip, Target, TargetKind};
use crate::ingress::types::{AddrRef, DestRef, DestinationLogging, HostKind, UnavailableCode};

/// Bytes of the key.
pub const KEY_LEN: usize = 32;
/// The key file: 64 hex characters and a line feed.
pub const KEY_FILE_LEN: usize = KEY_LEN * 2 + 1;
/// The longest host a token is computed over: a DNS name is at most 253
/// characters. The length goes into the message as a `u16`, so this is also the
/// bound that makes the cast total.
pub const MAX_HOST_LEN: usize = 255;

const KEY_ID_CONTEXT: &str = "ssk.ingress.dest.key-id.v1";
const MESSAGE_DOMAIN: &[u8] = b"ssk.ingress.dest.v1";

/// The byte that stands for the spelling class in the message.
const fn kind_byte(kind: HostKind) -> u8 {
    match kind {
        HostKind::Name => 0x01,
        HostKind::Ipv4 => 0x04,
        HostKind::Ipv6 => 0x06,
    }
}

fn host_kind(kind: TargetKind) -> HostKind {
    match kind {
        TargetKind::Name => HostKind::Name,
        TargetKind::Ipv4 => HostKind::Ipv4,
        TargetKind::Ipv6 => HostKind::Ipv6,
    }
}

/// The first `chars` characters of the lower-case hex form of a hash.
fn hex_prefix(hash: &blake3::Hash, chars: usize) -> String {
    let hex = hash.to_hex();
    hex.as_str().get(..chars).unwrap_or_default().to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// A host longer than any canonical host: nothing is recorded for it, and it
    /// is never recorded in clear instead.
    HostTooLong,
}

/// The per-installation secret and the id that names it.
pub struct DestKey {
    key: [u8; KEY_LEN],
    kid: String,
}

impl fmt::Debug for DestKey {
    /// Never the key.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl DestKey {
    #[must_use]
    pub fn from_bytes(key: [u8; KEY_LEN]) -> Self {
        let id = blake3::Hash::from_bytes(blake3::derive_key(KEY_ID_CONTEXT, &key));
        Self {
            key,
            kid: hex_prefix(&id, 16),
        }
    }

    /// Which key sealed a token: 16 hex characters.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// The token of a canonical host: 32 hex characters.
    ///
    /// # Errors
    /// [`SealError::HostTooLong`] for a host over [`MAX_HOST_LEN`] bytes.
    pub fn token(&self, kind: HostKind, host: &str) -> Result<String, SealError> {
        if host.len() > MAX_HOST_LEN {
            return Err(SealError::HostTooLong);
        }
        let len = u16::try_from(host.len()).map_err(|_| SealError::HostTooLong)?;
        let mut message = Vec::with_capacity(
            MESSAGE_DOMAIN
                .len()
                .saturating_add(4)
                .saturating_add(host.len()),
        );
        message.extend_from_slice(MESSAGE_DOMAIN);
        message.push(0x00);
        message.push(kind_byte(kind));
        message.extend_from_slice(&len.to_be_bytes());
        message.extend_from_slice(host.as_bytes());
        Ok(hex_prefix(&blake3::keyed_hash(&self.key, &message), 32))
    }
}

/// The two ways a destination is written, chosen once per boot.
#[derive(Clone)]
pub enum DestSealer {
    Plain,
    Hashed(Arc<DestKey>),
}

impl fmt::Debug for DestSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => f.write_str("DestSealer::Plain"),
            Self::Hashed(key) => write!(f, "DestSealer::Hashed({})", key.kid()),
        }
    }
}

impl DestSealer {
    #[must_use]
    pub const fn mode(&self) -> DestinationLogging {
        match self {
            Self::Plain => DestinationLogging::Plain,
            Self::Hashed(_) => DestinationLogging::Hashed,
        }
    }

    /// `Started.dest_key_id`: `None` in plain mode.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::Plain => None,
            Self::Hashed(key) => Some(key.kid()),
        }
    }

    /// The destination of an admitted flow.
    ///
    /// # Errors
    /// [`SealError::HostTooLong`] in hashed mode for a host no token is computed
    /// over; the record is not written in clear instead.
    pub fn dest(&self, target: &Target) -> Result<DestRef, SealError> {
        match self {
            Self::Plain => Ok(plain_dest(target)),
            Self::Hashed(key) => {
                let kind = host_kind(target.kind());
                Ok(DestRef::Hashed {
                    kid: key.kid().to_owned(),
                    kind,
                    token: key.token(kind, target.host())?,
                    port: target.port(),
                })
            }
        }
    }

    /// The destination of a refusal: always in clear (a refusal is evidence, and
    /// nothing was dialled).
    #[must_use]
    pub fn denied(&self, target: &Target) -> DestRef {
        plain_dest(target)
    }

    /// A resolved address (`Result.dialed`, `Result.attempted`), in the same
    /// mode. An IPv4-mapped IPv6 address is recorded as the IPv4 address it is,
    /// like everywhere else.
    ///
    /// # Errors
    /// Never in practice (an address is at most 45 characters); the signature
    /// matches [`DestSealer::dest`].
    pub fn addr(&self, addr: SocketAddr) -> Result<AddrRef, SealError> {
        let ip = unmap_ip(addr.ip());
        match self {
            Self::Plain => Ok(AddrRef::Plain {
                ip: ip.to_string(),
                port: addr.port(),
            }),
            Self::Hashed(key) => {
                let kind = match ip {
                    IpAddr::V4(_) => HostKind::Ipv4,
                    IpAddr::V6(_) => HostKind::Ipv6,
                };
                Ok(AddrRef::Hashed {
                    kid: key.kid().to_owned(),
                    kind,
                    token: key.token(kind, &ip.to_string())?,
                    port: addr.port(),
                })
            }
        }
    }
}

fn plain_dest(target: &Target) -> DestRef {
    DestRef::Plain {
        host: target.host().to_owned(),
        port: target.port(),
    }
}

// ---------------------------------------------------------------------------
// The key file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The store refused or failed.
    Store(StoreError),
    /// The key file exists and is not exactly 64 lowercase hex characters, a line
    /// feed, and a key that is not all zero. Never repaired: the operator removes
    /// it, which forgets every older token.
    Corrupt,
    /// The operating system's random source failed.
    Random,
}

impl KeyError {
    /// The code the ingress is unavailable with.
    #[must_use]
    pub const fn unavailable_code(self) -> UnavailableCode {
        UnavailableCode::AuditKeyUnavailable
    }

    /// What the operator does about it.
    #[must_use]
    pub fn operator_hint(self, root: &std::path::Path) -> String {
        match self {
            Self::Store(error) => error.operator_hint(root),
            Self::Corrupt => format!(
                "the destination key {}/{KEY_FILE_NAME} is not a key this daemon wrote; to use hashed destinations again remove it (older hashed destinations can then no longer be matched), or set destination_logging to plain",
                root.display()
            ),
            Self::Random => {
                "the operating system could not supply random bytes for the destination key"
                    .to_owned()
            }
        }
    }
}

/// The key file's content for `key`.
#[must_use]
pub fn render_key_file(key: &[u8; KEY_LEN]) -> Vec<u8> {
    let mut text = String::with_capacity(KEY_FILE_LEN);
    for byte in key {
        for nibble in [byte >> 4, byte & 0x0f] {
            text.push(char::from_digit(u32::from(nibble), 16).unwrap_or('0'));
        }
    }
    text.push('\n');
    text.into_bytes()
}

/// Exactly what [`render_key_file`] writes, and nothing else.
///
/// # Errors
/// [`KeyError::Corrupt`] for any other content, including a key that is all
/// zero (a zero-filled file is damage, not a key).
pub fn parse_key_file(bytes: &[u8]) -> Result<[u8; KEY_LEN], KeyError> {
    if bytes.len() != KEY_FILE_LEN || bytes.last() != Some(&b'\n') {
        return Err(KeyError::Corrupt);
    }
    let digits = bytes.get(..KEY_LEN * 2).ok_or(KeyError::Corrupt)?;
    let mut key = [0_u8; KEY_LEN];
    for (slot, pair) in key.iter_mut().zip(digits.chunks_exact(2)) {
        // Lower-case digits only: the writer never writes anything else.
        let nibble = |byte: Option<&u8>| match byte {
            Some(&b) if !b.is_ascii_uppercase() => char::from(b)
                .to_digit(16)
                .and_then(|digit| u8::try_from(digit).ok()),
            _ => None,
        };
        let (high, low) = (nibble(pair.first()), nibble(pair.get(1)));
        let (Some(high), Some(low)) = (high, low) else {
            return Err(KeyError::Corrupt);
        };
        *slot = (high << 4) | low;
    }
    if key.iter().all(|&byte| byte == 0) {
        return Err(KeyError::Corrupt);
    }
    Ok(key)
}

/// Loads the key, creating it when it does not exist (D3).
///
/// `fill` supplies random bytes and returns `false` when it cannot; production
/// passes the operating system's source.
///
/// # Errors
/// [`KeyError`].
pub fn load_or_create(
    fs: &dyn LedgerFs,
    fill: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<DestKey, KeyError> {
    // Two rounds: a key that is missing, created by this call, and read back; or
    // a create that lost a race (another process made it between the read and the
    // create) and a second read. A third round would only be a loop.
    for _ in 0..2 {
        if let Some(bytes) = fs.read_key_file().map_err(KeyError::Store)? {
            return parse_key_file(&bytes).map(DestKey::from_bytes);
        }
        let mut key = [0_u8; KEY_LEN];
        if !fill(&mut key) || key.iter().all(|&byte| byte == 0) {
            return Err(KeyError::Random);
        }
        match fs.create_key_file(&render_key_file(&key)) {
            Ok(()) => return Ok(DestKey::from_bytes(key)),
            Err(StoreError::Io("AUDIT_ALREADY_EXISTS")) => {}
            Err(error) => return Err(KeyError::Store(error)),
        }
    }
    Err(KeyError::Store(StoreError::Io("AUDIT_ALREADY_EXISTS")))
}

/// The operating system's random source.
pub fn os_random(buffer: &mut [u8]) -> bool {
    getrandom::fill(buffer).is_ok()
}

/// The sealer for a boot: `Plain` touches no file, `Hashed` loads or creates the
/// key.
///
/// # Errors
/// [`KeyError`] in hashed mode.
pub fn open_sealer(
    fs: &dyn LedgerFs,
    mode: DestinationLogging,
    fill: &mut dyn FnMut(&mut [u8]) -> bool,
) -> Result<DestSealer, KeyError> {
    match mode {
        DestinationLogging::Plain => Ok(DestSealer::Plain),
        DestinationLogging::Hashed => {
            load_or_create(fs, fill).map(|key| DestSealer::Hashed(Arc::new(key)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::target::{canonicalize, RawTarget};
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Key bytes 00 01 02 ... 1f: the key of the vectors in design 6.4.10.
    fn counting_key() -> DestKey {
        let mut key = [0_u8; KEY_LEN];
        for (slot, value) in key.iter_mut().zip(0_u8..) {
            *slot = value;
        }
        DestKey::from_bytes(key)
    }

    fn flat_key() -> DestKey {
        DestKey::from_bytes([0xa5; KEY_LEN])
    }

    fn name(host: &str, port: u16) -> Target {
        canonicalize(RawTarget::Name(host.as_bytes().to_vec(), port)).expect("a valid name")
    }

    // -- the function --------------------------------------------------------

    /// The vectors were computed by a second, independent implementation of BLAKE3
    /// (written from the specification in Python; it reproduces the official
    /// keyed-hash vector for the empty input), not by this crate.
    #[test]
    fn token_golden_vectors() {
        let key = counting_key();
        assert_eq!(key.kid(), "dcfd61fc2475cfd3");
        for (kind, host, token) in [
            (
                HostKind::Name,
                "example.com",
                "2c8a3534e4fd1ffbc2665f5baf190592",
            ),
            (
                HostKind::Name,
                "example.org",
                "99c3288699f4a46072979169e9d3d4b4",
            ),
            (
                HostKind::Ipv4,
                "192.0.2.1",
                "3b632276b0bcd7c49c671eadc4a46815",
            ),
            (
                HostKind::Ipv6,
                "2001:db8::1",
                "c29802ba065c13d951ac2ca4d71fea53",
            ),
        ] {
            assert_eq!(key.token(kind, host).as_deref(), Ok(token), "{host}");
        }
        let other = flat_key();
        assert_eq!(other.kid(), "3861d664c10b840d");
        let long_name = format!(
            "{}.{}.{}.{}",
            "x".repeat(63),
            "y".repeat(63),
            "z".repeat(63),
            "w".repeat(61)
        );
        assert_eq!(long_name.len(), 253);
        for (kind, host, token) in [
            (HostKind::Name, "a.b", "6ddfe3d49f32f2b81117c4ffcf0a93b9"),
            (
                HostKind::Name,
                long_name.as_str(),
                "fde683e51c65ba39606ccdf0e33351c6",
            ),
            (
                HostKind::Name,
                "192.0.2.1",
                "6a9541c9ac7b7b86cdc858a0c0adb2ee",
            ),
            (
                HostKind::Ipv6,
                "2001:db8:85a3::8a2e:370:7334",
                "0f98a79da312ffcac9c872489b7ccda2",
            ),
            (
                HostKind::Ipv4,
                "93.184.216.34",
                "e0bee7f47ca808aecd3bc6750069071a",
            ),
        ] {
            assert_eq!(other.token(kind, host).as_deref(), Ok(token), "{host}");
        }
    }

    #[test]
    fn the_token_is_not_the_unkeyed_hash_of_the_name() {
        // Anyone can compute this value; the token must not be it.
        let unkeyed = "74927756a0a08c17da48407c8adcedc9";
        assert_ne!(
            counting_key()
                .token(HostKind::Name, "example.com")
                .as_deref(),
            Ok(unkeyed)
        );
    }

    #[test]
    fn token_differs_per_key_and_equal_within_a_key() {
        let (a, b) = (counting_key(), flat_key());
        assert_ne!(a.kid(), b.kid());
        let first = a.token(HostKind::Name, "example.com").expect("token");
        assert_eq!(
            first,
            a.token(HostKind::Name, "example.com").expect("token")
        );
        assert_ne!(
            first,
            b.token(HostKind::Name, "example.com").expect("token")
        );
        // A different host, a different token.
        assert_ne!(
            first,
            a.token(HostKind::Name, "example.org").expect("token")
        );
        assert_eq!(first.len(), 32);
        assert!(first
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(a.kid().len(), 16);
    }

    #[test]
    fn the_kind_is_part_of_the_message() {
        let key = counting_key();
        // The same text under three spellings: three tokens.
        let tokens: Vec<String> = [HostKind::Name, HostKind::Ipv4, HostKind::Ipv6]
            .into_iter()
            .map(|kind| key.token(kind, "192.0.2.1").expect("token"))
            .collect();
        assert_ne!(tokens.first(), tokens.get(1));
        assert_ne!(tokens.get(1), tokens.get(2));
        assert_ne!(tokens.first(), tokens.get(2));
    }

    #[test]
    fn a_host_over_the_bound_has_no_token_and_the_bound_itself_has_one() {
        let key = counting_key();
        assert_eq!(
            key.token(HostKind::Name, &"a".repeat(MAX_HOST_LEN))
                .map(|t| t.len()),
            Ok(32)
        );
        assert_eq!(
            key.token(HostKind::Name, &"a".repeat(MAX_HOST_LEN + 1)),
            Err(SealError::HostTooLong)
        );
        assert_eq!(key.token(HostKind::Name, "").map(|t| t.len()), Ok(32));
    }

    #[test]
    fn the_debug_form_names_the_key_id_and_never_the_key() {
        // Exactly this, so that nothing can be added to it unnoticed.
        assert_eq!(
            format!("{:?}", counting_key()),
            r#"DestKey { kid: "dcfd61fc2475cfd3", .. }"#
        );
        assert_eq!(
            format!("{:?}", DestSealer::Hashed(Arc::new(counting_key()))),
            "DestSealer::Hashed(dcfd61fc2475cfd3)"
        );
        assert_eq!(format!("{:?}", DestSealer::Plain), "DestSealer::Plain");
    }

    // -- sealing -------------------------------------------------------------

    #[test]
    fn plain_mode_writes_the_canonical_host_and_the_port() {
        let sealer = DestSealer::Plain;
        assert_eq!(sealer.mode(), DestinationLogging::Plain);
        assert_eq!(sealer.kid(), None);
        assert_eq!(
            sealer.dest(&name("Example.COM.", 443)),
            Ok(DestRef::Plain {
                host: "example.com".into(),
                port: 443
            })
        );
        let addr = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        assert_eq!(
            sealer.addr(addr),
            Ok(AddrRef::Plain {
                ip: "93.184.216.34".into(),
                port: 443
            })
        );
    }

    #[test]
    fn hashed_mode_writes_kid_kind_token_and_the_port_in_clear() {
        let sealer = DestSealer::Hashed(Arc::new(counting_key()));
        assert_eq!(sealer.mode(), DestinationLogging::Hashed);
        assert_eq!(sealer.kid(), Some("dcfd61fc2475cfd3"));
        assert_eq!(
            sealer.dest(&name("example.com", 8443)),
            Ok(DestRef::Hashed {
                kid: "dcfd61fc2475cfd3".into(),
                kind: HostKind::Name,
                token: "2c8a3534e4fd1ffbc2665f5baf190592".into(),
                port: 8443,
            })
        );
        let v6 = SocketAddr::from((Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443));
        assert_eq!(
            sealer.addr(v6),
            Ok(AddrRef::Hashed {
                kid: "dcfd61fc2475cfd3".into(),
                kind: HostKind::Ipv6,
                token: "c29802ba065c13d951ac2ca4d71fea53".into(),
                port: 443,
            })
        );
        let v4 = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 80));
        assert_eq!(
            sealer.addr(v4),
            Ok(AddrRef::Hashed {
                kid: "dcfd61fc2475cfd3".into(),
                kind: HostKind::Ipv4,
                token: "3b632276b0bcd7c49c671eadc4a46815".into(),
                port: 80,
            })
        );
    }

    #[test]
    fn a_literal_target_is_sealed_under_its_own_kind() {
        let sealer = DestSealer::Hashed(Arc::new(counting_key()));
        let v4 = canonicalize(RawTarget::V4(Ipv4Addr::new(192, 0, 2, 1), 443)).expect("target");
        let Ok(DestRef::Hashed { kind, token, .. }) = sealer.dest(&v4) else {
            panic!("hashed");
        };
        assert_eq!(kind, HostKind::Ipv4);
        assert_eq!(token, "3b632276b0bcd7c49c671eadc4a46815");
        let v6 = canonicalize(RawTarget::V6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
        ))
        .expect("target");
        let Ok(DestRef::Hashed { kind, token, .. }) = sealer.dest(&v6) else {
            panic!("hashed");
        };
        assert_eq!(kind, HostKind::Ipv6);
        assert_eq!(token, "c29802ba065c13d951ac2ca4d71fea53");
    }

    #[test]
    fn port_is_not_part_of_the_token() {
        let sealer = DestSealer::Hashed(Arc::new(counting_key()));
        let (a, b) = (
            sealer.dest(&name("example.com", 80)),
            sealer.dest(&name("example.com", 443)),
        );
        let (
            Ok(DestRef::Hashed {
                token: ta,
                port: pa,
                ..
            }),
            Ok(DestRef::Hashed {
                token: tb,
                port: pb,
                ..
            }),
        ) = (a, b)
        else {
            panic!("hashed");
        };
        assert_eq!(ta, tb);
        assert_eq!((pa, pb), (80, 443));
    }

    #[test]
    fn a_refusal_is_in_clear_in_either_mode() {
        let target = name("blocked.example", 25);
        let expected = DestRef::Plain {
            host: "blocked.example".into(),
            port: 25,
        };
        assert_eq!(DestSealer::Plain.denied(&target), expected);
        assert_eq!(
            DestSealer::Hashed(Arc::new(counting_key())).denied(&target),
            expected
        );
    }

    #[test]
    fn a_mapped_address_is_recorded_as_the_address_it_is() {
        let mapped = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34).to_ipv6_mapped(), 443));
        let plain = SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), 443));
        for sealer in [DestSealer::Plain, DestSealer::Hashed(Arc::new(flat_key()))] {
            assert_eq!(sealer.addr(mapped), sealer.addr(plain));
        }
        // And the hashed form is the vector of the plain IPv4 address.
        assert_eq!(
            DestSealer::Hashed(Arc::new(flat_key())).addr(mapped),
            Ok(AddrRef::Hashed {
                kid: "3861d664c10b840d".into(),
                kind: HostKind::Ipv4,
                token: "e0bee7f47ca808aecd3bc6750069071a".into(),
                port: 443,
            })
        );
    }

    // -- the key file format -------------------------------------------------

    #[test]
    fn the_key_file_is_64_lowercase_hex_characters_and_a_line_feed() {
        let key: [u8; KEY_LEN] =
            std::array::from_fn(|i| u8::try_from((i * 9 + 1) & 0xff).expect("fits"));
        let text = render_key_file(&key);
        // The expected text comes from the independent implementation.
        assert_eq!(
            std::str::from_utf8(&text).expect("ascii"),
            "010a131c252e374049525b646d767f88919aa3acb5bec7d0d9e2ebf4fd060f18\n"
        );
        assert_eq!(text.len(), KEY_FILE_LEN);
        assert_eq!(parse_key_file(&text), Ok(key));
    }

    #[test]
    fn only_the_exact_form_parses() {
        let good = "010a131c252e374049525b646d767f88919aa3acb5bec7d0d9e2ebf4fd060f18\n";
        assert!(parse_key_file(good.as_bytes()).is_ok());
        let upper = good.to_uppercase();
        let crlf = good.replace('\n', "\r\n");
        let spaced = format!(" {good}");
        let zeros = format!("{}\n", "0".repeat(64));
        let non_hex = good.replacen('0', "g", 1);
        let tail_space = good.replacen('\n', " ", 1);
        let two_lines = format!("{good}{good}");
        let one_short = &good[1..];
        let one_long = format!("1{good}");
        let cases: [(&str, &[u8]); 11] = [
            ("empty", b""),
            ("no line feed", &good.as_bytes()[..64]),
            ("upper case", upper.as_bytes()),
            ("crlf", crlf.as_bytes()),
            ("leading space", spaced.as_bytes()),
            ("all zero", zeros.as_bytes()),
            ("not hex", non_hex.as_bytes()),
            ("line feed replaced", tail_space.as_bytes()),
            ("two keys", two_lines.as_bytes()),
            ("one short", one_short.as_bytes()),
            ("one long", one_long.as_bytes()),
        ];
        for (label, bytes) in cases {
            assert_eq!(parse_key_file(bytes), Err(KeyError::Corrupt), "{label}");
        }
        // A single flipped digit is a different key, not an error: the file has no
        // checksum, and the kid is what tells two keys apart.
        let flipped = good.replacen('0', "1", 1);
        let (Ok(a), Ok(b)) = (
            parse_key_file(good.as_bytes()),
            parse_key_file(flipped.as_bytes()),
        ) else {
            panic!("both parse");
        };
        assert_ne!(DestKey::from_bytes(a).kid(), DestKey::from_bytes(b).kid());
    }

    proptest! {
        #[test]
        fn any_non_zero_key_round_trips(key in proptest::array::uniform32(any::<u8>())) {
            prop_assume!(key.iter().any(|&byte| byte != 0));
            let text = render_key_file(&key);
            prop_assert_eq!(text.len(), KEY_FILE_LEN);
            prop_assert_eq!(parse_key_file(&text), Ok(key));
        }

        #[test]
        fn the_parser_never_panics_and_accepts_only_what_the_writer_writes(
            bytes in proptest::collection::vec(any::<u8>(), 0..160)
        ) {
            if let Ok(key) = parse_key_file(&bytes) {
                prop_assert_eq!(render_key_file(&key), bytes);
            }
        }
    }

    // -- loading and creating ------------------------------------------------

    use std::sync::Mutex;

    /// A store that answers from a script and records what it was asked.
    struct ScriptedFs {
        reads: Mutex<Vec<Result<Option<Vec<u8>>, StoreError>>>,
        creates: Mutex<Vec<Result<(), StoreError>>>,
        created: Mutex<Vec<Vec<u8>>>,
    }

    impl ScriptedFs {
        fn new(
            reads: Vec<Result<Option<Vec<u8>>, StoreError>>,
            creates: Vec<Result<(), StoreError>>,
        ) -> Self {
            Self {
                reads: Mutex::new(reads),
                creates: Mutex::new(creates),
                created: Mutex::new(Vec::new()),
            }
        }
    }

    impl LedgerFs for ScriptedFs {
        fn open_store(&self) -> Result<Box<dyn super::super::fs::LedgerStore>, StoreError> {
            Err(StoreError::Unsupported)
        }
        fn is_private_store(&self) -> bool {
            true
        }
        fn read_key_file(&self) -> Result<Option<Vec<u8>>, StoreError> {
            let mut script = self.reads.lock().expect("lock");
            if script.is_empty() {
                panic!("an unscripted read");
            }
            script.remove(0)
        }
        fn create_key_file(&self, bytes: &[u8]) -> Result<(), StoreError> {
            self.created.lock().expect("lock").push(bytes.to_vec());
            let mut script = self.creates.lock().expect("lock");
            if script.is_empty() {
                panic!("an unscripted create");
            }
            script.remove(0)
        }
    }

    fn fixed_fill(byte: u8) -> impl FnMut(&mut [u8]) -> bool {
        move |buffer: &mut [u8]| {
            buffer.fill(byte);
            true
        }
    }

    #[test]
    fn a_create_that_lost_a_race_reads_the_winners_key() {
        let winner = render_key_file(&[7_u8; KEY_LEN]);
        let fs = ScriptedFs::new(
            vec![Ok(None), Ok(Some(winner))],
            vec![Err(StoreError::Io("AUDIT_ALREADY_EXISTS"))],
        );
        let key = load_or_create(&fs, &mut fixed_fill(9)).expect("the winner's key");
        assert_eq!(key.kid(), DestKey::from_bytes([7; KEY_LEN]).kid());
        // The loser's own bytes were offered once and are not what is used.
        assert_eq!(
            fs.created.lock().expect("lock").as_slice(),
            [render_key_file(&[9_u8; KEY_LEN])]
        );
    }

    #[test]
    fn a_name_that_exists_and_cannot_be_read_is_an_error_not_a_loop() {
        let fs = ScriptedFs::new(
            vec![Ok(None), Ok(None)],
            vec![
                Err(StoreError::Io("AUDIT_ALREADY_EXISTS")),
                Err(StoreError::Io("AUDIT_ALREADY_EXISTS")),
            ],
        );
        assert_eq!(
            load_or_create(&fs, &mut fixed_fill(9)).err(),
            Some(KeyError::Store(StoreError::Io("AUDIT_ALREADY_EXISTS")))
        );
    }

    #[test]
    fn a_failing_create_is_the_stores_error_and_is_not_retried() {
        let fs = ScriptedFs::new(vec![Ok(None)], vec![Err(StoreError::Io("AUDIT_DISK_FULL"))]);
        assert_eq!(
            load_or_create(&fs, &mut fixed_fill(9)).err(),
            Some(KeyError::Store(StoreError::Io("AUDIT_DISK_FULL")))
        );
        let fs = ScriptedFs::new(
            vec![Err(StoreError::FileUnsafe(
                super::super::fs::UnsafeReason::HardLinked,
            ))],
            vec![],
        );
        assert_eq!(
            load_or_create(&fs, &mut fixed_fill(9)).err(),
            Some(KeyError::Store(StoreError::FileUnsafe(
                super::super::fs::UnsafeReason::HardLinked
            )))
        );
    }

    #[test]
    fn a_failing_random_source_creates_nothing() {
        let fs = ScriptedFs::new(vec![Ok(None)], vec![]);
        assert_eq!(
            load_or_create(&fs, &mut |_buffer: &mut [u8]| false).err(),
            Some(KeyError::Random)
        );
        assert!(fs.created.lock().expect("lock").is_empty());
        // A source that answers with zeros is as bad as one that fails.
        let fs = ScriptedFs::new(vec![Ok(None)], vec![]);
        assert_eq!(
            load_or_create(&fs, &mut fixed_fill(0)).err(),
            Some(KeyError::Random)
        );
        assert!(fs.created.lock().expect("lock").is_empty());
    }

    #[test]
    fn plain_mode_touches_no_file_and_asks_for_no_randomness() {
        // No read and no create are scripted: any call panics.
        let fs = ScriptedFs::new(vec![], vec![]);
        let sealer = open_sealer(
            &fs,
            DestinationLogging::Plain,
            &mut |_buffer: &mut [u8]| panic!("plain mode asked for random bytes"),
        )
        .expect("plain");
        assert!(matches!(sealer, DestSealer::Plain));
    }

    #[test]
    fn hashed_mode_returns_a_hashed_sealer_with_the_keys_id() {
        let stored = render_key_file(&[3_u8; KEY_LEN]);
        let fs = ScriptedFs::new(vec![Ok(Some(stored))], vec![]);
        let sealer = open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1)).expect("key");
        assert_eq!(sealer.mode(), DestinationLogging::Hashed);
        assert_eq!(sealer.kid(), Some(DestKey::from_bytes([3; KEY_LEN]).kid()));
    }

    #[test]
    fn every_key_error_makes_the_ingress_unavailable_with_one_code_and_a_hint() {
        use crate::ingress::types::contains_forbidden_word;
        let root = std::path::Path::new("/state");
        for error in [
            KeyError::Corrupt,
            KeyError::Random,
            KeyError::Store(StoreError::Io("AUDIT_IO")),
            KeyError::Store(StoreError::RootUnsafe(
                super::super::fs::UnsafeReason::GroupOrOtherWritable,
            )),
        ] {
            assert_eq!(
                error.unavailable_code(),
                UnavailableCode::AuditKeyUnavailable
            );
            let hint = error.operator_hint(root);
            assert!(!hint.is_empty());
            assert_eq!(contains_forbidden_word(&hint), None, "{hint}");
        }
        let corrupt = KeyError::Corrupt.operator_hint(root);
        assert!(
            corrupt.contains("/state/ingress-dest.key") && corrupt.contains("remove it"),
            "{corrupt}"
        );
        assert!(KeyError::Store(StoreError::RootUnsafe(
            super::super::fs::UnsafeReason::GroupOrOtherWritable
        ))
        .operator_hint(root)
        .contains("chmod go-w /state"));
    }

    #[test]
    fn the_operating_system_supplies_random_bytes_and_not_the_same_ones_twice() {
        let (mut a, mut b) = ([0_u8; KEY_LEN], [0_u8; KEY_LEN]);
        assert!(os_random(&mut a) && os_random(&mut b));
        assert_ne!(a, b);
        assert_ne!(a, [0_u8; KEY_LEN]);
    }

    // -- against a real directory (Unix) -------------------------------------

    #[cfg(unix)]
    mod on_disk {
        use super::*;
        use crate::ingress::audit::fs::{UnsafeReason, KEY_FILE_NAME, LEDGER_DIR};
        use crate::ingress::audit::fs_unix::UnixLedgerFs;
        use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

        fn root() -> tempfile::TempDir {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            dir
        }

        fn fs_at(dir: &tempfile::TempDir) -> UnixLedgerFs {
            UnixLedgerFs::new(dir.path().to_path_buf())
        }

        fn mode_of(path: &std::path::Path) -> u32 {
            std::fs::symlink_metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777
        }

        #[test]
        fn dest_key_file_is_private_and_outside_the_ledger_dir() {
            let dir = root();
            let fs = fs_at(&dir);
            let store = fs.open_store().expect("store");
            let key = load_or_create(&fs, &mut fixed_fill(0x42)).expect("creates");
            let path = dir.path().join(KEY_FILE_NAME);
            assert_eq!(mode_of(&path), 0o600);
            assert_eq!(std::fs::metadata(&path).expect("metadata").nlink(), 1);
            assert_eq!(
                std::fs::read(&path).expect("read"),
                render_key_file(&[0x42; KEY_LEN])
            );
            assert_eq!(key.kid(), DestKey::from_bytes([0x42; KEY_LEN]).kid());
            // A sibling of the ledger directory, not a file in it.
            assert!(!dir.path().join(LEDGER_DIR).join(KEY_FILE_NAME).exists());
            let listing = store.segments().expect("lists");
            assert!(listing.first_seqs.is_empty());
            assert_eq!(listing.ignored, 0, "the key is not in the ledger directory");
        }

        #[test]
        fn an_existing_key_is_read_not_replaced() {
            let dir = root();
            let fs = fs_at(&dir);
            let first = load_or_create(&fs, &mut fixed_fill(0x42)).expect("creates");
            let second = load_or_create(&fs, &mut |_buffer: &mut [u8]| {
                panic!("a key that exists is not generated again")
            })
            .expect("reads");
            assert_eq!(first.kid(), second.kid());
        }

        #[test]
        fn deleting_the_key_changes_the_kid() {
            let dir = root();
            let fs = fs_at(&dir);
            let first = load_or_create(&fs, &mut fixed_fill(0x42)).expect("creates");
            std::fs::remove_file(dir.path().join(KEY_FILE_NAME)).expect("forget");
            let second = load_or_create(&fs, &mut fixed_fill(0x43)).expect("creates again");
            assert_ne!(first.kid(), second.kid());
            // And the old token cannot be recomputed from the new key.
            assert_ne!(
                first.token(HostKind::Name, "example.com"),
                second.token(HostKind::Name, "example.com")
            );
        }

        #[test]
        fn corrupt_key_file_makes_ingress_unavailable_in_hashed_mode() {
            let dir = root();
            let fs = fs_at(&dir);
            let path = dir.path().join(KEY_FILE_NAME);
            for content in [&b""[..], b"not a key\n", &[b'0'; 64], &[b'a'; 200]] {
                std::fs::write(&path, content).expect("write");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                    .expect("chmod");
                let error = open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1))
                    .expect_err("refused");
                assert_eq!(error, KeyError::Corrupt, "{content:?}");
                assert_eq!(
                    error.unavailable_code(),
                    UnavailableCode::AuditKeyUnavailable
                );
                assert_eq!(
                    std::fs::read(&path).expect("read"),
                    content,
                    "never repaired"
                );
            }
            // Plain mode does not look at the file at all.
            assert!(open_sealer(&fs, DestinationLogging::Plain, &mut fixed_fill(1)).is_ok());
        }

        #[test]
        fn hashed_without_key_is_unavailable_never_plain() {
            // Every way the key can fail leaves `open_sealer` with an error, never
            // with `DestSealer::Plain`.
            let dir = root();
            let fs = fs_at(&dir);
            let path = dir.path().join(KEY_FILE_NAME);
            let target = dir.path().join("elsewhere");
            std::fs::write(&target, render_key_file(&[5; KEY_LEN])).expect("write");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
                .expect("chmod");
            symlink(&target, &path).expect("symlink");
            let linked = open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1));
            assert_eq!(
                linked.err(),
                Some(KeyError::Store(StoreError::FileUnsafe(
                    UnsafeReason::NotRegularFile
                )))
            );
            std::fs::remove_file(&path).expect("remove");

            // Group-readable.
            std::fs::write(&path, render_key_file(&[5; KEY_LEN])).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("chmod");
            assert_eq!(
                open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1)).err(),
                Some(KeyError::Store(StoreError::FileUnsafe(
                    UnsafeReason::GroupOrOtherAccess
                )))
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");

            // Hard-linked.
            std::fs::hard_link(&path, dir.path().join("planted")).expect("link");
            assert_eq!(
                open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1)).err(),
                Some(KeyError::Store(StoreError::FileUnsafe(
                    UnsafeReason::HardLinked
                )))
            );
            std::fs::remove_file(dir.path().join("planted")).expect("unlink");

            // A directory where the key should be.
            std::fs::remove_file(&path).expect("remove");
            std::fs::create_dir(&path).expect("mkdir");
            assert!(open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1)).is_err());
            std::fs::remove_dir(&path).expect("rmdir");

            // A state root others can write to: no key is created in it.
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775))
                .expect("chmod");
            assert_eq!(
                open_sealer(&fs, DestinationLogging::Hashed, &mut fixed_fill(1)).err(),
                Some(KeyError::Store(StoreError::RootUnsafe(
                    UnsafeReason::GroupOrOtherWritable
                )))
            );
            assert!(!path.exists(), "nothing was created");
        }

        #[test]
        fn a_symlink_in_the_way_of_a_new_key_is_never_written_through() {
            let dir = root();
            let fs = fs_at(&dir);
            let victim = dir.path().join("victim");
            std::fs::write(&victim, b"keep me").expect("write");
            // A dangling link: the name does not resolve, so a naive create follows it.
            symlink(
                dir.path().join("does-not-exist"),
                dir.path().join(KEY_FILE_NAME),
            )
            .expect("symlink");
            assert!(load_or_create(&fs, &mut fixed_fill(1)).is_err());
            assert!(!dir.path().join("does-not-exist").exists());
            assert_eq!(std::fs::read(&victim).expect("read"), b"keep me");
        }

        #[test]
        fn a_longer_file_is_cut_at_the_read_bound_and_refused() {
            let dir = root();
            let fs = fs_at(&dir);
            let path = dir.path().join(KEY_FILE_NAME);
            std::fs::write(&path, vec![b'a'; 1_000_000]).expect("write");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
            let read = fs.read_key_file().expect("reads").expect("present");
            assert_eq!(
                read.len(),
                66,
                "one byte more than a key file, not the megabyte"
            );
            assert_eq!(
                load_or_create(&fs, &mut fixed_fill(1)).err(),
                Some(KeyError::Corrupt)
            );
        }

        #[test]
        fn a_missing_key_is_none_and_a_failed_create_leaves_no_file() {
            let dir = root();
            let fs = fs_at(&dir);
            assert_eq!(fs.read_key_file(), Ok(None));
            fs.create_key_file(b"first\n").expect("creates");
            assert_eq!(
                fs.create_key_file(b"second\n").err(),
                Some(StoreError::Io("AUDIT_ALREADY_EXISTS"))
            );
            assert_eq!(
                std::fs::read(dir.path().join(KEY_FILE_NAME)).expect("read"),
                b"first\n",
                "an existing key is untouched"
            );
        }
    }
}
