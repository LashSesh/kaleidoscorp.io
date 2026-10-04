use serde::{Deserialize, Serialize};
use std::{fmt, fmt::Write, net::IpAddr};
use zeroize::Zeroizing;

pub const MAX_PROFILE_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProfileError {
    #[error("profile exceeds the size limit")]
    TooLarge,
    #[error("malformed or unsupported profile document")]
    Document,
    #[error("invalid profile identifier")]
    Id,
    #[error("invalid VPN endpoint or server name")]
    Endpoint,
    #[error("unsupported or malformed inline key material")]
    Material,
}

/// A logical name, never a path or an OpenVPN argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileId(String);

impl ProfileId {
    pub fn new(id: &str) -> Result<Self, ProfileError> {
        if id.is_empty()
            || id.len() > 64
            || !id.as_bytes()[0].is_ascii_lowercase()
            || !id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
        {
            return Err(ProfileError::Id);
        }
        Ok(Self(id.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Transport {
    Udp,
    Tcp,
}

/// No raw directives, external files, provider options, scripts or plugins.
/// Owned secret-field buffers are wiped on drop. Callers still own input bytes;
/// this does not promise that serde/OS internals never copied those bytes.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    id: String,
    remote_ip: IpAddr,
    remote_port: u16,
    transport: Transport,
    server_name: String,
    ca_pem: Zeroizing<String>,
    certificate_pem: Zeroizing<String>,
    private_key_pem: Zeroizing<String>,
    tls_crypt_key: Zeroizing<String>,
}

/// Validated, bounded input for a broker-generated configuration. Validation
/// proves the directive boundary, NOT certificate validity or key strength.
/// OpenVPN still has to verify the chain, expiry, server identity and key pair.
pub struct Profile(Document);

impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("id", &self.0.id)
            .field("material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl Profile {
    /// JSON v1 only. Duplicate/unknown fields and trailing documents fail.
    /// Errors deliberately contain none of the submitted document.
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge);
        }
        let document: Document =
            serde_json::from_slice(bytes).map_err(|_| ProfileError::Document)?;
        if document.version != 1 {
            return Err(ProfileError::Document);
        }
        ProfileId::new(&document.id)?;
        // IPv4-mapped IPv6 must not bypass the excluded-address policy.
        let endpoint = document.remote_ip.to_canonical();
        if document.remote_port == 0
            || endpoint.is_unspecified()
            || endpoint.is_multicast()
            || endpoint.is_loopback()
            || endpoint == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            || document.server_name.is_empty()
            || document.server_name.len() > 253
            || !document.server_name.as_bytes()[0].is_ascii_alphanumeric()
            || !document
                .server_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(ProfileError::Endpoint);
        }
        if !pem(&document.ca_pem, "CERTIFICATE")
            || !pem(&document.certificate_pem, "CERTIFICATE")
            || !["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"]
                .iter()
                .any(|label| pem(&document.private_key_pem, label))
            || !static_key(&document.tls_crypt_key)
        {
            return Err(ProfileError::Material);
        }
        Ok(Self(document))
    }

    pub fn id(&self) -> ProfileId {
        ProfileId(self.0.id.clone())
    }

    pub fn to_document(&self) -> Result<Zeroizing<Vec<u8>>, ProfileError> {
        // Reserve above the maximum accepted input; no growth copies secrets.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROFILE_BYTES));
        serde_json::to_writer(&mut *bytes, &self.0).map_err(|_| ProfileError::Document)?;
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge);
        }
        Ok(bytes)
    }

    /// Base config only: no management endpoint, secret file or launch policy.
    /// The host must append its own fixed management settings in protected
    /// storage. This cannot authorize egress and must never be run directly
    /// from caller-supplied paths. Pushed routes/DNS and external programs are
    /// disabled; interface configuration still requires host policy/VM testing.
    pub fn render_base_config(&self) -> Zeroizing<String> {
        let d = &self.0;
        let mut out = Zeroizing::new(String::with_capacity(MAX_PROFILE_BYTES));
        out.push_str("client\ndev tun\nnobind\nauth-nocache\nscript-security 0\nroute-nopull\nroute-noexec\nremote-cert-tls server\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\nallow-compression no\nverb 3\n");
        let proto = match (&d.transport, d.remote_ip) {
            (Transport::Udp, IpAddr::V4(_)) => "udp4",
            (Transport::Udp, IpAddr::V6(_)) => "udp6",
            (Transport::Tcp, IpAddr::V4(_)) => "tcp4-client",
            (Transport::Tcp, IpAddr::V6(_)) => "tcp6-client",
        };
        // Writing into a String is infallible.
        let _ = writeln!(
            out,
            "proto {proto}\nremote {} {}\nverify-x509-name {} name",
            d.remote_ip, d.remote_port, d.server_name
        );
        for (tag, value) in [
            ("ca", &d.ca_pem),
            ("cert", &d.certificate_pem),
            ("key", &d.private_key_pem),
            ("tls-crypt", &d.tls_crypt_key),
        ] {
            let _ = writeln!(out, "<{tag}>");
            out.push_str(value);
            let _ = writeln!(out, "</{tag}>");
        }
        out
    }
}

fn pem(value: &str, label: &str) -> bool {
    if value.len() > 24 * 1024 || !value.ends_with('\n') {
        return false;
    }
    let header = format!("-----BEGIN {label}-----");
    let footer = format!("-----END {label}-----");
    let mut lines = value.lines();
    if lines.next() != Some(header.as_str()) {
        return false;
    }
    let mut count = 0;
    while let Some(line) = lines.next() {
        if line == footer {
            return count > 0 && lines.next().is_none();
        }
        if line.is_empty()
            || line.len() > 64
            || !line
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b))
        {
            return false;
        }
        count += 1;
    }
    false
}

fn static_key(value: &str) -> bool {
    let mut lines = value.lines();
    if !value.ends_with('\n') || lines.next() != Some("-----BEGIN OpenVPN Static key V1-----") {
        return false;
    }
    for _ in 0..16 {
        if !lines
            .next()
            .is_some_and(|l| l.len() == 32 && l.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return false;
        }
    }
    lines.next() == Some("-----END OpenVPN Static key V1-----") && lines.next().is_none()
}
