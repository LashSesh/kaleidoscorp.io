use std::net::{Ipv4Addr, Ipv6Addr};
use zeroize::{Zeroize, Zeroizing};

/// Limit applies before UTF-8 decoding, including for ignored log messages.
pub const MAX_LINE_BYTES: usize = 8192;
const PROMPT: &[u8] = b"ENTER PASSWORD:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("OpenVPN management message exceeds the size limit")]
    TooLong,
    #[error("OpenVPN management message has invalid encoding or control bytes")]
    Encoding,
    #[error("malformed OpenVPN management message")]
    Malformed,
    #[error("unsupported OpenVPN management message")]
    Unsupported,
    #[error("OpenVPN management stream ended inside a message")]
    Truncated,
    #[error("OpenVPN management decoder is closed after a previous error")]
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Auth,
    PrivateKey,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnState {
    Initial,
    Connecting,
    Resolving,
    TcpConnecting,
    Waiting,
    Authenticating,
    AuthPending,
    GettingConfig,
    AssigningIp,
    AddingRoutes,
    Connected,
    Reconnecting,
    Exiting,
}

/// Peer-provided free text (including errors, logs and challenges) is discarded.
/// Debug output of an event can never echo those fields or credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    PasswordPrompt,
    Authenticated,
    AuthenticationRejected,
    Pid(u32),
    StateSubscribed,
    HoldReleased,
    TerminationAcknowledged,
    CommandRejected,
    Hold { retry_after_secs: u32 },
    State(VpnState),
    CredentialsRequired(CredentialKind),
    VpnAuthenticationFailed,
    Fatal,
    Ignored,
}

/// Incremental decoder. Call push once per byte to avoid an unbounded event
/// queue; one read may contain many lines or just part of the no-newline prompt.
pub struct Decoder {
    line: Zeroizing<Vec<u8>>,
    closed: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            line: Zeroizing::new(Vec::with_capacity(MAX_LINE_BYTES)),
            closed: false,
        }
    }
}

impl Decoder {
    pub fn push(&mut self, byte: u8) -> Result<Option<Event>, ProtocolError> {
        if self.closed {
            return Err(ProtocolError::Closed);
        }
        let result = self.push_inner(byte);
        if result.is_err() {
            self.closed = true;
            self.line.zeroize();
        }
        result
    }

    fn push_inner(&mut self, byte: u8) -> Result<Option<Event>, ProtocolError> {
        if byte == b'\n' {
            let bytes = self.line.strip_suffix(b"\r").unwrap_or(&self.line);
            let text = std::str::from_utf8(bytes).map_err(|_| ProtocolError::Encoding)?;
            let event = if text.is_empty() {
                Event::Ignored
            } else {
                parse_line(text)?
            };
            self.line.zeroize();
            return Ok(Some(event));
        }
        if byte < 0x20 && byte != b'\r' || byte == 0x7f {
            return Err(ProtocolError::Encoding);
        }
        if self.line.len() == MAX_LINE_BYTES {
            return Err(ProtocolError::TooLong);
        }
        if self.line.last() == Some(&b'\r') {
            return Err(ProtocolError::Encoding);
        }
        self.line.push(byte);
        // OpenVPN emits this prompt without CRLF (manage.c:man_prompt).
        if self.line.as_slice() == PROMPT {
            self.line.zeroize();
            return Ok(Some(Event::PasswordPrompt));
        }
        Ok(None)
    }

    pub fn finish(&mut self) -> Result<(), ProtocolError> {
        let result = if self.closed {
            Err(ProtocolError::Closed)
        } else if self.line.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Truncated)
        };
        self.closed = true;
        self.line.zeroize();
        result
    }
}

fn parse_line(line: &str) -> Result<Event, ProtocolError> {
    match line {
        "SUCCESS: password is correct" => return Ok(Event::Authenticated),
        "ERROR: bad password" => return Ok(Event::AuthenticationRejected),
        "SUCCESS: real-time state notification set to ON" => return Ok(Event::StateSubscribed),
        "SUCCESS: hold release succeeded" => return Ok(Event::HoldReleased),
        "SUCCESS: signal SIGTERM thrown" => return Ok(Event::TerminationAcknowledged),
        _ => {}
    }
    if let Some(pid) = line.strip_prefix("SUCCESS: pid=") {
        return Ok(Event::Pid(number(pid)?));
    }
    if line.starts_with("ERROR:") {
        return Ok(Event::CommandRejected);
    }
    if let Some(state) = line.strip_prefix(">STATE:") {
        return parse_state(state).map(Event::State);
    }
    if let Some(hold) = line.strip_prefix(">HOLD:Waiting for hold release") {
        let retry_after_secs = if hold.is_empty() {
            0
        } else {
            number(hold.strip_prefix(':').ok_or(ProtocolError::Malformed)?)?
        };
        if retry_after_secs > 300 {
            return Err(ProtocolError::Malformed);
        }
        return Ok(Event::Hold { retry_after_secs });
    }
    if let Some(password) = line.strip_prefix(">PASSWORD:") {
        if password.starts_with("Verification Failed:") {
            return Ok(Event::VpnAuthenticationFailed);
        }
        let kind = if password == "Need 'Auth' username/password" {
            CredentialKind::Auth
        } else if password == "Need 'Private Key' password" {
            CredentialKind::PrivateKey
        } else {
            CredentialKind::Other
        };
        return Ok(Event::CredentialsRequired(kind));
    }
    if line.starts_with(">FATAL:") {
        return Ok(Event::Fatal);
    }
    // No raw text retained. Unknown notification types are not ignored: some
    // request a security-sensitive decision (NEED-OK, REMOTE, PK_SIGN, ...).
    for prefix in [">INFO:", ">LOG:", ">ECHO:", ">BYTECOUNT:"] {
        if line.starts_with(prefix) {
            return Ok(Event::Ignored);
        }
    }
    Err(ProtocolError::Unsupported)
}

fn number<T: std::str::FromStr>(text: &str) -> Result<T, ProtocolError> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProtocolError::Malformed);
    }
    text.parse().map_err(|_| ProtocolError::Malformed)
}

fn parse_state(text: &str) -> Result<VpnState, ProtocolError> {
    // v2.x state rows contain timestamp, state, detail, local v4, remote IP,
    // remote port, local socket IP, local port and optional local tunnel v6.
    // The fixed array bounds metadata parsing without allocating a Vec.
    let mut fields = [""; 9];
    let mut count = 0;
    for field in text.split(',') {
        if count == fields.len() {
            return Err(ProtocolError::Malformed);
        }
        fields[count] = field;
        count += 1;
    }
    if count < 4 {
        return Err(ProtocolError::Malformed);
    }
    let _: u64 = number(fields[0])?;
    let state = match fields[1] {
        "INITIAL" => VpnState::Initial,
        "CONNECTING" => VpnState::Connecting,
        "RESOLVE" => VpnState::Resolving,
        "TCP_CONNECT" => VpnState::TcpConnecting,
        "WAIT" => VpnState::Waiting,
        "AUTH" => VpnState::Authenticating,
        "AUTH_PENDING" => VpnState::AuthPending,
        "GET_CONFIG" => VpnState::GettingConfig,
        "ASSIGN_IP" => VpnState::AssigningIp,
        "ADD_ROUTES" => VpnState::AddingRoutes,
        "CONNECTED" => VpnState::Connected,
        "RECONNECTING" => VpnState::Reconnecting,
        "EXITING" => VpnState::Exiting,
        _ => return Err(ProtocolError::Unsupported),
    };
    if !fields[3].is_empty() {
        fields[3]
            .parse::<Ipv4Addr>()
            .map_err(|_| ProtocolError::Malformed)?;
    }
    for index in [4, 6] {
        if !fields[index].is_empty() {
            fields[index]
                .parse::<std::net::IpAddr>()
                .map_err(|_| ProtocolError::Malformed)?;
        }
    }
    for index in [5, 7] {
        if !fields[index].is_empty() {
            let _: u16 = number(fields[index])?;
        }
    }
    if !fields[8].is_empty() {
        fields[8]
            .parse::<Ipv6Addr>()
            .map_err(|_| ProtocolError::Malformed)?;
    }
    if state == VpnState::Connected
        && (fields[2] != "SUCCESS" || (fields[3].is_empty() && fields[8].is_empty()))
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(state)
}
