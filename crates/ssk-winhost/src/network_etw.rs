//! Diagnostic decoding of classic kernel TCP/UDP version-2 event exports.
//! Windows TDH resolves named properties. The separate capture module supports
//! only private synthetic acceptance; no system capture or policy is enabled.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const TCP_PROVIDER: &str = "9a280ac0-c8e0-11d1-84e2-00c04fb998a2";
pub const UDP_PROVIDER: &str = "bf3a50c5-a9c9-4988-a005-2df0b7c80f80";
pub const MAX_PAYLOAD_BYTES: usize = 256;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawEvent {
    pub provider_guid: String,
    pub version: u8,
    pub opcode: u8,
    /// EVENT_HEADER flags. Classic + exactly one 32/64-bit width required.
    pub flags: u16,
    /// Diagnostic only. Never used as the network activity's process ID.
    pub header_pid: u32,
    pub timestamp_ticks: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Send,
    Receive,
    Connect,
    Accept,
    Disconnect,
    Retransmit,
    Reconnect,
    TcpCopy,
    Failure,
}

#[derive(Debug, Clone, Copy)]
struct EventSchema {
    transport: Transport,
    kind: EventKind,
    address_bytes: usize,
    pointer_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecodeError {
    UnsupportedProvider,
    UnsupportedVersion,
    UnsupportedOpcode,
    UnsupportedHeader,
    PayloadSize,
    TimestampRange,
    UnsupportedPlatform,
    PropertyQuery { field: &'static str, code: u32 },
    PropertySize { field: &'static str },
    MissingPayloadPid,
    MissingProcessKey,
    NativeDecoderState,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ETW decode unavailable: {self:?}")
    }
}
impl std::error::Error for DecodeError {}

/// No IPv6 scope ID is provided by these event schemas. Keep IP/port separate;
/// converting a link-local address into a scoped local endpoint would invent data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEndpoint {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedEvent {
    Network {
        transport: Transport,
        kind: EventKind,
        payload_pid: u32,
        reported_size: u32,
        source: EventEndpoint,
        destination: EventEndpoint,
        /// Opaque correlation hint, not an authenticated flow generation.
        connection_id: u64,
        /// Provider sequence field, not an ETW loss/delivery sequence.
        sequence_number: u32,
    },
    /// This schema has NO PID/endpoints. Do not fall back to header_pid.
    Failure {
        transport: Transport,
        address_family: u16,
        failure_code: u16,
    },
}

fn schema(event: &RawEvent) -> Result<EventSchema, DecodeError> {
    let transport = if event.provider_guid.eq_ignore_ascii_case(TCP_PROVIDER) {
        Transport::Tcp
    } else if event.provider_guid.eq_ignore_ascii_case(UDP_PROVIDER) {
        Transport::Udp
    } else {
        return Err(DecodeError::UnsupportedProvider);
    };
    if event.version != 2 {
        return Err(DecodeError::UnsupportedVersion);
    }
    // Explicit subset: no WPP, string-only, GUID reinterpretation or private
    // session headers. Other metadata flags do not change these properties.
    const ALLOWED: u16 = 0x100 | 0x20 | 0x40 | 0x10 | 0x200;
    if event.flags & 0x100 == 0 || event.flags & !ALLOWED != 0 {
        return Err(DecodeError::UnsupportedHeader);
    }
    let pointer_bytes = match event.flags & 0x60 {
        0x20 => 4,
        0x40 => 8,
        _ => return Err(DecodeError::UnsupportedHeader),
    };
    let (kind, address_bytes) = match (transport, event.opcode) {
        (_, 17) => (EventKind::Failure, 0),
        (_, 10) => (EventKind::Send, 4),
        (_, 11) => (EventKind::Receive, 4),
        (_, 26) => (EventKind::Send, 16),
        (_, 27) => (EventKind::Receive, 16),
        (Transport::Tcp, 12) => (EventKind::Connect, 4),
        (Transport::Tcp, 28) => (EventKind::Connect, 16),
        (Transport::Tcp, 15) => (EventKind::Accept, 4),
        (Transport::Tcp, 31) => (EventKind::Accept, 16),
        (Transport::Tcp, 13) => (EventKind::Disconnect, 4),
        (Transport::Tcp, 29) => (EventKind::Disconnect, 16),
        (Transport::Tcp, 14) => (EventKind::Retransmit, 4),
        (Transport::Tcp, 30) => (EventKind::Retransmit, 16),
        (Transport::Tcp, 16) => (EventKind::Reconnect, 4),
        (Transport::Tcp, 32) => (EventKind::Reconnect, 16),
        (Transport::Tcp, 18) => (EventKind::TcpCopy, 4),
        (Transport::Tcp, 34) => (EventKind::TcpCopy, 16),
        _ => return Err(DecodeError::UnsupportedOpcode),
    };
    if event.payload.is_empty() || event.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(DecodeError::PayloadSize);
    }
    if event.timestamp_ticks > i64::MAX as u64 {
        return Err(DecodeError::TimestampRange);
    }
    Ok(EventSchema {
        transport,
        kind,
        address_bytes,
        pointer_bytes,
    })
}

// Private injectable seam: raw schema selection and native field resolution
// remain separate from semantic interpretation. Names are fixed, never input code.
trait PropertySource {
    fn property<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N], DecodeError>;
}

fn decode_properties(
    schema: EventSchema,
    source: &mut impl PropertySource,
) -> Result<DecodedEvent, DecodeError> {
    if schema.kind == EventKind::Failure {
        return Ok(DecodedEvent::Failure {
            transport: schema.transport,
            address_family: u16::from_le_bytes(source.property("Proto")?),
            failure_code: u16::from_le_bytes(source.property("FailureCode")?),
        });
    }
    let payload_pid = u32::from_le_bytes(source.property("PID")?);
    if payload_pid == 0 || payload_pid == u32::MAX {
        return Err(DecodeError::MissingPayloadPid);
    }
    let reported_size = u32::from_le_bytes(source.property("size")?);
    fn endpoint(
        source: &mut impl PropertySource,
        size: usize,
        address: &'static str,
        port: &'static str,
    ) -> Result<EventEndpoint, DecodeError> {
        let address = if size == 4 {
            IpAddr::from(source.property::<4>(address)?)
        } else {
            IpAddr::from(source.property::<16>(address)?)
        };
        Ok(EventEndpoint {
            address,
            port: u16::from_be_bytes(source.property(port)?),
        })
    }
    let destination = endpoint(source, schema.address_bytes, "daddr", "dport")?;
    let origin = endpoint(source, schema.address_bytes, "saddr", "sport")?;
    let sequence_number = u32::from_le_bytes(source.property("seqnum")?);
    let connection_id = if schema.pointer_bytes == 4 {
        u64::from(u32::from_le_bytes(source.property("connid")?))
    } else {
        u64::from_le_bytes(source.property("connid")?)
    };
    Ok(DecodedEvent::Network {
        transport: schema.transport,
        kind: schema.kind,
        payload_pid,
        reported_size,
        source: origin,
        destination,
        connection_id,
        sequence_number,
    })
}

/// Decode an owned, untrusted export through Windows TDH. Schema resolution is
/// not authentication. No trace session is started and no live event is captured.
pub fn decode(event: &RawEvent) -> Result<DecodedEvent, DecodeError> {
    let selected = schema(event)?;
    #[cfg(windows)]
    {
        windows::decode(event, selected)
    }
    #[cfg(not(windows))]
    {
        struct Unavailable;
        impl PropertySource for Unavailable {
            fn property<const N: usize>(
                &mut self,
                _: &'static str,
            ) -> Result<[u8; N], DecodeError> {
                Err(DecodeError::UnsupportedPlatform)
            }
        }
        decode_properties(selected, &mut Unavailable)
    }
}

#[cfg(windows)]
mod windows;

pub mod capture;
pub mod etl;
pub mod replay;
mod session;
#[cfg(windows)]
mod worker_process;

#[cfg(any(windows, test))]
mod process_lifecycle;

#[cfg(test)]
mod tests;
