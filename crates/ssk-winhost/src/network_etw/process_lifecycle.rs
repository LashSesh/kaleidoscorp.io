//! Minimal classic process-event decoding. Never queries names, command lines,
//! SIDs or a currently running process to identify a historical event.
use super::{DecodeError, PropertySource};

#[cfg(windows)]
pub(super) const PROVIDER_ID: u128 = 0x3d6fa8d0_fe05_11d0_9dda_00c04fd7ba7c;
pub(super) const MAX_PAYLOAD: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    Start,
    End,
    RundownStart,
    RundownEnd,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Event {
    pub pid: u32,
    // Kernel object address: a within-file hint, NOT a permanent identity.
    pub key: u64,
    pub kind: Kind,
}

pub(super) struct Schema {
    kind: Kind,
    pointer_bytes: usize,
}

pub(super) fn schema(
    version: u8,
    opcode: u8,
    flags: u16,
    size: usize,
    ticks: i64,
) -> Result<Schema, DecodeError> {
    if !(2..=4).contains(&version) {
        return Err(DecodeError::UnsupportedVersion);
    }
    let kind = match opcode {
        1 => Kind::Start,
        2 => Kind::End,
        3 => Kind::RundownStart,
        4 => Kind::RundownEnd,
        _ => return Err(DecodeError::UnsupportedOpcode),
    };
    const ALLOWED: u16 = 0x100 | 0x20 | 0x40 | 0x10 | 0x200;
    if flags & 0x100 == 0 || flags & !ALLOWED != 0 {
        return Err(DecodeError::UnsupportedHeader);
    }
    let pointer_bytes = match flags & 0x60 {
        0x20 => 4,
        0x40 => 8,
        _ => return Err(DecodeError::UnsupportedHeader),
    };
    if size < pointer_bytes + 4 || size > MAX_PAYLOAD {
        return Err(DecodeError::PayloadSize);
    }
    if ticks < 0 {
        return Err(DecodeError::TimestampRange);
    }
    Ok(Schema {
        kind,
        pointer_bytes,
    })
}

pub(super) fn decode(
    schema: Schema,
    source: &mut impl PropertySource,
) -> Result<Event, DecodeError> {
    let pid = u32::from_le_bytes(source.property("ProcessId")?);
    let key = if schema.pointer_bytes == 4 {
        u64::from(u32::from_le_bytes(source.property("UniqueProcessKey")?))
    } else {
        u64::from_le_bytes(source.property("UniqueProcessKey")?)
    };
    // Idle PID 0 legitimately appears in rundown. It can never match a network
    // payload PID (the network decoder rejects zero); track it separately.
    if pid == u32::MAX {
        return Err(DecodeError::MissingPayloadPid);
    }
    if pid != 0 && key == 0 {
        return Err(DecodeError::MissingProcessKey);
    }
    Ok(Event {
        pid,
        key,
        kind: schema.kind,
    })
}

#[cfg(test)]
mod tests;
