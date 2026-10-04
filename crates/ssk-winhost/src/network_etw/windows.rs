use super::*;
use std::mem::{size_of, zeroed};
use std::sync::Mutex;
use windows_sys::{
    core::GUID,
    Win32::System::Diagnostics::Etw::{
        TdhGetProperty, TdhGetPropertySize, EVENT_HEADER, EVENT_RECORD, PROPERTY_DATA_DESCRIPTOR,
        TDH_CONTEXT, TDH_CONTEXT_POINTERSIZE,
    },
};

struct NativeProperties<'a> {
    record: &'a EVENT_RECORD,
}

// Mixed-width classic TDH lookups produced inconsistent property sizes under
// concurrent decoding locally, even with an explicit POINTERSIZE context.
// All entry points serialize an entire native record decode in this process.
// The ETL worker deadline still bounds a stuck native call or lock holder.
static NATIVE_DECODER: Mutex<()> = Mutex::new(());

// The ETL reader passes the native callback record without reconstructing its
// descriptor, context or metadata. The schema and payload bounds are checked first.
pub(super) fn decode_record(
    record: &EVENT_RECORD,
    schema: EventSchema,
) -> Result<DecodedEvent, DecodeError> {
    let _guard = NATIVE_DECODER
        .lock()
        .map_err(|_| DecodeError::NativeDecoderState)?;
    decode_properties(schema, &mut NativeProperties { record })
}

pub(super) fn decode_process_record(
    record: &EVENT_RECORD,
    schema: process_lifecycle::Schema,
) -> Result<process_lifecycle::Event, DecodeError> {
    let _guard = NATIVE_DECODER
        .lock()
        .map_err(|_| DecodeError::NativeDecoderState)?;
    process_lifecycle::decode(schema, &mut NativeProperties { record })
}

impl PropertySource for NativeProperties<'_> {
    fn property<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N], DecodeError> {
        // Only fixed network/process property names reach TDH.
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let descriptor = PROPERTY_DATA_DESCRIPTOR {
            PropertyName: wide.as_ptr() as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };
        let mut required = 0;
        let context = TDH_CONTEXT {
            ParameterValue: match self.record.EventHeader.Flags & 0x60 {
                0x20 => 4,
                0x40 => 8,
                _ => return Err(DecodeError::UnsupportedHeader),
            },
            ParameterType: TDH_CONTEXT_POINTERSIZE,
            ParameterSize: 0,
        };
        // SAFETY: owned EVENT_RECORD and its payload remain live; descriptor
        // points to a terminated name for this synchronous call. Explicit
        // classic-event pointer width avoids decoder-host/default-size inference.
        let result =
            unsafe { TdhGetPropertySize(self.record, 1, &context, 1, &descriptor, &mut required) };
        if result != 0 {
            return Err(DecodeError::PropertyQuery {
                field: name,
                code: result,
            });
        }
        if required as usize != N {
            return Err(DecodeError::PropertySize { field: name });
        }
        let mut bytes = [0u8; N];
        // SAFETY: same descriptor and record; exactly the validated output size.
        let result = unsafe {
            TdhGetProperty(
                self.record,
                1,
                &context,
                1,
                &descriptor,
                N as u32,
                bytes.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(DecodeError::PropertyQuery {
                field: name,
                code: result,
            });
        }
        Ok(bytes)
    }
}

pub(super) fn decode(input: &RawEvent, schema: EventSchema) -> Result<DecodedEvent, DecodeError> {
    // SAFETY: this POD contains integers/unions/raw pointers, all valid zeroed;
    // no callback or pointer is used before the owned payload is assigned.
    let mut record: EVENT_RECORD = unsafe { zeroed() };
    record.EventHeader.Size = size_of::<EVENT_HEADER>() as u16;
    record.EventHeader.Flags = input.flags;
    record.EventHeader.ProcessId = input.header_pid;
    record.EventHeader.TimeStamp = input.timestamp_ticks as i64;
    record.EventHeader.EventDescriptor.Version = input.version;
    record.EventHeader.EventDescriptor.Opcode = input.opcode;
    record.EventHeader.ProviderId = match schema.transport {
        Transport::Tcp => GUID::from_u128(0x9a280ac0_c8e0_11d1_84e2_00c04fb998a2),
        Transport::Udp => GUID::from_u128(0xbf3a50c5_a9c9_4988_a005_2df0b7c80f80),
    };
    // Own a mutable copy for the C API; bounded to 256 bytes by schema().
    let mut payload = input.payload.clone();
    record.UserDataLength = payload.len() as u16;
    record.UserData = payload.as_mut_ptr().cast();
    decode_record(&record, schema)
}
