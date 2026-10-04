use super::*;
struct Fields {
    pid: u32,
    key: u64,
    queries: Vec<&'static str>,
}
impl PropertySource for Fields {
    fn property<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N], DecodeError> {
        self.queries.push(name);
        let bytes = match name {
            "ProcessId" => self.pid.to_le_bytes().to_vec(),
            "UniqueProcessKey" if N == 4 => (self.key as u32).to_le_bytes().to_vec(),
            "UniqueProcessKey" => self.key.to_le_bytes().to_vec(),
            _ => panic!("unexpected private-data query: {name}"),
        };
        bytes
            .try_into()
            .map_err(|_| DecodeError::PropertySize { field: name })
    }
}

#[test]
fn versions_and_pointer_widths_query_only_two_identity_hints() {
    for version in 2..=4 {
        for flags in [0x120, 0x140] {
            for opcode in 1..=4 {
                let mut fields = Fields {
                    pid: 42,
                    key: 123,
                    queries: Vec::new(),
                };
                let event = decode(
                    schema(version, opcode, flags, 128, 10).unwrap(),
                    &mut fields,
                )
                .unwrap();
                assert_eq!(event.pid, 42);
                assert_eq!(event.key, 123);
                assert_eq!(fields.queries, ["ProcessId", "UniqueProcessKey"]);
                assert_eq!(
                    event.kind,
                    [Kind::Start, Kind::End, Kind::RundownStart, Kind::RundownEnd]
                        [opcode as usize - 1]
                );
            }
        }
    }
}

#[test]
fn unsupported_schemas_and_auxiliary_events_cannot_become_lifecycles() {
    for version in [0, 1, 5, 255] {
        assert!(matches!(
            schema(version, 1, 0x140, 128, 0),
            Err(DecodeError::UnsupportedVersion)
        ));
    }
    for opcode in [0, 11, 32, 33, 39, 255] {
        assert!(matches!(
            schema(4, opcode, 0x140, 128, 0),
            Err(DecodeError::UnsupportedOpcode)
        ));
    }
    for flags in [0, 0x100, 0x160, 0x141, 0x142, 0x144, 0x148, 0x1c0, 0x540] {
        assert!(matches!(
            schema(4, 1, flags, 128, 0),
            Err(DecodeError::UnsupportedHeader)
        ));
    }
}

#[test]
fn malformed_lengths_and_negative_ticks_are_rejected_before_properties() {
    for len in [0, 7, 11, MAX_PAYLOAD + 1] {
        assert!(matches!(
            schema(4, 1, 0x140, len, 0),
            Err(DecodeError::PayloadSize)
        ));
    }
    assert!(matches!(
        schema(4, 1, 0x140, 128, -1),
        Err(DecodeError::TimestampRange)
    ));
}

#[test]
fn missing_keys_and_invalid_pids_fail_but_idle_rundown_is_recognized() {
    for (pid, key, valid) in [
        (42, 0, false),
        (u32::MAX, 1, false),
        (0, 0, true),
        (4, 7, true),
    ] {
        let mut fields = Fields {
            pid,
            key,
            queries: Vec::new(),
        };
        assert_eq!(
            decode(schema(4, 3, 0x140, 128, 0).unwrap(), &mut fields).is_ok(),
            valid
        );
    }
}

#[test]
fn unavailable_properties_never_fall_back_to_header_or_guessed_offsets() {
    struct Missing;
    impl PropertySource for Missing {
        fn property<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N], DecodeError> {
            Err(DecodeError::PropertyQuery {
                field: name,
                code: 1168,
            })
        }
    }
    assert!(matches!(
        decode(schema(4, 1, 0x140, 128, 0).unwrap(), &mut Missing),
        Err(DecodeError::PropertyQuery {
            field: "ProcessId",
            code: 1168
        })
    ));
}
