use super::*;

pub(super) fn sample() -> RawEvent {
    // Synthetic TCP v4 Send: shared scalar/address prefix and an opaque tail.
    let mut payload = vec![0; 40];
    payload[0..4].copy_from_slice(&4321u32.to_le_bytes());
    payload[4..8].copy_from_slice(&1500u32.to_le_bytes());
    payload[8..12].copy_from_slice(&[192, 0, 2, 5]);
    payload[12..16].copy_from_slice(&[192, 0, 2, 1]);
    payload[16..18].copy_from_slice(&443u16.to_be_bytes());
    payload[18..20].copy_from_slice(&40000u16.to_be_bytes());
    payload[28..32].copy_from_slice(&123u32.to_le_bytes());
    payload[32..40].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    RawEvent {
        provider_guid: TCP_PROVIDER.into(),
        version: 2,
        opcode: 10,
        flags: 0x140,
        header_pid: 999,
        timestamp_ticks: 100,
        payload,
    }
}

#[cfg(windows)]
#[test]
fn native_tdh_resolves_synthetic_tcp_send_using_payload_pid() {
    let decoded = decode(&sample()).unwrap();
    let DecodedEvent::Network {
        payload_pid,
        reported_size,
        source,
        destination,
        connection_id,
        sequence_number,
        ..
    } = decoded
    else {
        panic!("wrong event");
    };
    assert_eq!(payload_pid, 4321);
    assert_eq!(reported_size, 1500);
    assert_eq!(destination.port, 443);
    assert_eq!(source.port, 40000);
    assert_eq!(connection_id, 0x1234_5678_9abc_def0);
    assert_eq!(sequence_number, 123);
}

#[test]
fn unsupported_schemas_and_ambiguous_widths_are_rejected_before_native_calls() {
    let mut event = sample();
    event.provider_guid = "untrusted-provider".into();
    assert!(matches!(
        schema(&event),
        Err(DecodeError::UnsupportedProvider)
    ));
    event = sample();
    event.version = 3;
    assert!(matches!(
        schema(&event),
        Err(DecodeError::UnsupportedVersion)
    ));
    event = sample();
    event.opcode = 255;
    assert!(matches!(
        schema(&event),
        Err(DecodeError::UnsupportedOpcode)
    ));
    for flags in [0, 0x100, 0x160, 0x40, 0x148, 0x144, 0x141, 0x142, 0x8000] {
        event = sample();
        event.flags = flags;
        assert!(
            matches!(schema(&event), Err(DecodeError::UnsupportedHeader)),
            "{flags:#x}"
        );
    }
}

#[test]
fn payload_and_timestamp_budgets_are_explicit() {
    let mut event = sample();
    event.payload.clear();
    assert!(matches!(schema(&event), Err(DecodeError::PayloadSize)));
    event.payload = vec![0; MAX_PAYLOAD_BYTES + 1];
    assert!(matches!(schema(&event), Err(DecodeError::PayloadSize)));
    event = sample();
    event.timestamp_ticks = u64::MAX;
    assert!(matches!(schema(&event), Err(DecodeError::TimestampRange)));
}

#[test]
fn udp_does_not_inherit_tcp_connect_or_retransmit_semantics() {
    let mut event = sample();
    event.provider_guid = UDP_PROVIDER.into();
    for opcode in [12, 13, 14, 15, 16, 18, 28, 29, 30, 31, 32, 34] {
        event.opcode = opcode;
        assert!(matches!(
            schema(&event),
            Err(DecodeError::UnsupportedOpcode)
        ));
    }
}

struct Fields(std::collections::BTreeMap<&'static str, Vec<u8>>);
impl PropertySource for Fields {
    fn property<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N], DecodeError> {
        let bytes = self.0.get(name).ok_or(DecodeError::PropertyQuery {
            field: name,
            code: 1168,
        })?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| DecodeError::PropertySize { field: name })
    }
}

fn fields(pointer_bytes: usize, address_bytes: usize) -> Fields {
    let destination = if address_bytes == 4 {
        vec![192, 0, 2, 5]
    } else {
        "2001:db8::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    };
    let origin = if address_bytes == 4 {
        vec![192, 0, 2, 1]
    } else {
        "2001:db8::1"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets()
            .to_vec()
    };
    Fields(std::collections::BTreeMap::from([
        ("PID", 4321u32.to_le_bytes().to_vec()),
        ("size", u32::MAX.to_le_bytes().to_vec()),
        ("daddr", destination),
        ("saddr", origin),
        ("dport", 443u16.to_be_bytes().to_vec()),
        ("sport", 40000u16.to_be_bytes().to_vec()),
        ("seqnum", 123u32.to_le_bytes().to_vec()),
        ("connid", vec![0xff; pointer_bytes]),
    ]))
}

#[test]
fn property_contract_preserves_ipv4_ipv6_and_both_pointer_widths() {
    for pointer_bytes in [4, 8] {
        for address_bytes in [4, 16] {
            let selected = EventSchema {
                transport: Transport::Tcp,
                kind: EventKind::Receive,
                address_bytes,
                pointer_bytes,
            };
            let DecodedEvent::Network {
                payload_pid,
                reported_size,
                source,
                destination,
                connection_id,
                sequence_number,
                ..
            } = decode_properties(selected, &mut fields(pointer_bytes, address_bytes)).unwrap()
            else {
                panic!("wrong kind");
            };
            assert_eq!(payload_pid, 4321);
            assert_eq!(reported_size, u32::MAX);
            assert_eq!(source.port, 40000);
            assert_eq!(destination.port, 443);
            assert_eq!(source.address.is_ipv6(), address_bytes == 16);
            assert_eq!(
                connection_id,
                if pointer_bytes == 4 {
                    u32::MAX as u64
                } else {
                    u64::MAX
                }
            );
            assert_eq!(sequence_number, 123);
        }
    }
}

#[test]
fn missing_or_wrong_sized_properties_and_missing_pid_never_fall_back() {
    let selected = schema(&sample()).unwrap();
    let mut source = fields(8, 4);
    source.0.remove("PID");
    assert_eq!(
        decode_properties(selected, &mut source),
        Err(DecodeError::PropertyQuery {
            field: "PID",
            code: 1168
        })
    );
    for pid in [0, u32::MAX] {
        let mut source = fields(8, 4);
        source.0.insert("PID", pid.to_le_bytes().to_vec());
        assert_eq!(
            decode_properties(selected, &mut source),
            Err(DecodeError::MissingPayloadPid)
        );
    }
    for name in [
        "PID", "size", "daddr", "saddr", "dport", "sport", "seqnum", "connid",
    ] {
        let mut source = fields(8, 4);
        source.0.insert(name, vec![0; 1]);
        assert_eq!(
            decode_properties(selected, &mut source),
            Err(DecodeError::PropertySize { field: name })
        );
    }
}

#[test]
fn failure_event_has_no_pid_endpoints_or_completed_attempt_result() {
    let mut raw = sample();
    raw.opcode = 17;
    raw.payload = vec![2, 0, 5, 0];
    let mut source = Fields(std::collections::BTreeMap::from([
        ("Proto", vec![2, 0]),
        ("FailureCode", vec![5, 0]),
    ]));
    assert_eq!(
        decode_properties(schema(&raw).unwrap(), &mut source).unwrap(),
        DecodedEvent::Failure {
            transport: Transport::Tcp,
            address_family: 2,
            failure_code: 5
        }
    );
}

#[cfg(windows)]
#[test]
fn native_tdh_decodes_both_families_transports_widths_and_failure_without_pid() {
    for provider in [TCP_PROVIDER, UDP_PROVIDER] {
        for flags in [0x120, 0x140] {
            let opcodes: &[u8] = if provider == TCP_PROVIDER {
                &[
                    10, 11, 12, 13, 14, 15, 16, 17, 18, 26, 27, 28, 29, 30, 31, 32, 34,
                ]
            } else {
                &[10, 11, 26, 27, 17]
            };
            for &opcode in opcodes {
                let mut event = sample();
                event.provider_guid = provider.into();
                event.flags = flags;
                event.opcode = opcode;
                if opcode == 17 {
                    event.payload = vec![23, 0, 5, 0];
                } else if opcode >= 26 {
                    event.payload = vec![0; 128];
                    event.payload[0..4].copy_from_slice(&4321u32.to_le_bytes());
                    event.payload[4..8].copy_from_slice(&1500u32.to_le_bytes());
                    event.payload[8..24].copy_from_slice(
                        &"2001:db8::5"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    event.payload[24..40].copy_from_slice(
                        &"2001:db8::1"
                            .parse::<std::net::Ipv6Addr>()
                            .unwrap()
                            .octets(),
                    );
                    event.payload[40..42].copy_from_slice(&443u16.to_be_bytes());
                    event.payload[42..44].copy_from_slice(&40000u16.to_be_bytes());
                } else {
                    event.payload.resize(48, 0);
                }
                let result = decode(&event)
                    .unwrap_or_else(|error| panic!("{provider}/{flags:x}/{opcode}: {error:?}"));
                match result {
                    DecodedEvent::Failure {
                        address_family,
                        failure_code,
                        ..
                    } => {
                        assert_eq!(address_family, 23);
                        assert_eq!(failure_code, 5);
                    }
                    DecodedEvent::Network {
                        payload_pid,
                        reported_size,
                        source,
                        destination,
                        ..
                    } => {
                        assert_eq!(payload_pid, 4321);
                        assert_eq!(reported_size, 1500);
                        assert_eq!(source.port, 40000);
                        assert_eq!(destination.port, 443);
                        assert_eq!(destination.address.is_ipv6(), opcode >= 26);
                    }
                }
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn native_tdh_rejects_truncated_payload_instead_of_reading_a_prefix() {
    let mut raw = sample();
    for length in [1, 3, 7, 19, 31] {
        raw.payload = sample().payload[..length].to_vec();
        assert!(decode(&raw).is_err(), "{length}");
    }
}

#[cfg(not(windows))]
#[test]
fn unsupported_platform_has_no_fake_decoder() {
    assert_eq!(decode(&sample()), Err(DecodeError::UnsupportedPlatform));
}
