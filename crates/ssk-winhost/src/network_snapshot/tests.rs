use super::*;

const PID: u32 = 4321;
const KINDS: [TableKind; 4] = [
    TableKind::TcpV4,
    TableKind::TcpV6,
    TableKind::UdpV4,
    TableKind::UdpV6,
];

fn put32(bytes: &mut [u8], offset: usize, n: u32) {
    bytes[offset..offset + 4].copy_from_slice(&n.to_le_bytes());
}

fn row(kind: TableKind, pid: u32) -> Vec<u8> {
    let mut row = vec![0; kind.row_size()];
    put32(&mut row, kind.pid_offset(), pid);
    match kind {
        TableKind::TcpV4 => {
            put32(&mut row, 0, 5);
            row[4..8].copy_from_slice(&[127, 0, 0, 1]);
            row[8..10].copy_from_slice(&40000u16.to_be_bytes());
            row[12..16].copy_from_slice(&[192, 0, 2, 5]);
            row[16..18].copy_from_slice(&443u16.to_be_bytes());
        }
        TableKind::UdpV4 => {
            row[0..4].copy_from_slice(&[127, 0, 0, 1]);
            row[4..6].copy_from_slice(&40000u16.to_be_bytes());
        }
        TableKind::TcpV6 | TableKind::UdpV6 => {
            row[0..16].copy_from_slice(&"fe80::1".parse::<Ipv6Addr>().unwrap().octets());
            row[16..20].copy_from_slice(&7u32.to_be_bytes());
            row[20..22].copy_from_slice(&40000u16.to_be_bytes());
            if kind == TableKind::TcpV6 {
                row[24..40].copy_from_slice(&"fe80::2".parse::<Ipv6Addr>().unwrap().octets());
                row[40..44].copy_from_slice(&9u32.to_be_bytes());
                row[44..46].copy_from_slice(&443u16.to_be_bytes());
                put32(&mut row, 48, 5);
            }
        }
    }
    row
}

fn table(rows: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = (rows.len() as u32).to_le_bytes().to_vec();
    for row in rows {
        bytes.extend(row);
    }
    bytes
}

#[test]
fn all_four_layouts_filter_other_pids_and_decode_network_ports() {
    for kind in KINDS {
        let parsed = parse_table(
            kind,
            &table(&[row(kind, 99), row(kind, PID), row(kind, 0)]),
            PID,
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].local.port(), 40000);
        if matches!(kind, TableKind::TcpV4 | TableKind::TcpV6) {
            assert_eq!(parsed[0].remote.unwrap().port(), 443);
            assert_eq!(parsed[0].tcp_state, Some(5));
        } else {
            assert_eq!(parsed[0].remote, None);
            assert_eq!(parsed[0].tcp_state, None);
        }
    }
}

#[test]
fn ipv6_scopes_are_preserved_in_network_byte_order() {
    for kind in [TableKind::TcpV6, TableKind::UdpV6] {
        let parsed = parse_table(kind, &table(&[row(kind, PID)]), PID).unwrap();
        assert_eq!(parsed[0].local, "[fe80::1%7]:40000".parse().unwrap());
        if kind == TableKind::TcpV6 {
            assert_eq!(parsed[0].remote, Some("[fe80::2%9]:443".parse().unwrap()));
        }
    }
}

#[test]
fn listeners_do_not_invent_a_remote_endpoint_or_http_success() {
    for kind in [TableKind::TcpV4, TableKind::TcpV6] {
        let mut raw = row(kind, PID);
        put32(&mut raw, if kind == TableKind::TcpV4 { 0 } else { 48 }, 2);
        let parsed = parse_table(kind, &table(&[raw]), PID).unwrap();
        assert_eq!(parsed[0].remote, None);
        assert_eq!(parsed[0].tcp_state, Some(2));
    }
}

#[test]
fn incomplete_headers_and_rows_never_return_a_successful_prefix() {
    for kind in KINDS {
        let bytes = table(&[row(kind, PID), row(kind, PID)]);
        for length in 0..bytes.len() {
            assert_eq!(
                parse_table(kind, &bytes[..length], PID),
                Err(SnapshotError::MalformedTable)
            );
        }
    }
}

#[test]
fn empty_table_is_valid_but_zero_bytes_and_unknown_pid_are_not() {
    for kind in KINDS {
        assert!(parse_table(kind, &[0; 4], PID).unwrap().is_empty());
        assert_eq!(
            parse_table(kind, &[], PID),
            Err(SnapshotError::MalformedTable)
        );
        assert_eq!(
            parse_table(kind, &[0; 4], 0),
            Err(SnapshotError::InvalidPid)
        );
    }
}

#[test]
fn table_and_matching_row_budgets_discard_the_entire_result() {
    assert_eq!(
        parse_table(TableKind::TcpV6, &vec![0; MAX_TABLE_BYTES + 1], PID),
        Err(SnapshotError::TableTooLarge)
    );
    for kind in KINDS {
        assert_eq!(
            parse_table(kind, &u32::MAX.to_le_bytes(), PID),
            Err(SnapshotError::TableRowLimit)
        );
        let rows = vec![row(kind, PID); MAX_MATCHING_ROWS];
        assert_eq!(
            parse_table(kind, &table(&rows), PID).unwrap().len(),
            MAX_MATCHING_ROWS
        );
        let rows = vec![row(kind, PID); MAX_MATCHING_ROWS + 1];
        assert_eq!(
            parse_table(kind, &table(&rows), PID),
            Err(SnapshotError::MatchingRowLimit)
        );
    }
}

#[test]
fn bounded_query_retries_table_growth_and_returns_only_reported_bytes() {
    let mut calls = 0;
    let result = bounded_query(
        |buffer, size| {
            calls += 1;
            match calls {
                1 => {
                    assert!(buffer.is_empty());
                    *size = 4;
                    QueryReply::Resize
                }
                2 => {
                    assert_eq!(*size, 4);
                    *size = 12;
                    QueryReply::Resize
                }
                3 => {
                    buffer.fill(u32::MAX);
                    buffer[0] = 0;
                    *size = 4;
                    QueryReply::Success
                }
                _ => panic!("unexpected retry"),
            }
        },
        || false,
    )
    .unwrap();
    assert_eq!(calls, 3);
    assert_eq!(result, vec![0; 4]);
}

#[test]
fn continual_table_growth_has_a_fixed_call_budget() {
    let mut calls = 0;
    assert_eq!(
        bounded_query(
            |_, size| {
                calls += 1;
                *size += 4;
                QueryReply::Resize
            },
            || false
        ),
        Err(SnapshotError::UnstableTable)
    );
    assert_eq!(calls, MAX_QUERY_CALLS);
}

#[test]
fn query_rejects_oversize_zero_and_invalid_success_lengths() {
    for (size, expected) in [
        (0, SnapshotError::MalformedTable),
        (3, SnapshotError::MalformedTable),
        ((MAX_TABLE_BYTES + 1) as u32, SnapshotError::TableTooLarge),
    ] {
        assert_eq!(
            bounded_query(
                |_, len| {
                    *len = size;
                    QueryReply::Resize
                },
                || false
            ),
            Err(expected)
        );
    }
    assert_eq!(
        bounded_query(
            |_, size| {
                *size = 4;
                QueryReply::Success
            },
            || false
        ),
        Err(SnapshotError::MalformedTable)
    );
    assert_eq!(
        bounded_query(|_, _| QueryReply::Failure(5), || false),
        Err(SnapshotError::TableQuery { code: 5 })
    );
    let mut calls = 0;
    assert_eq!(
        bounded_query(
            |_, size| {
                calls += 1;
                *size = if calls == 1 { 4 } else { 8 };
                if calls == 1 {
                    QueryReply::Resize
                } else {
                    QueryReply::Success
                }
            },
            || false
        ),
        Err(SnapshotError::MalformedTable)
    );
}

#[test]
fn time_budget_is_checked_before_and_after_each_os_call() {
    assert_eq!(
        bounded_query(|_, _| panic!("must not query"), || true),
        Err(SnapshotError::TimeBudgetExceeded)
    );
    let mut checks = 0;
    assert_eq!(
        bounded_query(
            |_, size| {
                *size = 4;
                QueryReply::Resize
            },
            || {
                checks += 1;
                checks > 1
            }
        ),
        Err(SnapshotError::TimeBudgetExceeded)
    );
}

struct FakeSource {
    alive_checks: usize,
    die_on_check: usize,
    reads: usize,
    created: u64,
    fail_table: Option<TableKind>,
    late: bool,
}

impl Default for FakeSource {
    fn default() -> Self {
        Self {
            alive_checks: 0,
            die_on_check: usize::MAX,
            reads: 0,
            created: 133_333_333_333_333_333,
            fail_table: None,
            late: false,
        }
    }
}

impl SnapshotSource for FakeSource {
    fn creation_time(&mut self) -> Result<u64, SnapshotError> {
        Ok(self.created)
    }
    fn require_alive(&mut self) -> Result<(), SnapshotError> {
        self.alive_checks += 1;
        if self.alive_checks == self.die_on_check {
            Err(SnapshotError::ProcessExited)
        } else {
            Ok(())
        }
    }
    fn read_table(&mut self, kind: TableKind) -> Result<Vec<EndpointRow>, SnapshotError> {
        self.reads += 1;
        if self.fail_table == Some(kind) {
            Err(SnapshotError::TableQuery { code: 5 })
        } else {
            parse_table(kind, &table(&[row(kind, PID)]), PID)
        }
    }
    fn elapsed_micros(&self) -> u64 {
        if self.late {
            MAX_CAPTURE_MICROS
        } else {
            self.reads as u64
        }
    }
}

#[test]
fn healthy_snapshot_exposes_missing_capabilities_and_exact_process_time() {
    let mut source = FakeSource::default();
    let report = capture_from(&mut source, PID, "fixture".into()).unwrap();
    assert!(report.all_tables_read());
    assert_eq!(source.alive_checks, 2);
    assert_eq!(source.reads, 4);
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["process_created_at_filetime_100ns"],
        source.created.to_string()
    );
    for flag in [
        "connection_history_complete",
        "attempt_outcomes_available",
        "byte_counts_available",
        "event_loss_observable",
        "baseline_compatible",
        "enforcement_active",
    ] {
        assert_eq!(json[flag], false, "{flag}");
    }
    assert_eq!(report.tables()[0].started_after_micros, 0);
    assert_eq!(report.tables()[3].ended_after_micros, 4);
}

#[test]
fn failed_table_is_explicitly_unavailable_while_other_tables_are_retained() {
    let mut source = FakeSource {
        fail_table: Some(TableKind::TcpV6),
        ..Default::default()
    };
    let report = capture_from(&mut source, PID, "fixture".into()).unwrap();
    assert!(!report.all_tables_read());
    assert!(matches!(
        report.tables()[0].outcome,
        TableOutcome::Observed { .. }
    ));
    assert!(matches!(
        report.tables()[1].outcome,
        TableOutcome::Unavailable {
            reason: SnapshotError::TableQuery { code: 5 }
        }
    ));
}

#[test]
fn exited_process_before_collection_prevents_every_table_query() {
    let mut source = FakeSource {
        die_on_check: 1,
        ..Default::default()
    };
    assert!(matches!(
        capture_from(&mut source, PID, "fixture".into()),
        Err(SnapshotError::ProcessExited)
    ));
    assert_eq!(source.reads, 0);
}

#[test]
fn exited_process_after_collection_discards_every_table() {
    let mut source = FakeSource {
        die_on_check: 2,
        ..Default::default()
    };
    assert!(matches!(
        capture_from(&mut source, PID, "fixture".into()),
        Err(SnapshotError::ProcessExited)
    ));
    assert_eq!(source.reads, 4);
}

#[test]
fn missing_creation_time_is_not_a_process_identity() {
    let mut source = FakeSource {
        created: 0,
        ..Default::default()
    };
    assert!(matches!(
        capture_from(&mut source, PID, "fixture".into()),
        Err(SnapshotError::InvalidProcessTime)
    ));
    assert_eq!(source.reads, 0);
}

#[test]
fn over_budget_source_is_not_published_and_invalid_pid_is_rejected() {
    let mut source = FakeSource {
        late: true,
        ..Default::default()
    };
    assert!(matches!(
        capture_from(&mut source, PID, "fixture".into()),
        Err(SnapshotError::TimeBudgetExceeded)
    ));
    assert_eq!(source.reads, 0);
    assert!(matches!(
        snapshot_process(0),
        Err(SnapshotError::InvalidPid)
    ));
}

#[cfg(not(windows))]
#[test]
fn unsupported_platform_never_returns_an_empty_success() {
    assert!(matches!(
        snapshot_process(PID),
        Err(SnapshotError::UnsupportedPlatform)
    ));
}

#[cfg(windows)]
#[test]
fn parser_sizes_and_offsets_match_the_pinned_windows_abi() {
    use std::mem::{offset_of, size_of};
    use windows_sys::Win32::NetworkManagement::IpHelper::*;
    assert_eq!(
        size_of::<MIB_TCPROW_OWNER_PID>(),
        TableKind::TcpV4.row_size()
    );
    assert_eq!(
        size_of::<MIB_TCP6ROW_OWNER_PID>(),
        TableKind::TcpV6.row_size()
    );
    assert_eq!(
        size_of::<MIB_UDPROW_OWNER_PID>(),
        TableKind::UdpV4.row_size()
    );
    assert_eq!(
        size_of::<MIB_UDP6ROW_OWNER_PID>(),
        TableKind::UdpV6.row_size()
    );
    assert_eq!(offset_of!(MIB_TCPTABLE_OWNER_PID, table), 4);
    assert_eq!(offset_of!(MIB_TCP6TABLE_OWNER_PID, table), 4);
    assert_eq!(offset_of!(MIB_UDPTABLE_OWNER_PID, table), 4);
    assert_eq!(offset_of!(MIB_UDP6TABLE_OWNER_PID, table), 4);
    assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwState), 48);
    assert_eq!(offset_of!(MIB_TCP6ROW_OWNER_PID, dwOwningPid), 52);
    assert_eq!(offset_of!(MIB_UDP6ROW_OWNER_PID, dwOwningPid), 24);
}
