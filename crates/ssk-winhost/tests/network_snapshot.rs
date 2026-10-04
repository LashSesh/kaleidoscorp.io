use std::process::Command;

#[test]
fn cli_help_and_bad_arguments_do_not_query_a_process() {
    let exe = env!("CARGO_BIN_EXE_ssk-netobserve");
    let help = Command::new(exe).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8(help.stdout)
        .unwrap()
        .contains("Read-only"));
    for args in [
        vec![],
        vec!["snapshot"],
        vec!["snapshot", "--pid", "0"],
        vec!["snapshot", "--pid", "-1"],
        vec!["snapshot", "--pid", "+1"],
        vec!["snapshot", "--pid", "4294967296"],
        vec!["snapshot", "--pid", "secret-value"],
        vec!["snapshot", "--self", "--enforce"],
    ] {
        let out = Command::new(exe).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8(out.stderr)
            .unwrap()
            .contains("secret-value"));
    }
}

#[cfg(windows)]
#[test]
fn real_process_and_all_four_tables_report_local_test_sockets() {
    use ssk_winhost::network_snapshot::{snapshot_process, TableKind, TableOutcome};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    let tcp4 = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp6 = TcpListener::bind("[::1]:0").unwrap();
    let udp4 = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp6 = UdpSocket::bind("[::1]:0").unwrap();
    let client = TcpStream::connect_timeout(
        &tcp4.local_addr().unwrap(),
        std::time::Duration::from_secs(1),
    )
    .unwrap();
    let (_accepted, _) = tcp4.accept().unwrap();
    let report = snapshot_process(std::process::id()).unwrap();
    assert!(report.all_tables_read(), "{report:?}");
    for (kind, address) in [
        (TableKind::TcpV4, tcp4.local_addr().unwrap()),
        (TableKind::TcpV6, tcp6.local_addr().unwrap()),
        (TableKind::UdpV4, udp4.local_addr().unwrap()),
        (TableKind::UdpV6, udp6.local_addr().unwrap()),
    ] {
        let TableOutcome::Observed { rows } = &report
            .tables()
            .iter()
            .find(|table| table.table == kind)
            .unwrap()
            .outcome
        else {
            panic!("missing table");
        };
        let observed = rows
            .iter()
            .find(|row| row.local == address && row.remote.is_none())
            .expect("local listener/binding not observed");
        assert_eq!(
            observed.tcp_state,
            if matches!(kind, TableKind::TcpV4 | TableKind::TcpV6) {
                Some(2)
            } else {
                None
            }
        );
    }
    let TableOutcome::Observed { rows } = &report.tables()[0].outcome else {
        panic!("missing TCP4");
    };
    assert!(rows
        .iter()
        .any(|row| row.local == client.local_addr().unwrap()
            && row.remote == Some(tcp4.local_addr().unwrap())
            && row.tcp_state == Some(5)));
    let second = snapshot_process(std::process::id()).unwrap();
    let a = serde_json::to_value(&report).unwrap();
    let b = serde_json::to_value(second).unwrap();
    assert_eq!(
        a["process_created_at_filetime_100ns"],
        b["process_created_at_filetime_100ns"]
    );
    assert_ne!(a["capture_id"], b["capture_id"]);
}

#[cfg(windows)]
#[test]
fn real_cli_self_snapshot_has_no_analysis_or_enforcement_authority() {
    let out = Command::new(env!("CARGO_BIN_EXE_ssk-netobserve"))
        .args(["snapshot", "--self"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["source"], "windows_ip_helper_owner_pid_snapshot_v1");
    assert_eq!(report["tables"].as_array().unwrap().len(), 4);
    for flag in [
        "connection_history_complete",
        "attempt_outcomes_available",
        "byte_counts_available",
        "event_loss_observable",
        "baseline_compatible",
        "enforcement_active",
    ] {
        assert_eq!(report[flag], false);
    }
    assert!(report.get("verdict").is_none());
}
