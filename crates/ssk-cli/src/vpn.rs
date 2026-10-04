use clap::Subcommand;

#[derive(clap::Args)]
pub struct JournalRecoveryArgs {
    archive: std::path::PathBuf,
    #[arg(long)]
    expected_archive_sha256: String,
    #[arg(long)]
    expected_head: String,
    #[arg(long)]
    expected_records: u64,
    #[arg(long)]
    expected_observed: String,
}
#[cfg(windows)]
impl JournalRecoveryArgs {
    fn request(&self) -> ssk_winhost::vpn_journal::RecoveryRequest<'_> {
        ssk_winhost::vpn_journal::RecoveryRequest {
            archive: &self.archive,
            expected_archive_sha256: &self.expected_archive_sha256,
            expected_head: &self.expected_head,
            expected_records: self.expected_records,
            expected_observed: &self.expected_observed,
        }
    }
}

#[derive(Subcommand)]
pub enum Command {
    /// Fingerprint even damaged journal segments without creating or repairing files.
    JournalDiagnose,
    /// Fence VPN domain startup and reconstruct a verified journal in protected quarantine.
    JournalRecoveryStage(JournalRecoveryArgs),
    /// Resume the pinned quarantine plan; preserve incomplete attempts. Never activate.
    JournalRecoveryResume {
        #[command(flatten)]
        input: JournalRecoveryArgs,
        #[arg(long)]
        expected_plan_sha256: String,
    },
    /// Copy all verified journal segments to a new confidential offline archive.
    JournalBackup {
        destination: std::path::PathBuf,
        #[arg(long)]
        expected_head: String,
        #[arg(long)]
        expected_records: u64,
    },
    /// Verify an archive against independently retained anchors, without restoring it.
    JournalBackupVerify {
        archive: std::path::PathBuf,
        #[arg(long)]
        expected_archive_sha256: String,
        #[arg(long)]
        expected_head: String,
        #[arg(long)]
        expected_records: u64,
    },
    /// Create a separate random backup key in an existing confidential directory.
    ConfigBackupKeyCreate { destination: std::path::PathBuf },
    /// Encrypt the committed active configuration to a new confidential archive.
    ConfigBackup {
        destination: std::path::PathBuf,
        #[arg(long)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        expected_committed: String,
    },
    /// Authenticate an archive against the current commitment without exporting plaintext.
    ConfigBackupVerify {
        archive: std::path::PathBuf,
        #[arg(long)]
        key_file: std::path::PathBuf,
        #[arg(long)]
        expected_committed: String,
    },
    /// Diagnose managed configuration damage offline without changing evidence.
    ConfigDiagnose,
    /// Restore exactly the last committed configuration, preserving damaged bytes.
    ConfigRestore {
        #[arg(long)]
        expected_committed: String,
        /// Observed active SHA-256 from diagnosis, or 'missing'.
        #[arg(long)]
        expected_observed: String,
        /// Optional confidential copy. Its bytes must match the journal commitment.
        #[arg(long, conflicts_with = "backup")]
        source: Option<std::path::PathBuf>,
        /// Encrypted archive; requires its separately retained key file.
        #[arg(long, requires = "key_file", conflicts_with = "source")]
        backup: Option<std::path::PathBuf>,
        #[arg(long, requires = "backup")]
        key_file: Option<std::path::PathBuf>,
    },
    /// Complete an interrupted restore after verifying its preserved evidence.
    ConfigRestoreReconcile,
    /// Stage a complete approved profile/grant snapshot from a confidential file.
    ConfigStage {
        document: std::path::PathBuf,
        #[arg(long)]
        approved_sha256: String,
    },
    /// Select a whole configuration offline, including grants and revocations.
    ConfigActivate {
        configuration_id: String,
        #[arg(long)]
        expected_active: String,
    },
    /// Report verified active configuration identifiers, never credentials.
    ConfigInspect,
    /// Reconcile an interrupted configuration selection from verified disk state.
    ConfigReconcile,
    /// Explicitly provision the protected VPN store. Elevated and offline.
    PackageProvision,
    /// Verify and stage an independently approved flat bundle; never execute it.
    PackageStage {
        manifest: std::path::PathBuf,
        #[arg(long)]
        approved_sha256: String,
    },
    /// Select a staged package for future starts. Requires a stopped service.
    PackageActivate {
        package_id: String,
        /// Current manifest SHA-256, or 'none' for a first installation.
        #[arg(long)]
        expected_active: String,
    },
    /// Verify the selected bundle and report its manifest SHA-256 offline.
    PackageInspect,
    /// Complete an interrupted selection's audit from verified disk state.
    PackageReconcile,
    /// Verify retained VPN journals and capacity offline. Requires protected-store
    /// access and a stopped service; never starts, repairs or deletes anything.
    JournalInspect,
    /// Query current status. A profile-specific status grant is required.
    Status { profile: String },
    /// Prepare authenticated management in HOLD. Does not connect a tunnel.
    Prepare {
        profile: String,
        #[arg(long)]
        expected_revision: u64,
        /// Reuse this 32-digit hex ID when retrying an uncertain request.
        #[arg(long)]
        operation_id: Option<String>,
    },
    /// Stop the owned held process. Completion requires confirmed OS exit.
    Stop {
        profile: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        operation_id: Option<String>,
    },
    /// Reconcile an interrupted attempt after proving OS exit and cleaning its files.
    /// Requires an explicit recover grant; never kills or reconnects a recorded PID.
    Recover {
        profile: String,
        #[arg(long)]
        expected_revision: u64,
        #[arg(long)]
        operation_id: Option<String>,
    },
}

#[cfg(windows)]
pub fn run(command: &Command, json: bool) -> Result<(), crate::AppError> {
    use ssk_netd_helper::{
        vpn::{client::Client, Command as WireCommand, Response, Verb},
        IdempotencyKey, Nonce,
    };
    use ssk_winhost::vpn_configuration as configuration;
    use ssk_winhost::vpn_deployment as deployment;
    let recovery = match command {
        Command::JournalDiagnose => Some(
            ssk_winhost::vpn_journal::diagnose()
                .and_then(|r| serde_json::to_value(r).map_err(std::io::Error::other)),
        ),
        Command::JournalRecoveryStage(input) => Some(
            ssk_winhost::vpn_journal::recovery_stage(input.request())
                .and_then(|r| serde_json::to_value(r).map_err(std::io::Error::other)),
        ),
        Command::JournalRecoveryResume {
            input,
            expected_plan_sha256,
        } => Some(
            ssk_winhost::vpn_journal::recovery_resume(input.request(), expected_plan_sha256)
                .and_then(|r| serde_json::to_value(r).map_err(std::io::Error::other)),
        ),
        _ => None,
    };
    if let Some(result) = recovery {
        let report = result.map_err(|e|crate::winhost_err("VPN_JOURNAL_RECOVERY_FAILED", e.to_string(), vec!["Preserve originals, the recovery marker and all attempts. Use the trusted archive/head/count, observed-set digest and pinned plan for resume. Quarantine never activates the journal or clears the service fence.".into()]))?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
        );
        return Ok(());
    }
    let journal_archive = match command {
        Command::JournalBackup {
            destination,
            expected_head,
            expected_records,
        } => Some(ssk_winhost::vpn_journal::backup(
            destination,
            expected_head,
            *expected_records,
        )),
        Command::JournalBackupVerify {
            archive,
            expected_archive_sha256,
            expected_head,
            expected_records,
        } => Some(ssk_winhost::vpn_journal::backup_verify(
            archive,
            expected_archive_sha256,
            expected_head,
            *expected_records,
        )),
        _ => None,
    };
    if let Some(result) = journal_archive {
        let report = result.map_err(|e| crate::winhost_err("VPN_JOURNAL_ARCHIVE_FAILED", e.to_string(),
            vec!["Use an elevated session, confidential archive storage and independently retained anchors. Stop the service before backup. Preserve originals and incomplete outputs on failure.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            println!("VPN journal archive: {}", report.action);
            println!(
                "Archive SHA-256: {}; bytes: {}",
                report.archive_sha256, report.archive_bytes
            );
            println!(
                "Historical head: {}; records: {}",
                report.inspection.head, report.inspection.records
            );
            println!("Restoration performed: {}", report.restoration_performed);
        }
        return Ok(());
    }
    let backup_result = match command {
        Command::ConfigBackupKeyCreate { destination } => {
            Some(configuration::backup_key_create(destination))
        }
        Command::ConfigBackup {
            destination,
            key_file,
            expected_committed,
        } => Some(configuration::backup(
            destination,
            key_file,
            expected_committed,
        )),
        Command::ConfigBackupVerify {
            archive,
            key_file,
            expected_committed,
        } => Some(configuration::backup_verify(
            archive,
            key_file,
            expected_committed,
        )),
        _ => None,
    };
    if let Some(result) = backup_result {
        let report = result.map_err(|e| crate::winhost_err("VPN_CONFIGURATION_BACKUP_FAILED", e.to_string(),
            vec!["Use an elevated offline session and existing confidential directories. Keep the random key separately; existing or incomplete artifacts are never overwritten.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            println!("VPN configuration backup: {}", report.action);
            if let Some(hash) = report.configuration_sha256 {
                println!("Configuration SHA-256: {hash}");
            }
            if let Some(hash) = report.archive_sha256 {
                println!("Archive SHA-256: {hash}");
            }
            if let Some(bytes) = report.archive_bytes {
                println!("Archive bytes: {bytes}");
            }
        }
        return Ok(());
    }
    let recovery = match command {
        Command::ConfigDiagnose => Some(configuration::diagnose()),
        Command::ConfigRestore {
            expected_committed,
            expected_observed,
            source,
            backup,
            key_file,
        } => Some(match (backup, key_file) {
            (Some(archive), Some(key_file)) => configuration::restore_backup(
                expected_committed,
                expected_observed,
                archive,
                key_file,
            ),
            (None, None) => {
                configuration::restore(expected_committed, expected_observed, source.as_deref())
            }
            _ => unreachable!("clap requires both archive and key"),
        }),
        Command::ConfigRestoreReconcile => Some(configuration::reconcile_restore()),
        _ => None,
    };
    if let Some(result) = recovery {
        let report = result.map_err(|e| crate::winhost_err("VPN_CONFIGURATION_RECOVERY_FAILED", e.to_string(),
            vec!["Preserve artifacts. Use an elevated offline session, config-diagnose and the matching reconciliation command. Restore cannot select another version or reset process history.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            let diagnosis = &report.diagnosis;
            println!(
                "VPN configuration recovery: {}; operation: {}",
                report.outcome,
                report.operation_id.as_deref().unwrap_or("none")
            );
            println!(
                "Committed SHA-256: {}",
                diagnosis
                    .expected_configuration_sha256
                    .as_deref()
                    .unwrap_or("none")
            );
            println!(
                "Active: {:?}; SHA-256: {}",
                diagnosis.active.state,
                diagnosis.active.sha256.as_deref().unwrap_or("unavailable")
            );
            if let Some(retained) = &diagnosis.retained {
                println!(
                    "Retained: {:?}; matches committed: {}",
                    retained.state, retained.matches_committed
                );
            }
            println!(
                "Next step: {:?}; process recovery required: {}",
                diagnosis.next_step, diagnosis.process_recovery_required
            );
        }
        return Ok(());
    }
    let config_result = match command {
        Command::ConfigStage {
            document,
            approved_sha256,
        } => Some(configuration::stage(document, approved_sha256)),
        Command::ConfigActivate {
            configuration_id,
            expected_active,
        } => Some(configuration::activate(configuration_id, expected_active)),
        Command::ConfigInspect => Some(configuration::inspect()),
        Command::ConfigReconcile => Some(configuration::reconcile()),
        _ => None,
    };
    if let Some(result) = config_result {
        let report = result.map_err(|e| crate::winhost_err("VPN_CONFIGURATION_FAILED", e.to_string(),
            vec!["Use an elevated offline session and confidential source files. Preserve evidence and reconcile pending configuration changes before service restart.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            println!(
                "VPN configuration: {}; SHA-256: {}",
                report.action,
                report.configuration_sha256.as_deref().unwrap_or("none")
            );
            println!(
                "Profiles: {}; granted principals: {}; pending change: {}",
                report.profile_ids.len(),
                report.principal_sids.len(),
                report.pending_deployment.is_some() || report.pending_repair.is_some()
            );
        }
        return Ok(());
    }
    let deployment = match command {
        Command::PackageProvision => Some(deployment::provision()),
        Command::PackageStage {
            manifest,
            approved_sha256,
        } => Some(deployment::stage(manifest, approved_sha256)),
        Command::PackageActivate {
            package_id,
            expected_active,
        } => Some(deployment::activate(package_id, expected_active)),
        Command::PackageInspect => Some(deployment::inspect()),
        Command::PackageReconcile => Some(deployment::reconcile()),
        _ => None,
    };
    if let Some(result) = deployment {
        let report = result.map_err(|e| crate::winhost_err("VPN_DEPLOYMENT_FAILED", e.to_string(),
            vec!["Use an elevated offline session. Preserve artifacts on failure; inspect the journal and reconcile any pending selection before restarting VPN control.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            println!("VPN package: {}", report.action);
            if let Some(id) = report.package_id {
                println!("Package ID: {id}");
            }
            if let Some(selection) = report.selection {
                println!(
                    "Manifest SHA-256: {}; directory: {}",
                    selection.manifest_sha256,
                    selection.directory.display()
                );
            }
            println!(
                "Pending maintenance: {}",
                report.pending_deployment.is_some() || report.pending_repair.is_some()
            );
        }
        return Ok(());
    }
    if matches!(command, Command::JournalInspect) {
        let report = ssk_winhost::vpn_journal::inspect().map_err(|e| crate::winhost_err(
            "VPN_JOURNAL_INSPECTION_FAILED", e.to_string(),
            vec!["Stop the service and use an account permitted to access the protected VPN store. Preserve files on verification failure.".into()]))?;
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).map_err(crate::winhost_json_err)?
            );
        } else {
            println!(
                "VPN journal chain verified: {} records; new intent capacity: {}",
                report.records, report.accepts_intent
            );
            println!(
                "Pending deployment: {}",
                report.pending_deployment.is_some() || report.pending_repair.is_some()
            );
            if let Some(storage) = report.storage {
                println!(
                    "Segments: {}/{}; bytes: {}/{}; reserved-size record slots: {}",
                    storage.segments,
                    storage.max_segments,
                    storage.total_bytes,
                    storage.max_total_bytes,
                    storage.guaranteed_record_slots
                );
            }
            if let Some(status) = report.last_status {
                println!(
                    "Last recorded phase: {:?}; revision {}; audit healthy: {}",
                    status.phase, status.revision, status.audit_healthy
                );
            }
        }
        return Ok(());
    }
    let (verb, profile, revision, operation_id) = match command {
        Command::JournalInspect
        | Command::JournalDiagnose
        | Command::JournalRecoveryStage(..)
        | Command::JournalRecoveryResume { .. }
        | Command::JournalBackup { .. }
        | Command::JournalBackupVerify { .. }
        | Command::ConfigBackupKeyCreate { .. }
        | Command::ConfigBackup { .. }
        | Command::ConfigBackupVerify { .. }
        | Command::ConfigDiagnose
        | Command::ConfigRestore { .. }
        | Command::ConfigRestoreReconcile
        | Command::ConfigStage { .. }
        | Command::ConfigActivate { .. }
        | Command::ConfigInspect
        | Command::ConfigReconcile
        | Command::PackageProvision
        | Command::PackageStage { .. }
        | Command::PackageActivate { .. }
        | Command::PackageInspect
        | Command::PackageReconcile => unreachable!(),
        Command::Status { profile } => (Verb::Status, profile, 0, None),
        Command::Prepare {
            profile,
            expected_revision,
            operation_id,
        } => (
            Verb::Prepare,
            profile,
            *expected_revision,
            operation_id.as_deref(),
        ),
        Command::Stop {
            profile,
            expected_revision,
            operation_id,
        } => (
            Verb::Stop,
            profile,
            *expected_revision,
            operation_id.as_deref(),
        ),
        Command::Recover {
            profile,
            expected_revision,
            operation_id,
        } => (
            Verb::Recover,
            profile,
            *expected_revision,
            operation_id.as_deref(),
        ),
    };
    let error = |message: String| {
        crate::winhost_err("VPN_CONTROL_FAILED", message,
        vec!["Check the service and its selected protected VPN configuration (or legacy policy before migration). No tunnel was authorized by this CLI.".into()])
    };
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| error("OS randomness unavailable".into()))?;
    let operation = match operation_id {
        Some(id) => parse_operation(id).map_err(|m| error(m.into()))?,
        None => {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).map_err(|_| error("OS randomness unavailable".into()))?;
            bytes
        }
    };
    let operation_hex: String = operation.iter().map(|b| format!("{b:02x}")).collect();
    let transport = ssk_winhost::NamedPipeClientTransport::connect(
        ssk_winhost::PRIVILEGED_PIPE_NAME,
        ssk_winhost::LOCAL_SYSTEM_SID,
    )
    .map_err(|e| error(e.to_string()))?;
    let mut client = Client::connect(transport).map_err(|e| error(e.to_string()))?;
    let response = client.send(WireCommand { verb, profile: profile.clone() }, revision, IdempotencyKey(operation), Nonce(nonce))
        .map_err(|e| if verb == Verb::Status { error(e.to_string()) } else {
            error(format!("{e}; outcome unknown, retry operation ID {operation_hex} with a fresh nonce in this service session"))
        })?;
    if let Response::Rejected(reason) = &response {
        return Err(crate::winhost_err(
            "VPN_REQUEST_REJECTED",
            format!("{reason:?}"),
            if matches!(reason, ssk_netd_helper::vpn::Reject::AuditUnavailable) {
                vec!["With the service stopped, run 'ssk --json winhost vpn journal-inspect' to verify the protected journal and its capacity.".into()]
            } else {
                vec![]
            },
        ));
    }
    let reported_operation = match &response {
        Response::Status(s) | Response::Accepted(s) | Response::Duplicate(s) => {
            s.operation.map(|id| {
                id.0.iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
        }
        Response::Rejected(_) => unreachable!(),
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"operation_id": reported_operation, "response": response})
            )
            .map_err(crate::winhost_json_err)?
        );
    } else {
        let (label, status) = match response {
            Response::Status(s) => ("Current status", s),
            Response::Accepted(s) => ("Accepted for asynchronous execution", s),
            Response::Duplicate(s) => (
                "Original acceptance; query status for the current result",
                s,
            ),
            Response::Rejected(_) => unreachable!(),
        };
        println!(
            "{label}: {:?}; revision {}; operation {}",
            status.phase,
            status.revision,
            reported_operation.as_deref().unwrap_or("none")
        );
        println!(
            "Exit confirmed: {:?}; audit healthy: {}; failure: {:?}",
            status.exit_confirmed, status.audit_healthy, status.failure
        );
        if let Some(reason) = status.recovery_failure {
            println!("Recovery failed: {reason:?}");
        }
        if let Some(proof) = status.recovery_evidence {
            println!("Recovery evidence: {proof:?}");
        }
        println!(
            "VPN preparation remains in HOLD. This status does not authorize network traffic."
        );
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn run(_: &Command, _: bool) -> Result<(), crate::AppError> {
    Err(crate::winhost_err(
        "VPN_REQUIRES_WINDOWS",
        "VPN service control requires Windows",
        vec![],
    ))
}

#[cfg(any(windows, test))]
fn parse_operation(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() != 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("operation ID must contain exactly 32 hexadecimal digits");
    }
    let mut bytes = [0u8; 16];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "invalid operation ID")?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn journal_recovery_cli_requires_observation_and_pinned_resume_plan_without_activation() {
        let hash = "ab".repeat(32);
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "journal-diagnose"]).is_ok());
        for command in ["journal-recovery-stage", "journal-recovery-resume"] {
            let mut args = vec![
                "ssk",
                "winhost",
                "vpn",
                command,
                "C:/Private/journal.sskj",
                "--expected-archive-sha256",
                &hash,
                "--expected-head",
                &hash,
                "--expected-records",
                "5",
            ];
            assert!(crate::Cli::try_parse_from(&args).is_err());
            args.extend(["--expected-observed", &hash]);
            if command.ends_with("resume") {
                assert!(crate::Cli::try_parse_from(&args).is_err());
                args.extend(["--expected-plan-sha256", &hash]);
            }
            assert!(crate::Cli::try_parse_from(&args).is_ok());
            args.push("--activate");
            assert!(crate::Cli::try_parse_from(&args).is_err());
        }
    }
    #[test]
    fn journal_archive_cli_requires_all_external_anchors_and_has_no_restore_force_switch() {
        let hash = "ab".repeat(32);
        for command in ["journal-backup", "journal-backup-verify"] {
            let mut args = vec!["ssk", "winhost", "vpn", command, "C:/Private/journal.sskj"];
            assert!(crate::Cli::try_parse_from(&args).is_err());
            args.extend(["--expected-head", &hash]);
            assert!(crate::Cli::try_parse_from(&args).is_err());
            args.extend(["--expected-records", "10"]);
            if command == "journal-backup-verify" {
                assert!(crate::Cli::try_parse_from(&args).is_err());
                args.extend(["--expected-archive-sha256", &hash]);
            }
            assert!(crate::Cli::try_parse_from(&args).is_ok());
            args.push("--force");
            assert!(crate::Cli::try_parse_from(&args).is_err());
        }
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "journal-restore"]).is_err());
    }
    #[test]
    fn restore_cli_requires_explicit_commit_and_observation_without_a_force_mode() {
        let id = "ab".repeat(32);
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "config-restore"]).is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-restore",
            "--expected-committed",
            &id
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-restore",
            "--expected-committed",
            &id,
            "--expected-observed",
            "missing",
            "--source",
            "C:/private/backup.json"
        ])
        .is_ok());
        for command in ["config-diagnose", "config-restore-reconcile"] {
            assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command]).is_ok());
            assert!(
                crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command, "--force"]).is_err()
            );
        }
    }
    #[test]
    fn configuration_commands_require_approval_and_explicit_previous_state() {
        let hash = "ab".repeat(32);
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-stage",
            "C:/private.json"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-stage",
            "C:/private.json",
            "--approved-sha256",
            &hash
        ])
        .is_ok());
        assert!(
            crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "config-activate", &hash])
                .is_err()
        );
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-activate",
            &hash,
            "--expected-active",
            "none"
        ])
        .is_ok());
        for command in ["config-inspect", "config-reconcile"] {
            assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command]).is_ok());
            assert!(
                crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command, "--force"]).is_err()
            );
        }
    }
    #[test]
    fn package_commands_require_independent_approval_and_explicit_previous_selection() {
        let hash = "ab".repeat(32);
        for command in ["package-provision", "package-inspect", "package-reconcile"] {
            assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command]).is_ok());
            assert!(
                crate::Cli::try_parse_from(["ssk", "winhost", "vpn", command, "--force"]).is_err()
            );
        }
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "package-stage",
            "C:/approved.json"
        ])
        .is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "package-stage",
            "C:/approved.json",
            "--approved-sha256",
            &hash
        ])
        .is_ok());
        assert!(
            crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "package-activate", &hash])
                .is_err()
        );
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "package-activate",
            &hash,
            "--expected-active",
            "none"
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "package-activate",
            &hash,
            "--expected-active",
            "none",
            "--connect"
        ])
        .is_err());
    }
    #[test]
    fn cli_requires_explicit_revision_and_rejects_tunnel_activation() {
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "prepare", "corp"]).is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "prepare",
            "corp",
            "--expected-revision",
            "4"
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "connect", "corp"]).is_err());
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "recover", "corp"]).is_err());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "recover",
            "corp",
            "--expected-revision",
            "9"
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from(["ssk", "winhost", "vpn", "journal-inspect"]).is_ok());
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "journal-inspect",
            "C:/untrusted.journal"
        ])
        .is_err());
        assert_eq!(parse_operation(&"ab".repeat(16)).unwrap(), [0xab; 16]);
        for invalid in ["ab", "../x", &"f".repeat(33), &"é".repeat(16)] {
            assert!(parse_operation(invalid).is_err());
        }
    }

    #[test]
    fn backup_cli_requires_file_key_and_committed_digest_and_unambiguous_restore_source() {
        let hash = "ab".repeat(32);
        for command in ["config-backup", "config-backup-verify"] {
            let base = ["ssk", "winhost", "vpn", command, "C:/Private/archive.sskb"];
            assert!(crate::Cli::try_parse_from(base).is_err());
            let mut args = base.to_vec();
            args.extend([
                "--key-file",
                "C:/Keys/recovery.key",
                "--expected-committed",
                &hash,
            ]);
            assert!(crate::Cli::try_parse_from(&args).is_ok());
            args.extend(["--password", "unsupported"]);
            assert!(crate::Cli::try_parse_from(&args).is_err());
        }
        assert!(crate::Cli::try_parse_from([
            "ssk",
            "winhost",
            "vpn",
            "config-backup-key-create",
            "C:/Keys/recovery.key"
        ])
        .is_ok());
        let base = [
            "ssk",
            "winhost",
            "vpn",
            "config-restore",
            "--expected-committed",
            &hash,
            "--expected-observed",
            "missing",
        ];
        let mut args = base.to_vec();
        args.extend(["--backup", "C:/Private/archive.sskb"]);
        assert!(crate::Cli::try_parse_from(&args).is_err());
        args.extend(["--key-file", "C:/Keys/recovery.key"]);
        assert!(crate::Cli::try_parse_from(&args).is_ok());
        args.extend(["--source", "C:/Private/plain.json"]);
        assert!(crate::Cli::try_parse_from(&args).is_err());
        let mut args = base.to_vec();
        args.extend(["--key-file", "C:/Keys/recovery.key"]);
        assert!(crate::Cli::try_parse_from(args).is_err());
    }
}
