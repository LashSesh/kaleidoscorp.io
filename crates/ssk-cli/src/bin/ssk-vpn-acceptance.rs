//! Offline evidence recorder. Never executes a VPN, service, shell or test case.
#[path = "../acceptance/mod.rs"]
mod acceptance;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    about = "Record and verify reviewed OpenVPN VM acceptance evidence; never operates the VPN"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Copy the three Windows binaries and fixed public guidance into a new development kit.
    KitCreate {
        #[arg(long)]
        cli: PathBuf,
        #[arg(long)]
        service: PathBuf,
        #[arg(long)]
        source_revision: String,
        #[arg(long)]
        worktree_dirty: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify an exact transferred kit against a separately retained manifest hash; never executes it.
    KitVerify {
        #[arg(long)]
        kit: PathBuf,
        #[arg(long)]
        expected_manifest_sha256: String,
    },
    /// Show the fixed case catalog and required evidence categories.
    Matrix,
    /// Create a new evidence bundle for one explicitly described disposable VM.
    Init {
        #[arg(long)]
        context: PathBuf,
        #[arg(long)]
        cli: PathBuf,
        #[arg(long)]
        service: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Append a reviewed observation and copies of its sanitized evidence files.
    Record {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        evidence_dir: PathBuf,
    },
    /// Verify every retained attempt/file and report latest outcomes; not a release gate.
    Report {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        expected_head: Option<String>,
    },
    /// Check both locales against externally retained heads. Exit 3 until coverage is complete.
    Check {
        #[arg(long)]
        en_us: PathBuf,
        #[arg(long)]
        de_de: PathBuf,
        #[arg(long)]
        expected_en_head: String,
        #[arg(long)]
        expected_de_head: String,
    },
}

fn execute(cli: Cli) -> Result<(serde_json::Value, u8), String> {
    let value = match cli.command {
        Command::KitCreate {
            cli,
            service,
            source_revision,
            worktree_dirty,
            out,
        } => {
            let recorder = std::env::current_exe().map_err(|_| "recorder path unavailable")?;
            serde_json::to_value(acceptance::kit_create(
                &cli,
                &service,
                &recorder,
                &source_revision,
                worktree_dirty,
                &out,
            )?)
        }
        Command::KitVerify {
            kit,
            expected_manifest_sha256,
        } => serde_json::to_value(acceptance::kit_verify(&kit, &expected_manifest_sha256)?),
        Command::Matrix => serde_json::to_value(acceptance::catalog()),
        Command::Init {
            context,
            cli,
            service,
            out,
        } => {
            let tool = std::env::current_exe().map_err(|_| "recorder path unavailable")?;
            acceptance::init(&context, &cli, &service, &tool, &out)?;
            serde_json::to_value(acceptance::report(&out, None)?)
        }
        Command::Record {
            bundle,
            observation,
            evidence_dir,
        } => {
            acceptance::record(&bundle, &observation, &evidence_dir)?;
            serde_json::to_value(acceptance::report(&bundle, None)?)
        }
        Command::Report {
            bundle,
            expected_head,
        } => serde_json::to_value(acceptance::report(&bundle, expected_head.as_deref())?),
        Command::Check {
            en_us,
            de_de,
            expected_en_head,
            expected_de_head,
        } => {
            let result = acceptance::check(&en_us, &de_de, &expected_en_head, &expected_de_head)?;
            let code = if result.coverage_complete { 0 } else { 3 };
            return Ok((
                serde_json::to_value(result).map_err(|_| "report encoding failed")?,
                code,
            ));
        }
    };
    Ok((value.map_err(|_| "report encoding failed")?, 0))
}
fn main() -> std::process::ExitCode {
    match execute(Cli::parse()) {
        Ok((value, code)) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).expect("JSON value is serializable")
            );
            std::process::ExitCode::from(code)
        }
        Err(message) => {
            eprintln!(
                "{}",
                serde_json::json!({"error":"ACCEPTANCE_EVIDENCE_INVALID", "message":message})
            );
            std::process::ExitCode::from(2)
        }
    }
}
