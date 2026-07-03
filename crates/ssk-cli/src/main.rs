#![forbid(unsafe_code)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ssk_gates::GateVector;
use ssk_locator::LocatorPool;
use ssk_replay::{DeterministicReplayEngine, ReplayEngine};
use ssk_runtime::{sample_intent, Runtime};
use ssk_tensor::{FileLedgerBackend, LedgerBackend, MemoryBackend};
use ssk_types::{Locator, LocatorId, LocatorType, ReplayVerdict};

#[derive(Parser)]
#[command(name = "ssk")]
#[command(about = "ScorpioSync-Kaleidoscorp Omega runtime CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run {
        #[arg(long, default_value_t = true)]
        valid_fixture: bool,
    },
    ReplayVerify {
        #[arg(long, default_value_t = true)]
        valid_fixture: bool,
    },
    VerifyLedger {
        #[arg(long)]
        path: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { valid_fixture } => {
            let tensor = MemoryBackend::new();
            let runtime = Runtime {
                gate_vector: GateVector::with_all_default(),
                tensor: &tensor,
            };
            let pool = default_pool();
            let (outcome, _) = runtime.run_once(sample_intent(valid_fixture), &pool)?;
            println!("{}", serde_json::to_string_pretty(&outcome)?);
        }
        Command::ReplayVerify { valid_fixture } => {
            let tensor = MemoryBackend::new();
            let runtime = Runtime {
                gate_vector: GateVector::with_all_default(),
                tensor: &tensor,
            };
            let pool = default_pool();
            let (actual, manifest) = runtime.run_once(sample_intent(valid_fixture), &pool)?;
            let (expected, _) = runtime.run_once(sample_intent(valid_fixture), &pool)?;
            let engine = DeterministicReplayEngine;
            let verdict = engine.replay(&manifest, &actual, &expected);
            match verdict {
                ReplayVerdict::Deterministic => println!("deterministic"),
                ReplayVerdict::Divergent { first_diff, detail } => {
                    anyhow::bail!("divergent at {first_diff:?}: {detail}")
                }
            }
        }
        Command::VerifyLedger { path } => {
            let ledger = FileLedgerBackend::new(path);
            ledger.verify().context("ledger verification failed")?;
            println!("ledger-ok");
        }
    }
    Ok(())
}

fn default_pool() -> LocatorPool {
    LocatorPool::new(vec![Locator {
        id: LocatorId::new("local"),
        locator_type: LocatorType::LocalOverlay,
        trusted: true,
        risk_score: 10,
    }])
}
