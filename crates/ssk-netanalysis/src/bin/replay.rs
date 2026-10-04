#![forbid(unsafe_code)]

use std::io::Write;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("Usage: ssk-netanalysis-replay <replay.json>\nOffline advisory analysis only. No capture, firewall changes or connection grants.\nExit 0: report produced (inspect verdict). Exit 2: invalid input or I/O failure.");
        return Ok(());
    }
    if args.len() != 1 {
        return Err("expected one replay JSON path; use --help".into());
    }
    let file = std::fs::File::open(&args[0])?;
    if !file.metadata()?.is_file() {
        return Err("replay input must be a regular file".into());
    }
    let report = ssk_netanalysis::replay::read_and_analyze(file)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer_pretty(&mut out, &report)?;
    writeln!(out)?;
    Ok(())
}
