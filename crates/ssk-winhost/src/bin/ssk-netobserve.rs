//! Standalone read-only diagnostic; does not start the service or analysis.
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
        println!("Usage: ssk-netobserve snapshot --self\n       ssk-netobserve snapshot --pid <decimal-pid>\n       ssk-netobserve etw-replay <export.json>\n       ssk-netobserve etl <recording.etl>\n       ssk-netobserve etl-check <recording.etl> <closure.json>\nRead-only diagnostics; no trace sessions are started.\nETL: local file <=64 MiB, supervised worker, 10 s deadline, 256 MiB commit limit.\nClosure: local JSON <=16 KiB; consistency and SHA-256 binding only, no attestation.\nNo verified process identity, complete attempt history, analysis or enforcement.\nExit 0: report produced; inspect status (etl-check: closure.status and etl.status). Exit 2: invalid input or worker failure.");
        return Ok(());
    }
    if let [verb, path] = args.as_slice() {
        if verb == "--etl-worker" {
            return ssk_winhost::network_etw::etl::worker(path.as_ref()).map_err(Into::into);
        }
        if verb == "etl" {
            let report = ssk_winhost::network_etw::etl::inspect(path.as_ref())?;
            let mut out = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
            return Ok(());
        }
        if verb == "etw-replay" {
            let file = std::fs::File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err("ETW replay input must be a regular file".into());
            }
            let report = ssk_winhost::network_etw::replay::read_and_audit(file)?;
            let mut out = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
            return Ok(());
        }
    }
    if let [verb, path, receipt] = args.as_slice() {
        if verb == "etl-check" {
            let report = ssk_winhost::network_etw::etl::inspect_with_closure(
                path.as_ref(),
                receipt.as_ref(),
            )?;
            let mut out = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
            return Ok(());
        }
    }
    let pid = match args.as_slice() {
        [verb, flag] if verb == "snapshot" && flag == "--self" => std::process::id(),
        [verb, flag, value] if verb == "snapshot" && flag == "--pid" => {
            let value = value.to_str().ok_or("PID must be a nonzero decimal u32")?;
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("PID must be a nonzero decimal u32".into());
            }
            value
                .parse::<u32>()
                .ok()
                .filter(|pid| *pid != 0)
                .ok_or("PID must be a nonzero decimal u32")?
        }
        _ => {
            return Err(
                "expected snapshot --self, snapshot --pid <decimal-pid>, etw-replay <export.json>, etl <recording.etl>, or etl-check <recording.etl> <closure.json>; use --help".into(),
            )
        }
    };
    let report = ssk_winhost::network_snapshot::snapshot_process(pid)?;
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, &report)?;
    writeln!(out)?;
    Ok(())
}
