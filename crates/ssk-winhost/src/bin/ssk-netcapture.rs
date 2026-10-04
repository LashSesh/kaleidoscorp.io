//! Explicit test activity, kept separate from the read-only diagnostic CLI.
#![forbid(unsafe_code)]
use ssk_winhost::network_etw::capture;
use std::io::Write;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::from(2)
        }
    }
}

fn print(value: &impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [verb, path] if verb == "--private-capture-worker" => {
            capture::private_worker(path.as_ref()).map_err(Into::into)
        }
        [verb] if verb == "--help" || verb == "-h" => {
            println!("Usage: ssk-netcapture plan\n       ssk-netcapture private-fixture <new-directory>\n       ssk-netcapture traffic\nplan: read-only, system capture remains unavailable.\nprivate-fixture: synthetic events in a contained child; 8 events, 1 MiB file cap, 1 s cooperative budget.\nSupervisor: 5 s worker deadline plus <=1 s exit observation, 256 MiB process commit, no descendants.\ntraffic: eight fixed 128-byte request/reply exchanges for TCP/UDP on IPv4/IPv6 loopback; 3 s cooperative budget.\nNo kernel/network ETW session, policy change or external traffic.\nExit 0: JSON report produced; inspect status. Exit 2: invalid input or capture failure.");
            Ok(())
        }
        [verb] if verb == "plan" => print(&capture::system_plan()),
        [verb] if verb == "traffic" => print(&capture::traffic::run()),
        [verb, path] if verb == "private-fixture" => {
            print(&capture::private_fixture(path.as_ref())?)
        }
        _ => Err("expected plan, private-fixture <new-directory>, or traffic; use --help".into()),
    }
}
