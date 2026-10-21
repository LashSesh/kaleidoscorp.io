// Standalone harmless management peer, compiled only by Windows launch tests.
// It opens loopback TCP, reads fixture launch files, and never touches OS VPNs.
use std::{env, fs, io::{BufRead, BufReader, Write}, net::TcpStream, process, thread, time::Duration};
fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 || args[1] != "--config" { process::exit(2); }
    if env::var("OPENSSL_CONF").ok().as_deref() != Some("NUL") || env::var_os("PATH").is_some() || env::var_os("SystemRoot").is_none() { process::exit(3); }
    let config = fs::read_to_string(&args[2]).expect("fixture configuration");
    let mode = config.lines().find_map(|l| l.strip_prefix("verify-x509-name ")).unwrap().split_whitespace().next().unwrap();
    if mode == "execution-marker" {
        fs::write(std::path::Path::new(&args[2]).with_extension("executed"), b"executed").unwrap();
        thread::sleep(Duration::from_secs(5)); return;
    }
    if mode == "exit-early" { process::exit(23); }
    if mode == "never-connect" { thread::sleep(Duration::from_secs(5)); return; }
    for required in ["management-client", "management-hold", "script-security 0", "ifconfig-noexec", "route-noexec"] {
        if !config.lines().any(|l| l == required) { process::exit(4); }
    }
    let management = config.lines().find_map(|l| l.strip_prefix("management 127.0.0.1 ")).unwrap();
    let (port, path) = management.split_once(' ').unwrap();
    let path = path.strip_prefix('"').unwrap().strip_suffix('"').unwrap().replace("\\\\", "\\");
    let secret = fs::read_to_string(path).expect("fixture password file");
    if secret.trim_end().len() != 64 { process::exit(5); }
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).expect("fixture management connect");
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut peer = BufReader::new(stream);
    peer.get_mut().write_all(b"ENTER PASS").unwrap();
    peer.get_mut().write_all(b"WORD:").unwrap();
    let mut received = String::new(); peer.read_line(&mut received).unwrap();
    if received != secret { process::exit(6); }
    if mode == "reject-auth" { peer.get_mut().write_all(b"ERROR: bad password\n").unwrap(); thread::sleep(Duration::from_secs(5)); return; }
    peer.get_mut().write_all(b"SUCCESS: password is correct\n>HOLD:Waiting for hold release:0\n").unwrap();
    let mut stop_ignored = false;
    loop {
        received.clear();
        if peer.read_line(&mut received).unwrap_or(0) == 0 {
            // A process that ignores the stop signal does not exit because its management
            // peer went away; only OS termination may end it. Exiting on EOF here raced the
            // controller's terminate (it closes the channel first) and could win under load
            // with a clean exit code 0, which is not the scenario `ignore-stop` stands for.
            if stop_ignored { thread::sleep(Duration::from_secs(5)); }
            return;
        }
        match received.as_str() {
            "pid\n" => { let pid = process::id() + u32::from(mode == "wrong-pid"); writeln!(peer.get_mut(), "SUCCESS: pid={pid}").unwrap(); }
            "state on\n" => {
                peer.get_mut().write_all(b"SUCCESS: real-time state notification set to ON\n").unwrap();
                if mode == "false-connected" { peer.get_mut().write_all(b">STATE:1,CONNECTED,SUCCESS,10.0.0.2\n").unwrap(); }
            }
            "signal SIGTERM\n" => { peer.get_mut().write_all(b"SUCCESS: signal SIGTERM thrown\n").unwrap(); if mode != "ignore-stop" { return; } stop_ignored = true; }
            // Receiving release in this fixture is a test failure, never a fake tunnel.
            _ => process::exit(99),
        }
    }
}
