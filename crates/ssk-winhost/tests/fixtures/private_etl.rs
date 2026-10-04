//! Use the real private controller; never start a kernel/network provider.
use std::{
    fs::{self, OpenOptions},
    os::windows::process::CommandExt,
    path::Path,
    process::Command,
};
static FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn write(path: &Path) -> serde_json::Value {
    let _serial = FIXTURE.lock().unwrap();
    let directory = path.with_extension("private-capture");
    let result = Command::new(env!("CARGO_BIN_EXE_ssk-netcapture"))
        .arg("private-fixture")
        .arg(&directory)
        .creation_flags(0x08000000)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let mut input = fs::File::open(directory.join("recording.etl")).unwrap();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    std::io::copy(&mut input, &mut output).unwrap();
    serde_json::from_slice(&fs::read(directory.join("closure.json")).unwrap()).unwrap()
}
