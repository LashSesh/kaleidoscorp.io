#![forbid(unsafe_code)]

use std::path::PathBuf;

/// The daemon's state directory: `$SSK_STATE_DIR`, or `.ssk` relative to the
/// current working directory (matching `ssk-cli`'s existing `.ssk/metrics.json`
/// convention). Shared by `sskd` (which creates it) and any client (which
/// must agree on where to find the socket).
#[must_use]
pub fn state_dir() -> PathBuf {
    std::env::var_os("SSK_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".ssk"))
}

/// Path to the daemon's Unix domain socket.
#[must_use]
pub fn socket_path() -> PathBuf {
    state_dir().join("sskd.sock")
}

/// Name of the daemon's Windows named pipe.
#[must_use]
pub fn named_pipe_name() -> &'static str {
    r"\\.\pipe\kaleidoscorp-sskd"
}
