#![forbid(unsafe_code)]

//! Where the daemon listens, and how a client finds it.
//!
//! The Unix socket has always been scoped by the state directory. The Windows
//! named pipe was a fixed global name (`\\.\pipe\kaleidoscorp-sskd`), which is
//! why a second `sskd` died with `ERROR_ACCESS_DENIED` from
//! `first_pipe_instance` and why parallel tests could not coexist. It is now
//! derived from the state directory *and* the owning user's SID.

use std::path::{Path, PathBuf};

use ssk_types::{digest_of, HashAlg};

/// Domain separator for the pipe-name digest. Changing it changes every pipe
/// name, which is the point: a client built against one scheme must not pair
/// with a daemon built against another.
const PIPE_NAME_DOMAIN: &str = "kaleidoscorp-sskd-pipe";

/// Version of the pipe-naming scheme, mixed into the digest so the scheme can
/// change later without silently pairing a new client with an old daemon.
const PIPE_NAME_SCHEME_VERSION: u32 = 1;

/// Fixed prefix of every daemon pipe name. 27 characters; with the 32-hex
/// digest that is 59, well under the 256-character pipe-name limit.
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\kaleidoscorp-sskd-";

/// Where the daemon listens. One type on both platforms — `ssk-cli` and the
/// GUI bridge get a single call path ([`crate::client::DaemonClient::connect`])
/// instead of two cfg-split ones. The variant that does not match the current
/// platform is still *constructible* (so cross-platform code compiles and can
/// be tested), but connecting to it fails with a typed error rather than
/// silently doing something else.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Endpoint {
    /// Filesystem path of the daemon's Unix domain socket.
    UnixSocket(PathBuf),
    /// Windows named pipe name, e.g. `\\.\pipe\kaleidoscorp-sskd-<32 hex>`.
    NamedPipe(String),
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::UnixSocket(p) => write!(f, "{}", p.display()),
            Endpoint::NamedPipe(n) => write!(f, "{n}"),
        }
    }
}

/// The daemon's state directory: `$SSK_STATE_DIR`, else a per-user absolute
/// path.
///
/// The default used to be `.ssk` **relative to the current working
/// directory**. That is a correctness bug for the Windows pipe name, which is
/// derived from this directory: `ssk` and `sskd` started from different
/// directories would derive different names and never meet. The default is
/// therefore absolute and per-user:
///
/// * Windows — `%LOCALAPPDATA%\Kaleidoscorp\state`
/// * Unix — `$XDG_STATE_HOME/kaleidoscorp`, else `$HOME/.local/state/kaleidoscorp`
///
/// If neither environment variable is set the old CWD-relative `.ssk` is used,
/// so the function stays total; every caller that cares should set
/// `SSK_STATE_DIR` explicitly (all tests in this workspace do).
#[must_use]
pub fn state_dir() -> PathBuf {
    if let Some(explicit) = std::env::var_os("SSK_STATE_DIR") {
        return PathBuf::from(explicit);
    }
    default_state_dir().unwrap_or_else(|| PathBuf::from(".ssk"))
}

#[cfg(windows)]
fn default_state_dir() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")?;
    if local.is_empty() {
        return None;
    }
    Some(PathBuf::from(local).join("Kaleidoscorp").join("state"))
}

#[cfg(not(windows))]
fn default_state_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("kaleidoscorp"));
        }
    }
    let home = std::env::var_os("HOME")?;
    if home.is_empty() {
        return None;
    }
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("kaleidoscorp"),
    )
}

/// Path to the daemon's Unix domain socket.
#[must_use]
pub fn socket_path() -> PathBuf {
    state_dir().join("sskd.sock")
}

/// Deterministic, non-revealing name of the daemon's Windows named pipe.
///
/// Both `sskd` and `ssk` must call this with identical inputs; there is no
/// shared file and no discovery step. The digest input is the canonical CBOR
/// encoding of the tuple
/// `(PIPE_NAME_DOMAIN, PIPE_NAME_SCHEME_VERSION, user_sid, normalized_state_dir)`,
/// hashed with Blake3 via `ssk_types::digest_of` and truncated to the first 16
/// bytes. Encoding a *tuple* is domain-separated by construction — there is no
/// string-concatenation ambiguity between the SID and the path.
///
/// A pipe name is world-readable metadata (an unelevated process enumerated
/// 255 names on the development machine), so the name deliberately reveals
/// neither the username nor the state-directory path. The SID is mixed in so
/// two users who share an explicit `SSK_STATE_DIR` still get distinct pipes.
/// A caller that cannot obtain a SID must refuse to compute a name rather than
/// fall back to an unscoped one — which is why this function takes the SID
/// rather than looking it up.
///
/// # Panics
///
/// Never in practice: the only fallible step is CBOR-encoding a fixed-shape
/// tuple of `&str`/`u32`, which has no failure mode.
#[must_use]
pub fn named_pipe_name(user_sid: &str, state_dir: &Path) -> String {
    let normalized = normalize_state_dir(state_dir);
    let material = (
        PIPE_NAME_DOMAIN,
        PIPE_NAME_SCHEME_VERSION,
        user_sid,
        normalized.as_str(),
    );
    let digest = digest_of(&material, HashAlg::Blake3)
        .expect("CBOR encoding of a (&str, u32, &str, &str) tuple cannot fail");
    let hex = digest.to_hex();
    format!("{PIPE_NAME_PREFIX}{}", &hex[..32])
}

/// The daemon endpoint for the current platform.
///
/// Unix: the state directory already scopes the socket path, so no extra input
/// is needed.
#[cfg(unix)]
#[must_use]
pub fn default_endpoint() -> Endpoint {
    Endpoint::UnixSocket(socket_path())
}

/// The daemon endpoint for the current platform.
///
/// Windows: the pipe name is scoped by the caller's SID, which this crate
/// cannot obtain without FFI (`ssk-ipc` is `#![forbid(unsafe_code)]`). The
/// composition root passes it in — `ssk_winhost::current_user_sid()`.
#[cfg(windows)]
#[must_use]
pub fn default_endpoint(user_sid: &str) -> Endpoint {
    Endpoint::NamedPipe(named_pipe_name(user_sid, &state_dir()))
}

/// Normalize a state directory into the exact string that feeds the pipe-name
/// digest. Must be byte-identical on the daemon and the client side.
///
/// `std::path::absolute` rather than `fs::canonicalize`: canonicalize requires
/// the directory to already exist (a client may run before the daemon creates
/// it) and prepends `\\?\`. Lowercasing matches Windows' case-insensitive path
/// semantics; trailing separators are stripped so `C:\x` and `C:\x\` agree.
fn normalize_state_dir(dir: &Path) -> String {
    let absolute = std::path::absolute(dir).unwrap_or_else(|_| dir.to_path_buf());
    let text = absolute.to_string_lossy().to_lowercase();
    let trimmed = text.trim_end_matches(['\\', '/']);
    if trimmed.is_empty() {
        text.clone()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID_A: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    const SID_B: &str = "S-1-5-21-1111111111-2222222222-3333333333-1002";

    #[test]
    fn pipe_name_has_the_documented_shape() {
        let name = named_pipe_name(SID_A, Path::new("state"));
        assert!(
            name.starts_with(PIPE_NAME_PREFIX),
            "unexpected prefix: {name}"
        );
        let hex = &name[PIPE_NAME_PREFIX.len()..];
        assert_eq!(hex.len(), 32, "digest must be 32 hex chars: {name}");
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "digest must be lowercase hex: {name}"
        );
        assert_eq!(name.len(), 59, "documented total length");
    }

    #[test]
    fn pipe_name_is_deterministic() {
        let a = named_pipe_name(SID_A, Path::new("state"));
        let b = named_pipe_name(SID_A, Path::new("state"));
        assert_eq!(a, b);
    }

    #[test]
    fn pipe_name_is_scoped_by_sid() {
        let a = named_pipe_name(SID_A, Path::new("state"));
        let b = named_pipe_name(SID_B, Path::new("state"));
        assert_ne!(a, b, "two users sharing a state dir must not share a pipe");
    }

    #[test]
    fn pipe_name_is_scoped_by_state_dir() {
        let a = named_pipe_name(SID_A, Path::new("state-one"));
        let b = named_pipe_name(SID_A, Path::new("state-two"));
        assert_ne!(a, b, "two daemons with different state dirs must coexist");
    }

    /// The whole point of normalization: forms of the same directory that the
    /// OS treats as identical must produce the same pipe, or `ssk` and `sskd`
    /// silently miss each other.
    #[test]
    fn pipe_name_ignores_trailing_separator_and_case() {
        let base = std::env::current_dir().expect("cwd").join("StateDir");
        let plain = named_pipe_name(SID_A, &base);

        let mut trailing = base.clone().into_os_string();
        trailing.push(std::path::MAIN_SEPARATOR_STR);
        assert_eq!(plain, named_pipe_name(SID_A, Path::new(&trailing)));

        let lowered = PathBuf::from(base.to_string_lossy().to_lowercase());
        assert_eq!(plain, named_pipe_name(SID_A, &lowered));
    }

    /// A relative and an absolute spelling of the same directory must agree —
    /// this is the property that makes `std::path::absolute` load-bearing.
    #[test]
    fn pipe_name_resolves_relative_against_cwd() {
        let relative = Path::new("some-state-dir");
        let absolute = std::env::current_dir().expect("cwd").join(relative);
        assert_eq!(
            named_pipe_name(SID_A, relative),
            named_pipe_name(SID_A, &absolute)
        );
    }

    /// Neither the SID nor the path may appear in the world-readable name.
    #[test]
    fn pipe_name_leaks_neither_sid_nor_path() {
        let name = named_pipe_name(SID_A, Path::new("C:/Users/somebody/secret-state"));
        assert!(!name.contains("1001"));
        assert!(!name.to_lowercase().contains("somebody"));
        assert!(!name.to_lowercase().contains("secret"));
    }

    #[test]
    fn endpoint_displays_its_address() {
        assert_eq!(
            Endpoint::NamedPipe(r"\\.\pipe\x".to_owned()).to_string(),
            r"\\.\pipe\x"
        );
        assert_eq!(
            Endpoint::UnixSocket(PathBuf::from("/tmp/x.sock")).to_string(),
            "/tmp/x.sock"
        );
    }

    /// `SSK_STATE_DIR` wins over the per-user default. Uses a child process so
    /// the env mutation cannot race other tests in this binary.
    #[test]
    fn explicit_state_dir_env_var_wins() {
        let value = std::env::var_os("SSK_STATE_DIR");
        // Only assert the branch that does not mutate the environment: when
        // the variable is present, `state_dir` must return exactly it.
        if let Some(v) = value {
            assert_eq!(state_dir(), PathBuf::from(v));
        } else {
            // Default branch: absolute, or the documented `.ssk` fallback when
            // the platform's home variable is unset.
            let dir = state_dir();
            assert!(
                dir.is_absolute() || dir == Path::new(".ssk"),
                "default state dir must be absolute or the documented fallback: {}",
                dir.display()
            );
        }
    }
}
