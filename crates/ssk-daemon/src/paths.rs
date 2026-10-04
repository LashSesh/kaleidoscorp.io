#![forbid(unsafe_code)]

//! Where `sskd` keeps its state, and what it refuses to accept.
//!
//! # Delegation, not duplication
//!
//! The platform mapping itself lives in [`ssk_ipc::paths::state_dir`], and it
//! must stay there: the Windows pipe name is a digest **over the state
//! directory**, so a daemon that resolved its root differently from a client
//! would derive a different pipe name and the two would never meet. This
//! module therefore does not re-derive `%LOCALAPPDATA%` / `$XDG_STATE_HOME`;
//! it applies the *daemon's* policy on top of the shared resolution.
//!
//! # The policy: never the working directory, at any cost
//!
//! `ssk_ipc::paths::state_dir()` is total — it falls back to the historical
//! CWD-relative `.ssk` when the platform's home variable is missing, so that
//! clients keep a value to talk about. A daemon must not accept that. A lock
//! file, an endpoint and a hash-chained audit ledger placed relative to
//! whatever directory the operator happened to `cd` into are not a location;
//! they are a different state directory per invocation.
//!
//! So [`resolve`] fails closed on any non-absolute result — which covers both
//! a relative `$SSK_STATE_DIR` override and the `.ssk` fallback — rather than
//! starting somewhere arbitrary.

use std::path::{Path, PathBuf};

pub use ssk_ipc::Endpoint;

/// The maximum number of bytes a `sockaddr_un.sun_path` can hold *including*
/// its NUL terminator on Linux. A path of `SUN_PATH_MAX - 1` bytes still fits.
pub const SUN_PATH_MAX: usize = 108;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathsError {
    #[error(
        "STATE_DIR_UNRESOLVABLE: the daemon's state directory resolved to `{0}`, which is not \
         absolute. Set SSK_STATE_DIR to an absolute path, or repair the platform's \
         %LOCALAPPDATA% / $XDG_STATE_HOME / $HOME environment. The daemon will not place its \
         lock, endpoint and audit ledger relative to the working directory."
    )]
    NotAbsolute(PathBuf),
    #[error(
        "unix socket path `{path}` is {len} bytes, which does not fit sun_path ({limit} bytes \
         including its NUL terminator), and no usable $XDG_RUNTIME_DIR was available"
    )]
    SocketPathTooLong {
        path: PathBuf,
        len: usize,
        limit: usize,
    },
    /// This build cannot name an endpoint at all, because a provider it needs
    /// does not exist yet. Distinct from the two above so it can never be
    /// mistaken for a misconfiguration the operator could fix.
    #[error("ENDPOINT_UNAVAILABLE: {0}")]
    EndpointUnavailable(String),
}

/// The daemon's state-directory root.
///
/// # Errors
/// [`PathsError::NotAbsolute`] when the shared resolution yields anything the
/// daemon must not use — see the module docs.
pub fn resolve() -> Result<PathBuf, PathsError> {
    accept(ssk_ipc::paths::state_dir())
}

/// The daemon's fail-closed policy, as a pure function over an already
/// resolved candidate. Split out so both branches are testable without
/// mutating the process environment.
///
/// # Errors
/// [`PathsError::NotAbsolute`] for a relative candidate.
pub fn accept(candidate: PathBuf) -> Result<PathBuf, PathsError> {
    if candidate.is_absolute() {
        Ok(candidate)
    } else {
        Err(PathsError::NotAbsolute(candidate))
    }
}

/// The concrete files and directories under a resolved root.
///
/// # Layout note — deliberately flat, and why
///
/// The lock, the socket and the audit ledger sit **directly under the root**
/// rather than in a `run/` subdirectory: `ssk_ipc::paths::socket_path()` is
/// `<state_dir>/sskd.sock` for every client, and
/// `ssk-daemon/tests/round_trip.rs` plus the two `ssk-cli` integration tests
/// poll exactly that path. Moving the socket is a change to the client-visible
/// contract and belongs with `ssk-ipc`, not here. `logs/` and `crash/` are new
/// and daemon-private, so they are nested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    /// Resolve the daemon's layout.
    ///
    /// # Errors
    /// See [`resolve`].
    pub fn resolve() -> Result<Self, PathsError> {
        Ok(Self::at(resolve()?))
    }

    #[must_use]
    pub fn at(root: PathBuf) -> Self {
        Self { root }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Kernel-arbitrated single-writer lock. See [`crate::lock`].
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.root.join("sskd.lock")
    }

    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.root.join("audit.json")
    }

    /// Must stay identical to `ssk_ipc::paths::socket_path()` for the same
    /// root — every client derives its own copy of this path.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.root.join("sskd.sock")
    }

    #[must_use]
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    #[must_use]
    pub fn crash_dir(&self) -> PathBuf {
        self.root.join("crash")
    }
}

/// The endpoint this build will actually bind.
///
/// The return type is [`ssk_ipc::Endpoint`], and that is the mechanism rather
/// than a convention: `main` cannot compute a Unix socket path on Windows and
/// log it. The previous code did exactly that — it logged
/// `ssk_ipc::paths::socket_path()` unconditionally, outside any `cfg`, and
/// then bound a named pipe, so the daemon announced a path it would never
/// bind.
///
/// # Errors
/// On Unix, [`PathsError::SocketPathTooLong`] when neither the state directory
/// nor `$XDG_RUNTIME_DIR` yields a path that fits `sun_path`.
#[cfg(unix)]
pub fn endpoint(layout: &Layout) -> Result<Endpoint, PathsError> {
    unix_socket_path(
        layout.socket_path(),
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
    )
    .map(Endpoint::UnixSocket)
}

/// The endpoint this build will actually bind.
///
/// Windows: `\\.\pipe\kaleidoscorp-sskd-<32 hex>`, where the digest covers the
/// daemon's own SID **and** `layout.root()`. Both inputs are load-bearing:
/// without the SID two users sharing an explicit `SSK_STATE_DIR` would collide,
/// and without the state directory two daemons could not coexist (the fixed
/// global name is what made a second instance die with `ERROR_ACCESS_DENIED`).
///
/// The SID comes from `ssk_winhost::current_user_sid` — Win32 FFI, in the one
/// crate exempt from `unsafe_code = "forbid"`. This is deliberately
/// [`ssk_ipc::paths::named_pipe_name`] against `layout.root()` rather than
/// `default_endpoint`, which re-reads `$SSK_STATE_DIR`: the root the daemon
/// actually locked, logged and put its ledger in is the one the pipe name must
/// be derived from. `main` pins `SSK_STATE_DIR` to that same root before any
/// client can observe it, so the two agree by construction — and a client
/// deriving the name from `default_endpoint` lands on the identical digest.
///
/// # Errors
/// [`PathsError::EndpointUnavailable`] if this process cannot read its own SID.
/// Fail-closed on purpose: the alternatives are inventing a SID or falling back
/// to the unscoped global pipe name that `ssk-ipc` deliberately removed.
#[cfg(windows)]
pub fn endpoint(layout: &Layout) -> Result<Endpoint, PathsError> {
    let sid = ssk_winhost::current_user_sid().map_err(|err| {
        PathsError::EndpointUnavailable(format!(
            "the named pipe is scoped by this daemon's own SID, and it could not be read: {err}. \
             Refusing rather than binding an unscoped pipe name."
        ))
    })?;
    Ok(Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(
        &sid,
        layout.root(),
    )))
}

/// Pick a Unix socket path that fits `sun_path`, falling back to
/// `$XDG_RUNTIME_DIR` when the state directory's path is too long.
///
/// Without this, moving the state directory off the CWD converts a
/// CWD-pollution bug into a *bind failure* for users with long home paths:
/// `.ssk/sskd.sock` is 14 bytes; `$HOME/.local/state/kaleidoscorp/sskd.sock`
/// is not.
///
/// # Errors
/// [`PathsError::SocketPathTooLong`] when neither candidate fits.
pub fn unix_socket_path(
    preferred: PathBuf,
    xdg_runtime: Option<PathBuf>,
) -> Result<PathBuf, PathsError> {
    let len = preferred.as_os_str().len();
    if len < SUN_PATH_MAX {
        return Ok(preferred);
    }
    // `Path::is_absolute` asks the *host* what absolute means, and this
    // function models Unix `sun_path` semantics regardless of where it is
    // compiled (so the boundary is testable from a Windows dev box). A leading
    // `/` is the Unix rule, so that is what is checked.
    if let Some(runtime) = xdg_runtime.filter(|p| p.to_string_lossy().starts_with('/')) {
        let candidate = runtime.join("kaleidoscorp-sskd.sock");
        if candidate.as_os_str().len() < SUN_PATH_MAX {
            return Ok(candidate);
        }
    }
    Err(PathsError::SocketPathTooLong {
        path: preferred,
        len,
        limit: SUN_PATH_MAX,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_candidate_is_accepted() {
        let absolute = std::env::temp_dir().join("ssk-accept");
        assert_eq!(accept(absolute.clone()).expect("accept"), absolute);
    }

    #[test]
    fn the_historical_dot_ssk_fallback_is_refused() {
        // The literal defect: `.ssk` relative to whatever directory the
        // operator happened to be in. `ssk-ipc` keeps it as a total fallback
        // for clients; a daemon must not start there.
        let err = accept(PathBuf::from(".ssk")).expect_err("must refuse");
        assert_eq!(err, PathsError::NotAbsolute(PathBuf::from(".ssk")));
    }

    #[test]
    fn any_relative_override_is_refused() {
        for candidate in ["state", "./state", "../state", "a/b/c"] {
            assert!(
                accept(PathBuf::from(candidate)).is_err(),
                "`{candidate}` must be refused"
            );
        }
    }

    #[test]
    fn the_refusal_message_names_the_override_and_never_suggests_the_cwd() {
        let err = accept(PathBuf::from(".ssk")).expect_err("must refuse");
        let text = err.to_string();
        assert!(text.contains("STATE_DIR_UNRESOLVABLE"), "{text}");
        assert!(text.contains("SSK_STATE_DIR"), "{text}");
    }

    #[test]
    fn the_daemon_layout_agrees_with_the_shared_socket_path() {
        // If these ever disagree, a client polling
        // `ssk_ipc::paths::socket_path()` and a daemon binding
        // `Layout::socket_path()` silently miss each other.
        let root = std::env::temp_dir().join("ssk-layout-agreement");
        let layout = Layout::at(root.clone());
        assert_eq!(layout.socket_path(), root.join("sskd.sock"));
        assert_eq!(layout.lock_path(), root.join("sskd.lock"));
        assert_eq!(layout.audit_path(), root.join("audit.json"));
        assert_eq!(layout.logs_dir(), root.join("logs"));
        assert_eq!(layout.crash_dir(), root.join("crash"));
    }

    #[test]
    fn a_short_socket_path_is_used_as_is() {
        let got = unix_socket_path(PathBuf::from("/home/u/state/sskd.sock"), None).expect("fits");
        assert_eq!(got, PathBuf::from("/home/u/state/sskd.sock"));
    }

    #[test]
    fn an_overlong_socket_path_falls_back_to_xdg_runtime_dir() {
        let long = PathBuf::from(format!("/home/{}/state/sskd.sock", "u".repeat(120)));
        let got = unix_socket_path(long, Some(PathBuf::from("/run/user/1000")))
            .expect("the runtime dir must rescue it");
        assert_eq!(got, PathBuf::from("/run/user/1000/kaleidoscorp-sskd.sock"));
    }

    #[test]
    fn an_overlong_socket_path_with_no_usable_fallback_is_an_error_not_a_truncation() {
        let long = PathBuf::from(format!("/home/{}/state/sskd.sock", "u".repeat(120)));
        let err = unix_socket_path(long, Some(PathBuf::from("relative")))
            .expect_err("must refuse rather than silently truncate");
        assert!(matches!(err, PathsError::SocketPathTooLong { .. }));
    }

    #[test]
    fn the_sun_path_boundary_is_exact() {
        // 107 bytes fits (the 108th is the NUL); 108 does not.
        let fits = PathBuf::from("/".to_string() + &"a".repeat(106));
        assert_eq!(fits.as_os_str().len(), 107);
        assert!(unix_socket_path(fits, None).is_ok());

        let does_not = PathBuf::from("/".to_string() + &"a".repeat(107));
        assert_eq!(does_not.as_os_str().len(), 108);
        assert!(unix_socket_path(does_not, None).is_err());
    }

    /// The exact defect this replaces: a Unix socket path computed outside
    /// any `cfg` and logged as what the daemon was about to bind.
    #[cfg(unix)]
    #[test]
    fn the_host_endpoint_is_a_unix_socket_on_unix() {
        let layout = Layout::at(std::env::temp_dir().join("ssk-endpoint-test"));
        let ep = endpoint(&layout).expect("a unix host must resolve a socket endpoint");
        assert!(matches!(ep, Endpoint::UnixSocket(_)), "{ep:?}");
    }

    /// On Windows the daemon binds a named pipe and must never announce a Unix
    /// socket path it will never bind — the exact defect this function
    /// replaced.
    #[cfg(windows)]
    #[test]
    fn the_host_endpoint_is_a_named_pipe_on_windows() {
        let layout = Layout::at(std::env::temp_dir().join("ssk-endpoint-test"));
        match endpoint(&layout).expect("a windows host must resolve a pipe endpoint") {
            Endpoint::NamedPipe(name) => {
                assert!(name.starts_with(r"\\.\pipe\kaleidoscorp-sskd-"), "{name}");
            }
            Endpoint::UnixSocket(path) => panic!(
                "Windows must never announce the unix socket path {}",
                path.display()
            ),
        }
    }

    /// The property that makes the daemon *reachable*: the name `sskd` binds
    /// and the name a client derives from the same state directory must be
    /// byte-identical. If these ever diverge, `ssk status` connects to nothing
    /// while the daemon listens beside it — which is precisely the P0 finding.
    #[cfg(windows)]
    #[test]
    fn the_daemon_and_a_client_derive_the_same_pipe_name() {
        let root = std::env::temp_dir().join("ssk-endpoint-agreement");
        let layout = Layout::at(root.clone());
        let sid = ssk_winhost::current_user_sid().expect("own sid");
        let bound = endpoint(&layout).expect("endpoint");
        assert_eq!(
            bound,
            Endpoint::NamedPipe(ssk_ipc::paths::named_pipe_name(&sid, &root))
        );
    }
}
