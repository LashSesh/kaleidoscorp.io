#![forbid(unsafe_code)]

//! The single-writer daemon lock.
//!
//! # The bug this replaces was a category error
//!
//! The previous lock was `OpenOptions::create_new(true)`, which makes *the
//! file's existence* the lock. Existence is user-space state that only a
//! graceful exit can revoke, so any route out that is not `ctrl_c` — Task
//! Manager, `CTRL_CLOSE`, OOM, a panic, power loss, a future
//! `SERVICE_CONTROL_STOP` — leaves the file behind and bricks the next start
//! with `ERROR_FILE_EXISTS` (`os error 80`). Adding cleanup to more exit paths
//! does not fix that; it only enlarges the set of exits that happen to work.
//!
//! **The lock here is a *handle*, arbitrated by the kernel.**
//!
//! * Windows — the file is opened `write` + `share_mode(FILE_SHARE_READ)`.
//!   A second writer is refused with `ERROR_SHARING_VIOLATION` while the
//!   holder lives; the kernel drops the share on process death, hard kill
//!   included; and a *reader* can still open it to report who holds it.
//! * Unix — `flock(LOCK_EX | LOCK_NB)`. Also released by the kernel on
//!   `SIGKILL`.
//!
//! **The file is never deleted.** Delete-on-exit is what created the
//! asymmetry in the first place, and it introduces a real race (holder A
//! exits and unlinks while waiter B has already opened the path).
//!
//! # PID liveness is deliberately not implemented
//!
//! Every PID-liveness scheme is racy: PID reuse means the answer can be wrong,
//! and there is an unavoidable window between "PID 1234 is dead" and
//! "therefore I may take the lock" into which a second daemon fits. The
//! kernel's handle table has no such window. The pid/exe recorded in the lock
//! file are **diagnostics for the error message only** and are never consulted
//! to decide whether the lock may be taken.
//!
//! # There is no `--force`
//!
//! Under a kernel-arbitrated lock "stale" is not an observable state — the
//! kernel already released it. A failed acquisition therefore always means a
//! live holder, so `--force` could only ever mean "run two daemons against one
//! state dir". `PersistedAuditLedger` is an append-only Blake3 hash chain; two
//! interleaved writers break it permanently (`AUDIT_CHAIN_BROKEN`). What is
//! offered instead is a bounded wait (`--lock-wait`) for the genuine restart
//! race, plus a short unconditional internal retry, because a transient
//! `ERROR_SHARING_VIOLATION` from an AV scanner or the search indexer is real
//! on Windows and is not a daemon.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Schema version of the lock file's JSON body.
pub const LOCK_SCHEMA: u32 = 1;

/// How long acquisition retries before reporting, even when the caller asked
/// for no wait at all. Absorbs a transient scanner/indexer share violation.
pub const INTERNAL_RETRY_BUDGET: Duration = Duration::from_millis(500);

/// Delay between acquisition attempts.
pub const RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[cfg(windows)]
mod share {
    pub const FILE_SHARE_READ: u32 = 0x0000_0001;
    pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;
}

/// Diagnostic contents of the lock file. Written *after* the lock is acquired,
/// read by a loser to name the holder. Never the arbiter of the lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockInfo {
    pub schema: u32,
    pub pid: u32,
    pub exe: String,
    pub started_unix: u64,
    pub state_dir: String,
    pub endpoint: String,
    pub build: String,
}

impl LockInfo {
    /// Describe the current process as the prospective holder.
    #[must_use]
    pub fn for_this_process(state_dir: &Path, endpoint: &str, build: &str) -> Self {
        Self {
            schema: LOCK_SCHEMA,
            pid: std::process::id(),
            exe: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into()),
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            state_dir: state_dir.display().to_string(),
            endpoint: endpoint.to_string(),
            build: build.to_string(),
        }
    }

    /// Whether this record plausibly describes an `sskd` process. Used only to
    /// choose between two *error messages*, never to decide the lock.
    #[must_use]
    pub fn looks_like_sskd(&self) -> bool {
        self.schema == LOCK_SCHEMA
            && Path::new(&self.exe)
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("sskd"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// A live `sskd` holds the lock, and it told us who it is.
    #[error(
        "DAEMON_ALREADY_RUNNING: `{}` is already held by sskd pid {} ({}) serving {}",
        path.display(), holder.pid, holder.exe, holder.endpoint
    )]
    // `holder` is boxed so `LockError` — and therefore every
    // `Result<_, LockError>` in this module — stays small.
    AlreadyRunning {
        path: PathBuf,
        holder: Box<LockInfo>,
    },
    /// Something holds the file open and it is not a daemon we recognise.
    /// Refuse anyway — guessing "probably stale" is how you end up with two
    /// daemons.
    #[error(
        "LOCK_CONTENDED: `{}` is held by another process, but no usable sskd \
         lock record could be read from it ({detail}) — commonly an anti-virus \
         scanner or the search indexer holding the file open",
        path.display()
    )]
    Contended { path: PathBuf, detail: String },
    #[error("failed to open the daemon lock at `{}`: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl LockError {
    /// The stable machine-readable code for this failure.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            LockError::AlreadyRunning { .. } => "DAEMON_ALREADY_RUNNING",
            LockError::Contended { .. } => "LOCK_CONTENDED",
            LockError::Io { .. } => "LOCK_IO_FAILED",
        }
    }
}

/// A held daemon lock. Releasing it means dropping the handle: the kernel does
/// the rest. The lock *file* is intentionally left on disk.
#[derive(Debug)]
pub struct DaemonLock {
    path: PathBuf,
    // Held for its side effect: while this handle is open, the kernel refuses
    // a second exclusive open (Windows) / a second `flock` (Unix). Dropping it
    // — including via process death — is what releases the lock.
    _file: File,
}

impl DaemonLock {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Acquire the daemon lock at `path`, writing `info` into it on success.
///
/// Retries for [`INTERNAL_RETRY_BUDGET`] plus `extra_wait` before giving up.
///
/// # Errors
/// [`LockError::AlreadyRunning`] when a live `sskd` holds it,
/// [`LockError::Contended`] when something else does, and [`LockError::Io`]
/// when the file could not be opened for a reason that is not contention.
pub fn acquire(
    path: &Path,
    info: &LockInfo,
    extra_wait: Duration,
) -> Result<DaemonLock, LockError> {
    let deadline = std::time::Instant::now() + INTERNAL_RETRY_BUDGET + extra_wait;
    let mut last_err;
    loop {
        match try_acquire_once(path) {
            Ok(mut file) => {
                write_info(&mut file, info).map_err(|source| LockError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
                return Ok(DaemonLock {
                    path: path.to_path_buf(),
                    _file: file,
                });
            }
            Err(err) => {
                if !is_contention(&err) {
                    return Err(LockError::Io {
                        path: path.to_path_buf(),
                        source: err,
                    });
                }
                last_err = err;
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(RETRY_INTERVAL);
    }
    let _ = last_err;
    Err(contention_error(path, read_raw(path)))
}

/// Read the lock file's diagnostic record without taking the lock.
///
/// Returns `None` when the file is absent, unreadable, or does not contain a
/// well-formed record. A `Some` result says nothing about liveness — that is
/// what the handle is for.
#[must_use]
pub fn read_holder(path: &Path) -> Option<LockInfo> {
    read_raw(path).and_then(|raw| serde_json::from_slice::<LockInfo>(&raw).ok())
}

/// Classify a failed acquisition from whatever the lock file contained.
/// Pure, so both branches are testable without racing a real holder.
#[must_use]
pub fn contention_error(path: &Path, raw: Option<Vec<u8>>) -> LockError {
    let path = path.to_path_buf();
    let Some(raw) = raw else {
        return LockError::Contended {
            path,
            detail: "the lock file could not be read".into(),
        };
    };
    if raw.is_empty() {
        return LockError::Contended {
            path,
            detail: "the lock file is empty".into(),
        };
    }
    match serde_json::from_slice::<LockInfo>(&raw) {
        Ok(holder) if holder.looks_like_sskd() => LockError::AlreadyRunning {
            path,
            holder: Box::new(holder),
        },
        Ok(holder) => LockError::Contended {
            path,
            detail: format!(
                "the record names `{}` (schema {}), which is not an sskd image",
                holder.exe, holder.schema
            ),
        },
        Err(err) => LockError::Contended {
            path,
            detail: format!("the lock record is malformed: {err}"),
        },
    }
}

fn write_info(file: &mut File, info: &LockInfo) -> std::io::Result<()> {
    let body = serde_json::to_vec(info)?;
    file.set_len(0)?;
    file.write_all(&body)?;
    file.sync_data()
}

#[cfg(windows)]
fn read_raw(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::windows::fs::OpenOptionsExt;
    // The holder opened the file with `FILE_SHARE_READ`, so a reader that
    // itself asks for the widest compatible sharing succeeds against a live
    // holder. This is what lets the loser name the winner.
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(share::FILE_SHARE_READ | share::FILE_SHARE_WRITE | share::FILE_SHARE_DELETE)
        .open(path)
        .ok()?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).ok()?;
    Some(buf)
}

#[cfg(not(windows))]
fn read_raw(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

#[cfg(windows)]
fn try_acquire_once(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    // `create(true)`, not `create_new(true)`: the file's *existence* is not the
    // lock, the handle is. A file left behind by a hard kill is reopened and
    // overwritten, which is precisely the `os error 80` brick this fixes.
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(share::FILE_SHARE_READ)
        .open(path)
}

#[cfg(unix)]
fn try_acquire_once(path: &Path) -> std::io::Result<File> {
    use rustix::fs::{flock, FlockOperation};
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|errno| std::io::Error::from_raw_os_error(errno.raw_os_error()))?;
    Ok(file)
}

#[cfg(not(any(windows, unix)))]
fn try_acquire_once(_path: &Path) -> std::io::Result<File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "no kernel-arbitrated file lock is available on this platform",
    ))
}

/// Whether an open failure means "someone else holds it" rather than a real
/// I/O problem. Only contention is retried, and only contention is reported as
/// a lock conflict — a genuinely unwritable state directory must surface as
/// [`LockError::Io`] rather than be misreported as another daemon.
fn is_contention(err: &std::io::Error) -> bool {
    // ERROR_SHARING_VIOLATION (32) is what Windows returns when the holder's
    // `FILE_SHARE_READ` refuses a second writer; ERROR_LOCK_VIOLATION (33) is
    // its byte-range sibling. ACCESS_DENIED is deliberately *not* here.
    #[cfg(windows)]
    const CONTENTION_OS_ERRORS: &[i32] = &[32, 33];
    // EAGAIN (11 on Linux) / EWOULDBLOCK (35 on the BSDs, macOS included) is
    // exactly what a non-blocking `flock` reports when another open file
    // description holds the lock.
    #[cfg(unix)]
    const CONTENTION_OS_ERRORS: &[i32] = &[11, 35];
    #[cfg(not(any(windows, unix)))]
    const CONTENTION_OS_ERRORS: &[i32] = &[];

    if let Some(code) = err.raw_os_error() {
        if CONTENTION_OS_ERRORS.contains(&code) {
            return true;
        }
    }
    err.kind() == std::io::ErrorKind::WouldBlock
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_for(dir: &Path) -> LockInfo {
        LockInfo {
            schema: LOCK_SCHEMA,
            pid: 9040,
            exe: if cfg!(windows) {
                r"C:\bin\sskd.exe".to_string()
            } else {
                "/usr/bin/sskd".to_string()
            },
            started_unix: 1_785_701_805,
            state_dir: dir.display().to_string(),
            endpoint: "test-endpoint".into(),
            build: "0.1.0".into(),
        }
    }

    #[test]
    fn a_second_acquisition_is_refused_while_the_first_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = info_for(dir.path());
        let _held = acquire(&path, &info, Duration::ZERO).expect("first acquire");
        let err = acquire(&path, &info, Duration::ZERO)
            .expect_err("a second daemon against one state dir must be refused");
        assert_eq!(err.code(), "DAEMON_ALREADY_RUNNING", "{err}");
    }

    #[test]
    fn a_lock_file_left_behind_by_a_hard_kill_does_not_brick_startup() {
        // The literal `os error 80` regression. A killed holder leaves the
        // file on disk with its contents intact and *no* handle; the kernel
        // has already released the lock, so the next start must succeed.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = info_for(dir.path());
        {
            let held = acquire(&path, &info, Duration::ZERO).expect("first acquire");
            assert_eq!(held.path(), path);
        }
        assert!(
            path.exists(),
            "the lock file must survive release: its existence is not the lock"
        );
        let again = acquire(&path, &info, Duration::ZERO)
            .expect("a leftover lock file must never brick the next start");
        assert_eq!(again.path(), path);
    }

    #[test]
    fn the_lock_file_is_never_deleted_on_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = info_for(dir.path());
        drop(acquire(&path, &info, Duration::ZERO).expect("acquire"));
        assert!(path.exists());
    }

    #[test]
    fn the_holder_is_readable_while_the_lock_is_held() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = info_for(dir.path());
        let _held = acquire(&path, &info, Duration::ZERO).expect("acquire");
        let read = read_holder(&path).expect("a live holder must still be readable");
        assert_eq!(read, info);
    }

    #[test]
    fn acquiring_overwrites_a_previous_holders_record_rather_than_appending() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let mut first = info_for(dir.path());
        first.pid = 1;
        drop(acquire(&path, &first, Duration::ZERO).expect("acquire"));
        let mut second = info_for(dir.path());
        second.pid = 2;
        let _held = acquire(&path, &second, Duration::ZERO).expect("acquire");
        assert_eq!(read_holder(&path).expect("record").pid, 2);
    }

    #[test]
    fn contention_with_no_readable_record_is_reported_as_contended_not_stale() {
        let err = contention_error(Path::new("/x/sskd.lock"), None);
        assert_eq!(err.code(), "LOCK_CONTENDED");
    }

    #[test]
    fn contention_with_an_empty_record_is_reported_as_contended() {
        let err = contention_error(Path::new("/x/sskd.lock"), Some(Vec::new()));
        assert_eq!(err.code(), "LOCK_CONTENDED");
    }

    #[test]
    fn contention_with_a_corrupt_record_is_reported_as_contended() {
        let err = contention_error(Path::new("/x/sskd.lock"), Some(b"{not json".to_vec()));
        assert_eq!(err.code(), "LOCK_CONTENDED");
    }

    #[test]
    fn a_record_naming_a_foreign_image_is_contended_not_already_running() {
        let mut info = info_for(Path::new("/x"));
        info.exe = "/usr/bin/notepad".into();
        let raw = serde_json::to_vec(&info).expect("serialize");
        let err = contention_error(Path::new("/x/sskd.lock"), Some(raw));
        assert_eq!(err.code(), "LOCK_CONTENDED");
    }

    #[test]
    fn a_record_from_a_future_schema_is_contended_not_already_running() {
        let mut info = info_for(Path::new("/x"));
        info.schema = LOCK_SCHEMA + 1;
        let raw = serde_json::to_vec(&info).expect("serialize");
        let err = contention_error(Path::new("/x/sskd.lock"), Some(raw));
        assert_eq!(err.code(), "LOCK_CONTENDED");
    }

    #[test]
    fn a_well_formed_sskd_record_names_the_holder_in_the_error() {
        let info = info_for(Path::new("/x"));
        let raw = serde_json::to_vec(&info).expect("serialize");
        let err = contention_error(Path::new("/x/sskd.lock"), Some(raw));
        assert_eq!(err.code(), "DAEMON_ALREADY_RUNNING");
        let rendered = err.to_string();
        assert!(rendered.contains("9040"), "{rendered}");
        assert!(rendered.contains("test-endpoint"), "{rendered}");
    }

    #[test]
    fn read_holder_of_a_missing_file_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_holder(&dir.path().join("absent.lock")).is_none());
    }

    #[test]
    fn for_this_process_records_this_process() {
        let info = LockInfo::for_this_process(Path::new("/state"), "endpoint", "0.1.0");
        assert_eq!(info.pid, std::process::id());
        assert_eq!(info.schema, LOCK_SCHEMA);
        assert_eq!(info.endpoint, "endpoint");
    }

    #[test]
    fn a_bounded_wait_still_reports_rather_than_hanging() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sskd.lock");
        let info = info_for(dir.path());
        let _held = acquire(&path, &info, Duration::ZERO).expect("acquire");
        let started = std::time::Instant::now();
        let err = acquire(&path, &info, Duration::from_millis(200)).expect_err("still held");
        assert_eq!(err.code(), "DAEMON_ALREADY_RUNNING");
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "the requested wait must actually be honoured"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "and it must be bounded"
        );
    }
}
