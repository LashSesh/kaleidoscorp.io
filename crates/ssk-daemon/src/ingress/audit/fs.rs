//! The file-system seam of the flow ledger (design 6.4.7, 6.4.8, 6.4.9).
//!
//! Everything the ledger needs from a file system goes through these traits, for
//! two reasons. The first is security: the Unix implementation is dirfd-relative
//! and refuses anything that is not exactly what the daemon created (owner, mode,
//! link count, no symlink), and a trait is where that contract is written down.
//! The second is testing: the writer's durability order (D1 to D6) and its
//! behaviour under a failing disk are asserted against doubles that record calls
//! and inject errors, which a real file system cannot do on demand.
//!
//! Segment names are `seg-<first_seq:020>.jsonl`. No segment is ever renamed and
//! no closed segment is ever truncated or rewritten: the ledger only creates new
//! names and deletes old ones.

use std::io::{self, BufRead};

use crate::ingress::types::UnavailableCode;

/// Why a path is not a store this daemon will use. Never carries a path or a
/// name: the operator hint is built separately, from the configured root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsafeReason {
    /// Not a directory (or a symlink where a directory was required).
    NotDirectory,
    /// Not a regular file (a directory, a symlink, a device, ...).
    NotRegularFile,
    /// Owned by another user than the daemon's effective user.
    WrongOwner,
    /// A group or other write bit on the state root.
    GroupOrOtherWritable,
    /// A group or other permission bit on the ledger directory or a file in it.
    GroupOrOtherAccess,
    /// More than one hard link to a file.
    HardLinked,
}

impl UnsafeReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDirectory => "not_directory",
            Self::NotRegularFile => "not_regular_file",
            Self::WrongOwner => "wrong_owner",
            Self::GroupOrOtherWritable => "group_or_other_writable",
            Self::GroupOrOtherAccess => "group_or_other_access",
            Self::HardLinked => "hard_linked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// The state root is not safe to put a ledger in.
    RootUnsafe(UnsafeReason),
    /// The ledger directory exists and is not what the daemon would have made.
    DirUnsafe(UnsafeReason),
    /// A segment (or the key file) is not what the daemon would have made.
    FileUnsafe(UnsafeReason),
    /// An operation failed; the code is a static label, never an OS message
    /// (which can contain a path).
    Io(&'static str),
    /// This platform has no store yet (the Windows stub).
    Unsupported,
}

impl StoreError {
    /// The code the ingress is unavailable with.
    #[must_use]
    pub const fn unavailable_code(self) -> UnavailableCode {
        match self {
            Self::RootUnsafe(_) => UnavailableCode::AuditRootUnsafe,
            Self::DirUnsafe(_) => UnavailableCode::AuditDirUnsafe,
            Self::FileUnsafe(_) => UnavailableCode::AuditFileUnsafe,
            Self::Io(_) | Self::Unsupported => UnavailableCode::AuditFailed,
        }
    }

    /// What the operator does about it, for the doctor and the status line. The
    /// daemon never repairs a store it did not make: an attacker-owned directory
    /// cannot be repaired, and a repaired-looking one is worse than a refusal.
    #[must_use]
    pub fn operator_hint(self, root: &std::path::Path) -> String {
        let root = root.display();
        match self {
            Self::RootUnsafe(UnsafeReason::GroupOrOtherWritable) => format!(
                "the state directory {root} is writable by group or others; run `chmod go-w {root}` and start sskd again"
            ),
            Self::RootUnsafe(UnsafeReason::WrongOwner) => format!(
                "the state directory {root} belongs to another user; point SSK_STATE_DIR at a directory you own"
            ),
            Self::RootUnsafe(_) => format!(
                "the state directory {root} is not a directory the ingress ledger may use; point SSK_STATE_DIR at a directory you own"
            ),
            Self::DirUnsafe(_) => format!(
                "the ingress ledger directory under {root} is not private to this user (mode 0700, owned by you); inspect it, then move it aside or fix it yourself: sskd never repairs it"
            ),
            Self::FileUnsafe(_) => format!(
                "a file of the ingress ledger under {root} is not a private regular file of this user with a single link; inspect it, then move it aside: sskd never repairs it"
            ),
            Self::Io(code) => format!("the ingress ledger under {root} could not be used ({code})"),
            Self::Unsupported => {
                "the ingress ledger has no store on this platform yet".to_owned()
            }
        }
    }

    /// A static label for logs and counters.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RootUnsafe(_) => "AUDIT_ROOT_UNSAFE",
            Self::DirUnsafe(_) => "AUDIT_DIR_UNSAFE",
            Self::FileUnsafe(_) => "AUDIT_FILE_UNSAFE",
            Self::Io(code) => code,
            Self::Unsupported => "AUDIT_STORE_UNSUPPORTED",
        }
    }
}

/// The label for an I/O error: the OS message can contain a path, so only a
/// class is kept.
#[must_use]
pub fn io_code(error: &io::Error) -> &'static str {
    match error.kind() {
        io::ErrorKind::StorageFull => "AUDIT_DISK_FULL",
        io::ErrorKind::PermissionDenied => "AUDIT_PERMISSION_DENIED",
        io::ErrorKind::NotFound => "AUDIT_NOT_FOUND",
        io::ErrorKind::AlreadyExists => "AUDIT_ALREADY_EXISTS",
        _ => "AUDIT_IO",
    }
}

/// `seg-` + 20 digits + `.jsonl`.
#[must_use]
pub fn segment_name(first_seq: u64) -> String {
    format!("seg-{first_seq:020}.jsonl")
}

/// The first sequence number a segment name carries; `None` for any other name
/// (and for 20 digits that do not fit a `u64`).
#[must_use]
pub fn parse_segment_name(name: &str) -> Option<u64> {
    let digits = name.strip_prefix("seg-")?.strip_suffix(".jsonl")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The directory entries, as the store found them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Segments {
    /// First sequence numbers of the segments, ascending.
    pub first_seqs: Vec<u64>,
    /// Entries whose name is not a segment name. Ignored, and counted for the
    /// doctor.
    pub ignored: usize,
}

/// What `fstat` of the open file says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveStat {
    pub len: u64,
    pub nlink: u64,
}

/// A segment open for reading: at most `len` bytes (its length when it was
/// opened) can be read from it, so a concurrent append is never half-read.
pub struct SegmentReader {
    pub len: u64,
    pub reader: Box<dyn BufRead + Send>,
}

/// The segment that is appended to.
pub trait ActiveSegment: Send + 'static {
    /// One write of `bytes` to a handle opened for append.
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn sync_data(&mut self) -> io::Result<()>;
    /// Data and metadata (a new file's size must be durable before the
    /// directory entry is relied on).
    fn sync_all(&mut self) -> io::Result<()>;
    /// `fstat` of the OPEN handle, not of the path: a file that was unlinked or
    /// appended to behind the writer's back shows here.
    fn stat(&self) -> io::Result<ActiveStat>;
    /// Cuts the file to `len` (a torn tail, or a failed batch).
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

/// An opened, verified ledger directory.
pub trait LedgerStore: Send + 'static {
    /// `true` when `open_store` made the directory (and made it durable).
    fn created(&self) -> bool;
    fn segments(&self) -> Result<Segments, StoreError>;
    fn open_reader(&self, first_seq: u64) -> Result<SegmentReader, StoreError>;
    fn open_active(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError>;
    /// `O_CREAT|O_EXCL`: an existing name is an error, never reused.
    fn create_segment(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError>;
    /// Unlinks a segment. A missing one is an error the caller classifies.
    fn remove_segment(&self, first_seq: u64) -> io::Result<()>;
    /// Makes directory entries (a created or removed segment) durable.
    fn sync_dir(&self) -> io::Result<()>;
}

/// The entry point: where a store is opened.
pub trait LedgerFs: Send + Sync + 'static {
    /// D1: creates the ledger directory if it is missing, verifies it, makes it
    /// durable; refuses anything unsafe (6.4.9). Blocking.
    fn open_store(&self) -> Result<Box<dyn LedgerStore>, StoreError>;
    /// `true` when this implementation makes the checks of 6.4.9; feeds
    /// `Controls.private_audit_store`.
    fn is_private_store(&self) -> bool;
    /// Reads the destination key file in the state root (design 6.4.10): the file
    /// is opened `O_NOFOLLOW` and must be a regular file of this user, private,
    /// with one link. `Ok(None)` when it does not exist. At most
    /// [`KEY_FILE_READ_MAX`] bytes are returned, so a file of any other length
    /// reaches the parser as a length it refuses. Blocking.
    fn read_key_file(&self) -> Result<Option<Vec<u8>>, StoreError>;
    /// D3: creates the key file exclusively with mode 0600, writes `bytes`,
    /// `sync_all`, then makes the state root's entry durable. An existing name is
    /// `Io("AUDIT_ALREADY_EXISTS")`, whatever it holds. A file that was created
    /// and could not be completed is removed again. Blocking.
    fn create_key_file(&self, bytes: &[u8]) -> Result<(), StoreError>;
}

/// What the writer's rotation and prune need from the active segment and the
/// directory together (design 6.4.7). Implemented over a `LedgerStore` by the
/// rotation commit and by fault-injection doubles in tests.
pub trait LedgerIo: Send + 'static {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn sync_data(&mut self) -> io::Result<()>;
    fn active_stat(&self) -> io::Result<ActiveStat>;
    fn truncate_active(&mut self, len: u64) -> io::Result<()>;
    /// Create, write, `sync_all`, `sync_dir`, switch.
    fn rotate(&mut self, next_first_seq: u64, first_record: &[u8]) -> io::Result<()>;
    /// Per-file failure is reported in the outcome, not as an error.
    fn prune(&mut self, keep: u32) -> io::Result<PruneOutcome>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    /// The first sequence number that survives, when something was pruned.
    pub pruned_before_seq: Option<u64>,
    /// Files that could not be removed and are kept.
    pub deferred: u32,
}

/// The ledger directory below a state root.
pub const LEDGER_DIR: &str = "ingress-audit";

/// The destination key file, a sibling of the ledger directory.
pub const KEY_FILE_NAME: &str = "ingress-dest.key";

/// A key file is 65 bytes; one more is read so that a longer file is seen as
/// longer and never mistaken for a valid one.
pub const KEY_FILE_READ_MAX: u64 = 66;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_is_reduced_to_a_class_and_never_carries_its_message() {
        for (kind, code) in [
            (io::ErrorKind::StorageFull, "AUDIT_DISK_FULL"),
            (io::ErrorKind::PermissionDenied, "AUDIT_PERMISSION_DENIED"),
            (io::ErrorKind::NotFound, "AUDIT_NOT_FOUND"),
            (io::ErrorKind::AlreadyExists, "AUDIT_ALREADY_EXISTS"),
            (io::ErrorKind::Other, "AUDIT_IO"),
            (io::ErrorKind::InvalidData, "AUDIT_IO"),
            (io::ErrorKind::Interrupted, "AUDIT_IO"),
        ] {
            let error = io::Error::new(kind, "/home/someone/.local/state/secret-path failed");
            assert_eq!(io_code(&error), code, "{kind:?}");
            assert!(!code.contains('/'), "{code}");
        }
    }

    #[test]
    fn every_store_error_has_a_stable_code_and_an_unavailable_code() {
        use crate::ingress::types::UnavailableCode as U;
        let reasons = [
            UnsafeReason::NotDirectory,
            UnsafeReason::NotRegularFile,
            UnsafeReason::WrongOwner,
            UnsafeReason::GroupOrOtherWritable,
            UnsafeReason::GroupOrOtherAccess,
            UnsafeReason::HardLinked,
        ];
        let names: Vec<&str> = reasons.iter().map(|reason| reason.as_str()).collect();
        assert_eq!(
            names,
            [
                "not_directory",
                "not_regular_file",
                "wrong_owner",
                "group_or_other_writable",
                "group_or_other_access",
                "hard_linked"
            ]
        );
        for reason in reasons {
            assert_eq!(StoreError::RootUnsafe(reason).code(), "AUDIT_ROOT_UNSAFE");
            assert_eq!(StoreError::DirUnsafe(reason).code(), "AUDIT_DIR_UNSAFE");
            assert_eq!(StoreError::FileUnsafe(reason).code(), "AUDIT_FILE_UNSAFE");
            assert_eq!(
                StoreError::RootUnsafe(reason).unavailable_code(),
                U::AuditRootUnsafe
            );
            assert_eq!(
                StoreError::DirUnsafe(reason).unavailable_code(),
                U::AuditDirUnsafe
            );
            assert_eq!(
                StoreError::FileUnsafe(reason).unavailable_code(),
                U::AuditFileUnsafe
            );
        }
        assert_eq!(StoreError::Io("AUDIT_IO").code(), "AUDIT_IO");
        assert_eq!(StoreError::Unsupported.code(), "AUDIT_STORE_UNSUPPORTED");
    }

    #[test]
    fn each_hint_says_what_the_operator_does() {
        let root = std::path::Path::new("/state");
        let hint = |error: StoreError| error.operator_hint(root);
        let writable = hint(StoreError::RootUnsafe(UnsafeReason::GroupOrOtherWritable));
        assert!(writable.contains("chmod go-w /state"), "{writable}");
        let owner = hint(StoreError::RootUnsafe(UnsafeReason::WrongOwner));
        assert!(
            owner.contains("SSK_STATE_DIR") && owner.contains("another user"),
            "{owner}"
        );
        let other_root = hint(StoreError::RootUnsafe(UnsafeReason::NotDirectory));
        assert!(
            other_root.contains("SSK_STATE_DIR") && !other_root.contains("another user"),
            "{other_root}"
        );
        let dir = hint(StoreError::DirUnsafe(UnsafeReason::GroupOrOtherAccess));
        assert!(
            dir.contains("0700") && dir.contains("never repairs"),
            "{dir}"
        );
        let file = hint(StoreError::FileUnsafe(UnsafeReason::HardLinked));
        assert!(
            file.contains("single link") && file.contains("never repairs"),
            "{file}"
        );
        let io = hint(StoreError::Io("AUDIT_DISK_FULL"));
        assert!(
            io.contains("AUDIT_DISK_FULL") && io.contains("/state"),
            "{io}"
        );
        assert!(hint(StoreError::Unsupported).contains("platform"));
        // Nothing the hint adds is a word the ingress never says.
        for text in [writable, owner, other_root, dir, file, io] {
            assert_eq!(
                crate::ingress::types::contains_forbidden_word(&text),
                None,
                "{text}"
            );
        }
    }
}
