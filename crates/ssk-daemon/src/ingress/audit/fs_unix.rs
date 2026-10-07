//! The Unix ledger store (design 6.4.9): `rustix`, dirfd-relative, no symlink is
//! ever followed, and nothing is used that is not exactly what this daemon would
//! have made.
//!
//! * The state root is opened once (`O_DIRECTORY|O_NOFOLLOW` on the canonicalised
//!   path, so a symlink the operator set up on purpose keeps working), and must be
//!   owned by the effective user with no group or other write bit. A missing root
//!   is created private by `paths::ensure_state_root`; an existing one that is
//!   writable by others is refused, never repaired.
//! * The ledger directory is made with `mkdirat(root_fd, .., 0700)` and opened
//!   through the root's descriptor, then checked: a directory, owned by the
//!   effective user, `mode & 0o077 == 0`. From then on it is addressed only
//!   through its descriptor, so a later swap of the path cannot redirect a write.
//! * Every segment is opened with `O_NOFOLLOW` relative to that descriptor and
//!   checked: a regular file, owned by the effective user, `mode & 0o077 == 0`,
//!   exactly one link. A new one is created `O_CREAT|O_EXCL`, mode 0600.
//!
//! `geteuid`, not `getuid`: the files this process creates are owned by its
//! effective user. (The peer check uses `getuid` like the IPC layer, and is off
//! when the two differ, so the two conventions never disagree silently.)
//!
//! File systems that do not enforce Unix modes report permissive bits and are
//! refused: the checks fail closed.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

use rustix::fs::{
    fstat, fsync, mkdirat, openat, statat, unlinkat, AtFlags, Dir, FileType, Mode, OFlags, Stat,
    CWD,
};
use rustix::io::Errno;

use super::fs::{
    io_code, parse_segment_name, segment_name, ActiveSegment, ActiveStat, LedgerFs, LedgerStore,
    SegmentReader, Segments, StoreError, UnsafeReason, KEY_FILE_NAME, KEY_FILE_READ_MAX,
    LEDGER_DIR,
};

/// What the checks look at, separated from `Stat` so the table can be tested
/// without a file system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Facts {
    pub is_dir: bool,
    pub is_file: bool,
    pub mode: u32,
    pub uid: u32,
    pub nlink: u64,
}

impl Facts {
    // `st_mode` and `st_nlink` are wider or narrower than `u32` and `u64` on
    // other Unixes; the conversion is a no-op only on Linux.
    #[allow(clippy::useless_conversion)]
    fn of(stat: &Stat) -> Self {
        let kind = FileType::from_raw_mode(stat.st_mode);
        Self {
            is_dir: kind == FileType::Directory,
            is_file: kind == FileType::RegularFile,
            mode: u32::from(stat.st_mode) & 0o7777,
            uid: stat.st_uid,
            nlink: u64::from(stat.st_nlink),
        }
    }
}

/// The state root: a directory of the effective user that no one else can write.
pub(super) fn check_root(facts: Facts, euid: u32) -> Result<(), UnsafeReason> {
    if !facts.is_dir {
        Err(UnsafeReason::NotDirectory)
    } else if facts.uid != euid {
        Err(UnsafeReason::WrongOwner)
    } else if facts.mode & 0o022 != 0 {
        Err(UnsafeReason::GroupOrOtherWritable)
    } else {
        Ok(())
    }
}

/// The ledger directory: a directory of the effective user, private.
pub(super) fn check_dir(facts: Facts, euid: u32) -> Result<(), UnsafeReason> {
    if !facts.is_dir {
        Err(UnsafeReason::NotDirectory)
    } else if facts.uid != euid {
        Err(UnsafeReason::WrongOwner)
    } else if facts.mode & 0o077 != 0 {
        Err(UnsafeReason::GroupOrOtherAccess)
    } else {
        Ok(())
    }
}

/// A segment: a regular file of the effective user, private, with one link.
pub(super) fn check_file(facts: Facts, euid: u32) -> Result<(), UnsafeReason> {
    if !facts.is_file {
        Err(UnsafeReason::NotRegularFile)
    } else if facts.uid != euid {
        Err(UnsafeReason::WrongOwner)
    } else if facts.mode & 0o077 != 0 {
        Err(UnsafeReason::GroupOrOtherAccess)
    } else if facts.nlink != 1 {
        Err(UnsafeReason::HardLinked)
    } else {
        Ok(())
    }
}

fn io_error(errno: Errno) -> StoreError {
    StoreError::Io(io_code(&io::Error::from(errno)))
}

/// A failed `O_NOFOLLOW` open: the kernel says `ELOOP` for a symlink and
/// `ENOTDIR` for a non-directory under `O_DIRECTORY`; both mean "not what the
/// daemon made".
fn unsafe_open(errno: Errno, unsafe_error: StoreError) -> StoreError {
    if matches!(errno, Errno::LOOP | Errno::NOTDIR) {
        unsafe_error
    } else {
        io_error(errno)
    }
}

/// The store below one state root.
#[derive(Debug, Clone)]
pub struct UnixLedgerFs {
    root: PathBuf,
}

impl UnixLedgerFs {
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl UnixLedgerFs {
    /// The state root, opened once and checked (design 6.4.9, item 1).
    fn open_root(&self) -> Result<(std::os::fd::OwnedFd, u32), StoreError> {
        let euid = rustix::process::geteuid().as_raw();
        // A symlinked root that the operator set up on purpose keeps working: it
        // is resolved once, here, and then only the descriptor is used.
        let root =
            std::fs::canonicalize(&self.root).map_err(|error| StoreError::Io(io_code(&error)))?;
        let root_fd = openat(
            CWD,
            &root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| unsafe_open(errno, StoreError::RootUnsafe(UnsafeReason::NotDirectory)))?;
        let stat = fstat(&root_fd).map_err(io_error)?;
        check_root(Facts::of(&stat), euid).map_err(StoreError::RootUnsafe)?;
        Ok((root_fd, euid))
    }
}

impl LedgerFs for UnixLedgerFs {
    fn open_store(&self) -> Result<Box<dyn LedgerStore>, StoreError> {
        let (root_fd, euid) = self.open_root()?;
        let created = match mkdirat(&root_fd, LEDGER_DIR, Mode::RWXU) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(errno) => return Err(io_error(errno)),
        };
        let dir_fd = openat(
            &root_fd,
            LEDGER_DIR,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| unsafe_open(errno, StoreError::DirUnsafe(UnsafeReason::NotDirectory)))?;
        let stat = fstat(&dir_fd).map_err(io_error)?;
        check_dir(Facts::of(&stat), euid).map_err(StoreError::DirUnsafe)?;
        if created {
            // D1: the directory and its entry in the root are durable before the
            // first segment is created in it.
            fsync(&dir_fd).map_err(io_error)?;
            fsync(&root_fd).map_err(io_error)?;
        }
        Ok(Box::new(UnixStore {
            dir_fd,
            euid,
            created,
        }))
    }

    fn is_private_store(&self) -> bool {
        true
    }

    fn read_key_file(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let (root_fd, euid) = self.open_root()?;
        let fd = match openat(
            &root_fd,
            KEY_FILE_NAME,
            // NONBLOCK: opening a FIFO that someone planted here must not wait for
            // a writer; the `fstat` below refuses it. It changes nothing for a
            // regular file.
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(errno) => {
                return Err(unsafe_open(
                    errno,
                    StoreError::FileUnsafe(UnsafeReason::NotRegularFile),
                ))
            }
        };
        let stat = fstat(&fd).map_err(io_error)?;
        check_file(Facts::of(&stat), euid).map_err(StoreError::FileUnsafe)?;
        let mut bytes = Vec::new();
        File::from(fd)
            .take(KEY_FILE_READ_MAX)
            .read_to_end(&mut bytes)
            .map_err(|error| StoreError::Io(io_code(&error)))?;
        Ok(Some(bytes))
    }

    fn create_key_file(&self, bytes: &[u8]) -> Result<(), StoreError> {
        self.create_key_with(bytes, &mut |file, bytes| file.write_all(bytes))
    }
}

impl UnixLedgerFs {
    /// `create_key_file` with the write as a parameter, so that a write that fails
    /// half-way can be tested: the production write is `write_all`.
    fn create_key_with(
        &self,
        bytes: &[u8],
        write: &mut dyn FnMut(&mut File, &[u8]) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let (root_fd, euid) = self.open_root()?;
        let fd = openat(
            &root_fd,
            KEY_FILE_NAME,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(io_error)?;
        // From here on the name exists and is ours: whatever fails, it is removed
        // again, so that a half-written key never survives to be read next start.
        let mut file = File::from(fd);
        let mut finish = || -> Result<(), StoreError> {
            let stat = fstat(&file).map_err(io_error)?;
            check_file(Facts::of(&stat), euid).map_err(StoreError::FileUnsafe)?;
            write(&mut file, bytes).map_err(|error| StoreError::Io(io_code(&error)))?;
            file.sync_all()
                .map_err(|error| StoreError::Io(io_code(&error)))?;
            // D3: the entry in the state root is durable before the key is used.
            fsync(&root_fd).map_err(io_error)
        };
        finish().inspect_err(|_| {
            let _ = unlinkat(&root_fd, KEY_FILE_NAME, AtFlags::empty());
        })
    }
}

struct UnixStore {
    dir_fd: std::os::fd::OwnedFd,
    euid: u32,
    created: bool,
}

impl UnixStore {
    /// Opens `name` below the ledger directory and checks what it is.
    fn open_checked(&self, first_seq: u64, flags: OFlags, mode: Mode) -> Result<File, StoreError> {
        let name = segment_name(first_seq);
        let fd = openat(
            &self.dir_fd,
            name.as_str(),
            // NONBLOCK for the reason given at `read_key_file`.
            flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            mode,
        )
        .map_err(|errno| {
            unsafe_open(errno, StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        })?;
        let stat = fstat(&fd).map_err(io_error)?;
        check_file(Facts::of(&stat), self.euid).map_err(StoreError::FileUnsafe)?;
        Ok(File::from(fd))
    }
}

impl LedgerStore for UnixStore {
    fn created(&self) -> bool {
        self.created
    }

    fn segments(&self) -> Result<Segments, StoreError> {
        let mut listing = Dir::read_from(&self.dir_fd).map_err(io_error)?;
        let mut found = Segments::default();
        while let Some(entry) = listing.read() {
            let entry = entry.map_err(io_error)?;
            let raw = entry.file_name().to_bytes();
            if raw == b"." || raw == b".." {
                continue;
            }
            let Some(seq) = std::str::from_utf8(raw).ok().and_then(parse_segment_name) else {
                found.ignored = found.ignored.saturating_add(1);
                continue;
            };
            // A directory, a symlink or a device with a segment's name is not a
            // segment, and it is not ignored either.
            let stat = statat(&self.dir_fd, entry.file_name(), AtFlags::SYMLINK_NOFOLLOW)
                .map_err(io_error)?;
            if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
                return Err(StoreError::FileUnsafe(UnsafeReason::NotRegularFile));
            }
            found.first_seqs.push(seq);
        }
        found.first_seqs.sort_unstable();
        Ok(found)
    }

    fn open_reader(&self, first_seq: u64) -> Result<SegmentReader, StoreError> {
        let file = self.open_checked(first_seq, OFlags::RDONLY, Mode::empty())?;
        // The length now: whatever is appended later is not part of this read.
        let len = file
            .metadata()
            .map_err(|error| StoreError::Io(io_code(&error)))?
            .len();
        Ok(SegmentReader {
            len,
            reader: Box::new(BufReader::new(file.take(len))),
        })
    }

    fn open_active(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
        let file = self.open_checked(first_seq, OFlags::WRONLY | OFlags::APPEND, Mode::empty())?;
        Ok(Box::new(UnixActive { file }))
    }

    fn create_segment(&self, first_seq: u64) -> Result<Box<dyn ActiveSegment>, StoreError> {
        // `EEXIST` (a segment, a symlink or anything else already has the name)
        // comes back as `AUDIT_ALREADY_EXISTS`: the name is never reused.
        let file = self.open_checked(
            first_seq,
            OFlags::WRONLY | OFlags::APPEND | OFlags::CREATE | OFlags::EXCL,
            Mode::RUSR | Mode::WUSR,
        )?;
        Ok(Box::new(UnixActive { file }))
    }

    fn remove_segment(&self, first_seq: u64) -> io::Result<()> {
        let name = segment_name(first_seq);
        unlinkat(&self.dir_fd, name.as_str(), AtFlags::empty()).map_err(io::Error::from)
    }

    fn sync_dir(&self) -> io::Result<()> {
        fsync(&self.dir_fd).map_err(io::Error::from)
    }
}

struct UnixActive {
    file: File,
}

impl ActiveSegment for UnixActive {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.file.write_all(bytes)
    }

    fn sync_data(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }

    fn sync_all(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }

    fn stat(&self) -> io::Result<ActiveStat> {
        let meta = self.file.metadata()?;
        Ok(ActiveStat {
            len: meta.len(),
            nlink: meta.nlink(),
        })
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::fs::{symlink, DirBuilderExt, PermissionsExt};
    use std::path::Path;

    fn euid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn private_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o7777
    }

    fn open(root: &Path) -> Result<Box<dyn LedgerStore>, StoreError> {
        UnixLedgerFs::new(root.to_path_buf()).open_store()
    }

    fn facts(is_dir: bool, is_file: bool, mode: u32, uid: u32, nlink: u64) -> Facts {
        Facts {
            is_dir,
            is_file,
            mode,
            uid,
            nlink,
        }
    }

    // -- the pure checks -------------------------------------------------------

    #[test]
    fn owner_check_table() {
        let me = 1000;
        // root: a directory of mine without group or other write
        for (mode, ok) in [
            (0o700, true),
            (0o750, true),
            (0o755, true),
            (0o500, true),
            (0o770, false),
            (0o775, false),
            (0o777, false),
            (0o757, false),
            (0o720, false),
            (0o702, false),
            (0o1777, false),
        ] {
            let got = check_root(facts(true, false, mode, me, 2), me);
            assert_eq!(got.is_ok(), ok, "root mode {mode:o}: {got:?}");
            if !ok {
                assert_eq!(got, Err(UnsafeReason::GroupOrOtherWritable));
            }
        }
        assert_eq!(
            check_root(facts(true, false, 0o700, me + 1, 2), me),
            Err(UnsafeReason::WrongOwner)
        );
        assert_eq!(
            check_root(facts(false, true, 0o700, me, 1), me),
            Err(UnsafeReason::NotDirectory)
        );
        // directory: private to me
        for (mode, ok) in [
            (0o700, true),
            (0o500, true),
            (0o750, false),
            (0o705, false),
            (0o740, false),
            (0o701, false),
            (0o755, false),
            (0o777, false),
        ] {
            let got = check_dir(facts(true, false, mode, me, 2), me);
            assert_eq!(got.is_ok(), ok, "dir mode {mode:o}: {got:?}");
            if !ok {
                assert_eq!(got, Err(UnsafeReason::GroupOrOtherAccess));
            }
        }
        assert_eq!(
            check_dir(facts(true, false, 0o700, me + 1, 2), me),
            Err(UnsafeReason::WrongOwner)
        );
        assert_eq!(
            check_dir(facts(false, true, 0o700, me, 1), me),
            Err(UnsafeReason::NotDirectory)
        );
        // file: regular, mine, private, one link
        for (mode, ok) in [
            (0o600, true),
            (0o400, true),
            (0o640, false),
            (0o604, false),
            (0o660, false),
            (0o644, false),
        ] {
            let got = check_file(facts(false, true, mode, me, 1), me);
            assert_eq!(got.is_ok(), ok, "file mode {mode:o}: {got:?}");
        }
        assert_eq!(
            check_file(facts(false, true, 0o600, me + 1, 1), me),
            Err(UnsafeReason::WrongOwner)
        );
        assert_eq!(
            check_file(facts(false, true, 0o600, me, 2), me),
            Err(UnsafeReason::HardLinked)
        );
        assert_eq!(
            check_file(facts(false, true, 0o600, me, 0), me),
            Err(UnsafeReason::HardLinked)
        );
        assert_eq!(
            check_file(facts(true, false, 0o700, me, 1), me),
            Err(UnsafeReason::NotRegularFile)
        );
        assert_eq!(
            check_file(facts(false, false, 0o600, me, 1), me),
            Err(UnsafeReason::NotRegularFile)
        );
    }

    #[test]
    fn segment_names_round_trip_and_nothing_else_parses() {
        assert_eq!(segment_name(1), "seg-00000000000000000001.jsonl");
        assert_eq!(segment_name(u64::MAX), "seg-18446744073709551615.jsonl");
        for seq in [0, 1, 104_857, 1 << 40, u64::MAX] {
            assert_eq!(parse_segment_name(&segment_name(seq)), Some(seq));
        }
        for bad in [
            "",
            "seg-1.jsonl",
            "seg-0000000000000000001.jsonl",
            "seg-000000000000000000001.jsonl",
            "seg-00000000000000000001.jsonl.bak",
            "SEG-00000000000000000001.jsonl",
            "seg-00000000000000000001.JSONL",
            "seg-0000000000000000000a.jsonl",
            "seg-+0000000000000000001.jsonl",
            "seg-99999999999999999999.jsonl",
            "xseg-00000000000000000001.jsonl",
            " seg-00000000000000000001.jsonl",
            "seg-00000000000000000001.jsonl ",
            "ingress-dest.key",
        ] {
            assert_eq!(parse_segment_name(bad), None, "{bad:?}");
        }
    }

    // -- a real directory ------------------------------------------------------

    #[test]
    fn the_ledger_directory_is_created_private_and_reopened() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        assert!(store.created());
        let ledger = root.path().join(LEDGER_DIR);
        assert_eq!(mode_of(&ledger), 0o700);
        assert!(store.segments().expect("lists").first_seqs.is_empty());
        let again = open(root.path()).expect("reopens");
        assert!(!again.created(), "an existing directory is not a new one");
    }

    #[test]
    fn ledger_dir_and_files_have_private_modes() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"line\n").expect("appends");
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        assert_eq!(mode_of(&seg), 0o600);
        assert_eq!(mode_of(&root.path().join(LEDGER_DIR)), 0o700);
        // Only the owner can read what the ledger holds.
        let meta = std::fs::metadata(&seg).expect("metadata");
        assert_eq!(meta.permissions().mode() & 0o077, 0);
        assert_eq!(meta.nlink(), 1);
    }

    #[test]
    fn state_root_writable_by_others_is_refused() {
        for mode in [0o770, 0o775, 0o777, 0o757, 0o722] {
            let root = private_root();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            assert_eq!(
                open(root.path()).err(),
                Some(StoreError::RootUnsafe(UnsafeReason::GroupOrOtherWritable)),
                "{mode:o}"
            );
            assert_eq!(mode_of(root.path()), mode, "the root is not repaired");
            assert!(
                !root.path().join(LEDGER_DIR).exists(),
                "nothing is created in it"
            );
        }
        // Read access for others is not the problem; write access is.
        let root = private_root();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod");
        assert!(open(root.path()).is_ok());
    }

    #[test]
    fn symlinked_state_root_set_up_on_purpose_still_works() {
        let real = private_root();
        let holder = private_root();
        let link = holder.path().join("state");
        symlink(real.path(), &link).expect("symlink");
        let store = open(&link).expect("a deliberate symlink is followed once, at the root");
        assert!(store.created());
        assert!(
            real.path().join(LEDGER_DIR).is_dir(),
            "the ledger is in the real directory"
        );
    }

    #[test]
    fn a_missing_or_unusable_root_is_an_io_error_not_a_safety_finding() {
        let root = private_root();
        assert_eq!(
            open(&root.path().join("absent")).err(),
            Some(StoreError::Io("AUDIT_NOT_FOUND"))
        );
        let file = root.path().join("file");
        std::fs::write(&file, b"x").expect("write");
        assert_eq!(
            open(&file).err(),
            Some(StoreError::RootUnsafe(UnsafeReason::NotDirectory))
        );
    }

    #[test]
    fn symlinked_ledger_dir_is_refused() {
        let root = private_root();
        let elsewhere = private_root();
        symlink(elsewhere.path(), root.path().join(LEDGER_DIR)).expect("symlink");
        assert_eq!(
            open(root.path()).err(),
            Some(StoreError::DirUnsafe(UnsafeReason::NotDirectory))
        );
        assert_eq!(
            std::fs::read_dir(elsewhere.path()).expect("list").count(),
            0,
            "nothing was written through the link"
        );
    }

    #[test]
    fn a_file_where_the_ledger_directory_should_be_is_refused() {
        let root = private_root();
        std::fs::write(root.path().join(LEDGER_DIR), b"not a directory").expect("write");
        assert_eq!(
            open(root.path()).err(),
            Some(StoreError::DirUnsafe(UnsafeReason::NotDirectory))
        );
    }

    #[test]
    fn existing_group_readable_ledger_dir_is_refused_not_repaired() {
        for mode in [0o750, 0o770, 0o705, 0o755, 0o701] {
            let root = private_root();
            let ledger = root.path().join(LEDGER_DIR);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&ledger)
                .expect("mkdir");
            std::fs::set_permissions(&ledger, std::fs::Permissions::from_mode(mode))
                .expect("chmod");
            assert_eq!(
                open(root.path()).err(),
                Some(StoreError::DirUnsafe(UnsafeReason::GroupOrOtherAccess)),
                "{mode:o}"
            );
            assert_eq!(mode_of(&ledger), mode, "refused, never repaired");
        }
    }

    #[test]
    fn symlinked_segment_is_refused() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let target = root.path().join("elsewhere");
        std::fs::write(&target, b"secret\n").expect("write");
        // A target that passes every check of a segment: only the link itself is wrong.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        symlink(&target, root.path().join(LEDGER_DIR).join(segment_name(7))).expect("symlink");
        assert_eq!(
            store.segments().err(),
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        );
        assert!(matches!(
            store.open_reader(7).err(),
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        ));
        assert!(matches!(
            store.open_active(7).err(),
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        ));
        // Creating over it fails too: the name exists, and nothing is followed.
        assert_eq!(
            store.create_segment(7).err(),
            Some(StoreError::Io("AUDIT_ALREADY_EXISTS"))
        );
        assert_eq!(
            std::fs::read(&target).expect("read"),
            b"secret\n",
            "the target is untouched"
        );
    }

    #[test]
    fn hard_linked_segment_is_refused() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        drop(store.create_segment(1).expect("creates"));
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        std::fs::hard_link(&seg, root.path().join("planted-link")).expect("hard link");
        assert!(matches!(
            store.open_reader(1).err(),
            Some(StoreError::FileUnsafe(UnsafeReason::HardLinked))
        ));
        assert!(matches!(
            store.open_active(1).err(),
            Some(StoreError::FileUnsafe(UnsafeReason::HardLinked))
        ));
    }

    #[test]
    fn a_segment_that_others_can_read_is_refused() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        drop(store.create_segment(1).expect("creates"));
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        for mode in [0o640, 0o604, 0o660, 0o644] {
            std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(
                matches!(
                    store.open_reader(1).err(),
                    Some(StoreError::FileUnsafe(UnsafeReason::GroupOrOtherAccess))
                ),
                "{mode:o}"
            );
        }
        std::fs::set_permissions(&seg, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        assert!(store.open_reader(1).is_ok());
    }

    #[test]
    fn a_directory_named_like_a_segment_is_refused() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        std::fs::create_dir(root.path().join(LEDGER_DIR).join(segment_name(3))).expect("mkdir");
        assert_eq!(
            store.segments().err(),
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        );
    }

    #[test]
    fn a_fifo_with_a_segments_name_is_refused_and_never_waited_for() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let fifo = root.path().join(LEDGER_DIR).join(segment_name(4));
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)
            .expect("mkfifo");
        // Run on a thread: a regression would block here for ever, and a hung test
        // run is worse than a failed one.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let reader = store.open_reader(4).err();
            let active = store.open_active(4).err();
            let listed = store.segments().err();
            let _ = sender.send((reader, active, listed));
        });
        let (reader, active, listed) = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("opening a FIFO must not block");
        assert!(matches!(
            reader,
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        ));
        assert!(matches!(
            active,
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile)) | Some(StoreError::Io(_))
        ));
        assert_eq!(
            listed,
            Some(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        );
    }

    #[test]
    fn a_fifo_in_the_place_of_the_key_is_refused_and_never_waited_for() {
        let root = private_root();
        let fifo = root.path().join(KEY_FILE_NAME);
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0)
            .expect("mkfifo");
        let fs = UnixLedgerFs::new(root.path().to_path_buf());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(fs.read_key_file());
        });
        let answer = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("opening a FIFO must not block");
        assert_eq!(
            answer,
            Err(StoreError::FileUnsafe(UnsafeReason::NotRegularFile))
        );
    }

    #[test]
    fn a_key_that_could_not_be_completed_does_not_stay_behind() {
        let root = private_root();
        let fs = UnixLedgerFs::new(root.path().to_path_buf());
        let key = root.path().join(KEY_FILE_NAME);
        // The write fails after the file exists, having written half of it.
        let failed = fs.create_key_with(b"0123456789", &mut |file, bytes| {
            file.write_all(bytes.get(..5).unwrap_or_default())?;
            Err(io::Error::from(io::ErrorKind::StorageFull))
        });
        assert_eq!(failed, Err(StoreError::Io("AUDIT_DISK_FULL")));
        assert!(!key.exists(), "a half-written key is removed");
        // And the next attempt works, as it would after the operator freed space.
        fs.create_key_file(b"0123456789").expect("creates");
        assert_eq!(std::fs::read(&key).expect("read"), b"0123456789");
        assert_eq!(mode_of(&key), 0o600);
    }

    /// Needs root: another user's directory, file and root.
    #[test]
    fn foreign_uid_dir_refused_when_running_as_root() {
        if euid() != 0 {
            eprintln!("skipped: not running as root, cannot create files of another user");
            return;
        }
        let other = 65_534_u32;
        // The ledger directory belongs to someone else.
        let root = private_root();
        let store = open(root.path()).expect("opens");
        drop(store);
        let ledger = root.path().join(LEDGER_DIR);
        std::os::unix::fs::chown(&ledger, Some(other), None).expect("chown");
        assert_eq!(
            open(root.path()).err(),
            Some(StoreError::DirUnsafe(UnsafeReason::WrongOwner))
        );
        std::os::unix::fs::chown(&ledger, Some(0), None).expect("chown back");

        // A segment belongs to someone else.
        let store = open(root.path()).expect("opens again");
        drop(store.create_segment(1).expect("creates"));
        let seg = ledger.join(segment_name(1));
        std::os::unix::fs::chown(&seg, Some(other), None).expect("chown");
        assert!(matches!(
            store.open_reader(1).err(),
            Some(StoreError::FileUnsafe(UnsafeReason::WrongOwner))
        ));

        // The state root belongs to someone else.
        let foreign = private_root();
        std::os::unix::fs::chown(foreign.path(), Some(other), None).expect("chown");
        assert_eq!(
            open(foreign.path()).err(),
            Some(StoreError::RootUnsafe(UnsafeReason::WrongOwner))
        );
        std::os::unix::fs::chown(foreign.path(), Some(0), None).expect("chown back");
    }

    // -- listing, reading, appending -------------------------------------------

    #[test]
    fn segments_lists_only_segment_names_ascending_and_counts_the_rest() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        // Created in both orders, so that a file system which lists in creation
        // order, or in reverse of it, cannot make an unsorted answer look sorted.
        for seq in [
            30, 1, 20, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ] {
            drop(store.create_segment(seq).expect("creates"));
        }
        for seq in (31..=40).rev() {
            drop(store.create_segment(seq).expect("creates"));
        }
        let ledger = root.path().join(LEDGER_DIR);
        for noise in [
            "notes.txt",
            "seg-1.jsonl",
            "seg-00000000000000000001.jsonl.bak",
            "SEG-00000000000000000001.jsonl",
            ".hidden",
        ] {
            std::fs::write(ledger.join(noise), b"x").expect("write");
        }
        let listed = store.segments().expect("lists");
        assert_eq!(
            listed.first_seqs,
            (1..=20).chain(30..=40).collect::<Vec<u64>>()
        );
        assert_eq!(listed.ignored, 5);
        // Listing twice gives the same answer (the directory handle is not consumed).
        assert_eq!(store.segments().expect("lists again"), listed);
    }

    #[test]
    fn create_segment_never_reuses_a_name() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut first = store.create_segment(5).expect("creates");
        first.append(b"original\n").expect("appends");
        assert_eq!(
            store.create_segment(5).err(),
            Some(StoreError::Io("AUDIT_ALREADY_EXISTS"))
        );
        let seg = root.path().join(LEDGER_DIR).join(segment_name(5));
        assert_eq!(
            std::fs::read(&seg).expect("read"),
            b"original\n",
            "the existing segment is untouched"
        );
    }

    #[test]
    fn a_reader_reads_only_the_length_seen_at_open() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"0123456789").expect("appends");
        let SegmentReader { len, mut reader } = store.open_reader(1).expect("opens");
        assert_eq!(len, 10);
        active.append(b"ABCDEFGHIJ").expect("appends more");
        let mut text = String::new();
        reader.read_to_string(&mut text).expect("reads");
        assert_eq!(text, "0123456789", "the later append is not half-read");
        // A reader opened now sees both.
        let SegmentReader { len, .. } = store.open_reader(1).expect("opens");
        assert_eq!(len, 20);
    }

    #[test]
    fn active_stat_sees_an_unlink_and_an_external_append() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"abc\n").expect("appends");
        assert_eq!(
            active.stat().expect("stat"),
            ActiveStat { len: 4, nlink: 1 }
        );
        // Someone else appends: the length is not what the writer expects.
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        std::fs::OpenOptions::new()
            .append(true)
            .open(&seg)
            .expect("open")
            .write_all(b"x")
            .expect("write");
        assert_eq!(active.stat().expect("stat").len, 5);
        // The segment is unlinked under the writer: the open handle says so.
        store.remove_segment(1).expect("removes");
        assert_eq!(active.stat().expect("stat").nlink, 0);
    }

    #[test]
    fn open_active_appends_after_what_is_already_there() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        let mut first = store.create_segment(1).expect("creates");
        first.append(b"one\n").expect("appends");
        drop(first);
        let mut again = store.open_active(1).expect("reopens for append");
        again.append(b"two\n").expect("appends");
        assert_eq!(std::fs::read(&seg).expect("read"), b"one\ntwo\n");
        // Appended to behind its back, the handle still writes at the end.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&seg)
            .expect("open")
            .write_all(b"x\n")
            .expect("write");
        again.append(b"three\n").expect("appends");
        assert_eq!(std::fs::read(&seg).expect("read"), b"one\ntwo\nx\nthree\n");
        // A reader handle cannot write: `open_reader` is read-only.
        let SegmentReader { len, .. } = store.open_reader(1).expect("reads");
        assert_eq!(len, 16);
        assert!(matches!(
            store.open_active(2).err(),
            Some(StoreError::Io("AUDIT_NOT_FOUND"))
        ));
    }

    #[test]
    fn truncate_cuts_a_torn_tail() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"whole\ntorn").expect("appends");
        active.truncate(6).expect("truncates");
        active.sync_all().expect("syncs");
        let seg = root.path().join(LEDGER_DIR).join(segment_name(1));
        assert_eq!(std::fs::read(&seg).expect("read"), b"whole\n");
        // Appending continues at the new end (the handle is O_APPEND).
        active.append(b"next\n").expect("appends");
        assert_eq!(std::fs::read(&seg).expect("read"), b"whole\nnext\n");
    }

    #[test]
    fn the_sync_calls_and_remove_work_and_a_missing_segment_is_an_error() {
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"x\n").expect("appends");
        active.sync_data().expect("sync_data");
        active.sync_all().expect("sync_all");
        store.sync_dir().expect("sync_dir");
        store.remove_segment(1).expect("removes");
        store.sync_dir().expect("sync_dir");
        assert_eq!(
            store.remove_segment(1).expect_err("gone").kind(),
            io::ErrorKind::NotFound
        );
        assert!(store.segments().expect("lists").first_seqs.is_empty());
        assert!(matches!(
            store.open_reader(1).err(),
            Some(StoreError::Io("AUDIT_NOT_FOUND"))
        ));
    }

    #[test]
    fn the_store_is_bound_to_the_directory_it_opened_not_to_the_path() {
        // After the store is open, the path is swapped for a symlink to another
        // directory. Every operation goes through the descriptor, so the new
        // segment lands in the original directory and nothing is written through
        // the link.
        let root = private_root();
        let store = open(root.path()).expect("opens");
        let ledger = root.path().join(LEDGER_DIR);
        let moved = root.path().join("moved-away");
        std::fs::rename(&ledger, &moved).expect("rename");
        let attacker = private_root();
        symlink(attacker.path(), &ledger).expect("symlink");
        let mut active = store.create_segment(1).expect("creates");
        active.append(b"evidence\n").expect("appends");
        assert!(
            moved.join(segment_name(1)).is_file(),
            "written where the store opened"
        );
        assert_eq!(std::fs::read_dir(attacker.path()).expect("list").count(), 0);
    }

    // -- the operator's message --------------------------------------------------

    #[test]
    fn the_hint_for_a_group_writable_root_is_the_chmod_the_operator_runs() {
        let hint = StoreError::RootUnsafe(UnsafeReason::GroupOrOtherWritable)
            .operator_hint(Path::new("/home/u/.local/state/kaleidoscorp"));
        assert!(
            hint.contains("chmod go-w /home/u/.local/state/kaleidoscorp"),
            "{hint}"
        );
        for error in [
            StoreError::RootUnsafe(UnsafeReason::WrongOwner),
            StoreError::DirUnsafe(UnsafeReason::GroupOrOtherAccess),
            StoreError::FileUnsafe(UnsafeReason::HardLinked),
            StoreError::Io("AUDIT_IO"),
            StoreError::Unsupported,
        ] {
            let text = error.operator_hint(Path::new("/state"));
            assert!(!text.is_empty());
            assert_eq!(
                crate::ingress::types::contains_forbidden_word(&text),
                None,
                "{text}"
            );
        }
    }

    #[test]
    fn store_errors_map_to_the_unavailable_codes() {
        use crate::ingress::types::UnavailableCode as U;
        assert_eq!(
            StoreError::RootUnsafe(UnsafeReason::WrongOwner).unavailable_code(),
            U::AuditRootUnsafe
        );
        assert_eq!(
            StoreError::DirUnsafe(UnsafeReason::WrongOwner).unavailable_code(),
            U::AuditDirUnsafe
        );
        assert_eq!(
            StoreError::FileUnsafe(UnsafeReason::WrongOwner).unavailable_code(),
            U::AuditFileUnsafe
        );
        assert_eq!(
            StoreError::Io("AUDIT_IO").unavailable_code(),
            U::AuditFailed
        );
        assert_eq!(StoreError::Unsupported.unavailable_code(), U::AuditFailed);
        assert!(UnixLedgerFs::new(PathBuf::from("/")).is_private_store());
    }
}
