//! Machine-owned OpenVPN profile/control storage. No caller-supplied paths,
//! raw .ovpn import, implicit repair or directory provisioning at service startup.
//! Public entry points use the real Windows ACL probe; test injection is private.
#[cfg(any(windows, test))]
use crate::{
    service::{acl, is_administrative_sid, PathSecurity, PathSecurityProbe},
    state_dir::{StateDirLayout, StateDirStatus},
};
#[cfg(any(windows, test))]
use ssk_vpnctl::MAX_PROFILE_BYTES;
use ssk_vpnctl::{Profile, ProfileError, ProfileId};
use std::io;
#[cfg(any(windows, test))]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
#[cfg(any(windows, test))]
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum ProfileStoreError {
    Unsupported,
    UnsafeDirectory,
    UnsafeFile,
    AlreadyExists,
    NotFound,
    Io(io::ErrorKind),
    Profile(ProfileError),
    IdMismatch,
    RecoveryRequired,
}
impl std::fmt::Display for ProfileStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenVPN profile store: {self:?}")
    }
}
impl std::error::Error for ProfileStoreError {}
impl From<io::Error> for ProfileStoreError {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::NotFound,
            io::ErrorKind::AlreadyExists => Self::AlreadyExists,
            kind => Self::Io(kind),
        }
    }
}

pub struct ProfileStore {
    #[cfg(any(windows, test))]
    layout: StateDirLayout,
}

impl ProfileStore {
    #[cfg(windows)]
    fn layout() -> Result<StateDirLayout, ProfileStoreError> {
        let state = StateDirLayout::default_program_data()
            .map_err(|_| ProfileStoreError::UnsafeDirectory)?;
        StateDirLayout::new(
            &state.leaf().join("openvpn-profiles"),
            state.owned().len() + 1,
        )
        .map_err(|_| ProfileStoreError::UnsafeDirectory)
    }

    /// Explicit elevated provisioning, using create-or-verify and post-ACL
    /// readback. Existing unsafe directories are refused, never repaired.
    #[cfg(windows)]
    pub fn provision(elevation: crate::Elevation) -> Result<Self, ProfileStoreError> {
        let layout = Self::layout()?;
        crate::state_dir::ensure_state_dir(&layout, elevation)
            .map_err(|_| ProfileStoreError::UnsafeDirectory)?;
        Self::open_layout(layout, &crate::service::Win32PathSecurityProbe)
    }

    #[cfg(windows)]
    pub fn open() -> Result<Self, ProfileStoreError> {
        Self::open_layout(Self::layout()?, &crate::service::Win32PathSecurityProbe)
    }

    #[cfg(not(windows))]
    pub fn open() -> Result<Self, ProfileStoreError> {
        Err(ProfileStoreError::Unsupported)
    }
    #[cfg(not(windows))]
    pub fn provision(_: crate::Elevation) -> Result<Self, ProfileStoreError> {
        Err(ProfileStoreError::Unsupported)
    }

    /// Create once. A duplicate ID is a conflict, including after a crash that
    /// left an incomplete file. Operators must inspect/remove such artifacts;
    /// they are never silently overwritten or adopted as a valid profile.
    #[cfg(windows)]
    pub fn create(&self, profile: &Profile) -> Result<(), ProfileStoreError> {
        self.create_with(profile, &crate::service::Win32PathSecurityProbe)
    }
    #[cfg(not(windows))]
    pub fn create(&self, _: &Profile) -> Result<(), ProfileStoreError> {
        Err(ProfileStoreError::Unsupported)
    }

    #[cfg(windows)]
    pub fn load(&self, id: &ProfileId) -> Result<Profile, ProfileStoreError> {
        self.load_with(id, &crate::service::Win32PathSecurityProbe)
    }
    #[cfg(not(windows))]
    pub fn load(&self, _: &ProfileId) -> Result<Profile, ProfileStoreError> {
        Err(ProfileStoreError::Unsupported)
    }
}

// Kept on non-Windows for private tests; no injectable public security bypass.
#[cfg(any(windows, test))]
impl ProfileStore {
    pub(crate) fn open_layout(
        layout: StateDirLayout,
        probe: &dyn PathSecurityProbe,
    ) -> Result<Self, ProfileStoreError> {
        let store = Self { layout };
        store.verify(probe)?;
        Ok(store)
    }

    pub(crate) fn verify(&self, probe: &dyn PathSecurityProbe) -> Result<(), ProfileStoreError> {
        if crate::state_dir::verify_state_dir_with(&self.layout, probe)
            .map_err(|_| ProfileStoreError::UnsafeDirectory)?
            != StateDirStatus::Protected
        {
            return Err(ProfileStoreError::UnsafeDirectory);
        }
        // Unlike the old symlink-only probe, reject ALL Windows reparse tags.
        for path in self.layout.ancestors().iter().chain(self.layout.owned()) {
            if reparse(path)? {
                return Err(ProfileStoreError::UnsafeDirectory);
            }
        }
        for path in self.layout.owned() {
            let security = probe
                .inspect(path)
                .map_err(|_| ProfileStoreError::UnsafeDirectory)?;
            if !confidential(&security) {
                return Err(ProfileStoreError::UnsafeDirectory);
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    pub(crate) fn directory(&self) -> &Path {
        self.layout.leaf()
    }

    #[cfg(windows)]
    pub(crate) fn child_store(
        &self,
        path: &Path,
        probe: &dyn PathSecurityProbe,
    ) -> Result<Self, ProfileStoreError> {
        if path.parent() != Some(self.directory()) {
            return Err(ProfileStoreError::UnsafeDirectory);
        }
        let layout = StateDirLayout::new(path, self.layout.owned().len() + 1)
            .map_err(|_| ProfileStoreError::UnsafeDirectory)?;
        Self::open_layout(layout, probe)
    }

    fn path(&self, id: &ProfileId) -> std::path::PathBuf {
        // Prefix also avoids Windows reserved DOS device basenames.
        self.layout.leaf().join(format!("vpn-{}.json", id.as_str()))
    }

    pub(crate) fn check_file(
        &self,
        file: &File,
        path: &Path,
        probe: &dyn PathSecurityProbe,
    ) -> Result<(), ProfileStoreError> {
        if !file.metadata()?.is_file()
            || reparse(path)?
            || !single_link(file)?
            || !confidential(
                &probe
                    .inspect(path)
                    .map_err(|_| ProfileStoreError::UnsafeFile)?,
            )
        {
            return Err(ProfileStoreError::UnsafeFile);
        }
        Ok(())
    }

    fn create_with(
        &self,
        profile: &Profile,
        probe: &dyn PathSecurityProbe,
    ) -> Result<(), ProfileStoreError> {
        self.verify(probe)?;
        let path = self.path(&profile.id());
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        deny_write_delete_sharing(&mut options);
        let mut file = options.open(&path)?;
        // Verify inherited confidentiality BEFORE writing any secret material.
        self.check_file(&file, &path, probe)?;
        let bytes = profile.to_document().map_err(ProfileStoreError::Profile)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }

    pub(crate) fn load_with(
        &self,
        id: &ProfileId,
        probe: &dyn PathSecurityProbe,
    ) -> Result<Profile, ProfileStoreError> {
        self.verify(probe)?;
        let path = self.path(id);
        let mut options = OpenOptions::new();
        options.read(true);
        deny_write_delete_sharing(&mut options);
        let file = options.open(&path)?;
        self.check_file(&file, &path, probe)?;
        if file.metadata()?.len() > MAX_PROFILE_BYTES as u64 {
            return Err(ProfileStoreError::Profile(ProfileError::TooLarge));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROFILE_BYTES + 1));
        file.take(MAX_PROFILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let profile = Profile::parse(&bytes).map_err(ProfileStoreError::Profile)?;
        if profile.id() != *id {
            return Err(ProfileStoreError::IdMismatch);
        }
        Ok(profile)
    }
}

/// Stronger than integrity-only state receipts: even read grants to another
/// principal are refused, including inherit-only ACEs that expose future keys.
#[cfg(any(windows, test))]
fn confidential(security: &PathSecurity) -> bool {
    !security.is_reparse_point
        && is_administrative_sid(&security.owner_sid)
        && security.aces.as_ref().is_some_and(|aces| {
            aces.iter().all(|ace| {
                ace.ace_type == acl::ACCESS_DENIED_ACE_TYPE
                    || (ace.ace_type == acl::ACCESS_ALLOWED_ACE_TYPE
                        && is_administrative_sid(&ace.sid))
            })
        })
}

#[cfg(any(windows, test))]
pub(crate) fn reparse(path: &Path) -> io::Result<bool> {
    let meta = fs::symlink_metadata(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(meta.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(meta.file_type().is_symlink())
    }
}

#[cfg(any(windows, test))]
pub(crate) fn deny_write_delete_sharing(options: &mut OpenOptions) {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Open the reparse object itself, then refuse it. Only read sharing.
        options.share_mode(1).custom_flags(0x00200000);
    }
    #[cfg(not(windows))]
    let _ = options;
}

#[cfg(windows)]
pub(crate) fn single_link(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: file owns a live handle; the API initializes info on success.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() }.nNumberOfLinks == 1)
}
#[cfg(all(not(windows), test))]
pub(crate) fn single_link(file: &File) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(file.metadata()?.nlink() == 1)
}

#[cfg(windows)]
pub(crate) struct LaunchFiles {
    pub(crate) launch_id: [u8; 16],
    config: std::path::PathBuf,
    password: std::path::PathBuf,
    locks: Vec<File>,
}
#[cfg(windows)]
impl LaunchFiles {
    pub(crate) fn config(&self) -> &Path {
        &self.config
    }
}
#[cfg(windows)]
impl Drop for LaunchFiles {
    fn drop(&mut self) {
        self.locks.clear();
        // Only these two freshly claimed files. No recursive deletion and no
        // scanning/removal of another run's artifacts. Crash leftovers stay ACL'd.
        if !self.config.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.config);
        }
        let _ = fs::remove_file(&self.password);
    }
}
#[cfg(windows)]
impl ProfileStore {
    /// Fixed control artifacts only; callers cannot supply a path through IPC.
    #[cfg(test)]
    pub(crate) fn control_file_with(
        &self,
        journal: bool,
        probe: &dyn PathSecurityProbe,
    ) -> Result<File, ProfileStoreError> {
        self.verify(probe)?;
        let path = self.layout.leaf().join(if journal {
            "openvpn-control.journal"
        } else {
            "openvpn-control.json"
        });
        let mut options = OpenOptions::new();
        options.read(true);
        if journal {
            options.append(true);
        }
        deny_write_delete_sharing(&mut options);
        let file = match options.open(&path) {
            Err(e) if journal && e.kind() == io::ErrorKind::NotFound => {
                options.create_new(true).open(&path)?
            }
            result => result?,
        };
        self.check_file(&file, &path, probe)?;
        Ok(file)
    }

    /// The journal namespace is reserved. Validate names and continuity before
    /// claiming a missing origin, so a missing first segment is never a reset.
    pub(crate) fn journal_indices(
        &self,
        probe: &dyn PathSecurityProbe,
    ) -> Result<Vec<usize>, ProfileStoreError> {
        self.verify(probe)?;
        let mut indices = Vec::new();
        for (count, entry) in fs::read_dir(self.layout.leaf())?.enumerate() {
            if count >= 4096 {
                return Err(ProfileStoreError::UnsafeDirectory);
            }
            let name = entry?.file_name();
            let Some(name) = name.to_str() else {
                return Err(ProfileStoreError::UnsafeFile);
            };
            if name.eq_ignore_ascii_case("openvpn-control-recovery.journal") {
                // Presence alone fences startup, including a torn/empty marker.
                // Older segmented readers also reject this reserved nonnumeric name.
                return Err(ProfileStoreError::RecoveryRequired);
            } else if name.eq_ignore_ascii_case("openvpn-control.journal") {
                if name != "openvpn-control.journal" {
                    return Err(ProfileStoreError::UnsafeFile);
                }
                indices.push(0);
            } else if name.to_ascii_lowercase().starts_with("openvpn-control-")
                && name.to_ascii_lowercase().ends_with(".journal")
            {
                let digits = name
                    .strip_prefix("openvpn-control-")
                    .and_then(|n| n.strip_suffix(".journal"))
                    .ok_or(ProfileStoreError::UnsafeFile)?;
                let index: usize = digits.parse().map_err(|_| ProfileStoreError::UnsafeFile)?;
                if digits.len() != 6
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                    || index == 0
                    || index >= ssk_netd_helper::vpn::journal::MAX_SEGMENTS
                {
                    return Err(ProfileStoreError::UnsafeFile);
                }
                indices.push(index);
            }
        }
        indices.sort_unstable();
        if indices.iter().copied().ne(0..indices.len()) {
            return Err(ProfileStoreError::UnsafeFile);
        }
        Ok(indices)
    }

    pub(crate) fn journal_segment(
        &self,
        index: usize,
        create: bool,
        probe: &dyn PathSecurityProbe,
    ) -> Result<File, ProfileStoreError> {
        if index >= ssk_netd_helper::vpn::journal::MAX_SEGMENTS {
            return Err(ProfileStoreError::UnsafeFile);
        }
        self.verify(probe)?;
        let name = if index == 0 {
            "openvpn-control.journal".to_owned()
        } else {
            format!("openvpn-control-{index:06}.journal")
        };
        let path = self.layout.leaf().join(name);
        let mut options = OpenOptions::new();
        options.read(true).append(true).create_new(create);
        deny_write_delete_sharing(&mut options);
        let file = options.open(&path)?;
        self.check_file(&file, &path, probe)?;
        Ok(file)
    }

    pub(crate) fn installation_manifest(&self) -> Result<Zeroizing<Vec<u8>>, ProfileStoreError> {
        let probe = crate::service::Win32PathSecurityProbe;
        self.verify(&probe)?;
        let path = self.layout.leaf().join("openvpn-installation.json");
        let mut options = OpenOptions::new();
        options.read(true);
        deny_write_delete_sharing(&mut options);
        let file = options.open(&path)?;
        self.check_file(&file, &path, &probe)?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            crate::vpn_installation::MAX_MANIFEST + 1,
        ));
        file.take(crate::vpn_installation::MAX_MANIFEST as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > crate::vpn_installation::MAX_MANIFEST {
            return Err(ProfileStoreError::UnsafeFile);
        }
        Ok(bytes)
    }

    /// Delete only the recorded attempt's two artifacts, after OS exit proof.
    /// Open without following the leaf reparse point, deny write/delete sharing,
    /// check ACL/link count, and delete via that same handle (no path swap gap).
    pub(crate) fn cleanup_run(
        &self,
        launch_id: [u8; 16],
        probe: &dyn PathSecurityProbe,
    ) -> Result<(), ProfileStoreError> {
        use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, DELETE, FILE_DISPOSITION_INFO,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        };
        if launch_id == [0; 16] {
            return Err(ProfileStoreError::UnsafeFile);
        }
        self.verify(probe)?;
        let id: String = launch_id.iter().map(|b| format!("{b:02x}")).collect();
        for extension in ["pw", "ovpn"] {
            let path = self.layout.leaf().join(format!("run-{id}.{extension}"));
            let file = match OpenOptions::new()
                .access_mode(FILE_GENERIC_READ | DELETE)
                // Allow another read-only ACL inspection handle, but never writes/deletes.
                .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            self.check_file(&file, &path, probe)?;
            let disposition = FILE_DISPOSITION_INFO { DeleteFile: 1 };
            // SAFETY: owned checked regular file with DELETE access, exact structure.
            if unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            drop(file);
        }
        Ok(())
    }

    pub(crate) fn launch_files(
        &self,
        profile: &Profile,
        secret: &[u8],
        port: u16,
        probe: &dyn PathSecurityProbe,
    ) -> Result<LaunchFiles, ProfileStoreError> {
        self.verify(probe)?;
        crate::vpn_installation::strict_path(self.layout.leaf())
            .map_err(|_| ProfileStoreError::UnsafeDirectory)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| ProfileStoreError::Io(io::ErrorKind::Other))?;
        if random == [0; 16] {
            return Err(ProfileStoreError::Io(io::ErrorKind::Other));
        }
        let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let config = self.layout.leaf().join(format!("run-{id}.ovpn"));
        let password = self.layout.leaf().join(format!("run-{id}.pw"));
        // Claim each path BEFORE putting it in the cleanup guard. A collision
        // must never delete somebody else's artifact, including on error.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        deny_write_delete_sharing(&mut options);
        let password_file = options.open(&password)?;
        let mut files = LaunchFiles {
            launch_id: random,
            config: std::path::PathBuf::new(),
            password,
            locks: vec![password_file],
        };
        let config_file = options.open(&config)?;
        files.config = config;
        files.locks.push(config_file);
        for (path, bytes) in [
            (&files.password, None),
            (&files.config, Some(profile.render_base_config())),
        ] {
            let mut file = files.locks.remove(0);
            self.check_file(&file, path, probe)?;
            if let Some(mut text) = bytes {
                use std::fmt::Write as _;
                let password_path = files
                    .password
                    .to_str()
                    .ok_or(ProfileStoreError::UnsafeFile)?
                    .replace('\\', "\\\\");
                let _ = writeln!(text, "management 127.0.0.1 {port} \"{password_path}\"\nmanagement-client\nmanagement-hold\nmanagement-query-passwords\nmanagement-forget-disconnect\nmanagement-log-cache 10\nifconfig-noexec");
                file.write_all(text.as_bytes())?;
            } else {
                file.write_all(secret)?;
                file.write_all(b"\n")?;
            }
            file.sync_all()?;
            drop(file);
            let mut read = OpenOptions::new();
            read.read(true);
            deny_write_delete_sharing(&mut read);
            let lock = read.open(path)?;
            self.check_file(&lock, path, probe)?;
            files.locks.push(lock);
        }
        Ok(files)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{AceEntry, ProbeError};
    use std::{cell::RefCell, collections::BTreeMap, path::PathBuf};
    #[derive(Default)]
    struct Probe {
        overrides: RefCell<BTreeMap<PathBuf, PathSecurity>>,
    }
    fn protected() -> PathSecurity {
        PathSecurity {
            owner_sid: acl::SID_LOCAL_SYSTEM.into(),
            aces: Some(vec![AceEntry::allow(
                acl::SID_LOCAL_SYSTEM,
                acl::GENERIC_ALL,
            )]),
            is_reparse_point: false,
        }
    }
    impl PathSecurityProbe for Probe {
        fn inspect(&self, path: &Path) -> Result<PathSecurity, ProbeError> {
            Ok(self
                .overrides
                .borrow()
                .get(path)
                .cloned()
                .unwrap_or_else(protected))
        }
    }
    fn setup() -> (tempfile::TempDir, ProfileStore, Probe) {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("profiles");
        fs::create_dir(&path).unwrap();
        let layout = StateDirLayout::new(&path, 1).unwrap();
        let probe = Probe::default();
        let store = ProfileStore::open_layout(layout, &probe).unwrap();
        (temp, store, probe)
    }
    fn profile() -> Profile {
        Profile::parse(include_bytes!(
            "../../ssk-vpnctl/tests/fixtures/profile.json"
        ))
        .unwrap()
    }
    #[test]
    fn protected_store_roundtrip_and_conflicting_id() {
        let (_temp, store, probe) = setup();
        let profile = profile();
        store.create_with(&profile, &probe).unwrap();
        assert_eq!(
            store.load_with(&profile.id(), &probe).unwrap().id(),
            profile.id()
        );
        assert!(matches!(
            store.create_with(&profile, &probe),
            Err(ProfileStoreError::AlreadyExists)
        ));
    }
    #[test]
    fn confidentiality_rejects_read_inherit_only_null_dacl_and_unknown_aces() {
        for flags in [0, acl::INHERIT_ONLY_ACE] {
            let mut security = protected();
            let mut read = AceEntry::allow("S-1-1-0", 1);
            read.flags = flags;
            security.aces.as_mut().unwrap().push(read);
            assert!(!confidential(&security));
        }
        let mut security = protected();
        security.aces = None;
        assert!(!confidential(&security));
        security = protected();
        security.is_reparse_point = true;
        assert!(!confidential(&security));
        security = protected();
        security.aces.as_mut().unwrap()[0].ace_type = 5;
        assert!(!confidential(&security));
        security = protected();
        security.owner_sid = "S-1-5-21-1234".into();
        assert!(!confidential(&security));
    }
    #[test]
    fn changed_directory_acl_is_rechecked_before_each_access() {
        let (_temp, store, probe) = setup();
        let profile = profile();
        store.create_with(&profile, &probe).unwrap();
        let mut bad = protected();
        bad.aces
            .as_mut()
            .unwrap()
            .push(AceEntry::allow("S-1-1-0", 1));
        probe
            .overrides
            .borrow_mut()
            .insert(store.layout.leaf().to_owned(), bad);
        assert!(matches!(
            store.load_with(&profile.id(), &probe),
            Err(ProfileStoreError::UnsafeDirectory)
        ));
        assert!(matches!(
            store.create_with(&profile, &probe),
            Err(ProfileStoreError::UnsafeDirectory)
        ));
    }
    #[test]
    fn inherited_file_acl_is_checked_before_any_secret_is_written() {
        let (_temp, store, probe) = setup();
        let profile = profile();
        let path = store.path(&profile.id());
        let mut bad = protected();
        bad.aces
            .as_mut()
            .unwrap()
            .push(AceEntry::allow("S-1-1-0", 1));
        probe.overrides.borrow_mut().insert(path.clone(), bad);
        assert!(matches!(
            store.create_with(&profile, &probe),
            Err(ProfileStoreError::UnsafeFile)
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }
    #[test]
    fn mismatched_truncated_and_oversized_documents_are_refused() {
        let (_temp, store, probe) = setup();
        let profile = profile();
        let id = ProfileId::new("different").unwrap();
        let path = store.path(&id);
        fs::write(&path, &*profile.to_document().unwrap()).unwrap();
        assert!(matches!(
            store.load_with(&id, &probe),
            Err(ProfileStoreError::IdMismatch)
        ));
        fs::write(&path, b"{\"version\":1,").unwrap();
        assert!(matches!(
            store.load_with(&id, &probe),
            Err(ProfileStoreError::Profile(ProfileError::Document))
        ));
        fs::write(&path, vec![b' '; MAX_PROFILE_BYTES + 1]).unwrap();
        assert!(matches!(
            store.load_with(&id, &probe),
            Err(ProfileStoreError::Profile(ProfileError::TooLarge))
        ));
    }
    #[test]
    fn hardlinked_files_are_refused_even_with_passing_acl() {
        let (temp, store, probe) = setup();
        let profile = profile();
        store.create_with(&profile, &probe).unwrap();
        fs::hard_link(store.path(&profile.id()), temp.path().join("alias")).unwrap();
        assert!(matches!(
            store.load_with(&profile.id(), &probe),
            Err(ProfileStoreError::UnsafeFile)
        ));
    }
    #[test]
    fn nonexistent_profile_does_not_create_an_artifact() {
        let (_temp, store, probe) = setup();
        let id = ProfileId::new("absent").unwrap();
        assert!(matches!(
            store.load_with(&id, &probe),
            Err(ProfileStoreError::NotFound)
        ));
        assert!(!store.path(&id).exists());
    }
}
