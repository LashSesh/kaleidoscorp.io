//! Administrator-pinned, flat OpenVPN bundle. No registry/PATH discovery and no
//! executable path or hash supplied through IPC. All files remain read-locked.
use crate::{
    service::{self, acl, ComponentKind, PathSecurityProbe},
    vpn_profiles::{deny_write_delete_sharing, reparse, single_link},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
};

pub(crate) const MAX_MANIFEST: usize = 16 * 1024;
const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationError {
    Manifest,
    Path,
    Permissions,
    Contents,
    Digest,
    Io(io::ErrorKind),
}
impl From<io::Error> for InstallationError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) schema: u32,
    pub(crate) protocol: String,
    pub(crate) directory: PathBuf,
    pub(crate) files: Vec<Entry>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) sha256: String,
}

pub(crate) struct Installation {
    pub(crate) directory: PathBuf,
    // Keep all approved images/provider modules immutable during the session.
    _files: Vec<File>,
}
impl Installation {
    pub(crate) fn open(bytes: &[u8]) -> Result<Self, InstallationError> {
        Self::open_with(bytes, &service::Win32PathSecurityProbe)
    }
    pub(crate) fn locked_files(&mut self) -> &mut [File] {
        &mut self._files
    }
    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }
    pub(crate) fn executable(&self) -> PathBuf {
        self.directory.join("openvpn.exe")
    }

    pub(crate) fn manifest(
        bytes: &[u8],
    ) -> Result<(PathBuf, BTreeMap<String, [u8; 32]>), InstallationError> {
        if bytes.len() > MAX_MANIFEST {
            return Err(InstallationError::Manifest);
        }
        let m: Manifest = serde_json::from_slice(bytes).map_err(|_| InstallationError::Manifest)?;
        if m.schema != 1 || m.protocol != "openvpn-2.6" || m.files.is_empty() || m.files.len() > 32
        {
            return Err(InstallationError::Manifest);
        }
        strict_path(&m.directory)?;
        let mut entries = BTreeMap::new();
        for e in m.files {
            if e.name.len() > 100
                || e.name.is_empty()
                || !e.name.as_bytes()[0].is_ascii_lowercase()
                || !e
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_.".contains(&b))
                || (e.name != "openvpn.exe" && !e.name.ends_with(".dll"))
                || e.name.contains("..")
            {
                return Err(InstallationError::Manifest);
            }
            let digest = digest(&e.sha256)?;
            if entries.insert(e.name, digest).is_some() {
                return Err(InstallationError::Manifest);
            }
        }
        if !entries.contains_key("openvpn.exe") {
            return Err(InstallationError::Manifest);
        }
        Ok((m.directory, entries))
    }

    pub(crate) fn open_with(
        bytes: &[u8],
        probe: &dyn PathSecurityProbe,
    ) -> Result<Self, InstallationError> {
        Self::open_checked(bytes, probe, true)
    }
    pub(crate) fn source(
        bytes: &[u8],
        probe: &dyn PathSecurityProbe,
    ) -> Result<Self, InstallationError> {
        Self::open_checked(bytes, probe, false)
    }
    fn open_checked(
        bytes: &[u8],
        probe: &dyn PathSecurityProbe,
        protected: bool,
    ) -> Result<Self, InstallationError> {
        let (directory, expected) = Self::manifest(bytes)?;
        let exe = directory.join("openvpn.exe");
        if protected {
            service::verify_image_path_protected(&exe, probe)
                .map_err(|_| InstallationError::Permissions)?;
        }
        for (path, kind) in service::image_path_chain(&exe).map_err(|_| InstallationError::Path)? {
            if reparse(&path)? {
                return Err(InstallationError::Permissions);
            }
            if protected && kind != ComponentKind::Ancestor {
                readonly_for_others(&path, probe)?;
            }
        }
        let mut observed = BTreeMap::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| InstallationError::Contents)?;
            if !expected.contains_key(&name)
                || !entry.file_type()?.is_file()
                || reparse(&entry.path())?
            {
                return Err(InstallationError::Contents);
            }
            observed.insert(name, entry.path());
            if observed.len() > 32 {
                return Err(InstallationError::Contents);
            }
        }
        if observed.len() != expected.len() {
            return Err(InstallationError::Contents);
        }
        let mut files = Vec::with_capacity(expected.len());
        let mut total = 0u64;
        for (name, hash) in expected {
            let path = observed.get(&name).ok_or(InstallationError::Contents)?;
            if protected {
                readonly_for_others(path, probe)?;
            }
            let mut options = OpenOptions::new();
            options.read(true);
            deny_write_delete_sharing(&mut options);
            let mut file = options.open(path)?;
            let length = file.metadata()?.len();
            total = total
                .checked_add(length)
                .ok_or(InstallationError::Contents)?;
            if !file.metadata()?.is_file()
                || !single_link(&file)?
                || length == 0
                || length > MAX_FILE
                || total > MAX_BUNDLE
            {
                return Err(InstallationError::Contents);
            }
            if hash_file(&mut file, length)? != hash {
                return Err(InstallationError::Digest);
            }
            files.push(file);
        }
        Ok(Self {
            directory,
            _files: files,
        })
    }
}

fn readonly_for_others(
    path: &Path,
    probe: &dyn PathSecurityProbe,
) -> Result<(), InstallationError> {
    let security = probe
        .inspect(path)
        .map_err(|_| InstallationError::Permissions)?;
    service::audit_component(ComponentKind::Image, path, &security)
        .map_err(|_| InstallationError::Permissions)?;
    // Include inherit-only entries and uncommon write-attribute/EA grants.
    const READ_ONLY: u32 = 0x0012_00a9 | 0x8000_0000 | 0x2000_0000;
    for ace in security.aces.ok_or(InstallationError::Permissions)? {
        if ace.ace_type == acl::ACCESS_ALLOWED_ACE_TYPE
            && !service::is_administrative_sid(&ace.sid)
            && ace.mask & !READ_ONLY != 0
        {
            return Err(InstallationError::Permissions);
        }
    }
    Ok(())
}

pub(crate) fn strict_path(path: &Path) -> Result<(), InstallationError> {
    service::reject_unsupported_path_form(path).map_err(|_| InstallationError::Path)?;
    let text = path.to_str().ok_or(InstallationError::Path)?;
    // Reject alternate streams, DOS normalization tricks and config quoting
    // ambiguity. Drive-colon is the only colon accepted. No UNC/device paths.
    if text.len() > 240
        || text.starts_with("\\\\")
        || text.get(2..).is_none_or(|s| s.contains(':'))
        || text.chars().any(|c| c.is_control() || c == '"')
        || text
            .split(['\\', '/'])
            .skip(1)
            .any(|s| s == "." || s == ".." || s.ends_with(['.', ' ']))
    {
        return Err(InstallationError::Path);
    }
    Ok(())
}

pub(crate) fn digest(value: &str) -> Result<[u8; 32], InstallationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(InstallationError::Manifest);
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| InstallationError::Manifest)?;
    }
    Ok(out)
}
pub(crate) fn hash_file(file: &mut File, length: u64) -> Result<[u8; 32], InstallationError> {
    let mut hasher = Sha256::new();
    let mut read = 0u64;
    let mut buf = [0u8; 16384];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > length {
            return Err(InstallationError::Contents);
        }
        hasher.update(&buf[..n]);
    }
    if read != length {
        return Err(InstallationError::Contents);
    }
    Ok(hasher.finalize().into())
}
