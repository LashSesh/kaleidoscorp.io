//! Fixed, non-secret development kit. The manifest is committed last; no archive
//! extraction, directory scanning of source trees, execution or install action.
use super::*;
use std::io::{Seek, SeekFrom};

macro_rules! asset {
    ($name:literal) => {
        (
            $name,
            include_bytes!(concat!("../../../../", $name)).as_slice(),
        )
    };
}
fn assets() -> Vec<(&'static str, &'static [u8])> {
    vec![
        asset!("docs/OPENVPN_TEST_KIT.md"),
        asset!("docs/OPENVPN_ACCEPTANCE_TOOL.md"),
        asset!("docs/OPENVPN_VM_ACCEPTANCE.md"),
        asset!("docs/OPENVPN_BROKER_CONTROL.md"),
        asset!("docs/OPENVPN_PACKAGE_DEPLOYMENT.md"),
        asset!("docs/OPENVPN_CONFIGURATION_DEPLOYMENT.md"),
        asset!("docs/OPENVPN_CONFIGURATION_RESTORE.md"),
        asset!("docs/OPENVPN_CONFIGURATION_BACKUP.md"),
        asset!("docs/OPENVPN_JOURNAL_RETENTION.md"),
        asset!("docs/OPENVPN_JOURNAL_BACKUP.md"),
        asset!("docs/OPENVPN_RECOVERY.md"),
        asset!("docs/OPENVPN_PROFILES_AND_PROCESS.md"),
        asset!("docs/OPENVPN_SECURE_START.md"),
        asset!("docs/OPENVPN_MANAGEMENT.md"),
        asset!("docs/examples/openvpn-acceptance-context.json"),
        asset!("docs/examples/openvpn-acceptance-observation.json"),
        asset!("scripts/openvpn-vm-host-probe.ps1"),
    ]
}
const BINARIES: [&str; 3] = [
    "bin/ssk.exe",
    "bin/ssk-svc.exe",
    "bin/ssk-vpn-acceptance.exe",
];
const DIRECTORIES: [&str; 4] = ["bin", "docs", "docs/examples", "scripts"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KitFile {
    path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    purpose: String,
    created_unix_ms: u64,
    source_revision: String,
    worktree_dirty: bool,
    development_only: bool,
    files: Vec<KitFile>,
}
#[derive(Serialize)]
pub struct KitReport {
    pub manifest_sha256: String,
    files: usize,
    total_bytes: u64,
    source_revision: String,
    worktree_dirty: bool,
    development_only: bool,
    release_ready: bool,
}
fn revision_valid(value: &str) -> bool {
    [40, 64].contains(&value.len())
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pe(file: &mut File) -> Result<()> {
    let len = io(file.metadata())?.len();
    if !(90..=MAX_BINARY).contains(&len) {
        return fail("kit binary size refused");
    }
    let mut dos = [0; 64];
    io(file.read_exact(&mut dos))?;
    if &dos[..2] != b"MZ" {
        return fail("kit requires Windows x64 PE executables");
    }
    let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    if !(64..=1024 * 1024).contains(&offset) || offset + 26 > len {
        return fail("invalid PE header offset");
    }
    io(file.seek(SeekFrom::Start(offset)))?;
    let mut header = [0; 26];
    io(file.read_exact(&mut header))?;
    let flags = u16::from_le_bytes([header[22], header[23]]);
    if &header[..4] != b"PE\0\0"
        || u16::from_le_bytes([header[4], header[5]]) != 0x8664
        || u16::from_le_bytes([header[6], header[7]]) == 0
        || flags & 0x2000 != 0
        || flags & 2 == 0
        || u16::from_le_bytes([header[20], header[21]]) < 2
        || u16::from_le_bytes([header[24], header[25]]) != 0x20b
    {
        return fail("kit requires Windows x64 PE executables");
    }
    io(file.seek(SeekFrom::Start(0)))?;
    Ok(())
}
fn claim(path: &Path) -> Result<File> {
    safe_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    io(options.open(path))
}
fn copy_binary(mut source: File, out: &Path, relative: &str) -> Result<KitFile> {
    let expected = io(source.metadata())?.len();
    let mut target = claim(&out.join(relative))?;
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buf = [0; 65536];
    loop {
        let n = io(source.read(&mut buf))?;
        if n == 0 {
            break;
        }
        count += n as u64;
        if count > MAX_BINARY {
            return fail("kit binary grew beyond bound");
        }
        io(target.write_all(&buf[..n]))?;
        hash.update(&buf[..n]);
    }
    if count != expected {
        return fail("kit binary changed while copying");
    }
    io(target.sync_all())?;
    drop(target);
    let sha256 = format!("{:x}", hash.finalize());
    if binary_hash(&out.join(relative))? != sha256 {
        return fail("kit binary readback mismatch");
    }
    Ok(KitFile {
        path: relative.into(),
        bytes: count,
        sha256,
    })
}
pub fn kit_create(
    cli: &Path,
    service: &Path,
    recorder: &Path,
    revision: &str,
    dirty: bool,
    out: &Path,
) -> Result<KitReport> {
    if !revision_valid(revision) {
        return fail("full non-placeholder source revision required");
    }
    let mut inputs = Vec::new();
    for path in [cli, service, recorder] {
        let mut file = open_file(path)?;
        pe(&mut file)?;
        inputs.push(file);
    }
    // Validate every input before claiming a destination. Keep source handles
    // pinned throughout copying on Windows (read sharing only).
    safe_path(out)?;
    io(fs::create_dir(out))?;
    for dir in DIRECTORIES {
        io(fs::create_dir(out.join(dir)))?;
    }
    let mut files = Vec::new();
    for (file, name) in inputs.into_iter().zip(BINARIES) {
        files.push(copy_binary(file, out, name)?);
    }
    for (name, bytes) in assets() {
        write_new(&out.join(name), bytes)?;
        if read(&out.join(name), MAX_EVIDENCE)? != bytes {
            return fail("kit reference readback mismatch");
        }
        files.push(KitFile {
            path: name.into(),
            bytes: bytes.len() as u64,
            sha256: sha(bytes),
        });
    }
    let manifest = Manifest {
        schema: 2,
        purpose: "openvpn-vm-acceptance-development".into(),
        created_unix_ms: now()?,
        source_revision: revision.into(),
        worktree_dirty: dirty,
        development_only: true,
        files,
    };
    let bytes = json(&manifest)?;
    write_new(&out.join("manifest.json"), &bytes)?;
    kit_verify(out, &sha(&bytes))
}
fn inventory(root: &Path, path: &Path, found: &mut BTreeSet<String>) -> Result<()> {
    safe_path(path)?;
    for item in io(fs::read_dir(path))? {
        let item = io(item)?;
        let child = item.path();
        safe_path(&child)?;
        if found.len() >= 64 {
            return fail("kit entry bound exceeded");
        }
        let relative = child
            .strip_prefix(root)
            .map_err(|_| "invalid kit path")?
            .to_str()
            .ok_or("invalid kit filename")?
            .replace('\\', "/");
        if relative.split('/').count() > 3 {
            return fail("kit directory depth exceeded");
        }
        found.insert(relative);
        if io(item.file_type())?.is_dir() {
            inventory(root, &child, found)?;
        }
    }
    Ok(())
}
pub fn kit_verify(root: &Path, expected: &str) -> Result<KitReport> {
    if !hash_valid(expected) {
        return fail("expected manifest SHA-256 required");
    }
    let bytes = read(&root.join("manifest.json"), MAX_JSON)?;
    if sha(&bytes) != expected {
        return fail("kit manifest differs from trusted expected hash");
    }
    let manifest: Manifest = parse(&bytes)?;
    if !matches!(manifest.schema, 1 | 2)
        || manifest.purpose != "openvpn-vm-acceptance-development"
        || !manifest.development_only
        || manifest.created_unix_ms == 0
        || !revision_valid(&manifest.source_revision)
    {
        return fail("unsupported kit manifest");
    }
    let expected_files = BINARIES
        .into_iter()
        .chain(
            assets()
                .iter()
                .map(|(name, _)| *name)
                .filter(|name| manifest.schema >= 2 || *name != "docs/OPENVPN_JOURNAL_BACKUP.md"),
        )
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    if manifest.files.len() != expected_files.len()
        || manifest
            .files
            .iter()
            .map(|f| f.path.clone())
            .collect::<BTreeSet<_>>()
            != expected_files
    {
        return fail("kit file list differs from fixed inventory");
    }
    let mut expected_paths = expected_files;
    expected_paths.extend(DIRECTORIES.map(str::to_string));
    expected_paths.insert("manifest.json".into());
    let mut paths = BTreeSet::new();
    inventory(root, root, &mut paths)?;
    if paths != expected_paths {
        return fail("missing or extra kit entries");
    }
    let mut total = 0;
    for file in &manifest.files {
        let path = root.join(&file.path);
        let mut handle = open_file(&path)?;
        if io(handle.metadata())?.len() != file.bytes {
            return fail("kit file size changed");
        }
        if BINARIES.contains(&file.path.as_str()) {
            pe(&mut handle)?;
        } else if file.bytes > MAX_EVIDENCE as u64 {
            return fail("kit reference size exceeded");
        }
        if binary_hash(&path)? != file.sha256 {
            return fail("kit file hash changed");
        }
        total += file.bytes;
    }
    Ok(KitReport {
        manifest_sha256: expected.into(),
        files: manifest.files.len(),
        total_bytes: total,
        source_revision: manifest.source_revision,
        worktree_dirty: manifest.worktree_dirty,
        development_only: true,
        release_ready: false,
    })
}

#[cfg(test)]
#[path = "kit_tests.rs"]
mod tests;
