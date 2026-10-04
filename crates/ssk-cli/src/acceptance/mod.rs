//! A bounded, append-only evidence bundle, not an automated VM test runner or
//! trusted attestation. All VM facts/outcomes are reviewed operator assertions.
mod catalog;
mod kit;
pub use catalog::catalog;
use catalog::EvidenceKind;
pub use kit::{kit_create, kit_verify};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path},
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, String>;
const MAX_JSON: usize = 64 * 1024;
const MAX_EVIDENCE: usize = 256 * 1024;
const MAX_ATTEMPTS: usize = 256;
const MAX_FILES: usize = 8;
const MAX_BINARY: u64 = 512 * 1024 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    schema: u32,
    vm_id: String,
    snapshot_id: String,
    windows_build: String,
    locale: String,
    disposable_vm: bool,
    isolated_network: bool,
    test_credentials_only: bool,
    operator_sid: String,
    granted_sid: String,
    ungranted_sid: String,
    admin_without_grant_sid: String,
    source_revision: String,
    worktree_dirty: bool,
    distribution: String,
    driver_version: String,
    approved_manifest_sha256: String,
    driver_sha256: String,
    configuration_sha256: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binaries {
    cli: String,
    service: String,
    recorder: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    schema: u32,
    run_id: String,
    created_unix_ms: u64,
    catalog_sha256: String,
    context: Context,
    binaries: Binaries,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Passed,
    Failed,
    Blocked,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceInput {
    file: String,
    kind: EvidenceKind,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observation {
    schema: u32,
    case_id: String,
    outcome: Outcome,
    started_unix_ms: u64,
    ended_unix_ms: u64,
    observed: String,
    sanitized: bool,
    evidence: Vec<EvidenceInput>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    file: String,
    bytes: usize,
    sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: u32,
    sequence: usize,
    run_sha256: String,
    previous: String,
    recorded_unix_ms: u64,
    observation: Observation,
    evidence: Vec<Evidence>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    body: Body,
    sha256: String,
}
struct Verified {
    run: Run,
    run_hash: String,
    head: String,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
pub struct Report {
    run_id: String,
    locale: String,
    vm_id: String,
    snapshot_id: String,
    run_sha256: String,
    head_sha256: String,
    attempts: usize,
    passed: usize,
    failed: usize,
    blocked: usize,
    not_run: usize,
    latest: BTreeMap<String, Outcome>,
    pending: Vec<String>,
    coverage_complete: bool,
    release_ready: bool,
    limitations: Vec<&'static str>,
}
#[derive(Serialize)]
pub struct CheckReport {
    pub coverage_complete: bool,
    release_ready: bool,
    runs: [Report; 2],
}

fn fail<T>(message: &str) -> Result<T> {
    Err(message.to_string())
}
fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|e| format!("evidence file operation failed: {:?}", e.kind()))
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| "evidence encoding failed".into())
}
fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|_| "invalid evidence JSON/schema".into())
}
fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "invalid clock".to_string())?
        .as_millis()
        .try_into()
        .map_err(|_| "invalid clock".into())
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn sid(value: &str) -> bool {
    ssk_netd_helper::PeerIdentity::parse_sid(value).is_ok()
}
fn validate_context(c: &Context) -> Result<()> {
    sanitize(&json(c)?)?;
    if c.schema != 1
        || !c.disposable_vm
        || !c.isolated_network
        || !c.test_credentials_only
        || !matches!(c.locale.as_str(), "en-US" | "de-DE")
        || [
            &c.vm_id,
            &c.snapshot_id,
            &c.windows_build,
            &c.distribution,
            &c.driver_version,
        ]
        .iter()
        .any(|s| !text(s, 200))
        || ![40, 64].contains(&c.source_revision.len())
        || !c
            .source_revision
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || [
            &c.approved_manifest_sha256,
            &c.driver_sha256,
            &c.configuration_sha256,
        ]
        .iter()
        .any(|h| !hash_valid(h))
        || [
            &c.operator_sid,
            &c.granted_sid,
            &c.ungranted_sid,
            &c.admin_without_grant_sid,
        ]
        .iter()
        .any(|s| !sid(s))
        || c.granted_sid == c.ungranted_sid
        || c.granted_sid == c.admin_without_grant_sid
        || c.ungranted_sid == c.admin_without_grant_sid
        || [&c.granted_sid, &c.ungranted_sid, &c.admin_without_grant_sid]
            .iter()
            .any(|s| s.as_str() == "S-1-5-18")
    {
        return fail(
            "incomplete VM context, distinct principals or explicit isolation assertions required",
        );
    }
    Ok(())
}
fn filename(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !name.starts_with('.')
        && !name.ends_with('.')
        && !name.contains("..")
        && (name.ends_with(".txt") || name.ends_with(".json"))
        && ![
            "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
            "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
        ]
        .contains(&stem.as_str())
}
fn sanitize(bytes: &[u8]) -> Result<()> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| "evidence must be reviewed UTF-8 text".to_string())?;
    if s.trim().is_empty()
        || s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return fail("empty or non-text evidence refused");
    }
    let lower = s.to_ascii_lowercase();
    if [
        "-----begin",
        "private_key",
        "password",
        "tls_auth",
        "tls_crypt",
        "sskkey01",
        "sskvpn01",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        return fail("possible credential material refused; review and sanitize evidence first");
    }
    Ok(())
}
fn validate_observation(o: &Observation) -> Result<()> {
    let case = catalog()
        .into_iter()
        .find(|c| c.id == o.case_id)
        .ok_or("unknown acceptance case")?;
    if o.schema != 1
        || !o.sanitized
        || !text(&o.observed, 4096)
        || o.evidence.len() > MAX_FILES
        || o.started_unix_ms == 0
        || o.ended_unix_ms < o.started_unix_ms
        || o.evidence.iter().any(|e| !filename(&e.file))
        || o.evidence
            .iter()
            .map(|e| &e.file)
            .collect::<BTreeSet<_>>()
            .len()
            != o.evidence.len()
    {
        return fail("invalid observation, timestamps or evidence names");
    }
    sanitize(o.observed.as_bytes())?;
    if o.outcome == Outcome::Passed
        && (!case.pass_available
            || case
                .required_evidence
                .iter()
                .any(|k| !o.evidence.iter().any(|e| &e.kind == k)))
    {
        return fail("pass requires every evidence category and implemented prerequisites");
    }
    Ok(())
}

fn safe_path(path: &Path) -> Result<()> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return fail("absolute evidence path without traversal required");
    }
    #[cfg(windows)]
    {
        let value = path.to_str().ok_or("unsupported evidence path")?;
        if value.starts_with("\\\\")
            || value.get(2..).is_none_or(|v| v.contains(':'))
            || value.chars().any(char::is_control)
            || value
                .split(['\\', '/'])
                .skip(1)
                .any(|v| v.ends_with(['.', ' ']))
        {
            return fail("device, UNC, stream or ambiguous evidence path refused");
        }
    }
    // Only inspect existing components; callers may claim a fresh final path.
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    meta.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let linked = meta.file_type().is_symlink();
                if linked {
                    return fail("symlink/reparse evidence path refused");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return io(Err(e)),
        }
    }
    Ok(())
}
fn open_file(path: &Path) -> Result<File> {
    safe_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1);
    }
    let file = io(options.open(path))?;
    if !io(file.metadata())?.is_file() {
        return fail("regular evidence file required");
    }
    Ok(file)
}
fn read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let file = open_file(path)?;
    if io(file.metadata())?.len() > max as u64 {
        return fail("evidence size limit exceeded");
    }
    let mut bytes = Vec::new();
    io(file.take(max as u64 + 1).read_to_end(&mut bytes))?;
    if bytes.len() > max {
        return fail("evidence size limit exceeded");
    }
    Ok(bytes)
}
fn binary_hash(path: &Path) -> Result<String> {
    let file = open_file(path)?;
    let len = io(file.metadata())?.len();
    if len == 0 || len > MAX_BINARY {
        return fail("binary size limit exceeded");
    }
    let mut reader = file.take(MAX_BINARY + 1);
    let mut bytes = [0; 65536];
    let mut count = 0;
    let mut hash = Sha256::new();
    loop {
        let n = io(reader.read(&mut bytes))?;
        if n == 0 {
            break;
        }
        count += n as u64;
        hash.update(&bytes[..n]);
    }
    if count != len {
        return fail("binary changed during fingerprinting");
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    safe_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
    }
    let mut file = io(options.open(path))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())
}
fn names(path: &Path, max: usize) -> Result<BTreeSet<String>> {
    safe_path(path)?;
    let mut names = BTreeSet::new();
    for entry in io(fs::read_dir(path))? {
        let entry = io(entry)?;
        if names.len() >= max {
            return fail("evidence directory entry limit exceeded");
        }
        names.insert(
            entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid evidence filename")?,
        );
    }
    Ok(names)
}

pub fn init(context: &Path, cli: &Path, service: &Path, recorder: &Path, out: &Path) -> Result<()> {
    let context: Context = parse(&read(context, MAX_JSON)?)?;
    validate_context(&context)?;
    let binaries = Binaries {
        cli: binary_hash(cli)?,
        service: binary_hash(service)?,
        recorder: binary_hash(recorder)?,
    };
    let mut run_id = [0; 16];
    getrandom::fill(&mut run_id).map_err(|_| "OS random source failed")?;
    let run = Run {
        schema: 1,
        run_id: run_id.iter().map(|b| format!("{b:02x}")).collect(),
        created_unix_ms: now()?,
        catalog_sha256: sha(&json(&catalog())?),
        context,
        binaries,
    };
    safe_path(out)?;
    io(fs::create_dir(out))?;
    io(fs::create_dir(out.join("attempts")))?;
    write_new(&out.join("run.json"), &json(&run)?)
}
fn verify(bundle: &Path, expected_head: Option<&str>) -> Result<Verified> {
    if names(bundle, 2)? != BTreeSet::from(["attempts".into(), "run.json".into()]) {
        return fail("unexpected bundle files");
    }
    let run: Run = parse(&read(&bundle.join("run.json"), MAX_JSON)?)?;
    validate_context(&run.context)?;
    if run.schema != 1
        || run.created_unix_ms == 0
        || run.run_id.len() != 32
        || !run
            .run_id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        || run.catalog_sha256 != sha(&json(&catalog())?)
        || [
            &run.binaries.cli,
            &run.binaries.service,
            &run.binaries.recorder,
        ]
        .iter()
        .any(|h| !hash_valid(h))
    {
        return fail("unsupported or invalid acceptance run");
    }
    let run_hash = sha(&json(&run)?);
    let mut head = run_hash.clone();
    let mut entries = Vec::new();
    let attempts = names(&bundle.join("attempts"), MAX_ATTEMPTS)?;
    for (index, name) in attempts.iter().enumerate() {
        if *name != format!("{:06}", index + 1) {
            return fail("missing or noncanonical attempt sequence");
        }
        let dir = bundle.join("attempts").join(name);
        let entry: Entry = parse(&read(&dir.join("record.json"), MAX_JSON)?)?;
        let body = &entry.body;
        validate_observation(&body.observation)?;
        if body.schema != 1
            || body.sequence != index + 1
            || body.run_sha256 != run_hash
            || body.previous != head
            || entry.sha256 != sha(&json(body)?)
            || body.evidence.len() != body.observation.evidence.len()
            || body.observation.started_unix_ms < run.created_unix_ms
            || body.recorded_unix_ms < body.observation.ended_unix_ms
        {
            return fail("broken attempt binding, timestamps or hash chain");
        }
        let mut expected_names = BTreeSet::from(["record.json".to_string()]);
        for (i, proof) in body.evidence.iter().enumerate() {
            if proof.file != format!("evidence-{:02}.txt", i + 1) || proof.bytes > MAX_EVIDENCE {
                return fail("invalid evidence binding");
            }
            expected_names.insert(proof.file.clone());
            let bytes = read(&dir.join(&proof.file), MAX_EVIDENCE)?;
            sanitize(&bytes)?;
            if bytes.len() != proof.bytes || sha(&bytes) != proof.sha256 {
                return fail("missing or changed evidence bytes");
            }
        }
        if names(&dir, MAX_FILES + 1)? != expected_names {
            return fail("unexpected attempt files");
        }
        head = entry.sha256.clone();
        entries.push(entry);
    }
    if expected_head.is_some_and(|expected| expected != head) {
        return fail("external head mismatch; history may have changed or shrunk");
    }
    Ok(Verified {
        run,
        run_hash,
        head,
        entries,
    })
}
pub fn record(bundle: &Path, observation: &Path, evidence_dir: &Path) -> Result<()> {
    let verified = verify(bundle, None)?;
    if verified.entries.len() >= MAX_ATTEMPTS {
        return fail("attempt capacity reached");
    }
    let observation: Observation = parse(&read(observation, MAX_JSON)?)?;
    validate_observation(&observation)?;
    let time = now()?;
    if observation.started_unix_ms < verified.run.created_unix_ms
        || observation.ended_unix_ms > time
    {
        return fail("observation must follow run creation and precede recording");
    }
    let mut copies = Vec::new();
    let mut evidence = Vec::new();
    for (i, input) in observation.evidence.iter().enumerate() {
        let bytes = read(&evidence_dir.join(&input.file), MAX_EVIDENCE)?;
        sanitize(&bytes)?;
        evidence.push(Evidence {
            file: format!("evidence-{:02}.txt", i + 1),
            bytes: bytes.len(),
            sha256: sha(&bytes),
        });
        copies.push(bytes);
    }
    let body = Body {
        schema: 1,
        sequence: verified.entries.len() + 1,
        run_sha256: verified.run_hash,
        previous: verified.head,
        recorded_unix_ms: time,
        observation,
        evidence,
    };
    let entry = Entry {
        sha256: sha(&json(&body)?),
        body,
    };
    let dir = bundle
        .join("attempts")
        .join(format!("{:06}", entry.body.sequence));
    // Atomic directory claim serializes writers; partial attempts remain visible
    // and block every later append rather than being silently skipped/replaced.
    safe_path(&dir)?;
    io(fs::create_dir(&dir))?;
    for (proof, bytes) in entry.body.evidence.iter().zip(copies) {
        write_new(&dir.join(&proof.file), &bytes)?;
    }
    write_new(&dir.join("record.json"), &json(&entry)?)?;
    verify(bundle, Some(&entry.sha256)).map(|_| ())
}
fn summarize(v: Verified) -> Report {
    let mut latest = BTreeMap::new();
    for entry in &v.entries {
        latest.insert(
            entry.body.observation.case_id.clone(),
            entry.body.observation.outcome,
        );
    }
    let pending = catalog()
        .into_iter()
        .filter(|c| latest.get(&c.id) != Some(&Outcome::Passed))
        .map(|c| c.id)
        .collect::<Vec<_>>();
    Report {
        run_id: v.run.run_id,
        locale: v.run.context.locale,
        vm_id: v.run.context.vm_id,
        snapshot_id: v.run.context.snapshot_id,
        run_sha256: v.run_hash,
        head_sha256: v.head,
        attempts: v.entries.len(),
        passed: latest.values().filter(|v| **v == Outcome::Passed).count(),
        failed: latest.values().filter(|v| **v == Outcome::Failed).count(),
        blocked: latest.values().filter(|v| **v == Outcome::Blocked).count(),
        not_run: catalog().len() - latest.len(),
        coverage_complete: pending.is_empty(),
        latest,
        pending,
        release_ready: false,
        limitations: vec![
            "operator assertions, not execution or attestation",
            "local hashes require a separately trusted head",
            "tunnel enforcement and operational release gates remain open",
        ],
    }
}
pub fn report(bundle: &Path, expected_head: Option<&str>) -> Result<Report> {
    Ok(summarize(verify(bundle, expected_head)?))
}
pub fn check(en: &Path, de: &Path, en_head: &str, de_head: &str) -> Result<CheckReport> {
    let en = verify(en, Some(en_head))?;
    let de = verify(de, Some(de_head))?;
    let a = &en.run;
    let b = &de.run;
    if a.context.locale != "en-US"
        || b.context.locale != "de-DE"
        || a.run_id == b.run_id
        || json(&a.binaries)? != json(&b.binaries)?
        || a.context.source_revision != b.context.source_revision
        || a.context.worktree_dirty != b.context.worktree_dirty
        || a.context.windows_build != b.context.windows_build
        || a.context.distribution != b.context.distribution
        || a.context.driver_version != b.context.driver_version
        || a.context.approved_manifest_sha256 != b.context.approved_manifest_sha256
        || a.context.driver_sha256 != b.context.driver_sha256
    {
        return fail("locale runs must test the same pinned build, OS, distribution and driver");
    }
    // Profile grants/credentials may legitimately differ across VM principals.
    let runs = [summarize(en), summarize(de)];
    Ok(CheckReport {
        coverage_complete: runs.iter().all(|r| r.coverage_complete),
        release_ready: false,
        runs,
    })
}

#[cfg(test)]
mod tests;
