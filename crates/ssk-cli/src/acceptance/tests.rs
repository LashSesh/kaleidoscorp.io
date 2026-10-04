use super::*;

struct Fixture {
    temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("binary.exe"),
            b"fixture binary, never executed",
        )
        .unwrap();
        fs::create_dir(temp.path().join("input")).unwrap();
        Self { temp }
    }
    fn path(&self, file: &str) -> std::path::PathBuf {
        self.temp.path().join(file)
    }
    fn context(&self, locale: &str) -> Context {
        Context {
            schema: 1,
            vm_id: "FIXTURE-VM".into(),
            snapshot_id: "fixture-snapshot".into(),
            windows_build: "fixture-Windows-build".into(),
            locale: locale.into(),
            disposable_vm: true,
            isolated_network: true,
            test_credentials_only: true,
            operator_sid: "S-1-5-21-1-2-3-1003".into(),
            granted_sid: "S-1-5-21-1-2-3-1001".into(),
            ungranted_sid: "S-1-5-21-1-2-3-1002".into(),
            admin_without_grant_sid: "S-1-5-21-1-2-3-1003".into(),
            source_revision: "ab".repeat(20),
            worktree_dirty: true,
            distribution: "fixture OpenVPN".into(),
            driver_version: "fixture driver".into(),
            approved_manifest_sha256: "cd".repeat(32),
            driver_sha256: "ef".repeat(32),
            configuration_sha256: "12".repeat(32),
        }
    }
    fn init(&self, locale: &str) -> std::path::PathBuf {
        let context = self.path(&format!("{locale}.json"));
        fs::write(&context, json(&self.context(locale)).unwrap()).unwrap();
        let out = self.path(locale);
        let binary = self.path("binary.exe");
        init(&context, &binary, &binary, &binary, &out).unwrap();
        out
    }
    fn observation(&self, case: &str, outcome: Outcome) -> Observation {
        let time = now().unwrap();
        let kinds = catalog()
            .into_iter()
            .find(|c| c.id == case)
            .unwrap()
            .required_evidence;
        let evidence = kinds
            .into_iter()
            .enumerate()
            .map(|(i, kind)| {
                let file = format!("proof-{i}.txt");
                fs::write(
                    self.path("input").join(&file),
                    format!("Reviewed fixture evidence category {kind:?}; no real VM test."),
                )
                .unwrap();
                EvidenceInput { file, kind }
            })
            .collect();
        Observation {
            schema: 1,
            case_id: case.into(),
            outcome,
            started_unix_ms: time,
            ended_unix_ms: time,
            observed: "Fixture-only outcome; no real acceptance performed.".into(),
            sanitized: true,
            evidence,
        }
    }
    fn record(&self, bundle: &Path, observation: &Observation) -> Result<()> {
        let path = self.path("observation.json");
        fs::write(&path, json(observation).unwrap()).unwrap();
        record(bundle, &path, &self.path("input"))
    }
}

#[test]
fn catalog_matches_every_documented_case_and_keeps_unimplemented_gates_blocked() {
    let markdown = include_str!("../../../../docs/OPENVPN_VM_ACCEPTANCE.md");
    let ids = markdown
        .lines()
        .filter_map(|line| {
            let id = line.strip_prefix("| ")?.split(" | ").next()?;
            (id.len() == 3 && id.as_bytes()[1..].iter().all(u8::is_ascii_digit))
                .then_some(id.to_string())
        })
        .collect::<BTreeSet<_>>();
    let cases = catalog();
    assert_eq!(cases.len(), 49);
    assert_eq!(ids, cases.iter().map(|c| c.id.clone()).collect());
    assert_eq!(
        cases
            .iter()
            .filter(|c| !c.pass_available)
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        vec!["J07", "D08", "B06"]
    );
}

#[test]
fn init_fingerprints_binaries_and_starts_all_cases_unexecuted() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    let report = report(&bundle, None).unwrap();
    assert_eq!(report.not_run, 49);
    assert_eq!(report.passed, 0);
    assert!(!report.coverage_complete);
    assert!(!report.release_ready);
    let run: Run = parse(&read(&bundle.join("run.json"), MAX_JSON).unwrap()).unwrap();
    assert_eq!(run.binaries.cli, sha(b"fixture binary, never executed"));
    let before = fs::read(bundle.join("run.json")).unwrap();
    assert!(init(
        &f.path("en-US.json"),
        &f.path("binary.exe"),
        &f.path("binary.exe"),
        &f.path("binary.exe"),
        &bundle
    )
    .is_err());
    assert_eq!(fs::read(bundle.join("run.json")).unwrap(), before);
}

#[test]
fn invalid_context_and_json_never_claim_a_bundle() {
    let f = Fixture::new();
    let binary = f.path("binary.exe");
    for field in ["disposable_vm", "isolated_network", "test_credentials_only"] {
        let mut c = serde_json::to_value(f.context("en-US")).unwrap();
        c[field] = false.into();
        fs::write(f.path("context.json"), serde_json::to_vec(&c).unwrap()).unwrap();
        assert!(init(
            &f.path("context.json"),
            &binary,
            &binary,
            &binary,
            &f.path("out")
        )
        .is_err());
        assert!(!f.path("out").exists());
    }
    for bytes in [
        b"{\"schema\":1,\"schema\":1}".as_slice(),
        b"{\"unknown\":true}",
        b"null",
    ] {
        assert!(parse::<Context>(bytes).is_err());
    }
    let mut c = f.context("fr-FR");
    assert!(validate_context(&c).is_err());
    c.locale = "de-DE".into();
    c.ungranted_sid = c.granted_sid.clone();
    assert!(validate_context(&c).is_err());
}

#[test]
fn attempts_are_appended_and_latest_failure_replaces_prior_pass_in_summary() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    f.record(&bundle, &f.observation("H02", Outcome::Passed))
        .unwrap();
    let first = fs::read(bundle.join("attempts/000001/record.json")).unwrap();
    let head = report(&bundle, None).unwrap().head_sha256;
    f.record(&bundle, &f.observation("H02", Outcome::Failed))
        .unwrap();
    let report = report(&bundle, None).unwrap();
    assert_eq!(report.attempts, 2);
    assert_eq!(report.passed, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(report.not_run, 48);
    assert!(report.pending.contains(&"H02".to_string()));
    assert_eq!(
        fs::read(bundle.join("attempts/000001/record.json")).unwrap(),
        first
    );
    assert!(super::report(&bundle, Some(&head)).is_err());
}

#[test]
fn pass_requires_reviewed_observation_and_all_categories() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    let mut o = f.observation("H01", Outcome::Passed);
    o.evidence.pop();
    assert!(f.record(&bundle, &o).is_err());
    o.outcome = Outcome::Blocked;
    o.evidence.clear();
    f.record(&bundle, &o).unwrap();
    let mut o = f.observation("H02", Outcome::Passed);
    o.sanitized = false;
    assert!(f.record(&bundle, &o).is_err());
    o.sanitized = true;
    o.observed.clear();
    assert!(f.record(&bundle, &o).is_err());
    for id in ["J07", "D08", "B06"] {
        assert!(f
            .record(&bundle, &f.observation(id, Outcome::Passed))
            .is_err());
    }
    assert_eq!(report(&bundle, None).unwrap().attempts, 1);
}

#[test]
fn missing_changed_and_unexpected_evidence_never_produces_success() {
    for fault in ["changed", "missing", "extra", "record"] {
        let f = Fixture::new();
        let bundle = f.init("en-US");
        f.record(&bundle, &f.observation("H02", Outcome::Passed))
            .unwrap();
        let dir = bundle.join("attempts/000001");
        match fault {
            "changed" => fs::write(dir.join("evidence-01.txt"), b"changed").unwrap(),
            "missing" => fs::remove_file(dir.join("evidence-01.txt")).unwrap(),
            "extra" => fs::write(dir.join("unbound.txt"), b"extra").unwrap(),
            _ => fs::write(dir.join("record.json"), b"{partial").unwrap(),
        }
        assert!(report(&bundle, None).is_err());
        assert!(f
            .record(&bundle, &f.observation("H03", Outcome::Blocked))
            .is_err());
    }
}

#[test]
fn partial_attempt_is_preserved_and_blocks_later_appends() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    let dir = bundle.join("attempts/000001");
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("evidence-01.txt"), b"partial retained evidence").unwrap();
    assert!(report(&bundle, None).is_err());
    assert!(f
        .record(&bundle, &f.observation("H02", Outcome::Passed))
        .is_err());
    assert_eq!(
        fs::read(dir.join("evidence-01.txt")).unwrap(),
        b"partial retained evidence"
    );
    assert!(!bundle.join("attempts/000002").exists());
}

#[test]
fn external_head_detects_removed_tail_and_run_edit() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    f.record(&bundle, &f.observation("H02", Outcome::Passed))
        .unwrap();
    let head = report(&bundle, None).unwrap().head_sha256;
    // Only a fixture-owned exact directory is removed to model a lost tail.
    fs::remove_dir_all(bundle.join("attempts/000001")).unwrap();
    assert!(report(&bundle, Some(&head)).is_err());
    assert_eq!(report(&bundle, None).unwrap().not_run, 49); // no local anchor, no invention of passes
    let initial = report(&bundle, None).unwrap().head_sha256;
    let mut run: Run = parse(&read(&bundle.join("run.json"), MAX_JSON).unwrap()).unwrap();
    run.context.snapshot_id = "changed".into();
    fs::write(bundle.join("run.json"), json(&run).unwrap()).unwrap();
    assert!(report(&bundle, Some(&initial)).is_err());
}

#[test]
fn swapped_attempts_and_noncanonical_or_gapped_sequences_are_refused() {
    for new_name in ["000002", "1", "000001-extra"] {
        let f = Fixture::new();
        let bundle = f.init("en-US");
        f.record(&bundle, &f.observation("H02", Outcome::Passed))
            .unwrap();
        fs::rename(
            bundle.join("attempts/000001"),
            bundle.join("attempts").join(new_name),
        )
        .unwrap();
        assert!(report(&bundle, None).is_err());
    }
    let f = Fixture::new();
    let en = f.init("en-US");
    let de = f.init("de-DE");
    f.record(&en, &f.observation("H02", Outcome::Passed))
        .unwrap();
    fs::rename(en.join("attempts/000001"), de.join("attempts/000001")).unwrap();
    assert!(report(&de, None).is_err());
}

#[test]
fn evidence_rejects_paths_secrets_binary_and_oversized_inputs_before_writing() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    for name in [
        "../escape.txt",
        "C:\\private.txt",
        "nul.txt",
        "proof.key",
        "a/b.txt",
        "a..b.json",
    ] {
        let mut o = f.observation("H02", Outcome::Passed);
        o.evidence[0].file = name.into();
        assert!(f.record(&bundle, &o).is_err());
    }
    for bytes in [
        b"-----BEGIN PRIVATE KEY-----".to_vec(),
        b"password=value".to_vec(),
        vec![0; 3],
        vec![b'a'; MAX_EVIDENCE + 1],
    ] {
        let o = f.observation("H02", Outcome::Passed);
        fs::write(f.path("input").join(&o.evidence[0].file), bytes).unwrap();
        assert!(f.record(&bundle, &o).is_err());
    }
    assert!(names(&bundle.join("attempts"), MAX_ATTEMPTS)
        .unwrap()
        .is_empty());
}

#[test]
fn clock_bounds_duplicate_names_and_json_limit_are_enforced() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    let mut o = f.observation("H02", Outcome::Passed);
    o.started_unix_ms = 1;
    assert!(f.record(&bundle, &o).is_err());
    let mut o = f.observation("H02", Outcome::Passed);
    o.ended_unix_ms = u64::MAX;
    assert!(f.record(&bundle, &o).is_err());
    let mut o = f.observation("H02", Outcome::Passed);
    o.evidence[1].file = o.evidence[0].file.clone();
    assert!(f.record(&bundle, &o).is_err());
    fs::write(f.path("observation.json"), vec![b' '; MAX_JSON + 1]).unwrap();
    assert!(record(&bundle, &f.path("observation.json"), &f.path("input")).is_err());
}

#[test]
fn locale_check_requires_independent_runs_matching_build_and_external_heads() {
    let f = Fixture::new();
    let en = f.init("en-US");
    let de = f.init("de-DE");
    let en_head = report(&en, None).unwrap().head_sha256;
    let de_head = report(&de, None).unwrap().head_sha256;
    let report = check(&en, &de, &en_head, &de_head).unwrap();
    assert!(!report.coverage_complete);
    assert!(!report.release_ready);
    assert!(check(&en, &en, &en_head, &en_head).is_err());
    assert!(check(&en, &de, &"0".repeat(64), &de_head).is_err());
    let mut run: Run = parse(&read(&de.join("run.json"), MAX_JSON).unwrap()).unwrap();
    run.binaries.cli = "11".repeat(32);
    fs::write(de.join("run.json"), json(&run).unwrap()).unwrap();
    let new_head = super::report(&de, None).unwrap().head_sha256;
    assert!(check(&en, &de, &en_head, &new_head).is_err());
}

#[cfg(unix)]
#[test]
fn linked_evidence_and_bundle_paths_are_refused() {
    let f = Fixture::new();
    let bundle = f.init("en-US");
    let o = f.observation("H02", Outcome::Passed);
    let path = f.path("input").join(&o.evidence[0].file);
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(f.path("binary.exe"), &path).unwrap();
    assert!(f.record(&bundle, &o).is_err());
    let alias = f.path("alias");
    std::os::unix::fs::symlink(&bundle, &alias).unwrap();
    assert!(report(&alias, None).is_err());
}
