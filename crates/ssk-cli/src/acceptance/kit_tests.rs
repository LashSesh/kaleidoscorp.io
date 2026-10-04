use super::*;
use serde_json::Value;

struct Fixture(tempfile::TempDir);
impl Fixture {
    fn new() -> Self {
        let f = Self(tempfile::tempdir().unwrap());
        // Structural PE fixture only: deliberately not a loadable program.
        let mut pe = vec![0; 128];
        pe[..2].copy_from_slice(b"MZ");
        pe[60..64].copy_from_slice(&64u32.to_le_bytes());
        pe[64..68].copy_from_slice(b"PE\0\0");
        pe[68..70].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[70..72].copy_from_slice(&1u16.to_le_bytes());
        pe[84..86].copy_from_slice(&2u16.to_le_bytes());
        pe[86..88].copy_from_slice(&2u16.to_le_bytes());
        pe[88..90].copy_from_slice(&0x20bu16.to_le_bytes());
        fs::write(f.path("source.exe"), pe).unwrap();
        f
    }
    fn path(&self, name: &str) -> std::path::PathBuf {
        self.0.path().join(name)
    }
    fn create(&self) -> Result<KitReport> {
        let source = self.path("source.exe");
        kit_create(
            &source,
            &source,
            &source,
            &"ab".repeat(20),
            true,
            &self.path("kit"),
        )
    }
    fn change_manifest(&self, change: impl FnOnce(&mut Value)) -> String {
        let path = self.path("kit/manifest.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        change(&mut value);
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(path, &bytes).unwrap();
        sha(&bytes)
    }
}

#[test]
fn kit_roundtrip_copies_only_fixed_public_assets_and_never_marks_release_ready() {
    let f = Fixture::new();
    fs::write(f.path("private-key.pem"), b"DO NOT INCLUDE THIS SIBLING").unwrap();
    let report = f.create().unwrap();
    assert!(report.development_only && report.worktree_dirty && !report.release_ready);
    assert_eq!(report.files, BINARIES.len() + assets().len());
    assert_eq!(report.source_revision, "ab".repeat(20));
    assert!(!f.path("kit/private-key.pem").exists());
    for binary in BINARIES {
        assert_eq!(
            fs::read(f.path("kit").join(binary)).unwrap(),
            fs::read(f.path("source.exe")).unwrap()
        );
    }
    let verified = kit_verify(&f.path("kit"), &report.manifest_sha256).unwrap();
    assert_eq!(verified.total_bytes, report.total_bytes);
    for (name, bytes) in assets() {
        assert_eq!(fs::read(f.path("kit").join(name)).unwrap(), bytes);
    }
}

#[test]
fn kit_schema_one_remains_verifiable_after_adding_journal_backup_guidance() {
    let f = Fixture::new();
    f.create().unwrap();
    fs::remove_file(f.path("kit/docs/OPENVPN_JOURNAL_BACKUP.md")).unwrap();
    let old_hash = f.change_manifest(|m| {
        m["schema"] = 1.into();
        m["files"]
            .as_array_mut()
            .unwrap()
            .retain(|file| file["path"] != "docs/OPENVPN_JOURNAL_BACKUP.md");
    });
    assert!(kit_verify(&f.path("kit"), &old_hash).is_ok());
    let missing_new_file_hash = f.change_manifest(|m| m["schema"] = 2.into());
    assert!(kit_verify(&f.path("kit"), &missing_new_file_hash).is_err());
    let unknown_version = f.change_manifest(|m| m["schema"] = 3.into());
    assert!(kit_verify(&f.path("kit"), &unknown_version).is_err());
}

#[test]
fn kit_refuses_existing_or_partial_destination_without_overwriting() {
    let f = Fixture::new();
    fs::create_dir(f.path("kit")).unwrap();
    fs::write(f.path("kit/sentinel"), b"preserve").unwrap();
    assert!(f.create().is_err());
    assert_eq!(fs::read(f.path("kit/sentinel")).unwrap(), b"preserve");
    assert!(!f.path("kit/manifest.json").exists());
    assert!(kit_verify(&f.path("kit"), &"ab".repeat(32)).is_err());
}

#[test]
fn kit_rejects_non_pe_wrong_arch_dll_truncation_and_oversize_before_claiming_output() {
    for (offset, bytes) in [
        (0, vec![0, 0]),
        (68, vec![0x4c, 1]),
        (86, vec![2, 0x20]),
        (60, u32::MAX.to_le_bytes().to_vec()),
    ] {
        let f = Fixture::new();
        let mut data = fs::read(f.path("source.exe")).unwrap();
        data[offset..offset + bytes.len()].copy_from_slice(&bytes);
        fs::write(f.path("source.exe"), data).unwrap();
        assert!(f.create().is_err());
        assert!(!f.path("kit").exists());
    }
    for length in [89, MAX_BINARY + 1] {
        let f = Fixture::new();
        OpenOptions::new()
            .write(true)
            .open(f.path("source.exe"))
            .unwrap()
            .set_len(length)
            .unwrap();
        assert!(f.create().is_err());
        assert!(!f.path("kit").exists());
    }
}

#[test]
fn kit_source_revision_must_be_full_and_non_placeholder() {
    let f = Fixture::new();
    for revision in [
        "short".to_string(),
        "0".repeat(40),
        "G".repeat(40),
        "a".repeat(41),
    ] {
        let source = f.path("source.exe");
        assert!(kit_create(&source, &source, &source, &revision, false, &f.path("kit")).is_err());
        assert!(!f.path("kit").exists());
    }
}

#[test]
fn kit_rejects_changed_binary_reference_missing_and_extra_entries() {
    for scenario in 0..5 {
        let f = Fixture::new();
        let report = f.create().unwrap();
        match scenario {
            0 => {
                let path = f.path("kit/bin/ssk.exe");
                let mut data = fs::read(&path).unwrap();
                data[100] ^= 1;
                fs::write(path, data).unwrap();
            }
            1 => fs::write(f.path("kit/docs/OPENVPN_TEST_KIT.md"), b"changed reference").unwrap(),
            2 => fs::remove_file(f.path("kit/bin/ssk-svc.exe")).unwrap(),
            3 => fs::write(f.path("kit/extra.txt"), b"extra").unwrap(),
            4 => fs::create_dir(f.path("kit/extra-empty-directory")).unwrap(),
            _ => unreachable!(),
        }
        assert!(kit_verify(&f.path("kit"), &report.manifest_sha256).is_err());
    }
}

#[test]
fn kit_requires_external_hash_and_rejects_manifest_tampering() {
    let f = Fixture::new();
    let report = f.create().unwrap();
    for hash in ["".to_string(), "ab".repeat(32), "x".repeat(64)] {
        assert!(kit_verify(&f.path("kit"), &hash).is_err());
    }
    let modified = f.change_manifest(|m| m["worktree_dirty"] = false.into());
    assert_ne!(report.manifest_sha256, modified);
    assert!(kit_verify(&f.path("kit"), &report.manifest_sha256).is_err());
    // A replacement externally trusted hash changes the trust premise; there
    // is no signature or claim that local bytes authenticate themselves.
    assert!(kit_verify(&f.path("kit"), &modified).is_ok());
}

#[test]
fn kit_rejects_unknown_fields_unsafe_manifest_paths_duplicates_and_release_claims() {
    for scenario in 0..6 {
        let f = Fixture::new();
        f.create().unwrap();
        let hash = f.change_manifest(|m| match scenario {
            0 => m["unknown"] = true.into(),
            1 => m["files"][0]["path"] = "../source.exe".into(),
            2 => m["files"][0]["path"] = "bin/ssk-svc.exe".into(),
            3 => m["development_only"] = false.into(),
            4 => m["source_revision"] = "0".repeat(40).into(),
            5 => m["files"][0]["bytes"] = 1.into(),
            _ => unreachable!(),
        });
        assert!(kit_verify(&f.path("kit"), &hash).is_err());
    }
}

#[test]
fn kit_rejects_oversized_reference_even_with_matching_manifest_size_and_hash() {
    let f = Fixture::new();
    f.create().unwrap();
    let bytes = vec![b'x'; MAX_EVIDENCE + 1];
    fs::write(f.path("kit/docs/OPENVPN_TEST_KIT.md"), &bytes).unwrap();
    let expected = f.change_manifest(|m| {
        let file = m["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v["path"] == "docs/OPENVPN_TEST_KIT.md")
            .unwrap();
        file["bytes"] = bytes.len().into();
        file["sha256"] = sha(&bytes).into();
    });
    assert!(kit_verify(&f.path("kit"), &expected).is_err());
}

#[cfg(unix)]
#[test]
fn kit_refuses_symlink_input_and_transferred_symlink_entries() {
    let f = Fixture::new();
    let report = f.create().unwrap();
    let target = f.path("kit/bin/ssk.exe");
    fs::remove_file(&target).unwrap();
    std::os::unix::fs::symlink(f.path("source.exe"), &target).unwrap();
    assert!(kit_verify(&f.path("kit"), &report.manifest_sha256).is_err());
    assert!(kit_create(
        &target,
        &target,
        &target,
        &"ab".repeat(20),
        false,
        &f.path("other-kit")
    )
    .is_err());
    assert!(!f.path("other-kit").exists());
}
