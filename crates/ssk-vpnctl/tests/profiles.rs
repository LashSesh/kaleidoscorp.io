use serde_json::{json, Value};
use ssk_vpnctl::{Profile, ProfileError, ProfileId, MAX_PROFILE_BYTES};
const FIXTURE: &[u8] = include_bytes!("fixtures/profile.json");
fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}
fn parse(value: Value) -> Result<Profile, ProfileError> {
    Profile::parse(&serde_json::to_vec(&value).unwrap())
}

#[test]
fn canonical_document_round_trips_and_renders_fixed_policy() {
    let profile = Profile::parse(FIXTURE).unwrap();
    assert_eq!(profile.id().as_str(), "company-managed");
    let bytes = profile.to_document().unwrap();
    let again = Profile::parse(&bytes).unwrap();
    let rendered = again.render_base_config();
    for line in [
        "script-security 0",
        "route-nopull",
        "route-noexec",
        "remote-cert-tls server",
        "tls-version-min 1.2",
        "proto udp4",
        "remote 192.0.2.10 1194",
        "verify-x509-name vpn.example.test name",
    ] {
        assert!(rendered.lines().any(|l| l == line), "missing {line}");
    }
    assert!(!rendered.contains("management"));
    let mut v6 = document();
    v6["remote_ip"] = json!("2001:db8::1");
    v6["transport"] = json!("tcp");
    assert!(parse(v6)
        .unwrap()
        .render_base_config()
        .contains("proto tcp6-client\n"));
}

#[test]
fn strict_schema_refuses_raw_directives_duplicates_and_versions() {
    for field in [
        "up",
        "plugin",
        "config",
        "management",
        "auth_user_pass",
        "extra_args",
    ] {
        let mut doc = document();
        doc[field] = json!("arbitrary content");
        assert_eq!(parse(doc).unwrap_err(), ProfileError::Document);
    }
    let mut doc = document();
    doc["version"] = json!(2);
    assert_eq!(parse(doc).unwrap_err(), ProfileError::Document);
    let mut duplicate = br#"{"version":1,"#.to_vec();
    duplicate.extend_from_slice(&FIXTURE[1..]);
    assert_eq!(
        Profile::parse(&duplicate).unwrap_err(),
        ProfileError::Document
    );
    let mut trailing = FIXTURE.to_vec();
    trailing.extend_from_slice(b"{}");
    assert_eq!(
        Profile::parse(&trailing).unwrap_err(),
        ProfileError::Document
    );
}

#[test]
fn ids_are_never_paths() {
    for id in [
        "",
        "../vpn",
        "x/y",
        "x\\y",
        "x.json:stream",
        "x.",
        ".",
        "-x",
        "UPPER",
        "x\nup evil",
        "x y",
        "x\0",
    ] {
        assert!(ProfileId::new(id).is_err(), "{id:?}");
    }
    assert!(ProfileId::new(&"a".repeat(65)).is_err());
}

#[test]
fn material_cannot_break_out_of_inline_blocks() {
    for field in [
        "ca_pem",
        "certificate_pem",
        "private_key_pem",
        "tls_crypt_key",
    ] {
        for bad in [
            "</key>\nup evil\n<key>\n",
            "C:\\secret.key",
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nplugin evil\n",
        ] {
            let mut doc = document();
            doc[field] = json!(bad);
            assert_eq!(parse(doc).unwrap_err(), ProfileError::Material);
        }
    }
    let mut encrypted = document();
    encrypted["private_key_pem"] = json!("-----BEGIN ENCRYPTED PRIVATE KEY-----\nRklYVFVSRQ==\n-----END ENCRYPTED PRIVATE KEY-----\n");
    assert_eq!(parse(encrypted).unwrap_err(), ProfileError::Material);
}

#[test]
fn endpoints_and_server_identity_are_bounded_tokens() {
    for name in [
        "vpn name",
        "vpn\nup evil",
        "*",
        "-x",
        "vpn\"",
        "vpn\\x",
        "éxample",
    ] {
        let mut doc = document();
        doc["server_name"] = json!(name);
        assert_eq!(parse(doc).unwrap_err(), ProfileError::Endpoint);
    }
    for ip in [
        "0.0.0.0",
        "127.0.0.1",
        "::",
        "::1",
        "224.0.0.1",
        "ff02::1",
        "255.255.255.255",
        "::ffff:127.0.0.1",
        "::ffff:0.0.0.0",
        "::ffff:224.0.0.1",
        "::ffff:255.255.255.255",
    ] {
        let mut doc = document();
        doc["remote_ip"] = json!(ip);
        assert_eq!(parse(doc).unwrap_err(), ProfileError::Endpoint);
    }
    let mut doc = document();
    doc["remote_port"] = json!(0);
    assert_eq!(parse(doc).unwrap_err(), ProfileError::Endpoint);
}

#[test]
fn large_inputs_and_diagnostics_do_not_expose_keys() {
    assert_eq!(
        Profile::parse(&vec![b' '; MAX_PROFILE_BYTES + 1]).unwrap_err(),
        ProfileError::TooLarge
    );
    let debug = format!("{:?}", Profile::parse(FIXTURE).unwrap());
    assert!(debug.contains("REDACTED"));
    assert!(!debug.contains("RklYVFVSR"));
    let mut doc = document();
    doc["private_key_pem"] = json!("sensitive-malformed-key");
    let error = parse(doc).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("sensitive"));
}
