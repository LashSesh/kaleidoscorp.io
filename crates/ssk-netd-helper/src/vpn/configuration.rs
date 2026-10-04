//! A complete profile/grant snapshot. Raw JSON is borrowed so nested parsers
//! still see duplicate fields; secret fields are owned only by redacted Profile.
use super::Policy;
use serde::Deserialize;
use serde_json::value::RawValue;
use ssk_vpnctl::{Profile, ProfileId};
use std::collections::BTreeMap;

pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_PROFILES: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    schema: u32,
    #[serde(borrow)]
    policy: &'a RawValue,
    #[serde(borrow)]
    profiles: Vec<&'a RawValue>,
}

pub struct ProfileSet(BTreeMap<String, Profile>);
impl ProfileSet {
    pub fn new(profiles: Vec<Profile>, policy: &Policy) -> Result<Self, &'static str> {
        let set = Self::from_profiles(profiles)?;
        if policy
            .profile_ids()
            .iter()
            .any(|id| !set.0.contains_key(id))
        {
            return Err("VPN grant references missing profile");
        }
        Ok(set)
    }
    /// Profiles carry no authority. Legacy hosts can snapshot only readable
    /// profiles while retaining separately authenticated stop/recovery grants.
    pub fn from_profiles(profiles: Vec<Profile>) -> Result<Self, &'static str> {
        if profiles.len() > MAX_PROFILES {
            return Err("too many VPN profiles");
        }
        let mut map = BTreeMap::new();
        for profile in profiles {
            if map
                .insert(profile.id().as_str().to_owned(), profile)
                .is_some()
            {
                return Err("duplicate VPN profile");
            }
        }
        Ok(Self(map))
    }
    pub fn get(&self, id: &ProfileId) -> Option<&Profile> {
        self.0.get(id.as_str())
    }
    pub fn ids(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }
}

/// Parse the entire snapshot before exposing policy or profiles. Callers own and
/// must protect/wipe input bytes. No submitted document is included in errors.
pub fn parse(bytes: &[u8]) -> Result<(Policy, ProfileSet), &'static str> {
    if bytes.len() > MAX_BYTES {
        return Err("VPN configuration too large");
    }
    let doc: Document<'_> =
        serde_json::from_slice(bytes).map_err(|_| "invalid VPN configuration")?;
    if doc.schema != 1 || doc.profiles.len() > MAX_PROFILES {
        return Err("unsupported VPN configuration");
    }
    let policy = Policy::parse(doc.policy.get().as_bytes())?;
    let profiles = doc
        .profiles
        .iter()
        .map(|p| Profile::parse(p.get().as_bytes()).map_err(|_| "invalid VPN profile"))
        .collect::<Result<Vec<_>, _>>()?;
    let profiles = ProfileSet::new(profiles, &policy)?;
    Ok((policy, profiles))
}

#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: &str = include_str!("../../../ssk-vpnctl/tests/fixtures/profile.json");
    fn document(profile: &str, policy: &str) -> String {
        format!(r#"{{"schema":1,"profiles":[{profile}],"policy":{policy}}}"#)
    }
    const POLICY: &str = r#"{"schema":1,"grants":[{"sid":"S-1-5-18","profile":"company-managed","verbs":["prepare","status"]}]}"#;
    #[test]
    fn snapshot_validates_profiles_and_exact_grants_together() {
        let (policy, profiles) = parse(document(PROFILE, POLICY).as_bytes()).unwrap();
        assert_eq!(profiles.ids(), ["company-managed"]);
        assert_eq!(
            policy.client_sids().into_iter().collect::<Vec<_>>(),
            ["S-1-5-18"]
        );
        assert!(profiles.get(&ProfileId::new("absent").unwrap()).is_none());
        assert!(
            parse(document(PROFILE, &POLICY.replace("company-managed", "absent")).as_bytes())
                .is_err()
        );
        assert!(parse(document(&format!("{PROFILE},{PROFILE}"), POLICY).as_bytes()).is_err());
    }
    #[test]
    fn nested_duplicate_unknown_and_trailing_fields_are_never_normalized_away() {
        for profile in [
            PROFILE.replace("\"version\": 1", "\"version\": 1,\"version\": 1"),
            PROFILE.replace(
                "\"version\": 1",
                "\"version\": 1,\"script\":\"secret-command\"",
            ),
        ] {
            assert!(parse(document(&profile, POLICY).as_bytes()).is_err());
        }
        for policy in [
            POLICY.replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
            POLICY.replace("\"schema\":1", "\"schema\":1,\"admin_override\":true"),
        ] {
            assert!(parse(document(PROFILE, &policy).as_bytes()).is_err());
        }
        let valid = document(PROFILE, POLICY);
        assert!(parse(format!("{valid} {{}}").as_bytes()).is_err());
        assert!(parse(
            valid
                .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1)
                .as_bytes()
        )
        .is_err());
    }
    #[test]
    fn complete_revocation_and_bounded_secret_input_are_supported() {
        let (policy, profiles) =
            parse(br#"{"schema":1,"policy":{"schema":1,"grants":[]},"profiles":[]}"#).unwrap();
        assert!(policy.client_sids().is_empty());
        assert!(profiles.ids().is_empty());
        assert!(parse(&vec![b' '; MAX_BYTES + 1]).is_err());
        assert!(
            parse(document(&vec![PROFILE; MAX_PROFILES + 1].join(","), POLICY).as_bytes()).is_err()
        );
        let invalid = PROFILE.replace("PRIVATE KEY", "SECRET_INVALID_KEY");
        let error = parse(document(&invalid, POLICY).as_bytes()).err().unwrap();
        assert!(!error.contains("SECRET_INVALID_KEY"));
        assert!(!error.contains("RklYVFVSR"));
    }
}
