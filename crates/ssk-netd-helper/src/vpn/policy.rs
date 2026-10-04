use super::Verb;
use crate::authz::{AuthenticatedPeer, PeerIdentity};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: u32,
    grants: Vec<Entry>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    sid: String,
    profile: String,
    verbs: Vec<Verb>,
}

/// No admin override, wildcard, implicit status right or kill-switch grant reuse.
pub struct Policy(BTreeSet<(PeerIdentity, String, Verb)>);
impl Policy {
    pub const MAX_BYTES: usize = 32 * 1024;

    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() > Self::MAX_BYTES {
            return Err("VPN policy too large");
        }
        let doc: Document = serde_json::from_slice(bytes).map_err(|_| "invalid VPN policy")?;
        if doc.schema != 1 || doc.grants.len() > 128 {
            return Err("unsupported VPN policy");
        }
        let mut grants = BTreeSet::new();
        for entry in doc.grants {
            let sid = PeerIdentity::parse_sid(&entry.sid).map_err(|_| "invalid VPN principal")?;
            ssk_vpnctl::ProfileId::new(&entry.profile).map_err(|_| "invalid VPN profile")?;
            if entry.verbs.is_empty() || entry.verbs.len() > 4 {
                return Err("invalid VPN verbs");
            }
            for verb in entry.verbs {
                if !grants.insert((sid.clone(), entry.profile.clone(), verb)) {
                    return Err("duplicate VPN grant");
                }
            }
        }
        Ok(Self(grants))
    }

    pub fn permits(&self, peer: &AuthenticatedPeer, profile: &str, verb: Verb) -> bool {
        self.0
            .contains(&(peer.sid.clone(), profile.to_owned(), verb))
    }

    pub fn client_sids(&self) -> BTreeSet<String> {
        self.0
            .iter()
            .map(|(sid, _, _)| sid.as_str().to_owned())
            .collect()
    }

    pub fn profile_ids(&self) -> BTreeSet<String> {
        self.0
            .iter()
            .map(|(_, profile, _)| profile.clone())
            .collect()
    }
}
