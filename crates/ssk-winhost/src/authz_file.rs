//! The privileged broker's allow-list on disk: who may command which verb.
//!
//! `%ProgramData%\ScorpioSync\state\authz.json`, read through the same
//! [`crate::state_dir`] gate the receipt store already goes through — that is
//! the whole reason it lives in that directory and not next to the binary. The
//! directory is create-or-verify, grants only `SYSTEM` + `Administrators`, and
//! is **refused rather than repaired** if some other principal already controls
//! it. An unprivileged process therefore provably cannot edit this file.
//!
//! ```json
//! { "scheme": 1,
//!   "grants": [ { "sid": "S-1-5-21-…-1001",
//!                 "verbs": ["read_status", "engage_kill_switch", "release_kill_switch"] } ] }
//! ```
//!
//! # Why a file, and not "members of Administrators"
//!
//! Measured on this hardware: an ACE for `BUILTIN\Administrators` admits an
//! *elevated* administrator and nobody else, because `S-1-5-32-544` is flagged
//! `SE_GROUP_USE_FOR_DENY_ONLY` on a UAC-filtered token. On the archetypal
//! single-admin Windows 11 install, gating tier C on that would mean the user
//! could engage the kill-switch from an ordinary shell and then need a UAC
//! prompt to undo it — "cannot un-sever their own machine", and not
//! hypothetical: it is what the token says.
//!
//! Reading `TokenGroups` *including* deny-only entries would admit that same
//! user, but it is an implicit property of an account rather than a decision
//! anybody recorded, it silently widens to every administrator on a multi-admin
//! box, and it deliberately reads a deny-only SID as if the kernel had not
//! flagged it. This file is the alternative: a **recorded decision with a
//! subject**, held where an unprivileged process cannot edit it.
//!
//! # The failure mode is read-only, not deny-all
//!
//! Missing, unreadable or malformed ⇒
//! [`ssk_netd_helper::TieredSidAuthorizer::read_only`] carrying the reason.
//! `GetStatus` still answers, so a severed machine stays diagnosable; every
//! mutating verb is refused with a message naming what to fix. Recovery is tier
//! O — an elevated administrator, who does not need this file at all.
//!
//! Deny-all was rejected for exactly one reason: the state this file protects is
//! a machine with **no egress**, and the operator's first question is "is it
//! still severed?".

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use ssk_netd_helper::authz::{ControlVerb, PeerIdentity, TieredSidAuthorizer};

use crate::pipe::MAX_CLIENT_ACES;

/// The file name inside the state directory.
pub const AUTHZ_FILE_NAME: &str = "authz.json";

/// The only scheme version this build understands.
///
/// An unknown scheme is a **refusal**, not a best-effort read: a future version
/// may express a *narrowing* this build cannot represent, and silently ignoring
/// it would turn a tightened allow-list into a looser one.
pub const AUTHZ_SCHEME: u32 = 1;

/// Largest allow-list file this will read, before parsing.
///
/// The parsed grants also cap the pipe's ACE count at
/// [`MAX_CLIENT_ACES`]; this is the cruder bound that stops an unbounded read.
pub const MAX_AUTHZ_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzDocument {
    scheme: u32,
    grants: Vec<AuthzGrant>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthzGrant {
    sid: String,
    verbs: Vec<String>,
}

/// What a load produced.
#[derive(Debug)]
pub enum AuthzLoad {
    /// The allow-list was read. `client_sids` is the distinct SID set, in file
    /// order, for the pipe's DACL — the same list that drives the per-request
    /// decision, so the two cannot describe different principals.
    Granted {
        authorizer: TieredSidAuthorizer,
        client_sids: Vec<String>,
    },
    /// The allow-list could not be used. The broker runs read-only and the pipe
    /// uses [`crate::sddl_for_read_only_fallback_pipe`].
    ReadOnly {
        authorizer: TieredSidAuthorizer,
        reason: String,
    },
}

impl AuthzLoad {
    /// The authorizer to hand to `Broker::recover_privileged`, whichever branch
    /// this is.
    #[must_use]
    pub fn authorizer(self) -> TieredSidAuthorizer {
        match self {
            AuthzLoad::Granted { authorizer, .. } | AuthzLoad::ReadOnly { authorizer, .. } => {
                authorizer
            }
        }
    }

    /// Whether the broker will refuse every mutating verb.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        matches!(self, AuthzLoad::ReadOnly { .. })
    }

    /// Why, if it is read-only.
    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            AuthzLoad::ReadOnly { reason, .. } => Some(reason),
            AuthzLoad::Granted { .. } => None,
        }
    }
}

/// The path the allow-list is read from, given a provisioned state directory.
#[must_use]
pub fn authz_path(state_dir: &Path) -> PathBuf {
    state_dir.join(AUTHZ_FILE_NAME)
}

/// Read and parse the allow-list, degrading to read-only with a stated reason.
///
/// **Never returns an error.** Every failure is a degradation, because a
/// privileged host that refuses to start because a file is missing is a host
/// that cannot tell an operator whether their machine is still severed.
#[must_use]
pub fn load(state_dir: &Path) -> AuthzLoad {
    let path = authz_path(state_dir);
    match std::fs::metadata(&path) {
        Err(e) => {
            return read_only(format!(
                "{} could not be read ({e}); an elevated administrator must create it — see the \
                 runbook",
                path.display()
            ))
        }
        Ok(meta) if meta.len() > MAX_AUTHZ_FILE_BYTES => {
            return read_only(format!(
                "{} is {} bytes, over the {MAX_AUTHZ_FILE_BYTES}-byte limit; refusing to parse it",
                path.display(),
                meta.len()
            ))
        }
        Ok(meta) if !meta.is_file() => {
            return read_only(format!("{} is not a regular file", path.display()))
        }
        Ok(_) => {}
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => return read_only(format!("{} could not be read: {e}", path.display())),
    };
    match parse(&bytes) {
        Ok((authorizer, client_sids)) => AuthzLoad::Granted {
            authorizer,
            client_sids,
        },
        Err(reason) => read_only(format!(
            "{} is not a usable allow-list: {reason}",
            path.display()
        )),
    }
}

fn read_only(reason: String) -> AuthzLoad {
    AuthzLoad::ReadOnly {
        authorizer: TieredSidAuthorizer::read_only(reason.clone()),
        reason,
    }
}

/// Pure parse. Split out so every refusal is testable without touching
/// `%ProgramData%`.
///
/// # Errors
/// A human-readable reason. Refuses: an unknown scheme, an empty grant set, a
/// SID that is not canonical, a verb this build does not know, `override`
/// (which is **not** grantable by file — tier O is decided by the caller's
/// token, and a file that could grant it would be a way to hand out elevation),
/// duplicate SIDs, and more than [`MAX_CLIENT_ACES`] distinct principals.
pub fn parse(bytes: &[u8]) -> Result<(TieredSidAuthorizer, Vec<String>), String> {
    let doc: AuthzDocument =
        serde_json::from_slice(bytes).map_err(|e| format!("malformed JSON: {e}"))?;
    if doc.scheme != AUTHZ_SCHEME {
        return Err(format!(
            "unknown scheme {} (this build understands {AUTHZ_SCHEME}); refusing rather than \
             reading a policy it may not represent faithfully",
            doc.scheme
        ));
    }
    if doc.grants.is_empty() {
        return Err(
            "no grants; an allow-list that names nobody is indistinguishable from a missing one, \
             and both mean the same thing — say so explicitly by deleting the file"
                .to_owned(),
        );
    }
    if doc.grants.len() > MAX_CLIENT_ACES {
        return Err(format!(
            "{} principals exceeds the {MAX_CLIENT_ACES} the pipe descriptor can carry",
            doc.grants.len()
        ));
    }

    let mut authorizer = TieredSidAuthorizer::deny_all();
    let mut client_sids: Vec<String> = Vec::with_capacity(doc.grants.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for grant in doc.grants {
        let identity = PeerIdentity::parse_sid(&grant.sid)
            .map_err(|e| format!("grant for {:?}: {e}", truncate(&grant.sid)))?;
        if !seen.insert(grant.sid.clone()) {
            // Two entries for one SID would silently union, so the file would
            // grant more than any single line of it says.
            return Err(format!(
                "{} appears more than once; merge the entries so one line is the whole grant",
                grant.sid
            ));
        }
        if grant.verbs.is_empty() {
            return Err(format!("{} is granted no verbs", grant.sid));
        }
        for verb in &grant.verbs {
            let verb = parse_verb(verb).ok_or_else(|| {
                format!(
                    "{}: unknown verb {:?}; expected one of read_status, engage_kill_switch, \
                     release_kill_switch",
                    grant.sid,
                    truncate(verb)
                )
            })?;
            authorizer = authorizer.allow(identity.clone(), verb);
        }
        client_sids.push(grant.sid);
    }
    Ok((authorizer, client_sids))
}

/// Map a file token to a verb.
///
/// `override` is deliberately absent, and the `match` has no `_` arm so a new
/// [`ControlVerb`] forces a decision here rather than defaulting either way.
fn parse_verb(token: &str) -> Option<ControlVerb> {
    ControlVerb::ALL.into_iter().find(|verb| {
        let grantable = match verb {
            ControlVerb::ReadStatus
            | ControlVerb::EngageKillSwitch
            | ControlVerb::ReleaseKillSwitch => true,
            // Tier O is decided by `CheckTokenMembership` on the caller's token.
            // A file that could grant it would be a way to hand out elevation to
            // a principal that does not hold it.
            ControlVerb::Override => false,
            // `ControlVerb` is `#[non_exhaustive]`; an unknown future verb is
            // NOT grantable by file until somebody decides it should be.
            _ => false,
        };
        grantable && verb.as_str() == token
    })
}

fn truncate(value: &str) -> String {
    value.chars().take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = "S-1-5-21-650032732-2086122598-1934225963-1001";

    fn doc(body: &str) -> Vec<u8> {
        body.as_bytes().to_vec()
    }

    #[test]
    fn a_well_formed_allow_list_yields_grants_and_the_dacl_sid_list() {
        let (authorizer, sids) = parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[{{"sid":"{SID}","verbs":["read_status","engage_kill_switch","release_kill_switch"]}}]}}"#
        )))
        .expect("a canonical allow-list must parse");
        assert!(!authorizer.is_read_only());
        assert_eq!(authorizer.grant_count(), 3);
        assert_eq!(sids, vec![SID.to_owned()]);
    }

    /// The SID list handed to the DACL and the SID set handed to the authorizer
    /// come from the same parse, so the pipe cannot admit a principal the
    /// authorizer has never heard of.
    #[test]
    fn the_dacl_list_and_the_grant_set_come_from_one_parse() {
        const OTHER: &str = "S-1-5-21-650032732-2086122598-1934225963-1002";
        let (authorizer, sids) = parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[
                {{"sid":"{SID}","verbs":["engage_kill_switch"]}},
                {{"sid":"{OTHER}","verbs":["release_kill_switch"]}}]}}"#
        )))
        .expect("parse");
        assert_eq!(sids, vec![SID.to_owned(), OTHER.to_owned()]);
        assert_eq!(authorizer.grant_count(), 2);
        // And the resulting SID list is exactly what the descriptor accepts.
        let refs: Vec<&str> = sids.iter().map(String::as_str).collect();
        let sddl = crate::sddl_for_system_owned_pipe(&refs).expect("descriptor");
        assert!(sddl.contains(SID));
        assert!(sddl.contains(OTHER));
    }

    #[test]
    fn an_unknown_scheme_is_refused_rather_than_read() {
        let err = parse(&doc(
            r#"{"scheme":2,"grants":[{"sid":"S-1-5-18","verbs":["read_status"]}]}"#,
        ))
        .expect_err("a future scheme may express a narrowing this build cannot represent");
        assert!(err.contains("unknown scheme 2"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let err = parse(&doc(
            r#"{"scheme":1,"grants":[{"sid":"S-1-5-18","verbs":["read_status"],"note":"x"}]}"#,
        ))
        .expect_err("deny_unknown_fields");
        assert!(err.contains("malformed JSON"), "{err}");
    }

    /// Tier O must not be grantable by file. A file that could hand out
    /// `override` would be a way to give a principal elevation it does not hold
    /// — and the file lives exactly where a compromised elevated attacker would
    /// write.
    #[test]
    fn the_override_tier_cannot_be_granted_by_file() {
        let err = parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[{{"sid":"{SID}","verbs":["override"]}}]}}"#
        )))
        .expect_err("tier O is decided by the caller's token, never by this file");
        assert!(err.contains("unknown verb"), "{err}");
    }

    #[test]
    fn a_malformed_or_injected_sid_is_refused() {
        for hostile in [
            "S-1-5-21-1)(A;;GA;;;WD",
            "s-1-5-18",
            "BUILTIN\\Administrators",
            "",
            "S-1-5-021-1",
        ] {
            let body = format!(
                r#"{{"scheme":1,"grants":[{{"sid":"{}","verbs":["read_status"]}}]}}"#,
                hostile.replace('\\', "\\\\")
            );
            assert!(
                parse(&doc(&body)).is_err(),
                "{hostile:?} must not become an allow-list key or an ACE"
            );
        }
    }

    #[test]
    fn a_duplicate_sid_is_refused_rather_than_unioned() {
        let err = parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[
                {{"sid":"{SID}","verbs":["read_status"]}},
                {{"sid":"{SID}","verbs":["engage_kill_switch"]}}]}}"#
        )))
        .expect_err("two lines for one SID would grant more than either line says");
        assert!(err.contains("more than once"), "{err}");
    }

    #[test]
    fn an_empty_grant_set_is_refused() {
        assert!(parse(&doc(r#"{"scheme":1,"grants":[]}"#)).is_err());
        assert!(parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[{{"sid":"{SID}","verbs":[]}}]}}"#
        )))
        .is_err());
    }

    #[test]
    fn more_principals_than_the_descriptor_can_carry_are_refused() {
        let grants: Vec<String> = (0..=MAX_CLIENT_ACES)
            .map(|n| {
                format!(
                    r#"{{"sid":"S-1-5-21-1-2-3-{}","verbs":["read_status"]}}"#,
                    1000 + n
                )
            })
            .collect();
        let err = parse(&doc(&format!(
            r#"{{"scheme":1,"grants":[{}]}}"#,
            grants.join(",")
        )))
        .expect_err("the allow-list must not exceed what the pipe descriptor can express");
        assert!(err.contains("exceeds"), "{err}");
    }

    /// The failure mode that matters most: an absent file must leave the broker
    /// **readable**, not dead. A severed machine has to stay diagnosable.
    #[test]
    fn a_missing_file_degrades_to_read_only_and_says_where_to_look() {
        let dir = tempfile::tempdir().expect("scratch");
        let load = load(dir.path());
        assert!(load.is_read_only());
        let reason = load
            .reason()
            .expect("a read-only load must say why")
            .to_owned();
        assert!(reason.contains(AUTHZ_FILE_NAME), "{reason}");
        assert!(
            load.authorizer().is_read_only(),
            "the authorizer must carry the degraded flag, not just an empty allow-list — the two \
             produce different refusals and only one of them tells an operator what to fix"
        );
    }

    #[test]
    fn a_garbage_file_degrades_to_read_only_and_names_the_path() {
        let dir = tempfile::tempdir().expect("scratch");
        std::fs::write(authz_path(dir.path()), b"{ not json").expect("write");
        let load = load(dir.path());
        assert!(load.is_read_only());
        assert!(load
            .reason()
            .expect("reason")
            .contains("not a usable allow-list"));
    }

    #[test]
    fn an_oversized_file_is_refused_before_it_is_parsed() {
        let dir = tempfile::tempdir().expect("scratch");
        let padding = vec![b' '; usize::try_from(MAX_AUTHZ_FILE_BYTES).unwrap_or(usize::MAX) + 1];
        std::fs::write(authz_path(dir.path()), padding).expect("write");
        let load = load(dir.path());
        assert!(load.reason().expect("reason").contains("over the"));
    }

    #[test]
    fn a_real_file_round_trips_through_load() {
        let dir = tempfile::tempdir().expect("scratch");
        std::fs::write(
            authz_path(dir.path()),
            format!(
                r#"{{"scheme":1,"grants":[{{"sid":"{SID}","verbs":["engage_kill_switch","release_kill_switch"]}}]}}"#
            ),
        )
        .expect("write");
        match load(dir.path()) {
            AuthzLoad::Granted {
                authorizer,
                client_sids,
            } => {
                assert!(!authorizer.is_read_only());
                assert_eq!(authorizer.grant_count(), 2);
                assert_eq!(client_sids, vec![SID.to_owned()]);
            }
            other => panic!("expected a granted load, got {other:?}"),
        }
    }
}
