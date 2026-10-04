//! **Who may command the broker** — the per-request peer authorization decision
//! (roadmap P3).
//!
//! # Two different questions, deliberately in two different places
//!
//! | Question | Answered by | When |
//! |---|---|---|
//! | *May this **broker** actuate the kill-switch at all?* | [`ssk_signature::policy::AuthorizationPolicyTable`] via [`crate::broker::ActuationAuthority`] | once, at construction |
//! | *May this **caller** perform this verb?* | this module | every request |
//!
//! Neither subsumes the other: the first is a deployment fact about the broker
//! process, the second is a fact about whoever is on the far end of the pipe.
//! P1 built the first and wired it nowhere; the second did not exist.
//!
//! # Why this is not folded into the transport's accept-time peer check
//!
//! `ssk_ipc`'s `check_peer_same_user` runs **once, at accept, before any frame
//! is read** — a load-bearing property, because moving it later would admit a
//! client that negotiated no impersonation quality of service. The *verb* is
//! not known at that moment. Authorization is therefore necessarily
//! per-request, and cannot be an extension of accept-time authentication.
//!
//! # Why an explicit SID allow-list rather than "is the caller an administrator"
//!
//! Measured on the development machine (Windows 11 de-DE, 2026-08-03, the only
//! interactive account, itself a member of `BUILTIN\Administrators`):
//!
//! * `CheckTokenMembership(S-1-5-32-544)` → **false**, because the token is
//!   UAC-filtered and carries `S-1-5-32-544` flagged `SE_GROUP_USE_FOR_DENY_ONLY`;
//! * a named pipe whose DACL grants only `SY` + `BA` **refused that same user**
//!   with `ERROR_ACCESS_DENIED`.
//!
//! So "members of `BUILTIN\Administrators`" means *elevated* administrators. A
//! design that gated the kill-switch on it would let the machine's only user
//! sever their own egress from an ordinary shell and then require a UAC prompt
//! to undo it. Reading the deny-only membership *as if it were enabled* is the
//! opposite error — it inverts the meaning the kernel assigned to the flag, and
//! on a multi-admin machine it silently widens to every administrator account.
//!
//! Both facts are therefore recorded on [`PeerToken`], separately and with
//! different names, and **neither is the gate**. The gate is an explicit
//! `(SID, verb)` allow-list: a recorded decision with a subject, held where an
//! unprivileged process cannot edit it.
//!
//! # The tiers
//!
//! | Tier | Verbs | Gate |
//! |---|---|---|
//! | **R** read | [`ControlVerb::ReadStatus`] | any peer the pipe DACL admitted |
//! | **C** control | [`ControlVerb::EngageKillSwitch`], [`ControlVerb::ReleaseKillSwitch`] | that exact `(SID, verb)` grant |
//! | **O** override | [`ControlVerb::Override`] | [`PeerToken::elevated_admin`], **no** allow-list entry needed |
//!
//! Tier R stays open on purpose: when the allow-list is missing or malformed the
//! authorizer degrades to [`TieredSidAuthorizer::read_only`] rather than
//! deny-all, so a severed machine remains *diagnosable*. Tier O is *designed* as
//! the recovery path that would make tier C's strictness acceptable — the
//! intended worst case for a user locked out of their own kill-switch is one
//! UAC prompt, never a reinstall.
//!
//! **That recovery path is not reachable today, and this must not be read as a
//! delivered property.** [`ControlVerb::Override`] is a real, tested decision —
//! [`TieredSidAuthorizer::authorize`] gates it on [`PeerToken::elevated_admin`]
//! correctly, degraded mode included — but [`ControlVerb::for_command`] is total
//! over [`crate::protocol::Command`], and that enum carries no variant that maps
//! to [`ControlVerb::Override`]. No client of this crate can construct a wire
//! request that reaches it. The one-UAC-prompt story is therefore this tier's
//! *intent*, verified in isolation at the authorization layer; wiring an actual
//! recovery verb through `Command` and the broker's dispatch is tracked
//! separately and is outside this file's scope (`Command` lives in
//! `crate::protocol`, which callers outside this crate also depend on).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::protocol::{Command, RejectReason};

/// The integrity RID of a Medium-integrity token (`S-1-16-8192`).
///
/// Recorded on [`PeerToken`] for diagnostics. It is **not** an authorization
/// input: an attacker who is already the user can spawn a Medium-integrity
/// process at will, so gating on it buys nothing while breaking legitimate
/// automation. Excluding *below*-Medium callers is done by the pipe's mandatory
/// label (`S:(ML;;NW;;;ME)`), which is a kernel effect and not a decision this
/// module makes.
pub const INTEGRITY_RID_MEDIUM: u32 = 0x2000;

/// The longest a well-formed SID string can be: `S-1-` + a 15-digit identifier
/// authority + 15 sub-authorities of up to 10 digits each, with separators.
pub const MAX_SID_STRING_LEN: usize = 184;

/// The maximum number of sub-authorities a SID may carry (`SID_MAX_SUB_AUTHORITIES`).
pub const MAX_SID_SUB_AUTHORITIES: usize = 15;

/// The largest value an identifier authority can hold (a 48-bit field).
const MAX_IDENTIFIER_AUTHORITY: u64 = (1u64 << 48) - 1;

/// The reserved holder label for the in-process caller of
/// [`crate::Broker::handle`].
///
/// It is deliberately **not** SID-shaped, so [`PeerIdentity::parse_sid`] can
/// never produce it and no allow-list built from real SIDs can ever contain it.
const IN_PROCESS_LABEL: &str = "in-process";

/// An authenticated OS principal, as a validated SID string.
///
/// This type does **not** authenticate anything — the transport does that (on
/// Windows, `ImpersonateNamedPipeClient` + `TokenUser` in `ssk-winhost`). What
/// it guarantees is that the string has SID *shape*, so it can be used as an
/// allow-list key and interpolated into an SDDL string without smuggling an
/// extra ACE. That is the same reason `ssk_signature::policy::Principal` exists
/// one layer up, and the two are deliberately not the same type: a `Principal`
/// names a component of this product, a `PeerIdentity` names an OS account.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerIdentity(String);

impl PeerIdentity {
    /// Parse a canonical SID string, e.g. `S-1-5-18` or
    /// `S-1-5-21-650032732-2086122598-1934225963-1001`.
    ///
    /// The accepted grammar is deliberately narrower than what Windows itself
    /// will parse:
    ///
    /// * the prefix must be exactly `S-1-` — **uppercase**. `ConvertSidToStringSidW`
    ///   only ever emits uppercase, so a lowercase spelling arrives from
    ///   somewhere else. It is refused rather than normalized, because
    ///   normalizing an identity is how two spellings of one account become two
    ///   allow-list keys (or one grant that matches more than it was written for).
    /// * the identifier authority is decimal only (no `0x…` form) and must fit
    ///   in 48 bits;
    /// * there must be between 1 and [`MAX_SID_SUB_AUTHORITIES`] sub-authorities,
    ///   each a `u32`;
    /// * no component may carry a leading zero, for the same
    ///   one-account-one-spelling reason.
    ///
    /// # Errors
    /// [`AuthzDenied::MalformedSid`] naming the reason.
    pub fn parse_sid(sid: &str) -> Result<Self, AuthzDenied> {
        let reject = |why: &str| {
            Err(AuthzDenied::MalformedSid {
                sid: sid.to_owned(),
                reason: why.to_owned(),
            })
        };
        if sid.len() > MAX_SID_STRING_LEN {
            return reject("longer than a SID string can be");
        }
        let Some(rest) = sid.strip_prefix("S-1-") else {
            return reject("does not start with the canonical uppercase `S-1-`");
        };
        let mut parts = rest.split('-');
        let Some(authority) = parts.next() else {
            return reject("no identifier authority");
        };
        if !is_canonical_decimal(authority) {
            return reject("identifier authority is not a canonical decimal number");
        }
        match authority.parse::<u64>() {
            Ok(value) if value <= MAX_IDENTIFIER_AUTHORITY => {}
            _ => return reject("identifier authority does not fit in 48 bits"),
        }
        let mut sub_authorities = 0usize;
        for part in parts {
            sub_authorities += 1;
            if sub_authorities > MAX_SID_SUB_AUTHORITIES {
                return reject("more sub-authorities than a SID can carry");
            }
            if !is_canonical_decimal(part) {
                return reject("sub-authority is not a canonical decimal number");
            }
            if part.parse::<u32>().is_err() {
                return reject("sub-authority does not fit in 32 bits");
            }
        }
        if sub_authorities == 0 {
            return reject("no sub-authority");
        }
        Ok(PeerIdentity(sid.to_owned()))
    }

    /// The in-process caller of [`crate::Broker::handle`] — the legacy,
    /// peer-less entry point. Crate-private on purpose: it must not be possible
    /// to name this identity from outside and have it looked up in an
    /// allow-list.
    pub(crate) fn in_process() -> Self {
        PeerIdentity(IN_PROCESS_LABEL.to_owned())
    }

    /// The broker acting on its own authority (startup reconciliation).
    pub(crate) fn broker_self() -> Self {
        PeerIdentity("broker-self".to_owned())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A decimal component with no leading zero (`"0"` itself is fine).
fn is_canonical_decimal(part: &str) -> bool {
    if part.is_empty() || part.len() > 20 {
        return false;
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !(part.len() > 1 && part.starts_with('0'))
}

/// What a peer's token **says**. Every field is a fact about the token; none is
/// a decision.
///
/// The two administrator fields are different questions and conflating them is
/// the trap this struct exists to make unmissable — see the module header for
/// the measurement that separates them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerToken {
    /// `CheckTokenMembership(S-1-5-32-544)` on the peer's token: the peer holds
    /// administrative rights **right now**. Measured *false* for an unelevated
    /// member of `Administrators` on Windows 11 de-DE.
    pub elevated_admin: bool,
    /// `S-1-5-32-544` present in `TokenGroups` **including entries flagged
    /// `SE_GROUP_USE_FOR_DENY_ONLY`**: the peer's *account* is an administrator.
    /// Measured *true* for that same unelevated caller.
    pub admin_account_filtered: bool,
    /// Integrity RID from the `S-1-16-…` label. [`INTEGRITY_RID_MEDIUM`] is
    /// Medium. Diagnostics only.
    pub integrity_rid: u32,
    /// The `SE_GROUP_LOGON_ID` SID.
    ///
    /// **Audited, never decisive.** Binding a release to the logon session that
    /// engaged is technically possible and was rejected: a user who logs off and
    /// back on gets a new logon SID, so the kill-switch would strand the machine
    /// across a reboot and require tier O to undo.
    pub logon_session: Option<PeerIdentity>,
}

impl PeerToken {
    /// A token that claims nothing: not elevated, not an administrator account,
    /// Medium integrity, no logon SID.
    ///
    /// This is the correct value for a caller whose token could not be read *in
    /// a context where a decision is still going to be made* — every field
    /// errs toward less privilege. It is **not** what a failed probe should
    /// produce on the served path: there, `peer_token` must return an error and
    /// the request must be refused, because "all false" silently downgrades a
    /// legitimate administrator out of tier O (a denial of recovery) and there
    /// is no "unknown" tier to fall back to.
    #[must_use]
    pub fn unprivileged() -> Self {
        PeerToken {
            elevated_admin: false,
            admin_account_filtered: false,
            integrity_rid: INTEGRITY_RID_MEDIUM,
            logon_session: None,
        }
    }

    /// The invariant that holds on every Windows token, elevated or not: you
    /// cannot hold administrative rights without the account being an
    /// administrator.
    ///
    /// Exposed so a test on an *elevated* CI runner and a test on an unelevated
    /// developer machine can assert the same thing — the pair
    /// `(elevated_admin == false, admin_account_filtered == true)` is real and
    /// measured here, but is not reproducible on GitHub's elevated
    /// `windows-latest`.
    #[must_use]
    pub fn is_coherent(&self) -> bool {
        !self.elevated_admin || self.admin_account_filtered
    }
}

/// An authenticated peer: who it is, plus what its token says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPeer {
    pub sid: PeerIdentity,
    pub token: PeerToken,
}

impl AuthenticatedPeer {
    #[must_use]
    pub fn new(sid: PeerIdentity, token: PeerToken) -> Self {
        AuthenticatedPeer { sid, token }
    }
}

/// The closed set of verbs the privileged transport authorizes.
///
/// `#[non_exhaustive]` for downstream crates; **inside** this crate every match
/// on it is exhaustive with no `_` arm, so adding a verb is a compile error at
/// each decision point rather than a silent fall-through to the lowest tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ControlVerb {
    /// Tier R. Read the authoritative status.
    ReadStatus,
    /// Tier C. Sever egress.
    EngageKillSwitch,
    /// Tier C. Restore egress.
    ReleaseKillSwitch,
    /// Tier O. Force the OS to match the journal (startup reconciliation),
    /// and any future policy edit. Requires real elevation.
    Override,
}

impl ControlVerb {
    /// Every verb, in tier order.
    pub const ALL: [ControlVerb; 4] = [
        ControlVerb::ReadStatus,
        ControlVerb::EngageKillSwitch,
        ControlVerb::ReleaseKillSwitch,
        ControlVerb::Override,
    ];

    /// Classify a wire [`Command`].
    ///
    /// Total and closed: the `match` below has **no `_` arm**, so adding a
    /// `Command` variant fails to compile here instead of defaulting to the
    /// unprivileged tier. That structural guarantee is the point of the
    /// function; it is not a convention.
    #[must_use]
    pub fn for_command(command: Command) -> ControlVerb {
        match command {
            Command::GetStatus => ControlVerb::ReadStatus,
            Command::EngageKillSwitch => ControlVerb::EngageKillSwitch,
            Command::ReleaseKillSwitch => ControlVerb::ReleaseKillSwitch,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ControlVerb::ReadStatus => "read_status",
            ControlVerb::EngageKillSwitch => "engage_kill_switch",
            ControlVerb::ReleaseKillSwitch => "release_kill_switch",
            ControlVerb::Override => "override",
        }
    }

    /// Whether this verb changes OS state. Read is the only one that does not.
    #[must_use]
    pub fn is_mutating(self) -> bool {
        match self {
            ControlVerb::ReadStatus => false,
            ControlVerb::EngageKillSwitch
            | ControlVerb::ReleaseKillSwitch
            | ControlVerb::Override => true,
        }
    }
}

impl fmt::Display for ControlVerb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a peer was refused a verb. Every variant names the specific reason, so
/// an operator gets a next step instead of a bare `false`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzDenied {
    /// The identity string was not a canonical SID.
    #[error("`{sid}` is not a canonical SID: {reason}")]
    MalformedSid { sid: String, reason: String },
    /// Tier C: the allow-list holds no grant for this exact `(SID, verb)` pair.
    #[error("`{sid}` is not granted `{verb}`")]
    NotGranted { sid: String, verb: ControlVerb },
    /// Tier C in the degraded mode: the allow-list could not be read, so every
    /// mutating verb is refused until an elevated administrator repairs it.
    #[error("the authorization allow-list is unavailable ({reason}); `{verb}` refused, status is still readable")]
    ReadOnlyMode { verb: ControlVerb, reason: String },
    /// Tier O: the verb requires rights the caller does not hold *right now*.
    /// An administrator whose token is UAC-filtered lands here, and the next
    /// step really is "re-run elevated" — unlike tier C, where it is not.
    #[error(
        "`{verb}` requires an elevated caller (`CheckTokenMembership(S-1-5-32-544)` was false)"
    )]
    RequiresElevation { verb: ControlVerb },
    /// The broker has no authorizer configured, so no peer-scoped decision can
    /// be made at all. Fail closed rather than assume.
    #[error("no peer authorizer is configured; `{verb}` cannot be decided")]
    NoAuthorizer { verb: ControlVerb },
    /// The verb the peer was authorized for is not the verb the envelope
    /// carries. Only reachable via a caller that mints a grant for one verb and
    /// dispatches another.
    #[error("grant is for `{granted}` but the command is `{submitted}`")]
    VerbMismatch {
        granted: ControlVerb,
        submitted: ControlVerb,
    },
}

impl AuthzDenied {
    /// A stable machine-readable code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AuthzDenied::MalformedSid { .. } => "PEER_SID_MALFORMED",
            AuthzDenied::NotGranted { .. } => "PEER_NOT_GRANTED",
            AuthzDenied::ReadOnlyMode { .. } => "PEER_READ_ONLY_MODE",
            AuthzDenied::RequiresElevation { .. } => "PEER_REQUIRES_ELEVATION",
            AuthzDenied::NoAuthorizer { .. } => "PEER_NO_AUTHORIZER",
            AuthzDenied::VerbMismatch { .. } => "PEER_VERB_MISMATCH",
        }
    }

    /// Map to the wire rejection the broker returns.
    #[must_use]
    pub fn to_reject_reason(&self) -> RejectReason {
        RejectReason::PeerUnauthorized {
            code: self.code().to_owned(),
            detail: self.to_string(),
        }
    }
}

/// Answers *"may this peer perform this verb?"*. Distinct from the transport's
/// peer **authentication**, which answers *"who is this peer?"*.
///
/// Implementations must be total and fail closed: every outcome that is not an
/// explicit grant — including "cannot tell" — is an `Err`.
pub trait PeerAuthorizer: Send + Sync {
    /// # Errors
    /// [`AuthzDenied`] naming why.
    fn authorize(&self, peer: &AuthenticatedPeer, verb: ControlVerb) -> Result<(), AuthzDenied>;
}

/// The shipped authorizer: the three tiers from the module header over an
/// explicit `(SID, verb)` allow-list.
///
/// Pure — no syscall, no IO, no clock — so every cell of the decision table is
/// unit-testable on any machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TieredSidAuthorizer {
    grants: BTreeMap<PeerIdentity, BTreeSet<ControlVerb>>,
    /// `Some(reason)` iff the allow-list could not be loaded. Tier C then
    /// refuses with [`AuthzDenied::ReadOnlyMode`], whose message carries the
    /// reason, instead of the less actionable "not granted".
    degraded: Option<String>,
}

impl TieredSidAuthorizer {
    /// An authorizer with an empty allow-list: status is readable, no peer may
    /// mutate, and an elevated caller may still use tier O.
    ///
    /// This is the correct *starting point* for a builder, not the fallback for
    /// a failed load — use [`TieredSidAuthorizer::read_only`] for that, so the
    /// refusal says why.
    #[must_use]
    pub fn deny_all() -> Self {
        TieredSidAuthorizer {
            grants: BTreeMap::new(),
            degraded: None,
        }
    }

    /// The **fallback** when `authz.json` is missing, unreadable or malformed.
    ///
    /// Read-only, not deny-all: a machine whose egress may be severed has to
    /// stay diagnosable, and refusing `GetStatus` would leave an operator with
    /// no way to tell whether the kill-switch is engaged. Every mutating verb is
    /// refused with the reason, and recovery is tier O.
    #[must_use]
    pub fn read_only(reason: impl Into<String>) -> Self {
        TieredSidAuthorizer {
            grants: BTreeMap::new(),
            degraded: Some(reason.into()),
        }
    }

    /// Grant one `(SID, verb)` pair. There is no wildcard and no
    /// "grant everything" constructor, for the same reason
    /// [`ssk_signature::policy::AuthorizationPolicyTable`] has none.
    #[must_use]
    pub fn allow(mut self, sid: PeerIdentity, verb: ControlVerb) -> Self {
        self.grants.entry(sid).or_default().insert(verb);
        self
    }

    /// Whether this authorizer is in the degraded, read-only mode.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.degraded.is_some()
    }

    /// How many `(SID, verb)` grants are held. Observability; never a decision.
    #[must_use]
    pub fn grant_count(&self) -> usize {
        self.grants.values().map(BTreeSet::len).sum()
    }
}

impl PeerAuthorizer for TieredSidAuthorizer {
    fn authorize(&self, peer: &AuthenticatedPeer, verb: ControlVerb) -> Result<(), AuthzDenied> {
        match verb {
            // Tier R. Any peer the pipe's DACL admitted may read. The DACL is
            // defense in depth and the allow-list is the gate, so this tier is
            // the one place where "the DACL let you in" is the whole decision —
            // and it grants nothing but observation.
            ControlVerb::ReadStatus => Ok(()),
            // Tier C.
            ControlVerb::EngageKillSwitch | ControlVerb::ReleaseKillSwitch => {
                if let Some(reason) = self.degraded.as_ref() {
                    return Err(AuthzDenied::ReadOnlyMode {
                        verb,
                        reason: reason.clone(),
                    });
                }
                if self
                    .grants
                    .get(&peer.sid)
                    .is_some_and(|verbs| verbs.contains(&verb))
                {
                    Ok(())
                } else {
                    Err(AuthzDenied::NotGranted {
                        sid: peer.sid.as_str().to_owned(),
                        verb,
                    })
                }
            }
            // Tier O. Deliberately independent of the allow-list: this is the
            // path that repairs an allow-list nobody can read any more.
            ControlVerb::Override => {
                if peer.token.elevated_admin {
                    Ok(())
                } else {
                    Err(AuthzDenied::RequiresElevation { verb })
                }
            }
        }
    }
}

/// Proof that a verb was authorized for a peer.
///
/// Private fields and **no public constructor**, exactly like
/// [`ssk_signature::policy::AuthorizedUse`] and for the same reason: a function
/// that demands one as an argument cannot be satisfied by a caller that skipped
/// the check. The broker's actuation methods take `&Grant`, so deleting the
/// authorization call from the served path is a compile error rather than a
/// silently permissive mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    peer: PeerIdentity,
    verb: ControlVerb,
}

impl Grant {
    /// Minted only inside this crate, and only immediately after a
    /// [`PeerAuthorizer`] returned `Ok`.
    pub(crate) fn mint(peer: PeerIdentity, verb: ControlVerb) -> Self {
        Grant { peer, verb }
    }

    #[must_use]
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    #[must_use]
    pub fn verb(&self) -> ControlVerb {
        self.verb
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(sid: &str) -> AuthenticatedPeer {
        AuthenticatedPeer::new(
            PeerIdentity::parse_sid(sid).expect("test sid"),
            PeerToken::unprivileged(),
        )
    }

    fn elevated(sid: &str) -> AuthenticatedPeer {
        AuthenticatedPeer::new(
            PeerIdentity::parse_sid(sid).expect("test sid"),
            PeerToken {
                elevated_admin: true,
                admin_account_filtered: true,
                integrity_rid: 0x3000,
                logon_session: None,
            },
        )
    }

    const USER: &str = "S-1-5-21-650032732-2086122598-1934225963-1001";

    // ── SID parsing ─────────────────────────────────────────────────────────

    #[test]
    fn canonical_sids_parse() {
        for sid in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-1-0",
            "S-1-16-8192",
            "S-1-5-5-0-198419",
            USER,
        ] {
            assert_eq!(
                PeerIdentity::parse_sid(sid).expect(sid).as_str(),
                sid,
                "{sid} must parse and round-trip verbatim"
            );
        }
    }

    /// The hostile-input table. Every entry is a way an attacker-controlled or
    /// merely sloppy string could otherwise reach an SDDL builder or become a
    /// second spelling of an existing allow-list key.
    #[test]
    fn malformed_sids_are_refused() {
        let cases = [
            ("", "empty"),
            ("S-1-5", "no sub-authority"),
            ("S-1-", "no authority at all"),
            ("S-1-5-", "trailing separator yields an empty sub-authority"),
            ("s-1-5-18", "lowercase prefix is not canonical"),
            ("X-1-5-18", "wrong prefix"),
            ("S-2-5-18", "wrong revision"),
            ("S-1-0x5-18", "hex identifier authority"),
            ("S-1-5-018", "leading zero is a second spelling"),
            ("S-1-05-18", "leading zero in the authority"),
            ("S-1-5-4294967296", "sub-authority overflows u32"),
            (
                "S-1-281474976710656-1",
                "identifier authority overflows 48 bits",
            ),
            ("S-1-5-18 ", "trailing space"),
            (" S-1-5-18", "leading space"),
            ("S-1-5-18)(A;;FA;;;WD", "SDDL ACE injection"),
            ("S-1-5-18\0", "embedded NUL"),
            (
                "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
                "16 sub-authorities",
            ),
            ("in-process", "the reserved in-process label"),
            ("broker-self", "the reserved broker label"),
        ];
        for (sid, why) in cases {
            let err = PeerIdentity::parse_sid(sid)
                .expect_err(&format!("`{sid}` must be refused ({why})"));
            assert!(
                matches!(err, AuthzDenied::MalformedSid { .. }),
                "`{sid}` ({why}) produced {err:?}"
            );
            assert_eq!(err.code(), "PEER_SID_MALFORMED");
        }
    }

    #[test]
    fn a_sid_at_the_length_cap_is_accepted_and_one_past_is_not() {
        // The largest legal SID string: a 15-digit 48-bit identifier authority
        // (2^48 - 1) plus 15 sub-authorities of 10 digits — 4 + 15 + 15 * 11 = 184.
        let mut sid = String::from("S-1-281474976710655");
        for _ in 0..MAX_SID_SUB_AUTHORITIES {
            sid.push_str("-4294967295");
        }
        assert_eq!(sid.len(), MAX_SID_STRING_LEN);
        assert!(PeerIdentity::parse_sid(&sid).is_ok(), "{sid}");

        let over = format!("{sid}0");
        assert!(PeerIdentity::parse_sid(&over).is_err());
    }

    /// The reserved internal identities can never be produced from a parsed
    /// string, so an allow-list built from real SIDs can never contain them.
    #[test]
    fn reserved_identities_are_unreachable_from_parsing() {
        for reserved in [PeerIdentity::in_process(), PeerIdentity::broker_self()] {
            assert!(
                PeerIdentity::parse_sid(reserved.as_str()).is_err(),
                "{reserved} must not be parseable"
            );
        }
    }

    // ── verb classification ─────────────────────────────────────────────────

    #[test]
    fn every_command_maps_to_its_tier() {
        assert_eq!(
            ControlVerb::for_command(Command::GetStatus),
            ControlVerb::ReadStatus
        );
        assert_eq!(
            ControlVerb::for_command(Command::EngageKillSwitch),
            ControlVerb::EngageKillSwitch
        );
        assert_eq!(
            ControlVerb::for_command(Command::ReleaseKillSwitch),
            ControlVerb::ReleaseKillSwitch
        );
    }

    #[test]
    fn the_mutating_classification_agrees_with_the_command_layer() {
        for command in [
            Command::GetStatus,
            Command::EngageKillSwitch,
            Command::ReleaseKillSwitch,
        ] {
            assert_eq!(
                ControlVerb::for_command(command).is_mutating(),
                command.is_mutating(),
                "{command:?}"
            );
        }
        // Override has no wire command and is mutating by definition.
        assert!(ControlVerb::Override.is_mutating());
    }

    #[test]
    fn verb_names_are_distinct_and_stable() {
        let names: BTreeSet<&str> = ControlVerb::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(names.len(), ControlVerb::ALL.len());
    }

    // ── the full tier decision table ────────────────────────────────────────

    /// Every (authorizer, peer, verb) cell, asserted explicitly. The point of
    /// enumerating rather than spot-checking is that a change to one tier
    /// cannot quietly move another.
    #[test]
    fn the_tier_table_is_exactly_as_designed() {
        let allowed = TieredSidAuthorizer::deny_all()
            .allow(
                PeerIdentity::parse_sid(USER).unwrap(),
                ControlVerb::EngageKillSwitch,
            )
            .allow(
                PeerIdentity::parse_sid(USER).unwrap(),
                ControlVerb::ReleaseKillSwitch,
            );
        let empty = TieredSidAuthorizer::deny_all();
        let degraded = TieredSidAuthorizer::read_only("authz.json is missing");

        let stranger = "S-1-5-21-1-2-3-1002";

        // (authorizer, peer, verb, expected Ok?)
        let table: [(&TieredSidAuthorizer, AuthenticatedPeer, ControlVerb, bool); 16] = [
            (&allowed, peer(USER), ControlVerb::ReadStatus, true),
            (&allowed, peer(USER), ControlVerb::EngageKillSwitch, true),
            (&allowed, peer(USER), ControlVerb::ReleaseKillSwitch, true),
            (&allowed, peer(USER), ControlVerb::Override, false),
            (&allowed, elevated(USER), ControlVerb::Override, true),
            (&allowed, peer(stranger), ControlVerb::ReadStatus, true),
            (
                &allowed,
                peer(stranger),
                ControlVerb::EngageKillSwitch,
                false,
            ),
            (
                &allowed,
                peer(stranger),
                ControlVerb::ReleaseKillSwitch,
                false,
            ),
            (&empty, peer(USER), ControlVerb::ReadStatus, true),
            (&empty, peer(USER), ControlVerb::EngageKillSwitch, false),
            (&empty, peer(USER), ControlVerb::ReleaseKillSwitch, false),
            (&empty, elevated(USER), ControlVerb::Override, true),
            (&degraded, peer(USER), ControlVerb::ReadStatus, true),
            (&degraded, peer(USER), ControlVerb::EngageKillSwitch, false),
            (&degraded, peer(USER), ControlVerb::ReleaseKillSwitch, false),
            // The recovery path out of read-only mode is still open.
            (&degraded, elevated(USER), ControlVerb::Override, true),
        ];

        for (authorizer, p, verb, expect_ok) in table {
            let got = authorizer.authorize(&p, verb);
            assert_eq!(
                got.is_ok(),
                expect_ok,
                "{} / {verb} / elevated={} → {got:?}",
                p.sid,
                p.token.elevated_admin
            );
        }
    }

    /// A grant for engage does not imply release, and vice versa. The two are
    /// separately recorded decisions because they point in opposite directions:
    /// engage is the denial-of-service direction, release is the recovery one.
    #[test]
    fn a_grant_for_one_tier_c_verb_does_not_imply_the_other() {
        let engage_only = TieredSidAuthorizer::deny_all().allow(
            PeerIdentity::parse_sid(USER).unwrap(),
            ControlVerb::EngageKillSwitch,
        );
        assert!(engage_only
            .authorize(&peer(USER), ControlVerb::EngageKillSwitch)
            .is_ok());
        let err = engage_only
            .authorize(&peer(USER), ControlVerb::ReleaseKillSwitch)
            .unwrap_err();
        assert_eq!(err.code(), "PEER_NOT_GRANTED");
    }

    /// An allow-list entry must **not** substitute for elevation on tier O:
    /// the override tier exists so a locked-out machine can be repaired by
    /// someone the allow-list does not mention, and letting a listed
    /// non-elevated SID reach it would collapse the two tiers into one.
    #[test]
    fn an_allow_list_entry_never_satisfies_the_override_tier() {
        let generous = TieredSidAuthorizer::deny_all()
            .allow(
                PeerIdentity::parse_sid(USER).unwrap(),
                ControlVerb::Override,
            )
            .allow(
                PeerIdentity::parse_sid(USER).unwrap(),
                ControlVerb::EngageKillSwitch,
            );
        let err = generous
            .authorize(&peer(USER), ControlVerb::Override)
            .unwrap_err();
        assert!(
            matches!(err, AuthzDenied::RequiresElevation { .. }),
            "{err:?}"
        );
        assert!(generous
            .authorize(&elevated(USER), ControlVerb::Override)
            .is_ok());
    }

    /// The measured Windows 11 reality: a UAC-filtered administrator is *not*
    /// elevated. If tier O ever consulted `admin_account_filtered` instead of
    /// `elevated_admin`, this peer would pass — which is the exact confusion the
    /// two fields exist to prevent.
    #[test]
    fn a_uac_filtered_administrator_does_not_reach_the_override_tier() {
        let filtered = AuthenticatedPeer::new(
            PeerIdentity::parse_sid(USER).unwrap(),
            PeerToken {
                elevated_admin: false,
                admin_account_filtered: true,
                integrity_rid: INTEGRITY_RID_MEDIUM,
                logon_session: PeerIdentity::parse_sid("S-1-5-5-0-198419").ok(),
            },
        );
        assert!(filtered.token.is_coherent());
        let err = TieredSidAuthorizer::deny_all()
            .authorize(&filtered, ControlVerb::Override)
            .unwrap_err();
        assert_eq!(err.code(), "PEER_REQUIRES_ELEVATION");
    }

    #[test]
    fn read_only_mode_says_why_and_still_serves_status() {
        let a = TieredSidAuthorizer::read_only("authz.json failed to parse at line 3");
        assert!(a.is_read_only());
        assert!(a.authorize(&peer(USER), ControlVerb::ReadStatus).is_ok());
        let err = a
            .authorize(&peer(USER), ControlVerb::EngageKillSwitch)
            .unwrap_err();
        assert_eq!(err.code(), "PEER_READ_ONLY_MODE");
        assert!(
            err.to_string().contains("line 3"),
            "the reason must reach the operator: {err}"
        );
    }

    #[test]
    fn grant_count_and_dedup() {
        let sid = PeerIdentity::parse_sid(USER).unwrap();
        let a = TieredSidAuthorizer::deny_all()
            .allow(sid.clone(), ControlVerb::EngageKillSwitch)
            .allow(sid.clone(), ControlVerb::EngageKillSwitch)
            .allow(sid, ControlVerb::ReleaseKillSwitch);
        assert_eq!(a.grant_count(), 2, "a repeated grant is one grant");
    }

    #[test]
    fn a_coherent_token_cannot_be_elevated_without_being_an_admin_account() {
        assert!(PeerToken::unprivileged().is_coherent());
        assert!(!PeerToken {
            elevated_admin: true,
            admin_account_filtered: false,
            integrity_rid: 0x3000,
            logon_session: None,
        }
        .is_coherent());
    }

    #[test]
    fn denials_map_to_a_typed_wire_rejection_that_carries_the_code() {
        let err = AuthzDenied::NotGranted {
            sid: USER.to_owned(),
            verb: ControlVerb::EngageKillSwitch,
        };
        match err.to_reject_reason() {
            RejectReason::PeerUnauthorized { code, detail } => {
                assert_eq!(code, "PEER_NOT_GRANTED");
                assert!(detail.contains(USER), "{detail}");
            }
            other => panic!("{other:?}"),
        }
    }
}
