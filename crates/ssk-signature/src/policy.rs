//! Operation contract — Chameleon `policy`.
//!
//! [`ChameleonPolicy`] validates that an evaluation mode is supported and that
//! an [`AuthorizationManifest`] covers the requested use. The allowed/blocked
//! mode sets are **configurable fields with the kernel author's own defaults**
//! — this port keeps them parametric rather than hard-coding any of them, and
//! carries no clock (a manifest's `created_at` is caller-supplied) so evaluation
//! stays deterministic and replay-friendly.
//!
//! # Two decisions live here, and they are not the same strength
//!
//! | API | What it is | Consults an allow-list? |
//! |---|---|---|
//! | [`AuthorizationManifest::authorize`] | a real authorization decision | **yes** — [`AuthorizationPolicyTable`] |
//! | [`AuthorizationManifest::is_valid_for`] | a *self-declaration* check | no |
//!
//! [`AuthorizationManifest::is_valid_for`] answers "does this manifest **claim**
//! this use?", not "is this actor **permitted** this use?". The manifest is
//! unauthenticated data: whoever constructs one picks its own `allowed_uses`.
//! It is retained because three crates outside this file (`ssk-boundary`,
//! `ssk-profile-manifold`, `ssk-service-host`) still gate privileged verbs on
//! it across seven call sites; see that method's own doc comment for the
//! migration and the phase that owns it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// Outcome of a policy evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyOutcome {
    Pass,
    Fail,
}

impl PolicyOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyOutcome::Pass => "PASS",
            PolicyOutcome::Fail => "FAIL",
        }
    }

    #[must_use]
    pub fn is_pass(self) -> bool {
        matches!(self, PolicyOutcome::Pass)
    }
}

/// A policy decision: outcome + machine-readable reason.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub outcome: PolicyOutcome,
    pub reason: String,
}

impl PolicyDecision {
    fn pass() -> Self {
        PolicyDecision {
            outcome: PolicyOutcome::Pass,
            reason: "operation_contract_pass".to_owned(),
        }
    }

    fn fail(reason: impl Into<String>) -> Self {
        PolicyDecision {
            outcome: PolicyOutcome::Fail,
            reason: reason.into(),
        }
    }
}

fn default_allowed_uses() -> Vec<String> {
    [
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "adapter_operation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

// ── Real authorization: principals, privileged verbs, and an allow-list ─────

/// Why an authorization decision said no. Every variant names the *specific*
/// failure so a caller can log a cause instead of a bare `false`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthorizationDenied {
    /// A manifest identity field was empty or whitespace-only.
    #[error("authorization manifest field `{field}` is blank")]
    BlankField { field: &'static str },
    /// A use token was not `[a-z0-9_]{{1,64}}`.
    #[error("`{use_}` is not a well-formed use token")]
    MalformedUse { use_: String },
    /// The manifest's `allowed_uses` contains an entry that is not a
    /// well-formed use token, so the whole declaration is untrustworthy.
    #[error("authorization manifest declares a malformed use token `{use_}`")]
    MalformedDeclaration { use_: String },
    /// The manifest does not claim this use at all.
    #[error("authorization manifest does not declare the use `{use_}`")]
    UseNotDeclared { use_: String },
    /// A principal name was not `[a-z0-9][a-z0-9_.-]{{0,63}}`.
    #[error("`{name}` is not a well-formed principal name")]
    MalformedPrincipal { name: String },
    /// A privileged control verb was requested by a manifest that carries no
    /// principal, so there is nothing to look up in the allow-list.
    #[error("`{use_}` is a privileged control verb and the manifest carries no principal")]
    NoPrincipal { use_: &'static str },
    /// The allow-list holds no `(principal, verb)` grant for this pair. This is
    /// the decision the four-non-empty-string check never made.
    #[error("principal `{principal}` is not granted the privileged use `{use_}`")]
    NotGranted {
        principal: String,
        use_: &'static str,
    },
}

/// A named actor requesting a use.
///
/// **This crate does not authenticate a principal.** It validates the *shape*
/// of the name and gives the name a type so it cannot be confused with a use, a
/// source name, or arbitrary prose. Binding a `Principal` to a verified OS
/// identity (a Windows client SID over the named pipe, `ssk-ipc/src/auth.rs`)
/// is P2/P3 work and is deliberately not faked here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Principal(String);

impl Principal {
    /// Parse a principal name: `[a-z0-9][a-z0-9_.-]{0,63}`.
    ///
    /// # Errors
    /// [`AuthorizationDenied::MalformedPrincipal`] if the name does not match.
    pub fn parse(name: &str) -> Result<Self, AuthorizationDenied> {
        let ok = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            && name.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
            });
        if ok {
            Ok(Principal(name.to_owned()))
        } else {
            Err(AuthorizationDenied::MalformedPrincipal {
                name: name.to_owned(),
            })
        }
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The closed set of **privileged control verbs** — the uses that actuate a
/// privileged OS effect rather than analyse data at rest.
///
/// # Why these strings are duplicated here
///
/// Each verb's canonical constant lives in the crate that enforces it
/// (`ssk_boundary::BOUNDARY_CONTROL_USE`, `ssk_boundary::BOUNDARY_OVERRIDE_USE`,
/// `ssk_profile_manifold::PROFILE_CONTROL_USE`,
/// `ssk_profile_manifold::PROFILE_DOWNGRADE_USE`,
/// `ssk_service_host::SERVICE_CONTROL_USE`). Every one of those crates depends
/// on `ssk-signature`, so `ssk-signature` cannot depend back on them without a
/// cycle — the literals must be restated. A drift guard for the two boundary
/// verbs runs in `ssk-netd-helper/tests/p1_hardening.rs`
/// (`privileged_use_literals_match_the_boundary_crate_constants`), which is the
/// one crate that can see both sides. **The profile and service verbs have no drift
/// guard**, because no crate in the workspace depends on both `ssk-signature`
/// and those crates; renaming one of those constants without editing this enum
/// would silently declassify it. Recorded rather than papered over.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum PrivilegedUse {
    /// Engage / release the egress kill-switch.
    BoundaryControl,
    /// Force the kill-switch from an unexpected state.
    BoundaryOverride,
    /// Change the active protection profile.
    ProfileControl,
    /// Lower the active protection profile.
    ProfileDowngrade,
    /// Install / start / stop / uninstall the privileged service host.
    ServiceControl,
}

impl PrivilegedUse {
    /// Every privileged verb, in a fixed order.
    pub const ALL: [PrivilegedUse; 5] = [
        PrivilegedUse::BoundaryControl,
        PrivilegedUse::BoundaryOverride,
        PrivilegedUse::ProfileControl,
        PrivilegedUse::ProfileDowngrade,
        PrivilegedUse::ServiceControl,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            PrivilegedUse::BoundaryControl => "boundary_control",
            PrivilegedUse::BoundaryOverride => "boundary_override",
            PrivilegedUse::ProfileControl => "profile_control",
            PrivilegedUse::ProfileDowngrade => "profile_downgrade",
            PrivilegedUse::ServiceControl => "service_control",
        }
    }

    /// Classify a use string. `None` means "not a privileged control verb" —
    /// an ordinary analysis/observation use, not an unknown-and-therefore-safe
    /// one.
    #[must_use]
    pub fn from_use_str(use_: &str) -> Option<Self> {
        PrivilegedUse::ALL.into_iter().find(|p| p.as_str() == use_)
    }
}

/// The explicit `(principal, privileged verb)` allow-list — the actual
/// authorization decision.
///
/// Empty by construction: [`AuthorizationPolicyTable::deny_all`] grants
/// nothing, and the only way to add a grant is to name both halves. There is no
/// wildcard and no "grant everything the manifest claims" constructor, because
/// either one would reintroduce exactly the self-declaration hole this type
/// exists to close.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthorizationPolicyTable {
    grants: BTreeSet<(Principal, PrivilegedUse)>,
}

impl AuthorizationPolicyTable {
    /// A table that permits nothing. The correct starting point.
    #[must_use]
    pub fn deny_all() -> Self {
        AuthorizationPolicyTable {
            grants: BTreeSet::new(),
        }
    }

    /// Add one explicit grant.
    #[must_use]
    pub fn allow(mut self, principal: Principal, use_: PrivilegedUse) -> Self {
        self.grants.insert((principal, use_));
        self
    }

    /// Whether this exact pair is granted.
    #[must_use]
    pub fn grants(&self, principal: &Principal, use_: PrivilegedUse) -> bool {
        self.grants
            .iter()
            .any(|(p, u)| p == principal && *u == use_)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }
}

/// Proof that a specific use was **authorized**, not merely declared.
///
/// Constructible only by [`AuthorizationManifest::authorize`] (its fields are
/// private and it has no public constructor), so a function that demands one as
/// an argument cannot be satisfied by a caller that skipped the check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedUse {
    use_: String,
    principal: Option<Principal>,
}

impl AuthorizedUse {
    #[must_use]
    pub fn use_str(&self) -> &str {
        &self.use_
    }

    /// The principal the grant was found for. `None` only for non-privileged
    /// uses, which are decided by declaration alone.
    #[must_use]
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_ref()
    }
}

/// A use token is `[a-z0-9_]{1,64}`.
fn is_well_formed_use(use_: &str) -> bool {
    !use_.is_empty()
        && use_.len() <= 64
        && use_
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Proof that traces/logs/endpoints are owned or explicitly authorized.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationManifest {
    pub source_name: String,
    pub owner_or_controller: String,
    pub permission_basis: String,
    pub allowed_uses: Vec<String>,
    /// Caller-supplied timestamp (no implicit clock, for determinism).
    pub created_at: Option<String>,
    pub evidence_ref: Option<String>,
    /// The actor this manifest speaks for, when one is known.
    ///
    /// `None` is the default and is **not** an escape hatch: a `None` principal
    /// can never satisfy [`AuthorizationManifest::authorize`] for a
    /// [`PrivilegedUse`].
    pub principal: Option<Principal>,
}

impl AuthorizationManifest {
    #[must_use]
    pub fn new(
        source_name: impl Into<String>,
        owner_or_controller: impl Into<String>,
        permission_basis: impl Into<String>,
    ) -> Self {
        AuthorizationManifest {
            source_name: source_name.into(),
            owner_or_controller: owner_or_controller.into(),
            permission_basis: permission_basis.into(),
            allowed_uses: default_allowed_uses(),
            created_at: None,
            evidence_ref: None,
            principal: None,
        }
    }

    #[must_use]
    pub fn with_allowed_uses<I, S>(mut self, uses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_uses = uses.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn with_evidence_ref(mut self, evidence_ref: impl Into<String>) -> Self {
        self.evidence_ref = Some(evidence_ref.into());
        self
    }

    /// Attach the actor this manifest speaks for. Required before any
    /// [`PrivilegedUse`] can be authorized.
    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Structural validity + self-declaration, with a typed reason.
    ///
    /// This is everything a manifest can prove **about itself**: that its
    /// identity fields are populated, that its declared uses are well-formed
    /// tokens, and that it claims the requested use. It performs no allow-list
    /// lookup and is therefore not, on its own, an authorization decision — see
    /// [`AuthorizationManifest::authorize`].
    ///
    /// # Errors
    /// [`AuthorizationDenied`], naming which of those three failed.
    pub fn declares(&self, use_: &str) -> Result<(), AuthorizationDenied> {
        for (field, value) in [
            ("source_name", &self.source_name),
            ("owner_or_controller", &self.owner_or_controller),
            ("permission_basis", &self.permission_basis),
        ] {
            if value.trim().is_empty() {
                return Err(AuthorizationDenied::BlankField { field });
            }
        }
        if !is_well_formed_use(use_) {
            return Err(AuthorizationDenied::MalformedUse {
                use_: use_.to_owned(),
            });
        }
        // A manifest carrying junk in `allowed_uses` is not a manifest we can
        // reason about, even if the *requested* use happens to be clean.
        if let Some(bad) = self
            .allowed_uses
            .iter()
            .find(|u| !is_well_formed_use(u.as_str()))
        {
            return Err(AuthorizationDenied::MalformedDeclaration { use_: bad.clone() });
        }
        if !self.allowed_uses.iter().any(|u| u == use_) {
            return Err(AuthorizationDenied::UseNotDeclared {
                use_: use_.to_owned(),
            });
        }
        Ok(())
    }

    /// **The real authorization decision.** Consults an explicit
    /// `(principal, verb)` allow-list for every [`PrivilegedUse`].
    ///
    /// A privileged verb requires *all* of:
    /// 1. a structurally sound manifest that declares the use ([`Self::declares`]),
    /// 2. a [`Principal`] on the manifest, and
    /// 3. an explicit grant for that exact `(principal, verb)` pair in `table`.
    ///
    /// Step 3 is what a self-declared `with_allowed_uses(["boundary_control"])`
    /// can never satisfy: the table is built by the composition root, not by
    /// the manifest's author.
    ///
    /// Non-privileged uses (`offline_analysis`, `network_observation`, host
    /// capability names, …) are decided by declaration alone and never consult
    /// the table. That asymmetry is deliberate: those uses gate parsing and
    /// reading, not an OS effect, and subjecting them to an allow-list would
    /// require every analysis caller in the workspace to own a table.
    ///
    /// # Errors
    /// [`AuthorizationDenied`] naming the exact reason.
    pub fn authorize(
        &self,
        use_: &str,
        table: &AuthorizationPolicyTable,
    ) -> Result<AuthorizedUse, AuthorizationDenied> {
        self.declares(use_)?;
        let Some(privileged) = PrivilegedUse::from_use_str(use_) else {
            return Ok(AuthorizedUse {
                use_: use_.to_owned(),
                principal: None,
            });
        };
        let Some(principal) = self.principal.as_ref() else {
            return Err(AuthorizationDenied::NoPrincipal {
                use_: privileged.as_str(),
            });
        };
        if !table.grants(principal, privileged) {
            return Err(AuthorizationDenied::NotGranted {
                principal: principal.as_str().to_owned(),
                use_: privileged.as_str(),
            });
        }
        Ok(AuthorizedUse {
            use_: use_.to_owned(),
            principal: Some(principal.clone()),
        })
    }

    /// **Self-declaration check — NOT an authorization decision.**
    ///
    /// Returns whether this manifest is structurally sound and *claims* `use_`.
    /// It answers "what does this manifest say about itself?", never "may this
    /// actor do this?". An [`AuthorizationManifest`] is unauthenticated data:
    /// any code that can build one picks its own `allowed_uses`, so
    /// `AuthorizationManifest::new("x", "me", "none")
    /// .with_allowed_uses(["boundary_control"])` passes this check and would
    /// sever all network egress. That is a real, currently-open hole and it is
    /// asserted by
    /// `tests::is_valid_for_still_accepts_a_self_declared_privileged_verb`.
    ///
    /// [`AuthorizationManifest::authorize`] is the decision that closes it, by
    /// consulting an [`AuthorizationPolicyTable`]. It is enforced today on the
    /// one path this change owns: `ssk_netd_helper::Broker::recover_with_policy`.
    ///
    /// **Migration (owned by P3, `docs/WINDOWS_PRODUCT_ROADMAP.md`).** Seven
    /// call sites outside this file still gate a privileged verb on
    /// `is_valid_for` and must move to `authorize`:
    /// `ssk-boundary/src/lib.rs` (engage, release, `override_engage`),
    /// `ssk-profile-manifold/src/lib.rs` (control, downgrade), and
    /// `ssk-service-host/src/lib.rs` (`require_control`, capability handshake).
    /// They are not changed here because this change's file scope is
    /// `ssk-netd-helper/**` + this file, and because each needs a table
    /// threaded in from its own composition root — an API change per crate, not
    /// a rename.
    ///
    /// What this method *does* now enforce, which it did not before:
    /// whitespace-only identity fields are rejected, and a malformed use token
    /// (or a manifest declaring one) is rejected rather than silently compared
    /// as a string.
    #[must_use]
    pub fn is_valid_for(&self, use_: &str) -> bool {
        self.declares(use_).is_ok()
    }
}

fn default_allowed_modes() -> Vec<String> {
    [
        "offline_analysis",
        "offline_redaction",
        "offline_reanalysis",
        "network_observation",
        "network_reanalysis",
        "adapter_operation",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn default_blocked_modes() -> Vec<String> {
    [
        "live_transform",
        "live_packet_manipulation",
        "proxy_or_vpn_control",
        "credential_use",
        "detector_bypass",
        "covert_channel",
        "packet_injection",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// The runtime operation contract (Chameleon `ChameleonPolicy`). All three sets
/// are configurable; the defaults reproduce the kernel author's own.
#[derive(Clone, Debug, PartialEq)]
pub struct ChameleonPolicy {
    pub require_authorization: bool,
    pub allowed_modes: Vec<String>,
    pub blocked_modes: Vec<String>,
}

impl Default for ChameleonPolicy {
    fn default() -> Self {
        ChameleonPolicy {
            require_authorization: true,
            allowed_modes: default_allowed_modes(),
            blocked_modes: default_blocked_modes(),
        }
    }
}

impl ChameleonPolicy {
    #[must_use]
    pub fn evaluate(
        &self,
        mode: &str,
        authorization: Option<&AuthorizationManifest>,
    ) -> PolicyDecision {
        if self.blocked_modes.iter().any(|m| m == mode) {
            return PolicyDecision::fail(format!("unsupported_operation:{mode}"));
        }
        if !self.allowed_modes.iter().any(|m| m == mode) {
            return PolicyDecision::fail(format!("mode_not_allowed:{mode}"));
        }
        if self.require_authorization {
            match authorization {
                None => return PolicyDecision::fail("authorization_manifest_missing"),
                Some(auth) if !auth.is_valid_for(mode) => {
                    return PolicyDecision::fail(format!(
                        "authorization_manifest_invalid_for:{mode}"
                    ));
                }
                Some(_) => {}
            }
        }
        PolicyDecision::pass()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_valid_for_offline_analysis() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned lab data")
            .with_allowed_uses(["offline_analysis"]);
        assert!(auth.is_valid_for("offline_analysis"));
        assert!(!auth.is_valid_for("network_observation"));
    }

    #[test]
    fn policy_requires_authorization() {
        let decision = ChameleonPolicy::default().evaluate("offline_analysis", None);
        assert_eq!(decision.outcome, PolicyOutcome::Fail);
        assert!(decision.reason.contains("authorization"));
    }

    #[test]
    fn policy_allows_authorized_network_observation() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned")
            .with_allowed_uses(["network_observation"]);
        let decision = ChameleonPolicy::default().evaluate("network_observation", Some(&auth));
        assert_eq!(decision.outcome, PolicyOutcome::Pass);
    }

    // ── The residual hole, asserted rather than described ───────────────────
    /// `is_valid_for` is a self-declaration check. This test exists so the hole
    /// is a **red test the day someone believes it is closed**, not a claim in
    /// a comment. When the P3 migration lands, this test must be deleted in the
    /// same commit that migrates the seven call sites named on `is_valid_for`.
    #[test]
    fn is_valid_for_still_accepts_a_self_declared_privileged_verb() {
        let forged =
            AuthorizationManifest::new("x", "me", "none").with_allowed_uses(["boundary_control"]);
        assert!(
            forged.is_valid_for("boundary_control"),
            "documented hole: self-declaration is accepted by is_valid_for"
        );
        // ...and the real decision refuses the same manifest.
        assert_eq!(
            forged.authorize("boundary_control", &AuthorizationPolicyTable::deny_all()),
            Err(AuthorizationDenied::NoPrincipal {
                use_: "boundary_control"
            })
        );
    }

    #[test]
    fn declares_rejects_blank_and_whitespace_only_fields() {
        let blank = AuthorizationManifest::new("", "me", "basis");
        assert_eq!(
            blank.declares("offline_analysis"),
            Err(AuthorizationDenied::BlankField {
                field: "source_name"
            })
        );
        // Whitespace-only passed the old four-non-empty-string check.
        let spaces = AuthorizationManifest::new("src", "   ", "basis");
        assert_eq!(
            spaces.declares("offline_analysis"),
            Err(AuthorizationDenied::BlankField {
                field: "owner_or_controller"
            })
        );
        assert!(!spaces.is_valid_for("offline_analysis"));
    }

    #[test]
    fn declares_rejects_malformed_use_tokens() {
        let m = AuthorizationManifest::new("src", "me", "basis");
        for bad in [
            "",
            "Boundary_Control",
            "boundary control",
            "boundary-control",
        ] {
            assert_eq!(
                m.declares(bad),
                Err(AuthorizationDenied::MalformedUse {
                    use_: bad.to_owned()
                }),
                "{bad:?} must not be a use token"
            );
        }
        // A manifest declaring junk is rejected even for a clean request.
        let junky = AuthorizationManifest::new("src", "me", "basis")
            .with_allowed_uses(["offline_analysis", "NOT A USE"]);
        assert_eq!(
            junky.declares("offline_analysis"),
            Err(AuthorizationDenied::MalformedDeclaration {
                use_: "NOT A USE".to_owned()
            })
        );
    }

    #[test]
    fn every_use_string_the_workspace_actually_passes_is_still_accepted() {
        // Regression guard for the tightening above: these are the use strings
        // grepped out of every `is_valid_for` / `with_allowed_uses` call site
        // in the workspace at the time of the change.
        let uses = [
            "offline_analysis",
            "offline_redaction",
            "offline_reanalysis",
            "network_observation",
            "network_reanalysis",
            "adapter_operation",
            "self_observation",
            "boundary_control",
            "boundary_override",
            "profile_control",
            "profile_downgrade",
            "service_control",
            "system_capture",
            "egress_teardown",
            "kernel_module",
            "live_packet_manipulation",
        ];
        let m =
            AuthorizationManifest::new("operator", "me", "host control").with_allowed_uses(uses);
        for u in uses {
            assert!(m.is_valid_for(u), "{u} must remain accepted");
        }
    }

    #[test]
    fn authorize_requires_an_explicit_principal_verb_grant() {
        let broker = Principal::parse("ssk-netd-helper").unwrap();
        let manifest = AuthorizationManifest::new("ssk-netd-helper", "system", "privileged broker")
            .with_allowed_uses(["boundary_control"])
            .with_principal(broker.clone());

        // Deny-all: refused, with the principal named.
        assert_eq!(
            manifest.authorize("boundary_control", &AuthorizationPolicyTable::deny_all()),
            Err(AuthorizationDenied::NotGranted {
                principal: "ssk-netd-helper".to_owned(),
                use_: "boundary_control"
            })
        );

        // A grant for a *different* verb does not carry over.
        let wrong_verb = AuthorizationPolicyTable::deny_all()
            .allow(broker.clone(), PrivilegedUse::ProfileControl);
        assert!(manifest.authorize("boundary_control", &wrong_verb).is_err());

        // A grant for a *different* principal does not carry over.
        let wrong_principal = AuthorizationPolicyTable::deny_all().allow(
            Principal::parse("someone-else").unwrap(),
            PrivilegedUse::BoundaryControl,
        );
        assert!(manifest
            .authorize("boundary_control", &wrong_principal)
            .is_err());

        // The exact pair is allowed.
        let table =
            AuthorizationPolicyTable::deny_all().allow(broker, PrivilegedUse::BoundaryControl);
        let granted = manifest.authorize("boundary_control", &table).unwrap();
        assert_eq!(granted.use_str(), "boundary_control");
        assert_eq!(
            granted.principal().map(Principal::as_str),
            Some("ssk-netd-helper")
        );
    }

    #[test]
    fn authorize_still_requires_declaration_even_when_granted() {
        let p = Principal::parse("ssk-netd-helper").unwrap();
        let table =
            AuthorizationPolicyTable::deny_all().allow(p.clone(), PrivilegedUse::BoundaryControl);
        // Granted in the table, but the manifest never claimed the use.
        let manifest = AuthorizationManifest::new("ssk-netd-helper", "system", "broker")
            .with_allowed_uses(["offline_analysis"])
            .with_principal(p);
        assert_eq!(
            manifest.authorize("boundary_control", &table),
            Err(AuthorizationDenied::UseNotDeclared {
                use_: "boundary_control".to_owned()
            })
        );
    }

    #[test]
    fn non_privileged_uses_do_not_consult_the_table() {
        let manifest = AuthorizationManifest::new("owned-log", "me", "self-owned lab data")
            .with_allowed_uses(["offline_analysis"]);
        let granted = manifest
            .authorize("offline_analysis", &AuthorizationPolicyTable::deny_all())
            .unwrap();
        assert!(granted.principal().is_none());
    }

    #[test]
    fn privileged_use_classification_is_closed_and_total() {
        for p in PrivilegedUse::ALL {
            assert_eq!(PrivilegedUse::from_use_str(p.as_str()), Some(p));
        }
        assert_eq!(PrivilegedUse::from_use_str("offline_analysis"), None);
        assert_eq!(PrivilegedUse::from_use_str("system_capture"), None);
        assert_eq!(PrivilegedUse::from_use_str(""), None);
    }

    #[test]
    fn principal_names_are_validated() {
        assert!(Principal::parse("ssk-netd-helper").is_ok());
        assert!(Principal::parse("operator.1").is_ok());
        for bad in ["", "-leading", "UPPER", "has space", "sid\\admin"] {
            assert_eq!(
                Principal::parse(bad),
                Err(AuthorizationDenied::MalformedPrincipal {
                    name: bad.to_owned()
                })
            );
        }
        assert!(Principal::parse(&"a".repeat(65)).is_err());
    }

    #[test]
    fn a_deny_all_table_is_empty_and_grants_are_exact() {
        let empty = AuthorizationPolicyTable::deny_all();
        assert!(empty.is_empty());
        let p = Principal::parse("operator").unwrap();
        let t = empty.allow(p.clone(), PrivilegedUse::ServiceControl);
        assert_eq!(t.len(), 1);
        assert!(t.grants(&p, PrivilegedUse::ServiceControl));
        assert!(!t.grants(&p, PrivilegedUse::BoundaryControl));
    }

    #[test]
    fn policy_denies_unsupported_live_mutation() {
        let auth = AuthorizationManifest::new("owned-log", "me", "self-owned")
            .with_allowed_uses(["adapter_operation"]);
        let decision = ChameleonPolicy::default().evaluate("live_packet_manipulation", Some(&auth));
        assert_eq!(decision.outcome, PolicyOutcome::Fail);
        assert!(decision.reason.starts_with("unsupported_operation"));
    }
}
