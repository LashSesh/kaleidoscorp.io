//! Kill-switch enforcement (firewall seam): a real [`ssk_boundary::BoundaryEnforcer`].
//!
//! Sever and restore *all outbound egress* by driving the Windows Firewall
//! through `netsh advfirewall firewall` via [`std::process::Command`]. No kernel
//! driver, no COM; requires Administrator at runtime.
//!
//! Design split (the reason this is testable off-Windows):
//! * a PURE, platform-neutral layer — rule-name derivation and *validation*,
//!   argument construction, netsh result classification, and receipt encoding —
//!   all unit-tested on any host;
//! * a THIN `#[cfg(windows)]` layer that is the only code that actually spawns
//!   `netsh`, deferring 100% of its logic to the pure functions.
//!
//! ## netsh is the INTERIM actuator, not the destination
//!
//! [`EgressMechanism`] names the seam. The destination is WFP dynamic session
//! filters (`FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC` +
//! `FwpmFilterAdd0`), whose filters auto-remove when the engine handle closes —
//! the property that makes a broker crash unable to strand a severed machine.
//! Nothing in this module's *public* shape assumes netsh: no rule name escapes
//! into a caller-visible type, [`NetshError`] appears in no signature outside
//! this crate, and no "rules removed" count is a success criterion (WFP deletes
//! by key and returns no count).
//!
//! ## Why no netsh output text is ever read
//!
//! `netsh` writes localized prose. Measured on a de-DE Windows 11 host, exit
//! code **1** is returned identically for "no rules match", "a specified value
//! is invalid", "the number of arguments is invalid" and "command not found";
//! exit **0** was observed only for rules that genuinely exist. So:
//!
//! > **exit 0 ⟹ present. Any other exit ⟹ indeterminate — never `Absent`.**
//!
//! That asymmetry is the whole classification ([`classify_show`]). Consequently
//! there are no English (or German) string constants here, and
//! [`RawInvocation`] carries **bytes**: the text is decoded lossily only to
//! build a diagnostic string for a human ([`RawInvocation::evidence`]), and no
//! branch reads it. The encoding question is then closed by construction rather
//! than by guessing netsh's codepage.
//!
//! ## Fail-closed, in the correct direction
//!
//! A failure to *observe* never prevents an action that *increases* protection;
//! it only prevents a *claim* of protection. [`engage_with`] therefore proceeds
//! to the `add` even when the pre-probe is unanswerable (recording
//! [`Ownership::Unknown`]), and gates success on a **post-condition** probe
//! instead. An unconfirmable post-condition yields
//! [`Verification::Unconfirmed`] — never `Ok` — while still handing back a
//! releasable receipt.
//!
//! ## Exact rollback, bounded by construction
//!
//! The rule name is a pure function of the scope, so a receipt is never needed
//! to *identify* the rule — only to carry the ownership bit. [`KillSwitchRuleName`]
//! is the only way a name reaches an argument list, and it can be built from
//! untrusted bytes exclusively through [`KillSwitchRuleName::parse`], which
//! enforces the `SSK-KillSwitch-<label>-<digest16>` grammar. A receipt can
//! therefore never name an arbitrary firewall rule — in particular it can never
//! name `all`, which `netsh advfirewall firewall delete rule name=all` would
//! expand to *every rule in the profile*.

#![allow(clippy::result_large_err)]

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryObservation, BoundaryProbe, BoundaryScope,
    EnforcementReceipt, Presence, ReleaseOutcome,
};
use ssk_types::{digest_of, HashAlg};

// ---------------------------------------------------------------------------
// Mechanism identity
// ---------------------------------------------------------------------------

/// Stable identifier for the interim netsh actuator, as it appears in a
/// [`BoundaryObservation::mechanism`].
pub const MECHANISM_NETSH: &str = "netsh-advfirewall";

/// Stable identifier for the WFP actuator this seam is heading toward.
pub const MECHANISM_WFP: &str = "wfp-session-filter";

/// Token written into a receipt's `prior_state` envelope by the netsh actuator.
/// A receipt tagged with any other mechanism must not be driven through netsh.
pub const MECH_TAG_NETSH: &str = "netsh";

/// Which actuator a [`WindowsEgressEnforcer`] drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum EgressMechanism {
    /// **Interim.** `netsh advfirewall`. Persistent rules: a broker crash
    /// strands the machine severed. Exit-code-only classification, positive
    /// direction only.
    #[default]
    NetshInterim,
    /// **Destination.** `FwpmEngineOpen0` with `FWPM_SESSION_FLAG_DYNAMIC`;
    /// filters auto-remove when the engine handle closes.
    ///
    /// **Not implemented.** Selecting it makes every operation return
    /// [`KillSwitchError::MechanismUnavailable`] rather than silently falling
    /// back to netsh — a fallback would make a caller that asked for
    /// crash-safe enforcement believe it got one.
    WfpSessionFilter,
}

impl EgressMechanism {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EgressMechanism::NetshInterim => MECHANISM_NETSH,
            EgressMechanism::WfpSessionFilter => MECHANISM_WFP,
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Raw, un-interpreted result of one `netsh` invocation — the seam between the
/// impure process spawn and the pure classifiers.
///
/// `stdout`/`stderr` are **bytes on purpose**. netsh's text is localized and its
/// encoding is not contractual; decoding it is therefore a *display* concern
/// (see [`RawInvocation::evidence`]) and never a decision input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInvocation {
    /// Process exit code; `None` if terminated by a signal (modelled honestly).
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl RawInvocation {
    #[must_use]
    pub fn new(
        exit_code: Option<i32>,
        stdout: impl Into<Vec<u8>>,
        stderr: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    /// A bounded, lossily-decoded rendering of the captured output, **for
    /// humans and logs only**.
    ///
    /// Nothing in this crate branches on the result. Lossy UTF-8 decoding is
    /// deliberate: on the measured de-DE host netsh emitted valid UTF-8
    /// (`ü` = `c3 bc`) under every console codepage tried (850/1252/65001) and
    /// through both a pipe and a file redirect, but because no decision depends
    /// on this string, a host where that does not hold degrades to mojibake in
    /// a log line rather than to a wrong enforcement decision.
    #[must_use]
    pub fn evidence(&self) -> String {
        const LIMIT: usize = 400;
        fn render(tag: &str, bytes: &[u8]) -> Option<String> {
            let text = String::from_utf8_lossy(bytes);
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return None;
            }
            let mut shown: String = trimmed.chars().take(LIMIT).collect();
            if trimmed.chars().nth(LIMIT).is_some() {
                shown.push_str("...");
            }
            Some(format!("{tag}={shown:?}"))
        }
        let parts: Vec<String> = [
            render("stdout", &self.stdout),
            render("stderr", &self.stderr),
        ]
        .into_iter()
        .flatten()
        .collect();
        if parts.is_empty() {
            "<no output>".to_owned()
        } else {
            parts.join(" ")
        }
    }

    #[must_use]
    pub fn is_success_exit(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Typed error from a `netsh` invocation.
///
/// There is exactly one variant, and that is the finding: netsh's exit code
/// conflates every failure mode into `1`, so there is nothing further to
/// classify without reading localized prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetshError {
    /// netsh exited non-zero. The cause is **not** determinable from the exit
    /// code — "no match", "invalid value", "invalid argument count", "unknown
    /// command" and (presumed, unmeasured) "access denied" all produce 1.
    NonZeroExit {
        code: Option<i32>,
        /// Opaque diagnostic payload. No branch reads this.
        evidence: String,
    },
}

impl std::fmt::Display for NetshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetshError::NonZeroExit { code, evidence } => write!(
                f,
                "netsh exited with {code:?} (the exit code does not identify the cause): {evidence}"
            ),
        }
    }
}

impl std::error::Error for NetshError {}

/// Why a candidate rule name was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleNameError {
    /// Does not begin with [`RULE_PREFIX`]. Note that merely *containing* the
    /// prefix is not enough.
    MissingPrefix,
    /// The label segment is empty, longer than 32, or not ASCII alphanumeric.
    BadLabel,
    /// The digest segment is not exactly 16 lowercase ASCII hex digits.
    BadDigest,
    /// Outside the 31..=64 byte range the grammar admits.
    BadLength { len: usize },
}

impl std::fmt::Display for RuleNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleNameError::MissingPrefix => {
                write!(f, "rule name does not start with {RULE_PREFIX:?}")
            }
            RuleNameError::BadLabel => write!(
                f,
                "rule name label must be 1..=32 ASCII alphanumeric characters"
            ),
            RuleNameError::BadDigest => write!(
                f,
                "rule name digest must be exactly 16 lowercase ASCII hex digits"
            ),
            RuleNameError::BadLength { len } => {
                write!(f, "rule name length {len} is outside 31..=64")
            }
        }
    }
}

impl std::error::Error for RuleNameError {}

/// Why a receipt's `prior_state` envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriorStateError {
    /// Not four `;`-separated fields in the expected order.
    Malformed,
    /// A version this build does not understand — including the pre-P1 `v1`
    /// form (`flowing;rule=...`), which is refused rather than imported.
    UnsupportedVersion { found: String },
    /// The receipt was written by a different actuator; driving it through this
    /// one would actuate the wrong subsystem.
    ForeignMechanism { found: String },
    /// The ownership token is not one this build knows.
    BadOwnership { found: String },
    /// The rule name failed the grammar. **This is the SEC-1 stop.**
    BadRuleName(RuleNameError),
}

impl std::fmt::Display for PriorStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PriorStateError::Malformed => write!(
                f,
                "receipt prior_state is not a well-formed \
                 'v2;mech=<m>;own=<o>;rule=<name>' envelope"
            ),
            PriorStateError::UnsupportedVersion { found } => write!(
                f,
                "receipt prior_state version {found:?} is not supported by this build \
                 (pre-P1 receipts are deliberately not imported; use the receipt-less \
                 recovery path instead)"
            ),
            PriorStateError::ForeignMechanism { found } => write!(
                f,
                "receipt was written by mechanism {found:?}, not {MECH_TAG_NETSH:?}"
            ),
            PriorStateError::BadOwnership { found } => {
                write!(f, "unknown ownership token {found:?}")
            }
            PriorStateError::BadRuleName(e) => write!(f, "receipt names an unacceptable rule: {e}"),
        }
    }
}

impl std::error::Error for PriorStateError {}

/// Top-level error surfaced by the pure orchestration functions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchError {
    /// The `netsh` process could not be spawned / waited on (I/O error text).
    Spawn(String),
    /// The `netsh` process ran but its result was an error.
    Netsh(NetshError),
    /// A receipt named a rule this enforcer refuses to touch.
    PriorState(PriorStateError),
    /// The action reported success but its post-condition did not hold.
    PostConditionUnmet {
        stage: &'static str,
        evidence: String,
    },
    /// The selected mechanism exists as a design decision but not yet as code.
    MechanismUnavailable { mechanism: &'static str },
    /// This build target has no privileged firewall backend (non-Windows).
    Unsupported,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KillSwitchError::Spawn(e) => write!(f, "failed to spawn netsh: {e}"),
            KillSwitchError::Netsh(e) => write!(f, "{e}"),
            KillSwitchError::PriorState(e) => write!(f, "{e}"),
            KillSwitchError::PostConditionUnmet { stage, evidence } => write!(
                f,
                "{stage}: the firewall rule is still present after the removal reported \
                 success — egress is still severed: {evidence}"
            ),
            KillSwitchError::MechanismUnavailable { mechanism } => write!(
                f,
                "egress mechanism {mechanism:?} is selected but not implemented in this build"
            ),
            KillSwitchError::Unsupported => {
                write!(
                    f,
                    "firewall enforcement requires Windows (this build has no netsh backend)"
                )
            }
        }
    }
}

impl std::error::Error for KillSwitchError {}

impl From<NetshError> for KillSwitchError {
    fn from(e: NetshError) -> Self {
        KillSwitchError::Netsh(e)
    }
}

impl From<PriorStateError> for KillSwitchError {
    fn from(e: PriorStateError) -> Self {
        KillSwitchError::PriorState(e)
    }
}

/// Who created the rule this engagement is responsible for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// Positively observed absent before the `add`, so this engagement created
    /// it — and release may delete it.
    ///
    /// The netsh actuator **never** produces this, because netsh has no
    /// trustworthy absence signal (see the module docs). It exists because the
    /// envelope grammar is mechanism-neutral: WFP (which knows exactly which
    /// filter keys it added) and the optional `Get-NetFirewallRule` cold path
    /// (which can distinguish "no match" from "query failed") can.
    Created,
    /// Positively observed **present** before the `add`. This engagement did
    /// not create it, so a faithful release must not delete it.
    Preexisting,
    /// The pre-probe could not answer. Release deletes the derived rule anyway:
    /// the name carries our own prefix and our own scope digest, so there is no
    /// other plausible owner, and leaving a machine severed is the worse
    /// outcome.
    Unknown,
}

impl Ownership {
    #[must_use]
    pub fn as_token(self) -> &'static str {
        match self {
            Ownership::Created => "created",
            Ownership::Preexisting => "preexisting",
            Ownership::Unknown => "unknown",
        }
    }

    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "created" => Some(Ownership::Created),
            "preexisting" => Some(Ownership::Preexisting),
            "unknown" => Some(Ownership::Unknown),
            _ => None,
        }
    }
}

/// Whether the enforcing action's post-condition was confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// The rule was positively observed present after the `add`.
    Confirmed,
    /// The `add` reported success but presence could not be confirmed. This is
    /// **not** a success and must never be reported as one — but the receipt
    /// that accompanies it is still releasable.
    Unconfirmed { evidence: String },
}

/// Outcome of a successful pure [`engage_with`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngageReceipt {
    /// The exact firewall rule name that was added (and that release deletes).
    pub rule_name: KillSwitchRuleName,
    /// What the pre-probe could establish about who owns the rule.
    pub ownership: Ownership,
    /// Whether the post-condition held.
    pub verification: Verification,
}

/// An engagement plus the evidence for (or against) it, for callers that want
/// both without matching on an error variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngageReport {
    /// Persist this **regardless of `verification`**. An enforcement that was
    /// applied and then lost its receipt is unreleasable.
    pub receipt: EnforcementReceipt,
    pub verification: Verification,
}

// ---------------------------------------------------------------------------
// Pure logic: the rule-name grammar (the damage bound)
// ---------------------------------------------------------------------------

/// Fixed prefix for every kill-switch rule this crate manages. The uniqueness
/// of this exact string is the correctness anchor: release deletes *only* rules
/// matching the derived name, so nothing else on the host is touched.
pub const RULE_PREFIX: &str = "SSK-KillSwitch-";

const DIGEST_LEN: usize = 16;
const LABEL_MAX: usize = 32;
const NAME_MIN: usize = RULE_PREFIX.len() + DIGEST_LEN; // 31
const NAME_MAX: usize = RULE_PREFIX.len() + LABEL_MAX + 1 + DIGEST_LEN; // 64

/// A firewall rule name this crate is willing to hand to the OS.
///
/// The grammar:
///
/// ```text
/// rule_name := "SSK-KillSwitch-" [ label "-" ] digest16
/// label     := [A-Za-z0-9]{1,32}
/// digest16  := [0-9a-f]{16}
/// ```
///
/// This type is the damage bound. [`KillSwitchRuleName::parse`] is the **only**
/// way to obtain one from untrusted bytes, and [`build_add_args`] /
/// [`build_delete_args`] / [`build_show_args`] are the only places a
/// `name=` argument is constructed — so there is no `&str` path from a receipt
/// into a netsh argument list. That is what makes the difference between "a
/// forged receipt deletes one of our own rules" and "a forged receipt runs
/// `delete rule name=all` and disables the host firewall".
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KillSwitchRuleName(String);

impl KillSwitchRuleName {
    /// Derive the canonical name for a scope. Infallible by construction: the
    /// digest is normalized to exactly 16 lowercase hex characters (right-padded
    /// with `0` in the degenerate case of a short input) and the label to at
    /// most 32 ASCII alphanumerics, so the result always satisfies
    /// [`KillSwitchRuleName::parse`].
    ///
    /// In production the digest argument is a `Digest::to_hex()` — 64 hex
    /// characters — so the padding branch is unreachable there; it exists so
    /// this constructor has no failure mode at all.
    #[must_use]
    pub fn derive(scope_label: &str, scope_digest_hex: &str) -> Self {
        let digest16 = normalize_digest16(scope_digest_hex);
        let label = sanitize_label(scope_label);
        let raw = if label.is_empty() {
            format!("{RULE_PREFIX}{digest16}")
        } else {
            format!("{RULE_PREFIX}{label}-{digest16}")
        };
        debug_assert!(
            Self::parse(&raw).is_ok(),
            "derive must always produce a name that parses: {raw:?}"
        );
        Self(raw)
    }

    /// Validate a candidate name from an untrusted source.
    ///
    /// # Errors
    /// [`RuleNameError`] if the candidate does not match the grammar exactly.
    pub fn parse(candidate: &str) -> Result<Self, RuleNameError> {
        if candidate.len() < NAME_MIN || candidate.len() > NAME_MAX {
            return Err(RuleNameError::BadLength {
                len: candidate.len(),
            });
        }
        let rest = candidate
            .strip_prefix(RULE_PREFIX)
            .ok_or(RuleNameError::MissingPrefix)?;
        // A label is ASCII-alphanumeric only, so at most one '-' can separate
        // label from digest, and it must be the LAST one. Splitting from the
        // right makes `SSK-KillSwitch-SSK-KillSwitch-0011223344556677` fail on
        // the label check rather than smuggle a second prefix through.
        let (label, digest) = match rest.rsplit_once('-') {
            Some((label, digest)) => (Some(label), digest),
            None => (None, rest),
        };
        if !is_digest16(digest) {
            return Err(RuleNameError::BadDigest);
        }
        if let Some(label) = label {
            if !is_label(label) {
                return Err(RuleNameError::BadLabel);
            }
        }
        Ok(Self(candidate.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for KillSwitchRuleName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn is_digest16(segment: &str) -> bool {
    segment.len() == DIGEST_LEN
        && segment
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_label(segment: &str) -> bool {
    (1..=LABEL_MAX).contains(&segment.len()) && segment.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn normalize_digest16(digest_hex: &str) -> String {
    let mut out: String = digest_hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .take(DIGEST_LEN)
        .collect();
    while out.len() < DIGEST_LEN {
        out.push('0');
    }
    out
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(LABEL_MAX)
        .collect()
}

/// The canonical rule name for a scope — the same pure function `engage` uses.
///
/// This is what makes receipt-less recovery sound: the rule is *identified* by
/// the scope, never by anything a receipt claims.
///
/// # Errors
/// [`BoundaryError::Enforcement`] if the scope cannot be digested.
pub fn rule_name_for_scope(scope: &BoundaryScope) -> Result<KillSwitchRuleName, BoundaryError> {
    let digest = digest_of(scope, HashAlg::Blake3)
        .map_err(|e| BoundaryError::Enforcement(format!("scope digest failed: {e}")))?;
    Ok(KillSwitchRuleName::derive(&scope.label, &digest.to_hex()))
}

// ---------------------------------------------------------------------------
// Pure logic: netsh argument construction
// ---------------------------------------------------------------------------

/// Args to ADD the outbound block rule: all programs (no `program=` filter),
/// all addresses, all profiles, direction out.
#[must_use]
pub fn build_add_args(rule_name: &KillSwitchRuleName) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={rule_name}"),
        "dir=out".into(),
        "action=block".into(),
        "enable=yes".into(),
        "profile=any".into(),
        "localip=any".into(),
        "remoteip=any".into(),
    ]
}

/// Args to DELETE exactly the rule(s) with this name. Matching solely on `name=`
/// is what guarantees we remove only what we added.
#[must_use]
pub fn build_delete_args(rule_name: &KillSwitchRuleName) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ]
}

/// Args to SHOW the rule with this name (the presence probe).
#[must_use]
pub fn build_show_args(rule_name: &KillSwitchRuleName) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "show".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ]
}

// ---------------------------------------------------------------------------
// Pure logic: classification (exit code only, positive direction only)
// ---------------------------------------------------------------------------

/// Classify a SHOW result into a three-valued [`Presence`].
///
/// `exit 0` is the only trustworthy signal, and it is trustworthy in one
/// direction: on the measured host no failure mode produced 0, and only real
/// rules did. Every other exit is [`Presence::Indeterminate`] — this function
/// **never returns [`Presence::Absent`]**, because netsh cannot distinguish
/// "no such rule" from "bad argument" from "service unreachable" from
/// (presumed) "access denied".
#[must_use]
pub fn classify_show(inv: &RawInvocation) -> Presence {
    if inv.is_success_exit() {
        Presence::Present
    } else {
        Presence::Indeterminate {
            detail: format!(
                "netsh show exited {:?}; the exit code does not distinguish absent from \
                 failed: {}",
                inv.exit_code,
                inv.evidence()
            ),
        }
    }
}

/// Classify an ADD result. Exit 0 is success; anything else is a hard failure.
///
/// There is no output-token check: `Ok.` is printed by unrelated netsh verbs
/// too (`show`, `show currentprofile`, `show allprofiles state`), so it
/// discriminates nothing — and reading it at all would reintroduce the locale
/// dependency this module exists to remove.
///
/// # Errors
/// [`NetshError::NonZeroExit`].
pub fn parse_add_output(inv: &RawInvocation) -> Result<(), NetshError> {
    if inv.is_success_exit() {
        Ok(())
    } else {
        Err(NetshError::NonZeroExit {
            code: inv.exit_code,
            evidence: inv.evidence(),
        })
    }
}

// ---------------------------------------------------------------------------
// Pure logic: the receipt `prior_state` envelope
// ---------------------------------------------------------------------------

/// Envelope version this build writes and is willing to read.
pub const PRIOR_STATE_VERSION: &str = "v2";

/// The decoded, **validated** contents of a receipt's `prior_state`.
///
/// Reaching this type means the mechanism tag matched, the ownership token was
/// known, and the rule name passed the grammar. Nothing downstream re-parses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorState {
    pub ownership: Ownership,
    pub rule_name: KillSwitchRuleName,
}

impl PriorState {
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{PRIOR_STATE_VERSION};mech={MECH_TAG_NETSH};own={};rule={}",
            self.ownership.as_token(),
            self.rule_name
        )
    }

    /// Decode a `prior_state` written by [`PriorState::encode`].
    ///
    /// Strict by design: exactly four `;`-separated fields, in order, with the
    /// exact expected keys. Strictness is what closes the pre-P1 `split_once`
    /// hole in which `"flowing;rule=SSK-KillSwitch-x;rule=evil"` yielded the
    /// rule name `SSK-KillSwitch-x;rule=evil`.
    ///
    /// # Errors
    /// [`PriorStateError`] for every rejection reason, so a caller can tell a
    /// stale receipt from a foreign mechanism from an unacceptable rule name.
    pub fn parse(prior_state: &str) -> Result<Self, PriorStateError> {
        let mut fields = prior_state.split(';');
        let version = fields.next().ok_or(PriorStateError::Malformed)?;
        let mech = fields.next().ok_or(PriorStateError::Malformed)?;
        let own = fields.next().ok_or(PriorStateError::Malformed)?;
        let rule = fields.next().ok_or(PriorStateError::Malformed)?;
        if fields.next().is_some() {
            return Err(PriorStateError::Malformed);
        }
        if version != PRIOR_STATE_VERSION {
            return Err(PriorStateError::UnsupportedVersion {
                found: version.to_owned(),
            });
        }
        let mech = mech
            .strip_prefix("mech=")
            .ok_or(PriorStateError::Malformed)?;
        let own = own.strip_prefix("own=").ok_or(PriorStateError::Malformed)?;
        let rule = rule
            .strip_prefix("rule=")
            .ok_or(PriorStateError::Malformed)?;
        if mech != MECH_TAG_NETSH {
            return Err(PriorStateError::ForeignMechanism {
                found: mech.to_owned(),
            });
        }
        let ownership =
            Ownership::from_token(own).ok_or_else(|| PriorStateError::BadOwnership {
                found: own.to_owned(),
            })?;
        let rule_name = KillSwitchRuleName::parse(rule).map_err(PriorStateError::BadRuleName)?;
        Ok(PriorState {
            ownership,
            rule_name,
        })
    }
}

/// Read only the mechanism tag out of an envelope, so a dispatcher can route a
/// receipt to the actuator that wrote it without first committing to netsh.
///
/// # Errors
/// [`PriorStateError::Malformed`] / [`PriorStateError::UnsupportedVersion`].
pub fn prior_state_mechanism(prior_state: &str) -> Result<String, PriorStateError> {
    let mut fields = prior_state.split(';');
    let version = fields.next().ok_or(PriorStateError::Malformed)?;
    if version != PRIOR_STATE_VERSION {
        return Err(PriorStateError::UnsupportedVersion {
            found: version.to_owned(),
        });
    }
    let mech = fields
        .next()
        .and_then(|f| f.strip_prefix("mech="))
        .ok_or(PriorStateError::Malformed)?;
    Ok(mech.to_owned())
}

/// Encode the engage outcome into the `prior_state` string the boundary layer
/// stores in its [`EnforcementReceipt`] and hands back verbatim on release.
#[must_use]
pub fn encode_prior_state(receipt: &EngageReceipt) -> String {
    PriorState {
        ownership: receipt.ownership,
        rule_name: receipt.rule_name.clone(),
    }
    .encode()
}

// ---------------------------------------------------------------------------
// Pure orchestration over an injected runner (testable off-Windows)
// ---------------------------------------------------------------------------

/// A runner turns a netsh arg list into a [`RawInvocation`] or a spawn error.
/// The Windows layer supplies a real [`std::process::Command`] runner; tests
/// supply a scripted one.
pub trait NetshRunner {
    fn run(&self, args: &[String]) -> Result<RawInvocation, KillSwitchError>;
}

impl<F> NetshRunner for F
where
    F: Fn(&[String]) -> Result<RawInvocation, KillSwitchError>,
{
    fn run(&self, args: &[String]) -> Result<RawInvocation, KillSwitchError> {
        self(args)
    }
}

/// Observe whether the scope's rule is present, without mutating anything.
///
/// Requires no elevation (measured: `netsh advfirewall firewall show rule`
/// returns a full dump unelevated). This is the probe the receipt-less
/// recovery path reconciles against.
#[must_use]
pub fn observe_with<R: NetshRunner>(
    scope_label: &str,
    scope_digest_hex: &str,
    runner: &R,
) -> BoundaryObservation {
    let name = KillSwitchRuleName::derive(scope_label, scope_digest_hex);
    match runner.run(&build_show_args(&name)) {
        Ok(inv) => BoundaryObservation {
            presence: classify_show(&inv),
            mechanism: MECHANISM_NETSH,
            evidence: inv.evidence(),
        },
        Err(e) => BoundaryObservation {
            presence: Presence::Indeterminate {
                detail: e.to_string(),
            },
            mechanism: MECHANISM_NETSH,
            evidence: e.to_string(),
        },
    }
}

/// Engage: record what the pre-probe could establish, add the outbound block
/// rule, then **verify the post-condition**. All impurity is inside `runner`.
///
/// The pre-probe never gates the `add`: an unanswerable ownership question is
/// recorded as [`Ownership::Unknown`] and the protective action proceeds. The
/// shipped pre-P1 behaviour — abort when the probe could not be classified —
/// was fail-*open*: it left egress flowing on every non-English Windows install
/// while reporting an elevation problem that did not exist.
///
/// Returns `Ok` with [`Verification::Unconfirmed`] when the `add` succeeded but
/// presence could not be confirmed: the caller must not report success, but it
/// **must** persist the receipt, or the rule becomes unreleasable.
///
/// # Errors
/// [`KillSwitchError::Spawn`] or [`KillSwitchError::Netsh`] — only from the
/// `add` itself, the one step that must not fail silently.
pub fn engage_with<R: NetshRunner>(
    scope_label: &str,
    scope_digest_hex: &str,
    runner: &R,
) -> Result<EngageReceipt, KillSwitchError> {
    let name = KillSwitchRuleName::derive(scope_label, scope_digest_hex);

    // Pre-probe: answers a ROLLBACK-OWNERSHIP question only. It has nothing to
    // say about whether egress should be severed, so it must never abort.
    let ownership = match runner.run(&build_show_args(&name)) {
        Ok(inv) if classify_show(&inv).is_present() => Ownership::Preexisting,
        _ => Ownership::Unknown,
    };

    // The protective action. If this did not run, there is nothing to claim.
    let add = runner.run(&build_add_args(&name))?;
    parse_add_output(&add)?;

    // The post-condition. This is where fail-closed belongs: it gates the
    // CLAIM, not the ACT.
    let verification = match runner.run(&build_show_args(&name)) {
        Ok(inv) => match classify_show(&inv) {
            Presence::Present => Verification::Confirmed,
            other => Verification::Unconfirmed {
                evidence: format!("post-add probe: {other:?}"),
            },
        },
        Err(e) => Verification::Unconfirmed {
            evidence: format!("post-add probe could not run: {e}"),
        },
    };

    Ok(EngageReceipt {
        rule_name: name,
        ownership,
        verification,
    })
}

/// Release: remove the rule this engagement is responsible for, then verify the
/// post-condition.
///
/// The delete's own exit code is **not** the criterion — exit 1 conflates
/// "nothing matched" with "denied". The criterion is that the rule is
/// afterwards *not* [`Presence::Present`]. Under netsh an absent rule reads as
/// [`Presence::Indeterminate`], so "not present" is the strongest true
/// statement available; a *positively present* rule after a delete is a hard
/// failure, because the machine is still severed and saying otherwise would be
/// a false claim on a security control.
///
/// # Errors
/// [`KillSwitchError::Spawn`] if netsh cannot be run, or
/// [`KillSwitchError::PostConditionUnmet`] if the rule survived.
pub fn release_with<R: NetshRunner>(
    prior: &PriorState,
    runner: &R,
) -> Result<ReleaseOutcome, KillSwitchError> {
    if prior.ownership == Ownership::Preexisting {
        // "Undo only what you created". Nothing is deleted, and the typed
        // outcome says so — the pre-P1 code returned a bare Ok(()) here and the
        // CLI printed "egress restored (rule deleted)" over it.
        return Ok(ReleaseOutcome::SkippedPreexisting);
    }

    let del = runner.run(&build_delete_args(&prior.rule_name))?;
    let delete_reported_success = del.is_success_exit();

    let post = runner.run(&build_show_args(&prior.rule_name))?;
    if classify_show(&post).is_present() {
        return Err(KillSwitchError::PostConditionUnmet {
            stage: "release",
            evidence: format!(
                "delete exited {:?} ({}); post-delete probe still reports the rule present ({})",
                del.exit_code,
                del.evidence(),
                post.evidence()
            ),
        });
    }

    Ok(if delete_reported_success {
        ReleaseOutcome::Reverted
    } else {
        ReleaseOutcome::AlreadyAbsent
    })
}

/// Receipt-less recovery: remove the rule *derived from the scope*, with no
/// receipt involved at all.
///
/// Immune to SEC-1 by construction — the name is computed, never read from any
/// file — which makes this the safest of the three verbs. It cannot know
/// whether the rule pre-existed; the deliberate call is to remove it, because a
/// stranded severed machine is the worse outcome and the name carries our own
/// prefix and our own scope digest.
///
/// # Errors
/// As [`release_with`].
pub fn recover_with<R: NetshRunner>(
    scope_label: &str,
    scope_digest_hex: &str,
    runner: &R,
) -> Result<ReleaseOutcome, KillSwitchError> {
    let prior = PriorState {
        ownership: Ownership::Unknown,
        rule_name: KillSwitchRuleName::derive(scope_label, scope_digest_hex),
    };
    release_with(&prior, runner)
}

// ---------------------------------------------------------------------------
// Thin Windows syscall layer: the ONLY code that spawns netsh.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::{KillSwitchError, NetshRunner, RawInvocation};
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::process::Command;

    /// Resolve `netsh.exe` by absolute path rather than through `PATH`.
    ///
    /// `Command::new("netsh")` searches `PATH`, and this process is elevated by
    /// requirement — a `PATH` entry an attacker controls would then be a direct
    /// elevated-code-execution path that every other control in this module
    /// sits behind. `%SystemRoot%` is inherited from the elevated launcher
    /// rather than searched, and if neither candidate exists we fail rather
    /// than fall back to a search.
    fn netsh_path() -> Result<OsString, KillSwitchError> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(root) = std::env::var_os("SystemRoot") {
            let mut p = PathBuf::from(root);
            p.push("System32");
            p.push("netsh.exe");
            candidates.push(p);
        }
        candidates.push(PathBuf::from(r"C:\Windows\System32\netsh.exe"));
        for candidate in candidates {
            if candidate.is_file() {
                return Ok(candidate.into_os_string());
            }
        }
        Err(KillSwitchError::Spawn(
            "netsh.exe not found under %SystemRoot%\\System32 (refusing to resolve it via PATH)"
                .to_owned(),
        ))
    }

    /// Real runner: spawn `netsh <args>` and capture its output as BYTES.
    pub struct SystemNetsh;

    impl NetshRunner for SystemNetsh {
        fn run(&self, args: &[String]) -> Result<RawInvocation, KillSwitchError> {
            let output = Command::new(netsh_path()?)
                .args(args)
                .output()
                .map_err(|e| KillSwitchError::Spawn(e.to_string()))?;
            // No decoding here: the bytes are carried verbatim and only ever
            // rendered for a human. See RawInvocation::evidence.
            Ok(RawInvocation {
                exit_code: output.status.code(),
                stdout: output.stdout,
                stderr: output.stderr,
            })
        }
    }
}

/// Engage on the current platform. Real netsh on Windows; `Unsupported` else.
fn platform_engage(
    scope_label: &str,
    scope_digest_hex: &str,
) -> Result<EngageReceipt, KillSwitchError> {
    #[cfg(windows)]
    {
        engage_with(scope_label, scope_digest_hex, &imp::SystemNetsh)
    }
    #[cfg(not(windows))]
    {
        let _ = (scope_label, scope_digest_hex);
        Err(KillSwitchError::Unsupported)
    }
}

/// Release on the current platform. Real netsh on Windows; `Unsupported` else.
fn platform_release(prior: &PriorState) -> Result<ReleaseOutcome, KillSwitchError> {
    // A skipped release touches nothing, so it is answerable on every platform.
    if prior.ownership == Ownership::Preexisting {
        return Ok(ReleaseOutcome::SkippedPreexisting);
    }
    #[cfg(windows)]
    {
        release_with(prior, &imp::SystemNetsh)
    }
    #[cfg(not(windows))]
    {
        Err(KillSwitchError::Unsupported)
    }
}

/// Observe on the current platform.
fn platform_observe(scope_label: &str, scope_digest_hex: &str) -> BoundaryObservation {
    #[cfg(windows)]
    {
        observe_with(scope_label, scope_digest_hex, &imp::SystemNetsh)
    }
    #[cfg(not(windows))]
    {
        let _ = (scope_label, scope_digest_hex);
        BoundaryObservation {
            presence: Presence::Indeterminate {
                detail: KillSwitchError::Unsupported.to_string(),
            },
            mechanism: MECHANISM_NETSH,
            evidence: "no Windows firewall backend in this build".to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// The real BoundaryEnforcer
// ---------------------------------------------------------------------------

/// A real [`BoundaryEnforcer`] backed by the host's egress mechanism.
///
/// `engage` severs all outbound egress for the scope by adding a
/// deterministically named block rule; `release` removes exactly that rule. The
/// rule name is derived from the scope's content digest, so it is stable,
/// unique per scope, and human-identifiable. All actions are logged at `warn`
/// (a kill-switch transition is security-critical in either direction).
///
/// ## Rollback ownership
///
/// The rule name is scope-scoped, not session-scoped (the
/// [`BoundaryEnforcer::engage`] contract only receives the scope), so two
/// sessions severing the same scope share one rule name. `engage` records what
/// it could establish about ownership and `release` honours it: a rule
/// *positively observed present* before the `add`
/// ([`Ownership::Preexisting`]) is left in place, reported as
/// [`ReleaseOutcome::SkippedPreexisting`] rather than as a deletion. When the
/// pre-probe could not answer ([`Ownership::Unknown`]) the rule is removed —
/// leaving a machine severed because an *observation* failed is the worse
/// outcome, and the name carries our own prefix and our own scope digest.
/// Full cross-session reference counting is a higher-tier concern (roadmap P3 /
/// WFP).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WindowsEgressEnforcer {
    mechanism: EgressMechanism,
}

/// Name the rest of the tree already uses. Kept so the WFP migration is a
/// change of [`EgressMechanism`], not a change of every call site.
pub type WindowsFirewallEnforcer = WindowsEgressEnforcer;

impl WindowsEgressEnforcer {
    #[must_use]
    pub fn new() -> Self {
        Self::detect()
    }

    /// The ONE place the mechanism is chosen.
    ///
    /// Today this always returns [`EgressMechanism::NetshInterim`]: the WFP
    /// backend is designed but not implemented, and reporting otherwise would
    /// be exactly the kind of claim this crate exists not to make.
    #[must_use]
    pub fn detect() -> Self {
        Self {
            mechanism: EgressMechanism::NetshInterim,
        }
    }

    #[must_use]
    pub fn with_mechanism(mechanism: EgressMechanism) -> Self {
        Self { mechanism }
    }

    #[must_use]
    pub fn mechanism(&self) -> EgressMechanism {
        self.mechanism
    }

    fn require_netsh(&self) -> Result<(), BoundaryError> {
        match self.mechanism {
            EgressMechanism::NetshInterim => Ok(()),
            EgressMechanism::WfpSessionFilter => Err(BoundaryError::Enforcement(
                KillSwitchError::MechanismUnavailable {
                    mechanism: MECHANISM_WFP,
                }
                .to_string(),
            )),
        }
    }

    /// Engage and hand back both the receipt and the evidence.
    ///
    /// Prefer this over [`BoundaryEnforcer::engage`] when the caller persists
    /// receipts: the receipt is returned on the success path *and* the
    /// unverified path, so persistence can be unconditional.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] if the `add` itself failed.
    pub fn engage_report(&self, scope: &BoundaryScope) -> Result<EngageReport, BoundaryError> {
        self.require_netsh()?;
        let digest = digest_of(scope, HashAlg::Blake3)
            .map_err(|e| BoundaryError::Enforcement(format!("scope digest failed: {e}")))?;
        let outcome = platform_engage(&scope.label, &digest.to_hex())
            .map_err(|e| BoundaryError::Enforcement(e.to_string()))?;

        tracing::warn!(
            target: "ssk.winhost.firewall",
            event = "kill_switch_engaged",
            mechanism = self.mechanism.as_str(),
            rule = %outcome.rule_name,
            ownership = outcome.ownership.as_token(),
            verified = matches!(outcome.verification, Verification::Confirmed),
            scope = %scope.label,
        );

        let receipt = EnforcementReceipt::new(scope, encode_prior_state(&outcome));
        Ok(EngageReport {
            receipt,
            verification: outcome.verification,
        })
    }

    /// Release, reporting what actually happened.
    ///
    /// When `expected_scope` is supplied, the rule name carried by the receipt
    /// must equal the name **re-derived from that scope**. That reduces the
    /// blast radius of a forged receipt from "any rule matching our grammar" to
    /// "exactly the one rule this scope maps to", and makes the receipt's rule
    /// name contribute nothing to the privileged action.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] for a rejected receipt, a scope mismatch,
    /// or a failed removal.
    pub fn release_reporting(
        &self,
        expected_scope: Option<&BoundaryScope>,
        receipt: &EnforcementReceipt,
    ) -> Result<ReleaseOutcome, BoundaryError> {
        self.require_netsh()?;
        let prior = PriorState::parse(&receipt.prior_state).map_err(|e| {
            BoundaryError::Enforcement(format!("refusing to act on this receipt: {e}"))
        })?;

        if let Some(scope) = expected_scope {
            let expected = rule_name_for_scope(scope)?;
            if expected != prior.rule_name {
                return Err(BoundaryError::Enforcement(format!(
                    "receipt names rule {} but scope {:?} derives {}; refusing to release",
                    prior.rule_name, scope.label, expected
                )));
            }
        }

        let outcome =
            platform_release(&prior).map_err(|e| BoundaryError::Enforcement(e.to_string()))?;

        tracing::warn!(
            target: "ssk.winhost.firewall",
            event = "kill_switch_release",
            mechanism = self.mechanism.as_str(),
            rule = %prior.rule_name,
            ownership = prior.ownership.as_token(),
            outcome = outcome.as_str(),
        );

        Ok(outcome)
    }

    /// Receipt-less recovery for a scope whose receipt was lost.
    ///
    /// # Errors
    /// [`BoundaryError::Enforcement`] if the removal or its post-condition
    /// failed.
    pub fn recover(&self, scope: &BoundaryScope) -> Result<ReleaseOutcome, BoundaryError> {
        self.require_netsh()?;
        let prior = PriorState {
            ownership: Ownership::Unknown,
            rule_name: rule_name_for_scope(scope)?,
        };
        let outcome =
            platform_release(&prior).map_err(|e| BoundaryError::Enforcement(e.to_string()))?;
        tracing::warn!(
            target: "ssk.winhost.firewall",
            event = "kill_switch_recovered",
            mechanism = self.mechanism.as_str(),
            rule = %prior.rule_name,
            outcome = outcome.as_str(),
            reason = "receipt-less; reconciled against the derived rule name",
        );
        Ok(outcome)
    }
}

impl BoundaryProbe for WindowsEgressEnforcer {
    fn observe(&self, scope: &BoundaryScope) -> BoundaryObservation {
        if self.mechanism != EgressMechanism::NetshInterim {
            return BoundaryObservation {
                presence: Presence::Indeterminate {
                    detail: KillSwitchError::MechanismUnavailable {
                        mechanism: self.mechanism.as_str(),
                    }
                    .to_string(),
                },
                mechanism: self.mechanism.as_str(),
                evidence: "mechanism not implemented".to_owned(),
            };
        }
        match digest_of(scope, HashAlg::Blake3) {
            Ok(digest) => platform_observe(&scope.label, &digest.to_hex()),
            Err(e) => BoundaryObservation {
                presence: Presence::Indeterminate {
                    detail: format!("scope digest failed: {e}"),
                },
                mechanism: MECHANISM_NETSH,
                evidence: e.to_string(),
            },
        }
    }
}

impl BoundaryEnforcer for WindowsEgressEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        let report = self.engage_report(scope)?;
        match report.verification {
            Verification::Confirmed => Ok(report.receipt),
            // Applied, but unconfirmable. Not Ok — and not receipt-less either.
            Verification::Unconfirmed { evidence } => Err(BoundaryError::EnforcementUnverified {
                receipt: Box::new(report.receipt),
                detail: evidence,
            }),
        }
    }

    fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        self.release_reporting(None, receipt).map(|_| ())
    }

    fn release_scoped(
        &self,
        scope: &BoundaryScope,
        receipt: &EnforcementReceipt,
    ) -> Result<ReleaseOutcome, BoundaryError> {
        self.release_reporting(Some(scope), receipt)
    }
}

// ---------------------------------------------------------------------------
// Tests (pure — run on any host)
//
// SAFETY NOTE FOR FUTURE EDITORS: no test in this module may reach
// `platform_engage` / `platform_release` on a Windows host, because those spawn
// a real `netsh add`/`delete` and would mutate the machine's firewall. Every
// test that reaches the platform layer is `#[cfg(not(windows))]`; everything
// else drives the pure functions through `ScriptedRunner`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const D64: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

    // ---- rule-name grammar: the damage bound ------------------------------

    #[test]
    fn derive_matches_canonical_shape_when_no_label() {
        let name = KillSwitchRuleName::derive("", D64);
        assert_eq!(name.as_str(), "SSK-KillSwitch-a1b2c3d4e5f60718");
        assert!(name.as_str().starts_with(RULE_PREFIX));
    }

    #[test]
    fn derive_is_deterministic() {
        let d = "DEADBEEFdeadbeef0000";
        assert_eq!(
            KillSwitchRuleName::derive("scope", d),
            KillSwitchRuleName::derive("scope", d)
        );
    }

    #[test]
    fn derive_lowercases_and_truncates_digest() {
        assert_eq!(
            KillSwitchRuleName::derive("", "ABCDEF0123456789ABCDEF").as_str(),
            "SSK-KillSwitch-abcdef0123456789"
        );
    }

    #[test]
    fn derive_embeds_sanitized_label() {
        assert_eq!(
            KillSwitchRuleName::derive("Tenant 7/prod", "0011223344556677").as_str(),
            "SSK-KillSwitch-Tenant7prod-0011223344556677"
        );
    }

    #[test]
    fn derive_distinct_scopes_distinct_names() {
        assert_ne!(
            KillSwitchRuleName::derive("x", "1111111111111111"),
            KillSwitchRuleName::derive("x", "2222222222222222")
        );
    }

    // The validator must never reject a name the deriver produces, or a
    // legitimate release becomes impossible.
    #[test]
    fn parse_accepts_everything_derive_produces() {
        let labels = [
            "",
            "x",
            "prod",
            "Tenant 7/prod",
            "\u{fc}mlaut",                              // non-ASCII is filtered out
            "0123456789012345678901234567890123456789", // >32, truncated
            "!!!",                                      // sanitizes to empty
            "all",
        ];
        let digests = [
            D64,
            "0011223344556677",
            "ABCDEF0123456789",
            "",   // degenerate: padded
            "zz", // no hex at all: padded
            "a",
        ];
        for label in labels {
            for digest in digests {
                let derived = KillSwitchRuleName::derive(label, digest);
                assert_eq!(
                    KillSwitchRuleName::parse(derived.as_str()).as_ref(),
                    Ok(&derived),
                    "derive({label:?}, {digest:?}) produced an unparseable name"
                );
            }
        }
    }

    #[test]
    fn parse_rejects_adversarial_names() {
        // (candidate, why it must be refused)
        let cases: &[(&str, &str)] = &[
            ("all", "netsh would expand name=all to EVERY rule"),
            ("", "empty"),
            ("SSK-KillSwitch-", "prefix only"),
            ("SSK-KillSwitch", "prefix without trailing dash"),
            ("SSK-KillSwitch-ABCDEF0123456789", "uppercase digest"),
            ("SSK-KillSwitch-001122334455667", "15-hex digest"),
            ("SSK-KillSwitch-00112233445566778", "17-hex digest"),
            ("SSK-KillSwitch-001122334455667g", "non-hex digest"),
            ("SSK-KillSwitch--0011223344556677", "empty label"),
            (
                "SSK-KillSwitch-a-b-0011223344556677",
                "two label separators",
            ),
            (
                "SSK-KillSwitch-x;rule=evil-0011223344556677",
                "envelope injection inside the label",
            ),
            (
                "SSK-KillSwitch-x 0011223344556677",
                "space smuggles a second netsh token",
            ),
            (
                "SSK-KillSwitch-0011223344556677 extra",
                "trailing junk after a valid name",
            ),
            (
                "SSK-KillSwitch-x\"-0011223344556677",
                "double quote in label",
            ),
            ("SSK-KillSwitch-x\n-0011223344556677", "embedded newline"),
            ("SSK-KillSwitch-x\r\n0011223344556677", "embedded CRLF"),
            ("SSK-KillSwitch-x\0-0011223344556677", "embedded NUL"),
            (
                "SSK-KillSwitch-..\\..\\evil-0011223344556677",
                "path traversal shape",
            ),
            ("SSK-KillSwitch-a/b-0011223344556677", "forward slash"),
            ("SSK-KillSwitch-*-0011223344556677", "wildcard"),
            ("SSK-KillSwitch-?-0011223344556677", "single-char wildcard"),
            ("SSK-KillSwitch-a=b-0011223344556677", "equals sign"),
            (
                "evil-SSK-KillSwitch-0011223344556677",
                "merely CONTAINS the prefix",
            ),
            (
                "SSK-KillSwitch-SSK-KillSwitch-0011223344556677",
                "prefix repeated as a label",
            ),
            (
                "ssk-killswitch-0011223344556677",
                "prefix differs only in case",
            ),
            (
                "SSK\u{2010}KillSwitch-0011223344556677",
                "unicode hyphen lookalike U+2010",
            ),
            (
                "SSK-KillSwitch-\u{0430}bc-0011223344556677",
                "cyrillic 'a' lookalike in the label",
            ),
            (
                "SSK-KillSwitch-\u{ff41}bc-0011223344556677",
                "fullwidth latin 'a' in the label",
            ),
            (
                "SSK-KillSwitch-0011223344556677\u{200b}",
                "zero-width space suffix",
            ),
            (
                "SSK-KillSwitch-000000000000000000000000000000000-0011223344556677",
                "33-char label",
            ),
        ];
        for (candidate, why) in cases {
            assert!(
                KillSwitchRuleName::parse(candidate).is_err(),
                "must reject {candidate:?} ({why})"
            );
        }
    }

    #[test]
    fn parse_accepts_the_boundary_lengths() {
        let min = format!("{RULE_PREFIX}0011223344556677");
        assert_eq!(min.len(), NAME_MIN);
        assert!(KillSwitchRuleName::parse(&min).is_ok());

        let max = format!("{RULE_PREFIX}{}-0011223344556677", "a".repeat(LABEL_MAX));
        assert_eq!(max.len(), NAME_MAX);
        assert!(KillSwitchRuleName::parse(&max).is_ok());

        let too_long = format!(
            "{RULE_PREFIX}{}-0011223344556677",
            "a".repeat(LABEL_MAX + 1)
        );
        assert_eq!(
            KillSwitchRuleName::parse(&too_long),
            Err(RuleNameError::BadLength {
                len: too_long.len()
            })
        );
    }

    #[test]
    fn parse_reports_a_useful_reason() {
        assert_eq!(
            KillSwitchRuleName::parse("NOT-OURS-0011223344556677xxxxxxx"),
            Err(RuleNameError::MissingPrefix)
        );
        assert_eq!(
            KillSwitchRuleName::parse("SSK-KillSwitch-x-00112233445566zz"),
            Err(RuleNameError::BadDigest)
        );
        assert_eq!(
            KillSwitchRuleName::parse("SSK-KillSwitch-x_y-0011223344556677"),
            Err(RuleNameError::BadLabel)
        );
    }

    // ---- argument construction ---------------------------------------------

    fn n(s: &str) -> KillSwitchRuleName {
        KillSwitchRuleName::parse(s).expect("test rule name must be valid")
    }

    const TEST_NAME: &str = "SSK-KillSwitch-abc-0011223344556677";

    #[test]
    fn add_args_are_outbound_block_all() {
        let args = build_add_args(&n(TEST_NAME));
        assert_eq!(args[0], "advfirewall");
        assert!(args.contains(&"dir=out".to_string()));
        assert!(args.contains(&"action=block".to_string()));
        assert!(args.contains(&"remoteip=any".to_string()));
        assert!(args.contains(&format!("name={TEST_NAME}")));
        assert!(!args.iter().any(|a| a.starts_with("program=")));
    }

    #[test]
    fn delete_args_match_by_name_only() {
        let args = build_delete_args(&n(TEST_NAME));
        let expected: Vec<String> = vec![
            "advfirewall".into(),
            "firewall".into(),
            "delete".into(),
            "rule".into(),
            format!("name={TEST_NAME}"),
        ];
        assert_eq!(args, expected);
        assert!(args.iter().all(|a| !a.starts_with("dir=")));
    }

    // ---- classification is exit-code-only and locale-independent ------------

    // The de-DE bytes measured on the target host, verbatim (UTF-8: `ü` = c3 bc).
    const DE_NO_MATCH: &[u8] =
        b"\r\nKeine Regeln stimmen mit den angegebenen Kriterien \xc3\xbcberein.\r\n\r\n";
    // The same sentence as CP850 would encode it, to prove no branch cares.
    const DE_NO_MATCH_CP850: &[u8] =
        b"\r\nKeine Regeln stimmen mit den angegebenen Kriterien \x81berein.\r\n\r\n";
    const EN_NO_MATCH: &[u8] = b"\r\nNo rules match the specified criteria.\r\n\r\n";

    #[test]
    fn presence_is_positive_direction_only() {
        assert_eq!(
            classify_show(&RawInvocation::new(Some(0), "Regelname: X\r\nOK.\r\n", "")),
            Presence::Present
        );
        for absent in [DE_NO_MATCH, DE_NO_MATCH_CP850, EN_NO_MATCH] {
            let presence = classify_show(&RawInvocation::new(Some(1), absent.to_vec(), ""));
            assert!(
                matches!(presence, Presence::Indeterminate { .. }),
                "exit 1 must be Indeterminate regardless of the message: {presence:?}"
            );
            assert_eq!(presence.as_option_bool(), None);
        }
    }

    // The locale regression, stated as a test: the identical exit code must
    // produce the identical classification in every locale and encoding.
    #[test]
    fn classification_is_identical_across_locales_and_encodings() {
        let variants: [&[u8]; 5] = [
            DE_NO_MATCH,
            DE_NO_MATCH_CP850,
            EN_NO_MATCH,
            b"",
            b"\xff\xfe",
        ];
        let classified: Vec<bool> = variants
            .iter()
            .map(|bytes| {
                classify_show(&RawInvocation::new(Some(1), bytes.to_vec(), "")).is_present()
            })
            .collect();
        assert_eq!(classified, vec![false; variants.len()]);

        let present: Vec<bool> = variants
            .iter()
            .map(|bytes| {
                classify_show(&RawInvocation::new(Some(0), bytes.to_vec(), "")).is_present()
            })
            .collect();
        assert_eq!(present, vec![true; variants.len()]);
    }

    // Guard against a future edit reintroducing a text discriminator.
    #[test]
    fn no_english_or_german_token_influences_any_decision() {
        for code in [Some(0), Some(1), Some(87), None] {
            let with_ok = RawInvocation::new(code, "Ok.\r\n", "");
            let with_prose = RawInvocation::new(code, DE_NO_MATCH.to_vec(), "");
            let empty = RawInvocation::new(code, "", "");
            assert_eq!(
                classify_show(&with_ok).is_present(),
                classify_show(&empty).is_present()
            );
            assert_eq!(
                classify_show(&with_prose).is_present(),
                classify_show(&empty).is_present()
            );
            assert_eq!(parse_add_output(&with_ok).is_ok(), code == Some(0));
            assert_eq!(parse_add_output(&with_prose).is_ok(), code == Some(0));
            assert_eq!(parse_add_output(&empty).is_ok(), code == Some(0));
        }
    }

    #[test]
    fn add_is_exit_code_only() {
        assert_eq!(
            parse_add_output(&RawInvocation::new(Some(0), "", "")),
            Ok(())
        );
        // Pre-P1 this "Ok."-less zero exit was rejected as UnexpectedOutput.
        assert_eq!(
            parse_add_output(&RawInvocation::new(Some(0), "something weird\n", "")),
            Ok(())
        );
        match parse_add_output(&RawInvocation::new(Some(1), "", "requires elevation")) {
            Err(NetshError::NonZeroExit { code, .. }) => assert_eq!(code, Some(1)),
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
        assert!(parse_add_output(&RawInvocation::new(None, "", "")).is_err());
    }

    #[test]
    fn evidence_is_lossy_bounded_and_never_panics_on_invalid_utf8() {
        let inv = RawInvocation::new(Some(1), DE_NO_MATCH.to_vec(), b"\xff\xfe\x00".to_vec());
        let ev = inv.evidence();
        assert!(ev.contains("stdout="));
        assert!(ev.contains("stderr="));
        assert!(ev.contains("Keine Regeln"));

        let huge = RawInvocation::new(Some(1), vec![b'x'; 10_000], "");
        assert!(huge.evidence().len() < 600, "evidence must be bounded");
        assert!(huge.evidence().contains("..."));

        assert_eq!(
            RawInvocation::new(Some(0), "", "").evidence(),
            "<no output>"
        );
    }

    // ---- prior_state envelope ----------------------------------------------

    #[test]
    fn prior_state_round_trips() {
        for ownership in [
            Ownership::Created,
            Ownership::Preexisting,
            Ownership::Unknown,
        ] {
            let prior = PriorState {
                ownership,
                rule_name: n(TEST_NAME),
            };
            let encoded = prior.encode();
            assert!(encoded.starts_with("v2;mech=netsh;own="));
            assert_eq!(PriorState::parse(&encoded), Ok(prior));
            assert_eq!(prior_state_mechanism(&encoded).as_deref(), Ok("netsh"));
        }
    }

    #[test]
    fn encode_prior_state_matches_the_engage_outcome() {
        let receipt = EngageReceipt {
            rule_name: n(TEST_NAME),
            ownership: Ownership::Unknown,
            verification: Verification::Confirmed,
        };
        assert_eq!(
            encode_prior_state(&receipt),
            format!("v2;mech=netsh;own=unknown;rule={TEST_NAME}")
        );
    }

    // SEC-1: the laundering point. Every one of these reached
    // `build_delete_args` before P1.
    #[test]
    fn prior_state_rejects_forged_and_stale_envelopes() {
        let bad: &[(&str, &str)] = &[
            ("", "empty"),
            ("flowing", "pre-P1, no rule"),
            (
                "flowing;rule=SSK-KillSwitch-abc-0011223344556677",
                "pre-P1 v1 envelope is not imported",
            ),
            ("severed;rule=all", "pre-P1 v1 naming the catastrophic rule"),
            (
                "flowing;rule=SSK-KillSwitch-x-0011223344556677;rule=evil",
                "the split_once injection",
            ),
            ("v2;mech=netsh;own=unknown;rule=all", "name=all"),
            ("v1;mech=netsh;own=unknown;rule=", "empty rule"),
            (
                "v3;mech=netsh;own=unknown;rule=SSK-KillSwitch-abc-0011223344556677",
                "future version",
            ),
            (
                "v2;mech=netsh;own=bogus;rule=SSK-KillSwitch-abc-0011223344556677",
                "unknown ownership token",
            ),
            (
                "v2;own=unknown;mech=netsh;rule=SSK-KillSwitch-abc-0011223344556677",
                "fields out of order",
            ),
            (
                "v2;mech=netsh;own=unknown;rule=SSK-KillSwitch-abc-0011223344556677;x=1",
                "trailing field",
            ),
            (
                "v2;mech=netsh;rule=SSK-KillSwitch-abc-0011223344556677",
                "missing field",
            ),
            (
                "v2;mech=netsh;own=unknown;rule=Windows Firewall Remote Management",
                "a real built-in rule name",
            ),
        ];
        for (candidate, why) in bad {
            assert!(
                PriorState::parse(candidate).is_err(),
                "must reject {candidate:?} ({why})"
            );
        }
    }

    // A receipt written by a different actuator must not drive this one.
    #[test]
    fn a_foreign_mechanism_is_typed_not_guessed() {
        let wfp = "v2;mech=wfp;own=created;rule=SSK-KillSwitch-abc-0011223344556677";
        assert_eq!(
            PriorState::parse(wfp),
            Err(PriorStateError::ForeignMechanism {
                found: "wfp".to_owned()
            })
        );
        assert_eq!(prior_state_mechanism(wfp).as_deref(), Ok("wfp"));
    }

    #[test]
    fn a_rejected_rule_name_says_which_rule_was_broken() {
        assert_eq!(
            PriorState::parse("v2;mech=netsh;own=unknown;rule=all"),
            Err(PriorStateError::BadRuleName(RuleNameError::BadLength {
                len: 3
            }))
        );
    }

    // ---- orchestration with a scripted fake runner --------------------------

    struct ScriptedRunner {
        responses:
            std::cell::RefCell<std::collections::VecDeque<Result<RawInvocation, KillSwitchError>>>,
        seen: std::cell::RefCell<Vec<Vec<String>>>,
    }

    impl ScriptedRunner {
        fn new(responses: Vec<Result<RawInvocation, KillSwitchError>>) -> Self {
            Self {
                responses: std::cell::RefCell::new(responses.into_iter().collect()),
                seen: std::cell::RefCell::new(Vec::new()),
            }
        }
        fn verbs(&self) -> Vec<String> {
            self.seen.borrow().iter().map(|a| a[2].clone()).collect()
        }
    }

    impl NetshRunner for ScriptedRunner {
        fn run(&self, args: &[String]) -> Result<RawInvocation, KillSwitchError> {
            self.seen.borrow_mut().push(args.to_vec());
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("no scripted response left")
        }
    }

    fn absent() -> Result<RawInvocation, KillSwitchError> {
        Ok(RawInvocation::new(Some(1), DE_NO_MATCH.to_vec(), ""))
    }
    fn present() -> Result<RawInvocation, KillSwitchError> {
        Ok(RawInvocation::new(Some(0), "Regelname: X\r\nOK.\r\n", ""))
    }
    fn ok0() -> Result<RawInvocation, KillSwitchError> {
        Ok(RawInvocation::new(Some(0), "Ok.\r\n", ""))
    }

    // THE shipped bug: on a de-DE host the pre-probe could not be classified
    // and `engage` aborted BEFORE the add, leaving egress flowing while
    // reporting an elevation problem. It must now add, and confirm.
    #[test]
    fn engage_proceeds_when_the_pre_probe_is_unanswerable() {
        let runner = ScriptedRunner::new(vec![absent(), ok0(), present()]);
        let receipt = engage_with("prod", "00112233445566778899", &runner).unwrap();
        assert_eq!(
            receipt.rule_name.as_str(),
            "SSK-KillSwitch-prod-0011223344556677"
        );
        assert_eq!(receipt.ownership, Ownership::Unknown);
        assert_eq!(receipt.verification, Verification::Confirmed);
        assert_eq!(runner.verbs(), vec!["show", "add", "show"]);
    }

    // Even a pre-probe that cannot RUN must not suppress the protective action.
    #[test]
    fn engage_proceeds_when_the_pre_probe_cannot_even_spawn() {
        let runner = ScriptedRunner::new(vec![
            Err(KillSwitchError::Spawn("boom".into())),
            ok0(),
            present(),
        ]);
        let receipt = engage_with("", "aaaaaaaaaaaaaaaa", &runner).unwrap();
        assert_eq!(receipt.ownership, Ownership::Unknown);
        assert_eq!(receipt.verification, Verification::Confirmed);
        assert_eq!(runner.verbs(), vec!["show", "add", "show"]);
    }

    #[test]
    fn engage_records_preexisting_only_on_a_positive_observation() {
        let runner = ScriptedRunner::new(vec![present(), ok0(), present()]);
        let receipt = engage_with("", "aaaaaaaaaaaaaaaa", &runner).unwrap();
        assert_eq!(receipt.ownership, Ownership::Preexisting);
    }

    // The add is the protective action; if it fails there is nothing to claim.
    #[test]
    fn engage_propagates_add_failure() {
        let runner = ScriptedRunner::new(vec![
            absent(),
            Ok(RawInvocation::new(Some(1), "", "requires elevation")),
        ]);
        assert!(matches!(
            engage_with("", "aaaaaaaaaaaaaaaa", &runner).unwrap_err(),
            KillSwitchError::Netsh(NetshError::NonZeroExit { .. })
        ));
        assert_eq!(runner.verbs(), vec!["show", "add"]);
    }

    // Fail-closed where it belongs: the CLAIM, not the ACT.
    #[test]
    fn engage_without_a_confirmed_post_condition_is_unverified_not_ok() {
        for post in [absent(), Err(KillSwitchError::Spawn("gone".into()))] {
            let runner = ScriptedRunner::new(vec![absent(), ok0(), post]);
            let receipt = engage_with("", "aaaaaaaaaaaaaaaa", &runner).unwrap();
            assert!(
                matches!(receipt.verification, Verification::Unconfirmed { .. }),
                "an unconfirmed post-condition must not be reported as verified"
            );
            // ...and the receipt still names a releasable rule.
            assert_eq!(
                PriorState::parse(&encode_prior_state(&receipt))
                    .unwrap()
                    .rule_name,
                receipt.rule_name
            );
        }
    }

    // ---- release ------------------------------------------------------------

    #[test]
    fn release_deletes_exactly_the_named_rule_and_verifies_absence() {
        let runner = ScriptedRunner::new(vec![ok0(), absent()]);
        let prior = PriorState {
            ownership: Ownership::Unknown,
            rule_name: n(TEST_NAME),
        };
        assert_eq!(release_with(&prior, &runner), Ok(ReleaseOutcome::Reverted));
        let seen = runner.seen.borrow();
        assert_eq!(seen[0][2], "delete");
        assert_eq!(seen[0][4], format!("name={TEST_NAME}"));
        assert_eq!(seen[1][2], "show");
    }

    // "Deleted 0" is no longer an error: with a post-verify proving the rule is
    // not present, egress IS restored, whatever netsh's exit code said.
    #[test]
    fn release_of_an_already_absent_rule_succeeds() {
        let runner = ScriptedRunner::new(vec![absent(), absent()]);
        let prior = PriorState {
            ownership: Ownership::Unknown,
            rule_name: n(TEST_NAME),
        };
        assert_eq!(
            release_with(&prior, &runner),
            Ok(ReleaseOutcome::AlreadyAbsent)
        );
    }

    // The loud failure: still severed, so say so.
    #[test]
    fn release_that_leaves_the_rule_in_place_is_a_hard_failure() {
        let runner = ScriptedRunner::new(vec![ok0(), present()]);
        let prior = PriorState {
            ownership: Ownership::Unknown,
            rule_name: n(TEST_NAME),
        };
        assert!(matches!(
            release_with(&prior, &runner).unwrap_err(),
            KillSwitchError::PostConditionUnmet {
                stage: "release",
                ..
            }
        ));
    }

    // The silent-skip fix: nothing is deleted, and the OUTCOME says so, so a
    // caller cannot print "rule deleted" over it.
    #[test]
    fn release_of_a_preexisting_rule_reports_the_skip_and_touches_nothing() {
        let runner = ScriptedRunner::new(vec![]); // any call would panic
        let prior = PriorState {
            ownership: Ownership::Preexisting,
            rule_name: n(TEST_NAME),
        };
        assert_eq!(
            release_with(&prior, &runner),
            Ok(ReleaseOutcome::SkippedPreexisting)
        );
        assert!(runner.seen.borrow().is_empty());
        assert!(!ReleaseOutcome::SkippedPreexisting.enforcement_confirmed_gone());
    }

    #[test]
    fn recover_derives_the_rule_name_and_never_reads_a_receipt() {
        let runner = ScriptedRunner::new(vec![ok0(), absent()]);
        assert_eq!(
            recover_with("prod", "00112233445566778899", &runner),
            Ok(ReleaseOutcome::Reverted)
        );
        assert_eq!(
            runner.seen.borrow()[0][4],
            "name=SSK-KillSwitch-prod-0011223344556677"
        );
    }

    // ---- observation ---------------------------------------------------------

    #[test]
    fn observe_reports_present_absent_unknown_without_mutating() {
        let runner = ScriptedRunner::new(vec![present()]);
        let obs = observe_with("prod", D64, &runner);
        assert_eq!(obs.presence, Presence::Present);
        assert_eq!(obs.mechanism, MECHANISM_NETSH);
        assert_eq!(runner.verbs(), vec!["show"]);

        let runner = ScriptedRunner::new(vec![absent()]);
        let obs = observe_with("prod", D64, &runner);
        assert_eq!(obs.presence.as_option_bool(), None);

        let runner = ScriptedRunner::new(vec![Err(KillSwitchError::Spawn("no netsh".into()))]);
        let obs = observe_with("prod", D64, &runner);
        assert!(matches!(obs.presence, Presence::Indeterminate { .. }));
        assert!(obs.evidence.contains("no netsh"));
    }

    // ---- the enforcer --------------------------------------------------------

    #[test]
    fn the_default_mechanism_is_the_interim_one_and_says_so() {
        assert_eq!(
            WindowsEgressEnforcer::new().mechanism(),
            EgressMechanism::NetshInterim
        );
        assert_eq!(
            WindowsEgressEnforcer::detect().mechanism(),
            EgressMechanism::NetshInterim
        );
    }

    // Selecting an unimplemented mechanism must fail loudly rather than fall
    // back to netsh: a caller that asked for crash-safe enforcement would
    // otherwise believe it got one.
    #[test]
    fn an_unimplemented_mechanism_never_silently_falls_back() {
        let enforcer = WindowsEgressEnforcer::with_mechanism(EgressMechanism::WfpSessionFilter);
        let scope = BoundaryScope::all_egress();
        match enforcer.engage(&scope) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("not implemented")),
            other => panic!("expected a typed unavailability error, got {other:?}"),
        }
        let obs = enforcer.observe(&scope);
        assert!(matches!(obs.presence, Presence::Indeterminate { .. }));
        assert_eq!(obs.mechanism, MECHANISM_WFP);
    }

    // A forged receipt is refused BEFORE any platform call, on every platform —
    // this is what stops SEC-1 short of netsh.
    #[test]
    fn a_forged_receipt_is_rejected_before_reaching_the_platform() {
        let enforcer = WindowsEgressEnforcer::new();
        let scope = BoundaryScope::all_egress();
        for forged in [
            "flowing;rule=all",
            "severed;rule=all",
            "v2;mech=netsh;own=unknown;rule=all",
            "v2;mech=netsh;own=unknown;rule=Windows Firewall Remote Management",
            "flowing;rule=SSK-KillSwitch-x-0011223344556677;rule=all",
            "flowing",
            "",
        ] {
            let receipt = EnforcementReceipt::new(&scope, forged);
            // The digest is recomputed by `new`, i.e. this is a PERFECT forgery
            // as far as receipt_id is concerned — and it still does not pass.
            assert_eq!(receipt.verify_against(&scope), Ok(()));
            match enforcer.release(&receipt) {
                Err(BoundaryError::Enforcement(msg)) => assert!(
                    msg.contains("refusing to act on this receipt"),
                    "unexpected message for {forged:?}: {msg}"
                ),
                other => panic!("forged receipt {forged:?} was not rejected: {other:?}"),
            }
        }
    }

    // Scope re-derivation: even a receipt whose rule name is grammatically
    // perfect is refused when it is not the name THIS scope derives.
    #[test]
    fn a_receipt_for_another_scope_is_refused_by_re_derivation() {
        let enforcer = WindowsEgressEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let other = BoundaryScope::new("other", ["*"]);
        let other_name = rule_name_for_scope(&other).unwrap();
        let receipt = EnforcementReceipt::new(
            &scope,
            PriorState {
                ownership: Ownership::Unknown,
                rule_name: other_name,
            }
            .encode(),
        );
        match enforcer.release_scoped(&scope, &receipt) {
            Err(BoundaryError::Enforcement(msg)) => {
                assert!(msg.contains("refusing to release"), "{msg}");
            }
            other => panic!("expected a scope mismatch rejection, got {other:?}"),
        }
    }

    // A pre-existing rule is never over-removed, and the outcome is typed —
    // this reaches no platform call, so it is safe on Windows too.
    #[test]
    fn enforcer_release_of_a_preexisting_rule_reports_skipped() {
        let enforcer = WindowsEgressEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let name = rule_name_for_scope(&scope).unwrap();
        let receipt = EnforcementReceipt::new(
            &scope,
            PriorState {
                ownership: Ownership::Preexisting,
                rule_name: name,
            }
            .encode(),
        );
        assert_eq!(
            enforcer.release_scoped(&scope, &receipt),
            Ok(ReleaseOutcome::SkippedPreexisting)
        );
    }

    // ---- platform-reaching tests: NON-WINDOWS ONLY (see the module note) ----

    #[cfg(not(windows))]
    #[test]
    fn enforcer_engage_is_unsupported_off_windows() {
        let enforcer = WindowsEgressEnforcer::new();
        match enforcer.engage(&BoundaryScope::all_egress()) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected an Enforcement error off-Windows, got {other:?}"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn enforcer_observe_is_indeterminate_off_windows_never_absent() {
        let obs = WindowsEgressEnforcer::new().observe(&BoundaryScope::all_egress());
        assert!(matches!(obs.presence, Presence::Indeterminate { .. }));
        assert_eq!(obs.presence.as_option_bool(), None);
    }

    #[cfg(not(windows))]
    #[test]
    fn release_of_a_rule_we_may_delete_reaches_the_platform() {
        let enforcer = WindowsEgressEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let name = rule_name_for_scope(&scope).unwrap();
        let receipt = EnforcementReceipt::new(
            &scope,
            PriorState {
                ownership: Ownership::Unknown,
                rule_name: name,
            }
            .encode(),
        );
        match enforcer.release_scoped(&scope, &receipt) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected a platform Enforcement error, got {other:?}"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn recover_reaches_the_platform_off_windows() {
        match WindowsEgressEnforcer::new().recover(&BoundaryScope::all_egress()) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected a platform Enforcement error, got {other:?}"),
        }
    }

    // ---- properties, over a deterministic corpus ----------------------------
    //
    // `ssk-winhost` declares no dev-dependencies (see its Cargo.toml, which is
    // outside this change's scope), so these are exhaustive-over-a-corpus
    // rather than proptest-generated. The corpus is built from every character
    // class the sanitizers must cope with.

    fn adversarial_corpus() -> Vec<String> {
        let fragments = [
            "",
            "a",
            "Z9",
            "prod",
            "all",
            " ",
            "\t",
            "\n",
            "\r\n",
            "\0",
            "\"",
            "'",
            ";",
            "=",
            "*",
            "?",
            "/",
            "\\",
            "..",
            "..\\..",
            "-",
            "--",
            "_",
            "%SystemRoot%",
            "name=all",
            "SSK-KillSwitch-",
            "\u{fc}",    // ü
            "\u{430}",   // cyrillic a
            "\u{ff41}",  // fullwidth a
            "\u{2010}",  // unicode hyphen
            "\u{200b}",  // zero-width space
            "\u{1f600}", // astral plane
            "0011223344556677",
            "ABCDEF0123456789",
            "0123456789abcdef0123456789abcdef",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 40 > LABEL_MAX
        ];
        let mut corpus: Vec<String> = fragments.iter().map(|s| (*s).to_owned()).collect();
        for a in fragments {
            for b in fragments {
                corpus.push(format!("{a}{b}"));
                corpus.push(format!("{RULE_PREFIX}{a}-{b}"));
                corpus.push(format!("{RULE_PREFIX}{a}{b}"));
            }
        }
        corpus
    }

    // The damage bound must never become a denial of service: whatever label
    // and digest a scope supplies, the derived name is accepted by the very
    // validator that guards release.
    #[test]
    fn parse_of_derive_is_always_ok() {
        let corpus = adversarial_corpus();
        // Sweep each argument against the full corpus while the other varies
        // over a small representative set, rather than the full O(n^2) cross
        // product (which is the same coverage at ~400x the runtime).
        let pivots = [
            "",
            "x",
            "prod",
            "all",
            "0011223344556677",
            "\u{430}",
            "-",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        let mut checked = 0usize;
        let mut check = |label: &str, digest: &str| {
            let derived = KillSwitchRuleName::derive(label, digest);
            assert_eq!(
                KillSwitchRuleName::parse(derived.as_str()).as_ref(),
                Ok(&derived),
                "derive({label:?}, {digest:?}) produced an unparseable name"
            );
            assert!(derived.as_str().starts_with(RULE_PREFIX));
            assert!((NAME_MIN..=NAME_MAX).contains(&derived.as_str().len()));
            assert!(derived.as_str().is_ascii());
            checked += 1;
        };
        for item in &corpus {
            for pivot in pivots {
                check(item, pivot);
                check(pivot, item);
            }
        }
        assert!(checked > 10_000, "coverage collapsed to {checked} cases");
    }

    // And the envelope round-trips for every derivable name.
    #[test]
    fn prior_state_round_trips_for_any_derived_name() {
        let corpus = adversarial_corpus();
        for (i, label) in corpus.iter().enumerate() {
            let ownership = match i % 3 {
                0 => Ownership::Created,
                1 => Ownership::Preexisting,
                _ => Ownership::Unknown,
            };
            let prior = PriorState {
                ownership,
                rule_name: KillSwitchRuleName::derive(label, "0011223344556677"),
            };
            assert_eq!(PriorState::parse(&prior.encode()), Ok(prior));
        }
    }

    // No arbitrary string is ever accepted as a rule name unless it literally
    // satisfies the grammar — and in particular can never be `all`, contain
    // whitespace, or contain a non-ASCII character.
    #[test]
    fn parse_accepts_only_grammar_conforming_strings() {
        for candidate in adversarial_corpus() {
            if let Ok(name) = KillSwitchRuleName::parse(&candidate) {
                let rest = name
                    .as_str()
                    .strip_prefix(RULE_PREFIX)
                    .expect("parse guarantees the prefix");
                let (label, digest) = match rest.rsplit_once('-') {
                    Some((l, d)) => (Some(l), d),
                    None => (None, rest),
                };
                assert!(is_digest16(digest), "{candidate:?}");
                if let Some(l) = label {
                    assert!(is_label(l), "{candidate:?}");
                }
                assert!(name.as_str().is_ascii(), "{candidate:?}");
                assert!(
                    !name.as_str().contains(char::is_whitespace),
                    "{candidate:?}"
                );
                assert_ne!(name.as_str(), "all");
            }
        }
    }

    // Every argument list this module can build carries exactly one `name=`
    // token, and it always holds a validated rule name — the grep-checkable
    // invariant that there is no `&str` path into a netsh argument list.
    #[test]
    fn no_argument_list_can_carry_an_unvalidated_name() {
        for candidate in adversarial_corpus() {
            let Ok(name) = KillSwitchRuleName::parse(&candidate) else {
                continue;
            };
            for args in [
                build_add_args(&name),
                build_delete_args(&name),
                build_show_args(&name),
            ] {
                let named: Vec<&String> = args.iter().filter(|a| a.starts_with("name=")).collect();
                assert_eq!(named.len(), 1, "{candidate:?}");
                assert_eq!(named[0], &format!("name={name}"));
                assert!(named[0].strip_prefix("name=").unwrap().is_ascii());
                assert!(args.iter().all(|a| !a.contains('\n') && !a.contains('\r')));
            }
        }
    }
}
