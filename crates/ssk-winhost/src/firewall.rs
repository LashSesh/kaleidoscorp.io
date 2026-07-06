//! Kill-switch enforcement (firewall seam): a real [`ssk_boundary::BoundaryEnforcer`].
//!
//! Tier-1 implementation: sever and restore *all outbound egress* by driving the
//! Windows Firewall through `netsh advfirewall firewall` via
//! [`std::process::Command`]. No kernel driver, no COM; requires Administrator
//! at runtime.
//!
//! Design split (the reason this is testable off-Windows):
//! * a PURE, platform-neutral layer — rule-name derivation, argument
//!   construction, netsh output parsing, and receipt encoding — all unit-tested
//!   on any host;
//! * a THIN `#[cfg(windows)]` layer that is the only code that actually spawns
//!   `netsh`, deferring 100% of its logic to the pure functions.
//!
//! ## Exact rollback
//! `engage` derives a deterministic rule name from the scope digest and records
//! it in the [`ssk_boundary::EnforcementReceipt`]; `release` deletes **exactly**
//! that rule, matching solely on `name=`, so nothing else on the host is
//! touched. This is the enforcement side of the boundary's reversible-receipt
//! contract.
//!
//! ## Deeper tier (documented, not yet built)
//! `netsh` is the honest first tier: transparent, driverless, admin-only. A
//! future tier could use WFP dynamic session filters (`FwpmEngineOpen0` /
//! `FwpmFilterAdd0`), which auto-remove when the engine handle closes — a
//! stronger crash-safety property — or the COM `INetFwRules` API for structured
//! errors. Both are a larger surface; `netsh` ships now and is auditable.

#![allow(clippy::result_large_err)]

use ssk_boundary::{BoundaryEnforcer, BoundaryError, BoundaryScope, EnforcementReceipt};
use ssk_types::{digest_of, HashAlg};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Raw, un-interpreted result of one `netsh` invocation — the seam between the
/// impure process spawn and the pure parsers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInvocation {
    /// Process exit code; `None` if terminated by a signal (modelled honestly).
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl RawInvocation {
    #[must_use]
    pub fn new(
        exit_code: Option<i32>,
        stdout: impl Into<String>,
        stderr: impl Into<String>,
    ) -> Self {
        Self {
            exit_code,
            stdout: stdout.into(),
            stderr: stderr.into(),
        }
    }

    fn is_success_exit(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Typed error from parsing a `netsh` result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetshError {
    /// netsh exited non-zero for a reason we did not specifically classify.
    NonZeroExit {
        code: Option<i32>,
        stdout: String,
        stderr: String,
    },
    /// netsh reported "No rules match the specified criteria." — meaningful on
    /// `delete` (nothing removed) and `show` (rule absent).
    NoRulesMatch,
    /// Exit code said success but stdout lacked the expected confirmation token.
    /// Surfaced rather than silently assumed-OK.
    UnexpectedOutput { stdout: String, stderr: String },
}

impl std::fmt::Display for NetshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetshError::NonZeroExit {
                code,
                stdout,
                stderr,
            } => write!(
                f,
                "netsh exited with {code:?}: stdout={stdout:?} stderr={stderr:?}"
            ),
            NetshError::NoRulesMatch => write!(f, "netsh: no rules match the specified criteria"),
            NetshError::UnexpectedOutput { stdout, stderr } => write!(
                f,
                "netsh: unexpected output (no confirmation token): stdout={stdout:?} stderr={stderr:?}"
            ),
        }
    }
}

impl std::error::Error for NetshError {}

/// Top-level error surfaced by the pure `engage_with` / `release_with`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchError {
    /// The `netsh` process could not be spawned / waited on (I/O error text).
    Spawn(String),
    /// The `netsh` process ran but its result was an error.
    Netsh(NetshError),
    /// This build target has no privileged firewall backend (non-Windows).
    Unsupported,
}

impl std::fmt::Display for KillSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KillSwitchError::Spawn(e) => write!(f, "failed to spawn netsh: {e}"),
            KillSwitchError::Netsh(e) => write!(f, "{e}"),
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

/// Receipt returned by a successful pure `engage_with`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngageReceipt {
    /// The exact firewall rule name that was added (and that release deletes).
    pub rule_name: String,
    /// Whether a rule of this name already existed *before* engage ran.
    pub prior_existed: bool,
}

// ---------------------------------------------------------------------------
// Pure logic: rule-name derivation
// ---------------------------------------------------------------------------

/// Fixed prefix for every kill-switch rule this crate manages. The uniqueness
/// of this exact string is the correctness anchor: release deletes *only* rules
/// matching the derived name, so nothing else on the host is touched.
pub const RULE_PREFIX: &str = "SSK-KillSwitch-";

/// Produce a deterministic, unique firewall rule name for a scope.
///
/// Shape: `SSK-KillSwitch-<first16hex>`, or `SSK-KillSwitch-<label>-<first16hex>`
/// when a non-empty scope label is given, so the rule is human-identifiable in
/// `netsh advfirewall firewall show rule`.
#[must_use]
pub fn rule_name(scope_label: &str, scope_digest_hex: &str) -> String {
    let digest16 = normalize_digest16(scope_digest_hex);
    let label = sanitize_label(scope_label);
    if label.is_empty() {
        format!("{RULE_PREFIX}{digest16}")
    } else {
        format!("{RULE_PREFIX}{label}-{digest16}")
    }
}

fn normalize_digest16(digest_hex: &str) -> String {
    digest_hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_lowercase())
        .take(16)
        .collect()
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(32)
        .collect()
}

// ---------------------------------------------------------------------------
// Pure logic: netsh argument construction
// ---------------------------------------------------------------------------

/// Args to ADD the outbound block rule: all programs (no `program=` filter),
/// all addresses, all profiles, direction out.
#[must_use]
pub fn build_add_args(rule_name: &str) -> Vec<String> {
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
pub fn build_delete_args(rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ]
}

/// Args to SHOW the rule with this name (used to probe prior existence).
#[must_use]
pub fn build_show_args(rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "show".into(),
        "rule".into(),
        format!("name={rule_name}"),
    ]
}

// ---------------------------------------------------------------------------
// Pure logic: netsh output parsing
// ---------------------------------------------------------------------------

const NO_MATCH_TOKEN: &str = "No rules match the specified criteria";
const OK_TOKEN: &str = "Ok.";

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Parse an ADD result. Success requires exit 0 AND the "Ok." token; a zero
/// exit with unexpected stdout is flagged, not trusted.
pub fn parse_add_output(inv: &RawInvocation) -> Result<(), NetshError> {
    if !inv.is_success_exit() {
        return Err(NetshError::NonZeroExit {
            code: inv.exit_code,
            stdout: inv.stdout.clone(),
            stderr: inv.stderr.clone(),
        });
    }
    if contains_ci(&inv.stdout, OK_TOKEN) {
        Ok(())
    } else {
        Err(NetshError::UnexpectedOutput {
            stdout: inv.stdout.clone(),
            stderr: inv.stderr.clone(),
        })
    }
}

/// Parse a DELETE result. Returns the number of rules deleted. "No rules match"
/// is surfaced as an error (release expected its rule to be present).
pub fn parse_delete_output(inv: &RawInvocation) -> Result<u32, NetshError> {
    let combined = format!("{}\n{}", inv.stdout, inv.stderr);
    if contains_ci(&combined, NO_MATCH_TOKEN) {
        return Err(NetshError::NoRulesMatch);
    }
    if !inv.is_success_exit() {
        return Err(NetshError::NonZeroExit {
            code: inv.exit_code,
            stdout: inv.stdout.clone(),
            stderr: inv.stderr.clone(),
        });
    }
    Ok(parse_deleted_count(&inv.stdout).unwrap_or(1))
}

/// Scrape the integer from a line like "Deleted 2 rule(s)." `None` if absent.
#[must_use]
pub fn parse_deleted_count(stdout: &str) -> Option<u32> {
    let lower = stdout.to_ascii_lowercase();
    let idx = lower.find("deleted")?;
    let tail = &stdout[idx..];
    let digits: String = tail
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse::<u32>().ok()
}

/// Parse a SHOW result into "does the rule exist?".
pub fn parse_show_output(inv: &RawInvocation) -> Result<bool, NetshError> {
    let combined = format!("{}\n{}", inv.stdout, inv.stderr);
    if contains_ci(&combined, NO_MATCH_TOKEN) {
        return Ok(false);
    }
    if inv.is_success_exit() {
        return Ok(true);
    }
    Err(NetshError::NonZeroExit {
        code: inv.exit_code,
        stdout: inv.stdout.clone(),
        stderr: inv.stderr.clone(),
    })
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

/// Engage: probe prior existence, then add the outbound block rule. All impurity
/// is inside `runner`.
pub fn engage_with<R: NetshRunner>(
    scope_label: &str,
    scope_digest_hex: &str,
    runner: &R,
) -> Result<EngageReceipt, KillSwitchError> {
    let name = rule_name(scope_label, scope_digest_hex);

    let show = runner.run(&build_show_args(&name))?;
    let prior_existed = parse_show_output(&show)?;

    let add = runner.run(&build_add_args(&name))?;
    parse_add_output(&add)?;

    Ok(EngageReceipt {
        rule_name: name,
        prior_existed,
    })
}

/// Release: delete exactly the named rule(s). Returns the number removed.
pub fn release_with<R: NetshRunner>(rule_name: &str, runner: &R) -> Result<u32, KillSwitchError> {
    let del = runner.run(&build_delete_args(rule_name))?;
    Ok(parse_delete_output(&del)?)
}

// ---------------------------------------------------------------------------
// Pure logic: receipt encoding (round-trips the exact rule name through the
// boundary's opaque `prior_state` string so release is exact and independent of
// re-deriving from the scope).
// ---------------------------------------------------------------------------

const RULE_TAG: &str = ";rule=";

/// Encode the engage outcome into the `prior_state` string the boundary layer
/// stores in its [`EnforcementReceipt`] and hands back verbatim on release.
#[must_use]
pub fn encode_prior_state(receipt: &EngageReceipt) -> String {
    let flow = if receipt.prior_existed {
        "severed"
    } else {
        "flowing"
    };
    format!("{flow}{RULE_TAG}{}", receipt.rule_name)
}

/// Recover the exact rule name from a receipt's `prior_state`. `None` if the
/// receipt was not produced by [`encode_prior_state`] (e.g. a foreign receipt).
#[must_use]
pub fn rule_from_prior_state(prior_state: &str) -> Option<String> {
    prior_state
        .split_once(RULE_TAG)
        .map(|(_, rule)| rule.to_owned())
        .filter(|r| !r.is_empty())
}

/// Recover whether the rule already existed *before* this engagement, from the
/// receipt's `prior_state` (the `severed`/`flowing` tag [`encode_prior_state`]
/// wrote). `true` means the block rule was already present, so this engagement
/// did not create it — and a faithful release must therefore *not* delete it.
#[must_use]
pub fn prior_existed_from_prior_state(prior_state: &str) -> bool {
    prior_state
        .split_once(RULE_TAG)
        .map(|(flag, _)| flag == "severed")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Thin Windows syscall layer: the ONLY code that spawns netsh.
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::{KillSwitchError, NetshRunner, RawInvocation};
    use std::process::Command;

    /// Real runner: spawn `netsh <args>` and capture its output.
    pub struct SystemNetsh;

    impl NetshRunner for SystemNetsh {
        fn run(&self, args: &[String]) -> Result<RawInvocation, KillSwitchError> {
            let output = Command::new("netsh")
                .args(args)
                .output()
                .map_err(|e| KillSwitchError::Spawn(e.to_string()))?;
            Ok(RawInvocation {
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
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
fn platform_release(rule_name: &str) -> Result<u32, KillSwitchError> {
    #[cfg(windows)]
    {
        release_with(rule_name, &imp::SystemNetsh)
    }
    #[cfg(not(windows))]
    {
        let _ = rule_name;
        Err(KillSwitchError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// The real BoundaryEnforcer
// ---------------------------------------------------------------------------

/// A real [`BoundaryEnforcer`] backed by the Windows Firewall.
///
/// `engage` severs all outbound egress for the scope by adding a deterministically
/// named block rule; `release` deletes exactly that rule. The rule name is
/// derived from the scope's content digest, so it is stable, unique per scope,
/// and human-identifiable. All actions are logged at `warn` (a kill-switch
/// transition is security-critical in either direction).
///
/// Multi-session note: the rule name is scope-scoped, not session-scoped (the
/// `BoundaryEnforcer::engage` contract only receives the scope). Two sessions
/// severing the same scope share one rule name. `engage` records whether the
/// rule already existed, and `release` honors it: only the engagement that
/// actually *created* the rule (prior state `flowing`) deletes it; an engagement
/// that found it already present (prior state `severed`) leaves it in place on
/// release, so it never over-removes a rule it did not create. Full cross-session
/// reference counting (N engagements needing N releases) is a higher-tier concern
/// beyond this enforcer, but the "undo only what you created" invariant holds.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsFirewallEnforcer;

impl WindowsFirewallEnforcer {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl BoundaryEnforcer for WindowsFirewallEnforcer {
    fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
        let digest = digest_of(scope, HashAlg::Blake3)
            .map_err(|e| BoundaryError::Enforcement(format!("scope digest failed: {e}")))?;
        let receipt = platform_engage(&scope.label, &digest.to_hex())
            .map_err(|e| BoundaryError::Enforcement(e.to_string()))?;

        tracing::warn!(
            target: "ssk.winhost.firewall",
            event = "kill_switch_engaged",
            rule = %receipt.rule_name,
            prior_existed = receipt.prior_existed,
            scope = %scope.label,
        );

        Ok(EnforcementReceipt::new(scope, encode_prior_state(&receipt)))
    }

    fn release(&self, receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
        let rule = rule_from_prior_state(&receipt.prior_state).ok_or_else(|| {
            BoundaryError::Enforcement(
                "receipt does not carry a winhost firewall rule name; cannot release exactly"
                    .into(),
            )
        })?;

        // Exact rollback (mirrors the service seam): if the block rule already
        // existed when we engaged, this engagement did not create it, so a
        // faithful release must NOT delete it — the prior state was already
        // "severed", and restoring the prior state means leaving it in place.
        // Deleting it would over-remove another party's rule (fail-open).
        if prior_existed_from_prior_state(&receipt.prior_state) {
            tracing::warn!(
                target: "ssk.winhost.firewall",
                event = "kill_switch_release_skipped_preexisting",
                rule = %rule,
            );
            return Ok(());
        }

        let removed =
            platform_release(&rule).map_err(|e| BoundaryError::Enforcement(e.to_string()))?;

        tracing::warn!(
            target: "ssk.winhost.firewall",
            event = "kill_switch_released",
            rule = %rule,
            rules_removed = removed,
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests (pure — run on any host, including this Linux build box)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_name_matches_canonical_shape_when_no_label() {
        let digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let name = rule_name("", digest);
        assert_eq!(name, "SSK-KillSwitch-a1b2c3d4e5f60718");
        assert!(name.starts_with(RULE_PREFIX));
    }

    #[test]
    fn rule_name_is_deterministic() {
        let d = "DEADBEEFdeadbeef0000";
        assert_eq!(rule_name("scope", d), rule_name("scope", d));
    }

    #[test]
    fn rule_name_lowercases_and_truncates_digest() {
        assert_eq!(
            rule_name("", "ABCDEF0123456789ABCDEF"),
            "SSK-KillSwitch-abcdef0123456789"
        );
    }

    #[test]
    fn rule_name_embeds_sanitized_label() {
        assert_eq!(
            rule_name("Tenant 7/prod", "0011223344556677"),
            "SSK-KillSwitch-Tenant7prod-0011223344556677"
        );
    }

    #[test]
    fn rule_name_distinct_scopes_distinct_names() {
        assert_ne!(
            rule_name("x", "1111111111111111"),
            rule_name("x", "2222222222222222")
        );
    }

    #[test]
    fn add_args_are_outbound_block_all() {
        let args = build_add_args("SSK-KillSwitch-abc");
        assert_eq!(args[0], "advfirewall");
        assert!(args.contains(&"dir=out".to_string()));
        assert!(args.contains(&"action=block".to_string()));
        assert!(args.contains(&"remoteip=any".to_string()));
        assert!(args.contains(&"name=SSK-KillSwitch-abc".to_string()));
        assert!(!args.iter().any(|a| a.starts_with("program=")));
    }

    #[test]
    fn delete_args_match_by_name_only() {
        let args = build_delete_args("SSK-KillSwitch-abc");
        assert_eq!(
            args,
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=SSK-KillSwitch-abc"
            ]
        );
        assert!(args.iter().all(|a| !a.starts_with("dir=")));
    }

    #[test]
    fn parse_add_ok() {
        assert_eq!(
            parse_add_output(&RawInvocation::new(Some(0), "Ok.\n", "")),
            Ok(())
        );
    }

    #[test]
    fn parse_add_nonzero_is_error() {
        let inv = RawInvocation::new(Some(1), "", "requires elevation");
        match parse_add_output(&inv) {
            Err(NetshError::NonZeroExit { code, .. }) => assert_eq!(code, Some(1)),
            other => panic!("expected NonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn parse_add_zero_exit_but_no_ok_token_is_flagged() {
        let inv = RawInvocation::new(Some(0), "something weird\n", "");
        assert!(matches!(
            parse_add_output(&inv),
            Err(NetshError::UnexpectedOutput { .. })
        ));
    }

    #[test]
    fn parse_delete_success_counts() {
        assert_eq!(
            parse_delete_output(&RawInvocation::new(
                Some(0),
                "Deleted 1 rule(s).\nOk.\n",
                ""
            )),
            Ok(1)
        );
        assert_eq!(
            parse_delete_output(&RawInvocation::new(Some(0), "Deleted 3 rule(s).\n", "")),
            Ok(3)
        );
    }

    #[test]
    fn parse_delete_no_match_is_surfaced() {
        let inv = RawInvocation::new(Some(1), "No rules match the specified criteria.\n", "");
        assert_eq!(parse_delete_output(&inv), Err(NetshError::NoRulesMatch));
    }

    #[test]
    fn parse_delete_other_nonzero_is_error() {
        let inv = RawInvocation::new(Some(1), "", "Access is denied.");
        assert!(matches!(
            parse_delete_output(&inv),
            Err(NetshError::NonZeroExit { .. })
        ));
    }

    #[test]
    fn parse_deleted_count_scrapes_number() {
        assert_eq!(parse_deleted_count("Deleted 2 rule(s)."), Some(2));
        assert_eq!(parse_deleted_count("deleted 10 rule(s)."), Some(10));
        assert_eq!(parse_deleted_count("Ok."), None);
    }

    #[test]
    fn parse_show_existing_and_absent() {
        let present = RawInvocation::new(
            Some(0),
            "Rule Name: SSK-KillSwitch-abc\r\nAction: Block\r\n",
            "",
        );
        assert_eq!(parse_show_output(&present), Ok(true));
        let absent = RawInvocation::new(Some(1), "No rules match the specified criteria.\n", "");
        assert_eq!(parse_show_output(&absent), Ok(false));
    }

    // ---- receipt encoding round-trip ----

    #[test]
    fn prior_state_round_trips_the_exact_rule_name() {
        let receipt = EngageReceipt {
            rule_name: "SSK-KillSwitch-prod-0011223344556677".into(),
            prior_existed: false,
        };
        let encoded = encode_prior_state(&receipt);
        assert!(encoded.starts_with("flowing;rule="));
        assert_eq!(
            rule_from_prior_state(&encoded).as_deref(),
            Some("SSK-KillSwitch-prod-0011223344556677")
        );
    }

    #[test]
    fn prior_state_records_prior_existence() {
        let receipt = EngageReceipt {
            rule_name: "SSK-KillSwitch-x".into(),
            prior_existed: true,
        };
        assert!(encode_prior_state(&receipt).starts_with("severed;rule="));
    }

    #[test]
    fn rule_from_a_foreign_receipt_is_none() {
        assert_eq!(rule_from_prior_state("flowing"), None);
        assert_eq!(rule_from_prior_state("severed;rule="), None);
        assert_eq!(rule_from_prior_state(""), None);
    }

    // ---- orchestration with a scripted fake runner ----

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

    #[test]
    fn engage_fresh_scope_reports_prior_absent_and_adds() {
        let runner = ScriptedRunner::new(vec![
            Ok(RawInvocation::new(
                Some(1),
                "No rules match the specified criteria.\n",
                "",
            )),
            Ok(RawInvocation::new(Some(0), "Ok.\n", "")),
        ]);
        let receipt = engage_with("prod", "00112233445566778899", &runner).unwrap();
        assert_eq!(receipt.rule_name, "SSK-KillSwitch-prod-0011223344556677");
        assert!(!receipt.prior_existed);
        let seen = runner.seen.borrow();
        assert_eq!(seen[0][2], "show");
        assert_eq!(seen[1][2], "add");
    }

    #[test]
    fn engage_reports_prior_present_when_rule_exists() {
        let runner = ScriptedRunner::new(vec![
            Ok(RawInvocation::new(
                Some(0),
                "Rule Name: SSK-KillSwitch-x\r\nAction: Block\r\n",
                "",
            )),
            Ok(RawInvocation::new(Some(0), "Ok.\n", "")),
        ]);
        assert!(
            engage_with("", "aaaaaaaaaaaaaaaa", &runner)
                .unwrap()
                .prior_existed
        );
    }

    #[test]
    fn engage_propagates_add_failure() {
        let runner = ScriptedRunner::new(vec![
            Ok(RawInvocation::new(
                Some(1),
                "No rules match the specified criteria.\n",
                "",
            )),
            Ok(RawInvocation::new(Some(1), "", "requires elevation")),
        ]);
        assert!(matches!(
            engage_with("", "aaaaaaaaaaaaaaaa", &runner).unwrap_err(),
            KillSwitchError::Netsh(NetshError::NonZeroExit { .. })
        ));
    }

    #[test]
    fn release_deletes_exactly_the_named_rule() {
        let runner = ScriptedRunner::new(vec![Ok(RawInvocation::new(
            Some(0),
            "Deleted 1 rule(s).\nOk.\n",
            "",
        ))]);
        assert_eq!(release_with("SSK-KillSwitch-abc", &runner).unwrap(), 1);
        let seen = runner.seen.borrow();
        assert_eq!(seen[0][2], "delete");
        assert_eq!(seen[0][4], "name=SSK-KillSwitch-abc");
    }

    #[test]
    fn release_surfaces_no_match() {
        let runner = ScriptedRunner::new(vec![Ok(RawInvocation::new(
            Some(1),
            "No rules match the specified criteria.\n",
            "",
        ))]);
        assert!(matches!(
            release_with("SSK-KillSwitch-missing", &runner).unwrap_err(),
            KillSwitchError::Netsh(NetshError::NoRulesMatch)
        ));
    }

    // ---- the enforcer on a non-Windows build returns Unsupported, not a silent ok ----

    #[cfg(not(windows))]
    #[test]
    fn enforcer_engage_is_unsupported_off_windows() {
        let enforcer = WindowsFirewallEnforcer::new();
        let scope = BoundaryScope::all_egress();
        match enforcer.engage(&scope) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected an Enforcement error off-Windows, got {other:?}"),
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn enforcer_release_needs_a_winhost_receipt() {
        let enforcer = WindowsFirewallEnforcer::new();
        let scope = BoundaryScope::all_egress();
        // A receipt whose prior_state has no rule tag cannot be released exactly.
        let foreign = EnforcementReceipt::new(&scope, "flowing");
        match enforcer.release(&foreign) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("does not carry")),
            other => panic!("expected an Enforcement error, got {other:?}"),
        }
    }

    #[test]
    fn prior_existed_flag_round_trips() {
        let created = EngageReceipt {
            rule_name: "SSK-KillSwitch-x".into(),
            prior_existed: false,
        };
        let preexisting = EngageReceipt {
            rule_name: "SSK-KillSwitch-x".into(),
            prior_existed: true,
        };
        assert!(!prior_existed_from_prior_state(&encode_prior_state(
            &created
        )));
        assert!(prior_existed_from_prior_state(&encode_prior_state(
            &preexisting
        )));
        // A foreign / tagless receipt is treated as "we created it" only if it
        // carries a rule; the flag parse itself defaults to false (not severed).
        assert!(!prior_existed_from_prior_state("flowing"));
        assert!(!prior_existed_from_prior_state("garbage"));
    }

    // Releasing a receipt whose rule PRE-EXISTED must not attempt any deletion —
    // even off-Windows it returns Ok WITHOUT reaching the platform layer (which
    // would otherwise report Unsupported). This proves "undo only what you
    // created": a pre-existing rule is never over-removed.
    #[test]
    fn release_of_a_preexisting_rule_is_a_no_op() {
        let enforcer = WindowsFirewallEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let receipt = EnforcementReceipt::new(&scope, "severed;rule=SSK-KillSwitch-shared");
        assert!(
            enforcer.release(&receipt).is_ok(),
            "releasing a pre-existing rule must be a no-op success, not a deletion"
        );
    }

    // Conversely, a rule WE created (flowing) must actually be released — which
    // off-Windows means it reaches the platform layer and reports Unsupported
    // (never a silent success).
    #[cfg(not(windows))]
    #[test]
    fn release_of_a_created_rule_reaches_the_platform() {
        let enforcer = WindowsFirewallEnforcer::new();
        let scope = BoundaryScope::all_egress();
        let receipt = EnforcementReceipt::new(&scope, "flowing;rule=SSK-KillSwitch-ours");
        match enforcer.release(&receipt) {
            Err(BoundaryError::Enforcement(msg)) => assert!(msg.contains("requires Windows")),
            other => panic!("expected a platform Enforcement error, got {other:?}"),
        }
    }
}
