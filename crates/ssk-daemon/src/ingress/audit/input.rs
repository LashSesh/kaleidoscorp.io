//! What the writer is given (design 6.4.7): plain structs, built by the engine and
//! the host from their own types, and the closed vocabularies the free-text-looking
//! fields of a record are drawn from.
//!
//! The direction of dependencies matters: the writer takes these and not the
//! engine's `Admitted`, because the audit module is built before the engine and
//! must not import it (`audit_module_has_no_upward_imports`). Everything that
//! could carry a destination goes through [`super::dest::DestSealer`] on the way
//! into a record, so a result cannot name a plain address in `hashed` mode.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use ssk_netadmin::admission::AdmissionToken;

use super::record::RepeatCount;
use crate::ingress::pump::PumpEnd;
use crate::ingress::target::{Provenance, Target, TargetKind};
use crate::ingress::types::{Actor, DisarmCause, Observation, Resolution, RuleTable, TripReason};

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// Used when a producer names a code that is not in its closed list. The record
/// is still written (an audit record that is missing is worse than one with a
/// generic word) and the writer counts it, so a producer that drifts from the list
/// shows in status and in a test of that producer.
pub const UNKNOWN_CODE: &str = "UNKNOWN_CODE";

/// `Result.error_code`: the codes of `NetcoreError::code()` and the ingress's own.
pub const RESULT_ERROR_CODES: [&str; 25] = [
    "OPENVPN_NOT_READY",
    "NETCORE_TIMEOUT",
    "NETCORE_CONNECTION_REFUSED",
    "NETCORE_DNS_FAILED",
    "NETCORE_TLS_FAILED",
    "NETCORE_PROXY_REJECTED",
    "NETCORE_UNSUPPORTED_ADAPTER",
    "NETCORE_POLICY_DENIED",
    "NETCORE_NO_ROUTE",
    "NETCORE_UNKNOWN_ADAPTER",
    "NETCORE_IO_ERROR",
    "NETCORE_PROTOCOL_ERROR",
    "NETCORE_INVALID_TARGET",
    "NETCORE_RESOLVER_BUSY",
    "NETCORE_ADDR_REFUSED",
    "NETCORE_FAMILY_DISABLED",
    "GATE_CLOSED",
    "FLOW_DROPPED",
    "AUDIT_ABANDONED",
    "RESULT_NOT_RECORDED",
    "DIAL_NOT_COMPLETED",
    "CONNECT_DEADLINE",
    "COOLING_OFF",
    "RECEIPT_MISMATCH",
    UNKNOWN_CODE,
];

/// `Result.refusal`: the static label of an address refusal, never an address. The
/// seventeen special-use labels of `target.rs` and the three guard labels of
/// `guard.rs` (a test ties both lists to the code that produces them).
pub const RESULT_REFUSALS: [&str; 21] = [
    "unspecified",
    "this_network",
    "loopback",
    "private",
    "shared_address_space",
    "link_local",
    "metadata",
    "multicast",
    "reserved",
    "broadcast",
    "documentation",
    "fake_ip",
    "protocol_assignment",
    "translation",
    "site_local",
    "discard",
    "dummy_prefix",
    "listener",
    "deny_rule",
    "not_armed",
    UNKNOWN_CODE,
];

/// `Denied.reason_code`.
pub const DENIED_REASON_CODES: [&str; 11] = [
    "TARGET_MALFORMED",
    "TARGET_NUMERIC_ALIAS",
    "TARGET_LOCALHOST",
    "TARGET_SELF_LOOP",
    "SPECIAL_USE_NEEDS_EXACT_RULE",
    "SPECIAL_USE_NEEDS_PORT",
    "POLICY_DENY",
    "NO_VIABLE_ROUTE",
    "ATTESTATION_REQUIRED",
    "NOT_ARMED",
    UNKNOWN_CODE,
];

/// Maps `code` into `list`; anything else becomes [`UNKNOWN_CODE`]. The second
/// value is `true` when the code was not in the list.
#[must_use]
pub fn closed(code: &str, list: &[&'static str]) -> (&'static str, bool) {
    list.iter()
        .find(|known| **known == code)
        .map_or((UNKNOWN_CODE, true), |known| (*known, false))
}

/// `Closed.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseReason {
    Eof,
    IdleTimeout,
    GateClosed,
    ClientError,
    UpstreamError,
    /// The flow task ended without closing the tunnel (a panic, an abort).
    Aborted,
    /// The `Closed` record could not be written when the tunnel ended.
    AuditAbandoned,
}

impl CloseReason {
    pub const ALL: [Self; 7] = [
        Self::Eof,
        Self::IdleTimeout,
        Self::GateClosed,
        Self::ClientError,
        Self::UpstreamError,
        Self::Aborted,
        Self::AuditAbandoned,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Eof => PumpEnd::Eof.reason(),
            Self::IdleTimeout => PumpEnd::IdleTimeout.reason(),
            Self::GateClosed => PumpEnd::GateClosed.reason(),
            Self::ClientError => PumpEnd::ClientError.reason(),
            Self::UpstreamError => PumpEnd::UpstreamError.reason(),
            Self::Aborted => "aborted",
            Self::AuditAbandoned => "audit_abandoned",
        }
    }
}

impl From<PumpEnd> for CloseReason {
    fn from(end: PumpEnd) -> Self {
        match end {
            PumpEnd::Eof => Self::Eof,
            PumpEnd::IdleTimeout => Self::IdleTimeout,
            PumpEnd::GateClosed => Self::GateClosed,
            PumpEnd::ClientError => Self::ClientError,
            PumpEnd::UpstreamError => Self::UpstreamError,
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// A flow that was admitted and is about to dial.
pub struct PendingInput<'a> {
    /// The host, port and route that will be dialled. The receipt's binding is
    /// computed from it, and the dial recomputes it from the token it consumes.
    pub token: &'a AdmissionToken,
    pub flow_id: &'a str,
    pub profile: &'a str,
    pub matched_rule: Option<&'a str>,
    pub peer: &'a str,
    pub peer_verified: bool,
    pub target_kind: TargetKind,
    pub provenance: Provenance,
    pub resolution: Resolution,
    pub planned_adapters: &'a [String],
}

/// The tunnel is established.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectedEvent {
    /// `AdapterKind` names through an exhaustive match, never `{:?}`.
    pub chain_kinds: Vec<&'static str>,
    pub dialed: Option<SocketAddr>,
    pub attempted: Vec<SocketAddr>,
    pub answers: Option<u8>,
    pub observations: Vec<Observation>,
}

/// A dial was started and failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailedEvent {
    pub error_code: &'static str,
    pub refusal: Option<&'static str>,
    pub attempted: Vec<SocketAddr>,
    pub answers: Option<u8>,
    pub observations: Vec<Observation>,
}

impl FailedEvent {
    /// A failure with a code and nothing else known.
    #[must_use]
    pub fn code(error_code: &'static str) -> Self {
        Self {
            error_code,
            refusal: None,
            attempted: Vec::new(),
            answers: None,
            observations: Vec::new(),
        }
    }
}

/// A refusal. The destination is always written in clear.
pub struct DeniedEvent<'a> {
    pub peer: &'a str,
    pub peer_verified: bool,
    pub target: &'a Target,
    pub profile: &'a str,
    pub matched_rule: Option<&'a str>,
    pub reason_code: &'static str,
    pub route: Option<String>,
    /// `true` when this record stands for a run of equal refusals.
    pub coalesced: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmedEvent {
    pub actor: Actor,
    pub profile: String,
    pub epoch: u64,
    pub profile_digest: String,
    pub rules: RuleTable,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisarmedEvent {
    pub cause: DisarmCause,
    pub epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrippedEvent {
    pub reason: TripReason,
    pub epoch: u64,
}

/// The tunnel ended. The duration is the receipt's own, from the moment its
/// `Result` was durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosedEvent {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub reason: CloseReason,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SummaryEvent {
    pub window_ms: u64,
    pub pre_admission_rejects: BTreeMap<String, u64>,
    pub denials_suppressed: BTreeMap<String, u64>,
    pub denials_over_quota: BTreeMap<String, u64>,
    pub denials_repeated: Vec<RepeatCount>,
    pub other_keys: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::target::SpecialUse;

    #[test]
    fn the_closed_lists_have_no_duplicates_and_only_printable_words() {
        for list in [
            RESULT_ERROR_CODES.as_slice(),
            RESULT_REFUSALS.as_slice(),
            DENIED_REASON_CODES.as_slice(),
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(sorted.len(), list.len(), "{list:?}");
            for word in list {
                assert!(word.bytes().all(|b| (0x21..=0x7e).contains(&b)), "{word}");
                // `OPENVPN_NOT_READY` is the machine code of an existing netcore
                // error, written only if a route names that adapter kind; it is
                // not a statement about anything and is the one exception.
                if *word != "OPENVPN_NOT_READY" {
                    assert_eq!(
                        crate::ingress::types::contains_forbidden_word(&word.to_lowercase()),
                        None,
                        "{word}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_netcore_error_code_is_in_the_closed_list() {
        use ssk_netcore::NetcoreError as E;
        let samples = [
            E::OpenVpnNotReady(String::new()),
            E::Timeout(String::new(), std::time::Duration::ZERO),
            E::ConnectionRefused(String::new(), String::new()),
            E::DnsResolutionFailed(String::new(), String::new(), String::new()),
            E::TlsHandshakeFailed(String::new(), String::new()),
            E::ProxyRejected(String::new(), String::new()),
            E::Unsupported(ssk_netadmin::adapter::AdapterKind::Direct),
            E::PolicyDenied(String::new()),
            E::NoRoute(String::new()),
            E::UnknownAdapter(String::new()),
            E::Io(
                String::new(),
                std::io::Error::from(std::io::ErrorKind::Other),
            ),
            E::ProtocolError(String::new(), String::new()),
            E::InvalidTarget(String::new()),
            E::ResolverBusy,
            E::AddressRefused {
                code: "loopback",
                refused: 1,
                answers: 1,
            },
            E::FamilyDisabled,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for error in samples {
            let code = error.code();
            assert!(seen.insert(code), "{code} twice");
            assert_eq!(
                closed(code, &RESULT_ERROR_CODES),
                (code_static(code), false),
                "{code}"
            );
        }
        // The sample is the whole enum: sixteen variants, sixteen codes.
        assert_eq!(seen.len(), 16);
    }

    fn code_static(code: &str) -> &'static str {
        RESULT_ERROR_CODES
            .iter()
            .find(|known| **known == code)
            .copied()
            .expect("in the list")
    }

    #[test]
    fn every_special_use_label_and_guard_label_is_a_known_refusal() {
        for special in SpecialUse::ALL {
            assert!(
                !closed(special.code(), &RESULT_REFUSALS).1,
                "{}",
                special.code()
            );
        }
        for label in [
            crate::ingress::guard::REFUSAL_LISTENER,
            crate::ingress::guard::REFUSAL_DENY_RULE,
            crate::ingress::guard::REFUSAL_NOT_ARMED,
        ] {
            assert!(!closed(label, &RESULT_REFUSALS).1, "{label}");
        }
        // And the list holds nothing else: 17 + 3 + the generic word.
        assert_eq!(RESULT_REFUSALS.len(), SpecialUse::ALL.len() + 3 + 1);
    }

    #[test]
    fn every_target_refusal_is_a_known_denial_code() {
        use crate::ingress::target::Refusal as R;
        for refusal in [
            R::Malformed,
            R::NumericAlias,
            R::LocalhostName,
            R::SelfLoop,
            R::SpecialUse(SpecialUse::Loopback),
            R::SpecialUseNeedsPort(SpecialUse::Loopback),
        ] {
            assert!(
                !closed(refusal.reason_code(), &DENIED_REASON_CODES).1,
                "{}",
                refusal.reason_code()
            );
        }
    }

    /// The words the ingress itself adds to the netcore codes (design 6.4.3) and to
    /// the target refusals: written into a persisted ledger, so a change is
    /// deliberate.
    #[test]
    fn the_ingress_own_codes_are_the_documented_ones() {
        assert_eq!(
            RESULT_ERROR_CODES.get(16..),
            Some(
                [
                    "GATE_CLOSED",
                    "FLOW_DROPPED",
                    "AUDIT_ABANDONED",
                    "RESULT_NOT_RECORDED",
                    "DIAL_NOT_COMPLETED",
                    "CONNECT_DEADLINE",
                    "COOLING_OFF",
                    "RECEIPT_MISMATCH",
                    "UNKNOWN_CODE",
                ]
                .as_slice()
            )
        );
        assert_eq!(
            DENIED_REASON_CODES.get(6..),
            Some(
                [
                    "POLICY_DENY",
                    "NO_VIABLE_ROUTE",
                    "ATTESTATION_REQUIRED",
                    "NOT_ARMED",
                    "UNKNOWN_CODE",
                ]
                .as_slice()
            )
        );
        assert_eq!(UNKNOWN_CODE, "UNKNOWN_CODE");
    }

    #[test]
    fn an_unknown_word_becomes_the_generic_code_and_says_so() {
        assert_eq!(closed("MADE_UP", &RESULT_ERROR_CODES), (UNKNOWN_CODE, true));
        assert_eq!(closed("", &DENIED_REASON_CODES), (UNKNOWN_CODE, true));
        assert_eq!(
            closed("NETCORE_TIMEOUT", &RESULT_ERROR_CODES),
            ("NETCORE_TIMEOUT", false)
        );
        // The generic word itself is a member, and is not reported as unknown twice.
        assert_eq!(
            closed(UNKNOWN_CODE, &RESULT_ERROR_CODES),
            (UNKNOWN_CODE, false)
        );
    }

    #[test]
    fn close_reasons_are_the_pump_words_plus_two() {
        let words: Vec<&str> = CloseReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "eof",
                "idle_timeout",
                "gate_closed",
                "client_error",
                "upstream_error",
                "aborted",
                "audit_abandoned"
            ]
        );
        for end in [
            PumpEnd::Eof,
            PumpEnd::IdleTimeout,
            PumpEnd::GateClosed,
            PumpEnd::ClientError,
            PumpEnd::UpstreamError,
        ] {
            assert_eq!(CloseReason::from(end).as_str(), end.reason());
        }
        for word in words {
            assert_eq!(crate::ingress::types::contains_forbidden_word(word), None);
        }
    }
}
