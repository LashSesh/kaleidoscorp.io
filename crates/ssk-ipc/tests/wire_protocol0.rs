//! The wire as it was before IPC protocol 1 (every build up to and including
//! `b62c4c8`; `StatusDto.protocol` is absent there, which reads as 0).
//!
//! The hex strings below were captured from the types of that build with
//! `ciborium::ser::into_writer`, the framing's own encoder, and are never
//! regenerated: a fixture that stops decoding means a change that an older peer
//! cannot ignore, and that needs a protocol bump and a `COMPATIBILITY_MATRIX.md`
//! entry (design `docs/M2_LOCAL_INGRESS_DESIGN.md` 11.2 and 11.12), not a new
//! fixture.
//!
//! The other direction, a protocol-0 peer reading what this build writes, is
//! tested against hand-written copies of the protocol-0 types: only a copy that
//! does not move with the crate can notice that the crate's types changed shape.

use serde::{Deserialize, Serialize};
use ssk_ipc::{
    ActivateProfileRequest, AdapterHealthSummaryDto, DaemonState, DeactivateRequest,
    ExplainRequest, FlowSummaryDto, IngressStatusDto, IngressWarningDto, IpcError, Request,
    Response, RouteTraceDto, StatusDto, SubscribeEventsRequest, IPC_PROTOCOL_VERSION,
};

/// `Response::Status` of an idle daemon: no `protocol` and no `ingress` key.
const PROTOCOL_0_STATUS: &str = "a166537461747573a865737461746568496e6163746976656e6163746976655f70726f66696c65f6686164617074657273806d646e735f70726f746563746564f46b6b696c6c5f737769746368f46a61756469745f68656164f66776657273696f6e65302e312e306a6c6173745f6572726f72f6";

/// One frame body per protocol-0 request, keyed by variant name.
const PROTOCOL_0_REQUESTS: [(&str, &str); 12] = [
    ("GetStatus", "69476574537461747573"),
    (
        "ActivateProfile",
        "a16f416374697661746550726f66696c65a36a70726f66696c655f69646764656661756c7469646573745f686f7374693132372e302e302e3169646573745f706f727409",
    ),
    (
        "Deactivate",
        "a16a44656163746976617465a17372656c656173655f6b696c6c5f737769746368f4",
    ),
    ("ListProfiles", "6c4c69737450726f66696c6573"),
    ("InspectFlow", "a16b496e7370656374466c6f77a167666c6f775f6964626631"),
    (
        "TraceRoute",
        "a16a5472616365526f757465a5666170705f6964f669646573745f686f73746b6578616d706c652e6f726769646573745f706f72741901bb6870726f746f636f6c63746370647269736b636c6f77",
    ),
    (
        "ListRecentFlows",
        "a16f4c697374526563656e74466c6f7773a1656c696d697405",
    ),
    (
        "GetAuditEntries",
        "a16f4765744175646974456e7472696573a1656c696d697405",
    ),
    ("VerifyAuditChain", "705665726966794175646974436861696e"),
    ("RunDoctor", "6952756e446f63746f72"),
    (
        "ExplainError",
        "a16c4578706c61696e4572726f72a164636f64656b4641494c5f434c4f534544",
    ),
    (
        "SubscribeEvents",
        "a16f5375627363726962654576656e7473a1656b696e6473f6",
    ),
];

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "odd-length hex fixture");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("fixture is hex"))
        .collect()
}

fn decode<T: serde::de::DeserializeOwned>(hex: &str) -> T {
    from_bytes(&bytes(hex)).expect("the fixture decodes")
}

fn to_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("encodes");
    out
}

fn from_bytes<T: serde::de::DeserializeOwned>(
    body: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(body)
}

/// The variant name of a request. No wildcard: a new `Request` variant does not
/// compile here until it is named, which is the point where someone has to decide
/// whether a protocol-0 fixture can exist for it (it cannot: a new request is
/// new, R1 of the design).
fn variant_name(request: &Request) -> &'static str {
    match request {
        Request::GetStatus => "GetStatus",
        Request::ActivateProfile(_) => "ActivateProfile",
        Request::Deactivate(_) => "Deactivate",
        Request::ListProfiles => "ListProfiles",
        Request::InspectFlow { .. } => "InspectFlow",
        Request::TraceRoute(_) => "TraceRoute",
        Request::ListRecentFlows { .. } => "ListRecentFlows",
        Request::GetAuditEntries { .. } => "GetAuditEntries",
        Request::VerifyAuditChain => "VerifyAuditChain",
        Request::RunDoctor => "RunDoctor",
        Request::ExplainError(_) => "ExplainError",
        Request::SubscribeEvents(_) => "SubscribeEvents",
        Request::SetIngress(_) => "SetIngress",
        Request::GetIngressAudit { .. } => "GetIngressAudit",
    }
}

// The protocol-0 types, copied. Fields that only exist to be decoded are never
// read, which is the whole of their job.

/// `StatusDto` as protocol 0 declared it.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct StatusDto0 {
    state: DaemonState,
    active_profile: Option<String>,
    adapters: Vec<AdapterHealthSummaryDto>,
    dns_protected: bool,
    kill_switch: bool,
    audit_head: Option<String>,
    version: String,
    last_error: Option<IpcError>,
}

/// The one `Response` variant these tests need, as an older client decodes it.
#[derive(Debug, Deserialize)]
enum Response0 {
    Status(StatusDto0),
}

/// `RouteTraceRequest` as protocol 0 declared it: no `profile_id`.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct RouteTraceRequest0 {
    app_id: Option<String>,
    dest_host: String,
    dest_port: u16,
    protocol: String,
    risk: String,
}

/// `Request` as a protocol-0 daemon declares it: twelve verbs, and nothing else
/// decodes.
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
enum Request0 {
    GetStatus,
    ActivateProfile(ActivateProfileRequest),
    Deactivate(DeactivateRequest),
    ListProfiles,
    InspectFlow { flow_id: String },
    TraceRoute(RouteTraceRequest0),
    ListRecentFlows { limit: usize },
    GetAuditEntries { limit: usize },
    VerifyAuditChain,
    RunDoctor,
    ExplainError(ExplainRequest),
    SubscribeEvents(SubscribeEventsRequest),
}

/// `FlowSummaryDto` as protocol 0 declared it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FlowSummaryDto0 {
    flow_id: String,
    app_id: String,
    destination: String,
    outcome: String,
}

/// `RouteTraceDto` as protocol 0 declared it.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct RouteTraceDto0 {
    route: ssk_netadmin::RouteKind,
    hops: Vec<String>,
    requires_attestation: bool,
}

/// A daemon of this build still understands every verb that an older client can
/// send, byte for byte as the older client encoded it.
#[test]
fn every_protocol_0_request_still_decodes() {
    for (name, hex) in PROTOCOL_0_REQUESTS {
        let request: Request = decode(hex);
        assert_eq!(
            variant_name(&request),
            name,
            "{name} decoded as another verb"
        );
    }
    // Two payloads, read back, so that a decoder that kept the verb and lost the
    // data would not pass.
    match decode::<Request>(PROTOCOL_0_REQUESTS[1].1) {
        Request::ActivateProfile(request) => {
            assert_eq!(request.profile_id, "default");
            assert_eq!(request.dest_host.as_deref(), Some("127.0.0.1"));
            assert_eq!(request.dest_port, Some(9));
        }
        other => panic!("{other:?}"),
    }
    match decode::<Request>(PROTOCOL_0_REQUESTS[5].1) {
        Request::TraceRoute(request) => {
            assert_eq!(request.dest_host, "example.org");
            assert_eq!(request.dest_port, 443);
            assert_eq!(
                request.profile_id, None,
                "a request that names no profile asks for none"
            );
        }
        other => panic!("{other:?}"),
    }
}

/// The reverse direction for the same twelve verbs: what this build encodes for
/// them is what a protocol-0 daemon decodes. Eleven are byte for byte what the
/// old build wrote; `TraceRoute` carries one extra key (`profile_id`), which a
/// protocol-0 daemon does not deny (R7) and ignores.
#[test]
fn a_new_client_writes_every_protocol_0_request_in_a_form_a_protocol_0_daemon_decodes() {
    for (name, hex) in PROTOCOL_0_REQUESTS {
        let request: Request = decode(hex);
        let written = to_bytes(&request);
        if name == "TraceRoute" {
            assert_ne!(written, bytes(hex), "the extra key is expected here");
        } else {
            assert_eq!(written, bytes(hex), "{name} is not written as it was");
        }
        let read: Request0 = from_bytes(&written)
            .unwrap_or_else(|error| panic!("a protocol-0 daemon cannot read {name}: {error}"));
        assert!(
            format!("{read:?}").starts_with(name),
            "{name} read as {read:?}"
        );
    }
}

#[test]
fn a_protocol_0_status_decodes_with_protocol_zero_and_no_ingress() {
    let status = match decode::<Response>(PROTOCOL_0_STATUS) {
        Response::Status(status) => status,
        other => panic!("a status frame decoded as {other:?}"),
    };
    assert_eq!(status.state, DaemonState::Inactive);
    assert_eq!(status.version, "0.1.0");
    assert_eq!(status.protocol, 0, "an absent protocol is protocol 0");
    assert!(
        status.ingress.is_none(),
        "an absent ingress block is a daemon that predates the proxy"
    );

    // And a client that needs more refuses it before it sends anything.
    assert!(status.require_protocol(0).is_ok());
    let refusal = status
        .require_protocol(1)
        .expect_err("protocol 0 does not speak protocol 1");
    assert_eq!(refusal.code, "DAEMON_TOO_OLD");
    assert_eq!(refusal.class, "Runtime");
    assert!(
        refusal
            .message
            .contains("speaks IPC protocol 0 but this client needs 1"),
        "{}",
        refusal.message
    );
    assert!(
        refusal
            .next_steps
            .iter()
            .any(|step| step.contains("Restart sskd")),
        "{:?}",
        refusal.next_steps
    );
}

/// A status as this build's daemon sends it, with every nested part holding
/// something, so that the old client has real keys to ignore at every level.
fn current_status() -> StatusDto {
    StatusDto {
        state: DaemonState::Protected,
        active_profile: Some("office".into()),
        adapters: vec![AdapterHealthSummaryDto {
            id: "exit".into(),
            health: "connected at activation; liveness not monitored".into(),
        }],
        dns_protected: true,
        kill_switch: true,
        audit_head: Some("abc".into()),
        version: "0.1.0".into(),
        last_error: None,
        protocol: IPC_PROTOCOL_VERSION,
        ingress: Some(IngressStatusDto {
            state: "armed".into(),
            coverage: "proxy_clients_only".into(),
            armed_profile: Some("office".into()),
            warnings: vec![IngressWarningDto {
                code: "PEER_CHECK_INACTIVE".into(),
                text: "No peer check is active.".into(),
            }],
            ..IngressStatusDto::default()
        }),
    }
}

#[test]
fn a_current_status_decodes_for_a_protocol_0_client() {
    let sent = to_bytes(&Response::Status(current_status()));
    let Response0::Status(read) = from_bytes(&sent).expect("a protocol-0 client reads the status");
    assert_eq!(read.state, DaemonState::Protected);
    assert_eq!(read.active_profile.as_deref(), Some("office"));
    assert_eq!(read.adapters.len(), 1);
    assert!(read.dns_protected && read.kill_switch);
    assert_eq!(read.audit_head.as_deref(), Some("abc"));
    assert_eq!(read.version, "0.1.0");
    assert!(read.last_error.is_none());
}

#[test]
fn set_ingress_is_an_unknown_variant_to_a_protocol_0_daemon() {
    let request = Request::SetIngress(ssk_ipc::SetIngressRequest {
        armed: true,
        profile_id: Some("office".into()),
        client: Some("cli".into()),
        expect_profile: None,
        expect_routing_digest: None,
    });
    let error = from_bytes::<Request0>(&to_bytes(&request))
        .expect_err("a protocol-0 daemon has no such verb");
    assert!(
        error.to_string().contains("unknown variant `SetIngress`"),
        "{error}"
    );
}

#[test]
fn get_ingress_audit_is_an_unknown_variant_to_a_protocol_0_daemon() {
    let request = Request::GetIngressAudit {
        limit: 5,
        before_seq: None,
        verify: false,
    };
    let error = from_bytes::<Request0>(&to_bytes(&request))
        .expect_err("a protocol-0 daemon has no such verb");
    assert!(
        error
            .to_string()
            .contains("unknown variant `GetIngressAudit`"),
        "{error}"
    );
}

/// Flows cross in both directions: an old row decodes with every new field at its
/// default, a new row decodes in an old reader with the four it knows.
#[test]
fn flow_summary_old_new_roundtrip() {
    let old = FlowSummaryDto0 {
        flow_id: "ingress:b1:7".into(),
        app_id: "local-proxy:unattributed".into(),
        destination: "example.org:443".into(),
        outcome: "closed".into(),
    };
    let new: FlowSummaryDto = from_bytes(&to_bytes(&old)).expect("a protocol-0 row decodes");
    assert_eq!(new.flow_id, old.flow_id);
    assert_eq!(new.outcome, old.outcome);
    assert_eq!(new.bytes_up, 0);
    assert_eq!(new.matched_rule, None);
    assert_eq!(new.destination_form, "");
    assert!(!new.peer_verified);

    let newer = FlowSummaryDto {
        peer: "uid:1000".into(),
        peer_verified: true,
        route: "Direct".into(),
        matched_rule: Some("echo".into()),
        bytes_up: 12,
        bytes_down: 34,
        started_ms: 1_700_000_000_000,
        destination_form: "plain".into(),
        ..new
    };
    let back: FlowSummaryDto0 =
        from_bytes(&to_bytes(&newer)).expect("a protocol-0 reader decodes a protocol-1 row");
    assert_eq!(back, old);
}

/// `TraceRoute` answers cross too: the preview a protocol-0 client reads has the
/// three keys it knows.
#[test]
fn a_current_route_trace_decodes_for_a_protocol_0_client() {
    let current = RouteTraceDto {
        route: ssk_netadmin::RouteKind::Direct,
        hops: vec![],
        requires_attestation: false,
        profile_used: Some("default".into()),
        profile_source: Some("default_profile".into()),
        evaluated_as: Some("legacy_activation".into()),
        app_id_used: Some("unknown-app".into()),
        refusal: None,
        guards_skipped: vec!["self_loop".into()],
    };
    let read: RouteTraceDto0 =
        from_bytes(&to_bytes(&current)).expect("a protocol-0 client reads the preview");
    assert_eq!(
        read,
        RouteTraceDto0 {
            route: ssk_netadmin::RouteKind::Direct,
            hops: vec![],
            requires_attestation: false,
        }
    );

    // The other way: an old daemon's preview has none of the new keys, and a
    // new client reads that as "profile not honoured" (R2), never as a profile.
    let old = RouteTraceDto0 {
        route: ssk_netadmin::RouteKind::Direct,
        hops: vec![],
        requires_attestation: false,
    };
    let read: RouteTraceDto = from_bytes(&to_bytes(&old)).expect("an old preview decodes");
    assert_eq!(read.profile_used, None);
    assert_eq!(read.profile_source, None);
    assert!(read.guards_skipped.is_empty());
}
