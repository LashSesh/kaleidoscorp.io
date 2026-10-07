//! What IPC protocol 1 adds to the wire (design `docs/M2_LOCAL_INGRESS_DESIGN.md`
//! 10.4, 10.5, 11.3, 11.4, 11.8), and the rule that keeps additions safe in both
//! directions: no IPC type denies unknown fields (11.2 R7). What an older peer
//! makes of these bytes is in `wire_protocol0.rs`.

use ciborium::Value;
use serde::de::DeserializeOwned;
use serde::Serialize;
use ssk_ipc::{
    ActivateProfileRequest, AdapterHealthSummaryDto, AuditEntryDto, ConfigDigestsDto,
    DeactivateRequest, DenialSummaryDto, DoctorCheckDto, DoctorReportDto, ExplainRequest,
    ExplainResponse, FlowInspectionDto, FlowSummaryDto, IngressAuditDto, IngressAuditEntryDto,
    IngressAuditPageDto, IngressControlsDto, IngressCountersDto, IngressEgressDto,
    IngressLimitsDto, IngressObservationsDto, IngressStatusDto, IngressVerifyDto,
    IngressWarningDto, IpcError, LastTransitionDto, ObservedRouteDto, ObservedSourceDto,
    PreviousRouteDto, ProfileSummaryDto, RejectedTargetDto, Request, Response, RouteTraceDto,
    RouteTraceRequest, SetIngressRequest, StatusDto, SubscribeEventsRequest,
    VerifyAuditChainResponse,
};

fn to_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("encodes");
    out
}

fn from_bytes<T: DeserializeOwned>(body: &[u8]) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::de::from_reader(body)
}

fn text(key: &str) -> Value {
    Value::Text(key.to_string())
}

const FUTURE_KEY: &str = "a_key_from_a_newer_build";

/// Adds a key this build has never heard of to every struct map under `value`
/// (never to the one-entry maps of an externally tagged enum, where a second key
/// would be a different shape and not an unknown field).
fn add_future_key_to_structs(value: &mut Value, struct_like: bool) {
    match value {
        Value::Map(entries) => {
            let tagged_enum = entries.len() == 1 && !struct_like;
            if !tagged_enum {
                entries.push((text(FUTURE_KEY), Value::Integer(1.into())));
            }
            for (_, inner) in entries.iter_mut() {
                add_future_key_to_structs(inner, false);
            }
        }
        Value::Array(items) => {
            for item in items {
                add_future_key_to_structs(item, false);
            }
        }
        _ => {}
    }
}

/// `sample` still decodes after its top-level struct gains an unknown key.
fn accepts_a_future_key<T: Serialize + DeserializeOwned>(what: &str, sample: &T) {
    let mut value = Value::serialized(sample).expect("sample converts");
    assert!(
        matches!(value, Value::Map(_)),
        "{what} is not a struct on the wire"
    );
    add_future_key_to_structs(&mut value, true);
    from_bytes::<T>(&to_bytes(&value))
        .unwrap_or_else(|error| panic!("{what} denies an unknown field: {error}"));
}

/// The same for every struct nested inside `sample` (which holds no enum that is
/// not a plain string).
fn accepts_a_future_key_at_every_level<T: Serialize + DeserializeOwned>(what: &str, sample: &T) {
    let mut value = Value::serialized(sample).expect("sample converts");
    add_future_key_to_structs(&mut value, true);
    from_bytes::<T>(&to_bytes(&value))
        .unwrap_or_else(|error| panic!("{what} denies an unknown field: {error}"));
}

/// A request whose payload is a struct (`SetIngress(..)`) or that is a struct
/// variant (`ListRecentFlows { .. }`) gains the key inside the variant's map.
fn request_accepts_a_future_key(request: &Request) {
    let mut value = Value::serialized(request).expect("request converts");
    let Value::Map(outer) = &mut value else {
        panic!("{request:?} has no payload");
    };
    let [(_, payload)] = outer.as_mut_slice() else {
        panic!("{request:?} is not externally tagged");
    };
    add_future_key_to_structs(payload, true);
    from_bytes::<Request>(&to_bytes(&value))
        .unwrap_or_else(|error| panic!("{request:?} denies an unknown field: {error}"));
}

fn populated_ingress() -> IngressStatusDto {
    IngressStatusDto {
        state: "armed".into(),
        coverage: "proxy_clients_only".into(),
        listen: Some("127.0.0.1:10800".into()),
        configured_listen: Some("127.0.0.1:10800".into()),
        protocols: vec!["socks5".into()],
        armed_profile: Some("office".into()),
        arm_profile: Some("office".into()),
        controls: IngressControlsDto {
            peer_check: true,
            hardening: "required".into(),
            ..IngressControlsDto::default()
        },
        counters: IngressCountersDto {
            admitted: 3,
            rejected_target: RejectedTargetDto {
                numeric_alias: 1,
                ..RejectedTargetDto::default()
            },
            ..IngressCountersDto::default()
        },
        last_error: Some(IpcError::new("Runtime", "INGRESS_BUSY", "busy").retriable()),
        last_denial: Some(DenialSummaryDto {
            host: "example.org".into(),
            port: 443,
            reason_code: "NO_POLICY_MATCH".into(),
            rule_id: None,
        }),
        epoch: 4,
        trips: 1,
        last_transition: Some(LastTransitionDto {
            epoch: 4,
            kind: "armed".into(),
            reason_code: String::new(),
            actor: Some("uid:1000".into()),
        }),
        limits: IngressLimitsDto {
            max_connections: 256,
            max_connections_effective: 72,
            clamped_by: Some("fd_limit".into()),
            fd_soft_limit: Some(400),
            ..IngressLimitsDto::default()
        },
        observations: IngressObservationsDto {
            route_v4: ObservedRouteDto {
                status: "observed".into(),
                probe: "192.0.2.1".into(),
                interface_index: Some(7),
                interface_alias: Some("Ethernet".into()),
                previous: Some(PreviousRouteDto {
                    interface_index: Some(9),
                    interface_alias: None,
                    replaced_ago_ms: 1_500,
                }),
                ..ObservedRouteDto::default()
            },
            last_direct_source: Some(ObservedSourceDto {
                address: "192.168.1.5".into(),
                kind: "direct".into(),
                flow_id: "ingress:b1:7".into(),
                age_ms: 20,
            }),
            ..IngressObservationsDto::default()
        },
        warnings: vec![IngressWarningDto {
            code: "PEER_CHECK_INACTIVE".into(),
            text: "No peer check is active.".into(),
        }],
        ..IngressStatusDto::default()
    }
}

/// R7: it is what makes an additive field safe in both directions, so it is
/// tested for every type that crosses the socket, the old ones included.
#[test]
fn ipc_types_do_not_deny_unknown_fields() {
    // The old DTOs.
    accepts_a_future_key(
        "AdapterHealthSummaryDto",
        &AdapterHealthSummaryDto {
            id: "a".into(),
            health: "ok".into(),
        },
    );
    accepts_a_future_key("IpcError", &IpcError::new("Runtime", "X", "y"));
    accepts_a_future_key(
        "ActivateProfileRequest",
        &ActivateProfileRequest {
            profile_id: "p".into(),
            dest_host: None,
            dest_port: None,
        },
    );
    accepts_a_future_key(
        "DeactivateRequest",
        &DeactivateRequest {
            release_kill_switch: false,
        },
    );
    accepts_a_future_key(
        "ProfileSummaryDto",
        &ProfileSummaryDto {
            id: "p".into(),
            name: "P".into(),
        },
    );
    accepts_a_future_key(
        "FlowInspectionDto",
        &FlowInspectionDto {
            descriptor: ssk_netadmin::FlowDescriptor::new(
                "app",
                "example.org",
                443,
                ssk_netadmin::ProtocolKind::Tcp,
                ssk_netadmin::RiskLevel::Low,
            ),
            matched_rule: None,
            action: ssk_netadmin::PolicyAction::Deny,
            route: ssk_netadmin::RouteKind::Direct,
            requires_attestation: false,
        },
    );
    accepts_a_future_key(
        "RouteTraceRequest",
        &RouteTraceRequest {
            app_id: None,
            dest_host: "example.org".into(),
            dest_port: 443,
            protocol: "tcp".into(),
            risk: "low".into(),
            profile_id: Some("office".into()),
        },
    );
    accepts_a_future_key(
        "RouteTraceDto",
        &RouteTraceDto {
            route: ssk_netadmin::RouteKind::Direct,
            hops: vec![],
            requires_attestation: false,
            profile_used: Some("office".into()),
            profile_source: Some("request".into()),
            evaluated_as: Some("ingress".into()),
            app_id_used: Some("local-proxy:unattributed".into()),
            refusal: None,
            guards_skipped: vec![],
        },
    );
    accepts_a_future_key(
        "FlowSummaryDto",
        &FlowSummaryDto {
            flow_id: "f".into(),
            app_id: "a".into(),
            destination: "d".into(),
            outcome: "closed".into(),
            ..FlowSummaryDto::default()
        },
    );
    accepts_a_future_key(
        "AuditEntryDto",
        &AuditEntryDto {
            entry_id: "e".into(),
            flow_id: "f".into(),
            outcome: "o".into(),
            route_kind_summary: "r".into(),
            epoch: 1,
            prev_hash: "p".into(),
            entry_hash: "h".into(),
        },
    );
    accepts_a_future_key(
        "VerifyAuditChainResponse",
        &VerifyAuditChainResponse {
            ok: true,
            head: None,
            broken_at: None,
        },
    );
    accepts_a_future_key(
        "DoctorCheckDto",
        &DoctorCheckDto {
            name: "n".into(),
            ok: true,
            detail: "d".into(),
            next_step: None,
        },
    );
    accepts_a_future_key("DoctorReportDto", &DoctorReportDto { checks: vec![] });
    accepts_a_future_key("ExplainRequest", &ExplainRequest { code: "C".into() });
    accepts_a_future_key(
        "ExplainResponse",
        &ExplainResponse {
            summary: "s".into(),
            details: "d".into(),
            next_steps: vec![],
        },
    );
    accepts_a_future_key(
        "SubscribeEventsRequest",
        &SubscribeEventsRequest { kinds: None },
    );

    // The status and the whole ingress block under it, level by level.
    accepts_a_future_key_at_every_level(
        "StatusDto",
        &StatusDto {
            last_error: Some(IpcError::new("Runtime", "X", "y")),
            ingress: Some(populated_ingress()),
            protocol: ssk_ipc::IPC_PROTOCOL_VERSION,
            ..StatusDto::default()
        },
    );
    accepts_a_future_key("IngressStatusDto", &populated_ingress());
    accepts_a_future_key("IngressControlsDto", &IngressControlsDto::default());
    accepts_a_future_key("IngressCountersDto", &IngressCountersDto::default());
    accepts_a_future_key("RejectedTargetDto", &RejectedTargetDto::default());
    accepts_a_future_key("IngressAuditDto", &IngressAuditDto::default());
    accepts_a_future_key("DenialSummaryDto", &DenialSummaryDto::default());
    accepts_a_future_key("LastTransitionDto", &LastTransitionDto::default());
    accepts_a_future_key("IngressLimitsDto", &IngressLimitsDto::default());
    accepts_a_future_key("ConfigDigestsDto", &ConfigDigestsDto::default());
    accepts_a_future_key("IngressEgressDto", &IngressEgressDto::default());
    accepts_a_future_key("IngressObservationsDto", &IngressObservationsDto::default());
    accepts_a_future_key("ObservedRouteDto", &ObservedRouteDto::default());
    accepts_a_future_key("PreviousRouteDto", &PreviousRouteDto::default());
    accepts_a_future_key("ObservedSourceDto", &ObservedSourceDto::default());
    accepts_a_future_key("IngressWarningDto", &IngressWarningDto::default());

    // The audit page.
    accepts_a_future_key("IngressAuditPageDto", &IngressAuditPageDto::default());
    accepts_a_future_key("IngressAuditEntryDto", &IngressAuditEntryDto::default());
    accepts_a_future_key("IngressVerifyDto", &IngressVerifyDto::default());

    // Every request that has a payload, the new ones included.
    for request in [
        Request::ActivateProfile(ActivateProfileRequest {
            profile_id: "p".into(),
            dest_host: None,
            dest_port: None,
        }),
        Request::Deactivate(DeactivateRequest {
            release_kill_switch: true,
        }),
        Request::InspectFlow {
            flow_id: "f".into(),
        },
        Request::TraceRoute(RouteTraceRequest {
            app_id: None,
            dest_host: "example.org".into(),
            dest_port: 443,
            protocol: "tcp".into(),
            risk: "low".into(),
            profile_id: None,
        }),
        Request::ListRecentFlows { limit: 5 },
        Request::GetAuditEntries { limit: 5 },
        Request::ExplainError(ExplainRequest { code: "C".into() }),
        Request::SubscribeEvents(SubscribeEventsRequest { kinds: None }),
        Request::SetIngress(SetIngressRequest {
            armed: true,
            profile_id: None,
            client: None,
            expect_profile: None,
            expect_routing_digest: None,
        }),
        Request::GetIngressAudit {
            limit: 5,
            before_seq: Some(9),
            verify: true,
        },
    ] {
        request_accepts_a_future_key(&request);
    }

    // And the one new response, as it is framed.
    let mut value = Value::serialized(&Response::IngressAudit(IngressAuditPageDto::default()))
        .expect("response converts");
    let Value::Map(outer) = &mut value else {
        panic!("a response is externally tagged");
    };
    let [(_, page)] = outer.as_mut_slice() else {
        panic!("a response has one key");
    };
    add_future_key_to_structs(page, true);
    from_bytes::<Response>(&to_bytes(&value)).expect("a page with an unknown key decodes");
}

#[test]
fn set_ingress_request_cbor_roundtrip() {
    let full = Request::SetIngress(SetIngressRequest {
        armed: true,
        profile_id: Some("office".into()),
        client: Some("desktop".into()),
        expect_profile: Some("office".into()),
        expect_routing_digest: Some("a".repeat(64)),
    });
    let sent = to_bytes(&full);
    let read: Request = from_bytes(&sent).expect("decodes");
    assert_eq!(to_bytes(&read), sent, "what is decoded is what was sent");
    match read {
        Request::SetIngress(request) => {
            assert!(request.armed);
            assert_eq!(request.profile_id.as_deref(), Some("office"));
            assert_eq!(request.client.as_deref(), Some("desktop"));
            assert_eq!(request.expect_profile.as_deref(), Some("office"));
            assert_eq!(request.expect_routing_digest, Some("a".repeat(64)));
        }
        other => panic!("{other:?}"),
    }

    // A request of only `armed` is what the CLI sends for "the default
    // profile": the four optional fields are absent from the bytes, not null.
    let minimal = Value::Map(vec![(
        text("SetIngress"),
        Value::Map(vec![(text("armed"), Value::Bool(false))]),
    )]);
    match from_bytes::<Request>(&to_bytes(&minimal)).expect("a minimal request decodes") {
        Request::SetIngress(request) => {
            assert!(!request.armed);
            assert_eq!(request.profile_id, None);
            assert_eq!(request.client, None);
            assert_eq!(request.expect_profile, None);
            assert_eq!(request.expect_routing_digest, None);
        }
        other => panic!("{other:?}"),
    }

    // `armed` is the whole meaning of the request. An omitted one must not
    // become `false`, which would turn a malformed request into a disarm.
    let without_armed = Value::Map(vec![(text("SetIngress"), Value::Map(vec![]))]);
    assert!(
        from_bytes::<Request>(&to_bytes(&without_armed)).is_err(),
        "a SetIngress without `armed` decoded"
    );
}

#[test]
fn get_ingress_audit_roundtrip() {
    let request = Request::GetIngressAudit {
        limit: 20,
        before_seq: Some(41),
        verify: true,
    };
    let sent = to_bytes(&request);
    match from_bytes::<Request>(&sent).expect("decodes") {
        Request::GetIngressAudit {
            limit,
            before_seq,
            verify,
        } => {
            assert_eq!(limit, 20);
            assert_eq!(before_seq, Some(41));
            assert!(verify);
        }
        other => panic!("{other:?}"),
    }

    // A reader that sends only a limit gets the newest page without a verify.
    let only_limit = Value::Map(vec![(
        text("GetIngressAudit"),
        Value::Map(vec![(text("limit"), Value::Integer(3.into()))]),
    )]);
    match from_bytes::<Request>(&to_bytes(&only_limit)).expect("decodes") {
        Request::GetIngressAudit {
            limit,
            before_seq,
            verify,
        } => {
            assert_eq!((limit, before_seq, verify), (3, None, false));
        }
        other => panic!("{other:?}"),
    }

    // The answer: `body` is carried verbatim, byte for byte, so a client can
    // recompute the hash itself.
    let body = "{\"k\":\"line\\u2028two\"}".to_string();
    let page = IngressAuditPageDto {
        entries: vec![IngressAuditEntryDto {
            seq: 41,
            entry_hash: "e".repeat(64),
            prev_hash: "p".repeat(64),
            body: body.clone(),
        }],
        head: Some("e".repeat(64)),
        entries_total: 42,
        oldest_seq: Some(1),
        truncated_by_bytes: false,
        verification: Some(IngressVerifyDto {
            ok: true,
            partial: false,
            entries_checked: 42,
            anchored_at_continue: false,
            error: None,
        }),
    };
    let sent = to_bytes(&Response::IngressAudit(page));
    match from_bytes::<Response>(&sent).expect("decodes") {
        Response::IngressAudit(read) => {
            assert_eq!(read.entries.len(), 1);
            assert_eq!(read.entries[0].seq, 41);
            assert_eq!(read.entries[0].body, body);
            assert_eq!(read.entries_total, 42);
            assert_eq!(read.oldest_seq, Some(1));
            assert!(read
                .verification
                .is_some_and(|v| v.ok && v.entries_checked == 42));
        }
        other => panic!("{other:?}"),
    }
}

/// The ingress block as the daemon sends it survives the wire unchanged, and a
/// block with nothing in it (every key absent) reads as "unknown, not covered":
/// no state word, no coverage word, and the constant `system_wide` false.
#[test]
fn ingress_status_roundtrip_and_an_empty_block_reads_as_unknown() {
    let sent = to_bytes(&populated_ingress());
    let read: IngressStatusDto = from_bytes(&sent).expect("decodes");
    assert_eq!(to_bytes(&read), sent);
    assert_eq!(read.state, "armed");
    assert_eq!(read.counters.rejected_target.numeric_alias, 1);
    assert_eq!(read.limits.clamped_by.as_deref(), Some("fd_limit"));

    let nothing = Value::Map(vec![]);
    let empty: IngressStatusDto = from_bytes(&to_bytes(&nothing)).expect("an empty map decodes");
    assert_eq!(empty.state, "");
    assert_eq!(empty.coverage, "");
    assert!(!empty.system_wide);
    assert!(empty.listen.is_none() && empty.warnings.is_empty());

    // The same through the status: a daemon that sends `ingress: null` and one
    // that sends no key at all are the same daemon.
    let status = StatusDto::default();
    let mut value = Value::serialized(&status).expect("converts");
    if let Value::Map(entries) = &mut value {
        entries.retain(|(key, _)| key != &text("ingress") && key != &text("protocol"));
    }
    let read: StatusDto = from_bytes(&to_bytes(&value)).expect("decodes without the new keys");
    assert_eq!(read.protocol, 0);
    assert!(read.ingress.is_none());
}

// --- An absent key, in every part of the ingress block ------------------------
//
// The block is meant to grow additively inside protocol 1 (design 10.4: "All
// fields are `#[serde(default)]`"), so a daemon built before a key existed
// sends a part without it, and a newer client must still read the whole status.
// That holds only while every part, not just the outermost, is
// `#[serde(default)]` as a whole. The tests above send either a complete block
// or an empty map (where the parent's default fills in the nested values), so
// they cannot see a nested part lose its default. These do, and they find the
// parts by walking the block, so a part added later is covered without being
// listed here.

/// The one subtree the walk does not own: `IpcError` is a protocol-0 type whose
/// `code`, `class` and `message` have always been required, and an error without
/// a code is not an error to be defaulted.
fn is_not_ours(path: &[String]) -> bool {
    path.len() == 1 && path[0] == "last_error"
}

fn child<'a>(value: &'a Value, step: &str) -> Option<&'a Value> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(key, _)| matches!(key, Value::Text(k) if k == step))
            .map(|(_, inner)| inner),
        Value::Array(items) => step.parse::<usize>().ok().and_then(|i| items.get(i)),
        _ => None,
    }
}

fn child_mut<'a>(value: &'a mut Value, step: &str) -> Option<&'a mut Value> {
    match value {
        Value::Map(entries) => entries
            .iter_mut()
            .find(|(key, _)| matches!(key, Value::Text(k) if k == step))
            .map(|(_, inner)| inner),
        Value::Array(items) => step.parse::<usize>().ok().and_then(|i| items.get_mut(i)),
        _ => None,
    }
}

fn at<'a>(value: &'a Value, path: &[String]) -> Option<&'a Value> {
    path.iter().try_fold(value, |node, step| child(node, step))
}

fn at_mut<'a>(value: &'a mut Value, path: &[String]) -> Option<&'a mut Value> {
    let mut node = value;
    for step in path {
        node = child_mut(node, step)?;
    }
    Some(node)
}

/// Every node under `value` with its path (map keys and array indexes), without
/// descending into what `is_not_ours`.
fn nodes(value: &Value) -> Vec<(Vec<String>, &Value)> {
    fn go<'a>(value: &'a Value, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, &'a Value)>) {
        out.push((path.clone(), value));
        if is_not_ours(path) {
            return;
        }
        match value {
            Value::Map(entries) => {
                for (key, inner) in entries {
                    let Value::Text(key) = key else {
                        panic!("a struct key is text, not {key:?}");
                    };
                    path.push(key.clone());
                    go(inner, path, out);
                    path.pop();
                }
            }
            Value::Array(items) => {
                for (index, inner) in items.iter().enumerate() {
                    path.push(index.to_string());
                    go(inner, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    go(value, &mut Vec::new(), &mut out);
    out
}

/// What a field reads as when its key is absent, by the rule of the block: no
/// state word, no coverage word, a flag is off, a counter is zero, an optional
/// part is missing. A default that "reads well" (an `ok` state, say) is the
/// failure this guards against.
fn is_unknown_default(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Integer(number) => i128::from(*number) == 0,
        Value::Text(word) => word.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Map(entries) => entries.iter().all(|(_, inner)| is_unknown_default(inner)),
        _ => false,
    }
}

/// Sets every scalar that is at its default to a value that is not, so that a
/// key dropped later is seen to come back as the default and not to have been
/// the default all along. A new scalar field needs no edit here.
fn move_scalars_off_their_defaults(value: &mut Value) {
    match value {
        Value::Bool(flag) => *flag = true,
        Value::Integer(number) if i128::from(*number) == 0 => *number = 7.into(),
        Value::Text(word) if word.is_empty() => *word = "x".into(),
        Value::Map(entries) => {
            for (_, inner) in entries {
                move_scalars_off_their_defaults(inner);
            }
        }
        Value::Array(items) => {
            for inner in items {
                move_scalars_off_their_defaults(inner);
            }
        }
        _ => {}
    }
}

/// A block with every part present: each optional part is `Some`, each list has
/// an element, each scalar is off its default. The seed only says which optional
/// parts and lists exist (the walk cannot guess the type of a `null`); the
/// scalars are filled in generically.
fn every_part_present() -> IngressStatusDto {
    let seed = IngressStatusDto {
        listen: Some(String::new()),
        configured_listen: Some(String::new()),
        protocols: vec![String::new()],
        armed_profile: Some(String::new()),
        arm_profile: Some(String::new()),
        audit: IngressAuditDto {
            head: Some(String::new()),
            oldest_ts_ms: Some(0),
            dest_key_id: Some(String::new()),
            ..IngressAuditDto::default()
        },
        last_error: Some(IpcError::new("Runtime", "INGRESS_BUSY", "busy")),
        last_denial: Some(DenialSummaryDto {
            rule_id: Some(String::new()),
            ..DenialSummaryDto::default()
        }),
        retry_hint: Some(String::new()),
        last_transition: Some(LastTransitionDto {
            actor: Some(String::new()),
            ..LastTransitionDto::default()
        }),
        phase: Some(String::new()),
        limits: IngressLimitsDto {
            clamped_by: Some(String::new()),
            fd_soft_limit: Some(0),
            ..IngressLimitsDto::default()
        },
        observations: IngressObservationsDto {
            route_v4: every_part_of_a_route(),
            route_v6: every_part_of_a_route(),
            last_direct_source: Some(ObservedSourceDto::default()),
            ..IngressObservationsDto::default()
        },
        warnings: vec![IngressWarningDto::default()],
        ..IngressStatusDto::default()
    };
    let mut value = Value::serialized(&seed).expect("seed converts");
    move_scalars_off_their_defaults(&mut value);
    from_bytes(&to_bytes(&value)).expect("the filled block decodes")
}

fn every_part_of_a_route() -> ObservedRouteDto {
    ObservedRouteDto {
        interface_index: Some(0),
        interface_alias: Some(String::new()),
        sampled_age_ms: Some(0),
        unchanged_for_ms: Some(0),
        previous: Some(PreviousRouteDto {
            interface_index: Some(0),
            interface_alias: Some(String::new()),
            replaced_ago_ms: 0,
        }),
        ..ObservedRouteDto::default()
    }
}

/// Decodes `variant` (the full block with one change) and checks that the part
/// that changed reads as the unknown default and that nothing else moved.
fn assert_reads_as_unknown(original: &Value, variant: &Value, changed: &[String], what: &str) {
    let read: IngressStatusDto = from_bytes(&to_bytes(variant))
        .unwrap_or_else(|error| panic!("{what} makes the whole block undecodable: {error}"));
    let reread = Value::serialized(&read).expect("converts");
    let got = at(&reread, changed).unwrap_or_else(|| panic!("{what}: nothing at the path"));
    assert!(
        is_unknown_default(got),
        "{what} does not read as the unknown default but as {got:?}"
    );
    let mut expected = original.clone();
    *at_mut(&mut expected, changed).expect("the path exists in the original") = got.clone();
    assert_eq!(reread, expected, "{what} changed something else");
}

#[test]
fn the_sample_for_the_absent_key_tests_leaves_nothing_at_its_default() {
    // If a field stayed at its default here, dropping its key would change
    // nothing and the tests below could not tell. A new optional part or list
    // that is not in `every_part_present` fails here, by its path.
    let original = Value::serialized(&every_part_present()).expect("converts");
    let at_default: Vec<String> = nodes(&original)
        .into_iter()
        .filter(|(_, node)| !matches!(node, Value::Map(_)) && is_unknown_default(node))
        .map(|(path, _)| path.join("/"))
        .collect();
    assert!(
        at_default.is_empty(),
        "every_part_present leaves {at_default:?} at the default: populate it"
    );
}

/// Dropping any one key of any part, at any depth, leaves a status that decodes,
/// with that key as the unknown default and every other value unchanged. A part
/// without `#[serde(default)]` as a whole fails on the first of its keys.
#[test]
fn a_dropped_key_in_any_part_of_the_ingress_block_reads_as_the_unknown_default() {
    let original = Value::serialized(&every_part_present()).expect("converts");
    let mut dropped = Vec::new();
    for (path, _) in nodes(&original) {
        let Some((key, parent)) = path.split_last() else {
            continue;
        };
        if !matches!(at(&original, parent), Some(Value::Map(_))) {
            continue;
        }
        let mut variant = original.clone();
        let Some(Value::Map(entries)) = at_mut(&mut variant, parent) else {
            panic!("no map at {parent:?}");
        };
        entries.retain(|(name, _)| name != &text(key));
        let what = format!("dropping `{}`", path.join("/"));
        assert_reads_as_unknown(&original, &variant, &path, &what);
        dropped.push(path.join("/"));
    }

    // The walk reached the part of every type of the block (the second route
    // and the list element included). A floor for the walk itself: a part added
    // later is found by the walk and the sample check above, not by this list.
    for reached in [
        "state",
        "controls/peer_check",
        "counters/accepted",
        "counters/rejected_target/localhost",
        "audit/state",
        "last_denial/host",
        "last_transition/kind",
        "limits/max_connections",
        "config/routing",
        "egress/direct_resolver",
        "observations/label",
        "observations/route_v4/status",
        "observations/route_v4/previous/replaced_ago_ms",
        "observations/route_v6/status",
        "observations/last_direct_source/flow_id",
        "warnings/0/code",
    ] {
        assert!(
            dropped.iter().any(|path| path == reached),
            "the walk never dropped `{reached}`"
        );
    }
}

/// The same for a part that arrives empty (`{}`) inside a block that is
/// otherwise there: what a daemon that knows the part but has nothing to say
/// for it sends, and what the empty-map test above shows only for the block as
/// a whole.
#[test]
fn an_empty_part_inside_the_ingress_block_reads_as_the_unknown_default() {
    let original = Value::serialized(&every_part_present()).expect("converts");
    let mut emptied = 0;
    for (path, node) in nodes(&original) {
        if !matches!(node, Value::Map(_)) || is_not_ours(&path) {
            continue;
        }
        let mut variant = original.clone();
        *at_mut(&mut variant, &path).expect("the path exists") = Value::Map(vec![]);
        assert_reads_as_unknown(
            &original,
            &variant,
            &path,
            &format!("emptying `/{}`", path.join("/")),
        );
        emptied += 1;
    }
    // A floor for the walk itself, not a list: the block and fourteen nested
    // types, of which the route and its `previous` occur twice (v4 and v6), are
    // seventeen maps. A part added later raises the count and is emptied like
    // the rest.
    assert!(emptied >= 17, "the walk found only {emptied} parts");
}
