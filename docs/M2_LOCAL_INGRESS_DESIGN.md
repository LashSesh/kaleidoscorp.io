# Milestone 2 design: local proxy ingress for sskd

> **Status: PROPOSED, UNDER REVIEW. Not accepted. Nothing in this document is implemented.**
>
> Produced on 2026-10-06 by a multi-agent design process (8 codebase readers, 3 competing
> designs, 3 judges, a synthesis and a completeness critic). The critic's verdict on this
> synthesis is **needs-revision**: see [Appendix A](#appendix-a-review-findings-unresolved).
> The decisions the product owner still has to make are in [Appendix B](#appendix-b-open-questions-for-the-product-owner).
>
> Execution order agreed for this work:
>
> 1. **Foundation commits first** (`C-N1`, `C-N2`, `C-P1`, `C-I1`, `C-S2`, `C-S3` below). Each fixes a
>    defect that exists in the repository today, independent of any listener.
> 2. **The ingress proper** (`C-C*`, `C-W1`, `C-G*`, `C-E*`, `C-F*`) only after Appendix A is resolved
>    in this document and Appendix B is answered. Do not implement it from this text as it stands.
>
> Everything below was written by reading the code; **no `cargo` command was run for the design**.
> Line numbers drift; function and area names are the stable reference.

---

# Milestone 2 design: local proxy ingress for sskd (final synthesis)

Repo `/home/user/kaleidoscorp.io`, HEAD `f748e10`, working tree clean when read. Design only; nothing in the repo was edited, built or run. Status of this document: proposed; becomes ADR 0009 (see C-00 in the commit plan).

## 0. Provenance: what this is made of

* **Base: the security-first design** (judge totals 20 vs 18 vs 15). Its spine is kept: ingress inside `ssk-daemon`, receipt type-state for audit ordering, disarmed-by-default listener, `hardening: required`, no local DNS for client-supplied names, route guards, own audit ledger with group commit, deny-lints on the ingress tree, SOCKS5 first.
* **Grafted from the desktop-product design:** first-occurrence-durable denial coalescer, matched-rule-bound special-use exemption, machine-readable coverage vocabulary, peer check and budget ordering, runtime teardown before lock release, bind retry on re-arm, `FLOW_NOT_RETAINED` truthfulness, GUI v3 contract (specified, scheduled M2.4), pinned-address Direct dial (as a follow-on, not in the M2 spine).
* **Grafted from the minimal-diff design:** audit-before-reply for denials, catch-all accept backoff (no errno classification), config floors consistent with test values, `FLOWS`-honesty, pure shared `decide()`, `pub` modules so each commit is dead-code clean, wrapping the real `NetcoreDataPlane` for fault injection (`EgressSession::new` is `pub(crate)`).
* **Rejected, with reasons (section 19):** gating the proxy on the held probe session; one-way rewrite of `audit.json`; publish-on-drop status guard; overloading `ActivateProfile` as the arm verb; trip-on-first-panic; capacity latch; allow-list second key for special-use targets.

## 1. What I verified at HEAD, what I inherited, what I did not check

Verified by reading the code in this session (locations are function/area names; line numbers drift):

* `RouteExecutor::connect` is `pub`, token-free, and its `RouteKind::Fallback` arm retries the fallback (including `Direct`) after any primary error. The planner never emits `Fallback`; that absence is the only thing keeping it unreachable.
* `DataPlane::connect_route(AdmissionToken)` is the token-consuming seam. `AdmissionToken` has private `route/host/port`, derives only `Debug`, is minted only by `RouteOrchestrator::admit`, which checks flow-id equality, denied route, attestation, empty/whitespace/control host, port 0, Udp/Dns/Custom. It does not validate host syntax. Its derived `Debug` would print `HopSpec.auth`.
* `EgressSession::new` is `pub(crate)`; `transport_mut` exists and has no caller anywhere (grep over `crates/` and `apps/`).
* `ActivateProfile` holds the tokio `Mutex<Inner>` across `connect_route().await`; a plan error sets FailClosed with no audit entry; `clear_egress()` runs before the new attempt; `Deactivate` is gated by `KILL_SWITCH_ARMED` in FailClosed. `status()` reads the entire ledger on every `GetStatus` and calls `refuse_activation` on a read error. The adapter health string is the constant `"live (real, connected)"` (supervisor.rs:326).
* `direct::connect_tcp` builds `format!("{host}:{port}")`; `http_connect` interpolates `CONNECT {host}:{port}` unbracketed and does no control-character check of its own (admit is the only guard).
* `MatchCriteria::matches` applies `dest_suffix` to IP-literal hosts (`"10.0.0.1".ends_with(".0.1")` is true for suffix `0.1`).
* IPC accept loops (`ssk-ipc/src/server.rs`, Unix and named-pipe) return on the first `accept()`/`connect()` error with `?`; `main.rs` then exits the daemon. `Request::GetAuditEntries { limit }` is a struct variant; `VerifyAuditChain` is a unit variant; `clamp_request_limits` has an `other => other` arm. `StatusDto` struct literals exist in `supervisor.rs` (builder), `ssk-desktop-client/src/tests.rs`, `apps/desktop/tests/webview_status.rs`.
* `ssk-config`: `CURRENT_CONFIG_VERSION = 4`; the `3 =>` migration arm inserts `routing` and deserializes directly (so it breaks when the version moves); CI `breaking_change_guard` only echoes.
* `ssk-diag`: crash records are written with `sync_all` per panic and are not capped (`MAX_LOG_FILES = 14` applies to logs only). Release profile is `panic = "unwind"`.
* `main.rs::run`: `drop(lock)` runs before the runtime is dropped at function exit; the 'drain' is `timeout(DRAIN_DEADLINE, yield_now())`.
* ADR 0008 and `dependency_closure.rs`: exact 17-crate `EXPECTED_CLOSURE`, `DENIED_CORE` of 9 including `ssk-runtime` and `ssk-netanalysis`. `unsafe_code = "forbid"` workspace-wide; `ssk-winhost` sets `allow`.
* `ssk-ipc` already uses `rustix = 0.38` with feature `process`; `ssk-daemon` pulls `rustix` with `fs`,`std` only. `blake3`, `hex`, `proptest`, `tempfile` are workspace dependencies. `socket2 = "0.6"` is used by `ssk-winhost` and is in `Cargo.lock`.

Inherited from the readers and not re-verified by me: every Windows behaviour (`SO_EXCLUSIVEADDRUSE`, owner-PID tables, named-pipe accept), CI behaviour, measured ledger timings, the `/proc/net/tcp` column layout (one reader probe), TLS adapter behaviour, all test counts. **I did not run `cargo`.** Everything in this document is unbuilt.

## 2. Shape in one page

* The ingress is a **second front end of the ADR 0008 path**: per connection `FlowRecord -> PolicyEngine::evaluate -> RouteOrchestrator::plan/admit -> AdmissionToken -> DataPlane::connect_route -> EgressSession::transport_mut`. It never calls `RouteExecutor::connect/probe`, never builds a `RouteKind`, never opens a socket other than the accepted client socket (a source-scan test enforces this).
* **Placement:** `crates/ssk-daemon/src/ingress/`. No new workspace crate, no new workspace edge, `dependency_closure.rs` untouched. New external deps: `blake3`, `hex`, `rustix` feature `process` (daemon, unix), `proptest` (dev), `socket2` (netcore, optional keepalive commit).
* **Independent of `DaemonState`.** The ingress has its own control object (`IngressShared`), gate, ledger and status words. `Protected` keeps meaning 'one held egress session'. Arming, flows, denials and trips never set `Protected`, `Active`, `Degraded` or `FailClosed`; `dns_protected` and `kill_switch` are never derived from the ingress. The ingress does **not** depend on `ssk activate`, a held probe session, or `--dest`.
* **Fail-closed lifecycle:** `enabled: false` by default; an enabled listener starts **disarmed** (accept, read nothing, close); arming is an explicit operator action (`SetIngress`, or the explicit config opt-in `arm_on_start`) and is itself durably audited before the gate opens; any audit/accept/panic-budget fault **latches** the gate to `tripped`; `tripped` and `unavailable` are cleared by an explicit re-arm that first re-verifies the ledger and rebinds, so no daemon restart is needed.
* **Type-level ordering:** `dial()` takes `&PendingReceipt`; the success reply and `pump()` take `&ResultReceipt`; receipts have private constructors inside `audit.rs`. No dial without a durable pending record; no byte without a durable result record.
* **Protocols in M2:** SOCKS5 CONNECT, NO_AUTH only. HTTP CONNECT is fully specified (section 20) and scheduled as M2.1; it is a separate parser, not required for acceptance.
* **Windows:** hardened bind and owner check are commits W1/W2 inside the M2 series (fail-closed until they land: `hardening: required` leaves the ingress `unavailable` on Windows). They are the only place `unsafe` appears.

## 3. Rules the implementation must keep (what a reviewer checks)

1. No byte path without (admission token + durable pending + durable result). A denial has no byte path at all.
2. The dialled `(host, port)` is the token's, which is the canonical `Target` that passed `target::canonicalize` and the guards; client text is never re-read after that point.
3. No local DNS for client-supplied names. Proxied routes forward the name unresolved. `Direct` is accepted only for IP-literal targets (`DIRECT_REQUIRES_LITERAL`) in M2.
4. No fallback of any kind, no retry, no second token. `RouteKind::Fallback` becomes non-executable in the executor and is refused by the ingress route guard.
5. A per-flow denial or failure never touches global state (`refuse_activation`, `record_task_failure`, `spawn_supervised` are never used for flows). Only ingress-local latches change ingress state.
6. Peer authorization runs before the first byte is read **and before any shared budget (accept bucket, permit, ledger) is charged**; `Unknown` means refuse.
7. Every limit is explicit, validated with a ceiling; 0 never means unlimited. Raw client text is logged only at DEBUG, escaped and truncated; records carry validated text only.
8. Status never claims more than is enforced (section 10). No string produced by the ingress contains the words in the forbidden list (a test enforces it, and the coverage notice below was written to pass that test).
9. A special-use destination (loopback, RFC1918, link-local, metadata, fake-IP range) is reachable only if the **matched rule's own `destination`** equals that literal exactly.
10. Faults latch; recovery is an explicit operator action that re-verifies before reopening. Nothing recovers silently.

## 4. Module and crate placement

```
crates/ssk-config/src/ingress.rs            NEW  IngressConfig + validate + schema_json
crates/ssk-config/src/lib.rs                v5, required field, migration arms, ConfigError::Ingress
crates/ssk-ipc/src/dto.rs                   IngressStatusDto; StatusDto.ingress; FlowSummaryDto/AuditEntryDto additive fields
crates/ssk-ipc/src/server.rs                Request::SetIngress; GetAuditEntries.ledger selector; accept loops back off
crates/ssk-netcore/src/{executor,direct,http_connect}.rs   no Fallback; whole-dial deadline; IPv6; (opt) keepalive
crates/ssk-netadmin/src/{policy,audit}.rs   dest_suffix never matches IP literals; pub summarise_route
crates/ssk-diag/src/lib.rs                  cap crash records
crates/ssk-daemon/src/ingress/
    mod.rs      #![deny(clippy::unwrap_used, expect_used, indexing_slicing, panic, todo, unimplemented, unreachable)]; re-exports
    types.rs    Gate, GateMode, TripReason, IngressState, Coverage, Tuning, constants, INGRESS_COVERAGE_NOTICE (leaf module, no deps on siblings)
    target.rs   RawTarget -> Target canonicalisation, special-use table, self-loop guard
    socks5.rs   server-side SOCKS5 parser/replier (no policy, no routing knowledge)
    audit.rs    FlowAuditWriter, LedgerIo, receipts, record types, verify_dir, recovery
    rotate.rs   (inside audit.rs tree) segment rotation + retention
    limits.rs   RateLimiter, PeerBudget, DenialCoalescer, FailureCooloff (all take an explicit Instant)
    peer.rs     PeerAuthorizer, IngressPlatform, Controls, Linux /proc/net/tcp resolver, fakes
    pump.rs     Counted<T>, bidirectional pump, idle watchdog, cancellation
    shared.rs   IngressShared: gate watch, status snapshot, counters, flow registry, arm/disarm/trip/recover
    engine.rs   decide(), route guards, open_tunnel() (pending -> dial -> result); protocol-agnostic
    flow.rs     per-connection SOCKS5 driver (state machine)
    host.rs     IngressHost: start/recover, accept loop, JoinSet, drain
crates/ssk-daemon/src/{supervisor,routing,main,paths}.rs   wiring
crates/ssk-cli/src/main.rs                  `ssk ingress status|arm|disarm|flows|inspect|audit`
crates/ssk-winhost/src/{ingress_bind,loopback_owner}.rs    Windows hardening (W1/W2)
tests/support/{net_fakes,socks5_client,daemon_harness}.rs  shared via the existing include! idiom
docs/adr/0009-local-proxy-ingress.md
```

All new items in `ingress` are `pub` in a `pub mod`, so no commit trips `dead_code` under `clippy -D warnings` before the next commit wires it (resolves the intermediate-commit problem the implementability judge raised). Shared leaf types live in `types.rs` and land first, which removes the circular `TripReason` dependency between `audit.rs` and `shared.rs`.

## 5. Configuration: `ssk-config` v5, section `ingress`

```rust
// crates/ssk-config/src/ingress.rs   (#[serde(deny_unknown_fields)] on EVERY struct; nested sections do not inherit it)
pub struct IngressConfig {
    pub enabled: bool,                       // default false
    pub listen: IngressListen,               // default 127.0.0.1:0
    pub protocols: Vec<IngressProtocol>,     // default [socks5]; closed snake_case enum { Socks5 }  (HttpConnect added in M2.1)
    pub hardening: IngressHardening,         // default Required; { Required, BestEffort }
    pub arm_on_start: Option<String>,        // default None; a routing profile id; explicit operator opt-in, audited with cause config_autostart
    pub limits: IngressLimits,
    pub audit: IngressAuditConfig,
}
pub struct IngressListen { pub address: std::net::Ipv4Addr, pub port: u16 }   // Ipv4Addr: hostnames, IPv6, brackets, zones cannot parse
pub struct IngressLimits {
    pub max_connections: u32,        // 64   1..=512   (open tunnels)
    pub handshake_timeout_ms: u32,   // 10_000  100..=60_000  (whole client handshake)
    pub connect_timeout_ms: u32,     // 20_000  100..=120_000 (whole upstream dial incl. proxy handshakes)
    pub idle_timeout_ms: u32,        // 600_000 100..=3_600_000 (no byte either way)
}
pub struct IngressAuditConfig {
    pub segment_mib: u32,            // 32   1..=256
    pub retain_segments: u32,        // 8    2..=64   (oldest segment pruned on rotation)
}
```

Validation (`IngressConfig::validate`, always run, even when disabled; `ConfigError::Ingress(String)`):

* `listen.address.is_loopback()` (127.0.0.0/8); `0.0.0.0` and LAN addresses fail. `port` may be 0 (the daemon publishes the bound address in status; tests need this because a spawned `sskd` cannot be handed a pre-bound socket; shipped configs should fix a port).
* `protocols` non-empty and unique; every limit within its documented range (named `pub const` min/max per field); floors are 100 ms for all timeouts so the 300-500 ms values used by real-`sskd` tests are valid configs (the earlier draft had a 1000 ms floor and tests below it).
* Cross-section checks in `AppConfig::validate` after `routing.validate()`: no routing adapter whose host is a loopback literal or `localhost` and whose port equals a non-zero `listen.port` (static self-loop); `arm_on_start`, when set, names an existing routing profile. With `port == 0` the same self-loop check re-runs at bind time against the real address.
* There is deliberately no field that selects an egress, a fallback, a policy bypass, credentials, or a special-use allow-list. (The earlier draft's `allow_special_use_targets` is removed: special-use access is decided by the matched rule, rule 9.)

Version bump and migration (mandatory; an additive optional field would let a v3/v4 file smuggle `ingress`):

```rust
CURRENT_CONFIG_VERSION = 5; AppConfig.ingress: IngressConfig (required; Default = disabled)
match version {
  1 | 2 => unchanged (..AppConfig::default() already supplies the new section)
  3 => { reject key "routing"; reject key "ingress"; insert version=5, routing=default, ingress=default; from_value }   // existing arm MUST change
  4 => { reject key "ingress"; insert version=5, ingress=default; from_value }                                         // new arm, before CURRENT
  CURRENT_CONFIG_VERSION => from_value,
  found => UnsupportedVersion
}
```
Same commit: schema `$id` -> `ssk-config-v5.json`, `required` and `properties.ingress` (from `ingress::schema_json()`), `schema_snapshot_stable` assertion, `routing_migration.rs` literals (`[3, CURRENT, 999]`, `json!("4")`, the `[1,2,3]` smuggling list, the v3 test must also remove `ingress`), `crates/ssk-config/examples/openvpn_config.rs` and regenerated `docs/examples/openvpn-routing.yaml`, a new `ingress.example.yaml`, the CLI string at `ssk-cli/src/main.rs:4373` ('to v2' -> `CURRENT_CONFIG_VERSION`), `COMPATIBILITY_MATRIX.md` (v4 files load as ingress-disabled; v5 files are rejected as `UnsupportedVersion` by older builds; migration is in memory only, files are never rewritten). Drift guard for the new section only: `ingress_schema_keys_equal_serialized_default_keys`.

## 6. Types and signatures

### 6.1 `ingress/types.rs`

```rust
pub const INGRESS_COVERAGE_NOTICE: &str =
    "Covers only applications that are configured to use this proxy. Everything else is not covered. Names an application resolves itself are not covered.";
// NOTE: the first draft's notice contained 'not system-wide' while the test forbade 'system-wide'; this one contains none of the forbidden words.
pub const FORBIDDEN_WORDS: &[&str] = &["protected", "protection", "secure", "system-wide", "system wide", "all traffic", "vpn"];

pub enum IngressState { Disabled, Starting, Unavailable, Disarmed, Armed, Tripped, Stopping }   // as_str() closed set
pub enum Coverage { None, ProxyClientsOnly }                                                    // ProxyClientsOnly only while Armed and healthy
pub enum TripReason { AuditWriteFailed, FlowPanicBudget, AcceptFatal, ListenerDied }
pub struct Gate { pub epoch: u64, pub mode: GateMode }
pub enum GateMode { Disarmed, Armed { profile: Arc<str> }, Tripped(TripReason), Closing }
pub struct Tuning {          // internal; NOT config; tests override via IngressDeps.tuning
    accept_burst: 32, accept_refill_per_s: 64,                 // charged only after peer authorization
    peer_burst: 64, peer_refill_per_s: 256, peer_inflight: 8, peer_timeout: 500 ms,
    denial_window: 60 s, denial_keys: 128, denial_burst: 20, denial_refill_per_s: 1, summary_tick: 10 s,
    panic_budget: 3, audit_deadline: 5 s, closed_deadline: 1 s, drain: 3 s,
    cooloff_failures: 5, cooloff_window: 30 s, cooloff: 10 s,
    audit_queue: 256, group_commit: 64,
}
```

Every gate transition bumps `epoch`. A flow records the `(epoch, profile)` it was admitted under and is cancelled by any change: disarm, re-arm (even to the same profile after a trip), trip, shutdown, or the optional resume heuristic. Arming an already-armed profile is an idempotent no-op that does not bump the epoch.

### 6.2 `ingress/target.rs` (pure, table-tested)

```rust
pub enum RawTarget { V4(Ipv4Addr, u16), V6(Ipv6Addr, u16), Name(Vec<u8>, u16) }
pub struct Target { pub host: String /*canonical*/, pub port: u16, pub kind: TargetKind, pub provenance: Provenance }
pub enum TargetKind { Ipv4, Ipv6, Name }
pub enum Provenance { ClientSuppliedLiteral, ClientSuppliedName }     // later front ends add NatOriginalDestination
pub enum Refusal { Malformed, NumericAlias, LocalhostName, SelfLoop, SpecialUse(SpecialUse) }
pub fn canonicalize(raw: RawTarget) -> Result<Target, Refusal>;        // Malformed|NumericAlias|LocalhostName only
pub fn classify_ip(ip: IpAddr) -> Option<SpecialUse>;
pub fn guard_self_loop(t: &Target, listener: SocketAddr) -> Result<(), Refusal>;       // pre-policy, never overridable
pub fn guard_special_use(t: &Target, matched_rule_destination: Option<&str>) -> Result<(), Refusal>;   // post-evaluate
```

`canonicalize`: port != 0; a mapped IPv6 is unmapped to V4 first; names must be ASCII (IDN only as punycode), one trailing dot trimmed, lowercased, 1..=253 bytes, must satisfy `ssk_config::routing::valid_host`; a name that parses as an IP becomes a literal; **the final label must start with an ASCII letter** (kills `2130706433`, `127.1`, `0x7f.1`, `0177.0.0.1`, `0x7f000001`, `2852039166`: all dialled as addresses by `getaddrinfo`, all invisible to the exact-match policy); `localhost` and `*.localhost` are refused. IPv6 canonical form is `Ipv6Addr::to_string()` unbracketed.

`classify_ip` covers IPv4 `0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15 (the project's reserved fake-IP range), 198.51.100/24, 203.0.113/24, 224/4, 240/4, 255.255.255.255` and IPv6 `::, ::1, fc00::/7, fe80::/10, ff00::/8, 2001:db8::/32, 64:ff9b::/96, 2002::/16`.

`guard_special_use` runs **after** `evaluate`, because it needs the matched rule: a special-use literal is allowed only if the matched rule has an exact `destination` (the policy engine has already proven that destination equals the literal, IP-normalised). A port-only rule, a suffix rule, or a rule elsewhere in the profile never opens a special-use address. The needed lookup is `ConfiguredRouting::rule_destination(profile, rule_id) -> Option<&str>`, built once from the config. `guard_self_loop` (target is the listener's address or an unspecified/loopback literal with the listener's port) runs before policy and cannot be overridden by any rule.

### 6.3 `ingress/socks5.rs` (exact-length reads, no `BufReader`)

```rust
pub enum Fault { Violation(Violation) /* silent close */, Reject(Reject) /* replied close */, Io }
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(), Fault>;     // 05 | n | n methods; require 0x00; reply 05 00 or 05 FF
pub async fn read_connect<S: AsyncRead + Unpin>(s: &mut S) -> Result<RawTarget, Fault>;         // 05 01 00 ATYP ADDR PORT, <= 4+1+255+2 bytes
pub async fn write_refusal<S: AsyncWrite + Unpin>(s: &mut S, rep: Rep) -> io::Result<()>;
pub async fn write_success<S: AsyncWrite + Unpin>(s: &mut S, _result: &ResultReceipt) -> io::Result<()>;  // 05 00 00 01 00*6, zeroed BND
pub enum Rep { Succeeded, GeneralFailure, NotAllowed, NetUnreachable, HostUnreachable, ConnectionRefused, CommandNotSupported, AddressTypeNotSupported }
```

The first byte must be `0x05`; anything else (TLS ClientHello `0x16`, `GET`, SOCKS4 `0x04`) closes **without writing a byte**. `NMETHODS` 1..=255 with `0x00` offered. CMD must be CONNECT (BIND/UDP ASSOCIATE get `0x07`), `RSV` must be 0, ATYP 1/3/4 only (else `0x08`), domain length >= 1, port != 0. Only the request is consumed, so early client payload stays in the kernel buffer and is pumped after admission (it is the client's own payload, post-admission, not smuggling). The whole handshake runs under `timeout(handshake_timeout)`. The success reply is written only with a `&ResultReceipt` in hand.

### 6.4 `ingress/audit.rs`: single writer, group commit, receipts, rotation

Own ledger directory `<state_dir>/ingress-audit/` of segments `seg-<first_seq:020>.jsonl`. Reasons for a separate ledger (and why unifying with `audit.json` was rejected, section 19): `audit.json` is a whole-file pretty-JSON rewrite with fsync, about four full reads per entry; its entry type has no destination/rule/peer/time; changing its hash body or converting it to JSONL is a one-way format change that sits under 23 pinned integration tests; `GetStatus` would inherit traffic-proportional cost.

Line format: `<64-hex entry_hash> <body_json>\n`, `entry_hash = blake3(prev_hash_hex ++ body_json_bytes)` over the **stored bytes** (no canonical-JSON dependence); first record's prev is the literal `genesis`. Body carries gapless `seq` and informational `ts_ms` (wall clock, documented untrusted).

```rust
pub struct FlowAuditRecord { pub seq: u64, pub ts_ms: u64, pub flow_id: String, #[serde(flatten)] pub event: FlowAuditEvent }
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FlowAuditEvent {
    Started   { daemon_version: String, ledger_format: u32 },             // flow ids of this boot: "ingress:b<seq of this record>:<n>"
    Recovered { truncated_tail_bytes: u64, after_trip: Option<String> },
    Armed     { profile: String, cause: String /* operator | config_autostart */ },
    Disarmed  { cause: String /* operator | deactivate | shutdown | resume_heuristic */ },
    Denied    { peer: String, peer_verified: bool, host: String, port: u16, target_provenance: String, profile: String,
                matched_rule: Option<String>, reason_code: String, route: Option<String>, coalesced: bool },
    Pending   { peer: String, peer_verified: bool, host: String, port: u16, target_provenance: String, profile: String,
                matched_rule: Option<String>, route: String, planned_adapters: Vec<String> },
    Result    { outcome: String /* connected | failed */, error_code: Option<String>, chain: Vec<String> },
    Closed    { bytes_up: u64, bytes_down: u64, duration_ms: u64, reason: String },
    Summary   { window_ms: u64, pre_admission_rejects: BTreeMap<String,u64>, denials_suppressed: BTreeMap<String,u64>, denials_repeated: Vec<RepeatCount> },
    Continue  { prev_segment_head: String, prev_seq: u64, pruned_before_seq: Option<u64> },
}
pub struct Receipt { pub seq: u64, pub entry_hash: String }          // constructors private to audit.rs (compile_fail doctest, like AdmissionToken's)
pub struct PendingReceipt(Receipt);  pub struct ResultReceipt(Receipt);
pub trait LedgerIo: Send + 'static { fn append(&mut self, b: &[u8]) -> io::Result<()>; fn sync(&mut self) -> io::Result<()>; fn len(&self) -> u64; fn rotate(&mut self, next_first_seq: u64) -> io::Result<()>; fn prune(&mut self, keep: u32) -> io::Result<Option<u64>>; }
impl FlowAuditWriter {
    pub fn open_dir(dir: &Path, cfg: AuditOpenCfg, on_trip: Arc<dyn Fn(TripReason) + Send + Sync>) -> Result<Self, AuditOpenError>;
    pub fn open_with(io: impl LedgerIo, replayed: Replayed, cfg: AuditOpenCfg, on_trip: ...) -> Self;      // test seam
    pub async fn append_pending(&self, flow_id: &str, ev: PendingEvent, deadline: Duration) -> Result<PendingReceipt, AuditError>;
    pub async fn append_result (&self, flow_id: &str, ev: ResultEvent,  deadline: Duration) -> Result<ResultReceipt,  AuditError>;
    pub async fn append_armed(&self, profile: &str, cause: &str, deadline: Duration) -> Result<Receipt, AuditError>;
    pub async fn append_denied_durable(&self, flow_id: &str, ev: DeniedEvent, deadline: Duration) -> Result<Receipt, AuditError>;
    pub async fn append_closed(&self, flow_id: &str, ev: ClosedEvent, bounded: Duration);    // loss counted, never trips by itself
    pub fn queue_summary(&self, s: SummaryEvent) -> bool;
    pub async fn flush(&self, deadline: Duration) -> Result<(), AuditError>;                 // barrier (tests, shutdown)
    pub fn head(&self) -> (u64 /*entries*/, Option<String> /*head hash*/);                   // atomics; no file read
    pub async fn close(self, deadline: Duration);
}
pub fn verify_dir(dir: &Path, mode: VerifyMode /* Open | Reader */) -> Result<VerifiedLedger, AuditVerifyError>;
pub enum AuditError { QueueFull, Timeout, WriterDown, Capacity, Io(String) }
```

Writer thread (`std::thread`, not a blocking-pool slot): `blocking_recv` one job, `try_recv` up to 63 more (**group commit**), serialise, one `append`, one `sync_data`, then send every reply. **A reply, and therefore a receipt, is only ever sent after the `sync` that covers it.** Before each batch the writer compares the active segment's `metadata().len()` with its own expected length (O(1)); a mismatch means an external writer or truncation and trips `AuditWriteFailed` (cheap external-modification detection). Any `append`/`sync`/rotate error replies `Err` to every job in the batch, calls `on_trip(AuditWriteFailed)` and exits the thread.

**Rotation and retention (M2, commit G4).** When the active segment reaches `segment_mib`, the writer (between batches, never splitting one) closes it, opens `seg-<next_seq>.jsonl` and writes `Continue{prev_segment_head, prev_seq, pruned_before_seq}` as its first record; if more than `retain_segments` exist, the oldest file is deleted and `pruned_before_seq` is recorded. A retained oldest segment may therefore begin with `Continue` instead of `genesis`; `verify_dir` accepts that as a trusted anchor and says so in its result. Until G4 lands, the core writer refuses new pending records at 128 MiB with `Capacity` (new dials refused with `0x01`, denials and terminal records still allowed, **no trip**); after G4 the capacity path is unreachable except when rotation itself fails, which is a write fault. There is no permanent capacity latch (the earlier draft latched at the cap and stayed down across restarts).

Open/recovery (`open_dir`): missing directory = empty chain; if the active segment does not end in `\n`, the tail after the last newline is a torn append that was never acknowledged (replies follow fsync), so it is truncated with `set_len` and a `Recovered` record is written first; every complete line must verify (hash, gapless `seq`, `Continue` linkage); any failure returns `AuditOpenError::Corrupt{segment,line}` and the ingress reports `unavailable` (`INGRESS_AUDIT_CORRUPT`) with **no port bound**. Then `Started` is appended. Open verifies up to `segment_mib * retain_segments` (default 256 MiB); the host does this in a background task so IPC is connectable immediately and status reads `starting` until it finishes.

Recording discipline: `host` in records is the canonical validated host, or (for refusals before canonicalisation, which are counted and not individually recorded) nothing. Nothing else from the client is recorded. Honest limits: prefix integrity only. Deleting the directory, deleting the newest segments, or truncating at a record boundary verifies; status publishes `(entries, head)` so an operator or the GUI can keep an out-of-band checkpoint.

### 6.5 `ingress/limits.rs` (deterministic: explicit `Instant` arguments)

```rust
pub struct RateLimiter { /* token bucket */ }          impl RateLimiter { pub fn try_take(&mut self, now: Instant) -> bool }
pub struct PeerBudget { /* bucket + in-flight cap */ } impl PeerBudget  { pub fn try_start(&mut self, now: Instant) -> Option<PeerCheckGuard> }
pub struct DenialCoalescer { /* key=(profile,host,port,reason,rule); 60 s window; <=128 live keys; bucket 1/s burst 20 for first occurrences */ }
impl DenialCoalescer {
    pub fn classify(&mut self, key: DenialKey, now: Instant) -> Disposition;     // FirstDurable | Repeat | Suppressed
    pub fn take_summary(&mut self, now: Instant) -> Option<SummaryEvent>;
}
pub struct FailureCooloff { /* 5 consecutive failures per planned chain within 30 s => refuse that chain for 10 s */ }   // commit E4
```

### 6.6 `ingress/peer.rs`

```rust
pub enum PeerVerdict { SameUser, DifferentUser, Unknown }
pub trait PeerAuthorizer: Send + Sync { fn authorize(&self, client: SocketAddr, listener: SocketAddr) -> PeerVerdict; }   // blocking; spawn_blocking under a 500 ms timeout
pub struct Controls { pub exclusive_bind: bool, pub peer_check: bool }
pub trait IngressPlatform: Send + Sync {
    fn controls(&self) -> Controls;                                                // does a real self-test (Linux: /proc/net/tcp readable and parseable)
    fn bind(&self, addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener>;
    fn peer_authorizer(&self) -> Option<Arc<dyn PeerAuthorizer>>;
}
pub fn default_platform() -> Arc<dyn IngressPlatform>;                              // cfg(linux) / cfg(unix, not linux) / cfg(windows)
```

* **Linux:** `controls = { exclusive_bind: true, peer_check: true }`. A live listener cannot be double-bound (reader probe: second bind to a live `127.0.0.1:port` fails `EADDRINUSE` with and without `SO_REUSEADDR`); I list this as a test to run, not as a fact I verified. `peer_check` parses `/proc/net/tcp`: find the row with `local == client addr:port` and `rem == listener addr:port`; the row's state must be in `{01 ESTABLISHED, 04 FIN_WAIT1, 05 FIN_WAIT2, 08 CLOSE_WAIT}` (so a client that wrote its request and half-closed is not refused; an earlier draft required ESTABLISHED only); inode must be non-zero (orphaned/TIME_WAIT rows carry no owner); compare the uid column with `rustix::process::geteuid()`. The server-side row (local = listener) belongs to us and must never be used. Row missing, parse failure, anything unexpected => `Unknown` => refuse. `parse_proc_net_tcp` is a pure function with golden lines (little-endian IPv4 hex such as `0100007F:DE2C`).
* **Other unix:** `{ exclusive_bind: true, peer_check: false }`. **Windows:** `{ false, false }` until W1/W2; then `{ true, true }`.
* `hardening: required` (default) and a platform lacking either control => ingress `unavailable`, `INGRESS_HARDENING_UNAVAILABLE`, listing the missing controls; nothing binds. `best_effort` runs with whatever exists; status reports exactly which controls are active and every `Pending`/`Denied` record carries `peer_verified`. The weaker mode is a visible operator choice, never a silent default.
* Trust boundary stated plainly: the same OS user (the repo's existing decision for IPC). Same-user hostile code is out of scope.

### 6.7 `ingress/engine.rs` (protocol-agnostic; no socket in its signatures)

```rust
pub struct EngineCtx { routing: Arc<ConfiguredRouting>, data_plane: Arc<dyn DataPlane>, audit: Arc<FlowAuditWriter>, shared: Arc<IngressShared>,
                       denials: Mutex<DenialCoalescer>, cooloff: Mutex<FailureCooloff>, limits: ResolvedLimits, listener: SocketAddr, boot: String, seq: AtomicU64, tuning: Tuning }
pub struct Admitted { pub token: AdmissionToken, pub route: RouteKind, pub rule: Option<String>, pub adapters: Vec<String>, pub flow: FlowRecord, pub epoch: u64 }
pub struct Denied   { pub reason: &'static str, pub class: DenyClass /* Policy | Route | Guard */, pub rule: Option<String>, pub route: Option<String> }
pub fn decide(ctx: &EngineCtx, profile: &str, flow_id: String, t: &Target) -> Result<Admitted, Denied>;
pub struct Established { pub session: EgressSession, pub result: ResultReceipt, pub chain: Vec<String> }
pub enum DialFault { Audit(AuditError), Dial(NetcoreError), Cancelled, Deadline }
pub async fn open_tunnel(ctx: &EngineCtx, adm: Admitted, gate: &mut watch::Receiver<Gate>) -> Result<Established, DialFault>;
async fn dial(ctx: &EngineCtx, token: AdmissionToken, _p: &PendingReceipt, gate: &mut watch::Receiver<Gate>, epoch: u64) -> Result<EgressSession, DialFault>;
```

`ConfiguredRouting` gains one pure function, used by the live path **and** `TraceRoute`, so preview and live cannot diverge: `pub fn decide(&self, profile: &str, flow: &FlowRecord) -> Result<Decided, DecideError>` (evaluate + plan; `Decided { decision, candidate }`). The live path then applies the guards below; the preview documents that the live path can refuse more.

`decide` order: `guard_self_loop` -> `FlowRecord{ flow_id, intake_epoch 0, app 'local-proxy:unattributed', Tcp, Low }` -> `routing.decide` -> policy deny / no rule / attestation / unknown adapter / plan error => `Denied` -> `guard_special_use` (matched rule's destination) -> **route guard** -> `orchestrator.admit` (error => `Denied`). Route guard refuses: `Denied`, `Fallback`, `OpenVpn` (`OPENVPN_NOT_READY`, no pending record, no socket), `Direct` with a name target (`DIRECT_REQUIRES_LITERAL`), and any route whose last hop kind is not `Socks5`/`HttpConnect` (`ROUTE_NOT_DIALABLE`; covers a terminal `TlsTunnel`, whose SNI is the target and which never conveys the destination). Unlike activation, a plan error here is a recorded denial. The token and route are never formatted with `{:?}` anywhere in the ingress (derived `Debug` prints `HopSpec.auth`).

`open_tunnel` order: (a) `append_pending` (deadline 5 s) -> `PendingReceipt`; (b) re-check gate epoch; (c) `timeout(connect_timeout, data_plane.connect_route(token))` raced with `gate.changed()` and the cooloff check; (d) `append_result(connected | failed{error_code}, chain)`. If (d) fails after a successful dial the session is dropped first (closes upstream) and the fault is returned; if the gate changes after (a) the engine still writes a bounded terminal `Result{failed, GATE_CLOSED}` (a pending-only orphan is legal but avoided). There is exactly one `connect_route` call site and no retry.

### 6.8 `ingress/pump.rs`

`Counted<T>` wraps both ends (atomics for bytes and last activity, so counts survive errors and cancellation). `tokio::io::copy_bidirectional_with_sizes(.., 16 KiB, 16 KiB)` over `Counted<TcpStream>` and `Counted<&mut BoxedTransport>` (from `session.transport_mut()`; the first caller of that method in the workspace), raced in `select!` against an idle/half-close watchdog and `gate.changed()`. Cancellation drops both sockets (abrupt close, the repo's fail-closed convention); normal EOF lets `copy_bidirectional` propagate shutdown. About 32 KiB per tunnel. `pump(client, session, _r: &ResultReceipt, idle, gate, epoch, stats) -> PumpEnd { Eof, IdleTimeout, GateClosed, ClientError, UpstreamError }`.

### 6.9 `ingress/shared.rs` and `ingress/host.rs`

```rust
pub struct IngressShared { /* watch::Sender<Gate>, std Mutex<StatusInner>, atomics, FlowRegistry, OnceLock<Arc<dyn HostControl>> */ }
impl IngressShared {
    pub fn new(cfg_view: IngressCfgView) -> Arc<Self>;                         // state Disabled / Starting
    pub fn snapshot(&self) -> IngressStatusDto;                                // atomics + short std Mutex; no file I/O, no tokio lock
    pub async fn arm(&self, profile: &str, cause: ArmCause) -> Result<(), IpcError>;   // recover-if-needed -> durable Armed record -> gate.send
    pub async fn disarm(&self, cause: DisarmCause);                            // gate.send(Disarmed) FIRST, then bounded record; never fails
    pub fn recent_flows(&self, limit: usize) -> Vec<FlowSummaryDto>;
    pub fn inspect(&self, flow_id: &str) -> Result<FlowInspectionDto, IpcError>;       // FLOW_NOT_RETAINED vs FLOW_NOT_FOUND
    pub(crate) fn trip(&self, why: TripReason);                                // latch, cancel all flows, idempotent
}
pub struct IngressHost { /* accept task, watchdog, Arc<FlowAuditWriter>, bound addr */ }
impl IngressHost {
    pub async fn start(deps: IngressDeps) -> IngressHost;                      // infallible: failures become shared.set_unavailable(code, msg)
    pub async fn recover(&self) -> Result<(), IpcError>;                       // re-verify ledger, reset panic count, rebind; all-or-nothing
    pub fn local_addr(&self) -> Option<SocketAddr>;
    pub async fn shutdown(self, drain: Duration);
}
```

`start` order is a security property: (1) `enabled`? else `Disabled`. (2) hardening evaluated from `platform.controls()`. (3) open and verify the ledger, write `Started` (corrupt => nothing is bound). (4) `platform.bind(addr)`; assert `local_addr()` is IPv4 loopback and equals the request (bind error => `INGRESS_BIND_FAILED`, never retried on another port). (5) runtime self-loop check: no routing adapter's literal address:port equals the bound address. (6) `set_bound(Disarmed)`; spawn accept loop and a watchdog that trips on abnormal accept-task end; (7) if `arm_on_start` is set, `arm(profile, config_autostart)`.

Arming from `unavailable`/`tripped` calls `recover()` first: ledger re-open (`Corrupt` stays `unavailable`; the RUNBOOK procedure is to move the segment directory aside), counter reset, rebind if the listener died or bind had failed. A hostile local user therefore cannot cause a state that only a daemon restart can clear.

## 7. The per-connection pipeline

### 7.1 Accept loop (single task; flow tasks live in its `JoinSet`)

`select!` over: shutdown, `join_next()` (a flow **panic** increments the panic counter; at `panic_budget` = 3 per boot it calls `trip(FlowPanicBudget)`; RAII guards release the permit and registry row on unwind), the summary tick, and `accept()`. Accept errors: increment `accept_errors`, sleep with exponential backoff 50 ms to 1 s, continue; after 100 consecutive errors call `trip(AcceptFatal)`. (No errno classification: `std::io::ErrorKind` cannot name `EMFILE`, so classification would have needed per-OS raw codes. A count-based rule is OS-neutral and unit-testable.) Nothing in the ingress can end `run_server` or the daemon.

For each accepted socket, **before reading any byte**, in this order:

1. gate must be `Armed` (else drop; `refused_disarmed`);
2. `peer_addr()` is loopback IPv4 and `local_addr()` equals the bound address (else drop);
3. `PeerBudget::try_start` (its own cheap bucket and an in-flight cap of 8; else drop; `refused_peer_budget`);
4. spawn an admission task: `authorize()` under `peer_timeout` (`SameUser`, or `best_effort` with no peer control => continue with `peer_verified=false`; else drop; `refused_peer`);
5. **only now** charge the shared budgets: `accept_bucket.try_take` (else drop; `refused_rate`), then `Semaphore::try_acquire_owned` (else drop; `refused_capacity`);
6. run the flow.

A different local user therefore spends only the cheap, separate peer budget; it cannot drain the admitted-flow bucket, the connection permits, the ledger, or any daemon state. What no design can promise is availability of a loopback port against a hostile local user who floods it at kernel level; the notice and RUNBOOK say so.

### 7.2 State machine

| # | State | Does | Deadline | Client sees on failure | Audit | Counter / gate |
|---|---|---|---|---|---|---|
| 0 | Accepted | steps 1-3 above | - | close, zero bytes | none | refused_* |
| 1 | PeerChecked | steps 4-5 above | 500 ms | close, zero bytes | none (Summary) | refused_peer / rate / capacity |
| 2 | Handshake | `negotiate` + `read_connect` | handshake_timeout | violation: silent close; `FF`/`07`/`08` replies per 6.3 | none per flow; counted `malformed` | malformed |
| 3 | Targeted | `canonicalize`, `guard_self_loop` | - | malformed/alias/localhost: `08` and close; self-loop: `02` | rejected input: counted only; self-loop: coalesced `Denied` | rejected_target / denied |
| 4 | Decided | mint flow id `ingress:b<boot>:<n>`; `engine::decide` (policy, special-use, route guard, admit) | - | policy/guard class: `02`; route class (openvpn, unsupported route, unknown adapter): `01` | `DenialCoalescer`: first occurrence **durable before the reply**, repeats counted into `Summary` | denied |
| 5 | **PendingDurable** | `append_pending` awaited | 5 s | `01`, no dial; token dropped unused | none possible | audit_fail; writer failure trips |
| 6 | Dialing | gate re-check; `connect_route` under `connect_timeout`, raced with gate | connect_timeout | see 7 | - | - |
| 7 | **ResultDurable** | `append_result(connected | failed)` awaited. Dial error: reply (`05` refused, `04` timeout, `01` other) then close; **never re-dial**. Result write fails: `drop(session)` first, then close client | 5 s | mapped reply, or silent close on durability failure | `result` | connect_failed / audit_fail |
| 8 | Replied | gate re-check; `write_success(&ResultReceipt)` | - | `05 00 00 01 00*6` | - | admitted |
| 9 | Pumping | `pump(...)` | idle_timeout | EOF/reset when torn down | - | active gauge |
| 10 | Closed | bounded `append_closed(bytes, duration, reason)`; registry final; permit released | 1 s | - | `closed` (loss counted, not fatal) | bytes totals |

Notes: (a) the denial path no longer uses a fire-and-forget queue: a client that sees a refusal for a fresh key has a durable record, so the Deny acceptance test can assert the ledger immediately after the reply with no polling; only repeats within the window and denials beyond the bucket (1/s, burst 20) are folded into `Summary` records, and the status counters reconcile exactly. (b) `NetcoreError` is mapped coarsely; upstream detail, adapter addresses and `HopSpec.auth` never reach the client, logs above DEBUG, status or IPC errors. (c) A flow whose gate epoch changed at any point is torn down with `Closed.reason = gate_closed`. (d) Per-flow tasks are never attached to `Supervisor::spawn_supervised` / `record_task_failure`.

## 8. Lifecycle

* **Start:** `main.rs` builds `Arc<ConfiguredRouting>` once and shares it; constructs `Shutdown` earlier; starts `IngressHost` after `Supervisor::new`; IPC comes up regardless. Config invalid => ingress `unavailable (CONFIG_INVALID)`, no listener.
* **Arm:** `Request::SetIngress{ profile_id: Some(p) }` (validated with the existing `validate_profile_id` against `routing.profiles()`), or `arm_on_start`. Durable `Armed` record first, gate second; failure leaves the previous gate unchanged. A restart comes back disarmed unless `arm_on_start` is configured. Armed state is not persisted.
* **Disarm:** `SetIngress{ None }` and `Deactivate`. `Deactivate` calls `ingress.disarm(Deactivate)` **first**, before the `KILL_SWITCH_ARMED` check (disarming only narrows what is forwarded, so it must always be possible). `Deactivate` is therefore documented as 'stop everything this daemon does for applications'; `ssk ingress disarm` is the ingress-only verb.
* **Trip and recover:** audit write failure, flow panic budget, fatal accept errors, listener death => `tripped`, all flows cancelled, status `retry_hint = re-arm to recover`. `arm` re-verifies and rebinds as in 6.9.
* **Shutdown** (replaces the `yield_now` 'drain' for the ingress): stop accepting and drop the listener; gate -> `Closing` cancels every flow; drain the `JoinSet` to 3 s then `abort_all` (each flow writes a bounded `Closed{shutdown}`); `audit.close` drains the queue and joins the writer; only then `serve()` returns; `run()` then calls `runtime.shutdown_timeout(2 s)` **before** `drop(lock)`, so the daemon lock outlives every ledger writer. Un-terminated `pending` records after a hard kill are legal and displayed as pending.
* **Decoupling from activation:** a failed `ssk activate` probe (FailClosed) does not stop the proxy, and a proxy fault does not change `DaemonState`. Rationale in section 19 (the judges' suggestion to serve only while the daemon is not FailClosed would let one failed probe kill the proxy; the ingress has its own latch and its own prerequisites: valid config, healthy ledger).

## 9. Audit semantics (summary)

* `Pending` durable before the dial; `Result` durable before the success reply and before any byte; `Closed` after. Audit failure **before** the dial => no dial. Audit failure **after** connect => upstream dropped before any reply, ingress trips.
* Denials: first occurrence per `(profile, host, port, reason, rule)` per 60 s window is durable before the refusal reply; repeats and over-budget denials are counted and emitted as one `Summary` record per key per window. Pre-handshake garbage, malformed targets and peer refusals are never recorded individually (the repo's existing 'rejected input must not grow the ledger' rule, supervisor.rs ActivateProfile validation) and are folded into `Summary` counters.
* Entry ids are the ledger `seq` (gapless across segments and restarts); flow ids are `ingress:b<seq of Started>:<n>` and do not depend on a clock or client data.
* Compatibility: new directory, new format (`ledger_format: 1`); `audit.json`, `ForensicEntry`, `ssk verify-ledger` and older binaries are untouched. The legacy activation trail stays in `audit.json`; `RunDoctor` reports both chains, `GetAuditEntries{ledger: Some("ingress")}` reads the ingress tail (section 11), and `COMPATIBILITY_MATRIX.md` documents both.
* Cost: `GetStatus` never reads a ledger. Group commit amortises fsync; one admitted flow costs two durable records plus a best-effort `Closed`.

## 10. Status semantics: what may be claimed

* `DaemonState` is untouched by the ingress. `dns_protected` and `kill_switch` keep their existing meaning. The word `Protected` keeps its one-held-session meaning and is never combined with ingress wording.
* New block `StatusDto.ingress: Option<IngressStatusDto>`:

```rust
pub struct IngressStatusDto {
    pub state: String,            // disabled | starting | unavailable | disarmed | armed | tripped | stopping
    pub coverage: String,         // none | proxy_clients_only   (the latter only while state == armed and healthy)
    pub system_wide: bool,        // constant false
    pub notice: String,           // INGRESS_COVERAGE_NOTICE
    pub listen: Option<String>,   // "127.0.0.1:<port>" only while bound
    pub protocols: Vec<String>, pub armed_profile: Option<String>,
    pub controls: IngressControlsDto,   // exclusive_bind, peer_check, hardening
    pub counters: IngressCountersDto,   // accepted, refused_*, malformed, denied, denied_suppressed, admitted, connect_failed, active_flows, bytes_up, bytes_down, panics, accept_errors, audit_close_lost
    pub audit: IngressAuditDto,         // entries, head, segments, state
    pub last_error: Option<IpcError>,   // the ingress's own slot; never merged into StatusDto.last_error
    pub last_denial: Option<DenialSummaryDto>,
    pub retry_hint: Option<String>,
}
```

* `armed` is computed, never stored: gate `Armed` AND accept task alive AND ledger writer alive AND (peer control available, or `best_effort` explicitly). `armed` means exactly: the listener evaluates each connection that reaches it under the named profile. It says nothing about applications that do not use the proxy, apps that fall back to direct on their own, DNS resolved by applications, UDP/QUIC, or any OS-level enforcement.
* Clients must render an unknown `state` or `coverage` string as 'unknown, not covered'. `Some(IngressStatusDto)` is also the **capability marker**: a new CLI refuses `ssk ingress arm` against a daemon whose status has `ingress: None`.

| Situation | DaemonState | ingress.state | coverage | Allowed headline |
|---|---|---|---|---|
| not configured | unchanged | disabled | none | Local proxy: off |
| config invalid | ConfigInvalid | unavailable | none | Local proxy unavailable: configuration invalid |
| ledger open / verify running | unchanged | starting | none | Local proxy starting |
| bound, not armed | unchanged | disarmed | none | Proxy ready, not activated: connections are refused |
| armed | unchanged | armed | proxy_clients_only | Proxy active for applications that use it (profile P). Everything else is not covered. |
| fault latched | unchanged | tripped | none | Proxy stopped: <code>. Re-arm to recover. |
| bind/hardening/ledger refused | unchanged | unavailable | none | Proxy unavailable: <code> |

Also corrected as part of the honesty work: the adapter health string becomes `connected at activation; liveness not monitored`, and the `Protected` doc comment in `ssk-ipc/src/state.rs` is corrected to the enforced meaning.

## 11. IPC and compatibility

Additive fields only, plus exactly one new `Request` variant:

* `StatusDto.ingress: Option<IngressStatusDto>` (`#[serde(default)]`). Update the three literal sites: `supervisor.rs` builder, `ssk-desktop-client/src/tests.rs`, `apps/desktop/tests/webview_status.rs` (Windows-only separate workspace; cannot be compiled here, flagged).
* `FlowSummaryDto` gains `#[serde(default)]` fields: `peer`, `route`, `matched_rule`, `reason_code`, `bytes_up`, `bytes_down`, `started_ms`, `ended_ms`, `audit_pending_seq`, `audit_result_seq`, `front_end`. `outcome` closed set: `denied | refused | connect_failed | active | closed | cancelled`. `app_id` is the literal `local-proxy:unattributed`, never client data.
* `AuditEntryDto` gains `adapter_id`, `decision_id`, `detail` (all `Option`, `serde(default)`), so ingress records can be returned in the same DTO.
* `Request::GetAuditEntries { limit, #[serde(default)] ledger: Option<String> }` (`None` = activation ledger as today, `Some("ingress")` = ingress tail). This is a field on an existing struct variant, hence additive; `clamp_request_limits`, the supervisor handler and the four test sites must be updated to the new shape.
* `ListRecentFlows` / `InspectFlow` become real (256-entry registry outside the mutex). `FLOW_NOT_FOUND` only for ids never issued; for ids of this boot that were evicted, or ids of another boot, `FLOW_NOT_RETAINED` ('not kept in memory; see the ingress audit'). Pre-policy refusals inspect as `PolicyAction::Deny`, `RouteKind::Denied{reason}`, `matched_rule: None`.
* **`Request::SetIngress(SetIngressRequest { profile_id: Option<String> })`**, declarative and idempotent (`Some` = arm, `None` = disarm); response `Response::Status`. The judges objected that a new variant breaks old peers (an old daemon drops the connection; a new client sees a misleading retriable `IPC_IO_FAILED`). I keep the variant on purpose: the alternative (overloading `ActivateProfile{ingress:true}`, `Deactivate{ingress_only:true}`) turns version skew into a **destructive** outcome, because an old daemon would ignore the flag and run the legacy no-destination path, which calls `clear_egress()` and enters FailClosed (verified in `supervisor.rs`). A dropped connection is harmless; a dropped probe session is not. Mitigation: the CLI checks the capability marker first and maps `IPC_IO_FAILED` after `SetIngress` to a 'daemon may predate ingress support' hint.
* No new `DaemonState`, `Event` or `Response` variants. No per-flow events on the 256-slot broadcast. Arm, disarm and trip emit the existing `Event::Warning{code,message}` (rate-limited).
* New `explain_code` entries: `INGRESS_DISABLED`, `INGRESS_UNAVAILABLE`, `INGRESS_BIND_FAILED`, `INGRESS_AUDIT_CORRUPT`, `INGRESS_HARDENING_UNAVAILABLE`, `INGRESS_CONFIG_CONFLICT`, `INGRESS_TRIPPED`, `INGRESS_AUDIT_FAILED`, `INGRESS_RECOVERY_FAILED`, `FLOW_NOT_RETAINED`, `ACTIVATION_CONNECT_TIMEOUT`, `DIRECT_REQUIRES_LITERAL`, `ROUTE_NOT_DIALABLE`.
* The desktop v2 contract is not touched (it projects only the fields it knows); a regression test proves `DesktopClient` still reads a daemon that returns `ingress: Some(..)`.

## 12. Changes in existing code

**Supervisor (`supervisor.rs`, `routing.rs`, `main.rs`, `paths.rs`)**

1. Hoist `Arc<ConfiguredRouting>` and `Arc<dyn DataPlane>` out of `Inner` onto `Supervisor` (read-only after construction; `Supervisor::new` keeps its `Box<dyn DataPlane>` signature via `Arc::from`; about eight use sites in `handle`). Add `ingress: Arc<IngressShared>` and an owned copy of the validated `IngressConfig` on `Supervisor` (the earlier draft's `Option<&IngressConfig>` accessor could not compile: it would have borrowed from `Inner` behind the tokio mutex). The ingress shares **the same planner and the same data plane** as activation, so decision and dial cannot disagree and test doubles inject into both.
2. `GetStatus` never waits behind a dial: acquire `Inner` with a 100 ms timeout; on timeout answer from `StatusHint` (the last `StatusDto` computed or published, with `state = Activating` while an activation is in flight; `last_error` unchanged). The hint is written after every normal `status()` and when `ActivateProfile` enters `Activating`. No publish-on-drop guard, no new global snapshot machinery; staleness is bounded by the duration of the in-flight request and carries `Activating`. This is the lighter variant of the desktop-product design's lock-free status, chosen to avoid its blast radius. `Activating` becomes observable for the first time.
3. The activation `connect_route` is wrapped in `tokio::time::timeout(ACTIVATE_DIAL_DEADLINE = 20 s)`; expiry is an ordinary connect error (durable `FailClosed` result, `ACTIVATION_CONNECT_TIMEOUT`, no retry). Test seam: `Supervisor::with_activation_deadline`. The activation sequence is otherwise unchanged (pinned by the 23 existing integration tests).
4. New arms: `SetIngress`; `GetStatus` fills `ingress`; `Deactivate` disarms first; `ListRecentFlows`/`InspectFlow`/`GetAuditEntries{ledger}` from the registry/ledger outside the mutex; `RunDoctor` gains `ingress`, `ingress:controls`, `ingress:audit` (re-verifies the retained chain; cost bounded by retention), `ingress:fd_budget`; `TraceRoute` uses `ConfiguredRouting::decide`.
5. `main.rs`: build routing once; start `IngressHost`; after the `select!`, `host.shutdown(DRAIN_DEADLINE)`; build the executor with `with_dial_deadline(connect_timeout + 5 s)` when the ingress is enabled; `runtime.shutdown_timeout(2 s)` before `drop(lock)`. `paths.rs`: `Layout::flow_audit_dir()`.

**`ssk-netcore`:** (a) `RouteKind::Fallback` arm returns `NetcoreError::NoRoute("fallback routes are not executable")` and never dials (the public variant stays, now inert by construction rather than by absence of a producer); (b) `RouteExecutor::with_dial_deadline` (default 30 s) wraps the whole `connect`, so a silent SOCKS5/CONNECT/TLS peer cannot hang any caller, including `probe`; (c) `direct::connect_tcp` uses `TcpStream::connect((host, port))` so IPv6 literals work; (d) `http_connect` brackets IPv6 authorities and refuses space/control characters itself (defence in depth below `admit`); (e) optional: TCP keepalive (60 s idle, 20 s interval, via `socket2::SockRef`) on first-hop and Direct upstream sockets.

**`ssk-netadmin`:** `MatchCriteria::matches` never applies `dest_suffix` to an IP-literal host; `pub fn summarise_route`; a test that the planner never emits `Fallback`. **`ssk-diag`:** crash records pruned to the newest 32. **`ssk-ipc`:** both accept loops back off and continue instead of returning; the Unix half uses a pure `AcceptRetry` helper (50 ms to 1 s, give up after 60 consecutive errors); the named-pipe half is a separate commit verified only by Windows CI.

## 13. Failure semantics: no direct fallback, ever

| Failure | Client sees | Daemon state | Record |
|---|---|---|---|
| ingress disabled / disarmed / tripped / unavailable | TCP close, zero bytes | unchanged | counter only |
| peer refused or Unknown | TCP close, zero bytes | unchanged | counter (Summary) |
| policy deny / no rule / attestation / unknown adapter / guard | SOCKS `02` (route class `01`) | unchanged | durable `Denied` (first occurrence) |
| OpenVPN route | `01`, `OPENVPN_NOT_READY` | unchanged | `Denied`; no pending, no socket |
| adapter down, refused, handshake rejected, silent proxy | `05` / `04` / `01` | unchanged | `Pending`, `Result failed` |
| lower-priority Direct rule exists | same as above; first match wins, **no second attempt** | unchanged | exactly one pending + one failed result |
| audit write fails before dial | `01`, no dial | ingress `tripped` | none possible |
| audit write fails after connect | upstream dropped, no reply | ingress `tripped` | pending exists, no result |
| flow task panics | that connection dies | none until panic budget (3) | `Closed` best-effort; crash record capped |
| gate change / disarm / shutdown | EOF | unchanged | `Closed{gate_closed|shutdown}` |
| failure cool-off active for a chain (E4) | `01` | unchanged | coalesced `Denied ADAPTER_COOLING_OFF`, no dial |

What the daemon cannot prevent (stated in the notice, status and docs): an application that is configured to use the proxy may itself fall back to a direct connection when the proxy refuses; applications that never use the proxy; DNS an application resolves before reaching the proxy (an IP-literal request will not match a domain rule); any UDP.

## 14. Threat mitigations

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 1 | Other local user/process uses the proxy | typed loopback bind; peer authorizer before the first byte and before shared budgets; `Unknown` refuses; `hardening: required` default; Windows unavailable until W1/W2 | `peer_other_user_is_refused_before_any_byte`, `peer_refusals_do_not_consume_accept_budget`, `linux_owner_lookup_returns_own_uid`, `hardening_required_makes_unhardened_platform_unavailable` |
| 2 | Port squat / hijack | no fallback port; bind error => `unavailable`; `local_addr` re-asserted; Linux semantics probed by a test; Windows exclusive bind (W1) | `bind_failure_is_reported_and_ipc_stays_up`, `second_bind_to_live_listener_fails_on_linux` |
| 3 | Browser / cross-protocol | first byte must be `0x05` else zero-byte close; no HTTP on the port in M2 | `cross_protocol_first_bytes_get_zero_bytes_back` |
| 4 | SSRF / special-use / numeric aliases | canonicalisation; matched-rule-bound exemption; suffix never matches IPs | `numeric_alias_targets_refused_before_policy`, `special_use_needs_matched_rule_destination`, `deny_rule_literal_does_not_unlock_port_only_rule` |
| 5 | Self-loop | non-overridable guard + bind-time adapter check + config cross-check | `self_loop_target_refused_even_with_matching_rule`, `adapter_pointing_at_listener_makes_ingress_unavailable` |
| 6 | DNS leaks | no local resolution of client names; Direct needs literals; `dns_protected` untouched | `direct_route_with_hostname_is_refused_without_resolution` |
| 7 | Parser abuse / smuggling | exact-length reads, no `BufReader`, deny-panic lints, proptest | `socks5_parser_*`, `socks5_parser_never_panics_on_arbitrary_bytes` |
| 8 | Resource exhaustion | permits via `try_acquire`, buckets, deadlines, backoff, IPC accept fix, drain | `max_connections_enforced_and_slot_reused`, `slowloris_handshake_times_out`, `sskd_survives_fd_exhaustion_on_ingress` |
| 9 | Audit flooding | own ledger, group commit, first-occurrence-durable coalescer, Summary, rotation/retention, no ledger read in status | `denial_flood_stays_bounded_and_reconciles`, `rotation_preserves_chain_and_prunes_oldest` |
| 10 | Log / crash injection | validate then log; DEBUG-only escaped truncated raw text; panic budget; crash-record cap | `crlf_host_cannot_forge_a_log_line`, `crash_records_are_capped` |
| 11 | Confused deputy | profile only from arm / `arm_on_start`; constant `app_id`; no client credentials or profile input | `client_cannot_influence_profile_or_app_id` |
| 12 | Honest status | section 10 | `status_never_claims_protection_while_armed`, `ingress_strings_contain_no_forbidden_words` |
| 13 | Direct fallback | executor Fallback removed; route guard; one dial site | `fallback_route_never_dials_direct`, `dead_adapter_plus_lower_priority_direct_never_reaches_target` |
| 14 | TLS terminal hop | `ROUTE_NOT_DIALABLE` unless last hop is Socks5/HttpConnect | `tls_terminal_route_is_refused` |

## 15. Windows plan (cannot be verified here)

* W1 (`ssk-winhost/src/ingress_bind.rs`, unsafe allowed): `bind_exclusive_loopback(SocketAddrV4, backlog) -> io::Result<std::net::TcpListener>` setting `SO_EXCLUSIVEADDRUSE` before bind, modelled on `vpn_endpoint.rs`; the daemon adapter calls `set_nonblocking(true)` and `TcpListener::from_std`.
* W2 (`ssk-winhost/src/loopback_owner.rs`): `loopback_peer_owner(client, listener) -> OwnerVerdict` via `GetExtendedTcpTable` owner PID -> `OpenProcessToken` -> `TokenUser` SID compared with `current_user_sid()`; failure => `Unknown` => refuse. IPv4 only (the existing table code is IPv4-only). PID reuse and protected processes are documented limitations (`pipe.rs` already records why PID identity is weaker than a kernel-captured credential).
* Until both land: `hardening: required` leaves the ingress `unavailable` on Windows (honest, fail closed). `best_effort` works but any local user could use or squat the proxy, and status and doctor say so.
* CI: real-`sskd` ingress tests set `hardening` through one helper (`Required` on Linux, `BestEffort` on Windows until W2), so `windows-latest` does not fail on the default; in-process tests inject a `FakePlatform{controls: both true}` on both OSes. No test file is gated wholesale by `cfg`.
* The interim `netsh` kill switch blocks all outbound programs including `sskd`'s own dials (per the winhost reader); ingress dials would therefore fail closed while it is engaged. Unverified.

## 16. What this does NOT protect (read this before writing any UI text)

* **Only applications that are configured to use the loopback proxy.** There is no capture: no Wintun, WFP, fake-IP, system-stack NAT, PAC, or OS proxy-settings writer. An application that ignores the proxy is unaffected and unrecorded. This is **not** system-wide coverage and no status text may imply it.
* An application configured for the proxy may itself fall back to direct when the proxy refuses or is disarmed; SSK cannot prevent that.
* DNS an application performs itself is outside the daemon; an application that resolves a name and sends the IP bypasses domain rules. The daemon never resolves client names for proxied routes (the upstream proxy does), and refuses Direct-by-name in M2. A malicious or misconfigured upstream proxy can resolve a name to an internal address (SSRF via the proxy); numeric aliases and `localhost` are refused locally, other names are not classifiable. The first-hop proxy hostname itself is resolved by the OS resolver.
* UDP, QUIC, UDP ASSOCIATE, BIND, IPv6 listeners (applications that resolve `localhost` to `::1` reach nothing; configure `127.0.0.1`), and any non-SOCKS5 front end.
* Same-user hostile code. Different local users: blocked on Linux, **not blocked on Windows** until W1/W2; reported in status.
* Process attribution: every flow is `local-proxy:unattributed`. No per-app rules.
* Audit integrity is prefix integrity only: deleting the directory or the newest segments is not detected; retention prunes history; `ts_ms` is an untrusted wall clock; the ledger records authorisation, destination, rule, result and byte counts, not payload.
* Destinations are recorded (host and port per admitted flow) for up to the retention window: a local browsing log (open question 6).
* Upstream proxy credentials, mTLS and TLS-then-CONNECT chains are not supported (config carries no credentials); a terminal `TlsTunnel` is refused. OpenVPN stays `OPENVPN_NOT_READY`.
* Suspend/resume: upstream tunnels that died during sleep persist until keepalive/idle timeout; the optional resume heuristic is a heuristic, not a power-event hook.
* A hostile local user can always make the port unusable by flooding it at kernel level.
* Nothing here changes the kill switch, and `Protected` still means one held egress session.

## 17. Documentation claims that must be corrected (code wins)

New: `docs/adr/0009-local-proxy-ingress.md` (and an ADR 0008 addendum: the ingress is a second caller of the same path, closure unchanged at 17); a dated continuation in `docs/RESTART_ASSESSMENT_2026-09-21.md` (do not edit history).

Existing statements, verified by grep unless marked inherited:

* `README.md:83, 162, 342, 504-505` ('no traffic ingress', 'writes zero bytes', 'no application bytes', `transport_mut` has no callers): accurate today, false after M2; rewrite as the scoped claim in section 16 rather than deleting. `README.md:507` ('AppConfig is not passed into Supervisor::new; registry hardcoded') is already false. `README.md:379, 560` show `version: 2` (current is 4, 5 after C-config). `README.md:645` says the scope decision is pending; it was decided 2026-08-02 (inherited from the decision-record reader). `README.md` describes `breaking_change_guard` as detection; it only echoes.
* `crates/ssk-ipc/src/state.rs:20`: `Protected` documented as 'Active and verified (route + DNS covered)'; the code sets it after connect and durable result regardless of DNS, kill switch or liveness.
* `crates/ssk-daemon/src/supervisor.rs:326`: static `"live (real, connected)"`; the ActivateProfile comment 'until the peer-SID check lands' (IPC peer check has landed); the `ListRecentFlows` comment and the `InspectFlow` message ('no captured flow'); `crates/ssk-ipc/src/dto.rs` `FlowSummaryDto` doc 'Empty until ssk-capture (Phase 4)'.
* `docs/adr/0008-...md`: 'no crate outside the token's defining crate can dispatch without one' holds only for the `DataPlane` trait (`RouteExecutor::connect` is public and token-free); the 16-crate closure text (test pins 17); the 'LoadedConfig is discarded', 'hardcoded rules' and 'CIDR / port-range / process-path criteria' statements.
* `docs/ROUTING_AND_OPENVPN_STATUS.md:38-42` (`trace-route`/`inspect-flow` are IPC requests, not CLI commands; `inspect-flow` now answers), `:29` ('no automatic direct-fallback action' is true of config and planner, was false of the executor until C-N1), `:99-103` open items.
* `docs/DESKTOP_CLIENT_ARCHITECTURE.md` G.4 #2 'No silent direct fallback' and #5 'DNS honors the route' (:589-593) claimed 'enforced + tested' (executor Fallback arm; OS resolver for Direct); K.1/K.2 `Protected` = route + DNS verified.
* `docs/COMPATIBILITY_MATRIX.md`: add config v5 (one-way), the new ledger directory/format, additive IPC fields, `SetIngress`. `docs/RUNBOOK.md`: arm/disarm/recover procedures, corrupt-ledger procedure, retention. `docs/P4_INGRESS_DESIGN.md` P4b row: the listener lives in `ssk-daemon`; an async `IngressProvider` cannot sit in async-free `ssk-netadmin`. `crates/ssk-netadmin/src/audit.rs` reserved-outcome comments, `ssk-ipc/src/auth.rs` `PeerIdentity` doc (public enum, not a capability), `main.rs` 'Bounded drain' comment, `shutdown.rs` service-host doc, `SECURITY.md` ('forbid(unsafe_code) workspace-wide' vs `ssk-winhost`; inherited).

## 18. Resolution of every serious flaw the judges raised

| Flaw | Resolution |
|---|---|
| Accept bucket and permits charged before peer authorization (security) | Fixed: peer budget is separate and cheap; shared budgets are charged only after a verified peer (7.1); test `peer_refusals_do_not_consume_accept_budget`. |
| Denials queued, not durable before reply (security) | Fixed: first occurrence per key durable before the reply; repeats folded into Summary (6.5, 7.2). |
| Permanent capacity latch, not shippable (security) | Fixed: rotation and retention in M2 (G4); capacity before G4 refuses new dials only; no trip. |
| One panic trips the whole ingress (security) | Changed: panic budget of 3 per boot, crash records capped (X1), trip is recoverable by re-arm. Still fails closed after the budget, deliberately: a panic on a hostile-input surface is a defect, and repeating it is worse than stopping. |
| Split audit trail (security, desktop) | Mitigated, unification rejected: one-way rewrite of `audit.json` under 23 pinned tests and an O(n) backend is the largest blast radius in the three designs (implementability judge scored it 3). Doctor verifies both; `GetAuditEntries{ledger}` and `ssk ingress audit` read the ingress tail; both documented. |
| Windows has no working default (security, desktop) | W1/W2 are in the series; `required` stays the default; `best_effort` is visible; open question 1. |
| New `Request::SetIngress` (all three) | Kept, reasoned in section 11. |
| Two-key special-use not tied to matched rule (security) | Fixed: single key bound to the matched rule's own destination; allow-list removed from config. |
| Names resolved remotely (security) | Residual, documented (16). |
| Too large; commit ordering circular; dead-code warnings (implementability) | Spine/release/optional classification (section 21); `types.rs` first; `pub` items; HTTP CONNECT, GUI v3, pinned Direct deferred. |
| Accept-error classification hand-waved (implementability) | Replaced by count-based backoff. |
| Windows CI would fail on `required` (implementability) | Test helper picks hardening per OS; fake platform in-process. |
| Audit-trail determinism, ill-specified flood test (implementability) | Durable first denial gives a barrier; flood test uses injected tuning and reconciles counts without a 10 s wait. |
| Test/config floor inconsistency (implementability) | Floors 100 ms. |
| `Refusal2` placeholder (implementability) | Removed; engine/front-end split uses concrete `Admitted`/`Denied`/`Established` types. |
| ESTABLISHED-only peer row flaky (implementability) | State set `{01,04,05,08}`, inode non-zero. |
| Direct-by-name refused (desktop) | Kept for M2 (no local DNS, no TOCTOU, no new netcore API); pinned resolve-filter-dial is follow-on M2.5; open question 3. |
| GetStatus stalls behind activation (desktop) | Lock timeout + `StatusHint` (S3), plus activation deadline (S2). |
| v2 GUI shows nothing; ring is memory-only (desktop) | GUI v3 specified (section 20) and scheduled M2.4; ingress tail readable over IPC. |
| Restart-only latches; bind once; reboot leaves apps refused (desktop) | Re-arm recovers; `arm_on_start` opt-in; keepalive and resume heuristic as optional commits. |
| Notice contradicted its own forbidden-words test (found while synthesising) | Notice rewritten without any forbidden word. |
| Minimal-diff: special-use set built from all rules; gate coupled to activation; no peer auth shipped; accept-loop death for IPC (not adopted) | Not carried over; see section 19. |

## 19. Decisions where I deliberately did not follow a judge or a design

* **Serve independent of activation and of `FailClosed`.** One judge suggested denying service whenever the daemon is FailClosed/ConfigInvalid. ConfigInvalid already means no listener. FailClosed in this daemon describes the last probe activation or an `audit.json` integrity break; coupling would let one failed `ssk activate --dest` kill the proxy and would make the ingress a function of an unrelated dial. The ingress has its own prerequisites (valid config, healthy ledger) and its own latch.
* **Own ledger, not `audit.json`.** See section 18. Cost: two chains to reconcile; mitigated as described.
* **No `ActivateProfile{ingress}` overload.** See section 11.
* **No publish-on-drop status snapshot.** The lock-timeout hint reaches the same user-visible goal (GetStatus answers during a dial; `Activating` visible) with a handful of lines.
* **Special-use opt-in by matched rule only.** One key is sufficient because the operator owns the rules; a second config key added surface without adding a boundary.
* **Client-leg keepalive not adopted.** The client leg is loopback; its death is immediate or covered by the idle timeout. Keepalive is for the upstream leg only.
* **Arm-on-start is config, not persisted state.** `arm_on_start` is an explicit, audited operator opt-in with default `None`; the daemon never remembers an arm across restarts by itself.

## 20. Follow-ons (specified now so M2 does not paint them out)

* **M2.1 HTTP CONNECT** (`protocols: [socks5, http_connect]`, first byte `C` sniff): authority-form `CONNECT host:port HTTP/1.x` only; the head is read **one byte at a time** up to 8 KiB until CRLFCRLF (same approach as the egress client; no over-read, so pipelined client bytes stay in the kernel buffer and are pumped after admission); CRLF only, no obs-fold, duplicate or `Transfer-Encoding`/`Content-Length`/`Origin`/`Sec-Fetch-*` headers refused; no 200 before the `ResultReceipt`; error replies bodiless (`403` policy class, `502`/`504` route/dial, `503` budget) with `Connection: close`; no PAC, status page or CORS headers. Adds a 4-line enum variant; no config version bump if shipped before v5 is released.
* **M2.4 `DesktopSnapshotV3`** (new schema, command, capability, fixtures): `ingress{state, coverage, system_wide:false, listen, armed_profile, controls, counters, audit{state,entries}, last_error_code, last_denial}`, bounded `flows` (<= 50) with `flows_unavailable`; old daemon renders 'Dienst veraltet: Proxy-Status nicht verfuegbar'; unknown values render 'unknown, not covered'; when armed the UI shows the fixed sentence 'Nur Anwendungen, die diesen Proxy verwenden, werden geroutet. Alle anderen Verbindungen sind nicht erfasst.' and never combines it with the word Protected. The webview stays read-only until a write command and capability are designed (the negative test that `activate_profile` is denied stays). Until M2.4, the existing panel shows nothing about the ingress: **M2.4 is a gate for any release that calls itself a desktop client.**
* **M2.5 Pinned Direct-by-name:** `RouteExecutor::with_direct_guard(Arc<dyn DirectAddrGuard>)`; `direct::connect_tcp` resolves once with `lookup_host`, filters through the guard, dials the pinned `SocketAddr`; guard refuses special-use results unless a matched Direct rule names that exact destination, always refuses the listener's own address; resolution mode recorded per flow; lifts `DIRECT_REQUIRES_LITERAL` for names.
* Later lanes (Wintun/fake-IP/system-stack) plug in as new front ends feeding `decide`/`open_tunnel` with `Provenance::{NatOriginalDestination, FakeIpMapped}`; `Coverage` may exceed `proxy_clients_only` only after the privileged broker proves capture is enforced, never because a listener exists. 198.18.0.0/15 is already denied as special-use so the range stays reserved. `FlowDescriptor` is not reshaped (P4-GATE-3 is not pre-empted).

## 21. Commit plan overview and classes

SPINE = needed for the four acceptance criteria; RELEASE = required before a user-facing release; OPT = recommended hardening. Every commit must keep `cargo fmt --check`, `cargo clippy --workspace --all-targets -D warnings`, `cargo test --workspace` and `dependency_closure.rs` green. The full ordered list with per-commit tests is in the structured `commit_plan`; the test names are in `test_plan`. Acceptance mapping: (1) real client reaches a target through the chosen adapter: direct-rule, SOCKS5-adapter and HTTP-CONNECT-adapter tests with a relaying fake upstream that records the exact destination; (2) Deny prevents arrival: sentinel listener plus durable denial barrier; (3) matching audit trail: pending/result/closed with one flow id, matched rule, destination and chain, `verify_dir` ok; (4) no unintended direct fallback: dead adapter plus lower-priority Direct rule, rejected handshake, silent upstream, audit failures, executor Fallback test, OpenVPN.

## 22. Verification status

Nothing here has been compiled or run. Items to verify during implementation, each with a named test or manual step: Linux `exclusive_bind` semantics; `/proc/net/tcp` state/inode behaviour for half-closed and orphaned clients; `rustix::process::geteuid` under the existing `0.38` pin with the `process` feature added to the daemon; `copy_bidirectional` half-close behaviour through each adapter kind; fsync cost per group commit on CI runners (the 5 s audit deadline may need tuning); `socket2::SockRef` keepalive getters on Windows; every Windows behaviour (W1/W2, named-pipe accept, TIME_WAIT with exclusive bind, `Instant` across sleep for the resume heuristic); IPv6 loopback availability on runners (IPv6 literal tests must self-skip); TLS success paths (untestable on Linux; terminal TLS is refused anyway). The different-user rejection cannot be exercised as root in CI; it is covered by a fake authorizer and the manual script `scripts/manual_ingress_peer_test.sh`, which is weaker than a live test.


---

## Decisions recorded by the synthesis

1. Base design is the security-first one (judge totals 20 vs 18 vs 15); everything below is a graft or a correction on it. No new workspace crate, no new workspace edge: dependency_closure.rs and ADR 0008 stay as they are and ssk-runtime stays out.
2. The ingress is a second front end of the ADR 0008 path (FlowRecord -> evaluate -> plan/admit -> AdmissionToken -> DataPlane::connect_route -> transport_mut). It never calls RouteExecutor::connect/probe, never builds a RouteKind, never opens a socket except the accepted client socket; a source-scan test enforces it.
3. The ingress is independent of the held probe session, of ssk activate --dest, and of DaemonState. Protected keeps meaning 'one held egress session'; arming, flows, denials and trips never set Protected/Active/Degraded/FailClosed; dns_protected and kill_switch are never derived from the ingress. A failed probe activation does not stop the proxy (rejected the 'serve only while not FailClosed' suggestion: it would let one failed probe kill the proxy).
4. Fail-closed lifecycle: enabled=false by default; an enabled listener starts disarmed (accept, read nothing, close); arming is an explicit audited operator action (SetIngress or the opt-in arm_on_start, default None) with the durable Armed record written before the gate opens; Deactivate disarms first and always works.
5. Latches are recoverable without a daemon restart: audit write failure, panic budget (3), fatal accept errors or listener death trip the gate; an explicit re-arm re-verifies the ledger, resets counters, rebinds if needed, and only then arms. A corrupt chain stays unavailable with a RUNBOOK procedure.
6. Ordering is enforced by types: dial() takes &PendingReceipt; write_success() and pump() take &ResultReceipt; receipts have private constructors in audit.rs (compile_fail doctest). Pending is durable before the dial, Result durable before any reply or byte, Closed best-effort after; audit failure before dial = no dial, after connect = upstream dropped before any reply.
7. Peer authorization runs before the first byte is read and before any shared budget is charged: a separate cheap PeerBudget (bucket + 8 in-flight) gates the check, and only verified peers consume the accept bucket and connection permits. Unknown means refuse. Linux uses /proc/net/tcp (client-side row, state in {01,04,05,08}, non-zero inode, uid vs geteuid). hardening: required is the default and makes a platform without exclusive bind and peer check unavailable.
8. Windows hardening (SO_EXCLUSIVEADDRUSE listener, owner-PID to SID resolver) is moved into the M2 series as commits W1/W2 in ssk-winhost (the only place unsafe appears); until they land Windows is unavailable under required. Tests choose hardening per OS through one helper so windows-latest CI does not fail; in-process tests inject a fake platform.
9. Own audit ledger directory (segments of JSONL, blake3 chain over stored bytes, single writer thread, group commit, replies only after fsync, torn-tail recovery, metadata-length tamper check). audit.json is not rewritten or converted (one-way format change, O(n) backend, 23 pinned tests). Rotation and retention are in M2 (Continue record), so there is no permanent capacity latch; defaults 8 x 32 MiB.
10. Denials: first occurrence per (profile,host,port,reason,rule) per 60 s window is durable before the refusal reply (bucket 1/s burst 20, 128 keys); repeats and over-budget denials are counted and emitted as Summary records so counters reconcile; pre-handshake garbage, malformed targets and peer refusals are counted only (the repo's 'rejected input must not grow the ledger' rule).
11. No local DNS for client-supplied names. Proxied routes forward names unresolved; Direct is accepted only for IP-literal targets (DIRECT_REQUIRES_LITERAL). Pinned resolve-filter-dial Direct-by-name is follow-on M2.5, gated by an open question.
12. Target canonicalisation before policy: ASCII only, lowercase, trailing dot trimmed, v4-mapped v6 unmapped, valid_host, final label must start with a letter (kills 2130706433, 127.1, 0x7f.1), localhost refused, listener self-loop unconditional. Special-use literals are reachable only if the matched rule's own destination equals the literal (single key; the allow-list config field from the security-first draft is dropped).
13. RouteKind::Fallback becomes non-executable in the executor (the only fallback mechanism in the codebase) and is refused by the ingress route guard together with OpenVPN, Direct+name and any route whose last hop is not Socks5/HttpConnect. Exactly one connect_route call site, no retry; optional fail-fast cool-off per adapter chain refuses instead of retrying.
14. Executor gets a whole-dial deadline (default 30 s; main.rs sets connect_timeout + 5 s when ingress is enabled); the activation connect gets a daemon-owned 20 s deadline; direct dial and http_connect become IPv6-literal safe. A silent proxy can no longer hang the supervisor mutex or a flow.
15. GetStatus never waits behind a dial: Inner lock with a 100 ms timeout, otherwise answer from a StatusHint (last status, Activating overlay while an activation is in flight). Rejected the publish-on-drop snapshot design (blast radius); Activating becomes observable for the first time.
16. IPC is additive plus one new variant: StatusDto.ingress (capability marker), FlowSummaryDto/AuditEntryDto extra Option fields, GetAuditEntries gains a ledger selector, ListRecentFlows/InspectFlow become real with FLOW_NOT_RETAINED vs FLOW_NOT_FOUND, and Request::SetIngress. The new variant is kept on purpose: overloading ActivateProfile would make version skew destructive (old daemon would clear the held session and go FailClosed), while an unknown variant only drops a connection.
17. Status honesty is structural: separate ingress block with closed state words, machine-readable coverage in {none, proxy_clients_only}, constant system_wide=false, computed 'armed', own last_error, unknown values render 'unknown, not covered', forbidden-words scan (protected, protection, secure, system-wide, all traffic, vpn). The security-first coverage notice contained 'system-wide' and would have failed its own scan; it is rewritten. The static adapter-health string and the Protected doc comment are corrected.
18. Config v5: required ingress section (default disabled) with deny_unknown_fields on every struct, Ipv4Addr listen, closed enums, limit floors of 100 ms and ceilings (0 never means unlimited), audit segment/retention knobs, optional arm_on_start validated against routing profiles, fixed 3-arm and new 4-arm in migrate_value, smuggling tests over versions 1-4 in both formats, schema/example/matrix updated in the same commit.
19. Scope control: SOCKS5 NO_AUTH only in M2; HTTP CONNECT (byte-at-a-time head read, no over-read) is specified as M2.1; GUI DesktopSnapshotV3 specified as M2.4 and made a gate for any release called a desktop client; CLI limited to ssk ingress status|arm|disarm|flows|inspect|audit. Commits classed SPINE / RELEASE / OPT.
20. Robustness fixes the ingress depends on are separate small commits: IPC accept loops back off and continue (count-based, give up after 60 consecutive errors) so ingress fd pressure cannot end the daemon; ssk-diag crash records capped (every panic fsyncs a record today); runtime.shutdown_timeout before drop(lock) and a real JoinSet/audit-writer drain.
21. Deny-lints (unwrap, expect, indexing, panic, todo, unimplemented, unreachable) on the whole ingress tree, enforced by the existing clippy -D warnings gate, plus proptest on the parser; modules and items are pub so each intermediate commit is dead-code clean; shared leaf types land first to avoid the circular dependency between audit and shared state.
22. Operational gaps from the desktop review are handled to the extent verifiable: upstream keepalive (opt), resume-skew heuristic that cancels flows (opt, marked unverified on Windows), failure cool-off, arm_on_start for reboots, recovery without restart. Client-leg keepalive and a power-event hook are not adopted (loopback leg; needs service/FFI work).

## Commit plan (as proposed)

* C-00 [SPINE] docs: add docs/adr/0009-local-proxy-ingress.md (Proposed) and this design as docs/M2_LOCAL_INGRESS_DESIGN.md. Docs only; records trust boundary, matched-rule special-use rule, no-local-DNS rule, audit ordering, status vocabulary, closure unchanged.
* C-N1 [SPINE] ssk-netcore: RouteKind::Fallback becomes non-executable in RouteExecutor::connect (returns NoRoute, never dials). Test fallback_route_never_dials_direct reproduces the verified silent-direct behaviour first (sentinel sees zero connections after the change). Independent; closes the only latent fallback path.
* C-N2 [SPINE] ssk-netcore: RouteExecutor::with_dial_deadline (default 30 s) wrapping the whole connect; direct::connect_tcp via (host,port) tuple so IPv6 literals work; http_connect brackets IPv6 authorities and refuses space/control characters. Tests: silent proxy bounded, IPv6 authority, IPv6 literal Direct (self-skips without ::1).
* C-P1 [SPINE] ssk-netadmin: MatchCriteria::matches never applies dest_suffix to an IP-literal host; pub summarise_route; test that the planner never emits Fallback. Tests: suffix_rule_never_matches_ip_literal, planner_never_emits_fallback.
* C-X1 [RELEASE] ssk-diag: prune crash records to the newest 32 on write (every panic currently fsyncs an uncapped record). Test crash_records_are_capped.
* C-I1 [SPINE] ssk-ipc: Unix accept loop backs off and continues on any accept error via a pure AcceptRetry helper (50 ms to 1 s, give up after 60 consecutive errors); unit tests on the helper only. Independent of ingress.
* C-I1w [RELEASE] ssk-ipc: same treatment for the named-pipe accept loop (recreate the listening instance on error). Compiled and tested only by Windows CI; kept as a separate commit so it can be dropped or fixed alone.
* C-S1 [SPINE] daemon refactor, no behaviour change: hoist Arc<ConfiguredRouting> and Arc<dyn DataPlane> from Inner onto Supervisor (Supervisor::new keeps its Box signature via Arc::from); add ConfiguredRouting::decide and rule_destination; TraceRoute uses decide; store an owned IngressConfig copy outside the mutex. All 84 unit + 23 integration daemon tests pass unchanged.
* C-S2 [RELEASE] daemon: wrap the activation connect_route in tokio::time::timeout(ACTIVATE_DIAL_DEADLINE 20 s) with Supervisor::with_activation_deadline for tests; expiry is a durable FailClosed result with ACTIVATION_CONNECT_TIMEOUT. Test: silent proxy ends FailClosed and status answers.
* C-S3 [RELEASE] daemon: GetStatus takes Inner with a 100 ms timeout and otherwise answers from StatusHint (Activating overlay while an activation is in flight); adapter health string becomes 'connected at activation; liveness not monitored'; correct the Protected doc comment in ssk-ipc/src/state.rs. Tests: status_answers_while_activation_dial_is_silent, activating_is_observable.
* C-C1 [SPINE] ssk-config: ingress section, CURRENT_CONFIG_VERSION 5, new 4-arm, fixed 3-arm, ConfigError::Ingress, validate and cross-checks (self-loop, arm_on_start profile), schema $id/required/properties, snapshot assertion, routing_migration.rs updates, regenerated openvpn-routing.yaml and new ingress.example.yaml, ssk-cli 'to v2' string, COMPATIBILITY_MATRIX section. Nothing consumes the section yet; fixtures compile through AppConfig::default().
* C-W1 [SPINE] ssk-ipc: additive wire types (IngressStatusDto, StatusDto.ingress, FlowSummaryDto/AuditEntryDto fields), Request::SetIngress, GetAuditEntries.ledger selector; update clamp_request_limits, the supervisor handler and all literal/pattern sites (supervisor builder, ssk-desktop-client tests, apps/desktop/tests/webview_status.rs, ssk-ipc and named_pipe tests); supervisor answers ingress: Some(disabled) and SetIngress with INGRESS_DISABLED. CBOR old<->new compatibility tests.
* C-G1 [SPINE] daemon: ingress/mod.rs scaffold with the deny-lints, types.rs (Gate, TripReason, IngressState, Coverage, Tuning, notice, forbidden words) and target.rs (canonicalize, classify_ip, guard_self_loop, guard_special_use) with table tests. Pure code, pub items.
* C-G2 [SPINE] daemon: ingress/socks5.rs server parser/replier with duplex table tests, the exact-read test and the proptest never-panics test. Pure code.
* C-G3 [SPINE] daemon: ingress/audit.rs core: record types, LedgerIo, writer thread with group commit, receipts, verify_dir (Open and Reader modes), torn-tail recovery, metadata-length tamper check, capacity refusal without trip; Layout::flow_audit_dir. Tests with LedgerIo doubles.
* C-G4 [RELEASE] daemon: audit rotation and retention with the Continue record and verify_dir across segments; removes the capacity-refusal path from reachability. Tests: rotation_preserves_chain_and_prunes_oldest, continue_linkage_detects_tamper, restart_across_rotation.
* C-G5 [SPINE] daemon: ingress/limits.rs RateLimiter, PeerBudget, DenialCoalescer with explicit-Instant tests (first occurrence durable classification, Summary reconciliation).
* C-G6 [SPINE] daemon: ingress/pump.rs Counted wrapper, watchdog, cancellation; tests over tokio::io::duplex and real TcpStream pairs.
* C-G7 [SPINE] daemon: ingress/peer.rs traits, Controls, Linux /proc/net/tcp resolver with golden-line parser tests, FakeAuthorizer/FakePlatform, scripts/manual_ingress_peer_test.sh; add rustix feature process to the daemon on unix.
* C-G8 [SPINE] tests/support: net_fakes.rs (echo target, relaying SOCKS5 and HTTP CONNECT upstreams that record the exact destination, silent proxy, held-bound closed port), socks5_client.rs, daemon_harness.rs (spawn sskd, readiness by IPC, port discovery through status, bounded wait_for_ledger), each with self-tests; included via the existing include! idiom.
* C-E1 [SPINE] daemon: ingress/shared.rs IngressShared (gate watch, epoch, status snapshot, counters, flow registry ring of 256, arm/disarm/trip/recover logic against a HostControl trait) with deterministic tests.
* C-E2 [SPINE] daemon: ingress/engine.rs decide, route guards, open_tunnel (pending -> dial -> result) with receipts; in-process acceptance matrix over the real NetcoreDataPlane wrapped for fault injection (direct, SOCKS5 adapter, HTTP CONNECT adapter, deny, no-rule, dead adapter + lower-priority Direct, handshake reject, silent proxy, OpenVPN, TLS-terminal, special-use, aliases, self-loop, audit failure before and after connect, ordering).
* C-E3 [SPINE] daemon: ingress/flow.rs (SOCKS5 driver) and ingress/host.rs (start, accept loop, peer-then-budget ordering, JoinSet, panic budget, backoff, drain, recover); in-process end-to-end tests on real loopback sockets (caps, slowloris, garbage, disarmed, disarm-cancel, panic budget, recovery, flood reconciliation). Not wired into main yet.
* C-E4 [RELEASE] daemon: FailureCooloff in the engine (5 consecutive failures per planned chain within 30 s refuse that chain for 10 s with a coalesced Denied ADAPTER_COOLING_OFF; never a retry, never a fallback). Droppable: nothing depends on it.
* C-F1 [SPINE] daemon wiring: IngressShared in Supervisor, SetIngress handler, StatusDto.ingress, Deactivate disarms first, ListRecentFlows/InspectFlow/GetAuditEntries{ledger}, RunDoctor checks, explain_code entries, main.rs host start with arm_on_start, real drain, runtime.shutdown_timeout before drop(lock), executor dial deadline from config.
* C-F2 [SPINE] daemon: real-sskd acceptance suite ingress_daemon.rs: all four acceptance criteria, fd exhaustion, bind failure, corrupt ledger, restart chain continuity, shutdown drain, activation/ingress isolation, arm_on_start, desktop client still reads status with ingress block, status honesty and forbidden-words scan.
* C-F3 [RELEASE] ssk-cli: ssk ingress status|arm|disarm|flows|inspect|audit, an ingress line in human ssk status, capability-marker check and IPC_IO_FAILED hint; subprocess tests against a real sskd.
* C-WIN1 [RELEASE] ssk-winhost: bind_exclusive_loopback (SO_EXCLUSIVEADDRUSE) and the daemon-side Windows IngressPlatform::bind; Windows test that a second bind fails. Cannot be verified here.
* C-WIN2 [RELEASE] ssk-winhost: loopback_peer_owner (owner PID to SID) and the Windows PeerAuthorizer; Windows test for the current user; flips Windows controls to both true.
* C-H1 [OPT] ssk-netcore: TCP keepalive (60 s / 20 s) on first-hop and Direct upstream sockets via socket2::SockRef; test asserts SO_KEEPALIVE is set.
* C-H2 [OPT] daemon: resume-skew heuristic (wall clock vs monotonic skew over 10 s bumps the gate epoch, cancelling flows; injected Clock in tests). Marked unverified on Windows; the real fix is a power-event hook in ssk-winhost/service.
* C-H3 [OPT] ci: make breaking_change_guard fail unless COMPATIBILITY_MATRIX.md changed when crates/ssk-config/, ssk-ipc/src, ssk-netadmin/src/audit.rs or ssk-daemon/src/ingress/audit.rs changed; fetch-depth 0 so the diff works. Cannot be verified without a CI run.
* C-D1 [RELEASE] docs: correct every statement in section 17, add RUNBOOK procedures, COMPATIBILITY_MATRIX entries, ADR 0008 addendum, dated RESTART_ASSESSMENT continuation, ADR 0009 to Accepted. Doc fixes also ride in the commit that makes each statement false.
* Follow-on M2.1 [after M2] HTTP CONNECT front end with the strict byte-at-a-time parser and hostile-input tests. Follow-on M2.4 DesktopSnapshotV3 plus UI section and Tauri command (gate for any release called a desktop client). Follow-on M2.5 pinned Direct-by-name with DirectAddrGuard.

## Test plan (as proposed)

* [ssk-config] ingress_default_is_disabled_loopback: default AppConfig has enabled=false, 127.0.0.1:0, [socks5], hardening required, arm_on_start None; old fixtures keep loading.
* [ssk-config] ingress_rejects_non_loopback_listen_in_both_formats: 0.0.0.0, LAN, ::1, localhost, [::1] rejected via YAML and TOML (assert_rejected_in_both_formats).
* [ssk-config] ingress_limits_and_protocols_validation: empty/duplicate protocols, zero and over-ceiling limits, audit.segment_mib/retain_segments out of range rejected; 100 ms floors accepted.
* [ssk-config] ingress_unknown_keys_rejected_at_every_level: typos in ingress, ingress.listen, ingress.limits, ingress.audit rejected.
* [ssk-config] v4_config_migrates_to_v5_with_ingress_disabled; v3_migration_still_inserts_default_routing_and_ingress; old_versions_cannot_smuggle_ingress (versions 1-4, both formats).
* [ssk-config] arm_on_start_must_name_a_routing_profile and adapter_endpoint_equal_to_listener_is_rejected (static self-loop; port 0 not rejected on that basis).
* [ssk-config] ingress_schema_keys_equal_serialized_default_keys and schema_snapshot_stable (v5 id).
* [ssk-netcore] fallback_route_never_dials_direct: Fallback{SingleHop(dead socks5), Direct} returns an error and a sentinel listener sees zero accepts.
* [ssk-netcore] dial_deadline_bounds_a_silent_proxy_handshake; http_connect_brackets_ipv6_authority_and_refuses_control_chars; direct_dial_accepts_ipv6_literal (self-skips without ::1); keepalive_is_set_on_upstream_sockets (opt commit).
* [ssk-netadmin] suffix_rule_never_matches_ip_literal (suffix 0.1 vs 10.0.0.1) and planner_never_emits_fallback.
* [ssk-diag] crash_records_are_capped_to_32_newest.
* [ssk-ipc] accept_retry_backoff_table_and_gives_up_after_60; status_dto_decodes_with_and_without_ingress (hand-written pre-change struct copy both ways over ciborium); flow_summary_and_audit_entry_old_new_roundtrip; get_audit_entries_with_and_without_ledger_selector; set_ingress_request_cbor_roundtrip.
* [daemon] all pre-existing suites (activation_safety, round_trip, event_backpressure, killed_task_transitions, kill_switch_status, peer_authentication, desktop_read, dependency_closure) stay green unchanged across the refactor commits; dependency_closure_is_the_set_adr_0008_recorded and denied_core_stays_out run on every commit.
* [daemon] activation_with_silent_proxy_times_out_and_status_stays_responsive; status_answers_while_activation_dial_is_silent (GetStatus under 500 ms, state Activating); status_hint_is_not_used_when_the_lock_is_free.
* [ingress::target] canonicalize_table (lowercase, trailing dot, mapped-v6 unmapping, ASCII only, 253-byte limit, underscore, brackets, localhost, name that parses as IP becomes literal); numeric_alias_targets_are_refused (2130706433, 127.1, 0x7f.1, 0177.0.0.1, 0x7f000001, 2852039166, 0); classify_ip_edges for every special-use range including 198.18.0.0/15, 169.254.169.254, 64:ff9b::/96, 2002::/16.
* [ingress::target] special_use_needs_matched_rule_destination (exact-destination rule unlocks only that literal); deny_rule_literal_does_not_unlock_port_only_rule; self_loop_refused_even_with_matching_rule (port matters).
* [ingress::socks5] greeting_requires_version_5; rejects_zero_methods; requires_no_auth_method (05 FF); bind_and_udp_associate_get_07; unknown_atyp_gets_08; empty_domain_zero_port_nonzero_reserved_close_silently; reads_exactly_the_request_and_not_one_byte_more; success_reply_has_zeroed_bnd.
* [ingress::socks5] socks5_parser_never_panics_on_arbitrary_bytes (proptest with_cases 256 plus truncation at every offset, bounded read count <= 519 bytes).
* [ingress::audit] roundtrip_and_verify; detects_modified_line; detects_deleted_middle_line; detects_reordered_lines; genesis_and_gapless_seq; reader_mode_ignores_a_partial_last_line.
* [ingress::audit] torn_tail_is_truncated_and_noted; complete_corrupt_line_refuses_open; missing_dir_is_empty_chain; external_truncation_trips_via_length_check.
* [ingress::audit] group_commit_acks_only_after_sync (LedgerIo double records call order; one sync covers a batch); sync_failure_fails_every_job_in_batch_and_trips; pre_rotation_capacity_refuses_pending_without_trip_and_allows_terminal_records.
* [ingress::audit] rotation_preserves_chain_and_prunes_oldest; continue_linkage_detects_tamper; restart_across_rotation_continues_seq_and_flow_ids; oldest_retained_segment_starting_with_continue_verifies_as_anchored.
* [ingress::audit] receipts_cannot_be_constructed_outside_the_module (compile_fail doctest mirroring AdmissionToken's).
* [ingress::limits] rate_limiter_refills_deterministically; peer_budget_caps_inflight; denial_coalescer_first_occurrence_durable_repeats_counted; summary_reconciles_exactly (durable + suppressed == observed); key_table_is_bounded_at_128.
* [ingress::peer] parse_proc_net_tcp_golden_lines (ESTABLISHED, FIN_WAIT, CLOSE_WAIT, TIME_WAIT, orphan inode 0, server-side row ignored); owner_lookup_returns_own_uid_for_a_real_loopback_connection (linux); half_closed_client_is_still_authorized (linux); hardening_required_makes_unhardened_platform_unavailable.
* [ingress::peer] peer_other_user_is_refused_before_any_byte (fake authorizer DifferentUser and Unknown; mutation-proven: with the check removed the server would answer 05 00); peer_refusals_do_not_consume_accept_budget (50 refused connections then one authorized connection is admitted with accept burst 2). Different-uid on a real kernel is only covered by scripts/manual_ingress_peer_test.sh.
* [ingress::pump] counts_bytes_both_directions; half_close_is_propagated_each_way; idle_timeout_cancels_and_keeps_counts; gate_change_cancels_immediately; backpressure_bounds_memory.
* [ingress::shared] gate_epoch_changes_on_every_transition; arm_is_idempotent_for_same_profile; recovery_clears_tripped_and_unavailable_without_restart; registry_ring_evicts_oldest_and_inspect_reports_not_retained.
* [ingress_flow, in-process, real loopback sockets] ACCEPT-1a socks5_client_reaches_echo_target_through_direct_rule: explicit Direct rule on 127.0.0.1, bytes round-trip, ledger shows pending, result connected, closed with one flow id and bytes_up == bytes_down == payload, verify_dir ok.
* [ingress_flow] ACCEPT-1b socks5_client_reaches_target_through_socks5_adapter_and_proxy_saw_exact_destination: relaying fake records ATYP/host/port (name forwarded unresolved; an unresolvable .test name that only the fake can map), target saw exactly one connection from the proxy, result chain is the adapter.
* [ingress_flow] ACCEPT-1c socks5_client_reaches_target_through_http_connect_adapter: same with the relaying CONNECT fake; request line is the exact authority.
* [ingress_flow] ACCEPT-2/3 deny_rule_prevents_arrival_and_is_audited_before_the_reply: sentinel target, client gets 02, ledger is read immediately after the reply with no polling and contains a durable Denied with matched rule id and reason POLICY_DENY and no Pending; sentinel assert_no_connection after the reply barrier.
* [ingress_flow] no_matching_rule_is_default_denied (POLICY_NO_RULE); attestation_rule_is_denied (ATTESTATION_REQUIRED); unknown_adapter_is_denied_not_direct.
* [ingress_flow] numeric_alias_never_reaches_policy_or_network (domain 2130706433 with a sentinel on 127.0.0.1 and a permissive rule: counted rejection, zero arrivals); direct_route_with_hostname_is_refused_without_resolution (DIRECT_REQUIRES_LITERAL).
* [ingress_flow] ACCEPT-4 dead_adapter_plus_lower_priority_direct_never_reaches_target: priority-10 SOCKS5 adapter on a held-bound never-listening port, priority-20 Direct to the same destination; failure reply, sentinel accept count 0, ledger has exactly one pending and one failed result.
* [ingress_flow] handshake_reject_by_upstream_proxy_is_not_retried_directly; silent_upstream_proxy_times_out_and_closes (connect_timeout 300 ms; client failure well under 2 s; permit freed; connect_failed counter); openvpn_route_is_refused_without_any_socket; tls_terminal_route_is_refused (engine guard fed directly); fallback_route_is_refused (guard fed a Fallback route).
* [ingress_flow] audit_failure_before_dial_prevents_dial (LedgerIo double fails the pending append; zero target connections; 01; gate tripped; next connection gets zero bytes); audit_failure_after_connect_closes_the_upstream (target observes EOF/reset, client never sees success, tripped); pending_is_durable_before_the_dial_observes_a_connection (DataPlane wrapper reads the ledger inside connect_route); result_is_durable_before_the_success_reply.
* [ingress_flow] disarmed_listener_reads_nothing_and_closes; disarm_and_rearm_cancel_in_flight_flows (both ends see EOF, Closed reason gate_closed); cancel_between_pending_and_result_writes_terminal_failed_record.
* [ingress_flow] max_connections_enforced_and_slot_reused; slowloris_handshake_times_out; cross_protocol_first_bytes_get_zero_bytes_back (TLS hello, GET, SOCKS4, random); idle_timeout_closes_tunnel; half_close_propagates_both_ways; large_transfer_4mib_each_way_keeps_counters_exact.
* [ingress_flow] denial_flood_stays_bounded_and_reconciles: injected Tuning (large accept burst, summary_tick 200 ms), 2000 denied connections, durable Denied records <= keys + bucket, after host.flush_summaries() durable + summary counts == the denied counter; GetStatus latency bounded during the flood; no 10 s wall-clock wait.
* [ingress_flow] flow_panic_budget_trips_after_three_and_rearm_resets (DataPlane double panics inside connect_route; two panics keep serving; third trips; later connections get zero bytes; IPC unaffected; re-arm recovers); tripped_gate_is_recoverable_by_rearm_without_daemon_restart (LedgerIo factory fails once, then healthy).
* [ingress_flow] failure_cooloff_refuses_chain_after_five_failures_without_dial_or_pending (explicit Instants); crlf_host_cannot_forge_a_log_line; client_cannot_influence_profile_or_app_id; trace_route_and_live_flow_agree_on_policy_plan.
* [ingress_daemon, real sskd] sskd_end_to_end_via_ipc_arm: enabled ingress with port 0; poll GetStatus until state disarmed and listen present; SetIngress arm; SOCKS5 client reaches echo target; ListRecentFlows/InspectFlow return the flow with audit seqs; Deactivate disarms; later connection gets zero bytes; verify_dir on the state dir succeeds.
* [ingress_daemon] status_never_claims_protection_while_armed (DaemonState stays Inactive, dns_protected false, StatusDto.last_error untouched, coverage proxy_clients_only, system_wide false); ingress_strings_contain_no_forbidden_words (notice, state words, doctor text, CLI lines, rendered status).
* [ingress_daemon] default_config_opens_no_listener; config_invalid_means_no_listener_and_ipc_stays_up; bind_failure_is_reported_and_ipc_stays_up (port pre-held; no other port used); corrupt_ledger_marks_ingress_unavailable_and_keeps_ipc; torn_tail_is_recovered_on_start; rearm_after_bind_failure_succeeds_once_port_is_free.
* [ingress_daemon] sskd_survives_fd_exhaustion_on_ingress (unix; sh -c 'ulimit -n 96; exec sskd'; GetStatus still answers and the process stays alive); graceful_shutdown_drains_flows_and_writes_closed_records (SIGTERM; exit 0; lock released after the writer joined); restart_continues_chain_and_flow_ids_are_unique; arm_on_start_arms_with_durable_record_cause_config_autostart.
* [ingress_daemon] activation_and_ingress_do_not_bleed_state (ssk activate --dest holds a session while a denial flood runs: state stays Protected; a failed activation does not disarm or trip the ingress); desktop_client_still_reads_status_with_ingress_block.
* [ingress_daemon] ingress_never_dials_by_itself (source scan in the style of the_cli_never_constructs_a_broker, needles built with concat!: RouteExecutor, connect_tcp, TcpStream::connect, AdmissionToken { in src/ingress above #[cfg(test)]); exactly_one_connect_route_per_admitted_flow_and_none_otherwise (counting DataPlane wrapper over NetcoreDataPlane).
* [ssk-cli] ingress_commands_against_real_sskd (arm/disarm/status/flows/inspect/audit); ingress_arm_against_daemon_without_ingress_block_prints_capability_error_and_sends_nothing.
* [ssk-winhost, Windows only, not run here] exclusive_bind_prevents_a_second_listener_on_the_same_port; windows_owner_resolver_identifies_the_current_user.
* [daemon, opt] resume_heuristic_cancels_flows_on_clock_skew (injected Clock).

---

## Appendix A: review findings (unresolved)

Verdict of the completeness critic: **needs-revision**.

### Gaps (missing from the design) (21)

* Arm/disarm/trip/recover are not serialized. arm() awaits an fsync (append_armed) and only then does gate.send; disarm() sends first. Nothing says a control mutex or generation compare-and-set guards them. A late-completing arm can overwrite a Deactivate/disarm or a trip, and two concurrent SetIngress calls with different profiles can leave the ledger's last Armed record disagreeing with the live gate. Needs one async control lock, or a check that the gate epoch is unchanged before gate.send.
* No story for how IngressShared emits events (see contradiction 1). Arm/disarm/trip notifications are specified as Event::Warning, but the bus is not reachable without the Inner lock, and IPC clients never receive events. Trip visibility therefore depends entirely on GetStatus polling. The design does not say so.
* StatusHint is underspecified. It must overlay a fresh IngressShared::snapshot() and a fresh kill_switch view (the provider sits outside the lock, supervisor.rs:35) on the cached StatusDto. As written ('the last StatusDto computed or published'), a trip or disarm during a 20 s activation dial still reports ingress.state=armed and coverage=proxy_clients_only. That is a status-honesty violation, and the design's own honesty test would not catch it.
* Only GetStatus gets the 100 ms lock timeout. ListProfiles, TraceRoute, GetAuditEntries, VerifyAuditChain, RunDoctor and Deactivate still queue on inner.lock() behind an activation dial for up to 20 s (supervisor.rs:673, 712, 724, 778, 793, 815). Deactivate-after-disarm therefore still hangs, and it can return KILL_SWITCH_ARMED (supervisor.rs:672-689) after the proxy was already disarmed, which is an error response with a partial effect.
* RunDoctor's new ingress:audit check re-verifies up to 256 MiB of retained segments. It sits in a handler that holds the Inner mutex for the whole call (supervisor.rs:814-815), so the verification would block activation, status fallback and every other handler. Specify spawn_blocking outside the lock. Specify too how verify_dir(Reader) behaves when the writer rotates and prunes a segment mid-read (ENOENT must not be reported as corruption).
* File-system durability and security of the new ledger are unspecified. (a) There is no parent-directory fsync after creating ingress-audit/ or a new seg-*.jsonl, or after rotate/prune, so a record acknowledged as durable can vanish with its directory entry. (b) There are no file or directory modes and no Windows ACL. The daemon creates the state dir with default permissions (main.rs:67), and only audit.json gets 0600 because tempfile creates it (ssk-tensor/src/lib.rs:409). The new ledger is a destination log and would be umask-readable. (c) No O_NOFOLLOW, create_new or owner check on the segment files. (d) On Windows, prune or rename of a segment that AV or a reader has open fails with a sharing violation. The design makes any rotate error a write fault (6.4) that trips the ingress, so the proxy would stop at each rotation until re-armed. Prune must be non-fatal, and readers must open with FILE_SHARE_DELETE (the repo already knows this: lock.rs:68-69, 286).
* Audit semantics for timeouts and cancellation. append_pending has a 5 s client-side deadline, but the queued job is still written later by the writer thread. A flow that answered 01 without dialing then leaves a durable Pending, which the ledger defines as 'dial may have happened', so an auditor cannot tell it from a real attempt with unknown outcome. The design also never says whether AuditError::Timeout trips the gate. 7.2 row 5 says 'writer failure trips', and a transient fsync stall (Defender) would otherwise force a manual re-arm. Receipts and queued jobs need cancel-safe semantics or a compensating terminal record. FlowAuditWriter::close(self) is also incompatible with the Arc<FlowAuditWriter> held by EngineCtx and IngressHost.
* Records carry matched_rule ids but no fingerprint of the active config or rule set (for example a digest in Started). After any config edit, rule-3 in an old record cannot be interpreted. The ledger is size-retained (8 x 32 MiB), so a steady stream of distinct first-occurrence denials (1/s allowed) evicts the admitted-flow evidence. There is no separate retention or budget for Denied versus Pending/Result.
* Shutdown budget and ordering are unspecified and internally inconsistent. main.rs:39 sets DRAIN_DEADLINE to 2 s, Tuning.drain is 3 s, section 8 says 3 s, and host.shutdown(DRAIN_DEADLINE) is used in section 12. On top come audit.close with an fsync, bounded Closed writes of 1 s each, and runtime.shutdown_timeout(2 s). The total is not compared with the OS deadlines main.rs:36-39 and shutdown.rs:28-40 (is_os_deadline) already say will not be waited for. Flows aborted after the drain cannot write Closed, because a Drop cannot await. Nothing says what a Windows ServicePreshutdown does to the audit writer or the lock ordering.
* Sustained fd pressure still ends the daemon or trips the ingress (see contradiction 4). Nothing ties max_connections (2 fds per tunnel plus dial transients plus 8 in-flight peer checks) to RLIMIT_NOFILE. There is no reserved fd for IPC and no pause of accept at capacity. The doctor check ingress:fd_budget only reports. Control-plane starvation (Deactivate/disarm failing at IPC accept) is not addressed.
* Windows restart failure mode: with SO_EXCLUSIVEADDRUSE, rebinding a fixed port while connections sit in TIME_WAIT can fail for minutes (the design lists it only under 'to verify'). Bind is retried only on a manual re-arm, so arm_on_start will fail on exactly the crash/restart/update case. A bounded automatic bind retry with backoff while the state is 'starting' is missing. Arm requests arriving during the background ledger verification ('starting') also have no defined behaviour.
* Default limits look unusable for a browsing desktop and are not configurable. These are max_connections 64, accept burst 32 / 64 per s, 8 in-flight peer checks each up to a 500 ms blocking /proc read, and idle_timeout 10 min. The Tuning constants are 'internal, NOT config'. Connections over the cap are closed with zero bytes instead of briefly queued. There is no per-source fairness, so one runaway app can take all 64 permits. There is no measurement or load test that backs the numbers.
* Linux peer authorizer coverage gap. Only /proc/net/tcp is read. A client that uses an AF_INET6 dual-stack socket to reach 127.0.0.1 (typical for JVM-based apps) is listed in /proc/net/tcp6 as a v4-mapped address, so its row is 'missing', the verdict is Unknown, and it is refused. Reads of /proc/net/tcp are also not an atomic snapshot (seq_file can skip or duplicate rows under socket churn), and the design has no retry. This makes legitimate refusals possible and makes real-authorizer tests flaky under parallel cargo test. Each check is O(table size) and can run 256/s with 8 in flight, which is a cheap CPU-amplification path for any local account. A short-lived parsed-table cache or a retry is not specified.
* IPC compatibility gaps. (a) GetAuditEntries.ledger is silently ignored by an old daemon: Request has no deny_unknown_fields (ssk-ipc/src/server.rs:31, handler supervisor.rs:777-791), so an old daemon returns the activation ledger as if it were the ingress ledger. The capability-marker check is specified only for `ssk ingress arm`. Likewise `ssk ingress flows/inspect` against an old daemon yield an empty list or FLOW_NOT_FOUND (supervisor.rs:718, 772-775) that read as 'no traffic'. (b) `ssk --json status` prints the whole StatusDto (ssk-cli/src/main.rs:3924-3939), so the new ingress key changes the CLI's machine-readable JSON contract. The design does not list or version it. (c) Adding http_connect to the closed protocols enum in M2.1 after v5 has shipped, with no version bump (section 20), contradicts the versioned-schema policy. The design hedges with 'if shipped before v5 is released', but the commit plan puts M2.1 after C-C1.
* Config blast radius. IngressConfig::validate always runs, even when the feature is disabled. A typo in arm_on_start or an ingress limit therefore makes the whole config invalid, puts the daemon in ConfigInvalid, and blocks the legacy activation path (supervisor.rs:473-476). Decide deliberately whether a disabled section may break unrelated functionality.
* Commit-plan defects. (1) C-S1 (listed before C-C1) says to 'store an owned IngressConfig copy' but IngressConfig is introduced in C-C1, so C-S1 cannot compile as ordered. (2) The name 'W1/W2' is used in the prose and section 15 for the Windows winhost commits, while the plan's C-W1 is the ssk-ipc wire-type commit (and the winhost ones are C-WIN1/2). (3) The deny-lint set (#![deny(clippy::unwrap_used, expect_used, indexing_slicing, panic, ...)] in ingress/mod.rs) also applies to #[cfg(test)] code in the ingress tree. The repo has no clippy.toml, its tests use .expect() throughout, and CI runs clippy --all-targets -D warnings. The plan needs cfg_attr(test, allow(...)) or clippy.toml allow-*-in-tests. Whether tokio::select!/#[tokio::test] expansions trip clippy::unreachable/panic under deny is not shown. (4) New test-support files included via include! need #[allow(dead_code)] as the existing support file has.
* Latency budget: pending and result are two durable writes on the connect path before the first byte, so each new connection adds two fsync latencies unless other flows are batched with it. There is no budget, no benchmark gate, and a 5 s deadline. Defender/AV on Windows can stall fsync for seconds, so the first-byte latency of the proxy will depend on the disk.
* Config fingerprint, HTTP CONNECT and similar follow-ons aside, the design never states how config edits take effect for a running ingress. The daemon builds ConfiguredRouting once, so a rule or limit change needs a daemon restart, which disarms the proxy unless arm_on_start is set. Make that explicit in the RUNBOOK and status text.
* Flaky-test sources not mitigated. (1) rearm_after_bind_failure_succeeds_once_port_is_free and bind_failure_is_reported need a fixed free port that is released and later reused: the same port-race that docs/RESTART_ASSESSMENT_2026-09-21.md records as the cause of an unstable test (activate_with_no_route_fails_closed). The design's own held-bound trick is used only in the dead-adapter test. (2) sskd_survives_fd_exhaustion_on_ingress relies on `sh -c 'ulimit -n 96; exec sskd'` and on GetStatus being answered while the flood holds every fd. IPC accept itself needs an fd, so the assertion races the flood. It also depends on a shell and on quoting of CARGO_BIN_EXE_sskd. (3) Real-authorizer tests read /proc/net/tcp under parallel load (see above). (4) 100-500 ms floors for handshake, connect and idle timeouts plus 'GetStatus bounded under flood' are wall-clock assertions on shared CI. (5) assert_no_connection style negatives (100 ms accept timeout, existing in activation_safety.rs:71-78) cannot prove absence. (6) graceful_shutdown_drains_flows (SIGTERM) and the ulimit test are unix-only, but the plan says no test file is cfg-gated wholesale. (7) ssk-cli subprocess tests locate sskd next to ssk in target/ (ipc_status_snapshot.rs: sskd_binary_path), so they can run against a stale daemon binary unless the workspace was built first.
* Hardening gap in the special-use exemption: it requires only that the matched rule has an exact `destination`, with no `port`. The repo's own test fixture is exactly that shape (tests/support/routing_config.rs: destination 127.0.0.1, port None), and it would let every proxy client reach every loopback service (databases, dev servers, other local proxies). Requiring a port (or an explicit acknowledgement) for the exemption is not part of the design.
* IPv6 special-use table is incomplete: Teredo 2001::/32, fec0::/10, 100::/64, 3fff::/20 and the deprecated IPv4-compatible ::a.b.c.d form are not classified, and only ::ffff:0:0/96 is unmapped. This matters only with literal-destination Direct rules, but the table is presented as covering the special-use ranges.

### Contradictions with the repository (8)

* Section 8/11 say arm/disarm/trip emit Event::Warning while IngressShared is 'independent of DaemonState' with 'no tokio lock'. The event bus is the broadcast::Sender inside StateMachine (crates/ssk-daemon/src/state.rs:10-13), owned by Inner.state (crates/ssk-daemon/src/supervisor.rs:38-39) behind the tokio Mutex. subscribe_events locks it (supervisor.rs:245-246), and ActivateProfile holds that lock across connect_route().await (supervisor.rs:472, 637). Section 12 hoists only ConfiguredRouting and DataPlane, not the sender. The audit writer's on_trip callback runs on a std::thread and cannot take the async mutex. In addition, SubscribeEvents only returns Response::Ack (supervisor.rs:855-859) and the IPC server never pushes events (ssk-ipc/src/server.rs:208-221), so no IPC client would see these events at all.
* Section 11/12 claim TraceRoute and the live path 'cannot diverge' because both use ConfiguredRouting::decide. TraceRoute picks its profile from inner.active_profile, else default_profile (supervisor.rs:728-731) and RouteTraceRequest has no profile field (crates/ssk-ipc/src/dto.rs:74). The ingress uses the armed profile, which can differ from both. Preview and live also differ in app_id ('unknown-app' vs 'local-proxy:unattributed') and in the post-evaluate guards, so the test trace_route_and_live_flow_agree_on_policy_plan is only true for one profile configuration.
* 6.6 specifies compare against rustix::process::geteuid(). The repo's existing same-user check uses getuid() (crates/ssk-ipc/src/auth.rs:74) while comparing against SO_PEERCRED's uid. Two different identity conventions in one daemon with no stated reason (rustix 0.38.44 has both, process/id.rs:54,68).
* Section 8/13 claim 'nothing in the ingress can end run_server or the daemon' and the test sskd_survives_fd_exhaustion_on_ingress. The design's own IPC fix (50 ms to 1 s backoff, give up after 60 consecutive errors) still returns Err from serve_unix_with_limits (ssk-ipc/src/server.rs:181-189), which main.rs maps to EXIT_SERVER (main.rs:299-300, 333-342). With a pending connection in the backlog (GUI polling GetStatus) each retry errors again, so about one minute of sustained EMFILE ends the daemon. Ingress tunnels live up to idle_timeout (default 10 min) and can hold the fds that long. On the ingress side, AcceptFatal after 100 consecutive errors (about 95 s of backoff) trips the proxy on the same condition and cancels every flow.
* Section 1/12 give the daemon test baseline as '84 unit + 23 integration'. Counting #[test]/#[tokio::test] gives 86 in crates/ssk-daemon/src and 24 in crates/ssk-daemon/tests (including dependency_closure.rs's 2). The '23 pinned integration tests' under audit.json cannot be reproduced from the repo. Small, but the figure is used to justify rejecting the audit.json conversion.
* Section 12(5)/6.9 say main.rs 'builds routing once' and shares it. Supervisor::new builds its own ConfiguredRouting from the config (supervisor.rs:192-240) and main.rs:258-262 builds a second one only to extract the adapter registry, so 'same planner and same data plane for decision and dial' needs a Supervisor::new/constructor change that section 12 does not list (it only says the signature is kept).
* Section 8 says Deactivate calls ingress.disarm(Deactivate) before the KILL_SWITCH_ARMED check. Today that early return (supervisor.rs:672-689) has no side effects. After the change it returns an error response (KILL_SWITCH_ARMED, 'pass release_kill_switch=true') after the proxy has already been disarmed, so the caller is told the deactivate was refused while part of it happened. The design does not define the response in that case.
* Section 20 says the HTTP CONNECT enum variant needs 'no config version bump if shipped before v5 is released'. The commit plan puts v5 (C-C1) in the M2 spine and M2.1 'after M2', so the condition is false as scheduled, and the existing CI guard (.github/workflows/ci.yml:157-168) only echoes, so nothing would catch the schema change.

### Security holes (7)

* Overflow panics on the hostile-input surface. The release profile has overflow-checks = true (Cargo.toml:144), so any unchecked +, -, * on lengths, ports, token buckets, byte counters or Instant/Duration arithmetic panics. The ingress deny-list covers unwrap/expect/indexing/panic/todo/unimplemented/unreachable but not clippy::arithmetic_side_effects (or cast lints), while sections 7.1/18 make 3 flow panics trip the whole ingress until an operator re-arms. A crafted input or timing that reaches one overflowing subtraction is therefore a remotely triggerable 'stop the proxy' button. Require checked/saturating math in the ingress tree and enable the lint.
* Arm vs disarm/trip race (see missing item 1): a Deactivate/disarm or an audit trip can be undone by an arm that was already past its fsync, so an operator-visible 'disarmed' (or a tripped, fail-closed state) can silently revert to an armed gate. The status 'armed' computation checks writer liveness, but the accept path only checks the gate.
* Stale status can claim coverage that no longer exists: with the StatusHint fallback (section 12) an unmodified cached StatusDto carries ingress.state=armed / coverage=proxy_clients_only for up to the 20 s activation window after a trip or disarm. This directly contradicts rule 8 (status never claims more than enforced).
* Ledger exposure: no mode/ACL, no no-follow or ownership checks for ingress-audit/ (see missing item 6). On a multi-user Linux box (state dir created with default permissions, main.rs:67) the new destination log is world-readable by umask. With a shared or writable SSK_STATE_DIR another user can pre-plant symlinks or files. The privacy concern the design itself raises (open question 5) is thus not mitigated at the file level.
* CPU amplification by other local accounts: each connect from any local user costs a full /proc/net/tcp parse (up to 256/s, 8 in flight) before being refused. The cheap PeerBudget protects the shared budgets but not the CPU or the blocking pool. Together with missing tcp6 coverage and non-atomic reads, the check yields both false refusals of legitimate clients and an inexpensive load vector.
* Special-use exemption by a portless exact-destination rule opens all ports on that host to all proxy clients (see missing item on hardening). Under hardening: best_effort on Linux without peer check, or on Windows before W1/W2, that includes every local user.
* Windows default is 'unavailable' under hardening: required until W1/W2 land (they are RELEASE, not SPINE). The target product is a Windows desktop client, so the first usable configuration there is best_effort, where any local user or session can use or squat the loopback port. The design says this is visible in status, but the acceptance suite never exercises the default-config path on Windows (tests choose hardening per OS).

### Claims nobody could verify (11)

* Provenance claims: 'judge totals 20 vs 18 vs 15', 'reader probe' for the EADDRINUSE behaviour and for the /proc/net/tcp layout, and the three source designs are not in the repo, so none of the design-selection reasoning can be checked from this tree.
* Every Windows behaviour (SO_EXCLUSIVEADDRUSE semantics and TIME_WAIT interaction, GetExtendedTcpTable owner PID to SID, PID reuse, named-pipe accept recovery, netsh kill switch blocking sskd's own dials, Instant across suspend, AV/FILE_SHARE interplay on prune). The existing vpn_endpoint.rs shows the pattern but not that it works for a long-lived listener.
* Linux specifics: that a second bind to a live 127.0.0.1:port fails with and without SO_REUSEADDR (mio sets SO_REUSEADDR on Unix listeners), that half-closed clients keep a non-zero inode in states 04/05/08, that the uid column is the client socket owner for every client type, and that dual-stack clients appear in /proc/net/tcp (likely false, see missing). The design lists these as tests to run; no evidence exists yet.
* That copy_bidirectional_with_sizes half-close propagation is correct through each adapter kind (TLS close_notify, SOCKS5/CONNECT streams, boxed Transport) and that dropping both sockets on cancel gives the described EOF/reset on both sides.
* fsync cost and the 5 s audit deadline on real hardware (both pending and result sit on the connect path); group-commit batch behaviour; 'GetStatus under 500 ms during a flood' and the 'flood reconciles' test thresholds.
* That the proposed lint set (deny of indexing_slicing/unreachable/panic) compiles cleanly against tokio::select!, #[tokio::test] and serde derive expansions, and that proptest 256 cases stays within CI time (CI sets PROPTEST_CASES=32).
* That serde #[serde(flatten)] on FlowAuditRecord with an internally tagged FlowAuditEvent (BTreeMap and Option fields) round-trips as required by verify_dir; the design hashes stored bytes (good) but still has to parse them.
* IPv6 literal Direct and IPv6-authority HTTP CONNECT tests self-skip on runners without ::1, so the C-N2 fixes may ship unexercised.
* TLS terminal-hop behaviour and any upstream TLS success path cannot be tested on Linux (acknowledged); the refusal of terminal TlsTunnel rests on reading executor.rs:apply_hop only.
* Nothing in the design was compiled or run (stated). Signatures such as FlowAuditWriter::close(self) with Arc ownership, open_with/open_dir sharing on_trip, and IngressShared holding OnceLock<Arc<dyn HostControl>> are unchecked for borrow/ownership problems.
* The README/docs line references in section 17 that I could check (README.md:83,162,342,379,504,505,507,560,645; ssk-ipc/src/state.rs:20; supervisor.rs:326; ssk-cli/src/main.rs:4373; ROUTING_AND_OPENVPN_STATUS.md:29,38-42; ADR 0008 16-crate text vs the 17-entry EXPECTED_CLOSURE) are accurate. Those I did not check (SECURITY.md wording, DESKTOP_CLIENT_ARCHITECTURE.md G.4/K.1 line numbers beyond 587-594, P4_INGRESS_DESIGN.md claims about IngressProvider) remain unverified.

---

## Appendix B: open questions for the product owner

* Windows timing and default: may Milestone 2 be declared done on Linux-verified acceptance with Windows running only under hardening: best_effort (or unavailable under required) until the Windows-only commits W1/W2 (exclusive bind, owner check) land, or must W1/W2 block M2? I cannot verify any Windows behaviour here. Related: is single-user Windows the only supported deployment, so a different local user being able to use the proxy under best_effort is acceptable for a first build?
* Protocol priority for the first desktop release: is SOCKS5 only acceptable, or must HTTP CONNECT (apps that only speak an HTTP proxy, WinINET-style system proxy) ship in the first release? Is an OS proxy-settings writer (with crash restore) in or out of scope for the desktop client?
* Direct-by-name: do users need per-site Direct rules written as hostnames in the first release? M2 refuses Direct for names (no local DNS, no rebinding window). Supporting it means the pinned resolve-filter-dial follow-on and explicitly accepting that the system resolver sees those names.
* Arming and persistence: should the desktop client arm the proxy automatically at logon (config arm_on_start, default None in this design), and must arming and disarming be possible from the GUI? Today the webview is read-only with a negative test that activate_profile is denied, so arming is CLI-only until a write command and capability are designed.
* Audit retention and privacy: the ledger records the destination host and port of every admitted flow (a local browsing log) for the retention window; defaults are 8 segments of 32 MiB and older history is deleted. Is a persistent local destination log acceptable for this product, how long must history be kept, and should destinations be redacted or hashed for admitted flows (not for denials)? Changing this after v5 ships needs another config version bump, so it should be decided now.
* Port and discovery: which fixed default listen port should the desktop client ship (config allows 0 for tests only), and is a stable port expected so applications can be configured once?
* Coverage wording: confirm that the product may only describe M2 as 'applications that use the proxy' and never as system-wide or Protected, and that GUI work (DesktopSnapshotV3, milestone M2.4) is a required gate before anything is called a desktop client release.
