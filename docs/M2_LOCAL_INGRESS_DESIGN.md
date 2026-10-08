# Milestone 2 design: local proxy ingress for sskd

> **Status: REVISED DRAFT 2, critic round 1 resolved. Not accepted. Owner decisions pending (Appendix B).**
>
> What is and is not established by this document:
>
> * **Nothing here is implemented.** The repository contains no ingress code (no `IngressStatusDto`, `SetIngress`,
>   `IngressShared` or `IngressHost` anywhere under `crates/` or `apps/`; checked by grep at HEAD `b62c4c8`).
> * **The design was written by reading code and was never compiled as a whole.** Where it disagrees with the code,
>   the code wins. Parts were prototyped in scratch crates and scratch copies **outside** the repository (config
>   v5, IPC types and protocol-0 fixtures, the fd-budget function, the contract-guard script, `ingress/path.rs`,
>   the lint set, the GUI V3 types and webview tests, clock-driven client tests). What was run, and what was not,
>   is listed in [section 26](#26-verification-status). Schematic Rust in this document is a specification, not
>   compiled code.
> * **Every Windows behaviour is UNVERIFIED** unless a repository file or a locked third-party source is cited.
>   The Tauri host (`apps/desktop`) cannot be built on the machine that produced this revision.
> * **Nothing about any third-party VPN application is known.** NordVPN is the working example of the owner's
>   scenario; no product was installed, contacted or inspected.
> * **Every number in a default, deadline or budget is a judgment, not a measurement**, unless a measurement is
>   cited next to it. Measurements were taken once, in one Linux sandbox, on debug builds.
> * Line numbers refer to HEAD `b62c4c8` on branch `claude/admiring-hawking-wgkq97` and drift; function and area
>   names are the stable reference.
>
> **Binding inputs.** The product owner's decisions of 2026-10-06 ([C.1](#c1-decisions-2026-10-06)) bind this
> revision: (1) M2 is accepted on Linux, Windows hardening follows and is verified on real Windows, the ingress
> stays unavailable on Windows under `hardening: required` until then; (2) SOCKS5 first, HTTP CONNECT later and
> separately, no system proxy-settings writer; (3) destination logging is configurable (plain or hashed for
> admitted flows, denials plain), default plain, in the first ingress config version; (4) the GUI must be able to
> arm and disarm the ingress. The primary scenario is the owner's: the commercial VPN desktop application stays the
> system-wide tunnel and Kaleidoscorp is the layer above it ([section 2.2](#22-primary-scenario-a-proxifier-like-layer-above-a-third-party-tunnel-application)).
>
> **Order of work.** Group A of the [commit plan](#22-commit-plan) (defect fixes and tests that are independent
> of the ingress) may land before the critic round. Everything else waits for it. The critic's 47 findings
> against the previous draft are answered in [Appendix A](#appendix-a-disposition-of-the-original-review-findings).
> Two independent critics then attacked this revision (critic round 1: 4 high and 18 medium findings, two of the
> medium ones duplicating high ones). A single writer re-checked every finding against the code and this text; the
> answers are in [Appendix E](#appendix-e-disposition-of-critic-round-1) and no high finding remains open.
> Open questions for the owner, including the two that the fixes raised (B18 and the addition to B9), are in
> [Appendix B](#appendix-b-open-questions-for-the-product-owner).
>
> **Evidence labels used below.** *Read* = read in this repository or in the locked sources of a dependency
> (file:line). *Ran* = compiled and run in a scratch crate outside the repository. **UNVERIFIED** = could not be
> checked here. A claim without a label is a design decision.

---

Repo `/home/user/kaleidoscorp.io`, revised against HEAD `b62c4c8`. Design only: nothing in the repository was edited by the process that produced this text except this file. The document becomes ADR 0009 once accepted (commit `C-D1`).

## 0. Provenance and revision history

* **Draft 1** (2026-10-06, HEAD `f748e10`): a synthesis of eight codebase readers, three competing designs, three judges and a completeness critic. Its selection reasoning (the "judge totals") and the reader probes cannot be reproduced from this repository and nothing below depends on them. Its spine is kept: ingress inside `ssk-daemon`, receipt type-state for audit ordering, disarmed-by-default listener, `hardening: required`, route guards, an own audit ledger with group commit, deny-lints on the ingress tree, SOCKS5 first. The critic's verdict on draft 1 was **needs-revision** (47 findings, Appendix A).
* **Foundation commits** (done, [C.2](#c2-foundation-commits-done-pushed)): `C-N1`, `C-N2`, `C-P1`, `C-I1`, `C-S2`, `C-S3`.
* **Draft 2** (this text): the owner's four decisions and the new primary scenario were applied, and six theme revisions (lifecycle and concurrency, audit and privacy, targets and DNS, coexistence with a third-party tunnel, GUI write path, configuration/IPC/CI) were merged into one document by a single writer. Where themes contradicted each other, the code was the arbiter where it could be; otherwise the decision is stated in the text and listed in [19.2](#192-decisions-taken-when-merging-draft-2). Statements that had become false were deleted, among them every statement that Direct-by-name is out of M2 and the follow-on "M2.5".
* **Critic round 1** (2026-10-06, same HEAD `b62c4c8`): an adversarial security critic and an implementer's critic attacked draft 2. A single writer re-checked every finding against the code and this text ([Appendix E](#appendix-e-disposition-of-critic-round-1)). All four high findings were real and are fixed in place: a `SetIngress` disarm could be swallowed by a no-op check while an arm was in flight; the headline said "active" for a disarmed proxy; no commit before the Windows-last hardening commits gave Windows a ledger store and a bind; and the audit writer and the engine depended on each other. The medium findings were fixed too, a few more narrowly than proposed (each says why). New decisions are MD-27 to MD-42 in [19.3](#193-decisions-taken-in-critic-round-1).
* **Rejected, with reasons (section 19):** gating the proxy on the held probe session; one-way rewrite of `audit.json`; publish-on-drop status guard; overloading `ActivateProfile` as the arm verb; trip-on-first-panic; capacity latch; an allow-list second key for special-use targets.

## 1. What was verified at HEAD, what was inherited, what was not checked

*Read* at `b62c4c8` (locations are file:line; they drift):

* `RouteExecutor::connect` is `pub` and token-free; since `C-N1` its `RouteKind::Fallback` arm returns `NetcoreError::NoRoute` and dials nothing (`crates/ssk-netcore/src/executor.rs:170`). The planner never emits `Fallback`. The whole dial has a deadline (default 30 s, `executor.rs:22`, `with_dial_deadline` at `:87`); each TCP connect has 10 s (`executor.rs:19`).
* `DataPlane::connect_route(AdmissionToken)` is the token-consuming seam. `AdmissionToken` has private `route/host/port`, derives only `Debug` (which would print `HopSpec.auth`), and is minted only by `RouteOrchestrator::admit`, which checks flow-id equality, denied route, attestation, empty/whitespace/control host, port 0, and Udp/Dns/Custom protocols (`crates/ssk-netadmin/src/admission.rs:25-34, 53-65`). It does not validate host syntax.
* `EgressSession::new` is `pub(crate)`; `transport_mut` has no caller anywhere (grep over `crates/` and `apps/`). `EgressSession::chain()` returns adapter kinds, not ids (`crates/ssk-netcore/src/session.rs:51`).
* `direct::connect_tcp` dials `TcpStream::connect((unbracket(host), port))` under a timeout (`crates/ssk-netcore/src/direct.rs:25`): an IP literal is used as an address, a name goes to tokio's resolver, **no interface or source address is bound**. That function is also the first-hop dial of every proxy chain (`executor.rs:195, 225`).
* `ActivateProfile` holds the tokio `Mutex<Inner>` across `connect_route().await`. The activation dial has its own 20 s deadline (`supervisor.rs:34`, `C-S2`). `GetStatus` waits `STATUS_LOCK_WAIT` = 100 ms for `Inner` (`supervisor.rs:43, 572-589`) and, while an activation is in flight (`ActivationsInFlight::any`, `supervisor.rs:78-86`), answers `activating_status(view)`, which is built from nothing but the kill-switch view and constants (`supervisor.rs:261-273`, `C-S3`). **There is no cached status hint in the code**; draft 1's `StatusHint` is superseded (10.3). Every other handler (`ListProfiles`, `TraceRoute`, `GetAuditEntries`, `VerifyAuditChain`, `RunDoctor`, `Deactivate`, `subscribe_events`) still awaits `inner.lock()`.
* `Deactivate` in `FailClosed` without `release_kill_switch` answers `KILL_SWITCH_ARMED` (`supervisor.rs:817-831`); that code concerns the daemon's own `FailClosed` state and does not reach any firewall rule.
* `Inner::status` reads the entire ledger on every call and `GetAuditEntries` does too; `Supervisor::handle` binds `_peer` and never reads it (`supervisor.rs:569`).
* `MatchCriteria::matches` compares a rule's `dest_host` with the flow host by value only when both parse as `IpAddr`, otherwise as text ignoring case and one trailing dot (`crates/ssk-netadmin/src/policy.rs:91-104`); a suffix rule never matches an IP literal or numeric alias since `C-P1` (`policy.rs:64-72`, `:111`). A rule `::1` does not match a flow host `[::1]`; `ssk-config` still accepts numeric-looking `domain_suffix` values and `valid_host` accepts every `inet_aton` spelling as a DNS name (`crates/ssk-config/src/routing.rs:102-119`). Rules are built from `destination`, `port` and `domain_suffix` only (`crates/ssk-daemon/src/routing.rs:75-80`); `RoutingRule` has no app, protocol or risk field.
* IPC: `Request` has 12 variants and no `deny_unknown_fields` (`crates/ssk-ipc/src/server.rs:22-36`); `clamp_request_limits` has an `other => other` arm (`server.rs:101-109`); `handle_connection` writes exactly one `Response` per `Request` (`server.rs:312-313`); `Response::Event` exists (`server.rs:49`) but is constructed nowhere, and `SubscribeEvents` answers `Ack` (`supervisor.rs:1000-1005`): **no IPC client ever receives an event**. The Unix accept loop backs off and gives up on the 60th consecutive error (`AcceptRetry::GIVE_UP_AFTER`, `server.rs:153-187, 265-275`); the named-pipe loop returns on its first accept or instance-creation error (`server.rs:429-432, 460`).
* `ssk-config`: `CURRENT_CONFIG_VERSION = 4` (`lib.rs:9`); the `3 =>` arm of `migrate_value` inserts `CURRENT_CONFIG_VERSION` and deserialises directly (`lib.rs:841-847`), so it breaks when the version moves; CI `breaking_change_guard` only echoes and misses most contract files (`.github/workflows/ci.yml:157-168`).
* `ssk-diag`: crash records are written per panic with `sync_all` and are not capped (`MAX_LOG_FILES = 14` applies to logs only, `crates/ssk-diag/src/lib.rs:71`). The release profile is `panic = "unwind"` and `overflow-checks = true` (`Cargo.toml:130, 144`); `unsafe_code = "forbid"` workspace-wide (`Cargo.toml:147`), `ssk-winhost` is exempt.
* `main.rs`: the config is loaded once (`load_daemon_config`, `:246`); a second `ConfiguredRouting` is built only to take its adapter registry (`:260`) while `Supervisor::new` builds its own (`supervisor.rs:302-307`); `drop(lock)` (`:164`) runs before the runtime is dropped at the end of `run()`; the "drain" is `timeout(DRAIN_DEADLINE, yield_now())` (`:322`, `DRAIN_DEADLINE` = 2 s at `:39`).
* The Windows kill switch adds **one outbound block rule for all programs**, `remoteip=any`, `profile=any`, no program filter, no interface, no exception (`crates/ssk-winhost/src/firewall.rs:589-606`).
* `ssk-ipc` has `rustix` with feature `process`; `ssk-daemon` has `rustix` with `fs`, `std` only (`crates/ssk-daemon/Cargo.toml:69`). `blake3`, `hex`, `proptest`, `tempfile` are workspace dependencies. ADR 0008 and `dependency_closure.rs` pin an exact 17-crate closure.
* Test counts at `b62c4c8`: `cargo test -p ssk-daemon -- --list` on Linux lists 89 unit and 26 integration tests (grep: 91 and 27 test attributes). The "84 unit + 23 integration" of draft 1 is stale; use the rule "every test present at the base commit passes unchanged" (17.1).

*Inherited from the readers and not re-verified:* every Windows behaviour (`SO_EXCLUSIVEADDRUSE`, owner-PID tables, named-pipe accept), CI behaviour, TLS adapter behaviour. **`cargo build`/`cargo test` of the workspace was not run for this design.**

## 2. Shape in one page

### 2.1 The mechanism

* The ingress is a **second front end of the ADR 0008 path**: per connection `FlowRecord -> PolicyEngine::evaluate -> RouteOrchestrator::plan/admit -> AdmissionToken -> DataPlane::connect_route -> EgressSession::transport_mut`. It never calls `RouteExecutor::connect/probe`, never builds a `RouteKind`, and opens no socket other than the accepted client socket; the dials happen inside the data plane (a source-scan test enforces this).
* **Placement:** `crates/ssk-daemon/src/ingress/`. No new workspace crate, no new workspace edge, `dependency_closure.rs` untouched. New external dependencies: `getrandom` (already in `Cargo.lock`; destination key), `rustix` feature `process` and `blake3`/`hex` for the daemon, `proptest` (dev), `socket2` (netcore dev-dependency for a behavioural test, normal dependency only if keepalive `C-H1` lands).
* **Independent of `DaemonState`.** The ingress has its own control object (`IngressShared`), gate, ledger and status words. `Protected` keeps meaning "one held egress session". Arming, flows, denials and trips never set `Protected`, `Active`, `Degraded` or `FailClosed`; `dns_protected` and `kill_switch` are never derived from the ingress. The ingress does **not** depend on `ssk activate`, a held probe session, or `--dest`.
* **Fail-closed lifecycle:** `enabled: false` by default; an enabled listener starts **disarmed** (accept, read nothing, close); arming is an explicit operator action (`SetIngress`, or the explicit config opt-in `arm_on_start`) and is itself durably audited before the gate opens; any audit/accept/panic-budget fault **latches** the gate to `tripped`; `tripped` and recoverable `unavailable` are cleared by an explicit re-arm that first re-verifies the ledger and rebinds, so no daemon restart is needed.
* **Type-level ordering:** `dial()` takes `&PendingReceipt`; the success reply and `pump()` take `&ResultReceipt`; receipts have private constructors inside `audit`. No dial without a durable pending record; no byte without a durable result record.
* **Protocols in M2:** SOCKS5 CONNECT, NO_AUTH only. HTTP CONNECT is fully specified (section 20) and scheduled as M2.1.
* **Direct by name is part of M2** (owner decision, because browsers send host names): the daemon resolves the name once through the operating system's resolver, filters every answer (special-use addresses, the listener, exact-IP deny rules of the armed profile), dials the pinned address and never resolves again (6.10).
* **Windows:** a baseline commit in the spine (`C-WIN0`: std-only ledger store, plain non-exclusive bind, all three controls false) lets `hardening: best_effort` run on Windows; hardened bind, owner check and a private ledger store are commits `C-WIN1`, `C-WIN2`, `C-WIN3`; until they are verified on a real machine `hardening: required` leaves the ingress `unavailable` on Windows (15).

### 2.2 Primary scenario: a Proxifier-like layer above a third-party tunnel application

**Decision of the product owner.** The owner has no infrastructure of their own. The system-wide tunnel is a commercial VPN desktop application (NordVPN is the working example; nothing below depends on its name) that keeps running on the same laptop. Kaleidoscorp is the layer **above** it: applications connect to the loopback SOCKS5 ingress, Kaleidoscorp applies policy and audit, and its `Direct` egress is whatever the operating system's routing table does with an ordinary outbound TCP connect, which is "through the tunnel adapter while the tunnel application is connected". The first desktop release is accepted against this scenario (24.2).

| Concern | Third-party tunnel application | Operating system | sskd |
|---|---|---|---|
| Tunnel, credentials, server choice | owns all of it | - | never sees, needs, starts, stops, configures or queries it |
| Interface a new connection uses | may install routes or filters | routing table decides | binds nothing, asks nothing: a plain connect (CO-1) |
| Name resolution | may set resolver addresses | resolver decides | Direct-by-name: one OS resolver call per flow (CO-4); proxy routes forward the name unresolved |
| Kill switch | its own; the only defence when the tunnel drops (13.2) | - | none in this scenario (13.2.4) |
| Per-application steering | owns the lists | - | the dialling process is `sskd.exe`, not the browser (13.2.3) |

`ssk-vpnctl`, the broker's VPN commands, `ssk winhost vpn ...`, OpenVPN adapters and profiles are **not part of the scenario** and the ingress cannot start them: an `OpenVpn` route is refused by the route guard (6.7.1) and by the executor (`executor.rs:157-159, 219-221`). Kaleidoscorp's own OpenVPN orchestration and a third-party tunnel application together are unsupported. The status vocabulary stays honest: the ingress is described only as "applications that use the proxy", never as Protected or system-wide, and Kaleidoscorp never claims that a third-party VPN is up or protecting anything; at most it **observes** facts (for example which interface the OS selects for a documentation probe address) and labels them as observations (10.5).

### 2.3 Coexistence rules (what a reviewer checks for this scenario)

* **CO-1 Nothing in the dial path binds an interface or a source address.** The only socket-creating call on the Direct path is `TcpStream::connect` in `direct::connect_tcp` (`direct.rs:25`; with Direct-by-name, `OsConnector`'s `TcpStream::connect(SocketAddr)` on pinned candidates, behind the `TcpConnector` seam of 6.10); it sets no option and calls no bind. Nothing may call `bind`, tokio's `TcpSocket::bind_device`, `SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IPV6_UNICAST_IF` or `IP_BOUND_IF` on a dial socket: each takes the egress decision from the routing table and would send Direct traffic around a third-party tunnel. The roadmap plans exactly such a call (`docs/P4_INGRESS_DESIGN.md:230`, P4c: "called from `ssk-netcore::direct::connect_tcp`"); section 17 withdraws it for this path. The one wildcard UDP bind in the crate (`dns.rs:59`) belongs to the `DnsOverride` resolver, whose entry point `resolve_via` has no caller anywhere in the workspace (only its definition, `executor.rs:95`). Proof in four layers (24.2.1): static (dependency list and source needles, both CI legs); type-level (the `TcpConnector` seam of 6.10 takes a destination address and nothing else, so the executor cannot ask for an interface or a source address); Linux behavioural (`SO_BINDTODEVICE` unset; the route-flip test in a network namespace is the only automated proof that the OS decides, `C-CO1b`); and manual on Windows, the only way to see what the Windows stack chose.
* **CO-2 The dialling process is `sskd.exe`.** Every per-application feature of the tunnel application (split-tunnel lists, bypass lists, an application kill switch) applies to `sskd.exe`, not to browsers or other proxy clients, and not to `ssk.exe` or the GUI (they use the IPC pipe only). Setup: 24.2.2.
* **CO-3 No resolver of our own:** no DoH, cache, override or hosts handling. Names Kaleidoscorp resolves go to the operating system's resolver and nothing else.
* **CO-4 Direct-by-name.** (a) one resolution per flow through the OS resolver, never a second; (b) every answer is guarded first (any special-use address, the listener, or an address named by an exact-IP deny rule of the armed profile refuses the whole flow), then candidates are filtered by `ingress.direct_address_families` (5.1; default `ipv4_only`); (c) under `any`, IPv4 candidates start first, a deliberate deviation from RFC 8305's IPv6-first preference, because an IPv6 path may bypass a tunnel that does not cover it; (d) the candidates race with a 250 ms stagger inside one shared connect budget (6.10); (e) the pinned peer of the winning attempt and every attempted address are recorded (6.4.3). Why: `direct.rs:25` hands a name to tokio, which resolves with `getaddrinfo` and tries every returned address one after another under ONE shared timeout (`tokio-1.53.1/src/net/tcp/stream.rs:118-136`). If the first address is IPv6 and the tunnel application drops IPv6 silently, the dial burns the whole default timeout and never reaches the IPv4 address; if it does not drop IPv6, the connection leaves through the physical adapter (13.2.5).
* **CO-5 Vocabulary.** Kaleidoscorp never says or implies that a third-party tunnel exists, is connected, protects anything or covers a flow. It shows OBSERVATIONS (10.5), labelled. Never-claim list: 10.6.
* **CO-6 No phone-home.** The daemon never contacts a third-party service (no echo-IP query, update check or vendor API). The operator runs the echo test (24.2.3). Rejected: `ssk ingress selftest` with a built-in echo endpoint; it would turn an unverifiable third-party answer into a Kaleidoscorp claim and add a destination to the audit trail that the owner did not choose.
* **CO-7 No firewall state.** The ingress never engages, releases or reconfigures firewall state. A source scan enforces that nothing under `src/ingress/` mentions `ssk_netd_helper`, `ssk_boundary`, `firewall` or `killswitch`; the kill-switch warning of 10.5 is added by the supervisor's status builder, which already owns the read-only provider (`supervisor.rs:59`).
* **CO-8 Observations never decide.** Nothing in `engine.rs`, `flow.rs`, the accept loop or the gate reads them (source scan).

### 2.4 Example configuration for the scenario

`crates/ssk-config/examples/coexistence_config.rs` (pattern of `examples/openvpn_config.rs`) generates the complete v5 file `docs/examples/ingress-coexistence.yaml`; a test regenerates it and fails on drift (`coexistence_example_is_current`). The two sections that matter:

```yaml
routing:
  default_profile: coexist
  profiles:
  - id: coexist
    name: Direct through the operating system route, proxy clients only
    rules:
    - {id: deny-blocked-example, priority: 5, domain_suffix: blocked.example, action: {kind: deny}}
    - {id: echo-ipify, priority: 10, destination: api.ipify.org, port: 443, action: {kind: direct}}
    - {id: echo-ipify-dual, priority: 11, destination: api64.ipify.org, port: 443, action: {kind: direct}}
    - {id: echo-ipify-v6, priority: 12, destination: api6.ipify.org, port: 443, action: {kind: direct}}
    - {id: allow-rest-443, priority: 900, port: 443, action: {kind: direct}}
    - {id: allow-rest-80, priority: 901, port: 80, action: {kind: direct}}
  adapters: []
ingress:
  enabled: true
  listen: {address: 127.0.0.1, port: 10800}   # the shipped default (5.1)
  protocols: [socks5]
  hardening: best_effort                      # Windows: needs C-WIN0, and stays until C-WIN1..C-WIN3 are verified; required on Linux
  arm_on_start: false                         # keep false in this scenario (2.5)
  direct_address_families: ipv4_only
```

Behaviour, verified against the code: rules are sorted by ascending priority, first match wins, no match is a fail-closed denial (`policy.rs:174-177, 195-214`). A by-name rule compares names ignoring case and a trailing dot, and an IP literal never equals a name (`policy.rs:91-104`), so a client that resolved `api.ipify.org` itself and sends an address does **not** match `echo-ipify`; it falls to `allow-rest-443`. That difference is visible in the flow list and used by the acceptance procedure. Other ports have no rule and are denied. `destination`, `domain_suffix`, `port` and `require_attestation` default when omitted (`ssk-config/src/routing.rs`). The two port-only rules `allow-rest-*` open every name on those ports for Direct, subject to the special-use guards of 6.2 and 6.10; an operator who wants less writes narrower rules. An exact-IP `deny` rule (there is none in this example) also refuses every address that a Direct name resolves to, whatever its priority (6.10 step 5), so a deny rule cannot be walked around by sending a name; the reverse does not exist, because a domain rule never sees a client that sends an address (6.11).

### 2.5 Start-up ordering and `arm_on_start`

Kaleidoscorp cannot know whether the tunnel application is connected, so `arm_on_start` arms whether or not the tunnel is up, and flows in that window follow the routing table without the tunnel. Nothing in the repository starts `sskd` at logon today (autostart is text in `DESKTOP_CLIENT_ARCHITECTURE.md` F.3), so the problem appears the day autostart ships. In this scenario leave `arm_on_start` false and arm by hand once the tunnel application shows connected. A disarmed proxy refuses every connection and sends no byte: the safe side.

## 3. Rules the implementation must keep (what a reviewer checks)

### 3.1 Data, policy and privacy rules

1. No byte path without (admission token + durable pending + durable result). A denial has no byte path at all.
2. The dialled `(host, port)` is the token's, which is the canonical `Target` that passed `target::canonicalize` and the guards; client text is never re-read after that point. For a `Direct` route to a name, the address actually dialled is one `SocketAddr` from the single resolver answer of this flow, and only after every address of that answer passed the guard. The daemon never resolves that name again.
3. Client-supplied names are resolved by this daemon only for a `Direct` route, only for an admitted flow, only after the durable `Pending` record, exactly once, through the OS resolver (6.10). Proxied routes forward the canonical name unresolved. A denied, unmatched or guard-refused name never reaches any resolver.
4. No fallback of any kind, no retry, no second token. `RouteKind::Fallback` is non-executable in the executor (done, `C-N1`) and refused by the ingress route guard.
5. A per-flow denial or failure never touches global state (`refuse_activation`, `record_task_failure`, `spawn_supervised` are never used for flows). Only ingress-local latches change ingress state.
6. Peer authorization runs before the first byte is read **and before any shared budget (accept bucket, permit, ledger) is charged**; `Unknown` means refuse.
7. Every limit is explicit, validated with a ceiling; 0 never means unlimited. Raw client text is logged only at DEBUG, escaped and truncated; records carry validated text only.
8. Status never claims more than is enforced (section 10). No string produced by the ingress contains a word of the forbidden list (10.7); a test enforces it.
9. A special-use LITERAL destination (loopback, RFC1918, link-local, metadata, fake-IP range, ...) is reachable only if the **matched rule's own `destination` equals that literal exactly AND the same rule names the port** (`port: Some`). A portless rule opens nothing. Names are never exempt: a resolver answer that contains any special-use address refuses the flow, and the guard has no exemption mechanism.
10. Faults latch; recovery is an explicit operator action that re-verifies before reopening. Nothing recovers silently (including a failed `arm_on_start`, which is logged and never retried).
11. Canonicalisation precedes policy: no host text reaches `MatchCriteria`, the audit writer, a log line above DEBUG, the token or any dial in a form other than `Target.host`; every spelling of one address collapses to one text, and numeric aliases, `localhost` and non-ASCII are refused for every route kind.
12. Resolver concurrency is bounded and the bound is tied to the OS thread, not to the future: a lookup permit is released only when the OS call returns, at most 16 lookups run, a 17th flow waits at most 500 ms for a permit (at most 32 flows wait) and then fails, and lookups never starve the tokio blocking pool.
13. The peer check has a bounded cost: one dedicated thread, batched snapshots, a duty cycle of at most one third of a core, no blocking-pool slot; whatever it cannot decide is `Unknown` and refuses.
14. A `Direct` dial binds no interface and no source address; the OS routing table decides (CO-1). No status or flow string makes a claim about the path an OS-routed dial takes or about any third-party software; at most an observation is shown, labelled as one.
15. No destination (host, resolved address, destination text of a rule) is written to any persistent artifact or shown on any surface except through `DestRef` or `AddrRef`: ledger, tracing at INFO and above, status, IPC DTOs, live flow lists, crash records. In `hashed` mode no surface shows more than the ledger would. `hashed` never degrades to `plain`.
16. A timeout is not a fault. Only an I/O error, a dead writer, sequence exhaustion or a 30 s fsync stall latches the gate for audit reasons.
17. A receipt that is dropped unresolved writes its own compensating record. Within one boot, a Pending without a Result and a connected Result without a Closed can exist only transiently.
18. The ledger describes what Kaleidoscorp decided and did. It never claims a property of the network path (tunnelled, protected, a third-party VPN being up). Observed facts are stored only as labelled `observations`.
19. The ledger store is private and is not followed through links: directory 0700, files 0600, dirfd-relative access, `O_NOFOLLOW`, owner equal to `geteuid()`, `st_nlink == 1`; an unsafe store is refused, never repaired.
20. The ingress never writes `audit.json`.
21. The webview can arm and disarm and nothing else: two zero-argument native commands, a dedicated capability, daemon-side authorisation that records the verified peer (25).
22. A narrowing request is never swallowed: `SetIngress{armed: false}` always reaches `IngressShared::disarm`, which bumps the epoch even when the gate already reads `Disarmed`, because that bump is what supersedes an arm that is waiting on its fsync (the gate still reads `Disarmed` during that wait). It is never rate limited and never short-circuited by a no-op check (11.4, 6.9.2).
23. An exact-IP `deny` rule of the armed profile applies to every address a Direct name resolves to, at any priority: a resolved name can only be refused more, never admitted more (6.10 step 5).

### 3.2 Lifecycle and concurrency rules (L1-L14)

The gate is the `Gate { epoch, mode }` value defined in 6.1.2.

* **L1 One lifecycle variable.** All lifecycle state is the gate, held in one `tokio::sync::watch` cell. There is no second flag (no `armed: AtomicBool`, no cached state word). `IngressState`, `coverage` and `armed_profile` are pure functions of the gate. Liveness booleans (accept task alive, writer alive) may only make an answer less permissive, never more.
* **L2 One write primitive.** Every gate write is `watch::Sender::send_if_modified` with a pure closure: no lock, no await, no I/O inside it. Every successful write bumps `epoch` by exactly one. On `u64` exhaustion the gate becomes `Closing` (terminal, fail closed); it never wraps.
* **L3 Conditional and unconditional writers.** Arm, recover and start-publish write only if `epoch` still equals the value they read before their first await (compare-and-set). Trip, disarm and close write unconditionally. An unconditional writer therefore always beats a conditional one: a late-completing arm cannot overwrite a disarm, a trip or a shutdown.
* **L4 Order of audit and effect.** Widening (arm) is durable record first, gate second. Narrowing (disarm, trip, close) is gate first, record second (bounded, best effort, loss counted). The ledger may therefore contain an `Armed` intent whose gate never opened; it can never contain a gate that opened without its durable `Armed` record.
* **L5 One control lock, never nested with `Inner`.** `IngressShared::control` (tokio Mutex, FIFO) serialises arm, recover and the bookkeeping half of disarm. No code path holds `control` and `Supervisor::inner` at the same time, in either order. `SetIngress` never takes `inner`; `Deactivate` finishes `ingress.disarm()` before it awaits `inner`; `ActivateProfile` never calls the ingress control API.
* **L6 Control operations are detached.** Arm and recover run as spawned tasks that own their lock guard. Dropping the requester's future (client gone, handler dropped) cannot stop them between "durable Armed" and the compare-and-set, or in the middle of recover. A panic inside a control task trips `ControlPanic` and answers `INGRESS_CONTROL_FAILED`.
* **L7 `trip` never blocks.** It is synchronous and callable from any thread (the audit writer thread, the accept task, panic accounting). It may use only atomics, `send_if_modified`, `broadcast::Sender::send`, a non-blocking `try_send` and a short std Mutex.
* **L8 No status field comes from a cache.** A status answer is composed at answer time from sources that need no `Inner` (the kill-switch provider, `IngressShared::snapshot()`, constants), plus the `Inner` fields only when `Inner` was actually obtained. The legacy block and the ingress block are each consistent as of their own read; they are not one atomic snapshot and nothing in the answer relies on that.
* **L9 What may hold `Inner`.** Bounded synchronous work, bounded awaits (at most `SESSION_SHUTDOWN_BOUND`), and the activation dial (at most the activation deadline), which every reader must answer around (12.2).
* **L10 Ledger reads stay off the lock.** Any verification of a retained ingress ledger, triggered by a request, by start or by recover, runs in `spawn_blocking`, single-flight, under a deadline, outside every async lock except `control` (recover only). A segment that vanishes while it is being read (rotation or prune) is `Inconclusive`, never `Corrupt`.
* **L11 File-descriptor budget.** The ingress can hold at most `soft RLIMIT_NOFILE - reserve` descriptors by construction (7.3). `max_connections` is clamped to what the budget allows. The IPC server's descriptors are inside the reserve.
* **L12 Checked arithmetic.** The ingress tree denies unchecked arithmetic and lossy casts (12.12). Release builds run with `overflow-checks = true` (`Cargo.toml:144`), so an unchecked operation is a panic, not a wrap.
* **L13 Poison-tolerant std Mutexes.** Every std Mutex in the ingress is locked through one helper that takes the guard out of a `PoisonError` (the pattern `CachedBrokerView::view` already uses, `killswitch.rs:389-405`). A panicking flow must not be able to make the next status read or the next trip panic.
* **L14 What can end the daemon.** The ingress can never end it by a fault of its own; it only moves its gate. The daemon still exits on shutdown signals, on startup failure, and when the IPC accept loop gives up after 60 consecutive errors (a deliberate last resort, 8.6). The descriptor budget (L11) is what keeps the ingress from ever causing that last case.

## 4. Module and crate placement

```
crates/ssk-config/src/ingress.rs            NEW  IngressConfig + validate + schema_json
crates/ssk-config/src/fingerprint.rs        NEW  ConfigFingerprint: daemon-independent view structs + blake3 digests (6.4.8); used by sskd and `ssk config lint`
crates/ssk-config/src/lib.rs                v5, required field, migration chain, ConfigError::Document
crates/ssk-config/tests/golden/             NEW  ssk-config-v5.schema.json
crates/ssk-config/examples/                 ingress_config.rs, coexistence_config.rs (NEW); openvpn_config.rs (regenerated)
crates/ssk-ipc/src/dto.rs                   IPC_PROTOCOL_VERSION; StatusDto.{protocol, ingress}; IngressStatusDto; FlowSummaryDto additive fields; IngressAuditPageDto; RouteTrace additions
crates/ssk-ipc/src/server.rs                Request::{SetIngress, GetIngressAudit}; exhaustive clamp; accept-loop retry (Unix done, C-I1; injectable accept source C-I1b; named pipe C-I1w)
crates/ssk-netcore/src/{executor,direct,resolve,connector,session,error}.rs
                                            no Fallback (done); whole-dial deadline (done); NameResolver/OsResolver/bounded resolve_once; TcpConnector/OsConnector
                                            (the one socket-creating call, destination only); pinned Direct dial; DirectAddrGuard; address-family filter;
                                            SessionResolution/DialAttempts; first_hop_local; (opt) keepalive, single-flight lookups
crates/ssk-netadmin/src/{policy,audit}.rs   suffix never matches IP literals (done); pub summarise_route
crates/ssk-diag/src/lib.rs                  cap crash records
crates/ssk-daemon/src/ingress/
    mod.rs      #![cfg_attr(not(test), deny(clippy::unwrap_used, expect_used, indexing_slicing, panic, todo, unimplemented, unreachable,
                           arithmetic_side_effects, cast_possible_truncation, cast_sign_loss, cast_possible_wrap))]; re-exports
    types.rs    Gate, GateMode, UnavailableCode, TripReason, DisarmCause, Actor, IngressState, Coverage, Tuning, constants,
                INGRESS_COVERAGE_NOTICE, FORBIDDEN_WORDS, Clock, Sleeper, IngressCfgView, ResolvedLimits (6.9.5), and the audit leaf types
                of 6.4.3 (leaf module, no deps on siblings)
    target.rs   RawTarget -> Target canonicalisation, special-use table, self-loop guard, RuleBinding
    socks5.rs   server-side SOCKS5 parser/replier (no policy, no routing knowledge)
    audit/      mod.rs, record.rs, receipts.rs, writer.rs, verify.rs, fs.rs, fs_unix.rs, fs_win.rs, dest.rs   (ledger, receipts, store security, destination key)
                record.rs also holds the audit INPUT types (PendingInput, ConnectedEvent, DeniedEvent, ArmedEvent, ...): the audit module imports only the
                leaf modules types.rs and target.rs, never engine, flow, host or shared (6.4.7)
    budget.rs   pure fd_budget(), getrlimit shim, FD_RESERVE and the other budget constants
    limits.rs   RateLimiter, PeerBudget, DenialCoalescer, FailureCooloff (all take an explicit Instant)
    peer.rs     PeerAuthorizer, PeerTableService, IngressPlatform, Controls, default_platform (Unix; Windows baseline from C-WIN0), Linux /proc/net/tcp{,6} parsers, fakes
    guard.rs    GuardCells (ListenerCell + gate receiver), IngressDirectGuard (netcore's DirectAddrGuard over classify_ip, the listener and the armed
                profile's exact-IP deny set), build_ingress_executor (the one place the ingress executor is assembled; 6.10)
    path.rs     PathObserver, Linux /proc/net/route observer, sanitise_alias (observations only; 6.12)
    pump.rs     Counted<T>, bidirectional pump, idle watchdog, cancellation
    shared.rs   IngressShared: gate watch, control lock, status snapshot, counters, flow registry, arm/disarm/trip/recover; LedgerSlot (6.9)
    engine.rs   decide(), route guards, open_tunnel() (pending -> dial -> result); protocol-agnostic and pure where it can be
    flow.rs     per-connection SOCKS5 driver (state machine), FlowGuard
    host.rs     IngressHost: start task, accept loop, JoinSet, watchdog, PathWatcher, shutdown(plan)
crates/ssk-daemon/src/{supervisor,routing,main,paths,shutdown,lock}.rs   wiring and the changes of section 12 (routing.rs: RuleBinding, Decided, DecideError,
                                            exact_ip_denials; paths.rs: ensure_state_root, 6.4.9)
crates/ssk-cli/src/main.rs                  `ssk ingress status|arm|disarm|flows|inspect|audit`; kill-switch pre-flight guard (13.2.4)
crates/ssk-winhost/src/{ingress_bind,loopback_owner,route_observe}.rs    Windows hardening and route lookup (C-WIN1, C-WIN2, C-CO6w; unsafe allowed there)
crates/ssk-winhost/src/private_store.rs     Windows ledger-store policy over PathSecurityProbe (C-WIN3)
tests/support/{net_fakes,socks5_client,daemon_harness,host_corpus}.rs     shared via the existing include! idiom; every function #[allow(dead_code)]
scripts/ci/{contract_guard.sh,contract_surfaces.txt,tests/contract_guard.test.sh}      CI gate (21)
scripts/{manual_ingress_peer_test.sh,manual_vpn_coexistence_check.ps1,tests/manual-vpn-coexistence-check.tests.ps1}   operator material (24.2, Appendix D)
docs/adr/0009-local-proxy-ingress.md, docs/examples/{ingress.example.yaml,ingress-coexistence.yaml}
```

All new items in `ingress` are `pub` in a `pub mod`, so no commit trips `dead_code` under `clippy -D warnings` before the next commit wires it. Shared leaf types live in `types.rs` and land first, which removes the circular `TripReason` dependency between `audit` and `shared`.

## 5. Configuration: `ssk-config` v5, section `ingress`

> **How this section was checked.** The configuration code below was written against HEAD `b62c4c8` in a scratch copy and run there; it is not committed. `cargo test -p ssk-config` went from 15 to 32 tests, all green; `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` are clean for `ssk-config` and `ssk-ipc`; `cargo check --all-targets` is clean for `ssk-daemon`, `ssk-cli`, `ssk-ipc` and `ssk-desktop-client` against the config change; the 89 `ssk-daemon` unit tests and the 4 `ssk-desktop-client` tests pass against it. The prototype predates three keys that were added by the merge (`direct_address_families`, `audit.destination_logging`, the `segment_mib x retain_segments` cross-check) and the fingerprint module; those are specified here and **not run**. Not checked: `apps/desktop` (separate Windows-only workspace), every Windows behaviour, GitHub Actions.

### 5.1 Shape

```rust
// crates/ssk-config/src/ingress.rs. EVERY struct: #[serde(deny_unknown_fields, default)].
pub struct IngressConfig {
    pub enabled: bool,                    // false
    pub listen: IngressListen,            // 127.0.0.1:10800
    pub protocols: Vec<IngressProtocol>,  // [socks5]
    pub hardening: IngressHardening,      // required   { required, best_effort }
    pub arm_on_start: bool,               // false      (arms routing.default_profile)
    pub direct_address_families: DirectAddressFamilies,   // ipv4_only { ipv4_only, any }
    pub limits: IngressLimits,
    pub audit: IngressAuditConfig,
}
pub struct IngressListen { pub address: Ipv4Addr, pub port: u16 }   // Ipv4Addr cannot spell a host name, IPv6, brackets or a zone
pub struct IngressLimits {
    pub max_connections: u32, pub accept_rate_per_s: u32,
    pub handshake_timeout_ms: u32, pub connect_timeout_ms: u32, pub idle_timeout_ms: u32,
}
pub struct IngressAuditConfig { pub segment_mib: u32, pub retain_segments: u32, pub destination_logging: DestinationLogging }
pub enum DestinationLogging { Plain, Hashed }                       // snake_case, default Plain; applies to admitted flows only (6.4.10)
pub enum DirectAddressFamilies { Ipv4Only, Any }                    // snake_case
#[serde(try_from = "String", into = "String")]
pub enum IngressProtocol { Socks5 }                                 // see 5.5
// Ranges are pub const RangeInclusive<u32> on IngressLimits / IngressAuditConfig; validate() AND schema_json() read the same constants.
```

`AppConfig` gains `pub ingress: IngressConfig` as a **required** field (no `#[serde(default)]` on the field: a v5 document states its stance explicitly, the same rule `routing` follows), while every field inside the section has a default, so `ingress: {}` is a valid, disabled section. `Default for AppConfig` uses `IngressConfig::default()`; the two struct literals in `lib.rs` (`upgrade_from_v1`, `upgrade_from_v2`) use `..AppConfig::default()` and need no edit.

| key | default | floor..ceiling | why this number |
|---|---|---|---|
| `enabled` | `false` | | an upgrade never opens a listener by itself |
| `listen.address` / `port` | `127.0.0.1` / `10800` | loopback `127.0.0.0/8` / `0..=65535` | applications are configured once, so the product port is fixed (owner question B1). 1080 is the port every upstream-SOCKS5 example in this repository uses (`ssk-netadmin` tests and examples, `docs/P4_INGRESS_DESIGN.md:228`), so a default of 1080 would collide with the static self-loop check for a local upstream proxy on the conventional port. 10800 is below 32768 (Linux ephemeral range) and 49152 (Windows dynamic range); **not checked** against the IANA registry or a Windows excluded-port range. `0` = OS-chosen, reported in status, for tests (5.7) |
| `protocols` | `[socks5]` | non-empty, unique, only values the build supports | 5.5 |
| `hardening` | `required` | | owner decision 1: on Windows the ingress stays unavailable until `C-WIN1`..`C-WIN3` are verified; `best_effort` is a visible operator choice |
| `arm_on_start` | `false` | | a restart comes back disarmed unless the operator opted in; arms `routing.default_profile` |
| `direct_address_families` | `ipv4_only` | `ipv4_only`, `any` | 13.2.5: a dual-stack name dialled over IPv6 may bypass a tunnel that does not cover IPv6; the price is that IPv6-only sites are unreachable through Direct until the operator sets `any`. Part of the first version because adding the key later would need another config version |
| `limits.max_connections` | `256` | `1..=4096` | open tunnels. A browser with several windows plus background tools fits (judgment, not measured). Each tunnel costs two descriptors; the value is clamped at start to what the fd budget allows (7.3), so a higher configured value is safe and shows in status as `clamped_by: fd_limit` |
| `limits.accept_rate_per_s` | `50` | `1..=10_000` | sustained rate of NEW admitted connections; the bucket holds `max_connections` tokens, so a full table can be re-established at once (tunnel reconnect, browser restore) and a connect/close loop is throttled. Each admitted flow costs about 3 ledger records (about 0.83 KB), so this is also the cap on how fast a runaway loop can push history out of a size-retained ledger: the default 256 MiB window is gone after about 1.8 hours of a sustained 50 flows/s (6.4.8, open question B18). The bucket is charged only after a complete SOCKS handshake and `canonicalize` (7.1), so a client that connects and says nothing costs no token |
| `limits.handshake_timeout_ms` | `10_000` | `100..=60_000` | whole client handshake, spent holding a pre-admission slot and no flow permit or accept token (7.1); once the 64 slots are full a silent socket is evictable after 1 s, so this value is a ceiling and not the time a flooder can hold a slot; floor 100 so real-`sskd` tests can use 300 ms |
| `limits.connect_timeout_ms` | `20_000` | `100..=120_000` | whole upstream dial including resolution (6.10); equals the activation deadline (`ACTIVATE_DIAL_DEADLINE`, `supervisor.rs:34`) so both paths give up together by default; `main.rs` derives the executor deadline from it (12.9) |
| `limits.idle_timeout_ms` | `3_600_000` | `100..=86_400_000` | no byte either way. 10 minutes would cut idle SSH or database sessions; a dead upstream is found by TCP keepalive (`C-H1`, RELEASE) and by idle eviction at capacity (`C-E5`), not by this timer. Open question B2 |
| `audit.segment_mib` / `retain_segments` | `32` / `8` | `1..=256` / `2..=64`; `segment_mib x retain_segments <= 1024` | open verifies everything retained at about 92 MiB/s (6.4.8), so the ceiling bounds start-up verification to about 11 s. The default holds about 320,000 admitted flows: days to weeks of browsing, about 1.8 hours at the sustained rate cap (6.4.8) |
| `audit.destination_logging` | `plain` | `plain`, `hashed` | owner decision 3; 5.8 and 6.4.10 |

Every number above is a judgment, not a measurement; nothing here was load-tested. They are pinned by the named tests of section 23 so a later change is a deliberate act. **A default is part of the contract**: once a tagged release exists, changing a default changes the meaning of every file that omits the key and needs a version bump (5.5). Decide the port (B1) before the first tag.

### 5.2 What the section deliberately does not contain

No field names a VPN, an interface, a source address, a credential, a token, an egress, a fallback, a policy bypass or a special-use allow-list. Kaleidoscorp in the primary scenario neither starts, configures nor authenticates a third-party VPN application: its `Direct` dial binds no interface or source address (`crates/ssk-netcore/src/direct.rs:25`), so the operating system's routing table decides, and no key is added that would imply Kaleidoscorp controls that. The routing section's `open_vpn` adapter is reserved and outside this scenario. A test (`ingress_schema_has_no_credential_vpn_or_interface_keys`) walks every key name in the exported ingress schema and fails on the substrings `vpn`, `interface`, `credential`, `password`, `secret`, `token`, `username`, `source_address`, `egress`; it is the mechanical form of this paragraph. (The audit settings `audit.destination_logging` and the family filter `direct_address_families` name no such thing.)

### 5.3 Validation

`IngressConfig::validate` always runs, also when `enabled` is `false` (a section that becomes invalid the moment the flag flips must not be loadable now). Per-field range errors read `ingress.limits.max_connections must be within 1..=4096 (got 0); 0 never means unlimited`. `AppConfig::validate` calls `self.ingress.validate()` and then `self.ingress.validate_against(&self.routing)` after `routing.validate()`. Cross-checks:

* **Static self-loop:** with a non-zero `listen.port`, no routing adapter (`socks5`, `http_connect`, `tls_tunnel`) may have a host that is `localhost` or an IPv4 loopback literal and the same port. With `port: 0` the check is repeated at bind time against the real address (6.9.4). Deliberately conservative: a second proxy on `127.0.0.2:<same port>` is rejected too, with a message that names the adapter.
* **Ledger size:** `audit.segment_mib x retain_segments <= 1024`.
* **Families:** with `direct_address_families: ipv4_only` an adapter host that is an IPv6 literal is a validation error (the first hop of a proxy chain obeys the same filter, 6.10).

**Blast radius (decision: accepted).** An invalid `ingress` section makes the whole file invalid: `Supervisor::new` re-validates (`supervisor.rs`, `loaded.config.validate()?`), the daemon enters `ConfigInvalid`, `ActivateProfile` is refused (`inner.config` is `Err`), and no listener exists. That is the existing contract for every section (a typo in `routing` does the same), it is fail-closed, IPC and diagnostics stay up (`RunDoctor` reports the error), and a hand edit is caught before restart by `ssk config lint`. Partial application of a security configuration was rejected: a daemon that skips the part of the file it dislikes runs a policy nobody wrote.

`arm_on_start` is a `bool` and not an `Option<String>`. Reasons: an `Option` that is `None` serialises to JSON `null`, and TOML cannot express `null`: `toml::to_string` of a JSON value containing one fails with `unsupported unit type`, which is exactly how `tests/routing_migration.rs` builds its TOML documents (reproduced: with the `Option` form, 3 of the 4 pre-existing migration tests panicked at `routing_migration.rs:10`, `toml::to_string(value).unwrap()`, and so did the new ones). And a named profile is not needed: every arming without an explicit profile (autostart, the GUI button, `ssk ingress arm`) uses `routing.default_profile`, which `routing.validate()` already guarantees exists. The GUI's write command therefore carries no profile choice (11.4, 25.3).

### 5.4 Version bump and migration

`CURRENT_CONFIG_VERSION = 5`. Versions 1 and 2 keep their typed legacy shapes (`LegacyPolicyV1`, `AppConfigV2`, which `deny_unknown_fields` and fill every newer section from `AppConfig::default()`). Versions 3 and 4 migrate through a **chain of one step per version**, replacing the single hard-coded `3 =>` arm (`ssk-config/src/lib.rs:841-847`, `migrate_value`: it inserts `CURRENT_CONFIG_VERSION` and deserialises directly, so with `CURRENT = 5` a v3 file fails with ``Document("missing field `ingress`")``; reproduced against the prototype):

```rust
const CHAIN_FLOOR: u32 = 3;
// in migrate_value:
//   1 => ..unchanged.. , 2 => ..unchanged..,
//   CHAIN_FLOOR..CURRENT_CONFIG_VERSION => { migrate_object_to_current(object, version)?; Self::from_document(value)? }
//   CURRENT_CONFIG_VERSION => Self::from_document(value)?,
fn migrate_object_to_current(object: &mut Map<String, Value>, from: u32) -> Result<(), ConfigError> {
    let mut at = from;
    while at < CURRENT_CONFIG_VERSION {
        match at {
            3 => step_3_to_4(object)?,   // introduce_section(object, "routing", 4, default routing)
            4 => step_4_to_5(object)?,   // introduce_section(object, "ingress", 5, default ingress)
            other => return Err(ConfigError::Structure(format!("no migration step from config version {other}"))),
        }
        at += 1;
    }
    object.insert("version".into(), CURRENT_CONFIG_VERSION.into());
    Ok(())
}
// introduce_section REJECTS the key when it is already present: "ingress requires config version 5".
```

No step mentions `CURRENT_CONFIG_VERSION`; version 6 adds `step_5_to_6` and one `match` arm. A key introduced at version N is rejected in every document labelled older than N by the step that introduces it (v3 containing `routing` or `ingress`, v4 containing `ingress`), which is the "no smuggling" rule stated once instead of per arm. Migration stays in memory; files are never rewritten; `migrated_from` is `Some(3)`/`Some(4)`. A v5 file given to a v4 build fails with ``config version `5` is unsupported; expected `4` `` (reproduced).

Same commit (`C-C1`): schema `$id` becomes `ssk-config-v5.json`; `required` gains `"ingress"`; `properties.ingress` is `IngressConfig::schema_json()`; `tests/routing_migration.rs` is updated as listed in 5.12; `ssk-cli/src/main.rs:4373` prints `migrated from v{from} to v{CURRENT_CONFIG_VERSION}` (it hard-codes `to v2` today); `crates/ssk-config/examples/openvpn_config.rs` (doc comment says v4) and `docs/examples/openvpn-routing.yaml` (`version: 4`) are regenerated; new `examples/ingress_config.rs` generates `docs/examples/ingress.example.yaml` and lints its own output (`ssk_config::lint`), and `examples/coexistence_config.rs` generates the scenario file of 2.4, so the examples cannot rot. `Cargo.lock` changes by one line (`blake3` under `ssk-config`, needed for the fingerprint, 6.4.8); `dependency_closure.rs` is unaffected (it walks workspace crates; `blake3` is already in the closure through `ssk-types`).

### 5.5 Schema evolution: why `http_connect` later is not a breaking change

The history is the policy: v2->v3 (Phase 8 sections), v3->v4 (`routing`) and v4->v5 (`ingress`) each added a **required section**. Nothing in the repository says a new allowed value needs a bump, and the CI guard (21) makes the actual rule enforceable. Written down in `docs/COMPATIBILITY_MATRIX.md` ("Config schema evolution"):

* **Compatible, no bump** (a new binary reads every old file as before): a new key that has a default; a new value in a validated vocabulary (`protocols`, `hardening`, `destination_logging`, `direct_address_families`); a widened range. Old binaries refuse a file that uses the new thing, because every section denies unknown keys and every vocabulary is validated, and the refusal names what is unsupported. Required: a golden-schema update, a matrix entry, a test that the old file shape still loads.
* **Bump + migration step + smuggling test**: a new required section or key; a changed default; a renamed or removed key; a narrowed range; any change of meaning of an existing value.

`protocols` is therefore a **list of validated names, parsed by `TryFrom<String>`**: this build accepts `socks5` and refuses anything else with ``unsupported ingress protocol `http_connect`; this build supports: socks5`` (daemon: `ConfigInvalid`, no listener). Adding `HttpConnect` in M2.1 is: one enum variant, one entry in `SUPPORTED`, the golden schema regenerated, a matrix line, and a test that `[socks5, http_connect]` loads on the new build. It is not breaking because (1) a file that does not mention it means exactly what it meant, since the default stays `[socks5]` (a default may not change inside a version); (2) a file that does mention it is refused by an older build at load with a message that says why, the same observable outcome as `UnsupportedVersion` with better wording; (3) nothing reinterprets an existing key. The contradiction in draft 1 ("no bump if shipped before v5 is released", while M2.1 is scheduled after `C-C1`) disappears: the answer no longer depends on a release date. For the record, `git tag` is empty at HEAD, so no config version has ever been in a tagged release.

### 5.6 Diagnostics, and the typo hole (measured)

`parse_with_migration_*` (the only path the daemon, `ssk` and `ssk config lint` use) deserialises through `serde_json::from_value`, so every document-shape failure was reported by `ConfigError::Json` as `json serialization error: ...`, also for YAML and TOML input. Measured on HEAD:

| input | result at HEAD |
|---|---|
| README.md minimal example (`version: 2`, `fail_closed: true`, `runtime.strict_mode`) via `ssk config lint` | `config-invalid`, exit 10: ``json serialization error: unknown field `fail_closed`, expected one of `version`, `policy`, `runtime`, `interop` ``. The README's "minimum valid configuration" is invalid today. |
| top-level typo `rutime` via the migration path (YAML and TOML) | ``json serialization error: unknown field `rutime`, expected one of ...`` (no line/column) |
| the same typo via `AppConfig::from_yaml` | `yaml parse error: ... at line 106 column 1` (correct label; not used by the daemon or CLI) |
| nested extra key `system.nmae` (YAML and TOML) | **accepted silently** (`Ok`, `migrated_from: None`) |

Fix: new `ConfigError::Document(String)` ("invalid configuration document: ..."), used for every `serde_json::from_value` failure and for the YAML-to-JSON value conversion; `ConfigError::Json` remains only for real serialisation (`to_value` of defaults). One path is kept on purpose: deserialising current-version text directly with `serde_yaml`/`toml` would give line numbers but is not behaviour-identical (TOML integers into the `f32` field `bcik.closure_threshold` are accepted through a JSON value and rejected by the TOML deserialiser; not run, stated from serde's typed-number rules, so UNVERIFIED; do not switch paths without a test). The loss of line/column for migrated documents is an accepted limitation; the message names the offending field and, for unknown keys, the allowed set. Nothing pins the old wording (grep of `crates`, `docs`, `ui`: only `lib.rs` itself).

The nested-section hole is real for the pre-v5 sections (`system`, `core`, `runtime`, ...: extra keys accepted) and is **not** widened to them here: tightening would reject files that load today, and a typo of a required field already fails as `missing field`. For `ingress` every field has a default, so a typo would silently keep the fail-closed default while the operator believes otherwise; hence `deny_unknown_fields` on every struct of the section, a test that typos at all four levels are rejected, and a schema test that every ingress object has `additionalProperties: false`.

### 5.7 Port 0 versus tests: reporting the bound address (decision)

Real-`sskd` tests (`crates/ssk-daemon/tests/*.rs`, `ssk-cli/tests/*.rs`) start the binary with `SSK_CONFIG_PATH` and cannot hand it a socket. The alternatives were (a) probe a free port, close it, write it into the config, and (b) `listen.port: 0` and read the real address from `IngressStatusDto.listen`. (a) is the probe-then-release race `docs/RESTART_ASSESSMENT_2026-09-21.md` records as the suspected cause of an unstable test (`activate_with_no_route_fails_closed`). A pre-bound listener inherited by the daemon (`LISTEN_FDS`-style) is not portable to Windows and would add a production code path whose only purpose is tests. **Decision: `port: 0` is valid and the bound address is reported** (`listen` is `Some("127.0.0.1:<port>")` only while bound; tests poll `GetStatus` for it). In-process tests use the `IngressPlatform::bind` seam to return a listener the test bound itself. Tests that need a port to be *taken* hold the listener for the whole test and pass that port, never a released one; a test that must re-bind after release retries the whole test on up to 5 fresh ports. A test helper (`ingress_test_config()`) sets `port: 0` and the per-OS `hardening`; a test that enables the ingress through any other route is rejected in review because the default port is shared by parallel tests.

### 5.8 `audit.destination_logging` (owner decision 3): config semantics

`plain` writes host and port of **admitted** flows in clear (the default); `hashed` writes a keyed token instead of the host and keeps `port` in clear. Denials are always plaintext. The record layout, the key, the token function, golden vectors and what an auditor can still verify are in 6.4.10. What the configuration promises:

* Every surface follows the ledger: resolved addresses of Direct-by-name, `tracing` output, the live flow registry, IPC DTOs, CLI and GUI show no more than the ledger would. Ingress code never logs a destination above DEBUG in either mode, and not at all in `hashed` mode.
* The setting is read at start (no reload, 5.9). The ledger is append-only: records written before a switch to `hashed` stay plain until retention prunes them; the `Started` record carries the mode in force. There is no scrub command; to remove older plaintext purge the ledger (RUNBOOK).
* Adding a third mode later (for example `omitted`) is a compatible vocabulary extension (5.5).

### 5.9 Configuration fingerprint, and how config edits take effect

`ssk_config::fingerprint::of(&AppConfig) -> ConfigFingerprint` (the definition is in 6.4.8) lives in `ssk-config`, not in the daemon, because `ssk config lint` must print the same digests and `ssk-cli` does not depend on `ssk-daemon` (`crates/ssk-cli/Cargo.toml`). The audit `Started` record stores all three digests; `IngressStatusDto.config` carries them so the GUI and CLI can show which configuration the running daemon holds.

There is **no hot reload**: `main.rs` loads once (`load_daemon_config`, `:246`), `Supervisor::new` takes the result once, and the `Request` enum has no reload verb. A rule or limit edit takes effect after a daemon restart, which disarms the ingress unless `arm_on_start` is `true`. RUNBOOK and the status text must say so; `ssk config lint` prints the file's digests (C-F3) so an operator can compare them with `ssk ingress status`.

### 5.10 Limits: what is configuration, what is not, and fairness

Configuration (floor/ceiling in 5.1): `max_connections`, `accept_rate_per_s`, the three timeouts, the two audit sizes. Everything else is internal `Tuning` (6.1.4), overridable by tests through `IngressDeps.tuning`. The accept bucket is derived from configuration: capacity `max_connections`, refill `accept_rate_per_s`; draft 1's fixed 32/64 per second would have admitted 38 of a 100-connection burst within a tenth of a second and closed 62 with zero bytes (arithmetic, not measured).

**Per-source fairness.** There is no per-process key to be fair to: on Linux the peer check yields only the owner uid, and on Windows an owner pid exists only after `C-WIN2` and is UNVERIFIED. A per-destination cap was rejected: one `npm install` or a load test legitimately opens many connections to one host. Fairness is therefore along the dimensions that are known: the refill rate bounds a runaway connect loop; a socket that connects and says nothing holds only a pre-admission slot, never a flow permit or an accept token, and is the first to be evicted when the 64 slots run out (7.1); a short capacity wait (250 ms, at most 8 waiting sockets, 7.1) absorbs a burst at capacity; and, as `C-E5` (RELEASE), idle eviction at capacity (close the longest-idle tunnel that has been idle for at least 30 s, at most one per arrival, never an active one) means an application that hoards idle tunnels cannot starve a new one. A runaway application that keeps all tunnels *busy* can still starve others for as long as it does; that is accepted for a single-user machine and is visible (`refused_capacity`, `ssk ingress flows`). **Decision:** draft 1's config-theme proposal of a 2 s / 128-waiter admission queue is not adopted; the descriptor budget (7.3) contains room for 8 waiting sockets and a larger queue would require re-deriving the fixed total.

The fd budget (`effective_max_connections`) is specified in 7.3 and is the only place that ties `max_connections` to `RLIMIT_NOFILE`. What backs the numbers: `defaults_admit_a_burst_up_to_max_connections` (in-process, fake data plane and ledger, explicit `Instant`s: `max_connections` connects within 100 ms, none refused for rate), `a_connect_loop_is_throttled_to_the_configured_rate`, `at_capacity_a_new_connection_waits_at_most_250ms_then_is_refused`, (`C-E3`) `silent_connections_do_not_prevent_an_authorised_handshake`, and (`C-E5`) `idle_tunnels_are_evicted_for_a_new_connection_but_active_ones_are_not`.

### 5.11 What pins the schema (replacing "schema_snapshot_stable pins nothing structural")

`schema_snapshot_stable` is four `contains` calls. It stays, and these are added: (1) `schema_matches_the_golden_file`: byte equality of `serde_json::to_string_pretty(&AppConfig::schema_json())` with `crates/ssk-config/tests/golden/ssk-config-v<N>.schema.json` (LF-normalised; `.gitattributes` already pins `*.json` to LF), regenerated only with `SSK_UPDATE_GOLDEN=1`, plus `the_golden_file_name_follows_the_current_version`; (2) `schema_properties_equal_serialized_default_keys`: walks every section of `AppConfig::default()` against the hand-written schema in both directions; at HEAD the whole config has exactly two omissions, `policy.gate_profile.thresholds` and `policy.gate_profile.required_evidence` (measured), which are listed in an allow-list that may only shrink; (3) `every_numeric_bound_is_enforced_at_both_edges`: table over the same `RangeInclusive` constants, edge, edge+-1 and 0; (4) `the_new_section_..._deny_unknown_keys_in_the_schema`. The `config_schema_guard` CI step `cargo test -p ssk-config schema_snapshot_stable` becomes `cargo test --locked --no-fail-fast -p ssk-config` (a name filter that matches nothing exits 0: measured, `0 passed; 11 filtered out`, exit 0, so renaming the test would have turned the job into a no-op).

### 5.12 Contents of the two configuration commits

`C-C0` (no schema change, `CURRENT` stays 4): `ConfigError::Document` and the label fix; the chain with only `step_3_to_4`; drift test; golden `ssk-config-v4.schema.json`; `the_default_config_survives_json_value_yaml_and_toml_round_trips`; `config_schema_guard` without the name filter. All 15 existing tests pass unchanged (message text excepted); 15 -> 20 tests.

`C-C1` (the bump): `ingress.rs`, `AppConfig.ingress`, `step_4_to_5`, v5 golden (rename + regenerate), schema entries, `routing_migration.rs` (`for version in [3, 4, CURRENT, 999]`, removing `routing` for 3 and `ingress` for 3 and 4; `json!(CURRENT_CONFIG_VERSION.to_string())` instead of `json!("4")`; smuggling list `[1, 2, 3, 4]`; the v3 test also removes `ingress`; new tests `v4_migration_preserves_routing_and_adds_a_disabled_ingress`, `ingress_rejects_bad_listen_limits_protocols_and_typos_in_both_formats` (11 mutations, both formats), `ingress_accepts_the_values_that_tests_and_operators_need`, `adapter_loops_are_checked_against_the_listener_port`); the two example generators and their drift tests; CLI string; docs rows of section 17; matrix section (5.13). The prototype ran 32 tests after `C-C1`; the key-name scan test of 5.2, the family and destination-logging tests and the ledger-size cross-check test are specified, not run. Expected count about 20 -> 38; CI is the authority.

`C-A3` (after `C-C1`): `ssk-config/src/fingerprint.rs` (6.4.8) with its tests.

### 5.13 `docs/COMPATIBILITY_MATRIX.md` text for `C-C1`

"**Config v5 and the local proxy.** Version 5 adds the required `ingress` section (disabled by default; every field inside it has a default, so `ingress: {}` is valid). Versions 1 to 4 migrate in memory to v5 with the ingress disabled; files are never rewritten. A v5 file is rejected by older builds with `UnsupportedVersion`. A section introduced by a version is rejected in a document that declares an older version. The section denies unknown keys at every level, `protocols` accepts only values the running build supports and names them in the error, and no key names a VPN, an interface or a credential. `ssk config schema` now reports `ssk-config-v5.json`; the exact schema is pinned in `crates/ssk-config/tests/golden/`. Malformed documents are reported as `invalid configuration document: ...` instead of `json serialization error: ...`; message wording is not a contract. **Config schema evolution.** Compatible within a version (no bump): a new key with a default, a new value in a validated vocabulary, a widened range; older builds refuse a file that uses it and say what they do not support. Requires a bump, a migration step and a smuggling test: a new required section or key, a changed default, a renamed or removed key, a narrowed range, a change of meaning. Every change to the schema or to its golden file needs an entry here (CI: `breaking_change_guard`)."

## 6. Types and signatures

### 6.1 `ingress/types.rs`

#### 6.1.1 Constants and vocabularies

```rust
pub const INGRESS_COVERAGE_NOTICE: &str =
    "Covers only applications that are configured to use this proxy. Everything else is not covered. Names an application resolves itself are not covered. Names this proxy resolves for direct routes are resolved by the operating system.";
// The notice must contain no word of FORBIDDEN_WORDS (10.7); a test enforces it.
pub const FORBIDDEN_WORDS: &[&str] = &[ /* the union list of 10.7: English and German */ ];

pub enum IngressState { Disabled, Starting, Unavailable, Disarmed, Armed, Tripped, Stopping }   // as_str() closed set
pub enum Coverage { None, ProxyClientsOnly }                                                    // ProxyClientsOnly only while Armed and healthy
```

#### 6.1.2 Gate, state mapping, transitions

```rust
pub struct Gate { pub epoch: u64, pub mode: GateMode }
pub enum GateMode {
    Disabled,
    Starting,
    Unavailable(UnavailableCode),
    Disarmed,
    Armed { profile: Arc<str> },
    Tripped(TripReason),
    Closing,                         // terminal: no write may change it
}
pub enum UnavailableCode {
    ConfigInvalid, HardeningUnavailable, FdLimitTooLow,                                   // properties of the process: not recoverable without a restart
    AuditCorrupt, AuditUnsupportedFormat, AuditRootUnsafe, AuditDirUnsafe, AuditFileUnsafe, AuditKeyUnavailable,
    AuditFailed, BindFailed, RecoveryFailed,                                              // recoverable (the audit ones only after the operator fixed or moved the store aside)
}
impl UnavailableCode {
    pub fn as_code(self) -> &'static str;     // CONFIG_INVALID, INGRESS_HARDENING_UNAVAILABLE, INGRESS_FD_LIMIT_TOO_LOW, INGRESS_AUDIT_CORRUPT, INGRESS_AUDIT_UNSUPPORTED_FORMAT,
                                              // INGRESS_AUDIT_ROOT_UNSAFE, INGRESS_AUDIT_DIR_UNSAFE, INGRESS_AUDIT_FILE_UNSAFE, INGRESS_AUDIT_KEY_UNAVAILABLE,
                                              // INGRESS_AUDIT_FAILED, INGRESS_BIND_FAILED, INGRESS_RECOVERY_FAILED
    pub fn recoverable(self) -> bool;
    pub fn from_trip(r: TripReason) -> Self;  // a trip while Starting: AuditWriteFailed | AuditStalled -> AuditFailed; every other reason -> RecoveryFailed
}
pub enum TripReason { AuditWriteFailed, AuditStalled, FlowPanicBudget, ControlPanic, AcceptFatal, ListenerDied }
pub enum DisarmCause { Operator, Deactivate, Shutdown, ArmSuperseded }
pub enum Actor { Operator { peer: Option<Arc<str>>, client: ClientLabel }, ConfigAutostart }   // peer = 'uid:<n>' or 'sid:<sid>' from the IPC PeerIdentity (auth.rs:47-54)
pub enum ClientLabel { Cli, Desktop, Unknown }                                                 // mapped from the request's self-declared label (11.4); never verified
```

**`IngressState` and `coverage` are functions of the mode:**

| GateMode | state | coverage | retry_hint |
|---|---|---|---|
| Disabled | disabled | none | none |
| Starting | starting | none | "starting; read status again" |
| Unavailable(c) | unavailable | none | recoverable: "arm again to retry"; otherwise the code's own next step (fix configuration, hardening or limit, then restart) |
| Disarmed | disarmed | none | none |
| Armed{p} | armed | `proxy_clients_only` only while accept task and writer are alive; otherwise reported as `tripped` with coverage none | none |
| Tripped(r) | tripped | none | "re-arm to recover" |
| Closing | stopping | none | none |

**Transitions.** "cond" = compare-and-set on `epoch`; "uncond" = always applied (L3).

| # | Event | From -> To | Kind | Who | Ledger |
|---|---|---|---|---|---|
| 1 | start publishes | Starting -> Disarmed, Unavailable(c) or Disabled | cond (epoch read at start) | host start task | `Started` durable before the bind |
| 2 | arm | Disarmed, Armed(q) -> Armed(p) | cond (epoch read under `control`, before the durable record) | control task | `Armed` durable first |
| 3 | arm, same profile | Armed(p) -> Armed(p) | no write | control task | none |
| 4 | recover | Tripped, recoverable Unavailable -> Disarmed | cond | control task | `Recovered` (written by the ledger open) |
| 5 | disarm | Armed -> Disarmed; Disarmed, Tripped, Unavailable keep their mode; Starting, Disabled, Closing: no write | uncond; epoch + 1 in Armed, Disarmed, Tripped, Unavailable | any task | `Disarmed` after the effect, only if it was Armed |
| 6 | trip(r) | Armed, Disarmed -> Tripped(r); Starting -> Unavailable(from_trip(r)); Tripped, Unavailable, Disabled, Closing -> no write | uncond | any thread | `Tripped` enqueued without awaiting, best effort |
| 7 | close | any -> Closing | uncond | shutdown | `Disarmed{shutdown}` best effort |

A disarm bumps the epoch even when the gate is already `Disarmed`, `Tripped` or `Unavailable`. That is deliberate: an arm or recover that is waiting on its fsync captured the old epoch, and the bump is what makes its compare-and-set fail. While an arm waits on its fsync the gate still reads `Disarmed` (arm writes the gate only at its compare-and-set, 6.9.2 step 5), so no caller may answer a disarm from a gate read: `SetIngress{armed: false}` always calls `disarm` (11.4), and the bump is never optimised away as a no-op. It does not write in `Starting` or `Disabled`, where no arm or recover can be in flight (arm answers `INGRESS_STARTING` or `INGRESS_DISABLED`) and where a bump would abort the start task, which publishes with a compare-and-set on its own epoch; there it only sets the `autostart_cancelled` flag. There is deliberately **no** "invalidate on observed route change" or "resume heuristic" transition: see 13.2.2 and 19.2 (MD-13).

Every transition bumps `epoch`. A flow records the `(epoch, profile)` it was admitted under and is cancelled by any change: disarm, re-arm (even to the same profile after a trip), trip, shutdown. Arming an already-armed profile is an idempotent no-op that does not bump the epoch.

#### 6.1.3 Trip policy: what trips and what does not

| Event | Effect |
|---|---|
| Writer reports an append, sync or segment-open (rotation) error; the writer thread exits for any reason (its drop guard calls `trip` before it clears its alive flag); the active segment's fd shows a length or link count that differs from the writer's own expectation; sequence-number exhaustion | `trip(AuditWriteFailed)` |
| One `sync_data` has been running for 30 s (stall detector: the host watchdog reads `sync_started_mono_ms` once per second) | `trip(AuditStalled)`; while the stalled writer thread is alive, arm answers `INGRESS_AUDIT_STALLED` and the operator restarts `sskd` (6.4.6) |
| One durable append times out, is cancelled while queued, or is refused as `Busy`, `QueueFull`, `Capacity`, `Closing`, `RecordTooLarge` | only that flow fails (`01`, no dial); counters `audit_busy`, `audit_timeouts`; **no trip** |
| Three flow-task panics since the last start or recover (`JoinError::is_panic`; tasks aborted at shutdown are `is_cancelled` and are not counted) | `trip(FlowPanicBudget)` |
| A control task panics | `trip(ControlPanic)` |
| 100 consecutive `accept()` errors (about 96 s of backoff) | `trip(AcceptFatal)` |
| The accept task ends while the gate is not `Closing` (panic or return) | `trip(ListenerDied)` |
| Per-flow dial failure, denial, peer refusal, handshake garbage, capacity shed, a dial that fails for lack of a descriptor | counters only, no trip |
| `append_closed` or summary loss; a segment prune failure (retention degrades, counted, shown as a status warning, retried at the next rotation) | counters only, no trip |
| Control lock not obtained within `control_lock_wait` | `INGRESS_BUSY` to the caller; no effect |

(The lifecycle review proposed tripping after three consecutive append timeouts; the audit design's job state machine and 30 s stall detector replace it because a timeout is not a fault, rule 16, and the detector looks at the actual blocked `sync_data`. MD-7.)

#### 6.1.4 `Tuning` (internal; NOT config; tests override via `IngressDeps.tuning`)

| group | values |
|---|---|
| accept | backoff 50 ms doubling to 1 s; `accept_fatal` 100; `capacity_wait` 250 ms; `capacity_wait_room` 8 |
| pre-admission and peer | `peer_burst` 256, `peer_refill_per_s` 1024, `pre_admission_slots` 64 (every socket from accept until its handshake is done: peer check and handshake), `handshake_evict_after` 1 s, `peer_timeout` 500 ms, `peer_queue` 256, `peer_min_snapshot_interval` 20 ms (6.6, 7.1) |
| denials | `denial_window` 60 s, `denial_keys` 128, `denial_burst` 20, `denial_refill_per_s` 1, `summary_tick` 10 s |
| budget | `panic_budget` 3 |
| audit | `audit_queue` 256, `group_commit` 64, `audit_queue_wait` 2 s, `audit_sync_wait` 5 s, `audit_stall_trip` 30 s, `summary_floor` 300 s, `closed_deadline` 1 s |
| control | `control_lock_wait` 10 s, `disarm_bookkeeping_wait` 2 s, `recover_verify_deadline` 60 s, `doctor_verify_deadline` 10 s (RunDoctor), `audit_read_verify_deadline` 30 s (`GetIngressAudit` with `verify`), `session_shutdown_bound` 1 s, `set_ingress_burst` 5, `set_ingress_refill` one token per 2 s (arm only, 11.4) |
| bind | `bind_retry_start` platform schedule (6.9.4: Unix 0, 250, 500, 1000, 2000, 4000 ms; Windows baseline bind: the Unix schedule; Windows exclusive bind 500 ms doubling to a 30 s cap, window 150 s, UNVERIFIED), `bind_retry_recover` 0, 250, 500 ms |
| cool-off (`C-E4`, OPT) | `cooloff_failures` 5, `cooloff_window` 30 s, `cooloff` 10 s |
| resolver / dial (netcore, 6.10) | `RESOLVE_TIMEOUT` 5 s (counted from the call, so the permit wait is inside it), `MAX_CONCURRENT_LOOKUPS` 16, `RESOLVER_WAIT` 500 ms, `RESOLVER_WAITERS` 32, `MAX_ANSWERS` 32, `MAX_DIAL_CANDIDATES` 8, `ATTEMPT_DELAY` 250 ms, `DIAL_EXTRA_PERMITS` 64 |
| observation | `POLL_INTERVAL` 5 s, `MAX_AGE` 15 s, `CHANGE_NOTICE_WINDOW` 600 s (6.12) |

Removed from draft 1: `accept_burst`/`accept_refill_per_s` (derived from configuration, 5.10), `audit_deadline` (replaced by `audit_queue_wait` + `audit_sync_wait`), `drain` (the shutdown plan of 8.5 is the only source of drain numbers).

### 6.2 `ingress/target.rs` (pure, table-tested)

Every client-supplied destination becomes ONE canonical `Target` BEFORE the policy engine, the audit writer or any log sees it. Why (each point proved against the code at HEAD with scratch probes outside the repo; nothing in the repo was edited):

* `MatchCriteria::matches` (`policy.rs:91-104`) compares a rule's `dest_host` with the flow host by value only when BOTH sides parse as `IpAddr`; otherwise it compares text. Rule `::1` does not match flow host `[::1]`; rule `::ffff:10.0.0.1` does not match flow `10.0.0.1` and the reverse. A deny rule written in one spelling is bypassed by the other.
* The OS dials spellings the policy never recognises. glibc `getaddrinfo` on the probe machine returns 127.0.0.1 for `127.1`, `2130706433`, `0x7f.1`, `0177.0.0.1`, `0x7f000001` and 169.254.169.254 for `2852039166`. Rust's `ToSocketAddrs`, which is what tokio's `(host, port)` dial calls (`tokio-1.53.1/src/net/addr.rs:190-222`), returns 8.0.0.1 for `010.0.0.1`.
* `ssk_config::routing::valid_host` (`routing.rs:102`) accepts all of these as DNS names, and `RoutingConfig::validate` accepts `domain_suffix: 0.1`, `destination: 2130706433` and `destination: ::ffff:10.0.0.1`. `C-P1` already stops a suffix rule from MATCHING an address form (`policy.rs:64-72 is_address_form`); the config still accepts the rule. `C-T1` closes that.
* The std IPv6-to-IPv4 conversion that is not `to_ipv4_mapped()` turns `::1` into 0.0.0.1 (probe). Only `to_ipv4_mapped()` may be used anywhere in the ingress; a source-scan test over `src/ingress` enforces it, in every call form and in comments (it does not scan the rest of the crate).

```rust
// pure: no I/O, no tokio, no clock
pub enum RawTarget { V4(Ipv4Addr, u16), V6(Ipv6Addr, u16), Name(Vec<u8>, u16) }  // Name = raw bytes of SOCKS5 ATYP 3 (HTTP CONNECT authority later feeds the same variant)
pub struct Target { /* private fields: host (canonical, never bracketed), ip, port, kind, provenance; read through host() ip() port() kind() provenance() */ }   // canonicalize() is the only constructor, so host, ip and kind cannot diverge
pub enum TargetKind { Ipv4, Ipv6, Name }
pub enum Provenance { ClientSuppliedLiteral, ClientSuppliedName }   // later front ends add NatOriginalDestination
pub enum Refusal { Malformed, NumericAlias, LocalhostName, SelfLoop, SpecialUse(SpecialUse), SpecialUseNeedsPort(SpecialUse) }
// RuleBinding { NoExactDestination, ExactWithoutPort, Exact { ip: IpAddr, port: u16 } } is defined in crates/ssk-daemon/src/routing.rs (C-S1, 6.7.1), computed once per rule by
// ConfiguredRouting::rule_binding, and only imported here: target.rs lands later than the commit that needs the type
pub enum SpecialUse { Unspecified, ThisNetwork, Loopback, Private, SharedAddressSpace, LinkLocal, Metadata, Multicast, Reserved, Broadcast, Documentation, FakeIp, ProtocolAssignment, Translation, SiteLocal, Discard, DummyPrefix }  // code() -> &'static str, snake_case; SpecialUse::ALL lists all 17
pub fn canonicalize(raw: RawTarget) -> Result<Target, Refusal>;          // returns only Malformed | NumericAlias | LocalhostName
pub fn classify_ip(ip: IpAddr) -> Option<SpecialUse>;                   // unmaps v4-mapped first; see table
pub fn guard_self_loop(t: &Target, listener: SocketAddr) -> Result<(), Refusal>;       // BEFORE policy, never overridable
pub fn guard_special_use(t: &Target, binding: RuleBinding) -> Result<(), Refusal>;     // AFTER evaluate; literals only
```

**`canonicalize` algorithm (the order is part of the contract):**

1. `port == 0` -> `Malformed`.
2. `V4(ip)` -> literal `ip`. `V6(ip)` -> if `ip.to_ipv4_mapped()` is `Some(v4)` the target is the literal `v4`, else the literal `ip`. Canonical text is `IpAddr::to_string()` (IPv6 compressed, lower case, NO brackets, no zone).
3. `Name(bytes)`:
   a. `1..=255` bytes and every byte in `0x21..=0x7E`; anything else (NUL, controls, space, DEL, every non-ASCII byte) -> `Malformed`. UTF-8 IDN is therefore refused; A-labels (`xn--`) are the only accepted IDN form and are NOT decoded or validated (policy compares ASCII text only, so look-alike Unicode cannot create a match, and no IDNA mapping step can rewrite the host behind the policy).
   b. ASCII-lowercase.
   c. If the text starts with `[` and ends with `]`, remove exactly that pair; the remainder MUST contain `:` (the same rule as `ssk-netcore/src/authority.rs unbracket`), else `Malformed`.
   d. If the text contains `:` it MUST parse as a strict `Ipv6Addr` (a zone id `%` fails) -> literal as in step 2; else `Malformed`.
   e. Remove exactly one trailing `.`; if the result is empty or still ends with `.` -> `Malformed`.
   f. If it parses as a strict `Ipv4Addr` (four decimal octets, no leading zeros) -> literal.
   g. Length `1..=253`; split on `.`; every label `1..=63`, first and last byte ASCII alphanumeric, inner bytes ASCII alphanumeric or `-`. Else `Malformed`. (This is `ssk_config::routing::valid_domain` plus the lower-case rule. Underscores and every other character are refused; accepted limitation, see 6.10.)
   h. The FINAL label must start with an ASCII letter, else `NumericAlias`. One rule kills every `inet_aton` spelling (decimal, octal, hex, short, single integer), because each of them ends in a component that starts with a digit, and a real TLD never does.
   i. Whole name `localhost` or suffix `.localhost` -> `LocalhostName`.
   j. Otherwise a `Name` target with the canonical text.

Effects: `[::1]`, `::1`, `0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1` and the domain-typed `127.0.0.1.` all become the same literal and match the same rule. A name that is really an IP literal never reaches the resolver. Brackets never reach policy, audit or the dial. `FlowRecord.descriptor.destination_host` is always `Target.host`, so the token's host (`AdmissionToken::target`) is the canonical text.

**Refusal handling.** `Malformed`, `NumericAlias`, `LocalhostName`: SOCKS reply `08`, close, counted per kind (`rejected_target.malformed|numeric_alias|localhost`) and never recorded individually (raw text is client-controlled). A numeric-alias or localhost attempt is the signature of a page trying to reach a local service through the proxy, which is why the three counters are separate. `SelfLoop`, `SpecialUse`, `SpecialUseNeedsPort`: SOCKS reply `02`, coalesced durable `Denied` (plaintext) with reason codes `TARGET_SELF_LOOP`, `SPECIAL_USE_NEEDS_EXACT_RULE`, `SPECIAL_USE_NEEDS_PORT`; `canonicalize` failures carry `TARGET_MALFORMED`, `TARGET_NUMERIC_ALIAS`, `TARGET_LOCALHOST` in counters and logs.

**Special-use table (`classify_ip`).** Checked most specific first; an IPv4-mapped IPv6 address is unmapped before lookup; the 64:ff9b::/96 NAT64 range is ALWAYS special-use: when the embedded IPv4 address is itself special-use the refusal names that reason (127.0.0.1 embedded is `loopback`), otherwise it is `translation`. Draft 2 classified a public embedded address as not special, which let `64:ff9b::808:808` through with no exact rule; it is another spelling than `8.8.8.8`, a deny rule for the IPv4 address does not match it, and on a network with a NAT64 gateway it reaches 8.8.8.8 (found by the review of `C-G1a`). IPv6 fails closed: everything outside the global unicast block 2000::/3 that is not otherwise named is `reserved`, because nothing is allocated there (this includes ::/8, so the IPv4-translated `::ffff:0:8.8.8.8` is refused). Prefixes were checked against the IANA special-purpose registry XML on 2026-10-07 (the registry lists `100:0:0:1::/64`, RFC 9780, which draft 2 missed); there is no lookup at run time. The table is pinned by an independent longest-prefix-match statement of it in the tests (`V4_ORACLE`, `V6_ORACLE`) probed at the first and last address of every prefix, the addresses next to them, every prefix bit flipped, every /16 block and random addresses; a mutation run over every numeric literal of `classify_v4` and `classify_v6` (229 mutants) is caught by it.

| Code | IPv4 | IPv6 |
|---|---|---|
| `unspecified` / `this_network` | 0.0.0.0/8 | ::/128 |
| `loopback` | 127.0.0.0/8 | ::1/128 |
| `private` | 10/8, 172.16/12, 192.168/16 | fc00::/7 |
| `shared_address_space` | 100.64/10 | none |
| `metadata` | 169.254.169.254/32 (checked before link_local) | none |
| `link_local` | 169.254/16 | fe80::/10 |
| `site_local` | none | fec0::/10 (deprecated, not in the IANA registry, refused conservatively) |
| `multicast` | 224/4 | ff00::/8 |
| `reserved` / `broadcast` | 240/4, 255.255.255.255 | everything outside 2000::/3 that is not named below: ::/8 (the deprecated IPv4-compatible ::/96 and the IPv4-translated ::ffff:0:0:0/96 included), 5f00::/16 (SRv6 SIDs), 100::/8 apart from its two /64s, 4000::/2, 8000::/1 |
| `documentation` | 192.0.2/24, 198.51.100/24, 203.0.113/24 | 2001:db8::/32, 3fff::/20 |
| `fake_ip` | 198.18.0.0/15 (benchmarking; the project's reserved fake-IP range) | none |
| `protocol_assignment` | 192.0.0.0/24 | 2001::/23 (covers Teredo 2001::/32) |
| `translation` | 192.88.99.0/24 | 2002::/16 (6to4), 64:ff9b::/96 (NAT64; a special-use embedded IPv4 address names its own reason instead), 64:ff9b:1::/48 (local-use NAT64) |
| `discard` | none | 100::/64 |
| `dummy_prefix` | none | 100:0:0:1::/64 (RFC 9780) |

**`guard_self_loop`** (runs before policy; no rule can override it): for a LITERAL target, refuse when `port == listener.port()` and (`ip == listener.ip()` or `ip.is_loopback()` or `ip.is_unspecified()`). A superset of the one address that could loop (`0.0.0.0:port` connects to the local host on Linux; Windows behaviour UNVERIFIED), harmless otherwise. A `Name` target cannot be checked before resolution; the resolved-address guard of 6.10 covers it (loopback is always refused there).

**`guard_special_use`** (runs after `evaluate`, because it needs the matched rule): a literal for which `classify_ip` is `Some` is allowed ONLY when `binding == Exact { ip, port }` with `ip == t.ip` and `port == t.port`. `ExactWithoutPort` yields `SpecialUseNeedsPort`; anything else yields `SpecialUse`. A rule with `destination: 127.0.0.1` and no `port` therefore opens nothing (the repo's own fixture `tests/support/routing_config.rs` has exactly that shape and is valid only for the activation path; ingress tests need `loopback_config_for_port(port)`). A port-only rule, a suffix rule, a deny rule, or an exact rule that is not the FIRST match in priority order never opens a special-use address; the operator must order the exact rule first. `Name` targets return `Ok` here: names are never exempt, because the exemption names an address and a name's address is not known before the dial (6.10).

**Proptests** (`ProptestConfig::default()`, so `PROPTEST_CASES=32` of the CI smoke job governs): `canonicalize` never panics on arbitrary bytes; its output host re-canonicalises to itself; an output host never contains `[`, `]`, an upper-case letter or a trailing dot; an output `Name` host never parses as an IP and its final label starts with a letter; two spellings of one address produce byte-identical hosts. Inputs are host-shaped (names, IPv6 spellings, mapped spellings, numeric aliases), not uniform bytes: uniform bytes are accepted about once in 150 draws and at `PROPTEST_CASES=32` most runs would see no accepted input at all; `generators_produce_mostly_acceptable_input` keeps the generators honest.

### 6.3 `ingress/socks5.rs` (exact-length reads, no `BufReader`)

```rust
pub enum Fault { Violation(Violation) /* silent close */, Reject(Reject) /* replied close */, Io }
pub async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<(), Fault>;     // 05 | n | n methods; require 0x00; reply 05 00 or 05 FF
pub async fn read_connect<S: AsyncRead + Unpin>(s: &mut S) -> Result<RawTarget, Fault>;         // 05 01 00 ATYP ADDR PORT, <= 4+1+255+2 bytes
pub async fn write_refusal<S: AsyncWrite + Unpin>(s: &mut S, rep: Rep) -> io::Result<()>;
pub async fn write_success<S: AsyncWrite + Unpin>(s: &mut S, _result: &ResultReceipt) -> io::Result<()>;  // 05 00 00 01 00*6, zeroed BND
pub enum Rep { Succeeded, GeneralFailure, NotAllowed, NetUnreachable, HostUnreachable, ConnectionRefused, CommandNotSupported, AddressTypeNotSupported }
```

The first byte must be `0x05`; anything else (TLS ClientHello `0x16`, `GET`, SOCKS4 `0x04`) closes **without writing a byte**. `NMETHODS` 1..=255 with `0x00` offered. CMD must be CONNECT (BIND/UDP ASSOCIATE get `0x07`), `RSV` must be 0, ATYP 1/3/4 only (else `0x08`), domain length >= 1, port != 0. ATYP 1 and 4 yield `RawTarget::V4/V6`, ATYP 3 yields `RawTarget::Name(bytes, port)` with the bytes untouched; everything that decides what the bytes mean happens in `canonicalize`. Only the request is consumed, so early client payload stays in the kernel buffer and is pumped after admission (it is the client's own payload, post-admission, not smuggling). The whole handshake runs under `timeout(handshake_timeout)`. The success reply is written only with a `&ResultReceipt` in hand.

**Refinements made at `C-G2`.** (1) `Fault` also has `Timeout`, and `handshake(stream, limit)` runs greeting and request under one deadline (a client that trickles a byte per second is cut off like a silent one); the flow code calls it instead of wrapping the two functions itself. (2) `Rep` has no `Succeeded`: a refusal code and the success code cannot be confused at a call site. `write_success` takes any `ResultProof` (a sealed trait in `types.rs`) instead of `&ResultReceipt`, because the receipt is defined by a later commit (`C-A6`) and the audit module must not import the SOCKS front end; `ResultReceipt` will be its only implementor. (3) `Reject::rep()` says which reply the CALLER still has to write; `NoAcceptableMethod` was answered `05 FF` inside `negotiate` and has none. (4) "domain length >= 1, port != 0" is enforced by `canonicalize` (`Malformed`, SOCKS reply `08`, counted `rejected_target.malformed`), not by the parser: the parser is purely structural and the meaning of the bytes is decided in one place. (5) `RSV != 0` and a wrong version byte in the request are silent closes, like a wrong first byte of the greeting.

### 6.4 `ingress/audit/`: the flow ledger (single writer, group commit, RAII receipts)

The ledger is a directory module `ingress/audit/{mod.rs, record.rs, receipts.rs, writer.rs, verify.rs, fs.rs, fs_unix.rs, fs_win.rs, dest.rs}`. The leaf enums of 6.4.3 live in `types.rs`, which lands first; `ConfigFingerprint` and `DestinationLogging` are defined in `ssk-config` and re-exported. Segments, rotation, retention and recovery are in 6.4.8; file-system security in 6.4.9; destination logging in 6.4.10; reading rules, log-injection rules and the status block in 6.4.11.

#### 6.4.1 Why a second ledger (measured; this replaces draft 1's "23 pinned tests" argument)

`audit.json` is a `GenericFileLedgerBackend` (`crates/ssk-tensor/src/lib.rs:372-430`). Every `append` reads the whole file, pushes one entry, pretty-prints the whole array into a temp file, `sync_all`s it and renames it over the target; no directory is fsynced anywhere (`write_entries`, `lib.rs:401-414`). `Inner::record_activation` (`supervisor.rs:157-189`) pays `verify()` (full read 1), `len()` (read 2), `record()` -> `entries()` (read 3) -> `append` -> `read_entries` (read 4) and then the full rewrite. `Inner::status` (`supervisor.rs:191-199`) and `GetAuditEntries` (`supervisor.rs:922-936`) read the whole file on every call.

Measured here with the real `AuditLedger::persisted` (scratch program, release build, ext4, about 370 bytes per entry): one activation-style append costs 0.96 ms at 101 entries, 9.45 ms at 1,001 and 51.6 ms at 5,001; one status read costs 0.08, 1.04 and 7.5 ms. The cost per operation is linear in the lifetime entry count. Three records per admitted flow would pass 5,000 entries after about 1,700 flows.

Decision: the ingress never writes `audit.json` and `audit.json` is not converted or rewritten in another format. Its growth stays proportional to human-driven activations. The O(n) `GetStatus` read is an accepted limitation of the activation ledger (the read is also what turns an unreadable ledger into FailClosed, and `unavailable_audit_blocks_dispatch_and_reports_the_cause` pins that, so it is not touched here). Which tests really pin `audit.json` is in 17.1.

#### 6.4.2 Line format

One record per line: `<64-hex entry_hash> <body_json>` followed by byte 0x0A. `entry_hash = blake3(prev_hash_hex ++ body_json_bytes)` over the stored bytes; the first record's prev is the literal `genesis`. The body is `serde_json::to_vec` output (compact). Proven here with serde 1.0.229 / serde_json 1.0.151: a record type with `#[serde(flatten)]` over an internally tagged enum (with `Option`, `Vec`, `BTreeMap`, `u64::MAX`) round-trips exactly, and the compact body contains no 0x0A byte even when a string field contains a line feed or U+2028 (line feed is emitted as the two characters backslash-n). Limits: `MAX_RECORD_BYTES = 64 KiB` (the writer refuses a larger body with `AuditError::RecordTooLarge`, which never trips); the reader reads lines with a bounded `read_until(0x0A)` capped at `MAX_RECORD_BYTES + 66` and treats a longer line as `Corrupt`, so a tampered file cannot make `verify_dir` allocate without bound. The reader splits on 0x0A only and requires byte 64 to be a space. Downgrade rule (matches COMPATIBILITY_MATRIX.md, "Local daemon audit ledger"): `Started.ledger_format` greater than the build's own value makes `open_dir` and `verify_dir` return `UnsupportedFormat` and the daemon appends nothing.

#### 6.4.3 Records

```rust
// types.rs (leaf)
pub use ssk_config::ingress::DestinationLogging;                    // Plain | Hashed
pub enum HostKind { Name, Ipv4, Ipv6 }
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DestRef {
    Plain  { host: String, port: u16 },
    Hashed { kid: String /*16 hex*/, kind: HostKind, token: String /*32 hex*/, port: u16 },
}
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AddrRef { Plain { ip: String, port: u16 }, Hashed { kid: String, kind: HostKind, token: String, port: u16 } }
pub enum Resolution { Literal, ProxyResolved, LocalPinned }         // planned at Pending time: a name on a proxied route is ProxyResolved, a name on Direct is LocalPinned (resolved once by sskd, filtered, dialled pinned)
pub enum ResultOutcome { Connected, Failed, NotDialed, Aborted }
pub struct Unresolved { pub pending: u64, pub open_tunnels: u64 }
pub use ssk_config::fingerprint::ConfigFingerprint;                 // { version: u32 /*1*/, config: String, routing: String, ingress: String }  64-hex blake3 each (6.4.8)
pub struct RuleTable { pub total: u32, pub truncated: bool, pub rules: Vec<RuleRow> }       // at most 256 rows
pub struct RuleRow { pub id: String, pub priority: u32, pub action: String /*direct | deny | adapter:<id>*/, pub attestation: bool,
                     pub exact_destination: bool, pub suffix: bool, pub port: Option<u16> }  // never the destination text
pub struct Observation { pub kind: String, pub value: String }       // closed kinds: egress_local, os_route_if (10.5); validated by Observation::new (rule R-O in 6.4.11)

// audit/record.rs
pub struct FlowAuditRecord { pub seq: u64, pub ts_ms: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")] pub flow_id: String,         // empty for non-flow records
    #[serde(flatten)] pub event: FlowAuditEvent }
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FlowAuditEvent {
    Started   { daemon_version: String, ledger_format: u32 /*1*/, config: ConfigFingerprint,
                destination_logging: DestinationLogging, dest_key_id: Option<String>, unresolved_before: Unresolved },
    Recovered { truncated_tail_bytes: u64, unresolved: Unresolved, after_trip: Option<String> },
    Armed     { profile: String, cause: String /*operator | config_autostart*/, client: String /*cli | desktop | config | unknown*/,
                requested_by: String /*uid:<n> | sid:<sid> | config*/, epoch: u64, profile_digest: String, rules: RuleTable, observations: Vec<Observation> },
    Disarmed  { cause: String /*operator | deactivate | shutdown | arm_superseded | arm_not_applied | arm_abandoned*/, epoch: u64 },
    Tripped   { reason: String, epoch: u64 },                          // best effort, bounded; cannot exist for AuditWriteFailed
    Denied    { peer: String, peer_verified: bool, dest: DestRef /*always Plain*/, target_provenance: String, target_kind: String /*ipv4|ipv6|name*/, profile: String,
                matched_rule: Option<String>, reason_code: String, route: Option<String>, coalesced: bool },
    Pending   { peer: String, peer_verified: bool, dest: DestRef, target_provenance: String, target_kind: String, resolution: Resolution, profile: String,
                matched_rule: Option<String>, route: String, planned_adapters: Vec<String> },
    Result    { outcome: ResultOutcome, error_code: Option<String>, refusal: Option<String> /*static label of an AddressRefused failure*/, chain_kinds: Vec<String>,
                dialed: Option<AddrRef>, attempted: Vec<AddrRef> /*<= 8, start order*/, answers: Option<u8>, observations: Vec<Observation> },
    Closed    { bytes_up: u64, bytes_down: u64, duration_ms: u64, reason: String },
    Summary   { window_ms: u64, pre_admission_rejects: BTreeMap<String,u64>, denials_suppressed: BTreeMap<String,u64>,
                denials_over_quota: BTreeMap<String,u64>, denials_repeated: Vec<RepeatCount> /*top 16*/, other_keys: u64 },
    Continue  { prev_segment_head: String, prev_seq: u64, pruned_before_seq: Option<u64>, prune_deferred: u32, refusals_unrecorded: u64 },
}
```

Semantics. `ResultOutcome::Connected`: the upstream tunnel is established; no application byte may follow before this record is durable. `Failed`: a dial was started and failed (`error_code` is `NetcoreError::code()`, `error.rs:53-69`, or an ingress code; a name refused after resolution is `NETCORE_ADDR_REFUSED`). `NotDialed`: no dial was started (guaranteed by the receipt type-state, 6.4.4). `Aborted`: a dial was started and the flow ended before the real outcome was recorded; the upstream may or may not have been established; no application byte reached the client's destination through this flow (bytes require a `ResultReceipt`). `chain_kinds` replaces draft 1's `chain`: `EgressSession::chain()` returns `&[AdapterKind]` (`session.rs:51`), that is adapter kinds, not adapter ids; the ids are `Pending.planned_adapters`. Kinds are written through an exhaustive match (`direct, socks5, http_connect, tls_tunnel, dns_override, open_vpn`), not `{:?}`. `Result.dialed` is the pinned peer address of the winning attempt of a Direct-by-name dial, `attempted` lists every address for which a connect was started (start order, at most 8; for a failed flow it is the only record of what was tried) and `answers` is the number of resolver answers (6.10); `dialed` and `attempted` follow the destination setting (`AddrRef`). A dial that is cancelled before it reports (gate change, deadline) is `Aborted` and its `attempted` list is unknown: its `Pending` says only that the dial may have happened. `refusal` is the closed, static label of an `AddressRefused` failure (`loopback`, `private`, ..., `listener`, `deny_rule`), never an address. `observations` holds only the two closed kinds of 10.5 (`egress_local`: the source address the OS gave the dial socket, `os_route_if`: the cached route-interface alias, at most 15 s old); both are optional so a failed or cancelled dial still writes a valid record. `Pending.resolution` is written before the dial and is a plan; the netcore `ResolutionMode` (`Literal`, `OsResolver`, `ForwardedUnresolved`) maps to it 1:1 (`literal`, `local_pinned`, `proxy_resolved`). Closed sets (constants in `types.rs`): `Closed.reason`, `Denied.reason_code`, `Result.error_code` (`NetcoreError::code()` values plus `GATE_CLOSED, FLOW_DROPPED, AUDIT_ABANDONED, RESULT_NOT_RECORDED, DIAL_NOT_COMPLETED, CONNECT_DEADLINE, COOLING_OFF, RECEIPT_MISMATCH`) and `Result.refusal` (the special-use codes of 6.2, `listener`, `deny_rule`, `not_armed`). Free text from a client, from `NetcoreError` Display, from a profile display name (`valid_id` is enforced for ids only; `profile.name` is any non-empty string, `ssk-config/src/routing.rs:145-148`) or from an upstream proxy never enters a record. `flow_id` is `ingress:b<seq of the governing Started>:<n>`; therefore every flow identifies its Started record and with it the configuration fingerprint (6.4.8).

`Started` is the first record of every daemon boot and of every re-open after a trip. `unresolved_before` is computed while the chain is verified at open (flows with a Pending and no Result, tunnels with a connected Result and no Closed, in all earlier epochs) and is recomputable by any verifier. `Recovered` is written before `Started` when a torn tail was truncated or the ledger was re-opened after a trip.

#### 6.4.4 Receipts: the type-state, with drop-time compensation

```rust
pub struct PendingReceipt { /* private: Arc<FlowCtl>, seq, entry_hash, binding */ }   // not Clone
pub struct ResultReceipt  { /* private: Arc<FlowCtl>, Arc<Stats>, seq, entry_hash */ }  // not Clone; the ONLY value that authorises a success reply or a byte
pub struct Receipt        { pub seq: u64, pub entry_hash: String }                       // any other durable record; private constructor
pub struct ArmReceipt     { /* private */ }     // Armed is durable; resolved by applied() or superseded(cause); dropped unresolved it compensates
```

Constructors are private to `audit` (a `compile_fail` doctest, like `AdmissionToken`'s at `crates/ssk-netadmin/src/admission.rs:12-16`). `append_result*` and `append_not_dialed` take `&PendingReceipt`; `write_success` and `pump` take `&ResultReceipt`; `dial` takes `&PendingReceipt` and consumes the `AdmissionToken`. Only a durable `connected` Result yields a `ResultReceipt`; failed, not-dialed and aborted outcomes yield a plain `Receipt`, which authorises nothing.

Binding. `append_pending` builds the record from the token itself, which its `PendingInput` carries by reference (6.4.7) (`AdmissionToken::target()` and `route()`, `admission.rs:25-34`, and `summarise_route(route)`, which must become `pub` in `ssk-netadmin/src/audit.rs:72`; it is still private at HEAD, commit `C-A1`) and stores `binding = blake3(kind || host || port || route summary)` in the receipt. `dial` recomputes the binding from the token it is about to consume and refuses with `DialFault::ReceiptMismatch` (recorded as `NotDialed`, `RECEIPT_MISMATCH`) when it differs: the ledger can never say X while the dial does Y, where X is the authorised host, port and route (for a Direct name the addresses are derived from one answer and are recorded in `Result.attempted`). `dial` also sets `ctl.dial_started` immediately before `connect_route`.

Compensation on drop. A receipt that is dropped unresolved sends one compensation job over an unbounded channel with a synchronous send (`tokio::sync::mpsc::UnboundedSender::send`; `Drop` cannot await, and a spawned cleanup task is not guaranteed during runtime shutdown). The writer drains compensation jobs with priority; they bypass the queue cap, the refusal quota and caller cancellation; `close()` drains them before it exits. The flow guard of 7.1 and the control tasks of 6.9 rely on exactly this and enqueue nothing else on drop.

| value dropped while | compensation record written | what an auditor may conclude |
|---|---|---|
| `PendingReceipt`, no dial started, no result submitted | `Result{NotDialed, code}` with the explicit code, else `FLOW_DROPPED`, else `AUDIT_ABANDONED` | no dial was started |
| `PendingReceipt`, dial started, no result submitted | `Result{Aborted, DIAL_NOT_COMPLETED or RESULT_NOT_RECORDED}` | a dial began; real outcome unknown; no application byte flowed |
| `ResultReceipt` not consumed by `closed()` | `Closed{aborted or audit_abandoned, bytes from Stats}` | tunnel ended without its normal close; counted bytes are real |
| `ArmReceipt` neither `applied()` nor `superseded(cause)` | `Disarmed{arm_not_applied or arm_abandoned}` | the gate was never opened for that Armed record |

A flow whose task panics or is aborted (JoinSet `abort_all` at shutdown, panic budget) therefore leaves a closed story without any cooperation from the dying task. The host must finish `abort_all` and join the aborted tasks before it calls `audit.close()` (8.5).

Ordering invariants the tests assert: I1 `Pending` is durable before `connect_route` is entered. I2 `Result{Connected}` is durable before the success reply and before any byte. I3 the first `Denied` of a key inside the refusal quota is durable before the refusal reply. I4 `Armed` is durable before the gate opens. I5 per flow, `seq(Pending) < seq(Result) < seq(Closed)`. I6 inside one boot every Pending is resolved by exactly one Result (explicit or compensating) and every connected Result by exactly one Closed; the only exceptions are traces of a dead process or a dead writer, and they are bounded by the next `Started` or `Recovered` record (`unresolved`), an upper bound on what may have happened.

#### 6.4.5 The writer thread

A named `std::thread` (not a blocking-pool slot, not a runtime worker; it uses `UnboundedReceiver::blocking_recv`, which is allowed off-runtime). One unbounded job channel carries everything; the depth of normal jobs is capped by an atomic counter (`audit_queue = 256`; compensation jobs bypass it), so `try_send` never blocks a runtime worker. `FlowAuditWriter::open_dir` takes a `LockProof` (a zero-sized `Copy` token that only `DaemonLock::proof(&self)` mints; a borrowed `&DaemonLock` could not move into `spawn_blocking`, which needs `'static`) as proof that the process holds the single-writer lock (`lock.rs`, acquired in `main.rs::run` before `serve`) and runs inside `spawn_blocking`.

Loop: (1) `blocking_recv` one job. (2) `try_recv` up to 63 more (group commit is opportunistic: no artificial delay, a lone job costs one fsync). (3) Claim: a normal job is claimed by `CAS Queued->Claimed`; a failed CAS means the caller cancelled it while queued, so it is skipped, writes nothing and consumes no `seq`. (4) Admission: refusal quota (6.4.8), hard capacity, `RecordTooLarge`. (5) If `expected_len + batch_bytes > segment_bytes` rotate first (6.4.8); a batch is never split, so `segment_bytes` is a soft limit exceeded by at most one batch (at most 64 x 64 KiB). (6) `fstat` the open fd, not the path: `st_nlink == 0` (unlinked under us) or `st_size != expected_len` (external append or truncate) is `Io(AUDIT_EXTERNAL_MODIFICATION)`. (7) Serialise in memory, assign `seq = next_seq + i` (checked add; overflow is `SeqExhausted`), `ts_ms` (`SystemTime` read with `map_or`, never `unwrap`), chain the hashes sequentially, one `append` of the concatenated lines (the file is opened `O_APPEND`), one `sync_data`. (8) Any error: best-effort `truncate_active(prev_len)`, every job in the batch gets `Err(Io(code))`, `on_trip(AuditWriteFailed)` is called, the thread exits; a `TripOnExit` guard calls `on_trip` when the thread dies by panic, so a dead writer can never leave the gate open. A partial tail that survives is handled by torn-tail recovery at the next open (6.4.8). (9) After the sync: update the status atomics (`entries, head, bytes, last_sync_ms`), then per job `CAS Claimed->Done` and `reply.send(Ok(receipt))`; a failed CAS (the caller abandoned the job after the claim) or a failed `send` (receiver gone) hands the receipt back to the writer, which drops it, and the receipt's `Drop` queues the compensation record. (10) `sync_started_mono_ms` is set before `sync_data` and cleared after it, for the stall detector.

A reply, and therefore a receipt, exists only after the `sync` that covers its record. All arithmetic in this tree is checked or saturating and the lint set of 12.12 applies (release builds have `overflow-checks = true`, `Cargo.toml:144`, so an unchecked add on a hostile-influenced number is a panic, and three flow panics trip the ingress).

#### 6.4.6 Errors, timeouts, cancellation, trips

The caller side of every append is one function with one state machine. Job state is an `Arc<AtomicU8>`: Queued, Claimed (writer owns it), Done (writer acknowledged and replied), Cancelled (caller won while queued), Abandoned (caller won after the claim). The caller waits `audit_queue_wait` (2 s) for the claim; if it times out it does `CAS Queued->Cancelled`: success returns `Busy` and the job will never be written; failure means the writer already claimed it, so the caller waits `audit_sync_wait` (5 s) for the reply, and on a second timeout does `CAS Claimed->Abandoned` and returns `Timeout`; a failed CAS means the reply is already there and is taken. A guard in the caller does the same CAS on drop (a cancelled caller future never leaves a half-owned job). Exactly one side wins each CAS, so there is no window in which a record is written, nobody holds its receipt and nobody compensates.

| error | meaning | ledger effect | client sees | trips the gate |
|---|---|---|---|---|
| `QueueFull` | normal-job depth is at `audit_queue` | none | `01` (Denied: `02`, no durable record, counted) | no |
| `Busy` | not claimed in 2 s; cancelled | none | `01` | no |
| `Timeout` | claimed, not acknowledged in 5 s; abandoned | the record may become durable later; its receipt compensates (6.4.4) | `01` | no |
| `Capacity` | segment count reached the hard cap because prune keeps failing (6.4.8) | none | `01` | no |
| `Closing` | `close()` has started | none | `01` | no |
| `RecordTooLarge` | body over 64 KiB (a bug, Armed tables are capped at 256 rows) | none | `01` | no |
| `WriterDown` | writer thread gone | n/a | `01` | yes (the thread guard already tripped) |
| `Io(code)` | append, sync, rotate, create or fstat check failed (`AUDIT_DISK_FULL` for `ErrorKind::StorageFull`, stable since 1.83, workspace MSRV is 1.85) | batch failed, possible torn tail | `01` | yes, `AuditWriteFailed` |
| `SeqExhausted` | `u64` overflow | none | `01` | yes |

Decision (answers "does `AuditError::Timeout` trip the gate"): no. A transient fsync stall (anti-virus, a slow disk) must not require a manual re-arm; `Busy` and `Timeout` are counted (`audit_busy`, `audit_timeouts`) and shown in status. A stall that does not end is caught by a separate detector: the host watchdog reads `sync_started_mono_ms` once per second and calls `trip(AuditStalled)` when one `sync_data` has been running for `audit_stall_trip` = 30 s. A thread blocked in the kernel cannot be replaced safely, so while the writer thread is still alive `arm` refuses with `INGRESS_AUDIT_STALLED` (and `recover` fails with the same code: it never opens a second writer on the same segment); the operator restarts `sskd`. This is an accepted limitation.

Worst-case audit wait on the connect path is therefore 7 s before the dial and 7 s after it; the dial keeps its own `connect_timeout`.

Latency budget. Each admitted flow pays two durable appends before its first byte (Pending, Result); concurrent flows share fsyncs through group commit. Measured here (scratch program, ext4 on a virtio disk in a VM, 400-byte record, 1,000 samples): `append + sync_data` p50 0.13 ms, p99 0.32 ms, max 0.95 ms; 64 records per `sync_data` p50 0.27 ms; directory fsync p50 0.03 ms; a full rotation (create, write, `sync_all`, directory fsync) p50 0.32 ms. These are not representative of Windows with a scanner: UNVERIFIED there. Budget: the mechanism bounds the damage (7 s ceilings, no trip), status exposes `sync_last_ms` and `sync_max_ms`, and `RunDoctor` runs a probe of 20 create/write/`sync_data`/unlink cycles in the state root (not in the ledger directory) and reports p50 and max with a warning above 250 ms. No test gates on wall-clock latency.

#### 6.4.7 API

```rust
pub struct AuditOpenCfg { pub segment_bytes: u64, pub retain_segments: u32, pub denied_share_percent: u8 /*20*/, pub summary_share_percent: u8 /*5*/,
                         pub destination_logging: DestinationLogging, pub fingerprint: ConfigFingerprint, pub daemon_version: String }   // bytes, so tests can use tiny segments
pub trait LedgerIo: Send + 'static {                                  // the I/O fault-injection seam
    fn append(&mut self, bytes: &[u8]) -> io::Result<()>;
    fn sync_data(&mut self) -> io::Result<()>;
    fn active_stat(&self) -> io::Result<ActiveStat>;                   // fstat of the OPEN fd: len, nlink
    fn truncate_active(&mut self, len: u64) -> io::Result<()>;
    fn rotate(&mut self, next_first_seq: u64, first_record: &[u8]) -> io::Result<()>;   // create, write, sync_all, sync_dir, switch
    fn prune(&mut self, keep: u32) -> io::Result<PruneOutcome>;        // per-file failure is reported in the outcome, not as Err
}
pub struct PruneOutcome { pub pruned_before_seq: Option<u64>, pub deferred: u32 }
impl FlowAuditWriter {
    pub fn open_dir(lock: LockProof, fs: Arc<dyn LedgerFs>, cfg: AuditOpenCfg, on_trip: Arc<dyn Fn(TripReason) + Send + Sync>) -> Result<Self, AuditOpenError>; // blocking
    pub fn open_with(io: impl LedgerIo, replayed: Replayed, cfg: AuditOpenCfg, on_trip: Arc<dyn Fn(TripReason) + Send + Sync>) -> Self;       // test seam
    pub async fn append_pending(&self, input: PendingInput<'_>, w: Waits) -> Result<PendingReceipt, AuditError>;
    pub async fn append_connected(&self, p: &PendingReceipt, ev: ConnectedEvent, w: Waits) -> Result<ResultReceipt, AuditError>;
    pub async fn append_failed(&self, p: &PendingReceipt, code: &'static str, w: Waits) -> Result<Receipt, AuditError>;
    pub async fn append_not_dialed(&self, p: &PendingReceipt, code: &'static str, bounded: Duration) -> Result<Receipt, AuditError>;
    pub async fn append_denied(&self, ev: DeniedEvent, w: Waits) -> Result<DeniedOutcome, AuditError>;   // Recorded(Receipt) | OverQuota
    pub async fn append_armed(&self, ev: ArmedEvent, w: Waits) -> Result<ArmReceipt, AuditError>;
    pub async fn append_disarmed(&self, ev: DisarmedEvent, bounded: Duration);                              // never fails the caller
    pub fn try_enqueue_tripped(&self, ev: TrippedEvent) -> bool;                                            // sync, never blocks, rides the compensation channel; used by trip()
    pub fn queue_summary(&self, s: SummaryEvent) -> bool;
    pub async fn flush(&self, deadline: Duration) -> Result<(), AuditError>;                                 // barrier
    pub fn status(&self) -> AuditStatus;                                                                     // atomics only, no file read
    pub async fn close(&self, deadline: Duration);                                                           // &self, idempotent
}
impl ResultReceipt { pub async fn closed(self, ev: ClosedEvent, bounded: Duration); }                        // consumes; loss is counted, never trips
impl ArmReceipt { pub fn applied(self); pub fn superseded(self, cause: DisarmCause); }                       // superseded queues Disarmed{arm_superseded} on the compensation channel
pub struct Waits { pub queue_wait: Duration, pub sync_wait: Duration }
pub enum AuditError { QueueFull, Busy, Timeout, Capacity, Closing, RecordTooLarge, WriterDown, SeqExhausted, Io(&'static str) }
```

**Input types and the dependency direction.** The writer's inputs are plain structs defined next to the records in `audit/record.rs`; they carry only types from `types.rs`, `target.rs`, `ssk-netadmin` and `ssk-config`:

```rust
pub struct PendingInput<'a> {
    pub token: &'a AdmissionToken,             // host, port and route that will be dialled; the receipt binding is computed from it (6.4.4)
    pub flow_id: &'a str, pub profile: &'a str, pub matched_rule: Option<&'a str>,
    pub peer: &'a str, pub peer_verified: bool,
    pub target_kind: TargetKind, pub provenance: Provenance,
    pub resolution: Resolution, pub planned_adapters: &'a [String],
}
pub struct PeerStamp { pub peer: Arc<str>, pub verified: bool }      // types.rs
// ConnectedEvent, DeniedEvent, ArmedEvent, DisarmedEvent, TrippedEvent, ClosedEvent, SummaryEvent: likewise plain owned structs in record.rs
```

`engine::Admitted::pending_input(&self, peer: &PeerStamp, profile: &str) -> PendingInput<'_>` (in `engine.rs`, `C-E2`) is the only bridge from the engine's type to the audit's. Draft 2 declared `append_pending(&self, adm: &Admitted, ..)`, which made the writer (`C-A6`) depend on a type that lives in the engine (`C-E2`), a commit that has to come after it. The source scan `audit_module_has_no_upward_imports` (needles `ingress::engine`, `ingress::flow`, `ingress::host`, `ingress::shared` inside `ingress/audit/`) keeps the direction.

`close(self)` of draft 1 cannot be called through the `Arc<FlowAuditWriter>` that `EngineCtx` and `IngressHost` both hold (an `Arc` cannot be moved out of while another clone exists), so `close` takes `&self`: it sets `Closing` (normal appends are refused, compensation jobs are still accepted), enqueues `Shutdown`, lets the writer drain, `sync_all` and exit, and joins the thread inside `spawn_blocking` under `deadline` (after the deadline the join is abandoned; the process is exiting and holds the daemon lock until it ends, 8.5).

**Refinements made at `C-A6`** (the writer, the receipts and the compensation; rotation, retention, the refusal quota and `open_dir` are `C-A7`). (1) `open_with(io, replayed, cfg, sealer, on_trip)` returns `Result`: it writes `Recovered` (when `Replayed` says a torn tail was cut or a trip preceded) and `Started` itself, synchronously, before the thread starts, and a failure there is the opener's to report and trips nothing. The flow id is `ingress:b<seq of this boot's Started>:<n>`, from `next_flow_id()`, so ids stay unique across restarts without being stored. (2) The waits: the caller does not learn of the claim separately, so `queue_wait` is the wait for the first answer and the claim is checked when it ends (still queued: cancelled, `Busy`; claimed: wait `sync_wait` more). The ceiling `queue_wait + sync_wait` is the design's 7 s; a job claimed at once and slow to sync is waited for from the submission, not from the claim. A caller that is dropped does the same compare-and-swap in a guard. (3) Compensation jobs share the one channel, in order, and bypass the queue cap, cancellation and `closing`; they are not drained "with priority" (nothing needs it: a compensation only has to be written). `send_comp` answers `false` and counts `compensations_lost` once the writer is down, whether or not its channel is closed yet. (4) A write fault trips first and answers second (`fail_batch`): whoever sees the error also sees a tripped gate, and `submit` refuses with `WriterDown` while the trip callback is still running. The same holds when a batch runs out of sequence numbers (what fitted is durable and answered, the trip comes next, and only then are the refused told) and when the writer thread panics (a guard declared after the values that hold the callers' reply channels trips while they are still alive; unwinding closes those channels afterwards). The callback runs on the writer thread and must not block. Review finding: the first version told callers before tripping on the panic and exhaustion paths, which no test saw because the panic test only waited for the trip. The jobs still queued behind a failed batch are dropped, which answers their callers `WriterDown` at once (the reply channel closes); a flush that was in the batch or behind it is told `false`. (5) Writer inputs are plain structs in `audit/input.rs` (not `record.rs`): `PendingInput`, `ConnectedEvent`, `FailedEvent` (a struct, because a failed dial's `attempted` list, `answers` and observations are its only record of what was tried), `DeniedEvent`, `ArmedEvent`, `DisarmedEvent`, `TrippedEvent`, `ClosedEvent` (the duration is the receipt's own), `SummaryEvent`. Addresses arrive as `SocketAddr`s and are sealed by the writer's `DestSealer`, so a result cannot name a plain address in `hashed` mode; the attempted list is cut at eight (the format's limit) instead of making a finished dial unrecordable. (6) The free-text-looking fields are closed lists tied to the code that produces them (`RESULT_ERROR_CODES` to `NetcoreError::code()` for every variant, `RESULT_REFUSALS` to the 17 special-use labels and the 3 guard labels, `DENIED_REASON_CODES` to `Refusal::reason_code()`, `CloseReason` to the pump's words); a producer's word outside its list is written as `UNKNOWN_CODE` and counted in `unknown_codes`, so a record is never lost to a vocabulary drift and the drift shows in status and in a test of that producer. The one code with the letters `vpn` in it, `OPENVPN_NOT_READY`, is the existing machine code of a netcore error, not a statement. (7) `Result` bookkeeping: `result_submitted` is set when the result is submitted, not when it is durable, so that a `Timeout` (the record may still land) never produces a second `Result`; any other failure reopens it and the `Pending`'s drop writes the honest one. A result future that is DROPPED (a flow task aborted at shutdown, a client that went away inside a `select!`) while its job is still queued has its job cancelled and never written, so the claim guard runs a callback when it wins that compare-and-swap: for a result it reopens the `Pending` (which then writes its own), for `closed()` it writes the `Closed` itself with the real byte counts and `audit_abandoned`. (Review finding: without the callback both stories stayed open, and the invariant "a flow whose task is aborted leaves a closed story" was false in exactly the case it exists for.) A job that was already claimed lands by itself and needs nothing (`RESULT_NOT_RECORDED` after a dial, or the explicit code of a `NotDialed` that could not be recorded, else `FLOW_DROPPED`, else `AUDIT_ABANDONED`). A second result for one `Pending` is refused. A `ResultReceipt` whose caller is gone is dropped by the writer and writes `Closed{audit_abandoned}` with the counted bytes; a `closed()` that could not be written is written by the drop with the real byte counts. (8) `ArmReceipt` has three ends: `applied()`, `superseded()` (`arm_superseded`), `not_applied()` (`arm_not_applied`), and a drop writes `arm_abandoned`. (9) `Denied` records carry no flow id; `DeniedOutcome::OverQuota` exists for `C-A7`. `open_with` is crate-internal (a writer over a disk of one's own choosing can issue receipts); the input events that hold plain addresses have a `Debug` that shows counts only. (10) `LockProof` is in `lock.rs`: zero-sized, `Copy`, minted only by `DaemonLock::proof`. (11) What is tested without a hook and what is not: the receipts' constructors, their lack of `Clone` and the sealed marker are pinned by compile-fail snapshots (`tests/ui_receipts.rs`, trybuild: the exact error is the snapshot; a `compile_fail` doctest passes for any compile error, including a missing field, so it would not notice a field made public) and by a scan that lists every non-test implementor, test modules cut out by brace position; the delivery state machine is tested on `deliver_fn` directly; the stall watchdog (`io_in_progress_for`) covers the whole disk part of a batch, not only `sync_data`; a clean shutdown closes the channel before its last look, so a late `send` is refused and counted (the window between the last look and the close cannot be forced in a test); the race in which the answer lands between a caller's second timeout and its compare-and-swap (the caller then takes the answer instead of reporting `Timeout`) cannot be forced deterministically and is covered by reasoning only, and the order of the two compare-and-swaps of the drop guard is immaterial (only one can succeed).

#### 6.4.8 Segments, rotation, retention, refusal quota, durability order, open and verify

Layout:

```
<state_dir>/ingress-audit/            mode 0700 (Layout::flow_audit_dir)
    seg-00000000000000000001.jsonl     mode 0600, name = seg-<first_seq:020>.jsonl
    seg-00000000000000104857.jsonl
<state_dir>/ingress-dest.key          mode 0600, hashed mode only (Layout::dest_key_path); outside the ledger directory on purpose
```

`paths.rs` gains both accessors and `the_daemon_layout_agrees_with_the_shared_socket_path` is extended.

**Durability order** (every step names what must be durable before the next):

| # | operation | order |
|---|---|---|
| D1 | create the ledger directory | `mkdirat(root_fd, 'ingress-audit', 0o700)`; `openat` it with `O_DIRECTORY\|O_NOFOLLOW`; verify (6.4.9); `fsync(dir_fd)`; `fsync(root_fd)` |
| D2 | create the first segment | `openat(..., O_CREAT\|O_EXCL\|O_APPEND\|O_NOFOLLOW, 0o600)`; verify; write `Started` (and `Recovered`); `sync_all`; `fsync(dir_fd)`; only then is the first receipt allowed to exist |
| D3 | create the destination key (hashed mode) | `create_new`, 0600, write 64 hex chars and 0x0A; `sync_all`; `fsync(state_root_fd)` |
| D4 | append | one `append`, one `sync_data` per batch (fdatasync also persists the size needed to read the data back) |
| D5 | rotate | R1 choose the prune set (all but the newest `retain_segments - 1` existing segments); R2 create the next segment (`create_new`); R3 write the `Continue` record (`pruned_before_seq` = first seq that survives, `prune_deferred` from the previous round, `refusals_unrecorded`); R4 `sync_all`; R5 `fsync(dir_fd)`; R6 switch the active handle (only now may the waiting batch be appended); R7 unlink pruned segments oldest first, then `fsync(dir_fd)` |
| D6 | prune failure | keep the file, count `prune_deferred`, log `AUDIT_PRUNE_DEFERRED` once at WARN without names, and stop at the first file that cannot be removed (the newer victims are kept too: no hole in the chain); a failed directory fsync after prune is logged and ignored; neither trips the gate |

No segment is ever renamed and no closed segment is ever truncated or rewritten (this removes the Windows rename/sharing-violation class entirely: the writer only creates new names and deletes old ones). A rotate failure in R2 to R6 is a write fault (`Io`, trips). If prune keeps failing and the segment count reaches `2 x retain_segments`, new Pending and Armed records are refused with `Capacity` (no trip) until a later prune succeeds. Rotation is part of the spine (`C-A7`): there is no milestone build in which a growing file is the only bound.

Crash windows and their recovery rules: after R2 before R4 the highest segment is empty or holds a torn first line: if it has a predecessor it is unlinked (with directory fsync) and the predecessor becomes active; if it is the only segment the ledger is a fresh chain. After R5 before R7 more than `retain_segments` segments exist: the next rotation prunes down (`while count > retain`). After R7 before the directory fsync a pruned segment may reappear: it is still a valid anchored prefix and is pruned again. `Continue.pruned_before_seq` greater than the first seq actually present means "prune pending" and is not an error.

**Refusal quota (a flood of distinct denials cannot evict admitted-flow evidence).** One chain, two classes. Per segment, `Denied` records may use at most `denied_share_percent = 20` and `Summary` records at most `summary_share_percent = 5` of `segment_bytes` (checked integer math). The writer keeps per-class byte counters of the active segment (recomputed from the active segment at open, reset at rotation). A `Denied` job over its share is not written: the writer replies `Ok(DeniedOutcome::OverQuota)`, the flow still answers `02`, and the refusal is counted (`denials_over_quota`, per reason code, carried in the next written `Summary`, and `refusals_unrecorded` in the next `Continue`). A `Summary` over its share is merged into the in-memory aggregate; one `Summary` is always allowed every `summary_floor = 300 s` (at most 2 KiB: totals per reason, the 16 most repeated keys, `other_keys`), which adds at most about 0.6 MiB per day. Consequences, each a test: a denial-only flood grows the active segment by at most the Denied share plus the Summary share (20 plus 5 percent, 8 MiB together at the default 32 MiB) plus the floor summaries (about 0.6 MiB per day), so the volume of the flood never reaches `segment_bytes`, never rotates and never prunes anything; with mixed traffic the evidence classes (Pending, Result, Closed, Armed, Disarmed, Started, Recovered, Tripped, Continue) keep at least 75 percent of every segment. Admitted-flow evidence can only be pushed out by admitted-flow volume (at the rate and in the time stated under Retention below). The "first occurrence durable before the reply" therefore holds inside the quota and degrades to "counted and summarised" beyond it, exactly as it already did beyond the 1 per second bucket.

**Retention** is by size only: `retain_segments` x `segment_mib` (default 8 x 32 MiB). Measured on a synthetic mix of Pending, Result and Closed lines, the average line is 277 bytes (about 0.83 KB per admitted flow), so the default holds about 320,000 admitted flows. That is days to weeks of ordinary browsing (the real window depends on traffic and is unverified for real browsing) **and about 1.8 hours at the sustained admission cap** (`accept_rate_per_s` 50: 268,435,456 bytes / 831 bytes per flow / 50 per second; arithmetic, not measured). The second figure is what a runaway loop does to the window, and what any process that is allowed to use the proxy can do on purpose with a connect-and-close loop to one allowed destination: older records are pruned, oldest first, and nothing keeps young ones. A size-only window therefore says nothing about how long history is kept. Status shows what is retained (`oldest_ts_ms`, `pruned_entries`) and warns with `AUDIT_WINDOW_SHORT` once pruning has begun and the oldest retained record is less than 24 hours old (10.5); the RUNBOOK states both figures. Whether the proxy should instead refuse new flows (`Capacity`, no trip) rather than prune a segment younger than a minimum age is an availability-against-evidence choice that belongs to the owner (B18); it is not adopted here, because a same-user process can already rewrite the whole chain (section 16) and a floor would turn a loop into a proxy outage. There is no age-based pruning in M2: `ts_ms` is an untrusted wall clock and a forward clock jump must not be able to delete evidence (open question B4). Status shows the effective window (`oldest_ts_ms`, `pruned_entries`). Purging is an operator action (RUNBOOK: stop `sskd`, move the directory aside); the chain then restarts at `genesis`. `segment_mib x retain_segments` must be at most 1024 (5.3) because open verifies everything retained.

**Open and recovery** (`open_dir`, blocking, inside `spawn_blocking`, never on a runtime worker):

1. Open and verify the store (6.4.9); any refusal is `AuditOpenError::UnsafeStore(code)` and the ingress is `unavailable` with no port bound.
2. List entries with `Dir::read_from(dir_fd)`; only names matching `seg-` + 20 digits + `.jsonl` count; a directory or symlink with such a name is refused; other names are ignored and counted for the doctor.
3. Open each segment dirfd-relative with `O_NOFOLLOW` and verify it (6.4.9). Read at most the `fstat` length captured at open.
4. Verify the chain across segments: gapless `seq`, hashes, `Continue` linkage (`prev_seq` and `prev_segment_head` equal the last record of the previous segment); the oldest retained segment starts at `genesis` or with an anchoring `Continue`; a gap, an overlap or a missing middle segment is `Corrupt{segment, line}`.
5. A missing final 0x0A on the active segment is a torn append that was never acknowledged (replies follow the fsync): truncate with `set_len`, `sync_all`, and write `Recovered` first.
6. Compute `Unresolved` while scanning (a set of flow ids bounded by the unresolved count).
7. Refuse a ledger whose `Started.ledger_format` is newer than this build (`UnsupportedFormat`).
8. Append `Started` (config fingerprint, destination logging mode, key id, unresolved).
9. The host runs 1 to 8 in a background task so IPC is connectable at once; status reads `starting` (phase `verifying_ledger`). The cost is bounded: typed verification measured here at 92 MiB/s (release build, one core; about 11 s for the 1 GiB ceiling, 2.8 s for the default 256 MiB; debug builds are roughly an order of magnitude slower; a 250,000-record, 66.1 MiB run took 0.72 s).

**`verify_dir(dir, mode)`.** `Open` is the strict mode of step 4. `Reader` is for concurrent readers (doctor, `GetIngressAudit`): it tolerates a partial last line of the active segment, reads each file only up to the length it had when opened, and treats `ENOENT` on a listed segment as a concurrent prune, the listing being stale: it re-lists and restarts (at most 3 times) anchored at the new oldest segment's `Continue`; if the vanished segment was not the oldest the new listing lacks it and the chain proves the hole as `Corrupt`; after the retries a vanished segment is `Inconclusive` (L10). In `Open` mode a vanished segment is `Corrupt{MissingSegment}`. It never takes the writer's lock and never runs under the supervisor mutex (6.4.11).

**Configuration fingerprint.** `ConfigFingerprint{version: 1, config, routing, ingress}` is computed once per boot by the pure function `ssk_config::fingerprint::of(&AppConfig)` (`ssk_types::digest_of(.., HashAlg::Blake3)` over explicit view structs defined in that module, so a field added to `ssk-config` does not silently change every digest; the view carries `version = 1`). It lives in `ssk-config` because `ssk config lint` prints it and `ssk-cli` does not depend on `ssk-daemon` (`crates/ssk-cli/Cargo.toml`). The view contains: `default_profile`; adapters sorted by id with kind, host, port or profile id; profiles sorted by id with rules sorted by `(priority, id)` and every rule field (`id, priority, destination, domain_suffix, port, action, require_attestation`); the profile display `name` is excluded. `ingress` is the digest of the validated ingress section including `destination_logging`. `Started` carries all three digests. `Armed` carries `profile_digest` (that profile's view plus the adapters its rules reference) and a `RuleTable` of at most 256 rows (id, priority, action as `direct | deny | adapter:<id>`, attestation flag, whether an exact destination or suffix exists, port; never the destination text) so that `matched_rule: rule-3` is interpretable as "rule-3 meant deny" without the old configuration file and verifiable against an archived file by recomputing the digest. This is sound because configuration cannot change inside a boot: `main.rs::serve` (`:244-247`) loads it once, `Supervisor::new` consumes it, and the daemon has no reload or SIGHUP path (grep of `crates/ssk-daemon/src` finds none); every edit therefore needs a restart, which writes a new `Started`, and every `flow_id` names its Started.

**Refinements made at `C-A7`** (segments, rotation, retention, the refusal quota, `open_dir` and `verify_dir`; the writer's rotation, hard cap and summary folding). (1) Four modules: `segments.rs` (pure state: `SegmentBook`, `Quota`, `merge_summary`), `verify.rs` (`verify_dir`, `CorruptKind`, `Tail`, `ClassBytes`), `store_io.rs` (`StoreIo`, the writer's disk over a `LedgerStore`, with the R2 to R6 order and the D6 prune) and `open.rs` (`open_dir`, `recover`). `FlowAuditWriter::open_with` stays crate-private; `open_dir` takes the `LockProof` and a `&dyn LedgerFs`. (2) A rotation creates the next segment, so retention counts it: before the rotation the newest `retain - 1` segments are kept, and `Continue.pruned_before_seq` is the first sequence number that survives (the new segment's own number when `retain` is 1). (3) Prune stops at the FIRST segment that cannot be unlinked, where D6 said "per file": unlinking a newer segment while an older one stays would leave a hole in the retained chain that no verifier can tell from damage. The stuck segment and every newer victim stay in the book, are counted (`prune_deferred` of the next `Continue`) and are victims again at the next rotation, being the oldest; once the count has reached twice the retention the writer also retries them at the start of every batch, so that the first success lifts the `Capacity` refusal without waiting for a rotation. (4) The writer folds all `Summary` jobs of a batch into one (counters add, repeated keys add by key, the sixteen most repeated are kept and the rest counted in `other_keys`), so a batch carries at most one and the share test has no batch term. The candidate is what was held, what arrived and the refusals counted for want of quota; written, it empties all three; held (over its share before the floor), it becomes the held aggregate and the refusal counts move into it. The first summary, and one every `summary_floor`, is written whatever its share. (5) `verify_dir(Reader)` starts over when ANY listed segment has vanished, not only the oldest: a stale listing cannot be told from a pruned one except by listing again, and if the vanished segment was in the middle the new listing lacks it and the chain proves the hole; after three restarts the answer is `Inconclusive`. In `Open` mode a vanished segment is `MissingSegment`. An opened segment with no links left is reported as not found (a prune that won the race), not as hard-linked. (6) Recovery: a newest segment with no complete line is unlinked, and the directory made durable, when it has a predecessor; alone it must be named 1 (cut to nothing and `sync_all`, a fresh chain), anything else is `Corrupt{AnchorMissing}`; a torn tail is cut with `set_len` and `sync_all` before anything is appended; `Replayed.new_segment` makes `open_with` call `make_durable` (D2) after `Started` and before the first receipt can exist. (7) The per-class byte counters of the quota are recomputed from the newest segment at open, so a restart does not hand the refusals a new budget (a test). (8) The mutation pass found code that no input could reach and it was removed rather than tested: a second linkage check in `verify_dir` that the resumed chain already implies, the tie-break of the summary sort (the keys arrive in key order and the sort is stable), a `len > MAX` guard in front of an arithmetic that is zero without it, and `rotate`'s own look at the sequence number (the caller passes the number it already holds).

#### 6.4.9 Ledger storage security (modes, ownership, no-follow, shared or planted state directories, Windows)

What exists today (verified): `main.rs:67` creates the state directory with `std::fs::create_dir_all` (umask default: mode 0755 under umask 022 but 0775 under umask 002, which Debian and Ubuntu use for a user with a private group; the mode arithmetic was run for this revision, whether the owner's machine uses 002 is UNVERIFIED); `lock.rs:313-324` opens `sskd.lock` with `create(true)` and no mode (umask default); `audit.json` is 0600 only because `tempfile` creates files 0600 (`tempfile-3.27.0/src/file/imp/unix.rs:23`); the rolling log files are opened with `append(true).create(true)` and no mode (`tracing-appender-0.2.5/src/rolling.rs:788-791`) and follow symlinks; `ssk-diag::write_crash_record` uses `File::create` (`lib.rs:299-313`). `SSK_STATE_DIR` is honoured as given (`ssk-ipc/src/paths.rs:67-72`) and may point into a shared directory. The new ledger holds a destination log and must not inherit any of that.

**Unix (the code path that is verified here).** All operations are dirfd-relative and use `rustix` 0.38 (`openat, mkdirat, fstat, fsync, unlinkat, Dir::read_from`, `OFlags::NOFOLLOW`; features `fs`, `std`, plus `process` for `geteuid`). The API surface was compiled here against rustix 0.38.44; a symlink opened with `NOFOLLOW|DIRECTORY` fails with `ENOTDIR`.

1. State root: `canonicalize` the configured root once (a symlinked state root that the user set up on purpose keeps working), open the result with `O_DIRECTORY|O_NOFOLLOW`, `fstat`: owner `== geteuid()` and no group or other write bit (`mode & 0o022 == 0`); otherwise `INGRESS_AUDIT_ROOT_UNSAFE`. A root in a world-writable directory such as a bare `/tmp` fails here. The daemon creates a MISSING root itself with mode 0700 (`DirBuilder::new().recursive(true).mode(0o700)` in `paths::ensure_state_root`, which `main.rs` calls in place of `create_dir_all`; `C-A5`) and never touches an existing one, so a fresh install passes under any umask. An EXISTING root with a group or other write bit (the expected case: a directory that an earlier `sskd` created under umask 002, mode 0775) is refused, never repaired, and the error text says what to do: `chmod go-w <path>`, an act of the operator (RUNBOOK). Tests: `daemon_creates_a_missing_state_root_private_under_umask_002` (real `sskd` started through `sh -c 'umask 002; exec ...'`), `existing_group_writable_state_root_is_refused_with_the_chmod_hint`.
2. Ledger directory: `mkdirat(root_fd, name, 0o700)`; `EEXIST` is fine; then `openat(O_DIRECTORY|O_NOFOLLOW)` and `fstat`: a directory, owner `== geteuid()`, `mode & 0o077 == 0`; otherwise `INGRESS_AUDIT_DIR_UNSAFE`. An existing directory is never chmod-repaired, because an attacker-owned directory cannot be repaired and a repaired-looking directory is worse than a refusal (the same stance as `ssk-winhost/src/state_dir.rs`). After this step the directory is addressed only through its fd, so a later path swap cannot redirect a write.
3. Segments and the key file: opened or created with `O_NOFOLLOW|O_CLOEXEC`, new ones with `O_CREAT|O_EXCL`, mode 0600; `fstat` must show a regular file, owner `== geteuid()`, `mode & 0o077 == 0`, `st_nlink == 1` (a planted hard link is refused); otherwise `INGRESS_AUDIT_FILE_UNSAFE`.
4. `geteuid`, not `getuid`, for **file ownership**: files this process creates are owned by its effective uid. The **peer check** deliberately uses `getuid()` like `ssk-ipc/src/auth.rs:74` (6.6); the two agree for a non-setuid `sskd`, and the peer check is disabled when they differ, so there is no state in which the two conventions disagree silently (MD-14).
5. File systems that do not enforce Unix modes (FAT, some network mounts) report permissive bits and are refused: fail closed.

**Windows (not executable here: every sentence is UNVERIFIED until a Windows run).** Default location `%LOCALAPPDATA%\Kaleidoscorp\state` (`ssk-ipc/src/paths.rs:74-81`), whose ACL is inherited from the user profile; an `SSK_STATE_DIR` override can point anywhere. Commit `C-WIN3` adds `ssk-winhost` code (the daemon stays `forbid(unsafe_code)`): (a) a pure function `private_dir_policy(&PathSecurity, current_user_sid) -> Result<(), PrivateDirRefusal>` over the existing injectable `PathSecurityProbe` / `PathSecurity` (`ssk-winhost/src/service.rs:357-399`), so it is testable on Linux with a fake probe: not a reparse point, owner SID is the current user or BUILTIN\Administrators, DACL not NULL, no allow ACE for any principal other than the current user, SYSTEM and Administrators carrying read, write, delete, WRITE_DAC or WRITE_OWNER; (b) creation by non-recursive `create_dir` with a re-probe afterwards and no DACL rewrite (the unelevated daemon cannot repair, and repair-after-squat is refused by `state_dir.rs` for the same reason); (c) the active segment opened with `share_mode(FILE_SHARE_READ)` (as `lock.rs:299-311`) and `FILE_FLAG_OPEN_REPARSE_POINT` followed by a refusal of reparse points (as `vpn_profiles.rs:262-269`) and a link-count check (`single_link`, `vpn_profiles.rs:280-293`, currently `pub(crate)`); (d) readers open with `FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE` (as `lock.rs:277-292`); the Rust standard library documents the default share mode as all three, so a std `File::open` reader does not block a prune; an anti-virus or indexer handle that lacks `FILE_SHARE_DELETE` can still make an unlink fail, which is why prune is non-fatal (D6); (e) directory fsync: `sync_dir` is a best-effort no-op on Windows and status says `dir_sync: unavailable`; whether `FlushFileBuffers` on a directory handle is permitted for an unprivileged process is unverified.

`Controls` has three fields: `exclusive_bind`, `peer_check`, `private_audit_store` (6.6). `private_audit_store` is true on Linux when the checks above pass and false on Windows until `C-WIN3` has been verified on a real machine, so under `hardening: required` the ingress stays `unavailable` on Windows (owner decision 1) with `INGRESS_HARDENING_UNAVAILABLE` naming the missing control. Under `best_effort` the ledger works with the inherited ACL from `C-WIN0` on (a std-only backend: path-based `std::fs`, the share modes of (c) and (d) through `OpenOptionsExt::share_mode`, no reparse-point, link-count or ACL claim, `sync_dir` a no-op), and status reports `private_audit_store: false` and the warning `AUDIT_STORE_NOT_PRIVATE` (10.5). Before `C-WIN0` `fs_win.rs` is a compiling stub that refuses to open, and the ingress is `unavailable` on Windows under either mode. `C-WIN3` upgrades the backend with (a) to (e) and is the only commit that may flip the control.

**What is not claimed.** The other files in the state directory keep their current modes (lock, logs, crash records) and are not part of this work; they must not contain destinations (rule 15). The doctor reports a state root that is group or world writable. Same-user hostile code, root, and a user who copies the ledger are out of scope. A power loss on a disk that acknowledges a flush it has not performed defeats every fsync scheme and is not detectable here.

**Refinements made at `C-A5`.** (1) The checks are three pure functions over a `Facts` value (`check_root`, `check_dir`, `check_file`), so the whole table of modes, owners and link counts is asserted without a file system, and the real directory tests only have to show that the facts are read from the right descriptor. (2) `StoreError` never carries a path or an OS message: it holds a closed `UnsafeReason` or a static code (`io_code` reduces an `io::Error` to a class: `AUDIT_DISK_FULL`, `AUDIT_PERMISSION_DENIED`, `AUDIT_NOT_FOUND`, `AUDIT_ALREADY_EXISTS`, `AUDIT_IO`), and the operator text is built by `operator_hint(root)` from the configured root. An existing name under `create_segment` is `AUDIT_ALREADY_EXISTS` (`EEXIST`, whatever the name holds), not a separate error type. (3) `open_store` fsyncs the ledger directory and the state root only when it created the directory (D1); `LedgerStore::sync_dir` is the later, explicit call for created and removed segments. (4) `segments()` lists with `statat(SYMLINK_NOFOLLOW)`: an entry that has a segment's name and is not a regular file is a refusal (`FileUnsafe(NotRegularFile)`), every other name is ignored and counted for the doctor. (5) `open_reader` reports the length seen at open and reads no further (`Read::take`), so an append that lands during a verification is not half-read. (6) A store is bound to the descriptor, not the path: `the_store_is_bound_to_the_directory_it_opened_not_to_the_path` renames the directory away and plants a symlink at the old path, and the next segment is created in the original directory. (7) `paths::ensure_state_root` creates the whole missing chain with mode 0700 (the parents too) and leaves an existing root, a symlink to a directory included, exactly as it is; the umask can only remove bits from 0700. `tests/state_root.rs` starts the real `sskd` through `sh -c 'umask 002; exec ...'`, with a control test that `sh` on the machine really produces a group-writable directory under that umask (otherwise the test could pass where the umask has no effect). The daemon-level form of the refusal (status `INGRESS_AUDIT_ROOT_UNSAFE`) needs the ingress wired and is a test of `C-F1`; until then the refusal is tested at the store, with the hint the operator is shown. (8) Not covered by a test, and why: the `O_NOFOLLOW` on the root open (the path was canonicalised an instruction earlier, so a symlink there needs a swap in between, which cannot be forced) and the `fsync` calls themselves (observable only as a syscall trace; the writer's order of D1 to D6 is asserted against a recording double in `C-A6`). (9) `LedgerIo` (rotate, prune, truncate) is declared here and implemented over a store in `C-A7`; `fs_win.rs` is the stub of 6.4.9 and its `is_private_store` is `false`.

#### 6.4.10 Destination logging: plain or hashed (owner decision 3)

Config field `ingress.audit.destination_logging: plain | hashed` (5.1), default `plain`, part of config v5. It applies to the destinations of **admitted** flows. **Denied** records always carry the plaintext destination.

| surface | plain | hashed |
|---|---|---|
| `Pending.dest` | `{mode: plain, host, port}` | `{mode: hashed, kid, kind, token, port}` |
| `Result.dialed` and each entry of `Result.attempted` (pinned Direct addresses) | `{mode: plain, ip, port}` | `{mode: hashed, kid, kind, token, port}` |
| `Denied.dest`, `Summary` repeated keys | plain | plain |
| tracing at INFO and above | no destination | no destination |
| tracing at DEBUG (`SSK_LOG`) | canonical host, escaped, truncated to 64 bytes | no destination, not even raw client text |
| live flow registry, `ListRecentFlows`, `InspectFlow`, GUI, CLI | host | `kid`, `kind`, `token`, port (`destination_form: hashed`) |
| `NetcoreError` Display (contains the host: `DnsResolutionFailed`, `ConnectionRefused` format the address, `ssk-netcore/src/error.rs:23-24`) | never logged above DEBUG; only `code()` is | never logged |
| crash records (`CrashRecord.payload` is deliberately not redacted) | ingress code never formats a destination into a panic path (`panic`, `expect`, `unwrap`, indexing are denied lints in the tree) | same |

Principle: no surface shows more than the ledger would. `hashed` never degrades to `plain`: if the key cannot be created, read or validated the ingress is `unavailable` (`INGRESS_AUDIT_KEY_UNAVAILABLE`). The mode is recorded in the ledger twice: `Started.destination_logging` (and `dest_key_id`) for the boot, and the self-describing `mode` and `kid` inside every `DestRef`, so a record cannot be misread without its Started record and a mode change is visible at the next `Started`. Records written before a switch stay as written (nothing is rewritten); to remove older plaintext purge the ledger (6.4.8 Retention). The live views follow the ledger in `hashed` mode (the safe default; whether they may show names is open question B5).

**What is hashed, with what, and why not a plain hash.** A plain hash of a host name is weak because the input space is small and public. Measured here: one core tests about 11.6 million candidate inputs per second with BLAKE3, so a list of one million names is exhausted in 0.09 s and the entire IPv4 literal space in about 6 minutes; a per-ledger public salt changes nothing (the attacker reads the salt from the ledger), and a per-record random salt would destroy equality and therefore the ability to verify. So the token is a keyed PRF output under a per-installation secret key that is not stored in the ledger.

```
key      32 random bytes (getrandom 0.3, already in Cargo.lock via ssk-diag; one new direct edge for ssk-daemon, no new crate),
         stored as 64 hex characters + 0x0A in <state_dir>/ingress-dest.key, mode 0600, created create_new, fsynced (D3)
kid      first 8 bytes of blake3::derive_key('ssk.ingress.dest.key-id.v1', key), lowercase hex (16 chars)
message  b'ssk.ingress.dest.v1' || 0x00 || kind (0x01 name, 0x04 ipv4 literal, 0x06 ipv6 literal) || len(host) as u16 big-endian || host (canonical ASCII form from target::canonicalize)
token    first 16 bytes of blake3::keyed_hash(key, message), lowercase hex (32 chars); the port is NOT part of the token and stays in clear
```

Golden vector (computed here with blake3 1.8.5; key bytes `00 01 02 ... 1f`): `kid = dcfd61fc2475cfd3`; token(name `example.com`) = `2c8a3534e4fd1ffbc2665f5baf190592`; token(name `example.org`) = `99c3288699f4a46072979169e9d3d4b4`; token(ipv4 `192.0.2.1`) = `3b632276b0bcd7c49c671eadc4a46815`; token(ipv6 `2001:db8::1`) = `c29802ba065c13d951ac2ca4d71fea53`. For contrast, the unkeyed `blake3(example.com)` truncated to 16 bytes is `74927756a0a08c17da48407c8adcedc9`, which anyone can compute. Any BLAKE3 implementation can reproduce a token from the key file, so verification does not depend on this program.

The key lives in the state root, not in `ingress-audit/`, so the ledger directory can be copied or attached to a bug report without the key. A leaked ledger without the key reveals counts, ports, timing, rules, routes and which flows share a destination, not names. Same-user code that can read both files can recover names with a dictionary; the key is in memory for the whole run and is not zeroized; on Windows no DPAPI wrapping is part of M2. `ssk ingress audit --find <host>` recomputes the token with the local key.

**What an auditor can still verify in hashed mode.**

| question | answer |
|---|---|
| is the chain intact, gapless, anchored | yes, unchanged |
| did flow F follow Pending, Result, Closed; under which rule, route, profile, config digest | yes |
| was a given host or IP contacted | yes, with the key: recompute the token and search; without the key no |
| do two flows share a destination | yes (equal tokens; this linkability is deliberate) |
| what are the names | not without key plus dictionary |
| across restarts | tokens compare only while `kid` is equal; deleting the key file is the operator's "forget" operation: the next hashed start creates a new key and a new `kid`, and older tokens become unverifiable |

Limit stated honestly: the matched rule id, the `RuleTable` and the route still say which rule fired; an exact-destination rule therefore identifies its destination to anyone who also has the configuration file. Hashing protects the log, not the policy. The RUNBOOK says to back the key up separately from the ledger if later verification matters.

**Refinements made at `C-A4`.** (1) The key file is read and created through two new methods of `LedgerFs` (`read_key_file`, `create_key_file`, both blocking), because it lives in the state root, not in the ledger directory, and has to meet the same checks as a segment: opened `O_NOFOLLOW`, a regular file of the effective user, `mode & 0o077 == 0`, one link. Both open with `O_NONBLOCK` so that a FIFO planted under the name is refused by the `fstat` and never waited for (the same flag is now on every segment open; a test for each). The read is cut at 66 bytes, so a longer file reaches the parser as a length it refuses. (2) `create_key_file` is D3: exclusive create, mode 0600, write, `sync_all`, `fsync` of the state root; a file that was created and could not be completed is removed again, so a half-written key does not survive to make the next start `Corrupt`. `O_NOFOLLOW` on the create is defence in depth: `O_CREAT|O_EXCL` already does not follow a symlink, so no test can tell it from the flag (an equivalent mutant, stated here instead of tested). (3) The form is strict: exactly 64 lower-case hex characters and one line feed; upper case, CRLF, a missing line feed, an all-zero key and anything of another length are `Corrupt`, never repaired, and the operator text says to remove the file, which forgets older tokens. A random source that fails or returns all zeros is `Random`, and nothing is created. (4) `load_or_create` has two rounds only: read, create, and if the create lost a race (`AUDIT_ALREADY_EXISTS`) read once more; a name that exists and still cannot be read is an error, not a loop. (5) `DestSealer` is the one place a destination becomes a `DestRef` or an `AddrRef`: `Plain` touches no file and asks for no randomness; `Hashed` carries the key; `denied()` is plain in both modes; `addr()` unmaps an IPv4-mapped address first, so the plain and the hashed form agree with the dial; a host over 255 bytes has no token and is an error, never recorded in clear instead. Results are sealed from `SocketAddr`s by the writer, so the engine cannot produce a plain address in hashed mode. (6) The token function was checked against a second implementation of BLAKE3 written from the specification (it reproduces the official keyed-hash vector for the empty input and every vector of this section); the vectors in the tests, including a 253-character name, an IPv4-mapped address and a name that looks like an IP address under the `name` kind, come from it and not from the crate under test. (7) `getrandom` 0.3 moved from the Windows-only dependencies of `ssk-daemon` to the common ones (same crate and major as `ssk-diag`; `Cargo.lock` does not change). (8) Debug output of a key or a sealer is exactly the key id (`DestKey { kid: .., .. }`), asserted as a whole string so that nothing can be added to it.

#### 6.4.11 Reading the ledger, log-injection rules, observations and the status block

**What each record proves (this goes into the RUNBOOK).**

* `Pending` followed by `Result{Connected|Failed|Aborted}`: the proxy authorised the destination under the named rule and a dial was started. `Result.attempted` lists the addresses a Direct-by-name dial tried (at most 8) and `dialed` the winner; after an `Aborted` result the list is unknown. `Pending` followed by `Result{NotDialed}`: no dial was started (type-state). A `Pending` with no `Result` before the next `Started` or `Recovered` record belongs to a dead process or a failed writer: the dial may have happened (an upper bound, never an under-report).
* `Result{Connected}` followed by `Closed`: a tunnel existed; the byte counts are counted by the proxy on its two sockets, not confirmed by the destination.
* `Denied`: refused, nothing dialled. `Summary` and `Continue.refusals_unrecorded` reconcile refusals that were not individually written.
* The ledger says what Kaleidoscorp decided and did. It never asserts a property of the network path (tunnelled, protected, a VPN being up). Facts observed about the host (for example which interface the operating system selects for a documentation probe address) may appear only as `observations`, each `{kind, value}` with a `kind` from the closed list of 10.5 and a value that is printable ASCII (0x20 to 0x7e) of at most 64 characters; anything else is stored as the text `(invalid)` (rule R-O). Absence of a record proves nothing about applications that do not use the proxy.
* `ts_ms` is an untrusted wall clock; `seq` is authoritative. Integrity is prefix integrity only: deleting the directory or the newest segments, or truncating at a record boundary, verifies. Status publishes `(entries, head)` so an operator can keep an out-of-band checkpoint.

**Log-injection rules (attacker-controlled host names).**

* R-L1 Only validated, canonical values reach a record or a log line: hosts passed `target::canonicalize` and `ssk_config::routing::valid_host` (`routing.rs:102-119`), so the character set is `[a-z0-9.-]` for names and `[0-9a-f:.]` for literals; ids pass `valid_id` (`[a-z0-9._-]`, at most 64); everything else in a record is a closed-set constant or a formatted number. Raw client text and rejected targets are never recorded (they are counted).
* R-L2 Bodies are compact `serde_json::to_vec` output, which cannot contain a raw 0x0A (proven in 6.4.2); the line parser splits on 0x0A only, requires byte 64 to be a space and caps the line length. A forged second record cannot be smuggled inside a string.
* R-L3 Tracing: fields use validated values; the only raw client text is DEBUG-level, `escape_debug()`-ed and truncated to 64 bytes and never in hashed mode (the repo's existing pattern is `profile_id = %req.profile_id.escape_debug()` at `supervisor.rs:650`).
* R-L4 `NetcoreError` Display is never logged above DEBUG and never in hashed mode; ingress code converts errors with one function `error_code(&NetcoreError) -> &'static str` (the crate's own convention: `InvalidTarget` documents that its message never echoes the target "because it could carry line breaks into logs", `error.rs:41-45`).
* R-L5 Every consumer that prints text from a ledger it has not verified (CLI `ssk ingress audit`, GUI) escapes control characters, U+2028, U+2029 and bidirectional controls before display.
* R-L6 A source-scan test bans `%err`, `?err`, `{err}` formatting of a `NetcoreError` inside `src/ingress/{engine,flow,host}.rs` and any `tracing` call whose fields name `host`, `dest` or `target` outside the DEBUG, plain-mode helper.
* R-O Observation values are produced by the coexistence code (6.12) but validated by the audit layer (`Observation::new`).

**Status block.** `IngressStatusDto.audit` (replaces draft 1's `IngressAuditDto{entries, head, segments, state}`):

```rust
pub struct IngressAuditDto {
    pub state: String,              // ok | starting | stalled | tripped | corrupt | unavailable | closing
    pub entries: u64, pub head: Option<String>, pub segments: u32, pub bytes: u64,
    pub oldest_ts_ms: Option<u64>,  // untrusted wall clock of the oldest retained record
    pub pruned_entries: u64, pub prune_deferred: u32,
    pub destination_logging: String, pub dest_key_id: Option<String>,
    pub refusal_quota_used_percent: u8, pub denials_over_quota: u64,
    pub busy: u64, pub timeouts: u64, pub sync_last_ms: u64, pub sync_max_ms: u64,
    pub dir_sync: String,           // fsync | unavailable
}
```

No field carries the key, a path or a destination; whether the store is private is `controls.private_audit_store` (10.4). `IngressShared::snapshot()` reads these from the writer's atomics (no file I/O, no tokio lock). `IngressShared::verify_audit()` is async, runs `verify_dir(Reader)` in `spawn_blocking` with a 30 s budget (`audit_read_verify_deadline`) and never touches the supervisor's `Inner` mutex, because `RunDoctor` currently holds that mutex for the whole handler (`supervisor.rs:959-960`); after the change the doctor handler needs no `Inner` (12.7).

### 6.5 `ingress/limits.rs` (deterministic: explicit `Instant` arguments)

```rust
pub struct RateLimiter { /* token bucket: capacity max_connections, refill accept_rate_per_s (5.1) */ }   impl RateLimiter { pub fn try_take(&mut self, now: Instant) -> bool }
pub struct PeerBudget { /* the pre-admission budget: bucket 256 burst / 1024 per s, and 64 slots shared by the peer check and the handshake (6.1.4, 7.1) */ }
impl PeerBudget  {
    pub fn try_start(&mut self, now: Instant) -> Option<PreAdmissionSlot>;    // all slots taken: cancels the oldest slot whose request is still incomplete and that is at least `handshake_evict_after` old, and takes its place; None when there is none
}
pub struct PreAdmissionSlot { /* RAII; `cancelled()` future for the owner; `request_complete()` ends its eviction eligibility; dropping it frees the slot */ }
pub struct DenialCoalescer { /* key=(profile,host,port,reason,rule); 60 s window; <=128 live keys; bucket 1/s burst 20 for first occurrences */ }
impl DenialCoalescer {
    pub fn classify(&mut self, key: DenialKey, now: Instant) -> Disposition;     // FirstDurable | Repeat | Suppressed
    pub fn take_summary(&mut self, now: Instant) -> Option<SummaryEvent>;
}
pub struct FailureCooloff { /* 5 consecutive failures per planned chain within 30 s => refuse that chain for 10 s */ }   // commit C-E4 (OPT)
```

The explicit-`Instant` limiters take `now` as an argument and never subtract two `Instant`s with `-` (12.12). The pure fd-budget function lives in `budget.rs` (7.3), not here.

**Refinements made at `C-G5`.** (1) One integer token bucket (billionths of a token, refilled `per_second` units per nanosecond) serves all three limiters: no floating point, no division, and no fraction lost however often it is called (a naive bucket that sets `last = now` on every call and rounds elapsed time to milliseconds never refills a caller that polls faster than a token's period; `a_fast_caller_still_gets_its_refill` pins it). (2) `PeerBudget::try_start` charges the bucket before it looks at the slots, so an attempt that is refused still paid (`a_refused_newcomer_still_paid_the_bucket`); an evicted slot is replaced in the table at once, so dropping the evicted owner's slot later frees nothing it no longer owns, and the owner learns of the eviction through `cancelled()` (a `Notify` permit, so a cancel that lands before anyone waits is not lost). `evicted_total()` is the `evicted_handshake` counter. (3) `DenialCoalescer`: the window of a key is fixed from its first occurrence (a steady repeater cannot keep it open, so every key produces a durable record at least once a minute); a new key is `Suppressed` when the 1-per-second bucket is empty or 128 keys are live, and a suppressed key is not tracked. The totals `suppressed[reason]` count EVERY occurrence that was not individually written (repeats and suppressed firsts), so `firsts + sum(suppressed) == occurrences` holds exactly (`summary_reconciles_exactly`, and a property over arbitrary schedules); the per-key detail (`repeated`, the 16 most repeated keys, and `other_keys`, the repeated keys beyond them) is best effort and bounded by the same 128, with the keys that no longer fit counted in `other_keys`. (4) `take_summary` returns a `DenialSummary` (window, totals, detail), not a `SummaryEvent`: the record type belongs to `C-A2`, and the writer adds what only it knows (refusals over its byte quota, the pre-admission rejects) when it builds the `Summary`. `FailureCooloff` stays with `C-E4`.

### 6.6 `ingress/peer.rs`

```rust
pub enum PeerVerdict { SameUser, DifferentUser, Unknown }
pub struct PeerQuery { pub client: SocketAddr, pub listener: SocketAddr }
pub trait PeerAuthorizer: Send + Sync {
    // Async on purpose: it must never block a runtime worker AND never occupy a tokio blocking-pool slot.
    fn authorize<'a>(&'a self, q: PeerQuery) -> ssk_netcore::BoxFuture<'a, PeerVerdict>;
}
pub struct Controls { pub exclusive_bind: bool, pub peer_check: bool, pub private_audit_store: bool }
pub trait IngressPlatform: Send + Sync {
    fn controls(&self) -> Controls;                       // does real self-tests (below and 6.4.9)
    fn bind(&self, addr: SocketAddrV4) -> io::Result<tokio::net::TcpListener>;
    fn bind_retry(&self) -> BindRetryPolicy;              // 6.9.4: a fixed schedule (Unix) or a doubling window (Windows, UNVERIFIED)
    fn peer_authorizer(&self) -> Option<Arc<dyn PeerAuthorizer>>;
}
pub fn default_platform() -> Arc<dyn IngressPlatform>;   // cfg(linux) / cfg(unix, not linux) / cfg(windows)
```

**Linux identity convention (resolves the getuid/geteuid contradiction).** The repo's IPC check compares the peer's uid with `rustix::process::getuid()` (`ssk-ipc/src/auth.rs:74`). The ingress peer check uses the SAME convention, `getuid()`, so the daemon has one meaning of "same user" for sockets. Probe evidence (this kernel, root, Python, uids set per process): the uid column of `/proc/net/tcp` for a client socket is the creator's EFFECTIVE uid (ruid 0 / euid 65534 -> column 65534; ruid 65534 / euid 0 -> column 0). `SO_PEERCRED` is likewise the peer's effective uid. The two conventions therefore only differ when the daemon itself runs with `getuid() != geteuid()` (setuid launch), which no supported deployment does. Rule: `peer_check` is available only if `getuid() == geteuid()`; otherwise `controls().peer_check = false` with reason `IDENTITY_AMBIGUOUS` (so `hardening: required` makes the ingress unavailable). The ledger-ownership check of 6.4.9 uses `geteuid()` for a different reason (files this process creates are owned by its effective uid). `rustix` feature `process` is added to `ssk-daemon` for unix (`rustix 0.38.44 process/id.rs:54 getuid, :68 geteuid`; the daemon currently enables `fs`, `std` only, `ssk-daemon/Cargo.toml:69`).

**Linux client-row lookup.** The row that identifies the CLIENT is the one with `local == client addr:port` and `rem == listener addr:port`. The accepted (server-side) socket has the mirror row (`local == listener`); it is owned by this daemon and is never used. Fields (verified on this kernel): `sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`, so `st` = field 3, `uid` = field 7, `inode` = field 9. IPv4 addresses are `%08X` of the host-order word of the network-order bytes (`0100007F` = 127.0.0.1), ports are big-endian hex. Decode with `u32::from_str_radix(.., 16)` then `to_ne_bytes()` (correct on both endiannesses; verified for IPv4, golden line `0100007F:8E1D`).

* **States.** Accept the client row only in `01 ESTABLISHED`, `04 FIN_WAIT1`, `05 FIN_WAIT2`. Observed here: the client row is `01` while open, `05` after the client `shutdown(SHUT_WR)`; `08 CLOSE_WAIT` appeared ONLY on the accepted socket's row, never on the client's (draft 1's `08` is dropped: it could only ever be matched by accident on the wrong row). A client that closed completely leaves an orphan row (observed: state `05`, inode `0`); `inode == 0` -> `Unknown` -> refuse (an orphan's uid column is not an owner). Half-closed clients (request written, write side shut down) are authorised.
* **Both tables.** Read `/proc/net/tcp` and, when it exists, `/proc/net/tcp6`; a missing `tcp6` (ENOENT, IPv6 disabled; this sandbox has none) is an empty table, not an error. A dual-stack client (an `AF_INET6` socket connecting to 127.0.0.1) is expected in `tcp6` with the IPv4-mapped form (`0000000000000000FFFF00000100007F`, derived from the kernel's formatting rule, NOT observed here because this machine has no IPv6). Matching normalises every address: IPv4-mapped IPv6 is unmapped to IPv4 before comparison.
* **Exactly one row.** Zero matches = miss; two or more DISTINCT `(state, uid, inode)` matches = `Unknown` (ambiguous); identical duplicates (seq_file may repeat a row under churn) are collapsed. A miss triggers exactly ONE re-read (5 ms later, shared with every other missed request of the batch) before `Unknown`; `/proc/net/tcp` is not an atomic snapshot (seq_file reads across multiple `read()` calls), so a skipped row is possible but not reproduced here.
* **Verdict.** valid row and `uid == getuid()` -> `SameUser`; valid row with another uid -> `DifferentUser`; everything else -> `Unknown`. `Unknown` always means refuse (rule 6).
* No PID is derived and `/proc/<pid>/fd` is never scanned, so there is no PID/inode-reuse race on Linux; the only race is row lifetime, and it fails closed. The 4-tuple of an established connection cannot be taken over while this daemon's accepted socket holds it.

**Refinements made at `C-G7a`** (the pure half of `peer.rs`: `parse_proc_net_tcp`, `parse_proc_net_tcp6`, `parse_tables`, `decide_row`). (1) A row of the client's connection in a state other than 01, 04 or 05 (TIME_WAIT, CLOSE_WAIT, ...) is `Unknown` at once, not a miss: it exists and is not a connected client; a TIME_WAIT row of an earlier incarnation next to the live row is ignored. A miss is only "no row at all". (2) The header line is checked (`sl`, `local_address`, `rem_address`, `st`, `uid`, `inode` in that order) and an unknown layout is an error, because the data lines are read by position; a data line that does not have the shape counts in `Table.malformed` and never becomes a row (hex fields are exactly 2, 4 or 8 digits with no sign: Rust's integer `parse` accepts a leading `+`, so the decimal fields are checked digit by digit as well). The self-test of `C-G7b` treats `malformed != 0` as a failed table. (3) The filter on the remote field is applied to the text before parsing (the 16 ms of a 12,000-row table are mostly parsing), for the IPv4 table and for the mapped form in `tcp6`; an unreadable present `tcp6` is an error, a missing one is an empty table. (4) A real loopback connection made by the test is found in the real `/proc/net/tcp` of the machine with this process's uid, which is what pins the endianness decoding (`to_ne_bytes`) to the kernel and not to my reading of it; the tcp6 mapped form is still derived, not observed (this machine has no IPv6). (5) `Controls` is defined in `types.rs` (`C-G1`); `peer.rs` adds `MissingControl` with the reason codes of 6.6.

**Cost bound (replaces "spawn_blocking under a 500 ms timeout").** Measured here: reading a 12,029-row `/proc/net/tcp` (1.8 MB) costs about 16 ms (three runs 15.1 to 16.8 ms); 256 checks/s each reading it would need about four cores, and per-check `spawn_blocking` calls would occupy blocking-pool threads. Instead:

* One `PeerTableService`: a dedicated `std::thread` (NOT a blocking-pool slot) fed by a bounded `std::sync::mpsc::sync_channel(256)`. `authorize` does `try_send` (full -> `Unknown`) and awaits a `oneshot` under `timeout(peer_timeout = 500 ms)` (timeout -> `Unknown`).
* The thread takes the first request, then every request already queued (up to 256), and serves the whole batch from ONE snapshot. Every request was enqueued after its connection was accepted, so a snapshot started afterwards already contains that connection's row: there is no TTL cache and no staleness window.
* Duty cycle: the next snapshot may start no earlier than `max(20 ms, 2 x duration of the previous snapshot)` after the previous start, so the service uses at most one third of one core however fast connections arrive. For the 12k-row table that is a snapshot at most every 32 ms.
* The read is capped at 16 MiB per table; larger -> `Unknown`. Only lines whose `rem` field equals the listener endpoint (computed once) are fully parsed.
* `PeerBudget` has 64 pre-admission slots (waiting on the service costs one `oneshot` and the accepted socket, not a thread; the descriptors are in the budget of 7.3; the same slots also cover the handshake, 7.1); the cheap token bucket is 256 burst, 1024 per second. The service is generic over `trait TableSource: Send + 'static { fn read(&mut self) -> io::Result<RawTables> }` so Windows can reuse the batching (`C-WIN2` supplies a `GetExtendedTcpTable` source) and tests inject a counting fake.
* Optional later (`C-G7c`, OPT): replace the source with a netlink `SOCK_DIAG` exact-tuple lookup. Probe (Python, this kernel): an exact lookup of the client socket returned `state/uid/inode` in 30 to 400 microseconds, including for a half-closed client (state 5, inode non-zero) and ENOENT (-2) for a missing tuple, i.e. O(1) with no table parse. It is not the default because the Rust path (hand-built netlink messages through `rustix::net`) cannot be compiled or tested here and a missing `CONFIG_INET_DIAG` or a seccomp filter would need a fallback anyway.

**Self-test.** `controls()` on Linux binds a temporary `127.0.0.1:0` listener, connects a std client to it, accepts, runs the real lookup on the client's address, and requires state `01`, `inode != 0` and `uid == getuid()`; any failure -> `peer_check = false` with reason `PEER_SELFTEST_FAILED`. This proves that `/proc/net/tcp` is readable, parseable and carries owners in THIS environment (hidepid-like mounts, containers, sandboxes), not merely that the file exists. Reasons are listed in `INGRESS_HARDENING_UNAVAILABLE`.

**Platforms.**

* **Linux:** `controls = { exclusive_bind: true, peer_check: <identity unambiguous and self-test passed>, private_audit_store: <6.4.9 checks passed> }`. A live listener cannot be double-bound: a test to run (`second_bind_to_live_listener_fails_on_linux`); the bind semantics were also measured in the sandbox (section 26: a second bind to a live listener fails `EADDRINUSE` with and without `SO_REUSEADDR`; mio sets `SO_REUSEADDR` on Unix listeners, `mio-1.2.2/src/net/tcp/listener.rs:82`).
* **Other unix:** `{ exclusive_bind: true, peer_check: false, private_audit_store: <checks> }`.
* **Windows:** `{ false, false, false }` from `C-WIN0` (plain non-exclusive bind through tokio, `peer_authorizer() = None`, the std-only ledger backend of 6.4.9) until `C-WIN1`/`C-WIN2`/`C-WIN3` flip the controls one by one, then `{ true, true, true }`. Before `C-WIN0` the Windows platform is a compiling stub (`bind` and the ledger refuse), so the ingress is `unavailable` there under either mode. `C-WIN2`'s `GetExtendedTcpTable` source is IPv4-only in the existing table code (`connections.rs:21`); whether a dual-stack client that connects to 127.0.0.1 appears in the IPv4 table, how PID reuse between the table read and `OpenProcessToken` behaves, and the cost of the call are all UNVERIFIED. Unresolvable -> `Unknown` -> refuse.
* `hardening: required` (default) and a platform lacking any of the three controls => ingress `unavailable`, `INGRESS_HARDENING_UNAVAILABLE`, listing the missing controls and the reasons above; nothing binds. `best_effort` runs with whatever exists; status reports exactly which controls are active (10.4) and every `Pending`/`Denied` record carries `peer_verified`. The weaker mode is a visible operator choice, never a silent default.
* Trust boundary stated plainly: the same OS user (the repo's existing decision for IPC). Same-user hostile code is out of scope. A different local user costs the cheap peer budget and at most one shared snapshot per 20 ms; it cannot drain the accept bucket, permits, ledger or daemon state.

**Different-user test.** The claim of draft 1 that this "cannot be exercised as root in CI" is too strong. When the test process runs as uid 0 it can spawn a helper with `std::os::unix::process::CommandExt::uid(65534)` (safe API) that connects to the listener; the authorizer must answer `DifferentUser`. The test self-skips with a printed reason when not root or when the helper cannot be executed by that uid. `scripts/manual_ingress_peer_test.sh` stays as the documented manual check. (`rustix::thread::set_thread_res_uid` would avoid the helper binary but needs `Uid::from_raw`, which is `unsafe` in rustix 0.38 and therefore unusable under `unsafe_code = forbid`.)

### 6.7 `ingress/engine.rs` (protocol-agnostic; no socket in its signatures)

```rust
pub struct EngineCtx { routing: Arc<ConfiguredRouting>, data_plane: Arc<dyn DataPlane>, audit: Arc<LedgerSlot>, shared: Arc<IngressShared>,
                       denials: Mutex<DenialCoalescer>, cooloff: Mutex<FailureCooloff>, limits: ResolvedLimits, families: DirectAddressFamilies,
                       listener: SocketAddr, seq: AtomicU64, tuning: Tuning }   // no `boot` field: the flow-id prefix comes from the installed writer (LedgerSlot, 6.9)
pub struct Admitted { pub token: AdmissionToken, pub route: RouteKind, pub rule: Option<String>, pub adapters: Vec<String>, pub flow: FlowRecord, pub epoch: u64 }
impl Admitted { pub fn pending_input(&self, peer: &PeerStamp, profile: &str) -> audit::PendingInput<'_>; }   // the only bridge from the engine to the audit module (6.4.7)
pub struct Denied   { pub reason: &'static str, pub class: DenyClass /* Policy | Route | Guard */, pub rule: Option<String>, pub route: Option<String> }
pub fn decide(ctx: &EngineCtx, profile: &str, flow_id: String, t: &Target) -> Result<Admitted, Denied>;     // pure: no audit, no socket, no token consumption beyond a dropped AdmissionToken
pub enum DialFault { Audit(AuditError), Dial(NetcoreError), Cancelled, Deadline, ReceiptMismatch }
pub async fn open_tunnel(ctx: &EngineCtx, adm: Admitted, gate: &mut watch::Receiver<Gate>) -> Result<Established, DialFault>;
async fn dial(ctx: &EngineCtx, token: AdmissionToken, _p: &PendingReceipt, gate: &mut watch::Receiver<Gate>, epoch: u64) -> Result<EgressSession, DialFault>;
pub struct Established { pub session: EgressSession, pub result: ResultReceipt, pub chain_kinds: Vec<String> }
```

#### 6.7.1 Decide order, special-use binding and route guard

`ConfiguredRouting` gains three pure functions and the types they return, all defined in `crates/ssk-daemon/src/routing.rs` by `C-S1` (nothing there depends on `ingress/`), computed from the validated config once and read-only afterwards:

* `decide(&self, profile, flow) -> Result<Decided, DecideError>` = `evaluate` + `plan`. It is the shared policy-and-plan core of the live path and `TraceRoute`. The claim "preview and live cannot diverge" is withdrawn: what is true is that both call one pure function and differ in their inputs (profile, flow context, live-only guards), and the preview reports which inputs it used (11.7). What IS guaranteed: `TraceRoute` runs the same `target::canonicalize` and the same pure guards (`guard_special_use`, route guard) when it evaluates as the ingress would, and reports a refusal as `RouteKind::Denied { reason: <CODE> }`; it does not run `guard_self_loop` (needs the bound listener) or the resolver. The live path may refuse more; the preview must never refuse something the live path would allow.
* `rule_binding(&self, profile, rule_id) -> RuleBinding` (replaces draft 1's `rule_destination -> Option<&str>`): `Exact { ip, port }` iff the rule's `destination` parses as an `IpAddr`, the rule has `port: Some(p)` and its action is not `Deny`; `ExactWithoutPort` iff `destination` is an IP and `port` is `None`; otherwise `NoExactDestination`.
* `exact_ip_denials(&self, profile) -> Vec<DenyIp>`: every rule of the profile whose action is `Deny` and whose `destination` parses as an `IpAddr`, as `DenyIp { ip, port, rule_id }`, where `port` is the rule's own criterion (`None` = any port; an IPv4-mapped IPv6 destination cannot occur, `C-T1` rejects it). The ingress guard applies this set to resolved answers (6.10 step 5).

```rust
// crates/ssk-daemon/src/routing.rs (C-S1)
pub type ConfigState = Result<ssk_config::LoadedConfig, IpcError>;          // what `Inner.config` is today (supervisor.rs:111), hoisted unchanged
pub struct Decided { pub decision: PolicyDecision, pub candidate: RouteCandidate }   // evaluate + plan; RouteCandidate is ssk-netadmin's (route.rs:71)
pub enum DecideError { UnknownProfile, Evaluate(NetAdminError), Plan(NetAdminError) }
pub enum RuleBinding { NoExactDestination, ExactWithoutPort, Exact { ip: IpAddr, port: u16 } }
pub struct DenyIp { pub ip: IpAddr, pub port: Option<u16>, pub rule_id: String }
```

`decide` order (`ingress::engine::decide`, the caller has already run `canonicalize`):

1. `guard_self_loop(&target, listener)` (literals).
2. Build `FlowRecord { flow_id, intake_epoch 0, app 'local-proxy:unattributed', ProtocolKind::Tcp, RiskLevel::Low }` with `destination_host = target.host` (canonical) and call `routing.decide`.
3. Policy deny / no rule / attestation / unknown adapter / plan error => `Denied` (a plan error is a recorded denial here, unlike activation).
4. `guard_special_use(&target, routing.rule_binding(profile, matched_rule))` for literal targets.
5. **Route guard** (table below).
6. `orchestrator.admit` (error => `Denied`).

Route guard (all refusals are `Denied` of class `Route` or `Guard`, plaintext, no `Pending`, no socket, no resolver call). **SOCKS reply convention (MD-18):** class `Guard` (target-related: special-use, self-loop, name eligibility) -> `02`; class `Route` (the route cannot be executed: OpenVPN, not dialable, missing guard) -> `01`; `DIRECT_FAMILY_DISABLED` -> `08` (address type not supported); canonicalisation failures -> `08` (6.2).

| Route | Target | Result | Reply |
|---|---|---|---|
| `Denied`, `Fallback` | any | refuse `ROUTE_NOT_DIALABLE` | `01` |
| `OpenVpn` | any | refuse `OPENVPN_NOT_READY` | `01` |
| any chain whose LAST hop kind is not `Socks5`/`HttpConnect` | any | refuse `ROUTE_NOT_DIALABLE`. Verified by reading, not by running: a terminal `TlsTunnel` hop only wraps the previous transport in TLS with SNI = `metadata sni` or `next_host` (`executor.rs:286-295`, and `ConfiguredRouting::new` registers every adapter with empty `metadata`, `crates/ssk-daemon/src/routing.rs:40-46`), so no destination is ever conveyed to the tunnel peer and client bytes would end at the tunnel's address instead of the target | `01` |
| `Direct` | IPv6 literal while `direct_address_families = ipv4_only` | refuse `DIRECT_FAMILY_DISABLED` | `08` |
| `Direct` | other literal | allowed (special-use already decided in step 4) | |
| `Direct` | `Name` | allowed only if `data_plane.guards_direct_names()` is true, else refuse `DIRECT_GUARD_MISSING` (`01`); and only if the name is resolvable by an FQDN lookup: at least one dot, not `.local`, not `.onion`, else `DIRECT_NAME_NOT_RESOLVABLE` (`02`, see 6.10 for why) | |
| `SingleHop`/`MultiHop` ending in `Socks5`/`HttpConnect` | literal or `Name` | allowed; a `Name` is forwarded unresolved | |

`DIRECT_REQUIRES_LITERAL` never existed in the code (grep over `crates/` finds nothing) and is not introduced; draft 1's code list in section 11 and its test are corrected accordingly. The token and route are never formatted with `{:?}` anywhere in the ingress (derived `Debug` prints `HopSpec.auth`). Denied names are never resolved: `Denied`/no-rule/guard outcomes happen before `append_pending`, and the resolver runs only inside `connect_route`.

#### 6.7.2 `open_tunnel` order with the receipts (replaces draft 1's paragraph)

(a) `let Installed { writer, boot } = ctx.audit.current()` (none: refuse `01`, no dial), then `pending = writer.append_pending(adm.pending_input(&peer, profile), waits)`. The record is built from the token's own `target()` and `route()`; `boot` is the prefix the flow id was minted with (6.9, `LedgerSlot`). `Busy`, `QueueFull`, `Timeout`, `Capacity`, `Closing`: refuse `01`, no dial, no trip. `Io`, `WriterDown`, `SeqExhausted`: refuse `01` (the host is already tripped). (b) Re-check the gate epoch; if it changed, `audit.append_not_dialed(&pending, GATE_CLOSED, closed_deadline)` and refuse. (c) `dial(token, &pending, gate, epoch)`: verifies the receipt binding, sets `dial_started`, then `timeout(connect_timeout, data_plane.connect_route(token))` raced with `gate.changed()` and the cool-off check; exactly one `connect_route` call site, no retry. (d) On `Ok(session)`: `audit.append_connected(&pending, ConnectedEvent{chain_kinds, dialed, answers, observations}, waits)` returns a `ResultReceipt`; on any error the session is dropped first (upstream closes), no reply is written, and `Io` has already tripped; `Busy` and `Timeout` do not trip (the Pending stays, or its Result lands late and the receipt compensates with `Closed{audit_abandoned}`). On `Err(e)`: `audit.append_failed(&pending, error_code(&e), waits)` then the mapped SOCKS reply (6.10 table). Cancellation at any point simply drops `pending`, whose `Drop` writes `NotDialed` or `Aborted` (6.4.4). (e) `write_success(&result)`, `pump(.., &result, ..)` with the `Stats` carried by the receipt, then `result.closed(ev, closed_deadline)`. The engine copies `session.resolution()` and `first_hop_local` of the session into the `Result` record (6.10, 6.12).

### 6.8 `ingress/pump.rs`

`Counted<T>` wraps both ends (atomics for bytes and last activity, so counts survive errors and cancellation). `tokio::io::copy_bidirectional_with_sizes(.., 16 KiB, 16 KiB)` over `Counted<TcpStream>` and `Counted<&mut BoxedTransport>` (from `session.transport_mut()`; the first caller of that method in the workspace), raced in `select!` against an idle/half-close watchdog and `gate.changed()`. Cancellation drops both sockets (abrupt close, the repo's fail-closed convention); normal EOF lets `copy_bidirectional` propagate shutdown. About 32 KiB per tunnel. `pump(client, session, _r: &ResultReceipt, idle, gate, epoch, stats) -> PumpEnd { Eof, IdleTimeout, GateClosed, ClientError, UpstreamError }`. Half-close propagation through each adapter kind (TLS close_notify, SOCKS5/CONNECT streams, boxed transport) is a test to run, not a verified fact.

**Refinements made at `C-G6`.** (1) `pump` is generic over the two streams (`AsyncRead + AsyncWrite + Unpin`), so it is tested with in-memory duplex streams and the flow code passes `session.transport_mut()`; it takes a `&ResultProof` (the sealed trait of 6.3) instead of `&ResultReceipt`, the `gate` as `&mut watch::Receiver<Gate>` and a caller-owned `&ByteCounts` instead of `stats`. (2) `ByteCounts.up` is what was WRITTEN to the upstream and `down` what was written to the client (not what was read), so a failed write counts nothing. Activity (for the idle timeout) is any byte read or written in either direction. (3) The gate is polled first (`biased`), so a flow whose gate has already moved on returns before the copy is polled once; an explicit check at the start would be dead code, and `a_gate_that_changed_before_the_pump_moves_no_byte` runs 64 rounds because an unbiased `select!` fails it only at random. A gate whose sender is gone ends the pump too. (4) Errors are attributed to the end that first reported one (`ClientError` or `UpstreamError`) by the wrappers, because `copy_bidirectional` does not say which side failed. (5) The idle and gate tests use tokio's paused clock (`test-util` as a dev-dependency), so "30 s of silence" is asserted to the second without waiting. (6) `half_close_is_propagated_each_way` is now a test for plain streams; the same test through each adapter kind (TLS close_notify, SOCKS5 and CONNECT streams) still has to be run when the flow is wired (`C-E3`).

### 6.9 `ingress/shared.rs` and `ingress/host.rs`: the control plane

`IngressShared` owns the gate and everything a status read needs. `IngressHost` owns the sockets and tasks. Neither imports `Supervisor`, `Inner` or `StateMachine`.

```rust
pub struct IngressShared {
    gate: watch::Sender<Gate>,                          // the only lifecycle state (L1)
    control: Arc<tokio::sync::Mutex<ControlState>>,     // FIFO; arm, recover and the bookkeeping half of disarm (L5)
    events: broadcast::Sender<ssk_ipc::Event>,          // a clone of the StateMachine's sender, taken before Inner exists (6.9.3)
    status: std::sync::Mutex<StatusInner>,              // last_error, last_denial, last_transition, observation slots; poison-tolerant (L13); never held across an await or inside a watch closure
    counters: Counters,                                 // atomics only (wrap, never panic); includes flow_panics, trips, accept_errors
    flows: FlowRegistry,                                // ring of 256 behind a short std Mutex
    ledger: Arc<LedgerSlot>,                            // the current audit writer: the host installs the first one at start and a fresh one at every recover (below)
    host: OnceLock<Arc<dyn HostControl>>,               // set by the host; used by recover
    cfg: IngressCfgView,                                // enabled, profile ids, arm_on_start, configured limits, effective limits (7.3), hardening, families, destination logging
}
struct ControlState;                                    // no fields: the lock exists to serialise operations, not to guard data
pub struct ArmOutcome    { pub epoch: u64, pub changed: bool }
pub struct DisarmOutcome { pub was_armed: bool, pub epoch: u64 }

impl IngressShared {
    pub fn new(cfg: IngressCfgView, events: broadcast::Sender<ssk_ipc::Event>) -> Arc<Self>;
    pub fn snapshot(&self) -> IngressStatusDto;         // no await, no tokio lock, no file I/O; never waits for `control`
    pub fn gate(&self) -> watch::Receiver<Gate>;
    pub async fn arm(self: &Arc<Self>, profile: &str, actor: Actor) -> Result<ArmOutcome, IpcError>;
    pub fn arm_would_be_noop(&self, profile: &str) -> bool;   // the 11.4 shortcut: the gate reads Armed{profile} AND control.try_lock() succeeds; holds the lock only for the check
    pub async fn disarm(self: &Arc<Self>, cause: DisarmCause) -> DisarmOutcome;   // the effect cannot fail
    pub fn trip(&self, why: TripReason);                // sync, any thread (L7)
    pub async fn recover(self: &Arc<Self>) -> Result<(), IpcError>;
    pub fn close(&self);                                // gate -> Closing
    pub fn recent_flows(&self, limit: usize) -> Vec<FlowSummaryDto>;
    pub fn inspect(&self, flow_id: &str) -> Result<FlowInspectionDto, IpcError>;   // FLOW_NOT_RETAINED vs FLOW_NOT_FOUND
}

pub trait ControlLedger: Send + Sync {                  // implemented by FlowAuditWriter; a fake in the unit tests
    fn append_armed(&self, r: ArmedEvent, w: Waits) -> BoxFuture<'_, Result<ArmReceipt, AuditError>>;      // durable
    fn append_disarmed(&self, r: DisarmedEvent, bounded: Duration) -> BoxFuture<'_, ()>;                    // durable, best effort; callers count a loss
    fn try_enqueue_tripped(&self, r: TrippedEvent) -> bool;                                                 // sync, never blocks
}
pub trait HostControl: Send + Sync {
    fn recover(&self) -> BoxFuture<'_, Result<(), RecoverError>>;   // all-or-nothing: the new writer is installed in the LedgerSlot as its last step, immediately before the gate write
}
```

**`LedgerSlot`: how a re-arm gets a new audit writer without a restart.** `recover` closes and joins the old writer and opens a new one (`FlowAuditWriter` has no reopen, and `close(&self)` leaves it in `Closing` for good). Draft 2 kept the writer in a `OnceLock`, which can be set only once, and in an immutable `Arc` inside `EngineCtx`: after the first recover every flow would have appended to a closed writer and been refused with `01`, and a second recover could not have replaced anything. One indirection fixes it:

```rust
pub struct LedgerSlot { current: std::sync::RwLock<Option<Installed>> }     // read through the poison-tolerant helper (L13); never held across an await
#[derive(Clone)] pub struct Installed { pub writer: Arc<FlowAuditWriter>, pub boot: Arc<str> }   // boot = "b<seq of the Started record>": the flow-id prefix
impl LedgerSlot {
    pub fn current(&self) -> Option<Installed>;                      // clones two Arcs under a read lock
    pub fn install(&self, new: Installed) -> Option<Installed>;      // host only (start task, recover); returns the previous one
}
impl ControlLedger for LedgerSlot { /* delegates to current(); with no writer: AuditError::Closing, that is refuse, never "write nothing and carry on" */ }
```

`IngressShared`, `EngineCtx` and the host hold the same `Arc<LedgerSlot>`; every append, every status read of the writer's atomics and every `ControlLedger` call goes through `current()`, so the first recover and the tenth look the same. A receipt keeps the channel of the writer that issued it (its private `Arc<FlowCtl>`), not a reference to the slot, so after a recover it resolves against the OLD writer: `close()` drains compensation jobs before that writer exits (6.4.7), and a receipt dropped after the old writer has gone has nothing to send to. That loss is counted (`audit_close_lost`) and the story of that flow is bounded by the next `Started` or `Recovered` record (`unresolved`, I6). A flow admitted under an older epoch is cancelled at the gate re-check of 6.7.2 (b); its id still names the boot it was minted under.

#### 6.9.1 The write primitive

```rust
fn cas<F>(&self, expect_epoch: Option<u64>, f: F) -> Option<Gate>
where F: FnOnce(&GateMode) -> Option<GateMode> {
    let mut applied = None;
    self.gate.send_if_modified(|g| {
        if matches!(g.mode, GateMode::Closing) { return false; }
        if expect_epoch.is_some_and(|e| e != g.epoch) { return false; }
        let Some(mode) = f(&g.mode) else { return false };
        match g.epoch.checked_add(1) {
            Some(next) => { g.epoch = next; g.mode = mode; }
            None => { g.mode = GateMode::Closing; }          // 2^64 transitions: unreachable, but never a wrap
        }
        applied = Some(g.clone());
        true
    });
    applied
}
```

The closure runs under the watch cell's internal write lock, so it takes no lock and does no I/O (L2). Receivers (accept loop, every flow, the watchdog) see the change through `changed()`; a flow compares the epoch it was admitted under with the current one. (The codebase already uses `send_if_modified` for the same kind of one-shot decision, `shutdown.rs:105-118`.)

#### 6.9.2 The four operations

**arm(profile, actor).** The caller (`Supervisor`) has already run `validate_profile_id` (`supervisor.rs:483`) and has written no ledger record for a rejected id. `arm` spawns a control task and awaits its `JoinHandle` (L6). The task:

1. `timeout(control_lock_wait, control.lock_owned())`; on expiry return `INGRESS_BUSY` (retriable); nothing has happened.
2. Branch on the mode: `Disabled` -> `INGRESS_DISABLED`; `Starting` -> `INGRESS_STARTING` (retriable); `Closing` -> `INGRESS_STOPPING`; `Armed{p}` with the same profile -> `Ok(changed: false)` with no record and no epoch change; `Tripped` or `Unavailable(c)` -> `recover_locked` (below) and, if it fails or `c` is not recoverable, return that error; `Disarmed` or `Armed{other}` -> continue.
3. `from = gate.epoch`, read after any recover.
4. `receipt = ledger.append_armed(ArmedEvent { profile, actor, epoch: from + 1, .. }, waits).await`. Failure -> `INGRESS_AUDIT_FAILED` (`INGRESS_AUDIT_STALLED` when the writer is stalled); other errors have already tripped the gate through the writer.
5. `cas(Some(from), |_| Some(Armed{profile}))`. `Some(g)`: `receipt.applied()`, counters, `Event::Warning{INGRESS_ARMED}`, `Ok(changed: true, epoch: g.epoch)`. `None`: a trip, disarm or close won: `receipt.superseded(ArmSuperseded)` (queues `Disarmed{arm_superseded}` on the compensation channel). Return `INGRESS_TRIPPED`, `INGRESS_STOPPING` or `INGRESS_SUPERSEDED` according to the mode now in the gate.

If the requester's future is dropped at any point, the task still runs steps 1-5 to completion (L6); if the task itself dies between 4 and 5 the unresolved `ArmReceipt` compensates on drop (`Disarmed{arm_abandoned}`, 6.4.4). A `JoinError` that `is_panic()` calls `trip(ControlPanic)` and answers `INGRESS_CONTROL_FAILED`.

**disarm(cause).**

1. Effect, first, lock-free, cannot fail: `cas(None, |m| match m { Armed{..} => Some(Disarmed), Disarmed | Tripped(_) | Unavailable(_) => Some(m.clone()), Starting | Disabled | Closing => None })`, remembering whether the old mode was `Armed`. `Some(m.clone())` is a write that only bumps the epoch. In `Starting` it writes nothing (a bump would make the start task's own compare-and-set fail) and only sets the `autostart_cancelled` flag so a pending `arm_on_start` does not arm.
2. If it was `Armed`: `timeout(disarm_bookkeeping_wait, control.lock())` and, once obtained, `append_disarmed(cause)` with a 1 s bound; failure or timeout increments `disarm_record_lost`. Then `Event::Warning{INGRESS_DISARMED}`.
3. Return `DisarmOutcome { was_armed, epoch }`.

Because step 1 never waits, `Deactivate` and `SetIngress{armed: false}` stop forwarding at once even while a recover holds `control` for seconds. `SetIngress{armed: false}` calls `disarm` unconditionally, never behind a gate read, a no-op check or a rate limit (11.4): a disarm that arrived while an arm waited on its fsync (the gate still reads `Disarmed`) would otherwise be acknowledged and the arm would then open the gate.

**trip(why).** `cas(None, ...)` per the table in 6.1.2. On a write: `trips += 1`, `status.last_transition`, `Event::Warning{INGRESS_TRIPPED}`, `ledger.try_enqueue_tripped(...)` (skipped for `AuditWriteFailed`, where the writer is the thing that failed). It never awaits and never takes `control`, so a writer thread can call it while an arm is blocked in the very fsync that failed.

**recover.** Public `recover` takes `control` like arm; `recover_locked(&OwnedMutexGuard<ControlState>)` takes the guard as a witness that the lock is held. It: requires `Tripped` or a recoverable `Unavailable`, otherwise returns that code; reads `e0`; calls `host.recover()` (previous writer closed and joined within 1.2 s, ledger opened and verified in `spawn_blocking` with `recover_verify_deadline`, the destination key re-read in hashed mode, listener bound again only if it is absent or dead, with `bind_retry_recover`, the `flow_panics` counter reset, and the new writer installed in the `LedgerSlot` as the last step, so a failure at any earlier step installs nothing and leaves the closed old writer in the slot, whose appends are refused; if the previous writer cannot be joined, recover fails with `INGRESS_AUDIT_STALLED` and never opens a second writer on the same segment); then `cas(Some(e0), |_| Some(Disarmed))`. On any failure: `cas(Some(e0), |_| Some(Unavailable(code)))` with the most specific code (`AuditCorrupt`, `AuditFailed`, the store codes, `BindFailed`, otherwise `RecoveryFailed`) and `INGRESS_RECOVERY_FAILED` with the cause in the message. Verification is single-flight: a second recover while the first one's blocking job still runs answers `INGRESS_BUSY`. With `listen.port = 0` (tests only) a rebind yields a new port and `status.listen` changes; shipped configurations fix the port.

#### 6.9.3 Events

`StateMachine::events` is a `broadcast::Sender` (`state.rs:12`); `Sender` is `Clone` and `send(&self)` is synchronous. `Supervisor::new` clones it (new `StateMachine::event_sender()`) before the `StateMachine` moves into `Inner`'s mutex, and `IngressShared::new(cfg, events.clone())` keeps the clone. Arm, disarm, trip and recover emit `Event::Warning { code, message }` with `INGRESS_ARMED`, `INGRESS_DISARMED`, `INGRESS_TRIPPED`, `INGRESS_RECOVERED` from any thread, including the audit writer thread, without touching `Inner`. `Supervisor::subscribe_events` uses the same sender and no longer queues behind a dial (it stays `pub async fn`). Draft 1's "rate-limited" claim is dropped: each event is one gate transition. **No IPC client receives these events**: `handle_connection` writes exactly one `Response` per `Request` (`server.rs:312-313`), `Response::Event` is constructed nowhere, and `SubscribeEvents` answers `Ack`. For IPC clients trip visibility is polling `GetStatus`; `ingress.epoch` and `ingress.trips` make a missed transition detectable (10.4).

#### 6.9.4 `IngressHost`

```rust
pub struct IngressHost { /* accept task slot, watchdog, PathWatcher, Arc<FlowAuditWriter>, bound addr, Arc<IngressShared> */ }
impl IngressHost {
    pub async fn start(deps: IngressDeps) -> IngressHost;              // returns at once; spawns the start task. Never fails: failures become Unavailable(code)
    pub fn local_addr(&self) -> Option<SocketAddr>;
    pub async fn shutdown(self, plan: ShutdownPlan) -> ShutdownOutcome;   // 8.5; ShutdownOutcome { flows_aborted, writer_joined, closed_lost }
}
pub enum BindRetryPolicy { Schedule(&'static [Duration]), Doubling { first: Duration, cap: Duration, window: Duration } }
```

**Start task**, with `e0` = the gate epoch while `Starting`. After every step it checks `gate.epoch == e0`; a shutdown or trip that arrived meanwhile ends the task (cooperative cancellation at phase boundaries; a running `spawn_blocking` is not cancelled, see 8.5 for why that is safe).

1. `enabled == false` -> `cas(Some(e0), Disabled)`.
2. Configuration valid and `platform.controls()` satisfy `hardening` -> otherwise `Unavailable(ConfigInvalid | HardeningUnavailable)`.
3. Descriptor budget (7.3); below the floor -> `Unavailable(FdLimitTooLow)`; otherwise publish the effective limits.
4. Phase `verifying_ledger`: `spawn_blocking(open_dir)` (the store checks of 6.4.9, then the ledger verify of up to `segment_mib * retain_segments`, default 256 MiB); corrupt, unsafe store, missing key or newer format -> the matching `Unavailable(...)` with nothing bound; other error -> `Unavailable(AuditFailed)`. Then `Started` is appended.
5. Phase `binding (attempt n of N)`: bind per `platform.bind_retry()`. **Unix:** 0, 250, 500, 1000, 2000, 4000 ms (at most 7.75 s); Linux needs no retry for `TIME_WAIT` because mio sets `SO_REUSEADDR` on Unix listeners (`mio-1.2.2/src/net/tcp/listener.rs:82`) and a rebind next to `TIME_WAIT` sockets succeeds, while a second bind to a live listener fails with `EADDRINUSE` (both measured, 26). **Windows baseline (`C-WIN0`, plain bind):** the Unix schedule above. **Windows (exclusive bind, `C-WIN1`):** 500 ms doubling to a 30 s cap, last attempt at 150 s, because a listener bound with `SO_EXCLUSIVEADDRUSE` is assumed to be unable to rebind while connections to its old local port linger in `TIME_WAIT`, commonly about 120 s after a crash or update (UNVERIFIED; a plain `best_effort` bind is expected not to have the delay, so it is a cost of `C-WIN1`). Only `AddrInUse` and `AddrNotAvailable` are retried; any other error fails at once (`PermissionDenied`, which Windows reports for an OS-reserved port, gets the hint that the port may be reserved by the operating system or need elevated rights, and the default port is below 49152). While retrying: `starting`, `listen` null, `phase` "binding (attempt n of N)", `retry_hint` "The port is busy; retrying (attempt n, next in s s). Gives up after w s.", `last_error` `INGRESS_BIND_FAILED` (retriable, sanitised OS text); status never names `TIME_WAIT` as the cause. Exhaustion -> `Unavailable(BindFailed)`; never another port. `local_addr()` is asserted to be the requested IPv4 loopback address. Tests inject a clock and a sleeper; none waits on a wall clock.
6. Runtime self-loop check (no routing adapter's literal address:port equals the bound address; 5.3).
7. Publish: install the first writer in the `LedgerSlot`, then `cas(Some(e0), |_| Some(Disarmed))`; set the `GuardCells` (the listener address and the gate receiver, 6.10); then spawn the accept task, the watchdog (a task that awaits the accept task's `JoinHandle` and calls `trip(ListenerDied)` if it ends while the gate is not `Closing`, plus the 1 Hz stall check of 6.4.6) and the `PathWatcher` (6.12; it does nothing while the ingress is `disabled`, `unavailable` or `starting`).
8. If `arm_on_start` is set and not cancelled: `arm(default_profile, ConfigAutostart)`. A failure is logged and emitted as a Warning; it is never retried automatically (rule 10).

An `arm` that arrives during steps 1-7 answers `INGRESS_STARTING` (retriable) and is never queued; `SetIngress{armed: false}` during start succeeds and cancels the autostart. An explicit arm from `Unavailable(BindFailed)` is a `recover` with the short `bind_retry_recover` schedule on every platform; a longer wait on Windows is a decision for the `C-WIN1` verification run (MD-15).

#### 6.9.5 Dependencies and seams (what tests inject)

Draft 2 used `IngressDeps`, `ResolvedLimits`, `IngressCfgView` and "an injected clock and sleeper" without defining them. They are:

```rust
pub struct IngressDeps {
    pub cfg: IngressCfgView,                     // validated, owned copy of the section plus what the host needs from routing (stored by C-F1)
    pub routing: Arc<ConfiguredRouting>,         // the planner (12.1)
    pub data_plane: Arc<dyn DataPlane>,          // the INGRESS data plane (6.10 "Two executors"); tests pass a counting double
    pub shared: Arc<IngressShared>,
    pub platform: Arc<dyn IngressPlatform>,      // bind, controls, peer authorizer (6.6)
    pub fs: Arc<dyn LedgerFs>, pub lock: LockProof, pub state_root: PathBuf,
    pub clock: Arc<dyn Clock>, pub sleeper: Arc<dyn Sleeper>,
    pub tuning: Tuning,                          // 6.1.4; tests shrink it
    pub guard_cells: Arc<GuardCells>,            // the listener cell and the gate receiver that the ingress guard reads (6.10)
}
pub trait Clock: Send + Sync { fn now(&self) -> std::time::Instant; fn wall_ms(&self) -> u64; }   // production: the std clocks; limiters take `now` as an argument
pub trait Sleeper: Send + Sync { fn sleep(&self, d: Duration) -> BoxFuture<'static, ()>; }       // production: tokio::time::sleep; tests record the request and complete at once
pub struct IngressCfgView { pub enabled: bool, pub listen: SocketAddrV4, pub protocols: Vec<IngressProtocol>, pub hardening: IngressHardening,
    pub arm_on_start: bool, pub default_profile: Arc<str>, pub profile_ids: Vec<Arc<str>>, pub families: DirectAddressFamilies,
    pub destination_logging: DestinationLogging, pub limits: IngressLimits, pub audit: IngressAuditConfig,
    pub fingerprint: ConfigFingerprint /* the running configuration's digests: Started, status, and the expect_routing_digest check of 11.4 */ }
pub struct ResolvedLimits { pub max_connections: u32 /* effective, 7.3 */, pub accept_rate_per_s: u32, pub handshake: Duration, pub connect: Duration,
    pub idle: Duration, pub fd: FdBudget }
```

`IngressCfgView` is built once by `C-F1` from the validated `AppConfig`, so the host never sees the whole `ssk-config` struct; `ResolvedLimits` is the configured limits after the descriptor budget of 7.3 has been applied (step 3 of the start task). `Clock` and `Sleeper` are the seams of the bind-retry and limiter tests; the types live in `types.rs` so that `audit`, `limits` and `host` can use them without importing each other.

### 6.10 Direct-by-name: resolve once, filter, pin, dial (M2 spine)

Owner decision of 2026-10-06: the browser sends host names, so a `Direct` rule must work for names in M2. The OS routing table decides the path; the daemon binds no interface and no source address (`ssk-netcore/src/direct.rs:25` dials `TcpStream::connect((unbracket(host), port))`; there is no `bind`, `TcpSocket` or `bind_device` in any netcore production file; a source-scan test keeps it so, CO-1).

**Where each step happens.** Engine, before `Pending`: canonicalise, policy, route guard (6.7.1). Executor, after the durable `Pending` and inside `connect_route`: resolve, guard, filter, pin, dial. So (1) a denied or unmatched name never reaches any resolver, and (2) the DNS query is itself an audited egress event whose record exists first.

**Executor algorithm (`RouteExecutor::connect_direct`, and the first-hop dial in `connect_chain`, `executor.rs:194-201` and `:225`):**

1. `h = unbracket(host)`. If `h` parses as `Ipv4Addr`/`Ipv6Addr`: refuse with `NetcoreError::FamilyDisabled` when its family is filtered out (defence in depth below the engine's `DIRECT_FAMILY_DISABLED`); otherwise one `TcpConnector::connect(SocketAddr)` (OS: `TcpStream::connect`) under `connect_timeout`; no resolver; the guard is NOT consulted for a `Target` literal (it was decided by the engine before the token existed: self-loop guard plus matched-rule binding). Resolution mode `Literal`.
2. Otherwise `h` is a name. Defence in depth below `canonicalize`: refuse with `NetcoreError::InvalidTarget` unless `is_resolvable_name(h)` (ASCII, labels as in 6.2 step g, final label starts with a letter, not an IP, at most 253 bytes). No numeric alias and no control character can reach `getaddrinfo` from netcore even if a future front end forgets to canonicalise.
3. `answers = bounded_resolver.resolve_once(h, port)`: exactly ONE call per dial, with the bare canonical name (see the search-list note in 6.11). Never repeated: not per address, not on connect failure, not for happy eyeballs, not on a gate-epoch retry (there is none). `Busy` (no permit within `RESOLVER_WAIT`, or the waiter cap reached) -> `NetcoreError::ResolverBusy`; deadline -> `Timeout(authority, resolve_timeout)`; OS error -> `DnsResolutionFailed(name, os-resolver, text)`; empty -> `DnsResolutionFailed(.., no addresses)`.
4. Normalise: unmap `::ffff:a.b.c.d` to IPv4, drop exact duplicates keeping the first occurrence, keep the first `MAX_ANSWERS = 32`.
5. Guard (when a guard is installed): call `guard.check(DialPurpose::Target, ip, port)` for EVERY remaining address, **before** the family filter. If ANY address is refused, no socket is created and the dial fails `AddressRefused { code (first refusal), refused, answers }`. All-or-nothing on purpose: a mixed answer (public + loopback/private) is the DNS-rebinding signature, it must be visible in the audit as one refusal, and no "dial only the allowed ones" selection exists to be gamed. The daemon's guard refuses an address that is special-use (`classify_ip`), that is the listener, or that equals an exact-IP `deny` rule of the **armed** profile whose port criterion is absent or equals the dial port (label `deny_rule`; the set is `exact_ip_denials`, 6.7.1). That is the rule set the policy engine can never apply to a client-sent name, because a name flow never equals an IP rule (`policy.rs:91-104`). First-match order decides which rule a name or a literal flow matches, but this check can only refuse more, never admit more, so it applies at any priority: a deny rule cannot be walked around by sending a name that resolves to the denied address (the reverse, a domain rule against a client that sends an address, cannot be enforced locally, 6.11). Cost: DNS64 answers in 64:ff9b::/96 are refused whatever IPv4 address they embed (the range always needs an exact rule, 6.2), and 100.64/10, 198.18/15 and private answers are refused (limitation below).
6. Family filter (`direct_address_families`, 5.1): under `ipv4_only` drop every IPv6 candidate; if no candidate remains the dial fails `NetcoreError::FamilyDisabled` (SOCKS reply `04`). Order: keep the OS's order inside a family; **IPv4 candidates start first** and the families then alternate (v4, v6, v4, v6, ...), keeping at most `MAX_DIAL_CANDIDATES = 8`. This deliberately differs from RFC 8305 section 4, which starts with the family of the first answer (usually IPv6 on a host with a global IPv6 address): an IPv6 path may bypass a third-party tunnel that does not cover it (13.2.5). No family is dropped under `any` (an IPv6-only host is handled by the attempts that fail, not by guessing).
7. Race (happy eyeballs without a second lookup): attempt 1 starts at t0; the next attempt starts at the EARLIER of `ATTEMPT_DELAY = 250 ms` after the previous start (RFC 8305: recommended 250 ms, minimum 100 ms, maximum 2 s) or the moment the previous attempt FAILED (design decision, not an RFC statement); every attempt is one `TcpConnector::connect(SocketAddr)` (the OS implementation is `TcpStream::connect(SocketAddr)`), which never touches a resolver; all attempts share ONE connect budget measured from t0 (resolution time is not part of it; the engine's outer `connect_timeout` is the binding bound, 12.9); the first established stream wins and the others are aborted (dropping the future closes its socket); a `JoinSet` owns the attempts so that dropping the whole dial (gate change, deadline) aborts them all. **Descriptor bound by construction (MD-9):** attempts after the first need a permit from the executor's shared semaphore of `DIAL_EXTRA_PERMITS = 64` (`try_acquire`; none free means the next attempt does not start until an earlier one has failed), so the transient sockets of all racing dials together never exceed 64 (7.3). Failure after all attempts: `Timeout` if the budget ended, `ConnectionRefused` if every error was a refusal, otherwise `Io` with the last error. Every failure after at least one attempt has started is returned as `NetcoreError::DialFailed { source, attempts }`, a wrapper whose `code()` and Display delegate to `source` and which carries `DialAttempts { answers, attempted }`, so that the ledger can say which addresses were tried (6.4.3); a failure before any attempt (`AddressRefused`, `FamilyDisabled`, `DnsResolutionFailed`, `ResolverBusy`) needs no wrapper. Today's behaviour for comparison: tokio's `TcpStream::connect` tries addresses one after another with no per-address timeout (`tokio-1.53.1/src/net/tcp/stream.rs:118-136`), so a blackholed first address burns the whole `timeout(connect_timeout, ..)` of `direct.rs:25` and later addresses are never tried.
8. Return the stream plus `DialResolution { mode: OsResolver, dialed: SocketAddr, attempted: Vec<SocketAddr>, answers: u8, local_addr: stream.local_addr() }`.

`DialPurpose::FirstHop` (the configured proxy's own host, resolved the same way and filtered by the same families): the guard is consulted for every literal and every resolved address, but the daemon's guard answers only the self-loop question (address equals the listener, or loopback/unspecified with the listener's port). Special-use first-hop addresses are NOT refused (a local proxy on 127.0.0.1 or a LAN proxy is legitimate operator configuration). This closes the "adapter host name that resolves to the listener" loop that the static config and bind-time literal checks cannot see.

**New netcore API (`ssk-netcore`, all `forbid(unsafe_code)`):**

```rust
pub trait NameResolver: Send + Sync + 'static {
    /// BLOCKING; called only from a thread that may block. `name` already passed is_resolvable_name.
    fn resolve(&self, name: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}
pub struct OsResolver;                       // std::net::ToSocketAddrs for (name, port), order preserved
/// The ONLY place a socket is created for a dial (CO-1). Its single parameter is the destination: neither an interface nor a source address can be asked for through this interface.
pub trait TcpConnector: Send + Sync + 'static {
    fn connect<'a>(&'a self, addr: SocketAddr) -> BoxFuture<'a, std::io::Result<Connected>>;
}
pub struct Connected { pub transport: BoxedTransport, pub local_addr: Option<SocketAddr> }
pub struct OsConnector;                      // `TcpStream::connect(addr)` and nothing else; its body is pinned by the static scan of 24.2.1
pub enum DialPurpose { Target, FirstHop }
pub enum AddressFamilies { Ipv4Only, Any }
pub struct AddrRefusal { pub code: &'static str }     // static label only (loopback, private, listener, ...): never the address
pub trait DirectAddrGuard: Send + Sync { fn check(&self, purpose: DialPurpose, ip: IpAddr, port: u16) -> Result<(), AddrRefusal>; }
impl RouteExecutor {
    pub fn with_resolver(self, r: Arc<dyn NameResolver>) -> Self;           // default OsResolver
    pub fn with_resolve_timeout(self, d: Duration) -> Self;                 // default 5 s, clamped to the dial deadline
    pub fn with_max_concurrent_lookups(self, n: usize) -> Self;             // default 16
    pub fn with_direct_guard(self, g: Arc<dyn DirectAddrGuard>) -> Self;    // default none
    pub fn with_address_families(self, f: AddressFamilies) -> Self;         // default Any (activation behaviour unchanged); the ingress executor passes the configured value
    pub fn with_attempt_delay(self, d: Duration) -> Self;                   // default 250 ms
    pub fn with_connector(self, c: Arc<dyn TcpConnector>) -> Self;          // default OsConnector; the paused-time dial tests pass a scripted double (23.3)
    pub fn with_max_extra_attempts(self, n: usize) -> Self;                 // default 64
    pub fn has_direct_guard(&self) -> bool;
    pub fn address_families(&self) -> AddressFamilies;                      // lets the wiring test assert what the daemon built (23.7)
}
pub trait DataPlane { /* existing */ fn guards_direct_names(&self) -> bool { false } }   // NetcoreDataPlane returns executor.has_direct_guard()
pub enum ResolutionMode { Literal, OsResolver, ForwardedUnresolved }
pub struct DialResolution { pub mode: ResolutionMode, pub dialed: Option<SocketAddr>, pub attempted: Vec<SocketAddr> /* <= 8 */, pub answers: u8, pub local_addr: Option<SocketAddr> }
pub struct SessionResolution { pub target: DialResolution, pub first_hop: Option<DialResolution> }
impl EgressSession { pub fn resolution(&self) -> &SessionResolution }
// NetcoreError gains: AddressRefused { code, refused, answers } (NETCORE_ADDR_REFUSED), ResolverBusy (NETCORE_RESOLVER_BUSY), FamilyDisabled (NETCORE_FAMILY_DISABLED),
//                     DialFailed { source: Box<NetcoreError>, attempts: DialAttempts } (code() and Display delegate to source); DialAttempts { answers: u8, attempted: Vec<SocketAddr> }
```

`ForwardedUnresolved` is recorded for a proxied route whose target is a name: the daemon did no lookup for the target (the upstream proxy resolves it). A proxied route to a literal records `Literal`. `local_addr` is a free observation (the source address the OS routing table chose for this socket, read from `TcpStream::local_addr()` of a socket the OS already configured; it adds no option and no bind); for a `Direct` route it is `target.local_addr`, for a proxy chain `first_hop.local_addr`. It says nothing about whether any third-party adapter is involved and must be labelled an observation wherever shown (10.5). Whether a tunnel application that steers per application rewrites it is UNVERIFIED, which is why the echo test, not this field, is the arbiter (13.2.3).

**Bounded resolver (resolves "stuck behind the blocking pool").** tokio's `(host, port)` dial runs `getaddrinfo` through `spawn_blocking` (`tokio-1.53.1/src/net/addr.rs:219`) on a pool whose default limit is 512 threads (`runtime/builder.rs:306`; the daemon builds `new_multi_thread().enable_all()` with no limit, `main.rs:148-150`). `timeout()` only drops the future; the blocking thread keeps running until the OS call returns, and enough hung lookups (a dead DNS server, a hostile client opening names) would exhaust the pool and stall every other `spawn_blocking` user (the kill-switch poller, `main.rs:225`). `resolve_once`:

```rust
let waiter = waiters.clone().try_acquire_owned().map_err(|_| ResolverBusy)?;                 // at most RESOLVER_WAITERS (32) flows wait; the 33rd fails at once
let permit = match timeout(resolver_wait, permits.clone().acquire_owned()).await {             // RESOLVER_WAIT = 500 ms
    Ok(Ok(p)) => p, _ => return Err(ResolverBusy) };
drop(waiter);
let (tx, rx) = oneshot::channel();
task::spawn_blocking(move || { let r = inner.resolve(&name, port); drop(permit); let _ = tx.send(r); });
// the PERMIT lives inside the thread: it returns only when the OS call has really returned
match timeout(resolve_timeout.saturating_sub(waited), rx).await { .. }                       // RESOLVE_TIMEOUT counts from the call: the wait is inside it
```

So at most `MAX_CONCURRENT_LOOKUPS = 16` pool threads can ever be held by lookups, whatever the timeouts do. A 17th concurrent Direct-by-name flow waits up to 500 ms for a permit (at most 32 flows wait; the 33rd fails at once) and then fails with `ResolverBusy` (SOCKS `01`); literals, proxied routes and every other blocking user are unaffected. Draft 2 failed the 17th flow at once. A browser page that sends dozens of distinct cold host names through the proxy would then have lost every name beyond the 16th for as long as the OS resolver took to answer the first 16, and a client does not retry a SOCKS `01`; the bounded wait absorbs a burst of fast lookups (the normal case), the waiter cap keeps the queue from growing, and `counters.resolver_busy` shows when that was not enough. A lookup whose flow gave up at `RESOLVE_TIMEOUT` keeps its permit until the OS call returns (a zombie): that is by design, because the permit is what bounds the threads, and the executor counts abandoned lookups so that status can say how many permits are pinned. The peer service (6.6) is a dedicated thread and does not use the pool at all. The OS cache absorbs repeated names (no daemon-side cache is added: a cache would be a second place that decides which address a name means).

**Resolver alternatives not adopted (critic round 1).** A dedicated resolver thread pool sized above 16: the tokio blocking pool has 512 threads (`runtime/builder.rs:306`) and the other known users need at most four (7.3), so the 16 lookups starve nothing; the cap exists for the OS resolver's load and the descriptor budget (up to 3 descriptors per lookup), not for pool safety. Single-flight coalescing of concurrent identical names: an optimisation with its own audit rule (only a flow that already has a durable `Pending` may join a lookup, and the lookup's initiator must have had its own first), deferred as `C-N5` (OPT) until a measurement with a real browser page says it is needed.

**Defaults (internal constants, not config; 6.1.4):** `RESOLVE_TIMEOUT 5 s` (effective `min(5 s, connect_timeout)`), `MAX_CONCURRENT_LOOKUPS 16`, `RESOLVER_WAIT 500 ms`, `RESOLVER_WAITERS 32`, `MAX_ANSWERS 32`, `MAX_DIAL_CANDIDATES 8`, `ATTEMPT_DELAY 250 ms`, `DIAL_EXTRA_PERMITS 64`. Their sufficiency for a browsing workload is UNVERIFIED.

**Errors to SOCKS replies:** (a `DialFailed` wrapper maps by its `source`) `AddressRefused` -> `02`; `DnsResolutionFailed` -> `04`; resolver `Timeout` and connect `Timeout` -> `04`; `FamilyDisabled` -> `04`; `ResolverBusy` -> `01`; `ConnectionRefused` -> `05`; `Io` with kind `NetworkUnreachable` -> `03`, `HostUnreachable` -> `04`, any other -> `01` (these `ErrorKind`s are stable on the pinned 1.95 toolchain). The Result record stores `error_code` and the static refusal label only, never an address.

**Name eligibility for the OS resolver (engine route guard, refused before `Pending`).** A `Direct` name must contain a dot, must not end in `.local` and must not end in `.onion`. Reasons: `.onion` must never go to DNS (RFC 7686, recalled), `.local` and single-label names may be answered by multicast or link-local mechanisms (mDNS, LLMNR, NetBIOS) instead of the configured DNS servers, which would send the name to the local network; both are Windows behaviours that are UNVERIFIED here and refused conservatively. Proxied routes are not restricted (the upstream resolves). Accepted limitations: names with `_`, any non-ASCII byte, or a final label starting with a digit cannot be used at all (no rule can name them either, `valid_host` rejects them); a name that resolves into loopback, private, link-local, 100.64/10 or 198.18/15 space (a hosts-file dev name such as `app.test -> 127.0.0.1`, a Meshnet-style name, a LAN name) is refused for `Direct`; use the client's proxy-bypass list for such names, or an exact literal rule with a port for a single LAN host (open question B7).

**Two executors.** The activation path (`ssk activate --dest`) keeps its existing, unguarded executor (`main.rs:262`; default dial deadline 30 s, above the 20 s activation deadline); the ingress gets its own `RouteExecutor` built from the SAME `AdapterRegistry` (it is `Clone`) with `with_direct_guard(IngressDirectGuard)`, `with_address_families(cfg.direct_address_families)`, `with_connect_timeout(cfg.connect_timeout)`, `with_resolve_timeout(min(5 s, connect_timeout))` and a dial deadline of `resolve_timeout + connect_timeout + 5 s`, wrapped in its own `NetcoreDataPlane`. The assembly is ONE library function, `guard::build_ingress_executor(adapters, &IngressCfgView, Arc<dyn DirectAddrGuard>) -> RouteExecutor` (not inline in `main.rs`, which has no unit tests), so that a test can assert what `main.rs` builds: `has_direct_guard()`, `address_families() == cfg.families` and, through `NetcoreDataPlane`, `guards_direct_names()` (23.7). A wiring regression (the guard missing, the family filter left at `any`) therefore fails a test; in draft 2 it would have stayed green. This deviates from draft 1's "the same data plane" on purpose: one executor with a guard would silently change what an operator's `ssk activate --dest name` may reach, which the activation suites pin. Decision and dial still use the same `ConfiguredRouting`/orchestrator; test doubles inject through `IngressDeps.data_plane`.

**`IngressDirectGuard` (daemon, `ingress/guard.rs`)** implements `DirectAddrGuard` over the one `classify_ip` table and `GuardCells`: a `ListenerCell` (an `AtomicU64`, 0 = unset, written by `IngressHost::start` after the bind and cleared on listener death) and a `watch::Receiver<Gate>` that the host sets once, so the guard reads the armed profile from the gate itself and keeps no lifecycle state of its own (L1). `Target` purpose refuses `classify_ip(ip).is_some()` (the codes of the table), the listener address (`listener`) and, when the gate is `Armed{profile}`, any address equal to an entry of that profile's `exact_ip_denials` whose port is absent or equals the dial port (`deny_rule`; the per-profile sets are computed once at start from the hoisted routing); when the gate is not `Armed` it refuses everything (`not_armed`). `FirstHop` purpose refuses only the self-loop. An unset cell refuses everything (fail closed). The `Target` guard has no exemption mechanism by design.

**Refinements made at `C-G1b`.** (1) The listener cell is a `Mutex<Option<SocketAddrV4>>` (poison-tolerant), not an `AtomicU64`: the guard asks once per resolved address, not per byte, and the packing would need casts that the lint set forbids. `GuardCells::set_gate` takes the receiver once (`OnceLock`); a second call returns `false` and changes nothing. (2) Fail closed means: `Target` refuses with `not_armed` when the listener cell is empty, when no gate was handed over, and when the gate is anything but `Armed`; `FirstHop` refuses with `not_armed` only when the listener cell is empty (it answers the loop question and has no use for the gate). (3) Order and labels for `Target`: gate, then the listener (`listener`, before special-use, because a self-loop is also loopback and the more specific label is the useful one), then `classify_ip` (its code), then the armed profile's deny set (`deny_rule`). Every address is unmapped first, so `::ffff:93.184.216.34` meets a deny rule written for `93.184.216.34`. (4) `build_ingress_executor` sets the guard, the families, `connect_timeout`, `resolve_timeout = min(5 s, connect_timeout)` and `dial_deadline = resolve + connect + 5 s`; `ssk-netcore` gained the getters `connect_timeout()`, `dial_deadline()`, `resolve_timeout()` and a public `RESOLVE_TIMEOUT` so that `ingress_executor_builder_installs_guard_and_family_filter` and `the_timeouts_follow_the_configured_connect_timeout` can assert every one of those against the code, which a wiring regression in `main.rs` would otherwise leave green. (5) The doubles of the two netcore seams (`FakeResolver`, `RecordingConnector`) are in `tests/support/net_fakes.rs` and are used here to drive the REAL executor through the REAL guard: a mixed answer is refused as a whole with no connect started for the allowed half, a loopback or metadata answer is refused, an exact-IP deny is applied to a name that resolves to it, a gate that moved to `Disarmed` while the lookup was in flight refuses, `ipv4_only` drops IPv6 answers before anything is dialled, and the unguarded activation executor dials the same loopback answer (which is why there are two executors). The SOCKS5 client and the daemon harness of `C-G8` join that file later.

**Review of `C-G1b` and `C-G7a` (independent, adversarial, findings reproduced) and what was done with each.** (a) HIGH, fixed: the kernel's `tcp6` header says `remote_address`, not `rem_address`; the header check of `C-G7a` rejected every real IPv6-enabled table, which would have made the peer check (and with `hardening: required`, the whole ingress) unavailable on mainstream desktops and was invisible here because this machine has no IPv6. The header is now the exact word list of each table (`HEADER_V4`, `HEADER_V6`), refused on any edit, and a populated `tcp6` table goes through `parse_tables` in a test. (b) MEDIUM, fixed: a guard whose gate sender is gone kept answering "armed"; `has_changed().is_err()` now refuses (the pump already treated the same condition as a gate change). (c) LOW, fixed: an armed profile the guard holds no deny set for (not even an empty one) is refused, not assumed to have no denials. (d) LOW, fixed: `FirstHop` also refuses the classes that are never a proxy (unspecified, this-network, metadata, multicast, broadcast, reserved, discard, dummy prefix); local, LAN, shared-space and link-local proxies stay allowed. (e) Defence in depth, done: a deny rule's own address is unmapped before the comparison; the table parsers split on ASCII white space only; `decide_row` returns `Unknown` at the second distinct row instead of collecting a quadratic list. (f) Test gaps, closed: the header order pairs, a listener port below 0x1000 (`%04X`), a populated tcp6 table, and a deny that an earlier allow for the same address would hide (also in `routing.rs`). The `ip == listener.ip()` arm of the loop test is an equivalent mutant (the listener is always in 127/8) and is kept as documentation. (g) CARRIED to the engine (`C-E2`): the guard asks which profile is armed NOW, not which profile the flow was admitted under, so a re-arm to another profile while a lookup is in flight lets the guard answer with the new profile's denials. The engine's dial is raced against the gate (`7.2` state 6) and a flow of an old epoch is cancelled; the test `a_gate_change_during_the_lookup_cancels_the_dial_and_no_socket_outlives_it` belongs to `C-E2` and must show that no connect survives the change. (h) CARRIED to `C-G7b`: the uid column of the table is translated into the READER's user namespace, so a client of uid 1000 shows as the overflow uid 65534 when the daemon runs in a namespace that does not map 1000; if the daemon's own `getuid()` is then the overflow uid, `decide_row` would say `SameUser` for a stranger. `controls().peer_check` is `false` (reason `IDENTITY_AMBIGUOUS`) when `getuid()` equals `/proc/sys/kernel/overflowuid` or the uid map is not the identity. (i) CARRIED to `C-E1`: with `listen.port == 0` (tests, 5.7) the host must call `GuardCells::set_listener(local_addr)` with the BOUND address, or the first-hop loop test compares against port 0. (j) ACCEPTED: a local user who fills the TCP table past 16 MiB (about 112,000 rows) makes the table `TooLarge` and every request `Unknown` (fails closed; the same user can already flood the port, 7.1).

**Resolution record per flow:** the engine copies `session.resolution()` into the `Result` record: `answers`, `dialed`, `attempted` and the `egress_local` observation; for a failed dial the same fields come from the `DialFailed` wrapper, and a refusal's static label goes to `Result.refusal`. `dialed` and `attempted` are destination information like `host` and follow the same plain/hashed setting (otherwise a Direct-by-name flow leaks the destination in the clear through the pinned address); `local_addr` and the mode are not destination data. A flow refused after resolution is an admitted flow: its `Pending` and `Result{failed, NETCORE_ADDR_REFUSED}` follow the admitted-flow (hashable) rules, and the client sees `02`.

### 6.11 The DNS path: what the OS resolver sees, proxied names, SSRF via the upstream proxy, what is only an observation

**Facts from the code.** (1) Direct names are resolved by this daemon exactly once per admitted flow, in the `sskd` process, through the OS resolver (`getaddrinfo` via `std::net::ToSocketAddrs`), never through a `DnsOverride` adapter: `ConfiguredRouting::new` registers only Socks5/HttpConnect/TlsTunnel adapters (daemon `routing.rs:25-47`; OpenVPN only in the orchestrator), so `dns_protected_for` (`supervisor.rs:437-446`) can only ever be true for a literal destination, and it is evaluated only in `ActivateProfile`. The ingress never sets `dns_protected`. (2) Proxied routes forward the canonical name unresolved: netcore's SOCKS5 client sends ATYP 3 with the name unless it parses as a strict IPv4/IPv6 address, and HTTP CONNECT writes the authority (`socks5.rs encode_address`, `http_connect.rs`). The upstream proxy resolves it. (3) The configured proxy's own host name, when it is a name, is resolved by the OS resolver at every dial (`executor.rs:225`), not forwarded.

**The third-party-tunnel scenario.** Kaleidoscorp applies policy and audit; for `Direct` the OS routing table picks the interface and the OS resolver picks the DNS servers. While the tunnel application is connected, a `Direct` dial from `sskd` follows whatever the OS routing table does for `sskd`'s socket, and the name is looked up through whatever DNS servers the OS selects for `sskd`'s lookup. Kaleidoscorp does not read, set or verify any of that and says nothing about it: it never states that a third-party VPN is up, never states DNS is protected, and the ingress strings contain none of the forbidden words (10.7). Everything below about the third-party application and about Windows resolver behaviour is UNVERIFIED:

* whether the application configures DNS servers on its adapter and whether it blocks DNS to other servers; Windows "smart multi-homed name resolution" may send the query to the DNS servers of every adapter (and so also the physical network's); the NRPT, LLMNR, mDNS and NetBIOS fallbacks for single-label and `.local` names (the reason 6.10 refuses those for Direct);
* whether the application handles IPv6 by disabling or blocking it (the family filter and the race of 6.10 are what keep a blackholed or bypassing IPv6 address from stalling or escaping a dial);
* whether a per-application rule of the tunnel application (split tunnelling) keys on the dialling process: the process that opens the Direct socket is `sskd`, not the browser, so a rule that names the browser does not apply to traffic that went through the proxy;
* that the OS applies its search list to a bare name: the daemon passes the canonical name WITHOUT a trailing dot on purpose (a probe shows that glibc `getaddrinfo` fails for `localhost.` while `localhost` resolves from the hosts file, i.e. a trailing dot would silently disable hosts-file entries); the consequence is that the OS may append a search suffix after the absolute lookup fails, so the dialled host can be a different FQDN than the one policy approved. The answer still passes the special-use guard. Accepted limitation (threat row 18).

What Kaleidoscorp MAY show, labelled as observations and never as a conclusion: the per-flow `local_addr` the OS chose as source address, and which interface the OS selects for a documentation probe address (6.12).

**What the client must do.** A client that resolves names itself and sends an address (SOCKS5 ATYP 1/4) bypasses domain rules entirely: only an IP-literal rule or a catch-all can match it, and under default-deny it is simply denied. Domain rules work only for clients configured to send names to the proxy (SOCKS5 with remote name resolution; which browsers do this by default is UNVERIFIED; observed with curl 8.5.0 on Linux against a loopback stub: `--socks5-hostname` sends the name, ATYP 3; `--socks5` sends the locally resolved address, ATYP 1). Denial records carry `target_kind` (`ipv4|ipv6|name`) so the UI can say "the client sent an address, not a name". The documented client setting for M2 is "configure remote DNS in the client" (open question B8).

**Deny rules and the directions a client can send.** (1) A client that sends a NAME is matched by name rules before resolution; after the single resolution every answer is also compared with the exact-IP `deny` rules of the armed profile (6.10 step 5), so a deny rule written for an address cannot be sidestepped by sending a name that resolves to it. Draft 2 lacked this direction: `MatchCriteria` compares an IP rule with a name flow as text and never finds them equal (`policy.rs:91-104`), and the executor applied only the special-use guard after resolution. (2) A client that sends an ADDRESS is matched by IP and catch-all rules only; a domain rule, allow or deny, never sees it (above). That direction cannot be closed locally: the daemon would have to reverse-resolve an address into names it cannot know. (3) Rules never apply across names that happen to share an address. The acceptance criterion "deny prevents arrival" (24.1) is stated accordingly.

**SSRF via the upstream proxy (statement for section 16).** A proxied route forwards the canonical name or literal to the upstream proxy, which resolves and dials it from ITS network position. Kaleidoscorp cannot see what an upstream resolves a name to, so name-based access to the upstream's internal network (names that resolve to private, link-local or metadata addresses on the upstream side) cannot be prevented locally. What limits it: default-deny (only destinations matched by an explicit rule are forwarded; a suffix or catch-all rule forwards everything under it, so write them narrowly); literal special-use targets are refused for EVERY route kind unless an exact host-and-port rule names them (6.2); numeric aliases and `localhost` are refused for every route kind, so the upstream is never handed `2130706433` or `127.1` to interpret; configs carry no upstream credentials. The upstream is operator-trusted; a malicious or misconfigured one remains out of scope.

### 6.12 `ingress/path.rs`: observing the operating system's path decision

Purpose: give status something TRUE to say about the path without claiming anything about third-party software (10.5). Everything here is read-only, sends no packet and feeds status only (CO-8). The pure part below was compiled, unit-tested and run through `clippy -D warnings` on Linux with the pinned toolchain (1.95.0) in a scratch crate; it is not yet in the workspace. Its test data are the real `/proc/net/route` lines of the machine it was written on plus a split-default table (two `/1` routes through a tunnel-shaped interface and a lower-metric `/0` through a physical-shaped one), which shows why the lookup must be a best-route lookup of a probe destination and not "find the `0.0.0.0/0` row": with split routes that row is not the one the OS uses. For the same reason nothing built on the lookup may be called "the default route" or be read as the route of any real destination: exclusion routes and per-application steering can send a real destination elsewhere than the probe address (10.6, item 9).

```rust
// crates/ssk-daemon/src/ingress/path.rs   (pure; no unsafe)
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const PROBE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);                      // RFC 5737 TEST-NET-1: never a real host
pub const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);  // RFC 3849 documentation prefix
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);          // same value as killswitch::DEFAULT_REFRESH_INTERVAL
pub const MAX_AGE: Duration = Duration::from_secs(15);               // same value as killswitch::DEFAULT_MAX_AGE
pub const CHANGE_NOTICE_WINDOW: Duration = Duration::from_secs(600);
pub const ALIAS_MAX_CHARS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteObservation { pub interface_index: Option<u32>, pub interface_alias: Option<String>, pub route_metric: u32 }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveError { Unsupported, NoRoute, LookupFailed(u32), Malformed }

pub trait PathObserver: Send + Sync + 'static {
    /// Blocking lookup in the local routing table; sends no packet. Called from spawn_blocking, never under a lock.
    fn best_route(&self, probe: IpAddr) -> Result<RouteObservation, ObserveError>;
}

/// OS-supplied text is data: control characters dropped, length bounded, never placed inside a sentence.
pub fn sanitise_alias(raw: &str) -> String {
    raw.chars().filter(|c| !c.is_control()).take(ALIAS_MAX_CHARS).collect()
}

// ---- Linux: /proc/net/route, IPv4 only ----
pub const RTF_UP: u16 = 0x0001;
pub const RTF_REJECT: u16 = 0x0200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRow { pub iface: String, pub destination: Ipv4Addr, pub flags: u16, pub metric: u32, pub mask: Ipv4Addr }

fn hex_addr(field: &str) -> Option<Ipv4Addr> {
    if field.len() != 8 { return None; }
    // The kernel prints the network-order word with %08X, so the text is host-endian.
    Some(Ipv4Addr::from(u32::from_str_radix(field, 16).ok()?.to_ne_bytes()))
}

pub fn parse_proc_net_route(text: &str) -> Result<Vec<RouteRow>, ObserveError> {
    let mut lines = text.lines();
    if !lines.next().is_some_and(|h| h.starts_with('I')) { return Err(ObserveError::Malformed); }
    let mut rows = Vec::new();
    for line in lines.filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let row = (|| {
            Some(RouteRow {
                iface: f.first()?.to_string(),
                destination: hex_addr(f.get(1)?)?,
                flags: u16::from_str_radix(f.get(3)?, 16).ok()?,
                metric: f.get(6)?.parse().ok()?,
                mask: hex_addr(f.get(7)?)?,
            })
        })();
        rows.push(row.ok_or(ObserveError::Malformed)?);
    }
    Ok(rows)
}

fn prefix_len(mask: Ipv4Addr) -> Option<u32> {
    let m = u32::from(mask);
    let ones = m.leading_ones();
    (m.checked_shl(ones).unwrap_or(0) == 0).then_some(ones)
}

/// Longest prefix wins, then the lowest metric. Rows that are down or rejecting are ignored.
pub fn best_route_v4(rows: &[RouteRow], dest: Ipv4Addr) -> Option<&RouteRow> {
    rows.iter()
        .filter(|r| r.flags & RTF_UP != 0 && r.flags & RTF_REJECT == 0)
        .filter_map(|r| {
            let m = u32::from(r.mask);
            (u32::from(dest) & m == u32::from(r.destination) & m).then_some((prefix_len(r.mask)?, r))
        })
        .max_by(|(la, a), (lb, b)| la.cmp(lb).then(b.metric.cmp(&a.metric)))
        .map(|(_, r)| r)
}

pub struct ProcNetRoute;
impl PathObserver for ProcNetRoute {
    fn best_route(&self, probe: IpAddr) -> Result<RouteObservation, ObserveError> {
        let IpAddr::V4(dest) = probe else { return Err(ObserveError::Unsupported) };
        let text = std::fs::read_to_string("/proc/net/route").map_err(|e| {
            ObserveError::LookupFailed(e.raw_os_error().and_then(|c| u32::try_from(c).ok()).unwrap_or(0))
        })?;
        let rows = parse_proc_net_route(&text)?;
        let best = best_route_v4(&rows, dest).ok_or(ObserveError::NoRoute)?;
        Ok(RouteObservation { interface_index: None, interface_alias: Some(sanitise_alias(&best.iface)), route_metric: best.metric })
    }
}
```

Linux reports IPv6 as `Unsupported` in M2: `/proc/net/ipv6_route` does not exist on the review machine (no IPv6), so its layout is unverified and no parser is specified. Other Unix targets report `Unsupported` for both families. The default observer is chosen by `cfg`: Linux `ProcNetRoute`, Windows the adapter below, otherwise an observer that always answers `Unsupported`.

**Windows (`C-CO6w`), `crates/ssk-winhost/src/route_observe.rs` (unsafe allowed there).** It needs one new feature in `ssk-winhost/Cargo.toml`, `Win32_NetworkManagement_Ndis`: `MIB_IPFORWARD_ROW2` is `cfg`-gated on it and on `Win32_Networking_WinSock` (`windows-sys-0.59.0/src/Windows/Win32/NetworkManagement/IpHelper/mod.rs:1814`); the other features are already enabled (`Cargo.toml:63-66`). The function below compiled and passed `clippy -D warnings` for `x86_64-pc-windows-gnu` in a scratch crate and has never run; that `GetBestRoute2` is a pure table lookup that sends nothing is documented behaviour, UNVERIFIED here.

```rust
use std::net::IpAddr;
use windows_sys::Win32::Foundation::NO_ERROR;
use windows_sys::Win32::NetworkManagement::IpHelper::{ConvertInterfaceLuidToAlias, GetBestRoute2, MIB_IPFORWARD_ROW2};
use windows_sys::Win32::NetworkManagement::Ndis::IF_MAX_STRING_SIZE;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

pub struct BestRoute { pub interface_index: u32, pub interface_alias: Option<String>, pub route_metric: u32 }
pub struct ObserveError { pub win32: u32 }

pub fn best_route(probe: IpAddr) -> Result<BestRoute, ObserveError> {
    // SAFETY: plain C data zero-initialised before use; every pointer refers to a live local for the call.
    unsafe {
        let mut dest: SOCKADDR_INET = std::mem::zeroed();
        match probe {
            IpAddr::V4(v4) => { dest.Ipv4.sin_family = AF_INET; dest.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets()); }
            IpAddr::V6(v6) => { dest.Ipv6.sin6_family = AF_INET6; dest.Ipv6.sin6_addr.u.Byte = v6.octets(); }
        }
        let mut route: MIB_IPFORWARD_ROW2 = std::mem::zeroed();
        let mut best_source: SOCKADDR_INET = std::mem::zeroed();
        let rc = GetBestRoute2(std::ptr::null(), 0, std::ptr::null(), &dest, 0, &mut route, &mut best_source);
        if rc != NO_ERROR { return Err(ObserveError { win32: rc }); }
        let mut alias = [0u16; IF_MAX_STRING_SIZE as usize + 1];
        let rc = ConvertInterfaceLuidToAlias(&route.InterfaceLuid, alias.as_mut_ptr(), alias.len());
        let interface_alias = (rc == NO_ERROR).then(|| {
            let end = alias.iter().position(|&c| c == 0).unwrap_or(alias.len());
            String::from_utf16_lossy(&alias[..end])
        });
        Ok(BestRoute { interface_index: route.InterfaceIndex, interface_alias, route_metric: route.Metric })
    }
}
```

The daemon holds a small `#[cfg(windows)]` adapter implementing `PathObserver` over this function (a nonzero Win32 code becomes `LookupFailed(code)`; the "network unreachable" codes become `NoRoute` through a table that a Windows test pins). It is the only reference to `ssk_winhost` under `src/ingress/`.

**Refinements made at `C-CO3`.** (1) The state the watcher keeps per probe address is a pure type in `path.rs` (`PathSlot::record(now, outcome)` and `view(now) -> PathView`), so the "previous interface", the 15 s staleness and the failure rules are tested with explicit `Instant`s and the poller of `C-E1` is a loop around it. The identity of an observation is (index, alias); a change of the metric alone is not a change of path. A failed lookup never erases the last good observation; a later success clears the failure. (2) `observe_v4(text, dest)` is the pure part of the Linux observer (`ProcNetRoute` only reads the file), so the alias sanitising is tested with a hostile interface name. (3) `sanitise_alias` also drops the invisible characters that `char::is_control` does not (bidirectional controls, zero-width characters, U+2028/2029, the byte order mark): an interface name is chosen by whoever installed the adapter. (4) A parse error is an error, never an empty answer, and a table over 4 MiB is not parsed. (5) The source scan for the never-claim vocabulary (10.6, item 3) lives in `ingress/mod.rs` (`vocabulary_scan`): it extracts the string literals of `path.rs`, skipping comments, and fails on any of the quoted words as a case-insensitive substring; the snapshot builder joins it when it exists (`C-E1`). Test data in `path.rs` therefore names interfaces `dev0` and `dev1`, not after what they might be. (6) The golden table lines are this sandbox's real `/proc/net/route` (a default route and an on-link /24); the split-default table is synthetic and says so.

**The watcher.** `IngressHost` owns one `PathWatcher` task, started when the state first becomes `disarmed` (a listener is bound; 6.9.4 step 7) and aborted first at shutdown, before the audit writer closes (an in-flight blocking lookup finishes and is discarded, as with the kill-switch poller, `ssk-daemon/src/main.rs:214`). Every `POLL_INTERVAL` it looks up `PROBE_V4` and `PROBE_V6` on `spawn_blocking` and stores per family: the last good observation, when it was sampled, when its identity (index, alias) was first seen, `previous = (identity, replaced_at)`, and the last failure kind. `previous` changes only when two successful samples differ; a failed lookup never erases the last good observation and is shown as `failed` or `no_route` with its age. `snapshot()` (6.9) reads the slots under a short std mutex: no lookup and no I/O on the status path. A sample older than `MAX_AGE` is rendered `stale`, mirroring the kill-switch view's 15 s rule (`killswitch.rs:88`). All time arithmetic uses `Instant::saturating_duration_since`; `Instant`s are never subtracted with `-` (overflow checks are on in release).

**Per-flow source address.** The `egress_local` observation of a flow is `session.resolution()`'s `local_addr` (6.10): `TcpStream::local_addr()` of the Direct socket or of the first hop. The engine copies it into the `Result` record (kind `egress_local`) and into `FlowSummaryDto.egress_local`; the latest successful one is `last_direct_source` (10.5; kind `first_hop` for a proxy route).

## 7. The per-connection pipeline

### 7.1 Accept loop (single task; flow tasks live in its `JoinSet`)

```rust
let mut set: JoinSet<()> = JoinSet::new();
let mut retry = AcceptBackoff::new();                  // pure: 50 ms doubling to 1 s; give-up threshold 100 (a trip, not an exit)
let mut resume_at: Option<tokio::time::Instant> = None;   // the pause is a select arm, not an inline sleep
loop {
    tokio::select! {
        biased;
        _ = gate_closing(&mut gate_rx) => break,                           // Closing: stop and drop the listener
        joined = set.join_next(), if !set.is_empty() => account(joined),   // a panic counts toward the budget; is_cancelled does not
        _ = sleep_until(resume_at.unwrap_or_else(tokio::time::Instant::now)), if resume_at.is_some() => { resume_at = None; }
        _ = summary_tick.tick() => emit_summaries(),
        accepted = listener.accept(), if resume_at.is_none() => match accepted {
            Ok((sock, peer)) => { retry.on_success(); admit(sock, peer); }
            Err(e) => {
                counters.accept_errors.fetch_add(1, Relaxed);
                match retry.on_error() {
                    Some(delay) => resume_at = tokio::time::Instant::now().checked_add(delay),
                    None => { shared.trip(TripReason::AcceptFatal); break; }   // the 100th consecutive error
                }
            }
        },
    }
}
```

(Schematic and uncompiled. A disabled `select!` branch still evaluates its expression but never polls it, which is why `unwrap_or_else` is enough here and no `unwrap` is needed in this tree, L12.) Because the pause is an arm, flow panics are still accounted and shutdown is still observed while the loop backs off, which an inline `sleep(delay).await` of up to 1 s would delay. Nothing in this loop can end `run_server` or the daemon (8.6); `AcceptFatal` trips the gate, which a re-arm recovers.

**Flow panics.** `account` calls `shared.note_flow_panic()`: using atomics only (it never takes `control`), it increments the count and, at `panic_budget` = 3 since the last start or recover, calls `trip(FlowPanicBudget)`. A `JoinError` for a task aborted by `abort_all` is `is_cancelled()` and is not counted. RAII guards release the permit and the registry row on unwind.

**Flow guard.** Each flow task owns a `FlowGuard { registry row, permit, phase, counters }` and the receipts it has been given. Its `Drop` is synchronous and never awaits: it finalises the registry row and drops the receipts, and an unresolved receipt writes its own compensating record through the writer's unbounded channel (6.4.4): a pending receipt becomes `Result{NotDialed}` or `Result{Aborted}`, an unconsumed result receipt becomes `Closed{aborted}` with the counted bytes. A job that was handed to the writer queue but whose acknowledgement has not returned is covered by the caller-side job state machine (6.4.6). This is what lets a flow that is aborted after the drain budget, or cancelled by a trip, still leave its `Closed` record (a `Drop` cannot await; it can enqueue). If the queue is full the loss is counted in `audit_close_lost`. Both kinds of record travel the same FIFO to the single writer, so the terminal record can never precede its `pending`.

For each accepted socket, in this order (steps 1 to 4 run **before any byte is read**, step 5 reads while the socket holds a pre-admission slot only, and the shared budgets are charged **after** the handshake, step 6; draft 2 charged them before it):

1. The gate (a lock-free `borrow()`) must be `Armed`; otherwise drop the socket (`refused_disarmed`). The profile and epoch the flow will run under are taken from this same borrow.
2. `peer_addr()` is loopback IPv4 and `local_addr()` equals the bound address; otherwise drop.
3. `PeerBudget::try_start`: its own cheap token bucket (256 burst, 1024 per second) and a pre-admission slot. The 64 slots (`pre_admission_slots`) cover every socket from here until its handshake is complete, the peer check and the handshake alike. When all are taken, the oldest slot whose request is still incomplete and that is at least `handshake_evict_after` = 1 s old is cancelled (its socket closes with zero bytes, counted `evicted_handshake`) and the newcomer takes its slot; if no slot is that old, drop (`refused_peer_budget`).
4. Spawn an admission task: `authorize()` through the `PeerTableService` under `peer_timeout` (`SameUser`, or `best_effort` with no peer control -> continue with `peer_verified = false`; otherwise drop, `refused_peer`).
5. Handshake: `negotiate` and `read_connect` under `handshake_timeout`, then `canonicalize` and `guard_self_loop` (7.2 states 2 and 3). The socket still holds only its pre-admission slot: no flow permit, no accept token, no ledger record. A complete, valid request ends the slot's eviction eligibility (`request_complete`).
6. **Only now** charge the shared budgets: `accept_bucket.try_take` (otherwise drop, `refused_rate`), then a flow permit: `try_acquire_owned`; if none is free, wait at most `capacity_wait` = 250 ms for one, with at most `capacity_wait_room` = 8 sockets waiting at the same time (a ninth is dropped at once). Otherwise drop (`refused_capacity`). The semaphore holds `effective_max_connections` permits (7.3), never the configured number. With `C-E5`, a socket that finds no permit first closes the longest-idle tunnel idle for at least 30 s (at most one per arrival) and takes its permit. A socket that waits for a permit leaves the 64-slot count and enters the waiting count of 7.3 (its descriptor is never in both).
7. Run the flow (`decide`, `Pending`, dial, ...: states 4 to 10 of 7.2).

A different local user therefore spends only the cheap, separate pre-admission budget; it cannot drain the accept bucket, the permits, the ledger or any daemon state. It can fill the 64 slots for as long as its sockets are not evictable, and so can any client that is allowed to connect: a connector of the same user (or, on Windows `best_effort`, of any account) that opens connections and sends nothing holds slots, never permits or tokens, and its oldest silent sockets are evicted by the next newcomer after one second (test `silent_connections_do_not_prevent_an_authorised_handshake`). In draft 2 such a connector held every one of the 256 permits for up to `handshake_timeout` and, with 50 tokens per second refilling against 256 permits held for 10 s, kept the accept bucket empty, so every legitimate client waited 250 ms for a permit and was dropped. The loop is not paused at capacity: accepting and closing costs at most one transient descriptor, which the budget includes (7.3), and a paused loop would leave clients hanging in the kernel backlog instead of failing fast. What no design can promise is availability of a loopback port against a hostile local user who opens connections faster than the pre-admission stage sheds them; the notice and RUNBOOK say so.

### 7.2 State machine

| # | State | Does | Deadline | Client sees on failure | Audit | Counter / gate |
|---|---|---|---|---|---|---|
| 0 | Accepted | steps 1-3 of 7.1 | - | close, zero bytes | none | refused_* |
| 1 | PeerChecked | step 4 of 7.1 | 500 ms | close, zero bytes | none (Summary) | refused_peer |
| 2 | Handshake | `negotiate` + `read_connect` (holds a pre-admission slot only; evictable after 1 s when the slots run out) | handshake_timeout | violation: silent close; `FF`/`07`/`08` replies per 6.3 | none per flow; counted `malformed` | malformed |
| 3 | Targeted | `canonicalize` (`RawTarget` -> `Target`), `guard_self_loop` | - | malformed / numeric alias / localhost: `08` and close; self-loop: `02` | rejected input: counted only, per kind; self-loop: coalesced `Denied` | rejected_target.* / denied |
| 3b | Budgeted | accept token and flow permit (step 6 of 7.1) | 250 ms capacity wait | close, zero bytes | none (Summary) | refused_rate / refused_capacity |
| 4 | Decided | mint flow id `ingress:b<boot>:<n>`; `engine::decide` (policy, special-use, route guard, admit) | - | Guard class (special-use, name eligibility): `02`; Route class (OpenVPN, not dialable, missing guard): `01`; `DIRECT_FAMILY_DISABLED`: `08` (6.7.1) | `DenialCoalescer`: first occurrence **durable before the reply** while inside the segment's refusal quota, repeats counted into `Summary` | denied |
| 5 | **PendingDurable** | `append_pending(adm.pending_input(..))` awaited; token dropped unused on error | 2 s queue + 5 s sync | `01`, no dial | `Pending` (or nothing: cancelled in queue) | Busy, QueueFull, Timeout, Capacity: counters only, no trip; Io, WriterDown, SeqExhausted: the gate is already tripped |
| 6 | Dialing | gate re-check; `connect_route` (for a Direct name: resolve once, guard, filter, race, 6.10) under `connect_timeout`, raced with the gate | connect_timeout | see 7 | - | - |
| 7 | **ResultDurable** | `append_connected` or `append_failed` awaited. Dial error: reply (`05` refused, `04` timeout, `01` other, `02` address refused, `04` DNS or family failure) then close, never re-dial. Result write error: `drop(session)` first, then close the client | 2 s queue + 5 s sync | mapped reply, or silent close on a durability failure | `Result` (`Connected`, `Failed`; `NotDialed` or `Aborted` by compensation) | connect_failed / audit counters; Io trips |
| 8 | Replied | gate re-check; `write_success(&ResultReceipt)` | - | `05 00 00 01 00*6` | - | admitted |
| 9 | Pumping | `pump(...)` | idle_timeout | EOF/reset when torn down | - | active gauge |
| 10 | Closed | `ResultReceipt::closed(ev)` bounded; an unconsumed receipt compensates on drop; registry final; permit released | `closed_deadline` 1 s | - | `Closed` (loss counted, never trips) | bytes totals |

Notes: (a) the denial path no longer uses a fire-and-forget queue: a client that sees a refusal for a fresh key inside the quota has a durable record, so the Deny acceptance test can assert the ledger immediately after the reply with no polling; only repeats within the window, denials beyond the bucket (1/s, burst 20) and denials beyond the segment's refusal quota are folded into `Summary` records, and the status counters reconcile exactly. (b) `NetcoreError` is mapped coarsely; upstream detail, adapter addresses and `HopSpec.auth` never reach the client, logs above DEBUG, status or IPC errors. (c) A flow whose gate epoch changed at any point is torn down with `Closed.reason = gate_closed`. (d) Per-flow tasks are never attached to `Supervisor::spawn_supervised` / `record_task_failure`.

### 7.3 Resource budget: file descriptors, blocking threads, capacity

Descriptors are a per-process limit (`RLIMIT_NOFILE`, Unix). The ingress must not be able to use the descriptors the IPC server and the daemon itself need, because an IPC `accept()` that fails 60 consecutive times ends the daemon (8.6).

**Measured here** (debug build, Linux 6.18, this sandbox; not CI, not a release build): an idle `sskd` holds 12 descriptors (stdio 3, lock file, log file, 2 epoll, 1 eventfd, 3 sockets). With 16 IPC clients connected it holds 28. With 40 clients it holds 29: the accept loop has accepted a 17th connection and is waiting for a permit, because `serve_unix_with_limits` takes the permit after `accept()` (`server.rs:280-283`). So the IPC server costs at most `ServeLimits::default().max_connections + 1` = 17 descriptors (`server.rs:90`).

**Budget** (derived by arithmetic from the components below; only `FD_RESERVE` is backed by the measurement above; the rest is a bound by construction, not a measurement):

| Item | Descriptors |
|---|---|
| process baseline plus a saturated IPC server (`FD_RESERVE` = 64; measured maximum 29, margin about 2.2x for `audit.json`, crash records and a second log file at rotation) | 64 |
| each open tunnel (client socket + upstream socket) | 2 x `effective_max_connections` |
| pre-admission sockets (peer check or handshake, `pre_admission_slots` = 64) plus the peer service's table reads (`tcp`, `tcp6`) | 66 |
| in-flight name resolutions (`MAX_CONCURRENT_LOOKUPS` = 16; each up to 3: UDP socket, hosts file, resolver configuration) | 48 |
| extra racing dial attempts (`DIAL_EXTRA_PERMITS` = 64, 6.10) | 64 |
| sockets waiting for a permit (`capacity_wait_room` = 8) | 8 |
| listener 1, shed-and-close transient 1, ledger (directory fd, active segment, next segment during rotation, state-root fd at open) 4 | 6 |
| **fixed total including the reserve** | **256** |

```
fd_needed(m)                = 256 + 2 * m
effective_max_connections   = min(configured, floor((soft - 256) / 2))
unavailable(INGRESS_FD_LIMIT_TOO_LOW) when effective_max_connections < 8   (soft < 272)
```

Examples: soft 1024 -> 384 (the default of 256 fits and needs 768); soft 4096 -> 1920; soft 20000 -> the configured value; soft 271 -> unavailable. A platform whose soft default is 256 (macOS) is therefore unavailable until the limit is raised; macOS is not a supported target of M2 and no automatic raise is part of it (MD-2; an OPT later). On Windows there is no `RLIMIT_NOFILE`; the function receives `None` and returns the configured value (UNVERIFIED that Windows handle limits never bind). (This table supersedes the lifecycle theme's 116-descriptor figure, which assumed 8 in-flight peer checks, 8 resolver slots and no racing dials; the merge raised those three components, 64, 16 and 64, see 19.2.)

`fd_budget(soft: Option<u64>, configured: u32) -> FdBudget { effective_max_connections, needed, soft, clamped }` is pure and table-tested. The only syscall is `rustix::process::getrlimit(Resource::Nofile)` (feature `process`, present in the locked rustix 0.38.44, safe API, so `unsafe_code = forbid` holds). The soft limit is not raised (no `setrlimit`): the daemon adapts to its limit instead of changing process-wide state. `RunDoctor` reports `ingress:fd_budget` (a failure when configured and effective differ) with these numbers; the status block carries `limits` (10.4).

**Refinements made at `C-L4`.** (1) The refusal is a property of the limit, not of the configured value: `FdBudget.too_low` is `floor((soft - 256) / 2) < 8`, so `max_connections: 4` on a machine with plenty of descriptors is served with 4, where reading "`effective_max_connections < 8`" literally would have made it unavailable. (2) `FdBudget` also carries `configured` and `clamped`; `needed` is the figure for the CONFIGURED value, which is what the doctor line has to explain ("needs 768, the limit is 400"). (3) `ResolvedLimits` lives in `budget.rs`, next to the `FdBudget` it holds, not in `types.rs`. (4) The components of the 256 are tied to the code that spends them: `MAX_CONCURRENT_LOOKUPS` (now a public constant of `ssk-netcore`), `DIAL_EXTRA_PERMITS`, `Tuning::pre_admission_slots` and `Tuning::capacity_wait_room` are compared with the budget by `fixed_total_is_the_sum_of_components_that_come_from_the_code`, so raising one of them fails a test until the budget is revisited. (5) `tests/fd_baseline.rs` re-measures the reserve against the real `sskd` (idle 12, saturated 29 on this kernel) and fails if the daemon never reached the saturated state, so a too-gentle load cannot make it pass.

**Capacity.** The permit semaphore holds `effective_max_connections`. At capacity a socket waits at most 250 ms for a permit (7.1 step 5). The accept loop is not paused: with the inequality above, `accept()` cannot hit EMFILE because of the ingress, and a paused loop would leave clients hanging in the kernel backlog instead of failing fast.

**Blocking pool.** Tokio's default is 512 blocking threads. Known users: kill-switch poller 1 (Windows), resolutions 16, ledger open or verify 1, doctor verification 1, path observer 1 (every 5 s): at most 20. (The peer check is a dedicated thread and uses none.) A cancelled dial does not cancel `getaddrinfo` (it runs inside `TcpStream::connect((host, port))` on the blocking pool: `direct.rs:25` and `tokio-1.53.1/src/net/addr.rs:182`), so the resolver permit is released by the blocking closure itself, not by the dial future (6.10, rule 12).

**Fairness.** Without process attribution (`local-proxy:unattributed`) there is no per-application fairness: one runaway application can take every permit. Accepted limitation; the capacity wait, the idle timeout and (`C-E5`) idle eviction bound the effect, and the status shows `active_flows` against `effective_max_connections` (5.10).

## 8. Lifecycle

### 8.1 Start

`main.rs` builds `ConfiguredRouting` and the data planes once (12.1), creates `Shutdown`, builds `Supervisor` (which builds `IngressShared` and keeps a clone of the event sender), and calls `IngressHost::start`, which returns at once and runs the start task of 6.9.4 in the background. IPC is connectable while the ingress is `starting`; an arm answers `INGRESS_STARTING` (retriable) until the state is `disarmed`. A configuration that fails validation gives `unavailable(CONFIG_INVALID)` (the existing code, `supervisor.rs:298`) and no listener (the daemon itself is `ConfigInvalid`).

### 8.2 Arm

`SetIngress { armed: true }` (the profile is `routing.default_profile`, or an explicit `profile_id` of the CLI, whose shape and membership are checked by the existing `validate_profile_id`, `supervisor.rs:483`; a rejected id writes no ledger record and emits a Warning event, as `ActivateProfile` does) or `arm_on_start`. The algorithm and its ordering against disarm, trip and recover are 6.9.2. Arming the armed profile is a no-op (no record, no epoch change). Armed state is never persisted: a restart is `disarmed` unless `arm_on_start` is configured.

### 8.3 Disarm and what it guarantees

`SetIngress { armed: false }` and `Deactivate` call `disarm`. The gate narrows first (it cannot fail and waits for no lock); the record and the event follow. **What is guaranteed once `disarm` has returned**, stated so that no status text reads more into it:

* the accept loop admits nothing new;
* a flow admitted earlier is torn down when it next polls the gate (sub-millisecond on an idle runtime; not measured under load);
* no SOCKS success reply is started and no new client byte is read for a flow whose epoch no longer matches at its next gate check (a reply or a read that is already past its check when the gate is written can still complete);
* data already inside the 16 KiB copy buffers or the kernel at the instant of the gate write may still be delivered (at most one buffer per direction per flow);
* a dial that was already in flight may already have sent one TCP SYN to the next hop before the dial future is dropped.

It does not promise that no byte is in transit at that instant, and the status never says it does.

`Deactivate` disarms first, before its `KILL_SWITCH_ARMED` check, because disarming only narrows what is forwarded. Its answer in every case is fixed in 11.5. `ssk ingress disarm` is the ingress-only verb; its effect never needs `Inner` (only the status it prints does, bounded as in 10.3).

### 8.4 Trip and recover

What trips and what does not is the table in 6.1.3. A trip sets the gate to `tripped`, cancels every flow (the epoch changes), leaves the listener bound unless it is the thing that died (it refuses with zero bytes) and sets `retry_hint = 're-arm to recover'`. An arm from `tripped`, or from a recoverable `unavailable`, runs `recover` first (6.9.2): the previous writer is closed and joined, the ledger is re-opened and verified in `spawn_blocking` (deadline 60 s, single-flight), the listener is bound again only if it is absent or dead, the panic counter is reset, and nothing is installed unless every step succeeded. A hostile local user therefore cannot cause a state that only a restart clears, except the non-recoverable `unavailable` codes (configuration, hardening, descriptor limit), which are properties of the process and are reported as such, and a stalled writer thread (`INGRESS_AUDIT_STALLED`, 6.4.6).

### 8.5 Shutdown plan

Shutdown is one pure plan, `ShutdownPlan::for_reason(reason)`, chosen by `ShutdownReason::is_os_deadline()` (`shutdown.rs:61-70`) and executed in this order. `main.rs::DRAIN_DEADLINE` (2 s; today a `timeout(DRAIN_DEADLINE, yield_now())` that waits for nothing, `main.rs:322`) and the former `Tuning.drain` (3 s) are both removed: this table is the only source of these numbers.

| Phase | Graceful (CtrlC, CtrlBreak, SigTerm, ServiceStop, ServerError) | OS deadline (ConsoleClose, Logoff, SystemShutdown, ServicePreshutdown) |
|---|---|---|
| P0 gate -> `Closing`, listener dropped, no new flow; `PathWatcher` aborted | immediate | immediate |
| P1 flows cancel themselves; `JoinSet` drained, then `abort_all` | 700 ms | 0 ms (abort at once) |
| P2 audit queue drained (including compensation records of aborted flows), final sync, writer thread joined (`close(&self)`) | 1200 ms | 600 ms |
| P3 IPC accept loop | already dropped by the `select!` in `serve` | same |
| P4 `runtime.shutdown_timeout` (drops every remaining task; blocking tasks are not waited for beyond the bound) | 1000 ms | 200 ms |
| **worst case** | **2.9 s** | **0.8 s** |

Rules:

1. `Closed` and terminal `Result` records of aborted flows are written by the receipts' drop-time compensation (6.4.4), so a flow aborted in P1 still leaves its record when the queue has room (losses counted as `audit_close_lost`). The host finishes `abort_all` and joins the aborted tasks before it calls `audit.close()`.
2. **The daemon lock is not dropped early.** `run()` calls `runtime.shutdown_timeout(plan.runtime_stop)` and then `DaemonLock::hold_until_exit()` in place of `drop(lock)` (`main.rs:164`): the handle stays open until the process ends and the kernel releases it. `shutdown_timeout` returns `()`, and when it times out "spawned work that did not stop in time and threads running it are leaked ... the work continues to run" (`tokio-1.53.1/src/runtime/runtime.rs:32-50`); a blocking task (name resolution, ledger open or verification) or the audit writer thread could otherwise write after a second daemon has taken the lock and corrupt the chain. Today the same hazard exists for activation tasks, because `drop(lock)` runs before the runtime is dropped at the end of `run()`. The cost is that a restart waits for process exit, which `--lock-wait` already covers.
3. A legacy activation that is mid-dial when P4 drops its task is settled by `ActivationScope` (12.4): terminal `FailClosed` record and state, not a dangling `DispatchPending`.
4. The OS budgets are not known from this repository (`shutdown.rs` says only "roughly `HungAppTimeout`" for `CTRL_CLOSE_EVENT` and `WaitToKillServiceTimeout` for services); the 0.8 s plan is small against any plausible value and is UNVERIFIED on Windows. The final `drop(guard)` log flush in `main` (`main.rs:99`) runs after the plan and is not measured.
5. Nothing in this repository triggers `ServicePreshutdown` or `ServiceStop`: the only caller of `Shutdown::trigger` is `spawn_os_signal_listener`, and `sskd` is not hosted as a service here (`ssk-svc` hosts the privileged broker). If it is hosted later, PRESHUTDOWN maps to `ServicePreshutdown` and gets the 0.8 s plan; the audit writer is joined in P2 and the lock is held to exit, so no ordering change is needed.
6. Measured: today a SIGTERM to an idle `sskd`, or to one with 16 IPC clients, exits in 3-5 ms. With the ingress disabled the plan adds nothing.

### 8.6 What can end the daemon (replaces draft 1's "nothing in the ingress can end `run_server` or the daemon")

* The ingress cannot end it by its own faults: accept failures, flow panics, audit failures, control-task panics and listener death only move the gate.
* The daemon exits when `serve_unix_with_limits` returns an error, which happens on the 60th consecutive failed `accept()` (`AcceptRetry::GIVE_UP_AFTER`, `server.rs:173`; about 55 s of backoff; `main.rs` maps it to `EXIT_SERVER`, `main.rs:333-343`). This is kept on purpose: an armed proxy that nobody can disarm or inspect is worse than a stopped one. It is a last resort for faults the budget does not model (a descriptor leak, a broken listener), not an ingress fault path. The descriptor budget (7.3) is what prevents the ingress from causing it; commit `C-I1b` adds the missing regression tests of the wiring (59 failures then success keeps serving; the 60th returns `IPC_ACCEPT_FAILED`).
* On Windows the named-pipe loop returns on the first `connect()` or `create_instance` error (`server.rs:429-432, 460`); the earlier fix attempt was reverted (C.3). Until `C-I1w` lands and is verified on Windows, a single pipe error ends `sskd` there. Accepted limitation (26). `privileged.rs` (SYSTEM control-pipe listener) has the same shape; it is outside the ingress and unchanged by M2.
* Shutdown signals, startup failures and a panic on the main thread end it as today.

### 8.7 Configuration changes

`sskd` reads its configuration once (`load_daemon_config`, `main.rs:246`) and compiles it once; there is no reload in M2. Any edit (rules, adapters, the `ingress` section) takes effect only after a restart, and a restart is a new boot: `disarmed` unless `arm_on_start` is set. The RUNBOOK says so in those words, and the `Started` record plus the status `epoch` make a restart visible. An OPT doctor advisory `ingress:config_drift` (digest of the file at start against now) may be added; it never changes behaviour.

### 8.8 Decoupling from activation

A failed `ssk activate` probe (`FailClosed`) does not stop the proxy, and a proxy fault does not change `DaemonState`. The two share the planner (`ConfiguredRouting`), the adapter registry and the kill-switch view and nothing else (the activation executor and the ingress executor are separate objects, 6.10); no lock is held across both (L5). Rationale as in section 19.

## 9. Audit semantics (summary)

* Order: `Pending` durable before the dial; `Result{Connected}` durable before the success reply and before any byte; `Closed` after, best effort but never lost silently (loss is counted; an unconsumed receipt compensates). Audit failure before the dial means no dial. Audit failure after a connect means the upstream is dropped before any reply. The ordering is enforced by receipt types (6.4.4); receipts are RAII values that write their own compensating record when dropped unresolved, so cancellation, panic and shutdown abort cannot leave a Pending whose meaning is ambiguous within a boot.
* Timeouts are not faults (6.4.6): `Busy`, `Timeout`, `QueueFull`, `Capacity` refuse the flow and are counted; only an I/O error, a dead writer, sequence exhaustion or a 30 s fsync stall latches the gate. A job cancelled while queued is never written; a job abandoned after its claim is compensated.
* Denials: the first occurrence per `(profile, host, port, reason, rule)` per 60 s window is durable before the refusal reply while it fits the segment's refusal quota (20 percent, 6.4.8); repeats, over-bucket and over-quota denials are counted and folded into `Summary`. Denials stay plaintext in both destination modes. Pre-handshake garbage, malformed targets and peer refusals are counted only (the repo's "rejected input must not grow the ledger" rule, `supervisor.rs:619-626`).
* A flood of distinct denials can never rotate or prune the ledger (its volume cannot fill a segment); admitted-flow evidence is pushed out only by admitted-flow volume (about 1.8 hours of the sustained admission cap fill the default window, 6.4.8).
* Entry ids are the ledger `seq` (gapless across segments and restarts); flow ids are `ingress:b<seq of Started>:<n>`, so every flow names the Started record that carries the configuration fingerprint, the destination logging mode and the key id.
* Destinations of admitted flows are recorded plain or as keyed tokens (owner decision 3, 6.4.10); the choice is recorded in the ledger.
* Compatibility: new directory, new format (`ledger_format: 1`), a newer format is refused, never appended to. `audit.json`, `ForensicEntry`, `ssk verify-ledger` and older binaries are untouched. `RunDoctor` reports both chains; the ingress ledger is read over IPC with the new `GetIngressAudit` request (11.8), not through `GetAuditEntries`.
* Cost: `GetStatus` never reads a ledger; group commit amortises fsync; one admitted flow costs two durable appends plus a best-effort `Closed`.

## 10. Status semantics: what may be claimed

### 10.1 Principles

* `DaemonState` is untouched by the ingress. `dns_protected` and `kill_switch` keep their existing meaning. The word `Protected` keeps its one-held-session meaning and is never combined with ingress wording.
* The ingress block is a separate `StatusDto.ingress: Option<IngressStatusDto>` (10.4) with closed state words, machine-readable coverage in `{none, proxy_clients_only}`, a constant `system_wide = false`, and its own `last_error` slot that is never merged into `StatusDto.last_error`.
* `armed` is computed, never stored: gate `Armed` AND accept task alive AND ledger writer alive AND every control that `hardening` requires is active (or `best_effort` was chosen explicitly). `armed` means exactly: the listener evaluates each connection that reaches it under the named profile. It says nothing about applications that do not use the proxy, apps that fall back to direct on their own, DNS resolved by applications, UDP/QUIC, or any OS-level enforcement.
* Clients must render an unknown `state` or `coverage` string as "unknown, not covered". `Some(IngressStatusDto)` is also the **capability marker**: `ingress: None` means only "this daemon predates ingress support", and a daemon with this code never answers `None` (a disabled ingress is `Some(state: disabled)`). A new CLI refuses `ssk ingress arm|flows|inspect|audit` against a daemon whose status has `ingress: None`; clients also check `StatusDto.protocol` (11.9).
* Kaleidoscorp never claims that a third-party VPN is up, protects anything or covers a flow; observed facts are labelled as observations (10.5, 10.6).

### 10.2 Allowed headlines

| Situation | DaemonState | ingress.state | coverage | Allowed headline |
|---|---|---|---|---|
| not configured | unchanged | disabled | none | Local proxy: off |
| config invalid | ConfigInvalid | unavailable | none | Local proxy unavailable: configuration invalid |
| ledger open / verify running, or bind retrying | unchanged | starting | none | Local proxy starting |
| bound, not armed | unchanged | disarmed | none | Proxy ready, not activated: connections are refused. |
| armed | unchanged | armed | proxy_clients_only | Proxy active for applications that use it (profile P). Everything else is not covered. |
| armed, `peer_check` false | unchanged | armed | proxy_clients_only | Proxy active for applications that use it (profile P). Everything else is not covered. Other local accounts may also use it: there is no peer check. |
| bound, not armed, `peer_check` false | unchanged | disarmed | none | Proxy ready, not activated: connections are refused. If activated, other local accounts could use it: there is no peer check. |
| fault latched | unchanged | tripped | none | Proxy stopped: <code>. Re-arm to recover. |
| bind/hardening/ledger/fd refused | unchanged | unavailable | none | Proxy unavailable: <code> |

**The headline is a pure function** of the status the daemon sends (`headline(state, controls, armed_profile, code)` in `types.rs`), so the CLI, the doctor and the GUI (which renders its own German sentences of 25.10 from the same inputs) cannot disagree. Draft 2 merged the last two rows into one headline that read "Proxy active ... (profile P)" also for a **disarmed** proxy, which on Windows before `C-WIN2` (the owner's platform, `best_effort`, no peer check) is the default start state. The test `headline_claims_activity_only_when_armed` runs every combination of state, `peer_check`, `exclusive_bind` and `private_audit_store` and asserts: the whole words "active" and "aktiv" (not "activated" or "aktiviert", which the disarmed headline uses), a profile id and the coverage sentence occur only when `state == armed`; a disarmed or unavailable state never says that the proxy is serving; every armed headline carries the coverage sentence; no headline contains the word "Protected". The corrected `Protected` doc comment in `ssk-ipc/src/state.rs` and the adapter health string ("connected at activation; liveness not monitored") were done by `C-S3`.

**Wording corrected at `C-G1`.** Draft 2's two peer-check notes ended in "no peer check is active", which put the whole word "active" into a **disarmed** headline and made the test below fail on the design's own text. The notes now read "there is no peer check"; nothing else in the table changed (the disarmed headlines end in a full stop, as the implementation writes them).

### 10.3 Status assembly: the fresh-overlay rule

The landed code does not cache a status at all. `GetStatus` waits `STATUS_LOCK_WAIT` (100 ms, `supervisor.rs:43`) for `Inner` and, if an activation is in flight (`ActivationsInFlight::any`, `supervisor.rs:86`), answers `activating_status(view)`, which is built from nothing but the kill-switch view and constants (`supervisor.rs:261-273`). Draft 1's `StatusHint` is superseded by this. The ingress extends that rule; it adds no cache.

1. **One builder.** `Supervisor::status_answer()` builds every `StatusDto` sent by `GetStatus`, `SetIngress`, `ActivateProfile` and `Deactivate`. `StatusDto.ingress` is a required field of the struct literal, so a call site that forgets it does not compile (the production literal sites are `Inner::status` and `activating_status`; the two test sites use `..Default::default()`, 11.10).
2. **Order inside it.** (a) `inner_unless_activating()`: `Held` -> `Inner::status(view, ..)`; `ActivationInFlight` -> `activating_status(view, ..)`. (b) The ingress block is taken **last**, with `IngressShared::snapshot()`, after any lock wait has ended. (c) The kill-switch view is read at the same moment as the legacy block. The ingress block never needs `Inner`, so it is identical in both branches: a trip or disarm that happens during a 20 s activation dial is visible in the very next `GetStatus`, and the honesty test asserts exactly that (`status_overlay_is_fresh_during_activation`).
3. **The kill-switch provider is itself an aging cache** (`CachedBrokerView`: an answer older than its maximum age becomes `Unknown`, `killswitch.rs:389-405`). "Fresh" therefore means "what `view()` returns at this call", never a copy the supervisor kept. The contract text of `KillSwitchProvider::view` ("called while the supervisor's mutex is held", `killswitch.rs:210-221`) is corrected: it is called with or without the mutex and must not block either way.
4. `last_transition` is published after the gate write, so a reader can briefly see the new gate with the previous `last_transition`. The snapshot labels it with its own epoch, and the `state` and `coverage` words come from the gate alone.

### 10.4 `IngressStatusDto`: the complete field list

All fields are `#[serde(default)]` (additive; an old client ignores them, a new client treats an absent one as unknown). Vocabularies are `String`s with a documented closed set (11.2 R6).

```rust
pub struct IngressStatusDto {
    pub state: String,            // disabled | starting | unavailable | disarmed | armed | tripped | stopping
    pub coverage: String,         // none | proxy_clients_only   (the latter only while state == armed and healthy)
    pub system_wide: bool,        // constant false
    pub notice: String,           // INGRESS_COVERAGE_NOTICE
    pub listen: Option<String>,   // "127.0.0.1:<port>" only while bound
    pub configured_listen: Option<String>,   // the configured value, shown when `listen` is None after a bind failure
    pub protocols: Vec<String>,
    pub armed_profile: Option<String>,
    pub arm_profile: Option<String>,         // routing.default_profile when the ingress is enabled; what an arm without a profile will use
    pub controls: IngressControlsDto,        // exclusive_bind, peer_check, private_audit_store, hardening (required | best_effort)
    pub counters: IngressCountersDto,        // accepted, refused_{disarmed,peer_budget,peer,rate,capacity}, malformed, rejected_target{malformed,numeric_alias,localhost},
                                             // denied, denied_suppressed, admitted, connect_failed, active_flows, bytes_up, bytes_down, panics, accept_errors,
                                             // audit_close_lost, audit_busy, audit_timeouts, disarm_record_lost, trips, evicted_handshake, resolver_busy, resolver_zombies
    pub audit: IngressAuditDto,              // 6.4.11
    pub last_error: Option<IpcError>,        // the ingress's own slot; never merged into StatusDto.last_error
    pub last_denial: Option<DenialSummaryDto>,
    pub retry_hint: Option<String>,
    pub epoch: u64,                          // gate epoch: changes on every transition, including a disarm of an already disarmed gate
    pub trips: u64,                          // trips since this boot; lets a poller see a trip followed by a re-arm that it missed
    pub last_transition: Option<LastTransitionDto>,   // { epoch, kind: started|armed|disarmed|tripped|recovered|unavailable|stopping, reason_code, actor: Option<String> }
    pub phase: Option<String>,               // only while starting: verifying_ledger | binding (attempt n of N)
    pub limits: IngressLimitsDto,            // { max_connections (configured), max_connections_effective, accept_rate_per_s, clamped_by: Option<"fd_limit">, fd_soft_limit: Option<u64>, fd_needed: u64 }
    pub config: ConfigDigestsDto,            // { config, routing, ingress }: the three 64-hex digests of the running configuration (6.4.8)
    pub egress: IngressEgressDto,            // 10.5
    pub observations: IngressObservationsDto,// 10.5
    pub warnings: Vec<IngressWarningDto>,    // 10.5
}
```

**No pushes.** No IPC client receives pushed events today (6.9.3). Trip visibility for IPC clients is therefore **polling only**, and `epoch` and `trips` are what make a missed transition detectable. In-process subscribers (tests, a future push) get the `Event::Warning` codes of 6.9.3.

### 10.5 Egress facts, observations and warnings (the coexistence scenario)

Additive to 10.4, closed vocabularies, an unknown value renders "unknown, not covered". None of it changes `state`, `coverage` or `DaemonState`.

```rust
pub struct IngressEgressDto {            // facts about Kaleidoscorp's own behaviour, each backed by a test
    pub binds_interface: bool,           // constant false (CO-1)
    pub binds_source_address: bool,      // constant false (CO-1)
    pub direct_resolver: String,         // constant "operating_system" (CO-3)
    pub direct_address_families: String, // "ipv4_only" | "any", from config
}
pub struct IngressObservationsDto {
    pub label: String,                   // OBSERVATION_LABEL
    pub route_v4: ObservedRouteDto,      // lookup of 192.0.2.1
    pub route_v6: ObservedRouteDto,      // lookup of 2001:db8::1
    pub last_direct_source: Option<ObservedSourceDto>,
}
pub struct ObservedRouteDto {
    pub status: String,                  // not_sampled | observed | stale | no_route | unsupported | failed
    pub probe: String,                   // the documentation address looked up
    pub interface_index: Option<u32>,
    pub interface_alias: Option<String>, // OS text: untrusted data, sanitised (6.12), never inside a sentence
    pub sampled_age_ms: Option<u64>,
    pub unchanged_for_ms: Option<u64>,
    pub previous: Option<PreviousRouteDto>,  // { interface_index, interface_alias, replaced_ago_ms }
}
pub struct ObservedSourceDto { pub address: String, pub kind: String /* direct | first_hop */, pub flow_id: String, pub age_ms: u64 }
pub struct IngressWarningDto { pub code: String, pub text: String }   // text fixed per code
```

`OBSERVATION_LABEL` = "Facts read from the operating system and from this daemon's own sockets. They describe what was seen, not what any other software is doing." (no forbidden word). The GUI reads `observations` (it has no separate route field of its own).

**Warnings** (closed set; fixed texts without forbidden words):

| Code | Emitted when | Text |
|---|---|---|
| `PEER_CHECK_INACTIVE` | a listener is bound and `controls.peer_check` is false | No peer check is active: any local account that can reach this port can use the proxy. |
| `EXCLUSIVE_BIND_INACTIVE` | bound and `controls.exclusive_bind` is false | The port is not bound exclusively: another local process might be able to share or take it. |
| `AUDIT_STORE_NOT_PRIVATE` | bound and `controls.private_audit_store` is false | The destination log is not verified as private: other local accounts might be able to read it. |
| `KILL_SWITCH_ENGAGED` | bound and the supervisor's `KillSwitchView` is `EngagedConfirmed` | The firewall kill switch is engaged. It blocks outbound connections of every program, including this daemon's, so connections through the proxy can fail. |
| `OS_ROUTE_CHANGED` | a family's `previous` exists and `unchanged_for` < 10 min | The network interface that the operating system selects for the probe address changed recently. See the observations. This says nothing about other destinations. |
| `DIRECT_MAY_USE_IPV6` | `direct_address_families == any` and `route_v6.status == observed` | Direct connections may use IPv6. Whether other network software covers that path is not known to this daemon. |
| `OBSERVATION_UNAVAILABLE` | `route_v4.status` is `unsupported` or `failed` | The operating system's routing lookup is not available here; no route observation is shown. |
| `AUDIT_WINDOW_SHORT` | `audit.pruned_entries > 0` and `audit.oldest_ts_ms` is less than 24 h before the wall clock (advisory: the clock is untrusted) | Older audit records have already been removed by size retention: the retained window is shorter than 24 hours. |

`KILL_SWITCH_ENGAGED` is added by the supervisor's status builder (it owns the read-only provider, `supervisor.rs:59`; `kill_switch_fields` at `:247`), not by code under `src/ingress/` (CO-7). The existing three-valued `kill_switch` and the `KILL_SWITCH_STATUS_UNKNOWN` advisory are unchanged; an `Unknown` view adds no warning.

### 10.6 The never-claim list

Kaleidoscorp must never produce, in any status field, CLI or doctor line, log above DEBUG, audit record or GUI sentence:

1. that a tunnel or VPN exists, is connected, is active, or is the reason for an observed interface;
2. that traffic is encrypted, anonymous, hidden, private or leak-free;
3. that an observed interface is a tunnel adapter: no classification by name, type, vendor or driver. A source scan fails if any of the quoted words vpn, nord, tun, tap, wintun, wireguard or openvpn (case-insensitive, as a string literal) appears in `path.rs` or the snapshot builder;
4. the public exit address or its country (CO-6);
5. that DNS or IPv6 is covered, blocked or tunnelled;
6. that a route change means "the tunnel dropped" (permitted: "the interface selected for the probe address changed");
7. that `sskd.exe` is or is not on a tunnel application's list;
8. anything about the kill switch beyond the existing three-valued view;
9. that the interface the probe lookup selects is "the default route", "the route for internet destinations" or the route that any real destination takes: the probe is a documentation address, and exclusion routes or per-application steering can send a real destination elsewhere (draft 2 labelled it "Standardroute"; test `ingress_never_labels_the_probe_as_the_default_route`).

Permitted, always labelled as observation: the interface (index and alias, as quoted OS data) the OS route lookup selects for the two documentation probes; when it changed and what it was; the local address the OS gave the last Direct or first-hop socket; the constant facts of `IngressEgressDto`.

### 10.7 Forbidden-word scan and third-party text

`FORBIDDEN_WORDS` (case-insensitive substrings; the union of the English list of draft 1 and the German forms, 25.10): `protected`, `protection`, `secure`, `system-wide`, `system wide`, `all traffic`, `vpn`, `geschützt`, `geschuetzt`, `schutz`, `sicher`, `systemweit`, `systemübergreifend`, `gesamter datenverkehr`, `gesamten datenverkehr`, `aller datenverkehr`, `alle verbindungen`, `tunnel`, `anonym`, `verschlüsselt`. It applies to every string the ingress PRODUCES: notice, state and coverage words, warning texts, label, headlines, CLI and doctor lines, errors, and (25.10) the GUI's own sentences. It does not apply to OS-supplied data, or an adapter alias containing the letters "vpn" would fail the test; nor to user-chosen ids, adapter names or observation values that appear in the ledger. The exemption is narrow and tested: `observed_text_never_enters_fixed_strings` renders status with an alias such as `Some VPN protected secure tunnel`, serialises it, and asserts the marker occurs only at `observations.route_v4.interface_alias`, `observations.route_v6.interface_alias` and the two `previous.interface_alias` paths.

### 10.8 Freshness

`snapshot()` reads the watcher slots, the bound-listener controls and the supervisor's kill-switch view at call time. The status answer built while an activation holds the supervisor lock (`activating_status`, `supervisor.rs:261`, from the `GetStatus` arm at `:572`) is built from nothing but what is true at that moment; it gains a fresh `IngressStatusDto` from `snapshot()` including observations and warnings. A trip or disarm during a 20 s activation therefore cannot leave `armed` or `proxy_clients_only` in an answer.

## 11. IPC and compatibility

> Checked by running the real `ssk_ipc::Request`/`StatusDto` (HEAD `b62c4c8`) against copies of the proposed shapes with `ciborium` 0.2 (the framing's encoder), then by a prototype of the wire changes (`cargo test -p ssk-ipc`: 30 -> 35 tests, `ssk-daemon` 89 unit tests and `ssk-desktop-client` 4 tests still green, clippy and fmt clean). The merge added `GetIngressAudit`, `client`, the lifecycle and coexistence DTO fields and the `RouteTrace` additions; those are specified here and not run. The `apps/desktop` literal could not be compiled here.

### 11.1 Measured behaviour (this is what the rules rest on)

| experiment | result |
|---|---|
| a new client sends `GetAuditEntries { limit: 5, ledger: Some("ingress") }` to a current daemon | decodes as `GetAuditEntries { limit: 5 }`: the selector is dropped without any signal and the daemon would answer with the activation ledger |
| a new client sends `SetIngress` to a current daemon | ``unknown variant `SetIngress`, expected one of `GetStatus`, ...``. The server (`read_with_timeout` then `handle_connection`, `ssk-ipc/src/server.rs`) returns the `IPC_DECODE_FAILED` error and drops the stream; no response frame is written, so the client's `read_frame` fails at `read_exact` and reports `IPC_IO_FAILED` (retriable). A crashed daemon looks identical. |
| current client bytes (`GetStatus`, `GetAuditEntries { limit }`) to a daemon whose `GetAuditEntries` has an extra `ledger` field | decode; `ledger` is `None` (an additive field is safe in this direction; the problem is the other one) |
| a new `StatusDto` (extra fields) to a current client | decodes; extra fields are ignored (no IPC type has `deny_unknown_fields`) |
| a current `StatusDto` (fields absent) to a new client | decodes; `ingress: None`, `protocol: 0`; an absent `Option` field decodes to `None` even without `#[serde(default)]` |

There is no version negotiation: `Request` has no hello, and `StatusDto.version` is `env!("CARGO_PKG_VERSION")`, which is `0.1.0` for every crate of the workspace (`[workspace.package]`), so it cannot tell two builds apart.

### 11.2 Rules (go into `COMPATIBILITY_MATRIX.md`, "IPC compatibility")

* **R1 New capability = new `Request` variant.** A peer that predates it drops the connection, which is harmless; it is detected by R5 before the request is sent.
* **R2 A new field on an existing request is allowed only if ignoring it still yields a correct answer** (a hint, a cap). A field that selects which data is returned or which profile is evaluated is a new variant, **or** is sent only after R5's protocol check. Consequences: draft 1's `GetAuditEntries { limit, ledger }` is replaced by the separate variant `GetIngressAudit` (11.8); `RouteTraceRequest.profile_id` (11.7) is allowed only because every client sets it after `require_protocol(1)`, and an answer without `profile_used` (an old daemon) is treated as "profile not honoured".
* **R3 A request whose answer changes meaning is guarded the same way.** `ListRecentFlows` returns `[]` and `InspectFlow` returns `FLOW_NOT_FOUND` on a daemon that predates the registry; both read as "no traffic". Clients show them only after R5.
* **R4 `clamp_request_limits` has no catch-all.** The `other => other` arm (`server.rs:109`) let any new variant pass unclamped; it is replaced by an exhaustive list of the size-free variants, so adding a variant is a compile error until someone decides whether it carries a peer-chosen size (the reason the clamp exists, `MAX_LIST_LIMIT` comment). Test: every protocol-0 request passes unchanged, the sized ones (`ListRecentFlows`, `GetAuditEntries`, `GetIngressAudit`) are clamped.
* **R5 The daemon announces what it speaks in `StatusDto.protocol`** (11.9); a client that needs more than protocol 0 checks it first.
* **R6 No new variant in any enum an older client decodes** (`DaemonState`, `Response`, `Event`, `RouteKind`, `PolicyAction`, `AuditOutcome`) without a protocol bump and a matrix entry. The existing matrix entry for `RouteKind::OpenVpn` ("older clients cannot decode them") is the precedent that this rule forbids repeating. **`Response::IngressAudit` is the one new `Response` variant of M2:** a protocol-0 client never sends `GetIngressAudit`, so it never receives it. New vocabularies (`ingress.state`, `coverage`, `outcome`, reason codes) are `String`s with a documented closed set; clients render an unknown word as "unknown, not covered".
* **R7 No `deny_unknown_fields` on any IPC type** (including `SetIngressRequest`, MD-4). It is what makes additive fields safe in both directions; a test decodes a map with an extra key for every DTO and request.

### 11.3 What M2 changes on the wire

* `pub const IPC_PROTOCOL_VERSION: u32 = 1` in `ssk-ipc/src/dto.rs`. `0` is every build up to and including `b62c4c8` (the field is absent). Raise it for a change an older peer cannot ignore after the first tag; until then protocol 1 is "M2".
* `StatusDto.protocol: u32` and `StatusDto.ingress: Option<IngressStatusDto>`, both `#[serde(default)]`; `IngressStatusDto` is the complete block of 10.4.
* `FlowSummaryDto` gains `#[serde(default)]` fields: `peer`, `peer_verified`, `route`, `matched_rule`, `reason_code`, `bytes_up`, `bytes_down`, `started_ms`, `ended_ms`, `audit_pending_seq`, `audit_result_seq`, `front_end`, `egress_local`, `destination_form` (`plain | hashed`). `outcome` closed set: `denied | refused | connect_failed | active | closed | cancelled`. `app_id` is the literal `local-proxy:unattributed`, never client data. `AuditEntryDto` is **not** widened (the ingress ledger has its own DTO, 11.8).
* `ListRecentFlows` / `InspectFlow` become real (256-entry registry outside the mutex, newest first, bounded, free of the `Inner` lock). `FLOW_NOT_FOUND` only for ids never issued; for ids of this boot that were evicted, or ids of another boot, `FLOW_NOT_RETAINED` ("not kept in memory; see the ingress audit"). Pre-policy refusals inspect as `PolicyAction::Deny`, `RouteKind::Denied{reason}`, `matched_rule: None`. In `hashed` mode the registry holds the token, not the host (6.4.10). Text fields obey the shapes of 25.5 (ids, codes, destinations).
* `Request::SetIngress(SetIngressRequest)` (11.4) and `Request::GetIngressAudit` (11.8); `RouteTraceRequest`/`RouteTraceDto` additions (11.7).
* No new `DaemonState`, `Event` variant. No per-flow events on the 256-slot broadcast. Arm, disarm, trip and recover emit the existing `Event::Warning{code,message}` (6.9.3).
* New `explain_code` entries: the table of 11.14. A test asserts that every code this milestone emits is explainable (pattern of `the_activation_timeout_code_is_explainable`).
* The desktop v2 contract is not touched by the wire change (it projects only the fields it knows); a regression test proves `DesktopClient` still reads a daemon that returns `ingress: Some(..)` until `C-U7` replaces v2.

### 11.4 `SetIngress`: authorisation and result

**Wire shape.** `Request::SetIngress(SetIngressRequest { armed: bool, #[serde(default)] profile_id: Option<String>, #[serde(default)] client: Option<String>, #[serde(default)] expect_profile: Option<String>, #[serde(default)] expect_routing_digest: Option<String> })`, declarative and idempotent, answered with `Response::Status(status_answer())`. `armed: true` arms `profile_id` or, when absent, `routing.default_profile` (the GUI sends `armed`, a `client` label and the two `expect_*` fields below and nothing else, so the webview cannot choose a profile); `armed: false` with a `profile_id` or an `expect_*` field, and `expect_*` together with a `profile_id`, are `Usage` errors (`INGRESS_ARGUMENT`). **`expect_profile` and `expect_routing_digest`** bind the request to what the caller showed its user: the daemon refuses with `INGRESS_CONFIG_CONFLICT` (nothing armed, no record, counted) when `expect_profile` differs from `routing.default_profile` or `expect_routing_digest` differs from the routing digest of the running configuration (`ConfigFingerprint.routing`, 6.4.8). Without them a restart with an edited configuration between the snapshot that a confirmation was rendered from and the click would arm whatever the new default profile is, while the ledger says that the desktop client asked (critic round 1). Both fields are optional, so the CLI (which names its profile or means "the default") needs neither; `SetIngress` is a new variant (R1), so they are part of its first shape, and the GUI sends them only after `require_protocol(1)`. `client` is the caller's self-declared label; the daemon maps `"cli"` and `"desktop"` to those values and everything else (or absent) to `unknown`; raw client text is never stored or logged above DEBUG (MD-4).

**Why a new variant and not an overload.** The judges objected that a new variant breaks old peers (an old daemon drops the connection; a new client sees a misleading retriable `IPC_IO_FAILED`). The variant is kept on purpose: the alternative (overloading `ActivateProfile{ingress:true}`, `Deactivate{ingress_only:true}`) turns version skew into a **destructive** outcome, because an old daemon would ignore the flag and run the legacy no-destination path, which calls `clear_egress()` and enters FailClosed (verified in `supervisor.rs`). A dropped connection is harmless; a dropped probe session is not. Mitigation: R5 and the CLI hint.

**What "authorised" means for a same-user peer.** The only authentication is the transport's same-principal check (`ssk-ipc/src/auth.rs:70-86` on Unix, SID comparison on Windows); the GUI and the CLI are the same principal, so the daemon does not try to tell them apart (25.2). What the daemon does:

* The handler is the first consumer of the `PeerIdentity` argument (`Supervisor::handle` binds `_peer` and ignores it today, `supervisor.rs:569`). The durable `Armed` and `Disarmed` records carry `requested_by` = the verified principal (`uid:1000` or `sid:S-1-5-21-...`, `auth.rs:47-54`) and `client` = the mapped label. The record says exactly: this principal asked, and claimed to be this client. It does not say which process.
* The request carries no profile, port, rule or limit that the caller can choose beyond the CLI's explicit `profile_id`, which passes `validate_profile_id`.
* **Disarm (`armed: false`) goes straight through.** After decode and the argument check above, the handler calls `IngressShared::disarm(Operator)` unconditionally: no mode pre-check, no no-op shortcut, no rate limit, no wait for `control`. `disarm` is the only thing that bumps the epoch, and the bump is what makes an arm that is waiting on its fsync lose its compare-and-set; during that wait the gate still reads `Disarmed` (arm writes the gate only at its compare-and-set, 6.9.2 step 5), so a handler that answered "already disarmed" from a gate read would acknowledge the operator's disarm and let the arm open the gate afterwards. Draft 2 had exactly that shortcut in its check (5), contradicting 6.1.2 and the table below. Only the ledger record is conditional (`was_armed`, 6.9.2), so a double click and a retry after `outcome_unknown` cost no record and are safe. The answer is `Response::Status(status_answer())`.
* **Arm (`armed: true`), order of checks:** (1) decode (an unknown request is a decode error); (2) ingress block present, else `INGRESS_DISABLED`; (3) mode allows the request (table below; `Starting` -> `INGRESS_STARTING`, `Closing` -> `INGRESS_STOPPING`); (4) profile shape and membership (`PROFILE_ID_INVALID`, `UNKNOWN_PROFILE`, via the existing `validate_profile_id`) and the `expect_*` fields (`INGRESS_CONFIG_CONFLICT`); (5) no-op detection for the profile that is already armed: it changes nothing, writes no record, consumes no rate-limit token and answers `Response::Status` with the current state. The shortcut is taken only when the gate reads `Armed{same profile}` AND `control.try_lock()` succeeds, that is, no control operation is in flight; otherwise the request goes on and the arm task decides authoritatively under the lock (6.9.2 step 2), so an arm of profile A that queues behind an in-flight arm of profile B is never dropped as a no-op; (6) the rate limit (below); (7) the control lock, `recover` if needed, the durable record, the gate (6.9.2). Refusals write no ledger record (the repository's rule that rejected input does not grow the ledger, `supervisor.rs:469-478`); they are counted and logged.
* **Rate limit: arm only.** Every arm costs an fsync and a durable record, and a re-arm cancels all flows, so flapping of the widening direction by any same-user process must be bounded: burst 5, one token per 2 s (`Tuning`), answer `INGRESS_RATE_LIMITED`. A disarm is never rate limited: it narrows, its record is written only when the gate was armed, and a flapper that keeps the arm bucket empty must not be able to hold back the operator's disarm (draft 2 limited both directions, which inverted the safety direction; test `set_ingress_disarm_works_with_an_empty_arm_bucket`). The GUI's own floor (750 ms between arms) is below the limit; its disarm has no floor (25.3).
* **No `Inner` lock.** The `SetIngress` path never takes `inner.lock()` (a 20 s activation dial holds it); profile validity comes from the hoisted `Arc<ConfiguredRouting>` (12.1). Disarm is answerable while an activation is in flight.
* Not attempted: separating the GUI's privileges from the CLI's (impossible with one principal), process identity, a shared secret.
* **Residual: the IPC connection cap.** Any request, a disarm included, is served only once the IPC server holds a permit for its connection: `ServeLimits` allows 16 connections, a silent one is dropped after 5 s, an idle one after 300 s, and the permit is taken after `accept()` (`ssk-ipc/src/server.rs:90-93, 280-283`). Sixteen same-user connections that each send one request and then idle keep the 17th client, a disarm included, waiting (12.5 measured the same for queued requests). The disarm is not rate limited and does not wait for `Inner`, but it cannot overtake the transport. The emergency stop in that state is to stop `sskd`, which closes the gate (RUNBOOK). Reserving a permit for narrowing requests would need the server to read the first frame before it takes a permit; that is not part of M2. 11.5 and 27 therefore say that a disarm is applied as soon as the request is served, not that it always happens.

**Result by current gate mode.**

| Mode | `armed: true` | `armed: false` |
|---|---|---|
| Disabled | `INGRESS_DISABLED` | ok, no change |
| Starting | `INGRESS_STARTING` (retriable) | ok; cancels a pending `arm_on_start` |
| Unavailable(c), c recoverable | recover, then arm; failure -> `INGRESS_RECOVERY_FAILED` (cause in the message) | ok, no change |
| Unavailable(c), c not recoverable | c's own code as the error code (`CONFIG_INVALID`, `INGRESS_HARDENING_UNAVAILABLE`, `INGRESS_FD_LIMIT_TOO_LOW`); `INGRESS_UNAVAILABLE` only when c has none | ok, no change |
| Disarmed | armed | ok; the epoch bump supersedes any arm in flight and is never skipped |
| Armed(p) | same profile: ok, no change. Other profile: re-arm (flows of the old epoch are cancelled) | disarmed |
| Tripped(r) | recover, then arm | ok; stays `tripped` (the latch is evidence; only an arm clears it) |
| Closing | `INGRESS_STOPPING` | ok, no change |

Every success answers `Response::Status(status_answer())` (10.3). Two concurrent arms with different profiles are serialised by `control` in arrival order; the second finds the first's profile in the gate and re-arms. Invariant I1: while the gate is `Armed(p)`, the newest `Armed` record in the ledger names `p` and was durable before the gate opened.

### 11.5 `Deactivate`

1. `ingress.disarm(Deactivate)`: effect first, no lock, applied as soon as the request is served (the residual of 11.4 on the IPC connection cap applies).
2. Mutator gate (12.5): `try_acquire`. Refused -> `Err(DAEMON_BUSY)`; its message starts with "The local proxy was disarmed." when step 1 changed anything.
3. `inner.lock().await`. The mutex is FIFO (`tokio-1.53.1/src/sync/mutex.rs:20`), so a `Deactivate` sent after an `ActivateProfile` runs after it and is never undone by it; it may wait up to the activation deadline (20 s), which is why step 1 comes first.
4. `FailClosed` and not `release_kill_switch` -> `Err(KILL_SWITCH_ARMED)`. The ingress was already disarmed in step 1, and the message says so when it was armed: "The local proxy was disarmed. The daemon is in its fail-closed state; the held session was not released. Pass release_kill_switch=true to release it." This is the only answer with a partial effect, and its text states the effect. A client that wants the truth reads `GetStatus`, whose `ingress.state` is the authority. The wording "kill switch is armed" of the current message (`supervisor.rs:824`) describes the daemon's `FailClosed` state, not the firewall rule; it is reworded (17.2) and the code stays (`release_kill_switch` does not reach the firewall rule, comment at `supervisor.rs:847-852`).
5. Otherwise: bounded session shutdown (12.6), `Inactive` or `ConfigInvalid` as today, final `Status` answer.

A GUI "Deactivate" button and a GUI "Disarm" button would be different commands; the GUI offers only Disarm (`SetIngress`) and never calls `Deactivate` (25.3). `ssk deactivate` for the legacy probe session also disarms the local proxy ("stop everything this daemon does for applications"); the CLI and GUI text say "The local proxy was disarmed" (open question B3).

### 11.6 Busy answers instead of queueing

`DAEMON_BUSY` (class Runtime, retriable) replaces a queue of up to 20 s in: `TraceRoute` when no profile can be chosen without `Inner`, `GetAuditEntries` (legacy ledger), `VerifyAuditChain`, whenever an activation is in flight; and in `ActivateProfile` and `Deactivate` when two mutating requests are already in flight. Handlers that need no `Inner` never return it: `ListProfiles`, `RunDoctor`, `InspectFlow`, `ListRecentFlows`, `ExplainError`, `SubscribeEvents`, `SetIngress`, `GetIngressAudit`, `TraceRoute` with a known profile.

### 11.7 `TraceRoute` and the live path

Replaces the claim in draft 1 that preview and live "cannot diverge". What is true: both call one pure function. `ConfiguredRouting::decide(profile, &FlowRecord)` is evaluate plus plan (policy engine, then `RouteOrchestrator::plan`), and `engine::decide(ctx, profile, flow_id, &Target)` of 6.7 is that function followed by the guards and `admit`. They differ in their inputs, and the preview now reports which inputs it used.

Today they differ in three ways, verified in the code: profile (TraceRoute uses `inner.active_profile`, else `default_profile`, `supervisor.rs:873-876`; the ingress will use the armed profile; `RouteTraceRequest` has no profile field, `dto.rs:74-80`), flow context (TraceRoute: caller `app_id` or `unknown-app`, caller protocol and risk, `supervisor.rs:882-892`; ingress: `local-proxy:unattributed`, Tcp, Low) and the live-only guards plus `admit` (which also rejects UDP, DNS and Custom protocols and whitespace or control characters in the host, `admission.rs:53-65`). The flow-context difference does not change a decision **today** only because the configuration cannot express it: `routing.rs:75-80` builds every rule's criteria from `destination`, `port` and `domain_suffix` alone, and `RoutingRule` (`ssk-config` `routing.rs:67-81`) has no app, protocol or risk field. A test pins that fact (`routing_rules_never_depend_on_flow_context_fields`) so that adding such a criterion fails loudly instead of silently breaking preview equivalence.

Changes (all additive, `#[serde(default)]`):

* `RouteTraceRequest.profile_id: Option<String>`; when given it is validated like `ActivateProfile`'s id. Clients set it only after `require_protocol(1)` (R2).
* Profile choice, reported in the answer: explicit `profile_id` (`request`), else the profile armed in the ingress gate (`armed_ingress`, lock-free), else the profile of the held session (`active_session`, needs `Inner`, `DAEMON_BUSY` while an activation is in flight), else the configured default (`default_profile`). With the ingress disabled the order is unchanged from today for every existing caller.
* When the profile came from `request` or `armed_ingress` and the ingress host exists, the preview canonicalises the target and runs `engine::decide` (pure, no audit, no socket) so it reports exactly what the live path would decide, including special-use and route guards; the request's `app_id`, `protocol` and `risk` are then ignored and the answer says so. Otherwise it runs `ConfiguredRouting::decide` as today.
* `RouteTraceDto` gains `profile_used`, `profile_source`, `evaluated_as` (`legacy_activation` or `ingress`), `app_id_used`, `refusal: Option<String>` (the `Denied` reason code of a guard or policy refusal, with `route` = `Denied`) and `guards_skipped: Vec<String>` (for example `self_loop` when no listener is bound; the resolver is never run).

### 11.8 `GetIngressAudit`: reading the ingress ledger over IPC

The selector of draft 1 is dropped. `Request` has no `deny_unknown_fields` (`ssk-ipc/src/server.rs:22-36`), so an old daemon would decode `GetAuditEntries{limit, ledger}`, ignore `ledger` and answer with the activation ledger as if it were the ingress ledger. A new request variant cannot be misread: an old daemon fails to decode it (`IPC_DECODE_FAILED`, `framing.rs:92`), `handle_connection` ends the connection, and the client sees `IPC_IO_FAILED`, which the CLI maps to "the daemon may predate ingress support". `AuditEntryDto` is not widened.

```rust
Request::GetIngressAudit { limit: usize, before_seq: Option<u64>, verify: bool }
Response::IngressAudit(IngressAuditPageDto)
pub struct IngressAuditPageDto { pub entries: Vec<IngressAuditEntryDto>, pub head: Option<String>, pub entries_total: u64,
                                 pub oldest_seq: Option<u64>, pub truncated_by_bytes: bool, pub verification: Option<IngressVerifyDto> }
pub struct IngressAuditEntryDto { pub seq: u64, pub entry_hash: String, pub prev_hash: String, pub body: String }   // body = the stored body bytes as UTF-8, verbatim
pub struct IngressVerifyDto { pub ok: bool, pub partial: bool, pub entries_checked: u64, pub anchored_at_continue: bool, pub error: Option<String> }
```

`body` is verbatim so a client can recompute `blake3(prev_hash ++ body)` itself. `clamp_request_limits` clamps `limit` to `MAX_LIST_LIMIT` (1000); the handler also stops at 768 KiB of encoded entries because responses are capped at 1 MiB (`framing.rs:40`). The handler reads the tail from the segments through the writer's directory handle without the supervisor mutex; `verify: true` runs `verify_dir(Reader)` in `spawn_blocking` (`audit_read_verify_deadline` 30 s, `partial` beyond it). The CLI gates `ssk ingress audit` on `StatusDto.ingress.is_some()` exactly like `arm`, and every `ssk ingress` verb that reads ingress state (`flows`, `inspect`, `audit`) does the same, so an old daemon's empty list or `FLOW_NOT_FOUND` can never read as "no traffic".

### 11.9 Version skew: how a client learns what the daemon speaks

The realistic skew is a newly installed app or CLI talking to a daemon that is still running its old binary (a running process keeps executing the executable it started from).

1. Every client that needs a post-protocol-0 feature calls `GetStatus` first (every daemon answers it) and applies `StatusDto::require_protocol(1)`: `Ok(())` when `protocol >= 1`, else `IpcError { class: "Runtime", code: "DAEMON_TOO_OLD", message: "the running sskd speaks IPC protocol 0 but this client needs 1", next step: "Restart sskd: a running daemon keeps executing the binary it was started from." }`.
2. `ssk ingress arm|disarm|flows|inspect|audit` do this before sending. `DesktopClient` does it on every snapshot (the v3 snapshot carries `protocol` and a `compat` word: `ok` or `daemon_too_old`) and again immediately before the write command; the webview never sees raw IPC errors. The `IPC_IO_FAILED` hint for a dropped `SetIngress` stays as a last resort for a race (daemon replaced between the two calls).
3. The same check detects a stale `sskd` in tests: `ssk-cli` subprocess tests locate `sskd` next to `ssk` in `target/` (`ipc_status_snapshot.rs` doc comment; they must run after `cargo build --workspace --all-targets`), so they can talk to an old binary. They assert `status.protocol == ssk_ipc::IPC_PROTOCOL_VERSION` and `status.ingress.is_some()` and fail with "stale sskd binary: build with cargo build -p ssk-daemon". The real-`sskd` acceptance suite lives in `ssk-daemon/tests/`, which use `env!("CARGO_BIN_EXE_sskd")` and are fresh by construction.
4. **Older app, newer daemon** works for everything the app knew (R1-R7, proven by the protocol-0 fixtures below) and says nothing about newer features; the daemon cannot warn because an old client sends nothing it could inspect. Accepted limitation; the installer/release must replace and restart both together.
5. Windows named-pipe and Unix-socket transports share all of this (same framing and types).

### 11.10 Sites that must change

`StatusDto` struct literals at HEAD: `supervisor.rs:215` (`Inner::status`), **`supervisor.rs:263` (`activating_status`, added by `C-S3`; draft 1 counted three sites and missed it)**, `ssk-desktop-client/src/tests.rs:5`, `apps/desktop/tests/webview_status.rs:48` (`cfg(windows)`, separate workspace, compiled only by the `desktop_host` job; the edit is mechanical and UNVERIFIED here). To stop every future additive field from touching test literals, `StatusDto` derives `Default` (needs `#[derive(Default)]` and `#[default] Inactive` on `DaemonState`, an additive change) and the two test sites use `..Default::default()`; the two production literals stay complete on purpose so a new field forces an answer there. `activating_status` must overlay a FRESH ingress snapshot (10.3), never a cached one. `match req` in `Supervisor::handle` has no wildcard, so `SetIngress` and `GetIngressAudit` are compile errors until handled. `Request::GetAuditEntries` is not modified, so its pattern sites (`server.rs` clamp, `supervisor.rs:922`, the `supervisor.rs` test at `Request::GetAuditEntries { limit: usize::MAX }`, `ssk-ipc/tests/named_pipe_transport.rs:556,567` on Windows) need no edit.

### 11.11 The CLI's machine-readable contract

`ssk --json status|activate|deactivate` print `{"status":"ok","state": <whole StatusDto>,"next_steps":[]}` (`ssk-cli/src/main.rs:3924-3939`, `print_status`); the new keys `protocol` and `ingress` appear under `state`. This is additive; the matrix says so and says consumers must ignore unknown keys. `activate_real_egress.rs:162` pins one existing key and is unaffected. Error message wording is not a contract.

### 11.12 Protocol-0 fixtures (never regenerated)

Captured from the types at `b62c4c8` (`ciborium::ser::into_writer`); `crates/ssk-ipc/tests/wire_protocol0.rs` decodes each with the current types (`every_protocol_0_request_still_decodes`), asserts the protocol-0 status decodes with `protocol == 0` and `ingress == None` and is refused by `require_protocol(1)`, decodes a current status with a hand-written protocol-0 struct (`a_current_status_decodes_for_a_protocol_0_client`), and shows `SetIngress` is an unknown variant to a protocol-0 enum copy.

```
GetStatus        69476574537461747573
ActivateProfile  a16f416374697661746550726f66696c65a36a70726f66696c655f69646764656661756c7469646573745f686f7374693132372e302e302e3169646573745f706f727409
Deactivate       a16a44656163746976617465a17372656c656173655f6b696c6c5f737769746368f4
ListProfiles     6c4c69737450726f66696c6573
InspectFlow      a16b496e7370656374466c6f77a167666c6f775f6964626631
TraceRoute       a16a5472616365526f757465a5666170705f6964f669646573745f686f73746b6578616d706c652e6f726769646573745f706f72741901bb6870726f746f636f6c63746370647269736b636c6f77
ListRecentFlows  a16f4c697374526563656e74466c6f7773a1656c696d697405
GetAuditEntries  a16f4765744175646974456e7472696573a1656c696d697405
VerifyAuditChain 705665726966794175646974436861696e
RunDoctor        6952756e446f63746f72
ExplainError     a16c4578706c61696e4572726f72a164636f64656b4641494c5f434c4f534544
SubscribeEvents  a16f5375627363726962654576656e7473a1656b696e6473f6
Response::Status (Inactive) a166537461747573a865737461746568496e6163746976656e6163746976655f70726f66696c65f6686164617074657273806d646e735f70726f746563746564f46b6b696c6c5f737769746368f46a61756469745f68656164f66776657273696f6e65302e312e306a6c6173745f6572726f72f6
```

### 11.13 `docs/COMPATIBILITY_MATRIX.md` text for `C-IPC1`

"IPC compatibility (protocol 1). `StatusDto` gains `protocol` and `ingress`; `FlowSummaryDto` gains optional fields; `Request::SetIngress` and `Request::GetIngressAudit` and `Response::IngressAudit` are new; `RouteTraceRequest`/`RouteTraceDto` gain optional fields. Older clients keep working (additive fields are ignored). An older daemon closes the connection on a new request and drops unknown request fields silently, so clients read `StatusDto.protocol` first and refuse with `DAEMON_TOO_OLD` below 1. Rules: new capability = new request variant; no new variant in enums older clients decode without a protocol bump; vocabularies are strings; no IPC type denies unknown fields. `ssk --json status|activate|deactivate` output gains the keys `protocol` and `ingress` under `state`; consumers must ignore unknown keys."

### 11.14 New machine codes (all get `explain_code` entries, as do the 12 `NETCORE_*` codes of `NetcoreError::code()` that have none today)

| Area | Codes |
|---|---|
| ingress state and control | `INGRESS_DISABLED`, `INGRESS_UNAVAILABLE`, `INGRESS_STARTING` (retriable), `INGRESS_BUSY` (retriable: control lock not obtained in 10 s, or a recover verification still running), `INGRESS_SUPERSEDED` (a disarm or another control operation won while this arm was in progress; nothing is armed), `INGRESS_TRIPPED`, `INGRESS_STOPPING`, `INGRESS_CONTROL_FAILED` (a control task panicked; the ingress has tripped), `INGRESS_RECOVERY_FAILED`, `INGRESS_RATE_LIMITED` (retriable), `INGRESS_ARGUMENT` (Usage), `INGRESS_CONFIG_CONFLICT` (`expect_profile` or `expect_routing_digest` differs from what the daemon holds; nothing was armed) |
| ingress start-up | `INGRESS_BIND_FAILED` (retriable), `INGRESS_HARDENING_UNAVAILABLE`, `INGRESS_FD_LIMIT_TOO_LOW` (Config) |
| ingress audit | `INGRESS_AUDIT_FAILED`, `INGRESS_AUDIT_CORRUPT`, `INGRESS_AUDIT_UNSUPPORTED_FORMAT`, `INGRESS_AUDIT_ROOT_UNSAFE`, `INGRESS_AUDIT_DIR_UNSAFE`, `INGRESS_AUDIT_FILE_UNSAFE`, `INGRESS_AUDIT_KEY_UNAVAILABLE`, `INGRESS_AUDIT_STALLED` |
| warning events (not errors) | `INGRESS_ARMED`, `INGRESS_DISARMED`, `INGRESS_RECOVERED` (and the existing `INGRESS_TRIPPED` as an event code) |
| daemon | `DAEMON_BUSY` (retriable), `DAEMON_TOO_OLD`, `ACTIVATION_CANCELLED`, `FLOW_NOT_RETAINED` (`ACTIVATION_CONNECT_TIMEOUT` exists since `C-S2`) |
| targets and routes | `TARGET_MALFORMED`, `TARGET_NUMERIC_ALIAS`, `TARGET_LOCALHOST`, `TARGET_SELF_LOOP`, `SPECIAL_USE_NEEDS_EXACT_RULE`, `SPECIAL_USE_NEEDS_PORT`, `ROUTE_NOT_DIALABLE`, `OPENVPN_NOT_READY`, `DIRECT_GUARD_MISSING`, `DIRECT_NAME_NOT_RESOLVABLE`, `DIRECT_FAMILY_DISABLED` |
| netcore | `NETCORE_ADDR_REFUSED`, `NETCORE_RESOLVER_BUSY`, `NETCORE_FAMILY_DISABLED` |
| CLI | `KILLSWITCH_REFUSED_INGRESS_BOUND` (13.2.4) |

(`DIRECT_REQUIRES_LITERAL` and `INGRESS_FD_BUDGET` of earlier drafts do not exist; MD-20.)

## 12. Changes in existing code

This section supersedes draft 1's "Supervisor" block. Items 2 and 3 of that block (StatusHint, activation deadline) are already landed in a different form (commits `f29784d`, `f5a1683`: `ActivationsInFlight`, `activating_status`, `ACTIVATE_DIAL_DEADLINE`). The code is the reference; this section builds on it. Line numbers are from `b62c4c8`.

### 12.1 Hoisting and construction (`C-S1`)

* `Inner.config` (a `Result<LoadedConfig, IpcError>`), `Inner.routing` and `Inner.data_plane` are never written after `Supervisor::new` (verified by grep of every `inner.config`, `inner.routing` and `inner.data_plane` use). They move onto `Supervisor` as `Arc<ConfigState>`, `Arc<ConfiguredRouting>` and `Arc<dyn DataPlane>` (`ConfigState` is the alias `Result<LoadedConfig, IpcError>` that `Inner.config` has today, 6.7.1). `Supervisor::new` keeps its signature (`Box<dyn DataPlane>` becomes an `Arc` with `Arc::from`).
* **One planner.** Today `Supervisor::new` builds its own `ConfiguredRouting` (`supervisor.rs:302-307`) and `main.rs` builds a second one only to take its adapter registry (`main.rs:258-262`); the executor and the planner therefore come from two compilations of the same config. New constructor `Supervisor::from_parts(audit_path, routing: Arc<ConfiguredRouting>, data_plane: Arc<dyn DataPlane>, kill_switch, config)`; `new` delegates to it. `main.rs` compiles the routing once, derives the executor registries from `routing.adapters` (`AdapterRegistry` is `Clone`), builds the activation executor and data plane (unchanged behaviour) and the ingress executor and data plane (6.10), and calls `from_parts`. Accessors `Supervisor::routing()` and `Supervisor::data_plane()` (the activation data plane) give `IngressHost` the planner; the ingress dials through its own data plane (`IngressDeps.data_plane`).
* `IngressConfig` does not exist before `C-C1`, so `C-S1` must not mention it (draft 1's commit-plan defect). The owned copy of the validated ingress config is stored by `C-F1` (MD-23).
* `StateMachine::event_sender() -> broadcast::Sender<Event>` (new, `C-L1`); `Supervisor` keeps a clone in a field `events`, and `subscribe_events` uses it without taking `Inner`.
* `ConfiguredRouting::decide`, `rule_binding` and `exact_ip_denials`, with `Decided`, `DecideError`, `RuleBinding`, `DenyIp` and the `ConfigState` alias (6.7.1), are added here, in `routing.rs`, so that nothing in this commit depends on the later `ingress/` tree; `TraceRoute` and the activation arm use `decide`.
* Comment corrections in the same commit: `Inner.active_egress` (state that `Activating` is answered without `Inner`), the `KillSwitchProvider::view` contract (10.3), the stale clause "until the peer-SID check lands" at `supervisor.rs:622`.

### 12.2 One lock helper, used by every reader

```rust
enum InnerAccess<'a> { Held(MutexGuard<'a, Inner>), ActivationInFlight }
async fn inner_unless_activating(&self) -> InnerAccess<'_> {
    let acquire = self.inner.lock();
    tokio::pin!(acquire);                       // kept, not re-created: a timed-out wait would otherwise forfeit its place in the queue
    match tokio::time::timeout(STATUS_LOCK_WAIT, &mut acquire).await {
        Ok(guard) => InnerAccess::Held(guard),
        Err(_) if self.activations.any() => InnerAccess::ActivationInFlight,
        Err(_) => InnerAccess::Held(acquire.await),     // any other holder is short (L9)
    }
}
```

This is the existing `GetStatus` structure (`supervisor.rs:572-589`) generalised. It keeps the pinned test `status_keeps_waiting_when_the_lock_is_held_by_something_else`: a holder that is not an activation is waited for.

### 12.3 Which handler needs what

| Request | Needs `Inner` | Behaviour during an activation dial |
|---|---|---|
| `GetStatus` | yes | `activating_status` plus the fresh ingress block (10.3) |
| `ActivateProfile` | yes, held across the dial | queued behind at most one other mutator (12.5) |
| `Deactivate` | yes, after `ingress.disarm` | waits its turn (FIFO) |
| `SetIngress` | no | immediate |
| `ListProfiles` | no (hoisted config and routing) | immediate |
| `RunDoctor` | no (hoisted config; ingress checks from `IngressShared`; ledger verification in `spawn_blocking`) | immediate |
| `TraceRoute` | only to read `active_profile` when neither an explicit nor an armed profile exists | `DAEMON_BUSY` in that case only |
| `GetAuditEntries` (legacy), `VerifyAuditChain` | yes (`Inner.audit`) | `DAEMON_BUSY` |
| `GetIngressAudit`, `ListRecentFlows`, `InspectFlow` | no | immediate |
| `ExplainError`, `SubscribeEvents` | no | immediate |

Measured before the change (scratch crate, 4 s activation deadline): `GetStatus` answered in 101 ms; `ListProfiles`, `RunDoctor`, `VerifyAuditChain`, `GetAuditEntries`, `TraceRoute` and `Deactivate` all completed at 4.04 s, that is, when the dial ended. With the production 20 s deadline each would have queued for up to 20 s.

### 12.4 `ActivationScope`: a cancelled or panicking activation settles

Today the only `await` after `state.transition(Activating)` is the dial (`supervisor.rs:665-669, 766-771`). If the `ActivateProfile` future is dropped there (abort of its task, runtime shutdown, a caller's timeout) or the handler panics while it holds `Inner`, nothing resets the state: reproduced against `HEAD`, `GetStatus` kept answering `Activating` with no profile and the ledger held a lone `DispatchPending`. Fix:

```rust
struct ActivationScope<'a>(MutexGuard<'a, Inner>);        // Deref / DerefMut to Inner; replaces the bare guard in the ActivateProfile arm
impl Drop for ActivationScope<'_> {
    fn drop(&mut self) {
        if self.0.state.current() == DaemonState::Activating {   // no normal path returns in this state, so this is exactly "abandoned"
            self.0.settle_abandoned_activation();
        }
    }
}
// Inner::settle_abandoned_activation:
//   let pending = self.pending_activation.take();
//   if !std::thread::panicking() { if let Some((flow_id, route)) = pending { let _ = self.record_activation(&flow_id, &route, AuditOutcome::FailClosed); } }   // edition 2021: no let-chains
//   self.refuse_activation(IpcError::new("Runtime", "ACTIVATION_CANCELLED", "the activation was interrupted before it completed; no session is held"));
```

`Inner.pending_activation: Option<(String, RouteKind)>` is set by `record_activation` when it writes `DispatchPending` and cleared when it writes a terminal outcome. The polarity is deliberate: the guard checks the state rather than a "disarmed" flag, so no early return can forget it. The scope is declared after `_in_flight` so the mutex is released before the marker (the existing ordering comment, `supervisor.rs:591-596`). The terminal record reuses `AuditOutcome::FailClosed`; no new audit variant is added (the audit type is serialised). A queued activation that is cancelled before it takes the lock never reaches `Activating` and is unaffected (existing test `an_activation_queued_for_the_lock_is_already_in_flight`).

### 12.5 Mutator gate

`Supervisor.mutators: tokio::sync::Semaphore` with 2 permits, taken with `try_acquire` by `ActivateProfile` (before it raises the in-flight marker) and by `Deactivate` (after its ingress disarm). A third concurrent mutating request answers `DAEMON_BUSY` at once. Why this is needed, reproduced against `HEAD`: with a silent dial running, 15 further IPC connections whose `ListProfiles` queued behind it, and the activation's own connection, all 16 IPC permits (`ServeLimits::default().max_connections`, `server.rs:90`) were held; a 17th client asking `GetStatus` was not served within 2 s (the desktop client's `READ_DEADLINE`, `ssk-desktop-client/src/lib.rs:11`) and was served 0.6 ms after the dial ended. The lock-timeout fix of `GetStatus` is defeated by IPC permit exhaustion unless the number of requests that can wait on the dial is bounded. With the readers of 12.3 no longer queueing, at most 2 connections can be occupied by waiting requests.

### 12.6 Bounded session shutdown

`Deactivate` (`supervisor.rs:836-838`) and `record_task_failure` (`supervisor.rs:370-372`) await `session.shutdown()` while holding `Inner`. A TLS stream's shutdown writes `close_notify` and flushes; with a peer that does not read, that can wait without bound, and `clear_egress` already documents that "drop closes the transport even when a graceful shutdown would wait on an unresponsive peer". Both call sites go through one helper, `close_bounded(&mut EgressSession)`: `timeout(SESSION_SHUTDOWN_BOUND = 1 s, session.shutdown())`, then drop. This makes the "short holder" assumption of L9 true.

### 12.7 `RunDoctor`

No `Inner`: the synchronous checks and the config check read hoisted data; the ingress checks come from `IngressShared::snapshot()` and the platform: `ingress`, `ingress:controls` (WARN per inactive control), `ingress:fd_budget` (fails when the configured and the effective limit differ), `ingress:audit_store` (modes, owner, foreign entries, state root writable by others), `ingress:audit_latency` (the 20-cycle fsync probe of 6.4.6, run in the state root), `ingress:port_owner` (Windows: reads the IPv4 owner table, `connections.rs:237`, and reports a LISTEN row with its owner PID or only lingering rows; it decides nothing), `ingress:coexistence` (kill-switch view versus listener, route observation status). `ingress:audit` runs `verify_dir(Reader)` in `spawn_blocking`, single-flight (a second doctor while one runs reports "verification already running", not a failure), with `doctor_verify_deadline` = 10 s; on expiry the check reports "not finished" and the blocking job runs on. Verification streams and snapshots the segment list once; a vanished segment is retried once and then `Inconclusive` (L10). The old handler held `Inner` for the whole call (`supervisor.rs:959-998`).

### 12.8 `main.rs`

```
let routing = Arc::new(ConfiguredRouting::new(..));                         // once (12.1)
let activation_executor = RouteExecutor::new(routing.adapters.clone());      // unchanged: unguarded, default 30 s dial deadline
let ingress_executor = guard::build_ingress_executor(routing.adapters.clone(), &cfg_view, guard.clone())   // 6.10: guard, families, timeouts and deadline (12.9) in ONE function that a test calls
let supervisor = Arc::new(Supervisor::from_parts(..));
let host = IngressHost::start(deps_from(&supervisor, ingress_data_plane)).await;     // returns at once
... serve: select! { run_server, watcher.wait() } ...
let plan = ShutdownPlan::for_reason(reason);                                // shutdown.rs, pure
let outcome = host.shutdown(plan).await;                                    // P0-P2 (8.5)
remove the unix socket
return (code, plan)                                                         // serve now returns the plan to run()
// run():
let (code, plan) = runtime.block_on(serve(..));
runtime.shutdown_timeout(plan.runtime_stop);                                // P4; consumes the runtime
lock.hold_until_exit();                                                     // NOT drop(lock): 8.5 rule 2
code
```

`DaemonLock::hold_until_exit(self)` is `std::mem::forget` on the lock with the reason in its doc comment. Dropping `serve`'s `select!` stops the IPC accept loop; connection tasks already spawned keep running until P4 drops them.

### 12.9 Deadline relations

| Deadline | Value | Where | Relation that must hold |
|---|---|---|---|
| `STATUS_LOCK_WAIT` | 100 ms | `supervisor.rs:43` | far below the desktop client's 2 s read deadline |
| `ACTIVATE_DIAL_DEADLINE` | 20 s | `supervisor.rs:34` | the daemon's own availability bound for the activation path; below the activation executor's |
| activation executor per-TCP `connect_timeout` / `dial_deadline` | 10 s / 30 s (unchanged) | `executor.rs:19, 22` | above the activation deadline: an activation can never end with `NETCORE_TIMEOUT` (its own 20 s fires first and says `ACTIVATION_CONNECT_TIMEOUT`); a slow-but-alive multi-hop activation is cut at 20 s, accepted because the activation deadline bounds how long the daemon's mutex can be held, not how long a route may take |
| ingress `connect_timeout` | config, default 20 s, range 100 ms to 120 s | config | the engine's outer bound for the whole upstream dial including resolution and proxy handshakes (6.7.2) |
| ingress executor `resolve_timeout` | `min(5 s, connect_timeout)` | main.rs | inside the outer bound |
| ingress executor per-TCP `connect_timeout` | = ingress `connect_timeout` | main.rs | measured from the end of resolution; the outer bound binds first |
| ingress executor `dial_deadline` | `ingress_executor_dial_deadline(r, c) = r + c + 5 s` | main.rs | above the engine's outer bound, so the executor never cuts an ingress dial before its own `connect_timeout`; it remains the safety net for callers that have none (`probe`). The function is pure and its table (c = 100 ms, 20 s, 120 s) is tested |
| durable audit append | 2 s queue + 5 s sync, before and after the dial | 6.4.6 | outside `connect_timeout` (the dial keeps its own bound) |
| `SESSION_SHUTDOWN_BOUND` | 1 s | 12.6 | below the desktop client's 2 s |

This supersedes the lifecycle theme's single formula `max(activation, ingress_connect) + 5 s`, which assumed one shared executor; with two executors (6.10) each deadline is set at its own executor (MD-25).

### 12.10 `SetIngress` in the supervisor

`SetIngress` follows the order of checks of 11.4: it validates an explicit id with `validate_profile_id` against the hoisted profiles, calls `ingress.arm(..)` or `ingress.disarm(..)` with `Actor::Operator { peer, client }` built from the `PeerIdentity` argument of `handle` and the mapped client label, and answers `status_answer`. `Deactivate` is 11.5.

### 12.11 Other crates

* **`ssk-netcore`:** done: `RouteKind::Fallback` is non-executable (`C-N1`, `executor.rs:170`); the whole-dial deadline, IPv6 literals in `connect_tcp`, bracketed IPv6 authorities and refusal of whitespace/control characters in `http_connect` (`C-N2`). To do: the resolver, pinned Direct dial, address guard, family filter, `TcpConnector` seam and race (`C-N3`, `C-N4`, 6.10); `SessionResolution` (6.10); (RELEASE) TCP keepalive (60 s idle, 20 s interval, via `socket2::SockRef`) on first-hop and Direct upstream sockets (`C-H1`; promoted from OPT because when a VPN application changes the route, existing Direct connections die silently and keepalive is what lets the daemon notice and close them). If `socket2` becomes a normal dependency of `ssk-netcore` the allow-list of the static test of 24.2.1 is extended in the same commit.
* **`ssk-netadmin`:** done: `MatchCriteria::matches` never applies `dest_suffix` to an IP literal, the planner never emits `Fallback` (`C-P1`). To do: `pub fn summarise_route` (`C-A1`, with a test that `HopSpec.auth` and addresses never appear in the summary).
* **`ssk-config`:** `C-T1` (host grammar), `C-C0`, `C-C1`, `C-A3` (5, 6.4.8).
* **`ssk-diag`:** crash records pruned to the newest 32 (`C-X1`).
* **`ssk-ipc`:** done: the Unix accept loop backs off and gives up on the 60th consecutive error (`C-I1`, pure `AcceptRetry`). To do: an injectable accept source with regression tests for the wiring (`C-I1b`); the named-pipe loop (`C-I1w`, Windows CI only); the wire changes (`C-IPC1`, 11); the client-side check that the process on the endpoint is the user's own daemon (`C-IPC2`, 25.2).
* **`ssk-winhost`:** `C-WIN1`, `C-WIN2`, `C-WIN3`, `C-CO6w` (15); the only place `unsafe` appears.
* **`ssk-daemon` outside `ingress/`:** `supervisor.rs`, `routing.rs`, `main.rs`, `paths.rs` (`Layout::flow_audit_dir()`, `Layout::dest_key_path()`), `shutdown.rs` (`ShutdownPlan`), `lock.rs` (`hold_until_exit`, `proof`).

### 12.12 Arithmetic and lint discipline for the ingress tree

The release profile sets `overflow-checks = true` (`Cargo.toml:144`) and `panic = unwind` (`Cargo.toml:130`). Every unchecked `+`, `-`, `*`, shift, `Instant + Duration` or narrowing `as` on the ingress's hostile-input paths (SOCKS lengths, token buckets, byte counters, deadlines) is therefore a panic, and three flow panics trip the whole ingress (6.1.3). That would make a crafted input or timing a "stop the proxy" button (a browser cannot deliver crafted SOCKS bytes, because HTTP and TLS never start with `0x05`, but any local process can). Three layers close it:

1. **Compile time.** `crates/ssk-daemon/src/ingress/mod.rs` begins with
```rust
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::todo,
        clippy::unimplemented, clippy::unreachable, clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap))]
```
The repository has no `clippy.toml`, its tests use `expect` throughout and CI runs `cargo clippy --workspace --all-targets -- -D warnings` (`ci.yml:75`), so the denies must not apply to test code. `cfg_attr(not(test), ...)` does that; running the deny set on 1.95.0 (the toolchain `rust-toolchain.toml` pins) showed it fails on `.expect()` in the module's own tests without the `cfg_attr`, that `#[tokio::test]`, `tokio::select!` and serde derive expansions raise none of the denied lints even with the allow removed, and that an unchecked `now + d` or `a + b` outside tests is an error (the equivalent form "deny, then `cfg_attr(test, allow(..))`" was also run and exits 0; MD-19).
2. **Idioms.** `checked_*` or `saturating_*` for integers; `Instant::checked_add` and `saturating_duration_since` for time (the explicit-`Instant` limiters of 6.5 take `now` as an argument and never subtract two `Instant`s with `-`); `usize::try_from` for lengths; `slice.get(..)` for indexing; atomics use `fetch_add`, which wraps and never panics (a 64-bit byte counter cannot wrap in practice); std Mutexes through the poison-tolerant helper (L13); the epoch uses `checked_add` and closes the gate on exhaustion (6.9.1).
3. **Runtime containment.** A panic that still gets through (in tokio, serde or the standard library) ends one flow task, not the daemon (`JoinSet`; the worker survives). The budget counts panics, not aborts (`is_cancelled` is not counted); it resets on a start or a recover; and `ssk-diag` writes one crash record per panic (`install_panic_hook`, `ssk-diag/src/lib.rs:319-372`, with `sync_all` per record and no cap until `C-X1`), which is why the budget is small and why `C-X1` is RELEASE.

Out of scope of the lint: arithmetic in dependencies, and the existing code outside `ingress/` (for example `AcceptRetry` in `ssk-ipc` already uses `saturating_*` and says why, `server.rs:185`). The GUI crates apply the same set to the V3 projection module (25.9).

## 13. Failure semantics: no direct fallback, ever

### 13.1 Failures of the ingress itself

| Failure | Caller or client sees | Gate / daemon state | Record |
|---|---|---|---|
| ingress disabled / disarmed / tripped / unavailable | TCP close, zero bytes | unchanged | counter only |
| peer refused or Unknown | TCP close, zero bytes | unchanged | counter (Summary) |
| malformed / numeric alias / localhost target | SOCKS `08` | unchanged | counter per kind only |
| policy deny / no rule / attestation / unknown adapter / special-use / self-loop / name not eligible | SOCKS `02` | unchanged | durable `Denied` (first occurrence, inside the quota) |
| OpenVPN route, not dialable route, missing guard | `01`, `OPENVPN_NOT_READY` / `ROUTE_NOT_DIALABLE` / `DIRECT_GUARD_MISSING` | unchanged | `Denied`; no pending, no socket |
| IPv6 literal under `ipv4_only` | `08`, `DIRECT_FAMILY_DISABLED` | unchanged | `Denied` |
| adapter down, refused, handshake rejected, silent proxy | `05` / `04` / `01` | unchanged | `Pending`, `Result failed` |
| Direct name: resolver busy / DNS failure or timeout / answer contains a special-use, listener or exact-IP-denied address / no candidate after the family filter | `01` / `04` / `02` / `04` | unchanged | `Pending`, `Result failed` with `NETCORE_RESOLVER_BUSY` / `NETCORE_DNS_FAILED` or `NETCORE_TIMEOUT` / `NETCORE_ADDR_REFUSED` / `NETCORE_FAMILY_DISABLED` |
| lower-priority Direct rule exists | same as above; first match wins, **no second attempt** | unchanged | exactly one pending + one failed result |
| one durable audit append times out | the flow gets `01`, no dial | unchanged; counter `audit_timeouts` | none for that flow |
| audit write fails before dial (I/O error) | `01`, no dial | ingress `tripped` | none possible |
| audit write fails after connect (I/O error) | upstream dropped, no reply | ingress `tripped` | pending exists, no result |
| one `sync_data` stalls for 30 s | later flows get `01` | gate `tripped(AuditStalled)` | `Tripped` best effort |
| flow task panics | that connection dies | none until panic budget (3) | `Closed` compensated; crash record capped |
| gate change / disarm / shutdown | EOF | unchanged | `Closed{gate_closed\|shutdown}` from the receipts |
| failure cool-off active for a chain (`C-E4`) | `01` | unchanged | coalesced `Denied ADAPTER_COOLING_OFF`, no dial |

### 13.1a Control-plane failures

| Failure | Caller or client sees | Gate / daemon state | Record |
|---|---|---|---|
| Disarm while an arm is in its fsync | disarm: ok at once. Arm: `INGRESS_SUPERSEDED` | `disarmed` | `Armed` intent, then `Disarmed{arm_superseded}` |
| Trip while an arm is in its fsync | arm: `INGRESS_TRIPPED` | `tripped` | `Armed` intent, `Tripped`, `Disarmed{arm_superseded}` best effort |
| Two concurrent arms with different profiles | both ok in arrival order | `armed(second)` | `Armed(first)`, `Armed(second)` |
| Requester disconnects or its handler future is dropped during arm or recover | none | the control task finishes; the gate is either unchanged or fully armed | as above |
| A control task panics | `INGRESS_CONTROL_FAILED` | `tripped(ControlPanic)` | `Tripped` best effort |
| Soft descriptor limit too low for even 8 tunnels | `INGRESS_FD_LIMIT_TOO_LOW` on arm | `unavailable` | `Started` only |
| IPC `accept()` fails 60 times in a row | IPC unreachable, then the daemon exits (`EXIT_SERVER`) | daemon stops; the ingress stops with it | none |
| `Deactivate` in `FailClosed` without `release_kill_switch` | `KILL_SWITCH_ARMED` whose message says the proxy was disarmed | ingress `disarmed`; session still held | `Disarmed{deactivate}` |
| Activation future dropped or panicking during its dial | the requester (if any) gets nothing | `FailClosed` with `ACTIVATION_CANCELLED` | terminal `FailClosed` record |
| Shutdown while flows are open | EOF | `Closing`, then the process ends | `Closed{shutdown}` from each flow's receipt; terminal `result` for an abandoned pending |

What the daemon cannot prevent (stated in the notice, status and docs): an application that is configured to use the proxy may itself fall back to a direct connection when the proxy refuses; applications that never use the proxy; DNS an application resolves before reaching the proxy (an IP-literal request will not match a domain rule); any UDP.

### 13.2 A third-party tunnel application underneath: what is detected, what is not, how it fails

Honesty rule for the whole section: Kaleidoscorp does not defend against any failure of the tunnel application. The defence is that application's own kill switch. Kaleidoscorp enforces policy for proxy clients, audits, and shows true observations. Statements about Windows or about a third-party product are UNVERIFIED unless a repository file or a command run for this review is cited.

#### 13.2.1 Detectable and not detectable

| Fact | Detectable? | How and where shown |
|---|---|---|
| Which interface the OS routing table selects for the probe address (a documentation address) now; that it changed and what it was | yes, as an observation of the probe only, not of any real destination | best-route lookup of the probe address (6.12); `observations.route_v4/v6`, `previous`, warning `OS_ROUTE_CHANGED` |
| The local address the OS gave sskd's own socket for one flow | yes | `TcpStream::local_addr()`; `Result` observation `egress_local`, `last_direct_source` |
| That an interface is a tunnel adapter; that the tunnel application runs or is connected | no, never inferred from names | nothing shown (10.6) |
| That `sskd.exe` is on or missing from a split-tunnel list | no | only the operator's echo test (13.2.3, 24.2.3 step 6) |
| The public exit address; where DNS goes; whether IPv6 is blocked or tunnelled | no (CO-6) | operator steps; only `DIRECT_MAY_USE_IPV6` is shown |

#### 13.2.2 Tunnel drops, reconnects, sleep, network changes

| Event | Effect on Kaleidoscorp's traffic | Status shows | Defence |
|---|---|---|---|
| Tunnel drops, flows open | Open Direct sockets lose their path and end by reset or timeout (OS and application). There is no upstream liveness check; a flow with no byte either way is closed by `idle_timeout_ms` (default 1 h), so a dead flow can stay in `active_flows` that long. Keepalive (`C-H1`: 60 s idle, 20 s probe interval) shortens it to minutes, the exact bound depending on the probe count, which `C-H1` must set explicitly and test; idle eviction (`C-E5`) frees permits at capacity | `active_flows` counts flows, not liveness; `OS_ROUTE_CHANGED` within about 5 s if the selected interface changed | none in Kaleidoscorp |
| Tunnel down, its own kill switch ON | New dials are blocked by that application's rules (mechanism UNVERIFIED); the client gets a SOCKS failure reply (7.2); ledger: `Pending` and a failed `Result` | `armed` unchanged, `connect_failed` rises | that kill switch |
| Tunnel down, no kill switch | New Direct dials follow the routing table out of the physical adapter. Kaleidoscorp neither blocks nor notices at dial time; the destination sees the ISP address | `OS_ROUTE_CHANGED` after at most one poll; `egress_local` of new flows is the physical adapter's address; `state` stays `armed` | that kill switch; nothing else |
| Tunnel reconnects | The adapter may return with a new address or index; new flows follow it, old flows do not migrate | `previous` shows the old identity for 10 min | - |
| Sleep and resume; Wi-Fi to Ethernet; DHCP renewal | As a drop plus reconnect, or a route change without a tunnel; the poller resumes by itself | `OS_ROUTE_CHANGED` | as above |

Deliberately NOT done: disarming or cancelling flows on an observed route change, and the resume-skew heuristic of draft 1 (`C-H2`, removed; MD-13). A poll lags by up to 5 s and cannot affect sockets already routed, roaming would trigger it falsely, a heuristic that compares a wall clock with a monotonic clock whose Windows behaviour is unknown would cancel live flows (and a changed system clock could trigger it), and it would read as a kill switch Kaleidoscorp does not have. If ever wanted it needs its own config key and so a later config version.

#### 13.2.3 Split tunnelling and the dialling process

The dialling process is `sskd.exe` (CO-2). All of the following are UNVERIFIED for any specific product.

* If `sskd.exe` is in a bypass list, or missing from an include-only list, its Direct connections silently skip the tunnel while the browser (not the dialling process) may be listed and is irrelevant. Kaleidoscorp cannot see this: a route lookup shows system-wide routes, a per-application driver acts below it, and `egress_local` may or may not differ depending on how the product steers. The arbiter is the echo test: the address through the proxy must equal the system path's address while the tunnel application is connected.
* A list keyed by executable path must name the path that runs. A developer who rebuilds into `target/debug` or `target/release` changes it; a list keyed otherwise may break on every rebuild. Run `sskd.exe` from one stable path while testing.
* `ssk.exe` and the GUI never dial and need no entry. If the tunnel application has an application-scoped kill switch, `sskd.exe` is the application to list.

#### 13.2.4 Two kill switches

**Proven by the repository.** The firewall kill switch adds one rule: `netsh advfirewall firewall add rule name=SSK-KillSwitch-... dir=out action=block enable=yes profile=any localip=any remoteip=any`, no `program=` filter, no interface, no exception (`firewall.rs:589-606`; test `add_args_are_outbound_block_all`, `:1526-1534`). It is the interim actuator and its rules persist (`firewall.rs:89-92`). `ssk winhost killswitch engage` takes a `Pinned` claim that survives the process and a reboot (`ssk-cli/src/main.rs:2916-2923`, `lease.rs:62-69`). The daemon never engages or releases it; it only reads a cached, bounded-age view (`killswitch.rs`, `ssk-daemon/src/main.rs:190`), and `main.rs` says no privileged service has ever been installed or started. Naming hazard: the daemon's `KILL_SWITCH_ARMED` error and `release_kill_switch` flag concern its own `FailClosed` state and do not reach the firewall rule (`supervisor.rs:817-830`; comment `:847-852`). In ingress documents "kill switch" means the firewall rule and "fail-closed state" means `FailClosed`.

**Expected, NOT verified** (Windows Firewall semantics are general knowledge; no Windows machine was available):

| Order | Expected result | Recovery |
|---|---|---|
| Tunnel connected, then Kaleidoscorp engages | The rule blocks outbound connections of every program: application traffic and the tunnel application's own transport. The tunnel stops carrying traffic; its client may retry, and the retries are blocked too | `ssk winhost killswitch release` (local pipe, needs no network), then reconnect |
| Engaged first, then the tunnel application connects | It cannot reach its server | release first |
| Engaged, then reboot | Rule and pinned claim persist; the tunnel application's auto-connect fails; no network until released | release |
| Both engaged, one released | Each keeps blocking until its owner releases it | each owner |
| Another vendor's allow rule | Windows Firewall block rules are generally stronger than allow rules, so allowing the tunnel application is not a way around ours; the tunnel product may also filter by other means. Do not rely on either order | - |
| Ingress armed while engaged | The daemon's own dials are blocked, so proxy connections can fail. Whether the loopback connection itself is affected is UNVERIFIED | release |

**Behaviour in this mode (decided).** The firewall kill switch is not a component of the scenario.

* B-1 `ssk winhost killswitch engage` pre-flights before opening the broker pipe: `GetStatus` with a hard 3 s budget (`call_daemon_at` has no timeout, `ssk-cli/src/main.rs:632-654`, so a bounded helper is added) and refusal with `KILLSWITCH_REFUSED_INGRESS_BOUND` when `ingress.listen.is_some() || ingress.state == "armed"`, that is, a loopback listener exists. The text says: the local proxy is bound on that address; the rule this command installs blocks outbound traffic of every program on this machine, has no program, interface or address exception, also blocks sskd's own connections and any third-party tunnel application's, and is pinned across reboots; nothing was changed; use the tunnel application's own kill switch, or disarm and stop the proxy first, or pass `--allow-with-ingress`. No forbidden word.
* B-2 If the daemon is unreachable or silent for 3 s the command proceeds as today and prints one note. The guard is advisory, not a security boundary; the broker's authorisation is unchanged.
* B-3 `--allow-with-ingress` skips only the pre-flight.
* B-4 Status: warning `KILL_SWITCH_ENGAGED` (10.5) while a listener is bound and the view is `EngagedConfirmed`; nothing else changes.
* B-5 No daemon, ingress or GUI path engages or releases the rule. If the Tauri bridge's `KillSwitchControl` (`ssk-tauri-bridge/src/control.rs`) is ever wired to a button it applies B-1 first; the webview has no such command today (`apps/desktop/src/main.rs` registers only `get_panel_snapshot_v2`).
* Why a CLI guard and not a mode flag: the rule is owned by a LocalSystem service that does not read the user's config, a daemon-side flag cannot stop a client from engaging, and the predicate is a fact (a listener is bound), not a belief about third-party software. Not planned: a kill switch with an exception for the tunnel application's executable (it needs vendor paths Kaleidoscorp must not hard-code).

#### 13.2.5 IPv6

* IPv6 is a path around an IPv4-only tunnel for any application and for Direct dials alike; whether the tunnel application blocks, tunnels or ignores it is its own property.
* Kaleidoscorp-originated exposure: `getaddrinfo` returns both families and the OS orders them (typically IPv6 first on a machine with a global IPv6 address). `direct.rs:25` hands a name to tokio, whose per-address loop dials the first address and tries the next only after it fails, under one timeout (CO-4). With a tunnel that does not cover IPv6 a dual-stack name connects over the physical adapter; with one that silently drops IPv6 every dual-stack name times out.
* So the first config version carries `ingress.direct_address_families`, default `ipv4_only`: the pinned dial removes IPv6 candidates (after the guard pass) and an IPv6 literal is refused with `DIRECT_FAMILY_DISABLED` (SOCKS reply `08`). IPv6-only sites are unreachable through Direct in that mode; the RUNBOOK says so. `any` is for tunnels that cover IPv6, tries IPv4 first and adds `DIRECT_MAY_USE_IPV6` while an IPv6 route is observed. The setting also covers the first hop of proxy chains (same dial function); an adapter host that is an IPv6 literal under `ipv4_only` is a validation error (5.3).
* Applications may still use IPv6 around the proxy (16).
* Tests that need `::1` self-skip with a printed reason (`direct.rs` `bind_ipv6_loopback`); `SSK_REQUIRE_IPV6=1` makes a missing `::1` a failure, set only on a leg where it was verified. The review machine has no IPv6 (`/proc/net/ipv6_route` does not exist), so no IPv6 dial ran here.

#### 13.2.6 DNS

| Client behaviour | Who resolves | Kaleidoscorp sees | Rules |
|---|---|---|---|
| SOCKS5 domain request (curl `--socks5-hostname`, a browser set to resolve through the proxy) | Direct: sskd, once, with the OS resolver. Proxy route: the upstream proxy | the name | by name |
| SOCKS5 address request (curl `--socks5`, client-side resolution) | the application, before it connects | an IP literal | domain rules do not match (2.4) |

Kaleidoscorp adds no resolver, cache or override (CO-3), so DNS follows the OS configuration: the servers it holds per interface, whatever the tunnel application set, whatever leaks around it. It neither knows nor claims where queries go. Observed with curl 8.5.0 on Linux against a loopback stub SOCKS5 server for this review: `--socks5-hostname` sends the name (ATYP 3), `--socks5` sends the locally resolved address (ATYP 1), both exit 97 on a SOCKS5 reply `02`. If the OS resolver answers a Direct name with a special-use address (a resolver-side block answering `0.0.0.0` is an example; whether any product does it is UNVERIFIED) the flow is refused under the special-use rule of 6.10 and nothing is dialled. A blocking `getaddrinfo` already running cannot be cancelled by the dial deadline (C.3); such calls are bounded by `MAX_CONCURRENT_LOOKUPS` = 16 against tokio's 512-thread blocking pool (`tokio-1.53.1/src/runtime/builder.rs:306`), an accepted limitation.

## 14. Threat mitigations

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 1 | Other local user/process uses the proxy | typed loopback bind; peer authorizer before the first byte and before shared budgets; `Unknown` refuses; client row in `tcp` and `tcp6`, states 01/04/05, inode non-zero, exactly one row; uid convention `getuid` equal to ssk-ipc, peer check refused when `getuid != geteuid`; real self-test in `controls()`; batched single-thread snapshots; `hardening: required` default; Windows unavailable until `C-WIN1`..`C-WIN3` | `peer_other_user_is_refused_before_any_byte`, `peer_refusals_do_not_consume_accept_budget`, `owner_lookup_returns_own_uid_for_a_real_loopback_connection`, `half_closed_client_is_still_authorized`, `orphaned_client_is_refused`, `different_uid_client_is_refused` (root only), `identity_ambiguous_disables_peer_check`, `hardening_required_makes_unhardened_platform_unavailable` |
| 2 | Port squat / hijack | no fallback port; bind error => `unavailable`; `local_addr` re-asserted; bounded bind retry per platform (6.9.4); Linux semantics probed by a test; Windows exclusive bind (`C-WIN1`) | `bind_failure_is_reported_and_ipc_stays_up`, `second_bind_to_live_listener_fails_on_linux`, `bind_retries_addr_in_use_with_backoff_then_succeeds`, `bind_permission_denied_is_not_retried` |
| 3 | Browser / cross-protocol | first byte must be `0x05` else zero-byte close; no HTTP on the port in M2 | `cross_protocol_first_bytes_get_zero_bytes_back` |
| 4 | SSRF / special-use / numeric aliases | canonicalisation before policy; literal special-use needs the matched rule's exact destination AND port; resolved answers all guarded, any special-use or exact-IP-denied answer refuses (a deny rule cannot be walked around by sending a name); suffix never matches IPs; config rejects address-form hosts (`C-T1`) | `numeric_alias_targets_refused_before_policy`, `special_use_needs_matched_rule_destination_and_port`, `portless_exact_rule_does_not_unlock_loopback`, `deny_rule_literal_does_not_unlock_port_only_rule`, `direct_name_resolving_to_special_use_is_refused_without_a_connection`, `direct_name_resolving_to_a_denied_ip_is_refused_without_a_connection`, `exact_ip_deny_applies_to_resolved_names_at_any_priority` |
| 5 | Self-loop | non-overridable literal guard before policy; resolved-address guard (loopback always refused); first-hop guard for adapter host names; bind-time and config literal checks | `self_loop_target_refused_even_with_matching_rule`, `self_loop_via_first_hop_name_refused`, `adapter_pointing_at_listener_makes_ingress_unavailable` |
| 6 | DNS path and leaks | denied or unmatched names never resolved; one OS lookup per admitted Direct flow, after durable `Pending`; proxied names forwarded unresolved; `dns_protected` untouched; the ingress makes no DNS claim | `denied_names_never_reach_the_resolver`, `resolver_is_called_only_after_pending_is_durable`, `proxied_route_forwards_name_unresolved_and_never_resolves` |
| 7 | Parser abuse / smuggling | exact-length reads, no `BufReader`, deny-panic and arithmetic lints, proptest | `socks5_parser_*`, `socks5_parser_never_panics_on_arbitrary_bytes` |
| 8 | Resource exhaustion | permits via `try_acquire`, buckets, deadlines, backoff, descriptor budget by construction (7.3), capacity wait, pre-admission slots with oldest-silent eviction and budgets charged only after the handshake (7.1), IPC accept fix, shutdown plan | `max_connections_enforced_and_slot_reused`, `slowloris_handshake_times_out`, `silent_connections_do_not_prevent_an_authorised_handshake`, `ingress_flood_cannot_starve_ipc_under_a_small_nofile_limit`, `ipc_reserve_covers_measured_baseline`, `fd_budget_table` |
| 9 | Audit flooding | own ledger, group commit, first-occurrence-durable coalescer, Summary, refusal quota, rotation/retention, no ledger read in status | `denial_flood_stays_bounded_and_reconciles`, `rotation_preserves_chain_and_prunes_oldest` |
| 10 | Log / crash injection | validate then log; DEBUG-only escaped truncated raw text; panic budget; crash-record cap | `crlf_host_cannot_forge_a_log_line`, `crash_records_are_capped` |
| 11 | Confused deputy | profile only from arm / `arm_on_start` / the CLI's explicit validated id; constant `app_id`; no client credentials or profile input; the GUI sends no profile | `client_cannot_influence_profile_or_app_id` |
| 12 | Honest status | section 10; the fresh-overlay rule | `status_never_claims_protection_while_armed`, `ingress_strings_contain_no_forbidden_words`, `status_overlay_is_fresh_during_activation`, `headline_claims_activity_only_when_armed` |
| 13 | Direct fallback | executor Fallback removed (done); route guard; one dial site | `fallback_route_never_dials_direct`, `dead_adapter_plus_lower_priority_direct_never_reaches_target` |
| 14 | TLS terminal hop | `ROUTE_NOT_DIALABLE` unless last hop is Socks5/HttpConnect | `tls_terminal_route_is_refused` |
| 15 | DNS rebinding / check-then-use on Direct names | one answer per flow, every address guarded before any socket, pinned `SocketAddr`, no second lookup anywhere | `resolver_called_exactly_once_per_dial_even_when_first_address_fails`, `second_answer_of_a_rebinding_resolver_is_never_used`, `direct_by_name_reaches_the_resolver_through_the_wired_executor`, `ingress_executor_builder_installs_guard_and_family_filter` |
| 16 | Resolver exhaustion / blocking-pool starvation | 16 permits tied to the lookup thread, 5 s deadline, a bounded 500 ms wait (32 waiters) before `ResolverBusy`, abandoned lookups counted, peer service on its own thread | `stuck_lookups_do_not_exhaust_the_blocking_pool`, `resolver_permit_is_held_until_the_thread_returns`, `a_17th_name_waits_for_a_permit_and_succeeds_when_one_frees`, `sixteen_lookups_blocked_for_30s_then_a_17th_distinct_name_is_busy_after_the_wait` |
| 17 | CPU amplification by the peer check | batching, adaptive duty cycle, 16 MiB cap, bounded queue, 500 ms `Unknown` | `snapshot_service_batches_concurrent_requests`, `snapshot_rate_is_bounded_under_flood` |
| 18 | Search-list rewriting: the OS may resolve a different FQDN than the approved name | accepted limitation (a trailing dot would disable hosts-file entries, probe); the answer is still guarded; recorded in 6.11 | none (documented) |
| 19 | Other local user reads the destination log | dir 0700 and files 0600 created atomically with the mode; existing store verified, never repaired; state root must be owned by `geteuid()` and not group or world writable | `ledger_dir_and_files_have_private_modes`, `existing_group_readable_ledger_dir_is_refused_not_repaired`, `state_root_writable_by_others_is_refused` |
| 20 | Symlink, hard link or planted file in a shared or writable state directory | dirfd-relative access, `O_NOFOLLOW`, `O_EXCL`, owner and `st_nlink == 1` checks | `symlinked_ledger_dir_is_refused`, `symlinked_segment_is_refused`, `hard_linked_segment_is_refused`, `owner_check_table` |
| 21 | Destination leaks through logs, status, IPC or flow lists in hashed mode | rule 15, one `DestRef` type, capture test over every surface | `hashed_mode_leaks_no_host_on_any_surface`, `tracing_capture_at_debug_has_no_destination_in_hashed_mode` |
| 22 | Offline dictionary attack on hashed destinations | keyed token, key outside the ledger directory, mode 0600, never exported | `token_golden_vectors`, `dest_key_file_is_private_and_outside_the_ledger_dir`, `hashed_without_key_is_unavailable_never_plain` |
| 23 | A denial flood evicts admitted-flow evidence | per-segment refusal quota (20 + 5 percent), summary floor | `denial_only_flood_never_rotates_or_prunes`, `evidence_keeps_75_percent_of_every_segment` |
| 24 | Orphan Pending after timeout, cancel, panic or abort | job state machine plus RAII receipts with compensation | `cancelled_in_queue_writes_nothing`, `abandoned_after_claim_is_compensated`, `dropped_receipt_compensates_exactly_once`, `abort_all_leaves_a_closed_story` |
| 25 | A transient fsync stall trips the proxy, or a permanent stall goes unnoticed | timeouts never trip; 30 s stall detector trips | `timeout_never_trips_but_io_error_does`, `stall_detector_trips_after_30s_fake_clock` |
| 26 | Crash between create, rotate and prune loses an acknowledged record or leaves a fork | durability order D1 to D6 and the recovery rules | `crash_after_segment_create_before_first_sync`, `crash_between_rotate_and_prune`, `pruned_segment_reappears_after_crash`, `directory_fsync_order_is_asserted` |
| 27 | Log injection through host names | rules R-L1 to R-L6 | `ledger_line_has_exactly_one_newline_for_any_string`, `crlf_host_cannot_forge_a_log_line`, `netcore_error_display_never_reaches_tracing` |
| 28 | Old records cannot be interpreted after a configuration change | `Started` fingerprint, `Armed` rule table, flow ids name their Started | `fingerprint_stable_under_reordering_and_renames`, `armed_record_lists_rule_ids_without_destinations` |
| 29 | Control-plane races: a late arm undoes a disarm or a trip; a requester that disconnects leaves half an arm | one gate, compare-and-set on the epoch, detached control tasks, FIFO control lock, `trip` never blocks (3.2) | `arm_in_flight_loses_to_disarm`, `arm_in_flight_loses_to_trip_and_reports_tripped`, `trip_never_waits_for_the_control_lock`, `concurrent_arms_serialise_and_the_ledger_agrees_with_the_gate`, `control_tasks_survive_requester_drop`, `set_ingress_disarm_during_an_arm_in_flight_supersedes_it`, `recovery_installs_a_fresh_writer_and_a_second_recovery_works` |
| 30 | Kaleidoscorp is mistaken for a kill switch or a statement about a third-party tunnel | vocabulary rules, never-claim list, observations labelled, echo test as the arbiter, CLI guard against the firewall rule (10.6, 13.2) | `ingress_strings_contain_no_forbidden_words`, `no_tunnel_vocabulary_in_path_and_snapshot`, `observed_text_never_enters_fixed_strings`, `ingress_never_touches_the_kill_switch` |
| 31 | Another process of the same user, or script in the webview, arms or disarms the ingress | same principal cannot be separated (25.2); no profile, port or rule in the request; rate limit; every change recorded with the verified peer; CSP, no sinks, zero-argument commands, bundled origin only | the tests of 23.9 and 25.8 |
| 32 | A process other than the user's own `sskd` answers on the IPC endpoint (a pre-created named pipe on Windows, a planted socket if the state directory is shared) and the GUI or CLI shows or acts on its answers | the client verifies the server before the first frame (`C-IPC2`, 25.2): Unix `peer_cred().uid == getuid()` and a socket file owned by `geteuid()`; Windows the pipe's owner equals the current SID (the client-side analogue of `require_pipe_owner`, `pipe.rs:1219`); until it lands the GUI says that a status is the report of the process on the endpoint and the RUNBOOK names the gap | `ipc_client_refuses_a_server_of_another_uid` (fake squatter, Linux), `ipc_client_refuses_a_pipe_owned_by_another_sid` (Windows only, UNVERIFIED) |
| 33 | Admitted-flow volume prunes earlier evidence (a runaway loop, or any process that is allowed to use the proxy) | the real window is stated (about 1.8 h at the sustained admission cap, 6.4.8), `AUDIT_WINDOW_SHORT`, `oldest_ts_ms` and `pruned_entries` in status; a minimum-age floor is an owner decision (B18), not adopted | `admitted_flow_volume_prunes_oldest_first_and_status_says_so`, `audit_window_short_warning_follows_pruned_entries_and_oldest_age` |
| 34 | The safety-narrowing request is throttled or swallowed (a flapper empties the bucket; a no-op check hides a disarm; the GUI's own arm blocks its disarm) | a disarm is never rate limited, never short-circuited, has its own client slot and no floor; the IPC connection cap is a stated residual (11.4) | `set_ingress_disarm_works_with_an_empty_arm_bucket`, `set_ingress_disarm_is_never_short_circuited_as_a_noop`, `a_disarm_does_not_queue_behind_the_clients_own_arm` |

## 15. Windows plan (cannot be verified here)

Nothing here was executed on Windows. Owner decision 1 (C.1) governs: M2 is accepted on Linux; the Windows hardening commits follow and are verified on a real Windows machine; until then `hardening: required` leaves the ingress unavailable on Windows.

**Names.** `C-WIN0` (the baseline, SPINE: std-only ledger store, plain bind, no hardening claim), `C-WIN1` (exclusive bind), `C-WIN2` (owner check), `C-WIN3` (private audit store, 6.4.9), `C-CO6w` (route observation, 6.12). Every earlier "W1/W2" means `C-WIN1/C-WIN2`; the wire-types commit `C-W1` is renamed `C-IPC1`.

### 15.1 What the repository proves

* On Windows mio's `TcpListener::bind` sets neither `SO_REUSEADDR` ("allows socket hijacking, so we explicitly don't set it") nor `SO_EXCLUSIVEADDRUSE`; on Unix it sets `SO_REUSEADDR` (`mio-1.2.2/src/net/tcp/listener.rs:63-83`, the locked version).
* The kill-switch rule has no program, interface or address exception (`firewall.rs:589-606`, test `:1526-1534`).
* The owner-table code is IPv4 only (`connections.rs:21`); the only existing peer match accepts TCP state 5 alone (`vpn_endpoint.rs:83`, `connections.rs:131-132`).
* `serve_named_pipe` returns on the first accept or instance-creation error (`ssk-ipc/src/server.rs:429-432, 460`).
* No code handles power or session events (no `PBT_APM*`, `RegisterPowerSettingNotification`, `SERVICE_CONTROL_POWEREVENT` anywhere), `ServicePreshutdown` is only triggered in tests, `sskd` is not hosted by `ssk-svc`, and nothing starts `sskd` at logon.
* `windows-sys 0.59.0` declares the IP Helper calls used; the function of 6.12 compiles for `x86_64-pc-windows-gnu`.
* CI runs the daemon crate's tests on `windows-latest` (`windows_crate_gates`), on an administrator account (`ci.yml:257`).

Windows runtime behaviour is UNVERIFIED; 15.12 is the register.

### 15.2 The configurations on Windows

| Config | State before `C-WIN1`, `C-WIN2` and `C-WIN3` are verified on real Windows | Status says | Who can use the proxy |
|---|---|---|---|
| default, `enabled: false` | `disabled`, no socket | Local proxy: off | nobody |
| `enabled: true`, `hardening: required` (default) | `unavailable`, `INGRESS_HARDENING_UNAVAILABLE`, missing `[exclusive_bind, peer_check, private_audit_store]`, nothing bound | Proxy unavailable: INGRESS_HARDENING_UNAVAILABLE | nobody |
| `enabled: true`, `hardening: best_effort` (first usable Windows config; exists from `C-WIN0`) | `disarmed` after start, `armed` on request; all three controls false; warnings `PEER_CHECK_INACTIVE`, `EXCLUSIVE_BIND_INACTIVE`, `AUDIT_STORE_NOT_PRIVATE`; every `Pending` and `Denied` record has `peer_verified: false` | disarmed (the default start state): Proxy ready, not activated: connections are refused. If activated, other local accounts could use it: there is no peer check. After an arm: Proxy active for applications that use it (profile P). Everything else is not covered. Other local accounts may also use it: there is no peer check. | 15.3 |
| after `C-WIN1` only | `exclusive_bind: true`; `required` stays unavailable | | |
| after all three verified | `required` usable; the pin test of 15.11 is edited in the same commit | warnings gone | other accounts refused (UNVERIFIED) |

**What makes the `best_effort` row exist.** Draft 2 called `best_effort` the first usable Windows config, but gave Windows no ledger store and no bind before the Windows-last hardening commits: `fs_win.rs` was a stub until `C-WIN3` and the Windows bind arrived with `C-WIN1`, so on the owner's only target the ingress would have been unavailable, or the Windows leg of `C-F2` red, until those were verified. `C-WIN0` (SPINE, after `C-A5` and `C-G7b`, before `C-F2`) is the baseline: the std-only ledger backend of 6.4.9, tokio's plain `TcpListener::bind` with the Unix retry schedule of 6.9.4, `Controls {false, false, false}` and no peer authorizer. It makes no hardening claim, so owner decision 1 stands: `required` stays `unavailable` on Windows until `C-WIN1` to `C-WIN3` are verified, and `C-WIN0` is itself unverified on real Windows (CI only). `C-WIN1` to `C-WIN3` replace parts of it.

### 15.3 `best_effort` on Windows, said exactly

* **Use.** Any process of any local account in any session (fast user switching, remote desktop) that can open a TCP connection to `127.0.0.1:port` can send SOCKS5 requests, judged under the armed profile, which is not per user. Here that means another account's traffic leaves through the owner's route (through the third-party tunnel, if it is connected: the owner's exit address, attributable to the owner's subscription) and is recorded as `local-proxy:unattributed` with `peer_verified: false`. It cannot read the owner's flows.
* **Squat before the bind.** If another process already listens on the port the bind fails (`INGRESS_BIND_FAILED`, retried per 6.9.4) and applications configured for that port talk to the squatter, not to sskd: SOCKS5 requests with host names and, for plain HTTP, the application bytes. Status says `starting` or `unavailable`; the applications cannot know.
* **Sharing after the bind.** The bind has neither `SO_EXCLUSIVEADDRUSE` nor `SO_REUSEADDR` (15.1). Whether another account can then bind the same port with `SO_REUSEADDR` is UNVERIFIED Windows behaviour; `EXCLUSIVE_BIND_INACTIVE` says so.
* **The destination log is not verified as private** (`AUDIT_STORE_NOT_PRIVATE`): the state directory under `%LOCALAPPDATA%` inherits the user profile's ACL.
* **Not weakened:** same-user hostile code is out of scope in every mode (6.6).
* **Who may enable it:** an operator who accepts this, on a machine with one interactive account (open question B9). Never a shipped default.
* **Visible as:** `controls`, the three warnings, the headline variant (10.2), `peer_verified: false`, doctor `ingress:controls` at WARN.

### 15.4 `C-WIN1`: exclusive bind, retry and TIME_WAIT

`C-WIN0` supplies the plain bind that this commit replaces (tokio's `TcpListener::bind`, which sets neither `SO_REUSEADDR` nor `SO_EXCLUSIVEADDRUSE` on Windows, 15.1, with the Unix retry schedule of 6.9.4). `bind_exclusive_loopback(addr: SocketAddrV4, backlog: i32) -> io::Result<std::net::TcpListener>` in `ssk-winhost/src/ingress_bind.rs` follows `vpn_endpoint.rs::reserve` (`:23-48`: raw `setsockopt(SO_EXCLUSIVEADDRUSE)` before `bind`; socket2 has no setter) with a fixed port, backlog 128, and no `SO_REUSEADDR` ever. The daemon adapter calls `set_nonblocking(true)` and `tokio::net::TcpListener::from_std`.

A review of draft 1 found that bind was retried only by manual re-arm. The assumption (UNVERIFIED) is that a listener bound with `SO_EXCLUSIVEADDRUSE` cannot be re-bound while connections to its old local port linger in TIME_WAIT, commonly about 120 s after a crash or update; a plain `best_effort` bind is expected not to have the delay, so it is a cost of `C-WIN1`. Linux cannot reproduce it: mio sets `SO_REUSEADDR`, and in this review's sandbox a rebind with it succeeded while TIME_WAIT sockets existed, a rebind without it failed with `EADDRINUSE`, and a second bind to a live listener failed with and without it. The Windows bind schedule (500 ms doubling to 30 s, window 150 s) and the platform-neutral rules of retry are in 6.9.4; they are testable on every OS with a fake platform, an injected clock and a sleeper. An explicit arm from `unavailable(BIND_FAILED)` is a `recover` with the short schedule (MD-15). Manual verification: 24.2.3 step 13. An `#[ignore]`d `exclusive_bind_rebind_delay_after_time_wait` can record the real delay on demand; it is not a gate.

### 15.5 `C-WIN2`: owner check

`loopback_peer_owner(client, listener) -> OwnerVerdict` in `ssk-winhost/src/loopback_owner.rs`, reusing `connections.rs`.

* IPv4 table only; exactly one row with `local == client` and `remote == listener`; any other count is `Unknown`.
* States: ESTABLISHED (5, proven) plus the half-close states of a client that wrote its request and closed its sending side (6 FIN_WAIT1, 7 FIN_WAIT2, 8 CLOSE_WAIT per the `MIB_TCP_STATE` documentation, UNVERIFIED here). Do not copy the `state == 5` of `vpn_endpoint.rs:83`.
* PID non-zero; open the process, read the token user SID, compare with `current_user_sid()`. Any failure is `Unknown`, and `Unknown` is refused. PID reuse between table read and open is a documented weakness (`pipe.rs`).
* A client reaching `127.0.0.1` through a dual-stack `AF_INET6` socket may or may not appear in the IPv4 table (UNVERIFIED). If not it is refused and counted as `refused_peer`. The real-machine test of this commit uses a dual-stack client and records the result; if such clients are refused, the reader gains the IPv6 table and v4-mapped matching BEFORE the controls flip to true.
* One table read per batch through the `PeerTableService` (6.6) with a `GetExtendedTcpTable` source, which bounds the cost.

### 15.6 `C-WIN3`: private audit store

The Windows half of 6.4.9: `private_dir_policy` over `PathSecurityProbe` (pure, Linux-testable with a fake probe), non-recursive create plus re-probe, share modes and reparse/link-count checks for the active segment, readers with all three share flags, best-effort `sync_dir`; the upgrade of the daemon-side `fs_win.rs` from the `C-WIN0` baseline; flips `Controls.private_audit_store` to true on Windows only after a real-machine run. Tests: the policy table on Linux; on Windows only: a second user cannot open the ledger, prune succeeds while a reader holds a handle, the `sync_dir` behaviour is recorded.

### 15.7 `C-CO6w`: route observation

6.12, plus Windows tests `route_observe_v4_returns_observation_or_typed_error` and `route_observe_v6_does_not_panic_without_ipv6`.

### 15.8 Suspend, resume and network change

* No power-event or network-change hook exists and none is added in M2; changes are visible only through the 5 s poll of 6.12.
* Nothing depends on `std::time::Instant` advancing during sleep (UNVERIFIED on Windows). Audit ordering uses `seq`. Timeouts only affect cleanup: if the clock stops in sleep a flow that died there lingers for the remaining idle time; if it advances, the idle watchdog closes everything at resume. Both are fail-safe.
* Rule for the ingress tree: never subtract `Instant`s with `-`; use `saturating_duration_since` or `checked_duration_since` (overflow checks are on in release, so a negative interval would panic on the hostile-input surface).
* `C-H2` (resume-skew heuristic) is REMOVED (13.2.2, MD-13). Dead flows are found by keepalive (`C-H1`) or by the application; a power-event hook belongs to a service or the GUI.
* `ts_ms` is a wall clock that may jump at resume; it is documented as untrusted.

### 15.9 The firewall kill switch on Windows

13.2.4. The privileged service has never been installed or started in this project (`ssk-daemon/src/main.rs:190` and its comment), so every kill-switch statement about a running Windows machine is expectation, not observation.

### 15.10 IPC accept loop on Windows

`C-I1w` is not fixed (C.3): one accept error ends `sskd` on Windows and the ingress with it. Closed by construction, but not available; restart is manual. Accepted until it is redone with a test only Windows can run.

### 15.11 CI, and what the acceptance suite can and cannot do on Windows

The suite DOES exercise the default-configuration path on Windows, in function-level `cfg`, never by gating a file:

| Test | Where | Proves |
|---|---|---|
| `hardening_required_with_unhardened_fake_platform_is_unavailable` | every OS, in process | the logic of `required` |
| `windows_default_config_opens_no_listener` | `windows-latest`, `ssk-daemon` gate, real `sskd` | the default config on Windows |
| `windows_required_hardening_is_unavailable_until_controls_land` | same, `#[cfg(windows)] fn` | the real controls are `{false, false, false}`; status says `unavailable` and lists them |
| `windows_best_effort_reports_inactive_controls_and_warnings` | same (needs `C-WIN0`, which precedes `C-F2`) | the first usable config shows the three warnings, `peer_verified: false` and, while disarmed, the headline of 10.2 that does not say "active" |
| `windows_baseline_ledger_round_trip_in_a_temp_dir`, `windows_baseline_platform_reports_no_controls` | `windows-latest`, in process (`C-WIN0`) | the std-only ledger backend opens, appends, verifies and prunes in a temp dir; the platform binds plainly with `{false, false, false}` |
| `windows_control_table_is_pinned` | same | the table flips only with an edit of this test, in the `C-WIN2`/`C-WIN3` commits |
| `route_observe_*`, the script fixture test | `windows-latest` | `C-CO6w` does not panic; the operator script's pure logic |

It CANNOT, and says so: refuse a different local user (one administrator account on the runner), prove exclusive-bind semantics against a hostile account, measure TIME_WAIT (the ignored test above can record it on demand), observe any tunnel application, or observe suspend and resume. Those are 24.2.3. Whether the runner has IPv6 is UNVERIFIED; IPv6 tests follow 13.2.5.

### 15.12 Register of UNVERIFIED Windows and third-party behaviour used by this design

`GetBestRoute2` sends no packet; alias text of any adapter; `SO_EXCLUSIVEADDRUSE` with TIME_WAIT (whether and how long); another account sharing a non-exclusive port with `SO_REUSEADDR`; `MIB_TCP_STATE` numbers other than 5; dual-stack clients in the IPv4 owner table; loopback traffic under an outbound firewall rule; block-over-allow precedence; filtering and per-application steering of third-party tunnel products; `Instant` across suspend; console control events reaching a hidden-console `sskd`; the privileged service starting at boot; `curl.exe` on the owner's build; `Find-NetRoute`, `Get-NetIPAddress` and `Get-DnsClientServerAddress` as used in the procedure; the ACL and owner SID of files created in `%LOCALAPPDATA%`; the std-only baseline ledger store of `C-WIN0` (share modes, prune while a reader holds a handle); `FlushFileBuffers` on a directory handle for an unprivileged process; antivirus interplay with prune and `FILE_SHARE_DELETE`; the real OS shutdown budgets (8.5); Windows resolver behaviour for `sskd` (6.11).

## 16. What this does NOT protect (read this before writing any UI text)

* **Only applications that are configured to use the loopback proxy.** There is no capture: no Wintun, WFP, fake-IP, system-stack NAT, PAC, or OS proxy-settings writer. An application that ignores the proxy is unaffected and unrecorded. This is **not** system-wide coverage and no status text may imply it. Everything an application sends around the proxy (its own DNS, IPv6, UDP, QUIC) keeps following the routing table and the tunnel application's rules, unrecorded.
* An application configured for the proxy may itself fall back to direct when the proxy refuses or is disarmed; SSK cannot prevent that.
* DNS an application performs itself is outside the daemon: an application that resolves a name and sends the address bypasses domain rules (only an IP-literal rule or a catch-all can match it). For `Direct` routes this daemon resolves the name itself, once per admitted flow, through the operating system's resolver; which DNS servers answer, on which interface the query leaves, and what any third-party software does about it are decided by the operating system and are not observed, claimed or changed by Kaleidoscorp. Proxied routes forward the name unresolved and the upstream proxy resolves it; that upstream can therefore reach names on its own network (SSRF via the upstream proxy): default-deny rules, the special-use guard for literals and the refusal of numeric aliases and `localhost` limit it, nothing can classify an upstream-resolved name locally. The configured proxy's own host name is resolved by the operating system at every dial.
* **Deny rules and names.** An exact-IP `deny` rule also refuses a Direct name that resolves to that address, at any priority (6.10 step 5). A deny rule for a name or a suffix cannot refuse a client that sends an address, and nothing can classify an upstream-resolved name (6.11).
* A `Direct` name that resolves to a loopback, private, link-local, shared-address (100.64/10), fake-IP (198.18/15) or otherwise special-use address is refused, as is any name with a single label, `.local` or `.onion`. Names containing `_` or non-ASCII bytes cannot be used (A-labels only). The operating system may append a search-list suffix to a bare name.
* The Direct dial binds no interface; it follows the operating system's routing table. `egress_local` in a flow record is an observation of the source address the system chose, not a statement about any VPN or adapter.
* UDP, QUIC, UDP ASSOCIATE, BIND, IPv6 listeners (applications that resolve `localhost` to `::1` reach nothing; configure `127.0.0.1`), and any non-SOCKS5 front end. With `ipv4_only` (default) IPv6-only destinations are unreachable through Direct; with `any` a dual-stack name can bypass a tunnel that does not cover IPv6.
* Same-user hostile code. Different local users: blocked on Linux, **not blocked on Windows** until `C-WIN1`/`C-WIN2`; reported in status. **Any other process of the same user can arm or disarm the ingress** from the GUI's pipe or the CLI: the transport authenticates the principal, not the program (25.2).
* Process attribution: every flow is `local-proxy:unattributed`. No per-app rules, no per-application fairness: all proxy clients share one egress identity, whatever the routing table gives `sskd.exe`.
* **Audit.** Destinations of admitted flows are recorded for the retention window (by default 8 x 32 MiB: about 320,000 admitted flows on a synthetic mix, which is days to weeks of browsing and about 1.8 hours at the sustained admission cap; the real window depends on traffic, and a loop can push older records out, 6.4.8): plain by default, or as keyed tokens when `destination_logging: hashed`. Denied destinations are always plain. In plain mode this is a local browsing log, readable by the same user and by any process running as that user; hashed mode protects the log file and every surface that follows it, not a process that can read both the ledger and `ingress-dest.key`. The matched rule ids, rule table and route remain visible and can identify an exact-destination rule to anyone who also has the configuration. A hash of a host name without a secret key is not privacy (about 11.6 million guesses per second per core here); the design therefore never offers one. Audit integrity is prefix integrity only: deleting the directory or the newest segments, or truncating at a record boundary, still verifies; retention prunes history by size; `ts_ms` is an untrusted wall clock; a same-user process can rewrite the whole chain consistently. The ledger records authorisation, destination, rule, result and byte counts as counted by the proxy, not payload and not what the destination saw. A Pending without a Result before a later Started or Recovered record is an upper bound ("the dial may have happened"), not a fact. A writer blocked in an fsync that never returns can be cleared only by restarting `sskd`; power-loss durability depends on the disk honouring flushes. The existing `audit.json`, lock file, logs and crash records keep their current modes; none of them may contain destinations. The activation ledger's cost is O(entries) per operation (6.4.1).
* Upstream proxy credentials, mTLS and TLS-then-CONNECT chains are not supported (config carries no credentials); a terminal `TlsTunnel` is refused. OpenVPN stays `OPENVPN_NOT_READY`.
* Suspend/resume: upstream tunnels that died during sleep persist until keepalive/idle timeout; there is no resume heuristic and no power-event hook (13.2.2).
* A hostile local user can always make the port unusable by flooding it at kernel level.
* **A third-party tunnel application underneath** (13.2): Kaleidoscorp does not know whether it is installed, running, connected or configured as assumed; it shows observations of the OS and of its own sockets (10.5) and nothing else about it. It is not a kill switch and does not become one: when the tunnel drops, new Direct connections follow the routing table and, unless that application's own kill switch blocks them, leave through the physical adapter. A per-application feature of the tunnel application applies to `sskd.exe`; a wrong entry silently sends Direct connections around the tunnel and is not detectable. Observations are sampled every 5 s, shown stale after 15 s, and decide nothing. `arm_on_start` arms whether or not the tunnel is up. OpenVPN orchestration and a third-party tunnel application are not supported together. The firewall kill switch is not part of this scenario and is guarded by the CLI; in ingress documents "kill switch" means the firewall rule and the daemon's own `FailClosed` state is "the fail-closed state". The echo test proves, for one laptop, one tunnel application, one set of settings and one moment, that the proxy path showed the same public address as the system path, nothing more.
* **The GUI.** A window that is hidden or minimised does not notice a trip or a change made elsewhere until it is visible again; there is no push channel, tray icon or notification in M2. The "Beobachtungen des Betriebssystems" card is an observation of one routing fact, not a statement about any other application. The confirmation step prevents accidental clicks; it is not a defence against script running in the webview (that defence is the CSP, the absence of sinks, shape-validated text and the zero-argument commands, 25.5). A client timeout does not cancel the daemon's work: after `outcome_unknown` the effect of the request is unknown until the next status read.
* **Who answers on the endpoint.** Today the GUI and the CLI do not verify that the process on the daemon's pipe or socket is the user's own `sskd` (`ssk-ipc/src/client.rs`: the pipe or socket is opened by name). On Windows another local account that can derive the pipe name (a digest of public inputs, `paths.rs`) could pre-create it and show an armed, covered proxy that does not exist; the same account would also stop the real daemon from starting, whose first-instance flag would fail. Windows behaviour is UNVERIFIED. `C-IPC2` closes it (25.2); until then every status the GUI shows is the report of the process on the endpoint.
* **Disarm and the IPC connection cap.** A disarm is applied as soon as the request is served; sixteen same-user connections that idle can keep a 17th client waiting (11.4). Stop `sskd` in that state.
* **Name-resolution capacity.** 16 concurrent OS lookups, a 500 ms wait for a 17th, 32 waiters: a page that makes dozens of distinct cold names resolve at once through a slow resolver can still see SOCKS `01` for some of them. It is counted (`resolver_busy`) and UNVERIFIED for a real browser.
* **Pre-admission.** Silent connections hold up to 64 pre-admission slots and are evicted oldest-first after one second; a connector that opens connections faster than they are shed can still make the port unusable (7.1).
* Nothing here changes the kill switch, and `Protected` still means one held egress session.

## 17. Documentation claims that must be corrected (code wins)

New: `docs/adr/0009-local-proxy-ingress.md` (`C-D1`; a "Proposed" stub may ride with `C-CI1`) and an ADR 0008 addendum (the ingress is a second caller of the same path; closure unchanged at 17); a dated continuation in `docs/RESTART_ASSESSMENT_2026-09-21.md` (history is not edited). The rule: a statement that a commit makes false is corrected IN that commit (the `breaking_change_guard` of 21 only covers the matrix, so this is review discipline).

### 17.1 Numbers and claims of this document's predecessor that were wrong

**The "23 pinned integration tests" (draft 1: 6.4, section 12 item 3, the "Split audit trail" row, Decisions item 9, commit `C-S1`) is not reproducible and is replaced.** Counting `#[test]` and `#[tokio::test]` attributes: at the base commit `f748e10` there were 24 in `crates/ssk-daemon/tests` (2 of them in `dependency_closure.rs`) and 86 in `crates/ssk-daemon/src`; at `b62c4c8` there are 27 and 91. `cargo test -p ssk-daemon -- --list` at `b62c4c8` on Linux lists 89 unit tests and 26 integration tests (`activation_safety` 11, `dependency_closure` 2, `desktop_read` 1, `event_backpressure` 1, `kill_switch_status` 6, `killed_task_transitions` 2, `peer_authentication` 1, `round_trip` 2; one Windows-only test is not compiled). Of these, only eight tests read, seed or corrupt `audit.json` by path or through `AuditLedger::persisted`, all in `activation_safety.rs`: `default_denial_and_required_attestation_never_reach_the_data_plane`, `configured_openvpn_is_visible_but_fails_explicitly_without_direct_fallback`, `invalid_or_missing_config_blocks_dispatch_but_keeps_diagnostics_available`, `unavailable_audit_blocks_dispatch_and_reports_the_cause`, `valid_config_records_pending_and_result_and_preserves_ids_across_restart`, `a_corrupted_existing_chain_is_not_extended_and_never_dispatches`, `audit_failure_after_connect_closes_the_socket_without_a_protected_event` and `silent_proxy_ends_fail_closed_at_the_activation_deadline_and_status_answers`. The others only pass `audit.json` as a path to `Supervisor::new`. Wherever a document gives an absolute count, replace it with the rule "every test that exists at the base commit passes unchanged; CI is the authority", and cite 89 + 26 only as the Linux listing at `b62c4c8`. The argument against converting `audit.json` stands on the measured O(n) cost in 6.4.1, not on a test count.

Other corrections: `summarise_route` is still private (`ssk-netadmin/src/audit.rs:72`); commits `0982387` and `7857618` did not publish it. `EgressSession::chain()` returns adapter kinds, not ids (`session.rs:51`). `FlowAuditWriter::close(self)` is replaced by `close(&self)`. `status()` and `GetAuditEntries` read the whole `audit.json` on every call (`supervisor.rs:192`, `:922-936`). No directory is fsynced anywhere in the repository (the `sync_all` hits are all on file handles, including `ssk-tensor/src/lib.rs:411`). The daemon has no configuration reload path, so a rule or limit change always needs a restart. `direct::connect_tcp` no longer builds `format!("{host}:{port}")` (since `C-N2`). `DIRECT_REQUIRES_LITERAL` never existed in code. The static `"live (real, connected)"` health string and the `Protected` doc comment no longer exist (`C-S3`). The `StatusHint` of draft 1 does not match the landed code (10.3).

### 17.2 Other documents and comments, keyed by the commit that must fix them

Line numbers were re-checked at HEAD `b62c4c8` (grep); the quoted text is the stable reference.

| commit | file:line (HEAD) | statement | correction |
|---|---|---|---|
| `C-D0` | `README.md:507` | "The loaded `AppConfig` is not passed into `Supervisor::new`; the adapter registry is hardcoded." False today: `main.rs:246-262` loads the config and builds the registry from it | delete the bullet |
| `C-D0` | `docs/ROUTING_AND_OPENVPN_STATUS.md:29` | "Config has no automatic direct-fallback action." True of config, now also of the executor (`ed143be`) | add "and `RouteExecutor::connect` refuses `RouteKind::Fallback` before opening a socket" |
| `C-D0` | `docs/COMPATIBILITY_MATRIX.md` | no entry for the foundation changes | add entries (plan row 2) |
| `C-CI1` | `README.md:576` | `breaking_change_guard`: "Contract-surface change detection on PRs" (it only echoes today) | "fails a push or pull request that changes a contract surface without a matrix entry or `Compat-Impact` trailer"; add the self-test row; `README.md:610` list of jobs |
| `C-C1` | `README.md:11` | "configured v4 routing profiles" | "v5" |
| `C-C1` | `README.md:379` | the "minimum valid configuration" (`version: 2`, `fail_closed: true`, `runtime.strict_mode`) | rejected by `ssk config lint` today (measured: exit 10, `unknown field fail_closed`). Replace with: start from `docs/examples/*.yaml` or `cargo run -p ssk-config --example ingress_config`; `version: 5` |
| `C-C1` | `README.md:560`, `docs/RUNBOOK.md:18` | "ensure `version=2`" | "`version: 5`; run `ssk config lint`" |
| `C-C1` | `docs/RUNBOOK.md:29` | "Routing now uses the validated v4 profile" | v5; add: a config edit needs a daemon restart, which disarms the proxy unless `arm_on_start` |
| `C-C1` | `docs/ROUTING_AND_OPENVPN_STATUS.md:13`, `:61` | "`AppConfig` v4", "The new `routing` section requires v4" | v5, plus one sentence on `ingress` and the migration chain |
| `C-C1` | `docs/examples/openvpn-routing.yaml:21`, `crates/ssk-config/examples/openvpn_config.rs:1`, `ssk-cli/src/main.rs:4373` | `version: 4`; doc comment "valid v4"; "migrated from v{from} to v2" | regenerate; `to v{CURRENT_CONFIG_VERSION}` |
| `C-C1` | `docs/COMPATIBILITY_MATRIX.md:38` ("Config v4 and routing") | | add "Config v5 and the local proxy" and "Config schema evolution" (5.13) |
| `C-IPC1` | `docs/COMPATIBILITY_MATRIX.md` | | the 11.13 paragraph; `ssk --json` keys |
| `C-S1` | `supervisor.rs:622` | comment "until the peer-SID check lands" (it landed) | delete the clause |
| `C-L2` | `supervisor.rs:824` | the `KILL_SWITCH_ARMED` message "kill switch is armed; pass release_kill_switch=true to override" describes the daemon's `FailClosed` state, and the comment at `:847-852` says `release_kill_switch` does not reach the firewall rule | reword to "the daemon is in its fail-closed state"; keep the code |
| `C-E3` | `README.md:83` (second half), `:505`, ADR 0008 "no callers" | "`transport_mut` has no callers", "writes zero bytes" | first caller is `flow.rs`; say "in the ingress path only" |
| `C-F1` | `README.md:83` (first half), `:162`, `:342`, `:504` | "There is no traffic ingress", "The session carries no application bytes", "no application bytes are written through it", "No proxy listener" | the scoped claim of section 16 and the owner's wording: applications that use the proxy are covered; everything else is not; Kaleidoscorp does not claim that a third-party VPN is up. Not "Protected", not "system-wide" |
| `C-F1` | `crates/ssk-ipc/src/dto.rs:90`, `supervisor.rs:863` and `:917` | "Empty until ssk-capture (Phase 4)", "No captured flow is available", "Honestly empty" | describe the 256-entry registry and `FLOW_NOT_RETAINED` |
| `C-F1` | `docs/ROUTING_AND_OPENVPN_STATUS.md:36-41` | "`inspect-flow` returns `FLOW_NOT_FOUND` until captured flows exist" | registry semantics |
| `C-L3` | `crates/ssk-daemon/src/main.rs:317-322` | "Bounded drain" comment around `yield_now` | the real shutdown plan |
| `C-N3` | `crates/ssk-netcore/src/direct.rs` doc ("resolving `host` via the OS resolver"), `docs/DESKTOP_CLIENT_ARCHITECTURE.md:589-593` G.4 #5 "DNS honors the route" | resolution of Direct names now goes through the guard | state the pinned-resolution rule and that `dns_protected` stays `false` for Direct names |
| `C-CO5` | `crates/ssk-winhost/src/firewall.rs` module doc; `RUNBOOK_WINDOWS.md` section 3 | the rule's scope is not stated; the section's rollback receipt in `%TEMP%` and its `engage` driving the firewall directly predate the broker (`ssk-cli/src/main.rs:2889-2915` records that those concerns moved into the privileged service) | add that the rule has no program, interface or address exception, blocks the tunnel application's own traffic too, is pinned across reboots, and that `ssk winhost killswitch engage` refuses while the local proxy is bound unless `--allow-with-ingress`; no exception for any other software exists or is planned |
| `C-CO7` | `docs/P4_INGRESS_DESIGN.md:110, 124, 230`, `docs/WINDOWS_PRODUCT_ROADMAP.md:632, 655` | Pattern B and P4c: "`IP_UNICAST_IF` wrapper in `ssk-winhost`, called from `ssk-netcore::direct::connect_tcp`" contradicts rule CO-1 (`IP_UNICAST_IF` pins a dial to a chosen interface and would send Direct dials around a third-party tunnel) | annotate "withdrawn for Direct dials; any future use needs its own decision about coexistence". `docs/P4_FULL_COVERAGE_FEASIBILITY.md:227` and `:248` already strike the coverage claim; the planned exclusion-route manager (P4k) has the same property for its lane and needs the same note |
| `C-CO7` | `README.md`, `docs/DESKTOP_CLIENT_ARCHITECTURE.md` | describe a Proxifier replacement and a "full protection" tier | neither may be quoted next to the ingress; the only permitted description remains "applications that use the proxy" |
| `C-U7`, `C-U8` | `docs/DESKTOP_BACKEND_CONNECTION.md:49` ("Es gibt noch keine automatische Aktualisierung"), `README.md:85` and `:224-230`, `docs/MODULAR_DESKTOP_UI.md:14` and `:80` (`get_panel_snapshot_v2`, "its v2 contract carries no verified protection claims"), `ssk-desktop-client/src/lib.rs` crate doc ("read-only") | the webview is read-only, polls never, and uses the v2 contract | V3, the three commands, the 2 s poll while visible, the write path of section 25; the negative test is replaced (25.8) |
| `C-D1` | `docs/adr/0008-...md:12, :15, :21, :114, :141, :150, :168` | "CIDR / port-range / process-path criteria", "LoadedConfig is discarded", "no crate outside the token's defining crate can dispatch without one" (true only for the `DataPlane` trait), the 16-crate text against the 17 pinned by `dependency_closure.rs` | addendum, not a rewrite |
| `C-D1` | `docs/DESKTOP_CLIENT_ARCHITECTURE.md:589-593` G.4 #2 | "No silent direct fallback ... enforced + tested": true for the executor since `ed143be`, not before | note the date; K.1/K.2 "`Protected` = route + DNS verified" is still wrong |
| `C-D1` | `docs/P4_INGRESS_DESIGN.md:229` (P4b) | "`IngressProvider` trait (`ssk-netadmin`)" | the listener lives in `ssk-daemon` (an async provider cannot sit in the async-free `ssk-netadmin`) |
| `C-D1` | `README.md:640-646` | scope decision "should be made before P1 starts" | cite Appendix C.1 |
| `C-D1` | `docs/RUNBOOK.md` | | arm/disarm/recover, corrupt ledger (move the segment directory aside), restart-after-edit, `hashed` mode switch does not scrub history, key backup and forget, the 60-error IPC exit, Windows ingress unavailable until verified, what `Deactivate` does to the proxy, what disarm guarantees (8.3), the coexistence troubleshooting entries (24.2.6), the retention figures (about 1.8 h at the sustained admission cap), `chmod go-w` for an existing group-writable state root, stopping `sskd` when the IPC connection cap blocks a disarm, what a status means while `C-IPC2` is missing |
| `C-D1` | `SECURITY.md:14` ("`forbid(unsafe_code)` enforced workspace-wide") | `ssk-winhost` is exempt | not re-verified by me; the owner's security text, check before editing |

## 18. Resolution of every serious flaw the judges raised

| Flaw | Resolution |
|---|---|
| Accept bucket and permits charged before peer authorization (security) | Fixed: the peer budget is separate and cheap; shared budgets are charged only after a verified peer (7.1); test `peer_refusals_do_not_consume_accept_budget`. |
| Denials queued, not durable before reply (security) | Fixed: first occurrence per key durable before the reply inside the segment's refusal quota; repeats folded into Summary (6.4.8, 7.2). |
| Permanent capacity latch, not shippable (security) | Fixed: rotation and retention are in the spine (`C-A7`); the pre-rotation capacity path no longer exists; `Capacity` at twice the retention refuses new flows without a trip (6.4.8). |
| One panic trips the whole ingress (security) | Changed: panic budget of 3 per boot, crash records capped (`C-X1`), trip is recoverable by re-arm, arithmetic lints remove the cheap panic sources (12.12). Still fails closed after the budget, deliberately: a panic on a hostile-input surface is a defect, and repeating it is worse than stopping. |
| Split audit trail (security, desktop) | Mitigated, unification rejected: a one-way rewrite of `audit.json` has the largest blast radius, and its O(n) cost was measured (6.4.1). Doctor verifies both; `GetIngressAudit` and `ssk ingress audit` read the ingress ledger; both documented. |
| Windows has no working default (security, desktop) | `C-WIN1`..`C-WIN3` are in the series; `required` stays the default; `best_effort` is a visible, exactly described choice (15.3); owner decision 1. |
| New `Request::SetIngress` (all three) | Kept, reasoned in 11.4. |
| Two-key special-use not tied to matched rule (security) | Fixed: single key bound to the matched rule's own destination and port; allow-list removed from config (6.2). |
| Names resolved remotely (security) | Residual, documented (6.11, 16). |
| Too large; commit ordering circular; dead-code warnings (implementability) | Spine/release/optional classification (22), `types.rs` first, `pub` items; HTTP CONNECT deferred, GUI write path in the series as a release gate. |
| Accept-error classification hand-waved (implementability) | Replaced by count-based backoff (7.1). |
| Windows CI would fail on `required` (implementability) | Per-test `cfg`, one test that runs the default config on Windows, fake platform in process (15.11). |
| Audit-trail determinism, ill-specified flood test (implementability) | Durable first denial gives a barrier; flood test uses injected tuning and reconciles counts without a 10 s wait. |
| Test/config floor inconsistency (implementability) | Floors 100 ms. |
| `Refusal2` placeholder (implementability) | Removed; engine/front-end split uses concrete `Admitted`/`Denied`/`Established` types. |
| ESTABLISHED-only peer row flaky (implementability) | State set `{01,04,05}`, inode non-zero, both tables, one retry, batching (6.6). |
| Direct-by-name refused (desktop) | **Reversed by the owner (2026-10-06): part of M2.** Resolve once, guard every answer, pin, never re-resolve (6.10). |
| GetStatus stalls behind activation (desktop) | Done (`C-S2`, `C-S3`) and generalised: every reader answers or says busy (12.2-12.5). |
| v2 GUI shows nothing; ring is memory-only (desktop) | GUI write path and V3 (25), flow registry and ingress ledger readable over IPC (11.3, 11.8). |
| Restart-only latches; bind once; reboot leaves apps refused (desktop) | Re-arm recovers; `arm_on_start` opt-in; bounded bind retry (6.9.4); keepalive (`C-H1`) and idle eviction (`C-E5`) as release commits. The resume heuristic was removed (13.2.2). |
| Notice contradicted its own forbidden-words test (found while synthesising) | Notice rewritten without any forbidden word (6.1.1). |
| Minimal-diff: special-use set built from all rules; gate coupled to activation; no peer auth shipped; accept-loop death for IPC (not adopted) | Not carried over; see section 19. |

## 19. Decisions where I deliberately did not follow a judge or a design, and decisions taken when merging draft 2

### 19.1 Standing decisions

* **Serve independent of activation and of `FailClosed`.** One judge suggested denying service whenever the daemon is FailClosed/ConfigInvalid. ConfigInvalid already means no listener. FailClosed in this daemon describes the last probe activation or an `audit.json` integrity break; coupling would let one failed `ssk activate --dest` kill the proxy and would make the ingress a function of an unrelated dial. The ingress has its own prerequisites (valid config, healthy ledger) and its own latch.
* **Own ledger, not `audit.json`.** See 6.4.1. Cost: two chains to reconcile; mitigated as described.
* **No `ActivateProfile{ingress}` overload.** See 11.4.
* **No publish-on-drop status snapshot, no cached hint.** The fresh-overlay rule (10.3) reaches the same user-visible goal with the code that already landed.
* **Special-use opt-in by matched rule only, and only with a port.** One key is sufficient because the operator owns the rules; a second config key added surface without adding a boundary; the port requirement closes the portless-rule hole (rule 9).
* **Client-leg keepalive not adopted.** The client leg is loopback; its death is immediate or covered by the idle timeout. Keepalive is for the upstream leg only.
* **Arm-on-start is config, not persisted state.** `arm_on_start` is an explicit, audited operator opt-in with default `false`; the daemon never remembers an arm across restarts by itself.
* **The ingress never writes `audit.json` and never touches the firewall kill switch.**

### 19.2 Decisions taken when merging draft 2

Where the six theme revisions disagreed, the code was the arbiter where it could be (cited); otherwise the choice is judgment, stated here so the critic can attack it. `MD-n` is referenced from the text.

* **MD-1 Default listen port 10800.** The config theme proposed 1080, the GUI theme 10800, the coexistence example 41080. Repository evidence: every upstream-SOCKS5 example in the repository uses 1080 (`ssk-netadmin` tests, `docs/P4_INGRESS_DESIGN.md:228`), and the static self-loop check (5.3) would reject a loopback upstream on that port. Not checked against the IANA registry or a Windows excluded-port range. Open question B1.
* **MD-2 One descriptor budget; default `max_connections` 256.** The lifecycle theme (measured, itemised, no `setrlimit`) and the config theme (`FD_RESERVE` 256, raise the soft limit, default 512, admission queue 2 s / 128) conflicted. Adopted: the lifecycle model with the components that the targets theme changed (64 in-flight peer sockets, 16 resolver slots, 64 extra dial attempts), giving a fixed total of 256 and `fd_needed(m) = 256 + 2m` (7.3); no `setrlimit` raise in M2; capacity wait 250 ms with 8 waiters; the 2 s / 128 queue is not adopted; default 256, ceiling 4096, clamped at start. Test names that assumed a 300-connection burst were restated for `max_connections`.
* **MD-3 `idle_timeout_ms` default 1 h.** The config theme proposed 1 h, the lifecycle theme recommended 10 min plus keepalive, the coexistence text said 10 min. Adopted 1 h so that idle SSH and database sessions survive, with keepalive (`C-H1`) and idle eviction at capacity (`C-E5`) as the answer to dead tunnels. Open question B2.
* **MD-4 `SetIngressRequest { armed, profile_id?, client? }`, no `deny_unknown_fields`.** Three shapes were proposed. `armed: bool` lets the GUI arm without naming a profile (no pre-read race, nothing to inject); the `client` label feeds the audit record; rule R7 forbids `deny_unknown_fields` on IPC types because the repository's `Request` has none (`server.rs:22-36`) and additive fields must stay safe.
* **MD-5 `ingress.audit.destination_logging`; the key file is outside the ledger directory; the live views follow the ledger.** The config theme called the key `audit.destinations` and put the key "next to the ledger" and the volatile flow list in plaintext; the audit theme named it `destination_logging`, put the key in the state root and applied "no surface shows more than the ledger". Adopted the audit theme; relaxing the live views later loses nothing. Open question B5.
* **MD-6 `arm_on_start` is a `bool`.** `Option<String>` cannot be serialised to TOML (reproduced); the coexistence example's `arm_on_start: null` is corrected to `false`.
* **MD-7 `AuditStalled` is the 30 s `sync_data` stall detector.** The lifecycle theme tripped after three consecutive append timeouts; the audit theme's rule is that a timeout is not a fault. Adopted the audit design; the three-timeout rule is dropped.
* **MD-8 The configuration fingerprint lives in `ssk-config`.** The config theme's `AppConfig::routing_digest()` (sorted JSON of the whole section, 32 hex, includes profile names) and the audit theme's `ConfigFingerprint` (view structs, 64 hex, excludes names, includes the `Armed` rule table) were reconciled in favour of the audit definition, placed in `ssk-config/src/fingerprint.rs` because `ssk-cli` does not depend on `ssk-daemon` (`crates/ssk-cli/Cargo.toml`) and `ssk config lint` must print the same digests.
* **MD-9 One Direct dial algorithm: guard every answer, then filter families, then race.** The targets theme specified a happy-eyeballs race that starts with the family of the first answer; the coexistence theme specified family filtering (default `ipv4_only`), IPv4 first and sequential 3 s attempts. Adopted: guard first (a mixed answer is the rebinding signature), then the family filter, then the 250 ms-stagger race with IPv4 starting first under `any`. The sequential per-address budget is dropped. Because each racing attempt is a descriptor, attempts after the first need a permit from a shared pool of 64 (`DIAL_EXTRA_PERMITS`), which keeps the descriptor budget true by construction. This pool is new in this merge and uncompiled.
* **MD-10 Three hardening controls.** `Controls { exclusive_bind, peer_check, private_audit_store }`; `required` needs all three; a third warning `AUDIT_STORE_NOT_PRIVATE` was added to the coexistence warning set.
* **MD-11 Commit IDs.** `C-WIN3` is the private audit store (audit theme); the coexistence theme's route observation on Windows is `C-CO6w` and its docs commit `C-CO7`; the config theme's placeholders `C-O1`, `C-O1w`, `C-U1`, `C-U2w` are replaced by the owners' IDs; `C-W1` is `C-IPC1`; `C-H3` is `C-CI1`.
* **MD-12 `RouteTraceRequest.profile_id` is a field guarded by the protocol check.** The lifecycle theme added it as a field, the config theme's rule R2 forbids bare profile selectors on old requests; both are satisfied by "sent only after `require_protocol(1)`, and an answer without `profile_used` means not honoured".
* **MD-13 The resume heuristic (`C-H2`) and every "invalidate on route change" hook are removed.** The coexistence theme gave the reasons (13.2.2); the lifecycle transition 8 and `DisarmCause::ResumeHeuristic` went with it.
* **MD-14 Peer identity.** The peer check uses `getuid()` like `ssk-ipc/src/auth.rs:74` and is disabled when `getuid() != geteuid()`; the ledger-ownership check uses `geteuid()` because created files are owned by the effective uid. The peer in-flight cap is 64 (targets), not 8 or 32.
* **MD-15 Bind retry is per platform.** Unix 0, 250, 500, 1000, 2000, 4000 ms (lifecycle; Linux needs no `TIME_WAIT` wait because mio sets `SO_REUSEADDR`); Windows exclusive bind 500 ms doubling to 30 s, window 150 s (coexistence, UNVERIFIED). An explicit arm from `unavailable(BIND_FAILED)` is a `recover` with the short schedule on every platform; the coexistence idea of restarting a 150 s window in the background was not adopted because the control plane has no `Unavailable -> Starting` transition.
* **MD-16 One DTO per fact.** `IngressLimitsDto` merges the lifecycle and config fields; the GUI reads the coexistence `observations` block instead of a separate default-route field; `private_store` moved from the audit DTO to `controls`.
* **MD-17 Record vocabulary.** The audit names `literal | proxy_resolved | local_pinned` are persisted; the netcore `ResolutionMode` maps 1:1. `Armed.cause` is `operator | config_autostart` (a recover happens before an arm and has its own `Recovered` record). `Disarmed.cause` has `arm_superseded` (explicit) beside `arm_not_applied` and `arm_abandoned` (receipt drop). `Result.answers` and the two observation kinds carry what the targets and coexistence themes wanted from the resolver and the socket.
* **MD-18 SOCKS reply convention.** Guard class (target-related) `02`, route class `01`, `DIRECT_FAMILY_DISABLED` `08`, canonicalisation failures `08` (6.7.1).
* **MD-19 Lint form.** `#![cfg_attr(not(test), deny(..))]` with the lifecycle theme's full set (the two forms are equivalent; both ran clean on 1.95.0).
* **MD-20 Code names.** `INGRESS_FD_LIMIT_TOO_LOW` (not `INGRESS_FD_BUDGET`); `DIRECT_REQUIRES_LITERAL` does not exist; `INGRESS_AUDIT_STALLED` is the refusal for a stalled writer.
* **MD-21 GUI commits are RELEASE.** The GUI theme classed `C-U1`..`C-U7` as SPINE. Owner decision 1 defines M2 acceptance on Linux with the four acceptance criteria and decision 4 makes the GUI a gate for any release called a desktop client; so they are the "desktop gate" inside RELEASE, not part of M2 acceptance.
* **MD-22 One forbidden-word list** (10.7), the union of the English, coexistence and GUI lists.
* **MD-23 `C-S1` does not mention `IngressConfig`.** The config theme wanted `C-C1` and `C-IPC1` before `C-S1` so that `C-S1` could store the config copy; the lifecycle theme moved the copy to `C-F1`. Adopted the latter: `C-S1` stays a pure refactor that can land early.
* **MD-24 Two verification deadlines.** `doctor_verify_deadline` 10 s (RunDoctor) and `audit_read_verify_deadline` 30 s (`GetIngressAudit` with `verify`).
* **MD-25 Two executors, two deadline formulas.** With a separate guarded ingress executor (targets) the lifecycle formula `max(activation, ingress_connect) + 5 s` for one shared executor no longer applies; the activation executor keeps its 30 s default, the ingress executor gets `resolve + connect + 5 s` (12.9).
* **MD-26 `first_hop_local` is folded into `SessionResolution`.** One struct carries the resolution mode, answers, pinned address and the local socket address for both the target and the first hop.

### 19.3 Decisions taken in critic round 1

Two critics attacked draft 2; every finding was re-checked against the code and the text ([Appendix E](#appendix-e-disposition-of-critic-round-1)). `MD-n` continues the numbering of 19.2.

* **MD-27 A disarm is never swallowed and never throttled.** `SetIngress{armed: false}` always calls `IngressShared::disarm`; the no-op shortcut survives only for an arm of the already-armed profile and only when `control` is free; the rate limit applies to arm only; the GUI's disarm has its own slot and no floor. Reason: during an in-flight arm the gate reads `Disarmed`, and only the epoch bump supersedes that arm (6.9.2 step 5). The IPC connection cap stays a stated residual (11.4); a reserved permit would change `ssk-ipc`'s accept order. `expect_profile` and `expect_routing_digest` bind a confirmation to what the user saw, and `INGRESS_CONFIG_CONFLICT` finally has an emitter.
* **MD-28 The headline is a pure function of the status**; the disarmed variant of the no-peer-check row says the proxy is not serving (10.2, 15.2).
* **MD-29 `C-WIN0` is a spine commit.** The Windows baseline (std-only ledger store, plain bind, three controls false) lets `best_effort` exist before the Windows-last hardening commits. It makes no hardening claim, so owner decision 1 is untouched. Rejected: declare the owner's Windows scenario unavailable until `C-WIN1` and `C-WIN3` land (it is the owner's only target, and the Windows leg of `C-F2` would have been red or ignored).
* **MD-30 The audit module imports no engine type.** `append_pending` takes a `PendingInput` defined in `audit/record.rs`; `Admitted::pending_input` is the bridge; `RuleBinding`, `Decided`, `DecideError`, `DenyIp` and `ConfigState` live in `routing.rs` (`C-S1`) so that no early commit needs a later one (22).
* **MD-31 `LedgerSlot` is the one place the current audit writer lives**; a recover installs a new one; receipts resolve against the writer that issued them (6.9).
* **MD-32 Pre-admission slots cover the handshake and the shared budgets are charged after it.** 64 slots (the former peer in-flight cap, same descriptor budget), the oldest silent socket evicted after 1 s when full, accept token and flow permit taken after `canonicalize` (7.1). Rejected: a per-peer cap (there is no per-process key to cap on loopback).
* **MD-33 Resolver: a bounded wait, not a bigger pool.** 500 ms and 32 waiters in front of the 16 permits. A dedicated resolver pool is rejected (the blocking pool has 512 threads and the cap serves the OS resolver and the descriptor budget); single-flight coalescing is deferred as `C-N5` (OPT).
* **MD-34 Exact-IP deny rules apply to resolved answers at any priority** (6.10 step 5). A conservative deviation from first-match order: the check can only refuse more. Rejected: apply only the deny rules that precede the matched rule (it needs per-flow state inside an executor-level guard, and an operator who writes `deny 203.0.113.9` means it for every route to that address).
* **MD-35 `Result.attempted`** records every address a Direct-by-name dial tried; `NetcoreError::DialFailed` carries it on failure. Rejected: dropping the 250 ms race for a sequential dial with one record per attempt (it brings back the black-holed-first-address stall, CO-4).
* **MD-36 Retention is stated honestly and the floor is the owner's call.** About 1.8 h at the sustained cap; `AUDIT_WINDOW_SHORT`; a minimum-age refusal is B18 and not adopted (a same-user process can already rewrite the whole chain, and a floor turns a loop into an outage).
* **MD-37 Observations are labelled for what they measure**: the interface the OS selects for the probe address, never "default route" (10.6, item 9); the GUI field is `os_route_probe`.
* **MD-38 Endpoint identity.** The client verifies the server before the first frame (`C-IPC2`, RELEASE, part of the desktop gate); until then the GUI's wording says whose report a status is (25.2).
* **MD-39 The state root is created 0700 by the daemon; an existing group-writable root is refused with a `chmod go-w` hint**, never repaired (6.4.9). Rejected: accepting `g+w` when the group is the owner's private group (the daemon cannot know the group's members) and repairing a directory that the user may have shared on purpose.
* **MD-40 The seams are specified**: `TcpConnector` in netcore (destination only, so CO-1 is type-level as well as scanned), `IngressDeps`, `Clock`, `Sleeper`, `IngressCfgView`, `ResolvedLimits` (6.9.5), `build_ingress_executor` (a library function that a test calls).
* **MD-41 Acceptance is wider than a literal loopback.** Direct-by-name has a wired-path test with a reserved TLD and a builder test (23.7, 23.8) and is a fifth acceptance criterion; ACCEPT-5 is an explicit gate before anything is called a desktop client, with a CI route-flip job (`C-CO1b`) for the one automated proof that the OS decides (24.1, 24.2, 22).
* **MD-42 The contract guard is satisfied per commit**: every commit that touches a guarded surface carries its matrix paragraph or a `Compat-Impact` trailer (22); the ledger matrix text moved from `C-A8` to `C-A2`, `C-A4` and `C-A7`, where the formats appear.

## 20. Follow-ons (specified now so M2 does not paint them out)

* **M2.1 HTTP CONNECT** (`protocols: [socks5, http_connect]`, first byte `C` sniff): authority-form `CONNECT host:port HTTP/1.x` only; the head is read **one byte at a time** up to 8 KiB until CRLFCRLF (same approach as the egress client; no over-read, so pipelined client bytes stay in the kernel buffer and are pumped after admission); CRLF only, no obs-fold, duplicate or `Transfer-Encoding`/`Content-Length`/`Origin`/`Sec-Fetch-*` headers refused; no 200 before the `ResultReceipt`; error replies bodiless (`403` policy class, `502`/`504` route/dial, `503` budget) with `Connection: close`; no PAC, status page or CORS headers. The authority text enters through `RawTarget::Name` and the same `canonicalize`, so no second canonicaliser is needed. Adds one enum variant and one entry in `IngressProtocol::SUPPORTED`; no config version bump (5.5).
* **The GUI write path and `DesktopSnapshotV3` are part of the series** as the desktop gate (`C-U0` to `C-U8`; `C-U9` on a real Windows machine and the optional `C-U10` follow; section 25). Owner decision 4: the webview arms and disarms the ingress through two zero-argument native commands behind a dedicated minimal capability; `activate_profile` and every other daemon request remain unreachable from the webview, and a strict ACL test replaces the old negative test. **It is a gate for any release that calls itself a desktop client.**
* **Pinned Direct-by-name is not a follow-on.** It is M2 spine work (6.10; `C-N3`, `C-N4`, `C-G1b`). The API names are `DirectAddrGuard` and `with_direct_guard`; `check` takes a `DialPurpose` and the guard has no exemption.
* Later lanes (Wintun/fake-IP/system-stack) plug in as new front ends feeding `decide`/`open_tunnel` with `Provenance::{NatOriginalDestination, FakeIpMapped}`; `Coverage` may exceed `proxy_clients_only` only after the privileged broker proves capture is enforced, never because a listener exists. 198.18.0.0/15 is already denied as special-use so the range stays reserved. `FlowDescriptor` is not reshaped (P4-GATE-3 is not pre-empted).
* Still later (not M2): CIDR + port-list rule criteria so that a LAN or private range can be reached by an explicit rule instead of one literal host and port at a time (needs a config-schema change and the same port requirement as rule 9); a per-rule opt-in for resolved special-use answers; a netlink `SOCK_DIAG` source for the Linux peer service (`C-G7c`); an automatic raise of the soft descriptor limit; `<state_dir>/config.yaml` discovery when `SSK_CONFIG_PATH` is unset (open question B16); a hot reload; a power-event hook in a service or the GUI.

## 21. CI gates for contract surfaces (`C-CI1`, replaces `C-H3`)

### 21.1 What is wrong today (`.github/workflows/ci.yml:157-168`)

* The job only echoes; nothing in it can fail except a git error, and that error is swallowed: the step has no `shell:` (GitHub's default for such a step is `bash -e {0}`, without `pipefail`), so `git diff ... | tee` takes `tee`'s exit status. Reproduced locally with a depth-1 fetch of a PR-style ref (what `actions/checkout` does by default, no `fetch-depth`): `git diff --name-only origin/main...HEAD` exits 128 (`unknown revision`), the pipeline exits 0, `grep` sees an empty list, the step is green. The shell default is GitHub's documented behaviour and UNVERIFIED here; the git half is measured.
* The path regex `^crates/ssk-interop/src/lib.rs|^crates/ssk-config/src/lib.rs|^docs/INTEROP_SPEC.md|^docs/COMPATIBILITY_MATRIX.md` omits `crates/ssk-config/src/routing.rs`, any `ingress.rs`, all of `ssk-ipc`, the ledger formats in `ssk-netadmin`, and it treats a change to `COMPATIBILITY_MATRIX.md` itself as a contract change (inverted).
* `if: github.event_name == 'pull_request'`; `ci_gate` counts `skipped` as success. A direct push is never checked.
* The `config_schema_guard` step `cargo test -p ssk-config schema_snapshot_stable` passes vacuously if the test is renamed (`cargo test <filter>` that matches nothing exits 0; measured).
* Dry run of the new guard on the real branch (`main..HEAD`, 18 commits, prototype script; `ssk-ipc/src/server.rs`, `state.rs`, `ssk-netadmin/src/{audit,policy,route}.rs` changed by the foundation commits): **FAIL**, because none of those commits touched `COMPATIBILITY_MATRIX.md`. `C-D0` writes those entries, so the first PR passes honestly, not through the escape hatch.

### 21.2 The guard

Files: `scripts/ci/contract_guard.sh BASE HEAD` (Appendix D.2), `scripts/ci/contract_surfaces.txt` (label TAB extended regex), `scripts/ci/tests/contract_guard.test.sh`. Rule: if any changed path in `merge-base(BASE,HEAD)..HEAD` matches a surface, then `docs/COMPATIBILITY_MATRIX.md` must be in the same range, **or** a commit message in the range has the trailer `Compat-Impact: none (<reason of at least 8 characters>)`. It fails closed: all-zero or unknown BASE, unknown HEAD, a missing table, no merge base, or a failing git command is exit 1, never a pass. Surfaces:

```
# label<TAB>extended regex over repository-relative paths (git diff --name-only --no-renames)
config	^crates/ssk-config/(src|tests/golden)/
ipc-wire	^crates/ssk-ipc/(src/|tests/wire_|tests/golden/)
activation-ledger-and-wire-types	^crates/ssk-netadmin/src/(audit|route|policy|adapter)\.rs$
ingress-ledger	^crates/ssk-daemon/src/ingress/audit/
ui-contract	^crates/ssk-ui-contract/src/
interop	^crates/ssk-interop/src/lib\.rs$
interop-spec	^docs/INTEROP_SPEC\.md$
```

(`ssk-config/tests/golden/`, `ssk-ipc/tests/golden/` and the never-regenerated `ssk-ipc/tests/wire_protocol0.rs` are in the table so a regenerated golden file or an edited protocol-0 fixture cannot land without a matrix line. The ingress ledger writer, store and records are listed as a directory; the rest of `ssk-daemon/src/ingress/` is not a format. `ssk-config/src/fingerprint.rs` is covered by the `config` row.)

Workflow changes:

```yaml
  breaking_change_guard:            # same job id: ci_gate.needs keeps working
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
        with:
          fetch-depth: 0
      - name: Contract surfaces need a compatibility note
        env:
          EVENT: ${{ github.event_name }}
          PR_BASE: ${{ github.event.pull_request.base.sha }}
          PR_HEAD: ${{ github.event.pull_request.head.sha }}
          PUSH_BEFORE: ${{ github.event.before }}
          DEFAULT_BRANCH: ${{ github.event.repository.default_branch }}
        run: |
          set -euo pipefail
          if [ "$EVENT" = "pull_request" ]; then
            base="$PR_BASE"; head="$PR_HEAD"
          else
            head="$GITHUB_SHA"; base="$PUSH_BEFORE"
            if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then   # new branch, force push
              base="$(git merge-base "origin/${DEFAULT_BRANCH}" "$head")"
            fi
          fi
          echo "contract guard: base=$base head=$head"
          bash scripts/ci/contract_guard.sh "$base" "$head"

  contract_guard_selftest:          # runs on every push AND pull_request
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - run: bash scripts/ci/tests/contract_guard.test.sh
```

Also: remove `if: github.event_name == 'pull_request'`; add `contract_guard_selftest` to `ci_gate.needs`; in `config_schema_guard` replace the filtered `cargo test` by `cargo test --locked --no-fail-fast -p ssk-config`; in `build_test` set `env: SSK_REQUIRE_IPV6: ${{ runner.os == 'Linux' && '1' || '0' }}` (tests that need `::1` panic instead of printing `SKIPPED:` when the value is exactly `1`; an unavailable `::1` on the runner is UNVERIFIED and the first run answers it, red means "decide", not "ignore"); add to `.github/PULL_REQUEST_TEMPLATE.md` under "ADR / Docs impact": `Compatibility: matrix entry, or a Compat-Impact trailer`; one README CI-table row for the self-test and a corrected description of `breaking_change_guard`; in `build_test` for Windows add the `pwsh` step of Appendix D.4. A push to the default branch is checked against `github.event.before`; a force push to it passes (merge-base is HEAD), so branch protection must forbid it (a GitHub setting, UNVERIFIED from the repository).

### 21.3 How it is verified, given that pull requests are the only trigger of the real thing

1. **Logic, locally and on every push.** `bash scripts/ci/tests/contract_guard.test.sh` builds throw-away repositories and asserts 15 outcomes: new `ingress.rs` without the matrix fails (the old regex missed it), `routing.rs` fails, surface plus matrix passes, trailer with a reason passes, empty or one-character reason fails, unrelated file passes, matrix-only change passes, ingress ledger writer fails, non-format ingress file passes, deleting a surface file fails, all-zero BASE, unknown BASE, missing table and a depth-1 clone all fail closed. All 15 pass in the prototype (with the earlier surface row `ingress/(audit|rotate).rs`; the row of 21.2 now names the `audit/` directory, so the two ledger cases must be updated in the same commit). The `contract_guard_selftest` job runs the same file on every push and pull request, so the guard's logic is exercised even when no pull request exists.
2. **Workflow wiring (the part only GitHub can run).** Once, after `C-CI1` lands, on a throw-away branch: open a PR that changes a comment in `crates/ssk-config/src/ingress.rs` only; expect `breaking_change_guard` red with the file listed; add a `Compat-Impact: none (comment only change)` trailer commit; expect green; separately touch the matrix instead; expect green. Record the three run URLs in the PR that introduces `C-CI1`. Until that is done the wiring (checkout depth, `github.event.*` fields, shell flags) is UNVERIFIED.
3. **Running the job on `push` as well is the backstop for pull-request-only blind spots** (the workflow already triggers on `push` and `pull_request`, `ci.yml:3-5`; only the job's `if:` excluded `push`): a direct push of a surface change without a matrix line is red.
4. Unverified and stated: how GitHub formats the body of a squash-merge commit (whether a trailer survives at the start of a line); if it does not, the `push` run on the default branch is red after an otherwise green PR and the remedy is a matrix line.

## 22. Commit plan

**Classes.** SPINE: needed for the acceptance of Milestone 2 on Linux (owner decision 1), or a prerequisite that must precede a SPINE commit. RELEASE: required before anything user-facing is called a release; the GUI series `C-U0`..`C-U8` is the **desktop gate** inside RELEASE (owner decision 4, MD-21). OPT: recommended, droppable, nothing depends on it. **Windows-only HARDENING commits are last** (`C-WIN1` to `C-WIN3`, `C-CO6w`, `C-I1w`). `C-WIN0`, the Windows baseline that the Windows leg of `C-F2` needs, is in the spine and makes no hardening claim. This list owns the IDs and the order; other sections refer to commits by these IDs.

**Every commit**: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` and `dependency_closure.rs` green on both `ubuntu-latest` and `windows-latest`; the `COMPATIBILITY_MATRIX.md` paragraph (or, where its row says so, a `Compat-Impact: none (<reason of at least 8 characters>)` trailer; the guard of 21 also runs on push and checks the range of that push, so a commit that touches a guarded surface without either is red when it is pushed alone, whatever a later commit of the same pull request adds) and the statements of section 17 that the commit makes false ride in that same commit; new `tests/support/*.rs` functions carry `#[allow(dead_code)]` (as `routing_config.rs` does today); no test file is gated by `cfg` as a whole (individual tests only). Until `C-WIN1`..`C-WIN3` are verified on a real Windows machine, a real-`sskd` ingress test that fails on `windows-latest` for a Windows-only reason is marked individually `#[cfg_attr(windows, ignore = "UNVERIFIED on Windows: <reason>")]` and listed in `RUNBOOK_WINDOWS.md`; never a whole file. One Windows test runs the DEFAULT config (`hardening: required`) and asserts the ingress is `unavailable` with `INGRESS_HARDENING_UNAVAILABLE`; the commits that flip the controls flip that test.

**Done (do not redo; C.2).** `C-N1` `ed143be`; `C-N2` `95b9d1b`; `C-P1` `0982387` + `7857618`; `C-I1` `051bfb6`; `C-S2` `f5a1683`; `C-S3` `f29784d`; docs `610bce9`; also `b62c4c8` (resolver-pool test) and `caaadb7` (decisions). `C-S3` already corrected the adapter-health string and the `Protected` doc comment.

**Order constraints** (critic round 1 made these complete: draft 2 listed some of them, left others implicit and contained one cycle). A commit may land later than the commits it needs, never earlier; a need is a compile-time or test-time dependency.

* Independent of the ingress: `C-CI1`, `C-D0`, `C-L0`, `C-L1`, `C-I1b`, `C-T1`, `C-X1`, `C-A1`, `C-N3`, `C-C0`, `C-S1`. `C-CO1` needs `C-N3` (its sibling test calls the new name-resolving dial).
* `C-C1` needs `C-C0`; `C-A3` needs `C-C1`.
* `C-S1` needs nothing from `ingress/`: `RuleBinding`, `Decided`, `DecideError`, `DenyIp` and the `ConfigState` alias are defined in `routing.rs` by this commit. (Draft 2 put `RuleBinding` in `ingress/target.rs`, which comes later, and never defined the other three.)
* `C-L2` and `C-L3` need `C-S1`; `C-IPC1` needs `C-C1` and `C-L2`.
* `C-N4` needs `C-N3`.
* `C-G1` needs `C-T1`, `C-C1` (`types.rs` re-exports `DestinationLogging`), `C-A3` (it re-exports `ConfigFingerprint`) and `C-S1` (`target.rs` imports `RuleBinding`).
* `C-G1b` needs `C-G1`, `C-N4` and `C-S1` (`exact_ip_denials`). `C-G2`, `C-G5`, `C-G6`, `C-G7a`, `C-L4` and `C-CO3` need `C-G1`. `C-G7b` needs `C-G1`, `C-G5` and `C-G7a`. `C-G8` needs `C-G1b`.
* Audit: `C-A2` and `C-A5` need `C-G1`; `C-A4` needs `C-A2`; `C-A6` needs `C-A2`, `C-A4` and `C-A5` and does NOT need the engine (it takes `PendingInput`, 6.4.7; draft 2's `append_pending(&Admitted)` needed `C-E2`, which follows `C-A6`, a cycle); `C-A7` needs `C-A6`.
* `C-WIN0` needs `C-A5` (`LedgerFs`) and `C-G7b` (`IngressPlatform`) and precedes `C-F2`.
* `C-E1` needs `C-C1`, `C-G1`, `C-A6`, `C-L1`, `C-L2`, `C-IPC1` (the snapshot returns `IngressStatusDto` and `FlowSummaryDto`), `C-L4` (the descriptor budget in the snapshot), `C-G7b` (`Controls`) and `C-CO3` (observations).
* `C-E2` needs `C-G1`, `C-G1b`, `C-G8`, `C-N4`, `C-A6` and `C-S1`.
* `C-E3` needs `C-E1`, `C-E2`, `C-G2`, `C-G5`, `C-G6`, `C-G7b`, `C-G8`, `C-L4`, `C-A7` and `C-CO3`.
* `C-F1` needs `C-E3`, `C-L3` and `C-IPC1`; `C-F2` needs `C-F1` and `C-WIN0`.

### Group A: independent of the ingress (may land before the critic round)

| ID | class | content | tests |
|---|---|---|---|
| `C-CI1` | SPINE | CI contract guard (21): script, surface table, self-test job, `fetch-depth: 0`, job runs on push too, `config_schema_guard` without the name filter, `SSK_REQUIRE_IPV6`, PR template line, README CI row. Must precede the first contract change. (was `C-H3`, OPT) | `contract_guard.test.sh` (15 cases); live proof on a PR (21.3) |
| `C-D0` | SPINE | docs only: matrix entries for the foundation commits (executor refuses `Fallback`; whole-dial deadline; suffix rules never match IP literals or numeric aliases; Unix accept retry; `GetStatus` answers `Activating`, activation deadline 20 s), and the statements already false at HEAD (17.2) | none |
| `C-L0` | SPINE | `ActivationScope` guard, `Inner.pending_activation`, `settle_abandoned_activation`, `ACTIVATION_CANCELLED` + explain entry (12.4). Regression test written first and seen to FAIL on HEAD | `a_cancelled_activation_settles_fail_closed_and_records_it`, `a_panicking_activation_settles_fail_closed`; existing `an_activation_queued_for_the_lock_is_already_in_flight` stays green |
| `C-L1` | SPINE | `StateMachine::event_sender`, `Supervisor.events` clone, lock-free `subscribe_events` (6.9.3) | `subscribe_events_does_not_wait_for_a_dial` |
| `C-I1b` | RELEASE | `ssk-ipc`: injectable accept source for `serve_unix_with_limits` and regression tests under paused time (dev-dependency tokio `test-util`) | `unix_accept_loop_keeps_serving_after_59_failures`, `unix_accept_loop_returns_ipc_accept_failed_on_the_60th`, `delays_follow_accept_retry` |
| `C-CO1` | SPINE | tests only: `dial_path_binds_nothing_static`, `first_hop_and_direct_share_one_dial_function`, `direct_dial_leaves_device_and_source_to_the_os`, `the_device_check_has_teeth` (24.2.1); dev-dependency `socket2` in `ssk-netcore`. Files that do not exist yet are skipped | as named |
| `C-T1` | SPINE | `ssk-config` host grammar: `valid_host` rejects names whose final label does not start with an ASCII letter (IP literals stay valid); `RoutingConfig::validate` rejects an IPv4-mapped IPv6 rule destination and a `domain_suffix` whose final label does not start with a letter; adapter hosts the same through `valid_host`. New shared corpus `tests/support/host_corpus.rs`. Records the tightening in `COMPATIBILITY_MATRIX.md` (a file that loaded before may now be `ConfigInvalid`) | `host_corpus_agrees_everywhere`, `config_rejects_numeric_alias_destination_suffix_and_adapter_host`, `config_rejects_ipv4_mapped_rule_destination` |
| `C-X1` | RELEASE | `ssk-diag`: prune crash records to the newest 32 on write | `crash_records_are_capped_to_32_newest` |
| `C-A1` | SPINE | `ssk-netadmin`: `summarise_route` becomes `pub` (`audit.rs:72`); guard: trailer `Compat-Impact: none (visibility only: no format or wire shape changes)` | `summarise_route_never_includes_hop_auth_or_address` |

### Group B: configuration

| ID | class | content | tests |
|---|---|---|---|
| `C-C0` | SPINE | 5.12: `ConfigError::Document`, migration chain (still 4), drift test, golden v4, no-vacuous schema job; matrix: the "Config schema evolution" paragraph of 5.13 and the document-error relabelling | `ssk-config` 15 -> 20 |
| `C-C1` | SPINE | 5: v5 + `ingress` (limits table, `destination_logging`, `direct_address_families`, ledger-size cross-check), `step_4_to_5`, v5 golden, example generators, CLI string, docs rows; matrix: "Config v5 and the local proxy" (5.13) | 20 -> about 38 (the prototype ran 32) |
| `C-A3` | SPINE | `ssk-config/src/fingerprint.rs`: `ConfigFingerprint`, view structs, digests (6.4.8) and the `Armed` rule-table builder; matrix: one paragraph (the digests are persisted in `Started`, so the view structs are part of the format) | `fingerprint_is_stable_under_rule_adapter_profile_reordering_and_profile_renames`, `fingerprint_changes_for_every_rule_field_adapter_field_default_profile_and_ingress_key`, `armed_record_lists_rule_ids_without_destinations` |

### Group C: supervisor refactor and wire

| ID | class | content | tests |
|---|---|---|---|
| `C-S1` | SPINE | hoist `Arc<ConfigState>`, `Arc<ConfiguredRouting>`, `Arc<dyn DataPlane>` onto `Supervisor`; `Supervisor::from_parts` (`main.rs` compiles routing once); `ConfiguredRouting::decide`, `rule_binding` and `exact_ip_denials` with their types `Decided`, `DecideError`, `RuleBinding`, `DenyIp` and the `ConfigState` alias, all in `routing.rs` (needs only `ssk-config` and `ssk-netadmin`); `TraceRoute` and the activation arm use `decide`; **no `IngressConfig`** (MD-23); comment fixes. The one test that reads `sup.inner.lock().await.routing` (`list_profiles_and_the_validator_share_one_registry`) uses the new accessor | every existing suite unchanged ("every test present at the base commit passes unchanged"; Linux listing 89 + 26), plus `exact_ip_denials_lists_only_deny_rules_with_an_ip_destination` |
| `C-L2` | SPINE | `inner_unless_activating`, `status_answer` (legacy block only at this point), `DAEMON_BUSY`, mutator gate (2), `close_bounded` for `Deactivate` and `record_task_failure`, `RunDoctor` and `ListProfiles` without `Inner`, `TraceRoute` lock-free when a profile is known, explain entries (`DAEMON_BUSY` and the 12 `NETCORE_*`), the `KILL_SWITCH_ARMED` wording | `read_handlers_answer_or_say_busy_while_activation_dials`, `status_is_served_while_mutators_queue_on_ipc`, `third_mutating_request_is_refused_daemon_busy`, `deactivate_waits_its_turn_behind_an_activation`, `close_bounded_gives_up_after_the_bound` |
| `C-L3` | SPINE | `ShutdownPlan` in `shutdown.rs`, `runtime.shutdown_timeout` after `block_on`, `DaemonLock::hold_until_exit` replacing `drop(lock)`, removal of `DRAIN_DEADLINE`, `ingress_executor_dial_deadline` with its table test; with the ingress absent the plan only covers the legacy parts | `shutdown_plan_totals_fit_their_budgets_and_reasons_map_to_plans`, `the_lock_is_still_held_after_hold_until_exit`, `ingress_executor_deadline_exceeds_the_engine_outer_bound`, real `sskd` (Unix): `sigterm_during_a_silent_activation_settles_the_ledger_and_exits_within_budget` |
| `C-IPC1` | SPINE | 11: `IPC_PROTOCOL_VERSION`, `StatusDto.{protocol, ingress}`, `IngressStatusDto` and the additive DTO fields (10.4, 10.5), `SetIngress`, `GetIngressAudit`/`IngressAudit`, exhaustive clamp, `DaemonState: Default`, `StatusDto: Default`, the four literal sites, `require_protocol`, protocol-0 fixtures, `RouteTrace` additions, the supervisor answers `ingress: Some(disabled)` and `SetIngress` with `INGRESS_DISABLED`. (was `C-W1`, renamed: the prose used W1/W2 for the Windows commits) | `ssk-ipc` +6 (30 -> 36; the prototype ran the first five); `ssk-daemon` +2 (`status_reports_protocol_and_a_disabled_ingress_block`, `set_ingress_is_refused_while_the_section_is_off`) |

### Group D: netcore

| ID | class | content | tests |
|---|---|---|---|
| `C-N3` | SPINE | `ssk-netcore/src/resolve.rs`: `NameResolver`, `OsResolver`, bounded `resolve_once` (permit inside the lookup thread, 16 permits, a 500 ms wait with 32 waiters, 5 s; abandoned lookups counted), `is_resolvable_name`, `ResolverBusy`; `direct.rs` `connect_host` (literal path unchanged; name path: resolve once, normalise); `SessionResolution` on `EgressSession` (including the local socket address of the target and the first hop); first-hop names use it too. `connect_tcp` stays as the thin literal wrapper the existing tests call | `resolver_called_exactly_once_per_dial_even_when_first_address_fails`, `numeric_alias_never_reaches_the_resolver`, `ipv6_and_ipv4_literals_never_call_the_resolver`, `resolver_busy_after_the_wait_and_literals_still_dial`, `a_17th_name_waits_for_a_permit_and_succeeds_when_one_frees`, `the_33rd_waiter_fails_at_once`, `sixteen_lookups_blocked_for_30s_then_a_17th_distinct_name_is_busy_after_the_wait`, `resolver_permit_is_held_until_the_thread_returns`, `stuck_lookups_do_not_exhaust_the_blocking_pool`, `os_resolver_resolves_localhost`, `direct_session_reports_the_sockets_local_address`, `proxy_chain_session_reports_the_first_hop_local_address` |
| `C-N4` | SPINE | `TcpConnector`/`OsConnector`/`with_connector`, `DirectAddrGuard`, `DialPurpose`, `with_direct_guard`, `has_direct_guard`, `address_families()`, `DialFailed`/`DialAttempts`, `DataPlane::guards_direct_names`, `AddressRefused`, all-or-nothing guard pass, `AddressFamilies` filter, IPv4-first interleave, the 250 ms race, `DIAL_EXTRA_PERMITS`; dev-dependency `test-util` | the paused-time dial tests of 23.3 |

### Group E: ingress modules (pure code first)

| ID | class | content | tests |
|---|---|---|---|
| `C-G1` | SPINE | `ingress/mod.rs` scaffold with the lint block (12.12), `types.rs` (6.1: gate types, `UnavailableCode`, `TripReason`, `Actor`, Tuning, notice, forbidden words, the audit leaf types), the poison-tolerant lock helper, `Clock`, `Sleeper`, `IngressCfgView`, `ResolvedLimits`, `PeerStamp` (6.9.5), the pure `headline()` of 10.2, `target.rs` (6.2 in full). Needs `C-T1`, `C-C1`, `C-A3`, `C-S1` | table tests, `host_corpus_agrees_everywhere`, proptests, `headline_claims_activity_only_when_armed` |
| `C-L4` | SPINE | `ingress/budget.rs`: pure `fd_budget`, `getrlimit` shim, constants (7.3); `rustix` feature `process` for unix in `ssk-daemon` | `fd_budget_table`, `ipc_reserve_covers_measured_baseline` (Linux, real `sskd`) |
| `C-G1b` | SPINE | `ingress/guard.rs`: `GuardCells` (listener cell and gate receiver), `IngressDirectGuard` (special-use, listener, and the armed profile's exact-IP deny set), `build_ingress_executor`; fake resolver, guard and connector doubles in `tests/support/net_fakes.rs`. Needs `C-G1`, `C-N4`, `C-S1` | as 23.3, plus `exact_ip_deny_applies_to_resolved_names_at_any_priority`, `deny_set_follows_the_armed_profile_and_refuses_when_unarmed`, `ingress_executor_builder_installs_guard_and_family_filter` |
| `C-G2` | SPINE | `ingress/socks5.rs` | duplex tables, `socks5_parser_never_panics_on_arbitrary_bytes` |
| `C-A2` | SPINE | `audit/record.rs`, leaf types, the audit input types (`PendingInput`, `*Event`), line encode/decode, hash chain, bounded line reader; matrix: the paragraph for the ingress ledger (`ledger_format` 1, line format, records, the `Started` fingerprint) | `flatten_round_trip_for_every_event_variant`, `ledger_line_has_exactly_one_newline_for_any_string`, tamper table, `unsupported_ledger_format_is_refused_and_not_appended`, `audit_module_has_no_upward_imports` |
| `C-A5` | SPINE | `audit/fs.rs` (`LedgerFs`, `LedgerIo`), `fs_unix.rs` (rustix, dirfd-relative store, checks of 6.4.9, D1-D3 order); `fs_win.rs` is a compiling stub that refuses to open until `C-WIN0` (so `private_audit_store` is false); `paths.rs` accessors and `paths::ensure_state_root` (the state root is created 0700; `main.rs` calls it in place of `create_dir_all`, 6.4.9); guard: trailer `Compat-Impact: none (store access code; the formats are those of C-A2)` | tests on real temp dirs (modes, symlink, hard link, foreign-mode table, root unsafe), call-order assertions with a recording double, `daemon_creates_a_missing_state_root_private_under_umask_002`, `existing_group_writable_state_root_is_refused_with_the_chmod_hint` |
| `C-A4` | SPINE | `audit/dest.rs`: key load/create, `kid`, `token()`, `DestRef`/`AddrRef` sealing, golden vectors (6.4.10); adds `getrandom` 0.3 to `ssk-daemon`; matrix: the destination token function and the key file are a persisted contract (one paragraph) | `token_golden_vectors`, `dest_key_file_is_private_and_outside_the_ledger_dir`, `hashed_without_key_is_unavailable_never_plain` |
| `C-A6` | SPINE | `audit/receipts.rs`, `writer.rs`: job state machine, RAII receipts and compensation, group commit, rollback, trip guard, stall atomics, quota counters, status atomics, `close(&self)`; `open_with` over `LedgerIo` doubles; takes `PendingInput`, not `Admitted`; `LockProof` and `DaemonLock::proof`; guard: trailer `Compat-Impact: none (writer behaviour inside the formats of C-A2 and C-A4)` | the writer tests of 23.6 |
| `C-A7` | SPINE | rotation, retention, quota enforcement, `Continue` records, non-fatal prune, hard cap, crash-window recovery, `verify_dir(Open \| Reader)` (was `C-G4`, RELEASE; now spine); matrix: segment naming and layout, `Continue` semantics and retention by size with the figures of 6.4.8 | `rotation_preserves_chain_and_prunes_oldest`, `continue_linkage_detects_tamper`, `restart_across_rotation_continues_seq_and_flow_ids`, the crash-window tests, `denial_only_flood_never_rotates_or_prunes` |
| `C-G5` | SPINE | `limits.rs`: `RateLimiter` (burst `max_connections`, refill `accept_rate_per_s`), `PeerBudget` (the pre-admission budget: bucket plus 64 slots with oldest-silent eviction, 6.5, 7.1), `DenialCoalescer` | `defaults_admit_a_burst_up_to_max_connections`, `a_connect_loop_is_throttled_to_the_configured_rate`, limiter tests with explicit `Instant`s |
| `C-G6` | SPINE | `pump.rs` | lifecycle/pump tests |
| `C-G7a` | SPINE | pure `parse_proc_net_tcp`/`parse_proc_net_tcp6`/`decide_row` with golden lines (tcp6 mapped form, orphan, server-side row, duplicates) | `parse_proc_net_tcp6_golden_lines`, `client_row_states_are_exactly_01_04_05`, `server_side_row_is_never_used`, `inode_zero_is_unknown`, `identical_duplicate_rows_collapse_conflicting_rows_are_unknown`, `missing_tcp6_file_is_an_empty_table` |
| `C-G7b` | SPINE | `PeerTableService`, Linux `PeerAuthorizer`, identity rule, `controls()` self-test with a temporary loopback listener, `scripts/manual_ingress_peer_test.sh`; `default_platform()` is real on Unix and a compiling stub on Windows until `C-WIN0` | `snapshot_service_batches_concurrent_requests`, `snapshot_rate_is_bounded_under_flood`, `identity_ambiguous_disables_peer_check`, real-socket tests of 23.6 |
| `C-CO3` | SPINE | `ingress/path.rs` (pure, Linux observer, `sanitise_alias`, constants) | the `ingress::path` tests of 23.6 |
| `C-G8` | SPINE | `tests/support`: fakes, SOCKS5 client, daemon harness (port 0, address from status) | self-tests |
| `C-WIN0` | SPINE | the Windows baseline (15.2, 6.4.9): `fs_win.rs` std-only ledger backend (path-based `std::fs`, share modes, no private-store claim, `sync_dir` a no-op) and the Windows `default_platform()` (tokio plain bind with the Unix retry schedule, `Controls {false, false, false}`, `peer_authorizer() = None`), replacing the compiling stubs of `C-A5` and `C-G7b`; guard: trailer `Compat-Impact: none (Windows store access code; the formats are those of C-A2)`. Makes no hardening claim: `required` stays unavailable. Needs `C-A5`, `C-G7b` | `windows_baseline_ledger_round_trip_in_a_temp_dir`, `windows_baseline_platform_reports_no_controls` (`windows-latest`, in process) |

### Group F: control plane, wiring, acceptance

| ID | class | content | tests |
|---|---|---|---|
| `C-E1` | SPINE | `shared.rs`: `IngressShared` per 6.9 with `ControlLedger`, `HostControl`, `LedgerSlot`, `cas()`, arm/disarm/trip/recover/close, events from the cloned sender, snapshot with the status fields | the control-plane tests of 23.6 (deterministic, `ControlLedger` double with `Notify` barriers, no sleeps), including `recovery_installs_a_fresh_writer_and_a_second_recovery_works` and the `Supervisor::handle`-level disarm tests of 23.6 |
| `C-E2` | SPINE | `engine.rs`: `decide` order and route guard (6.7.1), `open_tunnel` per 6.7.2 (`Admitted::pending_input` is the only bridge to the audit module's `PendingInput`, `dial()` takes `&PendingReceipt`, `ResultReceipt`, `chain_kinds`), `Result` records carry `session.resolution()` (`dialed`, `attempted`, `answers`, `refusal`) | the in-process matrix of 23.7 |
| `C-E3` | SPINE | `flow.rs`, `host.rs`: start phases with bind retry, watchdog, `PathWatcher`, recover, `shutdown(plan)`, accept loop per 7.1 (backoff as a select arm, `AcceptFatal`, pre-admission slots with oldest-silent eviction, shared budgets charged after the handshake, capacity wait, effective permits), flow guard; `IngressDeps` (6.9.5); `recover` installs the new writer in the `LedgerSlot`; the host joins aborted flow tasks before `audit.close()`; first caller of `transport_mut` | in-process tests on real loopback sockets, including `silent_connections_do_not_prevent_an_authorised_handshake` and `a_flow_after_recovery_reaches_a_durable_closed_record` |
| `C-F1` | SPINE | wiring: `SetIngress` handler (11.4: disarm straight through, arm-only rate limit, `expect_*`), `Deactivate` order (11.5), `status_answer` swaps the disabled stub for `IngressShared::snapshot()` with warnings and observations, `TraceRoute` via `engine::decide`, `RunDoctor` ingress checks (12.7), `main.rs` (two executors, the ingress one through `build_ingress_executor`, host start, `shutdown(plan)`), owned `IngressConfig` copy stored on `Supervisor`, `Layout` accessors | lifecycle tests |
| `C-F2` | SPINE | real-`sskd` acceptance suite in `ssk-daemon/tests/ingress_daemon.rs` (port 0; Windows default-config and `best_effort` tests, valid because `C-WIN0` precedes this commit): the four acceptance criteria and the fifth of 24.1 (Direct-by-name is wired), arm/disarm over IPC, restart disarms, `arm_on_start`, bind failure with a held port, corrupt ledger, shutdown during flows, status honesty and forbidden words, `ingress_flood_cannot_starve_ipc_under_a_small_nofile_limit` | 23.8 |

> **M2 ACCEPTANCE GATE (owner decision 1): `C-F2` green on `ubuntu-latest`; the Windows legs green or individually ignored as above.**
>
> **DESKTOP RELEASE GATE (owner decision 4 and the primary scenario; before anything is called a desktop client): `C-U0` to `C-U8` and `C-IPC2` done, and ACCEPT-5 (24.2) run on the owner's Windows laptop, with the script's report file and the operator's notes attached to the release notes. Owner of the run: the product owner. Needs `C-F3`, `C-CO7`, `C-CO6w`, `C-WIN0`, `C-CO1b` and either `C-WIN1` to `C-WIN3` verified or the owner's explicit acceptance of `best_effort` on that laptop (B9). `C-D1` (ADR 0009 Accepted for Linux) needs only the M2 gate and the reviewed ADR text; it does not claim this gate.**

### Group G: release (Linux)

| ID | class | content | tests |
|---|---|---|---|
| `C-H1` | RELEASE | upstream TCP keepalive (60 s idle, 20 s interval) on first-hop and Direct sockets via `socket2::SockRef`; extends the allow-list of `dial_path_binds_nothing_static`. Promoted from OPT: when a VPN application changes the route, existing Direct connections die silently | `keepalive_is_set_on_upstream_sockets` |
| `C-F3` | RELEASE | `ssk ingress status\|arm\|disarm\|flows\|inspect\|audit`, an ingress line in human `ssk status`, `require_protocol` before each, digests in `ssk config lint` and `ssk ingress status`, `ssk ingress audit --find` | CLI subprocess tests (stale-binary check first) |
| `C-IPC2` | RELEASE | `ssk-ipc` client: verify the server before the first frame (25.2): Unix `peer_cred().uid == getuid()` and a socket file owned by `geteuid()`; Windows the pipe's owner equals the current SID (the helpers `client_pipe_owner_sid` and `current_user_sid` exist in `ssk-winhost`, `pipe.rs`; `ssk-winhost` depends on `ssk-ipc`, so the check is injected as a seam); refuses with `IPC_ENDPOINT_UNTRUSTED`. Part of the desktop gate. Needs `C-IPC1` | `ipc_client_refuses_a_server_of_another_uid` (Linux, fake squatter), `ipc_client_accepts_the_users_own_daemon`; Windows: `ipc_client_refuses_a_pipe_owned_by_another_sid` (UNVERIFIED) |
| `C-CO1b` | RELEASE | a Linux CI job `route_flip_netns` that runs the ignored `direct_dial_follows_a_route_flip_in_a_network_namespace` (24.2.1) with `--ignored`, installing iproute2 if it is missing; it self-skips with a printed reason when `unshare -rn` or `ip` is unavailable and joins `ci_gate` only after its first green run on the runner (UNVERIFIED: hosted Ubuntu runners may restrict unprivileged user namespaces). Needs `C-N4`, `C-CO1` | the test itself |
| `C-E5` | RELEASE | idle eviction at capacity (>= 30 s idle, one per arrival, never an active tunnel) | `idle_tunnels_are_evicted_for_a_new_connection_but_active_ones_are_not` |
| `C-A8` | RELEASE | `RunDoctor` checks `ingress:audit`, `ingress:audit_store`, `ingress:audit_latency`; RUNBOOK entries for the ledger (the matrix text moved to `C-A2`, `C-A4` and `C-A7`, where the formats appear) | doctor tests of 23.8 |
| `C-CO5` | RELEASE | `ssk-cli` kill-switch pre-flight guard, bounded status helper, `--allow-with-ingress`; `firewall.rs` module-doc paragraph; `RUNBOOK_WINDOWS` box | `killswitch_engage_refuses_while_ingress_is_bound` and its three siblings (24.2.1) |
| `C-U0` | RELEASE | docs only: ADR 0009 addendum "GUI write path" (the binding rules of section 25) | none |
| `C-U1` | RELEASE | `ssk-ui-contract` `desktop_v3.rs` (types, `WriteError` code list), `ui/desktop/fixtures/daemon-v3-*.json`, `text-shapes.json`, `write-errors.json`, Rust round-trip tests; no new dependency | `desktop_v3_fixtures_round_trip_and_reject_authority_fields`, `write_error_codes_match_the_shared_fixture` |
| `C-U2` | RELEASE | `ssk-desktop-client` projection module (validators, `project_ingress`, `project_flows`, `project_observations`, `map_refusal`, `kill_switch_report`) under the deny lints; hostile-input tests; Rust half of the text-shape parity test. Needs `C-IPC1` | the projection tests of 23.9 |
| `C-U3` | RELEASE | `ssk-desktop-client` `read_snapshot_v3` and `switch_ingress` (deadlines, an arm floor, one arm in flight and a separate disarm slot, the remembered arm expectation of 25.3, outcome classification), source-scan test, paused-time tests, Unix-socket fake-peer tests on Linux, Windows pipe twins; V2 read kept so every commit stays green | the client tests of 23.9 |
| `C-U4` | RELEASE | `crates/ssk-daemon/tests/desktop_write.rs` with a real `sskd` (arm, disarm, the ledger names peer and client, disabled refusal, disarm during a silent activation, rate limit, `ingress` is `Some` on every path); `desktop_read.rs` gains the V3 assertions. Needs `C-F2`, `C-U3` | 23.9 |
| `C-U5` | RELEASE | `apps/desktop`: `get_panel_snapshot_v3`, `arm_ingress`, `disarm_ingress` next to v2; capabilities `read-panel` (v2 and v3) and `ingress-switch`; CSP additions; the static Node test; the Windows mock-runtime matrix with the probe command. Needs `C-U3` | 23.9 |
| `C-U6` | RELEASE | `ui/desktop` V3 webview (contract validators, ingress presentation, actions, poller, background refresh, minimal-diff DOM, components, `index.html` and `preview.html` sections, preview scenarios, package asset list, boundary tests); the daemon-card relabelling. Needs `C-U5` | 23.9 |
| `C-U7` | RELEASE | remove `get_panel_snapshot_v2` from host, manifest, capability, desktop-client read path, `project_status`, `DesktopSnapshotV2`, the v2 fixture and JS branch; the static test pins exactly three commands; the matrix gains `get_panel_snapshot_v2` as refused; `webview_status.rs` and `desktop_read.rs` move to V3 | 23.9 |
| `C-U8` | RELEASE | documentation corrections for the GUI documents (17.2) | none |
| `C-CO7` | RELEASE | `docs/examples/ingress-coexistence.yaml` and its example generator (rides `C-C1`), RUNBOOK entries (24.2.6), the PowerShell script and its test, the `ci.yml` `pwsh` step, the P4 document annotations | script fixture test on `windows-latest` |
| `C-D1` | RELEASE | final docs (section 17), RUNBOOK, ADR 0009 Accepted (Linux); pass criterion: the M2 acceptance gate green and the ADR text reviewed (ACCEPT-5 is not claimed by it, see the desktop release gate) | none |

### Group H: optional

| ID | class | content |
|---|---|---|
| `C-E4` | OPT | failure cool-off (was RELEASE; nothing depends on it and it adds a refuse-without-dialing path that needs its own review): 5 consecutive failures per planned chain within 30 s refuse that chain for 10 s with a coalesced `Denied ADAPTER_COOLING_OFF`; never a retry, never a fallback |
| `C-G7c` | OPT | netlink `SOCK_DIAG` `TableSource` behind the same trait |
| `C-N5` | OPT | single-flight coalescing of concurrent identical Direct names in the bounded resolver (only a flow with a durable `Pending` may join, 6.10); only after a real-browser measurement shows `resolver_busy` rising |
| `C-U10` | OPT, UNVERIFIED | Trusted Types CSP experiment, only after `C-U9` has run on real Windows |

Removed: `C-H2` (resume-skew heuristic, MD-13), `C-00` (the ADR is written in `C-D1`).

### Group I: Windows-only, last

| ID | class | content | verified on |
|---|---|---|---|
| `C-I1w` | RELEASE | named-pipe accept loop (and `privileged.rs`) retry: on `connect()`/`create_instance` error drop the instance and recreate through `AcceptRetry` (50 ms to 1 s, give up at 60); test with a fake `PipeFactory` failing N times. The first attempt was reverted | `windows_crate_gates` only |
| `C-WIN1` | RELEASE | exclusive loopback bind (`SO_EXCLUSIVEADDRUSE`, never `SO_REUSEADDR`); replaces the plain Windows bind of `C-WIN0`, with its own retry policy | `exclusive_bind_prevents_a_second_listener_on_the_same_port`, ignored `exclusive_bind_rebind_delay_after_time_wait`; real Windows |
| `C-WIN2` | RELEASE | owner-PID to SID peer check (half-close states, IPv4 table, dual-stack result recorded); flips `peer_check` and the pinned control table | `windows_owner_resolver_identifies_the_current_user`; real Windows |
| `C-WIN3` | RELEASE | `ssk-winhost/src/private_store.rs` (`private_dir_policy`), the upgrade of the daemon-side `fs_win.rs` from the `C-WIN0` baseline; flips `private_audit_store` only after a real-machine run | the policy table on Linux; Windows: second user cannot open the ledger, prune succeeds while a reader holds a handle |
| `C-CO6w` | RELEASE | `ssk-winhost/src/route_observe.rs`, `Win32_NetworkManagement_Ndis` feature, the daemon `cfg(windows)` `PathObserver` adapter; compile-checked only (windows-gnu) in this review | `route_observe_v4_returns_observation_or_typed_error`, `route_observe_v6_does_not_panic_without_ipv6` |
| `C-U9` | RELEASE | extends the ignored interactive `webview_status.rs` test to the V3 poll (`GetStatus` then `ListRecentFlows` with limit 51, nothing else) and adds the manual arm/disarm checklist to `docs/OPERATOR_VM_VALIDATION.md` | real Windows |
| `C-D2` | RELEASE | docs after real-Windows verification: Windows status in `RUNBOOK_WINDOWS`, ADR 0009 Accepted on Windows | none |

Not done and not planned: HTTP CONNECT (M2.1: one enum variant, `SUPPORTED`, golden regeneration, matrix line, 5.5), OS proxy-settings writer, UDP, IPv6 listener.

## 23. Test plan

Names are the contract; counts are approximate and CI is the authority. Absence is proven by counters (resolver, guard, connector, `connect_route` calls) read after a barrier, not by accept timeouts; the sentinel listener stays as a belt-and-braces assertion only. No test gates on wall-clock latency; deadlines are driven by paused time or explicit `Instant`s. Windows-only tests are marked as such.

### 23.1 `ssk-config`

* `ingress_default_is_disabled_loopback_socks5_required` (also `arm_on_start` false, `ipv4_only`, port 10800); `non_loopback_listen_addresses_are_rejected` (0.0.0.0, LAN, ::1, localhost, [::1], both formats); `every_numeric_bound_is_enforced_at_both_edges`; `unknown_or_duplicate_protocols_are_rejected_with_a_build_specific_message`; `typos_are_rejected_at_every_level_of_the_section`; `self_loop_adapters_are_rejected_only_when_the_port_is_known`; `segment_times_retain_over_1024_is_rejected`; `direct_address_families_default_is_ipv4_only`; `unknown_families_value_is_rejected`; `adapter_ipv6_literal_with_ipv4_only_is_rejected`; `destination_logging_default_is_plain_and_unknown_value_is_rejected`.
* `document_shape_errors_are_not_labelled_as_json_serialisation`; `schema_properties_equal_serialized_default_keys` (allow-list: `policy.gate_profile.thresholds` and `required_evidence`); `the_default_config_survives_json_value_yaml_and_toml_round_trips`; `schema_matches_the_golden_file`; `the_golden_file_name_follows_the_current_version`; `the_new_section_and_the_top_level_deny_unknown_keys_in_the_schema`; `ingress_schema_has_no_credential_vpn_or_interface_keys`.
* `tests/routing_migration.rs`: version loops `[3, 4, CURRENT, 999]`; `old_versions_cannot_smuggle_newer_sections` over `[1, 2, 3, 4]`; the v3 test also removes `ingress`; `v4_migration_preserves_routing_and_adds_a_disabled_ingress`; `ingress_rejects_bad_listen_limits_protocols_and_typos_in_both_formats` (11 mutations); `ingress_accepts_the_values_that_tests_and_operators_need` (port 0, `best_effort`, 100 ms, `hashed`, `arm_on_start`); `adapter_loops_are_checked_against_the_listener_port`.
* `coexistence_example_is_current`, `coexistence_example_validates`; `host_corpus_agrees_everywhere` (one table: names, IPs, brackets, mapped v6, numeric aliases, trailing dots, upper case, underscore, non-ASCII, 253/254 bytes, 63/64-byte labels, asserted against `valid_host`, `is_address_form` and `canonicalize`); `config_rejects_numeric_alias_destination_suffix_and_adapter_host`; `config_rejects_ipv4_mapped_rule_destination`; existing fixtures and examples still validate.
* `fingerprint_is_stable_under_rule_adapter_profile_reordering_and_profile_renames`; `fingerprint_changes_for_every_rule_field_adapter_field_default_profile_and_ingress_key` (table); `armed_record_lists_rule_ids_without_destinations` (scan the serialised body for every destination string of the fixture); `routing_rules_never_depend_on_flow_context_fields`.

### 23.2 `ssk-ipc` and the wire

* `every_protocol_0_request_still_decodes`; `a_protocol_0_status_decodes_with_protocol_zero_and_no_ingress` (and `require_protocol(1)` -> `DAEMON_TOO_OLD`); `a_current_status_decodes_for_a_protocol_0_client`; `set_ingress_is_an_unknown_variant_to_a_protocol_0_daemon`; `get_ingress_audit_is_an_unknown_variant_to_a_protocol_0_daemon` (hand-written old `Request` copy over `ciborium`); `clamp_keeps_every_size_free_variant_and_clamps_the_sized_ones`; `ipc_types_do_not_deny_unknown_fields` (an extra key is accepted for every DTO and request); `get_ingress_audit_roundtrip`; `set_ingress_request_cbor_roundtrip`; `flow_summary_old_new_roundtrip`.
* `unix_accept_loop_keeps_serving_after_59_failures`, `unix_accept_loop_returns_ipc_accept_failed_on_the_60th`, `delays_follow_accept_retry` (paused time, `C-I1b`); `accept_retry_backoff_table` and `accept_retry_gives_up_on_the_60th_consecutive_error` (exist).
* `every_code_this_milestone_emits_is_explainable` (11.14).
* `ipc_client_refuses_a_server_of_another_uid` and `ipc_client_accepts_the_users_own_daemon` (`C-IPC2`: the pure check as a table test on every OS, plus a root-only real test with a squatter socket that self-skips); Windows: `ipc_client_refuses_a_pipe_owned_by_another_sid` (UNVERIFIED).

### 23.3 `ssk-netcore` (resolver, dial, CO-1)

* Resolver: `resolver_called_exactly_once_per_dial_even_when_first_address_fails` (counting fake: two answers, first refused by a closed port, second connects, count == 1); `numeric_alias_never_reaches_the_resolver` (fake panics on `2130706433`, `127.1`, `0x7f.1`, `010.0.0.1`); `ipv6_and_ipv4_literals_never_call_the_resolver`; `resolver_busy_after_the_wait_and_literals_still_dial`; `a_17th_name_waits_for_a_permit_and_succeeds_when_one_frees`; `the_33rd_waiter_fails_at_once`; `sixteen_lookups_blocked_for_30s_then_a_17th_distinct_name_is_busy_after_the_wait` (paused time); `resolver_permit_is_held_until_the_thread_returns` (deadline fires, permits still 0, released after the fake returns); `stuck_lookups_do_not_exhaust_the_blocking_pool` (runtime with `max_blocking_threads(4)`, 2 permits, 2 stuck lookups, a plain `spawn_blocking` still completes); `os_resolver_resolves_localhost` (self-skips with a printed reason).
* Dial (paused time, scripted connector): `first_family_is_ipv4_then_alternates`; `ipv4_only_drops_every_ipv6_candidate`; `no_candidate_left_after_filtering_is_a_typed_failure`; `ipv6_literal_is_refused_with_family_disabled_under_ipv4_only`; `second_attempt_starts_after_250ms`; `failed_attempt_starts_the_next_immediately`; `all_attempts_share_one_budget`; `winner_aborts_the_losers`; `extra_attempts_never_exceed_the_shared_permit_pool`; `mixed_answer_with_one_special_use_address_refuses_the_whole_flow_without_a_socket`; `guard_runs_before_the_family_filter`; `guard_is_not_consulted_for_target_literals`; `first_hop_name_resolving_to_the_listener_is_refused_but_loopback_first_hop_is_allowed`; `session_records_mode_answers_dialed_and_local_addr`; `a_black_holed_first_candidate_does_not_consume_the_whole_connect_budget`; `attempted_addresses_are_recorded_on_success_and_on_failure` (`DialAttempts` through `DialFailed`).
* CO-1: `dial_path_binds_nothing_static`; `first_hop_and_direct_share_one_dial_function`; `direct_dial_leaves_device_and_source_to_the_os` and `the_device_check_has_teeth` (Linux, `SO_BINDTODEVICE`; the latter self-skips without `CAP_NET_RAW`); `direct_dial_binds_no_interface_or_source` (source scan); `os_connector_body_is_only_tcpstream_connect` (static scan of `connector.rs`); `executor_hands_the_connector_only_destinations` (a recording connector sees exactly the pinned candidates, in order, and nothing else can be passed).
* Existing: `fallback_route_never_dials_direct`, `dial_deadline_bounds_a_silent_socks5_proxy` (and its `http_connect`, `tls_relay` and every-hop siblings in `lib.rs`), `ipv6_authority_is_bracketed_on_the_wire` and `whitespace_and_control_characters_are_refused_before_any_byte_is_written` (`http_connect.rs`); `connects_to_an_ipv6_literal_listener` and the IPv6 authority test panic instead of skipping when `SSK_REQUIRE_IPV6=1`; `keepalive_is_set_on_upstream_sockets` (`C-H1`).
* Linux, `#[ignore]`, needs `unshare -rn` and iproute2; run by the CI job of `C-CO1b` (optional until that commit): `direct_dial_follows_a_route_flip_in_a_network_namespace` (24.2.1).

### 23.4 `ssk-netadmin`, `ssk-diag`

* `suffix_rule_never_matches_ip_literal`, `planner_never_emits_fallback` (exist); `summarise_route_never_includes_hop_auth_or_address`; `crash_records_are_capped_to_32_newest`.

### 23.5 `ssk-daemon`: supervisor, lifecycle, shutdown, budget

* Supervisor (uses the `silent_dial` fixture): `a_cancelled_activation_settles_fail_closed_and_records_it`; `a_panicking_activation_settles_fail_closed`; `status_answers_while_activation_dial_is_silent`; `status_keeps_waiting_when_the_lock_is_held_by_something_else` (exists); `status_overlay_is_fresh_during_activation` (trip or disarm during the dial; the next `GetStatus` says tripped/disarmed and coverage none); `deactivate_disarms_before_it_waits_for_inner` (hold `sup.inner`, send `Deactivate`, ingress disarmed within 100 ms while the response is pending); `deactivate_in_fail_closed_disarms_and_says_so` (state stays `FailClosed`, code `KILL_SWITCH_ARMED`, message contains "disarmed"); `lock_order_source_scan` (`ingress/` never names `Supervisor` or `inner`; `supervisor.rs` never names `control`); `close_bounded_gives_up_after_the_bound`; `session_shutdown_is_only_called_through_close_bounded`; `subscribe_events_does_not_wait_for_a_dial`.
* Real `serve_unix`: `status_is_served_while_mutators_queue_on_ipc` (16 connections occupied, 17th `GetStatus` within 1 s); `read_handlers_answer_or_say_busy_while_activation_dials` (`ListProfiles`, `RunDoctor`, `TraceRoute`, `GetAuditEntries`, `VerifyAuditChain` return within 1 s); `third_mutating_request_is_refused_daemon_busy`; `deactivate_waits_its_turn_behind_an_activation` (FIFO: result `Inactive`, not undone).
* Routing: `trace_route_reports_profile_source_and_equals_engine_decide` (property over random host/port/profile; the legacy path unchanged with the ingress disabled); `trace_route_reports_the_same_target_refusals_as_the_live_path`.
* Main/shutdown: `ingress_executor_deadline_exceeds_the_engine_outer_bound` (table: connect 100 ms, 20 s, 120 s); `shutdown_plan_totals_fit_their_budgets_and_reasons_map_to_plans` (graceful 2.9 s, OS 0.8 s, all 9 reasons); `the_lock_is_still_held_after_hold_until_exit` (a second acquire in the same process fails).
* Budget: `fd_budget_table` (soft `None`, 271, 272, 400, 1024, 20000; configured 1, 64, 256, 4096; pure and syscall-free); `ipc_reserve_covers_measured_baseline` (real `sskd`, 16+ IPC clients, `/proc/<pid>/fd` count at most 32).
* Doctor: `doctor_ingress_audit_runs_outside_inner` (hold `sup.inner`, `RunDoctor` returns); `doctor_verification_is_single_flight`; `doctor_reports_inconclusive_when_a_segment_vanishes` (fake verify); `ingress_audit_store_reports_group_writable_state_root`; `ingress_audit_latency_probe_reports_p50_and_max_in_state_root_not_in_ledger_dir`.
* Baseline: every test that exists at `b62c4c8` still passes unchanged; the listing (89 unit + 26 integration on Linux) is recorded in the `C-S1` commit message as the reference, not asserted by a test; `daemon_dependency_closure_is_the_set_adr_0008_recorded` and `decision_core_stays_out_of_the_daemon` run on every commit.

### 23.6 `ssk-daemon::ingress` modules

* **target:** `canonicalize_table` (brackets with and without colon, IPv6 in a domain field, `0:0:0:0:0:0:0:1`, `::ffff:127.0.0.1`, `::1` is NOT turned into 0.0.0.1, `::10.0.0.1` stays IPv6, `127.0.0.1.`, `a..b`, `.`, upper case, underscore, UTF-8 and NUL, `%` zone, 253 vs 254 bytes, 63 vs 64 byte labels, `0177.0.0.1`, `010.0.0.1`, `127.000.000.001`, `2130706433`, `2852039166`, `localhost`, `LOCALHOST.`, `a.localhost`); `classify_ip_table` over every row of the 6.2 table including `2001::/23`, `2001:db8::/32`, `3fff::/20`, `100::/64`, `::/96`, `fec0::/10`, `64:ff9b::/96` with a public and with a loopback embedded address, `64:ff9b:1::/48`, `192.0.0.0/24`, `169.254.169.254`; `special_use_needs_matched_rule_destination_and_port`; `portless_exact_rule_does_not_unlock_loopback`; `exact_rule_behind_a_broader_rule_does_not_unlock`; `deny_rule_literal_does_not_unlock_port_only_rule`; `self_loop_covers_unspecified_and_every_loopback_literal_with_the_listener_port`; `self_loop_refused_even_with_matching_rule`; `to_ipv4_is_never_used` (source scan); proptests of 6.2.
* **socks5:** `greeting_requires_version_5`; `rejects_zero_methods`; `requires_no_auth_method` (`05 FF`); `bind_and_udp_associate_get_07`; `unknown_atyp_gets_08`; `empty_domain_zero_port_nonzero_reserved_close_silently`; `reads_exactly_the_request_and_not_one_byte_more`; `success_reply_has_zeroed_bnd`; `socks5_parser_never_panics_on_arbitrary_bytes` (proptest plus truncation at every offset, bounded read count <= 519 bytes).
* **audit record:** `flatten_round_trip_for_every_event_variant` (including `u64::MAX`, `Option`, `Vec`, `BTreeMap`); `ledger_line_has_exactly_one_newline_for_any_string`; `oversize_line_is_corrupt_without_unbounded_allocation`; `unsupported_ledger_format_is_refused_and_not_appended`; `roundtrip_and_verify`; `detects_modified_line`; `detects_deleted_middle_line`; `detects_reordered_lines`; `genesis_and_gapless_seq`; `reader_mode_ignores_a_partial_last_line`; `torn_tail_is_truncated_and_noted`; `complete_corrupt_line_refuses_open`; `missing_dir_is_empty_chain`; `external_truncation_trips_via_fstat_check`.
* **audit writer:** `cancelled_in_queue_writes_nothing`; `abandoned_after_claim_is_compensated`; `caller_future_dropped_after_claim_is_compensated`; `dropped_receipt_compensates_exactly_once` (before dial: `NotDialed`; after `dial_started`: `Aborted`; after the result submission: nothing); `result_receipt_dropped_without_closed_writes_closed_with_counted_bytes`; `arm_receipt_not_applied_writes_disarmed`; `job_state_race_never_orphans`; `timeout_never_trips_but_io_error_does`; `sync_failure_fails_every_job_in_batch_and_trips`; `partial_append_is_rolled_back_or_recovered_as_torn_tail`; `writer_thread_panic_trips_via_exit_guard`; `stall_detector_trips_after_30s_with_fake_clock`; `arm_is_refused_while_stalled_writer_alive`; `queue_depth_cap_refuses_normal_jobs_but_never_compensation`; `close_is_idempotent_and_works_through_arc`; `close_drains_compensation_of_aborted_flows`; `seq_exhaustion_trips_without_panic`; `group_commit_acks_only_after_sync` (call-order double); `pending_is_durable_before_connect_route_is_entered` (`DataPlane` wrapper reads the ledger inside `connect_route`); `result_is_durable_before_success_reply`; `dial_refuses_a_receipt_bound_to_a_different_target_or_route`; `receipts_cannot_be_constructed_outside_the_module` (`compile_fail`).
* **audit quota, rotation, recovery, store:** `denial_only_flood_never_rotates_or_prunes` (tiny `segment_bytes`, 10,000 distinct denials); `evidence_keeps_75_percent_of_every_segment`; `over_quota_denial_still_gets_the_refusal_reply`; `summary_floor_is_written_once_per_300s_with_fake_clock`; `quota_counters_are_recomputed_at_open`; `rotation_preserves_chain_and_prunes_oldest`; `continue_linkage_detects_tamper`; `restart_across_rotation_continues_seq_and_flow_ids`; `oldest_retained_segment_starting_with_continue_verifies_as_anchored`; `directory_fsync_order_is_asserted`; `prune_failure_is_not_fatal_and_is_counted`; `hard_cap_refuses_pending_without_trip`; `segments_are_never_renamed_or_truncated`; `crash_after_segment_create_before_first_sync`; `crash_with_torn_first_line_in_new_segment`; `crash_between_rotate_and_prune`; `pruned_segment_reappears_after_crash`; `gap_or_overlap_in_segment_names_is_corrupt`; `unresolved_counts_in_started_match_the_scan`; `verify_reader_tolerates_concurrent_prune_enoent_on_oldest_but_not_in_the_middle`; `verify_reader_reads_only_the_length_seen_at_open`; `ledger_dir_and_files_have_private_modes`; `existing_group_readable_ledger_dir_is_refused_not_repaired`; `state_root_writable_by_others_is_refused`; `symlinked_ledger_dir_is_refused`; `symlinked_segment_is_refused`; `hard_linked_segment_is_refused`; `owner_check_table`; `foreign_uid_dir_refused_when_running_as_root` (self-skips); `symlinked_state_root_set_up_on_purpose_still_works`.
* **destination key:** `token_golden_vectors` (the four vectors and the `kid` of 6.4.10); `token_differs_per_key_and_equal_within_a_key`; `port_is_not_part_of_the_token`; `dest_key_file_is_private_and_outside_the_ledger_dir`; `hashed_without_key_is_unavailable_never_plain`; `corrupt_key_file_makes_ingress_unavailable_in_hashed_mode`; `mode_switch_is_visible_at_the_next_started_record`; `deleting_the_key_changes_the_kid`.
* **limits:** `rate_limiter_refills_deterministically`; `peer_budget_caps_slots_and_evicts_the_oldest_silent_socket_after_one_second`; `denial_coalescer_first_occurrence_durable_repeats_counted`; `summary_reconciles_exactly`; `key_table_is_bounded_at_128`; `defaults_admit_a_burst_up_to_max_connections`; `a_connect_loop_is_throttled_to_the_configured_rate`; (`C-E4`) `failure_cooloff_refuses_chain_after_five_failures_without_dial_or_pending`.
* **peer:** `parse_proc_net_tcp_golden_lines` (ESTABLISHED, FIN_WAIT, TIME_WAIT, orphan inode 0, server-side row ignored); `parse_proc_net_tcp6_golden_lines` (mapped v4 form, native v6); `client_row_states_are_exactly_01_04_05`; `server_side_row_is_never_used`; `inode_zero_is_unknown`; `identical_duplicate_rows_collapse_conflicting_rows_are_unknown`; `missing_tcp6_file_is_an_empty_table`; `miss_is_retried_once_then_unknown`; `snapshot_service_batches_concurrent_requests` (100 concurrent requests, at most 2 reads); `snapshot_rate_is_bounded_under_flood` (paused time); `queue_full_and_timeout_are_unknown`; `identity_ambiguous_disables_peer_check`; `controls_self_test_uses_a_temporary_listener_and_checks_state_inode_uid`; `hardening_required_makes_unhardened_platform_unavailable`; Linux real-socket: `owner_lookup_returns_own_uid_for_a_real_loopback_connection`, `half_closed_client_is_still_authorized`, `orphaned_client_is_refused`, `dual_stack_client_is_authorized` (self-skips without `AF_INET6`), `different_uid_client_is_refused` (root only, `CommandExt::uid(65534)` helper, self-skips); `peer_other_user_is_refused_before_any_byte` (fake authorizer `DifferentUser` and `Unknown`; mutation-proven); `peer_refusals_do_not_consume_accept_budget` (50 refused connections, then one authorized connection is admitted with accept burst 2). Real-socket tests assert only on their own connection (unique ephemeral ports).
* **path:** `parse_proc_net_route_golden_lines`; `longest_prefix_beats_a_lower_metric_default`; `garbage_route_table_is_an_error_not_an_empty_answer`; `alias_is_sanitised_and_bounded`; `route_change_records_previous_and_expires_after_the_notice_window`; `failed_lookup_never_erases_the_last_observation`; `stale_observation_is_labelled_stale_after_15s`; `observation_poller_does_not_run_while_disabled`.
* **pump:** `counts_bytes_both_directions`; `half_close_is_propagated_each_way`; `idle_timeout_cancels_and_keeps_counts`; `gate_change_cancels_immediately`; `backpressure_bounds_memory`.
* **control plane** (deterministic, `ControlLedger` double with `Notify` barriers, no sleeps): `arm_in_flight_loses_to_disarm` (hold `append_armed`, disarm returns at once, release: arm returns `INGRESS_SUPERSEDED`, gate stays disarmed, ledger `Armed` then `Disarmed{arm_superseded}`); `arm_in_flight_loses_to_trip_and_reports_tripped`; `arm_in_flight_loses_to_close_and_reports_stopping`; `disarm_bumps_the_epoch_even_when_already_disarmed`; `arm_same_profile_is_a_noop_without_epoch_bump_or_record`; `trip_never_waits_for_the_control_lock` (hold `control` inside a blocked arm, trip from a std thread, tripped within 50 ms of the call); `concurrent_arms_serialise_and_the_ledger_agrees_with_the_gate` (model-based, 200 seeded interleavings of arm(a), arm(b), disarm, trip, recover with random ledger latencies; invariant I1 and "every disarm/trip/close request that returned is reflected in the final state"); `control_tasks_survive_requester_drop`; `control_task_panic_trips_control_panic_and_answers_ingress_control_failed`; `epoch_exhaustion_closes_the_gate` (`Gate{epoch: u64::MAX}` injected); `recover_losing_to_disarm_leaves_the_state_unchanged`; `recover_is_single_flight_and_all_or_nothing`; `arm_during_starting_answers_ingress_starting`; `disarm_during_starting_cancels_arm_on_start_and_does_not_abort_the_start`; `events_are_emitted_without_the_inner_lock` (hold `Supervisor::inner`, arm, receive `Warning INGRESS_ARMED`); `status_snapshot_never_waits_for_the_control_lock`; `gate_epoch_changes_on_every_transition`; `recovery_clears_tripped_and_unavailable_without_restart` (gate state only; the flow-level proof is `a_flow_after_recovery_reaches_a_durable_closed_record`, 23.7); `registry_ring_evicts_oldest_and_inspect_reports_not_retained`; `set_ingress_rate_limit_answers_ingress_rate_limited_for_arm_only_and_noops_cost_no_token`. Draft 2's tests of the arm-versus-disarm race exercised `IngressShared` only, never `Supervisor::handle`, which is where the defect was; these go through the handler with the `ControlLedger` double: `set_ingress_disarm_during_an_arm_in_flight_supersedes_it` (hold `append_armed`, send `SetIngress{armed: false}`: it answers at once with `disarmed`; release: the arm answers `INGRESS_SUPERSEDED`, the final gate is `Disarmed`, the ledger shows `Armed` then `Disarmed{arm_superseded}`), `set_ingress_disarm_is_never_short_circuited_as_a_noop` (two disarms in a row each bump the epoch), `set_ingress_disarm_works_with_an_empty_arm_bucket`, `set_ingress_arm_queued_behind_an_arm_of_another_profile_is_not_dropped_as_a_noop`, `set_ingress_with_a_stale_expectation_is_refused_config_conflict_and_arms_nothing`. Recovery: `recovery_installs_a_fresh_writer_and_a_second_recovery_works` (trip with `AuditWriteFailed` through a failing `LedgerIo` double, re-arm, trip again, re-arm), `receipt_of_the_old_writer_never_writes_to_the_new_chain`, `flow_ids_stay_unique_across_a_recover`. Status: `headline_claims_activity_only_when_armed` (10.2), `audit_window_short_warning_follows_pruned_entries_and_oldest_age`, `admitted_flow_volume_prunes_oldest_first_and_status_says_so`.
* **host** (paused time, fake `IngressPlatform`): `accept_errors_back_off_as_a_select_arm_and_join_set_keeps_draining`; `accept_fatal_after_100_consecutive_errors_trips_and_does_not_exit`; `capacity_wait_admits_when_a_permit_frees_within_250ms_and_refuses_after` (restated from the 2 s queue of the config proposal); `ninth_waiting_socket_is_dropped_at_once`; `silent_connections_do_not_prevent_an_authorised_handshake` (100 silent connections, paused time advanced by 1 s, an authorised client completes its handshake; the accept bucket and the permits are untouched); `silent_handshake_sockets_never_charge_permits_or_tokens`; `a_socket_is_evicted_only_after_one_second_and_only_while_its_request_is_incomplete`; `bind_retries_addr_in_use_with_backoff_then_succeeds`; `bind_gives_up_after_the_window_and_reports_unavailable`; `bind_permission_denied_is_not_retried`; `bind_retry_follows_the_platform_schedule_and_never_changes_port`; `set_ingress_while_bind_retrying_is_answered_starting_and_not_queued`; `arm_on_start_applies_after_the_delayed_bind`; `flow_guard_enqueues_closed_and_a_terminal_result_on_abort`; `trip_during_starting_makes_the_ingress_unavailable`; `hardening_required_with_unhardened_fake_platform_is_unavailable`; `best_effort_with_unhardened_fake_platform_warns`; `at_capacity_a_new_connection_waits_at_most_250ms_then_is_refused`; (`C-E5`) `idle_tunnels_are_evicted_for_a_new_connection_but_active_ones_are_not`.
* **real loopback:** `bind_failure_reports_unavailable_and_ipc_stays_up` (a bound AND listening socket held for the whole test); `rearm_after_bind_failure_succeeds_once_the_port_is_free` (release, arm; retry the whole test on up to 5 fresh ports to absorb the port race that `docs/RESTART_ASSESSMENT_2026-09-21.md` recorded).

### 23.7 `ingress_flow`: in-process, real loopback sockets

* ACCEPT-1a `socks5_client_reaches_echo_target_through_direct_rule`: explicit Direct rule on 127.0.0.1 with its port, bytes round-trip, ledger shows pending, result connected, closed with one flow id and `bytes_up == bytes_down == payload`, `verify_dir` ok. ACCEPT-1b `socks5_client_reaches_target_through_socks5_adapter_and_proxy_saw_exact_destination` (a relaying fake records ATYP/host/port; the name is forwarded unresolved; target saw exactly one connection from the proxy; the result chain is the adapter). ACCEPT-1c `socks5_client_reaches_target_through_http_connect_adapter` (request line is the exact authority).
* ACCEPT-2/3 `deny_rule_prevents_arrival_and_is_audited_before_the_reply`: sentinel target, client gets `02`, the ledger read immediately after the reply with no polling contains a durable `Denied` with matched rule id and `POLICY_DENY` and no `Pending`; `no_matching_rule_is_default_denied`; `attestation_rule_is_denied`; `unknown_adapter_is_denied_not_direct`.
* ACCEPT-4 `dead_adapter_plus_lower_priority_direct_never_reaches_target` (priority-10 SOCKS5 adapter on a held-bound never-listening port, priority-20 Direct to the same destination; failure reply, sentinel accept count 0, exactly one pending and one failed result); `handshake_reject_by_upstream_proxy_is_not_retried_directly`; `silent_upstream_proxy_times_out_and_closes`; `openvpn_route_is_refused_without_any_socket`; `tls_terminal_route_is_refused` (guard fed directly); `fallback_route_is_refused`.
* Targets: `numeric_alias_never_reaches_resolver_or_policy`; `bracketed_ipv6_matches_the_plain_ipv6_rule`; `mapped_ipv6_matches_the_ipv4_rule`; `direct_by_name_resolves_once_dials_pinned_address_and_records_resolution` (fake resolver, permissive test guard); `direct_by_name_special_use_answer_is_refused_without_a_connection` (real `IngressDirectGuard`, fake resolver answering 127.0.0.1; the counting `DataPlane` wrapper shows the executor refused it and the sentinel sees nothing); `second_answer_of_a_rebinding_resolver_is_never_used`; `denied_names_never_reach_the_resolver`; `resolver_is_called_only_after_pending_is_durable`; `direct_name_single_label_dot_local_dot_onion_refused_without_resolution`; `direct_name_refused_when_data_plane_does_not_guard_names`; `proxied_route_forwards_name_unresolved_and_never_resolves`; `ipv6_literal_direct_is_refused_under_ipv4_only`; `a_black_holed_first_candidate_still_reaches_the_second`; `hashed_destination_mode_hashes_the_dialed_address_too`; `direct_name_resolving_to_a_denied_ip_is_refused_without_a_connection` (real `IngressDirectGuard` with a deny set, fake resolver; the counting data plane shows the executor refused it, the sentinel sees nothing, `Result.refusal` is `deny_rule`); `a_failed_race_records_every_attempted_address`; `ingress_executor_builder_installs_guard_and_family_filter` (`build_ingress_executor`: `has_direct_guard()`, `address_families() == cfg.families`, and through `NetcoreDataPlane` `guards_direct_names()`; the same builder without a guard makes the engine refuse a name with `DIRECT_GUARD_MISSING`); `activation_executor_stays_unguarded_and_any_family` (pins that `ssk activate --dest name` behaves as before).
* Audit and lifecycle: `audit_failure_before_dial_prevents_dial`; `audit_failure_after_connect_closes_the_upstream`; `one_audit_timeout_fails_only_its_flow`; `disarmed_listener_reads_nothing_and_closes`; `disarm_and_rearm_cancel_in_flight_flows`; `cancel_between_pending_and_result_writes_terminal_failed_record`; `abort_all_leaves_a_closed_story`; `a_flow_after_recovery_reaches_a_durable_closed_record` (a failing `LedgerIo` double trips the gate with `AuditWriteFailed`; re-arm; a full SOCKS flow runs to a durable `Closed`; `verify_dir` is ok and the flow id's boot prefix differs from the first boot's).
* Limits and abuse: `max_connections_enforced_and_slot_reused`; `slowloris_handshake_times_out`; `cross_protocol_first_bytes_get_zero_bytes_back` (TLS hello, GET, SOCKS4, random); `idle_timeout_closes_tunnel`; `half_close_propagates_both_ways`; `large_transfer_4mib_each_way_keeps_counters_exact`; `denial_flood_stays_bounded_and_reconciles` (injected `Tuning`, 2000 denied connections, after `host.flush_summaries()` durable + summary counts equal the denied counter; no 10 s wall-clock wait); `flow_panic_budget_trips_after_three_and_rearm_resets`; `tripped_gate_is_recoverable_by_rearm_without_daemon_restart`; `crlf_host_cannot_forge_a_log_line`; `client_cannot_influence_profile_or_app_id`; `netcore_error_display_never_reaches_tracing` (source scan, needles built with `concat!`).

### 23.8 `ingress_daemon`: real `sskd`

* `sskd_end_to_end_via_ipc_arm` (port 0; poll `GetStatus` for `disarmed` and `listen`; arm; a SOCKS5 client reaches the echo target; `ListRecentFlows`/`InspectFlow` return the flow with audit seqs; `Deactivate` disarms; a later connection gets zero bytes; `verify_dir` on the state dir succeeds); `restart_comes_back_disarmed_unless_arm_on_start`; `arm_on_start_arms_with_durable_record_cause_config_autostart`; `restart_continues_chain_and_flow_ids_are_unique`.
* Status: `status_never_claims_protection_while_armed` (`DaemonState` stays `Inactive`, `dns_protected` false, `StatusDto.last_error` untouched, coverage `proxy_clients_only`, `system_wide` false); `ingress_strings_contain_no_forbidden_words` (notice, state words, warning texts, doctor text, CLI lines, rendered status); `status_carries_observations_labelled_and_claims_nothing`; `observed_text_never_enters_fixed_strings`; `no_tunnel_vocabulary_in_path_and_snapshot`; `ingress_never_labels_the_probe_as_the_default_route` (needles `default route`, `standardroute`, `internet destination`, `internetziel` over every production string of the daemon, the CLI and the GUI modules); `observations_never_decide`; `ingress_never_touches_the_kill_switch`; `kill_switch_engaged_adds_warning_and_changes_nothing_else`; `ingress_audit_status_block_has_no_key_path_or_destination`; `status_ingress_is_some_on_every_path`.
* Start-up and faults: `default_config_opens_no_listener`; `config_invalid_means_no_listener_and_ipc_stays_up`; `corrupt_ledger_marks_ingress_unavailable_and_keeps_ipc`; `torn_tail_is_recovered_on_start`; `graceful_shutdown_drains_flows_and_writes_closed_records` (SIGTERM; exit 0; lock released after the writer joined); `sigterm_during_a_silent_activation_settles_the_ledger_and_exits_within_budget`.
* **`ingress_flood_cannot_starve_ipc_under_a_small_nofile_limit`** (replaces `sskd_survives_fd_exhaustion_on_ingress`; unix): start `sskd` through `sh -c` with `ulimit -n 400` followed by `exec` of the `sskd` path passed as `$0` (no quoting of `CARGO_BIN_EXE_sskd`); enabled ingress armed with a Direct rule to a local echo; open 300 SOCKS clients and hold them; `GetStatus` succeeds within 1 s at every poll; status shows `max_connections_effective` 72 (computed from the formula of 7.3: `(400 - 256) / 2`; to be confirmed when run) and `counters.refused_capacity > 0`; the process is alive; after the clients are released new flows work. Deterministic because the budget, not luck, keeps the IPC reserve.
* Isolation: `activation_and_ingress_do_not_bleed_state` (`ssk activate --dest` holds a session while a denial flood runs: state stays `Protected`; a failed activation does not disarm or trip the ingress); `desktop_client_still_reads_status_with_ingress_block`; `ingress_never_dials_by_itself` (source scan in the style of `the_cli_never_constructs_a_broker`: `RouteExecutor`, `connect_tcp`, `TcpStream::connect`, `AdmissionToken {` in `src/ingress` above `#[cfg(test)]`); `exactly_one_connect_route_per_admitted_flow_and_none_otherwise`; `get_ingress_audit_returns_verbatim_bodies_that_reverify_client_side`; `get_ingress_audit_respects_limit_before_seq_and_byte_cap`; `get_ingress_audit_does_not_take_the_supervisor_mutex`; `hashed_mode_leaks_no_host_on_any_surface` (raw ledger bytes, `StatusDto`, `ListRecentFlows`, `InspectFlow`, doctor text and a tracing capture at DEBUG; `Denied` stays plain); `plain_mode_debug_log_escapes_and_truncates`; `tracing_capture_at_debug_has_no_destination_in_hashed_mode`; Direct-by-name through the WIRED daemon (draft 2 had only a documented gap here, so a wiring regression such as every name refused `DIRECT_GUARD_MISSING` would have stayed green): `direct_by_name_reaches_the_resolver_through_the_wired_executor` (real `sskd`, `connect_timeout_ms` 300 so that the resolve deadline is 300 ms, a Direct rule matching `*.invalid`, a SOCKS5 client that sends the name `wired.invalid`; expected: reply `04`, a `Pending` with `resolution: local_pinned`, a `Result{Failed}` whose `error_code` is `NETCORE_DNS_FAILED` or `NETCORE_TIMEOUT`, and never `DIRECT_GUARD_MISSING` or `DIRECT_NAME_NOT_RESOLVABLE`, which shows that the name passed the route guard, that the daemon's executor holds a guard and that the OS resolver was called; `.invalid` never resolves, so the test needs no network and accepts either failure of an offline resolver), and `direct_by_name_eligibility_refusals_are_denials_without_a_resolver_call` (`intranet`, `x.local`, `x.onion`: reply `02`, a `Denied` record, resolver call count 0). The success path and resolve-once are proven in process with the fake resolver; the OS resolver path against a real name is `os_resolver_resolves_localhost` and step 6 of the manual procedure (24.2.3).
* `ssk-cli` against a real `sskd`: `ingress_commands_against_real_sskd`; every ingress subprocess test first asserts `status.ingress` is `Some` and `status.protocol == IPC_PROTOCOL_VERSION` ("stale sskd binary: build with cargo build -p ssk-daemon"); `ingress_arm_against_daemon_without_ingress_block_prints_capability_error_and_sends_nothing`; `killswitch_engage_refuses_while_ingress_is_bound`; `killswitch_engage_with_allow_flag_reaches_the_broker_layer` (off Windows the broker layer answers `KILLSWITCH_BROKER_UNSUPPORTED`, `ssk-cli/src/main.rs:1861-1887`); `killswitch_engage_without_a_daemon_proceeds_with_a_note`; `killswitch_guard_is_bounded_in_time` (a stub that never answers; injected budget).
* Windows, `windows-latest`, function-level `cfg`: the tests of 15.11.

### 23.9 GUI (section 25)

* **`ssk-ui-contract`:** `desktop_v3_fixtures_round_trip_and_reject_authority_fields` (extra keys `protection_confirmed`, `system_wide`, `notice`, `enforcement_active`, `app_id` fail; schema versions 1, 2, 4 fail; `panel_state` engaged fails); `write_error_codes_match_the_shared_fixture` (the 15 serialised `WriteError` names equal `fixtures/write-errors.json`, `WRITE_ERRORS` in `contract.js` and the keys of `WRITE_ERROR_TEXT`; an exhaustive match helper forces a new variant to update the list).
* **`ssk-desktop-client` projection:** `system_wide_claims_and_bad_text_are_rejected`; `inconsistent_state_never_reads_as_covered`; `listen_must_be_a_nonzero_ipv4_loopback_or_the_view_is_inconsistent`; `counters_are_clamped_to_js_safe_integers_without_overflow`; `hostile_flow_rows_invalidate_only_the_flows_section` (markup, bidi override, space, unknown `destination_form`, bad rule id, bad reason code, 97-byte flow id, 51 rows truncate); `route_observation_text_is_validated_and_never_labelled`; `refusal_codes_map_to_a_closed_set_and_text_is_never_forwarded`; `kill_switch_report_has_three_values`; `ingress_json_contains_no_forbidden_word` (all state x coverage); `text_shapes_match_the_shared_list`.
* **client** (paused time, Linux): `read_asks_for_flows_only_when_the_daemon_reports_an_ingress`; `a_hung_flow_list_degrades_only_the_flows_section`; `a_silent_daemon_is_a_deadline_and_a_second_read_is_busy`; `arm_sends_armed_true_with_the_client_label_the_remembered_expectation_and_no_profile`; `a_disarm_does_not_queue_behind_the_clients_own_arm`; `an_arm_after_the_daemon_changed_its_default_profile_is_refused_config_changed_and_sends_nothing`; `an_arm_without_a_prior_snapshot_is_unavailable_and_sends_nothing`; `disarm_sends_one_request_and_never_reads_first`; `arm_refuses_without_sending_when_the_daemon_has_no_ingress_or_is_too_old`; `a_failure_before_the_request_is_nothing_sent_and_after_it_is_outcome_unknown` (connect failure, lost reply, hung reply at 14 s, hung pre-read at 2 s); `daemon_refusals_become_codes_and_text_is_dropped` (an `Ack` is `invalid_response`); `arm_writes_are_serialised_and_floored_disarm_has_its_own_slot_and_reads_are_independent`; `unix_socket_fake_peer_round_trip` (a tokio `UnixListener` peer speaking `ssk_ipc::framing` answers `GetStatus`, `ListRecentFlows` and `SetIngress` to the real `DesktopClient`); `the_desktop_client_names_only_three_requests` (source scan: the set of `Request::` names equals `{GetStatus, ListRecentFlows, SetIngress}`).
* **real `sskd`:** `desktop_client_arms_and_disarms_a_real_daemon_and_the_ledger_names_the_caller` (the last two ledger records carry `uid:<getuid>` and `client: desktop`); `desktop_write_is_refused_when_ingress_is_disabled`; `desktop_disarm_answers_while_an_activation_dial_is_silent`; `set_ingress_arm_flapping_is_rate_limited_disarm_is_not_and_no_extra_records_are_written`; `set_ingress_with_an_extra_key_is_accepted_and_an_unknown_client_label_is_recorded_unknown`.
* **Node (Linux and Windows CI):** `ingress-contract.test.js` (every V3 fixture validates unchanged; 24 mutations; hostile destinations and aliases, each hiding code point built with `String.fromCodePoint`; the shared text-shapes list); `ingress-presentation.test.js` (no forbidden word in any wording over all state x coverage x phase and all fixtures; literal scan over five modules plus the three HTML sections, asserting more than 150 literals and the exact file set; armed is never green; the `allowedActions` matrix per fixture; old daemon and V2 snapshot handling; observation labelling (the probe address, never "Standardroute") and change line; hashed destinations; confirmation texts and the connection count); `ingress-wiring.test.js` (fake DOM built from the ids of `index.html`: the first click only opens the confirmation; a double confirm sends one request and re-reads; an unanswered confirmation withdraws after 20 s; a new observation withdraws it; disarm is immediate without active flows and confirmed with them; every failure code has its sentence and `outcome_unknown` re-reads; the preview has no action; an identical poll result performs zero DOM writes; when the status cannot be read arming is disabled and disarming sends directly); `controller.test.js` additions (a background refresh keeps the observation, keeps its freshness limit and still erases it on failure; a hung background read does not postpone the freshness limit; a manual refresh still blanks); `poller.test.js` (2000 ms cadence without overlap; a hidden window does not poll and becoming visible reads at once; a failing read never stops polling); `boundaries-write.test.js` (no sink pattern in any production file, 28 patterns; no link, form, frame, object, base, inline handler, inline style and exactly one module script; the transport names exactly the three commands as literals with no argument and nothing else calls `invoke` or reads `__TAURI__` except `main.js` once; only `bootstrap`, `actions` and `main` touch the action port); `package.test.js` replacements (the capability, three-list agreement and host-surface tests of 25.8, plus the packaging asset list).
* **`apps/desktop` (Windows only, not run here):** `compiled_capabilities_grant_exactly_three_commands_to_the_bundled_window` (the ACL matrix of 25.8 with the probe command and a strict "not allowed" assertion); `navigation_accepts_only_bundled_origins` unchanged; `bundled_webview_polls_status_then_flows_through_the_real_native_command` (ignored, interactive: the synthetic peer expects exactly `GetStatus` then `ListRecentFlows{limit: 51}`, or only `GetStatus` when it answers `ingress: None`, and nothing else) plus the manual checklist.

### 23.10 Scripts, CI and the third-party scenario

* `bash scripts/ci/tests/contract_guard.test.sh` (15 cases); `dial_path_binds_nothing_static` and its siblings (23.3); the `pwsh` fixture test of Appendix D.4; the manual procedure and script of 24.2 (not automated); `summarise_route_never_includes_hop_auth_or_address`.

The following draft-1 tests are **removed or replaced**: `direct_route_with_hostname_is_refused_without_resolution` (the rule it pinned was reversed), `sskd_survives_fd_exhaustion_on_ingress` (replaced, 23.8), `special_use_needs_matched_rule_destination` (renamed `..._and_port`), `trace_route_and_live_flow_agree_on_policy_plan` (replaced by `trace_route_reports_profile_source_and_equals_engine_decide`), `resume_heuristic_cancels_flows_on_clock_skew` (`C-H2` removed), `ingress_schema_keys_equal_serialized_default_keys` (subsumed by `schema_properties_equal_serialized_default_keys`).

## 24. Acceptance

### 24.1 The acceptance criteria (M2 on Linux): the four of the roadmap and a fifth

(1) A real client reaches a target through the chosen adapter: direct-rule, SOCKS5-adapter and HTTP-CONNECT-adapter tests with a relaying fake upstream that records the exact destination. (2) Deny prevents arrival: sentinel listener plus the durable-denial barrier, for the request the client makes; for a name also the exact-IP deny rules of the armed profile after resolution (6.10 step 5), because a name rule alone cannot stop a name that resolves to a denied address. (3) A matching audit trail: pending/result/closed with one flow id, matched rule, destination and chain, `verify_dir` ok. (4) No unintended direct fallback: dead adapter plus lower-priority Direct rule, rejected handshake, silent upstream, audit failures, the executor `Fallback` test, OpenVPN. (5) Direct-by-name is wired (added in draft 2 when owner decision 6 moved it into M2; the owner's original four are unchanged): the real `sskd` takes a Direct name through its own executor to the OS resolver and refuses it for the right reason (`direct_by_name_reaches_the_resolver_through_the_wired_executor`), the executor builder installs the guard and the family filter, and resolve-once, pinning and the guards are proven in process (23.7). All five are covered by `C-F2` (23.7, 23.8). The acceptance of the whole milestone is `C-F2` green on `ubuntu-latest` (owner decision 1).

### 24.2 ACCEPT-5: coexistence with a third-party tunnel application

ACCEPT-5 is the criterion the owner's laptop is accepted against; it is part of the release, not of the Linux gate, and it is an explicit gate: the desktop release gate of 22 names its owner, the commits it needs and the recorded run output. The one automated proof that the OS routing table decides the path is the route-flip test, a CI job only from `C-CO1b` on; until then the claim rests on the static scan, the connector seam and the manual run. The automated half runs without any tunnel application and proves what Kaleidoscorp itself does (it binds nothing, observes honestly, never claims, never touches the firewall rule). The manual half proves, for one laptop and one moment, that the proxy path shows the same public address as the system path.

#### 24.2.1 Automated half

* `dial_path_binds_nothing_static` in `crates/ssk-daemon/tests/dial_path_binds_nothing.rs`. It runs on both CI legs (the daemon gate runs on `windows-latest` too, `ci.yml` `windows_crate_gates`). (a) Via `cargo metadata` (method of `dependency_closure.rs`, normal and build edges) the direct dependencies of `ssk-netcore` are a subset of `rustls, rustls-native-certs, rustls-pki-types, ssk-netadmin, ssk-types, thiserror, tokio, tokio-rustls, tracing`; both crates are `forbid(unsafe_code)`, so nothing else can reach `setsockopt`. Adding `socket2` for keepalive (`C-H1`) extends the list in the same commit. (b) The non-test text (cut at the first `#[cfg(test)]`) of every `ssk-netcore/src/*.rs` except `dns.rs`, and of `ssk-daemon/src/ingress/{engine,flow,pump}.rs`, contains none of `.bind(`, `::bind(`, `bind_device`, `SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IPV6_UNICAST_IF`, `IP_BOUND_IF`, `setsockopt`, `windows_sys`, `libc::` (each built with `concat!` so the file does not match itself). (c) `resolve_via(` has no caller anywhere (today only its definition, `executor.rs:95`). Simulated by script against the current tree: zero hits, equal list.
* `first_hop_and_direct_share_one_dial_function` (same file): `direct::connect_tcp` (and, after `C-N3`, its name-resolving sibling) is called exactly twice in non-test `executor.rs` (`connect_direct`, first hop of `connect_chain`) and nowhere else.
* `direct_dial_leaves_device_and_source_to_the_os` and `the_device_check_has_teeth` in the `direct.rs` tests, `#[cfg(target_os = "linux")]` on the functions, dev-dependency `socket2 = { version = "0.6", features = ["all"] }`. The first binds a listener on the loopback alias 127.0.0.5, makes a control connection with a plain `std::net::TcpStream` and records its source address (the kernel picks 127.0.0.1, observed in the review sandbox, so it differs from the destination), dials with `connect_tcp`, and asserts `socket2::SockRef::from(&stream).device()` is `None`, the dial's source address equals the control's, and the control's differs from 127.0.0.5. What this proves and what it does not: `device()` being `None` shows that no `SO_BINDTODEVICE` was applied; the source-address equality is consistent with an unbound socket but cannot tell it from an explicit `bind(127.0.0.1)`, which gives the same address, so it is NOT claimed as proof that "the OS chose the source" (draft 2 claimed that). The proof that nothing binds is the static scan above plus the connector seam; the proof that the OS decides is the route-flip test below. The second dials through a `TcpSocket` on which the test itself calls `bind_device(Some(b"lo"))` and asserts `device()` returns it, so the first assertion is known able to fail; it self-skips without `CAP_NET_RAW`. Both were compiled, run and passed under clippy `-D warnings` in a scratch crate against a copy of `connect_tcp` (tokio 1.53.1, socket2 0.6.5).
* `executor_hands_the_connector_only_destinations` and `os_connector_body_is_only_tcpstream_connect` (23.3): the type-level layer of CO-1. `TcpConnector::connect` takes a `SocketAddr` and nothing else, so no code path can ask for an interface or a source address through it, and the only socket-creating call in `connector.rs` is `TcpStream::connect(addr)`; a regression has to change the trait, which the scan and review see.
* `direct_session_reports_the_sockets_local_address` and `proxy_chain_session_reports_the_first_hop_local_address`: `SessionResolution.local_addr` equals the address the listener saw.
* The `ingress::path` tests of 23.6; the status tests of 23.8 (`status_carries_observations_labelled_and_claims_nothing`, `observed_text_never_enters_fixed_strings`, the extended `ingress_strings_contain_no_forbidden_words`, `no_tunnel_vocabulary_in_path_and_snapshot`, `observations_never_decide`, `ingress_never_touches_the_kill_switch`, `kill_switch_engaged_adds_warning_and_changes_nothing_else`; in process, with a fixed provider like the existing `Fixed(KillSwitchView)` double in `supervisor.rs`).
* In `ssk-cli`, on Linux against a real `sskd`: the four kill-switch guard tests of 23.8.
* On every OS with a fake platform whose `bind` returns `AddrInUse` N times, injected clock and sleeper: the bind-retry tests of 23.6 and the two hardening-logic tests. On `windows-latest`: the Windows function-level tests of 15.11.
* A Linux CI job from `C-CO1b` (optional until then), `#[ignore]`, needs `unshare -rn` and iproute2: `direct_dial_follows_a_route_flip_in_a_network_namespace` re-executes the test binary in a new user and network namespace with two `dummy` interfaces (10.77.1.2/24, 10.77.2.2/24), routes 198.51.100.7/32 through one, dials it with a 1 s timeout (nothing answers), reads the pending socket's local address from `/proc/net/tcp`, flips the route and repeats; expected 10.77.1.2 then 10.77.2.2. The strongest automated proof that Direct follows the routing table. UNVERIFIED: `unshare -rn` works in the review sandbox but `ip` is not installed there, so it was not run.

Stated limits: nothing automated can show how the Windows stack, or any tunnel application, treats a socket; IPv6 tests self-skip without `::1` unless `SSK_REQUIRE_IPV6=1` (13.2.5).

#### 24.2.2 Laptop setup (operator)

1. The tunnel application is installed and signed in by you; Kaleidoscorp never sees its credentials. If it steers per application, put `sskd.exe` on the tunnel side (not in a bypass list; in an include-only list) using the exact path you start it from (13.2.3). Decide its own kill switch for each round of step 12.
2. `cargo build --release -p ssk-cli -p ssk-daemon`; use `docs/examples/ingress-coexistence.yaml` (2.4), `arm_on_start` false; in its own console `$env:SSK_CONFIG_PATH = (Resolve-Path docs\examples\ingress-coexistence.yaml); .\target\release\sskd.exe` (stderr is its log).
3. `curl.exe --version` must print (Windows 10 1803 and later are reported to ship it; UNVERIFIED for your build). In PowerShell always type `curl.exe`; `curl` is a different program there.

#### 24.2.3 Manual procedure

Default echo endpoints (script parameters): `https://api.ipify.org`, `https://api64.ipify.org`, `https://api6.ipify.org`. From the review sandbox, through its proxy, `api.ipify.org`, `api64.ipify.org`, `checkip.amazonaws.com`, `icanhazip.com` and `ifconfig.me/ip` each answered a bare address over HTTPS (the addresses are the proxy's); `api6.ipify.org` could not be reached from that IPv4-only sandbox, which says nothing about it; every endpoint's IPv6 behaviour is UNVERIFIED. Write every observed value down; the script's PASS lines cover only the stated conditions. The proxy address below is the default `127.0.0.1:10800`.

| # | Do | Expected observation | If it differs |
|---|---|---|---|
| 1 | `ssk --json status` (envelope `{status, state, next_steps}`, `ssk-cli/src/main.rs:3924-3939`); `ssk --json winhost killswitch status` | `.state.ingress`: `state` `disarmed`, `coverage` `none`, `system_wide` `false`, `listen` `127.0.0.1:10800`, `egress.binds_interface` `false`, `controls.hardening` `best_effort`; on Windows before `C-WIN1`..`C-WIN3` also the warnings `PEER_CHECK_INACTIVE`, `EXCLUSIVE_BIND_INACTIVE`, `AUDIT_STORE_NOT_PRIVATE`. `.broker.verdict` `not_engaged`, or the command fails because the privileged service is not installed (record "unknown"). | `unavailable`: read `.last_error` (on Windows `INGRESS_HARDENING_UNAVAILABLE` means `required`, 15.2). Verdict `engaged`: release it first. |
| 2 | Tunnel application DISCONNECTED: `curl.exe -s --noproxy '*' https://api.ipify.org` and `curl.exe -6 -s --noproxy '*' https://api64.ipify.org` | an IPv4 address (the ISP's); an IPv6 address or a failure (record which) | - |
| 3 | CONNECT it by hand; same two commands | IPv4 differs from step 2 (the premise). IPv6 differs or fails; an unchanged IPv6 address is a leak of the system path (tunnel application or OS), not of Kaleidoscorp. | equal IPv4: that application is not carrying this machine's traffic, or `curl.exe` is on its bypass list; stop |
| 4 | `ssk ingress arm --profile coexist`; `ssk --json status` | `state` `armed`, `coverage` `proxy_clients_only`, `system_wide` `false`; within 6 s `observations.route_v4.status` `observed` with an `interface_alias` | `unsupported` or `failed` with warning `OBSERVATION_UNAVAILABLE` |
| 5 | `Find-NetRoute -RemoteIPAddress 192.0.2.1` | its interface index equals `observations.route_v4.interface_index` (record both aliases) | a difference is an INFO finding about the lookup, not a failure |
| 6 | **Echo by name:** `curl.exe -s --socks5-hostname 127.0.0.1:10800 https://api.ipify.org`; note the elapsed time | the address equals step 3's and differs from step 2's | equal to step 2: `sskd.exe` does not follow the system path, check its entry (13.2.3). No answer: 24.2.6 |
| 7 | **Echo by address:** `curl.exe -s --socks5 127.0.0.1:10800 https://api.ipify.org` | the same address as step 6 | - |
| 8 | `ssk --json ingress flows --limit 20` | step 6's flow: `route` `Direct`, `matched_rule` `echo-ipify`, `outcome` `closed`. Step 7's flow: an IP-literal destination and `matched_rule` `allow-rest-443` (a name rule never matches an address, 2.4). `egress_local` is an address of the interface the OS selected (compare `Get-NetIPAddress -AddressFamily IPv4`). On Windows before `C-WIN2` `peer_verified` is `false`. | no rule match: the profile is not the example |
| 9 | `curl.exe -s --socks5-hostname 127.0.0.1:10800 https://blocked.example/` and `... http://api.ipify.org:8080/` | both fail at the SOCKS5 stage (non-zero; a refusal reply `02` gave exit 97 with curl 8.5.0 against a stub in this review); flows show `denied`, the first with `matched_rule` `deny-blocked-example`, the second with no match | an address is printed: the profile allows more than the example |
| 10 | `curl.exe -s --socks5-hostname 127.0.0.1:10800 https://api6.ipify.org` | under `ipv4_only` no address (an IPv6-only host has no IPv4 candidate); under `any` record the result and compare with step 2's IPv6 address | an IPv6 address under `ipv4_only` is a defect |
| 11 | DNS by hand: `Get-DnsClientServerAddress -AddressFamily IPv4`, then `IPv6`; then, in a browser set to the SOCKS5 proxy with remote name resolution, run a public DNS leak test page (for example dnsleaktest.com or ipleak.net; their behaviour is UNVERIFIED) | record the resolvers the page reports and the servers each interface holds. Kaleidoscorp adds no resolver and claims nothing; an ISP resolver in the report is a finding about the tunnel application or the OS | repeat with a client that resolves names itself (`--socks5`) and compare |
| 12 | **Tunnel drop** (script switch `-IncludeTunnelDrop`, two rounds). A: the tunnel application's kill switch ON, DISCONNECT, wait 7 s, repeat step 6. B: its kill switch OFF, DISCONNECT, wait 7 s, repeat step 6. RECONNECT after each. Optionally start a long transfer in a proxied browser first. | A: no address; `state` still `armed`; `counters.connect_failed` up; `OS_ROUTE_CHANGED` if the selected interface changed. B: no address, or the ISP address, which is the documented limit (13.2.2): new connections follow the routing table around the tunnel, Kaleidoscorp does not block them, and the newest flow's `egress_local` is the physical adapter's address. A long transfer stalls and stays `active` until the application gives up, the idle timeout or keepalive; record how long. After reconnect step 6 shows a tunnel address again (possibly another). | - |
| 13 | **Restart and bind:** with a connection through the proxy open, kill `sskd.exe` and start it at once; poll `ssk --json status` every second | `starting` may appear while the port is busy (6.9.4); record the seconds until `disarmed`. `best_effort`: an immediate bind is expected (UNVERIFIED); `required` after `C-WIN1`: up to about 150 s | `unavailable` after the window: `INGRESS_BIND_FAILED`; check `ingress:port_owner` in `ssk doctor` |
| 14 | **Sleep and resume:** armed and connected, sleep at least 60 s; on resume run step 6 every 2 s for 60 s and write each result | failures or tunnel-address answers are expected; an ISP address is the step-12-B limit; `state` stays `armed`; note `counters.active_flows` right after resume | - |
| 15 | **Guard probe, by hand, only if `ssk winhost killswitch engage --help` lists `--allow-with-ingress`:** run `ssk winhost killswitch engage` while armed | non-zero exit with `KILLSWITCH_REFUSED_INGRESS_BOUND`; `ssk --json winhost killswitch status` still `not_engaged`. NEVER add `--allow-with-ingress` here: it cuts the network and the tunnel. If it is not refused, run `ssk winhost killswitch release`. | - |
| 16 | `ssk ingress disarm`; repeat step 6 | refused or closed with no answer; `state` `disarmed` | an address is printed: the gate did not close |

#### 24.2.4 The operator script

`scripts/manual_vpn_coexistence_check.ps1` is specified in Appendix D.3. It is Windows PowerShell 5.1 and PowerShell 7 syntax only and was NOT executed or parsed in this review (no PowerShell was available). It needs these CLI shapes from `C-F3`: `ssk --json status` carrying `.state.ingress` (the envelope exists today), `ssk ingress arm --profile ID`, `ssk ingress disarm`, and `ssk --json ingress flows --limit N` printing `{status, flows, next_steps}` with the additive `FlowSummaryDto` fields `route`, `matched_rule`, `egress_local`, `peer_verified`. It follows the dot-source guard of `scripts/openvpn-vm-host-probe.ps1`. The script never runs `ssk winhost killswitch engage` (step 15 is done by hand because a missing guard would cut the network) and never touches the tunnel application. Its verdict names describe paths, never protection; a third address is INFO, not PASS. Its pure-logic fixture test and the CI step are Appendix D.4.

#### 24.2.5 The script's fixture test and CI step

`scripts/tests/manual-vpn-coexistence-check.tests.ps1` runs the pure logic of the script (address classification, path verdicts, port parsing) by dot-sourcing it; dot-sourcing does not run the check, start a process or touch the network. A step in the `build_test` job of `.github/workflows/ci.yml`, `if: runner.os == 'Windows'`, `shell: pwsh`, runs it next to the existing fixture step "Check read-only VM host assessment with synthetic facts". Both are Appendix D.4; neither was executed or parsed here.

#### 24.2.6 Troubleshooting entries for `docs/RUNBOOK.md` (commit `C-CO7`)

| Symptom | Most likely cause, and what to check |
|---|---|
| Step 6 prints step 2's address | `sskd.exe` bypasses the tunnel: its exact path in the tunnel application's list (13.2.3) |
| Step 6 no answer, flow timed out | the first address is IPv6 or blocked: `direct_address_families`, the tunnel application's blocking |
| Step 6 no answer, flow `denied` | no rule for the host and port: the profile of 2.4 |
| A browser works only partly, flows show IP literals | the application resolves names itself: enable remote name resolution (13.2.6) |
| `starting` for minutes after a restart | bind retry window (6.9.4): `ssk doctor`, `ingress:port_owner` |
| `unavailable` with `INGRESS_HARDENING_UNAVAILABLE` on Windows | `hardening: required` before `C-WIN1`..`C-WIN3` (15.2, 15.3) |
| `killswitch engage` refuses; warning `KILL_SWITCH_ENGAGED` | 13.2.4; `ssk winhost killswitch release` |

#### 24.2.7 What a PASS means

For this laptop, this tunnel application, these settings and this moment, the proxy path showed the same public address as the system path, the proxy refused what the profile denies, and status carried only observations. It says nothing about other applications, DNS, IPv6 outside the proxy, any later moment, or whether any third-party software protects anything.

## 25. GUI: write path, desktop snapshot v3 and desktop host

**Status: proposed.** It replaces every statement that the webview "stays read-only". Binding inputs: Appendix C.1 decision 4 (the GUI must be able to arm and disarm the ingress) and the product scenario (applications use the loopback proxy; the operating system routing table decides where Direct traffic leaves; the VPN application is neither started, configured nor described by Kaleidoscorp).

**Evidence labels.** *Read* = read in this repository at HEAD `b62c4c8` (file:line). *Tauri* = read in the crates.io sources of the locked versions (tauri 2.11.6, tauri-build 2.6.3, tauri-utils 2.9.3, from `apps/desktop/Cargo.lock`). *Ran* = compiled and run in a scratch crate or in a scratch copy of `ui/desktop` outside the repository: 20 Rust tests (V3 types, projection, client orchestration with paused time, one Unix-socket round trip against the real `ssk-ipc` framing), 52 Node tests, and about 50 mutations of those tests (each mutation that survived was answered with a stronger test until all were caught). **UNVERIFIED** = needs Windows or a Tauri build. The host crate cannot be built on this machine (no GTK/WebKit; its `build.rs` is `cfg(windows)`), so everything inside `apps/desktop/src/main.rs` is only `rustfmt`-parsed. The prototype used the request shape `SetIngress { profile_id, client }` of the GUI proposal; the merged shape of 11.4 (`armed`, `profile_id`, `client`) was not re-run.

### 25.1 What the repository does today (read)

* **Host.** `apps/desktop/src/main.rs` registers exactly one command, `get_panel_snapshot_v2` (`:20-34, :39`). It is declared in the app manifest by `build.rs:5-8`, granted by `capabilities/read-panel.json` (`local: true`, `windows: ["main"]`, `allow-get-panel-snapshot-v2`) and selected by `tauri.conf.json` (`capabilities: ["read-panel"]`). The handler checks window label `main` and `bundled_origin(window.url())` (`:25-29`). It reaches the daemon only through `ssk-desktop-client`, whose only request is `GetStatus` (`lib.rs:69-82`; the crate doc at `:2` says read-only). The host depends on `ssk-desktop-client`, `ssk-ui-contract` and `tauri`; `ssk-ipc` is a dev-dependency (`apps/desktop/Cargo.toml`), so the host cannot even name an IPC `Request`.
* **Webview.** It reads once at start and on the refresh button; the only timer is the 10 s freshness expiry (`controller.js:36-38`, `bootstrap.js:4-13`). `docs/DESKTOP_BACKEND_CONNECTION.md:49` says "Es gibt noch keine automatische Aktualisierung". `transports/tauri.js:3-10` is the only file that names a command. All text reaches the DOM through `textContent` (`components/dom.js`); there is no `innerHTML` anywhere in `ui/desktop/src` (grep).
* **The existing negative test is weaker than it looks.** `main.rs:78-125` pins four refusals; the `activate_profile` row (`:111`) passes when the error contains "not allowed" **or** "not found" (`:119-123`). `docs/DESKTOP_BACKEND_CONNECTION.md` ("Fenster und Vertrauensgrenze") says why the manifest matters: without an explicit app manifest app commands can stay reachable. If the manifest were removed from `build.rs`, the unregistered `activate_profile` would answer "not found" and the test would stay green while a registered, ungranted command would run. *Tauri* shows a strict assertion is possible: `webview/mod.rs:1823-1846` refuses every app command that has no resolved permission when the app has a manifest (`has_app_acl_manifest`), before the handler is looked up, and every refusal text contains "not allowed" (`ipc/authority.rs:229-432`; release builds: "Command X not allowed by ACL").
* **Other Tauri facts the design relies on (read, locked versions).** (a) `ipc/authority.rs:439-465` `resolve_access`: a command is allowed only if a capability's context matches the origin (`local: true` means the bundled origin) and the window label or the webview label matches the capability's patterns. (b) `webview/mod.rs:1698-1735` `is_local_url`: a URL is local when scheme and domain equal the protocol URL's (`http` and `tauri.localhost` on Windows) **without comparing the port**, or when it is relative to the app URL; so `http://tauri.localhost:5173` is local for the ACL, and the port check in `bundled_origin` (navigation guard and command handler) is load-bearing, not redundant. (c) tauri-build `acl.rs:265-331` writes `allow-<cmd>`/`deny-<cmd>` into `permissions/autogenerated` (git-ignored, `.gitignore`) and also merges every file under `apps/desktop/permissions/**`; `acl.rs:340-395` fails the build when a capability names an unknown permission. (d) tauri-utils `acl/build.rs:289-298`: the permission is `allow-` plus the command with `_` replaced by `-`. (e) `webview/mod.rs:2007`: DevTools exist in debug builds and in release builds only with the `devtools` feature (the host enables only `wry` and `compression`).
* **IPC authentication is the same-principal check and nothing more.** Unix: `auth.rs:70-86` compares the `SO_PEERCRED` uid with `rustix::process::getuid()` (`:74`). Windows: `transport_win.rs:120-136` compares SIDs obtained by impersonation; the pipe DACL is `O:<owner>D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;<owner>)` plus a medium mandatory label `S:(ML;;NW;;;ME)` (`pipe.rs:309-316`), and `pipe.rs` itself says the label's presence is verified but that it would block a below-Medium client is not. `auth.rs:7-24` explains why a token minted by the server proves nothing; this section adds no such token.
* **`ListRecentFlows` today** answers an empty list and does not take the `Inner` lock (`supervisor.rs:917-921`). On a daemon without ingress that empty list reads as "no traffic".
* **The kill-switch bool is three-valued through `last_error`** (`supervisor.rs:239-249`): `(true, None)` engaged, `(false, None)` not engaged, `(false, Some(KILL_SWITCH_STATUS_UNKNOWN))` unknown (`killswitch.rs:83`).
* **CI.** `desktop_ui` runs `npm --prefix ui/desktop test` on ubuntu and windows (`.github/workflows/ci.yml:15-28`); `desktop_host` builds and tests the host on windows only (`:30-48`). Baseline run here: 19 Node tests, 4+4+1 Rust tests of `ssk-desktop-client`/`ssk-ui-contract`, and the real-daemon tests `desktop_read` and `peer_authentication` all pass on Linux. No code constructs `Response::Event` and the server loop writes one response per request (6.9.3): the page polls.

### 25.2 Who can do what: the trust boundary, stated plainly

| Actor | Can it call arm/disarm? | What stops it, or why it does not matter |
|---|---|---|
| Another OS user | No | Transport check before any frame is read (25.1). Rejection of a genuinely different user is operator-validated, not automated (`auth.rs:140-150`, `pipe.rs` verification boundary). |
| Any other process of the same user (malware, a script, a dev tool) | **Yes** | Nothing can stop it: same principal, exactly as for `ActivateProfile` and `Deactivate` today. No secret can separate two processes of one user. What bounds the damage is 11.4: the request carries no profile, port or rule; arm uses the profile the daemon names; disarm only narrows; rate limit; every state change is recorded with the verified principal. |
| A same-user process at low integrity or inside an AppContainer (a compromised browser renderer) | UNVERIFIED | The pipe has the medium label with no-write-up; the repository states it was not tested against a below-Medium client. Do not claim protection from it. |
| Script injected into the webview | Only the three commands, with no argument | 25.5: CSP, no sinks, shape-validated text, bundled content only. An injected script can do what a click can do and nothing else. |
| Remote web content in the window | No | `on_navigation(bundled_origin)`, `on_new_window` deny, no `remote` capability, CSP `frame-src 'none'`; Tauri's ACL also refuses non-local origins (25.1 b). |
| A second window of the app | No | `windows: ["main"]` and the label check in the handler. |
| A process that answers on the daemon's pipe or socket instead of the user's `sskd` (a pre-created named pipe on Windows) | It can show any status that the GUI or CLI renders, and it receives the arm and disarm requests | Today nothing verifies the server: `DaemonClient::connect_unix` and `connect_named_pipe` open the endpoint by name (`ssk-ipc/src/client.rs`), whereas the privileged pipe's client does verify its owner (`pipe.rs:329-331`, `require_pipe_owner`). The Unix socket sits in the state directory, where another user cannot create files unless that directory is writable by them; the Windows pipe name is a digest of public inputs (`paths.rs`) that another account can derive: UNVERIFIED. Fix `C-IPC2` (RELEASE, desktop gate): before the first frame the client checks that the server is the user's own (Unix: `peer_cred` uid and socket-file owner; Windows: pipe owner SID). Until it lands, every status the GUI shows is the report of "the process on the endpoint", and the "Grenzen" list says so (25.10). |

The GUI and the CLI are the same principal. This design therefore does **not** attempt to let the daemon tell the GUI from the CLI or from another process: the verified `peer` is the same, the `client` label in the request is self-declared and unverified (11.4), and a process id is not used (`pipe.rs:35-46` explains why a pipe client PID is weaker than the kernel-captured identity; Linux `UCred::pid` is not wired and is not needed).

### 25.3 The three native commands

Names: `get_panel_snapshot_v3` (read), `arm_ingress`, `disarm_ingress` (write). Two write commands, not one `set_ingress(armed: bool)`: neither takes an argument, so there is nothing to validate or inject; they are separate permissions (`allow-arm-ingress`, `allow-disarm-ingress`), so a restricted window could one day hold only the narrowing direction; they need different friction (25.7) and different tests.

**What the write commands can never do** (each item has a test in 23.9):

1. Take any argument from the webview: no profile id, port, address, protocol, rule, host, count, path or text. Their signatures contain only the injected `window` and `state`.
2. Choose a profile. The request carries `armed: true` and no profile; the daemon arms `routing.default_profile`. The host shows that profile in the confirmation from the snapshot's `arm_profile`; no such profile means `no_arm_profile`, and nothing is sent. The profile and the routing digest of that same snapshot travel as `expect_profile` and `expect_routing_digest` (11.4), so a daemon that now holds another default profile or another routing configuration refuses (`config_changed`) instead of arming something the user did not see.
3. Send any IPC request other than `GetStatus`, `ListRecentFlows { limit: 51 }` and `SetIngress`. `IngressSwitch` is a closed two-variant enum; the only place a `SetIngress` request is built is `switch_ingress`; a source-scan test pins the set of `Request::` names in the crate.
4. Write configuration or change `listen`, `hardening`, `arm_on_start`, limits or audit options.
5. Call `ActivateProfile`, `Deactivate`, `TraceRoute`, `RunDoctor`, `ExplainError`, `SubscribeEvents`, `GetAuditEntries`, `VerifyAuditChain`, `GetIngressAudit`; any broker command; engage or release the kill switch; start or stop a daemon or a VPN; touch the system proxy settings. The host has no dependency on `ssk-tauri-bridge` (whose `control.rs` is the kill-switch broker control layer), `ssk-netd-helper`, `ssk-winhost`, `ssk-ipc`, `ssk-daemon`, `ssk-cli`.
6. Open a process, file, socket or plugin; emit or listen to events; evaluate script; open DevTools.
7. Return daemon text. Results are closed enums, validated ids and codes, and clamped numbers.

**Daemon-facing API** in `ssk-desktop-client` (Ran in a scratch crate with the earlier request shape):

```rust
pub enum IngressSwitch { Arm, Disarm }                      // closed; no payload
impl DesktopClient {
    pub async fn read_snapshot_v3(&self) -> Result<DesktopSnapshotV3, ReadError>;
    pub async fn switch_ingress(&self, which: IngressSwitch) -> Result<IngressViewDto, WriteError>;
}
// READ: one connection. GetStatus under READ_DEADLINE (2 s, unchanged). Only when the daemon reported an ingress block:
// ListRecentFlows{limit: 51} under FLOWS_DEADLINE (750 ms); a timeout or error degrades ONLY the flows section.
// An older daemon (ingress: None) is never asked for flows: its empty list would read as "no traffic".
const WRITE_DEADLINE: Duration = Duration::from_secs(12);   // the SetIngress call itself (daemon audit waits are 2 s + 5 s)
const WRITE_FLOOR: Duration = Duration::from_millis(750);    // two ARMS never start closer than this; a disarm has no floor

pub async fn switch_ingress(&self, which: IngressSwitch) -> Result<IngressViewDto, WriteError> {
    // A disarm has its own slot and no floor: it must never queue behind this window's own arm. The daemon orders the two (a disarm supersedes an arm in flight, 6.9.2).
    let _slot = match which {
        IngressSwitch::Arm => self.arm_slot.try_acquire(),
        IngressSwitch::Disarm => self.disarm_slot.try_acquire(),
    }.map_err(|_| WriteError::Busy)?;
    if matches!(which, IngressSwitch::Arm) {
        let mut last = self.last_arm.lock().map_err(|_| WriteError::Busy)?;          // tokio::time::Instant: testable with paused time
        let now = Instant::now();
        if last.is_some_and(|t| now.duration_since(t) < WRITE_FLOOR) { return Err(WriteError::Busy); }
        *last = Some(now);
    }
    // What the user was shown: remembered by read_snapshot_v3 from the snapshot behind the confirmation. The webview supplies nothing.
    let expected = match which {
        IngressSwitch::Arm => Some(self.confirmed.lock().map_err(|_| WriteError::Busy)?.clone().ok_or(WriteError::Unavailable)?),   // none: nothing was sent
        IngressSwitch::Disarm => None,
    };
    let mut sent = false;                                   // until the frame is handed over, a failure means "nothing was sent"
    let work = async {
        let mut session = self.connector.connect().await.map_err(|_| WriteError::Unavailable)?;
        if let Some(exp) = &expected {                      // arm only: a disarm never pre-reads, it must work when status is slow
            let pre = timeout(READ_DEADLINE, session.call(Req::GetStatus)).await.map_err(|_| WriteError::Unavailable)?;
            let status = match pre.map_err(|_| WriteError::Unavailable)? { Resp::Status(s) => s, _ => return Err(WriteError::InvalidResponse) };
            status.require_protocol(1).map_err(|_| WriteError::NotSupported)?;        // 11.9
            let ingress = status.ingress.as_ref().ok_or(WriteError::NotSupported)?;
            let view = project_ingress(ingress).map_err(|_| WriteError::InvalidResponse)?;
            let profile = view.arm_profile.clone().ok_or(WriteError::NoArmProfile)?;
            if profile != exp.profile || ingress.config.routing != exp.routing_digest { return Err(WriteError::ConfigChanged); }   // the daemon now holds something other than the confirmation named
        }
        sent = true;
        let req = SetIngressRequest { armed: expected.is_some(), profile_id: None, client: Some("desktop".into()),
            expect_profile: expected.as_ref().map(|e| e.profile.clone()), expect_routing_digest: expected.as_ref().map(|e| e.routing_digest.clone()) };
        match session.call(Req::SetIngress(req)).await.map_err(|_| WriteError::OutcomeUnknown)? {
            Resp::Status(s) => project_ingress(&s.ingress.ok_or(WriteError::InvalidResponse)?).map_err(|_| WriteError::InvalidResponse),
            Resp::Err(e) => Err(map_refusal(&e.code)),    // closed table; the daemon's message text is dropped
            _ => Err(WriteError::InvalidResponse),
        }
    };
    match timeout(READ_DEADLINE + WRITE_DEADLINE, work).await {
        Ok(result) => result,
        Err(_) if sent => Err(WriteError::OutcomeUnknown),
        Err(_) => Err(WriteError::Unavailable),
    }
}
```

(In the real crate `Req`/`Resp` are `ssk_ipc::Request`/`Response` and the connector is `DaemonClient::connect`; the scratch crate used a trait so deadlines could be tested with paused time. The scratch crate ran the earlier shape of this function, with one write slot, a floor for both directions and no expectation; the version above, which critic round 1 changed, is specified and not run.) `read_snapshot_v3` stores `ArmExpectation { profile, routing_digest }` from the projected snapshot, or clears it when the snapshot has no `arm_profile`; the pre-read above compares the live daemon with it, and the daemon compares again (`INGRESS_CONFIG_CONFLICT`, 11.4), so the window in which a restart could change what an arm means is milliseconds, not the age of a confirmation.

`WriteError` (serde `snake_case`, `Serialize` only, defined next to `ReadError` in `ssk-desktop-client`, 15 values): `endpoint_unavailable`, `unavailable` (nothing was sent), `outcome_unknown` (the request was sent and no valid answer arrived: the effect is unknown and the UI must say so and re-read), `busy`, `invalid_response`, `not_supported` (daemon reports no ingress block, or speaks protocol 0), `no_arm_profile`, `config_changed` (the daemon's default profile or routing configuration is no longer the one the confirmation named; also the daemon's `INGRESS_CONFIG_CONFLICT`), `refused_ingress_disabled`, `refused_ingress_unavailable` (also bind failed, audit corrupt, hardening unavailable, fd limit), `refused_ingress_starting`, `refused_recovery_failed` (also tripped, audit failed, audit stalled), `refused_rate_limited`, `refused_unknown_profile` (also profile id invalid), `refused_other`. The mapping function is a closed `match` on the daemon code; unknown codes become `refused_other`.

**Host code** (`apps/desktop/src/main.rs`, UNVERIFIED beyond `rustfmt` parsing; it follows the existing command's shape):

```rust
#[cfg(windows)]
mod windows {
    use ssk_desktop_client::{local_endpoint, DesktopClient, IngressSwitch, ReadError, WriteError};
    use ssk_ui_contract::{DesktopSnapshotV3, IngressViewDto};
    use tauri::{State, WebviewUrl, WebviewWindow, WebviewWindowBuilder};

    struct HostState(Result<DesktopClient, ReadError>);

    fn bundled_origin(url: &tauri::Url) -> bool { /* unchanged: no userinfo, no port, tauri://localhost or http://tauri.localhost */ }

    /// Every native command runs this first. Tauri's own origin test ignores the port of
    /// `http://tauri.localhost`, so this check and `on_navigation` below are load-bearing.
    fn caller_is_bundled_main<R: tauri::Runtime>(window: &WebviewWindow<R>) -> bool {
        window.label() == "main" && window.url().is_ok_and(|url| bundled_origin(&url))
    }

    #[tauri::command]
    async fn get_panel_snapshot_v3<R: tauri::Runtime>(window: WebviewWindow<R>, state: State<'_, HostState>)
        -> Result<DesktopSnapshotV3, ReadError> {
        if !caller_is_bundled_main(&window) { return Err(ReadError::Unavailable); }
        match &state.0 { Ok(client) => client.read_snapshot_v3().await, Err(error) => Err(*error) }
    }

    async fn switch<R: tauri::Runtime>(window: &WebviewWindow<R>, state: &State<'_, HostState>, which: IngressSwitch)
        -> Result<IngressViewDto, WriteError> {
        if !caller_is_bundled_main(window) { return Err(WriteError::Unavailable); }   // nothing was sent: the honest code
        match &state.0 { Ok(client) => client.switch_ingress(which).await, Err(_) => Err(WriteError::EndpointUnavailable) }
    }

    #[tauri::command]
    async fn arm_ingress<R: tauri::Runtime>(window: WebviewWindow<R>, state: State<'_, HostState>) -> Result<IngressViewDto, WriteError> {
        switch(&window, &state, IngressSwitch::Arm).await
    }
    #[tauri::command]
    async fn disarm_ingress<R: tauri::Runtime>(window: WebviewWindow<R>, state: State<'_, HostState>) -> Result<IngressViewDto, WriteError> {
        switch(&window, &state, IngressSwitch::Disarm).await
    }
    // run(): unchanged except  .invoke_handler(tauri::generate_handler![get_panel_snapshot_v3, arm_ingress, disarm_ingress])
}
```

### 25.4 Capability and permission set

`apps/desktop/build.rs`: `.commands(&["get_panel_snapshot_v3", "arm_ingress", "disarm_ingress"])`.

`apps/desktop/capabilities/read-panel.json` (unchanged shape): `"permissions": ["allow-get-panel-snapshot-v3"]`. New `apps/desktop/capabilities/ingress-switch.json`:

```json
{
  "identifier": "ingress-switch",
  "description": "The bundled main window may ask the daemon to arm or disarm the local proxy. Neither command takes an argument.",
  "local": true,
  "windows": ["main"],
  "permissions": ["allow-arm-ingress", "allow-disarm-ingress"]
}
```

`tauri.conf.json`: `"capabilities": ["read-panel", "ingress-switch"]` (listing restricts the active set to these two). Two files rather than one so that adding write power is a visible diff of its own file, and a test pins each file separately.

Scoping to the bundled window, in three independent layers: (1) the ACL: `local: true` + window pattern `main`, no `remote`, no `webviews`, no `platforms`; (2) the handler: `caller_is_bundled_main` checks the label and the full `bundled_origin` including the port (25.1 b); (3) the window: created in code only (`app.windows` is `[]`), `on_navigation(bundled_origin)`, `on_new_window` deny. Not granted: any `core:*` permission, hence no events (`plugin:event|listen`/`emit`), no window or webview management, no path, resource, menu, tray, image or app plugin; no plugin of any kind (a plugin would also need the `.plugin(` call, which a test forbids).

### 25.5 CSP, remote content and injected script

CSP in `tauri.conf.json`: the existing string plus `worker-src 'none'; manifest-src 'none'`. Final: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src ipc: http://ipc.localhost; object-src 'none'; base-uri 'none'; form-action 'none'; frame-src 'none'; frame-ancestors 'none'; worker-src 'none'; manifest-src 'none'`. The packaging step already strips the browser `<meta>` CSP so the host injects the compiled one with script hashes (`tools/package.mjs`, `package.test.js:14`). UNVERIFIED: how Tauri 2.11.6 delivers the policy (header or meta; `frame-ancestors` only works as a header), and that the two new directives survive its rewriting. None of the argument below depends on `frame-ancestors`.

Why a confused-deputy or injected-script call is infeasible, as an argument that a test backs:

1. **No sink.** `ui/desktop/src` and `index.html` contain no `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, string timers, `srcdoc`, `javascript:`, `window.open`, `postMessage`, `DOMParser`, `createContextualFragment`, inline `on*` handler, storage, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, `location` assignment, dynamic `import()`, worker or service worker; the page has no link, form, frame, object or embed, no inline `style`, and exactly one `<script type="module" src="src/main.js">`. Pinned by `boundaries-write.test.js` (Ran; 11 mutations of these rules were all caught).
2. **Hostile text cannot carry markup by shape.** The only strings an outsider can influence are destinations (any web page can make a browser send a host name through the proxy) and the interface alias (the operating system). Rust (host) and JavaScript (webview) both enforce: ids `[a-z0-9][a-z0-9._-]{0,63}` (the repository's `valid_id`, `routing.rs:92-99`), codes `[A-Z0-9_]{1,64}`, destinations `[A-Za-z0-9.:_[\]-]{1,262}`, aliases 1-64 characters without control characters, markup characters `< > & " ' backtick`, leading or trailing white space, or the reordering and hiding characters U+061C, U+200B-U+200F, U+2028-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF. A shared list `ui/desktop/fixtures/text-shapes.json` (accept and reject cases) is read by both test suites, so the two validators cannot drift (Ran). A row that violates a shape invalidates the whole flows section, never the status. In `hashed` mode a flow row carries the token form (`kid`, `kind`, `token`), which fits the destination shape.
3. **No remote content.** One window, bundled origin, navigation and new-window guards, no `remote` capability.
4. **Nothing to inject into the command.** Zero arguments; effect limited to arm of the daemon's own default profile and disarm.
5. **Supply chain.** `ui/desktop/package.json` has no dependencies; `tools/package.mjs` ships an explicit allow-list of files.
6. **DevTools.** Present in debug builds (the README's `cargo build` is one), absent in release builds unless the `devtools` feature is added, which a test forbids. A user with DevTools open is the same principal as the user (open question B15).

Optional hardening (`C-U10`, UNVERIFIED, must not be shipped blind): `require-trusted-types-for 'script'; trusted-types 'none'` in the CSP would make any future sink throw at runtime. It needs the interactive Windows smoke test, because Tauri's own injected scripts have not been checked against it.

### 25.6 Daemon-side authorisation

The daemon is the only authority; the GUI contributes no trust. The wire shape, the recorded caller, the order of checks, the rate limit, idempotence, trip semantics, the absence of the `Inner` lock and the always-present ingress block are specified once, in 11.4 and 10.3 (the GUI theme's requirements R1 to R11 were merged there: R1/R2 in the wire shape and the recorded principal, R3 no `Inner`, R4 order of checks, R5 idempotence, R6 rate limit, R7 trip semantics, R8 `ingress` is `Some` on every path including `activating_status`, R9 `arm_profile` and `configured_listen`, R10 the flow list, R11 the two new codes). The only GUI-specific consequences: the GUI sends `armed` and a `client` label and nothing else; it treats `INGRESS_STARTING`, `INGRESS_BUSY`, `DAEMON_BUSY` and `INGRESS_RATE_LIMITED` as retriable; it never calls `Deactivate`.

### 25.7 Friction and confirmation

The confirmation protects against an accidental click and states what is being switched on. It is **not** a boundary against injected script (a script can click too); that boundary is 25.5.

* **Arm** (`disarmed`, or `tripped`: label "Erneut aktivieren …"): the first click only opens an inline confirmation naming the profile, the address and the limits. German text: "Profil <id> wird für den lokalen Proxy aktiviert.", "Eine Anwendung nutzt ihn nur, wenn sie auf SOCKS5, <host>:<port>, ohne Anmeldung eingestellt ist.", the coverage sentence "Nur Anwendungen, die diesen Proxy verwenden, werden geroutet. Alle anderen Verbindungen sind nicht erfasst.", and "Dies ändert keine Systemeinstellung und startet oder konfiguriert keine andere Anwendung." Buttons "Abbrechen" (receives focus) and "Bestätigen". The confirmation withdraws itself after 20 s and whenever a new observation no longer allows arming. A double confirm sends one request. What the confirmation names (profile, address, limits) is exactly what the host remembers and sends as the daemon's expectation (25.3): if the daemon was restarted with another configuration in between, the arm is refused with "Die Konfiguration des Dienstes hat sich geändert. Bitte erneut prüfen." and nothing is armed.
* **Disarm** (`armed`): immediate when there are no active connections; otherwise the confirmation says "N aktive Verbindungen werden getrennt."
* **Disarm is never gated on a fresh observation** (it is the narrowing direction): in `stale` or `degraded` the button stays enabled, labelled "Proxy deaktivieren (Status unbekannt)", and sends directly. **Arm is always gated**: fresh (`ready`), consistent, state `disarmed` or `tripped`, `arm_profile` present, compat `ok`, source `desktop` (the preview never offers an action).
* After every action the card shows what the daemon answered ("Der Dienst meldet: Proxy aktiviert."), never what was requested; a different state is shown as such. `outcome_unknown` says the effect is unknown and triggers a re-read. The message disappears after 10 s.

### 25.8 The replacement for the negative test

Four layers; the first runs on Linux and Windows CI (Ran against a scratch copy, 21 mutations caught), the second only on `windows-latest`.

**(1) Static, in `ui/desktop/tests/package.test.js`, replacing the test at `:26-38`.** It pins, as exact equalities: the files in `capabilities/` (`ingress-switch.json`, `read-panel.json`); each file's key set (`description, identifier, local, permissions, windows`: no `remote`, `webviews`, `platforms`); `local === true`; `windows` deep-equals `["main"]`; permissions equal `["allow-get-panel-snapshot-v3"]` and `["allow-arm-ingress", "allow-disarm-ingress"]`, each matching `^allow-[a-z0-9]+(-[a-z0-9]+)*$` (no set, no default, no plugin prefix, no deny); the union equals `COMMANDS.map(c => 'allow-' + c.replaceAll('_','-'))`; `tauri.conf.json` capabilities, `app.windows === []`, `app.security` keys `[capabilities, csp]` only (no `dangerous*`), each CSP directive above, and no `unsafe-`, `*`, `data:`, `blob:`, `https:`, `ws:`; `build.rs` `.commands([...])`, the single production `generate_handler![...]` (text before `#[cfg(test)]`) and the `#[tauri::command]` functions all equal `COMMANDS = [arm_ingress, disarm_ingress, get_panel_snapshot_v3]`; the host `Cargo.toml` has no `tauri-plugin`, `devtools`, `protocol-asset`, `tray-icon`, `unstable`, keeps `features = ["wry", "compression"]`, and none of `ssk-ipc, ssk-winhost, ssk-tauri-bridge, ssk-netd-helper, ssk-vpnctl, ssk-daemon, ssk-cli` among its normal dependencies while `ssk-ipc` stays a dev-dependency; the production part of `main.rs` contains none of `.plugin(`, `ssk_ipc`, `std::process`, `std::fs`, `std::net`, `tokio::net`, `Command::new`, `dangerous`, `.devtools(`, `open_devtools`, `.eval(`, `.emit(`, `.listen(`, `on_page_load`, `initialization_script`; and `apps/desktop/permissions/` holds nothing but `autogenerated` (a hand-written file would be merged into the app manifest, 25.1 c). Mutations that were each caught: `core:default` added; a `remote` key; a second window; window `*`; an extra permission; a fourth command only in the handler; a fourth command only in the manifest; a plugin dependency; `.plugin(`; `frame-src` removed; `unsafe-inline`; `ssk-ipc` or `ssk-tauri-bridge` as a normal dependency; a hand-written permission file.

**(2) Behavioural, in `apps/desktop/src/main.rs` tests (Windows only; UNVERIFIED, copied from the existing test's API use, which `tauri::test` source confirms: `get_ipc_response<W: AsRef<Webview<MockRuntime>>>`, `assert_ipc_response`, `INVOKE_KEY`).** The mock app registers the production handlers **plus a probe** `probe_ungranted() -> "PROBE_REACHED"` that is registered but absent from the manifest. Matrix:

* From window `main`, origin `http://tauri.localhost`, each of the three commands reaches its handler: `assert_ipc_response(&main, request(cmd, origin), Err("endpoint_unavailable"))` with `HostState(Err(ReadError::EndpointUnavailable))`.
* Refused by the ACL itself, and the message must **contain "not allowed"** (the old test also accepted "not found"): each of the three commands from window `other`; each of the three from origins `https://example.com`, `http://localhost`, `file:///C:/index.html`; from `main` at the bundled origin: `probe_ungranted`, `get_panel_snapshot_v2`, `activate_profile`, `deactivate`, `set_ingress`, `arm_ingress_with_profile`, and plugin commands `plugin:window|close`, `plugin:event|listen`, `plugin:event|emit`, `plugin:app|version`, `plugin:path|resolve_directory`, `plugin:shell|execute`, `plugin:fs|read_file`, `plugin:http|fetch`, `plugin:opener|open_url`, `plugin:clipboard-manager|write_text`, `plugin:process|exit`.
* The probe row is what makes the test sensitive to the regression the old test could not see: if the app manifest disappeared, the probe would run, `get_ipc_response` would return `Ok`, and `expect_err` would fail.
* `bundled_origin` keeps its table test, including `http://tauri.localhost:5173` as refused. The row `http://tauri.localhost:5173` as a *request origin* is deliberately absent: Tauri's ACL treats it as local (25.1 b); the guard against it is `bundled_origin` in `on_navigation` and in `caller_is_bundled_main`, plus `frame-src 'none'`.

**(3) Source scan in `ssk-desktop-client` (Linux).** All non-test source files of the crate, comment lines removed, are scanned for `Request::` followed by an identifier; the set must equal `{GetStatus, ListRecentFlows, SetIngress}`. Needles are built with `concat!` like `the_cli_never_constructs_a_broker` (`ssk-cli/src/main.rs:6446`), so the test file does not match itself.

**(4) Webview side (Node, Linux).** `boundaries-write.test.js`: the transport names exactly `arm_ingress`, `disarm_ingress`, `get_panel_snapshot_v3` as string literals, each `invoke(` call has exactly that one argument, a computed name fails, no other file contains `invoke(`, only `main.js` reads `__TAURI__` (once), only `bootstrap.js`, `actions.js` and `main.js` touch the action port. The real click -> `invoke` -> ACL -> handler -> pipe chain in a real WebView2 is UNVERIFIED: `C-U9` adds a manual checklist because UI automation of WebView2 is not available here.

### 25.9 `DesktopSnapshotV3` and its projection

New schema because the V2 contract is `deny_unknown_fields` and the repository's rule is that incompatible changes get a new contract version (`docs/MODULAR_DESKTOP_UI.md`). `ssk-ui-contract` gains `desktop_v3.rs` (no new dependency; `dependency_boundary.rs` stays green). Types (Ran: serde round trip, `deny_unknown_fields`, closed enums; clippy `-D warnings` clean):

```rust
#[serde(try_from = "u32", into = "u32")] pub struct DesktopSchemaVersionV3;           // only 3
#[serde(deny_unknown_fields)] pub struct DesktopSnapshotV3 {
    pub schema_version: DesktopSchemaVersionV3,
    pub panel_state: DesktopPanelState,            // Degraded only, as in V2: a daemon summary never establishes a security-ready panel
    pub compat: CompatView,                        // ok | daemon_too_old (from StatusDto.protocol, 11.9)
    pub daemon: DaemonViewV3,                      // reported_state, version, active_profile(id), adapter_count<=256, last_error_code(code), kill_switch_report
    pub ingress: Option<IngressViewDto>,           // None ONLY for a daemon that reports no ingress block
    pub observations: ObservationsViewDto,         // os_route_probe: Option<{interface_alias, probe: 192.0.2.1 | 2001:db8::1, family ipv4|ipv6, observed_age_ms: Option<u64>}>, projected from IngressStatusDto.observations (10.5)
    pub flows: FlowsViewDto,                       // availability available|unavailable|not_reported|invalid, items<=50, truncated
}
pub enum KillSwitchReportView { Engaged, NotEngaged, Unknown }     // derived exactly as supervisor.rs:239-249 documents
#[serde(deny_unknown_fields)] pub struct IngressViewDto {
    pub state: IngressStateView,        // disabled|starting|unavailable|disarmed|armed|tripped|stopping|unknown
    pub coverage: CoverageView,         // none|proxy_clients_only|unknown
    pub consistent: bool,               // false when state and coverage disagree, either is unknown, or an address is not a loopback address
    pub listen: Option<ListenView>,     // {host: "127.x.y.z", port: 1..=65535}
    pub configured_listen: Option<ListenView>,
    pub protocols: Vec<ProtocolView>,   // <= 4; socks5|http_connect|unknown
    pub armed_profile: Option<String>, pub arm_profile: Option<String>,   // ids
    pub controls: ControlsView,         // exclusive_bind, peer_check, private_audit_store, hardening required|best_effort|unknown
    pub counters: CountersView,         // admitted, denied, denied_suppressed, refused (sum of refused_* and malformed), connect_failed, active_flows, bytes_up, bytes_down; each clamped to 2^53-1
    pub audit: AuditView,               // state ok|unavailable|unknown, entries
    pub last_error_code: Option<String>, pub last_denial: Option<DenialView>,   // {host, port, reason_code, rule_id}
}
// FlowRowView { flow_id, outcome, destination, destination_form: plain|hashed, route, matched_rule, reason_code, bytes_up, bytes_down, started_ms }
```

Projection rules in `ssk-desktop-client` (module with `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::arithmetic_side_effects))]`; Ran: the existing crate already passes these lints under the pinned 1.95.0 except one bounded `as u32` at `lib.rs:137`, which the V3 code replaces with `u32::try_from`; the scratch crate itself was linted with clippy 1.97):

```rust
pub fn id_text(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
    && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')) }
pub fn code_text(s: &str) -> bool { !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') }
pub fn destination_text(s: &str) -> bool { !s.is_empty() && s.len() <= 262
    && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-' | b'[' | b']')) }
pub fn alias_text(s: &str) -> bool { let n = s.chars().count(); (1..=64).contains(&n) && s.trim() == s
    && !s.chars().any(|c| c.is_control() || matches!(c, '<' | '>' | '&' | '"' | '\'' | '`')
        || matches!(c as u32, 0x061C | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2064 | 0x2066..=0x2069 | 0xFEFF)) }
/// Armed if and only if coverage is proxy_clients_only; anything unknown disagrees.
pub fn consistent(state: IngressStateView, coverage: CoverageView) -> bool { match (state, coverage) {
    (IngressStateView::Unknown, _) | (_, CoverageView::Unknown) => false,
    (IngressStateView::Armed, CoverageView::ProxyClientsOnly) => true,
    (IngressStateView::Armed, _) | (_, CoverageView::ProxyClientsOnly) => false,
    _ => true } }
```

`project_ingress(&IngressStatusDto) -> Result<IngressViewDto, ProjectionError>`: (1) `system_wide == true` rejects the whole snapshot (this product never produces it, so a daemon that says so is not believed); (2) unknown state, coverage, protocol, hardening or audit strings map to the `Unknown` variants (never to a default that reads well); (3) `listen` and `configured_listen` must parse as `SocketAddrV4` with an IPv4 loopback address and a non-zero port, otherwise the field becomes `None` and `consistent` is `false`; (4) ids and codes must match their shapes or the whole snapshot is rejected (`InvalidResponse`); (5) every counter goes through `n.min(MAX_JS_SAFE_INTEGER)`, the `refused` sum through `saturating_add`; (6) the daemon's `notice`, `retry_hint` and error messages are never copied (the GUI owns its sentences). `project_flows(rows)`: more than 50 rows sets `truncated` and keeps the first 50 (the request asks for 51); **one row violating a shape makes the whole flows section `invalid`** and leaves the rest of the snapshot intact. `project_observations`: the first of `route_v4`, `route_v6` whose status is `observed` or `stale` and whose alias passes `alias_text` becomes `os_route_probe` (with the probe address it was measured for); a failing alias or an unknown family yields `None`. Mutations that were each caught (Ran): system-wide accepted, armed with coverage none read as consistent, counters not clamped, `<` allowed in destinations, non-loopback listen accepted, one bad row tolerated, refusal mapping changed, arm sending a profile the daemon did not name, flows asked of an old daemon, no write floor, a hung request classified as `unavailable`, disarm pre-reading.

The daemon block keeps V2's rules (`version` at most 256 bytes without control characters, adapters at most 256) and uses `id_text` for `active_profile` and `code_text` for `last_error_code`, so the Rust host and the webview reject the same strings.

### 25.10 UI sections and wording

The V3 page is: **Lokaler Proxy** (new, first), **Beobachtungen des Betriebssystems**, **Letzte Verbindungen des Proxys**, **Hintergrunddienst**. The three legacy cards (Kill-Switch, Audit, Verbindungen) get ids `ks`, `au`, `co` and are hidden for the desktop source: with V3 they would only show "Keine Daten" and a standing "Schutzstatus unbekannt" next to an armed proxy. They stay for the labelled preview scenarios.

The daemon card is relabelled because `DaemonState` describes only the optional held activation session (`ssk-ipc/src/state.rs`): badge "Aktivierungssitzung: <Zustand>", intro "Der Zustand betrifft nur die optionale Aktivierungssitzung (ssk activate) und ist unabhängig vom lokalen Proxy.", and `protected` reads "offen (Angabe des Dienstes)" instead of "Geschützt (Angabe des Dienstes)", which beside an armed proxy would read as coverage. A row "Kill-Switch-Regel (Meldung des Dienstes)" shows "als aktiv gemeldet", "als nicht aktiv gemeldet" or "unbekannt" from `kill_switch_report`; the GUI never offers to change it.

| ingress.state (consistent) | Headline (fixed German) | Tone | Actions |
|---|---|---|---|
| no V3 snapshot (stale, degraded, connecting) | "Proxy-Status unbekannt: keine aktuelle Beobachtung." | neutral | disarm only in stale or degraded |
| `ingress` is `null`, or compat `daemon_too_old` | "Dienst veraltet: Proxy-Status nicht verfügbar." | notice | none |
| not consistent | "Widersprüchliche Angaben des Dienstes: nicht als erfasst behandelt." | alarm | none |
| disabled | "Lokaler Proxy: in der Konfiguration ausgeschaltet." + "Die Oberfläche ändert die Konfiguration nicht. Änderungen wirken erst nach einem Neustart des Dienstes." | neutral | none |
| starting | "Lokaler Proxy startet." | neutral | none |
| unavailable | "Lokaler Proxy nicht verfügbar." + "Fehlercode <CODE>: <fester Satz oder 'siehe Dokumentation'>" | notice | none |
| disarmed | "Proxy bereit, nicht aktiviert: Verbindungen werden abgewiesen." | neutral | arm |
| armed | "Proxy aktiv für Anwendungen, die ihn verwenden (Profil <id>)." + the coverage sentence | neutral | disarm |
| tripped | "Proxy angehalten." + Fehlercode + "Beim erneuten Aktivieren prüft der Dienst zuerst das Auditprotokoll." | alarm | arm ("Erneut aktivieren …") |
| stopping | "Lokaler Proxy wird beendet." | neutral | none |

No state is ever green (`ok` tone is never produced). Rows: Abdeckung, Adresse, Protokoll ("SOCKS5 (ohne Anmeldung)"), Exklusives Binden, Prüfung des lokalen Benutzers, Privates Auditprotokoll, Härtung, Weitergeleitet, Abgelehnt (Richtlinie), Weitere abgewiesene Verbindungen, Fehlgeschlagen, Aktive Verbindungen, Übertragen, Auditprotokoll des Proxys, Letzte Ablehnung. With `peer_check == false` in `armed` or `disarmed`, a notice line "Eingeschränkte Härtung: Andere lokale Benutzer könnten den Proxy nutzen." and tone notice (the Windows `best_effort` case). A static, collapsible "Grenzen" list: "Eine Anwendung kann bei einer Ablehnung selbst direkt verbinden; das verhindert dieser Proxy nicht.", "Namen, die eine Anwendung selbst auflöst, sind nicht erfasst.", "UDP und QUIC sind nicht erfasst.", "Dieser Proxy bindet keine Schnittstelle und keine Quelladresse; das Betriebssystem entscheidet.", and "Die Angaben stammen von dem Prozess, der den Dienstendpunkt bereitstellt; dessen Identität wird bis C-IPC2 nicht geprüft." Hashed destinations render as "# <16 Hex> (gehasht)", never as a host. Flows table columns: Kennung, Ergebnis, Ziel, Route, Regel, Grund, Bytes; Anwendung is not a column because every flow is `local-proxy:unattributed`.

**Forbidden words.** The scan uses the single list of 10.7 (the German list of this theme was merged into it; it now also applies to the daemon's strings). Scope: every string literal of `ingress-presentation.js`, `components/ingress.js`, `actions.js`, `poller.js` and `components/daemon.js` (the scan asserts it looked at more than 150 literals and at exactly those five files; the first version of the scan was vacuous because it read the wrong regex group, which a mutation exposed), the text of the `#ingress`, `#observations` and `#flows` sections of `index.html`, every output of the view-model functions over all state x coverage x phase combinations and all fixtures, the German error sentences, and, in Rust, the serialised `IngressViewDto` over all state x coverage combinations. ("Alle anderen Verbindungen sind nicht erfasst" does not contain `alle verbindungen`; the test proves it.) The legacy kill-switch card is outside the scope; it speaks of "Schutzstatus" only in the negative.

### 25.11 Polling versus push

There is no push (25.1). Consequences, stated so that nobody expects otherwise: a trip, a disarm by the CLI, or a daemon restart becomes visible at the next poll; while the window is hidden or minimised nothing is noticed until it is visible again; there is no tray icon, toast or sound in M2.

* `createPoller` (`src/poller.js`, Ran): 2000 ms between the end of one read and the start of the next, never overlapping; no timer while `document.visibilityState` is not `visible`; becoming visible reads at once; a failing read never stops the polling. WebView2's reporting of `hidden` on minimise is UNVERIFIED; if it reports `visible` the only cost is a request every 2 s.
* Cost: one connection and two frames per poll, at most 0.5 per second. The daemon keeps `GetStatus` free of ledger reads (section 9) and `ListRecentFlows` free of the `Inner` lock (11.3).
* **Background refresh** (`controller.refresh({ background: true })`, Ran): the observation stays on screen while the next one is read (no "Wird aktualisiert" frame, no blanking, so a selected address survives), the existing 10 s freshness limit keeps running and a hung background read does not postpone it, and any failure still removes the observation ("Daten nicht verfügbar"). A manual refresh keeps today's behaviour. Without this the 2 s poll would blank every card every 2 s.
* **Minimal-diff rendering**: `text()`, `rows()`, `list()` and `pairs()` in `components/dom.js` write only what changed; a repeated identical observation performs zero DOM writes (Ran, with a fake DOM that counts writes and is built from the ids that `index.html` really contains).
* Timings: host read 2 s + 0.75 s, below the webview's 3 s limit (`controller.js`, unchanged); write 2 s pre-read of an arm + 12 s request (the daemon's own audit waits are 2 s + 5 s; the 12 s and the 750 ms floor are untuned guesses, UNVERIFIED against the measured time of `recover()` on 256 MiB of ledger). A client timeout does not cancel the daemon's work, hence `outcome_unknown`.

### 25.12 Coexistence facts shown as observations

The VPN application is not mentioned by the GUI. What the GUI may show is the operating system's own answer, labelled as such:

* Card "Beobachtungen des Betriebssystems": "Schnittstelle für die Prüfadresse (laut Betriebssystem, Stichprobe)" = the raw alias text (validated, shown by `textContent`, never classified, so an interface named like a VPN adapter is not called a VPN), "Prüfadresse" (192.0.2.1 or 2001:db8::1, a documentation address), "Adressfamilie", "Beobachtet" ("vor N s", from the producer's `sampled_age_ms`, never from a GUI clock), and when two consecutive fresh snapshots differ: "Geändert seit der vorigen Beobachtung: vorher <A>, jetzt <B>." Fixed notice: "Beobachtung des Betriebssystems für die Prüfadresse. Sie sagt nichts über andere Zieladressen, nichts über andere Anwendungen und nichts darüber, wer die Route festlegt." Absent: "Keine Beobachtung verfügbar." The producer is `IngressStatusDto.observations` (6.12, 10.5).
* Fixed fact about the code, shown in the proxy card: "Dieser Proxy bindet keine Schnittstelle und keine Quelladresse; das Betriebssystem entscheidet." (`direct.rs` binds no interface or source address. Draft 2 said "Direkte Verbindungen dieses Proxys folgen der Routingtabelle des Betriebssystems", which 13.2.3 contradicts: a per-application driver acts below the routing table.)
* The kill-switch report row (25.10): Kaleidoscorp's own firewall rule blocks all outbound traffic of all programs, which includes the VPN application and the proxy's own dials; this is the one fact a user needs to explain "nothing connects". It is a labelled daemon report, not an OS observation.
* The GUI takes **no action** on an observation. Pausing the proxy when the probe-route interface changes would make Kaleidoscorp treat one interface as "the VPN"; that is not done (13.2.2; open question B14).

### 25.13 Default listen port and discovery

* **Discovery.** The GUI reads `ingress.listen` (the address the daemon actually bound) and `ingress.configured_listen` from the status; it never reads configuration, environment or the registry and never connects to the proxy. After a bind failure the card shows "Adresse: nicht belegt" and "Konfigurierte Adresse: 127.0.0.1:<port>" with the code text "die Adresse konnte nicht belegt werden (Port bereits in Benutzung?)". The address is plain selectable text; there is no clipboard plugin (a clipboard permission would be a second capability for no security benefit).
* **Default.** 10800 on 127.0.0.1 (5.1, MD-1), so that `enabled: true` alone gives a stable address that applications can be configured with once. `port: 0` stays valid for tests and is reported correctly because the GUI reads the bound port. Criteria: above 1023; below 32768 (the Linux ephemeral range starts there) and below 49152 (the Windows dynamic range); not 1080 (the port the repository's own upstream examples use), not 3128, 5173 (this repository's UI dev server), 7890/7891 (Clash), 8080, 8118, 8888, 9050/9150 (Tor), 10808/10809 (v2rayN). **Not checked against the IANA registry or against this or any Windows machine's excluded port ranges (`netsh int ipv4 show excludedportrange protocol=tcp`)**; a collision is reported honestly by the daemon (`INGRESS_BIND_FAILED`, never retried on another port) and the owner can change the value in one line of configuration. Open question B1.

### 25.14 What cannot be verified without Windows

The whole Tauri host (compile, ACL matrix, command ordering); that the compiled CSP is what 25.5 assumes and that Tauri accepts the two new directives; WebView2 behaviour (`visibilityState` on minimise, focus, text selection surviving a poll, DevTools in debug builds); the real click-to-pipe path; the pipe label's effect on low-integrity clients; named-pipe behaviour of the 12 s write deadline; everything about reading the OS route lookup; Windows `hardening: required` (the ingress stays `unavailable` until `C-WIN1`..`C-WIN3` are verified, owner decision 1; the GUI then shows `INGRESS_HARDENING_UNAVAILABLE` and the arm button is correctly absent, and the only way to run earlier is a manual `hardening: best_effort` configuration, which the GUI labels with the notice of 25.10). Linux CI covers everything else (22 marks each commit).

## 26. Verification status

Everything below was run in this Linux sandbox (kernel 6.18, rustc and clippy 1.95.0 unless stated, tokio 1.53.1, debug builds unless stated) against HEAD `b62c4c8`, from scratch crates outside the repository; no file of the repository was changed (except this document) and no network was touched beyond loopback, a Unix socket and the sandbox's proxy for the echo-endpoint probe. The sandbox toolchain is the one `rust-toolchain.toml` pins (1.95.0), except where a GUI scratch crate says clippy 1.97.

### 26.1 Test baselines at HEAD `b62c4c8` (Linux, `cargo test -p <crate> -- --list`)

| crate | unit | integration | total |
|---|---|---|---|
| `ssk-daemon` | **89** (lib; `main.rs` 0) | **26**: `activation_safety` 11, `dependency_closure` 2, `desktop_read` 1, `event_backpressure` 1, `kill_switch_status` 6, `killed_task_transitions` 2, `peer_authentication` 1, `round_trip` 2 | **115** |
| `ssk-config` | 11 | 4 (`routing_migration`) | 15 |
| `ssk-ipc` | 30 (one ignored: different-user needs a second OS user) | 0 on Linux (`named_pipe_transport.rs` is `cfg(windows)`) | 30 |
| `ssk-desktop-client` | 4 (the pipe tests are `cfg(windows)`) | | 4 |
| `ssk-cli` | 79 (`ssk`) + 23 (`ssk-vpn-acceptance`) | `activate_real_egress` 2, `ipc_status_snapshot` 1, `ux_snapshots` 14, `vpn_acceptance_cli` 4 | 123 |

The "84 unit + 23 integration" of draft 1 is stale (the critic's 86 + 24 was a grep count that predates `C-S2` and `C-S3`); use `-- --list` (it counts after `cfg` and macro expansion) and say "Linux". Windows counts differ. Expected after this series: `ssk-config` 15 -> 20 (`C-C0`) -> about 38 (`C-C1`); `ssk-ipc` 30 -> 36 (`C-IPC1`); `ssk-daemon` 89 -> 91 (`C-IPC1`); planned, not run.

### 26.2 Evidence gathered

| Claim | Method | Result |
|---|---|---|
| A dropped `ActivateProfile` future leaves the daemon in `Activating` | spawn an activation against a silent SOCKS proxy, `abort()` the task, read `GetStatus` and the ledger | `state = Activating`, no profile, ledger = one `DispatchPending` and nothing else |
| Only `GetStatus` is answered around a dial | silent dial with a 4 s deadline; six handlers sent at once | `GetStatus` 101 ms; `ListProfiles`, `RunDoctor`, `VerifyAuditChain`, `GetAuditEntries`, `TraceRoute`, `Deactivate` all completed at 4.04 s |
| IPC permits are exhausted by requests queued behind the dial | real `serve_unix`, 1 activation + 15 queued `ListProfiles` = 16 connections, then a 17th client asks `GetStatus` | not served within 2 s; served in 0.6 ms once the dial ended |
| IPC server descriptor cost | `/proc/<pid>/fd` of a real `sskd` | idle 12; 16 clients 28; 40 clients 29 |
| Shutdown cost today | SIGTERM to a real idle `sskd`, and with 16 IPC clients held | 3-5 ms |
| Linux bind semantics | Python on loopback | a second bind to a live listener fails `EADDRINUSE` with and without `SO_REUSEADDR`; rebind next to `TIME_WAIT` sockets succeeds only with `SO_REUSEADDR`, which mio sets on Unix listeners (`mio-1.2.2/src/net/tcp/listener.rs:82`) |
| The deny lint set compiles cleanly against `tokio::select!`, `#[tokio::test]` and serde derive | `cargo clippy --all-targets` on a scratch crate with the full set of 12.12 | exit 0 with `cfg_attr(not(test), deny(..))` (and with "deny, then `cfg_attr(test, allow(..))`"); `now + d` and `a + b` outside tests are errors; without any test exemption the denies fail on `.expect()` in the module's own tests |
| `broadcast::Sender` is `Clone` and `send(&self)`; tokio `Mutex` is FIFO | `state.rs:12, 43`; `tokio-1.53.1/src/sync/mutex.rs:20` | the event bus can be shared without `Inner`; arrival order is preserved |
| `Runtime` drop waits for blocking work indefinitely; `shutdown_timeout` leaks what does not stop | `tokio-1.53.1/src/runtime/runtime.rs:32-50` | hence "hold the lock until exit" (8.5) |
| Audit: cost of the activation ledger | the real `AuditLedger::persisted`, release build, ext4 | 0.96 / 9.45 / 51.6 ms per append at 101 / 1,001 / 5,001 entries; status read 0.08 / 1.04 / 7.5 ms |
| Audit: ledger records and speed | scratch programs (serde 1.0.229, serde_json 1.0.151, blake3 1.8.5) | flatten round trip exact (including `u64::MAX`, `BTreeMap`); no 0x0A in any compact body; verification 92 MiB/s (250,000 records, 66.1 MiB, 0.72 s); average line 277 bytes; fsync probe on ext4/virtio: `append + sync_data` p50 0.13 ms, p99 0.32 ms, directory fsync p50 0.03 ms, rotation p50 0.32 ms |
| Audit: keyed token | blake3 1.8.5 | the golden vectors of 6.4.10; unkeyed dictionary rate 11.6 M guesses/s/core |
| Audit: Unix store API | scratch crate, rustix 0.38.44 | `openat`, `mkdirat`, `fstat`, `fsync`, `unlinkat`, `Dir::read_from`, `OFlags::NOFOLLOW`, `process::geteuid` compile; a symlink opened with `NOFOLLOW\|DIRECTORY` fails with `ENOTDIR`; `ErrorKind::StorageFull` available |
| Targets: canonical forms and aliases | scratch probes against `valid_host`, `RoutingConfig::validate`, `MatchCriteria`, `Ipv6Addr::to_ipv4`, glibc `getaddrinfo` | the facts of 6.2 (aliases dialled as addresses, `::1` vs `[::1]` mismatch, `to_ipv4()` of `::1` is 0.0.0.1, `localhost.` fails while `localhost` resolves) |
| Targets: Linux peer rows | Python as root, uids set per process | client row `01` then `05` after half-close with a non-zero inode; `08` only on the server-side row; orphan: state `05`, inode 0; the uid column is the creator's effective uid; reading a 12,029-row `/proc/net/tcp` costs 15.1-16.8 ms; a netlink `SOCK_DIAG` exact lookup 30-400 microseconds (Python only) |
| Config v5 prototype | scratch copy, `ssk-config` | 32 tests green; clippy `-D warnings` and `rustfmt --check` clean; downstream `cargo check --all-targets` clean (`ssk-daemon`, `ssk-cli`, `ssk-ipc`, `ssk-desktop-client`); `ssk-daemon` 89 and `ssk-desktop-client` 4 unit tests green against it |
| Config mutations, both caught | `arm_on_start` as `Option<String>`; the old hard-coded v3 arm with `CURRENT = 5` | `toml::to_string` fails with `unsupported unit type` (3 of 4 migration tests panic at `routing_migration.rs:10`); ``Document("missing field `ingress`")`` |
| Config measured at HEAD | `ssk config lint`, YAML/TOML probes | the README "minimum valid configuration" is rejected (exit 10); nested extra key `system.nmae` accepted; top-level typo mislabelled `json serialization error`; v5 document on a v4 build: ``config version `5` is unsupported; expected `4` ``; schema vs serialised default keys differ only at `policy.gate_profile.{thresholds,required_evidence}`; a non-matching `cargo test` filter exits 0 |
| IPC wire | real `ssk_ipc` types, `ciborium` 0.2 | the five behaviours of 11.1; 12 protocol-0 request fixtures plus a status fixture; exhaustive clamp; `ssk-ipc` 35 tests green |
| CI guard | depth-1 PR-style checkout; throw-away repositories | reproduces the silent pass of the current guard; the new guard's 15 self-test cases pass; its dry run on `main..HEAD` fails as predicted |
| fd budget | rustc-only prototype of the lifecycle formula | 5 table tests (with the lifecycle constants; the merged constants of 7.3 are arithmetic, not run) |
| Coexistence: path observer | scratch crate, 1.95.0 | Linux `path.rs`: 4 tests, `clippy -D warnings` clean (test data include the real `/proc/net/route` lines of the machine plus a split-default table); Windows `best_route`: `clippy -D warnings` clean for `x86_64-pc-windows-gnu` against `windows-sys 0.59.0`, compile level only, never executed |
| Coexistence: no-binding tests | scratch crate against a copy of `connect_tcp` (tokio 1.53.1, socket2 0.6.5) | `direct_dial_leaves_device_and_source_to_the_os` and `the_device_check_has_teeth` passed; the static test simulated by script: zero needle hits outside `dns.rs`, direct dependencies of `ssk-netcore` equal to the allow-list, `resolve_via(` only at its definition |
| Sandbox observations | Python, curl 8.5.0, sandbox proxy | an unbound client reaches 127.0.0.5 from 127.0.0.1 and has no `SO_BINDTODEVICE`; curl sends the name with `--socks5-hostname` (ATYP 3) and the resolved address with `--socks5` (ATYP 1), exit 97 on reply `02`; five public echo endpoints answered a bare address over HTTPS through the proxy |
| GUI | scratch crate and scratch copy of `ui/desktop` | 20 Rust tests (V3 types, projection, client orchestration under paused time, a Unix-socket round trip with the real framing), 52 Node tests, about 50 mutations all caught (25.9); the existing `ssk-desktop-client` and `ssk-ui-contract` pass the lint set |
| Existing counts | grep and `--list` | 26.1 |
| Critic round 1: state-root mode | a scratch program calling `std::fs::create_dir_all` under three umasks | 0755 under umask 022, **0775 under umask 002**, 0700 under 077; `mode & 0o022 == 0` fails for 0775 (6.4.9) |
| Critic round 1: test names cited as existing | grep of `crates/` | five names that draft 2 called existing did not exist and were corrected: `accept_retry_backoff_table_and_gives_up_after_60`, `dial_deadline_bounds_a_silent_proxy_handshake`, `http_connect_brackets_ipv6_authority_and_refuses_control_chars`, `direct_dial_accepts_ipv6_literal`, `dependency_closure_is_the_set_adr_0008_recorded` and `denied_core_stays_out` (23.2, 23.3, 23.5) |

### 26.3 Not verifiable here (UNVERIFIED)

* **Every Windows behaviour** (15.12): `SO_EXCLUSIVEADDRUSE` with `TIME_WAIT` and the bind schedule; named-pipe accept recovery; the OS shutdown budgets for `CTRL_CLOSE_EVENT`, logoff, shutdown and preshutdown against the 0.8 s plan; whether handle limits ever bind; `Instant` across suspend; antivirus interplay with prune and `FILE_SHARE_DELETE`; owner-SID and ACL behaviour of files in `%LOCALAPPDATA%`; `FlushFileBuffers` on a directory handle; `GetBestRoute2` sending no packet; the Windows resolver behaviour for `sskd`; dual-stack clients in the IPv4 owner table; loopback traffic under the outbound kill-switch rule.
* **Everything about third-party tunnel products**, NordVPN included: split-tunnelling semantics, application-scoped kill switches, IPv6 handling, DNS settings, adapter naming, resolver-side blocking. Nothing was contacted or installed.
* **The Tauri host** (`apps/desktop`): compile, the ACL matrix and probe command, how Tauri 2.11.6 delivers and rewrites the CSP (including `frame-ancestors` and the two new directives), WebView2 behaviour (`visibilityState` on minimise, DevTools in debug builds, the real click-to-pipe path), the pipe label's effect on low-integrity clients. Everything inside `apps/desktop/src/main.rs` was only `rustfmt`-parsed.
* **The PowerShell script and its test** were not executed or parsed (no PowerShell here) and depend on CLI shapes that do not exist yet; `Find-NetRoute`, `Get-NetIPAddress`, `Get-DnsClientServerAddress` behaviour and `curl.exe` on the owner's build are unverified. The network-namespace test was not run (`unshare -rn` works, `ip` is not installed). Public echo endpoints: only five answered from the IPv4-only sandbox; their IPv6 behaviour and the DNS-leak sites named in 24.2.3 were not checked.
* **GitHub Actions**: checkout depth, the default shell flags, `github.event.*` fields, squash-merge body formatting for the trailer, branch protection, `ubuntu-latest` having `::1`; only the git half of the silent pass was reproduced.
* **Numbers**: fsync latency on real developer hardware and on Windows with Defender (the 2 s / 5 s waits, the 30 s stall detector, the 1.2 s audit-close budget are estimates); the time to verify 256 MiB of retained ledger (`recover_verify_deadline` 60 s, `doctor_verify_deadline` 10 s, `audit_read_verify_deadline` 30 s); the "sub-millisecond" gate-observation latency of 8.3 (an idle runtime only); descriptor numbers on a release build, on CI runners and on macOS; every default of 5.1 as a fit for real browsing (judgment, pinned by tests); the sufficiency of 16 lookups, 5 s, 8 candidates, 250 ms and 64 extra attempts; the write deadline, floor and poll interval of the GUI.
* **Code**: none of the schematic code in this document was compiled as part of the workspace: the detached control task with an owned guard, `ActivationScope` with a `Deref`/`DerefMut` wrapper in the long `ActivateProfile` arm (borrow-check), the `select!` with a `sleep_until` arm, `send_if_modified` closures capturing a result variable, the `ControlLedger`/`HostControl` `BoxFuture` traits, the `DIAL_EXTRA_PERMITS` pool (new in this merge), the merged `SetIngressRequest`, the merged fd budget of 7.3, and the additions of critic round 1 (`LedgerSlot`, the pre-admission eviction, the resolver wait, `TcpConnector`, `DialFailed`, `PendingInput`, the `expect_*` fields, the disarm slot of the GUI client). The regression tests named in the plan are not yet written in the repository. Whether `runtime.shutdown_timeout` behaves as documented when a `spawn_blocking` `getaddrinfo` is stuck is documented in `tokio-1.53.1/src/runtime/runtime.rs:32-50` and was not exercised.
* **Linux details not observed**: `/proc/net/tcp6` for `AF_INET6` clients connecting to 127.0.0.1 and the mapped-form text (this machine has no IPv6); seq_file row skips or duplicates under churn; whether the uid column equals the creator's fsuid in cases other than the ruid/euid combinations tried; the netlink `SOCK_DIAG` lookup in Rust. The IANA special-purpose prefixes and the RFC 8305 values were obtained through a summarising fetch, not read verbatim; RFC 7686 for `.onion` is recalled.
* **Browsers**: which clients send names to a SOCKS5 proxy by default.
* **Provenance** of draft 1 (judge totals, reader probes, the three source designs) is not in the repository and nothing here depends on it.

## 27. Decisions recorded by the synthesis

1. The ingress is a second front end of the ADR 0008 path (`FlowRecord -> evaluate -> plan/admit -> AdmissionToken -> DataPlane::connect_route -> transport_mut`). It never calls `RouteExecutor::connect/probe`, never builds a `RouteKind`, never opens a socket except the accepted client socket; a source-scan test enforces it. No new workspace crate, no new workspace edge: `dependency_closure.rs` and ADR 0008 stay as they are and `ssk-runtime` stays out.
2. The ingress is independent of the held probe session, of `ssk activate --dest`, and of `DaemonState`. `Protected` keeps meaning "one held egress session"; arming, flows, denials and trips never set `Protected`/`Active`/`Degraded`/`FailClosed`; `dns_protected` and `kill_switch` are never derived from the ingress. A failed probe activation does not stop the proxy.
3. Primary scenario (owner): the third-party VPN application stays the system-wide tunnel; Kaleidoscorp is the layer above; its Direct egress follows the OS routing table; it needs no VPN credentials, starts and configures no VPN; the OpenVPN orchestration is not part of it; the ingress is described only as "applications that use the proxy"; observed facts are labelled observations; nothing claims a third-party VPN is up (2.2, 2.3, 10.6).
4. Fail-closed lifecycle: `enabled=false` by default; an enabled listener starts disarmed; arming is an explicit audited operator action (`SetIngress`, or the opt-in `arm_on_start`, default false) with the durable `Armed` record written before the gate opens; `Deactivate` disarms first, and a disarm is applied as soon as the request is served (never swallowed, never rate limited).
5. One lifecycle variable, one write primitive: the `Gate { epoch, mode }` in a `watch` cell, compare-and-set for arm/recover/start and unconditional trip/disarm/close, one FIFO control lock never nested with `Inner`, detached control tasks, a synchronous never-blocking `trip` (3.2, 6.9). No status field comes from a cache (10.3).
6. Latches are recoverable without a daemon restart: audit write failure, a 30 s fsync stall, panic budget (3), fatal accept errors or listener death trip the gate; an explicit re-arm re-verifies the ledger, resets counters, rebinds if needed, and only then arms. Corrupt chain, unsafe store, missing key, descriptor limit, configuration and hardening are `unavailable` with a RUNBOOK procedure.
7. Ordering is enforced by types and compensated by RAII: `dial()` takes `&PendingReceipt`; `write_success()` and `pump()` take `&ResultReceipt`; receipts have private constructors and write their own compensating record when dropped unresolved (6.4.4). A timeout is not a fault.
8. Peer authorization runs before the first byte is read and before any shared budget is charged: a separate cheap `PeerBudget` (bucket 256/1024 per s, 64 pre-admission slots that also cover the handshake, the oldest silent socket evicted after 1 s) gates a single-thread batched `PeerTableService`; only verified peers whose handshake completed consume the accept bucket and permits. `Unknown` means refuse. Linux uses `/proc/net/tcp` and `tcp6` (client-side row, states 01/04/05, non-zero inode, exactly one row, `getuid`). `hardening: required` is the default and makes a platform without exclusive bind, peer check and private audit store unavailable.
9. Windows hardening (exclusive bind, owner-PID to SID resolver, private ledger store) is `C-WIN1`..`C-WIN3` in the series; until verified on a real machine Windows is unavailable under `required` (owner decision 1). `C-WIN0`, a spine baseline that makes no hardening claim, lets `best_effort` run on Windows before that. Tests choose hardening per OS through one helper; one Windows test runs the default config.
10. Own audit ledger directory (segments of JSONL, blake3 chain over stored bytes, single writer thread, group commit, replies only after fsync, torn-tail recovery, fd-based tamper check), private by construction (0700, 0600, dirfd-relative, `O_NOFOLLOW`, owner and link-count checks, refuse never repair). `audit.json` is not rewritten, converted or written by the ingress; the reason is the measured O(n) cost, not a test count. Rotation, retention, a refusal quota and a non-fatal prune are in the spine; defaults 8 x 32 MiB, at most 1 GiB.
11. Denials: the first occurrence per `(profile, host, port, reason, rule)` per 60 s window is durable before the refusal reply while the segment's refusal quota has room; repeats, over-bucket and over-quota denials are counted and summarised; the volume of a denial-only flood can neither rotate nor prune. Pre-handshake garbage, malformed targets and peer refusals are counted only. Denials stay plaintext.
12. Destination logging is `plain | hashed` (default plain) in config v5; hashed means a keyed BLAKE3 token under a per-installation key stored outside the ledger directory; the port stays in clear; the mode, key id and configuration fingerprint are recorded in the ledger; no surface shows more than the ledger (owner decision 3).
13. Name resolution (owner decision, reversing "Direct needs literals"): the daemon resolves a client-supplied name only for an admitted `Direct` flow, exactly once, through the OS resolver, after the durable `Pending` record; every address of the answer is guarded (any special-use address refuses the flow); families are filtered by `direct_address_families` (default `ipv4_only`); one pinned `SocketAddr` is dialled by an IPv4-first 250 ms-stagger race that never re-resolves; lookups are bounded (16 threads, 5 s, a 500 ms wait for a permit with at most 32 waiters, then `01`); an exact-IP deny rule of the armed profile also refuses a resolved address. Proxied routes forward names unresolved.
14. Target canonicalisation before policy: ASCII only, lower case, one trailing dot removed, brackets removed, IPv6 and v4-mapped IPv6 collapsed to one text, domain-typed IP literals become literals, final label must start with a letter (kills `2130706433`, `127.1`, `0x7f.1`), `localhost` refused, listener self-loop unconditional. A special-use LITERAL is reachable only if the matched rule's own destination equals it exactly and that rule names the port. Names are never exempt.
15. The Direct dial binds no interface and no source address (CO-1); the ingress has its own guarded executor built from the same adapter registry; the activation executor is unchanged.
16. `RouteKind::Fallback` is non-executable in the executor (done, `C-N1`) and refused by the ingress route guard together with OpenVPN, a terminal TLS hop, Direct with a name when the data plane does not guard names, and any route whose last hop is not Socks5/HttpConnect. Exactly one `connect_route` call site, no retry; an optional fail-fast cool-off refuses instead of retrying.
17. Deadlines: the executor has a whole-dial deadline (done); the activation connect has the daemon-owned 20 s deadline (done); the ingress executor's deadline is `resolve + connect + 5 s`; a silent proxy can no longer hang the supervisor mutex or a flow (12.9).
18. `GetStatus` never waits behind a dial (done) and every other reader either answers without `Inner` or says `DAEMON_BUSY`; at most two mutators can wait; a cancelled or panicking activation settles; session shutdown is bounded (12.2-12.6).
19. IPC is additive plus new variants for new capabilities: `StatusDto.protocol` and `.ingress` (capability marker), additive DTO fields, `SetIngress { armed, profile_id?, client? }`, `GetIngressAudit`, `ListRecentFlows`/`InspectFlow` become real with `FLOW_NOT_RETAINED`; no `deny_unknown_fields`; clients check the protocol first and refuse with `DAEMON_TOO_OLD` (11).
20. Status honesty is structural: a separate ingress block with closed state words, machine-readable coverage in `{none, proxy_clients_only}`, constant `system_wide=false`, computed `armed`, its own `last_error`, unknown values render "unknown, not covered", one forbidden-word list (English and German) over every string the ingress produces, observations labelled and never deciding, the never-claim list (10).
21. Config v5: required `ingress` section (default disabled) with `deny_unknown_fields` on every struct, `Ipv4Addr` listen (default 127.0.0.1:10800), closed enums, limit floors of 100 ms and ceilings (0 never means unlimited), `arm_on_start` as a bool, `direct_address_families`, `audit.destination_logging`, a migration chain with one step per version, schema evolution rules that make a new vocabulary value compatible, a golden schema, digests (5).
22. Scope control: SOCKS5 NO_AUTH only in M2; HTTP CONNECT is M2.1; the CLI is `ssk ingress status|arm|disarm|flows|inspect|audit`; commits are classed SPINE / RELEASE / OPT with Windows-only hardening commits last and the Windows baseline `C-WIN0` in the spine (22). Direct-by-name is spine.
23. The GUI can arm and disarm through two zero-argument native commands behind a dedicated minimal capability scoped to the bundled `main` window; it never chooses a profile; the daemon authorises with the verified peer, records it, rate-limits and is idempotent; a strict ACL test with a probe command replaces the old negative test; V3 and the 2 s visible-only poll; the GUI work is the desktop gate of RELEASE (25).
24. The firewall kill switch is not a component of the scenario: the CLI refuses `engage` while the local proxy is bound unless `--allow-with-ingress`; no daemon, ingress or GUI path engages or releases it (13.2.4).
25. Robustness fixes the ingress depends on are separate small commits: the IPC accept wiring tests (`C-I1b`), crash records capped (`C-X1`), the shutdown plan with `hold_until_exit` and a real drain (`C-L3`), the fd budget (`C-L4`), keepalive (`C-H1`), idle eviction (`C-E5`). The resume-skew heuristic is not adopted.
26. Deny-lints (unwrap, expect, indexing, panic, todo, unimplemented, unreachable, arithmetic, casts) on the whole ingress tree via `cfg_attr(not(test), deny(..))`, enforced by the existing `clippy -D warnings` gate; proptest on the parser and the canonicaliser; modules and items are `pub` so each intermediate commit is dead-code clean; shared leaf types land first.
27. CI: the contract guard fails closed, runs on push and pull request, covers the real contract surfaces and has a self-test (21); the schema is pinned by a golden file.
28. Merge decisions of draft 2 are MD-1 to MD-26 in 19.2, the decisions of critic round 1 are MD-27 to MD-42 in 19.3; the open owner questions are in Appendix B.

---

## Appendix A: disposition of the original review findings

The previous draft's completeness critic returned **needs-revision** with 47 findings (21 gaps, 8 contradictions, 7 security holes, 11 claims nobody could verify). This table has one row per original finding. Status vocabulary: **resolved** = the revised text specifies the fix and the commit plan implements it (nothing is built; see 26 for what was run); **accepted-limitation** = a deliberate, stated and bounded residual; **rejected-with-evidence** = the premise of the finding is false (no finding needed this); **still-open** = not settled, needs later evidence. Findings that were handled by a specific theme are mapped to the status the merged document gives them.

| ID | Finding (short) | Status | Where it is handled | Evidence |
|---|---|---|---|---|
| G1 | arm, disarm, trip and recover are not serialised; a late arm can overwrite a disarm or a trip; two concurrent `SetIngress` | resolved | 3.2 L1-L6; 6.1.2 transitions; 6.9.1-6.9.2; 11.4 (I1); tests of 23.6 (control plane, and since critic round 1 also through `Supervisor::handle`, Appendix E finding E-1) | `shutdown.rs:105-118` (`send_if_modified` precedent); `tokio-1.53.1/src/sync/mutex.rs:20` (FIFO); the reproduction of 12.3 shows the same lock hazards |
| G2 | no story for how `IngressShared` emits events; the bus is behind `Inner`; IPC never pushes | resolved | 6.9.3 (cloned `broadcast::Sender`); 10.4 "No pushes"; 11.3 | `state.rs:12, 43, 48`; `supervisor.rs:1000-1005`; `server.rs:312-313`; grep: `Response::Event` constructed nowhere |
| G3 | `StatusHint` underspecified; a cached status would claim armed after a trip | resolved (superseded by the code) | 10.3 (one builder, ingress block last, both branches); 10.8 | `supervisor.rs:261-273, 572-589`: the landed code has no cache; `activating_status` is built from facts only; test `status_overlay_is_fresh_during_activation` |
| G4 | only `GetStatus` has the 100 ms timeout; other handlers queue behind a dial for up to 20 s | resolved | 12.2-12.5; 11.6; `C-L2` | reproduced: `GetStatus` 101 ms, six others 4.04 s; 17th client not served within 2 s, 0.6 ms after the dial (26.2) |
| G5 | `RunDoctor` `ingress:audit` re-verifies up to 256 MiB under the `Inner` mutex; rotation mid-read | resolved | 12.7; L10; 6.4.8 `verify_dir(Reader)`; MD-24 | `supervisor.rs:959-998`; verification 92 MiB/s measured |
| G6 | ledger directory fsync, modes/ACL, `O_NOFOLLOW`, Windows prune sharing violation tripping at rotation | resolved (Unix); the Windows half is UNVERIFIED (U2) | 6.4.8 D1-D6; 6.4.9; 15.6; rules 19; `C-A5`, `C-WIN0` (baseline), `C-WIN3` | `ssk-tensor/src/lib.rs:401-414` (no directory fsync); `main.rs:67`; `lock.rs:313-324`; `tempfile-3.27.0/src/file/imp/unix.rs:23`; rustix API compiled; `lock.rs:68-72, 277-292` and `vpn_profiles.rs:262-293` precedents |
| G7 | timeouts and cancellation: orphan `Pending`; does `Timeout` trip; `close(self)` vs `Arc` | resolved | 6.4.4 (RAII receipts); 6.4.6 (job state machine, no trip, 30 s detector); 6.4.7 (`close(&self)`); 6.1.3; 7.1 flow guard; MD-7 | design 6.4/7.2 of draft 1 (job still queued after timeout); `admission.rs:25-34` |
| G8 | no config fingerprint in records; size retention lets denials evict admitted evidence | resolved | 6.4.8 fingerprint, refusal quota and the honest retention figure (MD-36); 5.9; MD-8 | `main.rs:244-247`; `supervisor.rs:285-329`; `ssk-types` `digest_of`; measured 277-byte average line |
| G9 | shutdown budget and ordering unspecified and inconsistent; aborted flows cannot write `Closed`; `ServicePreshutdown` | resolved (Windows budgets UNVERIFIED) | 8.5 (`ShutdownPlan`, `hold_until_exit`); 6.4.4 compensation; 12.8 | `main.rs:39, 164, 322`; `shutdown.rs:61-70`; `tokio-1.53.1/src/runtime/runtime.rs:32-50`; measured exit 3-5 ms |
| G10 | sustained fd pressure ends the daemon or trips the ingress; no tie to `RLIMIT_NOFILE`; no reserved IPC fd; no pause at capacity | resolved (the 60-error IPC exit is kept as a deliberate last resort; the Windows pipe loop is an accepted limitation, C.3) | 7.3 (descriptor budget by construction); 8.6; L11, L14; `C-L4`, `C-I1b` | `server.rs:90, 153-187, 256-292`; descriptors measured 12 / 28 / 29 |
| G11 | Windows restart failure (`SO_EXCLUSIVEADDRUSE` vs `TIME_WAIT`); bind only retried on a manual re-arm; arm during `starting` undefined | resolved (Windows delay UNVERIFIED) | 6.9.4 (per-platform retry, phases, `INGRESS_STARTING`); 15.4 (the plain `C-WIN0` bind and the exclusive `C-WIN1` bind); 11.4; MD-15 | `mio-1.2.2/src/net/tcp/listener.rs:63-83`; sandbox rebind next to `TIME_WAIT` |
| G12 | default limits unusable for a browsing desktop and not configurable; no fairness; no measurement | resolved (numbers are judgment) | 5.1 (configurable, new defaults); 5.10 (fairness: rate, pre-admission slots, capacity wait, idle eviction); 6.1.4; 7.1, 7.3 | the numbers are pinned by named tests, not measured against any browser (26.3) |
| G13 | Linux peer authorizer: no `tcp6`, non-atomic reads, no retry, CPU per check | resolved (dual-stack mapped form not observed) | 6.6 (both tables, one row, one retry, batching service, self-test); rule 13 | probes: client rows `01`/`05`, inode 0 for orphans; 16 ms per 12k rows; no IPv6 on the review machine |
| G14 | IPC compatibility: `GetAuditEntries.ledger` ignored by old daemons; `ssk --json status` contract; `http_connect` variant | resolved | 11.2 R1-R7; 11.8 (`GetIngressAudit`); 11.9; 11.11; 5.5 | 11.1: measured decode behaviour; `ssk-cli/src/main.rs:3924-3939` |
| G15 | `IngressConfig::validate` always runs; a typo makes the daemon `ConfigInvalid` and blocks activation | accepted-limitation | 5.3 "Blast radius" | the existing contract for every section; `supervisor.rs` re-validates; `ssk config lint` catches the edit |
| G16 | commit-plan defects: `C-S1` before `C-C1`; `W1/W2` naming; deny-lints in tests; `include!` dead code | resolved | 22 (IDs, order, rules); 12.12; MD-11, MD-19, MD-23 | clippy 1.95.0 run: `cfg_attr(not(test), deny(..))` fixes the test failure; `routing_config.rs` carries `#[allow(dead_code)]` |
| G17 | latency budget: two durable writes before the first byte | resolved (Windows UNVERIFIED) | 6.4.6 latency budget; 7.2 | measured fsync p50 0.13 ms, p99 0.32 ms (ext4/virtio VM) |
| G18 | never states how config edits take effect for a running ingress | resolved | 5.9; 8.7 | `main.rs:246`; no reload verb in `Request` |
| G19 | flaky-test sources (ports, fd test, `/proc` under load, wall clock, negatives, unix-only tests, stale `sskd`) | resolved | 5.7; 23 (header and 23.6, 23.8); 11.9 item 3; 15.11 | `activation_safety.rs:71-78`; `ipc_status_snapshot.rs` doc comment; `RESTART_ASSESSMENT_2026-09-21.md` |
| G20 | special-use exemption needs only an exact destination, no port | resolved | rule 9; 6.2 `guard_special_use`; 6.7.1 `rule_binding` | `tests/support/routing_config.rs` (destination `127.0.0.1`, port `None`) |
| G21 | IPv6 special-use table incomplete | resolved (implementer re-checks the registry) | 6.2 table | IANA registries via a summarising fetch (26.3) |
| C1 | `Event::Warning` vs `IngressShared` independent of the `Inner`-owned bus; IPC clients never receive events | resolved | 6.9.3; 10.4 | as G2 |
| C2 | `TraceRoute` and the live path "cannot diverge" | resolved (claim withdrawn) | 11.7; 6.7.1 | `supervisor.rs:873-892`; `dto.rs:74-80`; `routing.rs:75-80`; `ssk-config` `routing.rs:67-81`; `admission.rs:53-65` |
| C3 | `geteuid` (6.6) vs `getuid` (IPC check) | resolved | 6.6; 6.4.9 item 4; MD-14 | `ssk-ipc/src/auth.rs:74`; rustix `process/id.rs:54, 68`; probes of the uid column |
| C4 | "nothing can end `run_server`" vs the 60-error give-up | resolved (claim replaced) | 8.6; L14 | `server.rs:153-187`; `main.rs:333-343` |
| C5 | test baseline "84 unit + 23 integration" not reproducible | resolved | 17.1; 26.1 | `cargo test -- --list`: 89 + 26 |
| C6 | `main.rs` "builds routing once" vs `Supervisor::new` building its own | resolved | 12.1; 12.8; `C-S1` | `main.rs:258-262`; `supervisor.rs:302-307` |
| C7 | `Deactivate` disarms before `KILL_SWITCH_ARMED`, leaving a partial effect on an error | resolved | 11.5; test `deactivate_in_fail_closed_disarms_and_says_so` | `supervisor.rs:817-831, 847-852` |
| C8 | HTTP CONNECT enum variant "no bump if shipped before v5 is released" contradicts the schedule | resolved | 5.5; 20 | `git tag` is empty; the rule no longer depends on a release date |
| S1 | overflow panics on the hostile-input surface; arithmetic lints missing; 3 panics trip the proxy | resolved | 12.12; L12; 6.4.5 | `Cargo.toml:130, 144`; lint run on 1.95.0 (`arithmetic_side_effects` fires on an unchecked add) |
| S2 | arm vs disarm/trip race can revert to armed; the accept path checks only the gate | resolved | as G1; 6.9.4 step 7 (components convert liveness loss into a gate transition) | as G1 |
| S3 | stale status can claim coverage that no longer exists | resolved | 10.3; 10.8 | as G3 |
| S4 | ledger exposure: no mode/ACL, no no-follow or ownership checks | resolved (Unix; Windows UNVERIFIED) | 6.4.9; rules 19; threats 19-20 | as G6 |
| S5 | CPU amplification by other local accounts via `/proc/net/tcp` | resolved | 6.6 cost bound; rule 13; threat 17 | 16 ms per 12k-row read, duty cycle at most one third of a core |
| S6 | a portless exact-destination rule opens all ports | resolved | rule 9; 6.2 | as G20 |
| S7 | Windows default is `unavailable` under `hardening: required` until the Windows commits; the default path is never exercised on Windows | accepted-limitation | owner decision 1 (C.1); 15.2, 15.3, 15.11 (`best_effort` runs from `C-WIN0`, critic round 1); threat table | `mio-1.2.2/src/net/tcp/listener.rs:63-83`; `ci.yml:257` |
| U1 | provenance claims (judge totals, reader probes, source designs) not in the repository | accepted-limitation | 0; 26.3 | nothing in this document depends on them |
| U2 | every Windows behaviour | accepted-limitation | 15.12; 26.3; each mechanism has a conservative default (`Unknown` refuses, fail closed) | repository precedents cited where they exist (`lock.rs`, `vpn_profiles.rs`, `vpn_endpoint.rs`) |
| U3 | Linux specifics: second bind, half-closed inode, uid column, dual-stack | resolved except the `tcp6` mapped form (UNVERIFIED) | 6.6; 6.9.4; 26.2 | sandbox measurements and `mio-1.2.2/src/net/tcp/listener.rs:82` |
| U4 | `copy_bidirectional` half-close propagation through each adapter kind; cancel gives EOF on both sides | still-open | 6.8; tests `half_close_propagates_both_ways` and `gate_change_cancels_immediately` per adapter kind | not run; TLS success paths cannot be tested on Linux |
| U5 | fsync cost and the 5 s deadline; group commit; flood thresholds | accepted-limitation | 6.4.6 (waits 2 s + 5 s, no trip, stall detector, doctor probe) | measured on one Linux VM; Windows with Defender UNVERIFIED |
| U6 | the lint set compiles against `select!`, `#[tokio::test]`, serde derive; proptest 256 cases vs CI `PROPTEST_CASES=32` | resolved | 12.12; 6.2 proptest note | clippy 1.95.0 run (26.2); `ProptestConfig::default()` so the CI environment governs; the run time of the proptests was not measured |
| U7 | serde `flatten` with an internally tagged enum round-trips | resolved | 6.4.2 | scratch run: exact round trip, no 0x0A in bodies |
| U8 | IPv6 literal tests self-skip so `C-N2` may ship unexercised | resolved | 13.2.5; 21.2 (`SSK_REQUIRE_IPV6`); 24.2.3 steps 2, 3, 10 | the review machine has no IPv6; whether the runner has `::1` is UNVERIFIED |
| U9 | terminal `TlsTunnel` refusal rests on reading `executor.rs:apply_hop` only | resolved | 6.7.1 | `executor.rs:286-295`; `routing.rs:40-46` (empty metadata, SNI is `next_host`); the guard is tested by feeding it directly |
| U10 | nothing was compiled or run; ownership of `close(self)`, `on_trip`, `OnceLock<Arc<dyn HostControl>>` unchecked | accepted-limitation | header; 26.3 | `close(&self)`, `on_trip` and the trait ownership are specified; the schematic code stays uncompiled; scratch prototypes are listed |
| U11 | README/docs line references of section 17 (some unchecked) | still-open (one residual) | 17.2 | re-checked by grep at `b62c4c8`: `README.md`, `RUNBOOK.md`, `ROUTING_AND_OPENVPN_STATUS.md`, ADR 0008, `DESKTOP_CLIENT_ARCHITECTURE.md:589-593`, `P4_INGRESS_DESIGN.md:229`, `SECURITY.md:14` exist; whether `SECURITY.md:14` is inaccurate (the `ssk-winhost` exemption is `Cargo.toml:147`-adjacent) and the K.1/K.2 wording were not re-verified |

No finding was rejected: the critic was right on every point that could be checked, including the ones the themes reproduced against the code (G3 is the one place where the premise needed a correction, because the landed code has no cached hint, but the requirement survives).

## Appendix B: open questions for the product owner

Only questions that are still open are listed; the answered ones are in [C.1](#c1-decisions-2026-10-06). Each has a recommendation; none blocks the Linux acceptance of M2 except B1 (the port must be fixed before the first tag).

* **B1 Default listen port.** The design uses `127.0.0.1:10800` (5.1, MD-1). The config proposal was 1080 (the conventional SOCKS port; it collides with the repository's own upstream examples and with the static self-loop check), the GUI proposal 10800. Neither was checked against the IANA registry or a Windows excluded-port range. A default is part of the contract: changing it later silently re-ports every file that omits `listen.port`. A port already in use makes the bind fail with `INGRESS_BIND_FAILED` (never another port). Recommendation: 10800; decide before the first tag.
* **B2 Idle-timeout default.** 1 h (5.1, MD-3) so that idle SSH and database sessions survive; a dead tunnel after a route change holds a permit until the timeout, mitigated by keepalive (`C-H1`) and idle eviction (`C-E5`). The lifecycle theme recommended 10 min plus keepalive. Recommendation: keep 1 h; choose a shorter value only if you do not use long-lived idle connections through the proxy.
* **B3 `ssk deactivate` also disarms the local proxy.** It "stops everything this daemon does for applications". In the third-party-tunnel scenario the legacy probe session is likely unused, so a user typing `ssk deactivate` for the old session would stop the proxy their applications rely on. Recommendation: keep it (disarming only narrows, and a stop command that leaves a forwarding proxy running is the worse surprise); the CLI and GUI text say "The local proxy was disarmed"; the GUI offers Disarm as its own button that never touches the legacy session.
* **B4 Retention length.** Retention is by size only (8 x 32 MiB, roughly 300,000 admitted flows, days to weeks depending on traffic, shown in status); there is no age-based deletion because an untrusted clock must not be able to erase evidence. Do you want an additional age ceiling (for example delete plain destination records older than N days)? It would be a config key and therefore belongs in v5 if wanted. Recommendation: no age ceiling in M2; purge by moving the ledger directory aside (RUNBOOK). The real window is about 1.8 hours at the sustained admission cap (6.4.8; see B18).
* **B5 Hashed mode and the live views.** The design shows tokens instead of host names in the in-memory flow list, IPC and the GUI while `hashed` is configured, so that nothing shows more than the ledger (MD-5). The cost: the GUI cannot display names live in that mode. The config proposal was to show names live and persist only the setting. Recommendation: the design as written (relaxing it later loses nothing).
* **B6 Hashed semantics.** Is "host replaced by a keyed token (key in the state root, outside the ledger directory; port, rule id and route in clear; denials plain)" what you want to be able to say? Anyone holding both the ledger and the key can test guesses; the ledger alone reveals nothing. Recommendation: yes. The alternative (an unkeyed hash) is rejected as not private.
* **B7 LAN, CGNAT and local names through Direct.** Do you need to reach private/LAN addresses, Meshnet-style or other 100.64/10 or 198.18/15 addresses, single-label or `.local` names THROUGH the proxy with Direct? In this design a Direct name that resolves into those ranges is refused outright, single-label/`.local`/`.onion` names are refused for Direct, and a private IP literal works only with an exact host-and-port rule. Recommendation: accept that for M2 (it is the fail-closed choice; browsers can bypass the proxy for such names); if you need it, add CIDR-plus-port-list rule criteria in a later config version instead of loosening the guard.
* **B8 Remote DNS in the client.** Domain rules only work for clients that send NAMES to the proxy (SOCKS5 with remote name resolution); a client that resolves locally sends an address and is denied unless an IP-literal or catch-all rule matches. Do you accept documenting "configure remote DNS in the client" as the required client setting for M2 (with the denial hint "the client sent an address, not a name"), rather than building a capture lane with fake-IP mapping now? Recommendation: accept and document.
* **B9 `best_effort` on your own Windows laptop.** May the manual acceptance run use `hardening: best_effort` (no peer check, non-exclusive port, non-private ledger store; three warnings), because `required` is unavailable until `C-WIN1`..`C-WIN3` are verified? Decision 1 did not say "single-user Windows only", so this is asked, not assumed. Recommendation: yes, on a machine with one interactive account and no remote sessions, `arm_on_start` false (15.3); never as a shipped default. Critic round 1 added what this question needs in order to mean anything: `best_effort` runs on Windows only from `C-WIN0`, a spine baseline commit (std-only ledger store, plain bind, three controls false) that is itself unverified on real Windows until your run; without it the ingress would be unavailable on your laptop even under `best_effort`.
* **B10 `direct_address_families` default.** `ipv4_only` (5.1): a dual-stack name dialled over IPv6 may bypass a tunnel that does not cover IPv6, or stall on a silently dropped IPv6 address. Price: IPv6-only sites are unreachable through Direct until you set `any`. Adding the key later needs another config version, so decide now. Recommendation: `ipv4_only`.
* **B11 Confirmation for arming.** The GUI uses an inline two-step (the first click shows profile, address and limits, the second confirms) and no confirmation for disarm unless active connections would be cut. It protects against accidental clicks only, not against injected script. Recommendation: acceptable.
* **B12 Disarm when the status is unknown.** The GUI keeps the disarm button available (labelled "Status unbekannt") when the daemon cannot be read; arming is never offered on stale data. Recommendation: acceptable.
* **B13 GUI shows the firewall kill-switch rule.** A read-only, labelled report of the daemon (engaged, not engaged, unknown); the rule blocks all outbound traffic including the VPN application and the proxy's own dials and is the main reason "nothing connects"; the GUI never offers to change it. Recommendation: yes.
* **B14 Automatic reaction to a route change.** The GUI only displays the observation; pausing or disarming on a change of the probe-route interface would make Kaleidoscorp treat one interface as "the VPN", which the product wording forbids. Recommendation: no automatic reaction in M2.
* **B15 DevTools in debug builds.** Debug builds of the host keep Tauri's DevTools; release builds have none and a test forbids enabling them. Recommendation: acceptable (the README's `cargo build` is a development binary).
* **B16 Configuration discovery.** Today `sskd` reads only `SSK_CONFIG_PATH` (no default file). For a desktop product, may it read `<state_dir>/config.yaml|yml|toml` when the variable is unset (two files present means `ConfigInvalid`)? Recommendation: yes, as a RELEASE commit after the acceptance gate; not part of M2 acceptance.
* **B18 Retention floor: evidence or availability.** The default ledger window is about 1.8 hours at the sustained admission cap (50 flows/s) and days to weeks of browsing (6.4.8). A process that is allowed to use the proxy, or a runaway loop, can push older evidence out by volume. Option 1 (this draft): prune oldest first, state the figures, warn with `AUDIT_WINDOW_SHORT`. Option 2: a minimum retention age N: when the oldest segment is younger than N hours the proxy refuses new flows (`Capacity`, no trip) instead of pruning it, so a loop becomes a visible outage rather than silent evidence loss. Option 2 lets the same loop stop the proxy, and a same-user process can already rewrite the whole chain (16), so it protects against runaway software and, on Windows `best_effort`, other accounts, not against a determined same-user attacker. Recommendation: Option 1 in M2; revisit when real window figures are known. If N should be configurable it is a config key and therefore belongs in v5 (decide before the first tag); as an internal constant it can be added later without a version.
* **B17 Arm at logon.** Should the desktop client arm the proxy automatically at logon (`arm_on_start`, default false)? In the third-party-tunnel scenario it arms whether or not the tunnel is up (2.5). Recommendation: keep it false by default; an explicit opt-in per machine.

## Appendix C: decisions of the product owner and execution log

### C.1 Decisions (2026-10-06)

Answers to the questions of draft 1's Appendix B and the owner's follow-ups. They bind the revision of this design.

1. **Windows timing.** Milestone 2 counts as done when it is accepted on Linux. On Windows the ingress stays unavailable under `hardening: required` until the Windows-only commits (`C-WIN1` exclusive bind, `C-WIN2` owner check, and the ledger-store control `C-WIN3` that the revision added to the same set) have been verified on a real Windows machine. This was NOT answered as "single-user Windows only"; do not assume a second local user is acceptable (question B9 asks about the interim `best_effort`).
2. **Protocols.** SOCKS5 first. HTTP CONNECT (M2.1) follows as its own, fully specified step. No system proxy-settings writer in M2.
3. **Audit privacy.** Destination logging is configurable, default plaintext: a config option for plain or hashed destinations of admitted flows (denials stay plaintext). It is part of the first ingress config version (v5) so no later version bump is needed.
4. **Arming.** The GUI must be able to arm and disarm the ingress. This needs a dedicated, minimal write command with a minimal Tauri capability, authorisation at the daemon, and a replacement for the negative test that `activate_profile` is denied. It is a gate for any release called a desktop client. Specified in section 25.
5. **Primary scenario.** The owner has no infrastructure of their own and uses the commercial NordVPN desktop application on the same laptop. That application stays the system-wide tunnel. Kaleidoscorp is the Proxifier-like layer above it: applications connect to the loopback SOCKS5 ingress, Kaleidoscorp applies policy and audit, and its Direct egress follows the operating system's routing table, through the VPN's virtual adapter while the VPN application is connected. Kaleidoscorp must not need the VPN's credentials, must not start or configure the VPN, and the OpenVPN orchestration in the repository (`ssk-vpnctl`, the broker, profiles) is not part of this scenario. The ingress is described only as "applications that use the proxy", never as Protected or system-wide; Kaleidoscorp never claims that a third-party VPN is up or protecting anything and at most observes and labels facts (2.2).
6. **Direct-by-name is part of M2** (consequence of 5, because browsers send host names): the earlier rule "Direct is refused for host names in M2" is reversed; resolve once, filter, dial the pinned address, never re-resolve, with the rebinding and special-use guards (6.10).

Adopted without a question (the safe defaults; say so in the ADR): the ingress is described only as "applications that use the proxy", never as `Protected` or system-wide; HTTP CONNECT, an OS proxy-settings writer, UDP and an IPv6 listener are out of M2; the default listen port is 10800 pending B1; `arm_on_start` defaults to false; `direct_address_families` defaults to `ipv4_only` pending B10.

### C.2 Foundation commits (done, pushed)

Each has a regression test that was seen to FAIL on the old code and was independently reproduced by a reviewer.

| ID | Commit | Result |
|---|---|---|
| C-N1 | `ed143be` | `RouteKind::Fallback` is not executable; the executor returns `NoRoute` and dials nothing. |
| C-N2 | `95b9d1b` | The whole dial has a 30 s deadline; IPv6 authorities are bracketed in HTTP CONNECT; whitespace and control characters in the host are refused before any byte is written (`NETCORE_INVALID_TARGET`). |
| C-P1 | `0982387`, `7857618` | A suffix rule never matches an IP literal or a numeric IPv4 alias; the planner never emits `Fallback`. |
| C-I1 | `051bfb6` | The Unix accept loop retries with backoff (50 ms to 1 s, give up on the 60th consecutive error). |
| C-S2 | `f5a1683` | The activation dial is bounded to 20 s, expiry is a durable `FailClosed` with `ACTIVATION_CONNECT_TIMEOUT`. |
| C-S3 | `f29784d` | `GetStatus` answers `Activating` while an activation dial holds the lock; the adapter health string no longer claims liveness. |
| docs | `610bce9` | The `Fallback` doc comments in `ssk-netadmin` no longer describe a fallback that does not exist. |
| docs | `caaadb7` | the owner's decisions and the foundation work recorded in the design |
| test | `b62c4c8` | the resolver-pool test no longer depends on OS refusal speed |

### C.3 Known gaps left by the foundation work (each is closed or accepted in this design)

| Gap | Status | Where |
|---|---|---|
| **Windows named-pipe accept loop (`C-I1w`) is NOT fixed.** A first attempt was reverted after review: it left a window with no live pipe instance, had no test and cannot be executed here. On Windows `sskd` still exits on the first accept error. | accepted-limitation | 8.6, 15.10; spec kept for `C-I1w` (Windows CI only); `privileged.rs` has the same shape and is outside the ingress |
| The Unix loop wiring (continue on error, return the last error after the give-up) has no regression test; after 60 consecutive errors (about 55 s) `sskd` still exits, so sustained fd exhaustion still ends the daemon. | resolved (tests) / accepted-limitation (the exit) | `C-I1b`; 7.3 prevents the ingress from causing it; 8.6 |
| The IPv6 literal Direct dial was never exercised: this machine has no IPv6; only CI can tell. | resolved | `SSK_REQUIRE_IPV6` (13.2.5, 21.2); 24.2.3 steps 2, 3, 10 |
| **Hard requirement for the ingress:** a `dest_host` rule `::1` does not match `[::1]`, and `ssk-config` still accepts numeric-looking `domain_suffix` values; target canonicalisation must happen BEFORE the policy sees the host. | resolved | 6.2, rule 11, `C-T1`, `C-G1` |
| The daemon activation deadline (20 s) is shorter than the executor's 30 s dial deadline, so `NETCORE_TIMEOUT` can no longer be produced by an activation and a slow-but-alive multi-hop dial is cut at 20 s; `NETCORE_*` codes have no `explain_code` entry. | resolved (cut at 20 s accepted) | 12.9; 11.14 |
| If the `ActivateProfile` future is dropped mid-dial, `Inner.state` stays `Activating`; every other handler still queues behind the dial for up to 20 s. | resolved | 12.3-12.5; `C-L0`, `C-L2` |
| A blocking `getaddrinfo` already running on tokio's blocking pool cannot be cancelled by the dial deadline. | accepted-limitation | 6.10 (16 permits released by the lookup thread), 7.3, 8.5 rule 2 |
| `Inner.active_egress` and the `KillSwitchProvider::view` contract still carry comments that no longer match the code. | resolved | 12.1, 10.3 (`C-S1`) |
| When the ingress exists, the `Activating` answer must overlay a FRESH ingress snapshot (never a cached one). | resolved | 10.3, 10.8, 11.10 |

### C.4 Execution log of draft 2

* 2026-10-06: the owner's four decisions and the new primary scenario (C.1 items 1 to 6) were given; six theme agents revised the design in parallel against HEAD `b62c4c8` and produced prototypes and measurements outside the repository; a single writer merged them into this document, decided the conflicts (19.2), rebuilt the commit plan and test plan, replaced Appendix A by the disposition table and Appendix B by the open questions. Nothing was committed. An independent critic round on this text was the next step; it ran (next entry).
* 2026-10-06, critic round 1: two critics (an adversarial security critic and an implementer's critic) returned 4 high and 18 medium findings against draft 2 at the same HEAD `b62c4c8`. A single writer re-checked each against the code and the text (Appendix E), fixed all of them in this document in place, narrowed or declined the parts that the code or the owner's decisions did not support (each with its reason), and left no high finding open. Two owner questions arose (B18 and the addition to B9). Nothing was committed and no file other than this one was touched.

## Appendix D: scripts specified by this design

None of these files exists in the repository yet; the text below is the specification. D.2 was run in a scratch repository (the 15-case self-test passed); D.3 and D.4 were **not** executed or parsed (no PowerShell available).

### D.1 Where each belongs

`scripts/ci/contract_guard.sh` and its surface table (21.2); `scripts/manual_vpn_coexistence_check.ps1` and `scripts/tests/manual-vpn-coexistence-check.tests.ps1` (24.2.4, 24.2.5).

### D.2 `scripts/ci/contract_guard.sh`

```bash
#!/usr/bin/env bash
# Fails when a contract surface changed between BASE and HEAD without either
#   (a) a change to docs/COMPATIBILITY_MATRIX.md in the same range, or
#   (b) a commit trailer  "Compat-Impact: none (<reason of at least 8 characters>)".
# Fails CLOSED: an unresolvable BASE/HEAD or a failing git command is an error,
# never a pass.  Usage: contract_guard.sh BASE HEAD
set -euo pipefail

surfaces="${CONTRACT_SURFACES_FILE:-scripts/ci/contract_surfaces.txt}"
matrix="docs/COMPATIBILITY_MATRIX.md"
base="${1:?usage: contract_guard.sh BASE HEAD}"
head="${2:?usage: contract_guard.sh BASE HEAD}"

fail() { echo "contract_guard: FAIL: $*" >&2; exit 1; }

case "$base" in
  *[!0]*) ;;                         # contains a non-zero digit: fine
  *) fail "BASE is the all-zero sha (new branch); the workflow must pass a merge base" ;;
esac
git cat-file -e "${base}^{commit}" 2>/dev/null \
  || fail "BASE ${base} is not in this checkout (the job needs fetch-depth: 0)"
git cat-file -e "${head}^{commit}" 2>/dev/null || fail "HEAD ${head} is not in this checkout"
[ -r "$surfaces" ] || fail "surface table ${surfaces} is missing"

mb="$(git merge-base "$base" "$head")" || fail "no merge base between ${base} and ${head}"
changed="$(git diff --name-only --no-renames "$mb" "$head")" || fail "git diff failed"

hits=""
while IFS=$'\t' read -r label re; do
  case "$label" in ''|'#'*) continue ;; esac
  [ -n "$re" ] || fail "surface table line for '${label}' has no regex"
  matched="$(printf '%s\n' "$changed" | grep -E -e "$re" || true)"
  [ -z "$matched" ] || hits="${hits}${label}:"$'\n'"$(printf '%s\n' "$matched" | sed 's/^/    /')"$'\n'
done < "$surfaces"

if [ -z "$hits" ]; then
  echo "contract_guard: no contract surface changed in ${mb}..${head}"
  exit 0
fi

if printf '%s\n' "$changed" | grep -qxF "$matrix"; then
  echo "contract_guard: contract surface changed and ${matrix} was updated in the same range"
  exit 0
fi
if git log --format=%B "${mb}..${head}" | grep -Eq '^Compat-Impact: none \(.{8,}\)$'; then
  echo "contract_guard: contract surface changed; a 'Compat-Impact: none (...)' trailer was given"
  exit 0
fi

{
  echo "contract_guard: FAIL: a contract surface changed but ${matrix} did not, and no"
  echo "'Compat-Impact: none (<reason>)' trailer is present in ${mb}..${head}."
  echo "Changed surface files:"
  printf '%s' "$hits"
  echo "Either record the change in ${matrix}, or add the trailer to a commit message"
  echo "when the edit provably changes neither a file format nor a wire shape."
} >&2
exit 1
```

### D.3 `scripts/manual_vpn_coexistence_check.ps1`

Windows PowerShell 5.1 and PowerShell 7 syntax only. NOT executed or parsed in this review (no PowerShell was available). It needs the CLI shapes listed in 24.2.4. It follows the dot-source guard of `scripts/openvpn-vm-host-probe.ps1`.

```powershell
<#
.SYNOPSIS
Operator-run check of the Kaleidoscorp loopback proxy ABOVE a third-party system-wide tunnel application.
.DESCRIPTION
Starts, stops and configures nothing on the tunnel side and never needs its credentials: you connect and
disconnect that application by hand when asked. It compares the public address that three paths show (the
system, the proxy by host name, the proxy by IP literal) and prints what the operating system and sskd report
as OBSERVATIONS. It never states that a tunnel is up or that anything is protected. It makes no firewall
change; its only state change in Kaleidoscorp is arming and then disarming the proxy. The report file
contains your public IP addresses: do not post it.
Needs: Windows 10/11, ssk.exe and sskd.exe built from the ingress commits with the coexistence example config
loaded by the running sskd, and curl.exe.
#>
[CmdletBinding()]
param(
    [ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')][string]$ProfileId = 'coexist',
    [string]$Ssk = 'ssk.exe',
    [string]$Curl = 'curl.exe',
    [string]$Echo4 = 'https://api.ipify.org',
    [string]$Echo64 = 'https://api64.ipify.org',
    [string]$Echo6 = 'https://api6.ipify.org',
    [string]$DeniedHost = 'blocked.example',
    [ValidateRange(5, 120)][int]$MaxTimeSec = 15,
    [switch]$IncludeTunnelDrop,
    [string]$ReportPath
)

$script:Results = [System.Collections.Generic.List[object]]::new()

function Add-Result {
    param([string]$Id, [ValidateSet('PASS', 'FAIL', 'INFO', 'SKIP')][string]$Status, [string]$Text)
    $script:Results.Add([ordered]@{ id = $Id; status = $Status; text = $Text })
    Write-Host ('[{0}] {1} {2}' -f $Status, $Id, $Text)
}

function Test-PublicIPv4 {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $m = [regex]::Match($Text.Trim(), '^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$')
    if (-not $m.Success) { return $false }
    $o = @(1..4 | ForEach-Object { [int]$m.Groups[$_].Value })
    if (@($o | Where-Object { $_ -gt 255 }).Count -gt 0) { return $false }
    if ($o[0] -eq 0 -or $o[0] -eq 10 -or $o[0] -eq 127 -or $o[0] -ge 224) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }
    return $true
}

function Test-IPv6Text {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Text.Trim(), [ref]$ip)) { return $false }
    return ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $File @Arguments 2>$null
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previous }
    [pscustomobject]@{ ExitCode = $code; Output = ((@($out) -join [Environment]::NewLine).Trim()) }
}

function Get-EchoResult {
    param([string]$Url, [string[]]$Extra = @())
    $viaProxy = ($Extra -contains '--socks5-hostname') -or ($Extra -contains '--socks5')
    $curlArgs = @('-s', '--max-time', [string]$MaxTimeSec)
    if (-not $viaProxy) { $curlArgs += @('--noproxy', '*') }
    $curlArgs += $Extra
    $curlArgs += $Url
    $r = Invoke-Native -File $Curl -Arguments $curlArgs
    $ip = $null
    if ((Test-PublicIPv4 $r.Output) -or (Test-IPv6Text $r.Output)) { $ip = $r.Output.Trim() }
    [pscustomobject]@{ ExitCode = $r.ExitCode; Text = $r.Output; Ip = $ip }
}

function Get-PathVerdict {
    param([string]$Ip, [string]$BaselineIp, [string]$ConnectedIp)
    if ([string]::IsNullOrEmpty($Ip)) { return 'no_answer' }
    if ($Ip -eq $BaselineIp) { return 'same_as_baseline_without_tunnel_application' }
    if ($Ip -eq $ConnectedIp) { return 'same_as_system_path_while_tunnel_application_connected' }
    return 'other'
}

function Get-SskJson {
    param([string[]]$Arguments)
    $r = Invoke-Native -File $Ssk -Arguments (@('--json') + $Arguments)
    if ([string]::IsNullOrWhiteSpace($r.Output)) { return $null }
    try { return ($r.Output | ConvertFrom-Json) } catch { return $null }
}

function Get-IngressStatus {
    $j = Get-SskJson -Arguments @('status')
    if ($null -eq $j -or $null -eq $j.state) { return $null }
    return $j.state.ingress
}

function Get-ProxyPort {
    param($Ingress)
    if ($null -eq $Ingress -or [string]::IsNullOrEmpty([string]$Ingress.listen)) { return 0 }
    $m = [regex]::Match([string]$Ingress.listen, '^127[.]0[.]0[.]1:([0-9]{1,5})$')
    if (-not $m.Success) { return 0 }
    return [int]$m.Groups[1].Value
}

function Invoke-DropRound {
    param([string]$Label, [string]$Proxy, [string]$BaselineIp, [string]$ConnectedIp)
    Read-Host ('{0}: set the tunnel application kill switch as the procedure says, then DISCONNECT it. Press Enter when it shows disconnected' -f $Label) | Out-Null
    Start-Sleep -Seconds 7
    $r = Get-EchoResult $Echo4 @('--socks5-hostname', $Proxy)
    Add-Result ($Label + '.new_flow') 'INFO' ('through the proxy while disconnected: {0} (curl exit {1})' -f (Get-PathVerdict $r.Ip $BaselineIp $ConnectedIp), $r.ExitCode)
    $s = Get-IngressStatus
    $codes = @($s.warnings | ForEach-Object { $_.code }) -join ','
    Add-Result ($Label + '.status') 'INFO' ('state={0} connect_failed={1} warnings=[{2}] route_v4 interface={3} previous={4}' -f $s.state, $s.counters.connect_failed, $codes, $s.observations.route_v4.interface_alias, $s.observations.route_v4.previous.interface_alias)
    Read-Host ('{0}: RECONNECT the tunnel application. Press Enter when it shows connected' -f $Label) | Out-Null
    Start-Sleep -Seconds 7
}

function Invoke-CoexistenceCheck {
    foreach ($tool in @($Ssk, $Curl)) {
        if ($null -eq (Get-Command $tool -ErrorAction SilentlyContinue)) { Add-Result 'S1.tools' 'FAIL' ('not found: ' + $tool); return }
    }
    $ing = Get-IngressStatus
    if ($null -eq $ing) { Add-Result 'S1.capability' 'FAIL' 'ssk status has no ingress block: ssk or sskd predates the local proxy, or sskd is not running'; return }
    $port = Get-ProxyPort $ing
    Add-Result 'S1.state' 'INFO' ('state={0} listen={1} hardening={2} peer_check={3} exclusive_bind={4} private_audit_store={5} warnings=[{6}]' -f $ing.state, $ing.listen, $ing.controls.hardening, $ing.controls.peer_check, $ing.controls.exclusive_bind, $ing.controls.private_audit_store, ((@($ing.warnings | ForEach-Object { $_.code })) -join ','))
    if ($port -eq 0) { Add-Result 'S1.listen' 'FAIL' 'no loopback listener is bound; fix the configuration or the bind error first'; return }
    $ks = Get-SskJson -Arguments @('winhost', 'killswitch', 'status')
    $verdict = $null
    if ($null -ne $ks -and $null -ne $ks.broker) { $verdict = [string]$ks.broker.verdict }
    if ($verdict -eq 'not_engaged') {
        Add-Result 'S1.firewall_kill_switch' 'PASS' 'the firewall kill switch is not engaged'
    } elseif ($null -eq $verdict) {
        Add-Result 'S1.firewall_kill_switch' 'INFO' 'no authoritative answer (the privileged service may not be installed)'
    } else {
        Add-Result 'S1.firewall_kill_switch' 'FAIL' ('verdict=' + $verdict + '; release it first with: ssk winhost killswitch release')
        return
    }

    Read-Host 'S2: DISCONNECT the tunnel application now. Press Enter when it shows disconnected' | Out-Null
    $base4 = Get-EchoResult $Echo4
    if ($null -eq $base4.Ip) { Add-Result 'S2.baseline' 'FAIL' ('no IPv4 answer from {0} (curl exit {1})' -f $Echo4, $base4.ExitCode); return }
    Add-Result 'S2.baseline' 'INFO' ('address without the tunnel application: ' + $base4.Ip)
    $base6 = Get-EchoResult $Echo64 @('-6')
    Add-Result 'S2.baseline_v6' 'INFO' ('IPv6 address without the tunnel application: ' + $(if ($null -ne $base6.Ip) { $base6.Ip } else { 'none' }))

    Read-Host 'S3: CONNECT the tunnel application now. Press Enter when it shows connected' | Out-Null
    Start-Sleep -Seconds 5
    $conn4 = Get-EchoResult $Echo4
    if ($null -eq $conn4.Ip) { Add-Result 'S3.system_path' 'FAIL' ('no IPv4 answer (curl exit {0})' -f $conn4.ExitCode); return }
    if ($conn4.Ip -eq $base4.Ip) { Add-Result 'S3.premise' 'FAIL' 'the system path shows the same address as the baseline: nothing to compare. Check the tunnel application list for curl.exe'; return }
    Add-Result 'S3.premise' 'PASS' ('the system path address changed to ' + $conn4.Ip)
    $conn6 = Get-EchoResult $Echo64 @('-6')
    if ($null -ne $base6.Ip -and $null -ne $conn6.Ip -and $conn6.Ip -eq $base6.Ip) {
        Add-Result 'S3.system_ipv6' 'FAIL' ('the system IPv6 address is unchanged (' + $conn6.Ip + '): IPv6 goes around the tunnel. This concerns the tunnel application and the OS, not Kaleidoscorp')
    } else {
        Add-Result 'S3.system_ipv6' 'INFO' ('system IPv6 answer while connected: ' + $(if ($null -ne $conn6.Ip) { $conn6.Ip } else { 'none' }))
    }

    $arm = Invoke-Native -File $Ssk -Arguments @('ingress', 'arm', '--profile', $ProfileId)
    if ($arm.ExitCode -ne 0) { Add-Result 'S4.arm' 'FAIL' ('ssk ingress arm failed: ' + $arm.Output); return }
    try {
        Start-Sleep -Seconds 6
        $ing = Get-IngressStatus
        $ok = ($ing.state -eq 'armed') -and ($ing.coverage -eq 'proxy_clients_only') -and ($ing.system_wide -eq $false) -and ($ing.egress.binds_interface -eq $false)
        Add-Result 'S4.armed' $(if ($ok) { 'PASS' } else { 'FAIL' }) ('state={0} coverage={1} system_wide={2} binds_interface={3} families={4}' -f $ing.state, $ing.coverage, $ing.system_wide, $ing.egress.binds_interface, $ing.egress.direct_address_families)
        $obs = $ing.observations.route_v4
        Add-Result 'S5.observation' 'INFO' ('sskd observation: status={0} index={1} alias={2}; compare by hand with: Find-NetRoute -RemoteIPAddress 192.0.2.1' -f $obs.status, $obs.interface_index, $obs.interface_alias)

        $proxy = '127.0.0.1:' + $port
        $byName = Get-EchoResult $Echo4 @('--socks5-hostname', $proxy)
        switch (Get-PathVerdict $byName.Ip $base4.Ip $conn4.Ip) {
            'same_as_system_path_while_tunnel_application_connected' { Add-Result 'S6.by_name' 'PASS' ('proxy by name shows ' + $byName.Ip + ', equal to the system path') }
            'same_as_baseline_without_tunnel_application' { Add-Result 'S6.by_name' 'FAIL' 'the proxy path shows the baseline address: connections of sskd.exe do not follow the system path. Check the tunnel application list for sskd.exe (the process that dials), not for the browser' }
            'no_answer' { Add-Result 'S6.by_name' 'FAIL' ('no answer through the proxy (curl exit {0})' -f $byName.ExitCode) }
            default { Add-Result 'S6.by_name' 'INFO' ('a third address appeared: ' + $byName.Ip + '. Compare by hand; some tunnels use several exit addresses') }
        }
        $byAddr = Get-EchoResult $Echo4 @('--socks5', $proxy)
        $v = Get-PathVerdict $byAddr.Ip $base4.Ip $conn4.Ip
        Add-Result 'S7.by_address' $(if ($v -eq 'same_as_system_path_while_tunnel_application_connected') { 'PASS' } else { 'FAIL' }) ('proxy by address: {0} (curl exit {1})' -f $v, $byAddr.ExitCode)

        $echoHost = ([uri]$Echo4).Host
        $flows = Get-SskJson -Arguments @('ingress', 'flows', '--limit', '20')
        if ($null -eq $flows -or $null -eq $flows.flows) {
            Add-Result 'S8.flows' 'FAIL' 'ssk ingress flows returned no list'
        } else {
            $list = @($flows.flows)
            $named = @($list | Where-Object { ([string]$_.destination).StartsWith($echoHost + ':') -and $_.matched_rule -eq 'echo-ipify' -and $_.route -eq 'Direct' })
            $literal = @($list | Where-Object { ([string]$_.destination) -match '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+:' -and $_.matched_rule -eq 'allow-rest-443' })
            Add-Result 'S8.by_name_rule' $(if ($named.Count -gt 0) { 'PASS' } else { 'FAIL' }) 'a flow to the echo host by name matched rule echo-ipify with route Direct'
            Add-Result 'S8.by_address_rule' $(if ($literal.Count -gt 0) { 'PASS' } else { 'FAIL' }) 'a flow to an IP literal matched rule allow-rest-443 (a name rule never matches an address)'
            $local = @($list | Where-Object { -not [string]::IsNullOrEmpty([string]$_.egress_local) }) | Select-Object -First 1
            if ($null -ne $local) { Add-Result 'S8.source' 'INFO' ('local address the OS gave sskd for a Direct socket: {0}; compare with Get-NetIPAddress -AddressFamily IPv4' -f $local.egress_local) }
        }

        $den = Get-EchoResult ('https://' + $DeniedHost + '/') @('--socks5-hostname', $proxy)
        Add-Result 'S9.denied' $(if ($null -eq $den.Ip -and $den.ExitCode -ne 0) { 'PASS' } else { 'FAIL' }) ('request to {0} through the proxy ended with curl exit {1} (expected non-zero; 97 for a SOCKS5 refusal)' -f $DeniedHost, $den.ExitCode)
        $noRule = Get-EchoResult ('http://' + $echoHost + ':8080/') @('--socks5-hostname', $proxy)
        Add-Result 'S9.no_rule' $(if ($null -eq $noRule.Ip -and $noRule.ExitCode -ne 0) { 'PASS' } else { 'FAIL' }) 'port 8080 has no rule and is refused'

        $v6 = Get-EchoResult $Echo6 @('--socks5-hostname', $proxy)
        if ($ing.egress.direct_address_families -eq 'ipv4_only') {
            Add-Result 'S10.ipv6_through_proxy' $(if ($null -eq $v6.Ip) { 'PASS' } else { 'FAIL' }) ('with ipv4_only an IPv6-only echo host must not answer through the proxy; got ' + $(if ($null -ne $v6.Ip) { $v6.Ip } else { 'no answer' }))
        } else {
            Add-Result 'S10.ipv6_through_proxy' 'INFO' ('families=any; IPv6 answer through the proxy: ' + $(if ($null -ne $v6.Ip) { $v6.Ip } else { 'none' }) + '. Compare with the baseline printed by S2')
        }

        Add-Result 'S11.dns' 'INFO' 'DNS is checked by hand (step 11): Kaleidoscorp adds no resolver and does not know where queries go'

        if ($IncludeTunnelDrop) {
            Invoke-DropRound 'S12A' $proxy $base4.Ip $conn4.Ip
            Invoke-DropRound 'S12B' $proxy $base4.Ip $conn4.Ip
        }
    } finally {
        $off = Invoke-Native -File $Ssk -Arguments @('ingress', 'disarm')
        Add-Result 'S16.disarm' $(if ($off.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) 'ssk ingress disarm'
        $closed = Get-EchoResult $Echo4 @('--socks5-hostname', ('127.0.0.1:' + $port))
        Add-Result 'S16.refused_when_disarmed' $(if ($null -eq $closed.Ip) { 'PASS' } else { 'FAIL' }) ('through the proxy after disarm: curl exit {0}' -f $closed.ExitCode)
    }
}

function Write-Report {
    param([string]$Path)
    $report = [ordered]@{ schema = 1; collected_utc = [DateTime]::UtcNow.ToString('o'); results = @($script:Results.ToArray()) }
    ($report | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $Path -Encoding UTF8
}

if ($MyInvocation.InvocationName -ne '.') {
    if ($env:OS -ne 'Windows_NT') { throw 'This operator check requires Windows.' }
    Invoke-CoexistenceCheck
    if ($ReportPath) { Write-Report -Path $ReportPath }
    $failed = @($script:Results | Where-Object { $_.status -eq 'FAIL' }).Count
    $passed = @($script:Results | Where-Object { $_.status -eq 'PASS' }).Count
    Write-Host ('{0} PASS, {1} FAIL. PASS describes this machine, these settings and this moment only.' -f $passed, $failed)
    exit $(if ($failed -eq 0) { 0 } else { 1 })
}
```

### D.4 `scripts/tests/manual-vpn-coexistence-check.tests.ps1` and the CI step

```powershell
# Pure fixture checks. Dot-sourcing does not run the check, start a process or touch the network.
$ErrorActionPreference = 'Stop'
. (Join-Path (Join-Path $PSScriptRoot '..') 'manual_vpn_coexistence_check.ps1')
function Assert-Check([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
foreach ($ok in @('198.51.100.7', ' 203.0.113.9 ')) { Assert-Check (Test-PublicIPv4 $ok) ('public address refused: ' + $ok) }
foreach ($bad in @('', 'abc', '10.0.0.1', '256.1.1.1', '192.168.1.5', '100.64.0.1', '1.2.3.4 x')) { Assert-Check (-not (Test-PublicIPv4 $bad)) ('non-public text accepted: ' + $bad) }
Assert-Check (Test-IPv6Text '2001:db8::1') 'IPv6 text refused'
Assert-Check (-not (Test-IPv6Text '203.0.113.9')) 'IPv4 accepted as IPv6'
Assert-Check ((Get-PathVerdict '203.0.113.9' '198.51.100.7' '203.0.113.9') -eq 'same_as_system_path_while_tunnel_application_connected') 'verdict: connected path'
Assert-Check ((Get-PathVerdict '198.51.100.7' '198.51.100.7' '203.0.113.9') -eq 'same_as_baseline_without_tunnel_application') 'verdict: baseline path'
Assert-Check ((Get-PathVerdict $null '198.51.100.7' '203.0.113.9') -eq 'no_answer') 'verdict: none'
Assert-Check ((Get-PathVerdict '192.0.2.77' '198.51.100.7' '203.0.113.9') -eq 'other') 'verdict: other'
Assert-Check ((Get-ProxyPort ([pscustomobject]@{ listen = '127.0.0.1:10800' })) -eq 10800) 'port parse'
Assert-Check ((Get-ProxyPort ([pscustomobject]@{ listen = '0.0.0.0:10800' })) -eq 0) 'non-loopback listener refused'
Write-Output 'Coexistence script fixture checks passed; no process started, no network used.'
```

A step in the `build_test` job of `.github/workflows/ci.yml`, next to the existing fixture step "Check read-only VM host assessment with synthetic facts":

```yaml
      - name: Check the coexistence operator script's pure logic
        if: runner.os == 'Windows'
        shell: pwsh
        run: ./scripts/tests/manual-vpn-coexistence-check.tests.ps1
```


## Appendix E: disposition of critic round 1

Two critics attacked draft 2 (an adversarial security critic and an implementer's critic). Every finding below was re-checked against the code at HEAD `b62c4c8` and against this document before anything was changed. Status vocabulary as in Appendix A: **fixed** = the text now specifies the fix and the commit plan and test plan carry it; **narrowed** = fixed, but less than the critic proposed, with the reason; **residual** = a stated and bounded limitation instead of a fix; **duplicate** = the same defect as another row. Nothing is implemented and nothing was compiled; Windows behaviour stays UNVERIFIED.

| ID | Sev | Finding (short) | Verdict | What was checked | Where handled |
|---|---|---|---|---|---|
| E-1 | high | `SetIngress` check (5) treats "disarm of a disarmed ingress" as a no-op, but during an in-flight arm the gate still reads `Disarmed`; only `disarm` bumps the epoch, so the arm completes after the operator was told "disarmed" | **fixed** (real) | 11.4 check (5) against 6.1.2 transition 5, 6.9.2 arm step 5 (the gate is written only at the compare-and-set) and 11.4's own result table: the three statements contradict each other as claimed. No code exists to check (the ingress is not implemented). The control-plane tests exercised `IngressShared`, not `Supervisor::handle` | Rule 22 (3.1), 6.1.2, 6.9.2, 11.4 (disarm straight through; arm no-op only under a free `control`), MD-27; tests `set_ingress_disarm_during_an_arm_in_flight_supersedes_it` and four siblings (23.6) |
| E-2 | high | One headline row says "Proxy active ..." for armed and for disarmed with `peer_check` false; on Windows before `C-WIN2` that is the default start state | **fixed** (real) | 10.2 row text, 15.2 "Status says" column, GUI table 25.10 (already correct for disarmed) | 10.2 (two rows, headline as a pure function), 15.2, MD-28; test `headline_claims_activity_only_when_armed` over every state x controls combination |
| E-3 | high | No commit before the Windows-last commits gives Windows a ledger store or a bind, yet 6.4.9, 15.2, 15.11, B9 and 2.4 rely on `best_effort` working | **fixed** (real) | `C-A5` ("`fs_win.rs` returns unavailable"), `C-WIN1` (Windows bind), `C-WIN3` (`fs_win.rs`), 15.11 (a Windows test that needs an armed flow and a ledger inside `C-F2`). `ssk-daemon` is `forbid(unsafe_code)`; `OpenOptionsExt::share_mode` and tokio's bind are safe APIs, so a baseline needs no new unsafe | New spine commit `C-WIN0` (22, 15.2, 6.4.9, 6.6), MD-29; the alternative "declare Windows unavailable" was rejected because it is the owner's only target; owner decision 1 is untouched because `C-WIN0` claims no hardening |
| E-4 | high | `append_pending(&Admitted)` (`C-A6`) needs a type of `engine.rs` (`C-E2`), which follows `C-A6`: a cycle | **fixed** (real) | 6.4.7 signature, 6.7 `Admitted`, the old order-constraints line | `PendingInput` in `audit/record.rs`, `Admitted::pending_input` as the bridge, scan `audit_module_has_no_upward_imports` (6.4.7), MD-30 |
| E-5 | med | The narrowing action is throttled and starved like the widening one: (a) rate limit applies to disarm, (b) the GUI's disarm shares the write slot and floor with its arm, (c) 16 idle same-user IPC connections block a 17th client | **fixed** for (a) and (b), **residual** for (c) | (a) 11.4 rate-limit text. (b) 25.3 `switch_ingress` read: one `writes.try_acquire` and one floor for both. (c) `ssk-ipc/src/server.rs` read: `ServeLimits` 16 / first frame 5 s / idle 300 s, permit taken after `accept()` (lines 75-93, 280-283) | 11.4 (arm-only limit; residual paragraph), 25.3 (own disarm slot, no floor), 11.5 and 27 reworded from "always works" to "applied as soon as the request is served", threat row 34. A reserved permit for narrowing requests was not adopted: the server cannot know the request type before it takes a permit, and changing `ssk-ipc`'s accept order is outside M2 |
| E-6 | med | Direct-by-name fails at once with `01` when 16 lookups run, the permit is held until `getaddrinfo` returns, browsers do not retry | **narrowed** (real) | `tokio-1.53.1/src/net/addr.rs:190-222` read: the lookup is `spawn_blocking` and cannot be cancelled; 6.10 code and defaults | 6.10: a 500 ms wait with at most 32 waiters before `ResolverBusy`, abandoned lookups counted (`resolver_zombies`), `resolver_busy` counter; a dedicated pool **rejected** (512 blocking threads, the cap serves the OS resolver and the descriptor budget; 7.3 lists at most four other users); single-flight coalescing deferred as `C-N5` (OPT). Sufficiency for a real browser stays UNVERIFIED; the first ACCEPT-5 run is the measurement. MD-33 |
| E-7 | med | Admitted-flow volume can erase the 8 x 32 MiB ledger in about 1.8 h; "days to weeks" downplays it | **narrowed** (real) | Arithmetic: 268,435,456 B / (3 x 277 B) / 50 per s = 6,460 s = 1.8 h; 5.1 and 6.4.8 numbers read | 6.4.8, 5.1, 9, 16: both figures stated; warning `AUDIT_WINDOW_SHORT` (10.5); the retention **floor was not adopted** (a same-user process can already rewrite the whole chain, 16, and a floor lets the loop stop the proxy): owner question B18. MD-36 |
| E-8 | med | Policy runs on the client's name before resolution, so an exact-IP deny rule never applies to a name that resolves to that IP | **fixed** (real) | `crates/ssk-netadmin/src/policy.rs:91-104` read: IP-vs-IP, otherwise text; `crates/ssk-netcore/src/executor.rs:194-201` read: `connect_direct` resolves and dials with no policy hook | 6.10 step 5 and guard, 6.7.1 `exact_ip_denials`, 6.11, 16, 2.4, 24.1 criterion (2), threat row 4, MD-34. Reuses `NETCORE_ADDR_REFUSED` with `Result.refusal = deny_rule` and reply `02` instead of a new code. Applies at any priority (conservative; see MD-34 for the rejected "only rules before the matched one") |
| E-9 | med | The 250 ms race contacts up to 8 addresses but the ledger records only the winner | **fixed** (real), the stated contradiction **narrowed** | 6.4.3/6.10: `dialed` is the winner only and a failed flow has none. The quoted sentence "the ledger can never say X while the dial does Y" (6.4.4) is about the authorised host, port and route, not about contacted addresses, and "upper bound, never an under-report" (6.4.11) is about a Pending without Result, so neither was false as written; the gap is the missing list | `Result.attempted` (<= 8), `NetcoreError::DialFailed`/`DialAttempts` (6.4.3, 6.10), wording in 6.4.4 and 6.4.11, MD-35 |
| E-10 | med | The confirmation binds the click to a profile from an earlier snapshot; `SetIngress{armed:true}` carries no profile or digest; `INGRESS_CONFIG_CONFLICT` is never emitted | **fixed** (real, narrow exposure) | 25.3 code read: the pre-read checks only `arm_profile.is_some()`; 11.14 defines the code, no section emits it. The exposure needs a daemon restart with an edited configuration between snapshot and click | `expect_profile`, `expect_routing_digest` (11.4), `config_changed` (25.3), remembered `ArmExpectation`, MD-27 |
| E-11 | med | Neither client authenticates the server; a pre-created pipe can show a forged armed status | **fixed** as a plan item, wording interim (real, Windows part UNVERIFIED) | `ssk-ipc/src/client.rs` read: `connect_unix` and `connect_named_pipe` open by name only; `ssk-winhost/src/pipe.rs:329-331` and `require_pipe_owner` (`:1219`) show the repository treats the same gap as a defect for the privileged pipe; `ssk-ipc/src/paths.rs` read: the pipe name is a digest of the SID and the state directory | 25.2 row, threat row 32, 16, `C-IPC2` (RELEASE, desktop gate), "Grenzen" sentence (25.10), MD-38. Not in the M2 spine: the code is in the `ssk-ipc` client and its Windows half cannot run here |
| E-12 | med | "Standardroute" / `os_default_route` / "selects for internet destinations" claim more than a probe of 192.0.2.1 measures | **fixed** (real) | 6.12 itself says the `0.0.0.0/0` row is not what the OS uses under split routes; the GUI label (25.12), V3 field (25.9), warning (10.5) and the fixed sentence (25.12) against 13.2.3 | 10.5, 10.6 item 9, 13.2.1, 25.9, 25.10, 25.12, 2.2, 6.4.11; field `os_route_probe`; test `ingress_never_labels_the_probe_as_the_default_route`; MD-37 |
| E-13 | med | Flow permit and accept token are charged before the handshake; a silent connector holds all 256 permits and drains the bucket | **fixed** (real), part **narrowed** | 7.1 step order read: permits before the handshake; 50 x 10 s = 500 > 256 refill arithmetic. The claim that the shared `PeerBudget` is exhausted by any connector is intrinsic to a loopback port and was already stated ("a different local user spends only the cheap budget"); the text now says so plainly instead of "kernel-level flood" | 7.1, 7.2, 7.3, 5.1, 5.10, 6.1.4, 6.5: pre-admission slots cover the handshake, shared budgets are charged after `canonicalize`, the oldest silent socket is evicted after 1 s; a per-peer cap **rejected** (no per-process key on loopback). Eviction of established idle tunnels stays `C-E5` (RELEASE). MD-32 |
| E-14 | med | Forward and undeclared dependencies: `RuleBinding` in a later commit, `Decided`/`DecideError`/`ConfigState` undefined, `C-G1` and `C-E1` need commits they do not list | **fixed** (real) | `grep -rn "ConfigState\|Decided\|DecideError\|RuleBinding" crates apps` finds nothing; `Inner.config` is `Result<LoadedConfig, IpcError>` (`supervisor.rs:111`); `RouteCandidate` is `ssk-netadmin/src/route.rs:71` | 6.2, 6.7.1 (types defined in `routing.rs`), 12.1, complete order constraints (22), MD-30 |
| E-15 | med | Re-arm "without restart" has no way to install the re-opened writer (`OnceLock`, immutable `Arc` in `EngineCtx`, `close(&self)` is terminal) | **fixed** (real) | 6.9 struct, 6.7 `EngineCtx`, 6.4.7 `close` | `LedgerSlot`, recover installs last (6.9, 6.9.2, 6.9.4 step 7, 6.7.2 (a)); tests `recovery_installs_a_fresh_writer_and_a_second_recovery_works`, `a_flow_after_recovery_reaches_a_durable_closed_record`; MD-31 |
| E-16 | med | Direct-by-name, the owner's reversed rule, has no end-to-end test; wiring regressions stay green | **fixed** (real) | 23.8 text ("documented, not a test"), 24.1 | `build_ingress_executor` as a library function, wired-path test with a reserved TLD, eligibility test, builder test, fifth criterion (23.7, 23.8, 24.1); MD-40, MD-41. The `.invalid` test accepts either failure of an offline resolver; Windows UNVERIFIED |
| E-17 | med | ACCEPT-5 is asserted, not tested; the loopback source test cannot tell an explicit bind from none | **fixed** (real) | 24.2.1 text: the route-flip test is `#[ignore]` and was not run; source equality on loopback is consistent with `bind(127.0.0.1)` | Claim reworded (24.2.1, 2.3 CO-1), `TcpConnector` seam as a type-level proof (6.10), `C-CO1b` CI job, the desktop release gate with an owner (22), 24.2; whether hosted runners allow `unshare -rn` is UNVERIFIED. MD-41 |
| E-18 | med | Policy semantics of Direct-by-name: IP rules never match names; only the reverse direction is documented | **duplicate** of E-8 | as E-8 | as E-8 |
| E-19 | med | The daemon's default state root (`create_dir_all`, umask) can fail its own `mode & 0o022` check under umask 002 | **fixed** (real) | `crates/ssk-daemon/src/main.rs:67` read; Ran: `create_dir_all` gives 0755 (umask 022), **0775 (umask 002)**, 0700 (umask 077) | 6.4.9 (`paths::ensure_state_root`, mode 0700; an existing group-writable root is refused with a `chmod go-w` hint, never repaired), `C-A5`, tests under umask 002, RUNBOOK; MD-39 |
| E-20 | med | 11.4 check (5) vs 6.1.2 / 6.9.2 / the result table: a disarm can be lost | **duplicate** of E-1 | as E-1 | as E-1 |
| E-21 | med | Test-critical seams are undefined: no connector trait for the paused-time dial tests; `IngressDeps`, `Clock`, `Sleeper`, `ResolvedLimits`, `IngressCfgView` | **fixed** (real) | grep of the document: used, never defined | `TcpConnector` (6.10), 6.9.5, `LockProof` (6.4.5; `spawn_blocking` needs `'static`), MD-40 |
| E-22 | med | The plan is not green under the CI guard it introduces: surfaces include `ssk-config/src/`, `ssk-netadmin/src/audit.rs`, `ingress/audit/`, but no row carries a matrix paragraph or trailer; the job also runs on push | **fixed** (real) | `.github/workflows/ci.yml:3-5` (push and pull_request) and 21.2 surfaces; rows of 22 | Per-commit assignment (22 "Every commit", rows `C-A1`, `C-C0`, `C-A2` to `C-A7`, `C-WIN0`); the ledger matrix text moved from `C-A8` to the commits where the formats appear; MD-42 |
| E-23 | note | The implementer's lens counts "four tests the document calls existing that do not exist" | **fixed** (real, five names) | `grep -rn "fn <name>"` over `crates/` and `apps/` | 23.2, 23.3, 23.5 corrected to `accept_retry_backoff_table`, `accept_retry_gives_up_on_the_60th_consecutive_error`, `dial_deadline_bounds_a_silent_socks5_proxy` (and siblings), `ipv6_authority_is_bracketed_on_the_wire`, `whitespace_and_control_characters_are_refused_before_any_byte_is_written`, `connects_to_an_ipv6_literal_listener`, `daemon_dependency_closure_is_the_set_adr_0008_recorded`, `decision_core_stays_out_of_the_daemon`; 26.2 |

**Rejected outright: none.** Every finding was real as to its core; the narrowed and residual rows say what was not done and why.

**What remains open and is not a high finding:** B18 (retention floor) and the Windows addition to B9, both owner questions; the IPC connection cap residual (E-5); the sufficiency of the resolver numbers for a real browser (E-6); the Windows half of E-11 and `C-WIN0` itself (UNVERIFIED on real Windows); whether hosted CI runners allow the route-flip job (E-17).

### C.4 Implementation progress and carried-forward findings (2026-10-07)

Every commit below has a regression test seen to fail on the old code (or, where the production change IS the
seam, a mutation proving the test has teeth) and an independent review that re-ran that proof. Local gates only:
GitHub Actions has not started jobs for this repository since 2026-10-06 (account-level), so NOTHING below has run on
CI or on Windows.

**Done and pushed (beyond C.2):** `C-CI1`, `C-D0`, `C-L0`, `C-L1`, `C-I1b`, `C-T1`, `C-X1`, `C-A1`, `C-N3`, `C-CO1`,
`C-N4`, `C-C0`, `C-C1`, `C-A3`, `C-S1`, `C-L2`, `C-L3`, `C-IPC1` (each with fix commits where the review found
something). Next: the ingress modules (`C-G*`, `C-L4`, `C-CO3`), the audit ledger (`C-A2`..`C-A7`), then `C-G7b`,
`C-WIN0`, `C-E1`..`C-E3`, `C-F1`, `C-F2`.

**Findings the implementers and reviewers carried forward (each must be closed or accepted before M2 is called done):**

* `C-C0`: a rule action of kind `direct` or `deny` ignores unknown keys (serde does not apply `deny_unknown_fields` to
  the unit variants of an internally tagged enum): a typo in a policy rule is silently accepted. 16 documented
  divergences between the hand-written schema and the parser are listed in `ssk-config/tests/schema_contract.rs`
  (`KNOWN_DIVERGENCES`, may only shrink).
* `C-C1`: the static self-loop check misses `::ffff:127.0.0.1`; `destination: localhost` rules load but can never
  fire in the ingress; the schema pattern for `listen.address` is looser than the parser; sequence (positional)
  decoding of structs still works for the older config sections.
* `C-N3`/`C-N4`: until the ingress executor is built (`C-G1b`) a Direct name that resolves to loopback or a private
  address is dialled by the activation executor exactly as before; the ingress executor MUST be the guarded one. A
  failed LITERAL dial carries no `DialAttempts`, so the engine must fill `Result.attempted` itself; IPv4-mapped IPv6
  literals are not unmapped by `connect_host` (refused as `FamilyDisabled` under `ipv4_only`).
* `C-S1`: the plan-failure path of the activation arm sets `FailClosed` but never sets `activation_error`;
  `rule_binding` treats a Deny with an IP and a port differently from one without a port (decide in `C-G1`).
* `C-L2`/`C-L3`: `Deactivate` still waits its turn behind an activation dial by design; a hanging graceful shutdown
  is not tested against a stuck TLS peer; whether 200 ms is enough for the OS-deadline plan on Windows is an owner
  decision; the daemon cannot be type-checked for the windows-gnu target here (`ring`).
* `C-IPC1`: the ssk-cli subprocess tests that detect a stale `sskd` (11.9 item 3) belong with `C-F3`;
  `GetIngressAudit`'s answer DTOs have no container-level `#[serde(default)]`; `apps/desktop` is a separate
  workspace and was not built.
* Still open from C.3: the Windows named-pipe accept loop (`C-I1w`), `privileged.rs` has the same one-error-ends-it
  shape, IPv6 Direct dial unexercised on this host.
* Environment: the volume filled up twice (the incremental cache grew to 8 GB); build with `CARGO_INCREMENTAL=0`.

**Ingress modules landed since (2026-10-07, local gates only; the first CI run of any of it is still outstanding):**
`C-G1a` (`target.rs`) and its review fix, `C-G1` (`types.rs`), `C-L4` (`budget.rs`, `tests/fd_baseline.rs`), `C-G2`
(`socks5.rs`), `C-G5` (`limits.rs`), `C-G6` (`pump.rs`), `C-G7a` (`peer.rs`, the pure half), `C-CO3` (`path.rs`),
`C-G1b` (`guard.rs`, `tests/support/net_fakes.rs`) and its review fix, `C-A2` (`audit/record.rs`, with the format
paragraph in the compatibility matrix), `C-A5` (`audit/fs.rs`, `fs_unix.rs`, the private state root), `C-A4`
(`audit/dest.rs`), `C-A6` (`audit/writer.rs`, with the findings of its independent review) and `C-A7`
(`audit/{segments,verify,store_io,open}.rs`, with the segment layout in the compatibility matrix). Each has a "Refinements made at ..." paragraph at its section above; each was
mutation-tested (the survivors of the first run are listed in the commit messages and are tests now). Two commits
(`C-G1a` and `C-G1b` + `C-G7a`) were reviewed by an independent adversarial reviewer; the review of `C-G1b`/`C-G7a`
found a HIGH defect (the `tcp6` header word) that none of the author's tests could see on a machine without IPv6.

**Lessons that apply to every module still to write:**

* A parser of a kernel table must be tested against the REAL text of every table it will read; a machine without the
  feature (no IPv6 here) hides exactly the bug. Where the real file is unavailable, write the verbatim header from the
  kernel source into the test and say that it is derived.
* A test that compares a value with the constant it was computed from proves nothing (`MAX_AGE` against `MAX_AGE`,
  a sanitiser against itself): pin literals.
* Dead code that no input can reach is an equivalent mutant; remove it rather than keep a test that cannot fail
  (the `::/8` branch, the start-of-pump gate check, the zero-byte guard).
* `tokio::select!` without `biased` is random: a test of an ordering must run many rounds.
* A `cargo test` run for every mutant costs seconds only if the stale artifacts of earlier runs are deleted; the
  target directory grew to 24 GB (see the environment note above).

**Carried forward from these modules (open until the commit named is done):**

* `C-E2` (engine): the guard reads the armed profile NOW; the engine must cancel a dial on any gate change and a test
  must show that no connect survives it (6.10 review (g)). `FlowCtl` must fill `Result.attempted` for a failed literal
  dial itself.
* `C-G7b` (peer service): `peer_check` is off when `getuid()` is the overflow uid or the uid map is not the identity
  (6.10 review (h)); the self-test treats `Table.malformed != 0` as a failed table; the real `tcp6` of a machine with
  IPv6 must be read by `controls()` and by a test that self-skips without it.
* `C-E1` (host): `GuardCells::set_listener` with the BOUND address when `listen.port == 0`; `PathSlot` poller; snapshot
  builder joins the vocabulary scan of `ingress/mod.rs` (`vocabulary_scan`).
* `C-A6`/`C-A7`: the `*Event` input structs and `PendingInput`; segments, `Continue`; closed vocabularies for
  `Closed.reason`, `Denied.reason_code`, `Result.error_code`/`refusal` (the pump's `PumpEnd::reason`, the guard's
  labels and the `Refusal` codes are the producers); `limits::DenialSummary` to `Summary` conversion.
* `C-WIN2`/`C-CO6w`: nothing of `peer.rs` or `path.rs` runs on Windows; `Controls` are all `false` there until then.
