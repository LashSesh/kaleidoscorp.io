# P4 Ingress Design — Wintun + Fake-IP + OpenVPN

> **Status:** Design-spike output, 2026-08-03. Read-only investigation on real Windows 11 hardware
> (unelevated, de-DE). No adapter was created, no driver installed, no routing/firewall/DNS state
> changed, no `openvpn.exe` process spawned. Every claim below is marked either **[VERIFIED-HERE]**
> (executed/read on this machine) or **[UNVERIFIED]** (inferred from vendor documentation or general
> platform knowledge, not directly observed) — see §6 for the consolidated unverified list.
>
> This document is the detail behind `docs/WINDOWS_PRODUCT_ROADMAP.md`'s P4 section, which this spike
> resolved. Read that section first for the summary; this document is the evidence and the full
> sub-phase breakdown.

---

## 0. The architecture decision this spike was scoped against

Made by the user on 2026-08-03, before this spike ran (see memory `p4-ingress-architecture-decision`):

1. Local capture via a **TUN/TAP virtual adapter** (not a raw WFP callout, not WinDivert) — specifically
   **Wintun**, chosen to avoid building or signing a custom kernel driver.
2. Dispatch stays a **per-flow smart router** ("Model 1"): the existing `PolicyEngine`/
   `RouteOrchestrator`/`ssk-netcore` adapters decide and execute per flow — not a classic
   single-tunnel VPN client architecture.
3. **OpenVPN as one additional selectable adapter**, not a replacement for the model.
4. OpenVPN integration depth: **orchestrate the real `openvpn.exe` client as a subprocess**, not a
   native protocol reimplementation.

This spike's job was to turn that into a buildable design, with real evidence in place of assumptions.

---

## 1. Wintun: corrected facts

**The premise "Wintun is MIT-licensed" was imprecise — three licenses are actually in play, verified by
extracting and reading the real crate contents:**

| Component | License | Evidence |
|---|---|---|
| `wintun`/`wintun-bindings` Rust wrapper crates | MIT | **[VERIFIED-HERE]** — extracted both crates' `LICENSE` files from the local cargo cache |
| Vendored `wintun.dll` binary | WireGuard LLC proprietary "Prebuilt Binaries License" | **[VERIFIED-HERE]** — read `wintun/LICENSE.txt` inside the crate verbatim |
| Wintun's own driver *source* (not what we ship) | GPLv2 | **[VERIFIED-HERE]** — stated in the vendored `wintun/README.md` |

The prebuilt-binary license's §3d permits exactly this project's use ("distributed alongside other
software that uses the Software only via the Permitted API") but this is **not MIT** and needs its own
`NOTICE`/third-party-license entry in P6 — do not fold it into an MIT compliance claim.

**Signature reality — verified, and more precise than assumed:**

Running `Get-AuthenticodeSignature` **[VERIFIED-HERE]** on the vendored `wintun.dll` (the exact file
that ships inside the crate) shows:

```
Status         : Valid
Signer         : CN=WireGuard LLC, O=WireGuard LLC   (DigiCert EV Authenticode cert)
Signer NotBefore/NotAfter : 2018-12-10 / 2021-12-14   (leaf cert EXPIRED)
TimeStamper    : CN=DigiCert Timestamp 2021, valid to 2031-01-06
```

This is a plain DigiCert EV **Authenticode** signature — **not** a Microsoft WHQL logo or attestation
signature on the DLL itself, and the leaf cert is expired (the signature still validates via the 2021
RFC3161 timestamp, which is normal, not a red flag by itself). **There is no `.sys` file anywhere in the
crate** — Wintun's documented architecture embeds the actual kernel driver as a PE resource inside
`wintun.dll`, installed into the driver store at `WintunCreateAdapter()` time. **The embedded `.sys`'s
own signature chain was not extracted or verified here** — this is the single most important open item
for the operator VM (§6).

**Rust integration — two live, competing crates, both real dependencies today's `Cargo.lock` already
half-resolves:**

| | `wintun` | `wintun-bindings` (recommended) |
|---|---|---|
| Version / published | 0.5.1 / 2025-01-29 | 0.7.39 / 2026-06-05 |
| `windows-sys` required | 0.52 (already in `Cargo.lock` via `ring`) | 0.61.2 (already in `Cargo.lock` via clap/tokio) |
| Async, signature verification | No | Yes (`AsyncSession`, `verify_binary_signature` feature) |

Adding either does **not** introduce a new `windows-sys` major version — both land on versions already
resolved transitively. The one real friction: `wintun-bindings`'s `Adapter::get_luid()` returns its own
pinned-`windows-sys`-typed `NET_LUID_LH`, structurally identical to but nominally distinct from
`ssk-winhost`'s existing `windows-sys 0.59` `NET_LUID_LH` — a small, contained `unsafe` transmute/copy
is needed wherever the two meet, not a blocking conflict.

**`unsafe` surface — confirmed by reading the crate, not assumed:** exactly three public entry points
are `unsafe` (`load()`/`load_from_path()`/`load_from_library()` — loading an arbitrary DLL is inherently
unsafe). Every downstream call (`Adapter::create/open/delete`, `start_session`, `send_packet`,
`try_receive`) is a safe `pub fn`. **Consequence: this integration must live in `ssk-winhost`** (the one
`unsafe_code = "allow"` crate) — confirmed, not changed, from the existing P1/P2/P3 pattern.

**Privilege — the real architectural fork:** `wintun-bindings`'s own README states *"Must be run as
Administrator because we create network adapters"* **[VENDOR-DOCUMENTED, not independently executed]**.
Network adapter creation goes through the PnP/SetupAPI device-installation subsystem, which is
elevation-gated regardless of the driver behind it. **Consequence: TUN adapter lifecycle is a
privileged-broker (`ssk-svc`/`ssk-netd-helper`) responsibility, exactly like the firewall enforcer and
SCM install — never `ssk-daemon`.**

---

## 2. The routing-loop problem — the hardest question, resolved as a hybrid

**The problem, precisely:** a TUN adapter only receives packets the OS routing table sends to it.
Routing `0.0.0.0/0` through TUN to capture "everything" also captures the daemon's *own* re-dispatch
traffic once it decides "Direct" and dials out for real — a naive setup is circular. Windows' routing
table has no per-process/per-socket awareness **[VERIFIED-HERE via `route print`]** — it is keyed only
on destination-prefix + interface + metric.

**Four patterns evaluated:**

| Pattern | Mechanism | New effort | Closes the loop? |
|---|---|---|---|
| A — route only known-real destinations | n/a | — | **Rejected standalone**: circular — you only learn the destination by first seeing the packet |
| B — `IP_UNICAST_IF` per-socket override | one `setsockopt` wrapper in `ssk-winhost` | S | Only for the daemon's *own* sockets — a prerequisite, not a standalone ingress strategy |
| **C — fake-IP + DNS + narrow-range TUN** | new DNS resolver-server + scoped TUN route | M | **Yes, structurally** — see below |
| D — full `0.0.0.0/0` TUN + userspace TCP/IP stack | full Wintun I/O + `smoltcp`-class stack | XL | Yes, but at XL cost, deferred (see §4) |

**Decision: B + C together**, D deferred.

- **Pattern C**: a DNS resolver-server (reusing `ssk-netcore::dns.rs`'s existing RFC 1035 encode/decode
  helpers, `dns.rs:143-307`) answers queries with synthetic addresses from **`198.18.0.0/15`** (RFC
  2544's benchmarking range — the de-facto industry convention for exactly this purpose, since no real
  host ever answers there) and records `fake_ip → hostname`. **Only** that `/15` is routed through TUN.
  Per Windows' confirmed longest-prefix-match behavior **[VERIFIED-HERE against this machine's real
  routing table]**, this coexists with the real default route with zero interference. Failure mode is
  safe-by-construction: an unhandled fake IP just times out — it can never leak real traffic through the
  real stack, because nothing on the real internet answers there.
- **Pattern B** (`IP_UNICAST_IF`, a per-socket Winsock option, not privilege-gated) is the shared
  prerequisite underneath C: it lets the daemon's own re-dispatch and upstream-resolver sockets bypass
  the TUN-ward route entirely, so scoping the TUN route narrowly is safe without destination-based
  exclusions.

**A minimal TCP terminator is still needed** for connections addressed to the fake-IP range — not a
general-purpose stack, only enough to terminate the handshake for that narrow range and relay the
decoded stream to the existing dispatch pipeline. New crate `ssk-tunstack`, `forbid(unsafe_code)`,
wrapping `smoltcp` (MIT/Apache-2.0), with an injected `RawFrameSource`/`RawFrameSink` seam mirroring
`ssk-netd-helper::FrameTransport` so it is unit-testable with fake frames on Linux CI, without ever
touching real Wintun.

**What remains a genuine, unresolved design bet, not a verified fact:** whether `smoltcp` is actually
adequate for terminating real Windows TCP clients' handshakes (window scaling, SACK, PMTU) without full
general-purpose-stack correctness — **[UNVERIFIED]**, needs a hands-on spike against a real Windows TCP
client, not literature review. This is called out explicitly in P4g's work items.

---

## 3. OpenVPN subprocess adapter

- **OpenVPN is not installed on the investigation machine** **[VERIFIED-HERE]** — a real product must
  either require the user to install it or bundle a redistributable copy. OpenVPN's Windows binaries
  are GPL-2.0 — bundling a GPL-2.0 *binary* alongside this Apache-2.0 Rust workspace is a **packaging/
  distribution** question for P6 (NOTICE file, no static linking — which subprocess-spawning already
  satisfies), **not** a `deny.toml` Cargo-dependency question, since no Rust crate is involved.
- OpenVPN exposes a documented **management interface** (a local TCP/line-protocol for start/stop,
  state, and credential prompts) — the orchestration layer needs: process spawn with the right flags to
  enable it, a client for the line protocol (`SUCCESS`/`ERROR`/`END`, async `>STATE:`/`>PASSWORD:`
  demux), `.ovpn` config generation, and connection-state monitoring.
- OpenVPN's own Windows client also creates a privileged TUN/TAP-class adapter — **it inherits the same
  elevation boundary as Wintun**, so "subprocess orchestration" does not sidestep privilege: `openvpn.exe`
  must be spawned from, or by, the privileged broker, not from unprivileged `ssk-daemon`.
- For "OpenVPN as ONE selectable adapter, not the whole model," the generated config must use
  **`route-nopull`** plus explicit manual routes — the standard, documented OpenVPN client
  split-tunneling pattern — so the tunnel does not claim the default route.
- New crate `ssk-vpnctl`: process spawn (`std::process::Command`, mirroring the existing
  `firewall.rs`'s `Command::new(netsh)` pattern) + management-interface client with an injected
  transport trait (same testability pattern as everywhere else in this codebase) + config generation.
  Spawning a process is not `unsafe`, so this does **not** need to live in `ssk-winhost` by that
  criterion alone — but the broker/elevation placement (previous bullet) still applies.

---

## 4. Full coverage — DECIDED 2026-08-03: mandatory for v1.0

**Decision: full coverage.** The user was shown the tradeoff (DNS-visible-only via Lanes 1–3, vs. full
`0.0.0.0/0` TUN capture with a general-purpose userspace TCP/IP stack covering hardcoded-IP and
DoH-to-hardcoded-resolver traffic too) and chose **full coverage as a hard v1.0 requirement**, not a
deferred future phase. Pattern D — previously scoped as an optional, separately-sized future phase — is
now **in the critical path**, alongside Lanes 1–3, not instead of them (the fake-IP fast path from §2
remains valuable as a lower-overhead path for the common DNS-visible case; Pattern D becomes the
mandatory fallback/complete safety net for everything else, not the sole mechanism).

**What this changes, concretely:**

- The TUN route can no longer be scoped to the safe, self-contained `198.18.0.0/15` synthetic range
  only. Broader real-destination ranges must transit TUN, which reopens the routing-loop problem in its
  hard form. Missing an exemption here does not fail closed to a timeout (as an unhandled fake IP does)
  — it risks breaking real OS functionality, or capturing traffic the daemon has no policy basis to
  judge yet.

  > **CORRECTED 2026-08-03 — the original text here was structurally impossible and is struck.**
  > It read: *"every OS/system process's own traffic … needs a reliable `IP_UNICAST_IF`-based
  > exemption, not just the daemon's own sockets."* **`IP_UNICAST_IF` is a per-socket option settable
  > only by the process that owns the socket.** Windows exposes no way to set it on `svchost`'s,
  > `System`'s, or `openvpn.exe`'s sockets, so it can never exempt anything but SSK's own traffic.
  > Verified on this machine: pinning `IP_UNICAST_IF` to the physical NIC also breaks loopback
  > destinations outright (`WSAEADDRNOTAVAIL`, TCP and UDP) — which additionally breaks P4g's proposed
  > "fixed loopback port" relay as designed.
  >
  > What full coverage actually needs is a **broker-owned, journaled, dynamic exclusion-route set**
  > (new sub-phase P4k, L, privileged). Enumerated as captured-and-unexemptable on this machine right
  > now: W32Time (capturing NTP breaks TLS certificate validation machine-wide — including SSK's own
  > upstream, a self-inflicted bootstrap failure), Dnscache, WpnService over IPv6, iphlpsvc, CDPSvc,
  > System/SMB, and the installed third-party security suite's own cloud channel.
- **The `smoltcp` bet (§6 item 7) became load-bearing — and a follow-up investigation then found the
  bet was placed on the wrong risk.** See `docs/P4_FULL_COVERAGE_FEASIBILITY.md` (2026-08-03) for the
  full findings. In brief, measured by a real spike on this machine: the risk this document flagged
  (window scaling, handshake correctness) **is resolved in smoltcp's favour** — window scaling
  negotiates correctly across WS=2/8/14, `any_ip` terminates arbitrary non-interface destination IPs,
  RTO is RTT-estimated, ~27 Gbps single-connection on a 1.2 GHz laptop. But four risks this document
  never named turned out to be the real ones, one of them architectural and unfixable inside smoltcp
  (an O(n) linear `SocketSet` scan, measured at 15.9×–69× degradation at 1000–4000 concurrent
  connections). And a third architecture this document never considered — the "system stack"
  (NAT-to-a-local-kernel-listener, as used by sing-box/mihomo) — would collapse Pattern D's TCP half
  onto the Lane 1 listener P4b already builds, deleting rather than mitigating all four risks.
  **Do not implement P4g against smoltcp before running the three-way bake-off (gate P4-GATE-1).**
- UDP NAT for arbitrary destinations (not just fake-IP-mapped ones) and full IPv6 handling are now
  in scope, not deferred.
- The exit criterion changes from "a real application's traffic enters SSK... via Lane 1 or Lane 2" to
  requiring genuine coverage of hardcoded-destination and non-standard-DNS traffic too — `dns_unprotected`
  becomes a transitional/degraded-mode signal (used while full coverage is still being rolled out, or
  if the feasibility investigation forces a scope walk-back), not the accepted permanent v1.0 state.

**Effort impact:** the roadmap's P4 = XL estimate undersold the true cost once this decision is made —
see the corrected sub-phase table and the new P4k in `docs/P4_FULL_COVERAGE_FEASIBILITY.md`.

---

## 5. Sub-phase plan

| Sub-phase | Goal | Effort | Depends on |
|---|---|---|---|
| **P4a** | Real config schema: `AdapterKind::OpenVpn`, `RouteKind::LocalInterface{adapter_id, if_index_hint}` in `ssk-netadmin`; per-app rules; `LoadedConfig` actually passed into `Supervisor::new` (today `main.rs:39-51` loads and discards it, registry hardcoded to `proxy.corp.com:1080`) | M | — |
| **P4b** | Lane 1 (system-proxy): `IngressProvider` trait (`ssk-netadmin`) + `SystemProxyProvider` (`ssk-daemon`) — local SOCKS5/HTTP-CONNECT `TcpListener::accept()`; real per-connection `EgressSession` byte-pumping replacing the single idle socket; real `FlowDescriptor` (app id from owning PID via existing `ssk-winhost::connections.rs`, real destination/protocol/risk) | L | P4a (loose) |
| **P4c** | `IP_UNICAST_IF` prerequisite: `setsockopt` wrapper in `ssk-winhost`, called from `ssk-netcore::direct::connect_tcp` and the new DNS resolver's upstream queries | S | — |
| **P4d** | Wintun integration spike (implementation-level, not this design spike): pick `wintun-bindings`, confirm the exact unelevated `WintunCreateAdapter` error code, extract and check the embedded `.sys` signature, verify the `verify_binary_signature` feature actually works | S | — (blocks P4e) |
| **P4e** | TUN adapter lifecycle in the privileged broker: `ssk-winhost/src/tun.rs` (create/open/delete, session, packet pump), new `ssk-ipc` request/event types mirroring the existing kill-switch engage/release pattern, `ssk-svc` hosts the pump loop | L | P4d |
| **P4f** | Fake-IP DNS server + narrow-range routing: `ssk-netcore/src/dns_server.rs` (UDP:53, reusing existing RFC 1035 helpers), fake-IP allocation table with TTL/eviction, DNS-server takeover via `ssk-winhost`'s existing `netsh` subprocess pattern behind the broker | M | P4c, P4e |
| **P4g** | Minimal TCP terminator: new `ssk-tunstack` crate wrapping `smoltcp` behind injected frame source/sink traits; wire P4e's Wintun pump as the real frame source scoped to `198.18.0.0/15`; relay terminated connections to `ssk-daemon` over a fixed loopback port with a small preamble carrying the resolved hostname — **spike required**: confirm `smoltcp`'s correctness bar is sufficient (§2) | L | P4e, P4f |
| **P4h** | Packet-to-flow classification bridge: unify Lane 1 + Lane 2 on the existing `FlowDescriptor → PolicyEngine::evaluate → RouteOrchestrator::plan → RouteExecutor::connect` spine; implement or delete the typed-but-inert paths (`RouteKind::Fallback`, `SplitRoute`, mTLS, DoT); add liveness probing (`RouteExecutor::probe` has zero production callers) | M | P4b, P4g |
| **P4i** | Lane 3 (OpenVPN): new `ssk-vpnctl` crate (spawn, management-interface client, config generation with `route-nopull`); broker spawns/owns the process; wire `AdapterKind::OpenVpn`/`RouteKind::LocalInterface` through `RouteOrchestrator`; first-class "not installed" error path | L | P4a; parallel to P4d–h |
| **P4j** | Integration tier: full path (CLI → IPC → policy → executor → real proxy → destination) on Windows **and** Linux; fake-IP+TUN lane tested via `ssk-tunstack`'s fake transport (no real Wintun needed in CI); OpenVPN lane tested via `ssk-vpnctl`'s fake transport (no real `openvpn.exe` needed in CI) | M | P4h, P4i |

---

## 6. Consolidated unverified list — needs an elevated/VM run, in `docs/OPERATOR_VM_VALIDATION.md` style

1. Whether an unelevated `WintunCreateAdapter` call actually fails, and the exact Win32 error code
   (`ERROR_ACCESS_DENIED`/5 vs `PRIVILEGE_NOT_HELD`) — en-US and de-DE.
2. The embedded `.sys` kernel driver's own signature chain inside `wintun.dll` (only the outer DLL's
   WireGuard LLC/DigiCert Authenticode signature was checked here) — needs PE-resource extraction or an
   elevated `Get-WindowsDriver`/`driverquery /si` check.
3. Whether Wintun installs into the driver store persistently across restarts, and whether that needs
   re-elevation each time — `pnputil /enum-drivers` before/after on a VM.
4. Whether `wintun-bindings`'s `verify_binary_signature` feature actually blocks a tampered/renamed DLL
   at runtime (source was read, not executed).
5. Whether adding `wintun-bindings` as a real dependency keeps `Cargo.lock`'s `windows-sys 0.61.2` pinned
   exactly, or drifts — not tested by actually building with it added.
6. Whether a Wintun adapter/session handle can be shared across processes or must stay single-process —
   affects whether `ssk-tunstack`'s pump can live anywhere but directly beside the Wintun FFI.
7. **The `smoltcp` correctness bet** (§2) — needs a hands-on spike against a real Windows TCP client,
   not a literature review.
8. Whether `netsh interface ip set dns` / `Set-DnsClientServerAddress` behaves cleanly when a competing
   VPN client or corporate DHCP policy already owns DNS settings, and what the rollback path looks like.
9. Whether Wintun/DNS-takeover/`openvpn.exe`-spawn from an unsigned `ssk.exe` trips Defender/SmartScreen
   on a clean (not in-place-upgraded) Windows 11 VM — this development machine's Smart App Control is
   off, possibly from an in-place upgrade, so it may under-represent a real target machine.
10. Whether process-lineage EDR heuristics (`ssk.exe` spawning `openvpn.exe`) trigger in an
    enterprise-EDR-equipped environment — a bare Defender-only VM cannot surface this.
11. `bcdedit /enum {current}` and `Confirm-SecureBootUEFI` both failed access-denied unelevated on this
    machine (three invocation forms tried) — driver test-signing / Secure Boot baseline state needs an
    elevated run to capture.
12. Whether `route-nopull` + explicit client routes behaves as documented against a real OpenVPN server
    — no server was reached, OpenVPN is not installed here.
13. Whether the official OpenVPN Windows installer currently bundles Wintun or the older TAP-Windows6
    driver, and that driver's exact license — general knowledge only, no installer was downloaded.
14. Availability of a safe `socket2`-based wrapper for `IP_UNICAST_IF` versus needing raw `windows-sys`
    FFI in `ssk-winhost` — not checked; affects P4c's exact shape, not its size.
15. Whether the proposed loopback-relay preamble for handing P4g's terminated connections to
    `ssk-daemon` (a PROXY-protocol-v2-shaped header) is the right choice versus extending `ssk-ipc`
    itself to carry streamed bytes — a design choice made in this synthesis, not sanity-checked against
    `crates/ssk-ipc/src/framing.rs` yet. Do this check before P4g implementation starts.

---

## 7. What this spike got wrong from the original roadmap framing (calibration note)

The roadmap's original open question (§5.4, written 2026-08-02) assumed the unresolved risk was
"driver-signing requirements, WFP sublayer arbitration against existing AV/EDR filters." Both are now
moot — but the total unknown-unknowns did not shrink to zero, they **relocated**: driver signing is
genuinely de-risked (Wintun is pre-signed upstream), but the spike surfaced a comparable-weight risk
the original framing did not anticipate — DNS-server takeover and `openvpn.exe` subprocess-spawn as new
AV/EDR heuristic signals that would not exist under a WFP-only design. Net effect: roughly a wash, not a
clean win. The roadmap's "schedule this spike early because it changes the P3 kill-switch design"
reasoning also did not hold — the resolved mechanism (Wintun + fake-IP) turned out to be architecturally
independent of the kill-switch's netsh/WFP question, so running the spike after P0–P3 cost nothing.
