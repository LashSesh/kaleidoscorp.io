# P4 Full-Coverage Feasibility — verdict: CHANGE-MECHANISM (inside the plan, not at its head)

> **Status:** Feasibility investigation, 2026-08-03, triggered by the user's decision that full traffic
> coverage (hardcoded destination IPs, DoH/DoT to a hardcoded resolver, QUIC) is **mandatory for v1.0**
> rather than a deferred phase. That decision promoted a previously-deferred design (`Pattern D`) into
> the critical path and turned an explicitly-flagged unproven assumption into a load-bearing one.
>
> Four parallel investigation tracks, read-only on real Windows 11 hardware (25H2, build 26200.8875,
> de-DE, unelevated), plus one **real compiled-and-executed spike**. Claims are marked
> **[VERIFIED-HERE]** (executed/read on this machine) or **[UNVERIFIED]**.
>
> **This document supersedes `docs/P4_INGRESS_DESIGN.md` where they disagree.** Two statements in that
> document are now struck as factually wrong; both corrections are annotated in place there.

---

## 0. The verdict in one paragraph

**The capture mechanism decision stands — do not reopen TUN-vs-WFP for capture.** Every product in this
category (stream-level proxy egress + full capture) uses TUN plus L3→L4 translation, and SSK is
structurally locked into that category because all five of its adapters are stream-level
(`adapter.rs:15-21`, **[VERIFIED-HERE]**). WinDivert is separately disqualified on four grounds the
original spike never considered (§4). **The verdict is CHANGE-MECHANISM because two of the three
mechanism components *inside* the plan are wrong**, and one stated mechanism is structurally impossible.
Full coverage of *traffic* is genuinely achievable; the plan as written names the wrong userspace stack,
prices the routing-exemption surface at a fraction of its real cost via a mechanism that cannot work,
and contains no per-app enforcement at all — while the product's own `FlowDescriptor` puts `app_id`
first.

---

## 1. The spike bet on the wrong risk — and bet conservatively

`docs/P4_INGRESS_DESIGN.md` named the adequacy of `smoltcp` as its central unknown, specifically
window scaling / handshake correctness. A real spike was built and run **[VERIFIED-HERE]** (source at
`scratchpad/tcpspike/`, build artifacts deleted; test machine: Intel Core 3 100U, 6C/8T, 1.2 GHz,
Wi-Fi 6 at 270 Mbps — a low-power laptop, so numbers are conservative):

**That risk is resolved in smoltcp's favour:**
- Window scaling negotiates correctly across WS=2/8/14, and correctly emits nothing to a legacy SYN.
- `any_ip` terminates a SYN to `203.0.113.5` — an address that is not an interface address (with
  `any_ip` off: zero replies, silently dropped). This is exactly what Pattern D requires.
- RTO is RTT-estimated; CUBIC and Reno are available.
- ~27 Gbps single-connection throughput — roughly 100× this machine's actual link speed.

**Four risks the design document never named turned out to be the real ones:**

1. **An O(n) linear `SocketSet` scan on both ingress and egress — architectural, and unfixable inside
   smoltcp.** Measured at **15.9×–69× degradation at 1000–4000 concurrent connections**, with the hot
   socket placed in the best position specifically to rule out an ordering artifact. A desktop machine
   routinely holds several hundred concurrent connections.
2. **smoltcp contributes essentially nothing to the UDP half.** Its only wildcard-capable API is the raw
   socket, which reduces it to a header codec — a job `etherparse` already does.
3. **Under `any_ip` it fabricates liveness.** It forged an ICMP echo reply claiming to be from `8.8.8.8`
   for a host it had never contacted. This directly contradicts `ssk-netcore/src/lib.rs:15-16`
   (*"Nothing in this crate fabricates liveness"*) — a release-blocker-class problem against this
   project's own stated ethos, not a cosmetic one.
4. **Licensing:** smoltcp is **`0BSD`**, not the "MIT/Apache-2.0" the design document claims. 0BSD is
   *more* permissive, so this is not a legal problem — but **`deny.toml`'s allow-list does not contain
   `0BSD`**, so adding smoltcp fails `cargo deny check` on day one. A one-line fix, but a real gate
   break the incorrect claim would have hidden until CI went red.

**Prior art contradicts the choice:** `tun2proxy` — the closest direct prior art, maintained by the same
org as `wintun-bindings` — has **never shipped smoltcp**; all 62 published versions depend on `ipstack`
**[VERIFIED-HERE]**. That is *not* an endorsement of ipstack, which is materially less correct (no
window scaling at all; `send_window: u16` with no shift applied anywhere; fixed 1-second RTO; and it
**silently discards unacknowledged data after 3 retransmits**, a permanent hole in a TCP byte stream).

---

## 2. The architecture the spike never considered — and why it matters most

Track 4 surfaced a third option absent from the original four-pattern table: the **"system stack"**
(sing-box / mihomo `system` and `mixed` modes; `sing-tun/stack_system.go` read verbatim). It implements
**no userspace TCP state machine at all.** It rewrites packet addresses toward a local kernel listener
and keeps a NAT table; **Windows' own TCP stack does the termination.**

**The synthesis point no single track made: for SSK specifically, this collapses Pattern D's TCP half
onto the Lane 1 listener that P4b already builds.** Same `TcpListener::accept()`, same per-connection
`EgressSession` byte pump, minus the SOCKS handshake, plus a NAT-table lookup for the original
destination.

Adopting it **deletes rather than mitigates**: all four of §1's risks, the liveness-fabrication release
blocker, and the shadow-parser and socket-sharding work that was never budgeted. SACK, PLPMTUD,
congestion control and adversarial robustness become Microsoft's problem.

Its cost is real but **bounded and testable**: mihomo's own documentation states the system/mixed stacks
do not work with the Windows firewall enabled, remedied by allowing the core binary through — an action
SSK's existing P3 firewall broker could install as an audited operation. Note **[VERIFIED-HERE]** that a
third-party security suite, not Windows Firewall, is this machine's registered `FirewallProduct`, so
third-party firewalls belong in the test matrix.

**Committing to smoltcp now means committing to the more expensive of two options without ever having
compared them.**

---

## 3. Per-app steering — where WFP genuinely does reopen

`FlowDescriptor.app_id` is the **first field** of the product's flow model (`flow.rs:31`).
`README.md:320` names a *"WFP/WinDivert redirect layer"* as the ingress.
`docs/DESKTOP_CLIENT_ARCHITECTURE.md:601-605` table H.1 lists **two distinct rows** — "TUN interface /
all TCP+UDP / full protection" **and** "Per-app steering / WFP App-ID filters / Proxifier-parity" — with
a separate Phase-4c.

**The original spike silently merged two mechanisms serving two jobs into one mechanism serving all
jobs, and dropped the WFP thread without writing down why.** P4a–P4j contains no per-app enforcement
sub-phase and no WFP work item; P4a mentions per-app rules only as a *config schema* item — the rules
exist in config and nothing enforces them per-process at the OS level.

Proxifier (this README's own stated comparison point), Mullvad and Windscribe all implement per-app
steering with a **custom WFP callout driver at the ALE layers** (`ProxifierDrv`,
`mullvad-split-tunnel.sys`, `WindscribeSplitTunnel.sys`). **Not one derives per-app identity from TUN
packets.** From a TUN packet you get a 5-tuple and must reverse-map to a PID via `GetExtendedTcpTable`,
which is timing-racy — sing-box issue #2823 documents exactly this breaking in a mature Go product's
Windows alpha.

**"Full coverage" will be read as "full per-app fidelity," and TUN cannot deliver that.** This needs an
explicit decision with both prices attached (gate P4-GATE-3, §6).

---

## 4. Why WinDivert stays disqualified (four grounds, not one)

The original spike rejected WinDivert only implicitly. It is disqualified on grounds worth recording:

1. **LGPL/GPL** against a `deny.toml` allow-list containing neither **[VERIFIED-HERE, `deny.toml:15-26`]**.
2. Last repository push **2023-03-15**.
3. A **LOLDrivers entry with published YARA/Sigma detections** — self-inflicted for a product whose own
   open questions already ask "does this trip Defender/EDR?"
4. Volunteer-dependent signing.

---

## 5. The honest effort — re-sized

The roadmap says P4 = XL, priced for Lanes 1–3 only. Calibrated against this repo's actual delivered
quality bar (45 crates, hash-chained audit entries, `forbid(unsafe_code)` outside one crate, trybuild UI
tests, receipt-less idempotent recovery, the `OPERATOR_VM_VALIDATION.md` discipline), **one XL here is
2–4 months of focused work for one experienced Windows/Rust systems engineer**, with P2 and P3 as the
reference points.

| Block | Scope | Estimate |
|---|---|---|
| **A** | Lanes 1–3 as already scoped (P4a–P4j, the original XL) | **2–3 months** |
| **B** | What full coverage adds | **4–6 months** |
| **C** | Per-app steering at Proxifier parity (signed WFP ALE callout) | **3–6 months, if pursued** |

**Total: 6–9 months for full traffic coverage without per-app parity; 9–15 months with it.** That is
2–3 quarters minimum, 3–5 quarters realistically, for one focused engineer.

**Two structural items inside Block B are not additive work:**
- The **datagram dispatch spine (L) is a breaking change to `ssk-netcore`'s central abstraction** —
  `Transport` is `AsyncRead + AsyncWrite + Unpin + Send` (`session.rs:9`) and cannot represent a
  datagram; `RouteKind` has no datagram variant (`route.rs:44-58`) **[VERIFIED-HERE]**. It touches every
  adapter, the executor, the orchestrator, the data plane, and the audit chain.
- The **policy-model change (M) is required, not optional**: `MatchCriteria` (`policy.rs:32-44`) has
  `app_prefix`/`dest_suffix`/`protocol`/`min_risk`/`max_risk` and **no IP or CIDR field at all**
  **[VERIFIED-HERE]**; matching is `d.destination_host.ends_with(suffix)` (`policy.rs:57`). So every
  domain-suffix rule an operator writes is **structurally unmatchable for exactly the hardcoded-IP flows
  Pattern D exists to catch.**

**Two costs not in that number:**

- **The operator-VM validation loop is continuous, not a task.** There is **no unelevated path on
  Windows** to inject into or capture from the real TCP stack: `WintunCreateAdapter` needs elevation,
  `SOCK_RAW`/`IPPROTO_TCP` has been Administrator-only since XP SP2, capture drivers need install
  rights. So smoltcp-vs-real-Windows interop, `/1` route behaviour, Wintun's auto-assigned interface
  metric, adapter-teardown-deletes-routes, and `IP_UNICAST_IF` overriding a competing capture route are
  all unprovable from the dev machine. **Add 20–30% to Blocks A and B.**
- **The risk profile changes shape, not just size.** Lanes 1–3 fail closed to a timeout. Under full
  capture this component sits in the path of *all* machine connectivity, inside the privileged broker,
  adjacent to the one `unsafe_code = "allow"` crate. A bug is not "a feature does not work" — it is
  "the user's machine loses network," and **the worst case is worse than the kill-switch's**: a stranded
  firewall rule leaves a severed but *locally recoverable* machine, because `ssk-ipc` is a named pipe
  (`paths.rs:26`) and named pipes are unaffected by routing — whereas a **stranded `/1` capture route
  black-holes everything AND removes the remote-recovery path AND breaks any recovery tooling that
  itself needs the network.** `Broker::reconcile_startup` only runs if the broker starts, and the
  failure mode most needing survival is SSK not starting.

---

## 6. The four gates — three to five weeks, before any P4g code

Each costs almost nothing and can independently reshape or kill the plan.

### P4-GATE-0 — Does Wintun's embedded driver still load? **Do this first, before everything.**

**Microsoft removed trust for the cross-signed kernel driver program in the April 2026 Windows update**,
applying to 24H2/25H2/26H1 and later, with an allow-list for "a limited number of widely used and
reputable cross-signed drivers." **This machine is in the affected population [VERIFIED-HERE]:**
Windows 11 25H2, build 26200.8875, and the policy took effect **four months ago**. The earlier spike
verified there is **no `.sys` in the Wintun crate** (the driver is embedded as a PE resource) and that
**the embedded driver's signature chain was never checked**.

If it no longer loads on a current build, **the entire architecture is moot and the mechanism decision
genuinely reopens.** Cost: one elevated VM and an afternoon. This is the highest expected-value hour in
the whole plan.

### P4-GATE-1 — Three-way stack bake-off, before any P4g effort

System stack vs. smoltcp vs. ipstack, on Windows/Wintun, forking `Watfaq/netstack-bench` as the harness.
Measure correctness against real Windows clients, concurrency to 4000 sockets, and the firewall
interaction. **2–4 weeks that plausibly removes 2–4 months of work.**

### P4-GATE-2 — Exclusion-route manager + adapter-teardown fail-safe, on a VM

Prove that **OS object lifetime** is the primary fail-safe — the adapter must never outlive the pump
process, and killing the process must remove every route with *no SSK code running*. Must land before
any capture route is ever installed.

### P4-GATE-3 — The per-app decision, with both prices attached

Either accept best-effort attribution and state the race honestly in the roadmap **and the GUI** (cost
S — but it is the cost of a claim downgrade, not a feature), or commit to a signed WFP ALE callout
(Block C: 3–6 months, kernel-mode code in a repo whose posture is `forbid(unsafe_code)` everywhere but
one crate, an EV certificate, and Microsoft attestation — certificate procurement and hardware-token
issuance alone is weeks of calendar time independent of engineering). **Decide before the roadmap is
republished with the full-coverage decision in it, and before P4b freezes `FlowDescriptor`'s shape.**

---

## 7. New sub-phases this investigation adds

| Sub-phase | Goal | Effort | Privileged? |
|---|---|---|---|
| **P4k** | Broker-owned, journaled, dynamic **exclusion-route manager** — replaces the struck `IP_UNICAST_IF` claim. Must land before any capture route is installed. | L | Yes |
| **P4l** | Pump-liveness dead-man's switch + OS-object-lifetime fail-safe; must ship in the same release as the first capture route. | S–M | Yes |
| **P4m** | Datagram dispatch spine — breaking change to `ssk-netcore::Transport`/`RouteKind`. | L | No |
| **P4n** | IP/CIDR match criteria in `MatchCriteria` — schema change, do during P4a while it is cheap. | M | No |
| **P4v** | Protocol sniffing for hostname recovery (TLS ClientHello SNI, HTTP Host) — restores policy expressiveness for unnamed flows. | L | No |

Plus everything in Block B's aggregate: wildcard UDP capture (L), conntrack + eviction + per-class
timeouts (M), **SOCKS5 UDP ASSOCIATE (M — confirmed missing: `ssk-netcore/src/socks5.rs:13` defines
only `CMD_CONNECT = 0x01` and `socks5.rs:108` sends only that, so the crate is TCP-only today
[VERIFIED-HERE]. Every UDP flow policy-routed to a SOCKS5 adapter is unroutable until this is
built)**, LAN/multicast/link-local exclusion (M), UDP app attribution (M), QUIC detection and
policy (M), honest `quic_downgraded`/`udp_blocked` state (S), dual-stack IPv6 (L), IPv6 extension-header
and fragment handling (M — smoltcp has none), v6 DNS takeover and v6 fake-IP (M), `IPV6_UNICAST_IF` (S),
Happy-Eyeballs leak analysis (S, blocking), auto-reply suppression (S, blocking), ICMP disposition (M),
non-TCP/UDP protocol matrix (M).

---

## 8. What this means for the roadmap

- P4's XL is **wrong** under the full-coverage mandate — see §5's three blocks.
- The `IP_UNICAST_IF` full-coverage claim in `P4_INGRESS_DESIGN.md` §4 is **struck** (annotated there).
- The smoltcp choice is **not settled** and must not be implemented before P4-GATE-1.
- Per-app steering has **no line item** and needs an explicit decision (P4-GATE-3).
- **P4-GATE-0 may invalidate the entire architecture** and should run before any other work.
