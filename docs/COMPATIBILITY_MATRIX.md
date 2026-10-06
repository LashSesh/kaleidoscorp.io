# Compatibility Matrix

## Local daemon audit ledger (2026-09-22)

The daemon now writes the additional `AuditOutcome::DispatchPending` before a
network attempt, followed by its terminal result. Existing ledger entries remain
readable and their hashes are unchanged. New entries use two sequence numbers per
attempt; consumers must not assume that one entry equals one completed connection.

This is a **one-way local ledger format extension**: older binaries cannot decode
`DispatchPending`. Do not downgrade a daemon against a ledger written by this
version. Preserve the ledger and use a compatible reader; no reverse migration is
provided. The IPC `AuditEntryDto.outcome` remains a string, with the additional
value `DispatchPending`; its field layout and command IDs are unchanged. Consumers
must display this value as pending/unknown, never as protected or dispatched.

## Peer interoperability

| Local | Peer | Result | Reason |
|---|---|---|---|
| 1.0.0 | 1.0.0 | ✅ Compatible | Same major, min-compatible satisfied |
| 1.0.0 | 1.0.x | ✅ Compatible | Patch-level compatible |
| 1.0.0 | 1.1.x | ✅ Compatible | Minor-level compatible in same major |
| 1.0.0 | 0.x.y | ❌ Reject | Major mismatch |
| 1.0.0 | 2.x.y | ❌ Reject | Major mismatch |

## Required Capabilities
- `gate-vector-12`
- `replay-v1`

Missing any required capability results in `CapabilityMismatch`.

## Decoder Modes
- `Strict` (default): canonical byte equality required.
- `Permissive` (opt-in): accepts non-canonical payloads for diagnostics only.


## Config v4 and routing (2026-09-22)

Versions 1–3 migrate in memory to v4 with deny-all routing. Valid v3 sections are
preserved; invalid modern configurations cannot fall back to legacy defaults.
New routing keys in old-version files are rejected. v4 requires a routing section;
explicit profile rules are necessary before daemon egress is allowed.

`RouteKind::OpenVpn` and `AdapterKind::OpenVpn` are new wire enum variants; older
clients cannot decode them. Use matching CLI/daemon/bridge builds for VPN profile
previews. OpenVPN activation remains unavailable (`OPENVPN_NOT_READY`). This is
not a backwards-compatible claim for older binaries. See
[implementation status and migration](ROUTING_AND_OPENVPN_STATUS.md).

## Route executor: no fallback route, bounded dial (2026-10-06)

`RouteExecutor::connect` and `probe` refuse `RouteKind::Fallback` with
`NetcoreError::NoRoute` (`NETCORE_NO_ROUTE`) before any socket is opened. Earlier
builds dialled the primary route and, on any error, the fallback route, which could
be `Direct`; a failed route never becomes another dial now. No planner emits
`Fallback` (a test pins that), so only a caller that builds the route by hand is
affected. The variant stays in `RouteKind` and the audit summary text
`Fallback(a | b)` is unchanged; `AuditOutcome::FallbackDispatched` stays decodable
but nothing produces it. Consumers must not read either as evidence that a fallback
exists or happened.

The whole dial (name resolution, every hop's TCP connect and every SOCKS5, HTTP
CONNECT and TLS handshake) is bounded by one deadline, 30 s by default
(`RouteExecutor::with_dial_deadline`), and expires as `NETCORE_TIMEOUT`; the 10 s
limit on a single TCP connect is unchanged. Earlier builds had no bound after the
TCP connect, so a proxy that accepted the connection and stayed silent held the dial
(and `probe`) forever. The daemon does not set this deadline; an activation is cut
earlier, see "Activation deadline and status during an activation".

Targets sent to an upstream changed in two ways. HTTP CONNECT brackets IPv6
authorities (`CONNECT [::1]:443`; earlier builds sent `::1:443`), and SOCKS5 sends a
bracketed literal as an IPv6 address (ATYP 0x04) instead of as a domain name. An
HTTP CONNECT target containing whitespace or a control character is refused before
any byte is written with the new code `NETCORE_INVALID_TARGET`, which appears as
`last_error.code` of a failed activation; codes are strings, and a client that does
not know this one shows it as unknown. An upstream that depended on the old
malformed authority must be adapted. No wire or ledger format changed.

## Policy suffix rules and address forms (2026-10-06)

A `dest_suffix` criterion (`domain_suffix` in a routing rule) now applies to DNS
names only. It never matches an IP literal (IPv4, IPv6, bracketed, with a zone id or
IPv4-mapped) and never matches a numeric IPv4 alias that the system resolver dials
as an address (`127.1`, `0x7f.0.0.1`, `010.0.0.1`, `2130706433`). A host counts as an
address when it parses as an IP address, contains `:`, `[` or `]`, or has a last
label that does not start with an ASCII letter. Earlier builds compared text, so the
suffix `0.1` matched `10.0.0.1` and a domain rule could capture (allow, redirect) or
mis-fire (deny) an address it was never written for. A flow that a suffix rule used
to match this way now falls through to the next rule or to the default deny, and the
rule id recorded for it changes with that. To address a literal use `dest_host` in
its canonical spelling: it compares literals by parsed address only, so `::1` does
not equal `[::1]` and `127.1` does not equal `127.0.0.1`. Label-boundary matching of
real names (case, leading and trailing dots, `10.0.0.1.nip.io`, punycode top-level
labels) is unchanged. Configuration validation still accepts a `domain_suffix` whose
last label starts with a digit, such as `0.1`, unless it parses as an IP address,
but such a rule can no longer match any host: a deny rule written that way never
fires. No wire or ledger format changed.

## IPC accept loop (2026-10-06)

On Unix, `sskd` no longer exits when one `accept()` on its IPC socket fails. It
sleeps 50 ms, doubling up to 1 s, and accepts again; a successful accept resets the
count. Only the 60th consecutive failure ends the server with `IPC_ACCEPT_FAILED`,
after about 55 s of back-off, and `sskd` then exits with code 1. Earlier builds
exited on the first failure, for example `EMFILE` under descriptor pressure or a
client that vanished while queued. This is a bounded grace period, not protection
against sustained descriptor exhaustion. The Windows named-pipe accept loop is
unchanged and still ends the server on its first accept error. Protocol, framing and
command ids are unchanged.

## Activation deadline and status during an activation (2026-10-06)

`ActivateProfile` bounds its dial with a daemon-owned 20 s deadline, shorter than the
executor's 30 s. Expiry takes the existing failure path: the ledger holds
`DispatchPending` and then a durable `FailClosed` result, the state is `FailClosed`
with `last_error.code = ACTIVATION_CONNECT_TIMEOUT` (a new string code that the
daemon's `ExplainError` answers), no session is kept, and no direct connection is
made instead. A single TCP connect that times out first (10 s) is still reported as
`NETCORE_TIMEOUT`, and a slow but live multi-hop dial is cut at 20 s. Before, the
only bound was the executor's 30 s, so a silent upstream kept every other request
waiting that long.

`GetStatus` no longer waits behind an activation. When it cannot take the daemon's
state lock within 100 ms while an activation is in flight, it answers
`DaemonState::Activating`, built fresh: no active profile, no adapters,
`dns_protected` false, no `audit_head`, and the kill-switch fields as the broker
reports them at that moment (also the only source of `last_error` in this answer).
The `Activating` variant and the shape of `StatusDto` are unchanged, so every client
decodes it; what is new is that a status read can return it, for up to 20 s, where it
used to block. Clients must show it as in progress, never as protected, and must not
read the empty fields as a statement about the previous session or the ledger: an
absent `audit_head` means not read. Every other request that needs the state lock
(`Deactivate`, `ListProfiles`, `TraceRoute`, `GetAuditEntries`, `VerifyAuditChain`,
`RunDoctor`, event subscription) still waits behind the dial. The adapter health
text of a held session changed from `live (real, connected)` to `connected at
activation; liveness not monitored`; it is free text, nothing in this repository
parses it, and consumers must not.
