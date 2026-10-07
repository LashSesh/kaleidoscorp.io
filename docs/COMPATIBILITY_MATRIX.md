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
labels) is unchanged. Configuration validation used to accept a `domain_suffix` whose
last label starts with a digit, such as `0.1`, unless it parsed as an IP address,
although such a rule can no longer match any host: a deny rule written that way never
fires. It refuses such a suffix now, see "Host grammar in routing configuration". No
wire or ledger format changed.

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
(a second `ActivateProfile`, `Deactivate`, `ListProfiles`, `TraceRoute`,
`GetAuditEntries`, `VerifyAuditChain`, `RunDoctor`) still waits behind the dial.
`InspectFlow`, `ListRecentFlows`, `ExplainError` and `SubscribeEvents` never take that
lock and answer at once. `SubscribeEvents` only answers `Ack`: the server writes one
`Response` per `Request` and no IPC client receives events yet. The adapter health
text of a held session changed from `live (real, connected)` to `connected at
activation; liveness not monitored`; it is free text, nothing in this repository
parses it, and consumers must not.

## Host grammar in routing configuration (2026-10-06)

A routing rule `destination`, a rule `domain_suffix` and an adapter `host`
(`socks5`, `http_connect`, `tls_tunnel`) now share one host grammar, and it is
narrower than before: **a configuration file that loaded before can now be
refused**. The daemon then starts in `ConfigInvalid` with `invalid routing
configuration: ...`, `ActivateProfile` is refused, `ssk config lint` reports the same
error, and status and diagnostics stay available. Nothing is rewritten:
`CURRENT_CONFIG_VERSION` stays 4, no migration step touches these values, and the file
has to be edited by hand. Error wording is not a contract.

Refused now:

* A host whose last label does not start with an ASCII letter, with or without one
  trailing dot: `127.1`, `0x7f.0.0.1`, `010.0.0.1`, `2130706433`, `0.1`, `1`,
  `127.0.0.1.`. The system resolver dials such spellings as IPv4 addresses that
  `IpAddr` does not parse, and the old label grammar took them for names. Write the
  dotted-quad address (`127.0.0.1`) instead. Real names are unaffected: a top-level
  label starts with a letter, punycode `xn--` included, and digits in earlier labels
  stay valid (`10.0.0.1.nip.io`, `1password.com`).
* A rule `destination` that is an IPv4-mapped IPv6 address in any spelling
  (`::ffff:10.0.0.1`, `::ffff:a00:1`). It spells an IPv4 address a second way, and
  policy compares literals by parsed value, so such a rule never matched the plain
  IPv4 flow it was written for and a deny rule written this way did not deny it.
  Write the IPv4 address. Other IPv6 literals (`::1`, `2001:db8::1`) are unchanged,
  and an IPv4-mapped adapter `host` is still accepted.

Unchanged: IP literals stay valid as destinations and adapter hosts, a name may be
upper case and carry one trailing dot, labels are at most 63 and names at most 253
bytes, and a `domain_suffix` is still never an IP literal. The JSON schema does not
describe host syntax and is unchanged.

`ActivateProfile` (`ssk activate --dest host:port`) applies the same host check to its
destination: a numeric alias is answered `DEST_INVALID` before policy, audit or any
dial. Earlier builds evaluated policy for the alias text and, where a rule without
destination or suffix matched everything, handed it to the dialer, which connects to
the address the alias spells. No wire or ledger format changed.

## Name lookup for Direct dials (2026-10-07)

A host NAME that `sskd` dials itself, that is the destination of a `Direct` route
(`ssk activate --dest name:port`) or the `host` of an adapter that is a name, is now
looked up by the operating system's resolver exactly once per dial, through a bounded
resolver, and the dial then goes to the answers it got. Earlier builds handed the name
to tokio's `TcpStream::connect`, which ran an unbounded `getaddrinfo` inside the 10 s
connect limit and tried the answers in turn. What a user can now see:

* A lookup is cut after 5 s as `NETCORE_TIMEOUT`, and the lookup time no longer counts
  towards the 10 s connect limit, which now starts after the answer. The 30 s dial
  deadline still bounds the whole dial, and the 20 s activation deadline still cuts an
  activation earlier, so a slow resolver that answered after 5 to 10 s used to succeed
  and now fails.
* At most 16 lookups run at once. A 17th waits up to 500 ms for a free slot and then
  fails with the new code `NETCORE_RESOLVER_BUSY`; at most 32 dials wait, the next one
  fails at once. Literals and proxied targets never wait. A lookup that was cut still
  holds its slot until the operating system's call returns, so an activation can meet
  the new code when 16 earlier lookups are still stuck there (a dead DNS server). A
  client that does not know the code shows it as unknown.
* Answers are cleaned before the dial: an IPv4-mapped IPv6 answer is dialled as the
  IPv4 address, duplicates are dropped and the first 32 are kept. The name is not
  looked up again for the next answer or after a refusal.
* A host that is neither an IP literal nor a plain DNS name is refused with
  `NETCORE_INVALID_TARGET` before any lookup. Nothing that configuration validation or
  `--dest` accepts is newly refused (the host grammar of "Host grammar in routing
  configuration" is the same list); what changes is a caller that reaches the executor
  without that validation, for example a name with an underscore or an IPv6 zone id.
* `dns_protected` is unchanged: `true` only for an IP-literal destination, so it stays
  `false` for a `Direct` name, whose lookup the operating system's resolver did.
  Proxied routes still hand the name to the upstream proxy unresolved.

`EgressSession::resolution()` (library API of `ssk-netcore`, not a wire type) says how
each dial got its address. No wire, ledger or configuration format changed.
