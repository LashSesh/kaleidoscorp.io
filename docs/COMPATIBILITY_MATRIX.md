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
* A name that does not resolve is reported as `NETCORE_DNS_FAILED` where earlier builds
  reported `NETCORE_IO_ERROR`, and the message text changes with it. This holds for the
  destination of a `Direct` route and for a first hop that is a name, and it is the
  `code` that `ssk activate --dest name:port` shows, so a script that matched
  `NETCORE_IO_ERROR` for an unknown name has to match the new code. A connect error
  that is not a refusal stays `NETCORE_IO_ERROR`, and `NETCORE_CONNECTION_REFUSED` is
  now reported only when every answer refused; earlier builds reported what the last
  address tried returned.
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
each dial got its address. No wire, ledger or configuration format changed: the codes
above are values of the existing `code` string of the activation error.

## Dial order for Direct names (2026-10-07)

When `sskd` dials a host NAME itself, the destination of a `Direct` route
(`ssk activate --dest name:port`) or the `host` of an adapter that is a name, it no
longer tries the addresses of the answer one after another in the resolver's order. It
now starts with an IPv4 address and alternates the families (IPv4, IPv6, IPv4, ...,
keeping each family's order), starts the next address 250 ms after the previous one
started, or at once when the previous one failed, and keeps the first connection that is
established; the others are closed. The name is still looked up exactly once. What a user
can now see:

* A name with several addresses can connect through a later one while an earlier one is
  silent. Earlier builds spent the whole 10 s connect limit on a blackholed first address
  and never tried the rest. The limit is now one budget for all attempts of the dial,
  measured from the first attempt; `NETCORE_TIMEOUT` still means that budget ended.
* On a host with both families the connection now usually goes to an IPv4 address even
  where the resolver lists IPv6 first. An address that is only reachable over IPv6 is
  still tried (the activation path does not filter families).
* At most 8 addresses are tried (the first 32 were kept before); at most 64 attempts
  beyond the first of a dial can be in flight at once across all dials of the daemon, so
  a dial that finds none free starts its next address when an earlier one has failed.
  `NETCORE_CONNECTION_REFUSED` is still reported only when every address tried refused.
* `ssk-netcore` (a library, not a wire type) gains the seams the local proxy will use: an
  address guard that can refuse a whole answer, an address-family filter, and a connector
  through which every dial opens its socket. The activation path installs neither guard
  nor filter, so the two new `NetcoreError` variants that belong to them,
  `NETCORE_ADDR_REFUSED` and `NETCORE_FAMILY_DISABLED`, cannot occur there; a third,
  `DialFailed`, wraps the real error of a name dial that started a connect and reports its
  `code` and text unchanged. A Rust caller that matches `NetcoreError` exhaustively has to
  handle the new variants.

No wire, ledger or configuration format changed.

## Config schema evolution and document errors (2026-10-07)

**Config schema evolution.** `CURRENT_CONFIG_VERSION` stays 4 and this entry changes no
key, default or accepted document; it writes down when a later change needs a bump.
Compatible within a version, no bump: a new key that has a default, a new value in a
validated vocabulary, a widened range. Requires a bump, a step in the migration chain
(one step per version, `migrate_object_to_current`) and a test that an older version
cannot smuggle the new section: a new required section or key, a changed default, a
renamed or removed key, a narrowed range, a change of meaning of an existing value.
What an older build does with a file that uses something new depends on the section.
The top level and `routing` deny unknown keys, so it refuses the file and names the key
(one exception today: a `direct` or `deny` rule action ignores extra keys). `policy`,
`runtime`, `interop`, `system` and the other sections accept unknown keys, so an older
build loads such a file and ignores the new key; a change there must not rely on an
older build refusing it. A value of a typed vocabulary that an older build does not
know is refused with a message that lists the values it does know. Every change to the
exported schema (`ssk config schema`) or to its golden file,
`crates/ssk-config/tests/golden/ssk-config-v<N>.schema.json`, needs an entry in this
file; CI (`breaking_change_guard`) fails a change under `crates/ssk-config/src/` or in
that directory without one.

**Migration chain.** A version 3 document now migrates through one step per version
(`step_3_to_4` adds the deny-all `routing` section) instead of one hard-coded arm, so a
later version adds a step and nothing else changes. Behaviour is the same: a document
that declares version 3 and already has `routing` is refused with `routing requires
config version 4`, versions 1 and 2 keep their typed legacy shapes, files are never
rewritten and `migrated_from` is unchanged.

**Document errors.** A document that reads as YAML or TOML but does not fit the schema
(an unknown key, a missing key, a value of the wrong type, a YAML mapping key that JSON
cannot hold) is now reported as `invalid configuration document: ...` where it was
reported as `json serialization error: ...`, also for YAML and TOML input. The message
names the field; wording is not a contract, and `ssk config lint`, the daemon's
`ConfigInvalid` state and the exit codes are unchanged. `ssk_config::ConfigError`
(library API, not a wire type) has a new variant `Document(String)`; a Rust caller
that matches the enum exhaustively has to handle it. `ConfigError::Json` now means only
that a JSON value could not be built from our own defaults.

**Exported schema corrected, same documents.** `ssk config schema` listed two things that
never matched what the parser reads and writes: `interop.min_protocol` carried a pattern
that required a literal backslash, so no version string (the default `1.0.0` included)
satisfied it, and `privacy.adversary_model` listed `partial_network_observer` while the
value is read and written as `PartialNetworkObserver`. A tool that validated a
configuration file against the schema of an earlier build refused every file. The
pattern is now `^[0-9]+\.[0-9]+\.[0-9]+$` and the enumeration is `PartialNetworkObserver`;
the `$id` stays `ssk-config-v4.json`. No file that `sskd` loaded is refused and none that
it refused loads. The schema is written by hand and is not a complete description of the
parser: where it is looser or stricter than `sskd` (a name that is not a valid host, an
empty `system.name`, a repeated interop capability) the difference is listed in
`crates/ssk-config/tests/schema_contract.rs`, and a new one fails the build.
