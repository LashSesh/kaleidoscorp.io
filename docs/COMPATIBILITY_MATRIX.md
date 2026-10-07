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

## Config v5 and the local proxy (2026-10-07)

Version 5 adds the required `ingress` section (disabled by default; every field inside
it has a default, so `ingress: {}` is valid). Versions 1 to 4 migrate in memory to v5
with the ingress disabled; files are never rewritten, and a file that loaded before
still loads, including one whose routing has an adapter on `127.0.0.1:10800` or an IPv6
literal host (the section is checked against routing only when `enabled` is `true`).
A v5 file is rejected by older builds with `UnsupportedVersion`. A section introduced
by a version is rejected in a document that declares an older version (`ingress
requires config version 5` in a version 3 or 4 document). `CURRENT_CONFIG_VERSION` is 5
and `ssk config schema` reports `ssk-config-v5.json`; the exact schema is pinned in
`crates/ssk-config/tests/golden/`. `ssk config lint` named `v2` as the version it had
migrated to, whatever the file was; it now names the current one.

Unlike the older nested sections, which ignore unknown keys, `ingress` and each of its
parts (`listen`, `limits`, `audit`) deny them, and each is read from a map only (a list
is refused), so a misspelled key or a stray list never keeps a default. `protocols` is a
list of validated names: this build accepts `socks5` and refuses anything else with
``unsupported ingress protocol `http_connect`; this build supports: socks5``, naming what
it does support; a later `http_connect` is a new value of that vocabulary, not a new
config version. No key names a VPN, an interface, a source address or a credential. A
loopback `listen.address` (`127.0.0.0/8`) is required, `listen.port` may be `0` (the OS
chooses; for tests), every number has a floor and a ceiling, `0` never means unlimited,
and `audit.segment_mib x audit.retain_segments` may not exceed 1024 MiB. With the
section enabled, a routing adapter on the listener's own address and port (`localhost`
or any loopback address) is refused, and so is an IPv6 literal adapter host while
`direct_address_families` is `ipv4_only`. The numbers live in one table
(`ssk_config::ingress::bounds`) that validation, the schema and the generated example read.

Defaults (the owner's, pending confirmation before the first release tag; once a release
is tagged, changing one needs a new config version): loopback `127.0.0.1` port `10800`,
`protocols: [socks5]`, `hardening: required`, `arm_on_start: false`,
`direct_address_families: ipv4_only`, ledger retention by size only (32 MiB x 8 segments,
no age key), `audit.destination_logging: plain` (`hashed` is the other value), and
256 connections, 50 accepts per second, a 10 s handshake, a 20 s dial and a one hour idle
timeout. This build validates the section when the file loads; it opens no listener, so
`enabled: true` has no effect yet.

`ssk_config::ConfigError` (library API, not a wire type) has a new variant
`Ingress(String)`; a Rust caller that matches the enum exhaustively has to handle it.
`AppConfig` has a new required field `ingress`. Complete files to start from are generated
by `cargo run -p ssk-config --example ingress_config` and `coexistence_config` into
`docs/examples/`, and a test fails when either differs from its generator.

## Configuration fingerprint (2026-10-07)

`ssk_config::fingerprint` (library API, new) computes the three digests of a
configuration, `ConfigFingerprint { version, config, routing, ingress }`, and, for one
profile, what the ingress ledger's `Armed` record carries: a profile digest and a rule
table (`of`, `armed`, `ArmedFacts`, `RuleTable`, `RuleRow`). Nothing calls it yet and
nothing is written, so this build changes no file, wire message or ledger. It is recorded
here because the ledger will persist the three digests in its `Started` record and the
profile digest and rule table in `Armed`: the view structs the digests are computed over
are therefore part of a persisted format, and what an auditor recomputes from an archived
configuration file must keep agreeing with what the ledger holds.

Format version 1 (`FINGERPRINT_VERSION`). Each digest is the blake3 hash, as 64 lowercase
hex characters, of the canonical CBOR (`ssk_types::digest_of`) of an explicit view struct,
never of `AppConfig` itself. `routing` covers `default_profile`, the adapters sorted by id
(kind in the file's spelling, then host and port or the profile id) and the profiles
sorted by id with their rules sorted by `(priority, id)`, every rule field included (the
action as `direct`, `deny` or `adapter:<id>`). `ingress` covers every key of the validated
ingress section, `destination_logging` included. `config` covers those two and nothing
else. A profile's display `name`, the order of the three lists, the file's `version`
number and every section outside `routing` and `ingress` do not move a digest. The `Armed`
profile digest covers that profile's view plus the adapters its rules reference; the rule
table lists at most 256 rules in evaluation order (id, priority, action label, attestation
flag, whether an exact destination exists, whether a suffix exists, port) and never the
text of a destination or suffix, and `total` and `truncated` say when it is cut.

A change of this format needs a new `FINGERPRINT_VERSION` and an entry here: a field of a
view added, removed, renamed or moved, a changed spelling or sort key, a different hash or
encoding (an update of the CBOR writer behind `ssk-types` that alters bytes would make
every archived digest unverifiable). `crates/ssk-config/tests/fingerprint.rs` pins exact
digests for fixed configurations and `src/fingerprint.rs` pins the encoded bytes of the
default views. The views are built by naming every field of the routing section, its
profiles, rules and adapters and the ingress section, and every variant of the enums
inside them, so a new key or variant there stops the build until its place in the
fingerprint is decided; a new key in any other section changes no digest. `of`
returns a `Result` (`FingerprintError`): serialising a view cannot fail today, and a
fingerprint must not fall back to an invented value if it ever does.

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
absent `audit_head` means not read. `InspectFlow`, `ListRecentFlows`, `ExplainError`
and `SubscribeEvents` never take the state lock and answer at once; how the other
requests behave during a dial is described in "Requests during an activation" below.
`SubscribeEvents` only answers `Ack`: the server writes one `Response` per `Request`
and no IPC client receives events yet. The adapter health text of a held session
changed from `live (real, connected)` to `connected at activation; liveness not
monitored`; it is free text, nothing in this repository parses it, and consumers
must not.

## Requests during an activation (2026-10-07)

An `ActivateProfile` dial (at most 20 s) holds the daemon's state lock. Besides
`GetStatus`, the other requests no longer queue behind it, except a `Deactivate`
(last item):

* `ListProfiles` and `RunDoctor` answer at once: they read the startup configuration
  and the environment, not the state the dial holds.
* `TraceRoute`, `GetAuditEntries` and `VerifyAuditChain` do need that state. When an
  activation is in flight and the state lock is still taken after 100 ms, they answer
  an error with the new code `DAEMON_BUSY` (class `Runtime`, `retriable: true`) and
  change nothing, instead of waiting for the dial. With no activation in flight they
  wait for any other holder, as before. A client retries once the activation has
  ended; a client that does not know the code shows it as unknown, like any string
  code.
* At most two requests that change the state (`ActivateProfile`, `Deactivate`) are in
  flight at once: the one holding the lock and one waiting for it. A third answers
  `DAEMON_BUSY` at once, writes no ledger entry and emits no event. Reason: the IPC
  server serves 16 connections at a time and a waiting request keeps its connection;
  an activation and 15 waiting requests left a 17th client's `GetStatus` unserved for
  the whole dial (measured).
* `Deactivate` still waits for an activation that was accepted before it, up to the
  activation deadline. The lock is first come, first served, so its result is applied
  after the activation and is not overwritten by it.

Closing a held session, in `Deactivate` and in the watchdog that records a lost worker
task, now waits at most 1 s for the graceful close and then drops the transport, which
closes it. Before, a peer that never read could keep the state lock, and with it every
request above, for as long as it liked.

The text of the `KILL_SWITCH_ARMED` refusal of a `Deactivate` while the daemon is
fail-closed changed from "kill switch is armed; ..." to "the daemon is in its
fail-closed state; pass release_kill_switch=true to deactivate anyway", and its
`ExplainError` text with it. The code, the class and the behaviour are the same: the
refusal was always about the daemon's own state, and `release_kill_switch` never
reached the firewall rule, which the privileged broker owns. Messages are free text,
not a contract. `ExplainError` also answers `DAEMON_BUSY` and the `NETCORE_*` codes
that `last_error.code` can carry (it said "unknown error code" for them). No request,
response or DTO shape and no ledger format changed.

## Daemon shutdown and the daemon lock (2026-10-07)

`sskd` now keeps its daemon lock until the process has ended. Before, it released the
lock as soon as its serve loop returned and only then dropped its async runtime, so a
second `sskd` could take the lock, and extend the same audit ledger, while the first
was still dropping tasks. One of those tasks writes: an `ActivateProfile` that is
mid-dial when the daemon stops gets its terminal `FailClosed` ledger record when the
runtime drops it. That record is now written before the lock can be taken, when the
write finishes within the runtime stop bound described below (measured on Linux:
SIGTERM during a dial to a silent proxy; the successor that took the lock first saw
only `DispatchPending` before, in 12 of 12 runs).

What an operator or a service manager can see: a new `sskd` started right after the
old one was signalled, without `--lock-wait`, is refused with `DAEMON_ALREADY_RUNNING`
until the old process has exited (under 10 ms measured); `--lock-wait <ms>` covers that,
as it always did. The old process no longer waits for its runtime's blocking work without
a bound: the runtime is stopped with `Runtime::shutdown_timeout`, which waits at most 1 s
after Ctrl-C, Ctrl-Break, SIGTERM, a service stop or an end of the IPC server, and at
most 200 ms after console close, logoff, system shutdown or service pre-shutdown;
blocking work (name resolution) still running by then is abandoned with the process. The
`sskd stopping` log line carries `runtime_stop_ms` in place of `drain_budget_ms` (a fixed
2000, the ceiling on a `yield_now` that returns at once).

That bound also covers the `FailClosed` write above: the runtime drops its tasks on
threads the bound waits for, so a write that takes longer than the bound is cut off
where it stands when the process exits. The ledger file stays whole (it is rewritten
through a temp file and a rename) but lacks the record, so the activation's
`DispatchPending` has no result, as after a crash. The write verifies and rewrites the
whole ledger, so its time grows with the ledger and with a slow or busy disk. On a fast
local disk with a one-entry ledger the whole stop took under 10 ms; nothing has measured
it against the 200 ms on a large ledger, a slow disk or Windows, and that is an accepted
risk, not a verified margin. The lock is held in that case too, so no second daemon
appends in between.

The Windows reasons and times are UNVERIFIED: nothing here has run on Windows. No wire,
configuration or ledger format and no exit code changed.

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

## IPC compatibility (protocol 1) (2026-10-07)

`StatusDto` gains `protocol` (the IPC protocol the daemon speaks; this build sends
`ssk_ipc::IPC_PROTOCOL_VERSION`, which is 1) and `ingress` (the local proxy's block,
below). `FlowSummaryDto` gains optional fields (`peer`, `peer_verified`, `route`,
`matched_rule`, `reason_code`, `bytes_up`, `bytes_down`, `started_ms`, `ended_ms`,
`audit_pending_seq`, `audit_result_seq`, `front_end`, `egress_local`,
`destination_form`). `RouteTraceRequest` gains the optional `profile_id`, and
`RouteTraceDto` the optional `profile_used`, `profile_source`, `evaluated_as`,
`app_id_used`, `refusal` and `guards_skipped`. `Request::SetIngress`,
`Request::GetIngressAudit` and `Response::IngressAudit` are new. Protocol 0 is every
earlier build: its status has no `protocol` key, which reads as 0. Until the first
release tag, protocol 1 is the whole of M2 and further additions to it stay additive.

**Older client, newer daemon.** Everything the client knew keeps working: the twelve
requests of protocol 0 decode byte for byte (the frames of build `b62c4c8` are pinned in
`crates/ssk-ipc/tests/wire_protocol0.rs`), and fields the client does not know are
ignored. Measured with an `ssk` built before this change against a daemon built from it:
`status`, `--json status` and `list-profiles` answer as before.

**Newer client, older daemon.** An older daemon cannot decode `SetIngress` or
`GetIngressAudit`: it closes the connection without an answer (measured against a daemon
built before this change), which the client library reports as the retriable
`IPC_IO_FAILED`, exactly what a crashed daemon looks like. It decodes a `TraceRoute`
that carries `profile_id` and ignores the field, so it answers for its own choice of
profile, which is a wrong answer and not an error. A client that needs protocol 1
therefore reads `StatusDto.protocol` from a `GetStatus` first, which every daemon
answers, and refuses below it with the new code `DAEMON_TOO_OLD` (class `Runtime`,
`StatusDto::require_protocol`); it sets `profile_id` only then, and reads a preview
whose `profile_used` is absent or another profile as "not honoured". `ingress: None`
likewise means only "this daemon predates the proxy". A running daemon keeps executing
the binary it was started from, so `sskd` has to be restarted after an upgrade; an older
client sends nothing a daemon could inspect, so it cannot be warned about newer
features.

**Rules for later changes.** A new capability is a new request variant; a new field on
an existing request is allowed only where ignoring it still yields a correct answer. No
new variant in an enum that an older client decodes (`DaemonState`, `Response`, `Event`,
`RouteKind`, `PolicyAction`, `AuditOutcome`) without a protocol bump and an entry here.
`Response::IngressAudit` is the one new `Response` variant of M2; a protocol-0 client
never receives it, because it never sends `GetIngressAudit`. New vocabularies (the
ingress `state`, `coverage`, outcome and reason words) are strings with a documented
closed set, and a client renders a word it does not know as unknown. No IPC type denies
unknown fields; a test pins that for every type. `clamp_request_limits` has no catch-all
arm any more, so a new `Request` variant does not compile until it is listed as sized or
size-free; `GetIngressAudit.limit` is cut to 1000 like the other lists.

**What this build sends.** It opens no proxy listener yet. The `ingress` block is always
present and says `state: "disabled"`, `coverage: "none"` and `system_wide: false`, with
a fixed notice of what the coverage would be; everything else in it is the unknown
default (empty words, zero counters, no digests). The answer built during an activation
carries the same block. `SetIngress` (arm or disarm) and `GetIngressAudit` answer the
refusal `INGRESS_DISABLED` (class `Config`, not retriable, nothing changed, no ledger
entry). `ListRecentFlows` still answers an empty list and `InspectFlow`
`FLOW_NOT_FOUND`, so the new `FlowSummaryDto` fields are never sent. A `TraceRoute`
answer now names the profile it used (`profile_source` is `active_session` or
`default_profile`, `evaluated_as` is `legacy_activation`) and the application id
(`app_id_used`); the request's `profile_id` is not acted on yet.

**`ssk --json status|activate|deactivate`** prints the whole status under `state`, so
its output gains the keys `protocol` and `ingress` (an object) there; consumers must
ignore unknown keys. The human `ssk status` line is unchanged.

**Rust API (library, not wire).** A caller that builds a `StatusDto`,
`RouteTraceRequest` or `RouteTraceDto` with a struct literal has to name the new fields;
`StatusDto`, `FlowSummaryDto`, the ingress types and `DaemonState` (default `Inactive`)
implement `Default`, so `..Default::default()` is enough where a daemon that reports
nothing else is meant. A caller that matches `Request` or `Response` exhaustively needs
arms for the new variants.
