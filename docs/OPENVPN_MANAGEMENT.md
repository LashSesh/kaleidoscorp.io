# OpenVPN management controller — 2026-09-22

`ssk-vpnctl` now implements the protocol and management-session lifecycle for a
broker-owned OpenVPN process. The Windows host now depends on this library
for [protected profiles and process ownership](OPENVPN_PROFILES_AND_PROCESS.md),
and now composes a [verified, held startup](OPENVPN_SECURE_START.md),
with [authorized broker preparation/stop and a service worker](OPENVPN_BROKER_CONTROL.md).
The broker cannot release HOLD. Configured VPN activation still returns
`OPENVPN_NOT_READY`. No interface-bound egress or running OpenVPN integration is
claimed by this step.

## Implemented contract

The controller expects a freshly launched client in management hold, with a
per-launch management password. It accepts an already connected transport; it
does not choose an endpoint, launch an executable or open a profile file.

| Step | Required observation | Effect |
|---|---|---|
| Management authentication | Exact password prompt, then positive acknowledgement | Send the owned password once; never retry a failed authentication |
| Process consistency | PID reply equals the owner's expected PID | Enable real-time state notifications |
| Initial hold | Hold observed and requested retry delay elapsed | Send the hold-release command |
| Connection | Release acknowledged and a valid CONNECTED report | `ConnectedUnverified`; no egress permit |
| Loss/reconnect | Hold or non-connected state after connection | Discard the connected indication; enforce a fixed reconnect deadline |
| Liveness | Periodic PID request acknowledged | Refresh management liveness; informational traffic cannot satisfy it |
| Stop | Termination command followed by management EOF | `ManagementClosed`; OS process exit remains unconfirmed |
| Any terminal error | Protocol/authentication/I/O/timeout/unsupported interaction | `Failed`; close the transport and retain the first typed cause |

Only fixed commands are emitted. At most one reply is outstanding. An asynchronous
state, hold or error notification is processed while a command reply is pending;
it cannot masquerade as that reply. A stop requested during an outstanding command
waits for its reply under the existing deadline, then sends termination. It never
continues startup or releases another hold after stopping begins.

## Bounds and sensitive data

- Decoder limit: 8,192 bytes including any CR, before UTF-8 interpretation. It
  accepts CRLF/LF and a fragmented password prompt without a newline. Malformed,
  unsupported or overlong messages poison the decoder permanently.
- Each client poll reads at most 1,024 bytes. Read/write waits are capped at 100ms
  and shortened to the nearest lifecycle deadline. TCP partial writes share one
  absolute deadline. Injected transports must obey the same contract.
- Defaults: startup 30s, command 3s, reconnect 30s, heartbeat interval 5s and stop
  5s. Limits must be positive and no greater than 300s. Deadlines use local
  monotonic time; peer timestamps and repeated progress/log messages cannot move
  them. A failed heartbeat or stop is terminal, not a reason to preserve health.
- Server-provided diagnostic text, challenge contents and error text are
  discarded. Events/errors expose typed categories only. Passwords and command
  buffers are owned, non-cloneable and zeroized on drop; intermediate read/decoder
  buffers are zeroized, including on failure. Debug output redacts the password.
  This is not a guarantee that the OS, transport implementation or caller never
  copied secret data.
- VPN credentials, MFA, token confirmation and external-signing requests are
  unsupported and fail closed. The controller neither approves prompts nor
  submits arbitrary commands or application credentials.

`Client::poll` must run continuously on a dedicated worker. `last_snapshot` is
explicitly historical and carries its local observation time. It is not a current
readiness guarantee if the owner stops polling. `Session` is the deterministic
core for injected transports and virtual-clock tests; its owner must call `tick`
even if no messages arrive.

## Protocol reference and compatibility boundary

The implementation uses the [official management protocol specification](https://openvpn.net/community-docs/management-interface.html)
and checks exact prompts, replies and state-row layout against
[OpenVPN v2.6.14 manage.c](https://github.com/OpenVPN/openvpn/blob/v2.6.14/src/openvpn/manage.c).
That pinned source is a reproducible protocol reference, not a recommendation to
ship that version. No installed OpenVPN binary or live VPN server has been tested.
The supported subset deliberately excludes history/status tables and arbitrary
commands; unexpected acknowledgements and unknown state names are errors.

Management password authentication is not mutual authentication. Loopback and a
reported PID do not prove server identity. The future host must establish endpoint
and executable/process ownership before sending secrets. In particular, this
library must not become a generic command relay from unprivileged IPC.

## Host and broker integration

The [secure host preparation](OPENVPN_SECURE_START.md) now verifies an approved
executable/DLL bundle, generates protected launch files, establishes kernel TCP
peer ownership and composes the job process with `ManagedProcess::new_held`.
`Session::new_held` and `Client::new_held` authenticate/subscribe/heartbeat but
cannot send hold release. `PreparedHeld` requires all setup checks and an observed
HOLD; it never means connected or admitted. The existing automatic constructor
above is not used by the host's preparation path.

Authorized/audited broker operations and service worker ownership are now
[implemented](OPENVPN_BROKER_CONTROL.md). Still required: profile installation/update,
supported recovery, and verified interface/route/DNS/kill-switch behavior. Neither `PreparedHeld` nor `ConnectedUnverified` satisfies those gates.
Real OpenVPN distribution and privileged VM acceptance are still outstanding.

## Tests

The new crate has decoder, virtual-clock lifecycle and real loopback TCP tests.
The TCP peer is an independent scripted fixture, not an OpenVPN subprocess. Tests
cover fragmented/coalesced messages, interleaved notifications, IPv4/IPv6 state
records, malformed/oversized input, wrong PID/password, secret redaction, unsupported
credentials, fixed deadlines under noisy peers, reconnect hold, unexpected EOF,
partial-write failure, graceful management close and socket teardown on Drop.

Run `cargo test -p ssk-vpnctl --locked`. The existing workspace CI picks up this
member in its build/test/Clippy/format jobs. The later profile/host step deliberately
adds one daemon dependency; see ADR 0008's addendum. Windows local test evidence lives in `target/restart-audit/vpnctl-*.log`.


Initial management-only validation (before profile/process work): **20 new tests; 1,179 workspace tests passed, 0 failed,
1 pre-existing ignored generator**. Workspace all-targets build, Clippy with
`-D warnings` and `cargo fmt --all -- --check` passed. The existing daemon tests
still prove that a configured OpenVPN route fails without direct fallback, and
the daemon dependency closure was still 16 crates at that stage. No Linux execution,
live OpenVPN process/server or privileged VM acceptance was performed here.
