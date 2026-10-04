# OpenVPN secure preparation — 2026-09-22

**Follow-up:** [VPN broker control](OPENVPN_BROKER_CONTROL.md) now wraps this held
preparation in authorized/audited service operations. The text below records the
startup component increment; its then-pending broker gate is now implemented.
[Crash recovery](OPENVPN_RECOVERY.md) subsequently added suspended creation and
durable process identity before execution in the production broker path.

The production `PreparedVpn::prepare_tracked` path now receives a validated profile
from the broker's [fixed configuration snapshot](OPENVPN_CONFIGURATION_DEPLOYMENT.md).
The original public unaudited convenience entry points have been removed. It composes
an administrator-approved executable bundle, fresh launch files,
a Windows job, a reserved reverse-management endpoint and continuous management
supervision. It returns only after authentication, kernel peer ownership checks,
PID consistency, state subscription and a HOLD notification. It **cannot release
HOLD**, grant egress or connect application traffic. There is no new broker/CLI
command, service worker or live VPN acceptance claim in this increment.

## Trust and launch sequence

1. Open the existing protected profile store. Read its fixed
   `openvpn-installation.json` with file confidentiality, reparse and hardlink
   checks; use the strict profile already resolved by logical ID from the same
   service-lifetime snapshot as its grants.
2. Validate the bundle manifest and its absolute local directory. Walk the
   executable/parent ACL chain, reject all reparse tags, and refuse non-admin
   write/attribute/EA permissions on the bundle and its files. Match the complete
   directory inventory against the manifest, then hash every approved file.
3. Keep read handles denying write/delete sharing for **all** approved executable
   and DLL files for the lifetime of the prepared session. A filename check or an
   executable-only hash is insufficient. No registry/PATH discovery is performed.
4. Reserve an exclusive, ephemeral `127.0.0.1` listener **before** launching the
   child. `SO_EXCLUSIVEADDRUSE` is set before bind. Management uses IPv4 loopback
   independently of the VPN profile's remote address family.
5. Generate 32 random bytes using the OS CSPRNG and encode a fresh 64-character
   management password. Create randomly named `.pw`/`.ovpn` files in the protected
   store with `create_new`; check inherited confidentiality before writing,
   synchronize them and retain read locks. The password is never an argument,
   environment variable, log field or error detail.
6. Launch the approved absolute `openvpn.exe` in its job with only
   `--config <owned config path>`. Use a fixed environment and approved working
   directory; no shell, console window, inherited handles, PATH or user environment.
7. For each accepted socket, query Windows' TCP owner table and require the exact
   reverse IPv4 address/port tuple, ESTABLISHED state and owned child PID. Check the
   still-held process handle before and after that observation. A foreign peer is
   closed **without reading or writing protocol bytes**. Its repeated attempts do
   not extend the startup deadline. Exactly one accepted, verified peer is used;
   the listener then closes and the host never reattaches by PID or endpoint.
8. Authenticate, check the protocol's PID as an additional consistency check,
   subscribe to state, and confirm HOLD. Return `PreparedHeld`; continue heartbeat
   and process polling. Unexpected state claims, protocol errors, authentication
   failures, dead peers and timeouts terminate the owned job.

The endpoint implementation uses a DWORD-aligned buffer, a 4 MiB table cap and at
most three fetch attempts under table growth. It rejects truncated tables. The
[Windows TCP table API](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
provides the OS ownership observation; a self-reported PID is not its substitute.
Retained handles and a dedicated privileged worker are part of the trust model.
This does not protect against a compromised administrator or kernel.

## Administrator-approved bundle

The manifest is a strict JSON document, at most 16 KiB. Unknown/duplicate fields,
duplicate file entries, unsupported schema/protocol, nonlocal or ambiguous paths,
alternate streams and malformed hashes are errors. A conceptual manifest is:

```json
{
  "schema": 1,
  "protocol": "openvpn-2.6",
  "directory": "C:\\Program Files\\ScorpioSync\\OpenVPN",
  "files": [
    { "name": "openvpn.exe", "sha256": "<64 lowercase hex characters from the approved build>" },
    { "name": "libcrypto-3-x64.dll", "sha256": "<its separately approved SHA-256>" }
  ]
}
```

The placeholders deliberately fail validation. Enumerate every actual binary in
an approved **flat** bundle: exactly `openvpn.exe` plus named `.dll` files, at most
32 files, 64 MiB per file and 256 MiB total. Missing, extra, modified, nested or
multiply linked files are refused. This first layout is not an automatic importer
for a stock OpenVPN installation. Installation, updating and dependency selection
remain deployment work; stop prepared sessions before replacing pinned files.

The manifest itself must be installed through an authorized administrative
workflow. SHA-256 proves equality to that approved manifest, not publisher identity
or vulnerability-free software. Hashing an arbitrary local binary does not make it
trustworthy. `protocol: openvpn-2.6` selects the supported protocol contract; it is
not an executable version probe or a recommendation to deploy an old patch release.
No Authenticode, release download or automatic update policy is claimed.

The child receives only `SystemRoot`/`WINDIR` from `GetWindowsDirectoryW`,
`OPENSSL_CONF=NUL` and `OPENSSL_MODULES=<approved bundle>`. This removes inherited
OpenSSL configuration/module overrides; see the
[OpenSSL environment documentation](https://docs.openssl.org/3.0/man7/openssl-env/).
Actual OpenVPN/OpenSSL distribution compatibility still needs VM validation,
including system DLL dependencies outside the bundle. The low-level generic
`JobChild::spawn` remains a same-token primitive; only this composed entry point
performs the approval checks.

## Held management and cleanup

The config adds fixed `management-client`, `management-hold`, password-query and
bounded management-log settings; it also includes `ifconfig-noexec`. The
[OpenVPN management options](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html)
define reverse TCP connection and exit on management disconnect. HOLD suspends
initial tunnel setup until an explicit release; see the
[management protocol](https://openvpn.net/community-docs/management-interface.html).

`Session::new_held`, `Client::new_held` and `ManagedProcess::new_held` have no
hold-release operation. A prepared session continues heartbeats after the startup
deadline; reaching that state requires observed HOLD plus completed authentication,
PID verification and subscription. Claiming CONNECTED in this mode is a failure.
The existing automatic management-session constructor remains separate and is not
used by `PreparedVpn`.

The host startup deadline is shared across accept and authentication (default
30 seconds after process creation); rejected peers do not restart it. A dedicated
worker must continuously poll the returned object. Snapshots are historical, never
admission permits. Graceful stop still needs OS exit confirmation. Startup failure
requests job termination and polls the handle for up to two seconds; the error
reports whether exit was confirmed. Unconfirmed cleanup is not reported as success.
`abort_and_confirm` provides the same explicit confirmation for callers.

Only the two freshly claimed run files are removed on normal drop/failure. The
process/management owner is dropped before file and executable guards. A host
crash or failed deletion can leave protected run files; they are not reused or
silently swept, and deletion is not secure erasure. The later [recovery operation](OPENVPN_RECOVERY.md) cleans the recorded attempt
after OS exit proof; unrecorded leftovers and general retention remain open.

## Broker boundary and next integration

Inspection confirmed that the current broker command envelope, idempotency cache,
status response and durable journal all describe the kill-switch security domain.
A VPN operation must not borrow an unrelated kill-switch grant or report success
through a kill-switch-only response. No privileged launch command was enabled.

The next broker increment needs a distinct VPN operation/status contract, explicit
per-verb/profile authorization, durable intent/result records, idempotency and
service-owned worker lifetime. A worker may invoke this **held** preparation only
once those gates have accepted the request. Service cancellation and restart must
preserve enforcement, report real process termination and account for crash
leftovers. Tunnel release, interface-bound admission, route/DNS rules and kill-switch
coupling remain a separate gate, with disposable Windows VM acceptance. Existing
configured VPN routes still return `OPENVPN_NOT_READY` without direct fallback.

## Verification boundary

New checks cover held-mode heartbeat/timeout behavior, exact TCP ownership,
exclusive bind, foreign peers receiving no bytes, complete bundle hashing, file
locking, fresh passwords, temporary-file cleanup, malformed manifests and ACL
refusals. A standalone Rust fixture compiled during tests acts as the management
peer in an actual job-contained subprocess. It reads the generated config and
password, exercises the full composed path and can refuse authentication, lie about
its PID, claim CONNECTED while held, exit, remain silent or ignore shutdown.

The fixture is **not OpenVPN**. Tests inject trusted ACL observations for temporary
bundle/store paths, while process creation, sockets, owner-table queries, hashing,
file locks and termination are real Windows operations. No real VPN server/client,
SYSTEM installation, network route, firewall rule or service registration was tested
or changed. The 17-crate daemon workspace closure remains unchanged.

Local validation logs: `target/restart-audit/vpn-launch-*.log`.

Validation completed: **1,221 workspace tests passed, 0 failed, 1 existing ignored
golden generator**, including doc-tests; 15 test cases were added in this increment.
Windows workspace/all-targets build and Clippy (`-D warnings`), formatting and diff
checks passed. Linux all-targets Clippy for `ssk-vpnctl`/`ssk-winhost` also passed;
no Linux execution was performed. The exact 17-crate dependency-closure guard and
decision-core exclusion checks remain green.
