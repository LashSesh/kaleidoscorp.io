# OpenVPN profiles and process ownership — 2026-09-22

This increment adds strict profile parsing and an owned-process supervisor in
`ssk-vpnctl`, plus protected profile storage and real Windows job containment in
`ssk-winhost`. They are tested building blocks for the privileged broker. There
is now [held preparation/stop through the broker](OPENVPN_BROKER_CONTROL.md), but
no raw profile import, live OpenVPN acceptance or interface-bound
egress. The later [secure preparation](OPENVPN_SECURE_START.md) now composes these
components with bundle verification and kernel-verified management endpoint ownership. Configured VPN activation continues to return
`OPENVPN_NOT_READY` before any direct connection is opened.

## Profile contract

`Profile::parse` accepts a JSON v1 document of at most 128 KiB. All fields are
required and unknown/duplicate fields, trailing documents and unsupported versions
are errors. There is no `.ovpn` passthrough and no caller-supplied argv.

| Field | Accepted value |
|---|---|
| `version` | `1` |
| `id` | 1–64 characters; lowercase letter first, then lowercase letters, digits, `_` or `-` |
| `remote_ip` / `remote_port` | Literal IPv4/IPv6 endpoint and nonzero port; unspecified, multicast, loopback and IPv4 broadcast rejected |
| `transport` | `udp` or `tcp` |
| `server_name` | Exact certificate name, 1–253 ASCII letters/digits/dots/underscores/hyphens; alphanumeric first |
| `ca_pem` / `certificate_pem` | One bounded inline certificate PEM each |
| `private_key_pem` | Inline unencrypted PKCS#8, RSA or EC PEM; no external path |
| `tls_crypt_key` | OpenVPN static-key V1 envelope with exactly 256 bytes represented as hexadecimal |

PEM checks enforce the input/directive boundary; they do not validate DER,
certificate expiry, revocation, key strength or matching keys. OpenVPN must still
validate those credentials and authenticate the server. DNS endpoints, certificate
chains, encrypted keys, username/password, interactive MFA and external signing
are not supported by this first schema. Profile IDs are logical names, with a
`vpn-` filename prefix that also avoids Windows DOS device basenames.

The renderer emits a fixed base configuration with inline material, exact server
certificate-name checking, server certificate usage, TLS >= 1.2, AES-GCM ciphers,
no compression, no external programs and no automatically installed routes. It
contains **no management endpoint or management secret** and is not a complete
launch configuration. `script-security 0`, `route-nopull` and `route-noexec` are
from the [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html).
These settings do not prove interface isolation: the server can still supply
interface addresses. The host must finish the route/DNS/interface policy and test
actual Windows driver behavior before using this renderer for a live launch.

`Debug` and typed parser errors omit key material. Owned secret fields and output
buffers are zeroized on drop; the caller owns its input bytes. There is no promise
that parser internals, the OS, swap or backups never copy secrets. The fixture in
`crates/ssk-vpnctl/tests/fixtures/profile.json` contains **non-cryptographic test
material**, not a working profile or credentials to install.

## Protected storage

The [configuration deployment layer](OPENVPN_CONFIGURATION_DEPLOYMENT.md) now
installs profiles and grants together in one confidential, audited snapshot.
The per-profile APIs below remain building blocks for legacy storage. Managed
service launches use the selected snapshot; they do not reread legacy profile files.

`ssk_winhost::vpn_profiles::ProfileStore` has explicit provision/open/create/load
operations. Public methods always use the real Windows security probe. The test
probe is private; no public constructor can claim that an arbitrary directory is
protected. Non-Windows public methods return `Unsupported`.

The fixed store is `%ProgramData%\ScorpioSync\state\openvpn-profiles`. Provisioning
reuses the existing elevated create-or-verify path. Unsafe pre-existing directories
are refused, never silently repaired. Every access rechecks the ancestor/owned
chain. Additional confidentiality checks reject every non-administrative allow ACE,
including read-only and inherit-only grants. The inherited file ACL is checked
**before any secret bytes are written**. All reparse tags and multiply linked
files are refused. Files deny write/delete sharing while open.

Creation uses `create_new`, checks the new file, writes the bounded document and
calls `sync_all`. It does not replace existing profiles. An I/O error or crash can
leave an incomplete file; an ID remains occupied until an operator resolves it,
and invalid content cannot be loaded. This is not a multi-file transaction or an
installation/update workflow. Retention, key rotation, at-rest encryption and
backup policy remain product work; current confidentiality is Windows ACL based.
No production state directory was provisioned during this increment.

## Process supervision

`ManagedProcess` couples the management client to an owned `ChildProcess` handle.
It checks OS exit before reading management events, retains the first failure,
closes management on failure and requests termination of the execution container.
A graceful request has the existing stop deadline. Management EOF waits for real
OS exit; if it does not arrive, termination is requested. The additional exit grace
is configurable from >0 to 30 seconds. An unconfirmed termination is reported as
`TerminationUnconfirmed`, with its handle retained and any OS error visible. A late
exit confirmation updates the status without discarding the original failure.
Snapshots are historical and never network admission permits. Continuous polling
on a host worker remains necessary; Drop requests termination but cannot confirm it.

The Windows `JobChild` uses an unnamed, non-inheritable job with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and an active-process limit of one. Its job is
attached **atomically during CreateProcess** using `PROC_THREAD_ATTRIBUTE_JOB_LIST`,
so there is no spawn-then-assign orphan window. Descendants and breakaway are not
allowed. Closing the last job handle, including after abrupt owner death, terminates
the child. See Microsoft's [job object documentation](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
and [process attribute API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

The primitive uses an absolute application path, UTF-16 argument quoting, explicit
working directory, no shell, no inherited handles, an empty environment block and
a hidden console. It keeps the process handle; it never reopens a recycled PID for
control. Windows 10+ job-list support is required; incompatible enclosing jobs
cause failure rather than an uncontained fallback. The one-process constraint and
empty environment still need compatibility validation with the selected OpenVPN
build. `JobChild::spawn` is a **same-token low-level primitive**, not an executable
trust check or authorization grant. Arbitrary low-level launches are not exposed
through IPC; only the verified held preparation is.

## Integration gates at this increment

The later [secure preparation](OPENVPN_SECURE_START.md) implements the bundle,
per-launch secret and endpoint-ownership parts of items 1–2 below.
[Broker control](OPENVPN_BROKER_CONTROL.md) adds per-profile authority, durable audit,
idempotency and service cancellation. Deployment/update, supported recovery and
live VPN acceptance remain open.

Original integration gates (see the linked increments for completed parts):

1. Establish executable/version/hash or publisher trust and safe DLL/config search
   paths. The generic child primitive deliberately does not choose a VPN binary.
2. Mint per-launch management secrets in protected storage, establish socket/owned
   process identity before sending credentials, and compose the management worker
   with process ownership. Loopback, a management password and a reported PID do
   not mutually authenticate the server.
3. Add per-verb authorization, durable audit/idempotency, profile installation and
   update policy, service-stop/recovery behavior and enforcement retention. No
   caller may supply a command line or unrestricted `.ovpn` content to SYSTEM.
4. Verify interface binding and route/DNS/kill-switch behavior on disposable VMs,
   including process/service crash, restart, network changes and IPv4/IPv6 leaks.

The host dependency on `ssk-vpnctl` deliberately increases the daemon's structural
workspace closure from 16 to 17 via `ssk-winhost`. ADR 0008 and its allow-list test
record the reason; no decision-core crate returns to the flow path.

## Verification

The focused checks passed: 7 process-supervisor tests, 6 profile tests, 7 store
policy/file tests and 7 Windows process test cases (one is the fixture entrypoint).
The Windows tests run actual harmless processes and verify explicit termination,
Drop, abrupt owner death, rejected descendants, argument round-trips and invalid
launch inputs. Store tests exercise real file I/O/hardlinks with injected ACL
observations; they do not prove a SYSTEM deployment. No live OpenVPN client/server,
SCM registration, firewall change or production profile provisioning was performed.

Local evidence is recorded in `target/restart-audit/vpn-owner-*.log`.

Final validation: **1,206 workspace tests passed, 0 failed, 1 existing ignored
golden generator**, including documentation tests. Windows workspace/all-targets
build and Clippy (`-D warnings`), formatting and diff checks passed. Linux
all-targets cross-check and Clippy for `ssk-vpnctl`/`ssk-winhost` also passed; no
Linux binaries were executed. The Linux pass exposed unused Windows-only test
probes in `service.rs`; their definitions now carry the same platform gate as
their callers. The daemon's exact 17-crate closure and decision-core exclusion
checks passed.

For local Windows reruns, use `-j 2 --target-dir target/restart-audit/clean-build`.
An initial parallel link exhausted disk space. Removing only this task's verified
incremental cache (about 8 GiB) and the resulting corrupt daemon PDB allowed the
complete validation to pass. No source files or old user build directories were
removed.
