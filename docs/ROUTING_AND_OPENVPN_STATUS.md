# Routing and OpenVPN — implementation status, 2026-09-22

OpenVPN remains part of the product design. This increment implements its typed
configuration and fail-closed selection, **not a working VPN client**. The
subsequent `ssk-vpnctl` increment now implements a bounded management client and
lifecycle with real loopback protocol tests. The [VPN broker](OPENVPN_BROKER_CONTROL.md)
now exposes authorized, audited preparation/status/stop through the Windows service.
Its process stays in HOLD. Daemon activation still creates no VPN process, virtual
interface or OS route; it fails closed. See [management controller](OPENVPN_MANAGEMENT.md).

## Implemented product path

`SSK_CONFIG_PATH` → validated `AppConfig` v4 → configured profile → policy engine
→ route orchestrator → owned `AdmissionToken` → data plane → durable audit result.

- `list-profiles` and activation use the same startup profile registry. A missing
  rule match denies the connection. The implicit default profile has no rules.
- Rules use unique priorities (lower first), exact hostname/literal IP, domain
  suffix on label boundaries, and an optional destination port. Present criteria
  are combined with AND. A rule with no criteria deliberately matches everything.
  Policy matching performs no DNS resolution. Domain rules are not IP/CIDR rules.
  Hosts are checked at load: a name must end in a label that starts with a letter,
  so numeric aliases such as `127.1` are refused, and an IPv4-mapped IPv6
  destination is refused; write the dotted-quad address.
- Direct, SOCKS5, HTTP CONNECT and TLS tunnel selections use configured adapters.
  This increment's wire regression covers configured SOCKS5 via real daemon IPC;
  existing netcore tests cover the other implemented transports.
- OpenVPN is a separate route, referring to a broker-managed profile ID. It cannot
  be represented as a TCP proxy, executable path, arbitrary arguments or `.ovpn`
  path. Activation reports `FailClosed` with `last_error.code = OPENVPN_NOT_READY`.
  `RunDoctor` also reports configured OpenVPN adapters as unavailable.
- Config has no automatic direct-fallback action, and `RouteExecutor::connect`
  refuses `RouteKind::Fallback` before opening a socket. Selecting an unavailable
  VPN does not grant permission for a direct connection.
- A required attestation yields `ATTESTATION_REQUIRED` before any connect. The
  verifier is still pending. Deserialized attestation data is not accepted as proof.
- The data-plane connect API consumes a token owning its route and target. This
  prevents omission of the admission step or substitution of the target at this
  seam. It is an in-process contract for trusted policy code, not a cryptographic
  capability; lower-level executor/probe APIs remain available for diagnostics.

`trace-route` is a plan preview using the active profile, or `default_profile` when
inactive. It does not prove adapter readiness, attestation, tunnel binding or
traffic coverage. `inspect-flow` returns `FLOW_NOT_FOUND` until captured flows
exist, rather than classifying fabricated connection details. The older CLI
`net-admin` demonstration commands retain their separate built-in sample rules;
they are not the daemon's configured policy or an enforcement test.

## Configuration and migration

The complete [OpenVPN example](examples/openvpn-routing.yaml) can be linted with:

```powershell
ssk config lint --path docs/examples/openvpn-routing.yaml
$env:SSK_CONFIG_PATH = (Resolve-Path docs/examples/openvpn-routing.yaml).Path
# Start a fresh sskd with that environment, then inspect its configured profiles.
ssk list-profiles
```

This example intentionally cannot activate successfully yet. The profile
`corporate` requires adapter `corporate-vpn`, which references broker profile
`company-managed`. It contains no credentials and is not an OpenVPN server config.
Regenerate it with `cargo run -p ssk-config --example openvpn_config`.

The new `routing` section requires v4. Existing v1/v2/v3 documents migrate in
memory with deny-all routing; files are not rewritten. Valid v3 sections are
preserved. Invalid newer documents never fall back to an older decoder. Modern
top-level fields and the routing structures reject unknown fields, as do the
legacy migration envelopes. Routing keys in old-version files are rejected.
Invalid or ambiguous references, duplicate IDs/priorities and zero ports fail
validation. Add intentional routing rules before expecting migrated profiles to
connect. Configuration changes take effect after daemon restart.

## OpenVPN implementation sequence

The planned approach remains a supervised official OpenVPN client process owned
by the privileged broker. OpenVPN provides an external management protocol for
state, credential requests and shutdown; its documentation describes that protocol
as cleartext, so a local endpoint alone must not be treated as authentication.
See the [official management interface specification](https://openvpn.net/community-docs/management-interface.html).

1. **Implemented as an isolated library:** bounded management parser, authenticated
   session setup, state/hold handling, heartbeat, stop and fixed lifecycle deadlines
   in `ssk-vpnctl`. Tests include real loopback TCP, failure/EOF, malformed input and
   secret redaction. The held mode is now wired through the service worker.
2. **Components implemented:** [protected profile storage and process supervision](OPENVPN_PROFILES_AND_PROCESS.md),
   including real Windows job/crash tests. [Secure held startup](OPENVPN_SECURE_START.md)
   now adds a pinned executable/DLL bundle, fresh launch secrets and Windows TCP
   ownership checks. [Audited broker commands](OPENVPN_BROKER_CONTROL.md) are implemented;
   [explicit recovery after OS exit proof](OPENVPN_RECOVERY.md) is implemented.
   [Bounded journal retention](OPENVPN_JOURNAL_RETENTION.md) is implemented.
   Installation/update, missing-evidence handling and external archival/restore remain open.
   Only a strict declarative profile format is accepted; raw `.ovpn` import is unsupported.
3. Bind admitted sockets to a verified VPN interface and route/DNS policy. A
   management `CONNECTED` state alone is insufficient evidence. `route-nopull`
   excludes pushed routes and DNS-related options, but does not itself establish
   per-flow interface isolation; the [OpenVPN manual](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html)
   is the option reference, not proof of this product's enforcement.
4. Validate tunnel loss, process/broker crashes, IPv4/IPv6, DNS, network changes,
   suspend/resume and recovery in disposable Windows VMs before declaring VPN
   support available. The existing system-wide kill switch must participate.

The later full-coverage goal from `P4_FULL_COVERAGE_FEASIBILITY.md` remains in scope.
Application ingress, bidirectional byte pumping, CIDR/port-range rules, trusted
process attribution and protected policy distribution are still open. Current
`Protected` describes one held daemon egress session, not system-wide VPN coverage
or enterprise readiness.

## Regression evidence

Tests exercise real daemon IPC plus loopback sockets: default denial, attestation
denial, explicit OpenVPN unavailability without fallback, a custom profile and
SOCKS5 endpoint, exact destination forwarding, port restrictions and closure of a
previously active session on denial. YAML/TOML migration tests cover discarded
security settings and malformed routing. Existing audit-failure tests continue
to require durable intent/result and no successful state after persistence failure.


Validation on Windows: `cargo test --workspace --offline --locked --no-fail-fast`
completed with **1,159 passed, 0 failed, 1 existing ignored generator**. Workspace
build/all-targets, Clippy/all-targets with `-D warnings`, formatting and CLI lint
of the complete example passed. Local logs are in `target/restart-audit/`:
`routing-tests.log`, `routing-focused.log`, `routing-build.log`,
`routing-clippy.log`. The daemon's dependency-closure tests still pass. No
privileged OpenVPN/driver/firewall validation or live VPN-server connection was
performed; those remain separate acceptance work.
