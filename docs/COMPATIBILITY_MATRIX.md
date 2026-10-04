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
