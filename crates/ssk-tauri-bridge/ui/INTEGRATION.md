# Desktop host integration

The UI lives in [ui/desktop](../../../ui/desktop/README.md); the runnable Windows
host lives in [apps/desktop](../../../apps/desktop/README.md). The independent
wire types are in `ssk-ui-contract`. This bridge retains projections from system
types and compatibility re-exports; the host does not instantiate privileged
system objects from those projections.

The production command `get_panel_snapshot_v2` calls `ssk-desktop-client`, which
reads only the existing daemon `GetStatus` command. V2 carries a daemon summary
and deliberately cannot claim verified kill-switch, audit or connection evidence.
The old v1 DTOs remain usable by explicit development scenarios. The production
transport rejects v1 responses; production assets exclude preview fixtures.

See [desktop/backend boundaries](../../../docs/DESKTOP_BACKEND_CONNECTION.md) for
timeouts, capability restrictions, the remaining server-authentication gap and
future read/write integration. The UI's AbortSignal cancels interest in a result,
not the Tauri invoke; a separate native deadline bounds the actual read.
