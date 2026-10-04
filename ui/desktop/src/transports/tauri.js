// The sole production adapter. No shell, filesystem or privileged commands.
// The host implements a bounded read through ssk-desktop-client.
export function tauriSource(invoke) {
  if (typeof invoke !== "function") return { kind: "disconnected" };
  return { kind: "desktop", readSnapshot: async () => {
    const value = await invoke("get_panel_snapshot_v2");
    if (value?.schema_version !== 2) throw new Error("Unsupported desktop response");
    return value;
  } };
}
