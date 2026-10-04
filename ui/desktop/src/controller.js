import { validateSnapshot } from "./contract.js";

// Port: { kind, readSnapshot({signal}): Promise<PanelSnapshotV1> }.
// Only the composition root selects a transport; components never see one.
export function createController({ source, render, timeoutMs = 3000, freshnessMs = 10000,
  clock = { set: (fn, ms) => setTimeout(fn, ms), clear: id => clearTimeout(id) } }) {
  let generation = 0;
  let disposed = false;
  let current = null;
  let expiry = null;
  const show = (phase, snapshot = null) => render({ phase, snapshot, source: source.kind });
  const clearExpiry = () => { if (expiry !== null) clock.clear(expiry); expiry = null; };
  async function refresh() {
    if (disposed) return;
    const ticket = ++generation;
    current?.abort();
    clearExpiry();
    if (source.kind === "disconnected") { show("disconnected"); return; }
    const abort = new AbortController();
    current = abort;
    show("connecting");
    let timer;
    let abortListener;
    try {
      const cancellation = new Promise((_, reject) => {
        abortListener = () => reject(new Error("Snapshot cancelled"));
        abort.signal.addEventListener("abort", abortListener, { once: true });
        timer = clock.set(() => abort.abort(), timeoutMs);
      });
      const payload = await Promise.race([
        Promise.resolve().then(() => source.readSnapshot({ signal: abort.signal })), cancellation,
      ]);
      if (disposed || ticket !== generation) return;
      const snapshot = validateSnapshot(payload);
      show("ready", snapshot);
      expiry = clock.set(() => {
        if (!disposed && ticket === generation) show("stale");
      }, freshnessMs);
    } catch {
      if (!disposed && ticket === generation) show("degraded");
    } finally {
      clock.clear(timer);
      abort.signal.removeEventListener("abort", abortListener);
      if (ticket === generation) current = null;
    }
  }
  show("disconnected");
  return {
    refresh,
    dispose() {
      disposed = true;
      ++generation;
      current?.abort();
      clearExpiry();
    },
  };
}
