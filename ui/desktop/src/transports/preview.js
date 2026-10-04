import { PANEL_STATES } from "../contract.js";

// Explicit preview entry only. Never a fallback for failed desktop transport.
export function previewSource(getScenario, fetchFile = globalThis.fetch) {
  return {
    kind: "preview",
    async readSnapshot({ signal }) {
      const scenario = getScenario();
      if (![...PANEL_STATES, "daemon-v2"].includes(scenario)) throw new Error("Unknown preview scenario");
      const response = await fetchFile(new URL(`../../fixtures/${scenario}.json`, import.meta.url), { signal });
      if (!response.ok) throw new Error("Preview fixture unavailable");
      return response.json();
    },
  };
}
