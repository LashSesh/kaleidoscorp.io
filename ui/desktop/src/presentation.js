// Pure presentation decisions. This never authorizes or changes protection.
export function protectionView(model) {
  const s = model.snapshot;
  const k = s?.kill_switch;
  if (model.phase !== "ready" || !k) {
    return { tone: "neutral", text: "Schutzstatus unbekannt — keine aktuelle Bestätigung" };
  }
  if (k.is_alarm || k.severity === "alarm" || k.recovery === "inconsistent" ||
      s.panel_state === "inconsistent") {
    return { tone: "alarm", text: "Widersprüchlicher oder unbestätigter Schutzstatus" };
  }
  if (["degraded", "disconnected", "connecting"].includes(s.panel_state)) {
    return { tone: "notice", text: "Schutzstatus nicht verlässlich verfügbar" };
  }
  if (s.panel_state === "engaged" && k.protection_confirmed &&
      k.logical_state === "engaged" && k.os_rule === "present" &&
      k.recovery === "consistent" && k.severity === "ok" && k.journal_claims_engaged) {
    return { tone: "ok", text: "Kill-Switch: vom Backend als bestätigt gemeldet" };
  }
  if (k.logical_state === "engaged" || k.protection_confirmed || s.panel_state === "engaged") {
    return { tone: "alarm", text: "Schutzbehauptung ohne vollständige Bestätigung" };
  }
  return { tone: "neutral", text: "Kill-Switch nicht aktiviert" };
}

export const phaseLabels = Object.freeze({
  disconnected: "Nicht verbunden", connecting: "Wird aktualisiert …",
  ready: "Beobachtung geladen", degraded: "Daten nicht verfügbar",
  stale: "Daten veraltet — erneut aktualisieren", disposed: "Ansicht geschlossen",
});
