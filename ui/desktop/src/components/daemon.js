import { text } from "./dom.js";

const states = {
  inactive: "Inaktiv", activating: "Wird aktiviert", active: "Aktiv",
  protected: "Geschützt (Angabe des Dienstes)", degraded: "Eingeschränkt",
  fail_closed: "Sperrzustand", config_invalid: "Konfiguration ungültig",
  recovery_mode: "Wiederherstellung erforderlich",
};

export function renderDaemon(root, snapshot) {
  const daemon = snapshot?.daemon;
  text(root.querySelector("#daemon-state"), daemon ? states[daemon.reported_state] : "Keine Daten");
  const fields = root.querySelector("#daemon-fields");
  fields.replaceChildren();
  if (!daemon) return;
  for (const [label, value] of [
    ["Version", daemon.version], ["Aktives Profil", daemon.active_profile],
    ["Gemeldete Adapter", daemon.adapter_count], ["Letzter Fehlercode", daemon.last_error_code],
  ]) {
    const dt = fields.ownerDocument.createElement("dt");
    const dd = fields.ownerDocument.createElement("dd");
    text(dt, label); text(dd, value); fields.append(dt, dd);
  }
}
