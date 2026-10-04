import { text } from "./dom.js";
import { renderKillSwitch } from "./kill-switch.js";
import { renderAudit } from "./audit.js";
import { renderConnections } from "./connections.js";
import { renderDaemon } from "./daemon.js";
import { phaseLabels } from "../presentation.js";

export function renderPanel(root, model) {
  text(root.querySelector("#panel-state"), phaseLabels[model.phase]);
  text(root.querySelector("#source"), model.source === "preview" ?
    "Vorschau mit Beispieldaten · keine Aussage über diesen Rechner" :
    model.source === "desktop" ? "Desktop-Verbindung" : "Keine Backend-Verbindung");
  text(root.querySelector("#reported-state"), model.snapshot?.panel_state ?? "unbekannt");
  renderDaemon(root, model.snapshot);
  renderKillSwitch(root, model);
  renderAudit(root, model.snapshot);
  renderConnections(root, model.snapshot);
}
