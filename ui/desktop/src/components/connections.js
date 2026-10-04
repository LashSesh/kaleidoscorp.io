import { text, rows } from "./dom.js";

export function renderConnections(root, snapshot) {
  const connections = snapshot?.connections;
  const badge = root.querySelector("#co-note");
  text(badge, !connections ? "Keine Daten" : connections.parse_anomaly ?
    "Unvollständige oder fehlerhafte Daten" : !connections.live_supported ?
      "Live-Erfassung nicht verfügbar" : connections.rows.length + " Verbindungen gemeldet");
  badge.className = "badge " + (connections?.parse_anomaly ? "alarm" : "");
  rows(root.querySelector("#co-table tbody"), connections?.rows.map(r => [
    r.protocol, r.local, r.remote, r.pid, r.status,
  ]) ?? []);
}
