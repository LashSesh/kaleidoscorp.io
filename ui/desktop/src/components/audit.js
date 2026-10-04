import { text, rows } from "./dom.js";

export function renderAudit(root, snapshot) {
  const audit = snapshot?.audit;
  const badge = root.querySelector("#au-integrity");
  text(badge, !audit ? "Keine Daten" :
    audit.integrity.status === "verified" ? "Als geprüft gemeldet" : "Unbestätigt");
  badge.className = "badge " + (audit?.integrity.status === "unverified" ? "notice" : "");
  rows(root.querySelector("#au-table tbody"), audit?.entries.map(e => [
    e.seq, e.kind, e.from_state + " → " + e.to_state, e.actor, e.entry_hash_hex.slice(0, 12) + "…",
  ]) ?? []);
}
