// ScorpioSync control panel — framework-free renderer.
//
// This file renders STRICTLY from the DTOs produced by the Rust view core
// (crate ssk-tauri-bridge). The one safety-critical rule (SPEC_TAURI_GUI.md §7,
// review must-fix): a "protected/green" affordance binds ONLY to
// `protection_confirmed`, NEVER to `journal_claims_engaged`. An alarm always
// dominates. An unknown/degraded state is never rendered as green.

"use strict";

function txt(el, s) { el.textContent = s == null ? "—" : String(s); }

// ── Kill-switch security panel ───────────────────────────────────────────────
function renderKillSwitch(v) {
  const light = document.getElementById("ks-light");
  const headline = document.getElementById("ks-headline");

  // Colour class is driven by severity + protection_confirmed, never by the
  // journal claim alone.
  let cls, head;
  if (v.is_alarm) {
    cls = "alarm";
    head = v.recovery === "inconsistent"
      ? "ALARM — journal says engaged but the OS rule disagrees"
      : "ALARM — engaged but egress protection is NOT confirmed";
  } else if (v.protection_confirmed) {
    cls = "ok";
    head = "Protected — egress severed and confirmed";
  } else if (v.severity === "notice") {
    cls = "notice";
    head = "Engaged (reconciled after restart)";
  } else {
    cls = "neutral";
    head = v.logical_state === "armed" ? "Armed — egress flowing" : "Released — egress restored";
  }
  light.className = "light " + cls;
  txt(headline, head);

  const dl = document.getElementById("ks-fields");
  dl.innerHTML = "";
  const rows = [
    ["logical state", v.logical_state],
    ["OS rule", v.os_rule],
    ["recovery", v.recovery],
    ["severity", v.severity],
    ["journal claims engaged", v.journal_claims_engaged],
    ["protection confirmed", v.protection_confirmed],
    ["state version", v.state_version],
    ["audit entries", v.audit_len],
    ["audit head", v.audit_head_hex],
  ];
  for (const [k, val] of rows) {
    const dt = document.createElement("dt"); txt(dt, k);
    const dd = document.createElement("dd"); txt(dd, val);
    dl.append(dt, dd);
  }
}

// ── Audit ledger ─────────────────────────────────────────────────────────────
function renderAudit(a) {
  const badge = document.getElementById("au-integrity");
  txt(badge, a.integrity.status);
  badge.className = "badge " + (a.integrity.status === "verified" ? "ok" : "alarm");

  const tbody = document.querySelector("#au-table tbody");
  tbody.innerHTML = "";
  // Rows are ALWAYS shown, even when unverified — never hidden.
  for (const e of a.entries) {
    const tr = document.createElement("tr");
    for (const cell of [e.seq, e.kind, `${e.from_state}→${e.to_state}`, e.actor, e.entry_hash_hex.slice(0, 12) + "…"]) {
      const td = document.createElement("td"); txt(td, cell); tr.append(td);
    }
    tbody.append(tr);
  }
}

// ── Connections ──────────────────────────────────────────────────────────────
function renderConnections(c) {
  const note = document.getElementById("co-note");
  if (!c.live_supported) {
    txt(note, "live capture unsupported on this host");
    note.className = "badge notice";
  } else if (c.parse_anomaly) {
    txt(note, "parse anomaly — table may be corrupt");
    note.className = "badge alarm";
  } else {
    txt(note, `${c.rows.length} flows`);
    note.className = "badge";
  }
  const tbody = document.querySelector("#co-table tbody");
  tbody.innerHTML = "";
  for (const r of c.rows) {
    const tr = document.createElement("tr");
    for (const cell of [r.protocol, r.local, r.remote, r.pid, r.status]) {
      const td = document.createElement("td"); txt(td, cell); tr.append(td);
    }
    tbody.append(tr);
  }
}

function render(snapshot) {
  txt(document.getElementById("panel-state"), snapshot.panel_state);
  if (snapshot.kill_switch) renderKillSwitch(snapshot.kill_switch);
  if (snapshot.audit) renderAudit(snapshot.audit);
  if (snapshot.connections) renderConnections(snapshot.connections);
}

// ── Bootstrap ────────────────────────────────────────────────────────────────
// Under Tauri, poll the backend command (see ui/INTEGRATION.md). Standalone
// (no Tauri), show a Disconnected placeholder — never a fabricated "ok".
async function boot() {
  const tauri = window.__TAURI__;
  if (tauri && tauri.core && typeof tauri.core.invoke === "function") {
    try {
      const snap = await tauri.core.invoke("get_panel_snapshot");
      render(snap);
      return;
    } catch (err) {
      render({ panel_state: "degraded" });
      return;
    }
  }
  render({ panel_state: "disconnected" });
}

window.addEventListener("DOMContentLoaded", boot);
