import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { validateSnapshot, PANEL_STATES } from "../src/contract.js";
import { protectionView } from "../src/presentation.js";
import { tauriSource } from "../src/transports/tauri.js";
import { previewSource } from "../src/transports/preview.js";

export const fixture = async name => JSON.parse(await readFile(new URL(`../fixtures/${name}.json`, import.meta.url)));

test("all shared Rust/browser scenarios obey the wire contract", async () => {
  for (const name of PANEL_STATES) assert.deepEqual(validateSnapshot(await fixture(name)), await fixture(name));
});

test("unknown versions, extra authority, invalid sections and unsafe numbers fail closed", async () => {
  const valid = await fixture("engaged");
  for (const change of [
    s => { s.schema_version = 99; }, s => { delete s.schema_version; },
    s => { s.enforcement_active = true; }, s => { s.panel_state = "protected"; },
    s => { s.kill_switch.protection_confirmed = "true"; },
    s => { s.kill_switch.audit_len = Number.MAX_SAFE_INTEGER + 1; },
    s => { s.kill_switch.os_rule = "probably"; },
    s => { s.audit.entries = Array(257).fill(s.audit.entries[0]); },
    s => { s.connections.rows[0].pid = 2 ** 32; },
    s => { s.connections.rows[0].status = "x".repeat(1025); },
    s => { s.audit.integrity.status = "trusted"; },
  ]) {
    const changed = structuredClone(valid); change(changed);
    assert.throws(() => validateSnapshot(changed));
  }
});

test("absent sections are normalized and transport mutations cannot change the view", async () => {
  assert.equal(validateSnapshot({ schema_version: 1, panel_state: "degraded" }).kill_switch, null);
  const value = await fixture("engaged");
  const accepted = validateSnapshot(value);
  value.kill_switch.protection_confirmed = false;
  assert.equal(accepted.kill_switch.protection_confirmed, true);
});

test("green requires coherent complete evidence and a current observation", async () => {
  const snapshot = await fixture("engaged");
  assert.equal(protectionView({ phase: "ready", snapshot }).tone, "ok");
  for (const phase of ["disconnected", "connecting", "stale", "degraded"]) {
    assert.notEqual(protectionView({ phase, snapshot }).tone, "ok");
  }
  for (const change of [
    s => { s.panel_state = "degraded"; }, s => { s.panel_state = "inconsistent"; },
    s => { s.kill_switch = null; }, s => { s.kill_switch.os_rule = "unknown"; },
    s => { s.kill_switch.logical_state = "released"; },
    s => { s.kill_switch.protection_confirmed = false; },
    s => { s.kill_switch.is_alarm = true; },
    s => { s.kill_switch.severity = "alarm"; },
    s => { s.kill_switch.recovery = "reconciled"; },
    s => { s.kill_switch.journal_claims_engaged = false; },
  ]) {
    const changed = structuredClone(snapshot); change(changed);
    assert.notEqual(protectionView({ phase: "ready", snapshot: changed }).tone, "ok");
  }
});

test("desktop adapter exposes only a versioned read; absent host never selects preview", async () => {
  const calls = [];
  const source = tauriSource(async (...args) => { calls.push(args); return fixture("daemon-v2"); });
  assert.equal(source.kind, "desktop");
  await source.readSnapshot({});
  assert.deepEqual(calls, [["get_panel_snapshot_v2"]]);
  assert.deepEqual(tauriSource(undefined), { kind: "disconnected" });
  await assert.rejects(tauriSource(async () => fixture("engaged")).readSnapshot({}), /Unsupported desktop response/);
});

test("preview has an explicit identity and accepts only bundled scenarios", async () => {
  let scenario = "engaged";
  let path;
  const source = previewSource(() => scenario, async url => {
    path = url; return { ok: true, json: async () => fixture(scenario) };
  });
  assert.equal(source.kind, "preview");
  assert.equal((await source.readSnapshot({})).schema_version, 1);
  assert.ok(path.pathname.endsWith("/fixtures/engaged.json"));
  scenario = "../../../secret";
  await assert.rejects(source.readSnapshot({}));
});

test("daemon v2 claims are visible without implying verified protection", async () => {
  const input = await fixture("daemon-v2");
  for (const state of ["inactive", "activating", "active", "protected", "degraded", "fail_closed", "config_invalid", "recovery_mode"]) {
    input.daemon.reported_state = state;
    const accepted = validateSnapshot(input);
    assert.equal(accepted.daemon.reported_state, state);
    assert.equal(accepted.kill_switch, null);
    assert.equal(accepted.audit, null);
    assert.equal(accepted.connections, null);
    assert.notEqual(protectionView({ phase: "ready", snapshot: accepted }).tone, "ok");
  }
  for (const change of [
    s => { s.panel_state = "engaged"; },
    s => { s.kill_switch = null; },
    s => { s.daemon.protection_confirmed = true; },
    s => { s.daemon.adapter_count = 257; },
    s => { s.daemon.version = ""; },
    s => { s.daemon.active_profile = "é".repeat(129); },
    s => { s.daemon.last_error_code = "bad\ncode"; },
  ]) {
    const bad = structuredClone(input); change(bad);
    assert.throws(() => validateSnapshot(bad));
  }
});
