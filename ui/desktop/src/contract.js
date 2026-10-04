// Wire validation only. No DOM, transport, host or policy dependencies.
export const PANEL_STATES = Object.freeze([
  "disconnected", "connecting", "ready", "engaged", "released", "inconsistent", "degraded",
]);
const invalid = () => { throw new Error("Unsupported or malformed panel snapshot"); };
const boolean = v => typeof v === "boolean" || invalid();
const integer = v => (Number.isSafeInteger(v) && v >= 0) || invalid();
const string = v => (typeof v === "string" && v.length <= 1024) || invalid();
const hex = v => (typeof v === "string" && /^[0-9a-f]{64}$/.test(v)) || invalid();
const choice = values => v => values.includes(v) || invalid();
const optional = check => v => v == null || check(v);
const list = check => v => {
  if (!Array.isArray(v) || v.length > 256) invalid();
  v.forEach(check);
};
function object(fields, optionalKeys = []) {
  return value => {
    if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
    if (Object.keys(value).some(key => !Object.hasOwn(fields, key))) invalid();
    for (const [key, check] of Object.entries(fields)) {
      if (!Object.hasOwn(value, key) && !optionalKeys.includes(key)) invalid();
      check(value[key]);
    }
  };
}
const killSwitch = object({
  logical_state: choice(["armed", "engaged", "released"]),
  os_rule: choice(["present", "absent", "unknown"]),
  recovery: choice(["consistent", "reconciled", "inconsistent"]),
  severity: choice(["ok", "notice", "alarm"]),
  journal_claims_engaged: boolean, protection_confirmed: boolean, is_alarm: boolean,
  state_version: integer, audit_len: integer, audit_head_hex: hex,
  receipt: optional(object({ receipt_id_hex: hex, scope_label: string, prior_state: string })),
}, ["receipt"]);
const audit = object({
  entry_count: integer, head_hex: hex,
  integrity: object({ status: choice(["verified", "unverified"]) }),
  entries: list(object({
    seq: integer, kind: string, from_state: string, to_state: string, actor: string,
    reason: optional(string), entry_hash_hex: hex,
  }, ["reason"])),
});
const connections = object({
  source_id: string, live_supported: boolean, parse_anomaly: boolean,
  rows: list(object({ protocol: string, local: string, remote: string,
    pid: v => { integer(v); if (v > 0xffffffff) invalid(); }, status: string })),
});
const snapshot = object({
  schema_version: choice([1]), panel_state: choice(PANEL_STATES),
  kill_switch: optional(killSwitch), audit: optional(audit), connections: optional(connections),
}, ["kill_switch", "audit", "connections"]);

export function validateSnapshot(value) {
  if (value?.schema_version === 2) desktopSnapshot(value);
  else snapshot(value);
  // Own the observation; later mutation by a transport cannot change the view.
  return structuredClone({ ...value,
    kill_switch: value.kill_switch ?? null,
    audit: value.audit ?? null,
    connections: value.connections ?? null,
  });
}

const daemonText = v => {
  if (typeof v !== "string" || new TextEncoder().encode(v).length > 256 || /[\u0000-\u001f\u007f-\u009f]/u.test(v)) invalid();
};
const desktopSnapshot = object({
  schema_version: choice([2]), panel_state: choice(["degraded"]),
  daemon: object({
    reported_state: choice(["inactive", "activating", "active", "protected", "degraded", "fail_closed", "config_invalid", "recovery_mode"]),
    version: v => { daemonText(v); if (!v.length) invalid(); }, active_profile: optional(daemonText),
    adapter_count: v => { integer(v); if (v > 256) invalid(); },
    last_error_code: optional(daemonText),
  }, ["active_profile", "last_error_code"]),
});
