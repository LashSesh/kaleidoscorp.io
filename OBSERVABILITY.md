# Observability — the runtime-observable event catalog

This is the reference for the structured `tracing` events the fail-closed
decision points emit, added to close an enterprise-grade gap: the hash-chained
audit ledgers (`ssk-crown`, `ssk-boundary`, `ssk-service-host`, and — via
`ssk-audit-store` — durably for `ssk-crown`) are the tamper-evident **record**
of a decision, but until now nothing about a decision crossed the process
boundary at the moment it happened. These events are the runtime-observable
**projection** of that record: what an operator's log pipeline, SIEM, or
alerting rules actually see, in real time, without holding the live
supervisor object or parsing the ledger file after the fact.

**The ledger remains authoritative.** These events are a side channel for
observability, not a replacement for the audited chain — if an event is lost
(log pipeline down, disk full), the ledger (and, for `ssk-crown`, the durable
`ssk-audit-store` sink) still has the true, verifiable record. Nothing about
emitting these events changes a decision: the fields carry the full
multi-dimensional verdict exactly as computed, never a scalar collapse, and
severity is derived from the decision, never the other way around.

No event ever carries a wall-clock timestamp from inside these crates — they
stay pure and deterministic (logical time / no clock, matching the rest of
the system); the `tracing` subscriber the integration layer installs is what
stamps a real timestamp on the way out.

## Prerequisite: install a subscriber

None of the pure crates below install a global `tracing` subscriber
themselves — that is the integration layer's job (see `ssk-daemon/src/main.rs`
for the existing pattern: `tracing_subscriber::fmt::init()`). Without a
subscriber installed, these events are no-ops (cheap to check, safe to leave
in pure/test code).

## Event catalog

### `target: "ssk.emission"` — `ssk-crown::CrownSupervisor::evaluate`

One event per emission decision, fired at every `evaluate()` call.

| Field | Type | Meaning |
|---|---|---|
| `event` | `"emission_decision"` | Constant, for filtering. |
| `decision` | `"emit" \| "hold" \| "deny"` | The Crown's verdict. |
| `reasons` | `[String]` (Debug) | Every contributing reason, not just the first. |
| `signature_gate` | `GateOutcomeKind` (Debug) | The signature gate's own outcome. |
| `qlogic_gate` | `GateOutcomeKind` (Debug) | The QLOGIC six-axis verdict's outcome. |
| `kill_switch` | `"armed" \| "engaged" \| "released"` | Kill-switch state at evaluation time. |
| `open_obligations` | `usize` | Open residue/boundary obligation count. |
| `seq` | `u64` | This entry's ledger sequence number. |
| `ledger_head` | hex string | The emission-ledger head *after* this entry — cross-reference against `CrownSupervisor::head()` or the durable sink. |

**Severity:** `info` on `Emit`, `warn` on `Hold`, `error` on `Deny`.

**Suggested alert:** page on any `error`-level `ssk.emission` event, or on a
sustained rate of `warn`-level ones (repeated holds usually indicate a
misbehaving upstream subsystem, not a one-off).

### `target: "ssk.killswitch"` — `ssk-boundary::KillSwitch` (engage/release/override_engage)

One event per kill-switch state transition (including a no-op
`override_engage` while already engaged, which still audits the request).

| Field | Type | Meaning |
|---|---|---|
| `event` | `"kill_switch_transition"` | Constant. |
| `kind` | `"engage" \| "release" \| "override_engage"` | Which operation. |
| `from` / `to` | `"armed" \| "engaged" \| "released"` | The transition. |
| `actor` | `String` | `AuthorizationManifest::source_name` of the caller. |
| `reason` | `Option<String>` (Debug) | Present for `override_engage`. |
| `session` | `String` | The session this switch is bound to (session-local, never a stable identity). |
| `entry_hash` | hex string | This transition's audit-ledger entry hash. |

**Severity:** always `warn` — a kill-switch transition is security-critical in
either direction (severing or restoring egress), so it is never filtered out
by routine info-level log-level thresholds.

**Suggested alert:** alert on `kind = "engage"` or `kind = "override_engage"`
outside of expected maintenance windows.

### `target: "ssk.lifecycle"` — `ssk-service-host::ServiceHost` (install/handshake/start/stop/uninstall)

One event per lifecycle state transition.

| Field | Type | Meaning |
|---|---|---|
| `event` | `"lifecycle_transition"` | Constant. |
| `host` | hex string | The `HostManifest`'s content-addressed `host_id`. |
| `kind` | `"install" \| "handshake" \| "start" \| "stop" \| "uninstall"` | Which operation. |
| `from` / `to` | `ServiceState` (Debug string) | The transition (a `handshake` is a self-loop: `from == to`). |
| `actor` | `String` | The authorizing actor. |
| `detail` | `Option<String>` (Debug) | E.g. how many capabilities were granted. |
| `health` | `"healthy" \| "degraded" \| "down"` | The host's health *after* this transition. |

**Severity:** `info` — lifecycle transitions are expected, routine operational
events; the `health` field is what an alert should key on (e.g. `health !=
"healthy"` outside of an expected install/upgrade window), not the
transition itself.

### `target: "ssk.system"` — `ssk-system::SystemPipeline::evaluate`

One event per end-to-end pipeline evaluation — the composed view across
capture → field-tensor → transduction → signature gate → QLOGIC →
MetaResonance → ServiceHost health → CrownSupervisor. Fired *in addition to*
the `ssk.emission` event the inner `CrownSupervisor::evaluate` call already
emits (that one reflects only the Crown's own inputs; this one reflects the
final verdict *after* the host-health downgrade).

| Field | Type | Meaning |
|---|---|---|
| `event` | `"system_verdict"` | Constant. |
| `decision` | `"emit" \| "hold" \| "deny"` | The final `SystemVerdict::decision`, after any host-health downgrade. |
| `host_downgraded` | `bool` | Whether an un-emittable host forced a would-be `Emit` down to `Hold`. |
| `signature_gate` / `qlogic_gate` | `GateOutcomeKind` (Debug) | As computed for this evaluation. |
| `resonance_action` | `ResonanceAction` (Debug) | The MetaResonance loop's action for this step. |
| `reasons` | `[String]` (Debug) | The composed reason list (Crown's reasons plus, if applicable, the host-downgrade reason). |
| `field_digest` | hex string | The content-addressed digest of the assembled `FieldTensorSkin` — cross-reference for replay. |

**Severity:** `info` on `Emit`, `warn` on `Hold`, `error` on `Deny` (same
mapping as `ssk.emission`).

**Suggested alert:** the same `ssk.emission`-level alerts, plus specifically
watching `host_downgraded = true` as a signal that the privileged host itself
(not a data-plane gate) is the reason emission is being held.

## Adding a new event

If you add a decision point that should be observable, follow the pattern
above: pick a `target` scoped to the crate (`ssk.<area>`), give the event a
stable `event` name, carry the *full* decision vector as fields (never
collapse to one number), and map severity from the decision itself
(info/warn/error), never independently of it. Update this table in the same
change.
