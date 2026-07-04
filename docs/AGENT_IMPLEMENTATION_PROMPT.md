# Agent Implementation Prompt — Kaleidoscorp Desktop Client Runtime

> Copy the block below verbatim as the kickoff instruction for the coding agent that will implement
> the runtime. It is self-contained and references `docs/DESKTOP_CLIENT_ARCHITECTURE.md` as the
> single source of truth. It is scoped to **Phase 1 → Phase 2**, then hands off to later phases.

---

## Prompt (give this to the implementing agent)

You are implementing the runtime layer that turns the ScorpioSync-Kaleidoscorp Ω repository from a
synchronous decision-modeling core into a real desktop privacy client backend. Read
`docs/DESKTOP_CLIENT_ARCHITECTURE.md` first and treat it as authoritative — it contains the full
target architecture (sections A–O), the verified current-state inventory, the crate layering, the
API/DTOs, the state model, and the security guarantees.

### Ground truth about the repo (do not re-litigate; verify by file if unsure)

- The workspace has **zero `async`/`tokio`/sockets** today. `ssk-netadmin` adapters are
  **descriptor-only** (`crates/ssk-netadmin/src/adapter.rs:37-40`); routes are **planned not
  executed** (`crates/ssk-netadmin/src/route.rs:117-128`); policy returns enums; session/audit
  ledgers are **in-memory** (`crates/ssk-netadmin/src/audit.rs:86-144`).
- The reusable, real parts are the control plane: `ssk-types`, `ssk-gates`, `ssk-tensor` (with
  `FileLedgerBackend` persistence + `verify_chain`, `crates/ssk-tensor/src/lib.rs:52-119`),
  `ssk-interop`, `ssk-config` (v2 migration/validation, `crates/ssk-config/src/lib.rs:6,160-235`),
  `ssk-runtime`, and the `ssk-netadmin` decision logic. **Reuse them; do not rewrite them.**
- Attestation is a **symmetric** BLAKE3 keyed-MAC, not a signature; `ssk-crypto` is **traits-only**.
  `SECURITY.md:47` falsely claims zero-key constructors are test-restricted.

### Absolute rules

1. **Additive, not a rewrite.** New data-plane/service crates depend on the control-plane crates,
   never the reverse. Keep the `no_std`-friendly crates `no_std`-friendly; `tokio` lives only in new
   `std` crates.
2. **Fail-closed everywhere.** Never introduce a silent direct fallback. Unknown adapter ⇒ deny.
   `RouteKind::Denied` ⇒ block. Kill-switch is supreme.
3. **No attrappen / no throwaway MVP.** Every component does real, testable work. The system-proxy
   MVP must sit behind the `IngressProvider` seam so TUN/per-app are additive.
4. **Truthful claims.** Do not restore or add any forbidden claim from section L.3. When you make a
   claim true (e.g. ship ed25519 signing, ship a real data plane), update the docs to match.
5. **`#![forbid(unsafe_code)]`** on every new crate, except a single confined `ssk-capture` platform
   FFI submodule (behind a safe wrapper, `#![deny(unsafe_op_in_unsafe_fn)]`).
6. Every new capability ships with tests as specified in section N. Do not mark a phase done until
   its acceptance criteria (section M) pass.

### Phase 1 — Core completion & honesty pass — **done**

- Persisted `ssk-netadmin` `AuditLedger`/`SessionLedger` via a generalized `ssk-tensor` storage layer
  (`GenericLedgerBackend<E>`); added reserved `AuditOutcome` variants for Phase 3.
- Implemented ed25519 (`Ed25519KeyPair`/`Ed25519Verifier`) + ChaCha20-Poly1305 directly in
  `ssk-crypto` behind its existing `crypto` feature — no new `ssk-signing` crate was needed, since the
  optional `ed25519-dalek`/`chacha20poly1305` dependencies already sat unused there.
- Feature-gated zero/test keys so a **release** build cannot use them (verified: a plain
  `cargo build --release -p ssk-netadmin` rejects `AttestationBinder::new([0u8;32])`); corrected
  `SECURITY.md:47`.
- Corrected `NETADMIN_SPEC.md`'s `connect()` claim and the architecture doc's "signed"/"Proxifier
  replacement" wording (Section L.3).
- **AC verified:** audit/session chains verify across a real process restart; release build rejects
  a zero attestation key; `ed25519_vectors.rs` (9 tests) passes; `cargo test --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` are green; no forbidden claim remains.

### Then Phase 2 — Daemon + IPC

- Create `ssk-daemon` (bin `sskd`) and `ssk-ipc`.
- Implement the state machine (architecture section K.1, data-plane-independent subset), the
  `tokio::sync::broadcast` event bus (K.3), and IPC transport (Unix socket / Windows named pipe) with
  peer-credential + per-session-token local auth (F.5), CBOR-framed via `ssk-interop` canonical +
  strict decode.
- Implement Section-J commands 1–4 and 15–22 against a **mock** data plane (real data plane is
  Phase 3).
- Retarget `ssk-cli` status/activate/deactivate to drive `sskd` over `ssk-ipc`.
- **AC:** CLI drives the daemon over IPC; a second OS user is rejected; a killed daemon task
  transitions to `degraded`/`fail_closed` and emits an event; event backpressure yields `Lagged`.

### After Phase 2

Proceed through Phases 3–10 in `docs/DESKTOP_CLIENT_ARCHITECTURE.md` section M in order (adapter
runtime → OS integration → config/profiles → event/audit hardening → Tauri bridge → GUI readiness →
packaging/signing/updater → cross-platform hardening), honoring each phase's tests and acceptance
criteria. Stop and surface a decision to the user only when a platform/privilege trade-off is
genuinely ambiguous; otherwise implement the specified clean path.

### Deliverable discipline

- Keep commits scoped per phase with descriptive messages.
- Run `cargo build` + `cargo test` (and the per-OS integration jobs when touching `ssk-capture`)
  before declaring a phase complete.
- Update `docs/DESKTOP_CLIENT_ARCHITECTURE.md` only to correct a current-state claim you have made
  obsolete by shipping the corresponding runtime.
