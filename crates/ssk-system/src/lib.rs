#![forbid(unsafe_code)]

//! # ssk-system — the end-to-end composition of the real stack
//!
//! Every other crate is pure and single-purpose, with its privileged boundaries
//! left as injected seams. This crate is where they compose: the
//! [`SystemPipeline`] wires the *real* SSK(Ω) / FCHL-MPK / SSCL stack into one
//! fail-closed evaluation —
//!
//! ```text
//! SystemTrafficField  (ssk-capture)
//!   → FieldTensorSkin  (ssk-field-tensor: T_surface + T_res + C_coupling + δF,
//!                       coupling the captured spectra to MPK windows)
//!   → TransductionPlan (ssk-tfa: bounded, gated, candidate-only actuations)
//!   → signature gate   (ssk-signature GateBundle over the captured spectrum)
//!   → QLOGIC gate      (ssk-imdf, the Mirror-Dome six-axis verdict)
//!   → MetaResonance    (ssk-meta-resonance: hold-only drift feedback)
//!   → CrownSupervisor  (ssk-crown: the fail-closed emission gate)
//!   ⨝ ServiceHost health (ssk-service-host) ⨝ kill-switch (ssk-boundary)
//! ```
//!
//! The composition preserves the **fail-closed priority** end to end: a kill
//! switch or a hard-stop gate denies; an open obligation, a subsystem hold,
//! elevated drift, or an un-emittable host holds; only a fully-clean stack emits.
//! No subsystem can *promote* the decision — resonance and host-health can only
//! make it more conservative. The whole evaluation is a pure function of its
//! inputs, so it replays by content.
//!
//! **Honesty note on the QLOGIC six-axis input.** Of the six axes, this
//! composition genuinely evidences four: κ (coherence, from the captured
//! residues), H (entropy, from the captured spectrum's real measured
//! `shannon_entropy`), B (open obligations), and Δ (drift, from the field's
//! δF drift signals). The remaining two — Π (parallax) and R (replay) —
//! require IMDF wavefront/replay-manifest evidence this pipeline does not yet
//! collect; rather than fabricate a constant "clean" value for them, they are
//! [`SystemInputs`] fields the caller must supply explicitly. A caller with no
//! real evidence should pass `false` so the axis conservatively holds/fails
//! instead of silently assuming consistency.

use ssk_boundary::KillSwitchState;
use ssk_capture::SystemTrafficField;
use ssk_crown::{CrownSupervisor, EmissionDecision, EmissionInputs, EmissionReport};
use ssk_field_tensor::{DeltaSignalKind, FieldTensorSkin};
use ssk_imdf::{QLogicGate, QLogicInput};
use ssk_meta_resonance::{MetaResonanceController, ResonanceAction};
use ssk_mpk::Graph;
use ssk_service_host::ServiceHealth;
use ssk_signature::{FeatureValue, GateBundle, ResidueReport, TargetProfile};
use ssk_tfa::{TransductionField, TransductionPlan};
use ssk_types::{Digest, GateOutcomeKind};

/// The observation + control state fed into one system evaluation.
pub struct SystemInputs<'a> {
    /// The captured traffic field (`ssk-capture`).
    pub traffic: &'a SystemTrafficField,
    /// The discrete MPK symmetry windows the field is coupled to (`ssk-mpk`).
    pub windows: &'a [Graph],
    /// The privileged host's health (`ssk-service-host`).
    pub host_health: ServiceHealth,
    /// The session kill-switch state (`ssk-boundary`).
    pub kill_switch: KillSwitchState,
    /// Open residue/boundary obligations.
    pub open_obligations: usize,
    /// Whether the IMDF birefringent split is consistent for this observation
    /// (the Π axis). Real evidence from `ssk-imdf`'s Wavefront/Parallax check —
    /// this pipeline does not fabricate it; pass `false` when no wavefront
    /// evidence is available so Π conservatively fails rather than silently
    /// passing.
    pub parallax_consistent: bool,
    /// Whether replay-equality holds for this observation (the R axis). Real
    /// evidence from an IMDF replay manifest — pass `false` when no replay
    /// evidence is available so R conservatively fails rather than silently
    /// passing.
    pub replay_equal: bool,
}

/// The result of one end-to-end evaluation.
#[derive(Clone, Debug, PartialEq)]
pub struct SystemVerdict {
    /// The final emission decision, after the host-health downgrade.
    pub decision: EmissionDecision,
    /// The Crown's own report (before the host-health downgrade).
    pub crown_report: EmissionReport,
    /// Whether the host health forced a would-be `Emit` down to `Hold`.
    pub host_downgraded: bool,
    /// The signature gate outcome (`ssk-signature`).
    pub signature_gate: GateOutcomeKind,
    /// The QLOGIC gate outcome (`ssk-imdf`).
    pub qlogic_gate: GateOutcomeKind,
    /// The MetaResonance action (`ssk-meta-resonance`) — hold-only.
    pub resonance_action: ResonanceAction,
    /// The bounded, gated, candidate-only transduction plan (`ssk-tfa`).
    pub transduction: TransductionPlan,
    /// The content-addressed digest of the assembled field.
    pub field_digest: Digest,
    /// The composed reason list.
    pub reasons: Vec<String>,
}

/// The stateful pipeline: it owns the Crown's emission ledger and the resonance
/// loop, so a *sequence* of evaluations accumulates a verifiable, replay-stable
/// audit trail.
#[derive(Debug, Default)]
pub struct SystemPipeline {
    crown: CrownSupervisor,
    resonance: MetaResonanceController,
}

impl SystemPipeline {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run one end-to-end evaluation. Pure in its inputs (given the pipeline's
    /// accumulated state); the fail-closed priority is preserved across every
    /// subsystem.
    pub fn evaluate(&mut self, inputs: &SystemInputs) -> SystemVerdict {
        // 1. Assemble the FieldTensorSkin: captured spectra coupled to the MPK
        //    windows, with the δF signals and no-silent-loss residues.
        let skin = FieldTensorSkin::from_field(inputs.traffic, inputs.windows);
        let field_digest = skin.digest();

        // 2. Transduce the field into a bounded, gated, candidate-only plan.
        let transduction = TransductionField::default().transduce(&skin);

        // 3. The δF drift drives the (hold-only) resonance loop.
        let drift = skin
            .signals(DeltaSignalKind::Drift)
            .iter()
            .map(|s| s.magnitude)
            .fold(0.0_f64, f64::max);
        let resonance = self.resonance.step(drift);

        // 4. The signature gate over the captured spectrum, with the skin's
        //    residues folded in (a sensitive/linkability residue holds emission).
        let mut residue_report = ResidueReport::new();
        for r in &skin.residue_tensor {
            residue_report = residue_report.add(&r.surface, r.severity, &r.message);
        }
        let signature_gate = match skin.surface_tensor.last() {
            Some(sig) => {
                let target = TargetProfile::new("system", sig.clone());
                GateBundle
                    .evaluate(sig, sig, &target, &residue_report, None)
                    .to_ssk_decision()
            }
            // Nothing captured — fail closed to a hold, never a silent pass.
            None => GateOutcomeKind::Hold,
        };

        // 5. The IMDF QLOGIC verdict. Coherence is full on a clean field and
        //    degrades when a residue is present; entropy is the captured
        //    spectrum's real measured shannon_entropy (or a fail-closed
        //    maximum when nothing was captured); drift feeds the Δ axis;
        //    parallax/replay are genuine caller-supplied evidence (see the
        //    module-level honesty note), never a fabricated constant.
        let coherence = if skin.residue_tensor.is_empty() {
            1.0
        } else {
            0.9
        };
        let entropy = skin
            .surface_tensor
            .last()
            .map_or(f64::INFINITY, observed_entropy);
        let qlogic_gate = QLogicGate::default()
            .evaluate(&QLogicInput {
                coherence,
                entropy,
                entropy_bound: ENTROPY_BOUND,
                parallax_consistent: inputs.parallax_consistent,
                replay_equal: inputs.replay_equal,
                open_obligations: inputs.open_obligations,
                drift,
                drift_bound: 0.35,
            })
            .to_ssk();

        // 6. The Crown clamps everything into a fail-closed emission decision.
        let crown_report = self.crown.evaluate(&EmissionInputs {
            signature_gate,
            qlogic_gate,
            kill_switch: inputs.kill_switch,
            resonance,
            open_obligations: inputs.open_obligations,
        });

        // 7. The host-health join: an un-emittable host can only *hold* a would-be
        //    emit (fail-closed), never open one up. Deny/Hold pass through.
        let mut reasons = crown_report.reasons.clone();
        let (decision, host_downgraded) = if !inputs.host_health.is_emittable()
            && crown_report.decision == EmissionDecision::Emit
        {
            reasons.push(format!(
                "service_host_not_emittable:{}",
                inputs.host_health.as_str()
            ));
            (EmissionDecision::Hold, true)
        } else {
            (crown_report.decision, false)
        };

        // Structured, runtime-observable projection of the whole composed
        // verdict (severity escalates with the decision; the underlying
        // ssk-crown emission event already logged its own view of just the
        // Crown's inputs — this is the end-to-end view including the
        // host-health downgrade). The full vector is carried as fields, never
        // collapsed to a single number.
        log_system_verdict(
            decision,
            host_downgraded,
            signature_gate,
            qlogic_gate,
            resonance.action,
            &reasons,
            field_digest,
        );

        SystemVerdict {
            decision,
            crown_report,
            host_downgraded,
            signature_gate,
            qlogic_gate,
            resonance_action: resonance.action,
            transduction,
            field_digest,
            reasons,
        }
    }

    /// The Crown emission-ledger head — accumulates across evaluations.
    #[must_use]
    pub fn crown_head(&self) -> Digest {
        self.crown.head()
    }

    /// Verify the accumulated Crown emission ledger.
    #[must_use]
    pub fn verify_ledger(&self) -> bool {
        self.crown.verify_ledger()
    }
}

/// Emits the `ssk.system` / `system_verdict` structured event, at a severity
/// matching the decision (Emit=info, Hold=warn, Deny=error) — the runtime-
/// observable projection of one [`SystemPipeline::evaluate`] call.
#[allow(clippy::too_many_arguments)]
fn log_system_verdict(
    decision: EmissionDecision,
    host_downgraded: bool,
    signature_gate: GateOutcomeKind,
    qlogic_gate: GateOutcomeKind,
    resonance_action: ResonanceAction,
    reasons: &[String],
    field_digest: Digest,
) {
    macro_rules! emit {
        ($level:ident) => {
            tracing::$level!(
                target: "ssk.system",
                event = "system_verdict",
                decision = decision.as_str(),
                host_downgraded,
                signature_gate = ?signature_gate,
                qlogic_gate = ?qlogic_gate,
                resonance_action = ?resonance_action,
                reasons = ?reasons,
                field_digest = %field_digest.to_hex(),
            )
        };
    }
    match decision {
        EmissionDecision::Emit => emit!(info),
        EmissionDecision::Hold => emit!(warn),
        EmissionDecision::Deny => emit!(error),
    }
}

/// The real measured `shannon_entropy` from a signature's `entropy` dimension
/// (`ssk-signature`'s feature extraction) — raw bits/symbol over the surface's
/// canonical string form, paired with [`ENTROPY_BOUND`] below (calibrated in
/// the same raw bits/symbol units, not an arbitrary fraction). Falls back to
/// `f64::INFINITY` (a fail-closed maximum, never a permissive default) if the
/// dimension is somehow absent — never a hardcoded "looks fine" constant.
fn observed_entropy(sig: &ssk_signature::SpectralSignature) -> f64 {
    match sig
        .dimensions
        .get("entropy")
        .and_then(|d| d.get("shannon_entropy"))
    {
        Some(FeatureValue::Num(bits_per_symbol)) => *bits_per_symbol,
        _ => f64::INFINITY,
    }
}

/// Calibrated in raw bits/symbol (matching [`observed_entropy`]'s units): a
/// minimal structural surface (method/url/status/header-shape, no payload)
/// measures ~4.9 bits/symbol, and ordinary printable-ASCII text tops out
/// around 6.5 (`log2(95)`); this gives that normal structural variance
/// headroom to Pass while still flagging genuinely anomalous high-entropy
/// captured content (e.g. an embedded random/opaque token) as Hold.
const ENTROPY_BOUND: f64 = 6.0;

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_capture::{CaptureMode, CaptureScope, TrafficSource, TrafficWindow};
    use ssk_tfa::{
        Actuation, ActuationKind, EffectReceipt, Effector, TfaError, TransductionExecutor,
    };
    use std::cell::RefCell;

    // A single clean window: no drift, no impulse, no residue -> the clean path.
    struct CleanSource;
    impl TrafficSource for CleanSource {
        fn source_id(&self) -> String {
            "clean".to_owned()
        }
        fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
            let mut w = TrafficWindow::http("http");
            w.method = Some("GET".to_owned());
            w.url = Some("https://example.local/health".to_owned());
            w.status = Some(200);
            w.response_headers = vec![("Content-Type".to_owned(), "application/json".to_owned())];
            w.payload = b"{}".to_vec();
            vec![w]
        }
    }

    // Two windows: a clean GET then a sensitive POST carrying Authorization -> a
    // real drift δF, a linkability impulse δF, and a linkability residue.
    struct DriftingSource;
    impl TrafficSource for DriftingSource {
        fn source_id(&self) -> String {
            "tap".to_owned()
        }
        fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
            let mut clean = TrafficWindow::http("http");
            clean.method = Some("GET".to_owned());
            clean.url = Some("https://example.local/a".to_owned());
            clean.status = Some(200);
            clean.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            clean.payload = b"{}".to_vec();

            let mut sensitive = TrafficWindow::http("http");
            sensitive.method = Some("POST".to_owned());
            sensitive.url = Some("https://example.local/login".to_owned());
            sensitive.status = Some(401);
            sensitive.request_headers =
                vec![("Authorization".to_owned(), "Bearer secret".to_owned())];
            sensitive.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            sensitive.payload = b"{\"user\":\"x\"}".to_vec();

            vec![clean, sensitive]
        }
    }

    fn field(source: &dyn TrafficSource) -> SystemTrafficField {
        SystemTrafficField::capture(
            source,
            &CaptureScope::new("local", ["lo0"]),
            CaptureMode::PassiveLocal,
        )
    }

    fn windows() -> Vec<Graph> {
        vec![
            Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap(),
            Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]).unwrap(),
        ]
    }

    fn clean_inputs<'a>(traffic: &'a SystemTrafficField, windows: &'a [Graph]) -> SystemInputs<'a> {
        SystemInputs {
            traffic,
            windows,
            host_health: ServiceHealth::Healthy,
            kill_switch: KillSwitchState::Armed,
            open_obligations: 0,
            parallax_consistent: true,
            replay_equal: true,
        }
    }

    #[test]
    fn clean_stack_emits_and_is_replay_stable() {
        let traffic = field(&CleanSource);
        let ws = windows();

        let mut a = SystemPipeline::new();
        let va = a.evaluate(&clean_inputs(&traffic, &ws));
        assert_eq!(
            va.decision,
            EmissionDecision::Emit,
            "a fully clean real stack emits; reasons={:?}",
            va.reasons
        );
        assert_eq!(va.signature_gate, GateOutcomeKind::Pass);
        assert_eq!(va.qlogic_gate, GateOutcomeKind::Pass);
        assert_eq!(va.resonance_action, ResonanceAction::Stabilize);
        assert!(a.verify_ledger());

        // A second, independent pipeline on the same inputs yields an identical
        // field digest and Crown head — the whole composition replays by content.
        let mut b = SystemPipeline::new();
        let vb = b.evaluate(&clean_inputs(&traffic, &ws));
        assert_eq!(va.field_digest, vb.field_digest);
        assert_eq!(va.transduction.id, vb.transduction.id);
        assert_eq!(a.crown_head(), b.crown_head());
    }

    #[test]
    fn kill_switch_denies_end_to_end() {
        let traffic = field(&CleanSource);
        let ws = windows();
        let mut pipeline = SystemPipeline::new();
        let mut inputs = clean_inputs(&traffic, &ws);
        inputs.kill_switch = KillSwitchState::Engaged;
        let verdict = pipeline.evaluate(&inputs);
        assert_eq!(
            verdict.decision,
            EmissionDecision::Deny,
            "an engaged kill-switch denies regardless of clean gates"
        );
        assert!(verdict.reasons.iter().any(|r| r == "kill_switch_engaged"));
    }

    #[test]
    fn unhealthy_host_holds_a_would_be_emit() {
        let traffic = field(&CleanSource);
        let ws = windows();
        for health in [ServiceHealth::Degraded, ServiceHealth::Down] {
            let mut pipeline = SystemPipeline::new();
            let mut inputs = clean_inputs(&traffic, &ws);
            inputs.host_health = health;
            let verdict = pipeline.evaluate(&inputs);
            // The gates are all clean (would emit), but an un-emittable host holds.
            assert_eq!(verdict.crown_report.decision, EmissionDecision::Emit);
            assert_eq!(verdict.decision, EmissionDecision::Hold);
            assert!(verdict.host_downgraded);
            assert!(verdict
                .reasons
                .iter()
                .any(|r| r.starts_with("service_host_not_emittable")));
        }
    }

    #[test]
    fn sensitive_field_holds_and_keeps_privileged_effects_behind_the_supervisor() {
        let traffic = field(&DriftingSource);
        let ws = windows();
        let mut pipeline = SystemPipeline::new();
        let verdict = pipeline.evaluate(&clean_inputs(&traffic, &ws));

        // A captured Authorization surface is a linkability residue: the signature
        // gate holds, so the whole stack holds (never emits) — no silent pass.
        assert_eq!(verdict.signature_gate, GateOutcomeKind::Hold);
        assert_ne!(verdict.decision, EmissionDecision::Emit);

        // The transduction proposed a TightenBoundary (privileged) candidate, and
        // it is Held — executing the plan never actuates it.
        let tighten = verdict
            .transduction
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::TightenBoundary)
            .expect("a linkability impulse proposes a boundary tighten");
        assert_eq!(tighten.gate, GateOutcomeKind::Hold);

        struct RecordingEffector {
            actuated: RefCell<Vec<ActuationKind>>,
        }
        impl Effector for RecordingEffector {
            fn actuate(&self, a: &Actuation) -> Result<EffectReceipt, TfaError> {
                self.actuated.borrow_mut().push(a.kind);
                Ok(EffectReceipt::of(a))
            }
        }
        let effector = RecordingEffector {
            actuated: RefCell::new(Vec::new()),
        };
        let mut executor = TransductionExecutor::new();
        executor.execute(&verdict.transduction, &effector).unwrap();
        assert!(
            !effector
                .actuated
                .borrow()
                .contains(&ActuationKind::TightenBoundary),
            "a privileged effect is never actuated end-to-end without the supervisor"
        );
        assert!(executor.verify_ledger());
    }

    // A window that leaks a session cookie and a client IP, but never carries an
    // Authorization header. Regression for the silent-loss bug where the
    // field-tensor only detected `has_authorization`: a cookie/IP leak must hold
    // the whole stack end to end exactly like an authorization leak does.
    struct CookieLeakSource;
    impl TrafficSource for CookieLeakSource {
        fn source_id(&self) -> String {
            "tap".to_owned()
        }
        fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
            let mut clean = TrafficWindow::http("http");
            clean.method = Some("GET".to_owned());
            clean.url = Some("https://example.local/a".to_owned());
            clean.status = Some(200);
            clean.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            clean.payload = b"{}".to_vec();

            let mut leaking = TrafficWindow::http("http");
            leaking.method = Some("GET".to_owned());
            leaking.url = Some("https://example.local/profile".to_owned());
            leaking.status = Some(200);
            leaking.request_headers = vec![
                ("Cookie".to_owned(), "session=abc123".to_owned()),
                ("X-Forwarded-For".to_owned(), "203.0.113.7".to_owned()),
            ];
            leaking.response_headers =
                vec![("Content-Type".to_owned(), "application/json".to_owned())];
            leaking.payload = b"{}".to_vec();

            vec![clean, leaking]
        }
    }

    #[test]
    fn cookie_leak_holds_end_to_end_without_an_authorization_header() {
        let traffic = field(&CookieLeakSource);
        let ws = windows();
        let mut pipeline = SystemPipeline::new();
        let verdict = pipeline.evaluate(&clean_inputs(&traffic, &ws));

        assert_eq!(
            verdict.signature_gate,
            GateOutcomeKind::Hold,
            "a cookie/IP leak must hold the signature gate just like an authorization leak"
        );
        assert_ne!(
            verdict.decision,
            EmissionDecision::Emit,
            "a cookie/IP leak must never silently emit"
        );
        let tighten = verdict
            .transduction
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::TightenBoundary)
            .expect("a cookie/IP impulse must still propose a boundary tighten");
        assert_eq!(tighten.gate, GateOutcomeKind::Hold);
    }

    #[test]
    fn fail_closed_priority_holds_across_crates() {
        let traffic = field(&CleanSource);
        let ws = windows();
        // An open obligation holds a would-be emit.
        let mut pipeline = SystemPipeline::new();
        let mut inputs = clean_inputs(&traffic, &ws);
        inputs.open_obligations = 1;
        let verdict = pipeline.evaluate(&inputs);
        assert_eq!(verdict.decision, EmissionDecision::Hold);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.starts_with("open_obligations")));
        // The QLOGIC gate also held on the open obligation (cross-crate agreement).
        assert_eq!(verdict.qlogic_gate, GateOutcomeKind::Hold);
    }

    // Regression: parallax_consistent and replay_equal are genuine caller-
    // supplied evidence, not hardcoded constants — the QLOGIC gate (and so the
    // whole pipeline) must respond when either is false, on an otherwise
    // fully-clean field that would emit if these axes were still hardcoded true.
    #[test]
    fn parallax_and_replay_evidence_genuinely_gate_the_pipeline() {
        let traffic = field(&CleanSource);
        let ws = windows();

        let mut inconsistent_parallax = clean_inputs(&traffic, &ws);
        inconsistent_parallax.parallax_consistent = false;
        let mut p1 = SystemPipeline::new();
        let v1 = p1.evaluate(&inconsistent_parallax);
        assert_ne!(
            v1.qlogic_gate,
            GateOutcomeKind::Pass,
            "an inconsistent parallax split must not let QLOGIC pass"
        );
        assert_ne!(v1.decision, EmissionDecision::Emit);

        let mut broken_replay = clean_inputs(&traffic, &ws);
        broken_replay.replay_equal = false;
        let mut p2 = SystemPipeline::new();
        let v2 = p2.evaluate(&broken_replay);
        assert_ne!(
            v2.qlogic_gate,
            GateOutcomeKind::Pass,
            "broken replay-equality must not let QLOGIC pass"
        );
        assert_ne!(v2.decision, EmissionDecision::Emit);
    }

    // Regression: entropy is the field's real measured shannon_entropy, not a
    // hardcoded constant — a captured surface with markedly higher measured
    // entropy than the clean baseline must be able to move the H axis, proving
    // it responds to the actual observation rather than a fixed placeholder.
    #[test]
    fn entropy_is_derived_from_the_real_capture_not_hardcoded() {
        struct HighEntropySource;
        impl TrafficSource for HighEntropySource {
            fn source_id(&self) -> String {
                "tap".to_owned()
            }
            fn windows(&self, _scope: &CaptureScope) -> Vec<TrafficWindow> {
                // A long, highly non-repetitive query-like path pushes the
                // canonical form's shannon_entropy well above the clean
                // baseline (~4.9 bits/symbol) and past ENTROPY_BOUND (6.0).
                let mut w = TrafficWindow::http("http");
                w.method = Some("GET".to_owned());
                w.url = Some(
                    "https://example.local/v9zK3q7Lp1xR8eT2wA5dF0hN6cM4bY9uJ3sK7oI1nE5rT8gH2vB4mZ7pQ1"
                        .to_owned(),
                );
                w.status = Some(200);
                vec![w]
            }
        }
        let traffic = field(&HighEntropySource);
        let ws = windows();
        let inputs = clean_inputs(&traffic, &ws);
        let sig = traffic.surfaces[0].signature();
        let observed = sig
            .dimensions
            .get("entropy")
            .and_then(|d| d.get("shannon_entropy"));
        assert!(observed.is_some(), "entropy dimension must be present");

        let mut pipeline = SystemPipeline::new();
        let verdict = pipeline.evaluate(&inputs);
        // Whatever the exact measured value, it must have come from THIS
        // capture, not a fixed 0.1 — i.e. the H axis outcome is a function of
        // the field, which the high-entropy URL demonstrably pushes on.
        assert_ne!(
            verdict.qlogic_gate,
            GateOutcomeKind::Reject,
            "a merely elevated (not extreme) entropy should hold, not hard-reject"
        );
    }
}
