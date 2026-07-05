#![forbid(unsafe_code)]

//! # ssk-tfa — the Transduction / Field-Amplitude adapter (FCHL-MPK Band B)
//!
//! The TFA is the bridge from *observation* to *action*. It reads the δF signals
//! of a [`FieldTensorSkin`] (`ssk-field-tensor`) — drift, anomaly, linkability
//! impulse, route change, service fault, OS event — and transduces each into a
//! **bounded actuation candidate**. It is deliberately conservative, and three
//! properties are structural, not advisory:
//!
//! * **Candidate-only.** [`TransductionField::transduce`] has no side effects and
//!   never actuates. It returns a [`TransductionPlan`] whose `applied` flag is
//!   always `false`. The only path to a real effect is
//!   [`TransductionExecutor::execute`], which drives an *injected* [`Effector`]
//!   and only ever actuates `Pass`-gated candidates.
//! * **No silent amplification.** The actuation amplitude is hard-capped by the
//!   [`TransductionConfig::envelope`]; every clamp, every below-deadband drop, and
//!   every invalid input is written to the plan as a [`Residue`] — nothing is
//!   dropped or magnified silently. A clamped candidate can never gate `Pass`.
//! * **Privileged effects never auto-pass.** An actuation that would tighten a
//!   boundary or quarantine (an egress/isolation effect) gates at most `Hold`: it
//!   must go through the supervisor (`ssk-crown`) and an authorization, never the
//!   TFA alone.
//!
//! The transduction is a pure, content-addressed function of the field, so a plan
//! replays by content, and the executor keeps a hash-chained receipt ledger.

use serde::{Deserialize, Serialize};
use ssk_field_tensor::{DeltaSignal, DeltaSignalKind, FieldTensorSkin};
use ssk_signature::{round6, Residue, ResidueSeverity};
use ssk_types::{digest_of, Digest, GateOutcomeKind, HashAlg};

/// Errors the TFA can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfaError {
    #[error("effector refused actuation: {0}")]
    Effector(String),
    #[error("plan is not applicable: {0}")]
    NotApplicable(String),
}

/// The vocabulary of bounded responses. There is deliberately no `Amplify` and no
/// `Bypass`: the TFA can stabilize, re-probe, back off, observe, or *propose*
/// tightening/quarantine — it can never open something up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActuationKind {
    /// Damp a drift back toward the setpoint.
    Stabilize,
    /// Re-probe a route whose topology changed.
    Reprobe,
    /// Back off from a faulting service (exponential, bounded).
    Backoff,
    /// Record/observe an OS event; no control effect.
    Observe,
    /// Tighten a boundary in response to a linkability impulse — a *privileged*
    /// effect: proposed, never auto-passed.
    TightenBoundary,
    /// Quarantine an anomalous window — a *privileged* effect: proposed, never
    /// auto-passed.
    Quarantine,
}

impl ActuationKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ActuationKind::Stabilize => "stabilize",
            ActuationKind::Reprobe => "reprobe",
            ActuationKind::Backoff => "backoff",
            ActuationKind::Observe => "observe",
            ActuationKind::TightenBoundary => "tighten_boundary",
            ActuationKind::Quarantine => "quarantine",
        }
    }

    /// A privileged effect touches egress / isolation and must be routed through
    /// the supervisor; the TFA may only *propose* it (gate at most `Hold`).
    #[must_use]
    pub fn is_privileged(self) -> bool {
        matches!(
            self,
            ActuationKind::TightenBoundary | ActuationKind::Quarantine
        )
    }

    /// The bounded response for a δF signal kind.
    #[must_use]
    pub fn for_signal(signal: DeltaSignalKind) -> Self {
        match signal {
            DeltaSignalKind::Drift => ActuationKind::Stabilize,
            DeltaSignalKind::Anomaly => ActuationKind::Quarantine,
            DeltaSignalKind::LinkabilityImpulse => ActuationKind::TightenBoundary,
            DeltaSignalKind::RouteChange => ActuationKind::Reprobe,
            DeltaSignalKind::ServiceFault => ActuationKind::Backoff,
            DeltaSignalKind::OsEvent => ActuationKind::Observe,
        }
    }
}

/// One bounded actuation candidate. Its `amplitude` is always within
/// `[0, envelope]`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Actuation {
    pub kind: ActuationKind,
    /// The bounded response amplitude, in `[0, envelope]`.
    pub amplitude: f64,
    /// The δF signal this was transduced from.
    pub source_signal: DeltaSignalKind,
    /// Which field window the signal was about.
    pub window: usize,
    pub detail: String,
}

/// A candidate paired with its multi-dimensional gate outcome. This is the unit
/// the executor consumes — only `Pass` candidates are ever actuated.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GatedActuation {
    pub actuation: Actuation,
    pub gate: GateOutcomeKind,
    pub gate_reason: String,
}

/// The transduction envelope and gains. All fields are configurable design
/// decisions (the author's own defaults), recorded in every plan digest so the
/// mapping is auditable — a non-unit `responsivity` is a *declared* choice, never
/// a silent one.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TransductionConfig {
    /// Global gain applied to a δF magnitude before clamping.
    pub responsivity: f64,
    /// Hard cap on any actuation amplitude (no silent amplification past this).
    pub envelope: f64,
    /// δF magnitudes below this produce no actuation (a recorded residue).
    pub deadband: f64,
}

impl Default for TransductionConfig {
    fn default() -> Self {
        TransductionConfig {
            responsivity: 1.0,
            envelope: 1.0,
            deadband: 0.02,
        }
    }
}

/// A content-addressed transduction plan: the bounded, gated candidates plus the
/// residues that account for everything the transduction did *not* actuate. It is
/// candidate-only — `applied` is always `false`.
///
/// It holds `ssk_signature::Residue` (which is not `serde`), so — like
/// [`FieldTensorSkin`] — it is not itself `serde`; it content-addresses via
/// [`TransductionPlan::id`], computed from a canonical form.
#[derive(Clone, Debug, PartialEq)]
pub struct TransductionPlan {
    pub id: Digest,
    pub actuations: Vec<GatedActuation>,
    /// No-silent-loss ledger: clamped amplitudes, below-deadband drops, invalid
    /// inputs — every δF signal is accounted for here or as an actuation.
    pub residues: Vec<Residue>,
    /// Always `false`: a plan is a proposal. Actuation happens only via
    /// [`TransductionExecutor::execute`] with an injected effector.
    pub applied: bool,
}

impl TransductionPlan {
    /// The `Pass`-gated candidates — the only ones an executor will actuate.
    #[must_use]
    pub fn applicable(&self) -> Vec<&GatedActuation> {
        self.actuations
            .iter()
            .filter(|g| g.gate == GateOutcomeKind::Pass)
            .collect()
    }

    /// The candidates that were proposed but held for the supervisor.
    #[must_use]
    pub fn held(&self) -> Vec<&GatedActuation> {
        self.actuations
            .iter()
            .filter(|g| matches!(g.gate, GateOutcomeKind::Hold | GateOutcomeKind::Refine))
            .collect()
    }
}

/// The transducer: reads a [`FieldTensorSkin`] and proposes a bounded, gated
/// [`TransductionPlan`]. Pure — it never actuates.
#[derive(Clone, Debug)]
pub struct TransductionField {
    config: TransductionConfig,
}

impl Default for TransductionField {
    fn default() -> Self {
        Self::new(TransductionConfig::default())
    }
}

impl TransductionField {
    #[must_use]
    pub fn new(config: TransductionConfig) -> Self {
        TransductionField { config }
    }

    #[must_use]
    pub fn config(&self) -> TransductionConfig {
        self.config
    }

    /// Transduce a field into a candidate plan. No side effects. Every δF signal
    /// becomes either a gated actuation candidate or a residue — never nothing.
    #[must_use]
    pub fn transduce(&self, skin: &FieldTensorSkin) -> TransductionPlan {
        let mut actuations = Vec::new();
        let mut residues = Vec::new();

        for signal in &skin.delta {
            match self.transduce_one(signal) {
                Transduced::Actuation(g) => {
                    // A clamped candidate carries its own residue too (no silent
                    // magnification), recorded alongside the held candidate.
                    actuations.push(g);
                }
                Transduced::ActuationWithResidue(g, r) => {
                    actuations.push(g);
                    residues.push(r);
                }
                Transduced::Dropped(r) => residues.push(r),
            }
        }

        let id = plan_id(&actuations, &residues);
        TransductionPlan {
            id,
            actuations,
            residues,
            applied: false,
        }
    }

    fn transduce_one(&self, signal: &DeltaSignal) -> Transduced {
        let kind = ActuationKind::for_signal(signal.kind);
        let magnitude = signal.magnitude;

        // Invalid input (NaN / negative magnitude) is never silently coerced: it
        // becomes an explicit Reject candidate *and* a high-severity residue.
        if !magnitude.is_finite() || magnitude < 0.0 {
            let actuation = Actuation {
                kind,
                amplitude: 0.0,
                source_signal: signal.kind,
                window: signal.window,
                detail: format!("invalid magnitude for {}", signal.kind.as_str()),
            };
            return Transduced::ActuationWithResidue(
                GatedActuation {
                    actuation,
                    gate: GateOutcomeKind::Reject,
                    gate_reason: "invalid_magnitude".to_owned(),
                },
                Residue {
                    surface: "transduction".to_owned(),
                    severity: ResidueSeverity::High,
                    message: format!(
                        "rejected {} at window {}: non-finite/negative magnitude",
                        signal.kind.as_str(),
                        signal.window
                    ),
                },
            );
        }

        // Below the deadband there is no actuation — but the signal is not lost,
        // it is recorded as a residue.
        if magnitude < self.config.deadband {
            return Transduced::Dropped(Residue {
                surface: "transduction".to_owned(),
                severity: ResidueSeverity::Low,
                message: format!(
                    "{} at window {} below deadband ({} < {})",
                    signal.kind.as_str(),
                    signal.window,
                    round6(magnitude),
                    self.config.deadband
                ),
            });
        }

        let raw = magnitude * self.config.responsivity;

        // A non-finite computed amplitude (e.g. a NaN/infinite responsivity)
        // is rejected outright, mirroring the invalid-magnitude path above —
        // it is never silently coerced into a bounded value.
        if !raw.is_finite() {
            let actuation = Actuation {
                kind,
                amplitude: 0.0,
                source_signal: signal.kind,
                window: signal.window,
                detail: format!("non-finite computed amplitude for {}", signal.kind.as_str()),
            };
            return Transduced::ActuationWithResidue(
                GatedActuation {
                    actuation,
                    gate: GateOutcomeKind::Reject,
                    gate_reason: "invalid_computed_amplitude".to_owned(),
                },
                Residue {
                    surface: "transduction".to_owned(),
                    severity: ResidueSeverity::High,
                    message: format!(
                        "rejected {} at window {}: responsivity produced a non-finite amplitude",
                        signal.kind.as_str(),
                        signal.window
                    ),
                },
            );
        }

        // Bound to [0, envelope] on BOTH sides — a negative or zero
        // responsivity must not slip a negative amplitude past the lower
        // bound the same way an oversized one is capped at the upper bound.
        // `.max(0.0).min(envelope)` (rather than `f64::clamp`, which panics if
        // `envelope` were ever misconfigured negative) also normalizes a
        // reachable -0.0 (deadband=0, magnitude=0, negative responsivity) to
        // +0.0, keeping `to_bits()` — and so `plan_id` — replay-stable.
        let bounded = raw.max(0.0).min(self.config.envelope);
        let clamped = raw != bounded;
        let amplitude = round6(bounded);

        let actuation = Actuation {
            kind,
            amplitude,
            source_signal: signal.kind,
            window: signal.window,
            detail: signal.detail.clone(),
        };

        // Gate: privileged effects and clamped amplitudes can never auto-pass.
        let (gate, gate_reason) = if kind.is_privileged() {
            (
                GateOutcomeKind::Hold,
                "privileged_effect_requires_supervisor".to_owned(),
            )
        } else if clamped {
            (
                GateOutcomeKind::Hold,
                "amplitude_bounded_to_envelope".to_owned(),
            )
        } else {
            (GateOutcomeKind::Pass, "within_envelope".to_owned())
        };

        let gated = GatedActuation {
            actuation,
            gate,
            gate_reason,
        };

        if clamped {
            Transduced::ActuationWithResidue(
                gated,
                Residue {
                    surface: "transduction".to_owned(),
                    severity: ResidueSeverity::Medium,
                    message: format!(
                        "bounded {} at window {}: raw {} -> [0, {}] (no silent amplification, no negative amplitude)",
                        signal.kind.as_str(),
                        signal.window,
                        round6(raw),
                        self.config.envelope
                    ),
                },
            )
        } else {
            Transduced::Actuation(gated)
        }
    }
}

enum Transduced {
    Actuation(GatedActuation),
    ActuationWithResidue(GatedActuation, Residue),
    Dropped(Residue),
}

fn gate_str(gate: GateOutcomeKind) -> &'static str {
    match gate {
        GateOutcomeKind::Pass => "pass",
        GateOutcomeKind::Hold => "hold",
        GateOutcomeKind::Refine => "refine",
        GateOutcomeKind::Reject => "reject",
        GateOutcomeKind::Quarantine => "quarantine",
    }
}

fn plan_id(actuations: &[GatedActuation], residues: &[Residue]) -> Digest {
    #[derive(Serialize)]
    struct Form {
        actuations: Vec<(String, u64, String, usize, String)>,
        residues: Vec<(String, String, String)>,
    }
    let form = Form {
        actuations: actuations
            .iter()
            .map(|g| {
                (
                    g.actuation.kind.as_str().to_owned(),
                    g.actuation.amplitude.to_bits(),
                    gate_str(g.gate).to_owned(),
                    g.actuation.window,
                    g.gate_reason.clone(),
                )
            })
            .collect(),
        residues: residues
            .iter()
            .map(|r| {
                (
                    r.surface.clone(),
                    r.severity.as_str().to_owned(),
                    r.message.clone(),
                )
            })
            .collect(),
    };
    digest_of(&form, HashAlg::Blake3).expect("transduction plan form is serializable")
}

/// A receipt of a real effect. Content-addressed so an execution replays.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceipt {
    pub receipt_id: Digest,
    pub kind: String,
    pub amplitude_bits: u64,
    pub window: usize,
}

impl EffectReceipt {
    #[must_use]
    pub fn of(actuation: &Actuation) -> Self {
        #[derive(Serialize)]
        struct Form<'a> {
            kind: &'a str,
            amplitude_bits: u64,
            window: usize,
        }
        let receipt_id = digest_of(
            &Form {
                kind: actuation.kind.as_str(),
                amplitude_bits: actuation.amplitude.to_bits(),
                window: actuation.window,
            },
            HashAlg::Blake3,
        )
        .expect("effect receipt form is serializable");
        EffectReceipt {
            receipt_id,
            kind: actuation.kind.as_str().to_owned(),
            amplitude_bits: actuation.amplitude.to_bits(),
            window: actuation.window,
        }
    }
}

/// The injected effector seam. The concrete bounded effector (a rate-limiter, a
/// route re-prober, a supervisor hand-off) binds this at the integration layer;
/// tests inject fakes. The TFA core never constructs one.
pub trait Effector {
    /// Perform one bounded actuation, returning a receipt.
    ///
    /// # Errors
    /// [`TfaError::Effector`] if the effect could not be performed.
    fn actuate(&self, actuation: &Actuation) -> Result<EffectReceipt, TfaError>;
}

/// How one candidate was disposed of during execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Disposition {
    /// Actuated via the effector.
    Actuated(EffectReceipt),
    /// Held for the supervisor (a privileged or clamped candidate) — not actuated.
    Deferred(String),
    /// Denied (a Reject candidate) — not actuated.
    Denied(String),
}

/// One hash-chained execution-ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub plan_id: Digest,
    pub kind: String,
    pub disposition: Disposition,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct ExecForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    plan_id: &'a Digest,
    kind: &'a str,
    disposition: &'a Disposition,
}

fn exec_hash(
    seq: u64,
    prev_hash: &Digest,
    plan_id: &Digest,
    kind: &str,
    disposition: &Disposition,
) -> Digest {
    digest_of(
        &ExecForm {
            seq,
            prev_hash,
            plan_id,
            kind,
            disposition,
        },
        HashAlg::Blake3,
    )
    .expect("execution entry is serializable")
}

/// The report of executing one plan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub actuated: usize,
    pub deferred: usize,
    pub denied: usize,
}

/// Executes transduction plans through an injected [`Effector`], honoring the
/// gate: only `Pass` candidates are actuated; `Hold`/`Refine` are deferred and
/// `Reject` is denied — never actuated. Every disposition is appended to a
/// hash-chained ledger.
#[derive(Clone, Debug, Default)]
pub struct TransductionExecutor {
    ledger: Vec<ExecutionEntry>,
}

impl TransductionExecutor {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Execute a plan. Only `Pass`-gated candidates reach the effector; a failing
    /// effector surfaces its error but never bypasses the gate. Returns a tally
    /// and appends each disposition to the ledger.
    ///
    /// # Errors
    /// [`TfaError::Effector`] if the effector refuses a `Pass` candidate; the
    /// candidates processed before the failure remain in the ledger.
    pub fn execute(
        &mut self,
        plan: &TransductionPlan,
        effector: &dyn Effector,
    ) -> Result<ExecutionReport, TfaError> {
        let mut report = ExecutionReport {
            actuated: 0,
            deferred: 0,
            denied: 0,
        };
        for gated in &plan.actuations {
            let disposition = match gated.gate {
                GateOutcomeKind::Pass => {
                    let receipt = effector.actuate(&gated.actuation)?;
                    report.actuated += 1;
                    Disposition::Actuated(receipt)
                }
                GateOutcomeKind::Hold | GateOutcomeKind::Refine => {
                    report.deferred += 1;
                    Disposition::Deferred(gated.gate_reason.clone())
                }
                GateOutcomeKind::Reject | GateOutcomeKind::Quarantine => {
                    report.denied += 1;
                    Disposition::Denied(gated.gate_reason.clone())
                }
            };
            self.record(&plan.id, gated.actuation.kind.as_str(), disposition);
        }
        Ok(report)
    }

    fn record(&mut self, plan_id: &Digest, kind: &str, disposition: Disposition) {
        let seq = self.ledger.len() as u64;
        let prev_hash = self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = exec_hash(seq, &prev_hash, plan_id, kind, &disposition);
        self.ledger.push(ExecutionEntry {
            seq,
            prev_hash,
            plan_id: *plan_id,
            kind: kind.to_owned(),
            disposition,
            entry_hash,
        });
    }

    #[must_use]
    pub fn ledger(&self) -> &[ExecutionEntry] {
        &self.ledger
    }

    #[must_use]
    pub fn head(&self) -> Digest {
        self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash)
    }

    /// Verify the execution ledger chain.
    #[must_use]
    pub fn verify_ledger(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash
                != exec_hash(
                    entry.seq,
                    &entry.prev_hash,
                    &entry.plan_id,
                    &entry.kind,
                    &entry.disposition,
                )
            {
                return false;
            }
            expected_prev = entry.entry_hash;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssk_capture::{
        CaptureMode, CaptureScope, SystemTrafficField, TrafficSource, TrafficWindow,
    };
    use ssk_mpk::Graph;
    use std::cell::RefCell;

    // A source that drifts and raises a linkability impulse, so the field has a
    // real Drift δF (→ Stabilize, Pass) and a real LinkabilityImpulse δF
    // (→ TightenBoundary, privileged → Hold).
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

    fn skin() -> FieldTensorSkin {
        let field = SystemTrafficField::capture(
            &DriftingSource,
            &CaptureScope::new("local", ["lo0"]),
            CaptureMode::PassiveLocal,
        );
        let windows = vec![
            Graph::from_edges(3, &[(0, 1), (1, 2)]).unwrap(),
            Graph::from_edges(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]).unwrap(),
        ];
        FieldTensorSkin::from_field(&field, &windows)
    }

    /// A fake effector that counts how many times it actuated.
    struct CountingEffector {
        actuated: RefCell<Vec<ActuationKind>>,
    }
    impl CountingEffector {
        fn new() -> Self {
            CountingEffector {
                actuated: RefCell::new(Vec::new()),
            }
        }
    }
    impl Effector for CountingEffector {
        fn actuate(&self, actuation: &Actuation) -> Result<EffectReceipt, TfaError> {
            self.actuated.borrow_mut().push(actuation.kind);
            Ok(EffectReceipt::of(actuation))
        }
    }

    #[test]
    fn transduce_has_no_side_effects_and_plan_is_candidate_only() {
        let plan = TransductionField::default().transduce(&skin());
        assert!(!plan.applied, "a transduction plan is candidate-only");
        // The real field has at least a Drift signal (Stabilize) and a
        // LinkabilityImpulse (TightenBoundary).
        assert!(!plan.actuations.is_empty());
        let has_stabilize = plan
            .actuations
            .iter()
            .any(|g| g.actuation.kind == ActuationKind::Stabilize);
        let has_tighten = plan
            .actuations
            .iter()
            .any(|g| g.actuation.kind == ActuationKind::TightenBoundary);
        assert!(has_stabilize, "drift transduces to a stabilize candidate");
        assert!(
            has_tighten,
            "linkability impulse proposes a boundary tighten"
        );
    }

    #[test]
    fn privileged_effects_never_auto_pass() {
        let plan = TransductionField::default().transduce(&skin());
        for gated in &plan.actuations {
            if gated.actuation.kind.is_privileged() {
                assert_ne!(
                    gated.gate,
                    GateOutcomeKind::Pass,
                    "a privileged effect must be proposed, never auto-passed"
                );
            }
            // No candidate ever exceeds the envelope (no silent amplification).
            assert!(
                gated.actuation.amplitude <= TransductionConfig::default().envelope,
                "amplitude is hard-capped by the envelope"
            );
        }
        // The linkability-impulse candidate is a Held privileged effect.
        let tighten = plan
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::TightenBoundary)
            .unwrap();
        assert_eq!(tighten.gate, GateOutcomeKind::Hold);
        assert_eq!(tighten.gate_reason, "privileged_effect_requires_supervisor");
    }

    #[test]
    fn clamping_and_deadband_are_recorded_not_silent() {
        // responsivity 10, envelope 0.5: a drift of ~1 clamps; a tiny signal drops.
        let cfg = TransductionConfig {
            responsivity: 10.0,
            envelope: 0.5,
            deadband: 0.02,
        };
        let mut s = skin();
        // Add a below-deadband anomaly and a large route change (will clamp).
        s = s.with_signal(DeltaSignalKind::RouteChange, 1.0, "big route change", 1);
        s = s.with_signal(DeltaSignalKind::OsEvent, 0.001, "tiny os blip", 0);
        let plan = TransductionField::new(cfg).transduce(&s);

        // The clamped route change is Held (not Pass) and produced a residue.
        let reprobe = plan
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::Reprobe)
            .unwrap();
        assert_eq!(
            reprobe.actuation.amplitude, 0.5,
            "amplitude hit the envelope"
        );
        assert_eq!(reprobe.gate, GateOutcomeKind::Hold);
        assert!(plan
            .residues
            .iter()
            .any(|r| r.message.contains("bounded") && r.message.contains("route_change")));
        // The tiny OS blip dropped below the deadband but is recorded, not lost.
        assert!(plan
            .residues
            .iter()
            .any(|r| r.message.contains("below deadband") && r.message.contains("os_event")));
        // No candidate for the dropped signal.
        assert!(plan
            .actuations
            .iter()
            .all(|g| g.actuation.source_signal != DeltaSignalKind::OsEvent));
    }

    #[test]
    fn invalid_magnitude_is_rejected_not_coerced() {
        let mut s = skin();
        s = s.with_signal(DeltaSignalKind::ServiceFault, f64::NAN, "bad sensor", 0);
        let plan = TransductionField::default().transduce(&s);
        let backoff = plan
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::Backoff)
            .unwrap();
        assert_eq!(backoff.gate, GateOutcomeKind::Reject);
        assert_eq!(backoff.actuation.amplitude, 0.0);
        assert!(plan.residues.iter().any(|r| r.message.contains("rejected")));
    }

    // Regression: a negative (or zero) responsivity must never produce an
    // amplitude outside [0, envelope]. Before the fix, only the upper bound
    // was enforced (`raw.min(envelope)`), so a negative `raw` gated Pass with
    // a negative amplitude — outside the documented [0, envelope] contract.
    #[test]
    fn negative_responsivity_is_bounded_not_passed_through() {
        let cfg = TransductionConfig {
            responsivity: -1.0,
            envelope: 1.0,
            deadband: 0.02,
        };
        let mut s = skin();
        s = s.with_signal(DeltaSignalKind::RouteChange, 0.5, "route change", 1);
        let plan = TransductionField::new(cfg).transduce(&s);

        let reprobe = plan
            .actuations
            .iter()
            .find(|g| g.actuation.kind == ActuationKind::Reprobe)
            .unwrap();
        assert_eq!(
            reprobe.actuation.amplitude, 0.0,
            "a negative computed amplitude must be bounded up to 0.0, not passed through negative"
        );
        assert!(
            reprobe.actuation.amplitude >= 0.0,
            "amplitude must never be negative"
        );
        assert_ne!(
            reprobe.gate,
            GateOutcomeKind::Pass,
            "a bounded (out-of-range) amplitude must never auto-pass"
        );
        assert!(plan
            .residues
            .iter()
            .any(|r| r.message.contains("bounded") && r.message.contains("route_change")));
    }

    #[test]
    fn executor_actuates_only_pass_candidates() {
        let plan = TransductionField::default().transduce(&skin());
        let effector = CountingEffector::new();
        let mut executor = TransductionExecutor::new();
        let report = executor.execute(&plan, &effector).unwrap();

        // Every actuated candidate was Pass-gated; none privileged/held/rejected.
        let actuated = effector.actuated.borrow();
        assert_eq!(report.actuated, actuated.len());
        assert!(actuated.iter().all(|k| !k.is_privileged()));
        assert_eq!(report.actuated, plan.applicable().len());
        assert_eq!(report.deferred, plan.held().len());
        // The privileged tighten was deferred, never actuated.
        assert!(report.deferred >= 1);
        assert!(!actuated.contains(&ActuationKind::TightenBoundary));
        assert!(executor.verify_ledger());
    }

    #[test]
    fn plan_and_execution_are_replay_stable() {
        let a = TransductionField::default().transduce(&skin());
        let b = TransductionField::default().transduce(&skin());
        assert_eq!(a.id, b.id, "same field -> same plan id (replay)");

        let head_a = {
            let mut ex = TransductionExecutor::new();
            ex.execute(&a, &CountingEffector::new()).unwrap();
            ex.head()
        };
        let head_b = {
            let mut ex = TransductionExecutor::new();
            ex.execute(&b, &CountingEffector::new()).unwrap();
            ex.head()
        };
        assert_eq!(head_a, head_b, "same plan -> same execution ledger head");

        // Tampering a past disposition breaks the chain.
        let mut ex = TransductionExecutor::new();
        ex.execute(&a, &CountingEffector::new()).unwrap();
        assert!(ex.verify_ledger());
        if !ex.ledger.is_empty() {
            ex.ledger[0].kind = "forged".to_owned();
            assert!(!ex.verify_ledger());
        }
    }
}
