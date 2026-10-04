#![forbid(unsafe_code)]

//! # ssk-delivery — the DeliveryEnvelope: packaging / migration / uninstall (SSCL Crown)
//!
//! A [`DeliveryEnvelope`] is a **content-addressed** installable / upgradable /
//! removable unit: a name, a version, a set of content-addressed [`Component`]s,
//! and the capabilities it requires of the host. Because it is content-addressed,
//! [`DeliveryEnvelope::verify`] proves an envelope has not been tampered with.
//!
//! A [`DeliveryPlanner`] moves a [`Deployment`] between envelope states by
//! proposing a [`MigrationPlan`]. Exactly like the TopologyScalpel, planning is
//! **candidate-only, gated, and reversible**:
//!
//! * `plan_install` / `plan_uninstall` never mutate the live deployment; the plan
//!   is a proposal (`MigrationPlan::applied` is always `false`).
//! * Every plan carries a `rollback` — the reversed inverse of its steps — that
//!   exactly restores the pre-migration deployment. A plan whose rollback does not
//!   restore is gated `Reject`.
//! * A malformed migration (removing a component that isn't installed at the
//!   recorded version, adding one already present) simulates to failure and gates
//!   `Reject`.
//! * A migration touching a protected component gates `Hold`, never silently
//!   `Pass`.
//!
//! Applying a plan is a deliberate, caller-side step ([`Deployment::apply_plan`]),
//! and an uninstall yields a content-addressed [`UninstallReceipt`] so the removal
//! is auditable and reconstructible.
//!
//! ## Status — deferred, gated on packaging; zero consumers is the design
//!
//! Nothing depends on this crate, and nothing is meant to yet. It is the SSCL
//! Crown DeliveryEnvelope (`SYSTEM_ARCHITECTURE_CORRESPONDENCE.md:42`), part of
//! **Block S/D** (ServiceHost + DeliveryEnvelope, SSCL-5/8) in the integration
//! sequence (`:272`). It is gated on something this repository does not do yet:
//! SSCL-8 is graded **✗ "ships source not binaries"** (`:206`), and the named
//! remaining work is "a real system service / installer" (`:57`). Until the
//! release pipeline ships binaries, an envelope planner has nothing real to
//! plan over. **Honest caveat:** unlike its Band B siblings this crate has no
//! numbered phase and no named acceptance test in any document, and the Block
//! S/D rows at `:234`/`:254`/`:272` name a crate `ssk-package` rather than this
//! one — they predate it. Retire it only on a recorded decision, not as an
//! unreferenced-crate sweep.

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, GateOutcomeKind, HashAlg};
use std::collections::{BTreeMap, BTreeSet};

/// Errors the delivery layer can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    #[error("component already installed: {0}")]
    AlreadyInstalled(String),
    #[error("component not installed at the recorded state: {0}")]
    NotInstalled(String),
    #[error("malformed migration step: {0}")]
    Malformed(String),
    #[error("plan is not applicable (gate did not pass): {0}")]
    NotApplicable(String),
}

/// A content-addressed component of a delivery.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Component {
    pub id: String,
    pub version: String,
    /// Content digest of the component's payload.
    pub content: Digest,
}

impl Component {
    #[must_use]
    pub fn new(id: impl Into<String>, version: impl Into<String>, content: Digest) -> Self {
        Component {
            id: id.into(),
            version: version.into(),
            content,
        }
    }
}

/// A content-addressed installable / upgradable / removable unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryEnvelope {
    pub envelope_id: Digest,
    pub name: String,
    pub version: String,
    pub components: BTreeMap<String, Component>,
    /// Capabilities the envelope requires of the host (checked against the
    /// ServiceHost's granted set at the integration layer).
    pub requires: BTreeSet<String>,
}

fn envelope_digest(
    name: &str,
    version: &str,
    components: &BTreeMap<String, Component>,
    requires: &BTreeSet<String>,
) -> Digest {
    #[derive(Serialize)]
    struct Form<'a> {
        name: &'a str,
        version: &'a str,
        components: &'a BTreeMap<String, Component>,
        requires: &'a BTreeSet<String>,
    }
    digest_of(
        &Form {
            name,
            version,
            components,
            requires,
        },
        HashAlg::Blake3,
    )
    .expect("envelope form is serializable")
}

impl DeliveryEnvelope {
    /// Build an envelope, deriving its content-addressed `envelope_id`.
    #[must_use]
    pub fn new<C, R, S>(
        name: impl Into<String>,
        version: impl Into<String>,
        components: C,
        requires: R,
    ) -> Self
    where
        C: IntoIterator<Item = Component>,
        R: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.into();
        let version = version.into();
        let components: BTreeMap<String, Component> =
            components.into_iter().map(|c| (c.id.clone(), c)).collect();
        let requires: BTreeSet<String> = requires.into_iter().map(Into::into).collect();
        let envelope_id = envelope_digest(&name, &version, &components, &requires);
        DeliveryEnvelope {
            envelope_id,
            name,
            version,
            components,
            requires,
        }
    }

    /// Verify the envelope has not been tampered with (recompute its content id).
    #[must_use]
    pub fn verify(&self) -> bool {
        self.envelope_id
            == envelope_digest(&self.name, &self.version, &self.components, &self.requires)
    }

    /// The deployment this envelope describes when installed onto an empty host.
    #[must_use]
    pub fn as_deployment(&self) -> Deployment {
        Deployment {
            installed: self.components.clone(),
        }
    }
}

/// The current installed state: a content-addressed set of components.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Deployment {
    pub installed: BTreeMap<String, Component>,
}

impl Deployment {
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.installed.is_empty()
    }

    /// A content-addressed digest of the whole deployment (replay-stable).
    #[must_use]
    pub fn digest(&self) -> Digest {
        digest_of(&self.installed, HashAlg::Blake3).expect("deployment is serializable")
    }

    /// Apply one migration step in place.
    ///
    /// # Errors
    /// [`DeliveryError::AlreadyInstalled`], [`DeliveryError::NotInstalled`], or
    /// [`DeliveryError::Malformed`].
    pub fn apply_step(&mut self, step: &MigrationStep) -> Result<(), DeliveryError> {
        match step {
            MigrationStep::AddComponent(c) => {
                if self.installed.contains_key(&c.id) {
                    return Err(DeliveryError::AlreadyInstalled(c.id.clone()));
                }
                self.installed.insert(c.id.clone(), c.clone());
            }
            MigrationStep::RemoveComponent(c) => {
                if self.installed.get(&c.id) != Some(c) {
                    return Err(DeliveryError::NotInstalled(c.id.clone()));
                }
                self.installed.remove(&c.id);
            }
            MigrationStep::ReplaceComponent { from, to } => {
                if from.id != to.id {
                    return Err(DeliveryError::Malformed(format!(
                        "replace changes component id {} -> {}",
                        from.id, to.id
                    )));
                }
                if self.installed.get(&from.id) != Some(from) {
                    return Err(DeliveryError::NotInstalled(from.id.clone()));
                }
                self.installed.insert(to.id.clone(), to.clone());
            }
        }
        Ok(())
    }

    /// Apply a whole plan in place — but only if its gate passed AND `self` is
    /// exactly the deployment the plan was planned from. This is the
    /// deliberate, caller-side application; planning never mutates a
    /// deployment. Atomic: steps are applied to a clone first, and `self` is
    /// only overwritten if every step succeeds — a step failing partway
    /// through never leaves `self` half-migrated (a plan's reversibility proof
    /// only holds for the exact deployment it was planned from; applying it to
    /// a look-alike deployment and failing partway would otherwise strand the
    /// caller in a state neither the plan nor its rollback accounts for).
    ///
    /// # Errors
    /// [`DeliveryError::NotApplicable`] if the plan did not gate `Pass` or
    /// `self` does not match `plan.from_digest`, or any step error (in which
    /// case `self` is left completely unmodified).
    pub fn apply_plan(&mut self, plan: &MigrationPlan) -> Result<(), DeliveryError> {
        if !plan.is_applicable() {
            return Err(DeliveryError::NotApplicable(plan.gate_reason.clone()));
        }
        if self.digest() != plan.from_digest {
            return Err(DeliveryError::NotApplicable(
                "deployment does not match the plan's source digest".to_owned(),
            ));
        }
        let mut work = self.clone();
        for step in &plan.steps {
            work.apply_step(step)?;
        }
        *self = work;
        Ok(())
    }
}

/// One reversible migration step. Each carries enough state that [`inverse`] is
/// exact.
///
/// [`inverse`]: MigrationStep::inverse
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MigrationStep {
    AddComponent(Component),
    RemoveComponent(Component),
    ReplaceComponent { from: Component, to: Component },
}

impl MigrationStep {
    /// The exact inverse of this step.
    #[must_use]
    pub fn inverse(&self) -> MigrationStep {
        match self {
            MigrationStep::AddComponent(c) => MigrationStep::RemoveComponent(c.clone()),
            MigrationStep::RemoveComponent(c) => MigrationStep::AddComponent(c.clone()),
            MigrationStep::ReplaceComponent { from, to } => MigrationStep::ReplaceComponent {
                from: to.clone(),
                to: from.clone(),
            },
        }
    }

    /// The component id this step touches.
    #[must_use]
    pub fn component_id(&self) -> &str {
        match self {
            MigrationStep::AddComponent(c) | MigrationStep::RemoveComponent(c) => &c.id,
            MigrationStep::ReplaceComponent { to, .. } => &to.id,
        }
    }
}

/// A candidate-only, gated, reversible migration between two deployment states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub id: Digest,
    pub from_digest: Digest,
    pub to_digest: Digest,
    pub steps: Vec<MigrationStep>,
    /// The reversed inverse of `steps` — exactly restores the source deployment.
    pub rollback: Vec<MigrationStep>,
    pub gate: GateOutcomeKind,
    pub gate_reason: String,
    /// Always `false`: a plan is a proposal.
    pub applied: bool,
}

impl MigrationPlan {
    /// True only if the gate passed.
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        self.gate == GateOutcomeKind::Pass
    }
}

fn plan_id(from: &Digest, to: &Digest, steps: &[MigrationStep], gate: GateOutcomeKind) -> Digest {
    #[derive(Serialize)]
    struct Form<'a> {
        from: &'a Digest,
        to: &'a Digest,
        steps: &'a [MigrationStep],
        gate: &'a str,
    }
    let gate = match gate {
        GateOutcomeKind::Pass => "pass",
        GateOutcomeKind::Hold => "hold",
        GateOutcomeKind::Refine => "refine",
        GateOutcomeKind::Reject => "reject",
        GateOutcomeKind::Quarantine => "quarantine",
    };
    digest_of(
        &Form {
            from,
            to,
            steps,
            gate,
        },
        HashAlg::Blake3,
    )
    .expect("plan form is serializable")
}

/// Plans migrations between deployment states. It never mutates a live
/// deployment; it proposes gated, reversible [`MigrationPlan`]s.
#[derive(Clone, Debug, Default)]
pub struct DeliveryPlanner {
    protected: BTreeSet<String>,
}

impl DeliveryPlanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Protect a set of component ids — any migration touching one gates `Hold`.
    #[must_use]
    pub fn protecting<I, S>(protected: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        DeliveryPlanner {
            protected: protected.into_iter().map(Into::into).collect(),
        }
    }

    /// Propose a migration from `current` to the deployment described by `target`.
    #[must_use]
    pub fn plan_install(&self, current: &Deployment, target: &DeliveryEnvelope) -> MigrationPlan {
        self.plan_to(current, &target.as_deployment())
    }

    /// Propose an uninstall — a migration from `current` to the empty deployment.
    #[must_use]
    pub fn plan_uninstall(&self, current: &Deployment) -> MigrationPlan {
        self.plan_to(current, &Deployment::empty())
    }

    /// Compute the diff, order it deterministically (removes, then replaces, then
    /// adds — each sorted by id), attach the reversed-inverse rollback, and gate
    /// by simulating on a clone.
    fn plan_to(&self, current: &Deployment, target: &Deployment) -> MigrationPlan {
        let mut removes = Vec::new();
        let mut replaces = Vec::new();
        let mut adds = Vec::new();

        for (id, comp) in &current.installed {
            match target.installed.get(id) {
                None => removes.push(MigrationStep::RemoveComponent(comp.clone())),
                Some(t) if t != comp => replaces.push(MigrationStep::ReplaceComponent {
                    from: comp.clone(),
                    to: t.clone(),
                }),
                Some(_) => {}
            }
        }
        for (id, comp) in &target.installed {
            if !current.installed.contains_key(id) {
                adds.push(MigrationStep::AddComponent(comp.clone()));
            }
        }

        let mut steps = Vec::new();
        steps.append(&mut removes);
        steps.append(&mut replaces);
        steps.append(&mut adds);

        // Rollback is the reversed inverse of the forward steps.
        let rollback: Vec<MigrationStep> = steps.iter().rev().map(MigrationStep::inverse).collect();

        let from_digest = current.digest();
        let to_digest = target.digest();
        let (gate, gate_reason) = self.gate(current, target, &steps, &rollback);
        let id = plan_id(&from_digest, &to_digest, &steps, gate);

        MigrationPlan {
            id,
            from_digest,
            to_digest,
            steps,
            rollback,
            gate,
            gate_reason,
            applied: false,
        }
    }

    fn gate(
        &self,
        current: &Deployment,
        target: &Deployment,
        steps: &[MigrationStep],
        rollback: &[MigrationStep],
    ) -> (GateOutcomeKind, String) {
        // Simulate the forward migration on a clone (never the live deployment).
        let mut sim = current.clone();
        for step in steps {
            if let Err(e) = sim.apply_step(step) {
                return (GateOutcomeKind::Reject, format!("malformed_migration: {e}"));
            }
        }
        if sim.digest() != target.digest() {
            return (
                GateOutcomeKind::Reject,
                "migration_does_not_reach_target".to_owned(),
            );
        }
        // The rollback must exactly restore the source.
        for step in rollback {
            if let Err(e) = sim.apply_step(step) {
                return (GateOutcomeKind::Reject, format!("rollback_malformed: {e}"));
            }
        }
        if sim.digest() != current.digest() {
            return (
                GateOutcomeKind::Reject,
                "rollback_does_not_restore_source".to_owned(),
            );
        }
        // A migration touching a protected component is held for review.
        if let Some(step) = steps
            .iter()
            .find(|s| self.protected.contains(s.component_id()))
        {
            return (
                GateOutcomeKind::Hold,
                format!("touches_protected_component:{}", step.component_id()),
            );
        }
        (GateOutcomeKind::Pass, "reversible_and_clean".to_owned())
    }
}

/// A content-addressed proof of an uninstall, capturing what was removed so the
/// removal is auditable and reconstructible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallReceipt {
    pub receipt_id: Digest,
    /// The deployment digest before the uninstall.
    pub prior_digest: Digest,
    /// The reconstruct plan (the uninstall's rollback) — replays the removal.
    pub reconstruct: Vec<MigrationStep>,
}

impl UninstallReceipt {
    /// Build a receipt from a successfully-gated uninstall plan.
    ///
    /// # Errors
    /// [`DeliveryError::NotApplicable`] if the plan did not gate `Pass` or does
    /// not target the empty deployment.
    pub fn from_plan(plan: &MigrationPlan) -> Result<Self, DeliveryError> {
        if !plan.is_applicable() {
            return Err(DeliveryError::NotApplicable(plan.gate_reason.clone()));
        }
        if plan.to_digest != Deployment::empty().digest() {
            return Err(DeliveryError::NotApplicable(
                "not an uninstall (target is not empty)".to_owned(),
            ));
        }
        #[derive(Serialize)]
        struct Form<'a> {
            prior: &'a Digest,
            reconstruct: &'a [MigrationStep],
        }
        let receipt_id = digest_of(
            &Form {
                prior: &plan.from_digest,
                reconstruct: &plan.rollback,
            },
            HashAlg::Blake3,
        )
        .expect("receipt form is serializable");
        Ok(UninstallReceipt {
            receipt_id,
            prior_digest: plan.from_digest,
            reconstruct: plan.rollback.clone(),
        })
    }

    /// Reconstruct the prior deployment from empty using the receipt.
    ///
    /// # Errors
    /// Any step error, or a mismatch if reconstruction does not reproduce the
    /// prior deployment.
    pub fn reconstruct(&self) -> Result<Deployment, DeliveryError> {
        let mut d = Deployment::empty();
        for step in &self.reconstruct {
            d.apply_step(step)?;
        }
        if d.digest() != self.prior_digest {
            return Err(DeliveryError::Malformed(
                "reconstruction does not reproduce the prior deployment".to_owned(),
            ));
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(id: &str, version: &str, seed: u8) -> Component {
        Component::new(id, version, Digest([seed; 32]))
    }

    fn v1_envelope() -> DeliveryEnvelope {
        DeliveryEnvelope::new(
            "ssk-crown",
            "1.0.0",
            [comp("core", "1.0.0", 1), comp("capture", "1.0.0", 2)],
            ["system_capture"],
        )
    }

    fn v2_envelope() -> DeliveryEnvelope {
        DeliveryEnvelope::new(
            "ssk-crown",
            "2.0.0",
            [
                comp("core", "2.0.0", 3),     // replaced
                comp("capture", "1.0.0", 2),  // unchanged
                comp("boundary", "2.0.0", 4), // added
            ],
            ["system_capture", "egress_teardown"],
        )
    }

    #[test]
    fn envelope_is_content_addressed_and_verifiable() {
        let e = v1_envelope();
        assert!(e.verify());
        // Tampering a component breaks verification.
        let mut tampered = e.clone();
        tampered
            .components
            .insert("core".to_owned(), comp("core", "9.9.9", 99));
        assert!(!tampered.verify());
    }

    #[test]
    fn install_from_empty_is_reversible_and_passes() {
        let planner = DeliveryPlanner::new();
        let plan = planner.plan_install(&Deployment::empty(), &v1_envelope());
        assert!(!plan.applied, "a migration plan is candidate-only");
        assert_eq!(plan.gate, GateOutcomeKind::Pass);
        assert_eq!(plan.steps.len(), 2, "two adds");
        assert!(plan
            .steps
            .iter()
            .all(|s| matches!(s, MigrationStep::AddComponent(_))));

        // Apply on a real deployment; the result matches the envelope.
        let mut deployment = Deployment::empty();
        deployment.apply_plan(&plan).unwrap();
        assert_eq!(deployment.digest(), v1_envelope().as_deployment().digest());

        // Planning did not mutate the input empty deployment.
        assert!(Deployment::empty().is_empty());
    }

    #[test]
    fn upgrade_computes_add_replace_and_leaves_unchanged_alone() {
        let planner = DeliveryPlanner::new();
        let current = v1_envelope().as_deployment();
        let plan = planner.plan_install(&current, &v2_envelope());
        assert_eq!(plan.gate, GateOutcomeKind::Pass);
        // core replaced, boundary added, capture unchanged.
        assert!(plan
            .steps
            .iter()
            .any(|s| matches!(s, MigrationStep::ReplaceComponent { to, .. } if to.id == "core")));
        assert!(plan
            .steps
            .iter()
            .any(|s| matches!(s, MigrationStep::AddComponent(c) if c.id == "boundary")));
        assert!(plan.steps.iter().all(|s| s.component_id() != "capture"));

        let mut deployment = current.clone();
        deployment.apply_plan(&plan).unwrap();
        assert_eq!(deployment.digest(), v2_envelope().as_deployment().digest());

        // The current deployment was not mutated by planning.
        assert_eq!(current.digest(), v1_envelope().as_deployment().digest());
    }

    #[test]
    fn rollback_exactly_restores_the_source() {
        let planner = DeliveryPlanner::new();
        let current = v1_envelope().as_deployment();
        let plan = planner.plan_install(&current, &v2_envelope());

        let mut deployment = current.clone();
        deployment.apply_plan(&plan).unwrap();
        assert_ne!(deployment.digest(), current.digest());
        // Applying the rollback restores v1 exactly.
        for step in &plan.rollback {
            deployment.apply_step(step).unwrap();
        }
        assert_eq!(deployment.digest(), current.digest());
    }

    #[test]
    fn protected_component_holds() {
        let planner = DeliveryPlanner::protecting(["core"]);
        let plan = planner.plan_install(&v1_envelope().as_deployment(), &v2_envelope());
        // The upgrade replaces core, which is protected.
        assert_eq!(plan.gate, GateOutcomeKind::Hold);
        assert!(plan.gate_reason.contains("core"));
        // A held plan is not applicable.
        let mut deployment = v1_envelope().as_deployment();
        assert_eq!(
            deployment.apply_plan(&plan).unwrap_err(),
            DeliveryError::NotApplicable(plan.gate_reason.clone())
        );
    }

    #[test]
    fn uninstall_yields_a_reconstructible_receipt() {
        let planner = DeliveryPlanner::new();
        let current = v2_envelope().as_deployment();
        let plan = planner.plan_uninstall(&current);
        assert_eq!(plan.gate, GateOutcomeKind::Pass);
        assert_eq!(plan.to_digest, Deployment::empty().digest());

        // Apply the uninstall: the deployment becomes empty.
        let mut deployment = current.clone();
        deployment.apply_plan(&plan).unwrap();
        assert!(deployment.is_empty());

        // The receipt reconstructs the prior deployment exactly.
        let receipt = UninstallReceipt::from_plan(&plan).unwrap();
        assert_eq!(receipt.prior_digest, current.digest());
        let reconstructed = receipt.reconstruct().unwrap();
        assert_eq!(reconstructed.digest(), current.digest());
    }

    #[test]
    fn plan_id_is_deterministic() {
        let planner = DeliveryPlanner::new();
        let a = planner.plan_install(&Deployment::empty(), &v1_envelope());
        let b = planner.plan_install(&Deployment::empty(), &v1_envelope());
        assert_eq!(a.id, b.id, "same source + target -> same plan id (replay)");
    }

    // Regression: applying a Pass plan to a look-alike deployment (not the one
    // it was planned from) must be refused outright, not half-applied. Before
    // the fix: source S={c0@v1,c1@v1}; plan_uninstall(&S) -> steps
    // [Remove(c0@v1), Remove(c1@v1)]; applying that plan to a look-alike
    // S2={c0@v1,c1@v2} would remove c0, then fail removing c1 (wrong version),
    // leaving S2 half-migrated to {c1@v2} with neither the plan nor its
    // rollback able to restore it.
    #[test]
    fn apply_plan_refuses_a_deployment_that_does_not_match_the_plan_source() {
        let planner = DeliveryPlanner::new();
        let source = v1_envelope().as_deployment();
        let plan = planner.plan_uninstall(&source);
        assert_eq!(plan.gate, GateOutcomeKind::Pass);

        // A look-alike deployment: c0 unchanged, c1 rebuilt at a new version.
        let mut look_alike = Deployment::empty();
        look_alike
            .installed
            .insert("core".to_owned(), comp("core", "1.0.0", 1));
        look_alike
            .installed
            .insert("capture".to_owned(), comp("capture", "9.9.9", 99));
        let before = look_alike.clone();
        assert_ne!(before.digest(), plan.from_digest);

        assert_eq!(
            look_alike.apply_plan(&plan).unwrap_err(),
            DeliveryError::NotApplicable(
                "deployment does not match the plan's source digest".to_owned()
            )
        );
        // The look-alike deployment is completely unmodified, not half-migrated.
        assert_eq!(look_alike, before);
    }

    // Regression: if a step fails partway through an otherwise-matching plan
    // (only reachable via a hand-tampered plan, since a genuine plan's own
    // gate already proves its steps apply cleanly to its source), `self` must
    // be left completely unmodified rather than partially mutated.
    #[test]
    fn apply_plan_is_atomic_on_a_mid_plan_step_failure() {
        let planner = DeliveryPlanner::new();
        let source = v1_envelope().as_deployment();
        let mut plan = planner.plan_uninstall(&source);
        // Tamper the plan after gating: swap in a step that will fail
        // (removing a component version that was never installed).
        plan.steps.push(MigrationStep::RemoveComponent(comp(
            "nonexistent",
            "1.0.0",
            77,
        )));

        let before = source.clone();
        let mut work = source.clone();
        assert!(work.apply_plan(&plan).is_err());
        assert_eq!(
            work, before,
            "a mid-plan step failure must not leave a partially-migrated deployment"
        );
    }
}
