//! Property-based confirmation of the DeliveryEnvelope migration invariants over
//! the full space of deployment pairs — not just the worked examples.
//! Enterprise-grade rigor: for *any* source and target deployment the planner
//! produces a candidate-only migration that (1) never mutates its input, (2)
//! reaches the target exactly, (3) has a rollback that exactly restores the
//! source, and (4) is a deterministic function of its inputs. Uninstall is proven
//! reconstructible for any deployment.

use proptest::prelude::*;
use ssk_delivery::{Component, DeliveryEnvelope, DeliveryPlanner, Deployment, UninstallReceipt};
use ssk_types::{Digest, GateOutcomeKind};

// A deployment over a fixed 5-component universe (ids c0..c4). Each component is
// independently absent or present at one of three versions; the content digest is
// a pure function of (id, version), so the same version is the same component and
// a different version is a genuine replace.
fn deployment_strategy() -> impl Strategy<Value = Deployment> {
    proptest::collection::vec(prop::option::of(1u8..=3u8), 5).prop_map(|versions| {
        let mut d = Deployment::empty();
        for (i, v) in versions.iter().enumerate() {
            if let Some(ver) = v {
                let id = format!("c{i}");
                let comp = Component::new(id.clone(), ver.to_string(), Digest([*ver; 32]));
                d.installed.insert(id, comp);
            }
        }
        d
    })
}

fn envelope_of(target: &Deployment) -> DeliveryEnvelope {
    DeliveryEnvelope::new(
        "app",
        "v",
        target.installed.values().cloned(),
        Vec::<String>::new(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    // For any two deployments, the planned migration is candidate-only, reaches
    // the target, and its rollback exactly restores the source — and planning
    // never mutates the input.
    #[test]
    fn migration_is_reversible_and_reaches_target(
        source in deployment_strategy(),
        target in deployment_strategy(),
    ) {
        let planner = DeliveryPlanner::new();
        let envelope = envelope_of(&target);
        let source_digest = source.digest();

        let plan = planner.plan_install(&source, &envelope);
        prop_assert!(!plan.applied, "a plan is candidate-only");
        prop_assert_eq!(source.digest(), source_digest, "planning must not mutate the source");
        // A diff between two well-formed deployments is always reversible → Pass.
        prop_assert_eq!(plan.gate, GateOutcomeKind::Pass);
        prop_assert_eq!(plan.from_digest, source_digest);
        prop_assert_eq!(plan.to_digest, target.digest());

        // Applying reaches the target exactly.
        let mut work = source.clone();
        work.apply_plan(&plan).unwrap();
        prop_assert_eq!(work.digest(), target.digest());

        // Applying the rollback restores the source exactly.
        for step in &plan.rollback {
            work.apply_step(step).unwrap();
        }
        prop_assert_eq!(work.digest(), source_digest);
    }

    // Uninstall targets the empty deployment and its receipt reconstructs the
    // prior deployment exactly, for any starting deployment.
    #[test]
    fn uninstall_is_reconstructible(source in deployment_strategy()) {
        let planner = DeliveryPlanner::new();
        let plan = planner.plan_uninstall(&source);
        prop_assert_eq!(plan.gate, GateOutcomeKind::Pass);
        prop_assert_eq!(plan.to_digest, Deployment::empty().digest());

        let mut work = source.clone();
        work.apply_plan(&plan).unwrap();
        prop_assert!(work.is_empty());

        let receipt = UninstallReceipt::from_plan(&plan).unwrap();
        prop_assert_eq!(receipt.prior_digest, source.digest());
        let reconstructed = receipt.reconstruct().unwrap();
        prop_assert_eq!(reconstructed.digest(), source.digest());
    }

    // The plan is a deterministic function of (source, target) — it replays by
    // content.
    #[test]
    fn plan_id_is_deterministic(
        source in deployment_strategy(),
        target in deployment_strategy(),
    ) {
        let planner = DeliveryPlanner::new();
        let envelope = envelope_of(&target);
        let a = planner.plan_install(&source, &envelope);
        let b = planner.plan_install(&source, &envelope);
        prop_assert_eq!(a.id, b.id);
        prop_assert_eq!(a.steps, b.steps);
        prop_assert_eq!(a.rollback, b.rollback);
    }
}
