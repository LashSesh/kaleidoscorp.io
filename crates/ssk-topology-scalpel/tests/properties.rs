//! Property-based confirmation of the TopologyScalpel invariants over arbitrary
//! topologies and edit sequences — not just the worked examples. Enterprise-grade
//! rigor: for *any* topology and *any* edit sequence the scalpel (1) never mutates
//! the input, (2) always returns a candidate (`applied == false`), (3) is a
//! deterministic function of its inputs, and — the load-bearing safety property —
//! (4) **every `Pass` plan is genuinely reversible**: its edits apply cleanly and
//! its rollback restores the prior topology exactly.

use proptest::prelude::*;
use ssk_topology_scalpel::{EditOp, Topology, TopologyScalpel};
use ssk_types::GateOutcomeKind;

// A random topology over the node universe 0..5, with edges only between present
// nodes (a realistic starting state).
fn topology_strategy() -> impl Strategy<Value = Topology> {
    proptest::collection::vec(any::<bool>(), 5).prop_flat_map(|present| {
        let nodes: Vec<u64> = present
            .iter()
            .enumerate()
            .filter(|(_, &p)| p)
            .map(|(i, _)| i as u64)
            .collect();
        // Candidate edges are all pairs among present nodes.
        let pairs: Vec<(u64, u64)> = {
            let mut v = Vec::new();
            for i in 0..nodes.len() {
                for j in (i + 1)..nodes.len() {
                    v.push((nodes[i], nodes[j]));
                }
            }
            v
        };
        let mask_len = pairs.len();
        (
            Just(nodes),
            Just(pairs),
            proptest::collection::vec(any::<bool>(), mask_len),
        )
            .prop_map(|(nodes, pairs, mask)| {
                let edges: Vec<(u64, u64)> = pairs
                    .into_iter()
                    .zip(mask)
                    .filter(|(_, keep)| *keep)
                    .map(|(e, _)| e)
                    .collect();
                Topology::with(&nodes, &edges)
            })
    })
}

fn edit_of(tag: u8, a: u64, b: u64) -> EditOp {
    match tag % 4 {
        0 => EditOp::AddNode(a),
        1 => EditOp::RemoveNode(a),
        2 => EditOp::AddEdge(a, b),
        _ => EditOp::RemoveEdge(a, b),
    }
}

// A random edit sequence over nodes 0..6 (one beyond the topology universe, so
// adds of fresh nodes occur).
fn edits_strategy() -> impl Strategy<Value = Vec<EditOp>> {
    proptest::collection::vec((0u8..4, 0u64..6, 0u64..6), 0..6)
        .prop_map(|ops| ops.into_iter().map(|(t, a, b)| edit_of(t, a, b)).collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    // propose never mutates the input, always yields a candidate, and is
    // deterministic; and every Pass plan is genuinely reversible.
    #[test]
    fn pass_plans_are_reversible_and_propose_is_pure(
        current in topology_strategy(),
        edits in edits_strategy(),
    ) {
        let scalpel = TopologyScalpel::new();
        let before = current.clone();

        let plan = scalpel.propose(&current, edits.clone(), "prop");
        // (1) no mutation, (2) candidate-only.
        prop_assert_eq!(&current, &before);
        prop_assert!(!plan.applied);

        // (3) determinism: the same inputs give the same plan id.
        let again = scalpel.propose(&current, edits.clone(), "prop");
        prop_assert_eq!(plan.id, again.id);

        // (4) reversibility of every accepted plan.
        if plan.gate == GateOutcomeKind::Pass {
            let mut live = current.clone();
            // A Pass plan's edits must apply cleanly...
            prop_assert!(live.apply(&plan.edits).is_ok());
            // ...and its rollback must restore the prior topology exactly.
            prop_assert!(live.apply(&plan.rollback).is_ok());
            prop_assert_eq!(live, current);
        }
    }

    // Protecting every node means no edit that removes a node or a protected-
    // incident edge can Pass — such a plan is Hold or Reject, never applicable.
    #[test]
    fn removals_under_full_protection_never_pass(
        current in topology_strategy(),
        edits in edits_strategy(),
    ) {
        let scalpel = TopologyScalpel::new().protecting(0..6);
        let plan = scalpel.propose(&current, edits.clone(), "prop");
        let has_removal = edits
            .iter()
            .any(|op| matches!(op, EditOp::RemoveNode(_) | EditOp::RemoveEdge(..)));
        if has_removal && plan.gate != GateOutcomeKind::Reject {
            prop_assert_ne!(
                plan.gate,
                GateOutcomeKind::Pass,
                "a removal touching protected topology must not auto-pass"
            );
        }
    }
}
