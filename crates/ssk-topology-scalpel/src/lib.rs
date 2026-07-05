#![forbid(unsafe_code)]

//! # ssk-topology-scalpel — candidate-only, gated topology edits (Band B)
//!
//! The scalpel **proposes** changes to a [`Topology`]; it never applies them.
//! [`TopologyScalpel::propose`] returns a [`ScalpelPlan`] — a candidate carrying
//! the requested [`EditOp`]s, their exact inverse (rollback), and a gate verdict.
//! Applying a plan is a separate step the caller performs (gated elsewhere) via
//! [`Topology::apply`]. Two properties are structural:
//!
//! * **Candidate-only.** `propose` does not mutate the input topology, and a
//!   [`ScalpelPlan`] is always `applied == false`. There is no `apply` method on
//!   the scalpel at all.
//! * **Reversible.** Every well-formed plan carries a rollback that exactly
//!   restores the prior topology; a plan whose rollback would not restore, or
//!   which is malformed, is gated `Reject` and never marked applicable.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use ssk_types::{digest_of, Digest, GateOutcomeKind, HashAlg};

/// Errors from applying edits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScalpelError {
    #[error("node does not exist: {0}")]
    NoNode(u64),
    #[error("node already exists: {0}")]
    NodeExists(u64),
    #[error("edge does not exist: {0:?}")]
    NoEdge((u64, u64)),
    #[error("edge already exists: {0:?}")]
    EdgeExists((u64, u64)),
    #[error("edge endpoint missing: {0}")]
    EndpointMissing(u64),
    #[error("cannot remove a node with incident edges: {0}")]
    NodeNotIsolated(u64),
}

fn norm(a: u64, b: u64) -> (u64, u64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// A single topology edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EditOp {
    AddNode(u64),
    RemoveNode(u64),
    AddEdge(u64, u64),
    RemoveEdge(u64, u64),
}

impl EditOp {
    /// The inverse edit that undoes this one.
    #[must_use]
    pub fn inverse(self) -> EditOp {
        match self {
            EditOp::AddNode(n) => EditOp::RemoveNode(n),
            EditOp::RemoveNode(n) => EditOp::AddNode(n),
            EditOp::AddEdge(a, b) => EditOp::RemoveEdge(a, b),
            EditOp::RemoveEdge(a, b) => EditOp::AddEdge(a, b),
        }
    }

    fn touched_nodes(self) -> Vec<u64> {
        match self {
            EditOp::AddNode(n) | EditOp::RemoveNode(n) => vec![n],
            EditOp::AddEdge(a, b) | EditOp::RemoveEdge(a, b) => vec![a, b],
        }
    }
}

/// A small topology: a set of nodes and undirected edges.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    nodes: BTreeSet<u64>,
    edges: BTreeSet<(u64, u64)>,
}

impl Topology {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(nodes: &[u64], edges: &[(u64, u64)]) -> Self {
        let mut t = Topology::new();
        for &n in nodes {
            t.nodes.insert(n);
        }
        for &(a, b) in edges {
            t.edges.insert(norm(a, b));
        }
        t
    }

    #[must_use]
    pub fn has_node(&self, n: u64) -> bool {
        self.nodes.contains(&n)
    }

    #[must_use]
    pub fn has_edge(&self, a: u64, b: u64) -> bool {
        self.edges.contains(&norm(a, b))
    }

    fn incident(&self, n: u64) -> bool {
        self.edges.iter().any(|&(a, b)| a == n || b == n)
    }

    /// Apply a single edit (caller-side; the scalpel never calls this).
    ///
    /// # Errors
    /// [`ScalpelError`] if the edit is not well-formed against `self`.
    pub fn apply_one(&mut self, op: EditOp) -> Result<(), ScalpelError> {
        match op {
            EditOp::AddNode(n) => {
                if !self.nodes.insert(n) {
                    return Err(ScalpelError::NodeExists(n));
                }
            }
            EditOp::RemoveNode(n) => {
                if !self.nodes.contains(&n) {
                    return Err(ScalpelError::NoNode(n));
                }
                if self.incident(n) {
                    return Err(ScalpelError::NodeNotIsolated(n));
                }
                self.nodes.remove(&n);
            }
            EditOp::AddEdge(a, b) => {
                if !self.nodes.contains(&a) {
                    return Err(ScalpelError::EndpointMissing(a));
                }
                if !self.nodes.contains(&b) {
                    return Err(ScalpelError::EndpointMissing(b));
                }
                if !self.edges.insert(norm(a, b)) {
                    return Err(ScalpelError::EdgeExists(norm(a, b)));
                }
            }
            EditOp::RemoveEdge(a, b) => {
                if !self.edges.remove(&norm(a, b)) {
                    return Err(ScalpelError::NoEdge(norm(a, b)));
                }
            }
        }
        Ok(())
    }

    /// Apply a sequence of edits in order.
    ///
    /// # Errors
    /// [`ScalpelError`] on the first ill-formed edit (already-applied edits are
    /// not rolled back — callers work on a clone, as the scalpel does).
    pub fn apply(&mut self, edits: &[EditOp]) -> Result<(), ScalpelError> {
        for &op in edits {
            self.apply_one(op)?;
        }
        Ok(())
    }
}

/// A candidate topology-edit plan. Never applied by the scalpel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScalpelPlan {
    pub id: Digest,
    pub edits: Vec<EditOp>,
    pub rollback: Vec<EditOp>,
    pub rationale: String,
    pub gate: GateOutcomeKind,
    pub gate_reason: String,
    /// Always `false` — a scalpel plan is a candidate, never applied here.
    pub applied: bool,
}

impl ScalpelPlan {
    /// Whether the caller may apply this plan (it passed the gate).
    #[must_use]
    pub fn is_applicable(&self) -> bool {
        self.gate == GateOutcomeKind::Pass
    }
}

/// The scalpel: proposes gated, reversible edit plans over a topology.
#[derive(Clone, Debug, Default)]
pub struct TopologyScalpel {
    protected_nodes: BTreeSet<u64>,
}

impl TopologyScalpel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark nodes whose removal (or whose incident edges' removal) must be held
    /// for review rather than passed.
    #[must_use]
    pub fn protecting<I: IntoIterator<Item = u64>>(mut self, nodes: I) -> Self {
        self.protected_nodes = nodes.into_iter().collect();
        self
    }

    /// Propose a candidate plan. Does **not** mutate `current`.
    #[must_use]
    pub fn propose(
        &self,
        current: &Topology,
        edits: Vec<EditOp>,
        rationale: impl Into<String>,
    ) -> ScalpelPlan {
        let rationale = rationale.into();
        let rollback: Vec<EditOp> = edits.iter().rev().map(|op| op.inverse()).collect();

        let (gate, gate_reason) = self.gate(current, &edits, &rollback);

        let id = {
            #[derive(Serialize)]
            struct Form<'a> {
                domain: &'a str,
                edits: &'a [EditOp],
                rollback: &'a [EditOp],
                rationale: &'a str,
                gate: &'a str,
            }
            let gate_str = match gate {
                GateOutcomeKind::Pass => "pass",
                GateOutcomeKind::Hold => "hold",
                GateOutcomeKind::Refine => "refine",
                GateOutcomeKind::Reject => "reject",
                GateOutcomeKind::Quarantine => "quarantine",
            };
            digest_of(
                &Form {
                    domain: "fchl/scalpel-plan/v1",
                    edits: &edits,
                    rollback: &rollback,
                    rationale: &rationale,
                    gate: gate_str,
                },
                HashAlg::Blake3,
            )
            .expect("plan form is serializable")
        };

        ScalpelPlan {
            id,
            edits,
            rollback,
            rationale,
            gate,
            gate_reason,
            applied: false,
        }
    }

    fn gate(
        &self,
        current: &Topology,
        edits: &[EditOp],
        rollback: &[EditOp],
    ) -> (GateOutcomeKind, String) {
        // Well-formedness + reversibility, checked on a clone (no mutation).
        let mut sim = current.clone();
        if sim.apply(edits).is_err() {
            return (GateOutcomeKind::Reject, "malformed_edits".to_owned());
        }
        if sim.apply(rollback).is_err() || sim != *current {
            return (
                GateOutcomeKind::Reject,
                "rollback_does_not_restore".to_owned(),
            );
        }
        // Any edit that removes a protected node or an edge incident to one holds.
        let touches_protected = edits.iter().any(|op| match op {
            EditOp::RemoveNode(n) => self.protected_nodes.contains(n),
            EditOp::RemoveEdge(a, b) => {
                self.protected_nodes.contains(a) || self.protected_nodes.contains(b)
            }
            _ => {
                op.touched_nodes()
                    .iter()
                    .any(|n| self.protected_nodes.contains(n))
                    && matches!(op, EditOp::RemoveEdge(..))
            }
        });
        if touches_protected {
            return (
                GateOutcomeKind::Hold,
                "touches_protected_topology".to_owned(),
            );
        }
        (
            GateOutcomeKind::Pass,
            "well_formed_and_reversible".to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topology() -> Topology {
        Topology::with(&[1, 2, 3], &[(1, 2), (2, 3)])
    }

    #[test]
    fn propose_does_not_mutate_and_plan_is_candidate_only() {
        let t = topology();
        let scalpel = TopologyScalpel::new();
        let plan = scalpel.propose(
            &t,
            vec![EditOp::AddNode(4), EditOp::AddEdge(3, 4)],
            "extend",
        );
        // The input topology is untouched.
        assert_eq!(t, topology());
        assert!(
            !plan.applied,
            "a scalpel plan is always a candidate, never applied"
        );
        assert_eq!(plan.gate, GateOutcomeKind::Pass);
        assert!(plan.is_applicable());
    }

    #[test]
    fn plan_rollback_exactly_restores() {
        let t = topology();
        let scalpel = TopologyScalpel::new();
        let plan = scalpel.propose(
            &t,
            vec![
                EditOp::AddNode(4),
                EditOp::AddEdge(3, 4),
                EditOp::RemoveEdge(1, 2),
            ],
            "reshape",
        );
        assert_eq!(plan.gate, GateOutcomeKind::Pass);
        // The caller applies the plan, then its rollback, and lands back home.
        let mut live = t.clone();
        live.apply(&plan.edits).unwrap();
        assert!(live.has_edge(3, 4) && !live.has_edge(1, 2));
        live.apply(&plan.rollback).unwrap();
        assert_eq!(live, t, "rollback exactly restores the prior topology");
    }

    #[test]
    fn malformed_plan_is_rejected() {
        let t = topology();
        let scalpel = TopologyScalpel::new();
        // Removing a non-existent edge is malformed.
        let plan = scalpel.propose(&t, vec![EditOp::RemoveEdge(1, 3)], "bad");
        assert_eq!(plan.gate, GateOutcomeKind::Reject);
        assert!(!plan.is_applicable());
        // Removing a node that still has incident edges is malformed.
        let plan2 = scalpel.propose(&t, vec![EditOp::RemoveNode(2)], "bad2");
        assert_eq!(plan2.gate, GateOutcomeKind::Reject);
    }

    #[test]
    fn protected_topology_holds() {
        let t = topology();
        let scalpel = TopologyScalpel::new().protecting([2]);
        // Removing an edge incident to a protected node holds for review.
        let plan = scalpel.propose(&t, vec![EditOp::RemoveEdge(1, 2)], "touch protected");
        assert_eq!(plan.gate, GateOutcomeKind::Hold);
        assert!(!plan.is_applicable());
        assert_eq!(plan.gate_reason, "touches_protected_topology");
    }

    #[test]
    fn plan_id_is_deterministic() {
        let t = topology();
        let scalpel = TopologyScalpel::new();
        let a = scalpel.propose(&t, vec![EditOp::AddNode(9)], "x");
        let b = scalpel.propose(&t, vec![EditOp::AddNode(9)], "x");
        assert_eq!(a.id, b.id);
    }
}
