#![forbid(unsafe_code)]

//! # ssk-funnel-dag — the FunnelDAG (FCHL sense, Band B)
//!
//! A **host-relation work DAG**: nodes are tasks, each bound to a
//! [`ssk_host_cells::HostCellId`], with dependency ordering, a logical TTL,
//! explicit dissolution, and a hash-chained trace.
//!
//! Two things are structural:
//!
//! * **It is a DAG.** A node may only depend on nodes that already exist, so
//!   edges always point backward in creation order — a cycle is impossible by
//!   construction and [`FunnelDag::topological_order`] always succeeds.
//! * **Temporal-window replay.** Every mutation is appended to a hash-chained
//!   trace, so the same sequence of operations produces the same trace head.
//!
//! This is **not** the Ω locator funnel-DAG (`ssk-locator`'s `LocatorGraph`) —
//! a different object over a different plane. FunnelDAG nodes carry host cells
//! (a work/role relation), never locators (a routing relation).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ssk_host_cells::HostCellId;
use ssk_types::{digest_of, Digest, HashAlg};

/// Errors the funnel DAG can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FunnelError {
    #[error("no such node")]
    NotFound,
    #[error("dependency does not exist (a node may only depend on existing nodes)")]
    UnknownDependency,
    #[error("node is not runnable (dissolved or dependencies unmet)")]
    NotRunnable,
}

/// A node's lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    Pending,
    Done,
    Dissolved,
}

/// A stable, creation-ordered node id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FunnelNodeId(pub u64);

/// One work node bound to a host cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunnelNode {
    pub id: FunnelNodeId,
    pub task: String,
    pub host_cell: HostCellId,
    pub deps: Vec<FunnelNodeId>,
    pub spawned_at: u64,
    pub ttl: u64,
    pub state: NodeState,
}

impl FunnelNode {
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.spawned_at.saturating_add(self.ttl)
    }
}

/// The host-relation work DAG.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FunnelDag {
    now: u64,
    next_id: u64,
    nodes: BTreeMap<u64, FunnelNode>,
    trace: Vec<TraceEntry>,
}

/// A hash-chained trace entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub op: String,
    pub node: u64,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct TraceForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    op: &'a str,
    node: u64,
}

fn trace_hash(seq: u64, prev_hash: &Digest, op: &str, node: u64) -> Digest {
    digest_of(
        &TraceForm {
            seq,
            prev_hash,
            op,
            node,
        },
        HashAlg::Blake3,
    )
    .expect("trace entry is serializable")
}

impl FunnelDag {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    fn record(&mut self, op: &str, node: u64) {
        let seq = self.trace.len() as u64;
        let prev_hash = self.trace.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = trace_hash(seq, &prev_hash, op, node);
        self.trace.push(TraceEntry {
            seq,
            prev_hash,
            op: op.to_owned(),
            node,
            entry_hash,
        });
    }

    /// Add a node depending on existing nodes. Because dependencies must already
    /// exist, the graph stays acyclic.
    ///
    /// # Errors
    /// [`FunnelError::UnknownDependency`] if a dependency does not exist.
    pub fn add_node(
        &mut self,
        task: impl Into<String>,
        host_cell: HostCellId,
        deps: &[FunnelNodeId],
        ttl: u64,
    ) -> Result<FunnelNodeId, FunnelError> {
        for dep in deps {
            if !self.nodes.contains_key(&dep.0) {
                return Err(FunnelError::UnknownDependency);
            }
        }
        let id = FunnelNodeId(self.next_id);
        self.next_id += 1;
        self.nodes.insert(
            id.0,
            FunnelNode {
                id,
                task: task.into(),
                host_cell,
                deps: deps.to_vec(),
                spawned_at: self.now,
                ttl,
                state: NodeState::Pending,
            },
        );
        self.record("add", id.0);
        Ok(id)
    }

    #[must_use]
    pub fn get(&self, id: FunnelNodeId) -> Option<&FunnelNode> {
        self.nodes.get(&id.0)
    }

    fn is_live(&self, node: &FunnelNode) -> bool {
        node.state == NodeState::Pending && self.now < node.expires_at()
    }

    /// The nodes ready to run: pending, unexpired, with all dependencies done.
    #[must_use]
    pub fn ready(&self) -> Vec<FunnelNodeId> {
        self.nodes
            .values()
            .filter(|n| {
                self.is_live(n)
                    && n.deps.iter().all(|d| {
                        self.nodes
                            .get(&d.0)
                            .is_some_and(|dn| dn.state == NodeState::Done)
                    })
            })
            .map(|n| n.id)
            .collect()
    }

    /// Mark a node done. It must be live and all its dependencies done.
    ///
    /// # Errors
    /// [`FunnelError::NotFound`] or [`FunnelError::NotRunnable`].
    pub fn complete(&mut self, id: FunnelNodeId) -> Result<(), FunnelError> {
        let deps_done = {
            let node = self.nodes.get(&id.0).ok_or(FunnelError::NotFound)?;
            if !self.is_live(node) {
                return Err(FunnelError::NotRunnable);
            }
            node.deps.iter().all(|d| {
                self.nodes
                    .get(&d.0)
                    .is_some_and(|dn| dn.state == NodeState::Done)
            })
        };
        if !deps_done {
            return Err(FunnelError::NotRunnable);
        }
        self.nodes.get_mut(&id.0).expect("checked").state = NodeState::Done;
        self.record("complete", id.0);
        Ok(())
    }

    /// Explicitly dissolve a node.
    ///
    /// # Errors
    /// [`FunnelError::NotFound`].
    pub fn dissolve(&mut self, id: FunnelNodeId) -> Result<(), FunnelError> {
        let node = self.nodes.get_mut(&id.0).ok_or(FunnelError::NotFound)?;
        node.state = NodeState::Dissolved;
        self.record("dissolve", id.0);
        Ok(())
    }

    /// Advance logical time by one tick, dissolving nodes whose TTL elapsed.
    pub fn tick(&mut self) -> Vec<FunnelNodeId> {
        self.now += 1;
        let now = self.now;
        let mut dissolved = Vec::new();
        let expired: Vec<u64> = self
            .nodes
            .values()
            .filter(|n| n.state == NodeState::Pending && now >= n.expires_at())
            .map(|n| n.id.0)
            .collect();
        for id in expired {
            self.nodes.get_mut(&id).expect("just found").state = NodeState::Dissolved;
            self.record("ttl_dissolve", id);
            dissolved.push(FunnelNodeId(id));
        }
        dissolved
    }

    /// A dependency-respecting topological order. Always succeeds — the DAG has
    /// no cycles by construction.
    #[must_use]
    pub fn topological_order(&self) -> Vec<FunnelNodeId> {
        // Nodes were created in dependency order (deps precede dependents), so
        // ascending id order is already a valid topological order.
        self.nodes.keys().map(|k| FunnelNodeId(*k)).collect()
    }

    /// The current trace head.
    #[must_use]
    pub fn trace_head(&self) -> Digest {
        self.trace.last().map_or(Digest::GENESIS, |e| e.entry_hash)
    }

    /// Verify the trace chain.
    #[must_use]
    pub fn verify_trace(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.trace.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash != trace_hash(entry.seq, &entry.prev_hash, &entry.op, entry.node) {
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
    use ssk_host_cells::HostCellPlane;

    fn cell(plane: &mut HostCellPlane, role: &str) -> HostCellId {
        plane.spawn(role, ["work"], "session-1", 100)
    }

    // The graph is acyclic and topologically orderable; a node carries a host
    // cell (a work relation), never a locator.
    #[test]
    fn is_a_dag_over_host_cells() {
        let mut plane = HostCellPlane::new();
        let mut dag = FunnelDag::new();
        let a = dag
            .add_node("scan", cell(&mut plane, "scanner"), &[], 100)
            .unwrap();
        let b = dag
            .add_node("build", cell(&mut plane, "builder"), &[a], 100)
            .unwrap();
        let c = dag
            .add_node("emit", cell(&mut plane, "emitter"), &[a, b], 100)
            .unwrap();
        // A dependency must be an existing node — you cannot point forward, so no
        // cycle can be formed.
        assert_eq!(
            dag.add_node("x", cell(&mut plane, "x"), &[FunnelNodeId(999)], 100)
                .unwrap_err(),
            FunnelError::UnknownDependency
        );
        let order = dag.topological_order();
        assert_eq!(order, vec![a, b, c]);
        // Each node is bound to a host cell (host-relation work).
        assert_eq!(dag.get(c).unwrap().deps, vec![a, b]);
        let _ = dag.get(a).unwrap().host_cell;
    }

    #[test]
    fn ready_respects_dependencies() {
        let mut plane = HostCellPlane::new();
        let mut dag = FunnelDag::new();
        let a = dag.add_node("a", cell(&mut plane, "a"), &[], 100).unwrap();
        let b = dag.add_node("b", cell(&mut plane, "b"), &[a], 100).unwrap();
        // Only a is ready (b depends on a).
        assert_eq!(dag.ready(), vec![a]);
        // b cannot complete before a.
        assert_eq!(dag.complete(b).unwrap_err(), FunnelError::NotRunnable);
        dag.complete(a).unwrap();
        assert_eq!(dag.ready(), vec![b]);
        dag.complete(b).unwrap();
        assert!(dag.ready().is_empty());
    }

    #[test]
    fn ttl_dissolves_pending_nodes() {
        let mut plane = HostCellPlane::new();
        let mut dag = FunnelDag::new();
        let a = dag.add_node("a", cell(&mut plane, "a"), &[], 2).unwrap();
        assert!(dag.tick().is_empty()); // now 1
        assert_eq!(dag.tick(), vec![a]); // now 2 == expiry
        assert_eq!(dag.get(a).unwrap().state, NodeState::Dissolved);
        assert!(dag.ready().is_empty());
    }

    #[test]
    fn trace_is_replay_stable_and_tamper_evident() {
        let build = || {
            let mut plane = HostCellPlane::new();
            let mut dag = FunnelDag::new();
            let a = dag.add_node("a", cell(&mut plane, "a"), &[], 100).unwrap();
            let b = dag.add_node("b", cell(&mut plane, "b"), &[a], 100).unwrap();
            dag.complete(a).unwrap();
            dag.complete(b).unwrap();
            dag
        };
        let x = build();
        let y = build();
        assert_eq!(
            x.trace_head(),
            y.trace_head(),
            "same op sequence -> same trace head"
        );
        assert!(x.verify_trace());
        let mut tampered = x.clone();
        tampered.trace[0].op = "forge".to_owned();
        assert!(!tampered.verify_trace());
    }
}
