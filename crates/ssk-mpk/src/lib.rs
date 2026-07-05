#![forbid(unsafe_code)]

//! # ssk-mpk — the FCHL-MPK finite-symmetry core (Band A)
//!
//! A deterministic "microscope" over small (`n ≤ 8`) undirected graph windows.
//! Everything here is pure integer computation, content-addressed and
//! replay-verifiable, reusing the Ω `Digest` / `GateOutcomeKind` primitives.
//!
//! The apparatus and its invariants (FCHL-MPK Addendum, tested below):
//!
//! * [`Graph::canon`] — canonical form; deterministic and idempotent (I3).
//! * [`Graph::orbit_size`] / [`Graph::automorphism_count`] — with
//!   `|Orb|·|Stab| = n!` (I4, the orbit-stabilizer theorem).
//! * [`Graph::complement`] — with `Comp²(G) = G` (I5).
//! * [`Graph::spectrum`] — the characteristic polynomial (exact integer
//!   coefficients); cospectrality is polynomial equality.
//! * [`CospectralGate`] — spectrum alone is **not** identity: two cospectral but
//!   non-isomorphic graphs `Hold`, never `Pass` (I6).
//! * [`Catalog`] — an out-of-catalog window is a visible `Hold`, never a silent
//!   pass (I7).
//! * [`MpkFieldSample`] — a content-addressed per-window sample; the same window
//!   yields the same digest (I8, replay).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use ssk_types::{content_id, GateOutcomeKind, HashAlg};

content_id!(MpkSampleId);

/// The maximum window size this core operates on.
pub const MAX_VERTICES: usize = 8;

/// Errors the MPK core can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MpkError {
    #[error("graph exceeds MAX_VERTICES ({0} > {MAX_VERTICES})")]
    TooLarge(usize),
    #[error("edge endpoint out of range: {0}")]
    BadEdge(usize),
}

/// An undirected, loop-free graph on `n ≤ 8` vertices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Graph {
    n: usize,
    /// Row-major adjacency (symmetric, zero diagonal).
    adj: Vec<Vec<bool>>,
}

impl Graph {
    /// An empty graph on `n` vertices.
    ///
    /// # Errors
    /// [`MpkError::TooLarge`] if `n > MAX_VERTICES`.
    pub fn empty(n: usize) -> Result<Self, MpkError> {
        if n > MAX_VERTICES {
            return Err(MpkError::TooLarge(n));
        }
        Ok(Graph {
            n,
            adj: vec![vec![false; n]; n],
        })
    }

    /// Build a graph from an edge list.
    ///
    /// # Errors
    /// [`MpkError::TooLarge`] or [`MpkError::BadEdge`].
    pub fn from_edges(n: usize, edges: &[(usize, usize)]) -> Result<Self, MpkError> {
        let mut g = Graph::empty(n)?;
        for &(a, b) in edges {
            if a >= n || b >= n {
                return Err(MpkError::BadEdge(a.max(b)));
            }
            if a != b {
                g.adj[a][b] = true;
                g.adj[b][a] = true;
            }
        }
        Ok(g)
    }

    #[must_use]
    pub fn order(&self) -> usize {
        self.n
    }

    #[must_use]
    pub fn edge_count(&self) -> usize {
        let mut c = 0;
        for i in 0..self.n {
            for j in (i + 1)..self.n {
                if self.adj[i][j] {
                    c += 1;
                }
            }
        }
        c
    }

    /// The upper-triangle adjacency packed into a `u64` key (vertex order fixed).
    fn packed(&self) -> u64 {
        pack(&self.adj, self.n, &identity(self.n))
    }

    /// The canonical form's packed key — the lexicographically minimal packing
    /// over all vertex relabelings. Deterministic and idempotent (I3).
    #[must_use]
    pub fn canon_key(&self) -> u64 {
        permutations(self.n)
            .iter()
            .map(|p| pack(&self.adj, self.n, p))
            .min()
            .unwrap_or(0)
    }

    /// The canonical representative graph of `self`'s isomorphism class.
    #[must_use]
    pub fn canon(&self) -> Graph {
        unpack(self.canon_key(), self.n)
    }

    /// The number of automorphisms `|Aut(G)| = |Stab(G)|` under `S_n`.
    #[must_use]
    pub fn automorphism_count(&self) -> u64 {
        let base = self.packed();
        permutations(self.n)
            .iter()
            .filter(|p| pack(&self.adj, self.n, p) == base)
            .count() as u64
    }

    /// The orbit size `|Orb(G)|` — the number of distinct relabelings.
    #[must_use]
    pub fn orbit_size(&self) -> u64 {
        let distinct: BTreeSet<u64> = permutations(self.n)
            .iter()
            .map(|p| pack(&self.adj, self.n, p))
            .collect();
        distinct.len() as u64
    }

    /// The complement graph. `Comp²(G) = G` (I5).
    #[must_use]
    #[allow(clippy::needless_range_loop)]
    pub fn complement(&self) -> Graph {
        let mut adj = vec![vec![false; self.n]; self.n];
        for i in 0..self.n {
            for j in 0..self.n {
                if i != j {
                    adj[i][j] = !self.adj[i][j];
                }
            }
        }
        Graph { n: self.n, adj }
    }

    /// Two graphs are isomorphic iff their canonical forms coincide.
    #[must_use]
    pub fn is_isomorphic(&self, other: &Graph) -> bool {
        self.n == other.n && self.canon_key() == other.canon_key()
    }

    /// The spectrum, as the exact integer coefficients of the characteristic
    /// polynomial `det(xI − A) = xⁿ + c₁xⁿ⁻¹ + … + cₙ` (returns `[c₁ … cₙ]`).
    /// Cospectrality is equality of these vectors.
    #[must_use]
    pub fn spectrum(&self) -> Vec<i128> {
        characteristic_polynomial(&self.adj, self.n)
    }

    /// Whether `self` and `other` are cospectral (same spectrum).
    #[must_use]
    pub fn is_cospectral(&self, other: &Graph) -> bool {
        self.spectrum() == other.spectrum()
    }
}

fn identity(n: usize) -> Vec<usize> {
    (0..n).collect()
}

// Pack the upper triangle of `adj` under relabeling `perm` (perm[i] = new label
// of vertex i) into a u64. For n<=8 the triangle has <=28 bits.
#[allow(clippy::needless_range_loop)]
fn pack(adj: &[Vec<bool>], n: usize, perm: &[usize]) -> u64 {
    let mut bits = 0u64;
    // Build the relabeled adjacency (perm[i] = new label of vertex i), then read
    // its upper triangle in canonical bit order.
    let mut relabeled = vec![vec![false; n]; n];
    for i in 0..n {
        for j in 0..n {
            if adj[i][j] {
                relabeled[perm[i]][perm[j]] = true;
            }
        }
    }
    let mut pos = 0;
    for a in 0..n {
        for b in (a + 1)..n {
            if relabeled[a][b] {
                bits |= 1 << pos;
            }
            pos += 1;
        }
    }
    bits
}

#[allow(clippy::needless_range_loop)]
fn unpack(bits: u64, n: usize) -> Graph {
    let mut adj = vec![vec![false; n]; n];
    let mut pos = 0;
    for a in 0..n {
        for b in (a + 1)..n {
            if bits & (1 << pos) != 0 {
                adj[a][b] = true;
                adj[b][a] = true;
            }
            pos += 1;
        }
    }
    Graph { n, adj }
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur: Vec<usize> = (0..n).collect();
    permute(&mut cur, 0, &mut out);
    out
}

fn permute(cur: &mut Vec<usize>, k: usize, out: &mut Vec<Vec<usize>>) {
    if k == cur.len() {
        out.push(cur.clone());
        return;
    }
    for i in k..cur.len() {
        cur.swap(k, i);
        permute(cur, k + 1, out);
        cur.swap(k, i);
    }
}

/// `n!`, saturating at `u64::MAX` rather than overflowing. The orbit-
/// stabilizer identity `|Orb| * |Aut| == n!` this crate proves only holds for
/// `n <= 8` (`MAX_VERTICES`) in the first place — `21!` already exceeds
/// `u64::MAX`, so any caller passing a larger `n` gets a saturated, honestly-
/// wrong-but-non-panicking sentinel rather than a debug-build abort or a
/// silently-wrapped (also wrong) release-build value.
#[must_use]
pub fn factorial(n: usize) -> u64 {
    (1..=n as u64)
        .try_fold(1u64, |acc, k| acc.checked_mul(k))
        .unwrap_or(u64::MAX)
}

// Characteristic polynomial coefficients via Newton's identities from the power
// traces tr(A^k). Exact integer arithmetic (the divisions by k are exact).
#[allow(clippy::needless_range_loop)]
fn characteristic_polynomial(adj: &[Vec<bool>], n: usize) -> Vec<i128> {
    if n == 0 {
        return Vec::new();
    }
    // A as i128 matrix.
    let a: Vec<Vec<i128>> = adj
        .iter()
        .map(|row| row.iter().map(|&e| i128::from(e)).collect())
        .collect();
    // Power traces p_k = tr(A^k), k = 1..=n.
    let mut power = identity_matrix(n);
    let mut p = vec![0i128; n + 1];
    for k in 1..=n {
        power = matmul(&power, &a, n);
        p[k] = (0..n).map(|i| power[i][i]).sum();
    }
    // c_0 = 1; c_k = -(1/k) * (p_k + sum_{i=1}^{k-1} c_i p_{k-i}).
    let mut c = vec![0i128; n + 1];
    c[0] = 1;
    for k in 1..=n {
        let mut acc = p[k];
        for i in 1..k {
            acc += c[i] * p[k - i];
        }
        c[k] = -acc / (k as i128);
    }
    c[1..=n].to_vec()
}

fn identity_matrix(n: usize) -> Vec<Vec<i128>> {
    let mut m = vec![vec![0i128; n]; n];
    for (i, row) in m.iter_mut().enumerate() {
        row[i] = 1;
    }
    m
}

fn matmul(a: &[Vec<i128>], b: &[Vec<i128>], n: usize) -> Vec<Vec<i128>> {
    let mut c = vec![vec![0i128; n]; n];
    for i in 0..n {
        for k in 0..n {
            if a[i][k] != 0 {
                let aik = a[i][k];
                for j in 0..n {
                    c[i][j] += aik * b[k][j];
                }
            }
        }
    }
    c
}

/// A content-addressed per-window structural sample. The same graph yields the
/// same sample and digest (I8, replay).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpkFieldSample {
    pub id: MpkSampleId,
    pub order: usize,
    pub edge_count: usize,
    pub canon_key: u64,
    pub spectrum: Vec<i128>,
    pub orbit_size: u64,
    pub automorphism_count: u64,
}

#[derive(Serialize)]
struct SampleForm<'a> {
    order: usize,
    edge_count: usize,
    canon_key: u64,
    spectrum: &'a [i128],
    orbit_size: u64,
    automorphism_count: u64,
}

impl MpkFieldSample {
    /// Derive a sample from a graph (a pure function of the graph).
    #[must_use]
    pub fn of(graph: &Graph) -> Self {
        let order = graph.order();
        let edge_count = graph.edge_count();
        let canon_key = graph.canon_key();
        let spectrum = graph.spectrum();
        let orbit_size = graph.orbit_size();
        let automorphism_count = graph.automorphism_count();
        let id = MpkSampleId::of(
            &SampleForm {
                order,
                edge_count,
                canon_key,
                spectrum: &spectrum,
                orbit_size,
                automorphism_count,
            },
            HashAlg::Blake3,
        )
        .expect("sample form is serializable");
        MpkFieldSample {
            id,
            order,
            edge_count,
            canon_key,
            spectrum,
            orbit_size,
            automorphism_count,
        }
    }
}

/// The cospectral gate: spectrum alone is not identity.
///
/// Evaluating an "are these the same" claim between two graphs yields `Pass`
/// only for genuine isomorphism; two cospectral but non-isomorphic graphs
/// `Hold` (never `Pass`, I6); spectrally-distinct graphs `Reject`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CospectralGate;

impl CospectralGate {
    #[must_use]
    pub fn evaluate(&self, left: &Graph, right: &Graph) -> GateOutcomeKind {
        if left.is_isomorphic(right) {
            GateOutcomeKind::Pass
        } else if left.is_cospectral(right) {
            // Same spectrum, different isomorphism class — spectrum cannot decide
            // identity, so we hold rather than fabricate a pass.
            GateOutcomeKind::Hold
        } else {
            GateOutcomeKind::Reject
        }
    }
}

/// A catalog of known canonical forms → labels. An unknown window holds.
#[derive(Clone, Debug, Default)]
pub struct Catalog {
    entries: BTreeMap<u64, String>,
}

impl Catalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a graph's canonical form under a label.
    pub fn register(&mut self, graph: &Graph, label: impl Into<String>) {
        self.entries.insert(graph.canon_key(), label.into());
    }

    /// Look up a graph's label by canonical form. `None` for out-of-catalog.
    #[must_use]
    pub fn lookup(&self, graph: &Graph) -> Option<&str> {
        self.entries.get(&graph.canon_key()).map(String::as_str)
    }

    /// Classify a window: a catalog hit passes with its label; an out-of-catalog
    /// window is a visible `Hold`, never a silent pass (I7).
    #[must_use]
    pub fn classify(&self, graph: &Graph) -> (GateOutcomeKind, Option<String>) {
        match self.lookup(graph) {
            Some(label) => (GateOutcomeKind::Pass, Some(label.to_owned())),
            None => (GateOutcomeKind::Hold, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The classic Schwenk cospectral pair on 5 vertices.
    fn c4_plus_k1() -> Graph {
        Graph::from_edges(5, &[(0, 1), (1, 2), (2, 3), (3, 0)]).unwrap()
    }
    fn star_k14() -> Graph {
        Graph::from_edges(5, &[(0, 1), (0, 2), (0, 3), (0, 4)]).unwrap()
    }

    // FCHL-MPK I3: Canon is deterministic and idempotent.
    #[test]
    fn canon_is_idempotent() {
        for g in [c4_plus_k1(), star_k14()] {
            let c = g.canon();
            assert_eq!(c.canon_key(), g.canon_key());
            assert_eq!(
                c.canon().canon_key(),
                c.canon_key(),
                "Canon(Canon(G)) == Canon(G)"
            );
        }
    }

    // FCHL-MPK I4: |Orb(G)| · |Stab(G)| = n!.
    #[test]
    fn orbit_stabilizer_theorem() {
        for g in [
            c4_plus_k1(),
            star_k14(),
            Graph::from_edges(4, &[(0, 1), (2, 3)]).unwrap(),
        ] {
            assert_eq!(
                g.orbit_size() * g.automorphism_count(),
                factorial(g.order())
            );
        }
    }

    // FCHL-MPK I5: Comp²(G) = G.
    #[test]
    fn complement_is_an_involution() {
        for g in [c4_plus_k1(), star_k14()] {
            assert_eq!(g.complement().complement(), g);
        }
    }

    // FCHL-MPK I6: spectrum alone is not identity — cospectral, non-isomorphic
    // graphs Hold, never Pass.
    #[test]
    fn cospectral_non_isomorphic_holds_never_passes() {
        let a = c4_plus_k1();
        let b = star_k14();
        assert!(a.is_cospectral(&b), "the Schwenk pair is cospectral");
        assert!(!a.is_isomorphic(&b), "but not isomorphic");
        let outcome = CospectralGate.evaluate(&a, &b);
        assert_eq!(outcome, GateOutcomeKind::Hold);
        assert_ne!(
            outcome,
            GateOutcomeKind::Pass,
            "spectrum alone must never produce a Pass"
        );
        // Genuine isomorphism does pass; a spectrally distinct graph rejects.
        assert_eq!(
            CospectralGate.evaluate(&a, &a.canon()),
            GateOutcomeKind::Pass
        );
        let triangle = Graph::from_edges(5, &[(0, 1), (1, 2), (2, 0)]).unwrap();
        assert_eq!(
            CospectralGate.evaluate(&a, &triangle),
            GateOutcomeKind::Reject
        );
    }

    // FCHL-MPK I7: out-of-catalog window holds, never silently passes.
    #[test]
    fn out_of_catalog_holds() {
        let mut catalog = Catalog::new();
        catalog.register(&star_k14(), "star-k1-4");
        assert_eq!(
            catalog.classify(&star_k14()),
            (GateOutcomeKind::Pass, Some("star-k1-4".to_owned()))
        );
        // c4+k1 is cospectral with the star but a different isomorphism class,
        // so it is NOT in the catalog: it holds, it does not pass.
        let (outcome, label) = catalog.classify(&c4_plus_k1());
        assert_eq!(outcome, GateOutcomeKind::Hold);
        assert!(label.is_none());
    }

    // FCHL-MPK I8: same window ⇒ same sample digest (replay).
    #[test]
    fn sample_is_replay_stable() {
        let a = MpkFieldSample::of(&c4_plus_k1());
        let b = MpkFieldSample::of(&c4_plus_k1());
        assert_eq!(a, b);
        assert_eq!(a.id, b.id);
        // Cospectral graphs share a spectrum but differ by canonical form, so
        // their samples are distinct — the sample commits to more than spectrum.
        let s = MpkFieldSample::of(&star_k14());
        assert_eq!(a.spectrum, s.spectrum);
        assert_ne!(a.id, s.id);
    }

    // Regression: factorial(n) is a public fn taking an arbitrary usize; for
    // n >= 21 the true value exceeds u64::MAX. It must saturate, not panic
    // (debug/overflow-checks builds) or silently wrap to a wrong value
    // (release builds).
    #[test]
    fn factorial_saturates_instead_of_overflowing() {
        assert_eq!(factorial(0), 1);
        assert_eq!(factorial(1), 1);
        assert_eq!(factorial(5), 120);
        assert_eq!(factorial(20), 2_432_902_008_176_640_000);
        assert_eq!(
            factorial(21),
            u64::MAX,
            "21! exceeds u64::MAX -> saturate, don't panic or wrap"
        );
        assert_eq!(factorial(100), u64::MAX);
    }
}
