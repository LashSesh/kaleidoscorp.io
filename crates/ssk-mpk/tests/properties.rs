//! Property-based confirmation of the FCHL-MPK core invariants over the input
//! space — not just the worked examples. Enterprise-grade rigor: the
//! orbit-stabilizer theorem, canon idempotence + isomorphism-invariance, and the
//! complement involution are checked over hundreds of random graphs, and canon
//! is proven a genuine isomorphism invariant (invariant under relabeling).

use proptest::prelude::*;
use ssk_mpk::{factorial, Graph, MpkFieldSample};

// Enumerate the C(n,2) vertex pairs in canonical (a<b) order.
fn pairs(n: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for a in 0..n {
        for b in (a + 1)..n {
            out.push((a, b));
        }
    }
    out
}

// Build the edge list a `bits` bitmask selects over the pairs, optionally
// relabeled by `perm` (perm[i] = new label of vertex i).
fn edges_from_bits(n: usize, bits: u32, perm: &[usize]) -> Vec<(usize, usize)> {
    pairs(n)
        .into_iter()
        .enumerate()
        .filter(|(i, _)| bits & (1 << i) != 0)
        .map(|(_, (a, b))| (perm[a], perm[b]))
        .collect()
}

// A random graph on 2..=6 vertices (n! <= 720, so the exhaustive apparatus stays
// fast), paired with a random relabeling permutation of its vertices.
fn graph_and_perm() -> impl Strategy<Value = (usize, u32, Vec<usize>)> {
    (2usize..=6)
        .prop_flat_map(|n| {
            let bit_count = n * (n - 1) / 2;
            let max_bits = 1u32 << bit_count;
            (
                Just(n),
                0u32..max_bits,
                Just((0..n).collect::<Vec<usize>>()).prop_shuffle(),
            )
        })
        .prop_map(|(n, bits, perm)| (n, bits, perm))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]

    // FCHL-MPK I4: the orbit-stabilizer theorem holds for every graph.
    #[test]
    fn orbit_stabilizer_holds_for_all_graphs((n, bits, _) in graph_and_perm()) {
        let g = Graph::from_edges(n, &edges_from_bits(n, bits, &(0..n).collect::<Vec<_>>())).unwrap();
        prop_assert_eq!(g.orbit_size() * g.automorphism_count(), factorial(n));
    }

    // FCHL-MPK I3: Canon is idempotent for every graph.
    #[test]
    fn canon_is_idempotent_for_all_graphs((n, bits, _) in graph_and_perm()) {
        let g = Graph::from_edges(n, &edges_from_bits(n, bits, &(0..n).collect::<Vec<_>>())).unwrap();
        prop_assert_eq!(g.canon().canon_key(), g.canon_key());
    }

    // Canon is a genuine isomorphism invariant: relabeling the vertices does not
    // change the canonical form. This is the property that makes it an identity.
    #[test]
    fn canon_is_invariant_under_relabeling((n, bits, perm) in graph_and_perm()) {
        let identity: Vec<usize> = (0..n).collect();
        let g = Graph::from_edges(n, &edges_from_bits(n, bits, &identity)).unwrap();
        let relabeled = Graph::from_edges(n, &edges_from_bits(n, bits, &perm)).unwrap();
        prop_assert_eq!(g.canon_key(), relabeled.canon_key());
        prop_assert!(g.is_isomorphic(&relabeled));
        // An isomorphism invariant implies cospectrality (the converse is false —
        // that is exactly the Schwenk pair).
        prop_assert!(g.is_cospectral(&relabeled));
        // The MPK sample is likewise relabeling-invariant.
        prop_assert_eq!(MpkFieldSample::of(&g).canon_key, MpkFieldSample::of(&relabeled).canon_key);
    }

    // FCHL-MPK I5: the complement is an involution for every graph.
    #[test]
    fn complement_is_an_involution_for_all_graphs((n, bits, _) in graph_and_perm()) {
        let g = Graph::from_edges(n, &edges_from_bits(n, bits, &(0..n).collect::<Vec<_>>())).unwrap();
        prop_assert_eq!(g.complement().complement(), g);
    }

    // FCHL-MPK I8: the sample is a pure function of the graph (replay-stable).
    #[test]
    fn sample_is_deterministic_for_all_graphs((n, bits, _) in graph_and_perm()) {
        let g = Graph::from_edges(n, &edges_from_bits(n, bits, &(0..n).collect::<Vec<_>>())).unwrap();
        prop_assert_eq!(MpkFieldSample::of(&g), MpkFieldSample::of(&g));
    }
}
