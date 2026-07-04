//! Typestate machine for the connection lifecycle (Master Spec Ω+1 ch. 3.3).
//! An illegal transition is a compile error, not a runtime bug: each state's
//! impl block exposes only the one transition method the spec allows from
//! that state, so there is no public path, for example, from `Split` or
//! `Placed` directly to `Materialized`.
//!
//! Phase 0 scaffolding note (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md` Section
//! E.3): `canonicalize`/`birefract`/`place`/`gate`/`materialize` bodies are
//! deliberately stubbed here. The collaborator parameter types below
//! (`CoreCanonicalizer`, `Policy`, `Hypercube`, `GateVector`, `StitchTensor`)
//! are local placeholders, not the real cross-crate types of the same name.
//!
//! **Disclosed architectural constraint (as of Phase 4):** `place`/`gate`
//! cannot be wired to the real `ssk_gates::pch::Hypercube`/
//! `ssk_gates::GateVector` without creating a dependency cycle —
//! `ssk-gates` already depends on `ssk-core` (for `MirrorOrbit` and
//! `CoreObject`). Closing this for real needs dependency inversion: local
//! traits defined here in `ssk-core` that `ssk-gates`' concrete types
//! implement (since `ssk-gates` already sees this crate), so `place`/`gate`
//! become generic over the trait rather than naming `ssk-gates` types
//! directly. That redesign is deliberately out of scope for this pass — it
//! is a structural decision, not a per-phase content addition, so it should
//! land deliberately once made rather than being rushed alongside other
//! phase work. `materialize`'s real body — building an `Accepted` and
//! calling `ssk_tensor::StitchTensor::apply_sorted` (Section M, real and
//! tested as of Phase 4) — is deferred to land alongside Phase 5's
//! `RunOutcome`/pipeline-stage rework (Section R), since that is where the
//! runtime's gate-witness plumbing is already being reshaped to carry a
//! real `BcikStitch` forward instead of discarding it after `BcikGate`
//! evaluates; wiring `StitchTensor` in before that would mean computing the
//! same `Bcik::cross()` a second time here.

use core::marker::PhantomData;
use ssk_types::{BoundaryResidue, FaultKind, PhaseVector};

pub struct Intent;
pub struct Canonical;
pub struct Split;
pub struct Placed;
pub struct GatePassed;
pub struct Materialized;

/// Phase-0 placeholder for the real canonicalizer collaborator (Phase 1).
#[derive(Debug, Default)]
pub struct CoreCanonicalizer;

/// Phase-0 placeholder for the real `ssk-config::Policy` collaborator.
#[derive(Debug, Default)]
pub struct Policy;

/// Phase-0 placeholder for the real `ssk-gates::pch::Hypercube` collaborator (Phase 3).
#[derive(Debug, Default)]
pub struct Hypercube;

/// Phase-0 placeholder for the real `ssk-gates::GateVector` collaborator (Phase 3).
#[derive(Debug, Default)]
pub struct GateVector;

/// Phase-0 placeholder for the real `ssk-tensor::StitchTensor` collaborator (Phase 4).
#[derive(Debug, Default)]
pub struct StitchTensor;

/// Generic gate-outcome wrapper (Master Spec Ω+1 ch. 3.3): mirrors
/// `GateVerdict`'s five-way resolution but carries the passing payload
/// generically, since `Connection::gate`'s success value is a typestate, not
/// a `GateWitness`.
#[derive(Debug)]
pub enum GateOutcome<T> {
    Pass(T),
    Hold(BoundaryResidue),
    Refine(BoundaryResidue),
    Reject(BoundaryResidue),
    Quarantine(BoundaryResidue),
}

/// Opaque inner connection state. Phase-0 placeholder — grows real fields
/// (canonical core, rays, placement, gate report...) as later phases fill in
/// each transition's real body.
#[derive(Debug, Default)]
pub struct ConnectionInner;

/// The typestate-carrying connection value. `S` is a phantom marker for the
/// connection's current lifecycle stage; it carries no runtime data of its
/// own.
pub struct Connection<S> {
    inner: ConnectionInner,
    _s: PhantomData<S>,
}

impl Connection<Intent> {
    #[must_use]
    pub fn new(inner: ConnectionInner) -> Self {
        Self {
            inner,
            _s: PhantomData,
        }
    }

    /// Phase-0 stub: real canonicalization lands in Phase 1 (spec Section F).
    pub fn canonicalize(self, _c: &CoreCanonicalizer) -> Result<Connection<Canonical>, FaultKind> {
        Ok(Connection {
            inner: self.inner,
            _s: PhantomData,
        })
    }
}

impl Connection<Canonical> {
    /// Phase-0 stub: real birefringent split lands in Phase 1 (spec Section F.3).
    pub fn birefract(self, _p: &Policy) -> Result<Connection<Split>, FaultKind> {
        Ok(Connection {
            inner: self.inner,
            _s: PhantomData,
        })
    }
}

impl Connection<Split> {
    /// Phase-0 stub: real PCH placement lands in Phase 3 (spec Section I).
    pub fn place(
        self,
        _cube: &Hypercube,
        _theta: &PhaseVector,
    ) -> Result<Connection<Placed>, FaultKind> {
        Ok(Connection {
            inner: self.inner,
            _s: PhantomData,
        })
    }
}

impl Connection<Placed> {
    /// Only a `Placed` connection can be gated; only a `GatePassed`
    /// connection can be materialized. Enforced at compile time: there is no
    /// other public path to either transition.
    ///
    /// Phase-0 stub: real gate evaluation lands in Phase 3 (spec Section K).
    pub fn gate(self, _gv: &GateVector, _p: &Policy) -> GateOutcome<Connection<GatePassed>> {
        GateOutcome::Pass(Connection {
            inner: self.inner,
            _s: PhantomData,
        })
    }
}

impl Connection<GatePassed> {
    /// `StitchTensor::materialize` is reachable only from
    /// `Connection<GatePassed>` — there is no public path from `Placed` or
    /// `Split` to a tensor mutation. This makes fail-closed materialization a
    /// property of the API shape, not merely of runtime logic.
    ///
    /// Phase-0 stub: real tensor materialization lands in Phase 4 (spec Section M).
    pub fn materialize(
        self,
        _tensor: &mut StitchTensor,
    ) -> Result<Connection<Materialized>, FaultKind> {
        Ok(Connection {
            inner: self.inner,
            _s: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle_compiles_and_runs() {
        let c = Connection::<Intent>::new(ConnectionInner);
        let c = c.canonicalize(&CoreCanonicalizer).expect("canonicalize");
        let c = c.birefract(&Policy).expect("birefract");
        let c = c.place(&Hypercube, &PhaseVector::zero()).expect("place");
        let c = match c.gate(&GateVector, &Policy) {
            GateOutcome::Pass(c) => c,
            _ => panic!("expected GateOutcome::Pass"),
        };
        let _c = c.materialize(&mut StitchTensor).expect("materialize");
    }
}
