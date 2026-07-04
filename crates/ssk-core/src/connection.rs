//! Typestate machine for the connection lifecycle (Master Spec Ω+1 ch. 3.3).
//! An illegal transition is a compile error, not a runtime bug: each state's
//! impl block exposes only the one transition method the spec allows from
//! that state, so there is no public path, for example, from `Split` or
//! `Placed` directly to `Materialized`.
//!
//! Phase 0 scaffolding note (`docs/OMEGA_CORE_CONFORMANCE_SPEC.md` Section
//! E.3): `canonicalize`/`birefract`/`place`/`gate`/`materialize` bodies are
//! deliberately stubbed here — their real logic depends on later phases
//! (spec Section V): `birefract` needs Phase 1's real split logic, `place`
//! needs Phase 3's Hypercube, `gate` needs Phase 3's real gate vector,
//! `materialize` needs Phase 4's real tensor. The collaborator parameter
//! types below (`CoreCanonicalizer`, `Policy`, `Hypercube`, `GateVector`,
//! `StitchTensor`) are Phase-0-local placeholders, not the real cross-crate
//! types those names will resolve to once wired up in later phases — kept
//! local here so this foundation-crate skeleton compiles today without
//! introducing a dependency on higher crates before it is time.

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
