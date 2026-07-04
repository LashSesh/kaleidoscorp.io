#![forbid(unsafe_code)]

//! # ssk-host-cells — the HostCellPlane (Heavenly Hosts, FCHL-MPK Band B)
//!
//! Ephemeral **role cells**. A [`HostCell`] grants a capability set within a
//! scope for a bounded logical lifetime (TTL), then dissolves. Two rules are
//! structural:
//!
//! * **A HostCell is not a public identity.** Its id is a transient,
//!   domain-separated role handle: spawning "the same role" twice yields two
//!   *different* cells. A cell cannot be treated as a stable identity.
//! * **Capability- and scope-bound.** A cell may only act with a capability it
//!   was granted, within its scope, while it is still active.
//!
//! Time is logical (a tick counter) so the plane is pure and deterministic — no
//! clock. A cell dissolves either explicitly or when its TTL elapses; a
//! dissolved cell can do nothing.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use ssk_types::{content_id, HashAlg};

content_id!(HostCellId);

/// Errors the host-cell plane can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostCellError {
    #[error("no such host cell")]
    NotFound,
    #[error("host cell already dissolved")]
    AlreadyDissolved,
}

/// A cell's lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellState {
    Active,
    Dissolved,
}

/// An ephemeral, capability- and scope-bound role cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostCell {
    pub id: HostCellId,
    pub role: String,
    pub capabilities: BTreeSet<String>,
    pub scope: String,
    pub spawned_at: u64,
    pub ttl: u64,
    pub state: CellState,
}

impl HostCell {
    /// The logical tick at which this cell expires.
    #[must_use]
    pub fn expires_at(&self) -> u64 {
        self.spawned_at.saturating_add(self.ttl)
    }

    fn is_active_at(&self, now: u64) -> bool {
        self.state == CellState::Active && now < self.expires_at()
    }
}

/// The plane of live host cells, over logical time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostCellPlane {
    now: u64,
    seq: u64,
    cells: Vec<HostCell>,
}

impl HostCellPlane {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current logical time.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Spawn an ephemeral role cell. The id is domain-separated and includes a
    /// per-spawn sequence, so the same role spawned twice yields distinct cells
    /// (a cell is never a stable public identity).
    pub fn spawn<I: IntoIterator<Item = S>, S: Into<String>>(
        &mut self,
        role: impl Into<String>,
        capabilities: I,
        scope: impl Into<String>,
        ttl: u64,
    ) -> HostCellId {
        let role = role.into();
        let scope = scope.into();
        let seq = self.seq;
        self.seq += 1;
        #[derive(Serialize)]
        struct Form<'a> {
            domain: &'a str,
            role: &'a str,
            scope: &'a str,
            spawned_at: u64,
            seq: u64,
        }
        let id = HostCellId::of(
            &Form {
                domain: "fchl/host-cell/v1",
                role: &role,
                scope: &scope,
                spawned_at: self.now,
                seq,
            },
            HashAlg::Blake3,
        )
        .expect("host cell form is serializable");
        self.cells.push(HostCell {
            id,
            role,
            capabilities: capabilities.into_iter().map(Into::into).collect(),
            scope,
            spawned_at: self.now,
            ttl,
            state: CellState::Active,
        });
        id
    }

    /// Advance logical time by one tick, dissolving any cells whose TTL elapsed.
    /// Returns the ids of the cells that dissolved on this tick.
    pub fn tick(&mut self) -> Vec<HostCellId> {
        self.now += 1;
        let now = self.now;
        let mut dissolved = Vec::new();
        for cell in &mut self.cells {
            if cell.state == CellState::Active && now >= cell.expires_at() {
                cell.state = CellState::Dissolved;
                dissolved.push(cell.id);
            }
        }
        dissolved
    }

    /// Explicitly dissolve a cell.
    ///
    /// # Errors
    /// [`HostCellError::NotFound`] or [`HostCellError::AlreadyDissolved`].
    pub fn dissolve(&mut self, id: HostCellId) -> Result<(), HostCellError> {
        let cell = self
            .cells
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(HostCellError::NotFound)?;
        if cell.state == CellState::Dissolved {
            return Err(HostCellError::AlreadyDissolved);
        }
        cell.state = CellState::Dissolved;
        Ok(())
    }

    #[must_use]
    pub fn get(&self, id: HostCellId) -> Option<&HostCell> {
        self.cells.iter().find(|c| c.id == id)
    }

    /// Whether a cell is currently active (not dissolved, TTL not elapsed).
    #[must_use]
    pub fn is_active(&self, id: HostCellId) -> bool {
        self.get(id).is_some_and(|c| c.is_active_at(self.now))
    }

    /// Whether a cell may act with `capability` in `scope` right now — active,
    /// holds the capability, and its scope matches.
    #[must_use]
    pub fn can(&self, id: HostCellId, capability: &str, scope: &str) -> bool {
        self.get(id).is_some_and(|c| {
            c.is_active_at(self.now) && c.capabilities.contains(capability) && c.scope == scope
        })
    }

    /// The number of currently-active cells.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.cells
            .iter()
            .filter(|c| c.is_active_at(self.now))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plane() -> HostCellPlane {
        HostCellPlane::new()
    }

    // A HostCell is not a public identity: the same role spawned twice yields
    // two distinct cells.
    #[test]
    fn host_cell_is_not_public_identity() {
        let mut p = plane();
        let a = p.spawn("router", ["route"], "session-1", 5);
        let b = p.spawn("router", ["route"], "session-1", 5);
        assert_ne!(a, b, "the same role must yield distinct ephemeral cells");
        assert_ne!(a.0, b.0);
    }

    // A cell may only act with a granted capability, within its scope.
    #[test]
    fn capability_and_scope_bound() {
        let mut p = plane();
        let cell = p.spawn("egress", ["connect", "probe"], "session-1", 10);
        assert!(p.can(cell, "connect", "session-1"));
        assert!(p.can(cell, "probe", "session-1"));
        // Missing capability -> denied.
        assert!(!p.can(cell, "capture", "session-1"));
        // Wrong scope -> denied.
        assert!(!p.can(cell, "connect", "session-2"));
    }

    // A cell dissolves when its TTL elapses and can no longer act.
    #[test]
    fn ttl_dissolution() {
        let mut p = plane();
        let cell = p.spawn("short-lived", ["act"], "s", 2);
        assert!(p.is_active(cell));
        assert_eq!(p.tick(), vec![], "still alive after one tick");
        assert!(p.is_active(cell));
        let dissolved = p.tick(); // now == 2 == expires_at
        assert_eq!(dissolved, vec![cell], "cell dissolves when TTL elapses");
        assert!(!p.is_active(cell));
        assert!(!p.can(cell, "act", "s"), "a dissolved cell can do nothing");
        assert_eq!(p.get(cell).unwrap().state, CellState::Dissolved);
    }

    // A cell can be dissolved explicitly, once.
    #[test]
    fn explicit_dissolution_is_idempotent_guarded() {
        let mut p = plane();
        let cell = p.spawn("role", ["act"], "s", 100);
        assert_eq!(p.active_count(), 1);
        p.dissolve(cell).unwrap();
        assert!(!p.is_active(cell));
        assert_eq!(p.active_count(), 0);
        assert_eq!(
            p.dissolve(cell).unwrap_err(),
            HostCellError::AlreadyDissolved
        );
        // An unknown cell is not found.
        let bogus = HostCellId(ssk_types::digest_of(&"nope", HashAlg::Blake3).unwrap());
        assert_eq!(p.dissolve(bogus).unwrap_err(), HostCellError::NotFound);
    }
}
