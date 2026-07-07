//! The privileged broker (SPEC_TAURI_GUI.md §2, §5–§8, §12/P0).
//!
//! The single authoritative owner of the kill-switch security domain. Every
//! mutating verb runs under one operation lock and, in order (SPEC §5, §8):
//! command-auth → anti-replay nonce → idempotency → `expected_state_version` →
//! the `ssk-boundary` auth gate + hash-chained audit → the enforcer → durable
//! persist → version bump → authoritative status. The rollback/recovery contract
//! (SPEC §6) is enforced by the commit order: the durable snapshot is written
//! only *after* the OS effect succeeds, so a failure never leaves a
//! half-committed journal.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use ssk_boundary::{BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, KillSwitch};
use ssk_signature::AuthorizationManifest;
use ssk_types::{Digest, SessionId};

use crate::error::HelperError;
use crate::protocol::{BrokerResponse, CapabilityToken, Command, CommandEnvelope, RejectReason};
use crate::status::{EgressObserver, KillSwitchStatus};
use crate::store::{PersistedState, ReceiptStore};

/// The immutable configuration a broker is (re)constructed with.
pub struct BrokerConfig {
    /// The capability token minted for the active authenticated session.
    pub session_token: CapabilityToken,
    /// The broker's own authority to actuate the kill-switch (must be valid for
    /// the boundary control use).
    pub actuation_auth: AuthorizationManifest,
    pub scope: BoundaryScope,
    pub policy: BoundaryPolicy,
    pub session: SessionId,
}

struct BrokerInner {
    switch: KillSwitch,
    enforcer: Box<dyn BoundaryEnforcer + Send>,
    observer: Box<dyn EgressObserver + Send>,
    store: Box<dyn ReceiptStore>,
    session_token: CapabilityToken,
    actuation_auth: AuthorizationManifest,
    scope: BoundaryScope,
    state_version: u64,
    /// Per-session anti-replay set and idempotency cache. Bounded by session
    /// lifetime; a sliding window is a later refinement (SPEC §5.2/§8).
    seen_nonces: HashSet<[u8; 16]>,
    idempotency: HashMap<[u8; 16], KillSwitchStatus>,
    /// True iff this broker was reconstructed from a persisted snapshot
    /// (a restart/crash), so a coherent status is `Reconciled` not `Consistent`.
    recovered: bool,
}

/// The privileged broker. Cheap to share; the operation lock serializes verbs.
pub struct Broker {
    inner: Mutex<BrokerInner>,
}

impl Broker {
    /// Open the broker, recovering the authoritative kill-switch state from the
    /// durable store (SPEC §4, §12). A missing snapshot means first run (a fresh
    /// armed switch); a present snapshot is rehydrated and validated.
    ///
    /// # Errors
    /// [`HelperError`] if the store cannot be read or a present snapshot is
    /// corrupt / incoherent.
    pub fn recover(
        config: BrokerConfig,
        store: Box<dyn ReceiptStore>,
        enforcer: Box<dyn BoundaryEnforcer + Send>,
        observer: Box<dyn EgressObserver + Send>,
    ) -> Result<Self, HelperError> {
        let (switch, state_version, recovered) = match store.load()? {
            None => (
                KillSwitch::arm(
                    config.session.clone(),
                    config.scope.clone(),
                    config.policy.clone(),
                ),
                0,
                false,
            ),
            Some(snap) => {
                let switch = KillSwitch::rehydrate(
                    config.session.clone(),
                    config.scope.clone(),
                    config.policy.clone(),
                    snap.logical_state,
                    snap.receipt,
                    snap.journal,
                )?;
                (switch, snap.state_version, true)
            }
        };
        let inner = BrokerInner {
            switch,
            enforcer,
            observer,
            store,
            session_token: config.session_token,
            actuation_auth: config.actuation_auth,
            scope: config.scope,
            state_version,
            seen_nonces: HashSet::new(),
            idempotency: HashMap::new(),
            recovered,
        };
        Ok(Broker {
            inner: Mutex::new(inner),
        })
    }

    /// The authoritative status without mutating anything (read path).
    #[must_use]
    pub fn status(&self) -> KillSwitchStatus {
        self.inner.lock().expect("broker lock").status()
    }

    /// Handle one authenticated command envelope. Never panics on a bad command;
    /// a rejection is an explicit typed [`BrokerResponse::Rejected`].
    pub fn handle(&self, envelope: CommandEnvelope) -> BrokerResponse {
        let mut inner = self.inner.lock().expect("broker lock");

        // 1. Command-auth: the token must match this session's token.
        if envelope.session_token != inner.session_token {
            return BrokerResponse::Rejected(RejectReason::BadToken);
        }

        // Read-only verbs need only auth; no nonce/version/lock-mutation.
        if !envelope.command.is_mutating() {
            return BrokerResponse::Ok(inner.status());
        }

        // 2. Anti-replay: a nonce may be used at most once per session.
        if !inner.seen_nonces.insert(envelope.nonce.0) {
            return BrokerResponse::Rejected(RejectReason::ReplayedNonce);
        }

        // 3. Idempotency: a repeated key returns the cached result WITHOUT
        //    re-executing the OS effect (a retried engage never double-applies).
        //    Checked before the version gate so a retry after the version moved
        //    on still returns its original success.
        if let Some(cached) = inner.idempotency.get(&envelope.idempotency_key.0) {
            return BrokerResponse::Ok(cached.clone());
        }

        // 4. Optimistic concurrency: the client's expected version must be current.
        if envelope.expected_state_version != inner.state_version {
            return BrokerResponse::Rejected(RejectReason::StaleVersion {
                expected: envelope.expected_state_version,
                actual: inner.state_version,
            });
        }

        // 5. Execute the verb under the §6 commit order.
        let result = match envelope.command {
            Command::EngageKillSwitch => inner.do_engage(),
            Command::ReleaseKillSwitch => inner.do_release(),
            Command::GetStatus => unreachable!("GetStatus is non-mutating"),
        };
        match result {
            Ok(status) => {
                inner
                    .idempotency
                    .insert(envelope.idempotency_key.0, status.clone());
                BrokerResponse::Ok(status)
            }
            Err(HelperError::Boundary(BoundaryError::Unauthorized)) => {
                BrokerResponse::Rejected(RejectReason::Unauthorized)
            }
            Err(e) => BrokerResponse::Failed(e.to_string()),
        }
    }
}

impl BrokerInner {
    /// The audit chain head + length of the kill-switch journal.
    fn audit_head(&self) -> (Digest, u64) {
        let entries = self.switch.audit_entries();
        let head = entries.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        (head, entries.len() as u64)
    }

    /// Build the authoritative status (SPEC §4) — a reconciliation, never a flag.
    fn status(&self) -> KillSwitchStatus {
        let logical_state = self.switch.state();
        let os_rule_present = self.observer.rule_present(&self.scope.label);
        let (audit_head, audit_len) = self.audit_head();
        let recovery = KillSwitchStatus::reconcile(logical_state, os_rule_present, self.recovered);
        KillSwitchStatus {
            logical_state,
            receipt: self.switch.receipt().cloned(),
            os_rule_present,
            audit_head,
            audit_len,
            state_version: self.state_version,
            recovery,
        }
    }

    /// The durable snapshot for a given committed version.
    fn snapshot(&self, version: u64) -> PersistedState {
        PersistedState::new(
            self.switch.state(),
            self.switch.receipt().cloned(),
            version,
            self.switch.audit_entries().to_vec(),
        )
    }

    /// Engage: sever egress, then durably commit (SPEC §6). On enforcer failure
    /// the switch is unchanged and nothing is persisted. If persistence fails
    /// *after* the OS effect, the version is not bumped and the error surfaces —
    /// the in-memory status still reflects the (engaged) truth, and a later
    /// recovery reconciles it fail-closed.
    fn do_engage(&mut self) -> Result<KillSwitchStatus, HelperError> {
        self.switch
            .engage(&self.actuation_auth, self.enforcer.as_ref())?;
        let next = self.state_version + 1;
        self.store.save(&self.snapshot(next))?;
        self.state_version = next;
        Ok(self.status())
    }

    /// Release: restore egress using the broker-held receipt, then durably
    /// commit. On enforcer failure the receipt is retained and the state stays
    /// engaged (SPEC §6).
    fn do_release(&mut self) -> Result<KillSwitchStatus, HelperError> {
        self.switch
            .release(&self.actuation_auth, self.enforcer.as_ref())?;
        let next = self.state_version + 1;
        self.store.save(&self.snapshot(next))?;
        self.state_version = next;
        Ok(self.status())
    }
}
