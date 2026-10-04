//! The privileged broker (SPEC_TAURI_GUI.md §2, §5–§8, §12/P0).
//!
//! The single authoritative owner of the kill-switch security domain. Every
//! mutating verb runs under one operation lock and, in order (SPEC §5, §8):
//! **peer authorization** → command-auth (constant-time) → actuation
//! authorization → session budget → anti-replay nonce → idempotency (bound to
//! the command) → `expected_state_version` → the `ssk-boundary` auth gate +
//! hash-chained audit → the enforcer → durable persist → version bump →
//! authoritative status. Steps 3 and 4 are P1 additions; see
//! [`ActuationAuthority`] and [`MAX_SESSION_MUTATIONS`]. Step 1 is P3's; see
//! [`crate::authz`]. The rollback/recovery contract (SPEC §6) is enforced by the
//! commit order: the durable snapshot is written only *after* the OS effect
//! succeeds, so a failure never leaves a half-committed journal.
//!
//! # Two entry points, and why one of them refuses to mutate
//!
//! | Entry point | Peer | Mutating verbs |
//! |---|---|---|
//! | [`Broker::handle_from_peer`] | authenticated by the transport | authorized per request |
//! | [`Broker::handle`] | none — an in-process caller | **refused** whenever an authorizer is configured |
//!
//! [`Broker::handle`] predates P3 and is how the in-process Tauri bridge drives
//! a broker on a machine with no privileged transport. It performs **no peer
//! authorization**, which is correct for a broker that has none to perform and
//! unacceptable for one that does — so a broker built by
//! [`Broker::recover_privileged`] refuses every mutating verb that arrives
//! through it, with [`RejectReason::PeerAuthorizationRequired`]. The privileged
//! host therefore cannot reach the un-authorized path even by mistake, and the
//! property is asserted by test rather than by comment.
//!
//! # Refcounting
//!
//! Engaging takes a [`crate::lease::Lease`]; releasing drops one; the enforcer
//! is invoked only when the set becomes empty. See [`crate::lease`] for why the
//! refcount is a set of claims with liveness classes rather than a counter, and
//! [`crate::recover`] for what happens to those claims at startup.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use ssk_boundary::{
    BoundaryEnforcer, BoundaryError, BoundaryPolicy, BoundaryScope, KillSwitch, KillSwitchState,
};
use ssk_signature::policy::{AuthorizationPolicyTable, PrivilegedUse};
use ssk_signature::AuthorizationManifest;
use ssk_types::{Digest, SessionId};

use crate::authz::{
    AuthenticatedPeer, AuthzDenied, ControlVerb, Grant, PeerAuthorizer, PeerIdentity,
};
use crate::error::HelperError;
use crate::lease::{Lease, LeaseId, LeaseKind, LeaseSet};
use crate::protocol::{BrokerResponse, CapabilityToken, Command, CommandEnvelope, RejectReason};
use crate::recover::{BoundaryRecoverer, ReconcileAction, ReconcilePolicy, ReconcileReport};
use crate::status::{EgressObserver, KillSwitchStatus, Recovery};
use crate::store::{PersistedState, ReceiptStore};

/// The maximum number of **mutating** commands one broker session will accept.
///
/// # Why a cap, and why refusal rather than eviction
///
/// `seen_nonces` and the idempotency cache previously grew without bound, which
/// is a memory-exhaustion vector in a process that will be hosted as SYSTEM
/// (P3). The obvious fix — a TTL or an LRU — is the wrong one *for the nonce
/// set*: evicting a nonce restores its ability to be replayed, so an attacker
/// who can insert `N` fresh nonces can evict a nonce of interest and then
/// replay the command that carried it. A bound that forgets is a bound that
/// re-opens the exact window the set exists to close.
///
/// So the anti-replay window is the **entire session**, with no time component
/// at all, and the bound is on *count*: at the cap the broker refuses
/// **new** nonces with [`RejectReason::SessionMutationLimitReached`] while still
/// recognising every nonce it has already seen. Replay detection therefore stays
/// exact and total for the life of the session; only growth stops.
///
/// The trade this makes is denial-of-mutation instead of denial-of-replay-
/// protection. That trade is safe here because inserting a nonce requires
/// passing command-auth first: only a peer already holding the session's
/// capability token can consume budget, and such a peer can simply call
/// `engage`/`release` directly. Read-only `GetStatus` never consumes budget, so
/// an exhausted session can still be observed and diagnosed.
///
/// **Corrected at P3.** This previously said recovery was "a new session (a new
/// pipe connection mints a new token at P2)". That is not what the P3 transport
/// does: [`crate::handshake::ServerHello`] hands out the broker's *existing*
/// session token, and the nonce set lives on the broker, so a new connection
/// does **not** reset the budget. Recovery from an exhausted budget is
/// restarting the broker. Re-keying per connection was considered and rejected —
/// it would invalidate every other live connection's token — so the honest
/// statement is that the budget is process-wide, and it is recorded as a
/// residual rather than left as a comment describing behaviour that does not
/// exist.
///
/// 4096 is ~400× the plausible ceiling for real use — a kill-switch session
/// issues a handful of privileged mutations, not thousands — and bounds
/// per-session state at roughly 1 MiB (4096 × 16 B of nonce plus 4096 cached
/// statuses), which a P2 connection cap then multiplies by a known factor.
pub const MAX_SESSION_MUTATIONS: u64 = 4096;

/// How the broker decides whether its own actuation manifest may drive the
/// kill-switch.
///
/// This answers *"may this broker process actuate at all?"* — a deployment fact
/// fixed at construction. It is **not** the same question as *"may this caller
/// command it?"*, which is [`crate::authz::PeerAuthorizer`]'s, is decided per
/// request, and is not substitutable for this one in either direction.
pub enum ActuationAuthority {
    /// **Interim (P1), and not reachable from a privileged host.** Trust the
    /// manifest's self-declared `allowed_uses`, exactly as
    /// `ssk_boundary::KillSwitch::engage` does today via
    /// `AuthorizationManifest::is_valid_for`.
    ///
    /// This is not an authorization decision — it is a self-declaration check.
    /// [`Broker::recover_privileged`] takes an [`AuthorizationPolicyTable`] by
    /// value and offers no way to select this variant, so the privileged service
    /// host cannot construct a self-asserting broker. It remains reachable
    /// through [`Broker::recover`] / [`Broker::recover_with_policy`], which the
    /// in-process Tauri bridge uses on a machine with no privileged transport.
    ///
    /// **Residual, stated rather than implied:** routing through
    /// [`ActuationAuthority::Table`] places a real `(principal, verb)` decision
    /// *in front of* `ssk_boundary::KillSwitch::engage`, which still performs its
    /// own `is_valid_for` self-declaration check internally. Closing that inner
    /// check means threading an `AuthorizedUse` into `ssk-boundary`'s three
    /// control methods — an API change in a crate outside this change's file
    /// scope. "Routed through the broker" must therefore not be read as "the
    /// self-declaration hole is closed"; it is gated, not removed.
    SelfAsserted,
    /// The real decision: an explicit `(principal, verb)` allow-list. The
    /// broker's actuation manifest must carry a
    /// [`ssk_signature::policy::Principal`] that is granted
    /// [`PrivilegedUse::BoundaryControl`] in this table, or every mutating verb
    /// is rejected with [`RejectReason::Unauthorized`] **before** the enforcer
    /// is touched.
    Table(AuthorizationPolicyTable),
}

impl ActuationAuthority {
    /// Whether `manifest` may actuate the kill-switch.
    fn permits(&self, manifest: &AuthorizationManifest) -> bool {
        match self {
            ActuationAuthority::SelfAsserted => true,
            ActuationAuthority::Table(table) => manifest
                .authorize(PrivilegedUse::BoundaryControl.as_str(), table)
                .is_ok(),
        }
    }
}

/// Why [`Broker::adopt_lease`] refused an adoption request.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum LeaseAdoptError {
    /// No claim with this id is currently held. Minting one under a
    /// client-chosen id would be worse than refusing it.
    NoSuchLease,
    /// The claim exists but is [`LeaseKind::Session`], not
    /// [`LeaseKind::Pinned`] — adopting a session claim would let one
    /// connection take over another's live, connection-bound claim.
    NotPinned(LeaseKind),
    /// The connecting peer was not authorized for
    /// [`ControlVerb::ReleaseKillSwitch`]. See [`Broker::adopt_lease`] for why
    /// that is the exact grant this requires.
    Unauthorized(AuthzDenied),
}

impl std::fmt::Display for LeaseAdoptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LeaseAdoptError::NoSuchLease => write!(f, "no such claim is held"),
            LeaseAdoptError::NotPinned(kind) => {
                write!(
                    f,
                    "claim is {} and only a pinned claim may be adopted",
                    kind.as_str()
                )
            }
            LeaseAdoptError::Unauthorized(denied) => write!(f, "{denied}"),
        }
    }
}

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
    /// The receipt-less sweep, used by [`Broker::reconcile_startup`]. Absent
    /// means the sweep cannot run, which the report says out loud rather than
    /// reporting a clean start it did not establish.
    recoverer: Option<Box<dyn BoundaryRecoverer>>,
    session_token: CapabilityToken,
    actuation_auth: AuthorizationManifest,
    authority: ActuationAuthority,
    scope: BoundaryScope,
    state_version: u64,
    /// The live claims on the engaged kill-switch (see [`crate::lease`]).
    leases: LeaseSet,
    /// Duplicate lease ids found in the snapshot this broker was recovered
    /// from. Corruption, reported rather than silently collapsed.
    duplicate_leases: usize,
    /// Per-session anti-replay set and idempotency cache, both bounded by
    /// [`MAX_SESSION_MUTATIONS`] (SPEC §5.2/§8).
    seen_nonces: HashSet<[u8; 16]>,
    /// Keyed by the raw idempotency key, but **carrying the command it was
    /// first used with**. Returning the cached status without checking the verb
    /// is how the same key submitted as `Release` could be answered with a
    /// cached `Engage` result.
    idempotency: HashMap<[u8; 16], (Command, KillSwitchStatus)>,
    /// True iff this broker was reconstructed from a persisted snapshot
    /// (a restart/crash), so a coherent status is `Reconciled` not `Consistent`.
    recovered: bool,
}

/// The privileged broker. Cheap to share; the operation lock serializes verbs.
pub struct Broker {
    inner: Mutex<BrokerInner>,
    /// The per-request peer decision. `None` for a broker with no privileged
    /// transport in front of it — see this module's header for what that costs
    /// and what it does not.
    authorizer: Option<Box<dyn PeerAuthorizer>>,
}

impl Broker {
    /// Open the broker, recovering the authoritative kill-switch state from the
    /// durable store (SPEC §4, §12). A missing snapshot means first run (a fresh
    /// armed switch); a present snapshot is rehydrated and validated.
    ///
    /// No peer authorizer, and [`ActuationAuthority::SelfAsserted`]: this is the
    /// in-process constructor. A privileged host must use
    /// [`Broker::recover_privileged`].
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
        Self::recover_with_policy(
            config,
            ActuationAuthority::SelfAsserted,
            store,
            enforcer,
            observer,
        )
    }

    /// [`Broker::recover`] with an explicit [`ActuationAuthority`].
    ///
    /// Passing [`ActuationAuthority::Table`] is what turns the broker's
    /// actuation check from "the manifest says so" into a real
    /// `(principal, verb)` allow-list decision.
    ///
    /// # Errors
    /// As [`Broker::recover`].
    pub fn recover_with_policy(
        config: BrokerConfig,
        authority: ActuationAuthority,
        store: Box<dyn ReceiptStore>,
        enforcer: Box<dyn BoundaryEnforcer + Send>,
        observer: Box<dyn EgressObserver + Send>,
    ) -> Result<Self, HelperError> {
        Self::build(config, authority, None, store, enforcer, observer)
    }

    /// The **privileged host's** constructor (roadmap P3).
    ///
    /// Two things are different, and both are structural rather than
    /// conventional:
    ///
    /// * `authority` is an [`AuthorizationPolicyTable`] **by value, with no
    ///   default**. [`ActuationAuthority::SelfAsserted`] is therefore not
    ///   expressible here: a service running as LocalSystem cannot accidentally
    ///   ship a self-asserting broker, because the type will not let it.
    /// * `authorizer` is required, and its presence is what makes
    ///   [`Broker::handle`] refuse mutating verbs.
    ///
    /// The composition root must build the table as
    /// `AuthorizationPolicyTable::deny_all().allow(Principal::parse("ssk-netd-helper")?,
    /// PrivilegedUse::BoundaryControl)` **and** put that same principal on
    /// `config.actuation_auth` via `with_principal` — without it `authorize`
    /// returns `NoPrincipal` and every mutating verb is refused.
    ///
    /// # Errors
    /// As [`Broker::recover`].
    pub fn recover_privileged(
        config: BrokerConfig,
        authority: AuthorizationPolicyTable,
        authorizer: Box<dyn PeerAuthorizer>,
        store: Box<dyn ReceiptStore>,
        enforcer: Box<dyn BoundaryEnforcer + Send>,
        observer: Box<dyn EgressObserver + Send>,
    ) -> Result<Self, HelperError> {
        Self::build(
            config,
            ActuationAuthority::Table(authority),
            Some(authorizer),
            store,
            enforcer,
            observer,
        )
    }

    fn build(
        config: BrokerConfig,
        authority: ActuationAuthority,
        authorizer: Option<Box<dyn PeerAuthorizer>>,
        store: Box<dyn ReceiptStore>,
        enforcer: Box<dyn BoundaryEnforcer + Send>,
        observer: Box<dyn EgressObserver + Send>,
    ) -> Result<Self, HelperError> {
        let (switch, state_version, recovered, leases, duplicate_leases) = match store.load()? {
            None => (
                KillSwitch::arm(
                    config.session.clone(),
                    config.scope.clone(),
                    config.policy.clone(),
                ),
                0,
                false,
                LeaseSet::new(),
                0,
            ),
            Some(snap) => {
                // Recompute the receipt digest against the scope we are
                // actually configured for, instead of trusting the bytes on
                // disk. `KillSwitch::rehydrate` checks the audit chain and the
                // state/receipt pairing but never the receipt's own id.
                //
                // This detects corruption, truncation, a receipt paired with
                // the wrong scope, and naive tampering. It does **not** detect
                // forgery: `receipt_id` is an UNKEYED Blake3 hash over
                // {scope, prior_state} (ssk-boundary/src/lib.rs), so anyone who
                // can write this file can also compute a matching id for their
                // own `prior_state`. Forgery is prevented by the store DACL
                // (store.rs) and bounded by rule-name re-derivation in the
                // enforcer — not here.
                if let Some(receipt) = snap.receipt.as_ref() {
                    receipt.verify_against(&config.scope).map_err(|e| {
                        HelperError::CorruptState(format!("persisted receipt: {e}"))
                    })?;
                }
                // Rehydrating restores the claims as persisted. Deciding that a
                // claim is *dead* is a separate decision and belongs to
                // `reconcile_startup`, which can also make the OS agree — see
                // `LeaseSet::retain_restart_survivors`.
                let (leases, duplicates) = LeaseSet::from_persisted(snap.leases);
                let switch = KillSwitch::rehydrate(
                    config.session.clone(),
                    config.scope.clone(),
                    config.policy.clone(),
                    snap.logical_state,
                    snap.receipt,
                    snap.journal,
                )?;
                (switch, snap.state_version, true, leases, duplicates)
            }
        };
        let inner = BrokerInner {
            switch,
            enforcer,
            observer,
            store,
            recoverer: None,
            session_token: config.session_token,
            actuation_auth: config.actuation_auth,
            authority,
            scope: config.scope,
            state_version,
            leases,
            duplicate_leases,
            seen_nonces: HashSet::new(),
            idempotency: HashMap::new(),
            recovered,
        };
        Ok(Broker {
            inner: Mutex::new(inner),
            authorizer,
        })
    }

    /// Attach the receipt-less recovery seam used by
    /// [`Broker::reconcile_startup`]'s sweep.
    ///
    /// Optional because the sweep is a Windows-firewall capability that the
    /// in-process bridge does not have. Without it the sweep cannot run, and the
    /// reconcile report says exactly that instead of claiming a clean start.
    #[must_use]
    pub fn with_recoverer(self, recoverer: Box<dyn BoundaryRecoverer>) -> Self {
        self.inner.lock().expect("broker lock").recoverer = Some(recoverer);
        self
    }

    /// The authoritative status without mutating anything (read path).
    #[must_use]
    pub fn status(&self) -> KillSwitchStatus {
        self.inner.lock().expect("broker lock").status()
    }

    /// The live claims on the kill-switch. Observability; never a decision.
    #[must_use]
    pub fn leases(&self) -> Vec<Lease> {
        self.inner.lock().expect("broker lock").leases.to_vec()
    }

    /// The capability token this broker's session is keyed on, so the transport
    /// can put it in [`crate::handshake::ServerHello`].
    ///
    /// Handing this out is what makes the token a *session* credential rather
    /// than a peer credential; see [`CapabilityToken`] for the precise, narrow
    /// thing it proves. It is deliberately not per-connection: re-keying the
    /// broker per connection would invalidate every other connection's token,
    /// and the token is not the authorization boundary.
    #[must_use]
    pub fn session_token(&self) -> CapabilityToken {
        self.inner.lock().expect("broker lock").session_token
    }

    /// Whether a peer authorizer is configured — i.e. whether this broker is
    /// fronted by a privileged transport.
    #[must_use]
    pub fn is_peer_authorizing(&self) -> bool {
        self.authorizer.is_some()
    }

    /// Handle one command envelope from an **authenticated peer**. The served
    /// path.
    ///
    /// Peer authorization runs first — before the capability-token compare, so
    /// an unauthorized peer learns nothing about token correctness, and before
    /// any nonce or cache entry is recorded, so a refused command leaves no
    /// trace to exhaust.
    ///
    /// `lease` / `lease_kind` come from the connection's handshake, not from the
    /// envelope: what a claim's liveness is is a property of the client, and a
    /// per-command field would let one connection take a durable claim on a verb
    /// and a session claim on the next.
    pub fn handle_from_peer(
        &self,
        peer: &AuthenticatedPeer,
        lease: LeaseId,
        lease_kind: LeaseKind,
        envelope: CommandEnvelope,
    ) -> BrokerResponse {
        let verb = ControlVerb::for_command(envelope.command);
        let Some(authorizer) = self.authorizer.as_ref() else {
            // Fail closed: a broker with no authorizer cannot decide anything
            // about a peer, and answering as if it could is the whole failure
            // mode this returns instead of.
            return BrokerResponse::Rejected(AuthzDenied::NoAuthorizer { verb }.to_reject_reason());
        };
        if let Err(denied) = authorizer.authorize(peer, verb) {
            return BrokerResponse::Rejected(denied.to_reject_reason());
        }
        // The single minting site. A `Grant` exists only on the far side of a
        // successful `authorize`, and `BrokerInner::do_engage` / `do_release`
        // take one — so deleting this call is a compile error, not a silently
        // permissive broker.
        let grant = Grant::mint(peer.sid.clone(), verb);
        self.dispatch(&grant, lease, lease_kind, envelope)
    }

    /// Handle one command envelope from an **in-process** caller with no peer
    /// identity.
    ///
    /// On a broker built by [`Broker::recover_privileged`] every mutating verb
    /// that arrives here is refused with
    /// [`RejectReason::PeerAuthorizationRequired`]: the privileged deployment
    /// has a peer decision to make and this entry point cannot make it. Reads
    /// are still served, so an in-process diagnostic still works.
    pub fn handle(&self, envelope: CommandEnvelope) -> BrokerResponse {
        if self.authorizer.is_some() && envelope.command.is_mutating() {
            return BrokerResponse::Rejected(RejectReason::PeerAuthorizationRequired);
        }
        let verb = ControlVerb::for_command(envelope.command);
        let grant = Grant::mint(PeerIdentity::in_process(), verb);
        self.dispatch(&grant, LeaseId::IN_PROCESS, LeaseKind::Session, envelope)
    }

    /// The one place a command is executed. Both entry points funnel here and
    /// neither can reach the enforcer any other way.
    fn dispatch(
        &self,
        grant: &Grant,
        lease: LeaseId,
        lease_kind: LeaseKind,
        envelope: CommandEnvelope,
    ) -> BrokerResponse {
        // The grant must be for the verb actually being dispatched. Both call
        // sites derive both from the same envelope, so this cannot fire today —
        // it is here so that a future caller that mints once and dispatches a
        // loop cannot quietly reuse a `ReadStatus` grant for an engage.
        let submitted = ControlVerb::for_command(envelope.command);
        if grant.verb() != submitted {
            return BrokerResponse::Rejected(
                AuthzDenied::VerbMismatch {
                    granted: grant.verb(),
                    submitted,
                }
                .to_reject_reason(),
            );
        }

        let mut inner = self.inner.lock().expect("broker lock");

        // 2. Command-auth: the token must match this session's token, compared
        //    in constant time (a short-circuiting `==` leaks the token one byte
        //    at a time to a caller that can retry in a loop).
        if !envelope.session_token.ct_eq(&inner.session_token) {
            return BrokerResponse::Rejected(RejectReason::BadToken);
        }

        // Read-only verbs need only auth; no nonce/version/lock-mutation. They
        // also consume no session budget, so an exhausted session stays
        // observable.
        if !envelope.command.is_mutating() {
            return BrokerResponse::Ok(inner.status());
        }

        // 3. Actuation authorization: may this broker's manifest drive the
        //    kill-switch at all? Checked before any state is recorded, so a
        //    rejected command leaves no nonce and no cache entry behind.
        if !inner.authority.permits(&inner.actuation_auth) {
            return BrokerResponse::Rejected(RejectReason::Unauthorized);
        }

        // 4. Bounded session state. Checked *before* inserting, and only for
        //    nonces we have not seen: at the cap a replay is still detected
        //    exactly (step 5), only growth stops. See MAX_SESSION_MUTATIONS for
        //    why this refuses rather than evicts.
        if let Some(limit) = inner.mutation_budget_exceeded(&envelope) {
            return BrokerResponse::Rejected(RejectReason::SessionMutationLimitReached { limit });
        }

        // 5. Anti-replay: a nonce may be used at most once per session.
        if !inner.seen_nonces.insert(envelope.nonce.0) {
            return BrokerResponse::Rejected(RejectReason::ReplayedNonce);
        }

        // 6. Idempotency: a repeated key returns the cached result WITHOUT
        //    re-executing the OS effect (a retried engage never double-applies).
        //    Checked before the version gate so a retry after the version moved
        //    on still returns its original success.
        //
        //    The cached command must match: an idempotency key names one
        //    operation, so the same key arriving as a different verb is a
        //    conflict, not a hit. Without this, `release` submitted under an
        //    `engage`'s key is answered with the cached engage status — the
        //    caller is told egress was restored while it is still severed, and
        //    no enforcer call is ever made.
        if let Some((cached_command, cached_status)) =
            inner.idempotency.get(&envelope.idempotency_key.0)
        {
            if *cached_command != envelope.command {
                return BrokerResponse::Rejected(RejectReason::IdempotencyKeyConflict {
                    cached: *cached_command,
                    submitted: envelope.command,
                });
            }
            return BrokerResponse::Ok(cached_status.clone());
        }

        // 7. Optimistic concurrency: the client's expected version must be current.
        if envelope.expected_state_version != inner.state_version {
            return BrokerResponse::Rejected(RejectReason::StaleVersion {
                expected: envelope.expected_state_version,
                actual: inner.state_version,
            });
        }

        // 8. Execute the verb under the §6 commit order.
        let result = match envelope.command {
            Command::EngageKillSwitch => inner.do_engage(grant, lease, lease_kind),
            Command::ReleaseKillSwitch => inner.do_release(grant, lease),
            Command::GetStatus => unreachable!("GetStatus is non-mutating"),
        };
        match result {
            Ok(status) => {
                inner.idempotency.insert(
                    envelope.idempotency_key.0,
                    (envelope.command, status.clone()),
                );
                BrokerResponse::Ok(status)
            }
            Err(HelperError::Boundary(BoundaryError::Unauthorized)) => {
                BrokerResponse::Rejected(RejectReason::Unauthorized)
            }
            Err(e) => BrokerResponse::Failed(e.to_string()),
        }
    }

    /// Drop a claim because its holder went away (the connection ended, or the
    /// process holding it died).
    ///
    /// **Requires no fresh authorization — but only for the one case that is
    /// actually safe, and that safety is enforced *elsewhere*, not here.**
    ///
    /// This previously argued that dropping a claim can only ever *reduce*
    /// enforcement and is therefore always safe to leave ungated. That is
    /// false once adoption exists: taking over someone else's durable
    /// [`LeaseKind::Pinned`] claim and then letting *this* function drop it is
    /// functionally identical to calling [`Command::ReleaseKillSwitch`] on it —
    /// which every other path in this broker gates on a
    /// [`ControlVerb::ReleaseKillSwitch`] grant. An ungated `close_lease` would
    /// have made that gate provable and unenforceable in exactly one place.
    ///
    /// What **is** still true, and is what makes leaving this function itself
    /// ungated correct rather than merely convenient:
    ///
    /// * A peer's own freshly-minted, never-adopted [`LeaseKind::Session`]
    ///   claim lapsing at that connection's natural end is safe *precisely
    ///   because* the peer already cleared [`ControlVerb::EngageKillSwitch`]
    ///   authorization to create it, and a dead session's grip has to lapse —
    ///   that is the fail-safe this whole mechanism exists to provide, and it
    ///   is asserted by
    ///   `a_session_claim_is_dropped_when_the_connection_ends_and_egress_is_restored`
    ///   in `tests/p3_transport.rs`.
    /// * A [`LeaseKind::Pinned`] claim's `kind` is immutable once minted — no
    ///   adoption changes it (see [`Broker::adopt_lease`]) — so the *server's*
    ///   disconnect handling only ever reaches this function for a claim whose
    ///   real, recorded kind is `Session`. It must read that recorded kind, not
    ///   a disconnecting connection's own self-declared `hello.lease_kind`:
    ///   trusting the latter is exactly the P3→P4 defect (an adopting
    ///   connection could declare `Session` on a hello that adopted someone
    ///   else's `Pinned` claim and have it dropped here with no authorization
    ///   at all, on disconnect, having sent zero commands).
    /// * Taking over a `Pinned` claim in the first place — adoption — is
    ///   therefore the gate, and it now requires exactly the
    ///   [`ControlVerb::ReleaseKillSwitch`] grant this function's own doc used
    ///   to say was unnecessary. See [`Broker::adopt_lease`].
    ///
    /// Idempotent: dropping a claim that is not held changes nothing.
    ///
    /// # Errors
    /// [`HelperError`] if the release or the durable write failed. The broker is
    /// then left in the state the enforcer actually achieved, never a claimed
    /// one.
    pub fn close_lease(&self, lease: &LeaseId) -> Result<KillSwitchStatus, HelperError> {
        let mut inner = self.inner.lock().expect("broker lock");
        inner.drop_claim(lease)
    }

    /// Authorize and complete a peer's handshake-time request to **adopt** an
    /// existing durable claim (`hello.adopt_lease`) — the fix for the P3→P4
    /// adoption-authorization gap.
    ///
    /// Requires `id` to name a currently held [`LeaseKind::Pinned`] claim
    /// **and** `peer` to be authorized for [`ControlVerb::ReleaseKillSwitch`],
    /// checked against the exact same [`PeerAuthorizer`]
    /// [`Broker::handle_from_peer`] uses — there is deliberately no second
    /// authorization path to keep in sync with the first.
    ///
    /// # Why `ControlVerb::ReleaseKillSwitch`, specifically
    ///
    /// Adopting is how one connection becomes the connection whose disconnect
    /// governs a claim's fate. Per [`Broker::close_lease`], a `Session` claim
    /// lapses at disconnect with **no further check** — so a peer who could
    /// adopt for free could turn *any* `Pinned` claim into a claim one hang-up
    /// away from lapsing (by adopting, then disconnecting), which is the same
    /// effect as an explicit release. Every other path to that effect in this
    /// broker is gated on `ReleaseKillSwitch`; adoption must clear the same
    /// bar or it is a second, cheaper way to reach it.
    ///
    /// # Why identity is not an alternative gate
    ///
    /// A peer adopting a claim **they themselves** originally took
    /// (`peer.sid == lease.holder`, e.g. reconnecting after their own
    /// transport died) is checked exactly the same way, with no identity
    /// shortcut. `holder` records who took the claim **for the audit line
    /// only** (see [`crate::lease::Lease::holder`]) — it is not proof of what
    /// that peer was ever granted. An operator can hold `EngageKillSwitch` and
    /// nothing else: their own original connection could engage but could
    /// never have released, so letting them adopt-and-drop their own claim
    /// merely because the SID matches would hand that peer a release-shaped
    /// effect their grant never covered. Tier C's two verbs are separately
    /// recorded because they point in opposite directions (see
    /// [`crate::authz`] module docs); adoption sits on the release side for
    /// every peer, self included.
    ///
    /// # Why a successful adoption does not change the claim's `kind`
    ///
    /// The claim's `kind` stays exactly what it was at mint time. An
    /// authorized adopter who wants the claim gone calls
    /// [`Command::ReleaseKillSwitch`] explicitly — which they can, having just
    /// cleared this same grant — rather than this function quietly
    /// reclassifying a `Pinned` claim to `Session` so a later disconnect drops
    /// it implicitly. The explicit path stays inside the ordinary
    /// authorized-command audit trail (nonce, idempotency key, state version);
    /// a silent reclassification-then-lapse would not be.
    ///
    /// # Errors
    /// [`LeaseAdoptError`] naming why: the id names no held claim, names a
    /// claim that is not durable, or `peer` was refused the grant.
    pub fn adopt_lease(
        &self,
        peer: &AuthenticatedPeer,
        id: LeaseId,
    ) -> Result<LeaseId, LeaseAdoptError> {
        {
            let inner = self.inner.lock().expect("broker lock");
            match inner.leases.get(&id) {
                Some(l) if l.kind == LeaseKind::Pinned => {}
                Some(l) => return Err(LeaseAdoptError::NotPinned(l.kind)),
                None => return Err(LeaseAdoptError::NoSuchLease),
            }
        }
        let Some(authorizer) = self.authorizer.as_ref() else {
            // Fail closed, exactly as `handle_from_peer` does: a broker with
            // no authorizer cannot decide anything about a peer.
            return Err(LeaseAdoptError::Unauthorized(AuthzDenied::NoAuthorizer {
                verb: ControlVerb::ReleaseKillSwitch,
            }));
        };
        authorizer
            .authorize(peer, ControlVerb::ReleaseKillSwitch)
            .map_err(LeaseAdoptError::Unauthorized)?;
        Ok(id)
    }

    /// Reconcile the persisted journal against observed OS reality.
    ///
    /// Call **exactly once**, at service start, **before the privileged pipe
    /// accepts its first client**. Reconciliation is several operations under
    /// the op-lock, not one; a client that connected between them would read a
    /// status that is about to change and could engage or release into a
    /// half-reconciled machine. The op-lock does not protect against that —
    /// ordering does.
    ///
    /// See [`crate::recover`] for the decision table and, in particular, for why
    /// the sweep on a non-engaged journal is unconditional.
    ///
    /// # Errors
    /// [`HelperError`] if a mutating step failed, or
    /// [`HelperError::Boundary`]`(Unauthorized)` if this broker's own actuation
    /// authority does not permit it to touch the boundary.
    pub fn reconcile_startup(
        &self,
        policy: ReconcilePolicy,
    ) -> Result<ReconcileReport, HelperError> {
        let mut inner = self.inner.lock().expect("broker lock");
        inner.reconcile(policy)
    }

    /// How many distinct nonces this session has consumed. Observability for
    /// the bound; never part of a decision.
    #[must_use]
    pub fn session_nonces_seen(&self) -> u64 {
        self.inner.lock().expect("broker lock").seen_nonces.len() as u64
    }
}

impl BrokerInner {
    /// `Some(limit)` if accepting this envelope would grow bounded session
    /// state past [`MAX_SESSION_MUTATIONS`].
    ///
    /// A nonce already in the set costs nothing to re-check, and an idempotency
    /// key already cached costs nothing to serve, so neither is refused at the
    /// cap — that keeps replay rejection and idempotent retries working for the
    /// life of the session even after the budget is spent.
    fn mutation_budget_exceeded(&self, envelope: &CommandEnvelope) -> Option<u64> {
        let limit = MAX_SESSION_MUTATIONS;
        let new_nonce = !self.seen_nonces.contains(&envelope.nonce.0);
        let new_key = !self.idempotency.contains_key(&envelope.idempotency_key.0);
        let nonces_full = self.seen_nonces.len() as u64 >= limit;
        let keys_full = self.idempotency.len() as u64 >= limit;
        if (new_nonce && nonces_full) || (new_key && keys_full) {
            Some(limit)
        } else {
            None
        }
    }

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
            self.leases.to_vec(),
        )
    }

    /// Persist at `state_version + 1` and adopt the new version. Called only
    /// after whatever OS effect the transition needed has already succeeded
    /// (SPEC §6).
    fn commit(&mut self) -> Result<(), HelperError> {
        let next = self.state_version + 1;
        self.store.save(&self.snapshot(next))?;
        self.state_version = next;
        Ok(())
    }

    /// Engage: take a claim, severing egress if this is the first one.
    ///
    /// `grant` is unused except as proof that a
    /// [`crate::authz::PeerAuthorizer`] decision was made — the compile-level
    /// barrier described on [`Broker::handle_from_peer`]. Its holder identity is
    /// what is recorded on the claim, so the audit names the SID the transport
    /// authenticated and never a string the client supplied.
    fn do_engage(
        &mut self,
        grant: &Grant,
        lease: LeaseId,
        kind: LeaseKind,
    ) -> Result<KillSwitchStatus, HelperError> {
        let already_engaged = self.switch.state() == KillSwitchState::Engaged;
        if already_engaged && self.leases.contains(&lease) {
            // This holder already has this claim and egress is already severed:
            // nothing changed, so nothing is persisted and the version does not
            // move. A version bump for a no-op would invalidate every other
            // client's optimistic-concurrency token for free.
            return Ok(self.status());
        }
        if !already_engaged {
            // The enforcer runs *before* the claim is recorded, so a failed
            // engage leaves no claim behind to keep a machine severed that was
            // never severed.
            self.switch
                .engage(&self.actuation_auth, self.enforcer.as_ref())?;
        }
        self.leases.insert(Lease {
            id: lease,
            kind,
            holder: grant.peer().as_str().to_owned(),
            taken_at_version: self.state_version,
        });
        self.commit()?;
        Ok(self.status())
    }

    /// Release: drop this holder's claim, restoring egress only when it was the
    /// last one.
    fn do_release(
        &mut self,
        grant: &Grant,
        lease: LeaseId,
    ) -> Result<KillSwitchStatus, HelperError> {
        let _ = grant;
        self.drop_claim(&lease)
    }

    /// The shared body of "this holder is done": used by the `release` verb and
    /// by [`Broker::close_lease`] when a connection ends.
    ///
    /// **Idempotent in every branch.** Dropping a claim that is not held, or
    /// releasing a switch that is not engaged, is `Ok` with the authoritative
    /// status attached — it is not an error. The transport retries, a
    /// disconnect handler runs after an explicit release, and turning either of
    /// those into a failure would make a caller retry a release that had already
    /// happened. The truth is in the returned status, not in the error channel.
    fn drop_claim(&mut self, lease: &LeaseId) -> Result<KillSwitchStatus, HelperError> {
        let held = self.leases.remove(lease).is_some();
        if !self.leases.is_empty() {
            // Someone else still wants egress severed. No OS effect — you
            // cannot release another holder's claim. Persist only if the claim
            // set actually changed.
            if held {
                self.commit()?;
            }
            return Ok(self.status());
        }
        if self.switch.state() != KillSwitchState::Engaged {
            // Nothing is severed by us, so there is nothing to revert. Dropping
            // a claim here is bookkeeping, not a boundary transition.
            if held {
                self.commit()?;
            }
            return Ok(self.status());
        }
        // Last claim gone and the switch is engaged: restore egress.
        match self
            .switch
            .release_reporting(&self.actuation_auth, self.enforcer.as_ref())
        {
            Ok(_) => {
                self.commit()?;
                Ok(self.status())
            }
            Err(e) => {
                // The enforcement is still in place (or unknown). Put the claim
                // back so the refcount keeps naming a holder for enforcement
                // that is still there — dropping it here would leave a severed
                // machine with an empty claim set, which is the strand.
                if held {
                    self.leases.insert(Lease {
                        id: *lease,
                        kind: LeaseKind::Session,
                        holder: PeerIdentity::broker_self().as_str().to_owned(),
                        taken_at_version: self.state_version,
                    });
                }
                Err(e.into())
            }
        }
    }

    /// The startup reconciliation. See [`crate::recover`] for the table.
    fn reconcile(&mut self, policy: ReconcilePolicy) -> Result<ReconcileReport, HelperError> {
        let observed = self.observer.rule_present(&self.scope.label);
        let duplicate_leases = self.duplicate_leases;

        if policy == ReconcilePolicy::ObserveOnly {
            // Zero side effects: no enforcer call, no sweep, no claim discarded,
            // no durable write. `killswitch status` must be able to run on a
            // machine it is not allowed to change.
            return Ok(ReconcileReport {
                logical_state: self.switch.state(),
                observed,
                verdict: KillSwitchStatus::reconcile(self.switch.state(), observed, self.recovered),
                action: ReconcileAction::Observed,
                leases_discarded: Vec::new(),
                duplicate_leases,
                state_version: self.state_version,
            });
        }

        if !self.authority.permits(&self.actuation_auth) {
            return Err(HelperError::Boundary(BoundaryError::Unauthorized));
        }

        // Every claim that cannot survive a restart is provably dead: no
        // connection outlives the process that accepted it. The discards are
        // returned so the caller can record them; `ssk-boundary` exposes no way
        // to append a non-transition entry to the hash-chained journal, so they
        // are evidenced by the persisted snapshot and this report rather than by
        // a ledger entry. Recorded rather than papered over.
        let leases_discarded = self.leases.retain_restart_survivors();

        let action = match self.switch.state() {
            KillSwitchState::Engaged if self.leases.is_empty() => {
                // The only reason the machine was severed was claims that are
                // provably gone. Restore egress. This is a de-escalation, so it
                // is correct to perform it even on an unanswerable observation:
                // it can only ever restore egress, never assert a severance we
                // could not confirm.
                let outcome = self
                    .switch
                    .release_reporting(&self.actuation_auth, self.enforcer.as_ref())?;
                ReconcileAction::ReleasedWithNoRemainingHolder(outcome)
            }
            KillSwitchState::Engaged => match observed {
                Some(true) => ReconcileAction::None,
                Some(false) => {
                    // Someone removed our enforcement while a holder still wants
                    // it. Re-drive the enforcer and KEEP the existing receipt:
                    // the held receipt records the true pre-engagement state,
                    // and a receipt is derived from the scope, not from an
                    // instance, so it still names what was just re-created.
                    // Overwriting it would destroy the only record of what to
                    // restore to — the same reasoning `override_engage` gives
                    // for not re-engaging an already-engaged switch.
                    self.enforcer.engage(&self.scope)?;
                    ReconcileAction::ReEngaged
                }
                None => ReconcileAction::Deferred {
                    detail: "journal says engaged and the probe could not answer; \
                             nothing was mutated"
                        .to_owned(),
                },
            },
            KillSwitchState::Armed | KillSwitchState::Released => match self.recoverer.as_ref() {
                Some(recoverer) => ReconcileAction::Swept(recoverer.recover(&self.scope)?),
                None => ReconcileAction::Deferred {
                    detail: "no BoundaryRecoverer is configured, so a stranded rule \
                             from a previous run cannot be swept"
                        .to_owned(),
                },
            },
        };

        // Re-observe after any OS effect: the verdict must describe the machine
        // as it is now, not as it was before we touched it.
        let observed_after = if action.touched_the_os() {
            self.observer.rule_present(&self.scope.label)
        } else {
            observed
        };
        let verdict = match &action {
            ReconcileAction::Deferred { .. } => Recovery::Inconsistent,
            _ => KillSwitchStatus::reconcile(self.switch.state(), observed_after, true),
        };

        if action.touched_the_os() || !leases_discarded.is_empty() {
            self.commit()?;
        }

        Ok(ReconcileReport {
            logical_state: self.switch.state(),
            observed: observed_after,
            verdict,
            action,
            leases_discarded,
            duplicate_leases,
            state_version: self.state_version,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{PeerToken, TieredSidAuthorizer};
    use crate::protocol::{IdempotencyKey, Nonce};
    use ssk_boundary::{EnforcementReceipt, BOUNDARY_CONTROL_USE};

    struct NoopEnforcer;
    impl BoundaryEnforcer for NoopEnforcer {
        fn engage(&self, scope: &BoundaryScope) -> Result<EnforcementReceipt, BoundaryError> {
            Ok(EnforcementReceipt::new(scope, "flowing"))
        }
        fn release(&self, _receipt: &EnforcementReceipt) -> Result<(), BoundaryError> {
            Ok(())
        }
    }
    struct NoopObserver;
    impl EgressObserver for NoopObserver {
        fn rule_present(&self, _scope: &str) -> Option<bool> {
            None
        }
    }
    #[derive(Default)]
    struct NullStore;
    impl ReceiptStore for NullStore {
        fn save(&self, _state: &PersistedState) -> Result<(), HelperError> {
            Ok(())
        }
        fn load(&self) -> Result<Option<PersistedState>, HelperError> {
            Ok(None)
        }
    }

    fn config() -> BrokerConfig {
        BrokerConfig {
            session_token: CapabilityToken([1u8; 16]),
            actuation_auth: AuthorizationManifest::new("broker", "system", "test")
                .with_allowed_uses([BOUNDARY_CONTROL_USE]),
            scope: BoundaryScope::all_egress(),
            policy: BoundaryPolicy::default(),
            session: SessionId::new("unit"),
        }
    }

    fn broker() -> Broker {
        Broker::recover(
            config(),
            Box::new(NullStore),
            Box::new(NoopEnforcer),
            Box::new(NoopObserver),
        )
        .unwrap()
    }

    fn envelope(command: Command) -> CommandEnvelope {
        CommandEnvelope {
            session_token: CapabilityToken([1u8; 16]),
            nonce: Nonce([2u8; 16]),
            idempotency_key: IdempotencyKey([3u8; 16]),
            expected_state_version: 0,
            command,
        }
    }

    /// The choke point, exercised directly: a grant for one verb cannot be used
    /// to dispatch another. `Grant` is crate-private to construct, so this is
    /// the only place the mismatch can be built at all — which is the point.
    #[test]
    fn a_grant_for_the_wrong_verb_cannot_dispatch_a_command() {
        let b = broker();
        let wrong = Grant::mint(PeerIdentity::in_process(), ControlVerb::ReadStatus);
        let resp = b.dispatch(
            &wrong,
            LeaseId::IN_PROCESS,
            LeaseKind::Session,
            envelope(Command::EngageKillSwitch),
        );
        match resp {
            BrokerResponse::Rejected(RejectReason::PeerUnauthorized { code, .. }) => {
                assert_eq!(code, "PEER_VERB_MISMATCH");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(b.status().logical_state, KillSwitchState::Armed);
    }

    #[test]
    fn a_broker_without_an_authorizer_refuses_a_peer_request_outright() {
        let b = broker();
        assert!(!b.is_peer_authorizing());
        let peer = AuthenticatedPeer::new(
            PeerIdentity::parse_sid("S-1-5-21-1-2-3-1001").unwrap(),
            PeerToken::unprivileged(),
        );
        match b.handle_from_peer(
            &peer,
            LeaseId([9u8; 16]),
            LeaseKind::Session,
            envelope(Command::GetStatus),
        ) {
            BrokerResponse::Rejected(RejectReason::PeerUnauthorized { code, .. }) => {
                assert_eq!(code, "PEER_NO_AUTHORIZER");
            }
            other => panic!("{other:?}"),
        }
    }

    /// The barrier: on a privileged broker the peer-less entry point cannot
    /// mutate. Reads still work, so a diagnostic is not collateral damage.
    #[test]
    fn a_privileged_broker_refuses_mutation_through_the_peerless_entry_point() {
        let b = Broker::recover_privileged(
            config(),
            AuthorizationPolicyTable::deny_all(),
            Box::new(TieredSidAuthorizer::deny_all()),
            Box::new(NullStore),
            Box::new(NoopEnforcer),
            Box::new(NoopObserver),
        )
        .unwrap();
        assert!(b.is_peer_authorizing());
        assert_eq!(
            b.handle(envelope(Command::EngageKillSwitch)),
            BrokerResponse::Rejected(RejectReason::PeerAuthorizationRequired)
        );
        assert_eq!(
            b.handle(envelope(Command::ReleaseKillSwitch)),
            BrokerResponse::Rejected(RejectReason::PeerAuthorizationRequired)
        );
        assert!(matches!(
            b.handle(envelope(Command::GetStatus)),
            BrokerResponse::Ok(_)
        ));
    }
}
