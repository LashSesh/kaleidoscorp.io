#![forbid(unsafe_code)]

//! # ssk-service-host — the ServiceHost lifecycle + PrivilegedHelper seam (SSCL Crown)
//!
//! The SSCL Crown runs the system as a long-lived, privileged host (a system
//! service / helper). This crate is the **lifecycle controller** for that host: a
//! pure, authorization-gated, audited state machine
//!
//! ```text
//! Uninstalled → Installed → Running → Stopped → (Uninstalled)
//! ```
//!
//! plus a **capability handshake** that must complete before the host may run.
//! The controller never performs the privileged transitions itself — it drives an
//! injected [`PrivilegedHelper`] (the real system service binds it at the
//! integration layer; tests inject a fake), records every transition to a
//! hash-chained audit ledger, and rolls the install back on uninstall via the
//! receipt captured at install time.
//!
//! It is **fail-closed** by construction:
//!
//! * [`ServiceHost::start`] refuses unless the host is `Installed`, the handshake
//!   is complete, and *every* required [`Capability`] was granted.
//! * The handshake grants a capability only if the [`HostManifest`] provides it
//!   **and** the [`AuthorizationManifest`] authorizes that capability's use — an
//!   authorized request for a capability the host cannot provide is denied, not
//!   silently narrowed.
//! * Every control operation requires [`SERVICE_CONTROL_USE`]; an unauthorized
//!   call changes no state and never touches the helper.
//!
//! [`ServiceHost::health`] is a pure function of state that the CrownSupervisor
//! (`ssk-crown`) can consult so that emission is held while the host is not
//! healthily running.

use serde::{Deserialize, Serialize};
use ssk_signature::AuthorizationManifest;
use ssk_types::{digest_of, Digest, HashAlg};
use std::collections::BTreeSet;

/// Authorization use required to control the host lifecycle.
pub const SERVICE_CONTROL_USE: &str = "service_control";

/// Errors the service host can return.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    #[error("service operation requires authorization")]
    Unauthorized,
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
    #[error("host has not completed the capability handshake")]
    NotHandshaked,
    #[error("capability not provided by host: {0}")]
    CapabilityDenied(String),
    #[error("privileged helper failed: {0}")]
    Helper(String),
}

/// The host lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Uninstalled,
    Installed,
    Running,
    Stopped,
}

impl ServiceState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceState::Uninstalled => "uninstalled",
            ServiceState::Installed => "installed",
            ServiceState::Running => "running",
            ServiceState::Stopped => "stopped",
        }
    }
}

/// The host's operational health — a pure function of its state that the Crown
/// can consult. Only a `Running` host is `Healthy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceHealth {
    /// Installed and running with a completed handshake.
    Healthy,
    /// Installed but not running (staged, stopped) — emission should hold.
    Degraded,
    /// Not installed — emission should hold.
    Down,
}

impl ServiceHealth {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceHealth::Healthy => "healthy",
            ServiceHealth::Degraded => "degraded",
            ServiceHealth::Down => "down",
        }
    }

    /// True only when the host is healthily running — the Crown's precondition
    /// for emission.
    #[must_use]
    pub fn is_emittable(self) -> bool {
        self == ServiceHealth::Healthy
    }
}

/// A named privileged capability (e.g. `system_capture`, `egress_teardown`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Capability(pub String);

impl Capability {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Capability(name.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A content-addressed description of the host: what it is and which capabilities
/// it can provide.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostManifest {
    pub host_id: Digest,
    pub name: String,
    pub version: String,
    pub os_target: String,
    /// The capabilities this host can provide (a handshake may request a subset).
    pub provided: BTreeSet<String>,
}

impl HostManifest {
    /// Build a manifest, deriving its content-addressed `host_id`.
    #[must_use]
    pub fn new<I, S>(
        name: impl Into<String>,
        version: impl Into<String>,
        os_target: impl Into<String>,
        provided: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.into();
        let version = version.into();
        let os_target = os_target.into();
        let provided: BTreeSet<String> = provided.into_iter().map(Into::into).collect();
        #[derive(Serialize)]
        struct Form<'a> {
            name: &'a str,
            version: &'a str,
            os_target: &'a str,
            provided: &'a BTreeSet<String>,
        }
        let host_id = digest_of(
            &Form {
                name: &name,
                version: &version,
                os_target: &os_target,
                provided: &provided,
            },
            HashAlg::Blake3,
        )
        .expect("host manifest form is serializable");
        HostManifest {
            host_id,
            name,
            version,
            os_target,
            provided,
        }
    }

    #[must_use]
    pub fn provides(&self, capability: &Capability) -> bool {
        self.provided.contains(&capability.0)
    }
}

/// A receipt of an install — captures the prior state so uninstall can roll back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallReceipt {
    pub receipt_id: Digest,
    pub host_id: Digest,
    pub prior_state: String,
}

impl InstallReceipt {
    #[must_use]
    pub fn new(host_id: Digest, prior_state: ServiceState) -> Self {
        #[derive(Serialize)]
        struct Form<'a> {
            host_id: &'a Digest,
            prior_state: &'a str,
        }
        let receipt_id = digest_of(
            &Form {
                host_id: &host_id,
                prior_state: prior_state.as_str(),
            },
            HashAlg::Blake3,
        )
        .expect("install receipt form is serializable");
        InstallReceipt {
            receipt_id,
            host_id,
            prior_state: prior_state.as_str().to_owned(),
        }
    }
}

/// The pluggable privileged-transition seam. The real system service / helper
/// binds this at the integration layer; the controller only ever calls through
/// it — it performs no privileged work itself.
pub trait PrivilegedHelper {
    /// Install the host, returning a rollback receipt.
    ///
    /// # Errors
    /// [`ServiceError::Helper`] on failure.
    fn install(&self, manifest: &HostManifest) -> Result<InstallReceipt, ServiceError>;
    /// Start the installed host with the granted capability set.
    ///
    /// # Errors
    /// [`ServiceError::Helper`] on failure.
    fn start(&self, host_id: &Digest, granted: &BTreeSet<String>) -> Result<(), ServiceError>;
    /// Stop the running host.
    ///
    /// # Errors
    /// [`ServiceError::Helper`] on failure.
    fn stop(&self, host_id: &Digest) -> Result<(), ServiceError>;
    /// Uninstall the host, reverting the install described by the receipt.
    ///
    /// # Errors
    /// [`ServiceError::Helper`] on failure.
    fn uninstall(&self, receipt: &InstallReceipt) -> Result<(), ServiceError>;
}

/// One audited lifecycle transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceEvent {
    pub kind: String,
    pub from_state: String,
    pub to_state: String,
    pub actor: String,
    pub detail: Option<String>,
}

/// A hash-chained audit entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAuditEntry {
    pub seq: u64,
    pub prev_hash: Digest,
    pub event: ServiceEvent,
    pub entry_hash: Digest,
}

#[derive(Serialize)]
struct AuditForm<'a> {
    seq: u64,
    prev_hash: &'a Digest,
    event: &'a ServiceEvent,
}

fn audit_hash(seq: u64, prev_hash: &Digest, event: &ServiceEvent) -> Digest {
    digest_of(
        &AuditForm {
            seq,
            prev_hash,
            event,
        },
        HashAlg::Blake3,
    )
    .expect("service audit entry is serializable")
}

/// The lifecycle controller.
#[derive(Clone, Debug)]
pub struct ServiceHost {
    manifest: HostManifest,
    control_use: String,
    state: ServiceState,
    granted: BTreeSet<String>,
    handshake_done: bool,
    receipt: Option<InstallReceipt>,
    ledger: Vec<ServiceAuditEntry>,
}

impl ServiceHost {
    /// Stage a host for a manifest. It begins `Uninstalled`.
    #[must_use]
    pub fn stage(manifest: HostManifest) -> Self {
        ServiceHost {
            manifest,
            control_use: SERVICE_CONTROL_USE.to_owned(),
            state: ServiceState::Uninstalled,
            granted: BTreeSet::new(),
            handshake_done: false,
            receipt: None,
            ledger: Vec::new(),
        }
    }

    #[must_use]
    pub fn state(&self) -> ServiceState {
        self.state
    }

    #[must_use]
    pub fn manifest(&self) -> &HostManifest {
        &self.manifest
    }

    #[must_use]
    pub fn granted(&self) -> &BTreeSet<String> {
        &self.granted
    }

    #[must_use]
    pub fn handshake_complete(&self) -> bool {
        self.handshake_done
    }

    #[must_use]
    pub fn audit_entries(&self) -> &[ServiceAuditEntry] {
        &self.ledger
    }

    /// The host's health, as a pure function of its state — the Crown's emission
    /// precondition.
    #[must_use]
    pub fn health(&self) -> ServiceHealth {
        match self.state {
            ServiceState::Running => ServiceHealth::Healthy,
            ServiceState::Installed | ServiceState::Stopped => ServiceHealth::Degraded,
            ServiceState::Uninstalled => ServiceHealth::Down,
        }
    }

    fn record(
        &mut self,
        kind: &str,
        from: ServiceState,
        to: ServiceState,
        actor: &str,
        detail: Option<String>,
    ) {
        let event = ServiceEvent {
            kind: kind.to_owned(),
            from_state: from.as_str().to_owned(),
            to_state: to.as_str().to_owned(),
            actor: actor.to_owned(),
            detail: detail.clone(),
        };
        let seq = self.ledger.len() as u64;
        let prev_hash = self.ledger.last().map_or(Digest::GENESIS, |e| e.entry_hash);
        let entry_hash = audit_hash(seq, &prev_hash, &event);
        self.ledger.push(ServiceAuditEntry {
            seq,
            prev_hash,
            event,
            entry_hash,
        });

        tracing::info!(
            target: "ssk.lifecycle",
            event = "lifecycle_transition",
            host = %self.manifest.host_id.to_hex(),
            kind,
            from = from.as_str(),
            to = to.as_str(),
            actor,
            detail = ?detail,
            health = self.health().as_str(),
        );
    }

    fn require_control(&self, authorization: &AuthorizationManifest) -> Result<(), ServiceError> {
        if authorization.is_valid_for(&self.control_use) {
            Ok(())
        } else {
            Err(ServiceError::Unauthorized)
        }
    }

    /// Install the host. Requires a control authorization.
    ///
    /// # Errors
    /// [`ServiceError::Unauthorized`], [`ServiceError::InvalidTransition`] if not
    /// `Uninstalled`, or [`ServiceError::Helper`].
    pub fn install(
        &mut self,
        authorization: &AuthorizationManifest,
        helper: &dyn PrivilegedHelper,
    ) -> Result<(), ServiceError> {
        self.require_control(authorization)?;
        if self.state != ServiceState::Uninstalled {
            return Err(ServiceError::InvalidTransition(format!(
                "cannot install from {}",
                self.state.as_str()
            )));
        }
        let receipt = helper.install(&self.manifest)?;
        let from = self.state;
        self.state = ServiceState::Installed;
        self.receipt = Some(receipt);
        self.record(
            "install",
            from,
            self.state,
            &authorization.source_name,
            None,
        );
        Ok(())
    }

    /// Complete the capability handshake: grant each required capability that the
    /// host provides *and* the authorization permits. Requires a control
    /// authorization and an `Installed` host.
    ///
    /// # Errors
    /// [`ServiceError::Unauthorized`] (missing control use, or a required
    /// capability's use is not authorized), [`ServiceError::InvalidTransition`] if
    /// not `Installed`, or [`ServiceError::CapabilityDenied`] if the host does not
    /// provide a required capability.
    pub fn handshake(
        &mut self,
        required: &[Capability],
        authorization: &AuthorizationManifest,
    ) -> Result<(), ServiceError> {
        self.require_control(authorization)?;
        if self.state != ServiceState::Installed {
            return Err(ServiceError::InvalidTransition(format!(
                "handshake requires an installed host, not {}",
                self.state.as_str()
            )));
        }
        let mut granted = BTreeSet::new();
        for capability in required {
            if !self.manifest.provides(capability) {
                return Err(ServiceError::CapabilityDenied(capability.0.clone()));
            }
            // The capability's use must itself be authorized — an authorized
            // control call does not implicitly grant every capability.
            if !authorization.is_valid_for(capability.as_str()) {
                return Err(ServiceError::Unauthorized);
            }
            granted.insert(capability.0.clone());
        }
        self.granted = granted;
        self.handshake_done = true;
        self.record(
            "handshake",
            self.state,
            self.state,
            &authorization.source_name,
            Some(format!("granted {} capability/ies", self.granted.len())),
        );
        Ok(())
    }

    /// Start the host. Fail-closed: requires an `Installed` (or `Stopped`) host, a
    /// completed handshake, and every required capability granted.
    ///
    /// # Errors
    /// [`ServiceError::Unauthorized`], [`ServiceError::InvalidTransition`],
    /// [`ServiceError::NotHandshaked`], [`ServiceError::CapabilityDenied`] if a
    /// required capability was not granted, or [`ServiceError::Helper`].
    pub fn start(
        &mut self,
        required: &[Capability],
        authorization: &AuthorizationManifest,
        helper: &dyn PrivilegedHelper,
    ) -> Result<(), ServiceError> {
        self.require_control(authorization)?;
        if !matches!(self.state, ServiceState::Installed | ServiceState::Stopped) {
            return Err(ServiceError::InvalidTransition(format!(
                "cannot start from {}",
                self.state.as_str()
            )));
        }
        if !self.handshake_done {
            return Err(ServiceError::NotHandshaked);
        }
        for capability in required {
            if !self.granted.contains(&capability.0) {
                return Err(ServiceError::CapabilityDenied(capability.0.clone()));
            }
        }
        helper.start(&self.manifest.host_id, &self.granted)?;
        let from = self.state;
        self.state = ServiceState::Running;
        self.record("start", from, self.state, &authorization.source_name, None);
        Ok(())
    }

    /// Stop the running host. Requires a control authorization.
    ///
    /// # Errors
    /// [`ServiceError::Unauthorized`], [`ServiceError::InvalidTransition`] if not
    /// `Running`, or [`ServiceError::Helper`].
    pub fn stop(
        &mut self,
        authorization: &AuthorizationManifest,
        helper: &dyn PrivilegedHelper,
    ) -> Result<(), ServiceError> {
        self.require_control(authorization)?;
        if self.state != ServiceState::Running {
            return Err(ServiceError::InvalidTransition(format!(
                "cannot stop from {}",
                self.state.as_str()
            )));
        }
        helper.stop(&self.manifest.host_id)?;
        let from = self.state;
        self.state = ServiceState::Stopped;
        self.record("stop", from, self.state, &authorization.source_name, None);
        Ok(())
    }

    /// Uninstall the host, reverting the install (rollback via the receipt).
    /// Requires a control authorization. A running host is stopped first.
    ///
    /// # Errors
    /// [`ServiceError::Unauthorized`], [`ServiceError::InvalidTransition`] if
    /// already `Uninstalled`, or [`ServiceError::Helper`].
    pub fn uninstall(
        &mut self,
        authorization: &AuthorizationManifest,
        helper: &dyn PrivilegedHelper,
    ) -> Result<(), ServiceError> {
        self.require_control(authorization)?;
        if self.state == ServiceState::Uninstalled {
            return Err(ServiceError::InvalidTransition(
                "already uninstalled".to_owned(),
            ));
        }
        if self.state == ServiceState::Running {
            helper.stop(&self.manifest.host_id)?;
            let from = self.state;
            self.state = ServiceState::Stopped;
            self.record("stop", from, self.state, &authorization.source_name, None);
        }
        let receipt = self
            .receipt
            .take()
            .ok_or_else(|| ServiceError::InvalidTransition("no install receipt".to_owned()))?;
        helper.uninstall(&receipt)?;
        let from = self.state;
        self.state = ServiceState::Uninstalled;
        // The host must re-handshake after a fresh install.
        self.handshake_done = false;
        self.granted.clear();
        self.record(
            "uninstall",
            from,
            self.state,
            &authorization.source_name,
            None,
        );
        Ok(())
    }

    /// Verify the audit chain.
    #[must_use]
    pub fn verify_audit(&self) -> bool {
        let mut expected_prev = Digest::GENESIS;
        for (index, entry) in self.ledger.iter().enumerate() {
            if entry.seq != index as u64 || entry.prev_hash != expected_prev {
                return false;
            }
            if entry.entry_hash != audit_hash(entry.seq, &entry.prev_hash, &entry.event) {
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
    use std::cell::RefCell;

    /// A fake helper that records the sequence of privileged calls and tracks
    /// whether the host is currently installed/running.
    struct FakeHelper {
        calls: RefCell<Vec<String>>,
        installed: RefCell<bool>,
        running: RefCell<bool>,
    }
    impl FakeHelper {
        fn new() -> Self {
            FakeHelper {
                calls: RefCell::new(Vec::new()),
                installed: RefCell::new(false),
                running: RefCell::new(false),
            }
        }
    }
    impl PrivilegedHelper for FakeHelper {
        fn install(&self, manifest: &HostManifest) -> Result<InstallReceipt, ServiceError> {
            self.calls.borrow_mut().push("install".to_owned());
            *self.installed.borrow_mut() = true;
            Ok(InstallReceipt::new(
                manifest.host_id,
                ServiceState::Uninstalled,
            ))
        }
        fn start(&self, _id: &Digest, _granted: &BTreeSet<String>) -> Result<(), ServiceError> {
            self.calls.borrow_mut().push("start".to_owned());
            *self.running.borrow_mut() = true;
            Ok(())
        }
        fn stop(&self, _id: &Digest) -> Result<(), ServiceError> {
            self.calls.borrow_mut().push("stop".to_owned());
            *self.running.borrow_mut() = false;
            Ok(())
        }
        fn uninstall(&self, _receipt: &InstallReceipt) -> Result<(), ServiceError> {
            self.calls.borrow_mut().push("uninstall".to_owned());
            *self.installed.borrow_mut() = false;
            Ok(())
        }
    }

    fn manifest() -> HostManifest {
        HostManifest::new(
            "ssk-crown-host",
            "0.1.0",
            "linux",
            ["system_capture", "egress_teardown"],
        )
    }

    fn control_auth() -> AuthorizationManifest {
        AuthorizationManifest::new("operator", "me", "host control").with_allowed_uses([
            SERVICE_CONTROL_USE,
            "system_capture",
            "egress_teardown",
        ])
    }

    fn required() -> Vec<Capability> {
        vec![
            Capability::new("system_capture"),
            Capability::new("egress_teardown"),
        ]
    }

    #[test]
    fn full_lifecycle_is_ordered_and_audited() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        assert_eq!(host.state(), ServiceState::Uninstalled);
        assert_eq!(host.health(), ServiceHealth::Down);

        host.install(&control_auth(), &helper).unwrap();
        assert_eq!(host.state(), ServiceState::Installed);
        assert_eq!(host.health(), ServiceHealth::Degraded);

        host.handshake(&required(), &control_auth()).unwrap();
        assert!(host.handshake_complete());
        assert_eq!(host.granted().len(), 2);

        host.start(&required(), &control_auth(), &helper).unwrap();
        assert_eq!(host.state(), ServiceState::Running);
        assert_eq!(host.health(), ServiceHealth::Healthy);
        assert!(host.health().is_emittable());

        host.stop(&control_auth(), &helper).unwrap();
        assert_eq!(host.state(), ServiceState::Stopped);
        assert!(!host.health().is_emittable());

        host.uninstall(&control_auth(), &helper).unwrap();
        assert_eq!(host.state(), ServiceState::Uninstalled);
        // The handshake was cleared by uninstall.
        assert!(!host.handshake_complete());

        assert_eq!(
            *helper.calls.borrow(),
            vec!["install", "start", "stop", "uninstall"]
        );
        assert!(host.verify_audit());
    }

    #[test]
    fn start_is_fail_closed_without_handshake() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        host.install(&control_auth(), &helper).unwrap();
        // Starting before the handshake is refused, and the helper never starts.
        assert_eq!(
            host.start(&required(), &control_auth(), &helper)
                .unwrap_err(),
            ServiceError::NotHandshaked
        );
        assert_eq!(host.state(), ServiceState::Installed);
        assert!(!*helper.running.borrow());
    }

    #[test]
    fn handshake_denies_unprovided_capability() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        host.install(&control_auth(), &helper).unwrap();
        // The host does not provide "kernel_module".
        let over_reach = vec![Capability::new("kernel_module")];
        let auth = AuthorizationManifest::new("operator", "me", "host control")
            .with_allowed_uses([SERVICE_CONTROL_USE, "kernel_module"]);
        assert_eq!(
            host.handshake(&over_reach, &auth).unwrap_err(),
            ServiceError::CapabilityDenied("kernel_module".to_owned())
        );
        assert!(!host.handshake_complete());
    }

    #[test]
    fn handshake_requires_capability_use_authorization() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        host.install(&control_auth(), &helper).unwrap();
        // Control is authorized, but the capability use itself is not.
        let control_only = AuthorizationManifest::new("operator", "me", "host control")
            .with_allowed_uses([SERVICE_CONTROL_USE]);
        assert_eq!(
            host.handshake(&required(), &control_only).unwrap_err(),
            ServiceError::Unauthorized
        );
        assert!(!host.handshake_complete());
    }

    #[test]
    fn control_operations_require_authorization() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        let no_control =
            AuthorizationManifest::new("x", "me", "none").with_allowed_uses(["offline_analysis"]);
        assert_eq!(
            host.install(&no_control, &helper).unwrap_err(),
            ServiceError::Unauthorized
        );
        assert_eq!(host.state(), ServiceState::Uninstalled);
        assert!(host.audit_entries().is_empty());
        assert!(!*helper.installed.borrow());
    }

    #[test]
    fn uninstall_stops_a_running_host_and_rolls_back() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        host.install(&control_auth(), &helper).unwrap();
        host.handshake(&required(), &control_auth()).unwrap();
        host.start(&required(), &control_auth(), &helper).unwrap();
        assert!(*helper.running.borrow());
        // Uninstalling a running host stops it first, then rolls back.
        host.uninstall(&control_auth(), &helper).unwrap();
        assert!(!*helper.running.borrow());
        assert!(!*helper.installed.borrow());
        assert_eq!(host.state(), ServiceState::Uninstalled);
        assert!(host.audit_entries().iter().any(|e| e.event.kind == "stop"));
        assert!(host
            .audit_entries()
            .iter()
            .any(|e| e.event.kind == "uninstall"));
    }

    #[test]
    fn audit_is_tamper_evident() {
        let mut host = ServiceHost::stage(manifest());
        let helper = FakeHelper::new();
        host.install(&control_auth(), &helper).unwrap();
        host.handshake(&required(), &control_auth()).unwrap();
        host.start(&required(), &control_auth(), &helper).unwrap();
        assert!(host.verify_audit());
        // Same manifest + same operations -> same audit head (replay-stable).
        let mut twin = ServiceHost::stage(manifest());
        let helper2 = FakeHelper::new();
        twin.install(&control_auth(), &helper2).unwrap();
        twin.handshake(&required(), &control_auth()).unwrap();
        twin.start(&required(), &control_auth(), &helper2).unwrap();
        assert_eq!(
            host.audit_entries().last().unwrap().entry_hash,
            twin.audit_entries().last().unwrap().entry_hash
        );
        // Tampering a past event breaks the chain.
        let mut tampered = host.clone();
        tampered.ledger[0].event.actor = "someone-else".to_owned();
        assert!(!tampered.verify_audit());
    }
}
