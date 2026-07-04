#![forbid(unsafe_code)]

//! `ssk-netadmin` — In-process network administration layer.
//!
//! Replaces the need for third-party tools such as Proxifier by providing a
//! complete, policy-driven traffic-steering subsystem that integrates
//! directly with the SSK Ω runtime.
//!
//! # Architecture
//!
//! ```text
//! Application Intent
//!        │
//!        ▼
//! ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
//! │ Flow Intake │───▶│ Policy Engine│───▶│Route Orchestrator│
//! └─────────────┘    └──────────────┘    └─────────────────┘
//!        │                  │                      │
//!        ▼                  ▼                      ▼
//! ┌─────────────┐    ┌──────────────┐    ┌─────────────────┐
//! │  Attestation│    │Control Plane │    │ Data Plane      │
//! │  Binder     │    │(profiles/    │    │ Adapters        │
//! └─────────────┘    │ tenants/mode)│    │ (SOCKS5/HTTP/   │
//!        │           └──────────────┘    │  TLS/Direct/DNS)│
//!        ▼                               └─────────────────┘
//! ┌─────────────┐    ┌──────────────┐
//! │  Session    │    │ Audit/       │
//! │  Integrity  │───▶│ Forensics    │
//! │  (hash-     │    │ Ledger       │
//! │   chained)  │    └──────────────┘
//! └─────────────┘
//! ```
//!
//! Every layer enforces **fail-closed** semantics: on any uncertainty
//! (missing policy, unverified attestation, exhausted route candidates) the
//! system denies the flow and records a forensic entry.

pub mod adapter;
pub mod attestation;
pub mod audit;
pub mod control;
pub mod error;
pub mod flow;
pub mod policy;
pub mod route;
pub mod session;

pub use adapter::{
    AdapterDescriptor, AdapterKind, DataPlaneAdapter, DirectAdapter, DnsOverrideAdapter,
    HttpConnectAdapter, Socks5Adapter, TlsTunnelAdapter,
};
pub use attestation::{AttestationBinder, AttestationBinding};
pub use audit::{AuditLedger, AuditOutcome, ForensicEntry};
pub use control::{ControlPlane, OperatorProfile, RolloutMode, TenantContext};
pub use error::NetAdminError;
pub use flow::{FlowDescriptor, FlowRecord, ProtocolKind, RiskLevel};
pub use policy::{PolicyAction, PolicyDecision, PolicyEngine, PolicyRule};
pub use route::{HopSpec, RouteCandidate, RouteKind, RouteOrchestrator};
pub use session::{SessionDecision, SessionLedger};
