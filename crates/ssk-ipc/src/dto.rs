#![forbid(unsafe_code)]

//! DTOs for the GUI backend API (`docs/DESKTOP_CLIENT_ARCHITECTURE.md` section J),
//! commands 1-4 and 15-22 (Phase 2 scope). Reuses `ssk-netadmin`'s public
//! types directly wherever possible instead of re-declaring them.

use serde::{Deserialize, Serialize};

use crate::error::IpcError;
use crate::state::DaemonState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterHealthSummaryDto {
    pub id: String,
    pub health: String,
}

/// Response to `get_status` (command 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusDto {
    pub state: DaemonState,
    pub active_profile: Option<String>,
    pub adapters: Vec<AdapterHealthSummaryDto>,
    pub dns_protected: bool,
    pub kill_switch: bool,
    pub audit_head: Option<String>,
    pub version: String,
    pub last_error: Option<IpcError>,
}

/// Request for `activate_profile` (command 2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivateProfileRequest {
    pub profile_id: String,
}

/// Request for `deactivate` (command 3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeactivateRequest {
    pub release_kill_switch: bool,
}

/// One entry of `list_profiles` (command 4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileSummaryDto {
    pub id: String,
    pub name: String,
}

/// Response to `inspect_flow` (command 15). Reuses `ssk-netadmin`'s real
/// descriptor/action/route types rather than re-declaring them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowInspectionDto {
    pub descriptor: ssk_netadmin::FlowDescriptor,
    pub matched_rule: Option<String>,
    pub action: ssk_netadmin::PolicyAction,
    pub route: ssk_netadmin::RouteKind,
    pub requires_attestation: bool,
}

/// Request for `trace_route` (command 16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTraceRequest {
    pub app_id: Option<String>,
    pub dest_host: String,
    pub dest_port: u16,
    pub protocol: String,
    pub risk: String,
}

/// Response to `trace_route` (command 16).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteTraceDto {
    pub route: ssk_netadmin::RouteKind,
    pub hops: Vec<String>,
    pub requires_attestation: bool,
}

/// One entry of `list_recent_flows` (command 17). Empty until `ssk-capture`
/// (Phase 4) provides real traffic ingress — no flows are fabricated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowSummaryDto {
    pub flow_id: String,
    pub app_id: String,
    pub destination: String,
    pub outcome: String,
}

/// One entry of `get_audit_entries` (command 18).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryDto {
    pub entry_id: String,
    pub flow_id: String,
    pub outcome: String,
    pub route_kind_summary: String,
    pub epoch: u64,
    pub prev_hash: String,
    pub entry_hash: String,
}

impl From<&ssk_netadmin::ForensicEntry> for AuditEntryDto {
    fn from(e: &ssk_netadmin::ForensicEntry) -> Self {
        Self {
            entry_id: e.entry_id.clone(),
            flow_id: e.flow_id.clone(),
            outcome: format!("{:?}", e.outcome),
            route_kind_summary: e.route_kind_summary.clone(),
            epoch: e.epoch,
            prev_hash: e.prev_hash.clone(),
            entry_hash: e.entry_hash.clone(),
        }
    }
}

/// Response to `verify_audit_chain` (command 19).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyAuditChainResponse {
    pub ok: bool,
    pub head: Option<String>,
    pub broken_at: Option<String>,
}

/// One check within `run_doctor` (command 20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorCheckDto {
    pub name: String,
    pub ok: bool,
    pub detail: String,
    pub next_step: Option<String>,
}

/// Response to `run_doctor` (command 20).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReportDto {
    pub checks: Vec<DoctorCheckDto>,
}

/// Request for `explain_error` (command 21).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainRequest {
    pub code: String,
}

/// Response to `explain_error` (command 21).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    pub summary: String,
    pub details: String,
    pub next_steps: Vec<String>,
}

/// Request for `subscribe_events` (command 22).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeEventsRequest {
    pub kinds: Option<Vec<String>>,
}
