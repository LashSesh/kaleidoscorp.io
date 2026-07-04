#![forbid(unsafe_code)]

//! Flow Intake — captures and types outgoing connection descriptors.

use serde::{Deserialize, Serialize};

/// Network protocol of an outgoing connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolKind {
    Tcp,
    Udp,
    Tls,
    Http,
    Https,
    Dns,
    /// Any other protocol identified by a custom label.
    Custom,
}

/// Risk classification of a destination or application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Describes a single outgoing connection attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDescriptor {
    /// Identifier of the application or subsystem originating the flow.
    pub app_id: String,
    /// Destination hostname or IP address.
    pub destination_host: String,
    /// Destination port (0 if irrelevant, e.g. DNS).
    pub destination_port: u16,
    /// Network protocol in use.
    pub protocol: ProtocolKind,
    /// Risk classification assigned to this destination/app pair.
    pub risk_level: RiskLevel,
}

impl FlowDescriptor {
    pub fn new(
        app_id: impl Into<String>,
        destination_host: impl Into<String>,
        destination_port: u16,
        protocol: ProtocolKind,
        risk_level: RiskLevel,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            destination_host: destination_host.into(),
            destination_port,
            protocol,
            risk_level,
        }
    }
}

/// A flow as it enters the policy pipeline: the descriptor plus a unique flow
/// identifier and a deterministic clock epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    /// Unique, monotonically increasing flow identifier.
    pub flow_id: String,
    /// Deterministic epoch at the time of intake.
    pub intake_epoch: u64,
    /// The underlying connection descriptor.
    pub descriptor: FlowDescriptor,
}

impl FlowRecord {
    pub fn new(flow_id: impl Into<String>, intake_epoch: u64, descriptor: FlowDescriptor) -> Self {
        Self {
            flow_id: flow_id.into(),
            intake_epoch,
            descriptor,
        }
    }
}
