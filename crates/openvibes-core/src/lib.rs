#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Capability-neutral domain types and orchestration contracts.
//!
//! This crate must not access the filesystem, operating-system APIs, SQLite, or
//! the network. Concrete capabilities belong in the component crates and are
//! wired together by `openvibes-agent`.

mod alarm;
mod alarm_mask;
mod contracts;
mod detection;
mod distribution;
mod export;
mod health;
mod inventory;
mod limits;
mod matches;
mod services;

pub use alarm::{
    ALARM_ANCESTORS, ALARM_ARGS, ALARM_ARGS_BYTES, ALARM_BATCH_BYTES, ALARM_BYTES,
    ALARMS_PER_BATCH, Alarm, AlarmBatch, AlarmProcess,
};
pub use alarm_mask::{cap_args, mask_args};
pub use contracts::{
    CollectorError, CollectorErrorCode, Confidence, DeliveryAcknowledgement, EnrollmentRequest,
    EnrollmentResponse, EnrollmentToken, Fact, FactSet, FactValue, Finding, FindingBatch,
    Heartbeat, Identifier, PayloadEncoding, PlatformError, PlatformErrorCode, RejectedFinding,
    RenewalRequest, Rule, RuleKind, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope, Validate,
    ValidationError, validate_document_size,
};
pub use detection::{
    DETECTION_BYTES, Detection, DetectionInput, DetectionStatus, DetectionStep, DetectionValue,
};
pub use distribution::RuleBundleRequest;
pub use export::{
    FindingExport, InstalledPackage, InventoryChanges, InventoryExport, InventoryReport, OsRelease,
    PackageManager, is_kernel_release,
};
pub use health::{
    ALARM_QUEUE_MAX, AlarmHealth, BundleRefusal, CollectorOutcome, EVENT_OPERATIONS,
    HEALTH_MAX_COLLECTORS, HEALTH_MAX_EVENT_RULES, HEALTH_MAX_REASONS, HEALTH_MAX_RULE_SETS,
    Health, QueueHealth, RuleSetHealth, ScanHealth,
};
pub use inventory::{
    NormalizedPackage, digest_from_hex, hex, inventory_changes, inventory_fingerprint,
};
pub use limits::{PACKAGE_NAMES, ResourceLimits};
pub use matches::{
    EndedMatch, FindingChanges, MAX_CHANGE_ENTRIES, MAX_MATCHES, MAX_TRANSIENT, TransientMatch,
    match_digest, materially_differs,
};
pub use services::{
    HOST_SERVICES_BYTES, HostService, HostServices, ListenerProtocol, Owners, SERVICE_MAX_PROGRAMS,
    SERVICES_MAX_LISTENERS, SERVICES_MAX_SERVICES, ServiceListener, is_service_name, is_unit_name,
    listener_row, service_row, services_digest,
};

/// Human-readable name of this workspace component.
pub const COMPONENT_NAME: &str = "core";

/// Describes a component included in a scanner build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentDescriptor {
    name: &'static str,
}

impl ComponentDescriptor {
    /// Creates a descriptor for a statically named component.
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    /// Returns the component name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }
}

#[cfg(test)]
mod tests {
    use super::ComponentDescriptor;

    #[test]
    fn descriptor_preserves_component_name() {
        let descriptor = ComponentDescriptor::new("rules");

        assert_eq!(descriptor.name(), "rules");
    }
}
