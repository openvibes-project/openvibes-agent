#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Capability-neutral domain types and orchestration contracts.
//!
//! This crate must not access the filesystem, operating-system APIs, SQLite, or
//! the network. Concrete capabilities belong in the component crates and are
//! wired together by `openvibes-agent`.

mod contracts;
mod distribution;
mod export;
mod limits;

pub use contracts::{
    CollectorError, CollectorErrorCode, Confidence, DeliveryAcknowledgement, EnrollmentRequest,
    EnrollmentResponse, EnrollmentToken, Fact, FactSet, FactValue, Finding, FindingBatch,
    Heartbeat, Identifier, PayloadEncoding, PlatformError, PlatformErrorCode, RenewalRequest, Rule,
    RuleSet, SchemaVersion, Severity, SignedRuleEnvelope, Validate, ValidationError,
    validate_document_size,
};
pub use distribution::RuleBundleRequest;
pub use export::FindingExport;
pub use limits::ResourceLimits;

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
