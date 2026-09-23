use serde::{Deserialize, Serialize};

use crate::{
    Finding, Identifier, ResourceLimits, SchemaVersion, Validate, ValidationError,
    contracts::{validate_string, validate_unix_ms, validate_version},
};

/// One local-only export file: a delivery batch of findings plus the host it
/// came from. Unsigned in version 1; the collector stores imports as
/// unauthenticated.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FindingExport {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Random identifier generated once per agent installation.
    pub install_id: Identifier,
    /// Platform identity, present only while the agent is enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<Identifier>,
    /// Host name as reported by the OS, for operators only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Scanner software version.
    pub scanner_version: String,
    /// Export time as milliseconds since the Unix epoch.
    pub exported_at_unix_ms: i64,
    /// Findings in queue order.
    pub findings: Vec<Finding>,
}

impl Validate for FindingExport {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        if let Some(hostname) = &self.hostname {
            validate_string("hostname", hostname, limits)?;
        }
        validate_string("scanner_version", &self.scanner_version, limits)?;
        validate_unix_ms("exported_at_unix_ms", self.exported_at_unix_ms)?;
        if self.findings.is_empty() || self.findings.len() > limits.delivery_batch_items {
            return Err(ValidationError::new(
                "findings",
                "must contain between one and one delivery batch of findings",
            ));
        }
        self.findings
            .iter()
            .try_for_each(|finding| finding.validate(limits))
    }
}
