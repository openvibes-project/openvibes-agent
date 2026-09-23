use serde::{Deserialize, Serialize};

use crate::{
    Identifier, ResourceLimits, SchemaVersion, Validate, ValidationError,
    contracts::validate_version,
};

/// Asks the distribution service for one rule set's current signed bundle.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleBundleRequest {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// Rule set to fetch.
    pub rule_set_id: Identifier,
    /// Version the agent last accepted; `None` when it has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
}

impl Validate for RuleBundleRequest {
    fn validate(&self, _limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        if self.current_version == Some(0) {
            return Err(ValidationError::new(
                "current_version",
                "must be a positive version",
            ));
        }
        Ok(())
    }
}
