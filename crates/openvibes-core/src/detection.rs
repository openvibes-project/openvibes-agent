//! Bounded original evaluation explanations (protocol P17).

use crate::{Identifier, ResourceLimits, Validate, ValidationError, digest_from_hex};
use serde::{Deserialize, Serialize};

/// Maximum compact JSON bytes of one explanation.
pub const DETECTION_BYTES: usize = 8192;

/// Bundle identity and original evaluation evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Detection {
    /// Time of the captured sample, independent of match start or heartbeat.
    pub observed_at_unix_ms: i64,
    /// Version of the verified rule set.
    pub rule_set_version: u64,
    /// SHA-256 of the bundle's signing preimage (lowercase hex).
    pub preimage_sha256: String,
    /// Only input keys actually read by the interpreter.
    pub inputs: Vec<DetectionInput>,
    /// Boolean conditions in completion order; skipped branches are absent.
    pub steps: Vec<DetectionStep>,
    /// Capture ran out of space or work budget.
    pub truncated: bool,
}

/// One scalar value; lists are summarized without copying inventory.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum DetectionValue {
    /// Boolean input.
    Boolean(bool),
    /// Signed integer input.
    Integer(i64),
    /// Bounded UTF-8 text.
    String(String),
}

/// How much of an input was retained.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    /// Entire scalar value.
    Complete,
    /// Sensitive value intentionally omitted.
    Masked,
    /// Complete source list represented by its item count.
    Summarized,
    /// Clipped scalar string.
    Truncated,
}

/// A key actually read from the immutable evaluation input.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectionInput {
    /// Fact or event binding key.
    pub key: Identifier,
    /// Completeness and masking marker.
    pub status: DetectionStatus,
    /// Scalar value, omitted for masked values and lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<DetectionValue>,
    /// Size of a complete source list, without sending its contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_count: Option<usize>,
}

/// A Boolean expression evaluated during the original run.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DetectionStep {
    /// Canonical CEL containing rule literals and keys, never collected values.
    pub expression: String,
    /// Actual original result; skipped expressions have no step.
    pub result: bool,
}

impl Validate for Detection {
    fn validate(&self, _limits: ResourceLimits) -> Result<(), ValidationError> {
        let invalid = || ValidationError::new("detection", "invalid or over limit");
        if self.observed_at_unix_ms < 0
            || self.rule_set_version == 0
            || digest_from_hex(&self.preimage_sha256).is_none()
            || self.inputs.len() > 32
            || self.steps.len() > 32
        {
            return Err(invalid());
        }
        let mut keys = std::collections::BTreeSet::new();
        for input in &self.inputs {
            if !keys.insert(input.key.as_str()) {
                return Err(invalid());
            }
            let text_ok = match &input.value {
                Some(DetectionValue::String(value)) => value.len() <= 256 && !value.contains('\0'),
                _ => true,
            };
            let shape_ok = match input.status {
                DetectionStatus::Complete => input.value.is_some() && input.item_count.is_none(),
                DetectionStatus::Truncated => {
                    matches!(input.value, Some(DetectionValue::String(_)))
                        && input.item_count.is_none()
                }
                DetectionStatus::Masked => input.value.is_none() && input.item_count.is_none(),
                DetectionStatus::Summarized => {
                    input.value.is_none() && input.item_count.is_some_and(|n| n <= 50_000)
                }
            };
            if !text_ok || !shape_ok {
                return Err(invalid());
            }
        }
        if self.steps.iter().any(|s| {
            s.expression.is_empty() || s.expression.len() > 512 || s.expression.contains('\0')
        }) {
            return Err(invalid());
        }
        if serde_json::to_vec(self).map_err(|_| invalid())?.len() > DETECTION_BYTES {
            return Err(invalid());
        }
        Ok(())
    }
}
