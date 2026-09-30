//! Alarm wire types (protocol P14, `POST /v1/alarms`).

use serde::{Deserialize, Serialize};

use crate::{
    Confidence, Identifier, ResourceLimits, SchemaVersion, Severity, Validate, ValidationError,
    contracts::{validate_identifier, validate_string, validate_unix_ms, validate_version},
};

/// Alarms in one batch.
pub const ALARMS_PER_BATCH: usize = 100;
/// One batch, serialized, uncompressed.
pub const ALARM_BATCH_BYTES: usize = 262_144;
/// One alarm, serialized.
pub const ALARM_BYTES: usize = 65_536;
/// Arguments per process.
pub const ALARM_ARGS: usize = 256;
/// Arguments per process, UTF-8 bytes joined by single spaces.
pub const ALARM_ARGS_BYTES: usize = 4_096;
/// Ancestors per alarm.
pub const ALARM_ANCESTORS: usize = 5;

/// One process in an alarm.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlarmProcess {
    /// Process id.
    pub pid: u32,
    /// Executed file (for a seeded process: see the contract).
    pub exe: String,
    /// Masked, capped arguments.
    pub args: Vec<String>,
    /// Working directory, when readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Real user id.
    pub uid: u32,
    /// Effective user id (differs after a setuid exec such as `sudo`).
    pub euid: u32,
    /// Whether `args` was cut to the limit.
    pub truncated: bool,
    /// Learnt from `/proc` at start rather than from an exec event.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub seeded: bool,
}

/// One alarm raised by a `process_event` rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Alarm {
    /// Made once by the agent; repeats and retries reuse it.
    pub alarm_id: Identifier,
    /// Rule set of the matching rule.
    pub rule_set_id: Identifier,
    /// Its accepted version.
    pub rule_set_version: u64,
    /// Matching rule.
    pub rule_id: Identifier,
    /// Its version.
    pub rule_version: u64,
    /// Rule severity.
    pub severity: Severity,
    /// Rule confidence.
    pub confidence: Confidence,
    /// The rule's finding message.
    pub message: String,
    /// First match.
    pub first_seen_unix_ms: i64,
    /// Latest collapsed repeat.
    pub last_seen_unix_ms: i64,
    /// Matches collapsed into this alarm.
    pub count: u32,
    /// The process that started.
    pub process: AlarmProcess,
    /// Its parent first, then further ancestors.
    pub ancestors: Vec<AlarmProcess>,
}

/// Body of `POST /v1/alarms`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlarmBatch {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// The authenticated agent.
    pub agent_id: Identifier,
    /// Cumulative alarms dropped; never decreases.
    pub dropped_total: u64,
    /// 1 to 100 alarms.
    pub alarms: Vec<Alarm>,
}

impl Validate for AlarmProcess {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_string("process.exe", &self.exe, limits)?;
        if let Some(cwd) = &self.cwd {
            validate_string("process.cwd", cwd, limits)?;
        }
        if self.args.len() > ALARM_ARGS {
            return Err(ValidationError::new(
                "process.args",
                "holds too many arguments",
            ));
        }
        if self.args.iter().any(|arg| arg.contains('\0')) {
            return Err(ValidationError::new("process.args", "contains U+0000"));
        }
        let joined =
            self.args.iter().map(String::len).sum::<usize>() + self.args.len().saturating_sub(1);
        if joined > ALARM_ARGS_BYTES {
            return Err(ValidationError::new(
                "process.args",
                "exceeds 4096 bytes joined",
            ));
        }
        Ok(())
    }
}

impl Validate for Alarm {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        for (field, id) in [
            ("alarm_id", &self.alarm_id),
            ("rule_set_id", &self.rule_set_id),
            ("rule_id", &self.rule_id),
        ] {
            validate_identifier(field, id.as_str(), limits)?;
        }
        if self.rule_set_version == 0 || self.rule_version == 0 {
            return Err(ValidationError::new("rule_version", "must be positive"));
        }
        validate_string("message", &self.message, limits)?;
        validate_unix_ms("first_seen_unix_ms", self.first_seen_unix_ms)?;
        if self.last_seen_unix_ms < self.first_seen_unix_ms {
            return Err(ValidationError::new(
                "last_seen_unix_ms",
                "is before first_seen_unix_ms",
            ));
        }
        if self.count == 0 || self.count > i32::MAX as u32 {
            return Err(ValidationError::new("count", "must be 1 to 2^31-1"));
        }
        if self.ancestors.len() > ALARM_ANCESTORS {
            return Err(ValidationError::new(
                "ancestors",
                "holds more than 5 processes",
            ));
        }
        self.process.validate(limits)?;
        for ancestor in &self.ancestors {
            ancestor.validate(limits)?;
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ValidationError::new("alarm", "does not serialize"))?;
        if bytes.len() > ALARM_BYTES {
            return Err(ValidationError::new("alarm", "exceeds 64 KiB serialized"));
        }
        Ok(())
    }
}

impl Validate for AlarmBatch {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_identifier("agent_id", self.agent_id.as_str(), limits)?;
        if self.dropped_total > i64::MAX as u64 {
            return Err(ValidationError::new("dropped_total", "exceeds 2^63-1"));
        }
        if self.alarms.is_empty() || self.alarms.len() > ALARMS_PER_BATCH {
            return Err(ValidationError::new("alarms", "must hold 1 to 100 alarms"));
        }
        for alarm in &self.alarms {
            alarm.validate(limits)?;
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|_| ValidationError::new("batch", "does not serialize"))?;
        if bytes.len() > ALARM_BATCH_BYTES {
            return Err(ValidationError::new("batch", "exceeds 256 KiB serialized"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch() -> AlarmBatch {
        serde_json::from_str(include_str!(
            "../../../protocol/fixtures/v1/alarm-batch/valid.json"
        ))
        .unwrap()
    }

    #[test]
    fn last_seen_before_first_seen_is_refused() {
        let mut b = batch();
        b.alarms[0].last_seen_unix_ms = b.alarms[0].first_seen_unix_ms - 1;
        assert!(b.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn args_are_bounded_joined_by_spaces() {
        let mut b = batch();
        // 2047 + 1 + 2047 = 4095 bytes: fits.
        b.alarms[0].process.args = vec!["a".repeat(2047), "b".repeat(2047)];
        assert!(b.validate(ResourceLimits::V1).is_ok());
        // 2048 + 1 + 2048 = 4097: refused.
        b.alarms[0].process.args = vec!["a".repeat(2048), "b".repeat(2048)];
        assert!(b.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn a_nul_in_an_argument_is_refused_but_an_empty_one_is_not() {
        let mut b = batch();
        b.alarms[0].process.args = vec![String::new()];
        assert!(b.validate(ResourceLimits::V1).is_ok());
        b.alarms[0].process.args = vec!["a\0b".into()];
        assert!(b.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn count_and_dropped_total_stay_in_signed_range() {
        let mut b = batch();
        b.alarms[0].count = 1 << 31;
        assert!(b.validate(ResourceLimits::V1).is_err());
        let mut b = batch();
        b.dropped_total = 1 << 63;
        assert!(b.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn seeded_is_omitted_when_false() {
        let json = serde_json::to_string(&batch().alarms[0].process).unwrap();
        assert!(!json.contains("seeded"), "{json}");
    }
}
