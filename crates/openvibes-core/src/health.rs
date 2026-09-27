//! Agent health (protocol P12): the optional report a heartbeat carries.
//! Counts and codes only, bounded, and cumulative where it says total.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{CollectorErrorCode, Identifier, ResourceLimits, Validate, ValidationError};

/// Most collectors a report may list.
pub const HEALTH_MAX_COLLECTORS: usize = 16;
/// Most rule sets a report may list.
pub const HEALTH_MAX_RULE_SETS: usize = 64;
/// Most rejection reasons a report may list.
pub const HEALTH_MAX_REASONS: usize = 16;

/// The agent's health, sent in `Heartbeat.health`.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Health {
    /// The finding queue.
    pub queue: QueueHealth,
    /// The last scan; absent before the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan: Option<ScanHealth>,
    /// Each configured rule set.
    #[serde(default)]
    pub rule_sets: Vec<RuleSetHealth>,
    /// Local database failures since the agent started.
    pub storage_errors: u64,
    /// The last wall-clock jump detected, in seconds (positive: forward).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clock_jump_s: Option<i64>,
}

/// The finding queue's state and durable totals.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueHealth {
    /// Findings awaiting acknowledgement.
    pub pending: u64,
    /// Age of the oldest pending finding; absent when none is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_pending_age_s: Option<u64>,
    /// Bytes the queue uses.
    pub bytes: u64,
    /// The queue's byte limit.
    pub max_bytes: u64,
    /// Findings the rotating queue dropped since it was created.
    pub dropped_total: u64,
    /// Findings the platform refused permanently, by reason.
    #[serde(default)]
    pub rejected_total: BTreeMap<Identifier, u64>,
}

/// The last scan.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ScanHealth {
    /// When it finished (Unix ms).
    pub finished_at_unix_ms: i64,
    /// The configured scan interval in seconds.
    pub interval_s: u64,
    /// Rules that matched or did not.
    pub rules_evaluated: u64,
    /// Rules not evaluated because a fact was unavailable.
    pub rules_unavailable: u64,
    /// Rules that failed to evaluate.
    pub rules_failed: u64,
    /// Each enabled collector's outcome.
    pub collectors: BTreeMap<Identifier, CollectorOutcome>,
}

/// How a collector did in the last scan.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorOutcome {
    /// It collected.
    Ok,
    /// It lacked read access.
    PermissionDenied,
    /// Its source does not exist.
    NotFound,
    /// It ran out of time.
    TimedOut,
    /// Its source could not be parsed.
    InvalidData,
    /// Not supported on this platform.
    Unsupported,
    /// Anything else.
    Internal,
}

impl From<CollectorErrorCode> for CollectorOutcome {
    fn from(code: CollectorErrorCode) -> Self {
        use CollectorErrorCode as C;
        match code {
            C::PermissionDenied => Self::PermissionDenied,
            C::NotFound => Self::NotFound,
            C::TimedOut => Self::TimedOut,
            C::InvalidData => Self::InvalidData,
            C::Unsupported => Self::Unsupported,
            C::Internal => Self::Internal,
        }
    }
}

/// One configured rule set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuleSetHealth {
    /// Rule set id.
    pub id: Identifier,
    /// The bundle version in use; `None` before one was accepted.
    #[serde(default)]
    pub version: Option<u64>,
    /// When that bundle expires (Unix ms).
    #[serde(default)]
    pub expires_at_unix_ms: Option<i64>,
    /// Why the last provisioned bundle was refused, if it was.
    #[serde(default)]
    pub refused: Option<BundleRefusal>,
}

/// Why a rule bundle was refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleRefusal {
    /// Signature, issuer, or digest did not verify.
    Signature,
    /// Expired or not yet valid.
    Expired,
    /// Older than the accepted version.
    RolledBack,
    /// Anything else wrong with it.
    Invalid,
}

impl Validate for Health {
    fn validate(&self, _limits: ResourceLimits) -> Result<(), ValidationError> {
        if self.queue.rejected_total.len() > HEALTH_MAX_REASONS {
            return Err(ValidationError::new(
                "health.queue.rejected_total",
                "more than 16 reasons",
            ));
        }
        if self.rule_sets.len() > HEALTH_MAX_RULE_SETS {
            return Err(ValidationError::new(
                "health.rule_sets",
                "more than 64 rule sets",
            ));
        }
        if let Some(scan) = &self.last_scan {
            if scan.collectors.len() > HEALTH_MAX_COLLECTORS {
                return Err(ValidationError::new(
                    "health.last_scan.collectors",
                    "more than 16 collectors",
                ));
            }
            crate::contracts::validate_unix_ms(
                "health.last_scan.finished_at_unix_ms",
                scan.finished_at_unix_ms,
            )?;
        }
        for set in &self.rule_sets {
            if let Some(expires) = set.expires_at_unix_ms {
                crate::contracts::validate_unix_ms("health.rule_sets.expires_at_unix_ms", expires)?;
            }
            if set.version == Some(0) {
                return Err(ValidationError::new(
                    "health.rule_sets.version",
                    "versions start at 1",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Heartbeat, ResourceLimits, Validate};

    fn fixture(name: &str) -> Result<Heartbeat, String> {
        let text = std::fs::read_to_string(format!(
            "{}/../../protocol/fixtures/v1/heartbeat/{name}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let heartbeat: Heartbeat = serde_json::from_str(&text).map_err(|e| e.to_string())?;
        heartbeat
            .validate(ResourceLimits::V1)
            .map_err(|e| e.to_string())?;
        Ok(heartbeat)
    }

    #[test]
    fn the_protocol_fixtures_agree() {
        let health = fixture("valid-health.json").unwrap().health.unwrap();
        assert_eq!(health.queue.pending, 12);
        for invalid in [
            "invalid-health-negative-count.json",
            "invalid-health-unknown-outcome.json",
            "invalid-health-too-many-rule-sets.json",
        ] {
            assert!(fixture(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn a_heartbeat_without_health_is_still_valid() {
        let mut heartbeat = fixture("valid-health.json").unwrap();
        heartbeat.health = None;
        let text = serde_json::to_string(&heartbeat).unwrap();
        assert!(!text.contains("health"));
        assert!(heartbeat.validate(ResourceLimits::V1).is_ok());
    }
}
