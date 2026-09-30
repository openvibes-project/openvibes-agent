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
    /// Current matches beyond the kept ones (P13).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches_truncated: Option<u64>,
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

/// How a collector did in the last scan. Later versions may add codes;
/// one this build does not know reads as `Other` (a failure).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    /// A code from a later version.
    Other,
}

impl<'de> Deserialize<'de> for CollectorOutcome {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match open_code(deserializer)?.as_str() {
            "ok" => Self::Ok,
            "permission_denied" => Self::PermissionDenied,
            "not_found" => Self::NotFound,
            "timed_out" => Self::TimedOut,
            "invalid_data" => Self::InvalidData,
            "unsupported" => Self::Unsupported,
            "internal" => Self::Internal,
            _ => Self::Other,
        })
    }
}

/// An open code: any identifier (P12), so later versions can add values.
fn open_code<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Identifier, D::Error> {
    Identifier::deserialize(deserializer)
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

/// Why a rule bundle was refused. A code from a later version reads as
/// `Other`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
    /// A code from a later version.
    Other,
}

impl<'de> Deserialize<'de> for BundleRefusal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match open_code(deserializer)?.as_str() {
            "signature" => Self::Signature,
            "expired" => Self::Expired,
            "rolled_back" => Self::RolledBack,
            "invalid" => Self::Invalid,
            _ => Self::Other,
        })
    }
}

// Keep `fit` in openvibes-agent's health.rs in step: it leaves out what this
// refuses, so a rule added here and not there drops whole reports again (#66).
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
    use crate::{Heartbeat, Identifier, ResourceLimits, Validate};

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
        // Later versions may add outcome and refusal codes: they parse.
        let later = fixture("valid-health-unknown-values.json")
            .unwrap()
            .health
            .unwrap();
        let processes = Identifier::new("processes").unwrap();
        assert_eq!(
            later.last_scan.unwrap().collectors[&processes],
            super::CollectorOutcome::Other
        );
        assert_eq!(
            later.rule_sets[0].refused,
            Some(super::BundleRefusal::Other)
        );
        for invalid in [
            "invalid-health-negative-count.json",
            "invalid-health-outcome-with-space.json",
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
