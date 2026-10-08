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
    /// Process-event alarms (P14); absent when the agent does not watch
    /// process starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alarms: Option<AlarmHealth>,
}

/// Most alarms the agent keeps pending (P14).
pub const ALARM_QUEUE_MAX: u64 = 1_000;
/// Most `process_event` rules one count may report (P14).
pub const HEALTH_MAX_EVENT_RULES: u64 = 32_768;

/// Process-event alarms (P14), sent in `Heartbeat.health.alarms`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlarmHealth {
    /// The process-events collector's outcome.
    pub collector: CollectorOutcome,
    /// Process starts lost before evaluation, since the agent started.
    pub events_dropped_total: u64,
    /// Alarms dropped by the full queue or refused by the platform, kept
    /// across restarts.
    pub alarms_dropped_total: u64,
    /// Alarms awaiting delivery.
    pub pending: u64,
    /// The platform answered 404 on `/v1/alarms`.
    pub platform_unsupported: bool,
    /// `process_event` rules in use.
    pub rules_accepted: u64,
    /// `process_event` rules that did not compile.
    pub rules_refused: u64,
    /// Rules in use with no program prefilter (evaluated on every start).
    pub rules_without_prefilter: u64,
    /// Process starts whose evaluation stopped at the per-start budget
    /// across all `process_event` rules ([`EVENT_OPERATIONS`]), since the
    /// agent started. Optional on the wire (absent before board #105).
    #[serde(default)]
    pub events_budget_cut_total: u64,
    /// What feeds the alarms; absent from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<AlarmSource>,
    /// Why the agent is not on eBPF; absent when it is, or from older agents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<AlarmFallback>,
}

/// What feeds the process-event alarms.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlarmSource {
    /// The eBPF process watcher.
    Ebpf,
    /// The kernel audit fallback.
    Audit,
    /// Nothing is feeding alarms.
    None,
}

/// Why the eBPF watcher could not be used.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackDetail {
    /// The kernel has no BTF.
    NoBtf,
    /// The agent lacks the needed capability.
    Capability,
    /// Kernel lockdown forbids loading.
    Lockdown,
    /// A security module denied the load.
    LsmDenied,
    /// The verifier rejected the program.
    Verifier,
    /// Any other reason.
    Other,
}

/// The fallback from eBPF, sent in `health.alarms.fallback`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlarmFallback {
    /// Why eBPF was not used.
    pub detail: FallbackDetail,
    /// The audit rule is loaded.
    pub audit_rule_loaded: bool,
}

/// CEL operations one process start may use across all `process_event`
/// rules of every rule set (contract, P14): one rule's own limit, so many
/// rules can't multiply the work of one exec.
pub const EVENT_OPERATIONS: u64 = 50_000;

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
        if let Some(alarms) = &self.alarms {
            alarms.validate()?;
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

impl AlarmHealth {
    fn validate(&self) -> Result<(), ValidationError> {
        let max_total = i64::MAX.unsigned_abs();
        if self.events_dropped_total > max_total
            || self.alarms_dropped_total > max_total
            || self.events_budget_cut_total > max_total
        {
            return Err(ValidationError::new("health.alarms", "total out of range"));
        }
        if self.pending > ALARM_QUEUE_MAX {
            return Err(ValidationError::new(
                "health.alarms.pending",
                "more than 1000",
            ));
        }
        if [
            self.rules_accepted,
            self.rules_refused,
            self.rules_without_prefilter,
        ]
        .iter()
        .any(|count| *count > HEALTH_MAX_EVENT_RULES)
        {
            return Err(ValidationError::new(
                "health.alarms",
                "rule count over 32768",
            ));
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
            "invalid-alarms-health-negative-dropped.json",
            "invalid-alarms-source-unknown.json",
        ] {
            assert!(fixture(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn alarm_health_bounds() {
        let mut health = fixture("valid-alarms-health.json").unwrap().health.unwrap();
        assert_eq!(health.alarms.as_ref().unwrap().alarms_dropped_total, 3);
        health.alarms.as_mut().unwrap().pending = 1_001;
        assert!(health.validate(ResourceLimits::V1).is_err());
        health.alarms.as_mut().unwrap().pending = 0;
        health.alarms.as_mut().unwrap().rules_refused = 32_769;
        assert!(health.validate(ResourceLimits::V1).is_err());
        health.alarms.as_mut().unwrap().rules_refused = 0;
        health.alarms.as_mut().unwrap().events_dropped_total = u64::MAX;
        assert!(health.validate(ResourceLimits::V1).is_err());
        health.alarms.as_mut().unwrap().events_dropped_total = 0;
        health.alarms.as_mut().unwrap().events_budget_cut_total = u64::MAX;
        assert!(health.validate(ResourceLimits::V1).is_err());
    }

    #[test]
    fn alarm_health_round_trips_source_and_fallback() {
        use super::{AlarmFallback, AlarmHealth, AlarmSource, FallbackDetail};
        let json = r#"{"collector":"ok","events_dropped_total":0,"alarms_dropped_total":0,"pending":0,
            "platform_unsupported":false,"rules_accepted":5,"rules_refused":0,"rules_without_prefilter":0,
            "source":"audit","fallback":{"detail":"no_btf","audit_rule_loaded":true}}"#;
        let health: AlarmHealth = serde_json::from_str(json).unwrap();
        assert_eq!(health.source, Some(AlarmSource::Audit));
        assert_eq!(
            health.fallback,
            Some(AlarmFallback {
                detail: FallbackDetail::NoBtf,
                audit_rule_loaded: true
            })
        );
        let back: serde_json::Value = serde_json::to_value(&health).unwrap();
        assert_eq!(back["source"], "audit");
    }

    #[test]
    fn alarm_health_without_source_still_parses_and_omits_it() {
        use super::AlarmHealth;
        let json = r#"{"collector":"ok","events_dropped_total":0,"alarms_dropped_total":0,"pending":0,
            "platform_unsupported":false,"rules_accepted":0,"rules_refused":0,"rules_without_prefilter":0}"#;
        let health: AlarmHealth = serde_json::from_str(json).unwrap();
        assert_eq!(health.source, None);
        assert!(
            serde_json::to_value(&health)
                .unwrap()
                .get("source")
                .is_none()
        );
    }

    #[test]
    fn alarm_source_fixtures_parse() {
        use super::AlarmSource;
        let ebpf = fixture("valid-alarms-source-ebpf.json").unwrap();
        assert_eq!(
            ebpf.health.unwrap().alarms.unwrap().source,
            Some(AlarmSource::Ebpf)
        );
        let fallback = fixture("valid-alarms-fallback.json").unwrap();
        assert!(fallback.health.unwrap().alarms.unwrap().fallback.is_some());
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
