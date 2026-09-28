//! Finding changes (protocol P13): an agent reports when a rule match
//! starts, changes and ends, checked against the match digest.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    Finding, Identifier, ResourceLimits, SchemaVersion, Validate, ValidationError,
    contracts::{validate_unix_ms, validate_version},
    export::validate_sha256,
};

/// `started`, `changed` and `ended` together, per document.
pub const MAX_CHANGE_ENTRIES: usize = 500;
/// Transient matches per document.
pub const MAX_TRANSIENT: usize = 100;
/// Current matches an agent keeps.
pub const MAX_MATCHES: usize = 500;

/// An acknowledged match a later scan ended.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndedMatch {
    /// Rule set of the match.
    pub rule_set_id: Identifier,
    /// Rule of the match.
    pub rule_id: Identifier,
    /// When the scan that ended it ran.
    pub ended_at_unix_ms: i64,
}

/// A match that started and ended between two acknowledgements.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TransientMatch {
    /// The finding as it started.
    pub finding: Finding,
    /// When the scan that ended it ran.
    pub ended_at_unix_ms: i64,
}

/// `POST /v1/findings/changes` (P13).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FindingChanges {
    /// Wire schema version.
    pub schema_version: SchemaVersion,
    /// The sending agent.
    pub agent_id: Identifier,
    /// Digest of the acknowledged set (ignored with `replace`).
    pub base_sha256: String,
    /// Digest of the set after the changes.
    pub sha256: String,
    /// `started` holds the whole set; `changed` and `ended` are empty.
    pub replace: bool,
    /// When the scan behind these changes ran.
    pub scanned_at_unix_ms: i64,
    /// Matches the platform has not seen.
    pub started: Vec<Finding>,
    /// Acknowledged matches whose material fields differ.
    pub changed: Vec<Finding>,
    /// Acknowledged matches that ended.
    pub ended: Vec<EndedMatch>,
    /// Matches that started and ended since the last acknowledgement.
    pub transient: Vec<TransientMatch>,
    /// Transient matches not kept.
    pub transient_dropped: u64,
}

/// The contract's match: `[rule_set_id, rule_id, rule_version, severity,
/// message, evidence]`, evidence deduplicated and sorted.
fn match_row(finding: &Finding) -> String {
    let mut evidence: Vec<&str> = finding.evidence.iter().map(Identifier::as_str).collect();
    evidence.sort_unstable();
    evidence.dedup();
    let set = finding.rule_set_id.as_ref().map_or("", Identifier::as_str);
    // Strings, integers and a unit enum always serialize.
    serde_json::to_string(&(
        set,
        finding.rule_id.as_str(),
        finding.rule_version,
        finding.severity,
        &finding.message,
        evidence,
    ))
    .unwrap_or_default()
}

/// Whether two findings for the same rule differ in what the platform
/// stores (rule version, severity, message, evidence as a set).
#[must_use]
pub fn materially_differs(a: &Finding, b: &Finding) -> bool {
    match_row(a) != match_row(b)
}

/// SHA-256 of the compact JSON array of all matches, deduplicated and
/// sorted by their JSON text (contracts-v1, "Match digest (P13)").
#[must_use]
pub fn match_digest(findings: &[Finding]) -> [u8; 32] {
    let mut rows: Vec<String> = findings.iter().map(match_row).collect();
    rows.sort_unstable();
    rows.dedup();
    Sha256::digest(format!("[{}]", rows.join(",")).as_bytes()).into()
}

fn with_rule_set(finding: &Finding, limits: ResourceLimits) -> Result<&str, ValidationError> {
    let Some(set) = &finding.rule_set_id else {
        return Err(ValidationError::new(
            "rule_set_id",
            "required in finding changes",
        ));
    };
    finding.validate(limits)?;
    Ok(set.as_str())
}

impl Validate for FindingChanges {
    fn validate(&self, limits: ResourceLimits) -> Result<(), ValidationError> {
        validate_version(self.schema_version)?;
        validate_sha256("base_sha256", &self.base_sha256)?;
        validate_sha256("sha256", &self.sha256)?;
        validate_unix_ms("scanned_at_unix_ms", self.scanned_at_unix_ms)?;
        if self.started.len() + self.changed.len() + self.ended.len() > MAX_CHANGE_ENTRIES {
            return Err(ValidationError::new("started", "too many change entries"));
        }
        if self.transient.len() > MAX_TRANSIENT {
            return Err(ValidationError::new(
                "transient",
                "too many transient matches",
            ));
        }
        if self.replace && !(self.changed.is_empty() && self.ended.is_empty()) {
            return Err(ValidationError::new(
                "replace",
                "changed and ended must be empty",
            ));
        }
        let mut keys = BTreeSet::new();
        for finding in self.started.iter().chain(&self.changed) {
            let set = with_rule_set(finding, limits)?;
            if !keys.insert((set, finding.rule_id.as_str())) {
                return Err(ValidationError::new("started", "a rule is listed twice"));
            }
        }
        for ended in &self.ended {
            validate_unix_ms("ended_at_unix_ms", ended.ended_at_unix_ms)?;
            if !keys.insert((ended.rule_set_id.as_str(), ended.rule_id.as_str())) {
                return Err(ValidationError::new("ended", "a rule is listed twice"));
            }
        }
        for transient in &self.transient {
            with_rule_set(&transient.finding, limits)?;
            validate_unix_ms("ended_at_unix_ms", transient.ended_at_unix_ms)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Severity};

    #[derive(serde::Deserialize)]
    struct Vector {
        name: String,
        matches: Vec<VectorMatch>,
        sha256: String,
    }
    #[derive(serde::Deserialize)]
    struct VectorMatch {
        rule_set_id: Identifier,
        rule_id: Identifier,
        rule_version: u64,
        severity: Severity,
        message: String,
        evidence: Vec<Identifier>,
    }

    fn finding(m: VectorMatch) -> Finding {
        Finding {
            schema_version: SchemaVersion::V1,
            finding_id: Identifier::new("finding.v").unwrap(),
            scan_id: Identifier::new("scan.v").unwrap(),
            rule_set_id: Some(m.rule_set_id),
            rule_id: m.rule_id,
            rule_version: m.rule_version,
            observed_at_unix_ms: 1_790_000_000_000,
            severity: m.severity,
            confidence: Confidence::new(100).unwrap(),
            message: m.message,
            evidence: m.evidence,
        }
    }

    #[test]
    fn the_digest_matches_the_protocol_vectors() {
        let text = include_str!("../../../protocol/vectors/match-digest.json");
        let vectors: Vec<Vector> = serde_json::from_str(text).unwrap();
        assert_eq!(vectors.len(), 4);
        for vector in vectors {
            let findings: Vec<Finding> = vector.matches.into_iter().map(finding).collect();
            assert_eq!(
                crate::hex(&match_digest(&findings)),
                vector.sha256,
                "{}",
                vector.name
            );
        }
    }
}
