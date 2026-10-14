//! The project's own rule sets (rule-set assignment spec, 2026-10-14 §3;
//! protocol P20): compiled in with their public key, so a host gets them
//! with no `agent.toml` line, and the platform decides per host which of
//! the assignable ones run.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use openvibes_core::{Identifier, ResourceLimits};
use openvibes_rules::TrustedRuleKey;
use openvibes_transport::TransportError;

use crate::{AgentError, RuleSetConfig, RuleSetSource, ScanConfig, config::BASELINE_ALARMS};

/// The project's offline rule key, as in the rules repository's `*.key`
/// files (`baseline/baseline.key`, `alarms/alarms.key`,
/// `hardening/linux-l1/hardening-linux-l1.key`). A rotation ships in an
/// agent release, which is how rule keys reach hosts out of band.
const ISSUER: &str = "openvibes-1";
const PUBLIC_KEY: &str = "pKYklRzoYShX_heLdRF9-2opdn36L-L1__T_ZdfvW3I";

/// Id, Linux only, assignable. Keep in step with
/// `protocol/vectors/project-rule-sets.json` (a test checks).
const SETS: [(&str, bool, bool); 4] = [
    ("baseline", false, false),
    ("baseline-alarms", true, false),
    ("hardening-linux-l1", true, true),
    ("hardening-linux-l2", true, true),
];

/// Adds every project set of this OS family (`linux`) that `scan` does not
/// name, fetched from the distribution service only. An entry with the
/// same id wins whole: its keys and `restricted`, never merged. Added sets
/// are restricted except `baseline-alarms`, as for configured ones.
pub(crate) fn add(scan: &mut ScanConfig, linux: bool) -> Result<(), AgentError> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(PUBLIC_KEY)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(AgentError::Config)?;
    for (id, linux_only, assignable) in SETS {
        if (linux_only && !linux) || scan.rule_sets.iter().any(|set| set.id.as_str() == id) {
            continue;
        }
        let id = Identifier::new(id).map_err(|_| AgentError::Config)?;
        let issuer = Identifier::new(ISSUER).map_err(|_| AgentError::Config)?;
        scan.trusted_keys
            .push(TrustedRuleKey::new(id.clone(), issuer, key).map_err(|_| AgentError::Config)?);
        scan.rule_sets.push(RuleSetConfig {
            restricted: id.as_str() != BASELINE_ALARMS,
            id,
            bundle_file: None,
            source: RuleSetSource::Project { assignable },
        });
    }
    // The configured list was bounded before these were added.
    if scan.rule_sets.len() > ResourceLimits::V1.list_items {
        return Err(AgentError::Config);
    }
    Ok(())
}

/// What a 404 or 410 from the distribution service means for one set (P20).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Withdrawn {
    /// 404 for an added set: not published here. Nothing runs and nothing
    /// is reported; asked again next scan.
    NotOffered,
    /// 410 for an assignable added set: not assigned to this host. The
    /// set stops, its stored bundle is withdrawn (floor kept), health says so.
    NotAssigned,
}

/// `None`: a refused answer, like any other 4xx. A platform can never
/// withdraw the baseline, the alarms, a site set or a configured entry.
pub(crate) fn withdrawn(source: RuleSetSource, error: TransportError) -> Option<Withdrawn> {
    match (source, error) {
        (RuleSetSource::Project { .. }, TransportError::NotFound) => Some(Withdrawn::NotOffered),
        (RuleSetSource::Project { assignable: true }, TransportError::NotAssigned) => {
            Some(Withdrawn::NotAssigned)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use openvibes_core::{Identifier, ResourceLimits};
    use openvibes_transport::TransportError;

    use super::{SETS, Withdrawn, add, withdrawn};
    use crate::{Collectors, RuleSetConfig, RuleSetSource, ScanConfig};

    const FIXED: RuleSetSource = RuleSetSource::Project { assignable: false };
    const SWITCHED: RuleSetSource = RuleSetSource::Project { assignable: true };

    fn empty() -> ScanConfig {
        ScanConfig {
            interval_ms: 3_600_000,
            rule_sets: Vec::new(),
            trusted_keys: Vec::new(),
            collectors: Collectors::default(),
        }
    }

    fn listed(scan: &ScanConfig) -> Vec<(&str, bool, RuleSetSource)> {
        scan.rule_sets
            .iter()
            .map(|set| (set.id.as_str(), set.restricted, set.source))
            .collect()
    }

    #[test]
    fn linux_gets_every_project_set() {
        let mut scan = empty();
        add(&mut scan, true).unwrap();
        assert_eq!(
            listed(&scan),
            [
                ("baseline", true, FIXED),
                ("baseline-alarms", false, FIXED),
                ("hardening-linux-l1", true, SWITCHED),
                ("hardening-linux-l2", true, SWITCHED),
            ]
        );
        assert_eq!(scan.trusted_keys.len(), 4);
    }

    #[test]
    fn other_systems_get_only_the_baseline() {
        let mut scan = empty();
        add(&mut scan, false).unwrap();
        assert_eq!(listed(&scan), [("baseline", true, FIXED)]);
    }

    #[test]
    fn a_configured_entry_wins_whole() {
        let mut scan = empty();
        scan.rule_sets.push(RuleSetConfig {
            id: Identifier::new("hardening-linux-l1").unwrap(),
            bundle_file: None,
            restricted: false,
            source: RuleSetSource::Configured,
        });
        add(&mut scan, true).unwrap();
        assert_eq!(
            listed(&scan)[0],
            ("hardening-linux-l1", false, RuleSetSource::Configured)
        );
        assert_eq!(
            listed(&scan)
                .iter()
                .filter(|(id, ..)| *id == "hardening-linux-l1")
                .count(),
            1
        );
        assert_eq!(
            scan.trusted_keys.len(),
            3,
            "no project key for the configured set"
        );
    }

    #[test]
    fn the_table_follows_the_protocol_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/project-rule-sets.json"
        ))
        .unwrap();
        let expected: Vec<(String, bool, bool)> = vector["sets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|set| {
                (
                    set["id"].as_str().unwrap().to_owned(),
                    set["os_family"] == "linux",
                    set["assignable"].as_bool().unwrap(),
                )
            })
            .collect();
        let table: Vec<(String, bool, bool)> = SETS
            .iter()
            .map(|&(id, linux, assignable)| (id.to_owned(), linux, assignable))
            .collect();
        assert_eq!(table, expected);
    }

    #[test]
    fn the_answers_follow_the_protocol_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/vectors/project-rule-sets.json"
        ))
        .unwrap();
        for case in vector["cases"].as_array().unwrap() {
            let id = case["rule_set_id"].as_str().unwrap();
            let source = if case["configured"].as_bool().unwrap() {
                RuleSetSource::Configured
            } else {
                let &(_, _, assignable) = SETS.iter().find(|(set, ..)| *set == id).unwrap();
                RuleSetSource::Project { assignable }
            };
            let error = match case["status"].as_u64().unwrap() {
                404 => TransportError::NotFound,
                410 => TransportError::NotAssigned,
                other => panic!("status {other}"),
            };
            let agent = match withdrawn(source, error) {
                None => "refused",
                Some(Withdrawn::NotOffered) => "not_offered",
                Some(Withdrawn::NotAssigned) => "not_assigned",
            };
            assert_eq!(agent, case["agent"].as_str().unwrap(), "{}", case["name"]);
        }
    }

    #[test]
    fn the_added_sets_stay_within_the_list_bound() {
        let mut scan = empty();
        for n in 0..ResourceLimits::V1.list_items {
            scan.rule_sets.push(RuleSetConfig {
                id: Identifier::new(format!("site.{n}")).unwrap(),
                bundle_file: None,
                restricted: true,
                source: RuleSetSource::Configured,
            });
        }
        assert!(add(&mut scan, true).is_err(), "a full list leaves no room");
    }
}
