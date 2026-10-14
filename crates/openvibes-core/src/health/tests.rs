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
fn a_set_in_use_sends_no_state() {
    let set = super::RuleSetHealth {
        id: Identifier::new("baseline").unwrap(),
        version: Some(1),
        expires_at_unix_ms: None,
        refused: None,
        state: None,
    };
    let json = serde_json::to_value(&set).unwrap();
    assert!(
        json.get("state").is_none(),
        "older platforms see the same document"
    );
    let unassigned = super::RuleSetHealth {
        version: None,
        state: Some(super::RuleSetState::NotAssigned),
        ..set
    };
    assert_eq!(
        serde_json::to_value(&unassigned).unwrap()["state"],
        "not_assigned"
    );
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
    assert_eq!(
        later.rule_sets[0].state,
        Some(super::RuleSetState::Other),
        "a later state value parses"
    );
    let unassigned = fixture("valid-health-not-assigned.json")
        .unwrap()
        .health
        .unwrap();
    assert_eq!(unassigned.rule_sets[0].state, None);
    assert_eq!(
        unassigned.rule_sets[1].state,
        Some(super::RuleSetState::NotAssigned)
    );
    for invalid in [
        "invalid-health-rule-set-state-with-space.json",
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
