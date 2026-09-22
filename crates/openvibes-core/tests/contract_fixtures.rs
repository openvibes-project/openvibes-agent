use openvibes_core::{ResourceLimits, RuleSet, Validate, validate_document_size};

const JSON_RULE_SET: &str = include_str!("fixtures/rule-set-v1.json");
const YAML_RULE_SET: &str = include_str!("fixtures/rule-set-v1.yaml");

#[test]
fn json_rule_set_round_trips() {
    validate_document_size(JSON_RULE_SET.as_bytes(), ResourceLimits::V1)
        .expect("fixture is within document limit");
    let decoded: RuleSet = serde_json::from_str(JSON_RULE_SET).expect("valid JSON fixture");
    decoded
        .validate(ResourceLimits::V1)
        .expect("valid rule contract");

    let encoded = serde_json::to_string(&decoded).expect("serializable rule contract");
    let round_trip: RuleSet = serde_json::from_str(&encoded).expect("round-trip JSON");

    assert_eq!(round_trip, decoded);
}

#[test]
fn yaml_rule_set_round_trips_to_the_same_contract() {
    validate_document_size(YAML_RULE_SET.as_bytes(), ResourceLimits::V1)
        .expect("fixture is within document limit");
    let from_yaml: RuleSet = serde_saphyr::from_str(YAML_RULE_SET).expect("valid YAML fixture");
    let from_json: RuleSet = serde_json::from_str(JSON_RULE_SET).expect("valid JSON fixture");
    from_yaml
        .validate(ResourceLimits::V1)
        .expect("valid rule contract");

    let encoded = serde_saphyr::to_string(&from_yaml).expect("serializable rule contract");
    let round_trip: RuleSet = serde_saphyr::from_str(&encoded).expect("round-trip YAML");

    assert_eq!(from_yaml, from_json);
    assert_eq!(round_trip, from_yaml);
}

#[test]
fn incompatible_schema_version_is_rejected_after_decode() {
    let document = JSON_RULE_SET.replace("\"schema_version\": 1", "\"schema_version\": 2");
    let decoded: RuleSet = serde_json::from_str(&document).expect("structurally valid JSON");

    assert_eq!(
        decoded
            .validate(ResourceLimits::V1)
            .expect_err("unsupported version must fail")
            .field(),
        "schema_version"
    );
}

#[test]
fn oversized_document_is_rejected_before_decode() {
    let document = vec![b' '; ResourceLimits::V1.document_bytes + 1];

    assert!(validate_document_size(&document, ResourceLimits::V1).is_err());
}

#[test]
fn additional_fields_are_ignored_within_a_known_schema_version() {
    let document = JSON_RULE_SET.replace(
        "\"schema_version\": 1,",
        "\"schema_version\": 1, \"future_optional_field\": true,",
    );
    let decoded: RuleSet = serde_json::from_str(&document).expect("forward-compatible JSON");

    decoded
        .validate(ResourceLimits::V1)
        .expect("known schema remains valid");
}
