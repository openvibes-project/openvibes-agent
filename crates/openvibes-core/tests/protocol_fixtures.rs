//! The contract types agree with the shared protocol fixtures: every
//! `valid*` example parses and validates, every `invalid*` example is refused.
//! Fixtures come from the `protocol/` submodule, pinned to the protocol
//! version this agent implements.

use std::{fs, path::Path};

use openvibes_core::{
    DeliveryAcknowledgement, EnrollmentRequest, EnrollmentResponse, Finding, FindingBatch,
    FindingChanges, FindingExport, Heartbeat, InventoryChanges, InventoryExport, InventoryReport,
    PlatformError, RenewalRequest, ResourceLimits, RuleBundleRequest, RuleSet, SignedRuleEnvelope,
    Validate,
};
use serde::de::DeserializeOwned;

/// P13 fixtures (protocol #25) that the P13 agent PR implements. The pin
/// includes them because P14 merged after P13; whichever of the two agent
/// PRs merges second deletes this list.
const P13_FIXTURES: [&str; 4] = [
    "heartbeat/invalid-health-negative-matches-truncated.json",
    "heartbeat/invalid-match-sha256-uppercase.json",
    "heartbeat/valid-match-sha256.json",
    "platform-error/valid-findings-resync.json",
];

fn accepts<T: DeserializeOwned + Validate>(bytes: &[u8]) -> bool {
    serde_json::from_slice::<T>(bytes).is_ok_and(|value| value.validate(ResourceLimits::V1).is_ok())
}

#[test]
fn contract_types_agree_with_every_protocol_fixture() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/fixtures/v1");
    let messages = fs::read_dir(&root)
        .unwrap_or_else(|_| panic!("protocol fixtures missing; run `git submodule update --init`"));
    let mut checked = 0;
    for message in messages {
        let message = message.unwrap().path();
        let name = message.file_name().unwrap().to_str().unwrap().to_owned();
        let accepts: fn(&[u8]) -> bool = match name.as_str() {
            "enrollment-request" => accepts::<EnrollmentRequest>,
            "enrollment-response" => accepts::<EnrollmentResponse>,
            "renewal-request" => accepts::<RenewalRequest>,
            "heartbeat" => accepts::<Heartbeat>,
            "finding" => accepts::<Finding>,
            "finding-batch" => accepts::<FindingBatch>,
            "finding-export" => accepts::<FindingExport>,
            "inventory-export" => accepts::<InventoryExport>,
            "inventory-changes" => accepts::<InventoryChanges>,
            "finding-changes" => accepts::<FindingChanges>,
            "delivery-acknowledgement" => accepts::<DeliveryAcknowledgement>,
            "platform-error" => accepts::<PlatformError>,
            "signed-rule-envelope" => accepts::<SignedRuleEnvelope>,
            "rule-set" => accepts::<RuleSet>,
            "rule-bundle-request" => accepts::<RuleBundleRequest>,
            "inventory-report" => accepts::<InventoryReport>,
            // P13 (openvibes-agent, ponytail's PR) maps this; whichever of
            // the two PRs merges second replaces the skip.
            "finding-changes" => continue,
            // Mapped in Task 2 of the P14 plan.
            "alarm-batch" => continue,
            // A message this agent does not implement yet must be added here.
            other => panic!("no contract type mapped for protocol message `{other}`"),
        };
        for fixture in fs::read_dir(&message).unwrap() {
            let fixture = fixture.unwrap().path();
            let file = fixture.file_name().unwrap().to_str().unwrap();
            if P13_FIXTURES.contains(&format!("{name}/{file}").as_str()) {
                continue;
            }
            let expected = file.starts_with("valid");
            assert_eq!(
                accepts(&fs::read(&fixture).unwrap()),
                expected,
                "{name}/{file}"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no protocol fixtures found");
}
