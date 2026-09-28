//! The `event` binding, subset v2 and compiled `process_event` rules
//! against the protocol's vectors, plus the worst-case guarantee.

use std::{cell::Cell, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleKind, RuleSet,
    SchemaVersion, Severity, SignedRuleEnvelope,
};
use openvibes_rules::{
    EVENT_KEYS, EvaluationClock, EventType, EventValue, LoadContext, ProcessEvent, RuleLoader,
    TrustedRuleKey, VerifiedRuleSet, compile_event_rules, signing_preimage,
};
use sha2::{Digest, Sha256};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

struct Clock(Cell<u64>);
impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        Duration::from_millis(self.0.get())
    }
    fn unix_ms(&self) -> i64 {
        2_000
    }
}
fn clock() -> Clock {
    Clock(Cell::new(0))
}

fn signed(expression: &str, programs: Option<&[&str]>) -> VerifiedRuleSet {
    try_signed(expression, programs).unwrap()
}

fn try_signed(
    expression: &str,
    programs: Option<&[&str]>,
) -> Result<VerifiedRuleSet, openvibes_rules::LoadError> {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("rule.0"),
            version: 1,
            title: "Synthetic alarm rule".into(),
            severity: Severity::High,
            confidence: Confidence::new(80).unwrap(),
            expression: expression.to_owned(),
            finding_message: "Synthetic process started".into(),
            kind: RuleKind::ProcessEvent,
            programs: programs.map(|p| p.iter().map(|s| (*s).to_owned()).collect()),
        }],
    })
    .unwrap();
    // Test-only seed. No signing credentials are provisioned to the scanner.
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("synthetic-alarms"),
        rule_set_version: 1,
        issuer_key_id: id("test.key"),
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 3_000,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload_encoding: PayloadEncoding::Json,
        payload,
        signature_base64url: String::new(),
    };
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(
        key.sign(&signing_preimage(&envelope, ResourceLimits::V1).unwrap())
            .to_bytes(),
    );
    let loader = RuleLoader::new(
        vec![
            TrustedRuleKey::new(
                id("synthetic-alarms"),
                id("test.key"),
                key.verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
        ResourceLimits::V1,
    )
    .unwrap();
    loader.load_json(
        &serde_json::to_vec(&envelope).unwrap(),
        LoadContext {
            expected_rule_set_id: &id("synthetic-alarms"),
            now_unix_ms: 2_000,
            last_accepted: None,
        },
    )
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    kind: String,
    expression: String,
    bindings: serde_json::Map<String, serde_json::Value>,
    expect: String,
}

fn vectors() -> Vec<Vector> {
    serde_json::from_str(include_str!("../../../protocol/vectors/cel-subset-v2.json")).unwrap()
}

fn event_from(bindings: &serde_json::Map<String, serde_json::Value>) -> ProcessEvent {
    let mut event = ProcessEvent::default();
    for (key, value) in bindings {
        let value = match value {
            serde_json::Value::String(s) => EventValue::String(s.clone()),
            serde_json::Value::Bool(b) => EventValue::Boolean(*b),
            serde_json::Value::Number(n) => EventValue::Integer(n.as_i64().unwrap()),
            serde_json::Value::Array(a) => {
                EventValue::Strings(a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
            }
            other => panic!("unexpected binding {other}"),
        };
        event.set(key, value).unwrap();
    }
    event
}

#[test]
fn process_event_vectors_from_the_protocol() {
    let mut checked = 0;
    for v in vectors().iter().filter(|v| v.kind == "process_event") {
        if v.expect == "refused" {
            // The loader refuses it (so no signing tool can produce it).
            assert_eq!(
                try_signed(&v.expression, None).err(),
                Some(openvibes_rules::LoadError::InvalidRules),
                "{}",
                v.name
            );
        } else {
            let bundle = signed(&v.expression, None);
            let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
            assert!(
                compiled.refused.is_empty(),
                "{}: {:?}",
                v.name,
                compiled.refused
            );
            let out = compiled.evaluate(&bundle, &event_from(&v.bindings), &clock());
            let got = if out[0].unavailable {
                "unavailable"
            } else if out[0].matched {
                "true"
            } else {
                "false"
            };
            assert_eq!(got, v.expect, "{}: {:?}", v.name, out[0].failure);
        }
        checked += 1;
    }
    assert!(checked >= 25, "{checked}");
}

fn maximal_event() -> ProcessEvent {
    let mut event = ProcessEvent::default();
    for (key, ty, bound) in EVENT_KEYS {
        let value = match ty {
            EventType::String => EventValue::String("a".repeat(*bound)),
            EventType::Integer => EventValue::Integer(i64::MAX),
            EventType::Boolean => EventValue::Boolean(true),
            EventType::Strings => EventValue::Strings(
                (b'a'..b'f')
                    .map(|c| (c as char).to_string().repeat(*bound))
                    .collect(),
            ),
        };
        event.set(key, value).unwrap();
    }
    event
}

#[test]
fn an_accepted_rule_never_exceeds_its_budget_on_maximal_values() {
    for v in vectors()
        .iter()
        .filter(|v| v.kind == "process_event" && v.expect != "refused")
    {
        let bundle = signed(&v.expression, None);
        let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
        let out = compiled.evaluate(&bundle, &maximal_event(), &clock());
        assert!(out[0].failure.is_none(), "{}: {:?}", v.name, out[0].failure);
    }
}

#[test]
fn programs_filter_skips_evaluation() {
    let bundle = signed("true", Some(&["sh"]));
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    let mut event = ProcessEvent::default();
    event
        .set("process.exe", EventValue::String("/usr/bin/bash".into()))
        .unwrap();
    event
        .set("process.name", EventValue::String("bash".into()))
        .unwrap();
    assert!(compiled.evaluate(&bundle, &event, &clock()).is_empty());
    event
        .set("process.name", EventValue::String("sh".into()))
        .unwrap();
    assert_eq!(compiled.evaluate(&bundle, &event, &clock()).len(), 1);
}

#[test]
fn event_values_outside_the_contract_are_refused() {
    let mut event = ProcessEvent::default();
    assert!(
        event
            .set("process.nmae", EventValue::String("x".into()))
            .is_err()
    );
    assert!(
        event
            .set("process.uid", EventValue::String("0".into()))
            .is_err()
    );
    let unsorted = EventValue::Strings(vec!["b".into(), "a".into()]);
    assert!(event.set("ancestors.names", unsorted).is_err());
    let six = EventValue::Strings(["a", "b", "c", "d", "e", "f"].map(String::from).to_vec());
    assert!(event.set("ancestors.names", six).is_err());
    let long = EventValue::String("a".repeat(262_145));
    assert!(event.set("process.cmdline", long).is_err());
}
