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
    try_signed_rules(&[expression], programs)
}

/// One alarm rule per expression, `rule.0`, `rule.1`, … in order.
fn try_signed_rules(
    expressions: &[&str],
    programs: Option<&[&str]>,
) -> Result<VerifiedRuleSet, openvibes_rules::LoadError> {
    try_sign_rule_set(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: expressions
            .iter()
            .enumerate()
            .map(|(n, expression)| Rule {
                id: id(&format!("rule.{n}")),
                version: 1,
                title: "Synthetic alarm rule".into(),
                severity: Severity::High,
                confidence: Confidence::new(80).unwrap(),
                expression: (*expression).to_owned(),
                finding_message: "Synthetic process started".into(),
                kind: RuleKind::ProcessEvent,
                programs: programs.map(|p| p.iter().map(|s| (*s).to_owned()).collect()),
            })
            .collect(),
    })
}

/// `rules`, signed with the test key as rule set `synthetic-alarms`.
fn try_sign_rule_set(rules: &RuleSet) -> Result<VerifiedRuleSet, openvibes_rules::LoadError> {
    let payload = serde_json::to_string(rules).unwrap();
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
fn a_basename_program_also_matches_the_basename_of_exe() {
    // A 15-byte comm as `process.name` must not hide a rule naming the
    // full program (2a review).
    let bundle = signed("true", Some(&["systemd-journald"]));
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    let mut event = ProcessEvent::default();
    event
        .set(
            "process.exe",
            EventValue::String("/usr/lib/systemd/systemd-journald".into()),
        )
        .unwrap();
    event
        .set("process.name", EventValue::String("systemd-journal".into()))
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

/// Board #105: one budget per start across all rules. Two heavy rules
/// (eleven `contains` over the 256 KiB command line, about 4,096
/// operations each, so each rule within its own limit) spend it on a
/// maximal event: the cheap rule after them never runs and the start is
/// cut. On a normal event everything runs. `evaluate` alone never cuts.
#[test]
fn rules_share_one_budget_per_start() {
    let heavy = (0..11)
        .map(|n| format!("event['process.cmdline'].contains('zz{n}')"))
        .collect::<Vec<_>>()
        .join(" || ");
    let bundle = try_signed_rules(&[&heavy, &heavy, "true"], None).unwrap();
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    assert_eq!(
        compiled.rules(),
        3,
        "each heavy rule is within its own limit"
    );

    let mut budget = openvibes_core::EVENT_OPERATIONS;
    let (out, cut) = compiled.evaluate_within(&bundle, &maximal_event(), &clock(), &mut budget);
    assert!(cut, "two heavy rules spend one start's budget");
    assert!(out.len() < 3 && out.iter().all(|o| o.rule_id.as_str() != "rule.2"));
    assert!(
        out.iter().all(|o| o.failure.is_none()),
        "a cut is not a failure"
    );
    // A charge that would overrun is refused whole, so less than one more
    // `contains` over the command line is left.
    assert!(budget < 4_096, "{budget}");

    let mut small = ProcessEvent::default();
    small
        .set("process.exe", EventValue::String("/usr/bin/sh".into()))
        .unwrap();
    let mut budget = openvibes_core::EVENT_OPERATIONS;
    let (out, cut) = compiled.evaluate_within(&bundle, &small, &clock(), &mut budget);
    assert!(!cut);
    assert_eq!(out.len(), 3);
    assert!(out[2].matched, "the cheap rule runs and matches");
    assert!(budget > 0);

    assert_eq!(
        compiled.evaluate(&bundle, &maximal_event(), &clock()).len(),
        3
    );
}

/// Board #105: `baseline-alarms` is unrestricted, so it keeps per-rule
/// limits and is never cut by the per-start budget. What bounds it is its
/// own size, capped here (and by the rules repository's checker) at 150,000
/// operations in the worst case, every value at its contract bound. The
/// real rules (fixture copied from openvibes-rules `alarms/rules.json` at
/// a7252f58) are at 136,068 today: a new baseline rule that grows this
/// fails here, rather than quietly making every exec dearer.
#[test]
fn the_baseline_alarm_rules_stay_under_their_worst_case_cap() {
    let rules: RuleSet =
        serde_json::from_str(include_str!("fixtures/baseline-alarms-rules.json")).unwrap();
    let bundle = try_sign_rule_set(&rules).unwrap();
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    assert_eq!(
        compiled.rules(),
        rules.rules.len(),
        "every baseline rule compiles"
    );
    let total = compiled.worst_case_total();
    assert!(
        total <= 150_000,
        "baseline-alarms worst case {total} > 150,000"
    );
    assert!(
        total > 100_000,
        "the fixture is the real rule set ({total})"
    );
}

#[test]
fn alarm_trace_withholds_original_command_line_and_preserves_true_condition() {
    use openvibes_core::Validate;
    let bundle = signed("event['process.cmdline'].contains('curl')", None);
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    let mut event = ProcessEvent::default();
    event
        .set(
            "process.cmdline",
            EventValue::String("curl --password do-not-leak-this".into()),
        )
        .unwrap();
    let outcomes = compiled.evaluate(&bundle, &event, &clock());
    assert!(outcomes[0].matched);
    let detail = outcomes[0].detection.as_ref().unwrap();
    detail.validate(ResourceLimits::V1).unwrap();
    assert_eq!(
        detail.inputs[0].status,
        openvibes_core::DetectionStatus::Masked
    );
    assert!(detail.steps.iter().any(|step| step.result));
    assert!(
        !serde_json::to_string(detail)
            .unwrap()
            .contains("do-not-leak-this")
    );
}
