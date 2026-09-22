use std::{cell::Cell, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ovsvms_core::{
    CollectorError, CollectorErrorCode, Confidence, FactSet, FactValue, Identifier,
    PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
    Validate,
};
use ovsvms_rules::{
    EvaluationClock, EvaluationError as Error, EvaluationReport, Evaluator, LoadContext,
    RuleLoader, RuleOutcome, TrustedRuleKey, VerifiedRuleSet, signing_preimage,
};
use sha2::{Digest, Sha256};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

// Deterministic synthetic collector: never reads the host or alters host state.
fn collect() -> FactSet {
    serde_json::from_str(include_str!("fixtures/process-facts-v1.json")).unwrap()
}

struct Clock {
    millis: Cell<u64>,
    step: u64,
    unix: Cell<i64>,
}
impl Clock {
    fn fixed() -> Self {
        Self {
            millis: Cell::new(0),
            step: 0,
            unix: Cell::new(2_000),
        }
    }
}
impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        let current = self.millis.get();
        self.millis.set(current + self.step);
        Duration::from_millis(current)
    }
    fn unix_ms(&self) -> i64 {
        self.unix.get()
    }
}

fn signed(expressions: &[&str]) -> VerifiedRuleSet {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: expressions
            .iter()
            .enumerate()
            .map(|(i, expression)| Rule {
                id: id(&format!("rule.{i}")),
                version: 1,
                title: "Synthetic test rule".into(),
                severity: Severity::Medium,
                confidence: Confidence::new(100).unwrap(),
                expression: expression.to_string(),
                finding_message: "Synthetic condition detected".into(),
            })
            .collect(),
    })
    .unwrap();
    // Test-only seed. No signing credentials are provisioned to the scanner.
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("synthetic"),
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
                id("synthetic"),
                id("test.key"),
                key.verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
        ResourceLimits::V1,
    )
    .unwrap();
    loader
        .load_json(
            &serde_json::to_vec(&envelope).unwrap(),
            LoadContext {
                expected_rule_set_id: &id("synthetic"),
                now_unix_ms: 2_000,
                last_accepted: None,
            },
        )
        .unwrap()
}

fn evaluate(expressions: &[&str], facts: &FactSet, limits: ResourceLimits) -> EvaluationReport {
    Evaluator::new(limits)
        .unwrap()
        .evaluate(&signed(expressions), facts, &id("agent.1"), &Clock::fixed())
        .unwrap()
}

fn failure(expression: &str, expected: Error) {
    let report = evaluate(&[expression], &collect(), ResourceLimits::V1);
    assert!(
        matches!(report.results[0].outcome, RuleOutcome::Failed(error) if error == expected),
        "{expression}: {:?}",
        report.results[0]
    );
}

#[test]
fn verified_rule_and_synthetic_facts_produce_a_valid_finding() {
    let report = evaluate(
        &["'sshd' in facts['process.names']"],
        &collect(),
        ResourceLimits::V1,
    );
    assert!(!report.partial_collection);
    assert_eq!(report.scan_id, id("scan.synthetic.1"));
    let RuleOutcome::Match(finding) = &report.results[0].outcome else {
        panic!("expected match")
    };
    finding.validate(ResourceLimits::V1).unwrap();
    assert_eq!(finding.evidence, vec![id("process.names")]);
    assert_eq!(finding.rule_id, id("rule.0"));
    assert_eq!(finding.observed_at_unix_ms, 1_500);
    assert!(report.results[0].operations > 0);
}

#[test]
fn nonmatch_missing_data_and_type_errors_are_distinct() {
    let report = evaluate(
        &[
            "'apache' in facts['process.names']",
            "facts['missing'] == true",
            "facts['system.count'] == 'seven'",
        ],
        &collect(),
        ResourceLimits::V1,
    );
    assert!(matches!(report.results[0].outcome, RuleOutcome::NoMatch));
    assert!(matches!(
        report.results[1].outcome,
        RuleOutcome::Unavailable
    ));
    assert!(matches!(
        report.results[2].outcome,
        RuleOutcome::Failed(Error::TypeMismatch)
    ));
}

#[test]
fn partial_collector_data_is_not_treated_as_compliance() {
    let mut facts = collect();
    facts.errors.push(CollectorError {
        collector: id("processes"),
        code: CollectorErrorCode::PermissionDenied,
        message: "incomplete read".into(),
        retryable: true,
    });
    let report = evaluate(
        &[
            "'sshd' in facts['process.names']",
            "facts['service.enabled']",
        ],
        &facts,
        ResourceLimits::V1,
    );
    assert!(report.partial_collection);
    assert!(matches!(
        report.results[0].outcome,
        RuleOutcome::Unavailable
    ));
    assert!(matches!(report.results[1].outcome, RuleOutcome::Match(_)));
}

#[test]
fn all_required_facts_and_types_are_checked_even_in_short_circuit_branches() {
    for expression in ["true || facts['missing']", "false && facts['missing']"] {
        assert!(matches!(
            evaluate(&[expression], &collect(), ResourceLimits::V1).results[0].outcome,
            RuleOutcome::Unavailable
        ));
    }
    failure("true || 7", Error::TypeMismatch);
    failure("false && 7", Error::TypeMismatch);
}

#[test]
fn findings_have_stable_ids_scoped_to_agent_scan_and_signed_rule_content() {
    let verified = signed(&["true"]);
    let engine = Evaluator::new(ResourceLimits::V1).unwrap();
    let finding_id = |bundle: &VerifiedRuleSet, facts: &FactSet, agent: &str| {
        let report = engine
            .evaluate(bundle, facts, &id(agent), &Clock::fixed())
            .unwrap();
        let RuleOutcome::Match(finding) = &report.results[0].outcome else {
            panic!("expected match")
        };
        finding.finding_id.clone()
    };
    let first = finding_id(&verified, &collect(), "agent.1");
    assert_eq!(first, finding_id(&verified, &collect(), "agent.1"));
    assert_ne!(first, finding_id(&verified, &collect(), "agent.2"));
    let mut other_scan = collect();
    other_scan.scan_id = id("scan.2");
    assert_ne!(first, finding_id(&verified, &other_scan, "agent.1"));
    assert_ne!(
        first,
        finding_id(&signed(&["!false"]), &collect(), "agent.1")
    );
}

#[test]
fn evidence_is_sorted_and_deduplicated() {
    let report = evaluate(
        &["facts['service.enabled'] && facts['os.name'] == 'linux' && facts['service.enabled']"],
        &collect(),
        ResourceLimits::V1,
    );
    let RuleOutcome::Match(finding) = &report.results[0].outcome else {
        panic!("expected match")
    };
    assert_eq!(finding.evidence, vec![id("os.name"), id("service.enabled")]);
}

#[test]
fn unsupported_language_features_and_non_boolean_results_fail_explicitly() {
    for expression in [
        "facts['os.name'].matches('.*')",
        "size(facts['process.names']) > 0",
        "facts['process.names'].exists(p, p == 'sshd')",
        "1 + 2 == 3",
        "[1] == [1]",
        "{'a': 1} == {'a': 1}",
        "env('SECRET')",
        "facts[facts['os.name']] == 'linux'",
        "true ? true : false",
        "r'raw' == 'raw'",
        "1u == 1u",
        "1.5 == 1.5",
    ] {
        failure(expression, Error::UnsupportedExpression);
    }
    failure("facts['os.name']", Error::NonBoolean);
    failure("1", Error::NonBoolean);
    failure("true &&", Error::InvalidExpression);
}

#[test]
fn allowed_typed_expressions_agree_with_upstream_cel_results() {
    // Differential checks cover valid, fully typed expressions in the subset.
    let expressions = [
        "true",
        "false",
        "!true",
        "!!false",
        "-2 < 0",
        "1 <= 1",
        "2 > 1",
        "2 >= 2",
        "1 != 2",
        "'a' < 'b'",
        "'é' == '\\u00e9'",
        "'a\\'b' == \"a'b\"",
        "true && false || true",
        "true || false && false",
        "(true || false) && false",
        "'sshd' in facts['process.names']",
        "facts['system.count'] == 7",
        "facts['os.name'] == 'linux'",
        "!facts['service.enabled']",
    ];
    let mut context = cel::Context::default();
    let mut bindings = std::collections::HashMap::new();
    bindings.insert(
        "process.names".to_string(),
        cel::Value::from(vec!["init", "sshd"]),
    );
    bindings.insert("system.count".to_string(), cel::Value::Int(7));
    bindings.insert("os.name".to_string(), cel::Value::from("linux"));
    bindings.insert("service.enabled".to_string(), cel::Value::Bool(true));
    context.add_variable_from_value("facts", bindings);
    for expression in expressions {
        let reference = cel::Program::compile(expression)
            .unwrap()
            .execute(&context)
            .unwrap();
        let report = evaluate(&[expression], &collect(), ResourceLimits::V1);
        let actual = match report.results[0].outcome {
            RuleOutcome::Match(_) => true,
            RuleOutcome::NoMatch => false,
            _ => panic!("{expression}: {:?}", report.results[0]),
        };
        assert_eq!(reference, cel::Value::Bool(actual), "{expression}");
    }
}

#[test]
fn operation_limit_charges_list_comparisons_and_is_per_rule() {
    let mut facts = collect();
    facts.facts[0].value = FactValue::StringList(vec!["a".repeat(256); 100]);
    let report = evaluate(
        &["'absent' in facts['process.names']", "true"],
        &facts,
        ResourceLimits {
            evaluation_operations: 1_000,
            ..ResourceLimits::V1
        },
    );
    assert!(matches!(
        report.results[0].outcome,
        RuleOutcome::Failed(Error::OperationLimit)
    ));
    assert!(matches!(report.results[1].outcome, RuleOutcome::Match(_)));
}

#[test]
fn exact_operation_budget_succeeds_and_one_less_fails() {
    let expression = "facts['system.count'] >= 7";
    let baseline = evaluate(&[expression], &collect(), ResourceLimits::V1).results[0].operations;
    let exact = evaluate(
        &[expression],
        &collect(),
        ResourceLimits {
            evaluation_operations: baseline,
            ..ResourceLimits::V1
        },
    );
    assert!(matches!(exact.results[0].outcome, RuleOutcome::Match(_)));
    let below = evaluate(
        &[expression],
        &collect(),
        ResourceLimits {
            evaluation_operations: baseline - 1,
            ..ResourceLimits::V1
        },
    );
    assert!(matches!(
        below.results[0].outcome,
        RuleOutcome::Failed(Error::OperationLimit)
    ));
}

#[test]
fn deadline_and_expiration_are_enforced_with_deterministic_clocks() {
    let verified = signed(&["true"]);
    let engine = Evaluator::new(ResourceLimits::V1).unwrap();
    let clock = Clock {
        step: 100,
        ..Clock::fixed()
    };
    let report = engine
        .evaluate(&verified, &collect(), &id("agent.1"), &clock)
        .unwrap();
    assert!(matches!(
        report.results[0].outcome,
        RuleOutcome::Failed(Error::DeadlineExceeded)
    ));
    let clock = Clock::fixed();
    clock.unix.set(3_000);
    assert_eq!(
        engine
            .evaluate(&verified, &collect(), &id("agent.1"), &clock)
            .unwrap_err(),
        Error::BundleNotValid
    );
    clock.unix.set(999);
    assert_eq!(
        engine
            .evaluate(&verified, &collect(), &id("agent.1"), &clock)
            .unwrap_err(),
        Error::BundleNotValid
    );
    clock.unix.set(-1);
    assert_eq!(
        engine
            .evaluate(&verified, &collect(), &id("agent.1"), &clock)
            .unwrap_err(),
        Error::InvalidClock
    );
}

#[test]
fn depth_tokens_evidence_and_memory_are_bounded() {
    let nested = format!("{}true{}", "(".repeat(33), ")".repeat(33));
    failure(&nested, Error::DepthLimit);
    let long = vec!["true"; 100].join(" && ");
    failure(&long, Error::ExpressionLimit);
    let report = evaluate(
        &["facts['service.enabled'] && facts['os.name'] == 'linux'"],
        &collect(),
        ResourceLimits {
            evidence_per_finding: 1,
            ..ResourceLimits::V1
        },
    );
    assert!(matches!(
        report.results[0].outcome,
        RuleOutcome::Failed(Error::EvidenceLimit)
    ));
    let engine = Evaluator::new(ResourceLimits {
        fact_input_bytes: 10,
        ..ResourceLimits::V1
    })
    .unwrap();
    assert_eq!(
        engine
            .evaluate(
                &signed(&["true"]),
                &collect(),
                &id("agent.1"),
                &Clock::fixed()
            )
            .unwrap_err(),
        Error::FactBudgetExceeded
    );
}

#[test]
fn malformed_or_ambiguous_fact_snapshots_are_rejected() {
    let engine = Evaluator::new(ResourceLimits::V1).unwrap();
    let verified = signed(&["true"]);
    let mut facts = collect();
    facts.facts.push(facts.facts[0].clone());
    assert_eq!(
        engine
            .evaluate(&verified, &facts, &id("agent.1"), &Clock::fixed())
            .unwrap_err(),
        Error::InvalidFacts
    );
    facts = collect();
    facts.collected_at_unix_ms = 2_001;
    assert_eq!(
        engine
            .evaluate(&verified, &facts, &id("agent.1"), &Clock::fixed())
            .unwrap_err(),
        Error::InvalidFacts
    );
}

#[test]
fn limits_cannot_disable_or_enlarge_guards() {
    for limits in [
        ResourceLimits {
            evaluation_operations: 0,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            evaluation_milliseconds: 101,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            expression_nodes: usize::MAX,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            fact_input_bytes: 0,
            ..ResourceLimits::V1
        },
    ] {
        assert!(matches!(Evaluator::new(limits), Err(Error::InvalidLimits)));
    }
}
