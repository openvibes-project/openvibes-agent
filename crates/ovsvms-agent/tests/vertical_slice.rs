//! Milestone 2 exit criterion: only an authenticated rule can turn a collected
//! fact into a finding that reaches the platform.

use std::{convert::Infallible, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use ovsvms_core::{
    Confidence, DeliveryAcknowledgement, FactSet, Finding, Identifier, PayloadEncoding,
    ResourceLimits, Rule, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
};
use ovsvms_rules::{
    EvaluationClock, Evaluator, LoadContext, LoadError, RuleLoader, RuleOutcome, TrustedRuleKey,
    signing_preimage,
};
use ovsvms_storage::MemoryQueue;
use sha2::{Digest, Sha256};

const NOW: i64 = 2_000;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

// Deterministic synthetic collector: never reads the host or alters host state.
fn collect() -> FactSet {
    serde_json::from_str(include_str!(
        "../../ovsvms-rules/tests/fixtures/process-facts-v1.json"
    ))
    .unwrap()
}

struct FixedClock;
impl EvaluationClock for FixedClock {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
    fn unix_ms(&self) -> i64 {
        NOW
    }
}

/// Records every batch and acknowledges all of it, as an idempotent platform would.
#[derive(Default)]
struct MockPlatform {
    received: Vec<Finding>,
}
impl MockPlatform {
    fn send(&mut self, batch: &[Finding]) -> Result<DeliveryAcknowledgement, Infallible> {
        self.received.extend_from_slice(batch);
        Ok(DeliveryAcknowledgement {
            schema_version: SchemaVersion::V1,
            accepted_finding_ids: batch.iter().map(|f| f.finding_id.clone()).collect(),
            acknowledged_at_unix_ms: NOW,
        })
    }
}

fn envelope(expression: &str, key: &SigningKey) -> SignedRuleEnvelope {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("process.ssh.running"),
            version: 1,
            title: "SSH server is running".into(),
            severity: Severity::Medium,
            confidence: Confidence::new(100).unwrap(),
            expression: expression.into(),
            finding_message: "An SSH server process was observed".into(),
        }],
    })
    .unwrap();
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("baseline"),
        rule_set_version: 1,
        issuer_key_id: id("org.rules"),
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 3_000,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    envelope
}

/// The agent pipeline: verify rules, evaluate facts, queue matches, deliver.
fn run(
    envelope: &SignedRuleEnvelope,
    trusted: &SigningKey,
    platform: &mut MockPlatform,
) -> Result<usize, LoadError> {
    let loader = RuleLoader::new(
        vec![
            TrustedRuleKey::new(
                id("baseline"),
                id("org.rules"),
                trusted.verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
        ResourceLimits::V1,
    )
    .unwrap();
    let verified = loader.load_json(
        &serde_json::to_vec(envelope).unwrap(),
        LoadContext {
            expected_rule_set_id: &id("baseline"),
            now_unix_ms: NOW,
            last_accepted: None,
        },
    )?;
    let report = Evaluator::new(ResourceLimits::V1)
        .unwrap()
        .evaluate(&verified, &collect(), &id("agent.1"), &FixedClock)
        .unwrap();
    let mut queue = MemoryQueue::new(ResourceLimits::V1, 16).unwrap();
    for result in report.results {
        if let RuleOutcome::Match(finding) = result.outcome {
            queue.enqueue(*finding).unwrap();
        }
    }
    let delivered = queue.deliver(|batch| platform.send(batch)).unwrap();
    assert!(queue.is_empty());
    Ok(delivered)
}

// Test-only seeds. No signing credentials are provisioned to the scanner.
fn organization_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

#[test]
fn authenticated_rule_turns_a_collected_fact_into_a_delivered_finding() {
    let key = organization_key();
    let mut platform = MockPlatform::default();

    let delivered = run(
        &envelope("'sshd' in facts['process.names']", &key),
        &key,
        &mut platform,
    );

    assert_eq!(delivered, Ok(1));
    let [finding] = platform.received.as_slice() else {
        panic!("expected exactly one delivered finding");
    };
    assert_eq!(finding.rule_id, id("process.ssh.running"));
    assert_eq!(finding.scan_id, id("scan.synthetic.1"));
    assert_eq!(finding.evidence, [id("process.names")]);
}

#[test]
fn unauthenticated_rules_never_reach_the_platform() {
    let key = organization_key();
    let attacker = SigningKey::from_bytes(&[8; 32]);

    // Self-consistent forgery: valid digest, trusted issuer ID, attacker's key.
    let forged = envelope("'sshd' in facts['process.names']", &attacker);
    let mut tampered = envelope("'absent' in facts['process.names']", &key);
    let replacement = envelope("'sshd' in facts['process.names']", &key);
    tampered.payload = replacement.payload;
    let mut tampered_with_digest = tampered.clone();
    tampered_with_digest.payload_sha256_hex = replacement.payload_sha256_hex;

    for (envelope, expected) in [
        (forged, LoadError::InvalidSignature),
        (tampered, LoadError::DigestMismatch),
        (tampered_with_digest, LoadError::InvalidSignature),
    ] {
        let mut platform = MockPlatform::default();
        assert_eq!(run(&envelope, &key, &mut platform), Err(expected));
        assert!(platform.received.is_empty());
    }
}

#[test]
fn authenticated_non_matching_rule_delivers_nothing() {
    let key = organization_key();
    let mut platform = MockPlatform::default();

    let delivered = run(
        &envelope("'absent' in facts['process.names']", &key),
        &key,
        &mut platform,
    );

    assert_eq!(delivered, Ok(0));
    assert!(platform.received.is_empty());
}
