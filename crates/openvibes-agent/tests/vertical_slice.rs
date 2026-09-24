//! Milestone 2 exit criterion: only an authenticated rule can turn a collected
//! fact into a finding that reaches the platform.

use std::{
    convert::Infallible,
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Confidence, DeliveryAcknowledgement, FactSet, Finding, Identifier, PayloadEncoding,
    ResourceLimits, Rule, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
};
use openvibes_rules::{
    AcceptedVersion, EvaluationClock, Evaluator, LoadContext, LoadError, RuleLoader, RuleOutcome,
    TrustedRuleKey, signing_preimage,
};
use openvibes_storage::{RuleStore, SqliteQueue, StorageError, StoredRuleBundle};
use sha2::{Digest, Sha256};

const NOW: i64 = 2_000;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

// Deterministic synthetic collector: never reads the host or alters host state.
fn collect() -> FactSet {
    serde_json::from_str(include_str!(
        "../../openvibes-rules/tests/fixtures/process-facts-v1.json"
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
            rejected_findings: Vec::new(),
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

fn loader(trusted: &SigningKey) -> RuleLoader {
    RuleLoader::new(
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
    .unwrap()
}

/// Fresh state file; unique per call because tests run in parallel.
fn state_path() -> PathBuf {
    static RUNS: AtomicUsize = AtomicUsize::new(0);
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "vertical-slice-{}.sqlite",
        RUNS.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// The agent pipeline: verify rules, evaluate facts, queue matches, deliver.
fn run(
    envelope: &SignedRuleEnvelope,
    trusted: &SigningKey,
    platform: &mut MockPlatform,
) -> Result<usize, LoadError> {
    let verified = loader(trusted).load_json(
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
    let mut queue = SqliteQueue::open(&state_path(), ResourceLimits::V1).unwrap();
    for result in report.results {
        if let RuleOutcome::Match(finding) = result.outcome {
            queue.enqueue(&finding, NOW).unwrap();
        }
    }
    let delivered = queue.deliver(NOW, |batch| platform.send(batch)).unwrap();
    assert_eq!(queue.is_empty(), Ok(true));
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

/// Restart path: restore the persisted floor, re-verify the cached bundle, and
/// refuse different content under the same version.
#[test]
fn accepted_bundle_is_restored_and_its_floor_enforced_after_restart() {
    let key = organization_key();
    let set = id("baseline");
    let accepted = serde_json::to_vec(&envelope("'sshd' in facts['process.names']", &key)).unwrap();
    let context = |last_accepted| LoadContext {
        expected_rule_set_id: &set,
        now_unix_ms: NOW,
        last_accepted,
    };
    let state = state_path();

    let verified = loader(&key).load_json(&accepted, context(None)).unwrap();
    let version = verified.accepted_version();
    RuleStore::open(&state, ResourceLimits::V1)
        .unwrap()
        .accept(
            &set,
            &StoredRuleBundle {
                version: version.version(),
                preimage_sha256: *version.preimage_sha256(),
                envelope: accepted,
            },
        )
        .unwrap();

    // Restart: the floor is restored before any bundle is loaded.
    let mut store = RuleStore::open(&state, ResourceLimits::V1).unwrap();
    let stored = store.get(&set).unwrap().unwrap();
    let floor =
        AcceptedVersion::restore(set.clone(), stored.version, stored.preimage_sha256).unwrap();
    let cached = loader(&key).load_json(&stored.envelope, context(Some(&floor)));
    assert_eq!(cached.unwrap().accepted_version(), &floor);

    // Validly signed, same version, different content: the loader and the
    // store each refuse it.
    let replay = envelope("'absent' in facts['process.names']", &key);
    let replay = serde_json::to_vec(&replay).unwrap();
    assert_eq!(
        loader(&key).load_json(&replay, context(Some(&floor))).err(),
        Some(LoadError::VersionConflict)
    );
    let unchecked = loader(&key).load_json(&replay, context(None)).unwrap();
    let conflicting = StoredRuleBundle {
        version: unchecked.accepted_version().version(),
        preimage_sha256: *unchecked.accepted_version().preimage_sha256(),
        envelope: replay,
    };
    assert_eq!(
        store.accept(&set, &conflicting),
        Err(StorageError::VersionConflict)
    );
}
