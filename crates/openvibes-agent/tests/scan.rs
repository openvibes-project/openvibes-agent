//! Scan loop: locally provisioned signed rules, evaluated against the real
//! processes collector, queue findings; refused bundles never replace the last
//! accepted one.

use std::{
    fs,
    path::{Path, PathBuf},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_agent::{AgentError, Service, load_config};
use openvibes_core::{
    Confidence, Identifier, PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion,
    Severity, SignedRuleEnvelope,
};
use openvibes_rules::{LoadError, signing_preimage};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000_000;
const HOUR: i64 = 3_600_000;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

// Test-only seed. No signing credentials are provisioned to the scanner.
fn organization_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

/// A signed `baseline` bundle holding one rule with `expression`.
fn bundle(version: u64, expression: &str, key: &SigningKey) -> Vec<u8> {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("host.has.processes"),
            version: 1,
            title: "Processes are running".into(),
            severity: Severity::Info,
            confidence: Confidence::new(100).unwrap(),
            expression: expression.into(),
            finding_message: "The host runs processes".into(),
        }],
    })
    .unwrap();
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("baseline"),
        rule_set_version: version,
        issuer_key_id: id("org.rules"),
        created_at_unix_ms: NOW - HOUR,
        expires_at_unix_ms: NOW + 100 * HOUR,
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
    serde_json::to_vec(&envelope).unwrap()
}

/// Fresh local-only config with one `baseline` rule set trusting `key`.
fn scratch(test: &str, extra: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-scan")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    let config = dir.join("agent.toml");
    fs::write(
        &config,
        format!(
            "state_dir = {:?}\n{extra}\n[[rule_sets]]\nid = \"baseline\"\nbundle_file = {:?}\n\
             trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]\n",
            dir.join("state"),
            dir.join("baseline.json"),
        ),
    )
    .unwrap();
    (dir, config)
}

fn open(config: &Path) -> Service {
    Service::open(load_config(config).unwrap()).unwrap()
}

#[test]
fn scans_on_start_then_once_per_interval() {
    let (dir, config) = scratch("interval", "");
    let key = organization_key();
    fs::write(
        dir.join("baseline.json"),
        bundle(1, "facts['process.count'] >= 1", &key),
    )
    .unwrap();
    let mut service = open(&config);

    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(report.queued, 1);
    assert!(report.rule_set_errors.is_empty());
    assert!(!report.partial_collection);
    assert_eq!(service.scan_if_due(NOW + HOUR - 1).unwrap(), None);

    // Each scan is a new observation with its own finding.
    assert_eq!(service.scan_if_due(NOW + HOUR).unwrap().unwrap().queued, 1);
    assert_eq!(service.queue().len().unwrap(), 2);
    assert_eq!(service.export(&dir, NOW + HOUR).unwrap(), 2);
}

#[test]
fn a_non_matching_rule_queues_nothing() {
    let (dir, config) = scratch("no-match", "");
    let key = organization_key();
    fs::write(
        dir.join("baseline.json"),
        bundle(1, "facts['process.count'] < 1", &key),
    )
    .unwrap();
    let report = open(&config).scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(report.queued, 0);
    assert_eq!(report.failed_rules, 0);
}

#[test]
fn refused_bundles_never_replace_the_accepted_one() {
    let (dir, config) = scratch("refused", "");
    let key = organization_key();
    let file = dir.join("baseline.json");
    fs::write(&file, bundle(2, "facts['process.count'] >= 1", &key)).unwrap();
    assert_eq!(open(&config).scan_if_due(NOW).unwrap().unwrap().queued, 1);

    let attacker = SigningKey::from_bytes(&[8; 32]);
    let refused = [
        (
            bundle(3, "facts['process.count'] < 1", &attacker),
            LoadError::InvalidSignature,
        ),
        (
            bundle(1, "facts['process.count'] < 1", &key),
            LoadError::Rollback,
        ),
        (
            bundle(2, "facts['process.count'] < 1", &key),
            LoadError::VersionConflict,
        ),
    ];
    for (step, (bytes, expected)) in refused.into_iter().enumerate() {
        fs::write(&file, bytes).unwrap();
        // A restart each time: the floor and bundle come back from state.
        let report = open(&config)
            .scan_if_due(NOW + 1 + step as i64)
            .unwrap()
            .unwrap();
        assert_eq!(
            report.rule_set_errors,
            [(id("baseline"), AgentError::Rules(expected))]
        );
        assert_eq!(report.queued, 1, "the accepted v2 rule still ran");
    }

    fs::remove_file(&file).unwrap();
    let report = open(&config).scan_if_due(NOW + 10).unwrap().unwrap();
    assert_eq!(
        report.rule_set_errors,
        [(id("baseline"), AgentError::Config)]
    );
    assert_eq!(report.queued, 1);
}

#[test]
fn without_any_accepted_bundle_nothing_is_evaluated() {
    let (_, config) = scratch("missing", "");
    let report = open(&config).scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(
        report.rule_set_errors,
        [(id("baseline"), AgentError::Config)]
    );
    assert_eq!(report.queued, 0);
}

#[test]
fn no_rule_sets_means_no_scan() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("agent-scan-none");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let config = dir.join("agent.toml");
    fs::write(&config, format!("state_dir = {:?}\n", dir.join("state"))).unwrap();
    assert_eq!(open(&config).scan_if_due(NOW).unwrap(), None);
}

#[test]
fn invalid_scan_settings_are_refused() {
    for extra in [
        "scan_interval_seconds = 59",
        "scan_interval_seconds = 86401",
    ] {
        let (_, config) = scratch("bad-interval", extra);
        assert_eq!(
            load_config(&config).err(),
            Some(AgentError::Config),
            "{extra}"
        );
    }
    let (dir, config) = scratch("bad-keys", "");
    let text = fs::read_to_string(&config).unwrap();
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    let bad = [
        text.replace(&public, "not base64!"),
        text.replace(&public, &URL_SAFE_NO_PAD.encode([1u8; 31])),
        text.replace(&public, &URL_SAFE_NO_PAD.encode([0u8; 32])), // weak key
        text.replace(
            &format!("[{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]"),
            "[]",
        ),
        text.replace("bundle_file = ", "bundle_file = \"relative.json\"\n# "),
        format!("{text}{}", &text[text.find("[[rule_sets]]").unwrap()..]), // duplicate id
    ];
    for (index, variant) in bad.iter().enumerate() {
        let path = dir.join(format!("bad-{index}.toml"));
        fs::write(&path, variant).unwrap();
        assert_eq!(
            load_config(&path).err(),
            Some(AgentError::Config),
            "variant {index}"
        );
    }
}
