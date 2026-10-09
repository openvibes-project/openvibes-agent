//! Shared by the alarm tests (P14): the mock platform identity and a
//! signed `process_event` rule.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_agent::alarms::{
    compile,
    thread::{AlarmShared, Shared},
};
use openvibes_core::{
    Confidence, EnrollmentResponse, EnrollmentToken, Identifier, PayloadEncoding, ResourceLimits,
    Rule, RuleKind, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use openvibes_testkit::{Pki, Seen, json, serve};
use openvibes_transport::{
    ClientIdentity, DEFAULT_PLATFORM_PORT, HostKey, PlatformClient, TransportConfig,
};
use sha2::{Digest, Sha256};

pub fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

pub fn config(base_url: &str, pki: &Pki) -> TransportConfig {
    TransportConfig {
        base_url: base_url.to_owned(),
        default_port: DEFAULT_PLATFORM_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    }
}

pub fn enrolled_identity(pki: &Arc<Pki>) -> ClientIdentity {
    let issuer = pki.clone();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(move |seen: &Seen| {
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec![
                    issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                ],
                expires_at_unix_ms: 4_000_000_000_000,
            })
        })],
    );
    let key = HostKey::generate().unwrap();
    let response = PlatformClient::new(&config(&url, pki), None)
        .unwrap()
        .enroll(&EnrollmentToken::new("one-time").unwrap(), &key)
        .unwrap();
    ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem()).unwrap()
}

/// State for the alarm thread: one signed `process_event` rule
/// (no `programs` prefilter) and an enrolled identity.
pub fn shared(identity: ClientIdentity, expression: &str) -> Shared {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("shell-from-web"),
            version: 1,
            title: "Shell from a web server".into(),
            severity: Severity::High,
            confidence: Confidence::new(80).unwrap(),
            expression: expression.into(),
            finding_message: "A web server started a shell".into(),
            kind: RuleKind::ProcessEvent,
            programs: None,
            attack: None,
        }],
    })
    .unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("baseline-alarms"),
        rule_set_version: 1,
        issuer_key_id: id("test.key"),
        created_at_unix_ms: 1_000,
        expires_at_unix_ms: 4_000_000_000_000,
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
                id("baseline-alarms"),
                id("test.key"),
                key.verifying_key().to_bytes(),
            )
            .unwrap(),
        ],
        ResourceLimits::V1,
    )
    .unwrap();
    let bundle = loader
        .load_json(
            &serde_json::to_vec(&envelope).unwrap(),
            LoadContext {
                expected_rule_set_id: &id("baseline-alarms"),
                now_unix_ms: 2_000,
                last_accepted: None,
            },
        )
        .unwrap();
    let (rules, accepted, _, _) = compile(vec![bundle], |id| id.as_str() != "baseline-alarms");
    assert_eq!(accepted, 1);
    let shared = Arc::new(Mutex::new(AlarmShared::default()));
    let mut guard = shared.lock().unwrap();
    guard.rules = rules;
    guard.identity = Some((id("agent.1"), identity));
    drop(guard);
    shared
}
