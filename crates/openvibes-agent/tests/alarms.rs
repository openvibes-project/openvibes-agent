//! The alarm thread end to end (P14): recorded audit records in, one
//! collapsed alarm out to the mock platform; a platform before P14; no
//! audit permission.
#![cfg(target_os = "linux")]

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_agent::alarms::{
    compile,
    thread::{AlarmShared, Shared, spawn, spawn_with},
};
use openvibes_collectors::process_events::{Received, Seeded, Source, open_audit_socket};
use openvibes_core::{
    AlarmBatch, CollectorOutcome, Confidence, EnrollmentResponse, EnrollmentToken, Identifier,
    PayloadEncoding, ResourceLimits, Rule, RuleKind, RuleSet, SchemaVersion, Severity,
    SignedRuleEnvelope,
};
use openvibes_rules::{LoadContext, RuleLoader, TrustedRuleKey, signing_preimage};
use openvibes_storage::prepare_state_dir;
use openvibes_testkit::{Pki, Seen, json, serve, status};
use openvibes_transport::{
    ClientIdentity, DEFAULT_PLATFORM_PORT, HostKey, PlatformClient, TransportConfig,
};
use sha2::{Digest, Sha256};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn config(base_url: &str, pki: &Pki) -> TransportConfig {
    TransportConfig {
        base_url: base_url.to_owned(),
        default_port: DEFAULT_PLATFORM_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    }
}

fn state_dir(test: &str) -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("agent-alarms");
    fs::create_dir_all(&parent).unwrap();
    let dir = parent.join(test);
    let _ = fs::remove_dir_all(&dir);
    prepare_state_dir(&dir).unwrap();
    dir
}

fn enrolled_identity(pki: &Arc<Pki>) -> ClientIdentity {
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

/// The shipped example rule: a shell started by a web server.
fn shared(identity: ClientIdentity) -> Shared {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("shell-from-web"),
            version: 1,
            title: "Shell from a web server".into(),
            severity: Severity::High,
            confidence: Confidence::new(80).unwrap(),
            expression: "event['parent.name'] == 'nginx' && event['process.name'] == 'sh'".into(),
            finding_message: "A web server started a shell".into(),
            kind: RuleKind::ProcessEvent,
            programs: Some(vec!["sh".into()]),
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
    let (rules, accepted, _, _) = compile(vec![bundle]);
    assert_eq!(accepted, 1);
    let shared = Arc::new(Mutex::new(AlarmShared::default()));
    let mut guard = shared.lock().unwrap();
    guard.rules = rules;
    guard.identity = Some((id("agent.1"), identity));
    drop(guard);
    shared
}

fn message(kind: u16, serial: u64, text: &str) -> Vec<u8> {
    let body = format!("audit(1790000000.{:03}:{serial}): {text}", serial % 1000);
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(body.as_bytes());
    out
}

/// One exec event's records.
fn exec(serial: u64, pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Vec<Vec<u8>> {
    let args: String = argv
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            let hex: String = arg.bytes().map(|b| format!("{b:02X}")).collect();
            format!(" a{i}={hex}")
        })
        .collect();
    vec![
        message(
            1300,
            serial,
            &format!(
                "arch=c000003e syscall=59 success=yes exit=0 ppid={ppid} pid={pid} uid=33 \
                 euid=33 exe=\"{exe}\" key=\"openvibes-exec\""
            ),
        ),
        message(1309, serial, &format!("argc={}{args}", argv.len())),
        message(1320, serial, ""),
    ]
}

/// Recorded messages, then silence (as a quiet host).
struct Recorded(std::vec::IntoIter<Vec<u8>>);

impl Source for Recorded {
    fn recv(&mut self, buf: &mut [u8]) -> Received {
        match self.0.next() {
            Some(message) => {
                buf[..message.len()].copy_from_slice(&message);
                Received::Message(message.len())
            }
            None => {
                std::thread::sleep(Duration::from_millis(50));
                Received::Idle
            }
        }
    }
}

/// nginx exec'd, then `sh -c id` three times under it.
fn web_shells() -> Recorded {
    let mut messages = exec(1, 100, 1, "/usr/sbin/nginx", &["nginx"]);
    for n in 0..3 {
        messages.extend(exec(
            2 + n,
            200 + n as u32,
            100,
            "/usr/bin/sh",
            &["sh", "-c", "id"],
        ));
    }
    Recorded(messages.into_iter())
}

fn no_proc(_: u32) -> Option<Seeded> {
    None
}

#[test]
fn three_web_shells_arrive_as_one_alarm_with_count_three() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(202))],
    );
    let shared = shared(identity);
    let dir = state_dir("three");
    spawn_with(web_shells(), no_proc, config(&url, &pki), &shared, &dir).unwrap();
    let sent = seen.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(sent.path, "/v1/alarms");
    assert!(sent.client_cert);
    let batch: AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
    assert_eq!(batch.agent_id, id("agent.1"));
    assert_eq!(batch.alarms.len(), 1);
    let alarm = &batch.alarms[0];
    assert_eq!(alarm.count, 3);
    assert_eq!(alarm.process.args, ["sh", "-c", "id"]);
    assert_eq!(alarm.ancestors[0].exe, "/usr/sbin/nginx");
    assert!(alarm.alarm_id.as_str().starts_with("alarm."));
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(shared.lock().unwrap().health.pending, 0);
}

#[test]
fn a_platform_before_p14_keeps_the_alarm_and_says_so() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(404))],
    );
    let shared = shared(identity);
    let dir = state_dir("unsupported");
    spawn_with(web_shells(), no_proc, config(&url, &pki), &shared, &dir).unwrap();
    seen.recv_timeout(Duration::from_secs(10)).unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    let health = shared.lock().unwrap().health.clone();
    assert!(health.platform_unsupported);
    assert_eq!(health.pending, 1);
    assert_eq!(health.collector, CollectorOutcome::Ok);
}

#[test]
fn without_audit_permission_the_agent_runs_on_and_says_so() {
    let Err(error) = open_audit_socket() else {
        // Running with CAP_AUDIT_READ (as root): nothing to check here.
        return;
    };
    let pki = Pki::new();
    let shared: Shared = Arc::default();
    let dir = state_dir("denied");
    assert!(spawn(config("https://127.0.0.1:1", &pki), &shared, &dir).is_none());
    let outcome: CollectorOutcome = error.code.into();
    assert_eq!(shared.lock().unwrap().health.collector, outcome);
    assert_eq!(outcome, CollectorOutcome::PermissionDenied);
}
