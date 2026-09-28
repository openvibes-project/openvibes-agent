//! Finding changes (protocol P13) against a mock platform: matches are sent
//! as changes only when they change, a 409 brings a replace, a 404 brings
//! per-scan findings, and the acknowledged set survives a restart.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_agent::{Service, load_config};
use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, FindingChanges, Identifier,
    PayloadEncoding, ResourceLimits, Rule, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
};
use openvibes_rules::signing_preimage;
use openvibes_testkit::{Handler, Pki, Reply, Seen, json, serve, status};
use sha2::{Digest, Sha256};

const NOW: i64 = 1_800_000_000_000;
const HOUR: i64 = 3_600_000;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

/// A signed `baseline` bundle whose one rule always matches.
fn bundle(version: u64, rule_version: u64) -> Vec<u8> {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("host.has.processes"),
            version: rule_version,
            title: "Processes are running".into(),
            severity: Severity::Info,
            confidence: Confidence::new(100).unwrap(),
            expression: "facts['process.count'] >= 1".into(),
            finding_message: "The host runs processes".into(),
            kind: openvibes_core::RuleKind::Snapshot,
            programs: None,
        }],
    })
    .unwrap();
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id("baseline"),
        rule_set_version: version,
        issuer_key_id: id("org.rules"),
        created_at_unix_ms: NOW - HOUR,
        expires_at_unix_ms: NOW + 1_000 * HOUR,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key().sign(&preimage).to_bytes());
    serde_json::to_vec(&envelope).unwrap()
}

fn enroll(pki: &Arc<Pki>) -> Handler {
    let issuer = pki.clone();
    Box::new(move |seen: &Seen| {
        let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
        json(&EnrollmentResponse {
            schema_version: SchemaVersion::V1,
            agent_id: id("agent.1"),
            certificate_chain_pem: vec![issuer.issue_client(request["csr_pem"].as_str().unwrap())],
            expires_at_unix_ms: NOW + 1_000 * HOUR,
        })
    })
}

fn ok() -> Handler {
    Box::new(|_: &Seen| status(204))
}

fn code(status: u16, code: &'static str) -> Handler {
    Box::new(move |_: &Seen| Reply {
        status,
        ..json(&serde_json::json!({"schema_version": 1, "code": code}))
    })
}

fn acknowledge_all() -> Handler {
    Box::new(|seen: &Seen| {
        let batch: serde_json::Value = serde_json::from_slice(&seen.decoded_body()).unwrap();
        json(&DeliveryAcknowledgement {
            schema_version: SchemaVersion::V1,
            accepted_finding_ids: batch["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| id(f["finding_id"].as_str().unwrap()))
                .collect(),
            acknowledged_at_unix_ms: 2,
            rejected_findings: Vec::new(),
        })
    })
}

/// A state directory, CA, token and bundle for `test`; returns the config
/// path once the platform's URL is known.
fn setup(test: &str, pki: &Pki, url: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-finding-changes")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    write_config(&dir, pki, url);
    fs::write(dir.join("baseline.json"), bundle(1, 1)).unwrap();
    (dir.join("agent.toml"), dir)
}

fn write_config(dir: &Path, pki: &Pki, url: &str) {
    fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
    fs::write(dir.join("token"), "one-time\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(
        dir.join("token"),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    let public = URL_SAFE_NO_PAD.encode(key().verifying_key().to_bytes());
    fs::write(
        dir.join("agent.toml"),
        format!(
            "platform_url = {url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
             enrollment_token_file = {:?}\ncollectors = [\"processes\"]\n\
             [[rule_sets]]\nid = \"baseline\"\nbundle_file = {:?}\n\
             trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]\n",
            dir.join("ca.pem"),
            dir.join("state"),
            dir.join("token"),
            dir.join("baseline.json"),
        ),
    )
    .unwrap();
}

fn open(config: &Path) -> Service {
    Service::open(load_config(config).unwrap()).unwrap()
}

/// (path, decoded JSON body) of each request so far.
fn requests(seen: &mpsc::Receiver<Seen>) -> Vec<(String, serde_json::Value)> {
    seen.try_iter()
        .map(|seen| {
            let body = serde_json::from_slice(&seen.decoded_body()).unwrap_or_default();
            (seen.path, body)
        })
        .collect()
}

fn paths(requests: &[(String, serde_json::Value)]) -> Vec<&str> {
    requests.iter().map(|(path, _)| path.as_str()).collect()
}

fn changes_in(requests: &[(String, serde_json::Value)]) -> Vec<FindingChanges> {
    requests
        .iter()
        .filter(|(path, _)| path == "/v1/findings/changes")
        .map(|(_, body)| serde_json::from_value(body.clone()).unwrap())
        .collect()
}

#[test]
fn matches_are_sent_as_changes_and_only_when_they_change() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![enroll(&pki), ok(), ok(), ok(), ok(), ok()],
    );
    let (config, _) = setup("only_when_they_change", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    service.tick(NOW).unwrap();
    let first = requests(&seen);
    assert_eq!(
        paths(&first),
        ["/v1/enroll", "/v1/findings/changes", "/v1/heartbeat"]
    );
    let sent = &changes_in(&first)[0];
    assert!(sent.replace, "nothing acknowledged: a replace");
    assert_eq!(sent.started.len(), 1);
    assert_eq!(sent.started[0].rule_id.as_str(), "host.has.processes");
    assert_eq!(first[2].1["match_sha256"], sent.sha256.as_str());

    // The next scan finds the same match: only a heartbeat.
    service.scan_if_due(NOW + HOUR).unwrap();
    service.tick(NOW + HOUR).unwrap();
    let second = requests(&seen);
    assert_eq!(paths(&second), ["/v1/heartbeat"], "no per-scan findings");
    assert_eq!(second[0].1["match_sha256"], sent.sha256.as_str());
}

#[test]
fn a_platform_before_p13_gets_per_scan_findings() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            enroll(&pki),
            Box::new(|_: &Seen| status(404)),
            ok(),
            acknowledge_all(),
            ok(),
            acknowledge_all(),
        ],
    );
    let (config, _) = setup("before_p13", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    service.tick(NOW).unwrap();
    let first = requests(&seen);
    assert_eq!(
        paths(&first),
        [
            "/v1/enroll",
            "/v1/findings/changes",
            "/v1/heartbeat",
            "/v1/findings"
        ],
        "the current matches reach the queue in the same tick"
    );
    assert!(first[2].1.get("match_sha256").is_none());
    let report = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(report.queued, 1, "per scan again");
    service.tick(NOW + HOUR).unwrap();
    assert_eq!(paths(&requests(&seen)), ["/v1/heartbeat", "/v1/findings"]);
}

#[test]
fn a_409_on_a_diff_is_followed_by_a_replace_and_a_409_on_a_replace_backs_off() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            enroll(&pki),
            ok(),                         // replace
            ok(),                         // heartbeat
            code(409, "findings_resync"), // diff
            code(409, "findings_resync"), // replace
            ok(),                         // heartbeat
            ok(),                         // heartbeat (backing off)
            ok(),                         // replace after the backoff
            ok(),                         // heartbeat
        ],
    );
    let (config, dir) = setup("resync", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    service.tick(NOW).unwrap();
    requests(&seen);
    // A new rule version: a `changed` diff.
    fs::write(dir.join("baseline.json"), bundle(2, 2)).unwrap();
    service.scan_if_due(NOW + HOUR).unwrap();
    let report = service.tick(NOW + HOUR).unwrap();
    let tick = requests(&seen);
    let sent = changes_in(&tick);
    assert_eq!(sent.len(), 2);
    assert!(!sent[0].replace && sent[0].changed.len() == 1);
    assert!(
        sent[1].replace,
        "a 409 on the diff brings a replace at once"
    );
    assert!(
        report.matches_error.is_some(),
        "a 409 on the replace is refused"
    );
    service.tick(NOW + HOUR + 1_000).unwrap();
    assert_eq!(paths(&requests(&seen)), ["/v1/heartbeat"], "backing off");
    service.tick(NOW + HOUR + 61_000).unwrap();
    let after = changes_in(&requests(&seen));
    assert!(after.len() == 1 && after[0].replace);
}

#[test]
fn a_heartbeat_409_asks_for_a_replace_once() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            enroll(&pki),
            ok(),                         // replace
            code(409, "findings_resync"), // heartbeat
            ok(),                         // replace asked by the heartbeat
            ok(),                         // heartbeat
        ],
    );
    let (config, _) = setup("heartbeat_409", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    let report = service.tick(NOW).unwrap();
    assert!(
        report.heartbeat_error.is_none(),
        "the heartbeat was stored: not a failure"
    );
    requests(&seen);
    service.tick(NOW + 1_000).unwrap();
    let next = requests(&seen);
    assert_eq!(paths(&next), ["/v1/findings/changes", "/v1/heartbeat"]);
    assert!(changes_in(&next)[0].replace);
}

#[test]
fn the_acknowledged_set_survives_a_restart_and_a_corrupt_file_means_a_replace() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![enroll(&pki), ok(), ok(), ok(), ok(), ok()],
    );
    let (config, dir) = setup("restart", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    service.tick(NOW).unwrap();
    let digest = changes_in(&requests(&seen))[0].sha256.clone();
    drop(service);

    let mut service = open(&config);
    service.tick(NOW + 1_000).unwrap();
    let after_restart = requests(&seen);
    assert_eq!(paths(&after_restart), ["/v1/heartbeat"]);
    assert_eq!(after_restart[0].1["match_sha256"], digest.as_str());
    drop(service);

    fs::write(dir.join("state").join("matches.json"), "{").unwrap();
    let mut service = open(&config);
    service.scan_if_due(NOW + HOUR).unwrap();
    service.tick(NOW + HOUR).unwrap();
    let after_corruption = requests(&seen);
    assert!(changes_in(&after_corruption)[0].replace);
}

/// Tester (board #24 follow-up): removing the last rule set from the
/// configuration must end its matches (P13: "its rule set no longer
/// configured"), not leave them open forever.
#[test]
fn removing_every_rule_set_ends_the_matches() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![enroll(&pki), ok(), ok(), ok(), ok()],
    );
    let (config, _) = setup("no_rule_sets", &pki, &url);
    let mut service = open(&config);
    service.scan_if_due(NOW).unwrap();
    service.tick(NOW).unwrap();
    requests(&seen);
    drop(service);

    // The admin removes the only rule set.
    let text = fs::read_to_string(&config).unwrap();
    let without = &text[..text.find("[[rule_sets]]").unwrap()];
    fs::write(&config, without).unwrap();
    let mut service = open(&config);
    service.scan_if_due(NOW + HOUR).unwrap();
    service.tick(NOW + HOUR).unwrap();
    let sent = changes_in(&requests(&seen));
    assert_eq!(sent.len(), 1, "the end is reported");
    assert_eq!(sent[0].ended.len(), 1);
}
