//! Rule distribution against mock ingest and distribution services: fetch over
//! mTLS before a scan, `204` keeps the accepted bundle, refused envelopes never
//! replace it, and revocation from either service discards the identity.

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, mpsc},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_agent::{AgentError, Service, load_config};
use openvibes_core::{
    Confidence, EnrollmentResponse, Identifier, PayloadEncoding, PlatformError, PlatformErrorCode,
    ResourceLimits, Rule, RuleBundleRequest, RuleSet, SchemaVersion, Severity, SignedRuleEnvelope,
};
use openvibes_rules::{LoadError, signing_preimage};
use openvibes_testkit::{Handler, Pki, Reply, Seen, json, serve, status};
use openvibes_transport::TransportError;
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

/// A signed `baseline` bundle whose one rule always matches.
fn bundle(version: u64, key: &SigningKey) -> Vec<u8> {
    let payload = serde_json::to_string(&RuleSet {
        schema_version: SchemaVersion::V1,
        rules: vec![Rule {
            id: id("host.has.processes"),
            version: 1,
            title: "Processes are running".into(),
            severity: Severity::Info,
            confidence: Confidence::new(100).unwrap(),
            expression: "facts['process.count'] >= 1".into(),
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

fn raw(status: u16, body: Vec<u8>) -> Handler {
    Box::new(move |_: &Seen| Reply {
        status,
        headers: "",
        body,
        stall: false,
    })
}

fn revoked() -> Handler {
    Box::new(|_: &Seen| Reply {
        status: 403,
        ..json(&PlatformError {
            schema_version: SchemaVersion::V1,
            code: PlatformErrorCode::IdentityRevoked,
        })
    })
}

/// Enrollment, then one heartbeat; the queue is empty, so no delivery.
fn ingest(pki: &Arc<Pki>) -> Vec<Handler> {
    let issuer = pki.clone();
    vec![
        Box::new(move |seen: &Seen| {
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec![
                    issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                ],
                expires_at_unix_ms: NOW + 1_000 * HOUR,
            })
        }),
        Box::new(|_: &Seen| status(204)),
    ]
}

/// An enrolled online agent with `baseline` fetched from `distribution_url`
/// only (no bundle file).
fn enrolled(test: &str, pki: &Arc<Pki>, distribution_url: &str) -> Service {
    let mut service = configured(test, pki, distribution_url);
    service.tick(NOW).unwrap();
    service
}

/// The same agent before its first tick: not enrolled yet.
fn configured(test: &str, pki: &Arc<Pki>, distribution_url: &str) -> Service {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-distribution")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
    fs::write(dir.join("token"), "one-time\n").unwrap();
    let (ingest_url, _) = serve(pki.server_config(false, false), ingest(pki));
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    let config = dir.join("agent.toml");
    fs::write(
        &config,
        format!(
            "platform_url = {ingest_url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
             enrollment_token_file = {:?}\ndistribution_url = {distribution_url:?}\n\
             [[rule_sets]]\nid = \"baseline\"\n\
             trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]\n",
            dir.join("ca.pem"),
            dir.join("state"),
            dir.join("token"),
        ),
    )
    .unwrap();
    Service::open(load_config(&config).unwrap()).unwrap()
}

fn requests(seen: &mpsc::Receiver<Seen>) -> Vec<(String, bool, RuleBundleRequest)> {
    seen.try_iter()
        .map(|seen| {
            let request = serde_json::from_slice(&seen.body).unwrap();
            (seen.path, seen.client_cert, request)
        })
        .collect()
}

#[test]
fn fetched_bundles_are_verified_kept_and_never_replaced_by_refused_ones() {
    let pki = Arc::new(Pki::new());
    let key = organization_key();
    let attacker = SigningKey::from_bytes(&[8; 32]);
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![
            raw(200, bundle(1, &key)),
            raw(204, Vec::new()),
            raw(200, bundle(2, &attacker)),
            raw(200, bundle(2, &key)),
        ],
    );
    let mut service = enrolled("fetch", &pki, &url);

    let first = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!((first.queued, first.rule_set_errors.len()), (1, 0));
    let [(path, client_cert, request)] = requests(&seen).try_into().unwrap();
    assert_eq!((path.as_str(), client_cert), ("/v1/rule-bundle", true));
    assert_eq!(request.rule_set_id, id("baseline"));
    assert_eq!(request.current_version, None);

    // 204: nothing newer; the accepted v1 keeps running.
    let second = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!((second.queued, second.rule_set_errors.len()), (1, 0));
    assert_eq!(requests(&seen)[0].2.current_version, Some(1));

    // A forged v2 is refused; v1 still runs.
    let third = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!(third.queued, 1);
    assert_eq!(
        third.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Rules(LoadError::InvalidSignature)
        )]
    );

    // A genuine v2 is accepted; the refused one never raised the floor.
    let fourth = service.scan_if_due(NOW + 3 * HOUR).unwrap().unwrap();
    assert_eq!((fourth.queued, fourth.rule_set_errors.len()), (1, 0));
    let versions: Vec<_> = requests(&seen)
        .into_iter()
        .map(|(_, _, request)| request.current_version)
        .collect();
    assert_eq!(versions, [Some(1), Some(1)]);
}

#[test]
fn an_unreachable_or_failing_service_keeps_the_accepted_bundle() {
    let pki = Arc::new(Pki::new());
    let (url, _) = serve(
        pki.server_config(true, false),
        vec![
            raw(200, bundle(1, &organization_key())),
            raw(503, Vec::new()),
        ],
    );
    let mut service = enrolled("failing", &pki, &url);
    assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().queued, 1);

    let failed = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(failed.queued, 1);
    assert_eq!(
        failed.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Transport(TransportError::Rejected)
        )]
    );
}

#[test]
fn revocation_by_the_distribution_service_discards_the_identity() {
    let pki = Arc::new(Pki::new());
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![raw(200, bundle(1, &organization_key())), revoked()],
    );
    let mut service = enrolled("revoked", &pki, &url);
    assert_eq!(service.scan_if_due(NOW).unwrap().unwrap().queued, 1);

    let report = service.scan_if_due(NOW + HOUR).unwrap().unwrap();
    assert_eq!(report.queued, 1, "the accepted bundle still runs");
    assert_eq!(
        report.rule_set_errors,
        [(
            id("baseline"),
            AgentError::Transport(TransportError::IdentityRevoked)
        )]
    );
    assert_eq!(requests(&seen).len(), 2);

    // No identity now: the next scan does not contact the service at all.
    let next = service.scan_if_due(NOW + 2 * HOUR).unwrap().unwrap();
    assert_eq!((next.queued, next.rule_set_errors.len()), (1, 0));
    assert!(requests(&seen).is_empty());
}

#[test]
fn distribution_needs_a_platform_and_file_less_sets_need_distribution() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("agent-distribution-config");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    let set = format!(
        "[[rule_sets]]\nid = \"baseline\"\n\
         trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]\n"
    );
    let state = format!("state_dir = {:?}\n", dir.join("state"));
    for (name, text) in [
        ("no-source", format!("{state}{set}")),
        (
            "local-only-distribution",
            format!("{state}distribution_url = \"https://rules.example\"\n{set}"),
        ),
    ] {
        let path = dir.join(format!("{name}.toml"));
        fs::write(&path, text).unwrap();
        assert_eq!(load_config(&path).err(), Some(AgentError::Config), "{name}");
    }
}

#[test]
fn a_distribution_only_set_is_scanned_right_after_the_first_enrollment() {
    let pki = Arc::new(Pki::new());
    let (url, _) = serve(
        pki.server_config(true, false),
        vec![raw(200, bundle(1, &organization_key()))],
    );
    let mut service = configured("first-enrollment", &pki, &url);
    // The main loop scans before it ticks: nothing can be fetched yet.
    let before = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(
        before.rule_set_errors,
        [(id("baseline"), AgentError::NoRuleBundle)],
        "no bundle yet, not a configuration error"
    );
    service.tick(NOW).unwrap(); // enrolls
    // The next loop, a minute later, scans again instead of an hour later.
    let after = service
        .scan_if_due(NOW + 60_000)
        .unwrap()
        .expect("scanned again once enrolled");
    assert_eq!(after.queued, 1);
}

#[test]
fn a_damaged_identity_does_not_stop_file_provisioned_rules() {
    let pki = Arc::new(Pki::new());
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-distribution")
        .join("damaged-identity");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
    fs::write(dir.join("token"), "one-time\n").unwrap();
    fs::write(dir.join("baseline.json"), bundle(1, &organization_key())).unwrap();
    let (ingest_url, _) = serve(pki.server_config(false, false), ingest(&pki));
    let public = URL_SAFE_NO_PAD.encode(organization_key().verifying_key().to_bytes());
    let keys =
        format!("trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]");
    let config = dir.join("agent.toml");
    fs::write(
        &config,
        format!(
            "platform_url = {ingest_url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
             enrollment_token_file = {:?}\ndistribution_url = \"https://127.0.0.1:1\"\n\
             [[rule_sets]]\nid = \"remote\"\n{keys}\n\
             [[rule_sets]]\nid = \"baseline\"\nbundle_file = {:?}\n{keys}\n",
            dir.join("ca.pem"),
            dir.join("state"),
            dir.join("token"),
            dir.join("baseline.json"),
        ),
    )
    .unwrap();
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.tick(NOW).unwrap();
    drop(service);
    // Damage the stored identity record (the database itself stays valid).
    rusqlite_like_update(&dir.join("state").join("identity.sqlite"));
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    let report = service.scan_if_due(NOW).unwrap().unwrap();
    assert_eq!(report.queued, 1, "the file-provisioned set still scanned");
    assert!(
        report
            .rule_set_errors
            .iter()
            .any(|(set, error)| set == &id("remote")
                && *error == AgentError::Storage(openvibes_storage::StorageError::Corrupt)),
        "{:?}",
        report.rule_set_errors
    );
}

/// Replaces the stored chain with an empty list, which the store reports as
/// corrupt.
#[allow(clippy::disallowed_types)] // sqlite3 CLI for the test only
fn rusqlite_like_update(path: &std::path::Path) {
    assert!(
        std::process::Command::new("sqlite3")
            .arg(path)
            .arg("UPDATE identity SET chain_json = '[]'")
            .status()
            .unwrap()
            .success()
    );
}
