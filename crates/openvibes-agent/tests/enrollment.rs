//! Milestone 4 path: enroll once with a token, restart, reconnect with the
//! stored mTLS identity, and deliver a queued finding exactly once.

use std::{
    fs,
    path::PathBuf,
    sync::{Arc, mpsc},
};

use openvibes_agent::{AgentError, forget_if_revoked, load_or_enroll, renew_if_due};
use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, EnrollmentToken, Finding, Identifier,
    ResourceLimits, SchemaVersion, Severity,
};
use openvibes_storage::{DeliveryError, IdentityStore, SqliteQueue, prepare_state_dir};
use openvibes_testkit::{Pki, Reply, Seen, json, serve, status};
use openvibes_transport::{PlatformClient, TransportConfig, TransportError};

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn config(base_url: &str, pki: &Pki) -> TransportConfig {
    TransportConfig {
        base_url: base_url.to_owned(),
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    }
}

/// Fresh private state directory unique to one test.
fn state_dir(test: &str) -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("agent-enrollment");
    fs::create_dir_all(&parent).unwrap();
    let dir = parent.join(test);
    let _ = fs::remove_dir_all(&dir);
    prepare_state_dir(&dir).unwrap();
    dir
}

/// A platform that issues a certificate for `agent` expiring at `expires` for
/// the CSR in an enrollment or renewal request.
fn issuing_platform(
    pki: &Arc<Pki>,
    require_client_cert: bool,
    agent: &'static str,
    expires: i64,
) -> (String, mpsc::Receiver<Seen>) {
    let issuer = pki.clone();
    serve(
        pki.server_config(require_client_cert, false),
        vec![Box::new(move |seen: &Seen| {
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id(agent),
                certificate_chain_pem: vec![
                    issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                ],
                expires_at_unix_ms: expires,
            })
        })],
    )
}

fn enrolling_platform(pki: &Arc<Pki>) -> String {
    issuing_platform(pki, false, "agent.1", 10_000).0
}

/// A platform requiring mTLS that acknowledges every finding it receives.
fn acknowledging_platform(pki: &Pki) -> (String, mpsc::Receiver<Seen>) {
    serve(
        pki.server_config(true, false),
        vec![Box::new(|seen: &Seen| {
            let batch: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            let ids = batch["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|finding| id(finding["finding_id"].as_str().unwrap()))
                .collect();
            json(&DeliveryAcknowledgement {
                schema_version: SchemaVersion::V1,
                accepted_finding_ids: ids,
                acknowledged_at_unix_ms: 2,
            })
        })],
    )
}

fn finding(name: &str) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: id(name),
        scan_id: id("scan.1"),
        rule_id: id("rule.1"),
        rule_version: 1,
        observed_at_unix_ms: 1,
        severity: Severity::Medium,
        confidence: Confidence::new(100).unwrap(),
        message: "synthetic".into(),
        evidence: Vec::new(),
    }
}

#[test]
fn enrolled_agent_reconnects_after_restart_and_delivers_over_mtls() {
    let pki = Arc::new(Pki::new());
    let state = state_dir("restart");
    let token = EnrollmentToken::new("one-time").unwrap();

    let url = enrolling_platform(&pki);
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let enrolled = load_or_enroll(&mut store, &config(&url, &pki), Some(&token), 0).unwrap();
    assert_eq!(enrolled.agent_id, id("agent.1"));
    let mut queue = SqliteQueue::open(&state.join("queue.sqlite"), ResourceLimits::V1).unwrap();
    let finding = finding("finding.1");
    assert_eq!(queue.enqueue(&finding, 0), Ok(true));
    drop((store, queue));

    // Restart. The platform now requires a client certificate on every
    // connection, so any unauthenticated request, including a second
    // enrollment, would fail the handshake.
    let (url, seen) = acknowledging_platform(&pki);
    let config = config(&url, &pki);
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let restored = load_or_enroll(&mut store, &config, None, 0).unwrap();
    assert_eq!(restored.agent_id, id("agent.1"));
    let client = PlatformClient::new(&config, Some(&restored.identity)).unwrap();
    let mut queue = SqliteQueue::open(&state.join("queue.sqlite"), ResourceLimits::V1).unwrap();
    assert_eq!(queue.deliver(0, |batch| client.deliver(batch)), Ok(1));

    let delivery = seen.recv().unwrap();
    assert_eq!(delivery.path, "/v1/findings");
    assert!(delivery.client_cert);
    // Acknowledged: a replay of the same scan is not queued or sent again.
    assert_eq!(queue.enqueue(&finding, 1), Ok(false));
    assert_eq!(queue.is_empty(), Ok(true));
}

#[test]
fn unenrolled_agent_without_token_does_not_contact_the_platform() {
    let pki = Pki::new();
    let state = state_dir("no-token");
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let unreachable = config("https://127.0.0.1:9", &pki);
    assert_eq!(
        load_or_enroll(&mut store, &unreachable, None, 0).err(),
        Some(AgentError::NotEnrolled)
    );
}

#[test]
fn refused_enrollment_stores_nothing() {
    let pki = Pki::new();
    let state = state_dir("refused");
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(401))],
    );
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let token = EnrollmentToken::new("spent").unwrap();
    assert_eq!(
        load_or_enroll(&mut store, &config(&url, &pki), Some(&token), 0).err(),
        Some(AgentError::Transport(TransportError::Unauthorized))
    );
    assert_eq!(store.get(), Ok(None));
}

#[test]
fn chain_that_does_not_parse_is_never_stored() {
    let pki = Pki::new();
    let state = state_dir("bad-chain");
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| {
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec!["not a certificate".into()],
                expires_at_unix_ms: 10_000,
            })
        })],
    );
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let token = EnrollmentToken::new("one-time").unwrap();
    assert_eq!(
        load_or_enroll(&mut store, &config(&url, &pki), Some(&token), 0).err(),
        Some(AgentError::Transport(TransportError::InvalidIdentity))
    );
    assert_eq!(store.get(), Ok(None));
}

#[test]
fn identity_rotates_to_a_new_key_after_two_thirds_of_its_lifetime() {
    let pki = Arc::new(Pki::new());
    let state = state_dir("renew");
    let path = state.join("identity.sqlite");
    let mut store = IdentityStore::open(&path, ResourceLimits::V1).unwrap();
    let url = enrolling_platform(&pki);
    let token = EnrollmentToken::new("one-time").unwrap();
    // Obtained at 1_000, expires at 10_000: renewal is due at 7_000.
    let current = load_or_enroll(&mut store, &config(&url, &pki), Some(&token), 1_000).unwrap();
    let old_key = store.get().unwrap().unwrap().key_pem;

    let (url, seen) = issuing_platform(&pki, true, "agent.1", 20_000);
    let renew_config = config(&url, &pki);
    assert!(
        renew_if_due(&mut store, &renew_config, &current, 6_999)
            .unwrap()
            .is_none()
    );
    let renewed = renew_if_due(&mut store, &renew_config, &current, 7_000)
        .unwrap()
        .unwrap();
    let request = seen.recv().unwrap();
    assert_eq!(request.path, "/v1/renew");
    assert!(
        request.client_cert,
        "renewal is authenticated by the current identity"
    );

    let stored = store.get().unwrap().unwrap();
    assert_ne!(stored.key_pem, old_key, "renewal must rotate the key");
    assert_eq!(
        (stored.obtained_at_unix_ms, stored.expires_at_unix_ms),
        (7_000, 20_000)
    );
    assert_eq!(renewed.agent_id, id("agent.1"));

    // The rotated identity authenticates.
    let (url, seen) = acknowledging_platform(&pki);
    let client = PlatformClient::new(&config(&url, &pki), Some(&renewed.identity)).unwrap();
    assert_eq!(
        client
            .deliver(&[finding("f.a")])
            .map(|ack| ack.accepted_finding_ids.len()),
        Ok(1)
    );
    assert!(seen.recv().unwrap().client_cert);
}

#[test]
fn renewal_for_another_agent_keeps_the_current_identity() {
    let pki = Arc::new(Pki::new());
    let state = state_dir("renew-mismatch");
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let url = enrolling_platform(&pki);
    let token = EnrollmentToken::new("one-time").unwrap();
    let current = load_or_enroll(&mut store, &config(&url, &pki), Some(&token), 0).unwrap();
    let before = store.get().unwrap();

    let (url, _) = issuing_platform(&pki, true, "agent.other", 20_000);
    assert_eq!(
        renew_if_due(&mut store, &config(&url, &pki), &current, 9_000).err(),
        Some(AgentError::IdentityMismatch)
    );
    assert_eq!(store.get().unwrap(), before);
}

#[test]
fn revoked_agent_keeps_its_findings_and_recovers_by_re_enrolling() {
    let pki = Arc::new(Pki::new());
    let state = state_dir("revoked");
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let mut queue = SqliteQueue::open(&state.join("queue.sqlite"), ResourceLimits::V1).unwrap();
    let url = enrolling_platform(&pki);
    let first = EnrollmentToken::new("first").unwrap();
    let enrolled = load_or_enroll(&mut store, &config(&url, &pki), Some(&first), 0).unwrap();
    assert_eq!(queue.enqueue(&finding("f.a"), 0), Ok(true));

    let (url, _) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| Reply {
            body: br#"{"schema_version":1,"code":"identity_revoked"}"#.to_vec(),
            ..status(403)
        })],
    );
    let client = PlatformClient::new(&config(&url, &pki), Some(&enrolled.identity)).unwrap();
    let Err(DeliveryError::Transport(error)) = queue.deliver(0, |batch| client.deliver(batch))
    else {
        panic!("revoked delivery must fail");
    };
    assert_eq!(forget_if_revoked(&mut store, error), Ok(true));
    assert_eq!(store.get(), Ok(None));
    assert_eq!(queue.len(), Ok(1), "revocation never discards findings");
    assert_eq!(
        load_or_enroll(&mut store, &config(&url, &pki), None, 0).err(),
        Some(AgentError::NotEnrolled)
    );

    // An operator issues a new token; the agent re-enrolls and delivers.
    let url = issuing_platform(&pki, false, "agent.2", 10_000).0;
    let second = EnrollmentToken::new("second").unwrap();
    let recovered = load_or_enroll(&mut store, &config(&url, &pki), Some(&second), 0).unwrap();
    assert_eq!(recovered.agent_id, id("agent.2"));
    let (url, seen) = acknowledging_platform(&pki);
    let client = PlatformClient::new(&config(&url, &pki), Some(&recovered.identity)).unwrap();
    assert_eq!(queue.deliver(100_000, |batch| client.deliver(batch)), Ok(1));
    assert!(seen.recv().unwrap().client_cert);
}

#[test]
fn only_explicit_revocation_forgets_the_identity() {
    let state = state_dir("not-revoked");
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    for error in [
        TransportError::Unauthorized,
        TransportError::Tls,
        TransportError::Connect,
    ] {
        assert_eq!(forget_if_revoked(&mut store, error), Ok(false));
    }
}
