//! Milestone 4 path: enroll once with a token, restart, reconnect with the
//! stored mTLS identity, and deliver a queued finding exactly once.

use std::{fs, path::PathBuf, sync::Arc};

use openvibes_agent::{AgentError, load_or_enroll};
use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, EnrollmentToken, Finding, Identifier,
    ResourceLimits, SchemaVersion, Severity,
};
use openvibes_storage::{IdentityStore, SqliteQueue, prepare_state_dir};
use openvibes_testkit::{Pki, Seen, json, serve, status};
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

/// A platform that issues a client certificate for the enrollment CSR.
fn enrolling_platform(pki: &Arc<Pki>) -> String {
    let issuer = pki.clone();
    serve(
        pki.server_config(false, false),
        vec![Box::new(move |seen: &Seen| {
            assert_eq!(seen.path, "/v1/enroll");
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec![
                    issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                ],
                expires_at_unix_ms: 10_000,
            })
        })],
    )
    .0
}

#[test]
fn enrolled_agent_reconnects_after_restart_and_delivers_over_mtls() {
    let pki = Arc::new(Pki::new());
    let state = state_dir("restart");
    let token = EnrollmentToken::new("one-time").unwrap();

    let url = enrolling_platform(&pki);
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let enrolled = load_or_enroll(&mut store, &config(&url, &pki), Some(&token)).unwrap();
    assert_eq!(enrolled.agent_id, id("agent.1"));
    let mut queue = SqliteQueue::open(&state.join("queue.sqlite"), ResourceLimits::V1).unwrap();
    let finding = Finding {
        schema_version: SchemaVersion::V1,
        finding_id: id("finding.1"),
        scan_id: id("scan.1"),
        rule_id: id("rule.1"),
        rule_version: 1,
        observed_at_unix_ms: 1,
        severity: Severity::Medium,
        confidence: Confidence::new(100).unwrap(),
        message: "synthetic".into(),
        evidence: Vec::new(),
    };
    assert_eq!(queue.enqueue(&finding, 0), Ok(true));
    drop((store, queue));

    // Restart. The platform now requires a client certificate on every
    // connection, so any unauthenticated request, including a second
    // enrollment, would fail the handshake.
    let (url, seen) = serve(
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
    );
    let config = config(&url, &pki);
    let mut store =
        IdentityStore::open(&state.join("identity.sqlite"), ResourceLimits::V1).unwrap();
    let restored = load_or_enroll(&mut store, &config, None).unwrap();
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
        load_or_enroll(&mut store, &unreachable, None).err(),
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
        load_or_enroll(&mut store, &config(&url, &pki), Some(&token)).err(),
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
        load_or_enroll(&mut store, &config(&url, &pki), Some(&token)).err(),
        Some(AgentError::Transport(TransportError::InvalidIdentity))
    );
    assert_eq!(store.get(), Ok(None));
}
