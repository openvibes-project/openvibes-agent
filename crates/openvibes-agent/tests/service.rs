//! The service tick against a mock platform: configuration loading, first-run
//! enrollment, heartbeat, delivery, and renewal failures that must not block
//! delivery.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, mpsc},
};

use openvibes_agent::{AgentError, Service, TickReport, load_config};
use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, Finding, Identifier, SchemaVersion,
    Severity,
};
use openvibes_testkit::{Handler, Pki, Seen, json, serve, status};
use openvibes_transport::TransportError;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
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

/// Fresh scratch directory holding a config, CA bundle, and token file.
fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("agent-service")
        .join(test);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write_config(dir: &Path, pki: &Pki, url: &str, extra: &str) -> PathBuf {
    fs::write(dir.join("ca.pem"), pki.roots_pem()).unwrap();
    fs::write(dir.join("token"), "one-time\n").unwrap();
    let path = dir.join("agent.toml");
    // Debug formatting quotes and escapes the paths as TOML basic strings.
    fs::write(
        &path,
        format!(
            "platform_url = {url:?}\nplatform_ca_file = {:?}\nstate_dir = {:?}\n\
             enrollment_token_file = {:?}\n{extra}",
            dir.join("ca.pem"),
            dir.join("state"),
            dir.join("token"),
        ),
    )
    .unwrap();
    path
}

fn issue(pki: &Arc<Pki>, expires: i64) -> Handler {
    let issuer = pki.clone();
    Box::new(move |seen: &Seen| {
        let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
        json(&EnrollmentResponse {
            schema_version: SchemaVersion::V1,
            agent_id: id("agent.1"),
            certificate_chain_pem: vec![issuer.issue_client(request["csr_pem"].as_str().unwrap())],
            expires_at_unix_ms: expires,
        })
    })
}

fn acknowledge_all() -> Handler {
    Box::new(|seen: &Seen| {
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
            rejected_findings: Vec::new(),
        })
    })
}

fn paths(seen: &mpsc::Receiver<Seen>) -> Vec<(String, bool)> {
    seen.try_iter()
        .map(|seen| (seen.path, seen.client_cert))
        .collect()
}

#[test]
fn first_tick_enrolls_then_heartbeats_and_delivers_over_mtls() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("first-tick");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000),
            Box::new(|_: &Seen| status(204)),
            acknowledge_all(),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.a"), 0), Ok(true));

    let report = service.tick(0).unwrap();
    assert_eq!(
        report,
        TickReport {
            delivered: 1,
            ..TickReport::default()
        }
    );
    assert_eq!(
        paths(&seen),
        [
            ("/v1/enroll".to_owned(), false),
            ("/v1/heartbeat".to_owned(), true),
            ("/v1/findings".to_owned(), true),
        ]
    );
}

#[test]
fn failed_renewal_keeps_the_identity_and_still_delivers() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("renewal-fails");
    // Issued at 0, expiring at 900: renewal is due from 600.
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            // Tick at 0: enroll and heartbeat; nothing is queued yet.
            issue(&pki, 900),
            Box::new(|_: &Seen| status(204)),
            // Tick at 700: renewal fails, the rest proceeds.
            Box::new(|_: &Seen| status(503)),
            Box::new(|_: &Seen| status(204)),
            acknowledge_all(),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    service.tick(0).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.b"), 700), Ok(true));

    let report = service.tick(700).unwrap();
    assert_eq!(
        report,
        TickReport {
            renewal_error: Some(AgentError::Transport(TransportError::Rejected)),
            delivered: 1,
            ..TickReport::default()
        }
    );
    let requested: Vec<String> = paths(&seen).into_iter().map(|(path, _)| path).collect();
    assert_eq!(
        requested[2..],
        ["/v1/renew", "/v1/heartbeat", "/v1/findings"]
    );
}

#[test]
fn missing_token_waits_without_contacting_the_platform() {
    let pki = Pki::new();
    let dir = scratch("no-token");
    let config = write_config(&dir, &pki, "https://127.0.0.1:9", "");
    fs::remove_file(dir.join("token")).unwrap();
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    assert_eq!(service.tick(0).err(), Some(AgentError::NotEnrolled));
}

#[test]
fn export_is_refused_while_a_platform_is_configured() {
    let pki = Pki::new();
    let dir = scratch("export-online");
    let config = write_config(&dir, &pki, "https://127.0.0.1:9", "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.queue().enqueue(&finding("finding.1"), 0).unwrap();
    assert_eq!(
        service.export(&dir, 0).err(),
        Some(AgentError::NotLocalOnly)
    );
    assert_eq!(service.queue().len().unwrap(), 1);
}

#[test]
fn invalid_configuration_is_refused() {
    let pki = Pki::new();
    let dir = scratch("invalid");
    let good = write_config(&dir, &pki, "https://platform.example", "");
    assert!(load_config(&good).is_ok());

    let unknown_key = write_config(
        &dir,
        &pki,
        "https://platform.example",
        "platfrom_url = \"x\"\n",
    );
    assert_eq!(load_config(&unknown_key).err(), Some(AgentError::Config));

    fs::write(&good, "x".repeat(64 * 1024 + 1)).unwrap();
    assert_eq!(load_config(&good).err(), Some(AgentError::Config));

    fs::write(&good, "platform_url = \"https://p.example\"\nplatform_ca_file = \"ca.pem\"\nstate_dir = \"/state\"\n").unwrap();
    assert_eq!(
        load_config(&good).err(),
        Some(AgentError::Config),
        "relative path"
    );

    assert_eq!(
        load_config(&dir.join("absent.toml")).err(),
        Some(AgentError::Config)
    );

    let http = write_config(&dir, &pki, "http://platform.example", "");
    assert_eq!(
        Service::open(load_config(&http).unwrap()).err(),
        Some(AgentError::Transport(TransportError::InvalidConfig))
    );
}

#[test]
fn permanently_rejected_findings_leave_the_queue_and_are_counted() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("rejected");
    let (url, _seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000),
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| {
                json(&DeliveryAcknowledgement {
                    schema_version: SchemaVersion::V1,
                    accepted_finding_ids: vec![id("f.ok"), id("f.future")],
                    rejected_findings: vec![openvibes_core::RejectedFinding {
                        finding_id: id("f.future"),
                        reason: id("future_observation"),
                    }],
                    acknowledged_at_unix_ms: 2,
                })
            }),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.ok"), 0), Ok(true));
    assert_eq!(service.queue().enqueue(&finding("f.future"), 0), Ok(true));

    let report = service.tick(0).unwrap();
    assert_eq!(report.delivered, 2);
    assert_eq!(
        report.rejected.get("future_observation").copied(),
        Some(1),
        "counted by reason"
    );
    assert_eq!(service.queue().len(), Ok(0), "nothing is retried");
}

#[test]
fn an_expired_certificate_leads_to_re_enrollment_with_the_token_file() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("expired");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            // Tick at 0: enroll (expires at 900) and heartbeat.
            issue(&pki, 900),
            Box::new(|_: &Seen| status(204)),
            // Tick at 1000, after expiry (the laptop was off through the
            // renewal window): enroll again, then heartbeat.
            issue(&pki, 5_000),
            Box::new(|_: &Seen| status(204)),
            acknowledge_all(),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    service.tick(0).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.kept"), 0), Ok(true));
    let report = service.tick(1_000).unwrap();
    assert_eq!(report.delivered, 1, "the queue survives re-enrollment");
    assert_eq!(
        paths(&seen),
        [
            ("/v1/enroll".to_owned(), false),
            ("/v1/heartbeat".to_owned(), true),
            ("/v1/enroll".to_owned(), false),
            ("/v1/heartbeat".to_owned(), true),
            ("/v1/findings".to_owned(), true),
        ]
    );
}

#[test]
fn a_corrupt_queue_is_moved_aside_and_replaced() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("corrupt-queue");
    let config = write_config(&dir, &pki, "https://127.0.0.1:1", "");
    // First start creates the state directory; then the queue is damaged.
    drop(Service::open(load_config(&config).unwrap()).unwrap());
    let queue = dir.join("state").join("queue.sqlite");
    fs::write(&queue, vec![0xA5; 8_192]).unwrap();

    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    let moved = service
        .recovered_queue()
        .expect("the corrupt queue is reported")
        .to_path_buf();
    assert!(
        moved.starts_with(dir.join("state")),
        "kept in the state directory"
    );
    assert_eq!(
        fs::read(&moved).unwrap(),
        vec![0xA5; 8_192],
        "kept for inspection"
    );
    assert_eq!(service.queue().enqueue(&finding("f.new"), 0), Ok(true));
}
