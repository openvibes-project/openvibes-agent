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
#[cfg(target_os = "linux")]
use openvibes_core::{InstalledPackage, NormalizedPackage, OsRelease, hex, inventory_fingerprint};
use openvibes_testkit::{Handler, Pki, Seen, json, serve, status};
use openvibes_transport::TransportError;

/// Writes the enrollment token as operators must: unreadable by others.
fn write_token(path: &Path) {
    fs::write(path, "one-time\n").unwrap();
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
}
fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn finding(name: &str) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        rule_set_id: None,
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
    write_token(&dir.join("token"));
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
            // The install script waits for the line main prints from this.
            enrolled_as: Some("agent.1".into()),
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
    assert_eq!(
        service.tick(0).unwrap().enrolled_as.as_deref(),
        Some("agent.1")
    );
    assert_eq!(service.queue().enqueue(&finding("f.b"), 700), Ok(true));

    let report = service.tick(700).unwrap();
    assert_eq!(
        report,
        TickReport {
            // A 503 is "try again later" (TransportError::Unavailable).
            renewal_error: Some(AgentError::Transport(TransportError::Unavailable)),
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

/// Running as root, the agent must not take its platform, trust keys, or
/// token from files another user could change (or read, for the token).
#[cfg(unix)]
#[test]
fn configured_files_others_could_change_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    let chmod = |path: &Path, mode| {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    };
    let pki = Pki::new();
    let dir = scratch("insecure-files");
    let config = write_config(&dir, &pki, "https://platform.example", "");
    for (file, loose) in [("agent.toml", 0o666), ("ca.pem", 0o646)] {
        chmod(&dir.join(file), loose);
        assert_eq!(
            load_config(&config).err(),
            Some(AgentError::InsecureFile),
            "{file}"
        );
        chmod(&dir.join(file), 0o644);
    }

    // The token is read only when enrolling: refused before any request.
    chmod(&dir.join("token"), 0o604);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    assert_eq!(service.tick(0).err(), Some(AgentError::InsecureFile));
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

#[test]
fn a_failed_heartbeat_does_not_hold_up_delivery() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("heartbeat-fails");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000),
            Box::new(|_: &Seen| status(500)),
            acknowledge_all(),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.hb"), 0), Ok(true));
    let report = service.tick(0).unwrap();
    assert_eq!(report.delivered, 1, "findings still delivered");
    assert!(
        report.heartbeat_error.is_some(),
        "and the heartbeat failure reported"
    );
    let requested: Vec<String> = paths(&seen).into_iter().map(|(path, _)| path).collect();
    assert_eq!(requested, ["/v1/enroll", "/v1/heartbeat", "/v1/findings"]);
}

#[test]
fn a_forward_clock_jump_neither_prunes_findings_nor_drops_the_identity() {
    const DAY: i64 = 86_400_000;
    let pki = Arc::new(Pki::new());
    let dir = scratch("clock-jump");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 30 * DAY),
            Box::new(|_: &Seen| status(204)),
            // After the jump: renewal is due by the wall clock (harmless),
            // but the identity is not dropped and nothing is pruned.
            issue(&pki, 70 * DAY),
            Box::new(|_: &Seen| status(204)),
            acknowledge_all(),
        ],
    );
    let mut service =
        Service::open(load_config(&write_config(&dir, &pki, &url, "")).unwrap()).unwrap();
    service.tick(0).unwrap();
    assert_eq!(service.queue().enqueue(&finding("f.old"), 0), Ok(true));

    // Moments later the wall clock reads 40 days on.
    let report = service.tick(40 * DAY).unwrap();
    let jump = report.clock_jump_ms.expect("the jump is reported");
    assert!(jump > 39 * DAY, "{jump}");
    assert_eq!(
        report.delivered, 1,
        "the finding queued before the jump survived"
    );
    let requested: Vec<String> = paths(&seen).into_iter().map(|(path, _)| path).collect();
    assert_eq!(
        requested,
        [
            "/v1/enroll",
            "/v1/heartbeat",
            "/v1/renew",
            "/v1/heartbeat",
            "/v1/findings"
        ],
        "no re-enrollment: the identity was kept"
    );
}

#[test]
fn heartbeats_report_the_enabled_collectors() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("heartbeat-collectors");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![issue(&pki, 10_000), Box::new(|_: &Seen| status(204))],
    );
    let config = write_config(&dir, &pki, &url, "collectors = [\"ports\", \"processes\"]");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.tick(0).unwrap();
    let heartbeat = seen
        .try_iter()
        .find(|seen| seen.path == "/v1/heartbeat")
        .expect("a heartbeat");
    let body: serde_json::Value = serde_json::from_slice(&heartbeat.body).unwrap();
    // Protocol P7: the enabled collectors, in a fixed order.
    assert_eq!(
        body["capabilities"],
        serde_json::json!(["collector.processes", "collector.ports"])
    );
}

/// Requests seen so far, by path.
fn requested(seen: &std::sync::mpsc::Receiver<Seen>) -> Vec<(String, Vec<u8>)> {
    seen.try_iter()
        .map(|seen| (seen.path.clone(), seen.decoded_body()))
        .collect()
}

#[cfg(target_os = "linux")]
#[test]
fn inventory_is_reported_once_and_again_only_when_it_changes() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-once");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // inventory
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // heartbeat (restart, hash kept)
            Box::new(|_: &Seen| status(204)), // heartbeat (restart, hash changed)
            Box::new(|_: &Seen| status(204)), // inventory
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    assert_eq!(service.scan_if_due(0).unwrap(), None, "no rule sets");
    service.tick(0).unwrap();
    let first = requested(&seen);
    let paths: Vec<&str> = first.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["/v1/enroll", "/v1/heartbeat", "/v1/inventory"]);
    let heartbeat: serde_json::Value = serde_json::from_slice(&first[1].1).unwrap();
    assert!(
        heartbeat["capabilities"]
            .as_array()
            .unwrap()
            .contains(&"inventory.packages".into())
    );
    let report: serde_json::Value = serde_json::from_slice(&first[2].1).unwrap();
    assert!(!report["os"]["id"].as_str().unwrap().is_empty());
    assert!(report["packages"].as_array().unwrap().len() > 10);
    assert_eq!(
        report["running_kernel"].as_str(),
        openvibes_collectors::running_kernel().as_deref(),
        "protocol P9"
    );

    // Unchanged: a later scan and tick send no inventory.
    assert_eq!(service.scan_if_due(3_600_000).unwrap(), None);
    service.tick(3_600_000).unwrap();
    assert_eq!(requested(&seen).len(), 1, "heartbeat only");

    // The acknowledged hash survives a restart.
    drop(service);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_700_000).unwrap();
    service.tick(3_700_000).unwrap();
    assert_eq!(requested(&seen).len(), 1, "heartbeat only after restart");

    // A changed inventory (the stored hash no longer matches) is sent again.
    drop(service);
    std::fs::write(dir.join("state").join("inventory.sha256"), "0".repeat(64)).unwrap();
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_800_000).unwrap();
    service.tick(3_800_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}

#[cfg(target_os = "linux")]
#[test]
fn a_failed_inventory_report_is_retried_next_tick() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-retry");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(503)), // inventory fails
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // inventory retried
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    let report = service.tick(0).unwrap();
    assert!(report.inventory_error.is_some());
    let report = service.tick(60_000).unwrap();
    assert_eq!(report.inventory_error, None);
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        paths,
        [
            "/v1/enroll",
            "/v1/heartbeat",
            "/v1/inventory",
            "/v1/heartbeat",
            "/v1/inventory"
        ]
    );
}

#[test]
fn no_inventory_without_the_packages_collector() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-disabled");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![issue(&pki, 10_000_000), Box::new(|_: &Seen| status(204))],
    );
    let config = write_config(&dir, &pki, &url, "collectors = [\"processes\", \"ports\"]");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/enroll", "/v1/heartbeat"]);
}

/// M1 limits review: an inventory the platform refuses (4xx) is not sent
/// again every minute; it is sent again when it changes or after a restart.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_inventory_is_not_resent_until_it_changes() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-refused");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(400)), // inventory refused
            Box::new(|_: &Seen| status(400)), // and uncompressed (a platform before P11 would take it)
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // heartbeat (restart)
            Box::new(|_: &Seen| status(204)), // inventory sent again
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    let report = service.tick(0).unwrap();
    assert!(
        report.inventory_error.is_some(),
        "the refusal is reported once"
    );
    for minute in 1..=2 {
        let report = service.tick(minute * 60_000).unwrap();
        assert_eq!(report.inventory_error, None);
    }
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        paths,
        [
            "/v1/enroll",
            "/v1/heartbeat",
            "/v1/inventory",
            "/v1/inventory",
            "/v1/heartbeat",
            "/v1/heartbeat"
        ]
    );
    drop(service);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(200_000).unwrap();
    service.tick(200_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}

/// An inventory that keeps failing (unstable link, busy platform) is retried
/// with a back-off, 1, 2, 4 … minutes up to an hour, not re-uploaded every
/// minute; the first success ends it.
#[cfg(target_os = "linux")]
#[test]
fn a_failing_inventory_backs_off() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-backoff");
    let ok = || -> Box<dyn Fn(&Seen) -> openvibes_testkit::Reply + Send> {
        Box::new(|_: &Seen| status(204))
    };
    let busy = || -> Box<dyn Fn(&Seen) -> openvibes_testkit::Reply + Send> {
        Box::new(|_: &Seen| status(503))
    };
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            ok(),
            busy(), // 0 s: heartbeat, inventory fails (next try at 60 s)
            ok(),
            busy(), // 60 s: fails again (next at 180 s)
            ok(),   // 120 s: waiting
            ok(),
            busy(), // 180 s: fails (next at 420 s)
            ok(),   // 240 s
            ok(),   // 300 s
            ok(),
            ok(), // 420 s: sent
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    for second in [0, 60, 120, 180, 240, 300, 420] {
        service.tick(second * 1_000).unwrap();
    }
    let inventories = requested(&seen)
        .into_iter()
        .filter(|(path, _)| path == "/v1/inventory")
        .count();
    assert_eq!(inventories, 4, "attempts at 0, 60, 180 and 420 s");
}

/// Rewrites the stored base as if the host had one package less and one
/// more than now, with a matching `inventory.sha256`; returns the digest.
#[cfg(target_os = "linux")]
fn fake_base(state: &Path) -> (String, String, String) {
    let base: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("inventory-base.json")).unwrap()).unwrap();
    let os: OsRelease = serde_json::from_value(base["os"].clone()).unwrap();
    let kernel = base["running_kernel"].as_str().map(str::to_owned);
    let mut packages: Vec<InstalledPackage> =
        serde_json::from_value(base["packages"].clone()).unwrap();
    let dropped = packages.remove(0);
    packages.push(
        serde_json::from_value(serde_json::json!(
        {"manager": "rpm", "name": "openvibes-test-gone", "version": "1"}))
        .unwrap(),
    );
    let digest = hex(&inventory_fingerprint(
        &os,
        kernel.as_deref(),
        packages.iter().map(NormalizedPackage::from),
    ));
    fs::write(
        state.join("inventory-base.json"),
        serde_json::to_vec(&serde_json::json!(
        {"os": os, "running_kernel": kernel, "packages": packages}))
        .unwrap(),
    )
    .unwrap();
    fs::write(state.join("inventory.sha256"), &digest).unwrap();
    (digest, dropped.name, "openvibes-test-gone".into())
}

#[cfg(target_os = "linux")]
#[test]
fn changes_follow_the_first_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-changes");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // full inventory
            Box::new(|_: &Seen| status(204)), // heartbeat (restart)
            Box::new(|_: &Seen| status(204)), // changes
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let first: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(first, ["/v1/enroll", "/v1/heartbeat", "/v1/inventory"]);
    assert!(
        state.join("inventory-base.json").exists(),
        "base kept after the 2xx"
    );
    let real = fs::read_to_string(state.join("inventory.sha256")).unwrap();
    drop(service);
    let (base, dropped, gone) = fake_base(&state);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let sent = requested(&seen);
    assert_eq!(
        sent.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        ["/v1/heartbeat", "/v1/inventory/changes"]
    );
    let changes: serde_json::Value = serde_json::from_slice(&sent[1].1).unwrap();
    assert_eq!(changes["base_sha256"], base.as_str());
    assert_eq!(changes["sha256"], real.trim());
    assert_eq!(changes["added"].as_array().unwrap().len(), 1);
    assert_eq!(changes["added"][0]["name"], dropped.as_str());
    assert_eq!(changes["removed"][0]["name"], gone.as_str());
    assert_eq!(
        fs::read_to_string(state.join("inventory.sha256"))
            .unwrap()
            .trim(),
        real.trim()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_resync_or_an_old_platform_gets_the_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-resync");
    let resync = serde_json::json!({"schema_version": 1, "code": "inventory_resync"});
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 100_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // full
            Box::new(|_: &Seen| status(204)), // heartbeat (restart)
            Box::new(move |_: &Seen| openvibes_testkit::Reply {
                status: 409,
                ..json(&resync)
            }),
            Box::new(|_: &Seen| status(204)), // full, same tick
            Box::new(|_: &Seen| status(204)), // heartbeat (restart)
            Box::new(|_: &Seen| status(404)), // changes: an older platform
            Box::new(|_: &Seen| status(204)), // full, same tick
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let _ = requested(&seen);
    for at in [3_600_000, 7_200_000] {
        drop(service);
        let _ = fake_base(&state);
        service = Service::open(load_config(&config).unwrap()).unwrap();
        service.scan_if_due(at).unwrap();
        assert_eq!(
            service.tick(at).unwrap().inventory_error,
            None,
            "no error for a fallback"
        );
        let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
        assert_eq!(
            paths,
            ["/v1/heartbeat", "/v1/inventory/changes", "/v1/inventory"]
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_corrupt_base_means_a_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-corrupt-base");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(204)), // heartbeat, full
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(204)), // heartbeat, full
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let _ = requested(&seen);
    drop(service);
    fake_base(&state);
    fs::write(state.join("inventory-base.json"), b"{\"os\": trunc").unwrap();
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}

#[cfg(target_os = "linux")]
#[test]
fn large_changes_are_sent_in_full_and_no_base_before_a_2xx() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-large-changes");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(503)), // heartbeat, full fails
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(204)), // heartbeat, full
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(204)), // heartbeat (restart), full
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    assert!(
        !state.join("inventory-base.json").exists(),
        "no base without a 2xx"
    );
    service.tick(60_000).unwrap();
    assert!(state.join("inventory-base.json").exists());
    drop(service);
    // A base with nothing in common with the host: changes > half the report.
    let base: serde_json::Value =
        serde_json::from_slice(&fs::read(state.join("inventory-base.json")).unwrap()).unwrap();
    let os: OsRelease = serde_json::from_value(base["os"].clone()).unwrap();
    let count = base["packages"].as_array().unwrap().len();
    let packages: Vec<InstalledPackage> = (0..count)
        .map(|i| {
            serde_json::from_value(serde_json::json!(
        {"manager": "rpm", "name": format!("other-{i}"), "version": "1"}))
            .unwrap()
        })
        .collect();
    let digest = hex(&inventory_fingerprint(
        &os,
        None,
        packages.iter().map(NormalizedPackage::from),
    ));
    fs::write(
        state.join("inventory-base.json"),
        serde_json::to_vec(&serde_json::json!(
        {"os": os, "running_kernel": null, "packages": packages}))
        .unwrap(),
    )
    .unwrap();
    fs::write(state.join("inventory.sha256"), &digest).unwrap();
    let _ = requested(&seen);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    service.tick(3_600_000).unwrap();
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(paths, ["/v1/heartbeat", "/v1/inventory"]);
}

/// Review: an agent upgraded before its platform. The platform before P11
/// refuses a gzip body (400); the agent sends the full report again,
/// uncompressed, in the same tick, and the refusal is not reported.
#[cfg(target_os = "linux")]
#[test]
fn a_platform_before_p11_gets_uncompressed_full_reports() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-before-p11");
    let before_p11 = || -> Box<dyn Fn(&Seen) -> openvibes_testkit::Reply + Send> {
        Box::new(|seen: &Seen| {
            if seen.content_encoding.is_some() {
                status(400)
            } else {
                status(204)
            }
        })
    };
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            before_p11(),                     // gzip full: 400
            before_p11(),                     // plain full: 204
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    assert_eq!(service.tick(0).unwrap().inventory_error, None);
    let sent: Vec<Seen> = seen.try_iter().collect();
    let paths: Vec<&str> = sent.iter().map(|s| s.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/v1/enroll",
            "/v1/heartbeat",
            "/v1/inventory",
            "/v1/inventory"
        ]
    );
    assert_eq!(sent[3].content_encoding, None, "sent again uncompressed");
    assert!(dir.join("state").join("inventory-base.json").exists());
}

/// Review: a change set refused for any other reason (a proxy's 413, a
/// 400) is followed by the full report, so the platform does not keep a
/// stale inventory until the next change.
#[cfg(target_os = "linux")]
#[test]
fn a_refused_change_set_is_followed_by_the_full_report() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("inventory-changes-refused");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // full
            Box::new(|_: &Seen| status(204)), // heartbeat (restart)
            Box::new(|_: &Seen| status(413)), // changes refused
            Box::new(|_: &Seen| status(204)), // full, same tick
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let state = dir.join("state");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let _ = requested(&seen);
    drop(service);
    let _ = fake_base(&state);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(3_600_000).unwrap();
    assert_eq!(service.tick(3_600_000).unwrap().inventory_error, None);
    let paths: Vec<String> = requested(&seen).into_iter().map(|(p, _)| p).collect();
    assert_eq!(
        paths,
        ["/v1/heartbeat", "/v1/inventory/changes", "/v1/inventory"]
    );
}

fn heartbeat_json(seen: &std::sync::mpsc::Receiver<Seen>) -> serde_json::Value {
    let heartbeat = seen
        .try_iter()
        .find(|s| s.path == "/v1/heartbeat")
        .expect("a heartbeat was sent");
    serde_json::from_slice(&heartbeat.decoded_body()).unwrap()
}

/// P12: every heartbeat carries the health report.
#[test]
fn heartbeats_carry_health() {
    let pki = Arc::new(Pki::new());
    let dir = scratch("health");
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // inventory
        ],
    );
    let config = write_config(&dir, &pki, &url, "");
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(0).unwrap();
    service.tick(0).unwrap();
    let health = &heartbeat_json(&seen)["health"];
    assert_eq!(health["queue"]["pending"], 0);
    assert_eq!(
        health["queue"]["max_bytes"],
        openvibes_core::ResourceLimits::V1.queue_bytes
    );
    assert_eq!(health["queue"]["dropped_total"], 0);
    assert_eq!(health["storage_errors"], 0);
}

/// The last scan and the configured rule sets reach the next heartbeat.
#[test]
fn a_scan_shows_up_in_the_next_heartbeat() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let pki = Arc::new(Pki::new());
    let dir = scratch("health-scan");
    let public = URL_SAFE_NO_PAD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    // A rule set whose bundle file does not exist yet: the scan reports it
    // without a version.
    let extra = format!(
        "[[rule_sets]]\nid = \"baseline\"\nbundle_file = {:?}\n\
         trusted_keys = [{{ issuer_key_id = \"org.rules\", public_key = \"{public}\" }}]\n",
        dir.join("missing.json"),
    );
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            issue(&pki, 10_000_000),
            Box::new(|_: &Seen| status(204)), // heartbeat
            Box::new(|_: &Seen| status(204)), // inventory
        ],
    );
    let config = write_config(&dir, &pki, &url, &extra);
    let mut service = Service::open(load_config(&config).unwrap()).unwrap();
    service.scan_if_due(1_000_000).unwrap();
    service.tick(1_000_000).unwrap();
    let health = &heartbeat_json(&seen)["health"];
    assert_eq!(health["last_scan"]["finished_at_unix_ms"], 1_000_000);
    assert_eq!(health["last_scan"]["interval_s"], 3_600);
    assert_eq!(health["rule_sets"][0]["id"], "baseline");
    assert!(health["rule_sets"][0]["version"].is_null());
}
