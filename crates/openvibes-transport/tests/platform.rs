//! Transport behaviour against a local mock platform speaking real TLS:
//! enrollment into mTLS, pinned trust, TLS 1.3 only, and bounded, redirect-free
//! requests whose failures map to fixed categories.

use std::{sync::Arc, time::Duration};

use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, EnrollmentToken, Finding,
    FindingBatch, Heartbeat, Identifier, ResourceLimits, SchemaVersion, Severity,
};
use openvibes_testkit::{Pki, Reply, Seen, json, serve, status};
use openvibes_transport::{
    ClientIdentity, DEFAULT_PLATFORM_PORT, HostKey, PlatformClient, TransportConfig, TransportError,
};
use rcgen::CertificateSigningRequestParams;

fn config(base_url: &str, pki: &Pki) -> TransportConfig {
    TransportConfig {
        base_url: base_url.to_owned(),
        default_port: DEFAULT_PLATFORM_PORT,
        server_roots_pem: pki.roots_pem(),
        proxy_url: None,
        limits: ResourceLimits::V1,
    }
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
        severity: Severity::Low,
        confidence: Confidence::new(50).unwrap(),
        message: "synthetic".into(),
        evidence: Vec::new(),
    }
}

fn ack(ids: &[&str]) -> DeliveryAcknowledgement {
    DeliveryAcknowledgement {
        schema_version: SchemaVersion::V1,
        accepted_finding_ids: ids.iter().map(|name| id(name)).collect(),
        acknowledged_at_unix_ms: 2,
        rejected_findings: Vec::new(),
    }
}

/// Enrolls against a fresh platform and returns the resulting identity.
fn enrolled_identity(pki: &Arc<Pki>) -> ClientIdentity {
    let issuer = pki.clone();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(move |seen: &Seen| {
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            let csr = request["csr_pem"].as_str().unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec![issuer.issue_client(csr)],
                expires_at_unix_ms: 10_000,
            })
        })],
    );
    let key = HostKey::generate().unwrap();
    let client = PlatformClient::new(&config(&url, pki), None).unwrap();
    let response = client
        .enroll(&EnrollmentToken::new("one-time").unwrap(), &key)
        .unwrap();
    ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem()).unwrap()
}

#[test]
fn enrollment_yields_an_identity_the_platform_accepts_over_mtls() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);

    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![
            Box::new(|_: &Seen| json(&ack(&["f.a"]))),
            Box::new(|_: &Seen| status(204)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), Some(&identity)).unwrap();
    assert_eq!(client.deliver(&[finding("f.a")]), Ok(ack(&["f.a"])));
    let heartbeat = Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: id("agent.1"),
        scanner_version: "0.1.0".into(),
        hostname: Some("test-host".into()),
        observed_at_unix_ms: 1,
        capabilities: Vec::new(),
        health: None,
        match_sha256: None,
    };
    assert_eq!(client.heartbeat(&heartbeat), Ok(()));

    let delivery = seen.recv().unwrap();
    assert_eq!(delivery.path, "/v1/findings");
    assert!(delivery.client_cert);
    let batch: FindingBatch = serde_json::from_slice(&delivery.body).unwrap();
    assert_eq!(batch.findings, [finding("f.a")]);
    let heartbeat_request = seen.recv().unwrap();
    assert_eq!(heartbeat_request.path, "/v1/heartbeat");
    let sent: Heartbeat = serde_json::from_slice(&heartbeat_request.body).unwrap();
    assert_eq!(sent, heartbeat);
}

#[test]
fn enrollment_request_carries_the_token_and_a_csr() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(401))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let key = HostKey::generate().unwrap();
    assert_eq!(
        client.enroll(&EnrollmentToken::new("one-time").unwrap(), &key),
        Err(TransportError::Unauthorized)
    );
    let request: serde_json::Value = serde_json::from_slice(&seen.recv().unwrap().body).unwrap();
    assert_eq!(request["token"], "one-time");
    assert_eq!(request["csr_pem"], key.csr_pem());
    assert!(CertificateSigningRequestParams::from_pem(key.csr_pem()).is_ok());
    assert_eq!(format!("{key:?}"), "HostKey([REDACTED])");
}

#[test]
fn mtls_endpoint_refuses_a_client_without_identity() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(200))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    // TLS 1.3 rejects the client after its handshake completes, so the alert
    // races the request write: either category is a correct refusal.
    let result = client.deliver(&[finding("f.a")]);
    assert!(
        matches!(result, Err(TransportError::Tls | TransportError::Connect)),
        "{result:?}"
    );
    assert!(seen.recv().is_err());
}

#[test]
fn server_from_an_unpinned_ca_is_refused() {
    let (pki, other) = (Pki::new(), Pki::new());
    let (url, seen) = serve(
        other.server_config(false, false),
        vec![Box::new(|_: &Seen| status(200))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    assert_eq!(client.deliver(&[finding("f.a")]), Err(TransportError::Tls));
    assert!(seen.recv().is_err());
}

#[test]
fn tls_1_2_only_server_is_refused() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, true),
        vec![Box::new(|_: &Seen| status(200))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    assert_eq!(client.deliver(&[finding("f.a")]), Err(TransportError::Tls));
    assert!(seen.recv().is_err());
}

#[test]
fn redirects_are_not_followed() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| Reply {
                headers: "location: /elsewhere\r\n",
                ..status(307)
            }),
            Box::new(|_: &Seen| json(&ack(&["f.a"]))),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    assert_eq!(
        client.deliver(&[finding("f.a")]),
        Err(TransportError::Rejected)
    );
    assert_eq!(seen.recv().unwrap().path, "/v1/findings");
    assert!(seen.recv_timeout(Duration::from_millis(500)).is_err());
}

#[test]
fn oversized_and_invalid_responses_are_refused() {
    let pki = Pki::new();
    let mut bad_ack = ack(&["f.a"]);
    bad_ack.acknowledged_at_unix_ms = -1;
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| Reply {
                body: vec![b' '; 4_097],
                ..status(200)
            }),
            Box::new(move |_: &Seen| json(&bad_ack)),
            Box::new(|_: &Seen| Reply {
                body: b"{not json".to_vec(),
                ..status(200)
            }),
        ],
    );
    let mut config = config(&url, &pki);
    config.limits.document_bytes = 4_096;
    let client = PlatformClient::new(&config, None).unwrap();
    let batch = [finding("f.a")];
    assert_eq!(
        client.deliver(&batch),
        Err(TransportError::ResponseTooLarge)
    );
    assert_eq!(client.deliver(&batch), Err(TransportError::InvalidResponse));
    assert_eq!(client.deliver(&batch), Err(TransportError::InvalidResponse));
}

#[test]
fn stalled_platform_times_out() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| Reply {
            stall: true,
            ..status(200)
        })],
    );
    let mut config = config(&url, &pki);
    config.limits.network_request_seconds = 1;
    let client = PlatformClient::new(&config, None).unwrap();
    assert_eq!(
        client.deliver(&[finding("f.a")]),
        Err(TransportError::Timeout)
    );
}

#[test]
fn unsafe_configuration_and_requests_are_refused() {
    let pki = Pki::new();
    let good = config("https://platform.example", &pki);
    let too_slow = ResourceLimits {
        network_request_seconds: ResourceLimits::V1.network_request_seconds + 1,
        ..ResourceLimits::V1
    };
    for bad in [
        TransportConfig {
            base_url: "http://platform.example".into(),
            ..good.clone()
        },
        TransportConfig {
            base_url: "https://platform.example/".into(),
            ..good.clone()
        },
        TransportConfig {
            server_roots_pem: Vec::new(),
            ..good.clone()
        },
        TransportConfig {
            proxy_url: Some("not a url".into()),
            ..good.clone()
        },
        TransportConfig {
            limits: too_slow,
            ..good.clone()
        },
    ] {
        assert_eq!(
            PlatformClient::new(&bad, None).err(),
            Some(TransportError::InvalidConfig)
        );
    }
    // Invalid documents are refused before any connection is attempted.
    let client = PlatformClient::new(&good, None).unwrap();
    assert_eq!(client.deliver(&[]), Err(TransportError::InvalidRequest));
    assert_eq!(
        ClientIdentity::from_pem(&["garbage".into()], "garbage").err(),
        Some(TransportError::InvalidIdentity)
    );
}

#[test]
fn renewal_posts_a_new_csr_over_mtls() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let issuer = pki.clone();
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(move |seen: &Seen| {
            let request: serde_json::Value = serde_json::from_slice(&seen.body).unwrap();
            json(&EnrollmentResponse {
                schema_version: SchemaVersion::V1,
                agent_id: id("agent.1"),
                certificate_chain_pem: vec![
                    issuer.issue_client(request["csr_pem"].as_str().unwrap()),
                ],
                expires_at_unix_ms: 20_000,
            })
        })],
    );
    let client = PlatformClient::new(&config(&url, &pki), Some(&identity)).unwrap();
    let key = HostKey::generate().unwrap();
    let renewed = client.renew(&key).unwrap();
    assert_eq!(renewed.expires_at_unix_ms, 20_000);
    let request = seen.recv().unwrap();
    assert_eq!(request.path, "/v1/renew");
    assert!(request.client_cert);
    let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["csr_pem"], key.csr_pem());
    ClientIdentity::from_pem(&renewed.certificate_chain_pem, key.expose_key_pem()).unwrap();
}

#[test]
fn only_a_structured_revocation_is_reported_as_revoked() {
    let pki = Pki::new();
    let revoked = br#"{"schema_version":1,"code":"identity_revoked"}"#.to_vec();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(move |_: &Seen| Reply {
                body: revoked,
                ..status(403)
            }),
            Box::new(|_: &Seen| status(403)),
            Box::new(|_: &Seen| Reply {
                body: br#"{"schema_version":1,"code":"something_else"}"#.to_vec(),
                ..status(403)
            }),
            Box::new(|_: &Seen| Reply {
                body: br#"{"schema_version":2,"code":"identity_revoked"}"#.to_vec(),
                ..status(401)
            }),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let batch = [finding("f.a")];
    assert_eq!(client.deliver(&batch), Err(TransportError::IdentityRevoked));
    // A bare 403, an unknown code, or a wrong schema version (from a
    // misconfigured proxy or a future platform) must not destroy the identity.
    for _ in 0..3 {
        assert_eq!(client.deliver(&batch), Err(TransportError::Unauthorized));
    }
}

/// Protocol: the CSR subject is empty; the platform assigns the agent id.
/// A non-empty subject is refused by the platform's CSR check.
#[test]
fn host_key_csr_has_an_empty_subject() {
    let key = HostKey::generate().unwrap();
    let csr = rcgen::CertificateSigningRequestParams::from_pem(key.csr_pem()).unwrap();
    assert_eq!(csr.params.distinguished_name.iter().count(), 0);
}

#[test]
fn a_stored_host_key_signs_a_fresh_csr_for_the_same_public_key() {
    let key = HostKey::generate().unwrap();
    let again = HostKey::from_key_pem(key.expose_key_pem()).unwrap();
    use rcgen::PublicKeyData;
    let spki = |pem: &str| {
        rcgen::CertificateSigningRequestParams::from_pem(pem)
            .unwrap()
            .public_key
            .der_bytes()
            .to_vec()
    };
    assert_eq!(spki(again.csr_pem()), spki(key.csr_pem()));
    let csr = rcgen::CertificateSigningRequestParams::from_pem(again.csr_pem()).unwrap();
    assert_eq!(csr.params.distinguished_name.iter().count(), 0);
    assert!(HostKey::from_key_pem("not a key").is_err());
}

fn big_inventory(packages: usize) -> openvibes_core::InventoryReport {
    let mut report: openvibes_core::InventoryReport = serde_json::from_str(
        r#"{"schema_version":1,"agent_id":"agent.1","os":{"id":"fedora","version_id":"44"},
            "collected_at_unix_ms":1,"packages":[]}"#,
    )
    .unwrap();
    report.packages = (0..packages)
        .map(|i| {
            serde_json::from_value(serde_json::json!({
                "manager": "rpm", "name": format!("texlive-package-{i:06}"),
                "version": "20250308", "release": "91.fc44", "arch": "noarch",
                "vendor": "Fedora Project"
            }))
            .unwrap()
        })
        .collect();
    report
}

/// Inventories may be up to 8 MiB (M1 limits review); every other request
/// stays within 1 MiB.
#[test]
fn inventories_may_exceed_one_mib_and_nothing_else_may() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![Box::new(|_: &Seen| status(204))],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let report = big_inventory(15_000);
    client.report_inventory(&report).unwrap();
    assert!(seen.recv().unwrap().decoded_body().len() > 1024 * 1024);
    let mut long = finding("f.long");
    long.message = "x".repeat(4000);
    let batch: Vec<Finding> = (0..300)
        .map(|i| Finding {
            finding_id: id(&format!("f.{i}")),
            ..long.clone()
        })
        .collect();
    assert_eq!(client.deliver(&batch), Err(TransportError::InvalidRequest));
    assert_eq!(
        client.report_inventory(&big_inventory(70_000)),
        Err(TransportError::InvalidRequest),
        "over 50,000 packages"
    );
}

/// A 5xx means try again later; any other refusal is final for that request.
#[test]
fn server_errors_are_unavailable_other_refusals_rejected() {
    let pki = Pki::new();
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(503)),
            Box::new(|_: &Seen| status(500)),
            Box::new(|_: &Seen| status(408)),
            Box::new(|_: &Seen| status(429)),
            Box::new(|_: &Seen| status(400)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let report = big_inventory(1);
    // 5xx, a request timeout (408: a large body on a slow link) and too many
    // requests (429) are worth retrying; other refusals are final.
    for _ in 0..4 {
        assert_eq!(
            client.report_inventory(&report),
            Err(TransportError::Unavailable)
        );
    }
    assert_eq!(
        client.report_inventory(&report),
        Err(TransportError::Rejected)
    );
}

fn changes() -> openvibes_core::InventoryChanges {
    serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/inventory-changes/valid.json"
    ))
    .unwrap()
}

/// Both inventory endpoints are gzip-compressed (P11); nothing else is.
#[test]
fn inventories_are_sent_gzip_compressed() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(204)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let report = big_inventory(3_000);
    client.report_inventory(&report).unwrap();
    client.report_inventory_changes(&changes()).unwrap();
    for (seen, path) in seen
        .iter()
        .take(2)
        .zip(["/v1/inventory", "/v1/inventory/changes"])
    {
        assert_eq!(seen.path, path);
        assert_eq!(seen.content_encoding.as_deref(), Some("gzip"));
        let json: serde_json::Value = serde_json::from_slice(&seen.decoded_body()).unwrap();
        assert!(json.is_object());
        // A small change set barely compresses; a full inventory does.
        if path == "/v1/inventory" {
            assert!(
                seen.body.len() < seen.decoded_body().len() / 5,
                "compressed"
            );
        }
    }
}

/// 409 with `inventory_resync` and 404 are the change set's own answers;
/// other refusals stay as before, and 404 elsewhere is still `Rejected`.
#[test]
fn a_change_set_learns_resync_and_missing_endpoint() {
    let pki = Pki::new();
    let resync = serde_json::json!({"schema_version": 1, "code": "inventory_resync"});
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(move |_: &Seen| Reply {
                status: 409,
                ..json(&resync)
            }),
            Box::new(|_: &Seen| status(409)),
            Box::new(|_: &Seen| status(404)),
            Box::new(|_: &Seen| status(404)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    assert_eq!(
        client.report_inventory_changes(&changes()),
        Err(TransportError::InventoryResync)
    );
    assert_eq!(
        client.report_inventory_changes(&changes()),
        Err(TransportError::Rejected),
        "409 without the code"
    );
    assert_eq!(
        client.report_inventory_changes(&changes()),
        Err(TransportError::NotFound)
    );
    assert_eq!(
        client.report_inventory(&big_inventory(1)),
        Err(TransportError::Rejected),
        "404 on /v1/inventory"
    );
}

/// A platform before P11 reads the body as plain JSON, so a gzip body is a
/// 400 there; the same report sent uncompressed is accepted (review).
#[test]
fn an_uncompressed_report_is_available_for_platforms_before_p11() {
    let pki = Pki::new();
    let before_p11 = || -> Box<dyn Fn(&Seen) -> Reply + Send> {
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
        vec![before_p11(), before_p11()],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let report = big_inventory(10);
    assert_eq!(
        client.report_inventory(&report),
        Err(TransportError::Rejected)
    );
    client.report_inventory_uncompressed(&report).unwrap();
    let plain = seen.iter().nth(1).unwrap();
    assert_eq!(plain.content_encoding, None);
    let json: serde_json::Value = serde_json::from_slice(&plain.body).unwrap();
    assert_eq!(json["packages"].as_array().unwrap().len(), 10);
}

fn finding_changes() -> openvibes_core::FindingChanges {
    serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/finding-changes/valid.json"
    ))
    .unwrap()
}

/// Finding changes (P13) are gzip-compressed and learn 404 and 409
/// `findings_resync`; an inventory resync code there is only a refusal.
#[test]
fn finding_changes_are_gzip_and_learn_resync_and_missing_endpoint() {
    let pki = Pki::new();
    let reply = |code: &'static str| -> Box<dyn FnOnce(&Seen) -> Reply + Send> {
        Box::new(move |_: &Seen| Reply {
            status: 409,
            ..json(&serde_json::json!({"schema_version": 1, "code": code}))
        })
    };
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(204)),
            Box::new(|_: &Seen| status(404)),
            reply("findings_resync"),
            reply("inventory_resync"),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let changes = finding_changes();
    assert_eq!(client.report_finding_changes(&changes), Ok(()));
    let sent = seen.recv().unwrap();
    assert_eq!(sent.path, "/v1/findings/changes");
    assert_eq!(sent.content_encoding.as_deref(), Some("gzip"));
    let body: openvibes_core::FindingChanges =
        serde_json::from_slice(&sent.decoded_body()).unwrap();
    assert_eq!(body, changes);
    assert_eq!(
        client.report_finding_changes(&changes),
        Err(TransportError::NotFound)
    );
    assert_eq!(
        client.report_finding_changes(&changes),
        Err(TransportError::FindingsResync)
    );
    assert_eq!(
        client.report_finding_changes(&changes),
        Err(TransportError::Rejected),
        "another code on this endpoint"
    );
}

/// A heartbeat answered 409 `findings_resync` (P13) says so; a bare 409 on a
/// heartbeat is still a refusal.
#[test]
fn a_heartbeat_learns_findings_resync() {
    let pki = Pki::new();
    let resync = serde_json::json!({"schema_version": 1, "code": "findings_resync"});
    let (url, _) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(move |_: &Seen| Reply {
                status: 409,
                ..json(&resync)
            }),
            Box::new(|_: &Seen| status(409)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let heartbeat = Heartbeat {
        schema_version: SchemaVersion::V1,
        agent_id: id("agent.1"),
        scanner_version: "0.1.0".into(),
        hostname: None,
        observed_at_unix_ms: 1,
        capabilities: Vec::new(),
        health: None,
        match_sha256: None,
    };
    assert_eq!(
        client.heartbeat(&heartbeat),
        Err(TransportError::FindingsResync)
    );
    assert_eq!(client.heartbeat(&heartbeat), Err(TransportError::Rejected));
}

fn alarm_batch() -> openvibes_core::AlarmBatch {
    serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/alarm-batch/valid.json"
    ))
    .unwrap()
}

/// Alarms (P14) go gzip-compressed; 404 is a platform before P14, 400 and
/// 413 refuse the batch for good, and an invalid batch is never sent.
#[test]
fn alarms_are_gzip_and_learn_missing_endpoint_and_refusals() {
    let pki = Pki::new();
    let (url, seen) = serve(
        pki.server_config(false, false),
        vec![
            Box::new(|_: &Seen| status(202)),
            Box::new(|_: &Seen| status(404)),
            Box::new(|_: &Seen| status(400)),
            Box::new(|_: &Seen| status(413)),
            Box::new(|_: &Seen| status(405)),
            Box::new(|_: &Seen| status(421)),
            Box::new(|_: &Seen| status(302)),
        ],
    );
    let client = PlatformClient::new(&config(&url, &pki), None).unwrap();
    let batch = alarm_batch();
    assert_eq!(client.send_alarms(&batch), Ok(()));
    let sent = seen.recv().unwrap();
    assert_eq!(sent.path, "/v1/alarms");
    assert_eq!(sent.content_encoding.as_deref(), Some("gzip"));
    let body: openvibes_core::AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
    assert_eq!(body, batch);
    assert_eq!(client.send_alarms(&batch), Err(TransportError::NotFound));
    assert_eq!(client.send_alarms(&batch), Err(TransportError::Rejected));
    assert_eq!(client.send_alarms(&batch), Err(TransportError::Rejected));
    // A proxy's 405, a 421 or a redirect after a host change: retry, never
    // drop the alarms.
    for _ in 0..3 {
        assert_eq!(client.send_alarms(&batch), Err(TransportError::Unavailable));
    }

    let mut invalid = alarm_batch();
    invalid.alarms.clear();
    assert_eq!(
        client.send_alarms(&invalid),
        Err(TransportError::InvalidRequest)
    );
    // Four requests reached the platform; the invalid batch did not.
    assert_eq!(seen.try_iter().count(), 6);
}
