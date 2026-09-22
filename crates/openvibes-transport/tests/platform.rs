//! Transport behaviour against a local mock platform speaking real TLS:
//! enrollment into mTLS, pinned trust, TLS 1.3 only, and bounded, redirect-free
//! requests whose failures map to fixed categories.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use openvibes_core::{
    Confidence, DeliveryAcknowledgement, EnrollmentResponse, EnrollmentToken, Finding,
    FindingBatch, Heartbeat, Identifier, ResourceLimits, SchemaVersion, Severity,
};
use openvibes_transport::{
    ClientIdentity, HostKey, PlatformClient, TransportConfig, TransportError,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer,
    ExtendedKeyUsagePurpose, IsCa, KeyPair,
};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};

/// A test certificate authority standing in for the platform's PKI.
struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            ca: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    fn roots_pem(&self) -> Vec<u8> {
        self.ca.pem().into_bytes()
    }

    /// Issues a client certificate for a CSR, as the platform CA would.
    fn issue_client(&self, csr_pem: &str) -> String {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.signed_by(&self.ca).unwrap().pem()
    }

    fn server_config(&self, require_client_cert: bool, tls12_only: bool) -> Arc<ServerConfig> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = params.signed_by(&key, &self.ca).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(roots.into(), provider.clone());
        let verifier = if require_client_cert {
            verifier.build()
        } else {
            verifier.allow_unauthenticated().build()
        }
        .unwrap();
        let versions: &[_] = if tls12_only {
            &[&rustls::version::TLS12]
        } else {
            rustls::ALL_VERSIONS
        };
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        Arc::new(config)
    }
}

/// One request as the mock platform saw it.
struct Seen {
    path: String,
    body: Vec<u8>,
    client_cert: bool,
}

struct Reply {
    status: u16,
    headers: &'static str,
    body: Vec<u8>,
    stall: bool,
}

fn json(value: &impl serde::Serialize) -> Reply {
    Reply {
        status: 200,
        headers: "",
        body: serde_json::to_vec(value).unwrap(),
        stall: false,
    }
}

fn status(status: u16) -> Reply {
    Reply {
        status,
        headers: "",
        body: Vec::new(),
        stall: false,
    }
}

type Handler = Box<dyn FnOnce(&Seen) -> Reply + Send>;

/// Serves one connection per handler, then stops. Returns the base URL and
/// every request that completed a TLS handshake.
fn serve(config: Arc<ServerConfig>, handlers: Vec<Handler>) -> (String, mpsc::Receiver<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("https://{}", listener.local_addr().unwrap());
    let (seen_tx, seen_rx) = mpsc::channel();
    thread::spawn(move || {
        for handler in handlers {
            let (tcp, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(config.clone()).unwrap();
            let mut stream = BufReader::new(StreamOwned::new(connection, tcp));
            let mut request_line = String::new();
            if stream.read_line(&mut request_line).is_err() {
                // Handshake refused: flush the alert as a real server would.
                let StreamOwned { conn, sock } = stream.get_mut();
                let _ = conn.write_tls(sock);
                continue;
            }
            let mut length = 0;
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            let seen = Seen {
                path: request_line.split(' ').nth(1).unwrap().to_owned(),
                body,
                client_cert: stream.get_ref().conn.peer_certificates().is_some(),
            };
            let reply = handler(&seen);
            let _ = seen_tx.send(seen);
            if reply.stall {
                thread::sleep(Duration::from_secs(3));
                continue;
            }
            let stream = stream.get_mut();
            let _ = write!(
                stream,
                "HTTP/1.1 {} X\r\ncontent-length: {}\r\nconnection: close\r\n{}\r\n",
                reply.status,
                reply.body.len(),
                reply.headers
            );
            let _ = stream.write_all(&reply.body);
            let _ = stream.flush();
            stream.conn.send_close_notify();
            let _ = stream.flush();
        }
    });
    (base_url, seen_rx)
}

fn config(base_url: &str, pki: &Pki) -> TransportConfig {
    TransportConfig {
        base_url: base_url.to_owned(),
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
        observed_at_unix_ms: 1,
        capabilities: Vec::new(),
    };
    assert_eq!(client.heartbeat(&heartbeat), Ok(()));

    let delivery = seen.recv().unwrap();
    assert_eq!(delivery.path, "/v1/findings");
    assert!(delivery.client_cert);
    let batch: FindingBatch = serde_json::from_slice(&delivery.body).unwrap();
    assert_eq!(batch.findings, [finding("f.a")]);
    assert_eq!(seen.recv().unwrap().path, "/v1/heartbeat");
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
