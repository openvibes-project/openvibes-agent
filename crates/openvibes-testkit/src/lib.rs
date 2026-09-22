#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Test-only mock OpenVIBES Platform: a real `rustls` server backed by an
//! `rcgen` CA, answering one scripted reply per connection. Never a runtime
//! dependency.

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
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
pub struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Default for Pki {
    fn default() -> Self {
        Self::new()
    }
}

impl Pki {
    /// Creates a CA with a fresh key.
    #[must_use]
    pub fn new() -> Self {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        Self {
            ca: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    /// PEM of the CA certificate, for `TransportConfig::server_roots_pem`.
    #[must_use]
    pub fn roots_pem(&self) -> Vec<u8> {
        self.ca.pem().into_bytes()
    }

    /// Issues a client certificate for a CSR, as the platform CA would.
    #[must_use]
    pub fn issue_client(&self, csr_pem: &str) -> String {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.signed_by(&self.ca).unwrap().pem()
    }

    /// A server certificate for `127.0.0.1` issued by this CA; the client
    /// certificate is required or optional, over TLS 1.2 only or any version.
    #[must_use]
    pub fn server_config(&self, require_client_cert: bool, tls12_only: bool) -> Arc<ServerConfig> {
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
pub struct Seen {
    /// Request path.
    pub path: String,
    /// Request body.
    pub body: Vec<u8>,
    /// Whether the client presented a certificate.
    pub client_cert: bool,
}

/// The mock platform's answer to one request.
pub struct Reply {
    /// HTTP status code.
    pub status: u16,
    /// Extra header lines, each ending in `\r\n`.
    pub headers: &'static str,
    /// Response body.
    pub body: Vec<u8>,
    /// Never answer, to exercise client timeouts.
    pub stall: bool,
}

/// A 200 response with a JSON body.
#[must_use]
pub fn json(value: &impl serde::Serialize) -> Reply {
    Reply {
        status: 200,
        headers: "",
        body: serde_json::to_vec(value).unwrap(),
        stall: false,
    }
}

/// An empty response with `status`.
#[must_use]
pub fn status(status: u16) -> Reply {
    Reply {
        status,
        headers: "",
        body: Vec::new(),
        stall: false,
    }
}

/// Computes the reply to one request.
pub type Handler = Box<dyn FnOnce(&Seen) -> Reply + Send>;

/// Serves one connection per handler, then stops. Returns the base URL and
/// every request that completed a TLS handshake.
#[must_use]
pub fn serve(config: Arc<ServerConfig>, handlers: Vec<Handler>) -> (String, mpsc::Receiver<Seen>) {
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
