use std::{fmt, sync::Arc, time::Duration};

use openvibes_core::{
    DeliveryAcknowledgement, EnrollmentRequest, EnrollmentResponse, EnrollmentToken, Finding,
    FindingBatch, Heartbeat, PlatformError, PlatformErrorCode, RenewalRequest, ResourceLimits,
    RuleBundleRequest, SchemaVersion, Validate,
};
use rustls::{SupportedCipherSuite, crypto::CryptoProvider};
use serde::{Serialize, de::DeserializeOwned};
use ureq::{
    Agent,
    config::Config,
    tls::{Certificate, RootCerts, TlsConfig, TlsProvider},
};

use crate::{ClientIdentity, HostKey};

/// Fixed transport failure categories; no payload, URL, or secret is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The base URL is not `https://`, the proxy URL is invalid, the server
    /// roots contain no certificate, or a limit exceeds the V1 ceiling.
    InvalidConfig,
    /// The client certificate chain or private key could not be parsed.
    InvalidIdentity,
    /// Host key or CSR generation failed.
    KeyGeneration,
    /// The outgoing document violates its contract.
    InvalidRequest,
    /// The platform could not be reached.
    Connect,
    /// TLS failed: untrusted or invalid server certificate, a version or
    /// cipher mismatch, or a client certificate the server refused.
    Tls,
    /// A connection or request deadline passed.
    Timeout,
    /// The platform refused the credentials (HTTP 401 or 403) without saying
    /// the identity was revoked. Keep the identity and retry later.
    Unauthorized,
    /// The platform stated the client certificate is revoked. The agent must
    /// discard its identity and re-enroll with a new token.
    IdentityRevoked,
    /// The platform answered with another non-success status or a redirect.
    Rejected,
    /// The response exceeded the document or header size limit.
    ResponseTooLarge,
    /// The response body violates its contract.
    InvalidResponse,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "invalid transport configuration",
            Self::InvalidIdentity => "invalid client identity",
            Self::KeyGeneration => "host key generation failed",
            Self::InvalidRequest => "invalid outgoing platform document",
            Self::Connect => "platform connection failed",
            Self::Tls => "platform TLS handshake failed",
            Self::Timeout => "platform request timed out",
            Self::Unauthorized => "platform refused the credentials",
            Self::IdentityRevoked => "platform revoked the agent identity",
            Self::Rejected => "platform rejected the request",
            Self::ResponseTooLarge => "platform response too large",
            Self::InvalidResponse => "invalid platform response",
        })
    }
}

impl std::error::Error for TransportError {}

impl From<ureq::Error> for TransportError {
    fn from(error: ureq::Error) -> Self {
        use ureq::Error as E;
        match error {
            E::Timeout(_) => Self::Timeout,
            E::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => Self::Timeout,
            E::Io(error)
                if error
                    .get_ref()
                    .is_some_and(|inner| inner.is::<rustls::Error>()) =>
            {
                Self::Tls
            }
            E::Tls(_) | E::Rustls(_) | E::Pem(_) => Self::Tls,
            E::BodyExceedsLimit(_) | E::LargeResponseHeader(..) => Self::ResponseTooLarge,
            E::TooManyRedirects | E::RedirectFailed => Self::Rejected,
            E::RequireHttpsOnly(_) | E::BadUri(_) | E::InvalidProxyUrl => Self::InvalidConfig,
            _ => Self::Connect,
        }
    }
}

/// Port of the agent-facing platform API when the base URL names none. The
/// platform's web interface is a separate service on 443.
pub const DEFAULT_PLATFORM_PORT: u16 = 18423;

/// Port of the rule distribution service when its URL names none.
pub const DEFAULT_DISTRIBUTION_PORT: u16 = 18424;

/// How to reach and authenticate the platform.
#[derive(Clone, Debug)]
pub struct TransportConfig {
    /// Service base URL, `https://` only, without a trailing slash or user
    /// info. Without an explicit port, `default_port` is used.
    pub base_url: String,
    /// [`DEFAULT_PLATFORM_PORT`] for ingest, [`DEFAULT_DISTRIBUTION_PORT`]
    /// for rule distribution.
    pub default_port: u16,
    /// PEM bundle of the only CAs trusted to issue the platform's server
    /// certificate. System trust stores are never consulted.
    pub server_roots_pem: Vec<u8>,
    /// Explicit proxy URL. Proxy environment variables are ignored.
    pub proxy_url: Option<String>,
    /// Size and timeout limits; may tighten but never exceed V1.
    pub limits: ResourceLimits,
}

/// Blocking HTTPS client for the platform API (`openvibes-protocol/spec/contracts-v1.md`).
///
/// TLS 1.3 only, pinned server roots, no redirects, no environment proxies,
/// bounded timeouts, and response bodies bounded by `document_bytes`.
pub struct PlatformClient {
    agent: Agent,
    base_url: String,
    limits: ResourceLimits,
}

impl PlatformClient {
    /// Builds a client. Without `identity` it can only enroll.
    pub fn new(
        config: &TransportConfig,
        identity: Option<&ClientIdentity>,
    ) -> Result<Self, TransportError> {
        let limits = config.limits;
        let v1 = ResourceLimits::V1;
        let valid_limits = (1..=v1.network_connect_seconds)
            .contains(&limits.network_connect_seconds)
            && (1..=v1.network_request_seconds).contains(&limits.network_request_seconds)
            && (1..=v1.document_bytes).contains(&limits.document_bytes)
            && (1..=v1.delivery_batch_items).contains(&limits.delivery_batch_items);
        let base_url =
            with_default_port(&config.base_url, config.default_port).filter(|_| valid_limits);
        let Some(base_url) = base_url else {
            return Err(TransportError::InvalidConfig);
        };
        let roots = ureq::tls::parse_pem(&config.server_roots_pem)
            .filter_map(|item| match item {
                Ok(ureq::tls::PemItem::Certificate(certificate)) => Some(Ok(certificate)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<Certificate<'static>>, _>>()
            .map_err(|_| TransportError::InvalidConfig)?;
        if roots.is_empty() {
            return Err(TransportError::InvalidConfig);
        }
        let proxy = config
            .proxy_url
            .as_deref()
            .map(ureq::Proxy::new)
            .transpose()
            .map_err(|_| TransportError::InvalidConfig)?;
        let tls = TlsConfig::builder()
            .provider(TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(tls13_only())
            .root_certs(RootCerts::new_with_certs(&roots))
            .client_cert(identity.map(ClientIdentity::client_cert))
            .build();
        let agent: Agent = Config::builder()
            .tls_config(tls)
            .https_only(true)
            .max_redirects(0)
            .proxy(proxy)
            .http_status_as_error(false)
            .timeout_connect(Some(Duration::from_secs(limits.network_connect_seconds)))
            .timeout_global(Some(Duration::from_secs(limits.network_request_seconds)))
            .max_response_header_size(16 * 1024)
            .user_agent(concat!("openvibes-agent/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Self {
            agent,
            base_url,
            limits,
        })
    }

    /// Exchanges a single-use token and the host key's CSR for an identity.
    pub fn enroll(
        &self,
        token: &EnrollmentToken,
        key: &HostKey,
    ) -> Result<EnrollmentResponse, TransportError> {
        let request = EnrollmentRequest {
            schema_version: SchemaVersion::V1,
            token: token.clone(),
            csr_pem: key.csr_pem().to_owned(),
        };
        self.post_json("/v1/enroll", &request)
    }

    /// Exchanges the current mTLS identity and a new key's CSR for a fresh
    /// certificate for the same agent.
    pub fn renew(&self, key: &HostKey) -> Result<EnrollmentResponse, TransportError> {
        let request = RenewalRequest {
            schema_version: SchemaVersion::V1,
            csr_pem: key.csr_pem().to_owned(),
        };
        self.post_json("/v1/renew", &request)
    }

    /// Sends one queue batch and returns the platform's acknowledgement.
    /// Suitable as the `send` closure of `SqliteQueue::deliver`.
    pub fn deliver(&self, findings: &[Finding]) -> Result<DeliveryAcknowledgement, TransportError> {
        let batch = FindingBatch {
            schema_version: SchemaVersion::V1,
            findings: findings.to_vec(),
        };
        self.post_json("/v1/findings", &batch)
    }

    /// Reports scanner health; the response body is ignored.
    pub fn heartbeat(&self, heartbeat: &Heartbeat) -> Result<(), TransportError> {
        self.post(heartbeat, "/v1/heartbeat").map(drop)
    }

    /// Asks the distribution service for a rule set's envelope newer than
    /// `request.current_version`. Returns the envelope bytes exactly as
    /// received, for the rule loader to verify, or `None` on `204`.
    pub fn fetch_rule_bundle(
        &self,
        request: &RuleBundleRequest,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        match self.send(request, "/v1/rule-bundle")? {
            (204, _) => Ok(None),
            (200, body) if !body.is_empty() => Ok(Some(body)),
            _ => Err(TransportError::InvalidResponse),
        }
    }

    fn post_json<T, R>(&self, path: &str, request: &T) -> Result<R, TransportError>
    where
        T: Serialize + Validate,
        R: DeserializeOwned + Validate,
    {
        let body = self.post(request, path)?;
        let response: R =
            serde_json::from_slice(&body).map_err(|_| TransportError::InvalidResponse)?;
        response
            .validate(self.limits)
            .map_err(|_| TransportError::InvalidResponse)?;
        Ok(response)
    }

    fn post(
        &self,
        request: &(impl Serialize + Validate),
        path: &str,
    ) -> Result<Vec<u8>, TransportError> {
        self.send(request, path).map(|(_, body)| body)
    }

    /// Sends one validated request; returns the 2xx status and its body.
    fn send(
        &self,
        request: &(impl Serialize + Validate),
        path: &str,
    ) -> Result<(u16, Vec<u8>), TransportError> {
        request
            .validate(self.limits)
            .map_err(|_| TransportError::InvalidRequest)?;
        let body = serde_json::to_vec(request).map_err(|_| TransportError::InvalidRequest)?;
        if body.len() > self.limits.document_bytes {
            return Err(TransportError::InvalidRequest);
        }
        let mut response = self
            .agent
            .post(format!("{}{path}", self.base_url))
            .header("content-type", "application/json")
            .send(&body[..])?;
        let limit = u64::try_from(self.limits.document_bytes).unwrap_or(u64::MAX);
        let status = response.status().as_u16();
        let body = response.body_mut().with_config().limit(limit).read_to_vec();
        match status {
            200..=299 => Ok((status, body?)),
            401 | 403 => {
                let revoked = body
                    .ok()
                    .and_then(|body| serde_json::from_slice::<PlatformError>(&body).ok())
                    .is_some_and(|error| {
                        error.validate(self.limits).is_ok()
                            && error.code == PlatformErrorCode::IdentityRevoked
                    });
                Err(if revoked {
                    TransportError::IdentityRevoked
                } else {
                    TransportError::Unauthorized
                })
            }
            // Redirects are returned, not followed.
            _ => Err(TransportError::Rejected),
        }
    }
}

/// Validates an `https://` base URL and adds `default_port` when it names no
/// port. Returns `None` for any other scheme, a trailing slash, an empty host,
/// or user info.
fn with_default_port(url: &str, default_port: u16) -> Option<String> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() || authority.contains('@') || url.ends_with('/') {
        return None;
    }
    let has_port = authority.rsplit_once(':').is_some_and(|(host, port)| {
        !port.is_empty()
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && (!host.starts_with('[') || host.ends_with(']'))
    });
    Some(if has_port {
        url.to_owned()
    } else if path.is_empty() {
        format!("https://{authority}:{default_port}")
    } else {
        format!("https://{authority}:{default_port}/{path}")
    })
}

/// The `ring` provider restricted to TLS 1.3 cipher suites, so no older
/// protocol version can be negotiated.
fn tls13_only() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    Arc::new(provider)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_DISTRIBUTION_PORT, DEFAULT_PLATFORM_PORT, with_default_port};

    #[test]
    fn default_port_is_added_only_when_absent() {
        for (url, expected) in [
            ("https://p.example", Some("https://p.example:18423")),
            ("https://p.example/api", Some("https://p.example:18423/api")),
            ("https://p.example:443", Some("https://p.example:443")),
            ("https://10.0.0.1", Some("https://10.0.0.1:18423")),
            ("https://[::1]", Some("https://[::1]:18423")),
            ("https://[::1]:9", Some("https://[::1]:9")),
            ("http://p.example", None),
            ("https://p.example/", None),
            ("https://user@p.example", None),
            ("https://", None),
        ] {
            assert_eq!(
                with_default_port(url, DEFAULT_PLATFORM_PORT).as_deref(),
                expected,
                "{url}"
            );
        }
        assert_eq!(
            with_default_port("https://p.example", DEFAULT_DISTRIBUTION_PORT).as_deref(),
            Some("https://p.example:18424")
        );
    }
}
