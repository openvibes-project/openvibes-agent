#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Composition root: wires collectors, rules, storage, and transport together.

mod config;
mod scan;
mod service;

pub use config::{AgentConfig, RuleSetConfig, ScanConfig, load_config, read_enrollment_token};
pub use scan::ScanReport;
pub use service::{ExportReport, Service, TickReport};

use sha2::{Digest, Sha256};
use std::fmt;

use openvibes_core::{EnrollmentResponse, EnrollmentToken, Identifier};
use openvibes_rules::{EvaluationError, LoadError};
use openvibes_storage::{IdentityStore, StorageError, StoredIdentity};
use openvibes_transport::{
    ClientIdentity, HostKey, PlatformClient, TransportConfig, TransportError,
};
use zeroize::Zeroizing;

/// Agent-level failure, wrapping the component's fixed category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentError {
    /// Agent-owned state failed.
    Storage(StorageError),
    /// Platform communication failed.
    Transport(TransportError),
    /// No identity is stored and no enrollment token was supplied.
    NotEnrolled,
    /// The enrollment token belongs to an identity the platform revoked; an
    /// operator must supply a new one.
    TokenRefused,
    /// A renewal response was issued for a different agent.
    IdentityMismatch,
    /// The configuration or a file it names is missing, oversized, or invalid.
    Config,
    /// Export was requested while a platform is configured.
    NotLocalOnly,
    /// An export file could not be written; its findings stay queued.
    Export(ExportFailure),
    /// A rule bundle was refused by the loader.
    Rules(LoadError),
    /// A rule set could not be evaluated against the collected facts.
    Evaluation(EvaluationError),
}

impl From<StorageError> for AgentError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<TransportError> for AgentError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(f),
            Self::Transport(error) => error.fmt(f),
            Self::NotEnrolled => f.write_str("agent is not enrolled and has no token"),
            Self::TokenRefused => f.write_str(
                "the enrollment token belongs to a revoked identity; waiting for a new token",
            ),
            Self::IdentityMismatch => f.write_str("renewal issued for a different agent"),
            Self::Config => f.write_str("invalid agent configuration"),
            Self::NotLocalOnly => f.write_str("export requires a local-only configuration"),
            Self::Export(failure) => write!(f, "cannot write export file: {failure}"),
            Self::Rules(error) => error.fmt(f),
            Self::Evaluation(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for AgentError {}

/// Why an export file could not be written. Never names the path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFailure {
    /// The output directory does not exist.
    NoDirectory,
    /// A file of the same name already exists; nothing is overwritten.
    Exists,
    /// This identity may not write to the output directory.
    PermissionDenied,
    /// The document would exceed the 1 MiB document limit.
    TooLarge,
    /// The document violates its contract.
    Invalid,
    /// Writing or flushing failed, for example a full disk.
    Io,
}

impl fmt::Display for ExportFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoDirectory => "the output directory does not exist",
            Self::Exists => "a file of the same name already exists",
            Self::PermissionDenied => "permission denied on the output directory",
            Self::TooLarge => "the document exceeds the 1 MiB limit",
            Self::Invalid => "the document violates its contract",
            Self::Io => "writing or flushing the file failed",
        })
    }
}

/// The host identity in use for mTLS.
#[derive(Debug)]
pub struct Enrollment {
    /// Agent identity assigned by the platform.
    pub agent_id: Identifier,
    /// Client certificate and key for mTLS.
    pub identity: ClientIdentity,
    /// Local time the certificate was obtained, in Unix milliseconds.
    pub obtained_at_unix_ms: i64,
    /// Leaf certificate expiration as milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
}

/// Returns the stored identity, or enrolls with `token` and stores the result.
///
/// The host key is stored **before** the first attempt and reused for every
/// attempt with the same token, so a lost response is retried with the same
/// key and the platform returns the same identity. The issued chain must
/// parse with the key before it is stored. A token whose identity was
/// revoked is never used again ([`AgentError::TokenRefused`]).
pub fn load_or_enroll(
    store: &mut IdentityStore,
    config: &TransportConfig,
    token: Option<&EnrollmentToken>,
    now_unix_ms: i64,
) -> Result<Enrollment, AgentError> {
    if let Some(stored) = store.get()? {
        return Ok(Enrollment {
            identity: ClientIdentity::from_pem(&stored.certificate_chain_pem, &stored.key_pem)?,
            agent_id: stored.agent_id,
            obtained_at_unix_ms: stored.obtained_at_unix_ms,
            expires_at_unix_ms: stored.expires_at_unix_ms,
        });
    }
    let token = token.ok_or(AgentError::NotEnrolled)?;
    let token_sha256: [u8; 32] = Sha256::digest(token.expose_secret().as_bytes()).into();
    if store.is_refused(token_sha256)? {
        return Err(AgentError::TokenRefused);
    }
    let key = match store.begin_enrollment(token_sha256)? {
        Some(pending) => HostKey::from_key_pem(&pending)?,
        None => {
            let key = HostKey::generate()?;
            store.set_pending_key(token_sha256, key.expose_key_pem())?;
            key
        }
    };
    let response = PlatformClient::new(config, None)?.enroll(token, &key)?;
    let (stored, enrollment) = issued(&key, response, now_unix_ms)?;
    store.adopt_enrolled(&stored, token_sha256)?;
    Ok(enrollment)
}

/// Rotates to a new host key once two thirds of the certificate's lifetime,
/// measured from when it was obtained, have passed. Returns the new identity,
/// or `None` when renewal is not yet due.
///
/// The platform must reissue for the same agent; a response for another agent
/// is refused and the current identity is kept.
pub fn renew_if_due(
    store: &mut IdentityStore,
    config: &TransportConfig,
    current: &Enrollment,
    now_unix_ms: i64,
) -> Result<Option<Enrollment>, AgentError> {
    let lifetime = current
        .expires_at_unix_ms
        .saturating_sub(current.obtained_at_unix_ms);
    let due_at = current.obtained_at_unix_ms.saturating_add(lifetime / 3 * 2);
    if now_unix_ms < due_at {
        return Ok(None);
    }
    let key = HostKey::generate()?;
    let response = PlatformClient::new(config, Some(&current.identity))?.renew(&key)?;
    if response.agent_id != current.agent_id {
        return Err(AgentError::IdentityMismatch);
    }
    adopt(store, &key, response, now_unix_ms).map(Some)
}

/// Deletes the stored identity if `error` is the platform's explicit
/// revocation, and refuses the token it enrolled with, so the next
/// [`load_or_enroll`] requires a new token. Any other error, including a bare
/// 401 or 403, keeps the identity. Queued findings are unaffected. Returns
/// whether the identity was deleted.
pub fn forget_if_revoked(
    store: &mut IdentityStore,
    error: TransportError,
) -> Result<bool, AgentError> {
    if error != TransportError::IdentityRevoked {
        return Ok(false);
    }
    store.forget_revoked()?;
    Ok(true)
}

/// Stores an issued (renewed) certificate for `key` once its chain parses
/// with the key.
fn adopt(
    store: &mut IdentityStore,
    key: &HostKey,
    response: EnrollmentResponse,
    now_unix_ms: i64,
) -> Result<Enrollment, AgentError> {
    let (stored, enrollment) = issued(key, response, now_unix_ms)?;
    store.replace(&stored)?;
    Ok(enrollment)
}

/// The record to store and the identity to use for an issued certificate;
/// fails unless the chain parses with `key`.
fn issued(
    key: &HostKey,
    response: EnrollmentResponse,
    now_unix_ms: i64,
) -> Result<(StoredIdentity, Enrollment), AgentError> {
    let identity = ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem())?;
    let stored = StoredIdentity {
        agent_id: response.agent_id.clone(),
        key_pem: Zeroizing::new(key.expose_key_pem().to_owned()),
        certificate_chain_pem: response.certificate_chain_pem,
        obtained_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: response.expires_at_unix_ms,
    };
    let enrollment = Enrollment {
        agent_id: response.agent_id,
        identity,
        obtained_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: response.expires_at_unix_ms,
    };
    Ok((stored, enrollment))
}
