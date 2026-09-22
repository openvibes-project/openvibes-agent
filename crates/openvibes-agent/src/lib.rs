#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Composition root: wires collectors, rules, storage, and transport together.

use std::fmt;

use openvibes_core::{EnrollmentResponse, EnrollmentToken, Identifier};
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
    /// A renewal response was issued for a different agent.
    IdentityMismatch,
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
            Self::IdentityMismatch => f.write_str("renewal issued for a different agent"),
        }
    }
}

impl std::error::Error for AgentError {}

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
/// The issued chain must parse with the new key before it is stored, so a bad
/// response never replaces the (absent) identity. The token is only used when
/// nothing is stored.
// ponytail: the host key is stored only after enrollment succeeds, so a crash
// between the response and the store write needs a fresh token. Persist the
// pending key first if that window matters in practice.
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
    let key = HostKey::generate()?;
    let response = PlatformClient::new(config, None)?.enroll(token, &key)?;
    adopt(store, &key, response, now_unix_ms)
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
/// revocation, so the next [`load_or_enroll`] requires a new token. Any other
/// error, including a bare 401 or 403, keeps the identity. Queued findings are
/// unaffected. Returns whether the identity was deleted.
pub fn forget_if_revoked(
    store: &mut IdentityStore,
    error: TransportError,
) -> Result<bool, AgentError> {
    if error != TransportError::IdentityRevoked {
        return Ok(false);
    }
    store.clear()?;
    Ok(true)
}

/// Stores an issued certificate for `key` once its chain parses with the key.
fn adopt(
    store: &mut IdentityStore,
    key: &HostKey,
    response: EnrollmentResponse,
    now_unix_ms: i64,
) -> Result<Enrollment, AgentError> {
    let identity = ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem())?;
    store.replace(&StoredIdentity {
        agent_id: response.agent_id.clone(),
        key_pem: Zeroizing::new(key.expose_key_pem().to_owned()),
        certificate_chain_pem: response.certificate_chain_pem,
        obtained_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: response.expires_at_unix_ms,
    })?;
    Ok(Enrollment {
        agent_id: response.agent_id,
        identity,
        obtained_at_unix_ms: now_unix_ms,
        expires_at_unix_ms: response.expires_at_unix_ms,
    })
}
