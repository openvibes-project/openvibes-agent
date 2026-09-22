#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Composition root: wires collectors, rules, storage, and transport together.

use std::fmt;

use openvibes_core::{EnrollmentToken, Identifier};
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
) -> Result<Enrollment, AgentError> {
    if let Some(stored) = store.get()? {
        return Ok(Enrollment {
            identity: ClientIdentity::from_pem(&stored.certificate_chain_pem, &stored.key_pem)?,
            agent_id: stored.agent_id,
            expires_at_unix_ms: stored.expires_at_unix_ms,
        });
    }
    let token = token.ok_or(AgentError::NotEnrolled)?;
    let key = HostKey::generate()?;
    let response = PlatformClient::new(config, None)?.enroll(token, &key)?;
    let identity = ClientIdentity::from_pem(&response.certificate_chain_pem, key.expose_key_pem())?;
    store.replace(&StoredIdentity {
        agent_id: response.agent_id.clone(),
        key_pem: Zeroizing::new(key.expose_key_pem().to_owned()),
        certificate_chain_pem: response.certificate_chain_pem,
        expires_at_unix_ms: response.expires_at_unix_ms,
    })?;
    Ok(Enrollment {
        agent_id: response.agent_id,
        identity,
        expires_at_unix_ms: response.expires_at_unix_ms,
    })
}
