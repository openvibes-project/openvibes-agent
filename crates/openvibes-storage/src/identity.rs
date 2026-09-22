use std::{fmt, path::Path};

use openvibes_core::{Identifier, ResourceLimits};
use rusqlite::{Connection, OptionalExtension, params};
use zeroize::Zeroizing;

use crate::db::{StorageError, open_database, sql_int};

/// `PRAGMA application_id` marking this database kind (ASCII "OVI1").
const APPLICATION_ID: i32 = 0x4F56_4931;
const SCHEMA_V1: &str = "
    CREATE TABLE identity (
        slot INTEGER PRIMARY KEY CHECK (slot = 1),
        agent_id TEXT NOT NULL,
        key_pem TEXT NOT NULL,
        chain_json TEXT NOT NULL,
        expires_at_ms INTEGER NOT NULL
    ) STRICT;
    PRAGMA user_version = 1;
";

/// The enrolled host identity: private key, issued chain, and agent ID.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredIdentity {
    /// Agent identity assigned by the platform.
    pub agent_id: Identifier,
    /// PKCS#8 PEM host private key.
    pub key_pem: Zeroizing<String>,
    /// PEM certificate chain, leaf first.
    pub certificate_chain_pem: Vec<String>,
    /// Leaf certificate expiration as milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
}

impl fmt::Debug for StoredIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredIdentity")
            .field("agent_id", &self.agent_id)
            .field("key_pem", &"[REDACTED]")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish_non_exhaustive()
    }
}

/// Durable store holding at most one host identity.
///
/// Replacement is atomic, so rotation never leaves a key without its chain,
/// and `secure_delete` overwrites the previous key. The key is protected by
/// the state directory's OS access control (ADR-0003).
pub struct IdentityStore {
    connection: Connection,
    limits: ResourceLimits,
}

impl IdentityStore {
    /// Opens or creates the store at `path`, which must not be a symlink.
    pub fn open(path: &Path, limits: ResourceLimits) -> Result<Self, StorageError> {
        let v1 = ResourceLimits::V1;
        let valid = (1..=v1.string_bytes).contains(&limits.string_bytes)
            && (1..=v1.list_items).contains(&limits.list_items)
            && (1..=v1.document_bytes).contains(&limits.document_bytes);
        if !valid {
            return Err(StorageError::InvalidLimits);
        }
        let connection = open_database(path, APPLICATION_ID, SCHEMA_V1)?;
        Ok(Self { connection, limits })
    }

    /// Returns the stored identity, if the agent has enrolled.
    ///
    /// An invalid record is [`StorageError::Corrupt`], never treated as absent.
    pub fn get(&self) -> Result<Option<StoredIdentity>, StorageError> {
        let record = self
            .connection
            .query_row(
                "SELECT agent_id, key_pem,
                 CASE WHEN length(chain_json) <= ?1 THEN chain_json END, expires_at_ms
                 FROM identity WHERE slot = 1",
                [sql_int(self.limits.document_bytes)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        Zeroizing::new(row.get::<_, String>(1)?),
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((agent_id, key_pem, chain_json, expires_at_unix_ms)) = record else {
            return Ok(None);
        };
        let identity = StoredIdentity {
            agent_id: Identifier::new(agent_id).map_err(|_| StorageError::Corrupt)?,
            key_pem,
            certificate_chain_pem: chain_json
                .and_then(|json| serde_json::from_str(&json).ok())
                .ok_or(StorageError::Corrupt)?,
            expires_at_unix_ms,
        };
        if !self.valid(&identity) {
            return Err(StorageError::Corrupt);
        }
        Ok(Some(identity))
    }

    /// Atomically stores `identity`, replacing any previous one.
    pub fn replace(&mut self, identity: &StoredIdentity) -> Result<(), StorageError> {
        if !self.valid(identity) {
            return Err(StorageError::InvalidIdentity);
        }
        let chain_json = serde_json::to_string(&identity.certificate_chain_pem)
            .map_err(|_| StorageError::InvalidIdentity)?;
        self.connection.execute(
            "INSERT OR REPLACE INTO identity VALUES (1, ?1, ?2, ?3, ?4)",
            params![
                identity.agent_id.as_str(),
                identity.key_pem.as_str(),
                chain_json,
                identity.expires_at_unix_ms
            ],
        )?;
        Ok(())
    }

    /// Deletes the identity, for example after the platform revoked it.
    pub fn clear(&mut self) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM identity", [])?;
        Ok(())
    }

    fn valid(&self, identity: &StoredIdentity) -> bool {
        let limits = self.limits;
        let pem_ok = |pem: &str| !pem.is_empty() && pem.len() <= limits.string_bytes;
        pem_ok(&identity.key_pem)
            && (1..=limits.list_items).contains(&identity.certificate_chain_pem.len())
            && identity.certificate_chain_pem.iter().all(|pem| pem_ok(pem))
            && identity.expires_at_unix_ms >= 0
    }
}
