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
        obtained_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
    ) STRICT;
    PRAGMA user_version = 1;
";
/// Version 2: the token each identity was enrolled with (so revocation can
/// refuse it), a pending enrollment key kept across attempts, and the
/// refused tokens.
const UPGRADE_V2: &str = "
    ALTER TABLE identity ADD COLUMN token_sha256 BLOB;
    CREATE TABLE pending_enrollment (
        slot INTEGER PRIMARY KEY CHECK (slot = 1),
        token_sha256 BLOB NOT NULL,
        key_pem TEXT NOT NULL
    ) STRICT;
    CREATE TABLE refused_tokens (token_sha256 BLOB PRIMARY KEY) STRICT, WITHOUT ROWID;
    PRAGMA user_version = 2;
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
    /// Local time the certificate was obtained, as milliseconds since the Unix
    /// epoch. Renewal timing uses the local clock on both ends of the interval.
    pub obtained_at_unix_ms: i64,
    /// Leaf certificate expiration as milliseconds since the Unix epoch.
    pub expires_at_unix_ms: i64,
}

impl fmt::Debug for StoredIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredIdentity")
            .field("agent_id", &self.agent_id)
            .field("key_pem", &"[REDACTED]")
            .field("obtained_at_unix_ms", &self.obtained_at_unix_ms)
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
        let connection = open_database(path, APPLICATION_ID, SCHEMA_V1, &[UPGRADE_V2])?;
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
                 CASE WHEN length(chain_json) <= ?1 THEN chain_json END,
                 obtained_at_ms, expires_at_ms
                 FROM identity WHERE slot = 1",
                [sql_int(self.limits.document_bytes)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        Zeroizing::new(row.get::<_, String>(1)?),
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((agent_id, key_pem, chain_json, obtained_at_unix_ms, expires_at_unix_ms)) = record
        else {
            return Ok(None);
        };
        let identity = StoredIdentity {
            agent_id: Identifier::new(agent_id).map_err(|_| StorageError::Corrupt)?,
            key_pem,
            certificate_chain_pem: chain_json
                .and_then(|json| serde_json::from_str(&json).ok())
                .ok_or(StorageError::Corrupt)?,
            obtained_at_unix_ms,
            expires_at_unix_ms,
        };
        if !self.valid(&identity) {
            return Err(StorageError::Corrupt);
        }
        Ok(Some(identity))
    }

    /// Atomically stores `identity`, replacing any previous one. A renewal
    /// keeps the token the identity was enrolled with.
    pub fn replace(&mut self, identity: &StoredIdentity) -> Result<(), StorageError> {
        let chain_json = self.chain_json(identity)?;
        self.connection.execute(
            "INSERT INTO identity
                 (slot, agent_id, key_pem, chain_json, obtained_at_ms, expires_at_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (slot) DO UPDATE SET agent_id = excluded.agent_id,
                 key_pem = excluded.key_pem, chain_json = excluded.chain_json,
                 obtained_at_ms = excluded.obtained_at_ms,
                 expires_at_ms = excluded.expires_at_ms",
            params![
                identity.agent_id.as_str(),
                identity.key_pem.as_str(),
                chain_json,
                identity.obtained_at_unix_ms,
                identity.expires_at_unix_ms
            ],
        )?;
        Ok(())
    }

    fn chain_json(&self, identity: &StoredIdentity) -> Result<String, StorageError> {
        if !self.valid(identity) {
            return Err(StorageError::InvalidIdentity);
        }
        serde_json::to_string(&identity.certificate_chain_pem)
            .map_err(|_| StorageError::InvalidIdentity)
    }

    /// Deletes the identity without refusing its token, for example when
    /// its certificate has expired.
    pub fn clear(&mut self) -> Result<(), StorageError> {
        self.connection.execute("DELETE FROM identity", [])?;
        Ok(())
    }

    /// The key kept for an enrollment with the token hashing to
    /// `token_sha256`, if an earlier attempt stored one. Retrying with the
    /// same key lets the platform return the same identity after a lost
    /// response.
    pub fn begin_enrollment(
        &self,
        token_sha256: [u8; 32],
    ) -> Result<Option<Zeroizing<String>>, StorageError> {
        Ok(self
            .connection
            .query_row(
                "SELECT key_pem FROM pending_enrollment WHERE slot = 1 AND token_sha256 = ?1",
                [token_sha256.as_slice()],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(Zeroizing::new))
    }

    /// Stores the key for an enrollment attempt before it is sent.
    pub fn set_pending_key(
        &mut self,
        token_sha256: [u8; 32],
        key_pem: &str,
    ) -> Result<(), StorageError> {
        if key_pem.is_empty() || key_pem.len() > self.limits.string_bytes {
            return Err(StorageError::InvalidIdentity);
        }
        self.connection.execute(
            "INSERT OR REPLACE INTO pending_enrollment VALUES (1, ?1, ?2)",
            params![token_sha256.as_slice(), key_pem],
        )?;
        Ok(())
    }

    /// Stores a newly enrolled identity with the token it enrolled with and
    /// drops the pending key, in one transaction.
    pub fn adopt_enrolled(
        &mut self,
        identity: &StoredIdentity,
        token_sha256: [u8; 32],
    ) -> Result<(), StorageError> {
        let chain_json = self.chain_json(identity)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR REPLACE INTO identity VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                identity.agent_id.as_str(),
                identity.key_pem.as_str(),
                chain_json,
                identity.obtained_at_unix_ms,
                identity.expires_at_unix_ms,
                token_sha256.as_slice()
            ],
        )?;
        transaction.execute("DELETE FROM pending_enrollment", [])?;
        transaction.commit()?;
        Ok(())
    }

    /// Deletes a revoked identity and refuses the token it enrolled with, so
    /// the agent never re-enrolls with it (the operator provides a new one).
    pub fn forget_revoked(&mut self) -> Result<(), StorageError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT OR IGNORE INTO refused_tokens
             SELECT token_sha256 FROM identity WHERE token_sha256 IS NOT NULL",
            [],
        )?;
        transaction.execute("DELETE FROM identity", [])?;
        transaction.commit()?;
        Ok(())
    }

    /// Whether the token hashing to `token_sha256` enrolled an identity that
    /// was later revoked.
    pub fn is_refused(&self, token_sha256: [u8; 32]) -> Result<bool, StorageError> {
        Ok(self.connection.query_row(
            "SELECT EXISTS (SELECT 1 FROM refused_tokens WHERE token_sha256 = ?1)",
            [token_sha256.as_slice()],
            |row| row.get(0),
        )?)
    }

    fn valid(&self, identity: &StoredIdentity) -> bool {
        let limits = self.limits;
        let pem_ok = |pem: &str| !pem.is_empty() && pem.len() <= limits.string_bytes;
        pem_ok(&identity.key_pem)
            && (1..=limits.list_items).contains(&identity.certificate_chain_pem.len())
            && identity.certificate_chain_pem.iter().all(|pem| pem_ok(pem))
            && identity.obtained_at_unix_ms >= 0
            && identity.expires_at_unix_ms >= 0
    }
}
