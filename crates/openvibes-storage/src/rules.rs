use std::path::Path;

use openvibes_core::{Identifier, ResourceLimits};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::db::{StorageError, open_database, sql_int};

/// `PRAGMA application_id` marking this database kind (ASCII "OVR1").
const APPLICATION_ID: i32 = 0x4F56_5231;
const SCHEMA_V1: &str = "
    CREATE TABLE rule_bundles (
        rule_set_id TEXT PRIMARY KEY,
        version INTEGER NOT NULL,
        preimage_sha256 BLOB NOT NULL,
        envelope BLOB NOT NULL
    ) STRICT, WITHOUT ROWID;
    PRAGMA user_version = 1;
";

/// The last accepted signed bundle for one rule set and its rollback floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRuleBundle {
    /// Accepted, monotonically increasing bundle version (never zero).
    pub version: u64,
    /// SHA-256 of the accepted bundle's complete signing preimage.
    pub preimage_sha256: [u8; 32],
    /// The serialized signed envelope, to be re-verified before use.
    pub envelope: Vec<u8>,
}

/// Durable store of accepted rule bundles and their rollback floors.
///
/// Kept in its own database, separate from the finding queue, so a full queue
/// can never block persisting a newly accepted bundle. Stored envelopes are
/// untrusted and must pass the rule loader again on restore; the version floor
/// relies on OS protection of the state directory (ADR-0003).
pub struct RuleStore {
    connection: Connection,
    limits: ResourceLimits,
}

impl RuleStore {
    /// Opens or creates the store at `path`, which must not be a symlink.
    pub fn open(path: &Path, limits: ResourceLimits) -> Result<Self, StorageError> {
        if !(1..=ResourceLimits::V1.document_bytes).contains(&limits.document_bytes) {
            return Err(StorageError::InvalidLimits);
        }
        let connection = open_database(path, APPLICATION_ID, SCHEMA_V1, &[])?;
        Ok(Self { connection, limits })
    }

    /// Returns the last accepted bundle for `rule_set_id`, if any.
    ///
    /// An invalid record is reported as [`StorageError::Corrupt`], never
    /// skipped: treating it as absent would silently remove the rollback floor.
    pub fn get(&self, rule_set_id: &Identifier) -> Result<Option<StoredRuleBundle>, StorageError> {
        let record = self
            .connection
            .query_row(
                "SELECT version, preimage_sha256,
                 CASE WHEN length(envelope) <= ?2 THEN envelope END
                 FROM rule_bundles WHERE rule_set_id = ?1",
                params![rule_set_id.as_str(), sql_int(self.limits.document_bytes)],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((version, digest, envelope)) = record else {
            return Ok(None);
        };
        let version = u64::try_from(version).ok().filter(|&version| version > 0);
        match (version, <[u8; 32]>::try_from(digest), envelope) {
            (Some(version), Ok(preimage_sha256), Some(envelope)) if !envelope.is_empty() => {
                Ok(Some(StoredRuleBundle {
                    version,
                    preimage_sha256,
                    envelope,
                }))
            }
            _ => Err(StorageError::Corrupt),
        }
    }

    /// Atomically records `bundle` as the accepted bundle for `rule_set_id`.
    ///
    /// The floor check runs inside a write-locked transaction, so it holds
    /// across processes and against a floor read before verification: a lower
    /// version is [`StorageError::Rollback`], and the same version with a
    /// different digest is [`StorageError::VersionConflict`]. Re-accepting the
    /// identical version is a no-op.
    pub fn accept(
        &mut self,
        rule_set_id: &Identifier,
        bundle: &StoredRuleBundle,
    ) -> Result<(), StorageError> {
        let version = i64::try_from(bundle.version)
            .ok()
            .filter(|&version| version > 0)
            .ok_or(StorageError::InvalidBundle)?;
        if bundle.envelope.is_empty() || bundle.envelope.len() > self.limits.document_bytes {
            return Err(StorageError::InvalidBundle);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT version, preimage_sha256 FROM rule_bundles WHERE rule_set_id = ?1",
                [rule_set_id.as_str()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        match current {
            Some((floor, _)) if version < floor => return Err(StorageError::Rollback),
            Some((floor, digest)) if version == floor => {
                return if digest == bundle.preimage_sha256 {
                    Ok(())
                } else {
                    Err(StorageError::VersionConflict)
                };
            }
            _ => {}
        }
        transaction.execute(
            "INSERT OR REPLACE INTO rule_bundles VALUES (?1, ?2, ?3, ?4)",
            params![
                rule_set_id.as_str(),
                version,
                bundle.preimage_sha256,
                bundle.envelope
            ],
        )?;
        Ok(transaction.commit()?)
    }
}
