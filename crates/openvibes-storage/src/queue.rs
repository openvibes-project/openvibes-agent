use std::{collections::HashSet, fmt, path::Path};

use openvibes_core::{DeliveryAcknowledgement, Finding, Identifier, ResourceLimits, Validate};
use rusqlite::{Connection, OptionalExtension, params};

use crate::db::{StorageError, open_database, sql_int};

/// `PRAGMA application_id` marking this database kind (ASCII "OVQ1").
const APPLICATION_ID: i32 = 0x4F56_5131;
const SCHEMA_V1: &str = "
    CREATE TABLE pending (
        seq INTEGER PRIMARY KEY,
        finding_id TEXT NOT NULL UNIQUE,
        body BLOB NOT NULL,
        enqueued_at_ms INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_ms INTEGER NOT NULL
    ) STRICT;
    CREATE TABLE acknowledged (
        finding_id TEXT PRIMARY KEY,
        acknowledged_at_ms INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    PRAGMA user_version = 1;
";
const DAY_MS: i64 = 86_400_000;

/// Why a delivery attempt left the batch queued.
#[derive(Debug, Eq, PartialEq)]
pub enum DeliveryError<E> {
    /// The transport failed; the batch is rescheduled with backoff.
    Transport(E),
    /// The platform response violates the acknowledgement contract; the batch
    /// is rescheduled with backoff.
    InvalidAcknowledgement,
    /// Local storage failed; the outcome of this attempt may not be recorded.
    Queue(StorageError),
}

impl<E> From<StorageError> for DeliveryError<E> {
    fn from(error: StorageError) -> Self {
        Self::Queue(error)
    }
}

impl<E> From<rusqlite::Error> for DeliveryError<E> {
    fn from(error: rusqlite::Error) -> Self {
        Self::Queue(error.into())
    }
}

impl<E: fmt::Display> fmt::Display for DeliveryError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "finding delivery failed: {error}"),
            Self::InvalidAcknowledgement => f.write_str("invalid delivery acknowledgement"),
            Self::Queue(error) => error.fmt(f),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for DeliveryError<E> {}

/// Durable, bounded, deduplicating FIFO of findings awaiting acknowledgement.
///
/// Findings leave the queue only when the platform acknowledges them as part of
/// the batch they were sent in. Acknowledged IDs are remembered for the
/// retention period, so replayed findings are not sent again. Unacknowledged
/// findings are retried with jittered, capped exponential backoff and dropped after
/// `retention_days`. Time is always supplied by the caller.
pub struct SqliteQueue {
    connection: Connection,
    limits: ResourceLimits,
}

impl SqliteQueue {
    /// Opens or creates the queue at `path`, which must not be a symlink.
    /// Limits may tighten, but never exceed, the V1 ceilings.
    ///
    /// Creating the parent directory with restrictive permissions is the
    /// caller's job.
    pub fn open(path: &Path, limits: ResourceLimits) -> Result<Self, StorageError> {
        validate_limits(limits)?;
        let connection = open_database(path, APPLICATION_ID, SCHEMA_V1)?;
        // Not persistent: the byte bound is reapplied on every open. SQLite
        // then fails writes past it with SQLITE_FULL, the same path as a full disk.
        let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        let pages = (limits.queue_bytes / page_size.unsigned_abs().max(1)).max(1);
        connection.query_row(&format!("PRAGMA max_page_count = {pages}"), [], |_| Ok(()))?;
        Ok(Self { connection, limits })
    }

    /// Durably queues a validated finding. Returns `false` when the same stable
    /// identifier is pending or was acknowledged within the retention period.
    pub fn enqueue(&mut self, finding: &Finding, now_unix_ms: i64) -> Result<bool, StorageError> {
        finding
            .validate(self.limits)
            .map_err(|_| StorageError::InvalidFinding)?;
        let body = serde_json::to_vec(finding).map_err(|_| StorageError::InvalidFinding)?;
        if body.len() > self.limits.document_bytes {
            return Err(StorageError::InvalidFinding);
        }
        self.prune(now_unix_ms)?;
        let id = finding.finding_id.as_str();
        let transaction = self.connection.transaction()?;
        let acknowledged = transaction
            .query_row(
                "SELECT 1 FROM acknowledged WHERE finding_id = ?1",
                [id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if acknowledged {
            return Ok(false);
        }
        let inserted = transaction.execute(
            "INSERT INTO pending (finding_id, body, enqueued_at_ms, next_attempt_ms)
             VALUES (?1, ?2, ?3, ?3) ON CONFLICT (finding_id) DO NOTHING",
            params![id, body, now_unix_ms],
        )?;
        transaction.commit()?;
        Ok(inserted == 1)
    }

    /// Number of findings awaiting acknowledgement.
    pub fn len(&self) -> Result<usize, StorageError> {
        let count: i64 = self
            .connection
            .query_row("SELECT count(*) FROM pending", [], |row| row.get(0))?;
        usize::try_from(count).map_err(|_| StorageError::Corrupt)
    }

    /// Whether no findings await acknowledgement.
    pub fn is_empty(&self) -> Result<bool, StorageError> {
        Ok(self.len()? == 0)
    }

    /// Sends the oldest bounded batch of due findings through `send`. Removes
    /// only findings that were in that batch and are named by a valid
    /// acknowledgement; every other batch member is rescheduled with backoff.
    /// Returns the number removed; `send` is not called when nothing is due.
    ///
    /// Stored records are untrusted: a record that fails its size limit or
    /// contract is deleted, since it can never be delivered.
    pub fn deliver<E>(
        &mut self,
        now_unix_ms: i64,
        send: impl FnOnce(&[Finding]) -> Result<DeliveryAcknowledgement, E>,
    ) -> Result<usize, DeliveryError<E>> {
        self.prune(now_unix_ms)?;
        let batch = self.due_batch(now_unix_ms)?;
        if batch.is_empty() {
            return Ok(0);
        }
        let outcome = send(&batch);
        let ack_valid = matches!(&outcome, Ok(ack) if ack.validate(self.limits).is_ok());
        let accepted: HashSet<&Identifier> = match &outcome {
            Ok(ack) if ack_valid => ack.accepted_finding_ids.iter().collect(),
            _ => HashSet::new(),
        };
        let initial_ms = seconds_ms(self.limits.retry_initial_seconds);
        let max_ms = seconds_ms(self.limits.retry_max_seconds);
        let mut delivered = 0;
        let transaction = self.connection.transaction()?;
        for finding in &batch {
            let id = finding.finding_id.as_str();
            if accepted.contains(&finding.finding_id) {
                transaction.execute("DELETE FROM pending WHERE finding_id = ?1", [id])?;
                transaction.execute(
                    "INSERT OR REPLACE INTO acknowledged VALUES (?1, ?2)",
                    params![id, now_unix_ms],
                )?;
                delivered += 1;
            } else {
                // Equal jitter: wait between half and all of the capped
                // exponential delay, so agents that failed together spread out.
                transaction.execute(
                    "UPDATE pending SET attempts = attempts + 1,
                     next_attempt_ms = ?2 + delay / 2 + abs(random() % (delay / 2 + 1))
                     FROM (SELECT min(?4, ?3 << min(attempts, 20)) AS delay
                           FROM pending WHERE finding_id = ?1)
                     WHERE finding_id = ?1",
                    params![id, now_unix_ms, initial_ms, max_ms],
                )?;
            }
        }
        transaction.commit()?;
        match outcome {
            Err(error) => Err(DeliveryError::Transport(error)),
            Ok(_) if !ack_valid => Err(DeliveryError::InvalidAcknowledgement),
            Ok(_) => Ok(delivered),
        }
    }

    /// Loads the oldest due findings, deleting records that fail validation.
    /// A retry time further ahead than `retry_max_seconds` means the clock went
    /// backwards, so the record is treated as due.
    fn due_batch(&mut self, now_unix_ms: i64) -> Result<Vec<Finding>, StorageError> {
        let max_ms = seconds_ms(self.limits.retry_max_seconds);
        let mut statement = self.connection.prepare(
            "SELECT seq, finding_id, CASE WHEN length(body) <= ?4 THEN body END FROM pending
             WHERE next_attempt_ms <= ?1 OR next_attempt_ms > ?1 + ?2
             ORDER BY seq LIMIT ?3",
        )?;
        let rows = statement
            .query_map(
                params![
                    now_unix_ms,
                    max_ms,
                    sql_int(self.limits.delivery_batch_items),
                    sql_int(self.limits.document_bytes)
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )?
            .collect::<Result<Vec<_>, _>>()?;
        drop(statement);
        let mut batch = Vec::with_capacity(rows.len());
        let mut invalid = Vec::new();
        for (seq, id, body) in rows {
            match body.and_then(|body| serde_json::from_slice::<Finding>(&body).ok()) {
                Some(finding)
                    if finding.finding_id.as_str() == id
                        && finding.validate(self.limits).is_ok() =>
                {
                    batch.push(finding);
                }
                _ => invalid.push(seq),
            }
        }
        // ponytail: discarded silently; emit a health event once they exist.
        for seq in invalid {
            self.connection
                .execute("DELETE FROM pending WHERE seq = ?1", [seq])?;
        }
        Ok(batch)
    }

    /// Drops pending findings and acknowledgement records past retention.
    fn prune(&mut self, now_unix_ms: i64) -> Result<(), StorageError> {
        let cutoff = now_unix_ms.saturating_sub(i64::from(self.limits.retention_days) * DAY_MS);
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM pending WHERE enqueued_at_ms < ?1", [cutoff])?;
        transaction.execute(
            "DELETE FROM acknowledged WHERE acknowledged_at_ms < ?1",
            [cutoff],
        )?;
        Ok(transaction.commit()?)
    }
}

fn seconds_ms(seconds: u64) -> i64 {
    i64::try_from(seconds.saturating_mul(1_000)).unwrap_or(i64::MAX)
}

fn validate_limits(limits: ResourceLimits) -> Result<(), StorageError> {
    let v1 = ResourceLimits::V1;
    let valid = (1..=v1.delivery_batch_items).contains(&limits.delivery_batch_items)
        && (1..=v1.queue_bytes).contains(&limits.queue_bytes)
        && (1..=v1.retention_days).contains(&limits.retention_days)
        && (1..=v1.document_bytes).contains(&limits.document_bytes)
        && (1..=limits.retry_max_seconds).contains(&limits.retry_initial_seconds)
        && limits.retry_max_seconds <= v1.retry_max_seconds;
    valid.then_some(()).ok_or(StorageError::InvalidLimits)
}
