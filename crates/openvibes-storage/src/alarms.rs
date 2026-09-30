//! The alarm queue (P14): its own database, so a full finding queue never
//! blocks alarms and the other way round.

use std::path::Path;

use openvibes_core::{
    ALARM_BATCH_BYTES, ALARM_QUEUE_MAX, ALARMS_PER_BATCH, Alarm, ResourceLimits, Validate,
};
use rusqlite::{Connection, params};

use crate::db::{StorageError, open_database};

/// `PRAGMA application_id` marking this database kind (ASCII "OVA1").
const APPLICATION_ID: i32 = 0x4F56_4131;
/// `body` is the alarm as first queued; `count` and `last_seen_ms` follow
/// its repeats. A delivered row stays while its alarm can still grow.
const SCHEMA_V1: &str = "
    CREATE TABLE alarms (
        seq INTEGER PRIMARY KEY,
        alarm_id TEXT NOT NULL UNIQUE,
        body BLOB NOT NULL,
        first_seen_ms INTEGER NOT NULL,
        last_seen_ms INTEGER NOT NULL,
        count INTEGER NOT NULL,
        sent INTEGER NOT NULL DEFAULT 0
    ) STRICT;
    CREATE TABLE counters (
        name TEXT PRIMARY KEY,
        value INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    PRAGMA user_version = 1;
";
/// A delivered alarm is kept this long after its first match (the
/// collapse window), in case a repeat grows it.
const GROWS_FOR_MS: i64 = 600_000;
/// Room in a batch for everything but the alarms.
const BATCH_WRAPPER_BYTES: usize = 1_024;

/// Durable, bounded queue of alarms awaiting delivery.
pub struct AlarmQueue {
    connection: Connection,
}

impl AlarmQueue {
    /// Opens or creates the queue at `path`, which must not be a symlink.
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        Ok(Self {
            connection: open_database(path, APPLICATION_ID, SCHEMA_V1, &[])?,
        })
    }

    /// Queues a new alarm, or raises `count` and `last_seen` of the queued
    /// one with the same id and marks it unsent. At the cap the oldest
    /// delivered row goes first (not a loss); then the oldest unsent one,
    /// counted in [`dropped_total`](Self::dropped_total).
    pub fn upsert(&mut self, alarm: &Alarm) -> Result<(), StorageError> {
        alarm
            .validate(ResourceLimits::V1)
            .map_err(|_| StorageError::Corrupt)?;
        let body = serde_json::to_vec(alarm).map_err(|_| StorageError::Corrupt)?;
        let tx = self.connection.transaction()?;
        tx.execute(
            "DELETE FROM alarms WHERE sent = 1 AND first_seen_ms < ?1",
            [alarm.last_seen_unix_ms.saturating_sub(GROWS_FOR_MS)],
        )?;
        tx.execute(
            "INSERT INTO alarms (alarm_id, body, first_seen_ms, last_seen_ms, count)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT (alarm_id) DO UPDATE SET
                 count = max(count, excluded.count),
                 last_seen_ms = max(last_seen_ms, excluded.last_seen_ms),
                 sent = 0",
            params![
                alarm.alarm_id.as_str(),
                body,
                alarm.first_seen_unix_ms,
                alarm.last_seen_unix_ms,
                alarm.count
            ],
        )?;
        let rows: i64 = tx.query_row("SELECT count(*) FROM alarms", [], |row| row.get(0))?;
        if rows.unsigned_abs() > ALARM_QUEUE_MAX {
            let evicted_sent = tx.execute(
                "DELETE FROM alarms WHERE seq = (SELECT min(seq) FROM alarms WHERE sent = 1)",
                [],
            )?;
            if evicted_sent == 0 {
                tx.execute(
                    "DELETE FROM alarms WHERE seq = (SELECT min(seq) FROM alarms)",
                    [],
                )?;
                add_dropped(&tx, 1)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The oldest unsent alarms: at most 100, and at most 256 KiB as a
    /// batch. A stored row that no longer parses or validates is removed
    /// and counted as dropped.
    pub fn batch(&mut self) -> Result<Vec<Alarm>, StorageError> {
        let rows: Vec<(i64, Vec<u8>, i64, u32)> = {
            let mut statement = self.connection.prepare(
                "SELECT seq, body, last_seen_ms, count FROM alarms WHERE sent = 0 ORDER BY seq",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect::<Result<_, _>>()?
        };
        let mut batch = Vec::new();
        let mut bytes = BATCH_WRAPPER_BYTES;
        for (seq, body, last_seen, count) in rows {
            let alarm = serde_json::from_slice::<Alarm>(&body)
                .ok()
                .map(|mut alarm| {
                    alarm.last_seen_unix_ms = last_seen;
                    alarm.count = count;
                    alarm
                })
                .filter(|alarm| alarm.validate(ResourceLimits::V1).is_ok());
            let Some(alarm) = alarm else {
                self.connection
                    .execute("DELETE FROM alarms WHERE seq = ?1", [seq])?;
                add_dropped(&self.connection, 1)?;
                continue;
            };
            let size = serde_json::to_vec(&alarm).map_or(usize::MAX, |b| b.len()) + 1;
            if batch.len() == ALARMS_PER_BATCH || bytes + size > ALARM_BATCH_BYTES {
                break;
            }
            bytes += size;
            batch.push(alarm);
        }
        Ok(batch)
    }

    /// Marks alarms delivered, unless a repeat changed them since the
    /// batch was taken (then they go again).
    pub fn sent(&mut self, alarms: &[Alarm]) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        for alarm in alarms {
            tx.execute(
                "UPDATE alarms SET sent = 1
                 WHERE alarm_id = ?1 AND count = ?2 AND last_seen_ms = ?3",
                params![
                    alarm.alarm_id.as_str(),
                    alarm.count,
                    alarm.last_seen_unix_ms
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Removes alarms the platform refused for good and counts them.
    pub fn drop_batch(&mut self, alarms: &[Alarm]) -> Result<(), StorageError> {
        let tx = self.connection.transaction()?;
        let mut removed = 0;
        for alarm in alarms {
            removed += tx.execute(
                "DELETE FROM alarms WHERE alarm_id = ?1",
                [alarm.alarm_id.as_str()],
            )?;
        }
        add_dropped(&tx, removed)?;
        tx.commit()?;
        Ok(())
    }

    /// Alarms dropped since the queue was created; never decreases.
    pub fn dropped_total(&self) -> Result<u64, StorageError> {
        let value: Option<i64> = self
            .connection
            .query_row(
                "SELECT value FROM counters WHERE name = 'dropped'",
                [],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(other),
            })?;
        Ok(value.unwrap_or(0).max(0).unsigned_abs())
    }

    /// Alarms awaiting delivery.
    pub fn pending(&self) -> Result<u64, StorageError> {
        let value: i64 =
            self.connection
                .query_row("SELECT count(*) FROM alarms WHERE sent = 0", [], |row| {
                    row.get(0)
                })?;
        Ok(value.unsigned_abs())
    }
}

fn add_dropped(connection: &Connection, count: usize) -> Result<(), StorageError> {
    if count > 0 {
        connection.execute(
            "INSERT INTO counters (name, value) VALUES ('dropped', ?1)
             ON CONFLICT (name) DO UPDATE SET value = value + excluded.value",
            [i64::try_from(count).unwrap_or(i64::MAX)],
        )?;
    }
    Ok(())
}
