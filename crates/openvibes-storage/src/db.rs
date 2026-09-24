use std::{fmt, path::Path, time::Duration};

use rusqlite::{Connection, ErrorCode, OpenFlags};

use crate::paths::platform;

/// Fixed storage failure categories; no stored content or path is echoed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageError {
    /// A limit is zero, inconsistent, or above the V1 ceiling.
    InvalidLimits,
    /// The finding violates its versioned contract.
    InvalidFinding,
    /// The rule bundle record is empty, oversized, or has version zero.
    InvalidBundle,
    /// The host identity has an empty or oversized key or chain.
    InvalidIdentity,
    /// A higher rule bundle version was already accepted.
    Rollback,
    /// The same rule bundle version was accepted with different content.
    VersionConflict,
    /// A size bound was reached or the disk is full; the caller must apply
    /// backpressure. Nothing was written.
    Full,
    /// The database failed its integrity check, is not an agent database, or
    /// holds an invalid record that must not be discarded. See ADR-0003.
    Corrupt,
    /// The database was written by a newer, unknown schema version.
    UnsupportedSchema,
    /// The database could not be opened, read, or written.
    Unavailable,
    /// A state path is relative, a link, hard-linked, or accessible to
    /// another user. See [`prepare_state_dir`](crate::prepare_state_dir).
    InsecurePath,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "invalid queue limits",
            Self::InvalidFinding => "invalid finding contract",
            Self::InvalidBundle => "invalid rule bundle record",
            Self::InvalidIdentity => "invalid host identity record",
            Self::Rollback => "rule bundle version rollback rejected",
            Self::VersionConflict => "rule bundle version content conflict",
            Self::Full => "agent state is full",
            Self::Corrupt => "agent state is corrupt",
            Self::UnsupportedSchema => "unsupported agent state schema",
            Self::Unavailable => "agent state is unavailable",
            Self::InsecurePath => "agent state path is insecure",
        })
    }
}

impl std::error::Error for StorageError {}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(ErrorCode::DiskFull) => Self::Full,
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => Self::Corrupt,
            _ => Self::Unavailable,
        }
    }
}

/// Opens or creates an agent database at `path`, which must not be a symlink,
/// and checks its integrity. A fresh file is stamped with `application_id` and
/// gets `schema`, which must set `user_version` to 1; an existing file must
/// carry the same `application_id`, so one database kind never opens as another.
/// Opens (creating if needed) a database of one kind. `schema` creates
/// version 1; `upgrades[n]` takes version `n + 1` to `n + 2` and must set
/// `user_version` itself. A newer version than this build knows is refused.
pub(crate) fn open_database(
    path: &Path,
    application_id: i32,
    schema: &str,
    upgrades: &[&str],
) -> Result<Connection, StorageError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    platform::check_file_before_open(path)?;
    let connection = Connection::open_with_flags(path, flags)?;
    platform::restrict_file(path)?;
    // The service and an operator's export command may share a database.
    connection.busy_timeout(Duration::from_secs(5))?;
    // Overwrite deleted content, ignore schema-embedded SQL functions, and
    // detect corrupt pages on read.
    connection.execute_batch(
        "PRAGMA secure_delete = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA cell_size_check = ON;
         PRAGMA synchronous = FULL;",
    )?;
    let check: String = connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if check != "ok" {
        return Err(StorageError::Corrupt);
    }
    match connection.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))? {
        0 => connection
            .execute_batch(&format!(
                "BEGIN IMMEDIATE; PRAGMA application_id = {application_id}; {schema} COMMIT;"
            ))
            .map_err(|error| match StorageError::from(error) {
                // A pre-existing file with foreign tables is not our database.
                StorageError::Unavailable => StorageError::Corrupt,
                other => other,
            })?,
        version => {
            // A database stamped as another kind is corrupt whatever its
            // version; otherwise a version this build does not know is
            // refused as newer.
            let stamped: i32 =
                connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
            if stamped != application_id && stamped != 0 {
                return Err(StorageError::Corrupt);
            }
            if !(1..=latest(upgrades)).contains(&version) {
                return Err(StorageError::UnsupportedSchema);
            }
        }
    }
    let stamped: i32 = connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if stamped != application_id {
        return Err(StorageError::Corrupt);
    }
    loop {
        let version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        let Some(upgrade) = usize::try_from(version - 1)
            .ok()
            .and_then(|index| upgrades.get(index))
        else {
            break;
        };
        connection.execute_batch(&format!("BEGIN IMMEDIATE; {upgrade} COMMIT;"))?;
    }
    Ok(connection)
}

fn latest(upgrades: &[&str]) -> i64 {
    1 + i64::try_from(upgrades.len()).unwrap_or(i64::MAX - 1)
}

/// Converts a limit to an SQLite integer, saturating at `i64::MAX`.
pub(crate) fn sql_int(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
