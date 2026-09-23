use std::path::Path;

use openvibes_core::Identifier;

use crate::db::{StorageError, open_database};

/// `PRAGMA application_id` marking this database kind (ASCII "OVN1").
const APPLICATION_ID: i32 = 0x4F56_4E31;
// The ID is generated in the schema transaction, so it exists exactly once
// and never changes. SQLite's randomblob is seeded from the OS; the ID is not
// a secret, only unique.
const SCHEMA_V1: &str = "
    CREATE TABLE install (
        slot INTEGER PRIMARY KEY CHECK (slot = 1),
        install_id TEXT NOT NULL
    ) STRICT;
    INSERT INTO install VALUES (1, lower(hex(randomblob(16))));
    PRAGMA user_version = 1;
";

/// Returns this installation's random identifier, creating it at `path` on
/// first use. It survives enrollment and revocation.
pub fn install_id(path: &Path) -> Result<Identifier, StorageError> {
    let connection = open_database(path, APPLICATION_ID, SCHEMA_V1)?;
    let id: String =
        connection.query_row("SELECT install_id FROM install WHERE slot = 1", [], |row| {
            row.get(0)
        })?;
    Identifier::new(id).map_err(|_| StorageError::Corrupt)
}
