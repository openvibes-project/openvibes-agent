//! Rule bundle persistence: the rollback floor survives restarts, holds across
//! concurrent handles, and is never silently lost to a corrupt record.

use std::{
    fs,
    path::{Path, PathBuf},
};

use openvibes_core::{Identifier, ResourceLimits};
use openvibes_storage::{RuleStore, SqliteQueue, StorageError, StoredRuleBundle};
use rusqlite::Connection;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn bundle(version: u64, digest: u8) -> StoredRuleBundle {
    StoredRuleBundle {
        version,
        preimage_sha256: [digest; 32],
        envelope: format!("{{\"v\":{version}}}").into_bytes(),
    }
}

/// Fresh store path unique to one test.
fn path(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-rules");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{test}.sqlite"));
    let _ = fs::remove_file(&path);
    path
}

fn open(path: &Path) -> RuleStore {
    RuleStore::open(path, ResourceLimits::V1).unwrap()
}

#[test]
fn accepted_bundle_survives_restart() {
    let path = path("restart");
    let mut store = open(&path);
    assert_eq!(store.get(&id("baseline")), Ok(None));
    store.accept(&id("baseline"), &bundle(1, 1)).unwrap();
    drop(store);

    let store = open(&path);
    assert_eq!(store.get(&id("baseline")), Ok(Some(bundle(1, 1))));
    assert_eq!(store.get(&id("other")), Ok(None));
}

#[test]
fn floor_only_moves_forward() {
    let path = path("floor");
    let mut store = open(&path);
    let set = id("baseline");
    store.accept(&set, &bundle(2, 2)).unwrap();

    assert_eq!(
        store.accept(&set, &bundle(1, 1)),
        Err(StorageError::Rollback)
    );
    assert_eq!(
        store.accept(&set, &bundle(2, 9)),
        Err(StorageError::VersionConflict)
    );
    assert_eq!(store.accept(&set, &bundle(2, 2)), Ok(()));
    assert_eq!(store.get(&set), Ok(Some(bundle(2, 2))));

    store.accept(&set, &bundle(3, 3)).unwrap();
    assert_eq!(store.get(&set), Ok(Some(bundle(3, 3))));
}

#[test]
fn floor_holds_against_a_stale_concurrent_writer() {
    let path = path("concurrent");
    let set = id("baseline");
    let mut first = open(&path);
    let mut second = open(&path);
    // `second` read no floor, verified v1, and only now tries to persist it.
    assert_eq!(second.get(&set), Ok(None));
    first.accept(&set, &bundle(2, 2)).unwrap();
    assert_eq!(
        second.accept(&set, &bundle(1, 1)),
        Err(StorageError::Rollback)
    );
    assert_eq!(first.get(&set), Ok(Some(bundle(2, 2))));
}

#[test]
fn invalid_bundles_are_rejected() {
    let path = path("invalid");
    let mut store = open(&path);
    let set = id("baseline");
    let oversized = StoredRuleBundle {
        envelope: vec![b'x'; ResourceLimits::V1.document_bytes + 1],
        ..bundle(1, 1)
    };
    let empty = StoredRuleBundle {
        envelope: Vec::new(),
        ..bundle(1, 1)
    };
    for invalid in [bundle(0, 1), bundle(u64::MAX, 1), oversized, empty] {
        assert_eq!(
            store.accept(&set, &invalid),
            Err(StorageError::InvalidBundle)
        );
    }
    assert_eq!(store.get(&set), Ok(None));
}

#[test]
fn corrupt_records_are_errors_not_missing_floors() {
    let path = path("corrupt");
    let mut store = open(&path);
    for name in ["zero", "negative", "digest", "oversized", "empty"] {
        store.accept(&id(name), &bundle(5, 5)).unwrap();
    }
    drop(store);
    Connection::open(&path)
        .unwrap()
        .execute_batch(
            "UPDATE rule_bundles SET version = 0 WHERE rule_set_id = 'zero';
             UPDATE rule_bundles SET version = -1 WHERE rule_set_id = 'negative';
             UPDATE rule_bundles SET preimage_sha256 = zeroblob(31) WHERE rule_set_id = 'digest';
             UPDATE rule_bundles SET envelope = zeroblob(2000000) WHERE rule_set_id = 'oversized';
             UPDATE rule_bundles SET envelope = zeroblob(0) WHERE rule_set_id = 'empty';",
        )
        .unwrap();

    let store = open(&path);
    for name in ["zero", "negative", "digest", "oversized", "empty"] {
        assert_eq!(store.get(&id(name)), Err(StorageError::Corrupt), "{name}");
    }
}

#[test]
fn queue_and_rule_databases_are_not_interchangeable() {
    let rules = path("rules-as-queue");
    drop(open(&rules));
    assert_eq!(
        SqliteQueue::open(&rules, ResourceLimits::V1).err(),
        Some(StorageError::Corrupt)
    );

    let queue = path("queue-as-rules");
    drop(SqliteQueue::open(&queue, ResourceLimits::V1).unwrap());
    assert_eq!(
        RuleStore::open(&queue, ResourceLimits::V1).err(),
        Some(StorageError::Corrupt)
    );
}

#[test]
fn withdrawing_keeps_the_floor_and_accept_clears_the_mark() {
    let path = path("withdraw");
    let mut store = open(&path);
    let l1 = id("hardening-linux-l1");
    store.accept(&l1, &bundle(3, 3)).unwrap();
    store.accept(&id("baseline"), &bundle(2, 2)).unwrap();

    store.withdraw(&l1).unwrap();
    store.withdraw(&id("never-stored")).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(true));
    assert_eq!(
        store.is_withdrawn(&id("never-stored")),
        Ok(false),
        "nothing recorded"
    );
    assert_eq!(
        store.is_withdrawn(&id("baseline")),
        Ok(false),
        "others untouched"
    );
    drop(store);

    let mut store = open(&path);
    assert_eq!(
        store.is_withdrawn(&l1),
        Ok(true),
        "the mark survives a restart"
    );
    assert_eq!(store.get(&l1), Ok(Some(bundle(3, 3))), "the row is kept");
    assert_eq!(store.get(&id("baseline")), Ok(Some(bundle(2, 2))));
    // The floor holds while withdrawn.
    assert_eq!(
        store.accept(&l1, &bundle(2, 2)),
        Err(StorageError::Rollback)
    );
    assert_eq!(
        store.accept(&l1, &bundle(3, 9)),
        Err(StorageError::VersionConflict)
    );
    assert_eq!(
        store.is_withdrawn(&l1),
        Ok(true),
        "a refused bundle re-enables nothing"
    );
    // The identical version re-accepts and clears the mark.
    store.accept(&l1, &bundle(3, 3)).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(false));
    // So does a newer one, after another withdrawal.
    store.withdraw(&l1).unwrap();
    store.accept(&l1, &bundle(4, 4)).unwrap();
    assert_eq!(store.is_withdrawn(&l1), Ok(false));
}

#[test]
fn a_version_1_store_opens_and_migrates() {
    let path = path("migrate-v1");
    let connection = Connection::open(&path).unwrap();
    // The schema before P20; application_id is "OVR1" (0x4F565231).
    connection
        .execute_batch(
            "PRAGMA application_id = 1331057201;
             CREATE TABLE rule_bundles (
                 rule_set_id TEXT PRIMARY KEY,
                 version INTEGER NOT NULL,
                 preimage_sha256 BLOB NOT NULL,
                 envelope BLOB NOT NULL
             ) STRICT, WITHOUT ROWID;
             PRAGMA user_version = 1;",
        )
        .unwrap();
    let stored = bundle(2, 2);
    connection
        .execute(
            "INSERT INTO rule_bundles VALUES ('baseline', 2, ?1, ?2)",
            rusqlite::params![stored.preimage_sha256.to_vec(), stored.envelope],
        )
        .unwrap();
    drop(connection);

    let mut store = open(&path);
    assert_eq!(store.get(&id("baseline")), Ok(Some(bundle(2, 2))));
    assert_eq!(store.is_withdrawn(&id("baseline")), Ok(false));
    store.withdraw(&id("baseline")).unwrap();
    assert_eq!(store.is_withdrawn(&id("baseline")), Ok(true));
    drop(store);
    let version: i64 = Connection::open(&path)
        .unwrap()
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 2);
}
