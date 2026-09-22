//! Crash recovery: state captured while a write transaction is in flight, as a
//! killed process leaves it, reopens with only committed findings.

use std::{fs, path::PathBuf};

use openvibes_core::{Confidence, Finding, Identifier, ResourceLimits, SchemaVersion, Severity};
use openvibes_storage::SqliteQueue;
use rusqlite::Connection;

fn finding(name: &str) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: Identifier::new(name).unwrap(),
        scan_id: Identifier::new("scan.1").unwrap(),
        rule_id: Identifier::new("rule.1").unwrap(),
        rule_version: 1,
        observed_at_unix_ms: 1,
        severity: Severity::Low,
        confidence: Confidence::new(50).unwrap(),
        message: "x".repeat(4_000),
        evidence: Vec::new(),
    }
}

#[test]
fn state_captured_mid_transaction_recovers_to_last_commit() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-crash");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("after-crash")).unwrap();
    let live = dir.join("queue.sqlite");
    let copy = dir.join("after-crash/queue.sqlite");

    let mut queue = SqliteQueue::open(&live, ResourceLimits::V1).unwrap();
    assert_eq!(queue.enqueue(&finding("f.committed"), 0), Ok(true));
    drop(queue);
    let committed = fs::read(&live).unwrap();

    // A writer is killed mid-transaction: a one-page cache forces modified
    // pages into the database file before commit, and the connection is
    // leaked so nothing is rolled back or cleaned up.
    let writer = Connection::open(&live).unwrap();
    writer
        .execute_batch(
            "PRAGMA cache_size = 1;
             BEGIN IMMEDIATE;
             DELETE FROM pending;",
        )
        .unwrap();
    let body = serde_json::to_vec(&finding("f.uncommitted")).unwrap();
    for n in 0..20 {
        writer
            .execute(
                "INSERT INTO pending (finding_id, body, enqueued_at_ms, next_attempt_ms)
                 VALUES (?1, ?2, 0, 0)",
                (format!("f.uncommitted.{n}"), &body),
            )
            .unwrap();
    }
    let torn = fs::read(&live).unwrap();
    let journal = fs::read(dir.join("queue.sqlite-journal")).unwrap();
    std::mem::forget(writer);
    assert_ne!(
        torn, committed,
        "uncommitted pages reached the database file"
    );

    fs::write(&copy, torn).unwrap();
    fs::write(dir.join("after-crash/queue.sqlite-journal"), journal).unwrap();
    let mut recovered = SqliteQueue::open(&copy, ResourceLimits::V1).unwrap();
    assert_eq!(recovered.len(), Ok(1));
    let mut sent = Vec::new();
    recovered
        .deliver(0, |batch| {
            sent.extend(batch.iter().map(|f| f.finding_id.clone()));
            Err(())
        })
        .unwrap_err();
    assert_eq!(sent, [Identifier::new("f.committed").unwrap()]);
}
