//! Durable queue behaviour: restart survival, acknowledgement replay, backoff,
//! retention, byte bounds, and corrupt or hostile state.

use std::{fs, path::PathBuf};

use openvibes_core::{
    Confidence, DeliveryAcknowledgement, Finding, Identifier, ResourceLimits, SchemaVersion,
    Severity,
};
use openvibes_storage::{DeliveryError, SqliteQueue, StorageError};
use rusqlite::Connection;

const DAY_MS: i64 = 86_400_000;

fn id(value: &str) -> Identifier {
    Identifier::new(value).unwrap()
}

fn finding(name: &str) -> Finding {
    Finding {
        schema_version: SchemaVersion::V1,
        finding_id: id(name),
        scan_id: id("scan.1"),
        rule_id: id("rule.1"),
        rule_version: 1,
        observed_at_unix_ms: 1,
        severity: Severity::Low,
        confidence: Confidence::new(50).unwrap(),
        message: "synthetic".into(),
        evidence: Vec::new(),
    }
}

fn ack(ids: &[&str]) -> DeliveryAcknowledgement {
    DeliveryAcknowledgement {
        schema_version: SchemaVersion::V1,
        accepted_finding_ids: ids.iter().map(|name| id(name)).collect(),
        acknowledged_at_unix_ms: 2,
        rejected_findings: Vec::new(),
    }
}

/// Fresh database path unique to one test.
fn path(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-queue");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{test}.sqlite"));
    let _ = fs::remove_file(&path);
    path
}

fn limits(batch: usize) -> ResourceLimits {
    ResourceLimits {
        delivery_batch_items: batch,
        ..ResourceLimits::V1
    }
}

fn queue(test: &str, batch: usize, names: &[&str]) -> (PathBuf, SqliteQueue) {
    let path = path(test);
    let mut queue = SqliteQueue::open(&path, limits(batch)).unwrap();
    for name in names {
        assert_eq!(queue.enqueue(&finding(name), 0), Ok(true));
    }
    (path, queue)
}

/// Delivers at `now`, recording sent IDs and acknowledging `acked`.
fn deliver(
    queue: &mut SqliteQueue,
    now: i64,
    acked: &[&str],
) -> (Vec<Identifier>, Result<usize, DeliveryError<()>>) {
    let mut sent = Vec::new();
    let result = queue.deliver(now, |batch| {
        sent = batch.iter().map(|f| f.finding_id.clone()).collect();
        Ok(ack(acked))
    });
    (sent, result)
}

#[test]
fn limits_are_bounded() {
    let path = path("limits");
    for bad in [
        limits(0),
        limits(ResourceLimits::V1.delivery_batch_items + 1),
        ResourceLimits {
            queue_bytes: ResourceLimits::V1.queue_bytes + 1,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            retention_days: 0,
            ..ResourceLimits::V1
        },
        ResourceLimits {
            retry_initial_seconds: ResourceLimits::V1.retry_max_seconds + 1,
            ..ResourceLimits::V1
        },
    ] {
        assert_eq!(
            SqliteQueue::open(&path, bad).err(),
            Some(StorageError::InvalidLimits)
        );
    }
}

#[test]
fn enqueue_validates_and_deduplicates() {
    let (_, mut queue) = queue("enqueue", 10, &["f.a"]);
    assert_eq!(queue.enqueue(&finding("f.a"), 0), Ok(false));
    let mut invalid = finding("f.b");
    invalid.message.clear();
    assert_eq!(
        queue.enqueue(&invalid, 0),
        Err(StorageError::InvalidFinding)
    );
    assert_eq!(queue.len(), Ok(1));
}

#[test]
fn delivery_is_batched_fifo_and_removes_only_acknowledged_batch_members() {
    let (_, mut queue) = queue("fifo", 2, &["f.a", "f.b", "f.c"]);
    // f.c was not in this batch, so acknowledging it must not drop it.
    let (sent, result) = deliver(&mut queue, 0, &["f.a", "f.c"]);
    assert_eq!(sent, [id("f.a"), id("f.b")]);
    assert_eq!(result, Ok(1));
    assert_eq!(queue.len(), Ok(2));
    // Acknowledged findings are not queued again; pending ones stay deduplicated.
    assert_eq!(queue.enqueue(&finding("f.a"), 0), Ok(false));
    assert_eq!(queue.enqueue(&finding("f.b"), 0), Ok(false));
}

#[test]
fn findings_survive_restart_and_acknowledged_ones_are_not_sent_again() {
    let (path, queue) = queue("restart", 10, &["f.a", "f.b"]);
    drop(queue);

    let mut queue = SqliteQueue::open(&path, limits(10)).unwrap();
    assert_eq!(queue.len(), Ok(2));
    assert_eq!(deliver(&mut queue, 0, &["f.a", "f.b"]).1, Ok(2));
    drop(queue);

    // A replayed scan after restart produces the same stable IDs.
    let mut queue = SqliteQueue::open(&path, limits(10)).unwrap();
    assert_eq!(queue.enqueue(&finding("f.a"), 1), Ok(false));
    assert_eq!(queue.enqueue(&finding("f.b"), 1), Ok(false));
    assert_eq!(queue.is_empty(), Ok(true));
}

#[test]
fn failed_or_invalid_delivery_keeps_findings_and_backs_off() {
    let (_, mut queue) = queue("backoff", 10, &["f.a", "f.b"]);
    let initial = 15_000;
    assert_eq!(
        queue.deliver(0, |_| Err("offline")),
        Err(DeliveryError::Transport("offline"))
    );
    // Jittered: due somewhere in [initial / 2, initial].
    assert_eq!(
        deliver(&mut queue, initial / 2 - 1, &[]),
        (Vec::new(), Ok(0))
    );

    let mut bad = ack(&["f.a"]);
    bad.acknowledged_at_unix_ms = -1;
    assert_eq!(
        queue.deliver(initial, |_| Ok::<_, ()>(bad)),
        Err(DeliveryError::InvalidAcknowledgement)
    );
    assert_eq!(queue.len(), Ok(2));
    // The second failure doubles the delay: due in [2 * initial, 3 * initial].
    assert_eq!(deliver(&mut queue, 2 * initial - 1, &[]).0, []);
    assert_eq!(deliver(&mut queue, 3 * initial, &[]).0.len(), 2);
}

#[test]
fn retry_delays_are_jittered() {
    let names: Vec<String> = (0..40).map(|n| format!("f.{n}")).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let (path, mut queue) = queue("jitter", 100, &names);
    let _ = queue.deliver(0, |_| Err::<DeliveryAcknowledgement, _>(()));
    drop(queue);
    let delays: std::collections::HashSet<i64> = Connection::open(&path)
        .unwrap()
        .prepare("SELECT next_attempt_ms FROM pending")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(delays.iter().all(|delay| (7_500..=15_000).contains(delay)));
    assert!(
        delays.len() > 1,
        "all 40 retries were scheduled identically"
    );
}

#[test]
fn retry_time_beyond_the_maximum_delay_is_treated_as_clock_regression() {
    let (_, mut queue) = queue("clock", 10, &["f.a"]);
    let _ = queue.deliver(DAY_MS, |_| Err::<DeliveryAcknowledgement, _>(()));
    // The clock jumped back a day; the retry must not wait a day.
    assert_eq!(deliver(&mut queue, 0, &["f.a"]).1, Ok(1));
}

#[test]
fn empty_queue_does_not_call_transport() {
    let (_, mut queue) = queue("empty", 10, &[]);
    assert_eq!(
        queue.deliver(0, |_| -> Result<DeliveryAcknowledgement, ()> {
            panic!("transport called for an empty queue")
        }),
        Ok(0)
    );
}

#[test]
fn retention_drops_undelivered_and_forgets_acknowledged_findings() {
    let (_, mut queue) = queue("retention", 10, &["f.a", "f.b"]);
    assert_eq!(deliver(&mut queue, 0, &["f.a"]).1, Ok(1));
    let expired = 30 * DAY_MS + 1;
    assert_eq!(deliver(&mut queue, expired, &[]), (Vec::new(), Ok(0)));
    assert_eq!(queue.is_empty(), Ok(true));
    assert_eq!(queue.enqueue(&finding("f.a"), expired), Ok(true));
}

#[test]
fn byte_bound_applies_backpressure_until_delivery_frees_space() {
    let path = path("full");
    let small = ResourceLimits {
        queue_bytes: 64 * 1024,
        ..ResourceLimits::V1
    };
    let mut queue = SqliteQueue::open(&path, small).unwrap();
    let big = |n: usize| Finding {
        message: "x".repeat(4_000),
        ..finding(&format!("f.{n}"))
    };
    let mut queued = 0;
    let error = loop {
        match queue.enqueue(&big(queued), 0) {
            Ok(true) => queued += 1,
            other => break other,
        }
    };
    assert_eq!(error, Err(StorageError::Full));
    assert!(queued > 0);
    assert_eq!(queue.len(), Ok(queued));

    let removed = queue.deliver(0, |batch| {
        Ok::<_, ()>(DeliveryAcknowledgement {
            accepted_finding_ids: batch.iter().map(|f| f.finding_id.clone()).collect(),
            ..ack(&[])
        })
    });
    assert_eq!(removed, Ok(queued));
    assert_eq!(queue.enqueue(&big(queued), 0), Ok(true));
}

#[test]
fn corrupt_or_foreign_databases_are_rejected() {
    let garbage = path("garbage");
    fs::write(&garbage, vec![0xA5; 8_192]).unwrap();
    assert_eq!(
        SqliteQueue::open(&garbage, limits(10)).err(),
        Some(StorageError::Corrupt)
    );

    let foreign = path("foreign");
    Connection::open(&foreign)
        .unwrap()
        .execute_batch("CREATE TABLE pending (x);")
        .unwrap();
    assert_eq!(
        SqliteQueue::open(&foreign, limits(10)).err(),
        Some(StorageError::Corrupt)
    );

    let newer = path("newer");
    Connection::open(&newer)
        .unwrap()
        .execute_batch("PRAGMA user_version = 2;")
        .unwrap();
    assert_eq!(
        SqliteQueue::open(&newer, limits(10)).err(),
        Some(StorageError::UnsupportedSchema)
    );
}

#[test]
fn tampered_records_are_discarded_and_never_sent() {
    let (path, queue) = queue("tampered", 10, &["f.a", "f.b", "f.c", "f.d"]);
    drop(queue);
    let direct = Connection::open(&path).unwrap();
    direct
        .execute_batch(
            "UPDATE pending SET body = CAST('not json' AS BLOB) WHERE finding_id = 'f.a';
             UPDATE pending SET finding_id = 'f.x' WHERE finding_id = 'f.b';
             UPDATE pending SET body = zeroblob(2000000) WHERE finding_id = 'f.c';",
        )
        .unwrap();
    drop(direct);

    let mut queue = SqliteQueue::open(&path, limits(10)).unwrap();
    let (sent, result) = deliver(&mut queue, 0, &["f.d"]);
    assert_eq!(sent, [id("f.d")]);
    assert_eq!(result, Ok(1));
    assert_eq!(queue.is_empty(), Ok(true));
}

#[cfg(unix)]
#[test]
fn symlinked_database_path_is_refused() {
    let target = path("symlink-target");
    let link = path("symlink");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert_eq!(
        SqliteQueue::open(&link, limits(10)).err(),
        Some(StorageError::InsecurePath)
    );
    assert!(!target.exists());
}

#[test]
fn a_batch_never_exceeds_the_document_limit() {
    let path = path("byte-batch");
    let mut queue = SqliteQueue::open(&path, limits(500)).unwrap();
    for n in 0..500 {
        let big = Finding {
            message: "x".repeat(4_000),
            ..finding(&format!("f.{n}"))
        };
        assert_eq!(queue.enqueue(&big, 0), Ok(true));
    }
    let mut sizes = Vec::new();
    while !queue.is_empty().unwrap() {
        let removed = queue.deliver(0, |batch| {
            let document = serde_json::to_vec(&openvibes_core::FindingBatch {
                schema_version: SchemaVersion::V1,
                findings: batch.to_vec(),
            })
            .unwrap();
            sizes.push((batch.len(), document.len()));
            Ok::<_, ()>(ack(&batch
                .iter()
                .map(|f| f.finding_id.as_str())
                .collect::<Vec<_>>()))
        });
        assert!(removed.unwrap() > 0);
    }
    assert!(sizes.len() > 1, "split into several batches: {sizes:?}");
    assert!(
        sizes
            .iter()
            .all(|(_, bytes)| *bytes <= ResourceLimits::V1.document_bytes),
        "{sizes:?}"
    );
    assert_eq!(sizes.iter().map(|(n, _)| n).sum::<usize>(), 500);
}

#[test]
fn a_known_clock_skew_never_prunes_findings() {
    let path = path("skew");
    let mut queue = SqliteQueue::open(&path, limits(10)).unwrap();
    assert_eq!(queue.enqueue(&finding("f.a"), 0), Ok(true));
    let forty_days = 40 * 86_400_000;
    // The wall clock jumped 40 days forward; the agent measured it.
    queue.set_clock_skew(forty_days);
    assert_eq!(queue.enqueue(&finding("f.b"), forty_days), Ok(true));
    assert_eq!(queue.len(), Ok(2), "the jump pruned nothing");
    // Without the skew the same moment prunes the old finding.
    queue.set_clock_skew(0);
    assert_eq!(queue.enqueue(&finding("f.c"), forty_days), Ok(true));
    assert_eq!(queue.len(), Ok(2));
}
