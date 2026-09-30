//! The alarm queue: collapse updates, the cap, durable drop counts, batch
//! bounds.

use std::{fs, path::PathBuf};

use openvibes_core::{Alarm, AlarmBatch, Identifier};
use openvibes_storage::AlarmQueue;

const T: i64 = 1_790_000_000_000;

fn path(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("storage-alarms");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{test}.sqlite"));
    let _ = fs::remove_file(&path);
    path
}

fn alarm(n: u32) -> Alarm {
    let batch: AlarmBatch = serde_json::from_str(include_str!(
        "../../../protocol/fixtures/v1/alarm-batch/valid.json"
    ))
    .unwrap();
    let mut alarm = batch.alarms[0].clone();
    alarm.alarm_id = Identifier::new(format!("alarm.{n:032x}")).unwrap();
    alarm.first_seen_unix_ms = T;
    alarm.last_seen_unix_ms = T;
    alarm.count = 1;
    alarm
}

fn ids(alarms: &[Alarm]) -> Vec<&str> {
    alarms.iter().map(|a| a.alarm_id.as_str()).collect()
}

#[test]
fn a_repeat_updates_the_same_row() {
    let mut queue = AlarmQueue::open(&path("repeat")).unwrap();
    queue.upsert(&alarm(1)).unwrap();
    let mut again = alarm(1);
    again.count = 3;
    again.last_seen_unix_ms = T + 5;
    again.process.args = vec!["changed".into()];
    queue.upsert(&again).unwrap();
    let batch = queue.batch().unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!((batch[0].count, batch[0].last_seen_unix_ms), (3, T + 5));
    // Everything else stays as first queued.
    assert_eq!(batch[0].process.args, alarm(1).process.args);
    // A late, smaller repeat never lowers it.
    queue.upsert(&alarm(1)).unwrap();
    assert_eq!(queue.batch().unwrap()[0].count, 3);
}

#[test]
fn a_delivered_alarm_that_grew_is_unsent_again() {
    let mut queue = AlarmQueue::open(&path("grew")).unwrap();
    queue.upsert(&alarm(1)).unwrap();
    let batch = queue.batch().unwrap();
    queue.sent(&batch).unwrap();
    assert_eq!(queue.pending().unwrap(), 0);
    let mut again = alarm(1);
    again.count = 2;
    queue.upsert(&again).unwrap();
    assert_eq!(queue.pending().unwrap(), 1);
    assert_eq!(queue.batch().unwrap()[0].count, 2);
}

#[test]
fn a_repeat_during_delivery_is_not_marked_sent() {
    let mut queue = AlarmQueue::open(&path("race")).unwrap();
    queue.upsert(&alarm(1)).unwrap();
    let batch = queue.batch().unwrap();
    let mut again = alarm(1);
    again.count = 2;
    queue.upsert(&again).unwrap();
    queue.sent(&batch).unwrap();
    assert_eq!(queue.pending().unwrap(), 1);
}

#[test]
fn the_cap_drops_the_oldest_unsent_and_counts_only_those() {
    let path = path("cap");
    let mut queue = AlarmQueue::open(&path).unwrap();
    queue.upsert(&alarm(0)).unwrap();
    let batch = queue.batch().unwrap();
    queue.sent(&batch).unwrap();
    for n in 1..=1_000 {
        queue.upsert(&alarm(n)).unwrap();
    }
    // The delivered row made room first: nothing lost yet.
    assert_eq!(queue.dropped_total().unwrap(), 0);
    assert_eq!(queue.pending().unwrap(), 1_000);
    queue.upsert(&alarm(1_001)).unwrap();
    assert_eq!(queue.dropped_total().unwrap(), 1);
    assert_eq!(queue.pending().unwrap(), 1_000);
    assert_eq!(ids(&queue.batch().unwrap())[0], alarm(2).alarm_id.as_str());
    drop(queue);
    // Durable, and never decreases.
    let mut queue = AlarmQueue::open(&path).unwrap();
    assert_eq!(queue.dropped_total().unwrap(), 1);
    let batch = queue.batch().unwrap();
    queue.drop_batch(&batch).unwrap();
    queue.drop_batch(&batch).unwrap();
    let dropped = 1 + batch.len() as u64;
    assert_eq!(queue.dropped_total().unwrap(), dropped);
    drop(queue);
    assert_eq!(
        AlarmQueue::open(&path).unwrap().dropped_total().unwrap(),
        dropped
    );
}

#[test]
fn old_delivered_rows_are_pruned_without_counting() {
    let mut queue = AlarmQueue::open(&path("prune")).unwrap();
    queue.upsert(&alarm(1)).unwrap();
    let batch = queue.batch().unwrap();
    queue.sent(&batch).unwrap();
    let mut later = alarm(2);
    later.first_seen_unix_ms = T + 11 * 60_000;
    later.last_seen_unix_ms = later.first_seen_unix_ms;
    queue.upsert(&later).unwrap();
    // alarm 1 is gone: a repeat now would be a new row, unsent.
    let mut again = alarm(1);
    again.count = 2;
    queue.upsert(&again).unwrap();
    assert_eq!(queue.batch().unwrap()[1].count, 2);
    assert_eq!(queue.dropped_total().unwrap(), 0);
}

#[test]
fn batches_are_bounded_by_count_and_bytes() {
    let mut queue = AlarmQueue::open(&path("bounds")).unwrap();
    for n in 1..=150 {
        queue.upsert(&alarm(n)).unwrap();
    }
    assert_eq!(queue.batch().unwrap().len(), 100);

    let mut queue = AlarmQueue::open(&path("bytes")).unwrap();
    for n in 1..=20 {
        let mut big = alarm(n);
        big.process.args = vec!["x".repeat(4_000)];
        big.process.cwd = Some("/".repeat(4_000));
        big.ancestors.iter_mut().for_each(|a| {
            a.args = vec!["y".repeat(4_000)];
            a.cwd = Some("/".repeat(4_000));
        });
        queue.upsert(&big).unwrap();
    }
    let batch = queue.batch().unwrap();
    let size = serde_json::to_vec(&batch).unwrap().len();
    assert!(
        batch.len() < 20 && size <= 262_144,
        "{} {size}",
        batch.len()
    );
}

#[test]
fn alarms_lost_before_the_queue_are_counted_durably() {
    let path = path("lost");
    let mut queue = AlarmQueue::open(&path).unwrap();
    queue.add_dropped(2).unwrap();
    drop(queue);
    assert_eq!(AlarmQueue::open(&path).unwrap().dropped_total().unwrap(), 2);
}
