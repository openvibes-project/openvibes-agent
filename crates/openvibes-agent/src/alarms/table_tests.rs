use std::time::{Duration, Instant};

use openvibes_collectors::process_events::{ProcessStart, Seeded};
use openvibes_rules::{EventValue, ProcessEvent};

use super::table::{CMDLINE_BYTES, EXITED_KEPT, MAX_ENTRIES, PATH_BYTES, ProcessTable};

fn start(pid: u32, ppid: u32, exe: &str, args: &[&str]) -> ProcessStart {
    ProcessStart {
        pid,
        ppid,
        uid: 1000,
        euid: 1000,
        exe: exe.as_bytes().to_vec(),
        exe_from_filename: false,
        args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        args_truncated: false,
        cwd: Some(b"/srv".to_vec()),
        at_unix_ms: 1_790_000_000_000,
        parent: None,
    }
}

fn seeded(pid: u32, ppid: u32, comm: &str, exe: Option<&str>, args: &[&str]) -> Seeded {
    Seeded {
        pid,
        ppid,
        uid: 33,
        euid: 33,
        name: comm.as_bytes().to_vec(),
        exe: exe.map(|e| e.as_bytes().to_vec()),
        args: args.iter().map(|a| a.as_bytes().to_vec()).collect(),
        args_truncated: false,
        cwd: None,
    }
}

fn none(_: u32) -> Option<Seeded> {
    None
}

fn text<'a>(event: &'a ProcessEvent, key: &str) -> Option<&'a str> {
    match event.get(key) {
        Some(EventValue::String(value)) => Some(value),
        _ => None,
    }
}

fn list(event: &ProcessEvent, key: &str) -> Vec<String> {
    match event.get(key) {
        Some(EventValue::Strings(items)) => items.clone(),
        _ => panic!("{key} is not a list"),
    }
}

#[test]
fn bytes_decode_lossily_and_are_cut_on_char_boundaries() {
    let mut table = ProcessTable::default();
    let mut exe = b"/opt/".to_vec();
    exe.extend("é".repeat(PATH_BYTES).as_bytes());
    let mut s = start(10, 0, "", &[]);
    s.exe = exe;
    s.args = vec![b"a\xffb".to_vec(), vec![b'x'; CMDLINE_BYTES]];
    let (event, _) = table.start(&s, Instant::now(), none);
    let exe = text(&event, "process.exe").unwrap();
    assert!(exe.len() <= PATH_BYTES && exe.len() > PATH_BYTES - 2);
    let cmdline = text(&event, "process.cmdline").unwrap();
    assert!(cmdline.starts_with("a\u{fffd}b "));
    assert_eq!(cmdline.len(), CMDLINE_BYTES);
    assert_eq!(
        event.get("process.cmdline_truncated"),
        Some(&EventValue::Boolean(true))
    );
    assert_eq!(event.get("process.euid"), Some(&EventValue::Integer(1000)));
}

#[test]
fn a_truncated_start_is_marked_truncated() {
    let mut s = start(10, 0, "/bin/sh", &["sh"]);
    s.args_truncated = true;
    let (event, _) = ProcessTable::default().start(&s, Instant::now(), none);
    assert_eq!(
        event.get("process.cmdline_truncated"),
        Some(&EventValue::Boolean(true))
    );
}

#[test]
fn names_and_seeded_exes() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    // Readable link; absolute argv[0]; [comm]; [unknown].
    let parents = [
        seeded(2, 3, "nginx", Some("/usr/sbin/nginx"), &["nginx: worker"]),
        seeded(3, 4, "java", None, &["/usr/bin/java", "-jar"]),
        seeded(4, 5, "mysqld", None, &["mysqld"]),
        seeded(5, 0, "", None, &[]),
    ];
    let lookup = |pid: u32| parents.iter().find(|p| p.pid == pid).cloned();
    let (event, lineage) = table.start(&start(1, 2, "/usr/bin/sh", &["sh"]), now, lookup);
    assert_eq!(text(&event, "process.name"), Some("sh"));
    assert_eq!(text(&event, "parent.name"), Some("nginx"));
    assert_eq!(text(&event, "parent.exe"), Some("/usr/sbin/nginx"));
    let exes: Vec<&str> = lineage.ancestors.iter().map(|a| a.exe.as_str()).collect();
    assert_eq!(
        exes,
        ["/usr/sbin/nginx", "/usr/bin/java", "[mysqld]", "[unknown]"]
    );
    assert!(lineage.ancestors.iter().all(|a| a.seeded));
    assert_eq!(
        list(&event, "ancestors.names"),
        ["", "java", "mysqld", "nginx"]
    );
}

#[test]
fn a_forked_worker_is_read_on_a_miss_and_a_gone_parent_stays_missing() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    // nginx master exec'd after the agent started; its worker forked
    // without exec, so only /proc knows it.
    table.start(&start(100, 1, "/usr/sbin/nginx", &["nginx"]), now, none);
    let worker = seeded(101, 100, "nginx", None, &["nginx: worker process"]);
    let (event, lineage) = table.start(
        &start(102, 101, "/usr/bin/sh", &["sh", "-c", "id"]),
        now,
        |pid| (pid == 101).then(|| worker.clone()),
    );
    assert_eq!(text(&event, "parent.name"), Some("nginx"));
    assert_eq!(lineage.ancestors.len(), 2);
    assert_eq!(lineage.ancestors[1].exe, "/usr/sbin/nginx");
    assert!(!lineage.ancestors[1].seeded);

    let (event, lineage) = table.start(&start(200, 999, "/usr/bin/sh", &["sh"]), now, none);
    assert!(event.get("parent.name").is_none());
    assert!(event.get("ancestors.names").is_none());
    assert!(lineage.ancestors.is_empty());
}

#[test]
fn ancestors_are_nearest_first_at_most_five_and_deduplicated() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    for pid in 1..=7 {
        table.start(&start(pid, pid - 1, "/usr/bin/bash", &["bash"]), now, none);
    }
    let (event, lineage) = table.start(&start(8, 7, "/usr/bin/sh", &["sh"]), now, none);
    let pids: Vec<u32> = lineage.ancestors.iter().map(|a| a.pid).collect();
    assert_eq!(pids, [7, 6, 5, 4, 3]);
    assert_eq!(list(&event, "ancestors.names"), ["bash"]);
    assert_eq!(list(&event, "ancestors.exes"), ["/usr/bin/bash"]);
}

#[test]
fn a_reused_pid_replaces_the_entry() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    table.start(&start(5, 0, "/usr/bin/bash", &["bash"]), now, none);
    table.start(&start(5, 0, "/usr/bin/python3", &["python3"]), now, none);
    let (event, _) = table.start(&start(6, 5, "/usr/bin/sh", &["sh"]), now, none);
    assert_eq!(text(&event, "parent.name"), Some("python3"));
    assert_eq!(table.len(), 2);
}

#[test]
fn exited_processes_are_kept_ten_minutes() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    table.start(&start(5, 0, "/usr/bin/bash", &["bash"]), now, none);
    table.reap(|_| false, now);
    let (event, _) = table.start(&start(6, 5, "/usr/bin/sh", &["sh"]), now, none);
    assert_eq!(text(&event, "parent.name"), Some("bash"));
    table.reap(|pid| pid == 6, now + EXITED_KEPT + Duration::from_secs(1));
    assert_eq!(table.len(), 1);
}

#[test]
fn a_full_table_evicts_exited_then_seeded_first() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    table.start(&start(1, 0, "/usr/bin/exited", &["x"]), now, none);
    table.reap(|_| false, now);
    let old = seeded(2, 0, "seeded", None, &[]);
    let later = now + Duration::from_secs(60);
    table.start(&start(3, 2, "/usr/bin/live", &["x"]), later, |_| {
        Some(old.clone())
    });
    // Fill until the first eviction; the fillers are older than `live`.
    for pid in 10.. {
        let before = table.len();
        table.start(&start(pid, 0, "/bin/true", &["true"]), now, none);
        if table.len() < before {
            break;
        }
    }
    assert!(table.len() <= MAX_ENTRIES);
    let (event, _) = table.start(&start(900_000, 1, "/bin/sh", &["sh"]), now, none);
    assert!(event.get("parent.name").is_none(), "exited went first");
    let (event, _) = table.start(&start(900_001, 3, "/bin/sh", &["sh"]), now, none);
    assert_eq!(text(&event, "parent.name"), Some("live"));
}

#[test]
fn alarm_processes_are_masked_with_their_own_exe() {
    let mut table = ProcessTable::default();
    let now = Instant::now();
    // sudo's own arguments: masked through the program-word rule.
    table.start(
        &start(
            1,
            0,
            "/usr/bin/sudo",
            &["sudo", "mysql", "-uroot", "-psecret"],
        ),
        now,
        none,
    );
    // A pre-agent mysql whose exe link is unreadable: `[mysql]`, masked
    // through argv[0].
    let mysql = seeded(2, 0, "mysql", None, &["mysql", "-uroot", "-psecret"]);
    table.start(&start(3, 2, "/usr/bin/sh", &["sh"]), now, |_| {
        Some(mysql.clone())
    });
    let (_, lineage) = table.start(&start(4, 1, "/usr/bin/sh", &["sh"]), now, none);
    let (_, ancestors) = lineage.to_alarm_processes();
    assert_eq!(ancestors[0].args, ["sudo", "mysql", "-uroot", "-p***"]);
    let (_, lineage) = table.start(&start(5, 2, "/usr/bin/sh", &["sh"]), now, none);
    let (_, ancestors) = lineage.to_alarm_processes();
    assert_eq!(ancestors[0].exe, "[mysql]");
    assert_eq!(ancestors[0].args, ["mysql", "-uroot", "-p***"]);
    assert!(ancestors[0].seeded);
}

#[test]
fn a_parent_gone_before_the_engine_uses_the_readers_snapshot() {
    // The pre-agent parent exited between the reader joining the event and
    // the engine getting to it (seen on a real kernel under load).
    let mut table = ProcessTable::default();
    let mut s = start(20, 10, "/usr/bin/dash", &["sh", "-c", "true"]);
    s.parent = Some(seeded(10, 1, "fake-nginx", None, &["/tmp/fake-nginx"]));
    let (event, lineage) = table.start(&s, Instant::now(), none);
    assert_eq!(text(&event, "parent.name"), Some("fake-nginx"));
    assert_eq!(lineage.ancestors[0].exe, "/tmp/fake-nginx");
    // A snapshot of another pid is never used for this parent.
    let mut other = start(21, 11, "/usr/bin/dash", &["sh"]);
    other.parent = Some(seeded(12, 1, "wrong", None, &[]));
    let (event, _) = table.start(&other, Instant::now(), none);
    assert!(event.get("parent.name").is_none());
}
