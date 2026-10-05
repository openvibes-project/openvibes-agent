//! Synthetic audit records in the kernel's format (`kernel/auditsc.c`:
//! `audit_log_exit`, `audit_log_execve_info`).

use std::time::{Duration, Instant};

use super::{EVENT_ARG_BYTES, Joiner, OPEN_EVENTS, ProcessStart};

fn message(kind: u16, serial: u64, text: &str) -> Vec<u8> {
    let body = format!("audit(1790000000.123:{serial}): {text}");
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(body.as_bytes());
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

fn syscall(serial: u64, extra: &str) -> Vec<u8> {
    message(
        1300,
        serial,
        &format!(
            "arch=c000003e syscall=59 success=yes exit=0 a0=55d1 a1=55d2 a2=55d3 a3=0 \
             items=2 ppid=100 pid=200 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 \
             fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=3 comm=\"echo\" \
             exe=\"/usr/bin/echo\" subj=unconfined_u:unconfined_r:unconfined_t:s0 {extra}"
        ),
    )
}

/// The records of one event, `SYSCALL` first and `EOE` last.
fn event(serial: u64, key: &str, execve: &[&str]) -> Vec<Vec<u8>> {
    let mut records = vec![syscall(serial, key)];
    records.extend(execve.iter().map(|text| message(1309, serial, text)));
    records.push(message(1307, serial, "cwd=\"/home/user\""));
    records.push(message(
        1302,
        serial,
        "item=0 name=\"/usr/bin/echo\" inode=1 nametype=NORMAL",
    ));
    records.push(message(1327, serial, "proctitle=6563686F"));
    records.push(message(1320, serial, ""));
    records
}

fn join(records: &[Vec<u8>]) -> Vec<ProcessStart> {
    let mut joiner = Joiner::default();
    let now = Instant::now();
    records
        .iter()
        .filter_map(|record| joiner.push(record, now))
        .collect()
}

const KEY: &str = "key=\"openvibes-exec\"";

/// `echo "a b" 'c"d'`: spaces and quotes are hex-encoded.
fn quoting() -> Vec<Vec<u8>> {
    let execve = format!("argc=3 a0=\"echo\" a1={} a2={}", hex(b"a b"), hex(b"c\"d"));
    event(7, KEY, &[&execve])
}

#[test]
fn quoted_and_hex_arguments_join_exactly() {
    let starts = join(&quoting());
    assert_eq!(
        starts,
        vec![ProcessStart {
            pid: 200,
            ppid: 100,
            uid: 1000,
            euid: 1000,
            exe: b"/usr/bin/echo".to_vec(),
            args: vec![b"echo".to_vec(), b"a b".to_vec(), b"c\"d".to_vec()],
            args_truncated: false,
            cwd: Some(b"/home/user".to_vec()),
            at_unix_ms: 1_790_000_000_123,
            parent: None,
        }]
    );
}

#[test]
fn a_long_argument_joins_across_pieces_and_records() {
    // 10 KiB: `a1_len` then pieces, quoted or hex, split over two records.
    let long: Vec<u8> = (0..10_240).map(|i| b'a' + (i % 26) as u8).collect();
    let (first, rest) = long.split_at(7_500);
    let (second, third) = rest.split_at(2_000);
    let one = format!(
        "argc=3 a0=\"cat\" a1_len=10240 a1[0]=\"{}\"",
        std::str::from_utf8(first).unwrap()
    );
    let two = format!(
        "a1[1]={} a1[2]=\"{}\" a2=\"x\"",
        hex(second),
        std::str::from_utf8(third).unwrap()
    );
    let starts = join(&event(8, KEY, &[&one, &two]));
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].args, vec![b"cat".to_vec(), long, b"x".to_vec()]);
    assert!(!starts[0].args_truncated);
}

#[test]
fn a_non_utf8_byte_is_kept_raw() {
    let execve = format!("argc=2 a0=\"x\" a1={}", hex(b"A\xffB"));
    let starts = join(&event(9, KEY, &[&execve]));
    assert_eq!(starts[0].args[1], b"A\xffB");
}

#[test]
fn other_keys_and_failed_calls_are_ignored() {
    assert!(join(&event(1, "key=\"other\"", &["argc=1 a0=\"x\""])).is_empty());
    assert!(join(&event(2, "key=(null)", &["argc=1 a0=\"x\""])).is_empty());
    let mut failed = event(3, KEY, &["argc=1 a0=\"x\""]);
    failed[0] = message(
        1300,
        3,
        &format!("success=no exit=-2 ppid=1 pid=2 uid=0 exe=\"/x\" {KEY}"),
    );
    assert!(join(&failed).is_empty());
    // Several rule keys are hex, separated by 0x01.
    let keys = format!("key={}", hex(b"audit-all\x01openvibes-exec"));
    assert_eq!(join(&event(4, &keys, &["argc=1 a0=\"x\""])).len(), 1);
}

#[test]
fn an_event_without_eoe_is_dropped_after_a_second_and_counted() {
    let mut joiner = Joiner::default();
    let now = Instant::now();
    let records = quoting();
    for record in &records[..records.len() - 1] {
        assert!(joiner.push(record, now).is_none());
    }
    assert_eq!(joiner.expire(now + Duration::from_millis(900)), 0);
    assert_eq!(joiner.expire(now + Duration::from_millis(1_100)), 1);
    assert!(joiner.push(records.last().unwrap(), now).is_none());
    assert_eq!(joiner.expire(now + Duration::from_secs(5)), 0);
}

#[test]
fn too_many_open_events_drop_the_oldest_and_count() {
    let mut joiner = Joiner::default();
    let now = Instant::now();
    for serial in 0..=OPEN_EVENTS as u64 {
        joiner.push(&syscall(serial, KEY), now + Duration::from_micros(serial));
    }
    assert!(joiner.push(&message(1320, 0, ""), now).is_none());
    assert!(joiner.push(&message(1320, 1, ""), now).is_some());
    assert_eq!(joiner.expire(now), 1);
}

#[test]
fn arguments_over_the_budget_are_cut_not_dropped() {
    // A padded command line still raises its alarm (no evasion by size).
    let pad = "p".repeat(7_000);
    let texts: Vec<String> = std::iter::once("argc=13 a0=\"sh\"".to_owned())
        .chain((1..13).map(|i| format!("a{i}=\"{pad}\"")))
        .collect();
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let starts = join(&event(5, KEY, &refs));
    assert_eq!(starts.len(), 1);
    assert!(starts[0].args_truncated);
    let kept: usize = starts[0].args.iter().map(Vec::len).sum();
    assert_eq!(kept, EVENT_ARG_BYTES);
}

#[test]
fn missing_arguments_mark_the_start_truncated() {
    let starts = join(&event(6, KEY, &["argc=3 a0=\"x\" a2=\"z\""]));
    assert_eq!(starts[0].args, vec![b"x".to_vec()]);
    assert!(starts[0].args_truncated);
}

#[test]
fn garbage_never_panics() {
    let mut corpus: Vec<Vec<u8>> = quoting();
    corpus.extend(event(
        10,
        KEY,
        &["argc=2 a0=\"a\" a1_len=4 a1[0]=\"ab\" a1[1]=6364"],
    ));
    // A padded argument in kernel-sized pieces, so the decode that stops at
    // the budget (board #106) is mutated too: any `a1[i]` after the first
    // appends, whatever its order.
    let piece = "78".repeat(3_750);
    let pieces: Vec<String> = std::iter::once("argc=2 a0=\"sh\" a1_len=90000".to_owned())
        .chain((0..12).map(|i| format!("a1[{i}]={piece}")))
        .collect();
    let refs: Vec<&str> = pieces.iter().map(String::as_str).collect();
    corpus.extend(event(11, KEY, &refs));
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut joiner = Joiner::default();
    let now = Instant::now();
    for _ in 0..100_000 {
        let mut record = corpus[(next() % corpus.len() as u64) as usize].clone();
        for _ in 0..=next() % 4 {
            match next() % 3 {
                0 if !record.is_empty() => {
                    let at = (next() % record.len() as u64) as usize;
                    record[at] = next() as u8;
                }
                1 => record.truncate((next() % (record.len() as u64 + 1)) as usize),
                _ => record.push(next() as u8),
            }
        }
        let _ = joiner.push(&record, now);
        let _ = joiner.expire(now);
    }
}

struct Recorded(std::vec::IntoIter<super::Received>, Vec<Vec<u8>>);

impl super::Source for Recorded {
    fn recv(&mut self, buf: &mut [u8]) -> super::Received {
        let next = self.0.next().unwrap_or(super::Received::Closed);
        if let super::Received::Message(i) = next {
            let message = &self.1[i];
            buf[..message.len()].copy_from_slice(message);
            return super::Received::Message(message.len());
        }
        next
    }
}

#[test]
fn a_full_channel_counts_drops_and_never_blocks() {
    use std::sync::{Arc, mpsc::sync_channel};
    let mut messages = Vec::new();
    for serial in 0..3 {
        messages.extend(event(serial, KEY, &["argc=1 a0=\"x\""]));
    }
    let script = (0..messages.len())
        .map(super::Received::Message)
        // ENOBUFS once: counted, and reading goes on.
        .chain([super::Received::Lost, super::Received::Idle])
        .collect::<Vec<_>>();
    let (tx, rx) = sync_channel(1);
    let dropped = Arc::new(super::Drops::default());
    let reader = super::spawn_reader(
        Recorded(script.into_iter(), messages),
        tx,
        Arc::clone(&dropped),
        |pid| {
            Some(super::Seeded {
                pid,
                name: b"parent".to_vec(),
                ..super::Seeded::default()
            })
        },
    )
    .unwrap();
    // Nobody receives until the reader has finished: it must not block.
    reader.join().unwrap();
    assert_eq!(dropped.total(), 2 + 1);
    let starts: Vec<_> = rx.try_iter().collect();
    assert_eq!(starts.len(), 1);
    // The reader read the parent at once.
    assert_eq!(starts[0].parent.as_ref().unwrap().pid, starts[0].ppid);
}

#[cfg(target_os = "linux")]
#[test]
fn this_process_reads_from_proc() {
    let me = super::read_process(std::process::id()).unwrap();
    assert!(!me.name.is_empty());
    assert!(me.exe.is_some());
    assert!(!me.args.is_empty());
    assert_eq!(me.uid, rustix::process::getuid().as_raw());
    assert_eq!(
        super::read_process(std::process::id())
            .map(|me| me.ppid)
            .unwrap(),
        rustix::process::getppid().map_or(0, |p| p.as_raw_nonzero().get() as u32)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn opening_the_socket_fails_cleanly_without_the_capability() {
    // CI runs unprivileged: either permission_denied or (with the
    // capability, as root) a socket; never a panic.
    match super::open_audit_socket() {
        Ok(_) => {}
        Err(error) => assert_eq!(
            error.code,
            openvibes_core::CollectorErrorCode::PermissionDenied
        ),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_comm_with_spaces_and_parens_parses_and_long_cmdlines_are_cut() {
    let root = std::env::temp_dir().join(format!("ov-proc-{}", std::process::id()));
    let dir = root.join("42");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("stat"), "42 (a) b (c) S 7 42 42 0 -1").unwrap();
    std::fs::write(dir.join("status"), "Name:\tx\nUid:\t1000\t0\t0\t0\n").unwrap();
    let mut cmdline = b"mysql\0-psecret\0".to_vec();
    cmdline.extend(std::iter::repeat_n(b'x', 5_000));
    std::fs::write(dir.join("cmdline"), cmdline).unwrap();
    let seeded = super::seed::read_from(&root, 42).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
    assert_eq!(seeded.name, b"a) b (c");
    assert_eq!((seeded.ppid, seeded.uid, seeded.euid), (7, 1000, 0));
    assert_eq!(seeded.args[..2], [b"mysql".to_vec(), b"-psecret".to_vec()]);
    assert!(seeded.args_truncated);
    assert_eq!(seeded.exe, None);
    assert!(super::seed::read_from(&root, 43).is_none());
}

#[test]
fn a_parent_the_reader_saw_exec_is_not_read_again() {
    use std::sync::{Arc, mpsc::sync_channel};
    // pid 200 execs under 100, then 300 execs under 200.
    let mut messages = Vec::new();
    for (serial, (pid, ppid)) in [(200_u32, 100_u32), (300, 200)].into_iter().enumerate() {
        let mut records = event(serial as u64, KEY, &["argc=1 a0=\"x\""]);
        records[0] = message(
            1300,
            serial as u64,
            &format!("success=yes ppid={ppid} pid={pid} uid=0 euid=0 exe=\"/x\" {KEY}"),
        );
        messages.extend(records);
    }
    let script: Vec<_> = (0..messages.len()).map(super::Received::Message).collect();
    let (tx, rx) = sync_channel(8);
    super::spawn_reader(
        Recorded(script.into_iter(), messages),
        tx,
        Arc::new(super::Drops::default()),
        |pid| {
            Some(super::Seeded {
                pid,
                ..super::Seeded::default()
            })
        },
    )
    .unwrap()
    .join()
    .unwrap();
    let starts: Vec<_> = rx.try_iter().collect();
    assert!(starts[0].parent.is_some(), "100 was never seen exec");
    assert!(starts[1].parent.is_none(), "200 was: the table knows it");

    // A start dropped on a full channel never reached the table, so its
    // child still gets a snapshot: 50 fills the channel, 200 is dropped,
    // 300 (child of 200) must look 200 up.
    static LOOKED_UP: std::sync::Mutex<Vec<u32>> = std::sync::Mutex::new(Vec::new());
    let mut messages = Vec::new();
    for (serial, (pid, ppid)) in [(50_u32, 1_u32), (200, 100), (300, 200)]
        .into_iter()
        .enumerate()
    {
        let mut records = event(serial as u64, KEY, &["argc=1 a0=\"x\""]);
        records[0] = message(
            1300,
            serial as u64,
            &format!("success=yes ppid={ppid} pid={pid} uid=0 euid=0 exe=\"/x\" {KEY}"),
        );
        messages.extend(records);
    }
    let script: Vec<_> = (0..messages.len()).map(super::Received::Message).collect();
    let (tx, rx) = sync_channel(1);
    super::spawn_reader(
        Recorded(script.into_iter(), messages),
        tx,
        Arc::new(super::Drops::default()),
        |pid| {
            LOOKED_UP.lock().unwrap().push(pid);
            None
        },
    )
    .unwrap()
    .join()
    .unwrap();
    assert_eq!(rx.try_iter().count(), 1);
    assert!(LOOKED_UP.lock().unwrap().contains(&200));
}

/// Board #106: a long hex argument in pieces is decoded only as far as the
/// budget; the bytes kept are exact, and a piece past the budget that isn't
/// hex still marks the start truncated (checked, just not decoded).
#[test]
fn hex_pieces_past_the_budget_are_checked_not_decoded() {
    let arg: Vec<u8> = (0..70_000u32).map(|i| b"ab \x01"[i as usize % 4]).collect();
    let hexed = hex(&arg);
    let mut texts = vec![format!("argc=2 a0=\"sh\" a1_len={}", arg.len())];
    for (n, piece) in hexed.as_bytes().chunks(7_500).enumerate() {
        texts.push(format!("a1[{n}]={}", std::str::from_utf8(piece).unwrap()));
    }
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let starts = join(&event(7, KEY, &refs));
    assert_eq!(starts.len(), 1);
    assert!(starts[0].args_truncated);
    assert_eq!(
        starts[0].args[1],
        arg[..EVENT_ARG_BYTES - 2],
        "exact, cut at the budget"
    );

    // The last piece (past the budget) carries a non-hex byte.
    let last = texts.len() - 1;
    texts[last] = texts[last].replacen('6', "Z", 1);
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let starts = join(&event(8, KEY, &refs));
    assert!(starts[0].args_truncated);
    assert_eq!(
        starts[0].args[1].len(),
        EVENT_ARG_BYTES - 2,
        "what came before is kept"
    );
}
