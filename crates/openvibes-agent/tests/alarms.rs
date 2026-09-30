//! The alarm thread end to end (P14): recorded audit records in, one
//! collapsed alarm out to the mock platform; a platform before P14; no
//! audit permission.
#![cfg(target_os = "linux")]

mod support;

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use openvibes_agent::alarms::thread::{Shared, spawn, spawn_with};
use openvibes_collectors::process_events::{Received, Seeded, Source, open_audit_socket};
use openvibes_core::{AlarmBatch, CollectorOutcome};
use openvibes_storage::prepare_state_dir;
use openvibes_testkit::{Pki, Seen, serve, status};
use support::{config, enrolled_identity, id};

const WEB_SHELL: &str = "event['parent.name'] == 'nginx' && event['process.name'] == 'sh'";

fn shared(identity: openvibes_transport::ClientIdentity) -> Shared {
    support::shared(identity, WEB_SHELL)
}

fn state_dir(test: &str) -> PathBuf {
    let parent = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("agent-alarms");
    fs::create_dir_all(&parent).unwrap();
    let dir = parent.join(test);
    let _ = fs::remove_dir_all(&dir);
    prepare_state_dir(&dir).unwrap();
    dir
}

fn message(kind: u16, serial: u64, text: &str) -> Vec<u8> {
    let body = format!("audit(1790000000.{:03}:{serial}): {text}", serial % 1000);
    let mut out = Vec::new();
    out.extend_from_slice(&u32::try_from(16 + body.len()).unwrap().to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&[0; 10]);
    out.extend_from_slice(body.as_bytes());
    out
}

/// One exec event's records.
fn exec(serial: u64, pid: u32, ppid: u32, exe: &str, argv: &[&str]) -> Vec<Vec<u8>> {
    let args: String = argv
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            let hex: String = arg.bytes().map(|b| format!("{b:02X}")).collect();
            format!(" a{i}={hex}")
        })
        .collect();
    vec![
        message(
            1300,
            serial,
            &format!(
                "arch=c000003e syscall=59 success=yes exit=0 ppid={ppid} pid={pid} uid=33 \
                 euid=33 exe=\"{exe}\" key=\"openvibes-exec\""
            ),
        ),
        message(1309, serial, &format!("argc={}{args}", argv.len())),
        message(1320, serial, ""),
    ]
}

/// Recorded messages, then silence (as a quiet host).
struct Recorded(std::vec::IntoIter<Vec<u8>>);

impl Source for Recorded {
    fn recv(&mut self, buf: &mut [u8]) -> Received {
        match self.0.next() {
            Some(message) => {
                buf[..message.len()].copy_from_slice(&message);
                Received::Message(message.len())
            }
            None => {
                std::thread::sleep(Duration::from_millis(50));
                Received::Idle
            }
        }
    }
}

/// nginx exec'd, then `sh -c id` three times under it.
fn web_shells() -> Recorded {
    let mut messages = exec(1, 100, 1, "/usr/sbin/nginx", &["nginx"]);
    for n in 0..3 {
        messages.extend(exec(
            2 + n,
            200 + n as u32,
            100,
            "/usr/bin/sh",
            &["sh", "-c", "id"],
        ));
    }
    Recorded(messages.into_iter())
}

fn no_proc(_: u32) -> Option<Seeded> {
    None
}

#[test]
fn three_web_shells_arrive_as_one_alarm_with_count_three() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(202))],
    );
    let shared = shared(identity);
    let dir = state_dir("three");
    spawn_with(web_shells(), no_proc, config(&url, &pki), &shared, &dir).unwrap();
    let sent = seen.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(sent.path, "/v1/alarms");
    assert!(sent.client_cert);
    let batch: AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
    assert_eq!(batch.agent_id, id("agent.1"));
    assert_eq!(batch.alarms.len(), 1);
    let alarm = &batch.alarms[0];
    assert_eq!(alarm.count, 3);
    assert_eq!(alarm.process.args, ["sh", "-c", "id"]);
    assert_eq!(alarm.ancestors[0].exe, "/usr/sbin/nginx");
    assert!(alarm.alarm_id.as_str().starts_with("alarm."));
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(shared.lock().unwrap().health.pending, 0);
}

#[test]
fn a_platform_before_p14_keeps_the_alarm_and_says_so() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(404))],
    );
    let shared = shared(identity);
    let dir = state_dir("unsupported");
    spawn_with(web_shells(), no_proc, config(&url, &pki), &shared, &dir).unwrap();
    seen.recv_timeout(Duration::from_secs(10)).unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    let health = shared.lock().unwrap().health.clone();
    assert!(health.platform_unsupported);
    assert_eq!(health.pending, 1);
    assert_eq!(health.collector, CollectorOutcome::Ok);
}

#[test]
fn without_audit_permission_the_agent_runs_on_and_says_so() {
    let Err(error) = open_audit_socket() else {
        // Running with CAP_AUDIT_READ (as root): nothing to check here.
        return;
    };
    let pki = Pki::new();
    let shared: Shared = Arc::default();
    let dir = state_dir("denied");
    assert!(spawn(config("https://127.0.0.1:1", &pki), &shared, &dir).is_none());
    let outcome: CollectorOutcome = error.code.into();
    assert_eq!(shared.lock().unwrap().health.collector, outcome);
    assert_eq!(outcome, CollectorOutcome::PermissionDenied);
}

#[test]
fn alarms_kept_across_a_restart_are_sent_without_a_new_one() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let dir = state_dir("restart");
    // First run: the platform is down, so the alarm stays queued.
    let shared_first = shared(identity.clone());
    spawn_with(
        web_shells(),
        no_proc,
        config("https://127.0.0.1:1", &pki),
        &shared_first,
        &dir,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(1_500));
    assert_eq!(shared_first.lock().unwrap().health.pending, 1);
    // Restart: a quiet host (no events), and a platform that is up.
    let (url, seen) = serve(
        pki.server_config(true, false),
        vec![Box::new(|_: &Seen| status(202))],
    );
    let shared = shared(identity);
    spawn_with(
        Recorded(Vec::new().into_iter()),
        no_proc,
        config(&url, &pki),
        &shared,
        &dir,
    )
    .unwrap();
    let sent = seen.recv_timeout(Duration::from_secs(10)).unwrap();
    let batch: AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
    assert_eq!(batch.alarms[0].count, 3);
    // No exec event seen yet: the collector cannot tell whether the audit
    // rule is loaded.
    assert_eq!(
        shared.lock().unwrap().health.collector,
        CollectorOutcome::NotFound
    );
}
