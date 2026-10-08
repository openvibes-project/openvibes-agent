//! The alarm thread end to end (P14): recorded audit records in, one
//! collapsed alarm out to the mock platform; a platform before P14; no
//! audit permission.
#![cfg(target_os = "linux")]

mod support;

use std::{fs, path::PathBuf, sync::Arc, time::Duration};

use openvibes_agent::alarms::thread::{Shared, spawn, spawn_opened, spawn_with};
use openvibes_collectors::process_events::{
    Next, Opened, Received, Seeded, Source, StartSource, open_audit_socket, open_process_starts,
};
use openvibes_core::{AlarmBatch, AlarmFallback, AlarmSource, CollectorOutcome, FallbackDetail};
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
    assert!(
        spawn(config("https://127.0.0.1:1", &pki), true, &shared, &dir)
            .unwrap()
            .is_none()
    );
    let outcome: CollectorOutcome = error.code.into();
    assert_eq!(shared.lock().unwrap().health.collector, outcome);
    assert_eq!(outcome, CollectorOutcome::PermissionDenied);
    // Forced to audit: eBPF was not tried, so there is no fallback reason.
    let health = shared.lock().unwrap().health.clone();
    assert_eq!(health.source, Some(AlarmSource::None));
    assert_eq!(health.fallback, None);
}

#[cfg(feature = "ebpf")]
#[test]
fn every_ebpf_error_has_a_detail() {
    use openvibes_collectors::process_events::{EbpfError::*, fallback_detail};
    assert_eq!(fallback_detail(&NoBtf), FallbackDetail::NoBtf);
    assert_eq!(
        fallback_detail(&MissingField("task_struct")),
        FallbackDetail::Other
    );
    assert_eq!(fallback_detail(&Capability), FallbackDetail::Capability);
    assert_eq!(fallback_detail(&Lockdown), FallbackDetail::Lockdown);
    assert_eq!(fallback_detail(&LsmDenied), FallbackDetail::LsmDenied);
    assert_eq!(
        fallback_detail(&Verifier("x".into())),
        FallbackDetail::Verifier
    );
    assert_eq!(fallback_detail(&Other("x".into())), FallbackDetail::Other);
}

#[test]
fn forced_audit_reports_audit_without_fallback() {
    let opened = open_process_starts(true, || true);
    // `None` where the test host has no audit socket (no CAP_AUDIT_READ).
    assert!(matches!(
        opened.source,
        AlarmSource::Audit | AlarmSource::None
    ));
    assert_eq!(opened.starts.is_some(), opened.source == AlarmSource::Audit);
    assert!(opened.fallback.is_none());
}

#[test]
fn without_ebpf_the_fallback_says_why() {
    let opened = open_process_starts(false, || true);
    match opened.source {
        // Running with CAP_BPF and CAP_PERFMON (as root).
        AlarmSource::Ebpf => assert!(opened.fallback.is_none()),
        AlarmSource::Audit => assert!(opened.fallback.unwrap().audit_rule_loaded),
        AlarmSource::None => {
            assert!(!opened.fallback.unwrap().audit_rule_loaded);
            assert!(opened.error.is_some());
        }
    }
    assert_eq!(opened.starts.is_some(), opened.source != AlarmSource::None);
}

#[test]
fn the_first_keyed_record_shows_the_audit_rule_is_loaded() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let shared = shared(identity);
    shared.lock().unwrap().health.fallback = Some(AlarmFallback {
        detail: FallbackDetail::Capability,
        audit_rule_loaded: false,
    });
    let dir = state_dir("rule-loaded");
    spawn_with(
        web_shells(),
        no_proc,
        config("https://127.0.0.1:1", &pki),
        &shared,
        &dir,
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let health = shared.lock().unwrap().health.clone();
    assert_eq!(health.collector, CollectorOutcome::Ok);
    assert!(health.fallback.unwrap().audit_rule_loaded);
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

/// A new web shell (a new alarm) every 50 ms for 3.5 s, then silence.
struct Storm {
    messages: std::vec::IntoIter<Vec<u8>>,
    next_at: std::time::Instant,
}

impl Source for Storm {
    fn recv(&mut self, buf: &mut [u8]) -> Received {
        let now = std::time::Instant::now();
        if now < self.next_at {
            std::thread::sleep((self.next_at - now).min(Duration::from_millis(10)));
            return Received::Idle;
        }
        match self.messages.next() {
            Some(message) => {
                // An exec is 4 messages; pace whole execs.
                if message.len() > 16 && message[4..6] == 1320_u16.to_ne_bytes() {
                    self.next_at = std::time::Instant::now() + Duration::from_millis(50);
                }
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

/// Board #110: alarms go out about a second after the first, and a storm
/// still batches, at most one POST a second, not one per alarm.
#[test]
fn a_storm_is_sent_in_batches_at_most_once_a_second() {
    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let handlers: Vec<openvibes_testkit::Handler> = (0..20)
        .map(|_| Box::new(|_: &Seen| status(202)) as _)
        .collect();
    let (url, seen) = serve(pki.server_config(true, false), handlers);
    let shared = shared(identity);
    let dir = state_dir("storm");
    let mut messages = exec(1, 100, 1, "/usr/sbin/nginx", &["nginx"]);
    for n in 0..70u32 {
        let script = format!("id {n}");
        messages.extend(exec(
            2 + u64::from(n),
            200 + n,
            100,
            "/usr/bin/sh",
            &["sh", "-c", &script],
        ));
    }
    let storm = Storm {
        messages: messages.into_iter(),
        next_at: std::time::Instant::now(),
    };
    let started = std::time::Instant::now();
    spawn_with(storm, no_proc, config(&url, &pki), &shared, &dir).unwrap();
    let mut at = Vec::new();
    let mut alarms = 0;
    while let Ok(sent) = seen.recv_timeout(Duration::from_secs(4)) {
        at.push(started.elapsed());
        let batch: AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
        alarms += batch.alarms.len();
        if alarms >= 70 {
            break;
        }
    }
    assert_eq!(alarms, 70, "every alarm sent once ({at:?})");
    assert!(
        at[0] < Duration::from_millis(2_500),
        "the first within ~1 s of the first alarm: {at:?}"
    );
    assert!(
        at.len() <= 6,
        "batched, not one POST per alarm: {} POSTs at {at:?}",
        at.len()
    );
    for pair in at.windows(2) {
        assert!(
            pair[1] - pair[0] >= Duration::from_millis(900),
            "at most one POST a second: {at:?}"
        );
    }
}

/// A stand-in for the attached eBPF program; says when it is dropped
/// (detached).
struct Attached(Arc<std::sync::atomic::AtomicBool>);

impl StartSource for Attached {
    fn next(&mut self) -> Next {
        Next::Idle
    }
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn a_failed_capability_drop_stops_startup() {
    let pki = Pki::new();
    let shared: Shared = Arc::default();
    let dir = state_dir("caps-drop-failed");
    let detached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let opened = Opened {
        source: AlarmSource::Ebpf,
        fallback: None,
        starts: Some(Box::new(Attached(Arc::clone(&detached)))),
        error: None,
    };
    let error = spawn_opened(
        opened,
        || Err("capset: EPERM".into()),
        config("https://127.0.0.1:1", &pki),
        &shared,
        &dir,
    )
    .unwrap_err();
    assert!(
        error.contains("CAP_BPF") && error.contains("capset: EPERM"),
        "{error}"
    );
    assert!(detached.load(std::sync::atomic::Ordering::SeqCst));
    // Nothing was started: no alarm queue was opened.
    assert!(!dir.join("alarms.sqlite").exists());
}

#[test]
fn a_failed_capability_drop_on_the_audit_fallback_stops_startup_too() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static DROPPED: AtomicBool = AtomicBool::new(false);
    let pki = Pki::new();
    let shared: Shared = Arc::default();
    let dir = state_dir("caps-drop-audit");
    let closed = Arc::new(AtomicBool::new(false));
    let opened = Opened {
        source: AlarmSource::Audit,
        fallback: None,
        starts: Some(Box::new(Attached(Arc::clone(&closed)))),
        error: None,
    };
    // Fail closed whatever the source (R26): the drop runs on the audit
    // path too, and its failure stops startup.
    let error = spawn_opened(
        opened,
        || {
            DROPPED.store(true, Ordering::SeqCst);
            Err("capset: EPERM".into())
        },
        config("https://127.0.0.1:1", &pki),
        &shared,
        &dir,
    )
    .unwrap_err();
    assert!(DROPPED.load(Ordering::SeqCst));
    assert_eq!(error, "cannot drop CAP_BPF and CAP_PERFMON: capset: EPERM");
    assert!(closed.load(Ordering::SeqCst));
    assert!(!dir.join("alarms.sqlite").exists());
}
