//! The alarm path on a real kernel (P14), run by `scripts/alarms-kernel-e2e.sh`
//! in the CI job `alarms-kernel`: as `nobody` with only `CAP_AUDIT_READ`,
//! with the packaged audit rule loaded. The script starts a `fake-nginx`
//! (a copy of bash) before this test and another after it is ready; each
//! runs `sh -c` five times. Then, optionally, it runs an exec load while
//! this test measures its own memory and CPU.
#![cfg(target_os = "linux")]

mod support;

use std::{
    collections::BTreeMap,
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

use openvibes_agent::alarms::thread::spawn;
use openvibes_core::AlarmBatch;
use openvibes_storage::prepare_state_dir;
use openvibes_testkit::{Handler, Pki, Seen, serve, status};
use support::{config, enrolled_identity};

// `sh` is dash on Ubuntu, so `process.name` is `dash`: match argv instead.
const RULE: &str =
    "event['parent.name'] == 'fake-nginx' && event['process.cmdline'].startsWith('sh -c ')";

fn status_field(name: &str) -> String {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|line| line.strip_prefix(name).map(|v| v.trim().to_owned()))
        .unwrap()
}

/// User plus system CPU time of this process, in clock ticks.
fn cpu_ticks() -> u64 {
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let after = &stat[stat.rfind(')').unwrap() + 2..];
    let fields: Vec<&str> = after.split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

#[test]
#[ignore = "needs a real kernel, the audit rule and CAP_AUDIT_READ (CI job alarms-kernel)"]
fn alarms_on_a_real_kernel() {
    // Review Focus 5: exactly CAP_AUDIT_READ (bit 37) is effective.
    assert_eq!(status_field("CapEff:"), "0000002000000000");

    let pki = Arc::new(Pki::new());
    let identity = enrolled_identity(&pki);
    let handlers: Vec<Handler> = (0..64)
        .map(|_| Box::new(|_: &Seen| status(202)) as Handler)
        .collect();
    let (url, seen) = serve(pki.server_config(true, false), handlers);
    let shared = support::shared(identity, RULE);
    let dir = std::env::temp_dir().join(format!("ov-alarms-kernel-{}", std::process::id()));
    prepare_state_dir(&dir).unwrap();
    if spawn(config(&url, &pki), &shared, &dir).is_none() {
        panic!(
            "no audit socket: {:?}",
            shared.lock().unwrap().health.collector
        );
    }
    let ready = std::env::var("OV_READY").expect("OV_READY names the ready file");
    fs::write(&ready, b"").unwrap();

    // Command line → (highest count, parent exe, parent seeded).
    let mut alarms: BTreeMap<String, (u32, String, bool)> = BTreeMap::new();
    let done = |alarms: &BTreeMap<String, (u32, String, bool)>| {
        ["sh -c true pre", "sh -c true post"]
            .iter()
            .all(|line| alarms.get(*line).is_some_and(|(count, _, _)| *count == 5))
    };
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done(&alarms) && Instant::now() < deadline {
        let Ok(sent) = seen.recv_timeout(Duration::from_secs(1)) else {
            continue;
        };
        let batch: AlarmBatch = serde_json::from_slice(&sent.decoded_body()).unwrap();
        for alarm in batch.alarms {
            let parent = alarm.ancestors.first().unwrap();
            let entry = alarms.entry(alarm.process.args.join(" ")).or_default();
            *entry = (entry.0.max(alarm.count), parent.exe.clone(), parent.seeded);
        }
    }
    eprintln!("alarms: {alarms:?}");
    {
        let shared = shared.lock().unwrap();
        eprintln!(
            "starts {}, rule failures {}, unavailable {}, health {:?}",
            shared.starts, shared.rule_failures, shared.rule_unavailable, shared.health
        );
    }
    assert!(done(&alarms), "{alarms:?}");
    // Started before the agent: learnt from /proc. Its exe link is not
    // readable by nobody, so exe is the absolute argv[0]; the rule matched
    // on parent.name (comm).
    assert_eq!(
        alarms["sh -c true pre"],
        (5, "/tmp/fake-nginx".into(), true)
    );
    assert_eq!(
        alarms["sh -c true post"],
        (5, "/tmp/fake-nginx".into(), false)
    );

    // Cost: memory and CPU while the script runs its exec load.
    let seconds: u64 = std::env::var("OV_LOAD_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if seconds == 0 {
        return;
    }
    let rss_before: u64 = status_field("VmRSS:")
        .trim_end_matches(" kB")
        .parse()
        .unwrap();
    let cpu_before = cpu_ticks();
    fs::write(format!("{ready}.load"), b"").unwrap();
    std::thread::sleep(Duration::from_secs(seconds));
    let rss_after: u64 = status_field("VmRSS:")
        .trim_end_matches(" kB")
        .parse()
        .unwrap();
    let ticks = cpu_ticks() - cpu_before;
    // Clock ticks are 1/100 s on Linux (USER_HZ).
    let percent = ticks as f64 / seconds as f64;
    let health = shared.lock().unwrap().health.clone();
    eprintln!(
        "cost: RSS {rss_before} -> {rss_after} kB ({:+} kB), CPU {percent:.2} % of one core over {seconds} s, events dropped {}",
        rss_after as i64 - rss_before as i64,
        health.events_dropped_total
    );
}
