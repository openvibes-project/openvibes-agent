//! The alarm path on a real kernel (P14), run by `scripts/alarms-kernel-e2e.sh`
//! in the CI job `alarms-kernel`, once per source (`OV_SOURCE`):
//! - `audit`: as `nobody` with only `CAP_AUDIT_READ`, with the packaged
//!   audit rule loaded;
//! - `ebpf`: as `nobody` with only `CAP_BPF` and `CAP_PERFMON`, with no
//!   exec audit rule and auditd stopped; the capabilities are dropped once
//!   the program is attached and no task may hold them after.
//!
//! The script starts a `fake-nginx` (a copy of bash) before this test and
//! another after it is ready; each runs `sh -c` five times. Then,
//! optionally, it runs an exec load while this test measures its own memory
//! and CPU.
//!
//! No test harness (`harness = false`): the source is opened and the
//! capabilities dropped on the main thread while it is the only thread, as
//! the agent does at startup (libtest runs tests on worker threads, and the
//! main thread would keep the capabilities). Without `OV_READY` (any plain
//! `cargo test`) it does nothing.

#[cfg(not(target_os = "linux"))]
fn main() {}

#[cfg(target_os = "linux")]
mod support;

#[cfg(target_os = "linux")]
fn main() {
    let Ok(ready) = std::env::var("OV_READY") else {
        println!("alarms_kernel: skipped (needs a real kernel; scripts/alarms-kernel-e2e.sh)");
        return;
    };
    linux::alarms_on_a_real_kernel(&ready);
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        collections::BTreeMap,
        fs,
        sync::Arc,
        time::{Duration, Instant},
    };

    use openvibes_agent::{
        alarms::thread::spawn_opened,
        caps::{EBPF_CAPS, drop_ebpf_caps, task_caps},
    };
    use openvibes_collectors::process_events::open_process_starts;
    use openvibes_core::{AlarmBatch, AlarmSource};
    use openvibes_storage::prepare_state_dir;
    use openvibes_testkit::{Handler, Pki, Seen, serve, status};

    use super::support::{self, config, enrolled_identity};

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

    pub fn alarms_on_a_real_kernel(ready: &str) {
        let source = match std::env::var("OV_SOURCE").as_deref() {
            Ok("ebpf") => AlarmSource::Ebpf,
            _ => AlarmSource::Audit,
        };
        // Opened first, while this is the only thread (as `Service::open`).
        let opened = open_process_starts(source == AlarmSource::Audit, || false);
        assert_eq!(opened.source, source, "fallback {:?}", opened.fallback);
        if source == AlarmSource::Ebpf {
            // Exactly CAP_BPF and CAP_PERFMON (bits 39 and 38) until attached.
            assert_eq!(status_field("CapEff:"), "000000c000000000");
            drop_ebpf_caps().unwrap();
        } else {
            // Review Focus 5: exactly CAP_AUDIT_READ (bit 37) is effective.
            assert_eq!(status_field("CapEff:"), "0000002000000000");
        }

        let pki = Arc::new(Pki::new());
        let identity = enrolled_identity(&pki);
        let handlers: Vec<Handler> = (0..64)
            .map(|_| Box::new(|_: &Seen| status(202)) as Handler)
            .collect();
        let (url, seen) = serve(pki.server_config(true, false), handlers);
        let shared = support::shared(identity, RULE);
        let dir = std::env::temp_dir().join(format!("ov-alarms-kernel-{}", std::process::id()));
        prepare_state_dir(&dir).unwrap();
        // The capabilities are already dropped (above, on the main thread).
        if spawn_opened(opened, || Ok(()), config(&url, &pki), &shared, &dir)
            .unwrap()
            .is_none()
        {
            panic!(
                "no audit socket: {:?}",
                shared.lock().unwrap().health.collector
            );
        }
        fs::write(ready, b"").unwrap();

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
        assert_eq!(shared.lock().unwrap().health.source, Some(source));
        // Every task, the agent's threads included, is without the eBPF
        // capabilities (only checked here: audit never had them).
        for task in task_caps().unwrap() {
            assert_eq!(
                (task.eff | task.prm | task.amb) & EBPF_CAPS.bits(),
                0,
                "{task:?}"
            );
        }
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
}
