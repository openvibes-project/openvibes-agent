use std::time::{Duration, Instant};

use openvibes_core::{CollectorErrorCode, FactValue, ResourceLimits};

use super::{canonical_name, collect_processes, facts};

fn names(raw: &[&str], windows: bool) -> Vec<String> {
    let facts = facts(
        raw.iter().map(|&name| name.to_owned()).collect(),
        windows,
        ResourceLimits::V1,
    )
    .unwrap();
    match &facts[0].value {
        FactValue::StringList(names) => names.clone(),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn names_are_canonical_on_every_os() {
    assert_eq!(canonical_name("sshd\n", false).as_deref(), Some("sshd"));
    assert_eq!(canonical_name("SSHD.EXE", true).as_deref(), Some("sshd"));
    assert_eq!(
        canonical_name("Sshd.exe", false).as_deref(),
        Some("Sshd.exe")
    );
    assert_eq!(
        canonical_name("a-very-long-process-name", false).as_deref(),
        Some("a-very-long-pro")
    );
    // Truncation never splits a character: "é" is two bytes at bytes 14..16.
    assert_eq!(
        canonical_name("abcdefghijklmné", false).as_deref(),
        Some("abcdefghijklmn")
    );
    assert_eq!(canonical_name("\n", false), None);
    assert_eq!(canonical_name(".exe", true), None);
}

#[test]
fn facts_are_sorted_deduplicated_and_count_every_process() {
    assert_eq!(
        names(&["sshd", "init", "sshd", ""], false),
        ["init", "sshd"]
    );
    assert_eq!(
        names(&["svchost.exe", "SVCHOST.EXE", "System"], true),
        ["svchost", "system"]
    );
    let facts = facts(
        vec!["sshd".into(), "sshd".into(), String::new()],
        false,
        ResourceLimits::V1,
    )
    .unwrap();
    assert_eq!(facts[1].key.as_str(), "process.count");
    assert_eq!(facts[1].value, FactValue::Integer(3));
    assert!(facts.iter().all(|fact| fact.source.as_str() == "processes"));
}

#[test]
fn incomplete_lists_are_refused_not_truncated() {
    let limits = ResourceLimits::V1;
    let too_many = (0..=limits.fact_list_items)
        .map(|index| format!("p{index}"))
        .collect();
    let error = facts(too_many, false, limits).unwrap_err();
    assert_eq!(error.code, CollectorErrorCode::InvalidData);
    assert_eq!(
        facts(Vec::new(), false, limits).unwrap_err().code,
        CollectorErrorCode::Internal
    );
}

#[test]
fn a_passed_deadline_emits_no_facts() {
    let Some(past) = Instant::now().checked_sub(Duration::from_secs(1)) else {
        return;
    };
    let error = collect_processes(past, ResourceLimits::V1).unwrap_err();
    assert_eq!(error.code, CollectorErrorCode::TimedOut);
    assert!(error.retryable);
}

/// Runs on every CI host: the native path sees this test's own process.
#[test]
fn the_live_host_reports_processes() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let facts = collect_processes(deadline, ResourceLimits::V1).unwrap();
    let FactValue::StringList(names) = &facts[0].value else {
        panic!("process.names is not a list");
    };
    assert!(!names.is_empty());
    assert!(matches!(facts[1].value, FactValue::Integer(count) if count >= 1));
}

#[cfg(target_os = "linux")]
mod linux {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        time::{Duration, Instant},
    };

    use openvibes_core::CollectorErrorCode;

    use super::super::platform::{hides_processes, scan};

    /// A fake `/proc` with `entries` of (pid dir, comm bytes or no file).
    fn fake_proc(test: &str, entries: &[(&str, Option<&[u8]>)]) -> PathBuf {
        let root = std::env::temp_dir()
            .join(format!("openvibes-proc-{}", std::process::id()))
            .join(test);
        let _ = fs::remove_dir_all(&root);
        for (dir, comm) in entries {
            fs::create_dir_all(root.join(dir)).unwrap();
            if let Some(comm) = comm {
                fs::write(root.join(dir).join("comm"), comm).unwrap();
            }
        }
        root
    }

    fn later() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn scan_reads_pids_and_skips_everything_else() {
        let root = fake_proc(
            "basic",
            &[
                ("1", Some(b"init\n")),
                ("42", Some(b"sshd\n")),
                ("self", Some(b"not-a-pid\n")),
                ("sys", None),
                ("77", None), // exited mid-scan: comm vanished
                ("78", Some(b"\xff\xfebad-utf8\n")),
                ("79", Some(&[b'x'; 200])),
            ],
        );
        let names = scan(&root, later()).unwrap();
        assert_eq!(names.len(), 4);
        for expected in ["init\n", "sshd\n", "\u{fffd}\u{fffd}bad-utf8\n"] {
            assert!(names.contains(&expected.to_owned()), "{expected:?}");
        }
        // An oversized comm is read only 64 bytes far.
        assert!(names.contains(&"x".repeat(64)));
    }

    #[test]
    fn missing_proc_is_not_found() {
        let root = fake_proc("missing", &[]).join("absent");
        assert_eq!(
            scan(&root, later()).unwrap_err().code,
            CollectorErrorCode::NotFound
        );
    }

    #[test]
    fn a_denied_comm_fails_the_whole_scan() {
        if rustix::process::geteuid().is_root() {
            return; // root reads through file modes
        }
        let root = fake_proc(
            "denied",
            &[("1", Some(b"init\n")), ("2", Some(b"secret\n"))],
        );
        let comm = root.join("2").join("comm");
        fs::set_permissions(&comm, fs::Permissions::from_mode(0o000)).unwrap();
        let error = scan(&root, later()).unwrap_err();
        fs::set_permissions(&comm, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(error.code, CollectorErrorCode::PermissionDenied);
        assert!(!error.retryable);
    }

    #[test]
    fn hidepid_mounts_are_detected() {
        let line = |mount: &str, fs: &str, options: &str| {
            format!(
                "25 30 0:23 / {mount} rw,nosuid,nodev,noexec,relatime shared:13 - {fs} proc {options}"
            )
        };
        assert!(!hides_processes(&line("/proc", "proc", "rw")));
        assert!(!hides_processes(&line("/proc", "proc", "rw,hidepid=0")));
        assert!(!hides_processes(&line("/proc", "proc", "rw,hidepid=off")));
        assert!(hides_processes(&line("/proc", "proc", "rw,hidepid=2")));
        assert!(hides_processes(&line(
            "/proc",
            "proc",
            "rw,hidepid=invisible,gid=10"
        )));
        assert!(!hides_processes(&line("/srv/proc", "proc", "rw,hidepid=2")));
        assert!(!hides_processes(&line("/proc", "tmpfs", "rw,hidepid=2")));
        assert!(!hides_processes("garbage without separator"));
    }
}
