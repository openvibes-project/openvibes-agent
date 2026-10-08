//! Dropping `CAP_BPF` and `CAP_PERFMON` once the eBPF program is attached
//! (Linux). Both allow loading tracing programs, that is reading kernel
//! memory; the agent needs them only to load and attach its exec program.
//!
//! Capability sets belong to each thread, and a new thread copies its
//! creator's. The drop therefore runs on the main thread, right after the
//! eBPF program is attached in `alarms::thread::spawn` (called from
//! `Service::open`), before the agent starts any other thread: the
//! forwarder, the alarm thread and every later thread start without them.
//! [`drop_ebpf_caps`] checks this by reading every task of the process in
//! `/proc/self/task`.

use std::{fs, io};

use rustix::thread::{self, CapabilitySet, CapabilitySets};

/// `CAP_BPF` and `CAP_PERFMON`.
pub const EBPF_CAPS: CapabilitySet = CapabilitySet::BPF.union(CapabilitySet::PERFMON);

/// Removes [`EBPF_CAPS`] from the calling thread's effective, permitted,
/// inheritable and ambient sets, and from its bounding set when it holds
/// `CAP_SETPCAP` (the packaged agent does not; with empty permitted,
/// inheritable and ambient sets, a non-root user and `NoNewPrivileges`, the
/// bounding set cannot give them back). Then checks that no task of the
/// process holds them in any of those sets: a thread started before the
/// call would keep its own copy, and that is an error too.
pub fn drop_ebpf_caps() -> Result<(), String> {
    let sets = thread::capabilities(None).map_err(|e| format!("capget: {e}"))?;
    thread::set_capabilities(
        None,
        CapabilitySets {
            effective: sets.effective - EBPF_CAPS,
            permitted: sets.permitted - EBPF_CAPS,
            inheritable: sets.inheritable - EBPF_CAPS,
        },
    )
    .map_err(|e| format!("capset: {e}"))?;
    let bounding = sets.effective.contains(CapabilitySet::SETPCAP);
    for cap in [CapabilitySet::BPF, CapabilitySet::PERFMON] {
        thread::configure_capability_in_ambient_set(cap, false)
            .map_err(|e| format!("lowering the ambient set: {e}"))?;
        if bounding {
            thread::remove_capability_from_bounding_set(cap)
                .map_err(|e| format!("dropping from the bounding set: {e}"))?;
        }
    }
    let tasks = task_caps().map_err(|e| format!("reading /proc/self/task: {e}"))?;
    let me = rustix::process::Pid::as_raw(Some(thread::gettid()));
    none_holds_them(&tasks, me, bounding)
}

/// Fails unless `tasks` lists the calling thread `me` (so the list was
/// really read) and none of them holds [`EBPF_CAPS`] in its effective,
/// permitted or ambient set (and bounding set, when `bounding`).
fn none_holds_them(tasks: &[TaskCaps], me: i32, bounding: bool) -> Result<(), String> {
    if !tasks.iter().any(|task| task.tid == me) {
        return Err(format!("this thread ({me}) is not among the tasks read"));
    }
    let ebpf = EBPF_CAPS.bits();
    for task in tasks {
        let held = task.eff | task.prm | task.amb | if bounding { task.bnd } else { 0 };
        if held & ebpf != 0 {
            return Err(format!("thread {} still holds them: {task:?}", task.tid));
        }
    }
    Ok(())
}

/// Whether the agent may go on once the drop was tried, whatever the
/// source (eBPF, the audit fallback, or alarms off): only when it
/// succeeded. The drop only lowers the agent's own capabilities, so it
/// fails only through a bug, and no agent may run holding them with
/// `bpf()` allowed: the caller stops startup (fail closed).
///
/// # Errors
/// When `dropped` is `Err`, with the cause.
pub fn after_drop(dropped: Result<(), String>) -> Result<(), String> {
    dropped.map_err(|why| format!("cannot drop CAP_BPF and CAP_PERFMON: {why}"))
}

/// One task's capability sets, as `/proc/self/task/<tid>/status` shows
/// them (bit n is capability n).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TaskCaps {
    /// Thread id.
    pub tid: i32,
    /// `CapEff`.
    pub eff: u64,
    /// `CapPrm`.
    pub prm: u64,
    /// `CapBnd`.
    pub bnd: u64,
    /// `CapAmb`.
    pub amb: u64,
}

/// Every task (thread) of this process and its capability sets. The
/// real-kernel job (Task 9) uses it to show that, under the unit, no thread
/// keeps `CAP_BPF` or `CAP_PERFMON` after startup.
///
/// # Errors
/// When `/proc/self/task` or a status file cannot be read; a task that
/// exited meanwhile is skipped.
pub fn task_caps() -> io::Result<Vec<TaskCaps>> {
    let mut tasks = Vec::new();
    for entry in fs::read_dir("/proc/self/task")? {
        let entry = entry?;
        let Some(tid) = entry.file_name().to_str().and_then(|n| n.parse().ok()) else {
            continue;
        };
        let status = match fs::read_to_string(entry.path().join("status")) {
            Ok(status) => status,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        tasks.push(parse_task_caps(tid, &status)?);
    }
    Ok(tasks)
}

/// One task's sets from its `status` text. All four `Cap*` lines are
/// required: a missing one is an error, never "none held".
fn parse_task_caps(tid: i32, status: &str) -> io::Result<TaskCaps> {
    let mut sets = [None; 4];
    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let Some(i) = ["CapEff", "CapPrm", "CapBnd", "CapAmb"]
            .iter()
            .position(|k| *k == key)
        else {
            continue;
        };
        sets[i] = Some(
            u64::from_str_radix(value.trim(), 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
    }
    let [Some(eff), Some(prm), Some(bnd), Some(amb)] = sets else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("task {tid}: a CapEff, CapPrm, CapBnd or CapAmb line is missing"),
        ));
    };
    Ok(TaskCaps {
        tid,
        eff,
        prm,
        bnd,
        amb,
    })
}

#[cfg(test)]
mod tests {
    use rustix::thread::{self, CapabilitySet};

    use super::{
        EBPF_CAPS, TaskCaps, after_drop, drop_ebpf_caps, none_holds_them, parse_task_caps,
        task_caps,
    };

    #[test]
    fn after_the_drop_no_ebpf_capability_is_held() {
        drop_ebpf_caps().unwrap();
        let sets = thread::capabilities(None).unwrap();
        for set in [sets.effective, sets.permitted, sets.inheritable] {
            assert!(!set.intersects(EBPF_CAPS));
        }
        for cap in [CapabilitySet::BPF, CapabilitySet::PERFMON] {
            assert!(!thread::capability_is_in_ambient_set(cap).unwrap());
        }
    }

    #[test]
    fn task_caps_reads_every_set_of_this_process() {
        let tasks = task_caps().unwrap();
        let me = tasks
            .iter()
            .find(|task| task.tid == rustix::process::Pid::as_raw(Some(thread::gettid())))
            .expect("this thread is listed");
        // An ordinary user's bounding set is full: CAP_BPF is in it.
        let bounding = thread::capability_is_in_bounding_set(CapabilitySet::BPF).unwrap();
        assert_eq!(me.bnd & CapabilitySet::BPF.bits() != 0, bounding);
        assert_eq!(me.eff, thread::capabilities(None).unwrap().effective.bits());
    }

    #[test]
    fn a_failed_drop_stops_startup_whatever_the_source() {
        let error = after_drop(Err("x".into())).unwrap_err();
        assert_eq!(error, "cannot drop CAP_BPF and CAP_PERFMON: x");
        assert_eq!(after_drop(Ok(())), Ok(()));
    }

    const FULL: &str = "Name:\tx\nCapInh:\t0\nCapPrm:\t0000000000000001\n\
        CapEff:\t0000000000000002\nCapBnd:\t000000c000000000\nCapAmb:\t0000000000000000\n";

    #[test]
    fn a_status_needs_all_four_capability_lines() {
        let task = parse_task_caps(7, FULL).unwrap();
        assert_eq!(
            (task.tid, task.prm, task.eff, task.bnd, task.amb),
            (7, 1, 2, EBPF_CAPS.bits(), 0)
        );
        for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
            let cut: String = FULL
                .lines()
                .filter(|line| !line.starts_with(key))
                .map(|line| format!("{line}\n"))
                .collect();
            assert!(parse_task_caps(7, &cut).is_err(), "without {key}");
        }
        assert!(parse_task_caps(7, "").is_err());
    }

    #[test]
    fn the_check_needs_this_thread_among_the_tasks() {
        let clean = TaskCaps {
            tid: 7,
            ..TaskCaps::default()
        };
        assert!(none_holds_them(&[], 7, false).is_err());
        assert!(none_holds_them(&[clean], 8, false).is_err());
        assert_eq!(none_holds_them(&[clean], 7, false), Ok(()));
        let held = TaskCaps {
            tid: 9,
            amb: CapabilitySet::BPF.bits(),
            ..TaskCaps::default()
        };
        assert!(none_holds_them(&[clean, held], 7, false).is_err());
        // The bounding set counts only when it could be cleared.
        let bnd = TaskCaps {
            tid: 7,
            bnd: EBPF_CAPS.bits(),
            ..TaskCaps::default()
        };
        assert_eq!(none_holds_them(&[bnd], 7, false), Ok(()));
        assert!(none_holds_them(&[bnd], 7, true).is_err());
    }
}
