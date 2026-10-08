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

use openvibes_core::AlarmSource;
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
    let ebpf = EBPF_CAPS.bits();
    for task in task_caps().map_err(|e| format!("reading /proc/self/task: {e}"))? {
        let held = task.eff | task.prm | task.amb | if bounding { task.bnd } else { 0 };
        if held & ebpf != 0 {
            return Err(format!("thread {} still holds them: {task:?}", task.tid));
        }
    }
    Ok(())
}

/// Whether the agent may go on once the drop was tried: `Ok(source)` when
/// it succeeded or the source is not eBPF (the capabilities were never
/// used, so a failed drop is not fatal), `Err` with
/// the cause when it failed. The agent never runs on holding `CAP_BPF` or
/// `CAP_PERFMON`: the caller stops startup.
///
/// # Errors
/// When `source` is eBPF and `dropped` is `Err`.
pub fn after_drop(dropped: Result<(), String>, source: AlarmSource) -> Result<AlarmSource, String> {
    match (dropped, source) {
        (Err(why), AlarmSource::Ebpf) => Err(format!(
            "cannot drop CAP_BPF and CAP_PERFMON after loading eBPF: {why}"
        )),
        (_, source) => Ok(source),
    }
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
        let mut task = TaskCaps {
            tid,
            ..TaskCaps::default()
        };
        for line in status.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let field = match key {
                "CapEff" => &mut task.eff,
                "CapPrm" => &mut task.prm,
                "CapBnd" => &mut task.bnd,
                "CapAmb" => &mut task.amb,
                _ => continue,
            };
            *field = u64::from_str_radix(value.trim(), 16)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        tasks.push(task);
    }
    Ok(tasks)
}

#[cfg(test)]
mod tests {
    use openvibes_core::AlarmSource;
    use rustix::thread::{self, CapabilitySet};

    use super::{EBPF_CAPS, after_drop, drop_ebpf_caps, task_caps};

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
    fn drop_failure_means_no_ebpf() {
        let error = after_drop(Err("x".into()), AlarmSource::Ebpf).unwrap_err();
        assert!(
            error.contains("CAP_BPF") && error.ends_with(": x"),
            "{error}"
        );
        assert_eq!(after_drop(Ok(()), AlarmSource::Ebpf), Ok(AlarmSource::Ebpf));
        // Not eBPF: the drop was never needed.
        assert_eq!(
            after_drop(Ok(()), AlarmSource::Audit),
            Ok(AlarmSource::Audit)
        );
    }
}
