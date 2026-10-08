//! The capability drop as the agent does it at startup: on the main thread,
//! while it is the only thread; then a thread is started and no task of the
//! process may hold `CAP_BPF` or `CAP_PERFMON` in any set. No test harness
//! (`harness = false`), so no other thread exists at the drop.
//!
//! As an ordinary user it only shows the drop succeeds. To see it remove
//! capabilities really held, run it as root in a user namespace:
//! `unshare -Ur target/debug/deps/caps_drop-*` (the bounding set is
//! dropped too there, as that root holds `CAP_SETPCAP`), or under the unit.

#[cfg(target_os = "linux")]
fn main() {
    use openvibes_agent::caps::{EBPF_CAPS, drop_ebpf_caps, task_caps};

    let ebpf = EBPF_CAPS.bits();
    let before = task_caps().unwrap();
    assert_eq!(before.len(), 1, "only the main thread: {before:?}");
    println!("caps_drop: before {:?}", before[0]);
    drop_ebpf_caps().unwrap();
    let tasks = std::thread::spawn(task_caps).join().unwrap().unwrap();
    assert_eq!(tasks.len(), 2, "{tasks:?}");
    for task in &tasks {
        assert_eq!((task.eff | task.prm | task.amb) & ebpf, 0, "{task:?}");
        // Dropped from the bounding set only when it was allowed to.
        if before[0].eff & (1 << 8) != 0 {
            assert_eq!(task.bnd & ebpf, 0, "{task:?}");
        }
    }
    println!("caps_drop: after {tasks:?}");
}

#[cfg(not(target_os = "linux"))]
fn main() {}
