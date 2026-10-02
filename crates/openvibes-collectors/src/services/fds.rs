//! Exact socket owners for the opt-in drop-in (decision B, 2026-10-01):
//! with `CAP_DAC_READ_SEARCH` and `CAP_SYS_PTRACE` the agent may list and
//! read another user's `/proc/PID/fd` links; `socket:[INODE]` names the
//! process holding a listener. Without both it does not try.

use std::{
    collections::{HashMap, HashSet},
    fs,
    time::Instant,
};

/// fd links read at most per scan; past it owners are `partial`. About
/// 4.5 µs each (measured 2026-10-01), so the walk stays near the 5 ms scan
/// budget. The first pass (the listeners' own cgroups) normally needs a
/// few hundred.
// ponytail: a host whose listeners sit behind systemd sockets past the
// first 1,000 links stays partial; raise the cap if exact names matter
// more there than the CPU.
pub(super) const MAX_FDS: usize = 1_000;

/// `CAP_DAC_READ_SEARCH` (2) and `CAP_SYS_PTRACE` (19) in a `CapEff` mask.
const OWNER_CAPS: u64 = (1 << 2) | (1 << 19);

/// Whether this process holds both capabilities in its effective set.
pub(super) fn has_owner_caps() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let mask = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
            u64::from_str_radix(mask.trim(), 16).ok()
        })
        .is_some_and(|mask| mask & OWNER_CAPS == OWNER_CAPS)
}

/// Which pid holds each listener socket.
#[derive(Debug, Default, Eq, PartialEq)]
pub(super) struct Owners {
    pub(super) pids: HashMap<u64, u32>,
    /// Every listener was found, or every process was read.
    pub(super) complete: bool,
}

/// Looks for `inodes` in the fds of `first`, in order (the listeners'
/// cgroups, then every system service), then of every other process while
/// a socket has no holder at all, reading at most `max_fds` links
/// ([`MAX_FDS`] in a scan).
///
/// A socket systemd (pid 1) opened for socket activation is also held by
/// the service it started, which is a system service: it is credited to
/// that service. Held by pid 1 alone after the first pass (no daemon
/// running yet), systemd is its holder and it counts as found.
pub(super) fn find(
    inodes: &HashSet<u64>,
    first: &[u32],
    max_fds: usize,
    deadline: Instant,
) -> Owners {
    let mut owners = Owners::default();
    let mut budget = max_fds;
    let mut fully_read = true;
    // Every socket held by a process other than systemd: nothing left to
    // learn anywhere.
    let by_daemons = |owners: &Owners| {
        inodes
            .iter()
            .all(|inode| owners.pids.get(inode).is_some_and(|&pid| pid != 1))
    };
    let held = |owners: &Owners| inodes.iter().all(|inode| owners.pids.contains_key(inode));
    let mut visited = HashSet::new();
    let mut first_read = true;
    for &pid in first {
        if !visited.insert(pid) {
            continue;
        }
        first_read &= read_fds(pid, inodes, &mut owners, &mut budget, deadline);
        if budget == 0 || by_daemons(&owners) {
            break;
        }
    }
    fully_read &= first_read;
    // After the whole first pass, a socket only systemd holds has no other
    // holder: the activated daemon would be a system service.
    let found = |owners: &Owners| by_daemons(owners) || (first_read && held(owners));
    if !found(&owners) {
        let rest = fs::read_dir("/proc").into_iter().flatten().flatten();
        for pid in rest.filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok()) {
            if !visited.insert(pid) {
                continue;
            }
            fully_read &= read_fds(pid, inodes, &mut owners, &mut budget, deadline);
            if budget == 0 || found(&owners) {
                break;
            }
        }
    }
    owners.complete = found(&owners) || (fully_read && budget > 0);
    owners
}

/// Reads one process's fd links; `false` when it could not be read whole
/// (denied, the budget or the deadline ran out). A process that exited
/// meanwhile counts as read.
fn read_fds(
    pid: u32,
    inodes: &HashSet<u64>,
    owners: &mut Owners,
    budget: &mut usize,
    deadline: Instant,
) -> bool {
    let dir = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(dir) => dir,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    for entry in dir.flatten() {
        if *budget == 0 || Instant::now() > deadline {
            return false;
        }
        *budget -= 1;
        let Ok(link) = fs::read_link(entry.path()) else {
            continue;
        };
        let inode = link
            .to_str()
            .and_then(|l| l.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok());
        if let Some(inode) = inode.filter(|i| inodes.contains(i)) {
            let held = owners.pids.entry(inode).or_insert(pid);
            if *held == 1 {
                *held = pid;
            }
        }
    }
    true
}
