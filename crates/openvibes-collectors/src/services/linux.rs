//! The reads behind [`super::assemble`] on Linux.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    path::Path,
    time::Instant,
};

use openvibes_core::{CollectorError, CollectorErrorCode};

use super::{Inputs, Process, error, is_system, unit_path};
use crate::ports::{Listener, Protocol};

/// The cgroup v2 root.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Cgroup directories walked at most; a busy host has a few hundred.
const MAX_CGROUPS: usize = 20_000;
/// Processes read at most.
const MAX_PROCESSES: usize = 100_000;
/// Processes read per unit, the lowest pids first.
const PROCESSES_PER_UNIT: usize = 64;
/// Netlink messages read per dump at most (each socket is one message).
const MAX_DIAG_MESSAGES: usize = 200_000;

pub(super) fn inputs(deadline: Instant) -> Result<Inputs, CollectorError> {
    let ephemeral_start = fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok())
        .unwrap_or(32_768);
    // The kernel filters by state, so this is far cheaper than the socket
    // tables, and it gives each socket's cgroup; the tables are the
    // fallback (owners are best effort, the lists always go out).
    let (listeners, socket_cgroups) = match diag_sockets() {
        Ok(sockets) => {
            let cgroups = sockets
                .iter()
                .filter_map(|(l, id)| Some((l.inode, (*id)?)))
                .collect();
            (sockets.into_iter().map(|(l, _)| l).collect(), Some(cgroups))
        }
        Err(_) => (crate::ports::platform::listeners(deadline)?, None),
    };
    let mut inputs = Inputs {
        listeners,
        ephemeral_start,
        socket_cgroups,
        ..Inputs::default()
    };
    // ponytail: a cgroup v1 host (no cgroup.controllers) gets no owners and
    // no services; v2 is the default on every supported distribution.
    if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
        return Ok(inputs);
    }
    // System services first; the rest of the tree only for a listener
    // whose cgroup is elsewhere (a user's app, a container).
    let mut cgroups = HashMap::new();
    walk("/system.slice", None, &mut cgroups, deadline);
    let unresolved = inputs
        .socket_cgroups
        .iter()
        .flat_map(HashMap::values)
        .any(|id| !cgroups.contains_key(id));
    if unresolved {
        walk("", Some("/system.slice"), &mut cgroups, deadline);
    }
    inputs.cgroups = cgroups;
    let wanted: HashSet<&str> = owner_units(&inputs)
        .chain(
            inputs
                .cgroups
                .values()
                .filter_map(|p| unit_path(p))
                .filter(|u| is_system(u)),
        )
        .collect();
    let mut processes: BTreeMap<String, Vec<Process>> = BTreeMap::new();
    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut buf = Vec::with_capacity(4096);
    let mut read = 0;
    for path in inputs.cgroups.values() {
        let Some(unit) = unit_path(path).filter(|unit| wanted.contains(unit)) else {
            continue;
        };
        let Some(pids) = read_small(&format!("{CGROUP_ROOT}{path}/cgroup.procs"), &mut buf) else {
            continue;
        };
        let mut pids: Vec<u32> = pids.lines().filter_map(|pid| pid.parse().ok()).collect();
        pids.sort_unstable();
        *counts.entry(unit.to_owned()).or_default() +=
            u32::try_from(pids.len()).unwrap_or(u32::MAX);
        let sample = processes.entry(unit.to_owned()).or_default();
        // ponytail: the lowest 64 pids name a unit's programs; a unit whose
        // later processes run another program (rare) shows only these.
        for pid in pids
            .into_iter()
            .take(PROCESSES_PER_UNIT.saturating_sub(sample.len()))
        {
            read += 1;
            if read > MAX_PROCESSES || Instant::now() > deadline {
                break;
            }
            // A process that exited meanwhile is left out.
            if let Some(comm) = read_small(&format!("/proc/{pid}/comm"), &mut buf)
                .map(|comm| comm.trim_end_matches('\n').to_owned())
                .filter(|comm| !comm.is_empty())
            {
                sample.push(Process {
                    pid,
                    comm,
                    uid: None,
                });
            }
        }
    }
    inputs.process_counts = counts;
    // The user only of each unit's main (lowest) pid: /proc/PID/status is
    // the costly read.
    for unit in processes.values_mut() {
        if let Some(main) = unit.iter_mut().min_by_key(|p| p.pid) {
            main.uid = real_uid(main.pid);
        }
    }
    inputs.processes = processes;
    inputs.users = super::users(&fs::read_to_string("/etc/passwd").unwrap_or_default());
    Ok(inputs)
}

/// A small `/proc` or cgroup file into `buf`: open, read, close, without
/// the size query `read_to_string` makes (a third of the cost here).
fn read_small<'a>(path: &str, buf: &'a mut Vec<u8>) -> Option<&'a str> {
    use std::io::Read;
    buf.clear();
    fs::File::open(path).ok()?.read_to_end(buf).ok()?;
    std::str::from_utf8(buf).ok()
}

/// The unit paths owning a listener.
fn owner_units(inputs: &Inputs) -> impl Iterator<Item = &str> {
    inputs.listeners.iter().filter_map(|listener| {
        let id = inputs.socket_cgroups.as_ref()?.get(&listener.inode)?;
        unit_path(inputs.cgroups.get(id)?)
    })
}

/// The real uid (`Uid:` real, effective, saved, filesystem). Not the owner
/// of `/proc/PID`, which is root for a daemon that dropped privileges.
fn real_uid(pid: u32) -> Option<u32> {
    read_small(
        &format!("/proc/{pid}/status"),
        &mut Vec::with_capacity(2048),
    )?
    .lines()
    .find_map(|line| line.strip_prefix("Uid:"))?
    .split_whitespace()
    .next()?
    .parse()
    .ok()
}

/// Adds every cgroup directory under `start` (below the root; `""` is the
/// root itself), except the subtree `skip`: its inode (the cgroup id) → its
/// path (`/` for the root).
fn walk(start: &str, skip: Option<&str>, found: &mut HashMap<u64, String>, deadline: Instant) {
    let Ok(meta) = fs::metadata(format!("{CGROUP_ROOT}{start}")) else {
        return;
    };
    found.insert(
        meta.ino(),
        if start.is_empty() {
            "/".into()
        } else {
            start.to_owned()
        },
    );
    let mut stack = vec![start.to_owned()];
    while let Some(path) = stack.pop() {
        if found.len() >= MAX_CGROUPS || Instant::now() > deadline {
            break;
        }
        let Ok(entries) = fs::read_dir(format!("{CGROUP_ROOT}{path}")) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|t| t.is_dir())
                && let Some(name) = entry.file_name().to_str()
            {
                let child = format!("{path}/{name}");
                if skip == Some(child.as_str()) {
                    continue;
                }
                // The directory entry's inode: no stat per cgroup.
                found.insert(std::os::unix::fs::DirEntryExt::ino(&entry), child.clone());
                stack.push(child);
            }
        }
    }
}

/// TCP listeners and unconnected UDP sockets with their cgroup ids, from
/// `sock_diag` (any user may dump them).
fn diag_sockets() -> Result<Vec<(Listener, Option<u64>)>, CollectorError> {
    let mut found = Vec::new();
    for family in [AF_INET, AF_INET6] {
        for (protocol, states) in [
            (IPPROTO_TCP, 1 << TCP_LISTEN),
            (IPPROTO_UDP, 1 << TCP_CLOSE),
        ] {
            dump(&diag_request(family, protocol, states), &mut found)?;
        }
    }
    Ok(found)
}

fn dump(request: &[u8], found: &mut Vec<(Listener, Option<u64>)>) -> Result<(), CollectorError> {
    use rustix::net::{
        AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, netlink, recv, send,
        socket_with,
    };
    let failed = |what: &str| error(CollectorErrorCode::Internal, what);
    let fd = socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        Some(netlink::SOCK_DIAG),
    )
    .map_err(|_| failed("cannot open a sock_diag socket"))?;
    rustix::net::sockopt::set_socket_timeout(
        &fd,
        rustix::net::sockopt::Timeout::Recv,
        Some(std::time::Duration::from_secs(2)),
    )
    .map_err(|_| failed("cannot set the sock_diag timeout"))?;
    send(&fd, request, SendFlags::empty()).map_err(|_| failed("sock_diag request failed"))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut messages = 0;
    loop {
        let (len, _) = recv(&fd, &mut buf[..], RecvFlags::empty())
            .map_err(|_| failed("sock_diag read failed"))?;
        match parse_dump(&buf[..len], found, &mut messages) {
            Ok(true) => return Ok(()),
            Ok(false) if messages <= MAX_DIAG_MESSAGES => {}
            _ => return Err(failed("malformed or oversized sock_diag dump")),
        }
    }
}

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const TCP_LISTEN: u32 = 10;
/// Unconnected UDP sockets report `TCP_CLOSE`.
const TCP_CLOSE: u32 = 7;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
/// `INET_DIAG_CGROUP_ID` (Linux 5.7): the socket's cgroup id, a u64.
const INET_DIAG_CGROUP_ID: u16 = 21;
/// `struct inet_diag_msg`: the inode is its last field.
const DIAG_MSG_LEN: usize = 72;
const DIAG_MSG_INODE: usize = 68;

/// `nlmsghdr` and `inet_diag_req_v2` asking to dump `family`/`protocol`
/// sockets in `states` (a bit mask of TCP states).
pub(super) fn diag_request(family: u8, protocol: u8, states: u32) -> [u8; 72] {
    let mut req = [0u8; 72];
    req[0..4].copy_from_slice(&72u32.to_ne_bytes());
    req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
    req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    req[16] = family;
    req[17] = protocol;
    req[20..24].copy_from_slice(&states.to_ne_bytes());
    req
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}
const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Reads one netlink datagram of a dump into `found` (each socket and its
/// cgroup id, when the kernel gives one); `Ok(true)` at its end, `Err` on
/// an error message or a malformed one.
pub(super) fn parse_dump(
    buf: &[u8],
    found: &mut Vec<(Listener, Option<u64>)>,
    messages: &mut usize,
) -> Result<bool, ()> {
    let mut at = 0;
    while at < buf.len() {
        let len = u32_at(buf, at).ok_or(())? as usize;
        let kind = u16_at(buf, at + 4).ok_or(())?;
        if len < 16 || at + len > buf.len() {
            return Err(());
        }
        match kind {
            NLMSG_DONE => return Ok(true),
            NLMSG_ERROR => return Err(()),
            SOCK_DIAG_BY_FAMILY => {
                *messages += 1;
                found.push(diag_message(&buf[at + 16..at + len]).ok_or(())?);
            }
            _ => {}
        }
        at += align4(len);
    }
    Ok(false)
}

/// One `inet_diag_msg`: family, state, then `inet_diag_sockid` (source
/// port and address in network order), …, the inode; then attributes.
fn diag_message(msg: &[u8]) -> Option<(Listener, Option<u64>)> {
    if msg.len() < DIAG_MSG_LEN {
        return None;
    }
    let protocol = if msg[1] == TCP_LISTEN as u8 {
        Protocol::Tcp
    } else {
        Protocol::Udp
    };
    let port = u16::from_be_bytes([msg[4], msg[5]]);
    let address = match msg[0] {
        AF_INET => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&msg[8..12]).ok()?)),
        AF_INET6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&msg[8..24]).ok()?)),
        _ => return None,
    };
    let inode = u64::from(u32_at(msg, DIAG_MSG_INODE)?);
    let mut cgroup = None;
    let mut attr = DIAG_MSG_LEN;
    while attr + 4 <= msg.len() {
        let attr_len = usize::from(u16_at(msg, attr)?);
        if attr_len < 4 || attr + attr_len > msg.len() {
            return None;
        }
        if u16_at(msg, attr + 2) == Some(INET_DIAG_CGROUP_ID) && attr_len >= 12 {
            cgroup = Some(u64_at(msg, attr + 4)?);
        }
        attr += align4(attr_len);
    }
    Some((
        Listener {
            protocol,
            address,
            port,
            inode,
        },
        cgroup,
    ))
}
